"""The approval workflow for AI systems: a per-tenant policy by risk tier, requests, distinct approvers, approval
scopes, and what happens when an approval is used up, runs out or is revoked.

- The policy (ai_system_approval_policies; no row means the defaults below) says, for each risk tier, how many
  distinct people must approve, whether the requester may approve their own request (only when one approval is
  needed), which roles may approve, and which scopes an approver may choose: ``blanket`` (stands until revoked),
  ``one_time`` (consumed by the first governed use through the gateway) or ``time_bound`` (ends at a set time).
- A request is an ``approval_requests`` row (the same table the gateway's and GitHub's approvals use) with
  ``request_payload.type == "ai_system_approval"``. It stays ``pending`` until enough distinct approvers said yes;
  then it is ``approved`` and an ``ai_system_approval_grants`` row stands for the approval. One "no" denies it.
- Only a grant makes an AI system approved: PATCH /ai-systems/{id} refuses to set an approved status without one
  (app/api/routers/ai_systems.py).
- A consumed, expired or revoked grant puts the system in ``pending_reapproval``; the governance decisions
  (app/services/governance_resolution.py) read it, and a lapsed time-bound approval, as not approved at once, before
  the scheduled check (app/jobs/enforcement_jobs.py ``expire_ai_system_approvals``) records the expiry.

Every request, approval, denial, expiry, consumption and revocation writes an audit log entry and an evidence node.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.db.models.ai_system import AISystem
from app.db.models.ai_system_approval import AISystemApprovalGrant, AISystemApprovalPolicy
from app.db.models.policy import ApprovalRequest
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node
from app.services.governance_resolution import (
    ONE_TIME_IN_USE_KEY,
    ai_system_is_approved,
    approval_has_lapsed,
)


REQUEST_TYPE = "ai_system_approval"
SCOPES: tuple[str, ...] = ("blanket", "one_time", "time_bound")
#: The risk tiers the policy sets, lowest to highest (app/api/routers/ai_systems.py RISK_RANK).
TIERS: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH", "CRITICAL", "RESTRICTED")
#: Tiers that are never approvable: the governance check blocks them whatever their state.
NOT_APPROVABLE_TIERS = frozenset({"PROHIBITED"})
#: Other names for tiers met in the inventory; anything else unknown is treated as CRITICAL.
TIER_ALIASES = {"MINIMAL": "LOW", "LIMITED": "MEDIUM"}
UNKNOWN_TIER = "CRITICAL"

MAX_APPROVERS = 5
MAX_DURATION_HOURS = 8760  # one year
MAX_REQUEST_TTL_HOURS = 720  # thirty days
DEFAULT_REQUEST_TTL_HOURS = 168  # seven days
#: After a one-time approval is consumed by a gateway request, the separate response check of that same use
#: (POST /llm-gateway/response) still passes for this long.
ONE_TIME_RESPONSE_GRACE_SECONDS = 300

#: The governed uses that consume a one-time approval: the gateway's entry points, not its follow-up checks.
CONSUMING_ACTIONS = frozenset(
    {"gateway.llm.intercept", "gateway.mcp.authorize", "llm_gateway.request", "llm_gateway.chat.complete"}
)
RESPONSE_ACTIONS = frozenset({"llm_gateway.response"})

#: Statuses that mean approved (app/services/governance_resolution.py APPROVED_STATES, lower case).
APPROVED_STATUSES = frozenset({"approved", "active", "live"})
#: The status an approval may put a system in. LIVE has prerequisites of its own: PATCH /ai-systems/{id} after approval.
TARGET_STATUSES = ("approved", "active")

_ROLE_KEY = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,31}$")

#: The defaults: higher tiers are stricter. Nobody approves their own request by default.
DEFAULT_TIER_RULES: dict[str, dict[str, Any]] = {
    "LOW": {
        "min_approvers": 1,
        "allow_self_approval": False,
        "approver_roles": ["owner", "admin", "operator"],
        "allowed_scopes": ["blanket", "one_time", "time_bound"],
        "default_scope": "blanket",
        "default_duration_hours": 2160,
        "max_duration_hours": 8760,
    },
    "MEDIUM": {
        "min_approvers": 1,
        "allow_self_approval": False,
        "approver_roles": ["owner", "admin"],
        "allowed_scopes": ["blanket", "one_time", "time_bound"],
        "default_scope": "time_bound",
        "default_duration_hours": 2160,
        "max_duration_hours": 8760,
    },
    "HIGH": {
        "min_approvers": 2,
        "allow_self_approval": False,
        "approver_roles": ["owner", "admin"],
        "allowed_scopes": ["one_time", "time_bound"],
        "default_scope": "time_bound",
        "default_duration_hours": 720,
        "max_duration_hours": 2160,
    },
    "CRITICAL": {
        "min_approvers": 2,
        "allow_self_approval": False,
        "approver_roles": ["owner", "admin"],
        "allowed_scopes": ["time_bound"],
        "default_scope": "time_bound",
        "default_duration_hours": 168,
        "max_duration_hours": 720,
    },
    "RESTRICTED": {
        "min_approvers": 2,
        "allow_self_approval": False,
        "approver_roles": ["owner", "admin"],
        "allowed_scopes": ["one_time", "time_bound"],
        "default_scope": "one_time",
        "default_duration_hours": 24,
        "max_duration_hours": 168,
    },
}


class ApprovalWorkflowError(Exception):
    """A refused step, with the HTTP status the API answers and a stable code."""

    def __init__(self, message: str, *, status_code: int = 409, code: str = "approval_refused") -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    moment = _utc(value)
    return moment.isoformat() if moment else None


# ---------------------------------------------------------------------------------------------------------------------
# The policy
# ---------------------------------------------------------------------------------------------------------------------


def default_config() -> dict[str, Any]:
    return {
        "tiers": {tier: {**rule, "approver_roles": list(rule["approver_roles"]), "allowed_scopes": list(rule["allowed_scopes"])} for tier, rule in DEFAULT_TIER_RULES.items()},
        "request_ttl_hours": DEFAULT_REQUEST_TTL_HOURS,
    }


def _int(value: Any, *, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ApprovalWorkflowError(f"{name} must be a whole number.", status_code=400, code="invalid_policy")
    if not low <= value <= high:
        raise ApprovalWorkflowError(f"{name} must be between {low} and {high}.", status_code=400, code="invalid_policy")
    return value


def _sanitize_rule(tier: str, raw: Any, base: dict[str, Any], known_roles: Iterable[str] | None) -> dict[str, Any]:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ApprovalWorkflowError(f"{tier}: the rule must be an object.", status_code=400, code="invalid_policy")
    unknown = sorted(set(raw) - set(DEFAULT_TIER_RULES["LOW"]))
    if unknown:
        raise ApprovalWorkflowError(f"{tier}: unknown field {unknown[0]}.", status_code=400, code="invalid_policy")
    merged = {**base, **raw}
    min_approvers = _int(merged.get("min_approvers"), name=f"{tier}: approvers", low=1, high=MAX_APPROVERS)
    allow_self = merged.get("allow_self_approval")
    if not isinstance(allow_self, bool):
        raise ApprovalWorkflowError(f"{tier}: self-approval must be true or false.", status_code=400, code="invalid_policy")
    if allow_self and min_approvers > 1:
        raise ApprovalWorkflowError(
            f"{tier}: the requester may approve their own request only when one approval is needed.",
            status_code=400,
            code="invalid_policy",
        )
    roles_raw = merged.get("approver_roles")
    if not isinstance(roles_raw, list) or not roles_raw:
        raise ApprovalWorkflowError(f"{tier}: name at least one role that may approve.", status_code=400, code="invalid_policy")
    roles: list[str] = []
    known = set(known_roles) if known_roles is not None else None
    for item in roles_raw:
        key = str(item or "").strip().lower()
        if not _ROLE_KEY.fullmatch(key):
            raise ApprovalWorkflowError(f"{tier}: {str(item)[:40]!r} is not a role.", status_code=400, code="invalid_policy")
        if known is not None and key not in known:
            raise ApprovalWorkflowError(f"{tier}: there is no role {key!r} in this tenant.", status_code=400, code="invalid_policy")
        if key not in roles:
            roles.append(key)
    if len(roles) > 12:
        raise ApprovalWorkflowError(f"{tier}: at most 12 roles.", status_code=400, code="invalid_policy")
    scopes_raw = merged.get("allowed_scopes")
    if not isinstance(scopes_raw, list) or not scopes_raw:
        raise ApprovalWorkflowError(f"{tier}: allow at least one approval scope.", status_code=400, code="invalid_policy")
    scopes = [scope for scope in SCOPES if scope in {str(item or "").strip().lower() for item in scopes_raw}]
    if len(scopes) != len({str(item or "").strip().lower() for item in scopes_raw}):
        raise ApprovalWorkflowError(
            f"{tier}: approval scopes are blanket, one_time and time_bound.", status_code=400, code="invalid_policy"
        )
    default_scope = str(merged.get("default_scope") or "").strip().lower()
    if default_scope not in scopes:
        raise ApprovalWorkflowError(f"{tier}: the default scope must be one of the allowed scopes.", status_code=400, code="invalid_policy")
    max_hours = _int(merged.get("max_duration_hours"), name=f"{tier}: longest time-bound approval (hours)", low=1, high=MAX_DURATION_HOURS)
    default_hours = _int(merged.get("default_duration_hours"), name=f"{tier}: default time-bound approval (hours)", low=1, high=max_hours)
    return {
        "min_approvers": min_approvers,
        "allow_self_approval": allow_self,
        "approver_roles": roles,
        "allowed_scopes": scopes,
        "default_scope": default_scope,
        "default_duration_hours": default_hours,
        "max_duration_hours": max_hours,
    }


def sanitize_config(raw: Any, *, base: dict[str, Any] | None = None, known_roles: Iterable[str] | None = None) -> dict[str, Any]:
    """A complete, checked policy: ``raw`` over ``base`` (the policy in force), tier by tier and field by field."""

    current = base if isinstance(base, dict) else default_config()
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ApprovalWorkflowError("The policy must be an object.", status_code=400, code="invalid_policy")
    unknown = sorted(set(raw) - {"tiers", "request_ttl_hours"})
    if unknown:
        raise ApprovalWorkflowError(f"Unknown field {unknown[0]}.", status_code=400, code="invalid_policy")
    tiers_raw = raw.get("tiers") or {}
    if not isinstance(tiers_raw, dict):
        raise ApprovalWorkflowError("tiers must be an object by risk tier.", status_code=400, code="invalid_policy")
    unknown_tiers = sorted({str(key).upper() for key in tiers_raw} - set(TIERS))
    if unknown_tiers:
        raise ApprovalWorkflowError(
            f"There is no policy for risk tier {unknown_tiers[0]} (tiers: {', '.join(TIERS)}).", status_code=400, code="invalid_policy"
        )
    tiers_in = {str(key).upper(): value for key, value in tiers_raw.items()}
    current_tiers = current.get("tiers") if isinstance(current.get("tiers"), dict) else {}
    tiers: dict[str, dict[str, Any]] = {}
    for tier in TIERS:
        base_rule = current_tiers.get(tier) if isinstance(current_tiers.get(tier), dict) else DEFAULT_TIER_RULES[tier]
        base_rule = {**DEFAULT_TIER_RULES[tier], **{k: v for k, v in base_rule.items() if k in DEFAULT_TIER_RULES[tier]}}
        tiers[tier] = _sanitize_rule(tier, tiers_in.get(tier), base_rule, known_roles if tier in tiers_in else None)
    ttl = raw.get("request_ttl_hours", current.get("request_ttl_hours", DEFAULT_REQUEST_TTL_HOURS))
    return {
        "tiers": tiers,
        "request_ttl_hours": _int(ttl, name="How long a request waits (hours)", low=1, high=MAX_REQUEST_TTL_HOURS),
    }


def load_config(db: Session, tenant_id: str) -> dict[str, Any]:
    row = db.get(AISystemApprovalPolicy, tenant_id)
    if row is None:
        return default_config()
    try:
        return sanitize_config({}, base=row.config if isinstance(row.config, dict) else None)
    except ApprovalWorkflowError:
        # A stored policy that no longer reads is replaced by the defaults, never by something laxer.
        return default_config()


def _tenant_role_keys(db: Session, tenant_id: str) -> list[str]:
    from app.services import iam_service

    try:
        return [role.key for role in iam_service.roles(db, tenant_id)]
    except Exception:  # noqa: BLE001 - a database without the roles table (tests of one feature): the built-in roles
        from app.core.permissions import BUILTIN_ORDER

        return list(BUILTIN_ORDER)


def policy_view(db: Session, tenant_id: str) -> dict[str, Any]:
    row = db.get(AISystemApprovalPolicy, tenant_id)
    return {
        "policy": load_config(db, tenant_id),
        "defaults": default_config(),
        "tiers": list(TIERS),
        "not_approvable_tiers": sorted(NOT_APPROVABLE_TIERS),
        "unknown_tier_reads_as": UNKNOWN_TIER,
        "scopes": list(SCOPES),
        "roles": _tenant_role_keys(db, tenant_id),
        "revision": int(row.revision or 0) if row else 0,
        "updated_at": _iso(row.updated_at) if row else None,
        "updated_by": (row.updated_by or None) if row else None,
    }


def save_policy(db: Session, tenant_id: str, body: Any, *, by: str) -> dict[str, Any]:
    before = load_config(db, tenant_id)
    config = sanitize_config(body, base=before, known_roles=_tenant_role_keys(db, tenant_id))
    row = db.get(AISystemApprovalPolicy, tenant_id)
    if row is None:
        row = AISystemApprovalPolicy(tenant_id=tenant_id, config=config, revision=0, updated_by="")
        db.add(row)
    row.config = config
    row.revision = int(row.revision or 0) + 1
    row.updated_at = utcnow()
    row.updated_by = (by or "")[:320]
    db.flush()
    return {"before": before, "view": policy_view(db, tenant_id)}


def tier_of(risk_tier: str | None) -> str | None:
    """The policy tier an AI system's risk tier falls under; None when it is never approvable."""

    normalized = str(risk_tier or "").strip().upper()
    if normalized in NOT_APPROVABLE_TIERS:
        return None
    normalized = TIER_ALIASES.get(normalized, normalized)
    return normalized if normalized in TIERS else UNKNOWN_TIER


def rule_for(config: dict[str, Any], risk_tier: str | None) -> tuple[str, dict[str, Any]]:
    tier = tier_of(risk_tier)
    if tier is None:
        raise ApprovalWorkflowError(
            f"AI systems of risk tier {str(risk_tier or '').upper()} cannot be approved.", code="tier_not_approvable"
        )
    return tier, dict(config["tiers"][tier])


def check_scope(rule: dict[str, Any], scope: str | None, duration_hours: Any, *, tier: str) -> tuple[str, int | None]:
    """The scope and the duration (hours, time-bound only) an approver may give within the rule."""

    chosen = str(scope or rule["default_scope"]).strip().lower()
    if chosen not in SCOPES:
        raise ApprovalWorkflowError("The scope must be blanket, one_time or time_bound.", status_code=400, code="invalid_scope")
    if chosen not in rule["allowed_scopes"]:
        allowed = ", ".join(rule["allowed_scopes"])
        raise ApprovalWorkflowError(
            f"The {tier} policy does not allow a {chosen} approval (allowed: {allowed}).", code="scope_not_allowed"
        )
    if chosen != "time_bound":
        if duration_hours not in (None, ""):
            raise ApprovalWorkflowError("Only a time-bound approval has a duration.", status_code=400, code="invalid_scope")
        return chosen, None
    hours = rule["default_duration_hours"] if duration_hours in (None, "") else duration_hours
    if isinstance(hours, bool) or not isinstance(hours, int) or hours < 1:
        raise ApprovalWorkflowError("The duration is a whole number of hours, at least 1.", status_code=400, code="invalid_scope")
    if hours > int(rule["max_duration_hours"]):
        raise ApprovalWorkflowError(
            f"The {tier} policy allows time-bound approvals of at most {rule['max_duration_hours']} hours.", code="scope_not_allowed"
        )
    return chosen, hours


# ---------------------------------------------------------------------------------------------------------------------
# Audit and evidence
# ---------------------------------------------------------------------------------------------------------------------


def _record(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    action: str,
    ai_system_id: str,
    payload: dict[str, Any],
    actor_type: str = "human",
) -> None:
    """One audit log entry and one evidence node, as the other governance changes write them."""

    node = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="ai_system_approval",
        signal_type=action,
        label=f"AI system approval: {action.rsplit('.', 1)[-1]}",
        payload={"ai_system_id": ai_system_id, **payload},
    )
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type=actor_type,
        action=action,
        resource_type="ai_system",
        resource_id=ai_system_id,
        payload={**payload, "evidence_node_id": node.id},
    )


def record_refusal(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    ai_system_id: str,
    error: ApprovalWorkflowError,
    step: str,
    extra: dict[str, Any] | None = None,
) -> None:
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="ai_system.approval.refused",
        resource_type="ai_system",
        resource_id=ai_system_id,
        payload={"outcome": "refused", "step": step, "code": error.code, "reason": error.message, **(extra or {})},
    )


# ---------------------------------------------------------------------------------------------------------------------
# Requests and decisions
# ---------------------------------------------------------------------------------------------------------------------


def is_ai_system_approval_request(request: ApprovalRequest | None) -> bool:
    payload = request.request_payload if request is not None and isinstance(request.request_payload, dict) else {}
    return payload.get("type") == REQUEST_TYPE


def _load_system(db: Session, tenant_id: str, ai_system_id: str) -> AISystem:
    row = db.scalar(select(AISystem).where(AISystem.tenant_id == tenant_id, AISystem.id == ai_system_id))
    if row is None:
        raise ApprovalWorkflowError("AI system not found", status_code=404, code="not_found")
    return row


def pending_request_for(db: Session, tenant_id: str, ai_system_id: str) -> ApprovalRequest | None:
    rows = db.scalars(
        select(ApprovalRequest).where(
            ApprovalRequest.tenant_id == tenant_id,
            ApprovalRequest.ai_system_id == ai_system_id,
            ApprovalRequest.status == "pending",
        )
    ).all()
    return next((row for row in rows if is_ai_system_approval_request(row)), None)


def request_approval(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    actor_user_id: str | None,
    scope: str | None = None,
    duration_hours: Any = None,
    reason: str | None = None,
    origin: str = "ai_systems",
    target_status: str | None = None,
    now: datetime | None = None,
) -> ApprovalRequest:
    """Ask for an AI system to be approved. The scope asked for must be one the tier's policy allows; the first
    approver may change it within the policy."""

    moment = _utc(now) or utcnow()
    if not actor_user_id:
        raise ApprovalWorkflowError("Only a signed-in person can ask for an approval.", status_code=403, code="identity_required")
    system = _load_system(db, tenant_id, ai_system_id)
    config = load_config(db, tenant_id)
    tier, rule = rule_for(config, system.risk_tier)
    chosen_scope, hours = check_scope(rule, scope, duration_hours, tier=tier)
    target = str(target_status or "approved").strip().lower()
    if target not in TARGET_STATUSES:
        raise ApprovalWorkflowError("An approval makes a system approved or active.", status_code=400, code="invalid_target_status")
    if pending_request_for(db, tenant_id, system.id) is not None:
        raise ApprovalWorkflowError("This AI system already has an approval request waiting.", code="request_pending")
    previous_status = str(system.status or "draft")
    renewal = ai_system_is_approved(system, now=moment)
    request = ApprovalRequest(
        tenant_id=tenant_id,
        ai_system_id=system.id,
        enforcement_event_id=None,
        request_payload={
            "type": REQUEST_TYPE,
            "requested_by": actor_user_id,
            "requested_at": moment.isoformat(),
            "reason": str(reason or "").strip()[:500],
            "origin": origin,
            "risk_tier": str(system.risk_tier or "").upper(),
            "tier": tier,
            "rule": rule,
            "scope": chosen_scope,
            "duration_hours": hours,
            "previous_status": previous_status,
            "target_status": target,
            "renewal": renewal,
            "approvals": [],
        },
        required_roles=list(rule["approver_roles"]),
        sla_minutes=int(config["request_ttl_hours"]) * 60,
        default_if_timeout="block",
        status="pending",
        decision_version=0,
    )
    db.add(request)
    db.flush()
    if not renewal:
        system.status = "pending_approval"
        metadata = dict(system.metadata_json or {})
        metadata["approval_request_id"] = request.id
        system.metadata_json = metadata
    _record(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        action="ai_system.approval.requested",
        ai_system_id=system.id,
        payload={
            "approval_request_id": request.id,
            "risk_tier": str(system.risk_tier or "").upper(),
            "tier": tier,
            "scope": chosen_scope,
            "duration_hours": hours,
            "min_approvers": rule["min_approvers"],
            "approver_roles": rule["approver_roles"],
            "renewal": renewal,
            "origin": origin,
        },
    )
    db.flush()
    return request


def _request_deadline(request: ApprovalRequest) -> datetime:
    return (_utc(request.created_at) or utcnow()) + timedelta(minutes=int(request.sla_minutes or 0))


def _lock_request(db: Session, tenant_id: str, request_id: str) -> ApprovalRequest:
    request = db.scalar(
        select(ApprovalRequest)
        .where(ApprovalRequest.tenant_id == tenant_id, ApprovalRequest.id == request_id)
        .with_for_update()
    )
    if request is None or not is_ai_system_approval_request(request):
        raise ApprovalWorkflowError("Approval request not found", status_code=404, code="not_found")
    return request


def decide(
    db: Session,
    *,
    tenant_id: str,
    request_id: str,
    actor_user_id: str | None,
    actor_role: str | None,
    decision: str,
    scope: str | None = None,
    duration_hours: Any = None,
    reason: str | None = None,
    now: datetime | None = None,
) -> tuple[ApprovalRequest, AISystemApprovalGrant | None]:
    """One approver's yes or no. The request is approved when the tier's number of distinct approvers said yes; one no
    denies it. Returns the request and, once approved, the grant."""

    moment = _utc(now) or utcnow()
    if decision not in {"approve", "deny"}:
        raise ApprovalWorkflowError("The decision is approve or deny.", status_code=400, code="invalid_decision")
    if not actor_user_id:
        raise ApprovalWorkflowError("Only a signed-in person can decide an approval.", status_code=403, code="identity_required")
    request = _lock_request(db, tenant_id, request_id)
    payload = dict(request.request_payload or {})
    rule = dict(payload.get("rule") or {})
    tier = str(payload.get("tier") or "")
    if request.status != "pending":
        raise ApprovalWorkflowError(f"This request is {request.status}, not waiting for a decision.", code="request_closed")
    if moment >= _request_deadline(request):
        expire_request(db, request, now=moment)
        raise ApprovalWorkflowError("This request waited too long and has expired. Ask again.", code="request_expired")
    system = _load_system(db, tenant_id, request.ai_system_id)
    # The tier the request was made under must still be the system's: a re-tiered system is asked for again.
    if tier_of(system.risk_tier) != tier:
        raise ApprovalWorkflowError(
            "The AI system's risk tier changed after this request was made. Deny it and ask again.", code="tier_changed"
        )
    role = str(actor_role or "").strip().lower()
    if role not in {str(r).lower() for r in rule.get("approver_roles") or []}:
        raise ApprovalWorkflowError(
            f"Your role may not approve {tier} AI systems (approvers: {', '.join(rule.get('approver_roles') or [])}).",
            status_code=403,
            code="role_not_allowed",
        )
    requester = str(payload.get("requested_by") or "")
    approvals = [dict(item) for item in payload.get("approvals") or [] if isinstance(item, dict)]
    needed = int(rule.get("min_approvers") or 1)
    if decision == "approve":
        if actor_user_id == requester and (needed > 1 or not rule.get("allow_self_approval")):
            raise ApprovalWorkflowError(
                "You asked for this approval, so someone else must approve it." if needed == 1 else
                f"You asked for this approval: {needed} other people must approve it.",
                status_code=403,
                code="self_approval_refused",
            )
        if any(item.get("user_id") == actor_user_id for item in approvals):
            raise ApprovalWorkflowError(
                f"You have already approved this request. It needs {needed} different approvers.",
                code="duplicate_approver",
            )
        if approvals:
            # The first approver set the scope; the others approve that, or deny.
            fixed_scope = str(payload.get("scope") or "")
            fixed_hours = payload.get("duration_hours")
            if (scope not in (None, "") and str(scope).lower() != fixed_scope) or (
                duration_hours not in (None, "") and duration_hours != fixed_hours
            ):
                raise ApprovalWorkflowError(
                    f"The first approver chose {fixed_scope}" + (f" for {fixed_hours} hours" if fixed_hours else "")
                    + ". Approve that, or deny.",
                    code="scope_fixed",
                )
            chosen_scope, hours = fixed_scope, fixed_hours
        else:
            chosen_scope, hours = check_scope(
                rule,
                scope if scope not in (None, "") else payload.get("scope"),
                duration_hours if duration_hours not in (None, "") or scope not in (None, "") else payload.get("duration_hours"),
                tier=tier,
            )
    request.decision_version = int(request.decision_version or 0) + 1
    if decision == "deny":
        request.status = "denied"
        request.decision = "deny"
        request.decided_by = actor_user_id
        request.decided_at = moment
        payload["denied_by"] = actor_user_id
        payload["denied_reason"] = str(reason or "").strip()[:500]
        request.request_payload = payload
        _restore_after_closed_request(system, request)
        _record(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            action="ai_system.approval.denied",
            ai_system_id=system.id,
            payload={"approval_request_id": request.id, "tier": tier, "reason": payload["denied_reason"], "approvals_before": len(approvals)},
        )
        db.flush()
        return request, None

    approvals.append({"user_id": actor_user_id, "role": role, "at": moment.isoformat(), "reason": str(reason or "").strip()[:500]})
    payload["approvals"] = approvals
    payload["scope"] = chosen_scope
    payload["duration_hours"] = hours
    request.request_payload = payload
    _record(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        action="ai_system.approval.approved",
        ai_system_id=system.id,
        payload={
            "approval_request_id": request.id,
            "tier": tier,
            "scope": chosen_scope,
            "duration_hours": hours,
            "approvals": len(approvals),
            "approvals_needed": needed,
            "self_approval": actor_user_id == requester,
        },
    )
    if len(approvals) < needed:
        db.flush()
        return request, None

    request.status = "approved"
    request.decision = "approve"
    request.decided_by = actor_user_id
    request.decided_at = moment
    grant = _issue_grant(db, tenant_id=tenant_id, system=system, request=request, scope=chosen_scope, hours=hours, now=moment)
    return request, grant


def _restore_after_closed_request(system: AISystem, request: ApprovalRequest) -> None:
    """A denied or expired request leaves the system as it was before it was asked for."""

    payload = request.request_payload if isinstance(request.request_payload, dict) else {}
    metadata = dict(system.metadata_json or {})
    if metadata.get("approval_request_id") == request.id:
        metadata.pop("approval_request_id", None)
        system.metadata_json = metadata
    if str(system.status or "") == "pending_approval":
        previous = str(payload.get("previous_status") or "draft")
        # Never back to an approved status: a system is approved only by a grant.
        system.status = "draft" if previous.lower() in APPROVED_STATUSES or previous == "pending_approval" else previous


def _issue_grant(
    db: Session,
    *,
    tenant_id: str,
    system: AISystem,
    request: ApprovalRequest,
    scope: str,
    hours: int | None,
    now: datetime,
) -> AISystemApprovalGrant:
    payload = request.request_payload if isinstance(request.request_payload, dict) else {}
    approvers = [str(item.get("user_id")) for item in payload.get("approvals") or [] if isinstance(item, dict)]
    expires_at = now + timedelta(hours=int(hours)) if scope == "time_bound" and hours else None
    for older in db.scalars(
        select(AISystemApprovalGrant).where(
            AISystemApprovalGrant.tenant_id == tenant_id,
            AISystemApprovalGrant.ai_system_id == system.id,
            AISystemApprovalGrant.state == "ACTIVE",
        )
    ).all():
        older.state = "SUPERSEDED"
        older.ended_at = now
        older.end_reason = f"replaced by the approval of request {request.id}"[:255]
        _record(
            db,
            tenant_id=tenant_id,
            actor_user_id=request.decided_by,
            action="ai_system.approval.superseded",
            ai_system_id=system.id,
            payload={"grant_id": older.id, "scope": older.scope, "approval_request_id": request.id},
        )
    grant = AISystemApprovalGrant(
        tenant_id=tenant_id,
        ai_system_id=system.id,
        approval_request_id=request.id,
        scope=scope,
        state="ACTIVE",
        risk_tier=str(system.risk_tier or "").upper()[:16],
        origin="workflow",
        requested_by=str(payload.get("requested_by") or "") or None,
        approver_user_ids=approvers,
        expires_at=expires_at,
        end_reason="",
    )
    db.add(grant)
    db.flush()

    was_approved = ai_system_is_approved(system, now=now)
    current = str(system.status or "").lower()
    if current not in APPROVED_STATUSES:
        target = str(payload.get("target_status") or "approved")
        system.status = target if target in TARGET_STATUSES else "approved"
    metadata = dict(system.metadata_json or {})
    metadata.pop("approval_request_id", None)
    metadata["governance_state"] = "APPROVED"
    lifecycle = str(metadata.get("lifecycle_state") or "").upper()
    if not lifecycle or lifecycle in {"PENDING_APPROVAL", "PENDING_REAPPROVAL", "PENDING_REVIEW", "REVIEW", "PROPOSED", "DRAFT"}:
        metadata["lifecycle_state"] = "ACTIVE"
    metadata["approved_at"] = now.isoformat()
    metadata["requires_reapproval"] = False
    metadata["approval"] = {
        "grant_id": grant.id,
        "approval_request_id": request.id,
        "scope": scope,
        "state": "active",
        "origin": "workflow",
        "expires_at": _iso(expires_at),
        "approved_at": now.isoformat(),
        "approver_user_ids": approvers,
    }
    system.metadata_json = metadata
    _record(
        db,
        tenant_id=tenant_id,
        actor_user_id=request.decided_by,
        action="ai_system.approval.granted",
        ai_system_id=system.id,
        payload={
            "grant_id": grant.id,
            "approval_request_id": request.id,
            "scope": scope,
            "expires_at": _iso(expires_at),
            "approver_user_ids": approvers,
            "requested_by": grant.requested_by,
            "risk_tier": grant.risk_tier,
        },
    )
    if not was_approved or current not in APPROVED_STATUSES:
        from app.services.simulation_scheduler_service import schedule_for_ai_system_approved

        schedule_for_ai_system_approved(db, tenant_id=tenant_id, ai_system_id=system.id, actor_user_id=request.decided_by)
    db.flush()
    return grant


def expire_request(db: Session, request: ApprovalRequest, *, now: datetime | None = None) -> None:
    """A request that waited past its time: expired, and the system left as it was before."""

    moment = _utc(now) or utcnow()
    if request.status != "pending":
        return
    request.status = "expired"
    request.decision = "timeout_block"
    request.decided_at = moment
    request.decided_by = None
    request.decision_version = int(request.decision_version or 0) + 1
    system = db.scalar(select(AISystem).where(AISystem.tenant_id == request.tenant_id, AISystem.id == request.ai_system_id))
    if system is not None:
        _restore_after_closed_request(system, request)
    _record(
        db,
        tenant_id=request.tenant_id,
        actor_user_id=None,
        actor_type="system",
        action="ai_system.approval.request_expired",
        ai_system_id=request.ai_system_id,
        payload={"approval_request_id": request.id, "approvals": len((request.request_payload or {}).get("approvals") or [])},
    )
    db.flush()


# ---------------------------------------------------------------------------------------------------------------------
# The end of an approval: consumed, expired, revoked
# ---------------------------------------------------------------------------------------------------------------------


def _end_grant(
    db: Session,
    grant: AISystemApprovalGrant,
    *,
    state: str,
    now: datetime,
    actor_user_id: str | None,
    reason: str,
) -> bool:
    """Move an ACTIVE grant to its end state (a conditional update: two callers cannot both end it), and the system it
    approved to pending re-approval when it was that system's standing approval."""

    ended = db.execute(
        update(AISystemApprovalGrant)
        .where(
            AISystemApprovalGrant.tenant_id == grant.tenant_id,
            AISystemApprovalGrant.id == grant.id,
            AISystemApprovalGrant.state == "ACTIVE",
        )
        .values(state=state, ended_at=now, ended_by=actor_user_id, end_reason=reason[:255])
        .execution_options(synchronize_session=False)
    )
    if ended.rowcount != 1:
        return False
    db.refresh(grant)
    system = db.scalar(select(AISystem).where(AISystem.tenant_id == grant.tenant_id, AISystem.id == grant.ai_system_id))
    if system is None:
        return True
    metadata = dict(system.metadata_json or {})
    approval = metadata.get("approval") if isinstance(metadata.get("approval"), dict) else None
    if approval is not None and approval.get("grant_id") == grant.id:
        metadata["approval"] = {**approval, "state": state.lower(), "ended_at": now.isoformat()}
        if str(metadata.get("governance_state") or "").upper() in {"APPROVED", "ACTIVE", "LIVE", ""} or str(system.status or "").lower() in APPROVED_STATUSES:
            metadata["governance_state"] = "PENDING_REAPPROVAL"
            metadata["lifecycle_state"] = "PENDING_REAPPROVAL"
            metadata["requires_reapproval"] = True
            system.status = "pending_reapproval"
        system.metadata_json = metadata
    db.flush()
    return True


def revoke_grant(
    db: Session,
    *,
    tenant_id: str,
    grant_id: str,
    actor_user_id: str | None,
    actor_role: str | None,
    may_manage: bool,
    reason: str | None,
    now: datetime | None = None,
) -> AISystemApprovalGrant:
    """Revoke a standing approval. Anyone who may approve the system's tier may revoke it, and owners and admins (who
    manage the policy) always may."""

    moment = _utc(now) or utcnow()
    grant = db.scalar(
        select(AISystemApprovalGrant).where(AISystemApprovalGrant.tenant_id == tenant_id, AISystemApprovalGrant.id == grant_id)
    )
    if grant is None:
        raise ApprovalWorkflowError("Approval not found", status_code=404, code="not_found")
    if grant.state != "ACTIVE":
        raise ApprovalWorkflowError(f"This approval is already {grant.state.lower()}.", code="grant_closed")
    if not may_manage:
        config = load_config(db, tenant_id)
        tier = tier_of(grant.risk_tier) or UNKNOWN_TIER
        roles = {str(r).lower() for r in config["tiers"][tier]["approver_roles"]}
        if str(actor_role or "").strip().lower() not in roles:
            raise ApprovalWorkflowError("Your role may not revoke this approval.", status_code=403, code="role_not_allowed")
    text = str(reason or "").strip()[:255] or "revoked"
    if not _end_grant(db, grant, state="REVOKED", now=moment, actor_user_id=actor_user_id, reason=text):
        raise ApprovalWorkflowError("This approval has already ended.", code="grant_closed")
    _record(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        action="ai_system.approval.revoked",
        ai_system_id=grant.ai_system_id,
        payload={"grant_id": grant.id, "scope": grant.scope, "reason": text, "origin": grant.origin},
    )
    db.flush()
    return grant


def expire_due(db: Session, *, now: datetime | None = None, tenant_id: str | None = None, batch_limit: int = 500) -> dict[str, Any]:
    """The scheduled check: time-bound approvals whose time is up, and requests that waited too long."""

    moment = _utc(now) or utcnow()
    query = select(AISystemApprovalGrant).where(
        AISystemApprovalGrant.state == "ACTIVE",
        AISystemApprovalGrant.scope == "time_bound",
        AISystemApprovalGrant.expires_at.is_not(None),
    )
    if tenant_id:
        query = query.where(AISystemApprovalGrant.tenant_id == tenant_id)
    expired: list[str] = []
    for grant in db.scalars(query.order_by(AISystemApprovalGrant.expires_at.asc())).all():
        if len(expired) >= batch_limit:
            break
        if (_utc(grant.expires_at) or moment) > moment:
            continue
        if not _end_grant(db, grant, state="EXPIRED", now=moment, actor_user_id=None, reason="its time ran out"):
            continue
        _record(
            db,
            tenant_id=grant.tenant_id,
            actor_user_id=None,
            actor_type="system",
            action="ai_system.approval.expired",
            ai_system_id=grant.ai_system_id,
            payload={"grant_id": grant.id, "scope": grant.scope, "expires_at": _iso(grant.expires_at)},
        )
        expired.append(grant.id)

    request_query = select(ApprovalRequest).where(ApprovalRequest.status == "pending")
    if tenant_id:
        request_query = request_query.where(ApprovalRequest.tenant_id == tenant_id)
    expired_requests: list[str] = []
    for request in db.scalars(request_query.order_by(ApprovalRequest.created_at.asc())).all():
        if len(expired_requests) >= batch_limit:
            break
        if not is_ai_system_approval_request(request) or _request_deadline(request) > moment:
            continue
        expire_request(db, request, now=moment)
        expired_requests.append(request.id)
    db.flush()
    return {
        "expired_grant_count": len(expired),
        "expired_grant_ids": expired,
        "expired_request_count": len(expired_requests),
        "expired_request_ids": expired_requests,
    }


def _in_use(db: Session) -> dict[str, str]:
    info = db.info if isinstance(db.info, dict) else {}
    current = info.get(ONE_TIME_IN_USE_KEY)
    if not isinstance(current, dict):
        current = {}
        info[ONE_TIME_IN_USE_KEY] = current
    return current


def allow_response_after_one_time_use(db: Session, *, tenant_id: str, ai_system_id: str | None, now: datetime | None = None) -> None:
    """The response check of the use that consumed a one-time approval (a separate call) passes for a short while."""

    if not ai_system_id:
        return
    moment = _utc(now) or utcnow()
    system = db.scalar(select(AISystem).where(AISystem.tenant_id == tenant_id, AISystem.id == ai_system_id))
    if system is None:
        return
    approval = (system.metadata_json or {}).get("approval") if isinstance(system.metadata_json, dict) else None
    if not isinstance(approval, dict) or approval.get("scope") != "one_time" or approval.get("state") != "consumed":
        return
    ended = approval.get("ended_at")
    try:
        ended_at = _utc(datetime.fromisoformat(str(ended)))
    except ValueError:
        return
    if ended_at is not None and timedelta(0) <= moment - ended_at <= timedelta(seconds=ONE_TIME_RESPONSE_GRACE_SECONDS):
        _in_use(db)[system.id] = str(approval.get("grant_id") or "")


def consume_one_time(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    action: str,
    now: datetime | None = None,
) -> bool:
    """The first governed use of a system approved one time consumes the approval: the system goes to pending
    re-approval, and only the rest of this same use (this session) still sees it approved."""

    if not ai_system_id or action not in CONSUMING_ACTIONS:
        return False
    moment = _utc(now) or utcnow()
    system = db.scalar(select(AISystem).where(AISystem.tenant_id == tenant_id, AISystem.id == ai_system_id))
    if system is None:
        return False
    approval = (system.metadata_json or {}).get("approval") if isinstance(system.metadata_json, dict) else None
    if not isinstance(approval, dict) or approval.get("scope") != "one_time" or approval.get("state") != "active":
        return False
    grant = db.scalar(
        select(AISystemApprovalGrant).where(
            AISystemApprovalGrant.tenant_id == tenant_id, AISystemApprovalGrant.id == str(approval.get("grant_id") or "")
        )
    )
    if grant is None or grant.state != "ACTIVE":
        return False
    if not _end_grant(db, grant, state="CONSUMED", now=moment, actor_user_id=None, reason=f"used by {action}"):
        return False
    _in_use(db)[system.id] = grant.id
    _record(
        db,
        tenant_id=tenant_id,
        actor_user_id=None,
        actor_type="system",
        action="ai_system.approval.consumed",
        ai_system_id=system.id,
        payload={"grant_id": grant.id, "governed_action": action},
    )
    db.flush()
    return True


# ---------------------------------------------------------------------------------------------------------------------
# What the API shows
# ---------------------------------------------------------------------------------------------------------------------


def request_view(request: ApprovalRequest, *, system: AISystem | None = None, actor_user_id: str | None = None, actor_role: str | None = None) -> dict[str, Any]:
    payload = request.request_payload if isinstance(request.request_payload, dict) else {}
    rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
    approvals = [item for item in payload.get("approvals") or [] if isinstance(item, dict)]
    needed = int(rule.get("min_approvers") or 1)
    requester = str(payload.get("requested_by") or "")
    role = str(actor_role or "").strip().lower()
    may_decide = (
        request.status == "pending"
        and bool(actor_user_id)
        and role in {str(r).lower() for r in rule.get("approver_roles") or []}
        and not any(item.get("user_id") == actor_user_id for item in approvals)
    )
    if may_decide and actor_user_id == requester:
        may_decide_approve = needed == 1 and bool(rule.get("allow_self_approval"))
    else:
        may_decide_approve = may_decide
    return {
        "id": request.id,
        "ai_system_id": request.ai_system_id,
        "ai_system_name": system.name if system is not None else None,
        "risk_tier": payload.get("risk_tier"),
        "tier": payload.get("tier"),
        "status": request.status,
        "requested_by": requester or None,
        "requested_at": payload.get("requested_at"),
        "reason": payload.get("reason") or "",
        "scope": payload.get("scope"),
        "duration_hours": payload.get("duration_hours"),
        "renewal": bool(payload.get("renewal")),
        "target_status": payload.get("target_status") or "approved",
        "approvals": approvals,
        "approvals_needed": needed,
        "allow_self_approval": bool(rule.get("allow_self_approval")),
        "approver_roles": list(rule.get("approver_roles") or []),
        "allowed_scopes": list(rule.get("allowed_scopes") or []),
        "max_duration_hours": rule.get("max_duration_hours"),
        "scope_fixed": bool(approvals),
        "expires_at": _iso(_request_deadline(request)),
        "decided_by": request.decided_by,
        "decided_at": _iso(request.decided_at),
        "denied_reason": payload.get("denied_reason") or None,
        "may_approve": bool(may_decide_approve),
        "may_deny": bool(may_decide),
    }


def grant_view(grant: AISystemApprovalGrant, *, system: AISystem | None = None, now: datetime | None = None) -> dict[str, Any]:
    moment = _utc(now) or utcnow()
    expires_at = _utc(grant.expires_at)
    return {
        "id": grant.id,
        "ai_system_id": grant.ai_system_id,
        "ai_system_name": system.name if system is not None else None,
        "approval_request_id": grant.approval_request_id,
        "scope": grant.scope,
        "state": grant.state,
        "risk_tier": grant.risk_tier,
        "origin": grant.origin,
        "requested_by": grant.requested_by,
        "approver_user_ids": list(grant.approver_user_ids or []),
        "expires_at": _iso(expires_at),
        "lapsed": bool(grant.state == "ACTIVE" and expires_at is not None and expires_at <= moment),
        "created_at": _iso(grant.created_at),
        "ended_at": _iso(grant.ended_at),
        "ended_by": grant.ended_by,
        "end_reason": grant.end_reason or None,
    }


__all__ = [
    "APPROVED_STATUSES",
    "ApprovalWorkflowError",
    "CONSUMING_ACTIONS",
    "DEFAULT_TIER_RULES",
    "REQUEST_TYPE",
    "SCOPES",
    "TIERS",
    "ai_system_is_approved",
    "allow_response_after_one_time_use",
    "approval_has_lapsed",
    "check_scope",
    "consume_one_time",
    "decide",
    "default_config",
    "expire_due",
    "expire_request",
    "grant_view",
    "is_ai_system_approval_request",
    "load_config",
    "pending_request_for",
    "policy_view",
    "record_refusal",
    "request_approval",
    "request_view",
    "revoke_grant",
    "rule_for",
    "sanitize_config",
    "save_policy",
    "tier_of",
]
