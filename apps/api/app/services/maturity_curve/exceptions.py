"""Least-privilege, expiry-bound policy exception records.

An exception is never a broad application allow.  It is bound to one tenant,
one approved maturity rollout, one exact policy version, a bounded typed
condition tree, named request/approval principals, and a short expiry.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.maturity_curve import MaturityPolicyException, MaturityPolicyRollout
from app.services.maturity_curve.entitlements import require_maturity_capability
from app.services.maturity_curve.policy_conditions import evaluate_condition_tree, normalize_condition_tree


MAX_EXCEPTION_LIFETIME = timedelta(days=7)
ACTION_BINDING_FIELDS = {"action_type", "operation", "action_class", "tool_name", "mcp_server", "destination"}
SUBJECT_BINDING_FIELDS = {
    "actor_user_id",
    "actor_role",
    "actor_department",
    "agent_id",
    "endpoint_id",
    "source_surface",
    "application",
    "ai_system_id",
    "provider",
    "model",
    "environment",
    "business_purpose",
}


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _tree_fields(node: Mapping[str, Any]) -> set[str]:
    if "field" in node:
        return {str(node["field"])}
    if "not" in node and isinstance(node["not"], Mapping):
        return _tree_fields(node["not"])
    fields: set[str] = set()
    for key in ("all", "any"):
        children = node.get(key)
        if isinstance(children, list):
            for child in children:
                if isinstance(child, Mapping):
                    fields.update(_tree_fields(child))
    return fields


def _normalize_exception_scope(scope: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(scope, dict) or set(scope) != {"condition_tree"}:
        raise ValueError("maturity_exception_scope_must_contain_only_condition_tree")
    tree = normalize_condition_tree(scope.get("condition_tree"))
    fields = _tree_fields(tree)
    if not fields.intersection(ACTION_BINDING_FIELDS):
        raise ValueError("maturity_exception_requires_action_binding")
    if not fields.intersection(SUBJECT_BINDING_FIELDS):
        raise ValueError("maturity_exception_requires_subject_or_context_binding")
    return {"condition_tree": tree}


def exception_is_active(exception: MaturityPolicyException, *, now: datetime | None = None) -> bool:
    current = _utc(now or datetime.now(timezone.utc))
    expiry = _utc(exception.expires_at)
    return exception.status == "APPROVED" and expiry > current


def create_policy_exception(
    db: Session,
    *,
    tenant_id: str,
    rollout_id: str,
    policy_version_id: str,
    scope: dict[str, Any],
    reason: str,
    requested_by_ref: str,
    approved_by_ref: str,
    expires_at: datetime,
    now: datetime | None = None,
) -> MaturityPolicyException:
    """Create a narrow, administrator-approved exception record.

    Callers must later bind any active exception at the existing policy
    resolution seam.  This service deliberately creates no bypass channel and
    never changes a policy version in place.
    """

    require_maturity_capability(db, tenant_id=tenant_id, capability="approval_workflow")
    rollout = db.scalar(
        select(MaturityPolicyRollout).where(
            MaturityPolicyRollout.tenant_id == tenant_id,
            MaturityPolicyRollout.id == rollout_id,
        )
    )
    if rollout is None:
        raise ValueError("maturity_exception_rollout_not_found")
    if not policy_version_id or policy_version_id != rollout.policy_version_id:
        raise ValueError("maturity_exception_policy_version_mismatch")
    if str(rollout.state or "").upper() not in {"SHADOW", "ENFORCE", "MONITOR"}:
        raise ValueError("maturity_exception_requires_active_rollout")
    normalized_scope = _normalize_exception_scope(scope)
    message = str(reason or "").strip()
    requester = str(requested_by_ref or "").strip()
    approver = str(approved_by_ref or "").strip()
    if len(message) < 3 or len(message) > 2_000 or not requester or not approver:
        raise ValueError("maturity_exception_invalid_request")
    current = _utc(now or datetime.now(timezone.utc))
    expiry = _utc(expires_at)
    if expiry <= current or expiry > current + MAX_EXCEPTION_LIFETIME:
        raise ValueError("maturity_exception_expiry_out_of_bounds")

    row = MaturityPolicyException(
        tenant_id=tenant_id,
        rollout_id=rollout.id,
        policy_version_id=policy_version_id,
        scope=normalized_scope,
        reason=message,
        status="APPROVED",
        requested_by_ref=requester,
        approved_by_ref=approver,
        expires_at=expiry,
    )
    db.add(row)
    db.flush()
    row.audit_ref = f"maturity_policy_exception:{row.id}"
    db.flush()
    return row


def find_matching_active_policy_exception(
    db: Session,
    *,
    tenant_id: str,
    policy_version_id: str,
    context: dict[str, Any],
    now: datetime | None = None,
) -> MaturityPolicyException | None:
    """Return the single narrow exception matching exact evaluated context.

    This uses the same bounded condition interpreter as policy scopes. It is
    deliberately callable only from the existing policy-resolution seam; it is
    not a parallel exception evaluator or a general bypass mechanism.
    """

    current = _utc(now or datetime.now(timezone.utc))
    rows = db.scalars(
        select(MaturityPolicyException)
        .join(
            MaturityPolicyRollout,
            (MaturityPolicyRollout.tenant_id == MaturityPolicyException.tenant_id)
            & (MaturityPolicyRollout.id == MaturityPolicyException.rollout_id),
        )
        .where(
            MaturityPolicyException.tenant_id == tenant_id,
            MaturityPolicyException.policy_version_id == policy_version_id,
            MaturityPolicyException.status == "APPROVED",
            MaturityPolicyException.expires_at > current,
            MaturityPolicyRollout.state.in_(("SHADOW", "ENFORCE", "MONITOR")),
        )
        .order_by(MaturityPolicyException.expires_at.asc(), MaturityPolicyException.id.asc())
    ).all()
    for row in rows:
        scope = row.scope if isinstance(row.scope, dict) else {}
        tree = scope.get("condition_tree")
        try:
            if tree is not None and evaluate_condition_tree(tree, context).matched:
                return row
        except ValueError:
            # A malformed persisted record never becomes an allow.
            continue
    return None
