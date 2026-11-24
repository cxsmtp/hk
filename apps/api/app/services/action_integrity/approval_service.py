"""Transactional, router-independent V2 approval authority."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.action_integrity import ApprovalAuthorityEventV2, ApprovalAuthorityProjectionV2, ApprovalBindingV2Extension
from app.db.models.policy import ApprovalRequest
from app.services.audit_service import write_audit_log

from .approval_binding import issue_exact_approval_binding
from .canonical_v2 import canonical_action_hash_v2, domain_hash
from .signing import SigningKeyProvider, active_key_id, sign_object


APPROVAL_EVENT_DOMAIN = "hawk:approval-decision-event:v2"


class ApprovalRequestExpiredError(ValueError):
    """A terminal timeout whose fail-closed state must be committed by the caller."""


@dataclass(frozen=True, slots=True)
class ApprovalDecisionResult:
    result: str
    approval_request_id: str
    binding_id: str | None
    binding_hash: str | None = None
    idempotency_key: str | None = None
    profile_selection_id: str | None = None
    profile_selection_hash: str | None = None
    control_selection_id: str | None = None
    control_plan_id: str | None = None


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _body_hash(dto: Any) -> str:
    return domain_hash(
        "hawk:approval-decision-request:v2",
        {
            "schema_version": str(getattr(dto, "schema_version", "2.0")),
            "decision": str(getattr(dto, "decision", "")),
            "expected_version": int(getattr(dto, "expected_version", 0)),
            "idempotency_key": str(getattr(dto, "idempotency_key", "")),
            "reason": getattr(dto, "reason", None),
        },
    )


def _require_v2_current_request(
    db: Session,
    request: ApprovalRequest,
    *,
    provider: SigningKeyProvider,
    tenant_id: str,
    now: datetime,
) -> Mapping[str, Any]:
    payload = request.request_payload
    if request.authority_schema_version != "2.0" or not isinstance(payload, Mapping):
        raise ValueError("approval request is not a V2 request")
    action = payload.get("canonical_action")
    if not isinstance(action, Mapping) or action.get("tenant_id") != tenant_id:
        raise ValueError("approval request does not have a tenant-bound canonical action")
    if int(action.get("policy_epoch") or 0) <= 0 or not action.get("control_plan_digest"):
        raise ValueError("approval request has stale or incomplete authority material")
    if str(request.default_if_timeout).lower() not in {"deny", "block"}:
        raise ValueError("consequential V2 request must fail closed on timeout")
    decision_receipt_id = str(payload.get("decision_receipt_id") or "")
    selection_id = str(payload.get("profile_selection_id") or "")
    selection_hash = str(payload.get("profile_selection_hash") or "")
    control_selection_id = str(payload.get("control_selection_id") or "")
    if not decision_receipt_id or not selection_id or len(selection_hash) != 64 or not control_selection_id:
        raise ValueError("approval request lacks complete stored authority bindings")
    if request.decision_receipt_id != decision_receipt_id:
        raise ValueError("approval request decision receipt does not match its signed payload")
    from .stored_authority import require_current_decision_authority_v1

    try:
        decision, authority = require_current_decision_authority_v1(
            db,
            provider=provider,
            tenant_id=tenant_id,
            decision_receipt_id=decision_receipt_id,
            action=action,
            now=now,
        )
    except PermissionError as exc:
        raise ValueError("approval request stored authority is not current") from exc
    if (
        decision.authoritative_decision.upper() != "REQUIRE_APPROVAL"
        or decision.receipt_id != decision_receipt_id
        or decision.profile_selection_id != selection_id
        or decision.profile_selection_hash != selection_hash
        or decision.control_selection_id != control_selection_id
        or authority.native_selection.control_plan_id != action.get("control_plan_id")
    ):
        raise ValueError("approval request native control plan is not current")
    return payload


def _normalized_roles(request: ApprovalRequest) -> set[str]:
    if not isinstance(request.required_roles, list):
        return set()
    return {str(role).strip().lower() for role in request.required_roles if str(role).strip()}


def _event_envelope(
    provider: SigningKeyProvider,
    *,
    tenant_id: str,
    request: ApprovalRequest,
    binding_id: str | None,
    decision: str,
    body_hash: str,
    idempotency_key: str,
    reason_code: str | None,
    observed_at: datetime,
) -> dict[str, Any]:
    key_id = active_key_id(provider, purpose="approval_binding_signing", tenant_id=tenant_id)
    return sign_object(
        provider,
        purpose="approval_binding_signing",
        domain=APPROVAL_EVENT_DOMAIN,
        tenant_id=tenant_id,
        key_id=key_id,
        value={
            "schema_version": "1.0",
            "event_id": "",  # the persisted event ID is signed after allocation below
            "tenant_id": tenant_id,
            "approval_binding_id": binding_id,
            "approval_request_id": request.id,
            "sequence": 1,
            "event_type": "DECIDED",
            "decision": decision,
            "request_version": request.decision_version + 1,
            "body_hash": body_hash,
            "prior_event_id": None,
            "prior_event_hash": None,
            "idempotency_key": idempotency_key,
            "reason_code": reason_code,
            "observed_at": observed_at.isoformat(),
        },
    )


def decide_approval_request_v2(
    db: Session,
    *,
    tenant_id: str,
    approval_request_id: str,
    actor: Any,
    dto: Any,
    signing_provider: SigningKeyProvider,
    now: datetime | None = None,
) -> ApprovalDecisionResult:
    """Apply or deterministically replay one signed V2 approval decision.

    The caller owns the surrounding transaction.  The request row is locked,
    then its event, immutable binding (on approval), projection, and audit row
    are inserted in that same transaction.  Nothing is committed here.
    """
    decision_now = _utc(now or datetime.now(timezone.utc))
    request = db.scalar(
        select(ApprovalRequest)
        .where(ApprovalRequest.tenant_id == tenant_id, ApprovalRequest.id == approval_request_id)
        .with_for_update()
    )
    if request is None:
        raise LookupError("approval request not found")
    if getattr(dto, "decision", None) not in {"approve", "deny"} or int(getattr(dto, "expected_version", 0)) <= 0:
        raise ValueError("invalid V2 approval decision")
    idempotency_key = str(getattr(dto, "idempotency_key", ""))
    if not (16 <= len(idempotency_key) <= 128):
        raise ValueError("invalid approval idempotency key")
    body_hash = _body_hash(dto)
    payload = _require_v2_current_request(
        db,
        request,
        provider=signing_provider,
        tenant_id=tenant_id,
        now=decision_now,
    )
    role = str(getattr(actor, "role", "")).strip().lower()
    if not role or role not in _normalized_roles(request):
        raise PermissionError("actor role is not authorized for this approval")
    actor_id = getattr(actor, "id", None)
    if not actor_id:
        raise PermissionError("authenticated approver identity is required")
    action = payload["canonical_action"]
    prior = db.scalar(
        select(ApprovalAuthorityEventV2)
        .where(
            ApprovalAuthorityEventV2.tenant_id == tenant_id,
            ApprovalAuthorityEventV2.approval_request_id == approval_request_id,
            ApprovalAuthorityEventV2.idempotency_key == idempotency_key,
        )
        .with_for_update()
    )
    if prior is not None:
        # An idempotency record is scoped to its tenant/request and is only a
        # replay of the *current* decision. It never bypasses live role, actor,
        # request status, or optimistic-version checks above.
        expected_status = "approved" if prior.decision == "approve" else "denied"
        if prior.body_hash != body_hash:
            raise ValueError("approval idempotency key conflicts with the original decision")
        if (
            prior.request_version != int(dto.expected_version) + 1
            or request.status != expected_status
            or request.decision != prior.decision
            or request.decision_version != prior.request_version
            or request.decided_by != str(actor_id)
        ):
            raise ValueError("approval replay is no longer current or authorized")
        binding = db.scalar(
            select(ApprovalBindingV2Extension).where(
                ApprovalBindingV2Extension.tenant_id == tenant_id,
                ApprovalBindingV2Extension.approval_request_id == approval_request_id,
            )
        )
        return ApprovalDecisionResult(
            "REPLAYED", request.id, prior.binding_id, binding.binding_hash if binding else None, idempotency_key,
            str(payload.get("profile_selection_id") or "") or None,
            str(payload.get("profile_selection_hash") or "") or None,
            str(payload.get("control_selection_id") or "") or None,
            str(action.get("control_plan_id") or "") or None,
        )

    if request.status != "pending":
        raise ValueError("approval request is not pending")
    if request.decision_version != int(dto.expected_version):
        raise ValueError("stale approval decision version")
    deadline = _utc(request.created_at) + timedelta(minutes=int(request.sla_minutes))
    if decision_now >= deadline:
        request.status = "expired"
        request.decision_version += 1
        request.decided_at = decision_now
        # This is an intentional terminal mutation, not a rejected decision.
        # The HTTP adapter commits it before returning the conflict response.
        raise ApprovalRequestExpiredError("approval request expired")

    binding_row: ApprovalBindingV2Extension | None = None
    binding_id: str | None = None
    binding_hash: str | None = None
    decision = str(dto.decision)
    if decision == "approve":
        issued = issue_exact_approval_binding(
            signing_provider,
            tenant_id=tenant_id,
            approval_request_id=request.id,
            action=action,
            request_payload=payload,
            approver_principal_ref=str(actor_id),
            approver_role=role,
            issued_at=decision_now,
            expires_at=deadline,
            use_limit=int(payload.get("use_limit", 1)),
        )
        binding_id = str(issued.binding["approval_binding_id"])
        binding_hash = issued.binding_hash
        binding_row = ApprovalBindingV2Extension(
            approval_request_id=request.id,
            tenant_id=tenant_id,
            authority_binding_version=1,
            decision_receipt_id=str(issued.binding["decision_receipt_id"]),
            binding_id=binding_id,
            canonical_action_hash=str(issued.binding["canonical_action_hash"]),
            material_fields_hash=str(issued.binding["material_fields_hash"]),
            profile_selection_id=str(issued.binding["profile_selection_id"]),
            profile_selection_hash=str(issued.binding["profile_selection_hash"]),
            control_selection_id=str(issued.binding["control_selection_id"]),
            control_plan_digest=str(issued.binding["control_plan_digest"]),
            policy_epoch=int(issued.binding["policy_epoch"]),
            use_limit=int(issued.binding["use_limit"]),
            expires_at=deadline,
            permitted_variation_envelope_id=str(issued.variation["envelope_id"]),
            permitted_variation_hash=issued.variation_hash,
            permitted_variation_envelope=issued.variation,
            trusted_approval_rendering_hash=str(issued.binding["trusted_approval_rendering_hash"]),
            decision_idempotency_key=idempotency_key,
            binding_hash=binding_hash,
            signed_envelope=issued.binding,
            algorithm=str(issued.binding["algorithm"]),
            signing_key_id=str(issued.binding["signing_key_id"]),
            signature=str(issued.binding["signature"]),
        )
        db.add(binding_row)

    event = _event_envelope(
        signing_provider,
        tenant_id=tenant_id,
        request=request,
        binding_id=binding_id,
        decision=decision,
        body_hash=body_hash,
        idempotency_key=idempotency_key,
        reason_code=getattr(dto, "reason", None),
        observed_at=decision_now,
    )
    event_id = str(uuid4())
    # Allocate an ID before signature: the event ID is immutable signed material.
    event["event_id"] = event_id
    key_id = str(event["signing_key_id"])
    event = sign_object(
        signing_provider,
        purpose="approval_binding_signing",
        domain=APPROVAL_EVENT_DOMAIN,
        tenant_id=tenant_id,
        key_id=key_id,
        value={key: value for key, value in event.items() if key not in {"algorithm", "signing_key_id", "signature"}},
    )
    db.add(
        ApprovalAuthorityEventV2(
            id=event_id,
            tenant_id=tenant_id,
            approval_request_id=request.id,
            binding_id=binding_id,
            sequence=1,
            event_type="DECIDED",
            decision=decision,
            request_version=request.decision_version + 1,
            body_hash=body_hash,
            prior_event_id=None,
            prior_event_hash=None,
            idempotency_key=idempotency_key,
            reason_code=getattr(dto, "reason", None),
            observed_at=decision_now,
            algorithm=str(event["algorithm"]),
            signing_key_id=str(event["signing_key_id"]),
            signature=str(event["signature"]),
            signed_envelope=event,
        )
    )
    db.add(
        ApprovalAuthorityProjectionV2(
            tenant_id=tenant_id,
            approval_request_id=request.id,
            state="APPROVED" if decision == "approve" else "DENIED",
            uses_consumed=0,
            state_version=0,
            reconstruction_status="VERIFIED",
            history_head_event_id=event_id,
            history_head_event_hash=domain_hash("hawk:approval-authority-event-envelope-hash:v1", event),
            history_head_sequence=1,
        )
    )
    request.status = "approved" if decision == "approve" else "denied"
    request.decision = decision
    request.decision_version += 1
    request.decided_at = decision_now
    request.decided_by = str(actor_id)
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=str(actor_id),
        actor_type="human",
        action="approval.decision.v2",
        resource_type="approval_request",
        resource_id=request.id,
        payload={"decision": decision, "binding_id": binding_id, "idempotency_key": idempotency_key},
    )
    return ApprovalDecisionResult(
        "APPLIED", request.id, binding_id, binding_hash, idempotency_key,
        str(payload.get("profile_selection_id") or "") or None,
        str(payload.get("profile_selection_hash") or "") or None,
        str(payload.get("control_selection_id") or "") or None,
        str(action.get("control_plan_id") or "") or None,
    )
