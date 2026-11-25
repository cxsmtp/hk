from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.enforcement import EnforcementEvent
from app.db.models.policy import ApprovalRequest
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.action_integrity.approval_service import ApprovalRequestExpiredError, decide_approval_request_v2
from app.services.action_integrity.signing import KmsHsmSigningKeyProvider


router = APIRouter(prefix="/enforcement", tags=["enforcement"])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ApprovalDecisionRequest(BaseModel):
    decision: str  # approve | deny


class ApprovalDecisionRequestV2(BaseModel):
    schema_version: str = Field(pattern="^2\\.0$")
    decision: Literal["approve", "deny"]
    expected_version: int = Field(gt=0)
    idempotency_key: str = Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    reason: str | None = Field(default=None, max_length=128)


class ApprovalDecisionResponseV2(BaseModel):
    schema_version: Literal["2.0"] = "2.0"
    result: Literal["APPLIED", "REPLAYED"]
    idempotency_key: str
    approval_request_id: str
    approval_binding_id: str | None
    approval_binding_hash: str | None
    profile_selection_id: str | None
    profile_selection_hash: str | None
    control_selection_id: str | None
    control_plan_id: str | None


class ReversibleMaskingFactsResponse(BaseModel):
    enabled: bool
    applied: bool
    restored: bool
    entity_type_counts: dict[str, int]
    mapping_destroyed: bool


class EnforcementEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    ai_system_id: str
    actor_type: str
    actor_id: str
    request_id: str
    timestamp: datetime
    correlation_id: str | None = None
    final_decision: str
    policy_version_id: str | None = None
    evidence_nodes_created: list
    controls_impacted: list
    provider: str | None = None
    model: str | None = None
    model_version: str | None = None
    prompt_hash: str | None = None
    response_hash: str | None = None
    governance_version: str | None = None
    api_endpoint: str | None = None
    tool_name: str | None = None
    tool_category: str | None = None
    data_source: str | None = None
    chain_depth: int | None = None
    document_format: Literal["pdf", "docx"] | None = None
    document_block_count: int | None = None
    reversible_masking: ReversibleMaskingFactsResponse | None = None


class ApprovalRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    enforcement_event_id: str | None = None
    ai_system_id: str
    request_payload: dict
    required_roles: list
    sla_minutes: int
    default_if_timeout: str
    status: str
    decided_by: str | None = None
    decided_at: datetime | None = None
    decision: str | None = None
    created_at: datetime
    updated_at: datetime


@router.get("/events", response_model=ListEnvelope[EnforcementEventResponse])
def list_events(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_permission("policies.review")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(
        select(EnforcementEvent).where(EnforcementEvent.tenant_id == ctx.tenant.id).order_by(EnforcementEvent.timestamp.desc())
    ).all()
    dto_rows = [_event_response(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[EnforcementEventResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


def _event_response(row: EnforcementEvent) -> EnforcementEventResponse:
    actions = dict(row.final_actions or {}) if isinstance(row.final_actions, dict) else {}
    trace = dict(actions.get("_trace") or {}) if isinstance(actions.get("_trace"), dict) else {}
    meta = dict(actions.get("_meta") or {}) if isinstance(actions.get("_meta"), dict) else {}
    mcp = dict(actions.get("mcp") or {}) if isinstance(actions.get("mcp"), dict) else {}
    document = dict(actions.get("document") or {}) if isinstance(actions.get("document"), dict) else {}
    trace_masking = trace.get("reversible_masking") if isinstance(trace.get("reversible_masking"), dict) else None
    masking_facts = None
    if trace_masking is not None:
        counts = trace_masking.get("entity_type_counts")
        masking_facts = {
            "enabled": bool(trace_masking.get("enabled")),
            "applied": bool(trace_masking.get("applied")),
            "restored": bool(trace_masking.get("restored")),
            "entity_type_counts": {
                str(kind): int(count)
                for kind, count in counts.items()
                if isinstance(kind, str) and isinstance(count, int) and not isinstance(count, bool)
            } if isinstance(counts, dict) else {},
            "mapping_destroyed": bool(trace_masking.get("mapping_destroyed")),
        }

    chain_depth = trace.get("chain_depth")
    if chain_depth is None:
        chain_depth = mcp.get("chain_depth")
    if chain_depth is None:
        chain_depth = meta.get("chain_depth")
    parsed_chain_depth = None
    if isinstance(chain_depth, int):
        parsed_chain_depth = chain_depth
    elif isinstance(chain_depth, str) and chain_depth.strip().isdigit():
        parsed_chain_depth = int(chain_depth.strip())

    return EnforcementEventResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        ai_system_id=row.ai_system_id,
        actor_type=row.actor_type,
        actor_id=row.actor_id,
        request_id=row.request_id,
        timestamp=row.timestamp,
        correlation_id=row.correlation_id,
        final_decision=row.final_decision,
        policy_version_id=row.policy_version_id,
        evidence_nodes_created=list(row.evidence_nodes_created or []),
        controls_impacted=list(row.controls_impacted or []),
        provider=(
            str(trace.get("provider") or meta.get("provider") or "").strip() or None
        ),
        model=(
            str(trace.get("model") or meta.get("model_name") or "").strip() or None
        ),
        model_version=(
            str(trace.get("model_version") or meta.get("model_version") or "").strip() or None
        ),
        prompt_hash=(
            str(trace.get("prompt_hash") or meta.get("prompt_hash") or "").strip() or None
        ),
        response_hash=(
            str(trace.get("response_hash") or meta.get("response_hash") or "").strip() or None
        ),
        governance_version=(
            str(trace.get("governance_version") or meta.get("governance_version") or "").strip() or None
        ),
        api_endpoint=(
            str(trace.get("api_endpoint") or mcp.get("api_endpoint") or meta.get("api_endpoint") or "").strip() or None
        ),
        tool_name=(
            str(trace.get("tool_name") or mcp.get("tool_name") or mcp.get("action") or meta.get("tool_name") or "").strip() or None
        ),
        tool_category=(
            str(trace.get("tool_category") or mcp.get("tool_category") or meta.get("tool_category") or "").strip() or None
        ),
        data_source=(
            str(trace.get("data_source") or mcp.get("data_source") or meta.get("data_source") or "").strip() or None
        ),
        chain_depth=parsed_chain_depth,
        document_format=(document.get("format") if document.get("format") in {"pdf", "docx"} else None),
        document_block_count=(document.get("block_count") if isinstance(document.get("block_count"), int) and 0 <= document["block_count"] <= 1000 else None),
        reversible_masking=masking_facts,
    )


@router.get("/approvals", response_model=ListEnvelope[ApprovalRequestResponse])
def list_approvals(
    status_filter: str = "pending",
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_permission("policies.review")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(
        select(ApprovalRequest)
        .where(ApprovalRequest.tenant_id == ctx.tenant.id, ApprovalRequest.status == status_filter)
        .order_by(ApprovalRequest.created_at.desc())
    ).all()
    dto_rows = [ApprovalRequestResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[ApprovalRequestResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.post("/approvals/{approval_id}/decision", response_model=ApprovalRequestResponse | ApprovalDecisionResponseV2)
def decide_approval(
    approval_id: str,
    payload: ApprovalDecisionRequestV2 | ApprovalDecisionRequest,
    # A V2 decision endpoint is an approver surface; viewers/auditors cannot
    # reach the replay path before the request-specific role check below.
    ctx: TenantContext = Depends(require_permission("policies.operate")),
    db: Session = Depends(get_db),
):
    if payload.decision not in {"approve", "deny"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="decision must be approve|deny")

    req = db.scalar(
        select(ApprovalRequest).where(ApprovalRequest.id == approval_id, ApprovalRequest.tenant_id == ctx.tenant.id)
    )
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval request not found")

    is_v2_request = req.authority_schema_version == "2.0"
    is_v2_payload = isinstance(payload, ApprovalDecisionRequestV2)
    if is_v2_request != is_v2_payload:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="approval decision body does not match stored request schema")
    if is_v2_request:
        provider = db.info.get("phase5_signing_provider") if isinstance(db.info, dict) else None
        provider = provider or KmsHsmSigningKeyProvider()
        try:
            result = decide_approval_request_v2(
                db,
                tenant_id=ctx.tenant.id,
                approval_request_id=approval_id,
                actor=type("Actor", (), {"id": getattr(getattr(ctx, "user", None), "id", None), "role": ctx.role})(),
                dto=payload,
                signing_provider=provider,
            )
            db.commit()
        except LookupError as exc:
            db.rollback()
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval request not found") from exc
        except PermissionError as exc:
            db.rollback()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except ApprovalRequestExpiredError as exc:
            # SLA expiry is a terminal fail-closed decision.  Preserve the
            # durable state instead of rolling it back with a rejected input.
            db.commit()
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        except ValueError as exc:
            # A production request without a configured opaque ES256/EdDSA
            # provider is an availability failure, never a local-HMAC fallback.
            db.rollback()
            detail = str(exc)
            code = status.HTTP_503_SERVICE_UNAVAILABLE if "KMS/HSM" in detail or "signing" in detail else status.HTTP_409_CONFLICT
            raise HTTPException(status_code=code, detail=detail) from exc
        return ApprovalDecisionResponseV2(
            result=result.result,
            idempotency_key=str(result.idempotency_key or payload.idempotency_key),
            approval_request_id=result.approval_request_id,
            approval_binding_id=result.binding_id,
            approval_binding_hash=result.binding_hash,
            profile_selection_id=result.profile_selection_id,
            profile_selection_hash=result.profile_selection_hash,
            control_selection_id=result.control_selection_id,
            control_plan_id=result.control_plan_id,
        )

    known_roles = {"viewer", "operator", "auditor", "admin", "owner"}
    raw_required_roles = req.required_roles
    if not isinstance(raw_required_roles, list):
        normalized_required_roles: set[str] = set()
    else:
        normalized_required_roles = {
            str(role).strip().lower()
            for role in raw_required_roles
            if isinstance(role, str) and str(role).strip()
        }
    normalized_ctx_role = str(ctx.role or "").strip().lower()
    if (
        not normalized_required_roles
        or not normalized_required_roles.issubset(known_roles)
        or normalized_ctx_role not in normalized_required_roles
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Role is not authorized for this approval")

    created_at = req.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    else:
        created_at = created_at.astimezone(timezone.utc)
    approval_deadline = created_at + timedelta(minutes=int(req.sla_minutes))
    decision_now = _utcnow()
    if decision_now >= approval_deadline:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Approval request expired outside its SLA")

    authenticated_user = getattr(ctx, "user", None)
    authenticated_user_id = getattr(authenticated_user, "id", None)
    decided_at = decision_now
    next_status = "approved" if payload.decision == "approve" else "denied"
    transition = db.execute(
        update(ApprovalRequest)
        .where(
            ApprovalRequest.id == approval_id,
            ApprovalRequest.tenant_id == ctx.tenant.id,
            ApprovalRequest.status == "pending",
        )
        .values(
            status=next_status,
            decision=payload.decision,
            decided_at=decided_at,
            decided_by=authenticated_user_id,
        )
        .execution_options(synchronize_session=False)
    )
    if transition.rowcount != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Approval request is no longer pending",
        )
    if _utcnow() >= approval_deadline:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Approval request expired during decision")
    db.flush()
    db.refresh(req)

    if req.enforcement_event_id:
        event = db.scalar(
            select(EnforcementEvent).where(
                EnforcementEvent.id == req.enforcement_event_id,
                EnforcementEvent.tenant_id == ctx.tenant.id,
            )
        )
        if event:
            event.final_decision = "allow" if payload.decision == "approve" else "block"
            actions = event.final_actions or {}
            actions["approval_decision"] = payload.decision
            event.final_actions = actions

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=authenticated_user_id,
        actor_type="human",
        action="approval.decision",
        resource_type="approval_request",
        resource_id=req.id,
        payload={"decision": payload.decision},
    )

    db.commit()
    db.refresh(req)
    return ApprovalRequestResponse.model_validate(req)
