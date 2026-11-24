from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.auth import get_current_user
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.agui import AGUIDecision
from app.db.models.ai_iam import AgentIdentity, CapabilityToken
from app.db.models.ai_system import AISystem
from app.db.models.discovery import DiscoveryApplication
from app.db.models.finding import Finding
from app.db.models.maturity import ControlConflict
from app.db.models.policy import PolicyVersion
from app.db.models.simulation import SimulationDefinition, SimulationRun
from app.db.models.snapshot import AuditorSnapshot
from app.db.models.user import User
from app.db.session import get_db
from app.services.agui.context import AGUIExecutionContext
from app.services.agui.registry import get_agui_registry


router = APIRouter(prefix="/agui", tags=["agui"])


RUNTIME_SOURCE_MARKERS = {"runtime", "__runtime__", "*", "unknown", ""}


class AGUIActionResponse(BaseModel):
    action_id: str
    action_type: str
    title: str
    description: str
    source_module: str
    source_object_type: str
    source_object_id: str
    required_role: list[str]
    decision_options: list[str]
    requires_justification: bool
    requires_evidence_display: bool
    requires_diff_preview: bool
    side_effect_level: str
    created_at: datetime
    source_summary: str
    proof_timeline_url: str | None = None


class AGUIActionDecisionRequest(BaseModel):
    decision: str = Field(min_length=1)
    justification: str | None = None
    evidence_node_ids: list[str] = Field(default_factory=list)
    decision_payload: dict[str, Any] = Field(default_factory=dict)
    source_module: str | None = None
    source_object_type: str | None = None
    source_object_id: str | None = None
    evidence_displayed: bool = False
    diff_preview_displayed: bool = False


class AGUIDecisionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    decision_id: str
    action_id: str
    decision: str
    justification: str | None = None
    decided_by: str | None = None
    decided_at: datetime
    correlation_id: str | None = None
    evidence_node_ids: list[str]
    audit_log_id: str
    source_module: str
    source_object_type: str
    source_object_id: str
    source_summary: str
    proof_timeline_url: str | None = None


def _clean(value: str | None) -> str:
    return str(value or "").strip()


def _proof_timeline_url(source_object_type: str, source_object_id: str) -> str | None:
    object_type = _clean(source_object_type).lower()
    object_id = _clean(source_object_id)
    if object_type in {"finding", "findings"}:
        if object_id and object_id.lower() not in RUNTIME_SOURCE_MARKERS:
            return f"/discovery/findings/{object_id}"
        return "/discovery/findings"
    if object_type in {"discovery_application", "application"}:
        return "/discovery/applications"
    if object_type in {"control_conflict", "conflict"}:
        return "/auditor/conflicts"
    if object_type in {"policy_version", "policy"}:
        return "/policies"
    if object_type in {"ai_system", "governance_application"}:
        return "/governance"
    if object_type in {"simulation_run", "simulation_definition", "simulation"}:
        return "/simulations"
    if object_type in {"agent_identity", "capability_token", "agent"}:
        return "/ai-iam"
    if object_type in {"auditor_snapshot", "snapshot"}:
        return "/auditor"
    return "/dashboard"


def _source_summary(
    db: Session,
    *,
    tenant_id: str,
    source_object_type: str,
    source_object_id: str,
) -> str:
    source_type = _clean(source_object_type).lower()
    source_id = _clean(source_object_id)
    if source_id.lower() in RUNTIME_SOURCE_MARKERS:
        return "Runtime source object. Provide source_object_id in decision payload for concrete traceability."

    if source_type in {"finding", "findings"}:
        row = db.scalar(
            select(Finding).where(
                Finding.tenant_id == tenant_id,
                Finding.finding_id == source_id,
            )
        )
        if row:
            return (
                f"Finding {row.finding_id}: severity={row.severity}, status={row.status}, "
                f"tool={row.ai_tool}, risk_category={row.risk_category}"
            )

    if source_type in {"discovery_application", "application"}:
        row = db.scalar(
            select(DiscoveryApplication).where(
                DiscoveryApplication.tenant_id == tenant_id,
                DiscoveryApplication.id == source_id,
            )
        )
        if row:
            return (
                f"Discovery app {row.tool_name} ({row.vendor}): status={row.status}, "
                f"risk_tier={row.provisional_risk_tier or '-'}"
            )

    if source_type in {"ai_system", "governance_application"}:
        row = db.scalar(
            select(AISystem).where(
                AISystem.tenant_id == tenant_id,
                AISystem.id == source_id,
            )
        )
        if row:
            return f"AI system {row.name}: risk_tier={row.risk_tier}, status={row.status}"

    if source_type in {"policy_version", "policy"}:
        row = db.scalar(
            select(PolicyVersion).where(
                PolicyVersion.tenant_id == tenant_id,
                PolicyVersion.id == source_id,
            )
        )
        if row:
            return f"Policy version {row.version} ({row.id})"

    if source_type in {"simulation_run"}:
        row = db.scalar(
            select(SimulationRun).where(
                SimulationRun.tenant_id == tenant_id,
                SimulationRun.id == source_id,
            )
        )
        if row:
            result = str((row.results or {}).get("result") or "-")
            return f"Simulation run {row.id}: mode={row.mode}, result={result}"

    if source_type in {"simulation_definition", "simulation"}:
        row = db.scalar(
            select(SimulationDefinition).where(
                SimulationDefinition.tenant_id == tenant_id,
                SimulationDefinition.id == source_id,
            )
        )
        if row:
            return f"Simulation definition {row.name} ({row.id})"

    if source_type in {"control_conflict", "conflict"}:
        row = db.scalar(
            select(ControlConflict).where(
                ControlConflict.tenant_id == tenant_id,
                ControlConflict.id == source_id,
            )
        )
        if row:
            return (
                f"Control conflict {row.id}: control={row.control_id}, status={row.status}, "
                f"signals(+/-)={row.positive_signals}/{row.negative_signals}"
            )

    if source_type in {"auditor_snapshot", "snapshot"}:
        row = db.scalar(
            select(AuditorSnapshot).where(
                AuditorSnapshot.tenant_id == tenant_id,
                AuditorSnapshot.id == source_id,
            )
        )
        if row:
            return f"Auditor snapshot {row.id}: trigger={row.trigger_type}, ai_system_id={row.ai_system_id or '-'}"

    if source_type in {"agent_identity", "agent"}:
        row = db.scalar(
            select(AgentIdentity).where(
                AgentIdentity.tenant_id == tenant_id,
                AgentIdentity.id == source_id,
            )
        )
        if row:
            return f"Agent identity {row.name}: status={row.status}, max_chain_depth={row.max_chain_depth}"

    if source_type in {"capability_token", "token"}:
        row = db.scalar(
            select(CapabilityToken).where(
                CapabilityToken.tenant_id == tenant_id,
                CapabilityToken.id == source_id,
            )
        )
        if row:
            return (
                f"Capability token {row.id}: agent_id={row.agent_identity_id}, "
                f"expires_at={row.expires_at.isoformat() if row.expires_at else '-'}"
            )

    return f"Source object '{source_id}' not found for type '{source_object_type}'."


def _action_to_response(db: Session, *, tenant_id: str, payload: dict[str, Any]) -> AGUIActionResponse:
    source_object_type = _clean(payload.get("source_object_type"))
    source_object_id = _clean(payload.get("source_object_id"))
    summary = _source_summary(
        db,
        tenant_id=tenant_id,
        source_object_type=source_object_type,
        source_object_id=source_object_id,
    )
    return AGUIActionResponse(
        action_id=_clean(payload.get("action_id")),
        action_type=_clean(payload.get("action_type")),
        title=_clean(payload.get("title")),
        description=_clean(payload.get("description")),
        source_module=_clean(payload.get("source_module")),
        source_object_type=source_object_type,
        source_object_id=source_object_id,
        required_role=[str(role) for role in (payload.get("required_role") or [])],
        decision_options=[str(option) for option in (payload.get("decision_options") or [])],
        requires_justification=bool(payload.get("requires_justification")),
        requires_evidence_display=bool(payload.get("requires_evidence_display")),
        requires_diff_preview=bool(payload.get("requires_diff_preview")),
        side_effect_level=_clean(payload.get("side_effect_level")),
        created_at=payload.get("created_at") or datetime.utcnow(),
        source_summary=summary,
        proof_timeline_url=_proof_timeline_url(source_object_type, source_object_id),
    )


def _decision_to_response(db: Session, *, tenant_id: str, row: AGUIDecision) -> AGUIDecisionResponse:
    source_object_type = _clean(row.source_object_type)
    source_object_id = _clean(row.source_object_id)
    return AGUIDecisionResponse(
        decision_id=row.decision_id,
        action_id=row.action_id,
        decision=row.decision,
        justification=row.justification,
        decided_by=row.decided_by,
        decided_at=row.decided_at,
        correlation_id=row.correlation_id,
        evidence_node_ids=[str(item) for item in (row.evidence_node_ids or [])],
        audit_log_id=row.audit_log_id,
        source_module=row.source_module,
        source_object_type=source_object_type,
        source_object_id=source_object_id,
        source_summary=_source_summary(
            db,
            tenant_id=tenant_id,
            source_object_type=source_object_type,
            source_object_id=source_object_id,
        ),
        proof_timeline_url=_proof_timeline_url(source_object_type, source_object_id),
    )


@router.get("/actions", response_model=ListEnvelope[AGUIActionResponse])
def list_actions(
    source_module: str | None = None,
    action_prefix: str | None = None,
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    rows = get_agui_registry().list_actions()
    if source_module:
        module = _clean(source_module).lower()
        rows = [row for row in rows if _clean(row.get("source_module")).lower() == module]
    if action_prefix:
        prefix = _clean(action_prefix).lower()
        rows = [row for row in rows if _clean(row.get("action_id")).lower().startswith(prefix)]

    dto_rows = [_action_to_response(db, tenant_id=ctx.tenant.id, payload=row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[AGUIActionResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/actions/{action_id}", response_model=AGUIActionResponse)
def get_action(
    action_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    registration = get_agui_registry().get_action(action_id)
    if registration is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AGUI action not found")
    payload = registration.contract.model_dump(mode="json")
    return _action_to_response(db, tenant_id=ctx.tenant.id, payload=payload)


@router.get("/decisions", response_model=ListEnvelope[AGUIDecisionResponse])
def list_decisions(
    action_id: str | None = None,
    source_module: str | None = None,
    source_object_type: str | None = None,
    source_object_id: str | None = None,
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    query = select(AGUIDecision).where(AGUIDecision.tenant_id == ctx.tenant.id)
    if action_id:
        query = query.where(AGUIDecision.action_id == _clean(action_id))
    if source_module:
        query = query.where(AGUIDecision.source_module == _clean(source_module))
    if source_object_type:
        query = query.where(AGUIDecision.source_object_type == _clean(source_object_type))
    if source_object_id:
        query = query.where(AGUIDecision.source_object_id == _clean(source_object_id))

    rows = db.scalars(query.order_by(AGUIDecision.decided_at.desc())).all()
    dto_rows = [_decision_to_response(db, tenant_id=ctx.tenant.id, row=row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[AGUIDecisionResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.post("/actions/{action_id}/decide", response_model=AGUIDecisionResponse)
def decide_action(
    action_id: str,
    payload: AGUIActionDecisionRequest,
    request: Request,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    registry = get_agui_registry()
    if registry.get_action(action_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AGUI action not found")

    decision_payload = dict(payload.decision_payload or {})
    if payload.source_module:
        decision_payload["source_module"] = _clean(payload.source_module)
    if payload.source_object_type:
        decision_payload["source_object_type"] = _clean(payload.source_object_type)
    if payload.source_object_id:
        decision_payload["source_object_id"] = _clean(payload.source_object_id)

    correlation_id = getattr(request.state, "correlation_id", None)
    context = AGUIExecutionContext(
        tenant_id=ctx.tenant.id,
        user_id=current_user.id,
        user_role=ctx.role,
        correlation_id=correlation_id,
        evidence_displayed=payload.evidence_displayed,
        diff_preview_displayed=payload.diff_preview_displayed,
    )

    try:
        decision_record = registry.execute_decision(
            db=db,
            context=context,
            action_id=action_id,
            decision=payload.decision,
            justification=payload.justification,
            evidence_node_ids=payload.evidence_node_ids,
            decision_payload=decision_payload,
        )
        db.commit()
    except PermissionError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    decision_row = db.scalar(
        select(AGUIDecision).where(
            AGUIDecision.tenant_id == ctx.tenant.id,
            AGUIDecision.decision_id == decision_record.decision_id,
        )
    )
    if decision_row is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="AGUI decision persisted row not found")
    return _decision_to_response(db, tenant_id=ctx.tenant.id, row=decision_row)
