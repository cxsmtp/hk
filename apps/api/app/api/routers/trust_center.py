from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.activity_audit import AISession
from app.db.models.ai_system import AISystem
from app.db.models.audit import AuditLog
from app.db.models.evidence import EvidenceEdge, EvidenceNode
from app.db.models.finding import Finding
from app.db.models.maturity import ControlMaturity
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.session import get_db
from app.services.maturity_service import get_maturity_score_explanation
from app.services.remediation import list_remediation_actions


router = APIRouter(prefix="/trust-center", tags=["trust-center"])


class EvidenceNodeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    node_type: str
    signal_type: str
    label: str
    payload: dict
    created_at: datetime
    updated_at: datetime


class EvidenceEdgeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    from_node_id: str
    to_node_id: str
    edge_type: str
    payload: dict
    created_at: datetime
    updated_at: datetime


class ControlMaturityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    ai_system_id: str
    control_id: str
    technical_enforcement_score: float
    simulation_pass_rate: float
    coverage_score: float
    maturity_score: float
    status: str
    confidence_score: float
    confidence_inputs: dict
    updated_at: datetime


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str | None = None
    actor_user_id: str | None = None
    actor_type: str
    action: str
    resource_type: str
    resource_id: str
    payload: dict
    created_at: datetime


class TrustCenterRemediationStateResponse(BaseModel):
    ai_system_id: str
    ai_system_status: str
    risk_tier: str
    lifecycle_state: str | None = None
    governance_state: str | None = None
    ownership_state: str | None = None
    business_owner: str | None = None
    technical_owner: str | None = None
    open_remediations: int
    applied_remediations: int
    failed_remediations: int
    latest_remediations: list[dict]
    remediation_logs: list[dict]


class TrustCenterAssetActivityResponse(BaseModel):
    event_id: str
    timestamp: datetime
    source_surface: str
    ai_surface: str
    action_type: str
    decision: str
    application: str | None = None
    user_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    ai_client: str | None = None
    mcp_server_id: str | None = None
    mcp_tool_id: str | None = None
    tool_name: str | None = None
    risk_score: float = 0.0
    finding_id: str | None = None
    correlation_id: str | None = None
    context_id: str | None = None
    chain_id: str | None = None


class TrustCenterAssetFindingResponse(BaseModel):
    finding_id: str
    severity: str
    status: str
    finding_type: str
    risk_category: str
    source_surface: str
    ai_tool: str
    ai_system_id: str | None = None
    user_id: str | None = None
    agent_id: str | None = None
    machine_id: str | None = None
    recommended_action: str
    related_event_ids: list[str]
    evidence_node_ids: list[str]
    last_seen_at: datetime | None = None
    created_at: datetime


class TrustCenterAssetSessionResponse(BaseModel):
    session_id: str
    start_time: datetime | None = None
    end_time: datetime | None = None
    event_count: int
    user_id: str | None = None
    agent_id: str | None = None
    ai_client: str | None = None
    mcp_server_id: str | None = None
    decisions: list[str]
    highest_risk_score: float


def _metadata_dict(value: Any) -> dict[str, Any]:
    return dict(value or {}) if isinstance(value, dict) else {}


def _metadata_str(metadata: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = metadata.get(key)
        if value is None:
            continue
        normalized = str(value).strip()
        if normalized:
            return normalized
    return None


def _metadata_list(metadata: dict[str, Any], *keys: str) -> list[str]:
    out: list[str] = []
    for key in keys:
        value = metadata.get(key)
        if not isinstance(value, list):
            continue
        for item in value:
            normalized = str(item).strip()
            if normalized and normalized not in out:
                out.append(normalized)
    return out


def _event_decision(row: RuntimeEvent) -> str:
    metadata = _metadata_dict(row.metadata_json)
    decision = str(metadata.get("decision") or metadata.get("final_decision") or "").strip().lower()
    if decision:
        return decision
    severity = str(row.severity or "").strip().lower()
    if severity in {"critical", "high"}:
        return "block"
    if severity in {"med", "medium"}:
        return "warn"
    return "allow"


def _asset_match(row: RuntimeEvent, *, asset_norm: str) -> bool:
    metadata = _metadata_dict(row.metadata_json)
    candidates = [
        str(row.ai_system_id or "").strip(),
        str(row.app_id or "").strip(),
        _metadata_str(metadata, "asset_id", "ai_system_id", "mcp_server_id", "mcp_tool_id"),
    ]
    tools = _metadata_list(metadata, "connected_tools", "tool_registry")
    for tool_id in tools:
        candidates.append(tool_id)
    for candidate in candidates:
        if candidate and candidate.lower() == asset_norm:
            return True
    return False


def _runtime_activity_row(row: RuntimeEvent) -> TrustCenterAssetActivityResponse:
    metadata = _metadata_dict(row.metadata_json)
    return TrustCenterAssetActivityResponse(
        event_id=row.event_id,
        timestamp=row.created_at,
        source_surface=row.source_surface,
        ai_surface=_metadata_str(metadata, "ai_surface", "surface") or row.source_surface,
        action_type=_metadata_str(metadata, "action_type", "operation") or row.event_type,
        decision=_event_decision(row),
        application=str(row.app_id or "").strip() or _metadata_str(metadata, "application", "domain", "destination_domain"),
        user_id=row.user_id,
        agent_id=row.agent_id,
        session_id=_metadata_str(metadata, "session_id"),
        ai_client=_metadata_str(metadata, "ai_client", "client", "client_name"),
        mcp_server_id=_metadata_str(metadata, "mcp_server_id"),
        mcp_tool_id=_metadata_str(metadata, "mcp_tool_id"),
        tool_name=_metadata_str(metadata, "tool_name"),
        risk_score=float(row.risk_score or metadata.get("risk_score") or 0.0),
        finding_id=_metadata_str(metadata, "finding_id"),
        correlation_id=row.correlation_id,
        context_id=row.context_id,
        chain_id=row.chain_id,
    )


@router.get("/evidence/nodes", response_model=ListEnvelope[EvidenceNodeResponse])
def list_evidence_nodes(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(select(EvidenceNode).where(EvidenceNode.tenant_id == ctx.tenant.id).order_by(EvidenceNode.created_at.desc())).all()
    dto_rows = [EvidenceNodeResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[EvidenceNodeResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/evidence/edges", response_model=ListEnvelope[EvidenceEdgeResponse])
def list_evidence_edges(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(select(EvidenceEdge).where(EvidenceEdge.tenant_id == ctx.tenant.id).order_by(EvidenceEdge.created_at.desc())).all()
    dto_rows = [EvidenceEdgeResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[EvidenceEdgeResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/maturity", response_model=ListEnvelope[ControlMaturityResponse])
def list_maturity(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="auditor")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(select(ControlMaturity).where(ControlMaturity.tenant_id == ctx.tenant.id)).all()
    dto_rows = [ControlMaturityResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[ControlMaturityResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/maturity/{ai_system_id}/controls/{control_id}/explanation")
def maturity_score_explanation(
    ai_system_id: str,
    control_id: str,
    ctx: TenantContext = Depends(require_role(min_role="auditor")),
    db: Session = Depends(get_db),
):
    try:
        return get_maturity_score_explanation(
            db,
            tenant_id=ctx.tenant.id,
            ai_system_id=ai_system_id,
            control_id=control_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/audit-logs", response_model=ListEnvelope[AuditLogResponse])
def list_audit_logs(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="auditor")),
    db: Session = Depends(get_db),
):
    safe_page = max(1, int(page))
    safe_page_size = max(1, min(200, int(page_size)))
    tenant_filter = AuditLog.tenant_id == ctx.tenant.id
    total = int(db.scalar(select(func.count()).select_from(AuditLog).where(tenant_filter)) or 0)
    rows = db.scalars(
        select(AuditLog)
        .where(tenant_filter)
        .order_by(AuditLog.created_at.desc())
        .offset((safe_page - 1) * safe_page_size)
        .limit(safe_page_size)
    ).all()
    dto_rows = [AuditLogResponse.model_validate(row) for row in rows]
    return ListEnvelope[AuditLogResponse](
        items=dto_rows,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/ai-systems/{ai_system_id}/remediation-state", response_model=TrustCenterRemediationStateResponse)
def ai_system_remediation_state(
    ai_system_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    ai_system = db.scalar(
        select(AISystem).where(
            AISystem.tenant_id == ctx.tenant.id,
            AISystem.id == ai_system_id,
        )
    )
    if ai_system is None:
        raise HTTPException(status_code=404, detail="AI system not found")

    rows = list_remediation_actions(
        db,
        tenant_id=ctx.tenant.id,
        target_type="ai_system",
        target_id=ai_system_id,
    )
    open_count = sum(1 for row in rows if str(row.status).lower() in {"proposed"})
    applied_count = sum(1 for row in rows if str(row.status).lower() in {"applied"})
    failed_count = sum(1 for row in rows if str(row.status).lower() in {"failed"})

    metadata = dict(ai_system.metadata_json or {})
    latest = [
        {
            "id": row.id,
            "type": row.remediation_type,
            "status": row.status,
            "risk_level": row.risk_level,
            "requires_approval": row.requires_approval,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "applied_at": row.applied_at.isoformat() if row.applied_at else None,
            "source_trigger_type": row.source_trigger_type,
            "source_trigger_id": row.source_trigger_id,
            "state_before": dict((row.rollback_payload or {}).get("before") or {}),
            "state_after": dict((row.rollback_payload or {}).get("after") or {}),
            "missing_requirements": list(
                dict((row.rollback_payload or {}).get("context") or {}).get("missing_requirements") or []
            ),
        }
        for row in rows[:10]
    ]

    audit_rows = db.scalars(
        select(AuditLog)
        .where(
            AuditLog.tenant_id == ctx.tenant.id,
            AuditLog.resource_type == "ai_system",
            AuditLog.resource_id == ai_system_id,
        )
        .order_by(AuditLog.created_at.desc())
        .limit(200)
    ).all()
    remediation_logs = []
    for entry in audit_rows:
        payload = dict(entry.payload or {})
        remediation_id = str(payload.get("remediation_id") or "").strip()
        if not remediation_id:
            continue
        remediation_logs.append(
            {
                "audit_log_id": entry.id,
                "action": entry.action,
                "created_at": entry.created_at.isoformat() if entry.created_at else None,
                "remediation_id": remediation_id,
                "state_before": dict(payload.get("state_before") or {}),
                "state_after": dict(payload.get("state_after") or {}),
                "missing_requirements": list(payload.get("missing_requirements") or []),
            }
        )

    return TrustCenterRemediationStateResponse(
        ai_system_id=ai_system.id,
        ai_system_status=ai_system.status,
        risk_tier=ai_system.risk_tier,
        lifecycle_state=str(metadata.get("lifecycle_state") or "") or None,
        governance_state=str(metadata.get("governance_state") or "") or None,
        ownership_state=str(metadata.get("ownership_state") or "") or None,
        business_owner=(
            str(metadata.get("business_owner_user_id") or metadata.get("owner_user_id") or "").strip() or None
        ),
        technical_owner=(str(metadata.get("technical_owner_user_id") or "").strip() or None),
        open_remediations=open_count,
        applied_remediations=applied_count,
        failed_remediations=failed_count,
        latest_remediations=latest,
        remediation_logs=remediation_logs,
    )


@router.get("/assets/{asset_id}/activity", response_model=ListEnvelope[TrustCenterAssetActivityResponse])
def trust_center_asset_activity(
    asset_id: str,
    page: int = 1,
    page_size: int = 100,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    asset_norm = str(asset_id or "").strip().lower()
    if not asset_norm:
        raise HTTPException(status_code=400, detail="asset_id is required")

    rows = db.scalars(
        select(RuntimeEvent)
        .where(RuntimeEvent.tenant_id == ctx.tenant.id)
        .order_by(desc(RuntimeEvent.created_at))
        .limit(6000)
    ).all()
    dto_rows = [_runtime_activity_row(row) for row in rows if _asset_match(row, asset_norm=asset_norm)]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[TrustCenterAssetActivityResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/assets/{asset_id}/findings", response_model=ListEnvelope[TrustCenterAssetFindingResponse])
def trust_center_asset_findings(
    asset_id: str,
    page: int = 1,
    page_size: int = 100,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    asset_norm = str(asset_id or "").strip().lower()
    if not asset_norm:
        raise HTTPException(status_code=400, detail="asset_id is required")

    events = db.scalars(
        select(RuntimeEvent)
        .where(RuntimeEvent.tenant_id == ctx.tenant.id)
        .order_by(desc(RuntimeEvent.created_at))
        .limit(6000)
    ).all()
    matched_event_ids = {row.event_id for row in events if _asset_match(row, asset_norm=asset_norm)}

    rows = db.scalars(
        select(Finding)
        .where(Finding.tenant_id == ctx.tenant.id)
        .order_by(desc(Finding.last_seen_at), desc(Finding.updated_at))
        .limit(3000)
    ).all()

    dto_rows: list[TrustCenterAssetFindingResponse] = []
    for row in rows:
        related_event_ids = [str(item).strip() for item in list(row.related_event_ids or []) if str(item).strip()]
        direct_asset_match = (
            str(row.ai_system_id or "").strip().lower() == asset_norm
            or str(row.ai_tool or "").strip().lower() == asset_norm
        )
        related_match = bool(matched_event_ids.intersection(related_event_ids))
        if not direct_asset_match and not related_match:
            continue

        dto_rows.append(
            TrustCenterAssetFindingResponse(
                finding_id=row.finding_id,
                severity=row.severity,
                status=row.status,
                finding_type=row.finding_type,
                risk_category=row.risk_category,
                source_surface=row.source_surface,
                ai_tool=row.ai_tool,
                ai_system_id=row.ai_system_id,
                user_id=row.user_id,
                agent_id=row.agent_id,
                machine_id=row.machine_id,
                recommended_action=row.recommended_action,
                related_event_ids=related_event_ids,
                evidence_node_ids=[str(item).strip() for item in list(row.evidence_node_ids or []) if str(item).strip()],
                last_seen_at=row.last_seen_at,
                created_at=row.created_at,
            )
        )

    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[TrustCenterAssetFindingResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/assets/{asset_id}/evidence", response_model=ListEnvelope[EvidenceNodeResponse])
def trust_center_asset_evidence(
    asset_id: str,
    page: int = 1,
    page_size: int = 100,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    asset_norm = str(asset_id or "").strip().lower()
    if not asset_norm:
        raise HTTPException(status_code=400, detail="asset_id is required")

    events = db.scalars(
        select(RuntimeEvent)
        .where(RuntimeEvent.tenant_id == ctx.tenant.id)
        .order_by(desc(RuntimeEvent.created_at))
        .limit(6000)
    ).all()
    matched_correlations: set[str] = set()
    for row in events:
        if not _asset_match(row, asset_norm=asset_norm):
            continue
        correlation_id = str(row.correlation_id or "").strip()
        if correlation_id:
            matched_correlations.add(correlation_id)

    nodes = db.scalars(
        select(EvidenceNode)
        .where(EvidenceNode.tenant_id == ctx.tenant.id)
        .order_by(desc(EvidenceNode.created_at))
        .limit(4000)
    ).all()
    filtered: list[EvidenceNodeResponse] = []
    for node in nodes:
        payload = _metadata_dict(node.payload)
        payload_keys = [
            str(payload.get("asset_id") or "").strip().lower(),
            str(payload.get("ai_system_id") or "").strip().lower(),
            str(payload.get("mcp_server_id") or "").strip().lower(),
            str(payload.get("mcp_tool_id") or "").strip().lower(),
        ]
        payload_match = any(key and key == asset_norm for key in payload_keys)
        correlation_match = str(node.correlation_id or "").strip() in matched_correlations
        if payload_match or correlation_match:
            filtered.append(EvidenceNodeResponse.model_validate(node))

    page_items, total, safe_page, safe_page_size = paginate_rows(filtered, page=page, page_size=page_size)
    return ListEnvelope[EvidenceNodeResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/assets/{asset_id}/sessions", response_model=ListEnvelope[TrustCenterAssetSessionResponse])
def trust_center_asset_sessions(
    asset_id: str,
    page: int = 1,
    page_size: int = 100,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    asset_norm = str(asset_id or "").strip().lower()
    if not asset_norm:
        raise HTTPException(status_code=400, detail="asset_id is required")

    runtime_rows = db.scalars(
        select(RuntimeEvent)
        .where(RuntimeEvent.tenant_id == ctx.tenant.id)
        .order_by(desc(RuntimeEvent.created_at))
        .limit(10000)
    ).all()

    sessions: dict[str, dict[str, Any]] = {}
    for row in reversed(runtime_rows):
        if not _asset_match(row, asset_norm=asset_norm):
            continue
        metadata = _metadata_dict(row.metadata_json)
        session_id = (
            _metadata_str(metadata, "session_id")
            or str(row.context_id or "").strip()
            or str(row.chain_id or "").strip()
            or str(row.correlation_id or "").strip()
            or f"event:{row.event_id}"
        )
        item = sessions.setdefault(
            session_id,
            {
                "session_id": session_id,
                "start_time": row.created_at,
                "end_time": row.created_at,
                "event_count": 0,
                "user_id": row.user_id,
                "agent_id": row.agent_id,
                "ai_client": _metadata_str(metadata, "ai_client", "client", "client_name"),
                "mcp_server_id": _metadata_str(metadata, "mcp_server_id"),
                "decisions": set(),
                "highest_risk_score": 0.0,
            },
        )
        item["event_count"] += 1
        item["start_time"] = min(item["start_time"], row.created_at)
        item["end_time"] = max(item["end_time"], row.created_at)
        item["decisions"].add(_event_decision(row))
        item["highest_risk_score"] = max(float(item["highest_risk_score"]), float(row.risk_score or 0.0))
        if not item.get("user_id") and row.user_id:
            item["user_id"] = row.user_id
        if not item.get("agent_id") and row.agent_id:
            item["agent_id"] = row.agent_id
        if not item.get("ai_client"):
            item["ai_client"] = _metadata_str(metadata, "ai_client", "client", "client_name")
        if not item.get("mcp_server_id"):
            item["mcp_server_id"] = _metadata_str(metadata, "mcp_server_id")

    ai_sessions = db.scalars(
        select(AISession)
        .where(AISession.tenant_id == ctx.tenant.id)
        .order_by(desc(AISession.start_time))
        .limit(3000)
    ).all()
    for row in ai_sessions:
        metadata = _metadata_dict(row.metadata_json)
        candidates = [
            str(row.ai_app or "").strip().lower(),
            str(metadata.get("asset_id") or "").strip().lower(),
            str(metadata.get("mcp_server_id") or "").strip().lower(),
        ]
        if not any(item and item == asset_norm for item in candidates):
            continue
        session_id = str(row.session_id or "").strip() or f"legacy:{asset_id}"
        item = sessions.setdefault(
            session_id,
            {
                "session_id": session_id,
                "start_time": row.start_time,
                "end_time": row.end_time or row.start_time,
                "event_count": 0,
                "user_id": row.user_id,
                "agent_id": _metadata_str(metadata, "agent_id"),
                "ai_client": _metadata_str(metadata, "ai_client", "client"),
                "mcp_server_id": _metadata_str(metadata, "mcp_server_id"),
                "decisions": set(),
                "highest_risk_score": float(row.risk_score or 0.0),
            },
        )
        item["start_time"] = min(item["start_time"], row.start_time)
        item["end_time"] = max(item["end_time"], row.end_time or row.start_time)
        item["highest_risk_score"] = max(float(item["highest_risk_score"]), float(row.risk_score or 0.0))

    dto_rows = [
        TrustCenterAssetSessionResponse(
            session_id=str(item["session_id"]),
            start_time=item.get("start_time"),
            end_time=item.get("end_time"),
            event_count=int(item.get("event_count") or 0),
            user_id=str(item.get("user_id") or "").strip() or None,
            agent_id=str(item.get("agent_id") or "").strip() or None,
            ai_client=str(item.get("ai_client") or "").strip() or None,
            mcp_server_id=str(item.get("mcp_server_id") or "").strip() or None,
            decisions=sorted({str(decision).strip() for decision in item.get("decisions", set()) if str(decision).strip()}),
            highest_risk_score=float(item.get("highest_risk_score") or 0.0),
        )
        for item in sessions.values()
    ]
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    dto_rows = sorted(
        dto_rows,
        key=lambda item: ((item.end_time or item.start_time or epoch).timestamp()),
        reverse=True,
    )
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[TrustCenterAssetSessionResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )
