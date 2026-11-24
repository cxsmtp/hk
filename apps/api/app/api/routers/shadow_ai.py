from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.auth import get_current_user
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.finding import Finding
from app.db.models.shadow_ai import ShadowAIEntity, ShadowAISignal, ShadowAIUsage
from app.db.models.user import User
from app.db.session import get_db
from app.services.shadow_ai.dns_ingest_service import ingest_dns_signal
from app.services.shadow_ai.endpoint_ingest_service import ingest_endpoint_signal
from app.services.shadow_ai.provider_catalog import list_catalog
from app.services.shadow_ai.proxy_ingest_service import ingest_proxy_signal
from app.services.shadow_ai.reconciliation_service import (
    link_entity_to_ai_system,
    merge_shadow_entities,
    reconcile_to_trust_center_candidate,
    reject_shadow_entity,
)


router = APIRouter(prefix="/shadow-ai", tags=["shadow-ai"])


class TelemetryImportRequest(BaseModel):
    format: Literal["defender_csv", "swg_csv"]
    source_instance: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    content: str = Field(min_length=1, max_length=1048576)
    window_start: datetime
    window_end: datetime
    preview: bool = True


@router.post("/telemetry-import")
def import_shadow_telemetry(
    payload: TelemetryImportRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin"])),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from app.services.shadow_ai.telemetry_import import import_telemetry, TelemetryImportError
    try:
        result = import_telemetry(db, tenant_id=ctx.tenant.id, actor_user_id=current_user.id, payload=payload.model_dump())
        if not payload.preview:
            db.commit()
        return result
    except TelemetryImportError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from None


class ShadowAISignalResponse(BaseModel):
    id: str
    tenant_id: str
    shadow_ai_entity_id: str | None = None
    source_surface: str
    source_event_id: str
    domain: str | None = None
    provider: str | None = None
    model_name: str | None = None
    tool_name: str | None = None
    api_endpoint: str | None = None
    user_id: str | None = None
    agent_id: str | None = None
    confidence_signal: dict[str, Any]
    raw_fingerprint: dict[str, Any]
    created_at: datetime


class ShadowAIEntityResponse(BaseModel):
    id: str
    tenant_id: str
    canonical_name: str
    discovery_status: str
    confidence_score: float
    confidence_level: str
    provisional_risk_tier: str | None = None
    source_surfaces: list[str]
    vendor: str | None = None
    deployment_type: str | None = None
    ai_type: str | None = None
    first_seen: datetime
    last_seen: datetime
    linked_ai_system_id: str | None = None
    approved_status: str
    risk_score: float
    usage_count: int
    unique_users: int
    endpoints_count: int
    signal_count: int
    open_findings: int
    metadata_json: dict[str, Any]
    contributing_surfaces: list[str] = Field(default_factory=list)
    observed_domains: list[str] = Field(default_factory=list)
    observed_processes: list[str] = Field(default_factory=list)
    observed_providers: list[str] = Field(default_factory=list)
    first_seen_by_surface: dict[str, str] = Field(default_factory=dict)
    last_seen_by_surface: dict[str, str] = Field(default_factory=dict)
    health_status_summary: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class ShadowAIEntityDetailResponse(ShadowAIEntityResponse):
    signals: list[ShadowAISignalResponse] = Field(default_factory=list)
    linked_findings: list[str] = Field(default_factory=list)
    evidence_node_ids: list[str] = Field(default_factory=list)
    observed_tools: list[str] = Field(default_factory=list)
    usage_by_user: list[dict[str, Any]] = Field(default_factory=list)
    usage_by_endpoint: list[dict[str, Any]] = Field(default_factory=list)
    recent_usage: list[dict[str, Any]] = Field(default_factory=list)


class ShadowAIPromoteRequest(BaseModel):
    force: bool = True


class ShadowAILinkRequest(BaseModel):
    ai_system_id: str


class ShadowAIRejectRequest(BaseModel):
    reason: str | None = None


class ShadowAIMergeRequest(BaseModel):
    target_entity_id: str


class ShadowAIEndpointIngestRequest(BaseModel):
    source_event_id: str | None = None
    ai_system_id: str | None = None
    process_name: str
    executable_path: str | None = None
    command_line: str | None = None
    destination_domain: str | None = None
    destination_ip: str | None = None
    api_endpoint: str | None = None
    provider: str | None = None
    model_provider: str | None = None
    model_name: str | None = None
    tool_name: str | None = None
    tool_category: str | None = None
    user_id: str | None = None
    agent_id: str | None = None
    host_id: str | None = None
    host_sensitivity: str | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None
    severity: str | None = "high"
    timestamp: datetime | None = None
    correlation_id: str | None = None


class ShadowAIDNSIngestRequest(BaseModel):
    source_event_id: str | None = None
    ai_system_id: str | None = None
    queried_domain: str
    resolved_ip: str | None = None
    provider: str | None = None
    tool_name: str | None = None
    api_endpoint: str | None = None
    full_url: str | None = None
    model_name: str | None = None
    user_id: str | None = None
    agent_id: str | None = None
    host_id: str | None = None
    source_system: str | None = None
    query_time: datetime | None = None
    query_count: int = 1
    force_runtime: bool = False
    severity: str | None = "med"
    correlation_id: str | None = None


class ShadowAIProxyIngestRequest(BaseModel):
    source_event_id: str | None = None
    ai_system_id: str | None = None
    request_domain: str
    full_url: str | None = None
    api_endpoint: str | None = None
    method: str | None = None
    response_code: int | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None
    user_id: str | None = None
    agent_id: str | None = None
    host_id: str | None = None
    app_category: str | None = None
    provider: str | None = None
    model_provider: str | None = None
    model_name: str | None = None
    tool_name: str | None = None
    severity: str | None = "high"
    timestamp: datetime | None = None
    correlation_id: str | None = None


class ShadowAIIngestResponse(BaseModel):
    source_signal_id: str
    runtime_event_id: str | None = None
    shadow_ai_entity_id: str | None = None
    finding_id: str | None = None
    confidence_level: str
    promoted_to_runtime: bool | None = None


class ShadowAICoverageResponse(BaseModel):
    discovered_via_browser: int
    discovered_via_endpoint: int
    discovered_via_dns: int
    discovered_via_proxy: int
    discovered_via_gateway: int
    reconciled_entities: int
    promoted_entities: int
    unresolved_low_confidence_clusters: int
    unresolved_signal_count: int


def _confidence_level(score: float) -> str:
    if score >= 0.8:
        return "high"
    if score >= 0.5:
        return "medium"
    return "low"


def _to_signal_response(row: ShadowAISignal) -> ShadowAISignalResponse:
    return ShadowAISignalResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        shadow_ai_entity_id=row.shadow_ai_entity_id,
        source_surface=row.source_surface,
        source_event_id=row.source_event_id,
        domain=row.domain,
        provider=row.provider,
        model_name=row.model_name,
        tool_name=row.tool_name,
        api_endpoint=row.api_endpoint,
        user_id=row.user_id,
        agent_id=row.agent_id,
        confidence_signal=dict(row.confidence_signal or {}),
        raw_fingerprint=dict(row.raw_fingerprint or {}),
        created_at=row.created_at,
    )


def _to_entity_response(
    row: ShadowAIEntity,
    *,
    signal_count: int,
    open_findings: int,
    observed_domains: list[str] | None = None,
    observed_processes: list[str] | None = None,
    observed_providers: list[str] | None = None,
    first_seen_by_surface: dict[str, str] | None = None,
    last_seen_by_surface: dict[str, str] | None = None,
    health_status_summary: dict[str, Any] | None = None,
) -> ShadowAIEntityResponse:
    surfaces = [str(item) for item in (row.source_surfaces or []) if str(item).strip()]
    return ShadowAIEntityResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        canonical_name=row.canonical_name,
        discovery_status=row.discovery_status,
        confidence_score=float(row.confidence_score or 0.0),
        confidence_level=_confidence_level(float(row.confidence_score or 0.0)),
        provisional_risk_tier=row.provisional_risk_tier,
        source_surfaces=surfaces,
        vendor=row.vendor,
        deployment_type=row.deployment_type,
        ai_type=row.ai_type,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        linked_ai_system_id=row.linked_ai_system_id,
        approved_status=str(row.approved_status or "unknown"),
        risk_score=float(row.risk_score or 0.0),
        usage_count=int(row.usage_count or 0),
        unique_users=int(row.unique_users or 0),
        endpoints_count=int(row.endpoints_count or 0),
        signal_count=signal_count,
        open_findings=open_findings,
        metadata_json=dict(row.metadata_json or {}),
        contributing_surfaces=sorted({str(item).strip().lower() for item in surfaces if str(item).strip()}),
        observed_domains=sorted(set(observed_domains or [])),
        observed_processes=sorted(set(observed_processes or [])),
        observed_providers=sorted(set(observed_providers or [])),
        first_seen_by_surface=dict(first_seen_by_surface or {}),
        last_seen_by_surface=dict(last_seen_by_surface or {}),
        health_status_summary=dict(health_status_summary or {}),
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _entity_or_404(db: Session, *, tenant_id: str, entity_id: str) -> ShadowAIEntity:
    entity = db.scalar(
        select(ShadowAIEntity).where(
            ShadowAIEntity.tenant_id == tenant_id,
            ShadowAIEntity.id == entity_id,
        )
    )
    if entity is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Shadow AI entity not found")
    return entity


@router.get("/entities", response_model=ListEnvelope[ShadowAIEntityResponse])
def list_shadow_ai_entities(
    status_filter: str | None = None,
    source_surface: str | None = None,
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    stmt = select(ShadowAIEntity).where(ShadowAIEntity.tenant_id == ctx.tenant.id)
    if status_filter:
        stmt = stmt.where(ShadowAIEntity.discovery_status == status_filter)
    rows = db.scalars(stmt.order_by(desc(ShadowAIEntity.last_seen))).all()
    if source_surface:
        wanted = str(source_surface).strip().lower()
        rows = [
            row
            for row in rows
            if wanted in {str(item).strip().lower() for item in (row.source_surfaces or []) if str(item).strip()}
        ]

    signal_counts = dict(
        db.execute(
            select(ShadowAISignal.shadow_ai_entity_id, func.count())
            .where(
                ShadowAISignal.tenant_id == ctx.tenant.id,
                ShadowAISignal.shadow_ai_entity_id.is_not(None),
            )
            .group_by(ShadowAISignal.shadow_ai_entity_id)
        ).all()
    )
    signals = db.scalars(
        select(ShadowAISignal).where(
            ShadowAISignal.tenant_id == ctx.tenant.id,
            ShadowAISignal.shadow_ai_entity_id.is_not(None),
        )
    ).all()
    by_entity_domains: dict[str, set[str]] = {}
    by_entity_processes: dict[str, set[str]] = {}
    by_entity_providers: dict[str, set[str]] = {}
    by_entity_first_surface: dict[str, dict[str, str]] = {}
    by_entity_last_surface: dict[str, dict[str, str]] = {}
    for signal in signals:
        entity_id = str(signal.shadow_ai_entity_id or "").strip()
        if not entity_id:
            continue
        domain = str(signal.domain or "").strip()
        provider = str(signal.provider or "").strip()
        process = str((signal.raw_fingerprint or {}).get("process_name") or "").strip() if isinstance(signal.raw_fingerprint, dict) else ""
        surface = str(signal.source_surface or "").strip().lower() or "unknown"
        created_at = signal.created_at.isoformat() if signal.created_at else ""
        if domain:
            by_entity_domains.setdefault(entity_id, set()).add(domain)
        if provider:
            by_entity_providers.setdefault(entity_id, set()).add(provider)
        if process:
            by_entity_processes.setdefault(entity_id, set()).add(process)
        if created_at:
            first_map = by_entity_first_surface.setdefault(entity_id, {})
            last_map = by_entity_last_surface.setdefault(entity_id, {})
            if not first_map.get(surface) or created_at < first_map[surface]:
                first_map[surface] = created_at
            if not last_map.get(surface) or created_at > last_map[surface]:
                last_map[surface] = created_at

    finding_counts = dict(
        db.execute(
            select(Finding.ai_tool, func.count())
            .where(
                Finding.tenant_id == ctx.tenant.id,
                Finding.status.in_(["open", "reviewing"]),
            )
            .group_by(Finding.ai_tool)
        ).all()
    )
    dto_rows = [
        _to_entity_response(
            row,
            signal_count=int(signal_counts.get(row.id) or 0),
            open_findings=int(finding_counts.get(row.canonical_name) or 0),
            observed_domains=sorted(by_entity_domains.get(row.id, set())),
            observed_processes=sorted(by_entity_processes.get(row.id, set())),
            observed_providers=sorted(by_entity_providers.get(row.id, set())),
            first_seen_by_surface=by_entity_first_surface.get(row.id, {}),
            last_seen_by_surface=by_entity_last_surface.get(row.id, {}),
            health_status_summary={"signal_count": int(signal_counts.get(row.id) or 0)},
        )
        for row in rows
    ]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[ShadowAIEntityResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/entities/{entity_id}", response_model=ShadowAIEntityDetailResponse)
def get_shadow_ai_entity(
    entity_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    entity = _entity_or_404(db, tenant_id=ctx.tenant.id, entity_id=entity_id)
    signals = db.scalars(
        select(ShadowAISignal)
        .where(
            ShadowAISignal.tenant_id == ctx.tenant.id,
            ShadowAISignal.shadow_ai_entity_id == entity.id,
        )
        .order_by(desc(ShadowAISignal.created_at))
    ).all()
    open_findings = db.scalars(
        select(Finding).where(
            Finding.tenant_id == ctx.tenant.id,
            Finding.ai_tool == entity.canonical_name,
            Finding.status.in_(["open", "reviewing"]),
        )
    ).all()
    usage_rows = db.scalars(
        select(ShadowAIUsage)
        .where(
            ShadowAIUsage.tenant_id == ctx.tenant.id,
            ShadowAIUsage.asset_id == entity.id,
        )
        .order_by(desc(ShadowAIUsage.timestamp))
    ).all()
    first_seen_by_surface: dict[str, str] = {}
    last_seen_by_surface: dict[str, str] = {}
    observed_processes = sorted(
        {
            str((row.raw_fingerprint or {}).get("process_name")).strip()
            for row in signals
            if isinstance(row.raw_fingerprint, dict) and str((row.raw_fingerprint or {}).get("process_name") or "").strip()
        }
    )
    for row in signals:
        surface = str(row.source_surface or "").strip().lower() or "unknown"
        timestamp = row.created_at.isoformat()
        if not first_seen_by_surface.get(surface) or timestamp < first_seen_by_surface[surface]:
            first_seen_by_surface[surface] = timestamp
        if not last_seen_by_surface.get(surface) or timestamp > last_seen_by_surface[surface]:
            last_seen_by_surface[surface] = timestamp
    base = _to_entity_response(
        entity,
        signal_count=len(signals),
        open_findings=len(open_findings),
        observed_domains=sorted({str(row.domain).strip() for row in signals if str(row.domain or "").strip()}),
        observed_processes=observed_processes,
        observed_providers=sorted({str(row.provider).strip() for row in signals if str(row.provider or "").strip()}),
        first_seen_by_surface=first_seen_by_surface,
        last_seen_by_surface=last_seen_by_surface,
        health_status_summary={"signal_count": len(signals)},
    )
    observed_domains = sorted({str(row.domain).strip() for row in signals if str(row.domain or "").strip()})
    observed_providers = sorted({str(row.provider).strip() for row in signals if str(row.provider or "").strip()})
    observed_tools = sorted({str(row.tool_name).strip() for row in signals if str(row.tool_name or "").strip()})
    usage_by_user: dict[str, dict[str, Any]] = {}
    usage_by_endpoint: dict[str, dict[str, Any]] = {}
    recent_usage: list[dict[str, Any]] = []
    for usage in usage_rows:
        usage_time = usage.timestamp.isoformat() if usage.timestamp else None
        if usage.user_id:
            bucket = usage_by_user.setdefault(
                usage.user_id,
                {"user_id": usage.user_id, "count": 0, "last_seen": usage_time, "high_sensitivity_events": 0},
            )
            bucket["count"] = int(bucket["count"]) + 1
            if usage_time and (not bucket.get("last_seen") or str(usage_time) > str(bucket["last_seen"])):
                bucket["last_seen"] = usage_time
            if usage.sensitivity_detected:
                bucket["high_sensitivity_events"] = int(bucket["high_sensitivity_events"]) + 1
        if usage.endpoint_id:
            endpoint_bucket = usage_by_endpoint.setdefault(
                usage.endpoint_id,
                {"endpoint_id": usage.endpoint_id, "count": 0, "last_seen": usage_time, "high_sensitivity_events": 0},
            )
            endpoint_bucket["count"] = int(endpoint_bucket["count"]) + 1
            if usage_time and (not endpoint_bucket.get("last_seen") or str(usage_time) > str(endpoint_bucket["last_seen"])):
                endpoint_bucket["last_seen"] = usage_time
            if usage.sensitivity_detected:
                endpoint_bucket["high_sensitivity_events"] = int(endpoint_bucket["high_sensitivity_events"]) + 1
        if len(recent_usage) < 50:
            recent_usage.append(
                {
                    "usage_id": usage.id,
                    "timestamp": usage_time,
                    "interaction_type": usage.interaction_type,
                    "user_id": usage.user_id,
                    "endpoint_id": usage.endpoint_id,
                    "session_id": usage.session_id,
                    "sensitivity_detected": bool(usage.sensitivity_detected),
                    "policy_triggered": usage.policy_triggered,
                    "metadata": dict(usage.metadata_json or {}),
                }
            )
    evidence_ids = sorted(
        {
            str(node_id).strip()
            for finding in open_findings
            for node_id in (finding.evidence_node_ids or [])
            if str(node_id).strip()
        }
    )
    evidence_ids = sorted(set(evidence_ids) | {
        str(row.raw_fingerprint["evidence_node_id"])
        for row in signals
        if isinstance(row.raw_fingerprint, dict)
        and row.raw_fingerprint.get("provenance") == "customer_uploaded_export"
        and row.raw_fingerprint.get("evidence_node_id")
    })
    return ShadowAIEntityDetailResponse(
        **base.model_dump(),
        signals=[_to_signal_response(row) for row in signals],
        linked_findings=[str(item.finding_id) for item in open_findings],
        evidence_node_ids=evidence_ids,
        observed_tools=observed_tools,
        usage_by_user=sorted(usage_by_user.values(), key=lambda item: int(item.get("count") or 0), reverse=True),
        usage_by_endpoint=sorted(usage_by_endpoint.values(), key=lambda item: int(item.get("count") or 0), reverse=True),
        recent_usage=recent_usage,
    )


@router.post("/entities/{entity_id}/promote", response_model=ShadowAIEntityDetailResponse)
def promote_shadow_ai_entity(
    entity_id: str,
    payload: ShadowAIPromoteRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin", "auditor"])),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    entity = _entity_or_404(db, tenant_id=ctx.tenant.id, entity_id=entity_id)
    signals = db.scalars(
        select(ShadowAISignal).where(
            ShadowAISignal.tenant_id == ctx.tenant.id,
            ShadowAISignal.shadow_ai_entity_id == entity.id,
        )
    ).all()
    evidence_summary = [
        str(row.id)
        for row in signals
    ]
    reconcile_to_trust_center_candidate(
        db,
        tenant_id=ctx.tenant.id,
        entity=entity,
        confidence_score=float(entity.confidence_score or 0.0),
        confidence_level=_confidence_level(float(entity.confidence_score or 0.0)),
        evidence_node_ids=evidence_summary,
        actor_user_id=current_user.id,
        force_promote=bool(payload.force),
    )
    db.commit()
    return get_shadow_ai_entity(entity_id, ctx, db)


@router.post("/entities/{entity_id}/link-to-ai-system", response_model=ShadowAIEntityDetailResponse)
def link_shadow_entity(
    entity_id: str,
    payload: ShadowAILinkRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin", "auditor"])),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    entity = _entity_or_404(db, tenant_id=ctx.tenant.id, entity_id=entity_id)
    try:
        link_entity_to_ai_system(
            db,
            tenant_id=ctx.tenant.id,
            entity=entity,
            ai_system_id=payload.ai_system_id,
            actor_user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    db.commit()
    return get_shadow_ai_entity(entity_id, ctx, db)


@router.post("/entities/{entity_id}/reject", response_model=ShadowAIEntityDetailResponse)
def reject_entity(
    entity_id: str,
    payload: ShadowAIRejectRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin", "auditor"])),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    entity = _entity_or_404(db, tenant_id=ctx.tenant.id, entity_id=entity_id)
    reject_shadow_entity(
        db,
        tenant_id=ctx.tenant.id,
        entity=entity,
        reason=payload.reason,
        actor_user_id=current_user.id,
    )
    db.commit()
    return get_shadow_ai_entity(entity_id, ctx, db)


@router.post("/entities/{entity_id}/merge", response_model=ShadowAIEntityDetailResponse)
def merge_entities(
    entity_id: str,
    payload: ShadowAIMergeRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin", "auditor"])),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    source_entity = _entity_or_404(db, tenant_id=ctx.tenant.id, entity_id=entity_id)
    target_entity = _entity_or_404(db, tenant_id=ctx.tenant.id, entity_id=payload.target_entity_id)
    try:
        merged = merge_shadow_entities(
            db,
            tenant_id=ctx.tenant.id,
            source_entity=source_entity,
            target_entity=target_entity,
            actor_user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    db.commit()
    return get_shadow_ai_entity(merged.id, ctx, db)


@router.get("/unresolved-signals", response_model=ListEnvelope[ShadowAISignalResponse])
def unresolved_shadow_signals(
    page: int = 1,
    page_size: int = 100,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(
        select(ShadowAISignal)
        .where(ShadowAISignal.tenant_id == ctx.tenant.id)
        .order_by(desc(ShadowAISignal.created_at))
    ).all()

    unresolved_rows: list[ShadowAISignal] = []
    for row in rows:
        if not row.shadow_ai_entity_id:
            unresolved_rows.append(row)
            continue
        entity = db.scalar(
            select(ShadowAIEntity).where(
                ShadowAIEntity.tenant_id == ctx.tenant.id,
                ShadowAIEntity.id == row.shadow_ai_entity_id,
            )
        )
        if entity is None or entity.discovery_status in {"discovered"} and float(entity.confidence_score or 0.0) < 0.5:
            unresolved_rows.append(row)

    dto_rows = [_to_signal_response(row) for row in unresolved_rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[ShadowAISignalResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.post("/ingest/endpoint", response_model=ShadowAIIngestResponse)
def ingest_shadow_ai_endpoint(
    payload: ShadowAIEndpointIngestRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin", "auditor"])),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    result = ingest_endpoint_signal(
        db,
        tenant_id=ctx.tenant.id,
        payload=payload.model_dump(),
        actor_user_id=current_user.id,
    )
    db.commit()
    return ShadowAIIngestResponse(
        source_signal_id=result.source_signal_id,
        runtime_event_id=result.runtime_event_id,
        shadow_ai_entity_id=result.shadow_ai_entity_id,
        finding_id=result.finding_id,
        confidence_level=result.confidence_level,
        promoted_to_runtime=None,
    )


@router.post("/ingest/dns", response_model=ShadowAIIngestResponse)
def ingest_shadow_ai_dns(
    payload: ShadowAIDNSIngestRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin", "auditor"])),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    result = ingest_dns_signal(
        db,
        tenant_id=ctx.tenant.id,
        payload=payload.model_dump(),
        actor_user_id=current_user.id,
    )
    db.commit()
    return ShadowAIIngestResponse(
        source_signal_id=result.source_signal_id,
        runtime_event_id=result.runtime_event_id,
        shadow_ai_entity_id=result.shadow_ai_entity_id,
        finding_id=result.finding_id,
        confidence_level=result.confidence_level,
        promoted_to_runtime=result.promoted_to_runtime,
    )


@router.post("/ingest/proxy", response_model=ShadowAIIngestResponse)
def ingest_shadow_ai_proxy(
    payload: ShadowAIProxyIngestRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin", "auditor"])),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    result = ingest_proxy_signal(
        db,
        tenant_id=ctx.tenant.id,
        payload=payload.model_dump(),
        actor_user_id=current_user.id,
    )
    db.commit()
    return ShadowAIIngestResponse(
        source_signal_id=result.source_signal_id,
        runtime_event_id=result.runtime_event_id,
        shadow_ai_entity_id=result.shadow_ai_entity_id,
        finding_id=result.finding_id,
        confidence_level=result.confidence_level,
        promoted_to_runtime=None,
    )


@router.get("/provider-catalog", response_model=list[dict[str, Any]])
def get_provider_catalog(
    _ctx: TenantContext = Depends(require_role(min_role="viewer")),
):
    return list_catalog()


@router.get("/coverage", response_model=ShadowAICoverageResponse)
def get_shadow_ai_coverage(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    entities = db.scalars(
        select(ShadowAIEntity).where(ShadowAIEntity.tenant_id == ctx.tenant.id)
    ).all()
    unresolved_signals = db.scalars(
        select(ShadowAISignal).where(
            ShadowAISignal.tenant_id == ctx.tenant.id,
            ShadowAISignal.shadow_ai_entity_id.is_(None),
        )
    ).all()

    def count_surface(surface: str) -> int:
        return sum(
            1
            for row in entities
            if surface in {str(item).strip().lower() for item in (row.source_surfaces or []) if str(item).strip()}
        )

    unresolved_clusters = sum(
        1
        for row in entities
        if row.discovery_status == "discovered" and float(row.confidence_score or 0.0) < 0.5
    )

    return ShadowAICoverageResponse(
        discovered_via_browser=count_surface("browser"),
        discovered_via_endpoint=count_surface("endpoint"),
        discovered_via_dns=count_surface("dns"),
        discovered_via_proxy=count_surface("proxy"),
        discovered_via_gateway=count_surface("gateway"),
        reconciled_entities=sum(1 for row in entities if row.discovery_status == "reconciled"),
        promoted_entities=sum(1 for row in entities if row.discovery_status == "promoted"),
        unresolved_low_confidence_clusters=unresolved_clusters,
        unresolved_signal_count=len(unresolved_signals),
    )
