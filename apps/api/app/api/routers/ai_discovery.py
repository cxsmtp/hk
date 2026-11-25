from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope
from app.core.auth import get_current_user
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.user import User
from app.db.session import get_db
from app.services.ai_anomaly import list_recent_anomaly_events
from app.services.ai_discovery.agent_security_service import (
    build_agent_attack_surface_map,
    compute_agent_blast_radius,
    enforce_agent_security_action,
    get_agent_owasp_coverage,
    get_agent_behavior_profile,
    list_agent_anomaly_events,
    list_agent_entities,
    run_agent_security_simulation,
)
from app.services.ai_discovery import (
    build_discovery_panel_state,
    get_identity_profile,
    list_identity_profiles,
    list_usage_events,
    process_runtime_event_for_ai_discovery,
)
from app.services.ai_graph import build_unified_ai_graph


router = APIRouter(prefix="/ai-discovery", tags=["ai-discovery"])


class AIDiscoveryOverviewResponse(BaseModel):
    window_hours: int
    apps_detected: int
    total_usage_events: int
    shadow_ai_count: int
    approved_apps: int
    blocked_apps: int
    source_breakdown: dict[str, int]
    risk_breakdown: dict[str, int]
    usage_trend: list[dict[str, Any]] = Field(default_factory=list)
    top_apps: list[dict[str, Any]] = Field(default_factory=list)


class AIUsageEventResponse(BaseModel):
    user_id: str | None = None
    device_id: str | None = None
    browser_type: str | None = None
    app_name: str
    model: str | None = None
    agent_id: str | None = None
    tool_used: str | None = None
    timestamp: datetime
    action_type: str
    source_surface: str
    risk_level: str
    risk_score: float
    metadata: dict[str, Any] = Field(default_factory=dict)


class AIIdentityProfileResponse(BaseModel):
    user_id: str
    display_name: str = ""
    email: str = ""
    devices: list[str] = Field(default_factory=list)
    browsers: list[str] = Field(default_factory=list)
    ai_apps: list[str] = Field(default_factory=list)
    agents: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    usage_patterns: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0
    anomaly_score: float = 0.0
    anomaly_count_7d: int = 0


class AIDiscoveryGraphResponse(BaseModel):
    window_hours: int
    filters: dict[str, Any] = Field(default_factory=dict)
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)


class AIAnomalyEventResponse(BaseModel):
    id: str
    signal_type: str
    anomaly_type: str
    severity: str
    reason: str
    confidence: float
    created_at: str | None = None
    related_entities: list[dict[str, str]] = Field(default_factory=list)
    control_ids: list[str] = Field(default_factory=list)
    runtime_event_id: str | None = None
    monitoring_signal_id: str | None = None
    risk_context: dict[str, float] = Field(default_factory=dict)
    owasp_mappings: list[dict[str, Any]] = Field(default_factory=list)
    payload: dict[str, Any] = Field(default_factory=dict)


class AIDiscoveryRecomputeResponse(BaseModel):
    tenant_id: str
    recomputed_events: int
    started_at: str
    finished_at: str


class AIAgentEntityResponse(BaseModel):
    agent_id: str
    owner: str | None = None
    model: str | None = None
    tools: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    data_access: list[str] = Field(default_factory=list)
    environment: list[str] = Field(default_factory=list)
    connected_systems: list[str] = Field(default_factory=list)
    status: str = "discovered_unregistered"
    risk_score: float = 0.0
    anomaly_score: float = 0.0
    event_count: int = 0
    anomaly_count: int = 0
    source_surfaces: list[str] = Field(default_factory=list)
    over_scoped_flag: bool = False
    last_seen_at: str | None = None


class AIAgentDiscoveryOverviewResponse(BaseModel):
    window_hours: int
    discovered_agents: int
    registered_agents: int
    unregistered_agents: int
    high_risk_agents: int
    agents: list[AIAgentEntityResponse] = Field(default_factory=list)


class AIAgentAttackSurfaceResponse(BaseModel):
    agent_id: str
    window_hours: int
    live_updated_at: str
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    owasp_risk_overlays: list[dict[str, Any]] = Field(default_factory=list)
    top_connections: list[dict[str, Any]] = Field(default_factory=list)


class AIAgentBlastRadiusResponse(BaseModel):
    agent_id: str
    window_hours: int
    reachable_assets: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0
    financial_impact: dict[str, Any] = Field(default_factory=dict)
    control_ids: list[str] = Field(default_factory=list)
    owasp_risk_overlays: list[dict[str, Any]] = Field(default_factory=list)
    propagation_paths: list[dict[str, Any]] = Field(default_factory=list)
    attack_surface_stats: dict[str, Any] = Field(default_factory=dict)
    updated_at: str


class AIAgentBehaviorResponse(BaseModel):
    agent_id: str
    window_hours: int
    usage_patterns: dict[str, Any] = Field(default_factory=dict)
    chain_depth: dict[str, Any] = Field(default_factory=dict)
    data_volume: dict[str, Any] = Field(default_factory=dict)
    baseline: list[dict[str, Any]] = Field(default_factory=list)
    anomaly_score: float = 0.0
    anomaly_count_7d: int = 0
    updated_at: str


class AIAgentEnforcementRequest(BaseModel):
    action: Literal["block_agent", "restrict_tools", "require_approval", "isolate_execution"]
    reason: str = "Manual operator enforcement"
    tool_allowlist: list[str] = Field(default_factory=list)
    required_approval: bool = False
    ai_system_id: str | None = None
    control_ids: list[str] = Field(default_factory=list)


class AIAgentEnforcementResponse(BaseModel):
    agent_id: str
    action: str
    status: str
    reason: str
    required_approval: bool = False
    control_ids: list[str] = Field(default_factory=list)
    previous_state: dict[str, Any] = Field(default_factory=dict)
    updated_state: dict[str, Any] = Field(default_factory=dict)
    revoked_tokens: int = 0
    revoked_delegations: int = 0
    impacted_agent_ids: list[str] = Field(default_factory=list)
    owasp_mappings: list[dict[str, Any]] = Field(default_factory=list)
    evidence_node_id: str
    audit_log_id: str
    runtime_event_id: str | None = None
    enforced_at: str


class AIAgentSimulationRequest(BaseModel):
    pack_id: str | None = None
    attack_type: str | None = None
    ai_system_id: str | None = None
    mode: Literal["deterministic", "stochastic"] = "deterministic"
    max_definitions: int = 8
    target_control_ids: list[str] = Field(default_factory=list)


class AIAgentSimulationResponse(BaseModel):
    agent_id: str
    attack_type: str
    resolved_pack_id: str
    execution_status: str
    pack_id: str
    ai_system_id: str
    mode: str
    stochastic_runs: int
    total_definitions: int
    total_runs: int
    passes: int
    fails: int
    pass_rate: float
    run_ids: list[str] = Field(default_factory=list)
    related_control_ids: list[str] = Field(default_factory=list)
    owasp_mappings: list[dict[str, Any]] = Field(default_factory=list)
    started_at: str | None = None
    finished_at: str | None = None
    evidence_node_id: str | None = None


class AIAgentOWASPCategoryResponse(BaseModel):
    risk_id: str
    framework: str
    framework_key: str
    reference: str
    title: str
    source_reference_url: str
    risk_tags: list[str] = Field(default_factory=list)
    controls: list[str] = Field(default_factory=list)
    matched_controls: list[str] = Field(default_factory=list)
    simulations: list[str] = Field(default_factory=list)
    mapped_catalog_simulations: list[str] = Field(default_factory=list)
    enforcement_actions: list[str] = Field(default_factory=list)
    blast_radius_dimensions: list[str] = Field(default_factory=list)
    remediation_templates: list[str] = Field(default_factory=list)
    audit_metadata: dict[str, Any] = Field(default_factory=dict)
    extends_llm_risks: list[str] = Field(default_factory=list)
    runtime_event_hits: int = 0
    anomaly_hits: int = 0
    simulation_runs: dict[str, int] = Field(default_factory=dict)
    simulation_pass_rate: float = 0.0
    defined_simulations: int = 0
    executable_simulations: int = 0
    partially_executable_simulations: int = 0
    not_executable_simulations: int = 0
    coverage_status: str = "mapped_only"


class AIAgentOWASPCoverageResponse(BaseModel):
    agent_id: str
    window_hours: int
    generated_at: str
    framework_registry: list[dict[str, Any]] = Field(default_factory=list)
    categories: list[AIAgentOWASPCategoryResponse] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)


@router.get("/overview", response_model=AIDiscoveryOverviewResponse)
def ai_discovery_overview(
    lookback_hours: int = 24 * 7,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
):
    payload = build_discovery_panel_state(
        db,
        tenant_id=ctx.tenant.id,
        lookback_hours=lookback_hours,
    )
    return AIDiscoveryOverviewResponse.model_validate(payload)


@router.get("/usage-events", response_model=ListEnvelope[AIUsageEventResponse])
def ai_usage_events(
    lookback_hours: int = 24 * 7,
    source_surface: str | None = None,
    user_id: str | None = None,
    page: int = 1,
    page_size: int = 100,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
):
    payload = list_usage_events(
        db,
        tenant_id=ctx.tenant.id,
        lookback_hours=lookback_hours,
        source_surface=source_surface,
        user_id=user_id,
        page=page,
        page_size=page_size,
    )
    return ListEnvelope[AIUsageEventResponse](
        items=[AIUsageEventResponse.model_validate(item) for item in list(payload.get("items") or [])],
        total=int(payload.get("total") or 0),
        page=int(payload.get("page") or page),
        page_size=int(payload.get("page_size") or page_size),
    )


@router.get("/graph", response_model=AIDiscoveryGraphResponse)
def ai_discovery_graph(
    lookback_hours: int = 24 * 7,
    user_id: str | None = None,
    agent_id: str | None = None,
    ai_app: str | None = None,
    max_edges: int = 1200,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
):
    payload = build_unified_ai_graph(
        db,
        tenant_id=ctx.tenant.id,
        lookback_hours=lookback_hours,
        user_id=user_id,
        agent_id=agent_id,
        ai_app=ai_app,
        max_edges=max_edges,
    )
    return AIDiscoveryGraphResponse.model_validate(payload)


@router.get("/identities", response_model=ListEnvelope[AIIdentityProfileResponse])
def ai_discovery_identities(
    q: str | None = None,
    limit: int = 100,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
):
    items = list_identity_profiles(
        db,
        tenant_id=ctx.tenant.id,
        q=q,
        limit=limit,
    )
    dto_items = [AIIdentityProfileResponse.model_validate(item) for item in items]
    return ListEnvelope[AIIdentityProfileResponse](
        items=dto_items,
        total=len(dto_items),
        page=1,
        page_size=max(1, min(500, int(limit or 100))),
    )


@router.get("/identities/{user_id}", response_model=AIIdentityProfileResponse)
def ai_discovery_identity_detail(
    user_id: str,
    lookback_hours: int = 24 * 30,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
):
    payload = get_identity_profile(
        db,
        tenant_id=ctx.tenant.id,
        user_id=user_id,
        lookback_hours=lookback_hours,
    )
    return AIIdentityProfileResponse.model_validate(payload)


@router.get("/anomalies", response_model=ListEnvelope[AIAnomalyEventResponse])
def ai_discovery_anomalies(
    lookback_hours: int = 24 * 7,
    severity: str | None = None,
    user_id: str | None = None,
    limit: int = 200,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
):
    rows = list_recent_anomaly_events(
        db,
        tenant_id=ctx.tenant.id,
        lookback_hours=lookback_hours,
        severity=severity,
        user_id=user_id,
        limit=limit,
    )
    dto_rows = [AIAnomalyEventResponse.model_validate(item) for item in rows]
    return ListEnvelope[AIAnomalyEventResponse](
        items=dto_rows,
        total=len(dto_rows),
        page=1,
        page_size=max(1, min(1000, int(limit or 200))),
    )


@router.get("/agents/overview", response_model=AIAgentDiscoveryOverviewResponse)
def ai_discovery_agents_overview(
    lookback_hours: int = 24 * 7,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
):
    payload = list_agent_entities(
        db,
        tenant_id=ctx.tenant.id,
        lookback_hours=lookback_hours,
    )
    return AIAgentDiscoveryOverviewResponse.model_validate(payload)


@router.get("/agents/{agent_id}/attack-surface", response_model=AIAgentAttackSurfaceResponse)
def ai_discovery_agent_attack_surface(
    agent_id: str,
    lookback_hours: int = 24 * 7,
    max_edges: int = 1200,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
):
    try:
        payload = build_agent_attack_surface_map(
            db,
            tenant_id=ctx.tenant.id,
            agent_id=agent_id,
            lookback_hours=lookback_hours,
            max_edges=max_edges,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return AIAgentAttackSurfaceResponse.model_validate(payload)


@router.get("/agents/{agent_id}/blast-radius", response_model=AIAgentBlastRadiusResponse)
def ai_discovery_agent_blast_radius(
    agent_id: str,
    lookback_hours: int = 24 * 7,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
):
    payload = compute_agent_blast_radius(
        db,
        tenant_id=ctx.tenant.id,
        agent_id=agent_id,
        lookback_hours=lookback_hours,
    )
    return AIAgentBlastRadiusResponse.model_validate(payload)


@router.get("/agents/{agent_id}/behavior", response_model=AIAgentBehaviorResponse)
def ai_discovery_agent_behavior(
    agent_id: str,
    lookback_hours: int = 24 * 7,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
):
    payload = get_agent_behavior_profile(
        db,
        tenant_id=ctx.tenant.id,
        agent_id=agent_id,
        lookback_hours=lookback_hours,
    )
    return AIAgentBehaviorResponse.model_validate(payload)


@router.get("/agents/{agent_id}/owasp-coverage", response_model=AIAgentOWASPCoverageResponse)
def ai_discovery_agent_owasp_coverage(
    agent_id: str,
    lookback_hours: int = 24 * 7,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
):
    try:
        payload = get_agent_owasp_coverage(
            db,
            tenant_id=ctx.tenant.id,
            agent_id=agent_id,
            lookback_hours=lookback_hours,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return AIAgentOWASPCoverageResponse.model_validate(payload)


@router.get("/agents/{agent_id}/anomalies", response_model=ListEnvelope[AIAnomalyEventResponse])
def ai_discovery_agent_anomalies(
    agent_id: str,
    lookback_hours: int = 24 * 7,
    limit: int = 80,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
):
    rows = list_agent_anomaly_events(
        db,
        tenant_id=ctx.tenant.id,
        agent_id=agent_id,
        lookback_hours=lookback_hours,
        limit=limit,
    )
    dto_rows = [AIAnomalyEventResponse.model_validate(item) for item in rows]
    return ListEnvelope[AIAnomalyEventResponse](
        items=dto_rows,
        total=len(dto_rows),
        page=1,
        page_size=max(1, min(1000, int(limit or 80))),
    )


@router.post("/agents/{agent_id}/enforce", response_model=AIAgentEnforcementResponse)
def ai_discovery_enforce_agent(
    agent_id: str,
    payload: AIAgentEnforcementRequest,
    ctx: TenantContext = Depends(require_permission("discovery.manage")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        result = enforce_agent_security_action(
            db,
            tenant_id=ctx.tenant.id,
            agent_id=agent_id,
            action=payload.action,
            reason=payload.reason,
            actor_user_id=current_user.id,
            tool_allowlist=payload.tool_allowlist,
            required_approval=payload.required_approval,
            ai_system_id=payload.ai_system_id,
            control_ids=payload.control_ids,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    db.commit()
    return AIAgentEnforcementResponse.model_validate(result)


@router.post("/agents/{agent_id}/simulate", response_model=AIAgentSimulationResponse)
def ai_discovery_simulate_agent(
    agent_id: str,
    payload: AIAgentSimulationRequest,
    ctx: TenantContext = Depends(require_permission("discovery.operate")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        result = run_agent_security_simulation(
            db,
            tenant_id=ctx.tenant.id,
            agent_id=agent_id,
            actor_user_id=current_user.id,
            ai_system_id=payload.ai_system_id,
            pack_id=payload.pack_id,
            attack_type=payload.attack_type,
            mode=payload.mode,
            max_definitions=payload.max_definitions,
            target_control_ids=payload.target_control_ids,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    db.commit()
    return AIAgentSimulationResponse.model_validate(result)


@router.post("/recompute", response_model=AIDiscoveryRecomputeResponse)
def recompute_discovery_from_runtime(
    lookback_hours: int = 24 * 7,
    max_events: int = 5000,
    ctx: TenantContext = Depends(require_permission("discovery.manage")),
    db: Session = Depends(get_db),
):
    started = datetime.now(timezone.utc)
    safe_hours = max(1, min(24 * 180, int(lookback_hours or 24 * 7)))
    safe_max_events = max(1, min(20000, int(max_events or 5000)))
    started_at = started - timedelta(hours=safe_hours)

    rows = db.scalars(
        select(RuntimeEvent)
        .where(
            RuntimeEvent.tenant_id == ctx.tenant.id,
            RuntimeEvent.created_at >= started_at,
        )
        .order_by(desc(RuntimeEvent.created_at))
        .limit(safe_max_events)
    ).all()
    processed = 0
    for row in rows:
        process_runtime_event_for_ai_discovery(db, event=row)
        processed += 1
    db.commit()

    finished = datetime.now(timezone.utc)
    return AIDiscoveryRecomputeResponse(
        tenant_id=ctx.tenant.id,
        recomputed_events=processed,
        started_at=started.isoformat(),
        finished_at=finished.isoformat(),
    )
