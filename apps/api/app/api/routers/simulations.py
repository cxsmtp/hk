from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.deps_control_plane import require_control_plane_healthy
from app.core.deps_governance import governance_payload_dependency
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.simulation import Control, SimulationDefinition, SimulationRun, SimulationTemplate
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.agentic_chain_validation_harness import (
    DEFENSE_MODES,
    SCENARIOS,
    ChainIntegrityReport,
    calculate_metrics,
    persist_chain_integrity_reports,
    run_scenario,
    run_scenario_library,
)
from app.services.fail_secure_service import enforce_fail_secure_or_raise
from app.services.governance_guard import GovernanceFailSecureError, GovernanceViolationError
from app.services.maturity_service import get_control_traceability
from app.services.simulation_contract_service import validate_and_normalize_simulation_dsl
from app.services.control_graph_service import ensure_canonical_controls, normalize_control_ids
from app.services.simulation_pack_service import (
    bootstrap_rfp_simulation_catalog,
    execute_pack,
    get_pack_coverage,
    get_pack_definition,
    get_simulation_coverage_summary,
    get_simulation_heatmap,
    get_simulation_trends,
    list_pack_definitions,
)
from app.services.simulation_seed_pack_service import bootstrap_initial_real_seed_simulations
from app.services.simulation_service import get_simulation_run_trace, run_simulation
from app.services.simulation_orchestrator import stream_simulation_updates
from app.services.simulation_template_service import create_template, generate_from_template
from app.services.tenant_default_seed_service import persist_tenant_canonical_controls


router = APIRouter(
    prefix="/simulations",
    tags=["simulations"],
    dependencies=[Depends(require_control_plane_healthy(module="simulations"))],
)


class ControlCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    category: str
    description: str
    mapped_framework_refs: list[dict] = []
    risk_tags: list[str] = []
    severity: str = "med"
    enforcement_points: list[str] = []
    detection_methods: list[str] = []
    response_actions: list[str] = []
    evidence_types: list[str] = []
    remediation_templates: list[str] = []
    is_global: bool = False
    success_criteria: dict = Field(
        default_factory=lambda: {
            "required_sim_pass_rate": 0.8,
            "required_evidence_sources": ["telemetry", "simulation", "config"],
            "min_maturity": 3,
        }
    )


class SimulationDefCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    category: str
    target_module: str
    version: str
    dsl_json: dict


class SimulationDefUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    category: str | None = None
    target_module: str | None = None
    version: str | None = None
    dsl_json: dict | None = None


class SimulationRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ai_system_id: str
    mode: str = "deterministic"
    stochastic_runs: int = Field(default=5, ge=1, le=100)
    inputs_used: dict = Field(default_factory=dict)
    live_session_id: str | None = None
    execution_environment: str = "sandbox"
    approval_granted: bool = False


class SimulationTemplateCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    status: str = "active"
    category: str
    target_module: str
    version_prefix: str = "1.0"
    parameter_schema: dict = Field(default_factory=dict)
    template_body: dict
    generation_defaults: dict = Field(default_factory=dict)


class SimulationTemplateGenerateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    count: int = Field(default=1, ge=1, le=200)
    parameter_sets: list[dict] | None = None


class ControlResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str | None = None
    is_global: bool
    name: str
    category: str
    description: str
    mapped_framework_refs: list[dict]
    risk_tags: list[str]
    severity: str
    enforcement_points: list[str]
    detection_methods: list[str]
    response_actions: list[str]
    evidence_types: list[str]
    remediation_templates: list[str]
    success_criteria: dict
    created_at: datetime
    updated_at: datetime


class SimulationDefinitionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    name: str
    category: str
    target_module: str
    version: str
    dsl_json: dict
    created_at: datetime
    updated_at: datetime


class SimulationRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    simulation_id: str
    ai_system_id: str
    started_at: datetime
    finished_at: datetime | None = None
    mode: str
    inputs_used: dict
    results: dict
    controls_impacted: list
    notes: str


class SimulationExecutionStepResponse(BaseModel):
    id: str
    simulation_run_id: str
    iteration_index: int
    step_id: str
    step_order: int
    step_type: str
    title: str
    status: str
    timestamp_started: datetime | None = None
    timestamp_completed: datetime | None = None
    actor: str
    target_surface: str
    input_payload_ref: dict
    output_payload_ref: dict
    control_refs: list[str]
    decision_ref: dict
    evidence_refs: list[str]
    notes: str


class SimulationRunTraceResponse(BaseModel):
    simulation_run_id: str
    simulation_id: str
    ai_system_id: str
    mode: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    final_outcome: str
    execution_status: str
    support_matrix: list[dict]
    steps: list[SimulationExecutionStepResponse]
    summary: dict


def _simulation_stream_response(*, tenant_id: str) -> StreamingResponse:
    return StreamingResponse(
        stream_simulation_updates(tenant_id=tenant_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


class SimulationTemplateResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    name: str
    description: str
    status: str
    category: str
    target_module: str
    version_prefix: str
    parameter_schema: dict
    template_body: dict
    generation_defaults: dict
    created_at: datetime
    updated_at: datetime


class SimulationTemplateGenerateResponse(BaseModel):
    template_id: str
    generated: list[SimulationDefinitionResponse]
    total_generated: int


class SimulationPackResponse(BaseModel):
    pack_id: str
    name: str
    description: str
    categories: list[str]
    trigger_reason_codes: list[str]
    simulation_count: int
    run_count: int
    pass_rate: float
    latest_run_at: datetime | None = None
    target_ready: bool


class SimulationPackRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ai_system_id: str
    mode: str = "deterministic"
    stochastic_runs: int = Field(default=5, ge=1, le=100)
    inputs_used: dict = Field(default_factory=dict)
    max_definitions: int = Field(default=25, ge=1, le=200)
    target_control_ids: list[str] | None = None
    execution_environment: str = "sandbox"
    approval_granted: bool = False


class SimulationPackRunResponse(BaseModel):
    pack_id: str
    ai_system_id: str
    mode: str
    stochastic_runs: int
    total_definitions: int
    total_runs: int
    passes: int
    fails: int
    pass_rate: float
    run_ids: list[str]
    related_control_ids: list[str]
    started_at: datetime | None = None
    finished_at: datetime | None = None
    evidence_node_id: str | None = None


class SimulationCatalogBootstrapRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    per_category_target: int = Field(default=35, ge=1, le=100)


class SimulationSeedPackBootstrapRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    update_existing: bool = False


class AgenticChainScenarioResponse(BaseModel):
    scenario_id: str
    title: str
    description: str
    mapped_research_questions: list[str]
    expected_safe_result: str
    expected_hawk_decision: str
    expected_findings: list[str]
    threat_classes: list[str]
    involved_agents: list[str]
    involved_tools: list[str]
    involved_fake_saas_systems: list[str]
    expected_evidence_fields: list[str]
    expected_graph_nodes: list[str]
    expected_graph_edges: list[str]


class AgenticChainScenarioListResponse(BaseModel):
    items: list[AgenticChainScenarioResponse]
    total: int
    defense_modes: list[str]


class AgenticChainRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str | None = None
    defense_mode: str = "hawk_chain_integrity"
    run_all: bool = False


class AgenticChainRunResponse(BaseModel):
    total_runs: int
    reports: list[dict]
    metrics: dict
    persistence: dict = Field(default_factory=dict)


@router.get("/templates", response_model=ListEnvelope[SimulationTemplateResponse])
def list_templates(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(select(SimulationTemplate).where(SimulationTemplate.tenant_id == ctx.tenant.id)).all()
    dto_rows = [SimulationTemplateResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[SimulationTemplateResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/agentic-chain-integrity/scenarios", response_model=AgenticChainScenarioListResponse)
def list_agentic_chain_integrity_scenarios(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
):
    del ctx
    return AgenticChainScenarioListResponse(
        items=[AgenticChainScenarioResponse(**scenario.__dict__) for scenario in SCENARIOS],
        total=len(SCENARIOS),
        defense_modes=list(DEFENSE_MODES),
    )


@router.post("/agentic-chain-integrity/run", response_model=AgenticChainRunResponse)
def run_agentic_chain_integrity_validation(
    payload: AgenticChainRunRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    try:
        if payload.run_all:
            reports = run_scenario_library()
        else:
            if not payload.scenario_id:
                raise ValueError("scenario_id is required unless run_all=true")
            reports = [run_scenario(payload.scenario_id, payload.defense_mode)]  # type: ignore[arg-type]
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    persistence = persist_chain_integrity_reports(db, tenant_id=ctx.tenant.id, reports=reports)
    db.commit()
    return AgenticChainRunResponse(
        total_runs=len(reports),
        reports=[report.model_dump() if isinstance(report, ChainIntegrityReport) else dict(report) for report in reports],
        metrics=calculate_metrics(reports),
        persistence=persistence,
    )


@router.get("/agentic-chain-integrity/metrics")
def agentic_chain_integrity_metrics(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
):
    del ctx
    reports = run_scenario_library()
    return calculate_metrics(reports)


@router.post("/templates", response_model=SimulationTemplateResponse)
def create_simulation_template(
    payload: SimulationTemplateCreate,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    row = create_template(
        db,
        tenant_id=ctx.tenant.id,
        name=payload.name,
        description=payload.description,
        status=payload.status,
        category=payload.category,
        target_module=payload.target_module,
        version_prefix=payload.version_prefix,
        parameter_schema=payload.parameter_schema,
        template_body=payload.template_body,
        generation_defaults=payload.generation_defaults,
    )

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="simulation.template.create",
        resource_type="simulation_template",
        resource_id=row.id,
        payload={"name": row.name, "status": row.status},
    )
    db.commit()
    db.refresh(row)
    return SimulationTemplateResponse.model_validate(row)


@router.post("/templates/{template_id}/generate", response_model=SimulationTemplateGenerateResponse)
def generate_simulation_definitions(
    template_id: str,
    payload: SimulationTemplateGenerateRequest,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(SimulationTemplate).where(
            SimulationTemplate.id == template_id,
            SimulationTemplate.tenant_id == ctx.tenant.id,
        )
    )
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Simulation template not found")

    try:
        generated = generate_from_template(
            db,
            tenant_id=ctx.tenant.id,
            template=row,
            count=payload.count,
            parameter_sets=payload.parameter_sets,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="simulation.template.generate",
        resource_type="simulation_template",
        resource_id=row.id,
        payload={"count": payload.count, "generated_count": len(generated)},
    )

    db.commit()
    for item in generated:
        db.refresh(item)
    return SimulationTemplateGenerateResponse(
        template_id=row.id,
        generated=[SimulationDefinitionResponse.model_validate(item) for item in generated],
        total_generated=len(generated),
    )


@router.post("/catalog/bootstrap-rfp")
def bootstrap_rfp_catalog(
    payload: SimulationCatalogBootstrapRequest,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    try:
        summary = bootstrap_rfp_simulation_catalog(
            db,
            tenant_id=ctx.tenant.id,
            per_category_target=payload.per_category_target,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="simulation.catalog.bootstrap_rfp",
        resource_type="simulation_catalog",
        resource_id=ctx.tenant.id,
        payload={
            "per_category_target": payload.per_category_target,
            "generated_total": int((summary.get("bootstrap") or {}).get("generated_total") or 0),
        },
    )
    db.commit()
    return summary


@router.post("/catalog/bootstrap-initial-real-seed-pack")
def bootstrap_initial_real_seed_pack(
    payload: SimulationSeedPackBootstrapRequest,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    summary = bootstrap_initial_real_seed_simulations(
        db,
        tenant_id=ctx.tenant.id,
        update_existing=bool(payload.update_existing),
    )
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="simulation.catalog.bootstrap_initial_real_seed_pack",
        resource_type="simulation_catalog",
        resource_id=ctx.tenant.id,
        payload={
            "update_existing": bool(payload.update_existing),
            "created": int(summary.get("created") or 0),
            "updated": int(summary.get("updated") or 0),
            "defined_total": int(summary.get("defined_total") or 0),
        },
    )
    db.commit()
    return summary


@router.get("/packs", response_model=ListEnvelope[SimulationPackResponse])
def list_simulation_packs(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    metadata_rows = {str(row["pack_id"]): row for row in list_pack_definitions()}
    coverage_rows = get_pack_coverage(db, tenant_id=ctx.tenant.id)
    merged: list[SimulationPackResponse] = []
    for row in coverage_rows:
        pack_id = str(row.get("pack_id") or "")
        meta = metadata_rows.get(pack_id, {})
        merged.append(
            SimulationPackResponse(
                pack_id=pack_id,
                name=str(row.get("name") or meta.get("name") or pack_id),
                description=str(row.get("description") or meta.get("description") or ""),
                categories=[str(item) for item in (row.get("categories") or meta.get("categories") or [])],
                trigger_reason_codes=[str(item) for item in (row.get("trigger_reason_codes") or meta.get("trigger_reason_codes") or [])],
                simulation_count=int(row.get("simulation_count") or 0),
                run_count=int(row.get("run_count") or 0),
                pass_rate=float(row.get("pass_rate") or 0.0),
                latest_run_at=row.get("latest_run_at"),
                target_ready=bool(row.get("target_ready")),
            )
        )
    page_items, total, safe_page, safe_page_size = paginate_rows(merged, page=page, page_size=page_size)
    return ListEnvelope[SimulationPackResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.post(
    "/packs/{pack_id}/run",
    response_model=SimulationPackRunResponse,
    dependencies=[
        Depends(
            governance_payload_dependency(
                action="simulations.run",
                route="/simulations/packs/{pack_id}/run",
                module="simulations",
            )
        )
    ],
)
def run_simulation_pack(
    pack_id: str,
    payload: SimulationPackRunRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    pack = get_pack_definition(pack_id)
    if pack is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Simulation pack not found")

    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="simulations",
        ai_system_id=payload.ai_system_id,
        request_id=f"simulation.pack.run:{pack.pack_id}",
    )

    try:
        summary = execute_pack(
            db,
            tenant_id=ctx.tenant.id,
            pack_id=pack.pack_id,
            ai_system_id=payload.ai_system_id,
            mode=payload.mode,
            stochastic_runs=payload.stochastic_runs,
            inputs_used=payload.inputs_used,
            actor_user_id=None,
            max_definitions=payload.max_definitions,
            target_control_ids=payload.target_control_ids,
            execution_environment=str(payload.execution_environment or "sandbox"),
            approval_granted=bool(payload.approval_granted),
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except GovernanceViolationError as exc:
        db.rollback()
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": "governance_context_blocked", "reason_code": exc.reason_code, "message": exc.message},
        ) from exc
    except GovernanceFailSecureError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "governance_fail_secure", "reason_code": exc.reason_code, "message": exc.message},
        ) from exc

    db.commit()
    return SimulationPackRunResponse.model_validate(summary)


@router.get("/coverage/summary")
def simulation_coverage_summary(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    return get_simulation_coverage_summary(
        db,
        tenant_id=ctx.tenant.id,
    )


@router.get("/coverage/heatmap")
def simulation_coverage_heatmap(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    return get_simulation_heatmap(
        db,
        tenant_id=ctx.tenant.id,
    )


@router.get("/coverage/trends")
def simulation_coverage_trends(
    lookback_days: int = 14,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    return get_simulation_trends(
        db,
        tenant_id=ctx.tenant.id,
        lookback_days=lookback_days,
    )


def _ensure_controls_exist(db: Session, *, tenant_id: str, control_ids: list[str]) -> None:
    ensure_canonical_controls(db, tenant_id=tenant_id)
    normalized_control_ids = normalize_control_ids(control_ids)
    if not normalized_control_ids:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="maps_to_controls cannot be empty")

    rows = db.scalars(
        select(Control).where(
            Control.id.in_(normalized_control_ids),
            Control.tenant_id == tenant_id,
        )
    ).all()
    found = {row.id for row in rows}
    missing = [control_id for control_id in normalized_control_ids if control_id not in found]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown control ids in maps_to_controls: {', '.join(missing)}",
        )


@router.get("/controls", response_model=ListEnvelope[ControlResponse])
def list_controls(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    persist_tenant_canonical_controls(db, tenant_id=ctx.tenant.id)
    rows = db.scalars(select(Control).where(Control.tenant_id == ctx.tenant.id)).all()
    dto_rows = [ControlResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[ControlResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.post("/controls", response_model=ControlResponse)
def create_control(
    payload: ControlCreate,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    if payload.is_global:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Tenant administrators cannot create global controls",
        )
    row = Control(
        id=payload.id,
        tenant_id=ctx.tenant.id,
        is_global=False,
        name=payload.name,
        category=payload.category,
        description=payload.description,
        mapped_framework_refs=payload.mapped_framework_refs,
        risk_tags=payload.risk_tags,
        severity=payload.severity,
        enforcement_points=payload.enforcement_points,
        detection_methods=payload.detection_methods,
        response_actions=payload.response_actions,
        evidence_types=payload.evidence_types,
        remediation_templates=payload.remediation_templates,
        success_criteria=payload.success_criteria,
    )
    db.add(row)
    db.flush()

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="simulation.control.create",
        resource_type="control",
        resource_id=row.id,
        payload={"is_global": row.is_global},
    )
    db.commit()
    db.refresh(row)
    return ControlResponse.model_validate(row)


@router.get("/controls/traceability", response_model=ListEnvelope[dict])
def control_traceability(
    ai_system_id: str,
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    try:
        rows = get_control_traceability(
            db,
            tenant_id=ctx.tenant.id,
            ai_system_id=ai_system_id,
        )
        page_items, total, safe_page, safe_page_size = paginate_rows(rows, page=page, page_size=page_size)
        return ListEnvelope[dict](
            items=page_items,
            total=total,
            page=safe_page,
            page_size=safe_page_size,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/definitions", response_model=ListEnvelope[SimulationDefinitionResponse])
def list_definitions(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(select(SimulationDefinition).where(SimulationDefinition.tenant_id == ctx.tenant.id)).all()
    dto_rows = [SimulationDefinitionResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[SimulationDefinitionResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.post("/definitions", response_model=SimulationDefinitionResponse)
def create_definition(
    payload: SimulationDefCreate,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    try:
        normalized_dsl = validate_and_normalize_simulation_dsl(
            dsl_json=payload.dsl_json,
            tenant_id=ctx.tenant.id,
            simulation_id=None,
            name=payload.name,
            category=payload.category,
            target_module=payload.target_module,
            version=payload.version,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    _ensure_controls_exist(db, tenant_id=ctx.tenant.id, control_ids=normalized_dsl["maps_to_controls"])

    row = SimulationDefinition(
        tenant_id=ctx.tenant.id,
        name=payload.name,
        category=payload.category,
        target_module=payload.target_module,
        version=payload.version,
        dsl_json=normalized_dsl,
    )
    db.add(row)
    db.flush()

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="simulation.definition.create",
        resource_type="simulation_definition",
        resource_id=row.id,
        payload={
            "name": row.name,
            "category": row.category,
            "maps_to_controls": normalized_dsl.get("maps_to_controls", []),
        },
    )

    db.commit()
    db.refresh(row)
    return SimulationDefinitionResponse.model_validate(row)


@router.patch("/definitions/{simulation_id}", response_model=SimulationDefinitionResponse)
def update_definition(
    simulation_id: str,
    payload: SimulationDefUpdate,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(SimulationDefinition).where(
            SimulationDefinition.id == simulation_id,
            SimulationDefinition.tenant_id == ctx.tenant.id,
        )
    )
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Simulation definition not found")

    name = payload.name or row.name
    category = payload.category or row.category
    target_module = payload.target_module or row.target_module
    version = payload.version or row.version
    dsl_source = payload.dsl_json if payload.dsl_json is not None else row.dsl_json
    dsl_id = str((dsl_source or {}).get("id") or (row.dsl_json or {}).get("id") or simulation_id)

    try:
        normalized_dsl = validate_and_normalize_simulation_dsl(
            dsl_json=dsl_source,
            tenant_id=ctx.tenant.id,
            simulation_id=dsl_id,
            name=name,
            category=category,
            target_module=target_module,
            version=version,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    _ensure_controls_exist(db, tenant_id=ctx.tenant.id, control_ids=normalized_dsl["maps_to_controls"])

    row.name = name
    row.category = category
    row.target_module = target_module
    row.version = version
    row.dsl_json = normalized_dsl

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="simulation.definition.update",
        resource_type="simulation_definition",
        resource_id=row.id,
        payload={
            "name": row.name,
            "category": row.category,
            "target_module": row.target_module,
            "version": row.version,
            "maps_to_controls": normalized_dsl.get("maps_to_controls", []),
        },
    )

    db.commit()
    db.refresh(row)
    return SimulationDefinitionResponse.model_validate(row)


@router.post(
    "/definitions/{simulation_id}/run",
    response_model=SimulationRunResponse,
    dependencies=[
        Depends(
            governance_payload_dependency(
                action="simulations.run",
                route="/simulations/definitions/{simulation_id}/run",
                module="simulations",
            )
        )
    ],
)
def run_definition(
    simulation_id: str,
    payload: SimulationRunRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="simulations",
        ai_system_id=payload.ai_system_id,
        request_id=f"simulation.run:{simulation_id}",
    )
    sim = db.scalar(
        select(SimulationDefinition).where(
            SimulationDefinition.id == simulation_id,
            SimulationDefinition.tenant_id == ctx.tenant.id,
        )
    )
    if not sim:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Simulation definition not found")

    try:
        run = run_simulation(
            db,
            tenant_id=ctx.tenant.id,
            simulation=sim,
            ai_system_id=payload.ai_system_id,
            mode=payload.mode,
            stochastic_runs=payload.stochastic_runs,
            inputs_used=payload.inputs_used,
            actor_user_id=None,
            live_session_id=payload.live_session_id,
            execution_mode="manual",
            execution_environment=str(payload.execution_environment or (payload.inputs_used or {}).get("execution_environment") or "sandbox"),
            approval_granted=bool(payload.approval_granted),
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except GovernanceViolationError as exc:
        db.rollback()
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": "governance_context_blocked", "reason_code": exc.reason_code, "message": exc.message},
        ) from exc
    except GovernanceFailSecureError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "governance_fail_secure", "reason_code": exc.reason_code, "message": exc.message},
        ) from exc

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="simulation.run",
        resource_type="simulation_run",
        resource_id=run.id,
        payload={
            "simulation_id": simulation_id,
            "result": run.results.get("result"),
            "pass_rate": run.results.get("pass_rate"),
            "iterations": run.results.get("iterations"),
        },
    )

    db.commit()
    db.refresh(run)
    return SimulationRunResponse.model_validate(run)


@router.get("/runs/stream")
def stream_simulation_runs(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
):
    return _simulation_stream_response(tenant_id=ctx.tenant.id)


@router.get("/runs", response_model=ListEnvelope[SimulationRunResponse])
def list_runs(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(select(SimulationRun).where(SimulationRun.tenant_id == ctx.tenant.id).order_by(SimulationRun.started_at.desc())).all()
    dto_rows = [SimulationRunResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[SimulationRunResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/runs/{run_id}/trace", response_model=SimulationRunTraceResponse)
def get_run_trace(
    run_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    try:
        payload = get_simulation_run_trace(db, tenant_id=ctx.tenant.id, run_id=run_id)
        return SimulationRunTraceResponse.model_validate(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
