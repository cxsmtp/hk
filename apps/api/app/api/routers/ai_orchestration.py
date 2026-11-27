from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.ai_iam import AgentIdentity
from app.db.models.ai_orchestration import AIReasoningTrace
from app.db.models.ai_system import AISystem
from app.db.models.finding import Finding
from app.db.models.monitoring import DriftAlert
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.runtime_intelligence import RuntimePattern
from app.db.models.simulation import SimulationDefinition, SimulationRun
from app.db.models.shadow_ai import ShadowAIEntity
from app.db.models.user import User
from app.db.session import get_db
from app.services.ai_orchestration.itsm import build_ticket_payload, create_ticket
from app.services.ai_orchestration.remediation_guidance_service import generate_remediation_guidance
from app.services.ai_orchestration.schemas import OrchestrationResult, OrchestrationTaskRequest, TaskType
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node
from app.services.action_integrity.execution_authority import install_generic_seam_authority, invoke_final_seam
from app.services.action_integrity.canonical_v2 import domain_hash


router = APIRouter(prefix="/ai-orchestration", tags=["ai-orchestration"])


class GuidanceOverrides(BaseModel):
    task_type: TaskType = "remediation_guidance"
    data_sensitivity: str = "internal"
    customer_region: str = "global"
    region_requirement: str = "global"
    residency_requirement: str = ""
    residency_required: bool = False
    cost_ceiling_usd: float = Field(default=0.25, ge=0.0)
    customer_policy_profile: dict[str, Any] = Field(default_factory=dict)
    policy_version: str = ""
    governance_version: str = ""
    allowed_remediation_types: list[str] = Field(default_factory=list)
    context_payload: dict[str, Any] = Field(default_factory=dict)
    route_policy_overrides: dict[str, Any] = Field(default_factory=dict)


class GenericGuidanceRequest(BaseModel):
    task: OrchestrationTaskRequest


class TraceResponse(BaseModel):
    id: str
    tenant_id: str
    control_id: str
    issue_type: str
    issue_id: str
    task_type: str
    provider: str
    model: str
    model_version: str
    prompt_template_id: str
    prompt_template_version: str
    prompt_template_status: str
    prompt_variables_json: dict
    retrieval_refs_json: list
    retrieval_source_ids_json: list
    evidence_refs_json: list
    runtime_event_refs_json: list
    policy_version: str
    governance_version: str
    control_decision_json: dict
    simulation_result_json: dict
    routing_context_json: dict
    risk_context_json: dict
    remediation_impact_json: dict
    routing_policy_id: str
    policy_route_id: str
    region_route: str
    pre_call_guard_results_json: dict
    post_call_guard_results_json: dict
    output_schema_valid: bool
    token_usage_json: dict
    cost_estimate_usd: float
    status: str
    output_json: dict
    rejection_reason: str | None = None
    correlation_id: str | None = None


class TicketPayloadRequest(BaseModel):
    system: str = "jira"


class TicketPayloadResponse(BaseModel):
    system: str
    title: str
    severity: str
    description: str
    trace_id: str
    issue_type: str
    issue_id: str
    provider: str
    model: str
    routing_policy_id: str
    policy_route_id: str


class TicketCreateResponse(TicketPayloadResponse):
    status: str
    ticket_id: str
    external_url: str = ""
    error: str = ""
    created_externally: bool = False
    audit_log_id: str | None = None
    evidence_node_id: str | None = None


def _with_default_task_type(payload: GuidanceOverrides | None, default_task_type: TaskType) -> GuidanceOverrides:
    if payload is None:
        return GuidanceOverrides(task_type=default_task_type)
    if "task_type" not in payload.model_fields_set:
        return payload.model_copy(update={"task_type": default_task_type})
    return payload


def _map_data_sensitivity(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"public", "internal", "sensitive", "restricted"}:
        return normalized
    if normalized in {"pii", "protected", "confidential"}:
        return "sensitive"
    return "internal"


_SENSITIVITY_RANK = {"public": 0, "internal": 1, "sensitive": 2, "restricted": 3}


def _recorded_floor(requested: str | None, recorded: Any) -> str:
    """The data sensitivity a task is routed with: what the caller asks for, never below what is recorded for the
    finding or system. ``requested`` defaults to "internal", so ``requested or recorded`` sent a restricted finding
    to the providers allowed for internal data, and a caller could lower it on purpose."""

    asked = _map_data_sensitivity(requested)
    if recorded is None or not str(recorded).strip():
        return asked
    kept = _map_data_sensitivity(str(recorded))
    return asked if _SENSITIVITY_RANK[asked] >= _SENSITIVITY_RANK[kept] else kept


def _severity_from_risk_tier(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"critical", "restricted", "prohibited"}:
        return "critical"
    if normalized in {"high"}:
        return "high"
    if normalized in {"medium", "med"}:
        return "med"
    if normalized in {"low", "minimal", "limited"}:
        return "low"
    return "med"


def _default_control_for_issue(issue_type: str) -> str:
    mapping = {
        "finding": "POLICY_ENFORCEMENT_CONTROL",
        "simulation_run": "POLICY_ENFORCEMENT_CONTROL",
        "drift_alert": "PRIVILEGE_DRIFT_DETECTION",
        "runtime_pattern": "POLICY_ENFORCEMENT_CONTROL",
        "ai_system": "AI_SYSTEM_INVENTORY_CONTROL",
        "agent_identity": "AGENT_ACTION_AUTHORIZATION",
        "shadow_ai_entity": "SHADOW_AI_DETECTION",
    }
    return mapping.get(str(issue_type or "").strip().lower(), "POLICY_ENFORCEMENT_CONTROL")


def _finding_task(
    *,
    row: Finding,
    overrides: GuidanceOverrides,
) -> OrchestrationTaskRequest:
    summary = row.recommended_action or f"Finding {row.finding_type} on {row.ai_tool}"
    related_controls = [str(item) for item in (row.related_control_ids or []) if str(item).strip()]
    return OrchestrationTaskRequest(
        task_type=overrides.task_type,  # type: ignore[arg-type]
        control_id=(related_controls[0] if related_controls else _default_control_for_issue("finding")),
        issue_type="finding",
        issue_id=row.finding_id,
        issue_title=f"{row.finding_type}:{row.ai_tool}",
        issue_summary=summary,
        severity=row.severity,
        risk_tier=row.severity,
        data_sensitivity=_recorded_floor(overrides.data_sensitivity, row.data_classification),
        customer_region=overrides.customer_region,
        region_requirement=overrides.region_requirement or overrides.customer_region,
        residency_requirement=overrides.residency_requirement,
        residency_required=overrides.residency_required,
        cost_ceiling_usd=overrides.cost_ceiling_usd,
        customer_policy_profile=dict(overrides.customer_policy_profile or {}),
        policy_version=overrides.policy_version,
        governance_version=overrides.governance_version,
        evidence_refs=[str(item) for item in (row.evidence_node_ids or []) if str(item).strip()],
        runtime_event_refs=[],
        current_controls=related_controls,
        governance_state=row.status,
        allowed_remediation_types=list(overrides.allowed_remediation_types),
        context_payload={
            **dict(overrides.context_payload or {}),
            "ai_system_id": row.ai_system_id,
            "source_surface": row.source_surface,
            "risk_category": row.risk_category,
        },
        route_policy_overrides=overrides.route_policy_overrides,
    )


def _simulation_task(
    *,
    run: SimulationRun,
    definition: SimulationDefinition | None,
    overrides: GuidanceOverrides,
) -> OrchestrationTaskRequest:
    result = str((run.results or {}).get("final_outcome") or (run.results or {}).get("result") or "unknown").lower()
    severity = "high" if result in {"fail", "partial"} else "med"
    evidence_refs = [str(item) for item in ((run.results or {}).get("evidence_node_ids") or []) if str(item).strip()]
    summary = str((run.results or {}).get("summary") or run.notes or "")
    controls_impacted = [
        str(item.get("control_id"))
        for item in (run.controls_impacted or [])
        if isinstance(item, dict) and str(item.get("control_id") or "").strip()
    ]
    return OrchestrationTaskRequest(
        task_type=overrides.task_type,  # type: ignore[arg-type]
        control_id=(controls_impacted[0] if controls_impacted else _default_control_for_issue("simulation_run")),
        issue_type="simulation_run",
        issue_id=run.id,
        issue_title=definition.name if definition else f"Simulation {run.simulation_id}",
        issue_summary=summary,
        severity=severity,
        risk_tier=severity,
        data_sensitivity=_map_data_sensitivity(overrides.data_sensitivity),
        customer_region=overrides.customer_region,
        region_requirement=overrides.region_requirement or overrides.customer_region,
        residency_requirement=overrides.residency_requirement,
        residency_required=overrides.residency_required,
        cost_ceiling_usd=overrides.cost_ceiling_usd,
        customer_policy_profile=dict(overrides.customer_policy_profile or {}),
        policy_version=overrides.policy_version,
        governance_version=overrides.governance_version,
        evidence_refs=evidence_refs,
        runtime_event_refs=[],
        simulation_result=dict(run.results or {}),
        current_controls=controls_impacted,
        governance_state="open" if severity in {"high", "critical"} else "monitor",
        allowed_remediation_types=list(overrides.allowed_remediation_types),
        context_payload={
            **dict(overrides.context_payload or {}),
            "ai_system_id": run.ai_system_id,
            "mode": run.mode,
            "simulation_definition_id": run.simulation_id,
            "result": result,
        },
        route_policy_overrides=overrides.route_policy_overrides,
    )


def _drift_task(
    *,
    row: DriftAlert,
    overrides: GuidanceOverrides,
) -> OrchestrationTaskRequest:
    severity = "high" if row.status in {"open", "critical"} else "med"
    return OrchestrationTaskRequest(
        task_type=overrides.task_type,  # type: ignore[arg-type]
        control_id=_default_control_for_issue("drift_alert"),
        issue_type="drift_alert",
        issue_id=row.id,
        issue_title=row.title,
        issue_summary=row.details,
        severity=severity,
        risk_tier=severity,
        data_sensitivity=_map_data_sensitivity(overrides.data_sensitivity),
        customer_region=overrides.customer_region,
        region_requirement=overrides.region_requirement or overrides.customer_region,
        residency_requirement=overrides.residency_requirement,
        residency_required=overrides.residency_required,
        cost_ceiling_usd=overrides.cost_ceiling_usd,
        customer_policy_profile=dict(overrides.customer_policy_profile or {}),
        policy_version=overrides.policy_version,
        governance_version=overrides.governance_version,
        evidence_refs=[],
        runtime_event_refs=[],
        current_controls=[],
        governance_state=row.status,
        allowed_remediation_types=list(overrides.allowed_remediation_types),
        context_payload={
            **dict(overrides.context_payload or {}),
            "ai_system_id": row.ai_system_id,
            "status": row.status,
        },
        route_policy_overrides=overrides.route_policy_overrides,
    )


def _pattern_task(
    *,
    row: RuntimePattern,
    overrides: GuidanceOverrides,
) -> OrchestrationTaskRequest:
    severity = str(row.severity or "med").lower()
    summary = f"Pattern type={row.type}, frequency={row.frequency}, affected_entities={len(row.affected_entities or [])}"
    return OrchestrationTaskRequest(
        task_type=overrides.task_type,  # type: ignore[arg-type]
        control_id=_default_control_for_issue("runtime_pattern"),
        issue_type="runtime_pattern",
        issue_id=row.pattern_id,
        issue_title=row.type,
        issue_summary=summary,
        severity=severity,
        risk_tier=severity,
        data_sensitivity=_map_data_sensitivity(overrides.data_sensitivity),
        customer_region=overrides.customer_region,
        region_requirement=overrides.region_requirement or overrides.customer_region,
        residency_requirement=overrides.residency_requirement,
        residency_required=overrides.residency_required,
        cost_ceiling_usd=overrides.cost_ceiling_usd,
        customer_policy_profile=dict(overrides.customer_policy_profile or {}),
        policy_version=overrides.policy_version,
        governance_version=overrides.governance_version,
        evidence_refs=[],
        runtime_event_refs=[],
        current_controls=[],
        governance_state="open",
        allowed_remediation_types=list(overrides.allowed_remediation_types),
        context_payload={
            **dict(overrides.context_payload or {}),
            "pattern_type": row.type,
            "frequency": row.frequency,
            "affected_entities": row.affected_entities,
        },
        route_policy_overrides=overrides.route_policy_overrides,
    )


def _ai_system_task(
    *,
    row: AISystem,
    findings: list[Finding],
    overrides: GuidanceOverrides,
) -> OrchestrationTaskRequest:
    metadata = dict(row.metadata_json or {})
    controls = {
        *(str(item).strip() for item in (metadata.get("related_control_ids") or []) if str(item).strip()),
        *(
            str(item).strip()
            for finding in findings
            for item in (finding.related_control_ids or [])
            if str(item).strip()
        ),
    }
    evidence_refs = {
        *(str(item).strip() for item in (metadata.get("evidence_node_ids") or []) if str(item).strip()),
        *(
            str(item).strip()
            for finding in findings
            for item in (finding.evidence_node_ids or [])
            if str(item).strip()
        ),
    }
    frameworks = [str(item) for item in (metadata.get("framework_refs") or []) if str(item).strip()]
    open_findings = len([f for f in findings if str(f.status or "").lower() == "open"])
    summary = (
        f"AI system '{row.name}' governance review. "
        f"status={row.status}, risk_tier={row.risk_tier}, open_findings={open_findings}, total_findings={len(findings)}."
    )
    return OrchestrationTaskRequest(
        task_type=overrides.task_type,  # type: ignore[arg-type]
        control_id=(sorted(controls)[0] if controls else _default_control_for_issue("ai_system")),
        issue_type="ai_system",
        issue_id=row.id,
        issue_title=row.name,
        issue_summary=summary,
        severity=_severity_from_risk_tier(row.risk_tier),
        risk_tier=str(row.risk_tier or "medium"),
        data_sensitivity=_recorded_floor(overrides.data_sensitivity, metadata.get("data_sensitivity")),
        customer_region=overrides.customer_region,
        region_requirement=overrides.region_requirement or overrides.customer_region,
        residency_requirement=overrides.residency_requirement,
        residency_required=overrides.residency_required,
        cost_ceiling_usd=overrides.cost_ceiling_usd,
        customer_policy_profile=dict(overrides.customer_policy_profile or {}),
        policy_version=overrides.policy_version,
        governance_version=overrides.governance_version,
        evidence_refs=sorted(evidence_refs),
        runtime_event_refs=[],
        current_controls=sorted(controls),
        governance_state=str(row.status or "unknown").lower(),
        allowed_remediation_types=list(overrides.allowed_remediation_types),
        framework_refs=frameworks,
        context_payload={
            **dict(overrides.context_payload or {}),
            "ai_system_id": row.id,
            "description": row.description,
            "metadata": metadata,
            "open_findings": open_findings,
            "total_findings": len(findings),
        },
        route_policy_overrides=overrides.route_policy_overrides,
    )


def _agent_task(
    *,
    row: AgentIdentity,
    recent_events: list[RuntimeEvent],
    overrides: GuidanceOverrides,
) -> OrchestrationTaskRequest:
    evidence_refs = {
        str(item).strip()
        for event in recent_events
        for item in (event.evidence_node_ids or [])
        if str(item).strip()
    }
    high_risk_events = len([event for event in recent_events if float(event.risk_score or 0.0) >= 0.67])
    blocked_events = len(
        [
            event
            for event in recent_events
            if str((event.metadata_json or {}).get("decision") or "").strip().lower() in {"block", "deny", "denied"}
        ]
    )
    summary = (
        f"Agent '{row.name}' IAM remediation review. "
        f"status={row.status}, max_chain_depth={row.max_chain_depth}, "
        f"recent_events={len(recent_events)}, high_risk_events={high_risk_events}, blocked_events={blocked_events}."
    )
    return OrchestrationTaskRequest(
        task_type=overrides.task_type,  # type: ignore[arg-type]
        control_id=_default_control_for_issue("agent_identity"),
        issue_type="agent_identity",
        issue_id=row.id,
        issue_title=row.name,
        issue_summary=summary,
        severity="high" if high_risk_events > 0 else "med",
        risk_tier="high" if high_risk_events > 0 else "medium",
        data_sensitivity=_map_data_sensitivity(overrides.data_sensitivity),
        customer_region=overrides.customer_region,
        region_requirement=overrides.region_requirement or overrides.customer_region,
        residency_requirement=overrides.residency_requirement,
        residency_required=overrides.residency_required,
        cost_ceiling_usd=overrides.cost_ceiling_usd,
        customer_policy_profile=dict(overrides.customer_policy_profile or {}),
        policy_version=overrides.policy_version,
        governance_version=overrides.governance_version,
        evidence_refs=sorted(evidence_refs),
        runtime_event_refs=[str(event.event_id) for event in recent_events if str(event.event_id).strip()],
        current_controls=[
            "ai_iam.action_scope",
            "ai_iam.tool_allowlist",
            "ai_iam.chain_depth_guard",
            "ai_iam.kill_switch",
        ],
        governance_state=str(row.status or "unknown").lower(),
        allowed_remediation_types=list(overrides.allowed_remediation_types),
        context_payload={
            **dict(overrides.context_payload or {}),
            "agent_id": row.id,
            "agent_type": row.agent_type,
            "autonomy_level": row.autonomy_level,
            "max_chain_depth": row.max_chain_depth,
            "action_scope": list(row.action_scope or []),
            "tool_registry": list(row.tool_registry or []),
            "recent_event_count": len(recent_events),
            "recent_high_risk_count": high_risk_events,
            "recent_blocked_count": blocked_events,
        },
        route_policy_overrides=overrides.route_policy_overrides,
    )


def _shadow_entity_task(
    *,
    row: ShadowAIEntity,
    overrides: GuidanceOverrides,
) -> OrchestrationTaskRequest:
    metadata = dict(row.metadata_json or {})
    summary = (
        f"Shadow AI governance escalation for '{row.canonical_name}'. "
        f"status={row.discovery_status}, confidence={row.confidence_score:.2f}, risk_score={row.risk_score:.2f}, "
        f"approved_status={row.approved_status}, usage_count={row.usage_count}."
    )
    return OrchestrationTaskRequest(
        task_type=overrides.task_type,  # type: ignore[arg-type]
        control_id=_default_control_for_issue("shadow_ai_entity"),
        issue_type="shadow_ai_entity",
        issue_id=row.id,
        issue_title=row.canonical_name,
        issue_summary=summary,
        severity=_severity_from_risk_tier(row.provisional_risk_tier or "medium"),
        risk_tier=str(row.provisional_risk_tier or "medium"),
        data_sensitivity=_recorded_floor(overrides.data_sensitivity, metadata.get("data_sensitivity")),
        customer_region=overrides.customer_region,
        region_requirement=overrides.region_requirement or overrides.customer_region,
        residency_requirement=overrides.residency_requirement,
        residency_required=overrides.residency_required,
        cost_ceiling_usd=overrides.cost_ceiling_usd,
        customer_policy_profile=dict(overrides.customer_policy_profile or {}),
        policy_version=overrides.policy_version,
        governance_version=overrides.governance_version,
        evidence_refs=[str(item) for item in (metadata.get("evidence_node_ids") or []) if str(item).strip()],
        runtime_event_refs=[],
        current_controls=[str(item) for item in (metadata.get("related_control_ids") or []) if str(item).strip()],
        governance_state=str(row.discovery_status or "discovered").lower(),
        allowed_remediation_types=list(overrides.allowed_remediation_types),
        framework_refs=[str(item) for item in (metadata.get("framework_refs") or []) if str(item).strip()],
        context_payload={
            **dict(overrides.context_payload or {}),
            "shadow_ai_entity_id": row.id,
            "source_surfaces": list(row.source_surfaces or []),
            "vendor": row.vendor,
            "deployment_type": row.deployment_type,
            "ai_type": row.ai_type,
            "approved_status": row.approved_status,
            "linked_ai_system_id": row.linked_ai_system_id,
        },
        route_policy_overrides=overrides.route_policy_overrides,
    )


@router.post("/reason", response_model=OrchestrationResult)
def orchestrate_generic_reasoning(
    payload: GenericGuidanceRequest,
    ctx: TenantContext = Depends(require_permission("assistant.operate")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    result = generate_remediation_guidance(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        task=payload.task,
        correlation_id=None,
    )
    db.commit()
    return result


@router.post("/findings/{finding_id}/remediation-guidance", response_model=OrchestrationResult)
def generate_finding_guidance(
    finding_id: str,
    payload: GuidanceOverrides | None = None,
    ctx: TenantContext = Depends(require_permission("assistant.operate")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(Finding).where(
            Finding.finding_id == finding_id,
            Finding.tenant_id == ctx.tenant.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    overrides = payload or GuidanceOverrides()
    task = _finding_task(row=row, overrides=overrides)
    result = generate_remediation_guidance(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        task=task,
        correlation_id=None,
    )
    db.commit()
    return result


@router.post("/simulations/{run_id}/remediation-guidance", response_model=OrchestrationResult)
def generate_simulation_guidance(
    run_id: str,
    payload: GuidanceOverrides | None = None,
    ctx: TenantContext = Depends(require_permission("assistant.operate")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    run = db.scalar(
        select(SimulationRun).where(
            SimulationRun.id == run_id,
            SimulationRun.tenant_id == ctx.tenant.id,
        )
    )
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Simulation run not found")

    definition = db.scalar(
        select(SimulationDefinition).where(
            SimulationDefinition.id == run.simulation_id,
            SimulationDefinition.tenant_id == ctx.tenant.id,
        )
    )
    overrides = _with_default_task_type(payload, "simulation_failure_explanation")
    task = _simulation_task(run=run, definition=definition, overrides=overrides)
    result = generate_remediation_guidance(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        task=task,
        correlation_id=run.correlation_id,
    )
    db.commit()
    return result


@router.post("/drift-alerts/{alert_id}/remediation-guidance", response_model=OrchestrationResult)
def generate_drift_guidance(
    alert_id: str,
    payload: GuidanceOverrides | None = None,
    ctx: TenantContext = Depends(require_permission("assistant.operate")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(DriftAlert).where(
            DriftAlert.id == alert_id,
            DriftAlert.tenant_id == ctx.tenant.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Drift alert not found")

    overrides = _with_default_task_type(payload, "drift_explanation")
    task = _drift_task(row=row, overrides=overrides)
    result = generate_remediation_guidance(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        task=task,
        correlation_id=None,
    )
    db.commit()
    return result


@router.post("/runtime-patterns/{pattern_id}/remediation-guidance", response_model=OrchestrationResult)
def generate_pattern_guidance(
    pattern_id: str,
    payload: GuidanceOverrides | None = None,
    ctx: TenantContext = Depends(require_permission("assistant.operate")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(RuntimePattern).where(
            RuntimePattern.pattern_id == pattern_id,
            RuntimePattern.tenant_id == ctx.tenant.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Runtime pattern not found")

    overrides = _with_default_task_type(payload, "control_gap_analysis")
    task = _pattern_task(row=row, overrides=overrides)
    result = generate_remediation_guidance(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        task=task,
        correlation_id=None,
    )
    db.commit()
    return result


@router.post("/ai-systems/{ai_system_id}/remediation-guidance", response_model=OrchestrationResult)
def generate_ai_system_guidance(
    ai_system_id: str,
    payload: GuidanceOverrides | None = None,
    ctx: TenantContext = Depends(require_permission("assistant.operate")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(AISystem).where(
            AISystem.id == ai_system_id,
            AISystem.tenant_id == ctx.tenant.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI system not found")

    finding_rows = db.scalars(
        select(Finding).where(
            Finding.tenant_id == ctx.tenant.id,
            Finding.ai_system_id == row.id,
        )
    ).all()
    overrides = _with_default_task_type(payload, "vulnerability_analysis")
    task = _ai_system_task(row=row, findings=finding_rows, overrides=overrides)
    result = generate_remediation_guidance(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        task=task,
        correlation_id=None,
    )
    db.commit()
    return result


@router.post("/agents/{agent_id}/remediation-guidance", response_model=OrchestrationResult)
def generate_agent_guidance(
    agent_id: str,
    payload: GuidanceOverrides | None = None,
    ctx: TenantContext = Depends(require_permission("assistant.operate")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == agent_id,
            AgentIdentity.tenant_id == ctx.tenant.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    recent_events = db.scalars(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == ctx.tenant.id,
            RuntimeEvent.agent_id.in_([row.id, row.name]),
        )
    ).all()
    overrides = _with_default_task_type(payload, "control_gap_analysis")
    task = _agent_task(row=row, recent_events=recent_events[:250], overrides=overrides)
    result = generate_remediation_guidance(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        task=task,
        correlation_id=None,
    )
    db.commit()
    return result


@router.post("/shadow-entities/{entity_id}/remediation-guidance", response_model=OrchestrationResult)
def generate_shadow_entity_guidance(
    entity_id: str,
    payload: GuidanceOverrides | None = None,
    ctx: TenantContext = Depends(require_permission("assistant.operate")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(ShadowAIEntity).where(
            ShadowAIEntity.id == entity_id,
            ShadowAIEntity.tenant_id == ctx.tenant.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Shadow AI entity not found")

    overrides = _with_default_task_type(payload, "remediation_guidance")
    task = _shadow_entity_task(row=row, overrides=overrides)
    result = generate_remediation_guidance(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        task=task,
        correlation_id=None,
    )
    db.commit()
    return result


@router.get("/traces/{trace_id}", response_model=TraceResponse)
def get_reasoning_trace(
    trace_id: str,
    ctx: TenantContext = Depends(require_permission("assistant.use")),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(AIReasoningTrace).where(
            AIReasoningTrace.id == trace_id,
            AIReasoningTrace.tenant_id == ctx.tenant.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Trace not found")

    return TraceResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        control_id=row.control_id,
        issue_type=row.issue_type,
        issue_id=row.issue_id,
        task_type=row.task_type,
        provider=row.provider,
        model=row.model,
        model_version=row.model_version,
        prompt_template_id=row.prompt_template_id,
        prompt_template_version=row.prompt_template_version,
        prompt_template_status=row.prompt_template_status,
        prompt_variables_json=dict(row.prompt_variables_json or {}),
        retrieval_refs_json=list(row.retrieval_refs_json or []),
        retrieval_source_ids_json=list(row.retrieval_source_ids_json or []),
        evidence_refs_json=list(row.evidence_refs_json or []),
        runtime_event_refs_json=list(row.runtime_event_refs_json or []),
        policy_version=str(row.policy_version or ""),
        governance_version=str(row.governance_version or ""),
        control_decision_json=dict(row.control_decision_json or {}),
        simulation_result_json=dict(row.simulation_result_json or {}),
        routing_context_json=dict(row.routing_context_json or {}),
        risk_context_json=dict(row.risk_context_json or {}),
        remediation_impact_json=dict(row.remediation_impact_json or {}),
        routing_policy_id=row.routing_policy_id,
        policy_route_id=row.policy_route_id,
        region_route=row.region_route,
        pre_call_guard_results_json=dict(row.pre_call_guard_results_json or {}),
        post_call_guard_results_json=dict(row.post_call_guard_results_json or {}),
        output_schema_valid=bool(row.output_schema_valid),
        token_usage_json=dict(row.token_usage_json or {}),
        cost_estimate_usd=float(row.cost_estimate_usd or 0.0),
        status=row.status,
        output_json=dict(row.output_json or {}),
        rejection_reason=row.rejection_reason,
        correlation_id=row.correlation_id,
    )


@router.post("/traces/{trace_id}/ticket-payload", response_model=TicketPayloadResponse)
def generate_reasoning_ticket_payload(
    trace_id: str,
    payload: TicketPayloadRequest,
    ctx: TenantContext = Depends(require_permission("assistant.operate")),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(AIReasoningTrace).where(
            AIReasoningTrace.id == trace_id,
            AIReasoningTrace.tenant_id == ctx.tenant.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Trace not found")

    out = build_ticket_payload(trace=row, system=payload.system)
    return TicketPayloadResponse(**out)


@router.post("/traces/{trace_id}/ticket-create", response_model=TicketCreateResponse)
def create_reasoning_ticket(
    trace_id: str,
    payload: TicketPayloadRequest,
    ctx: TenantContext = Depends(require_permission("assistant.operate")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(AIReasoningTrace).where(
            AIReasoningTrace.id == trace_id,
            AIReasoningTrace.tenant_id == ctx.tenant.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Trace not found")

    install_generic_seam_authority(
        db, tenant_id=ctx.tenant.id, seam_ref="itsm.http_post", action_id=f"itsm:{row.id}", chain_id=row.correlation_id or row.id,
        actor_principal=f"user:{current_user.id}", executing_principal="service:ai-orchestration", operation="ticket_create",
        tool_or_service_ref=payload.system, parameter_hash=domain_hash("hawk:itsm-ticket:v1", {"trace_id": row.id, "system": payload.system}), target_ref=payload.system,
    )
    out = create_ticket(
        trace=row,
        system=payload.system,
        final_seam=lambda callback: invoke_final_seam(db, seam_ref="itsm.http_post", executor=callback),
    )
    audit = write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        actor_type="human",
        action="ai_orchestration.ticket.create",
        resource_type="ai_reasoning_trace",
        resource_id=row.id,
        payload={
            "trace_id": row.id,
            "ticket_system": out.get("system"),
            "ticket_status": out.get("status"),
            "ticket_id": out.get("ticket_id"),
            "created_externally": bool(out.get("created_externally")),
            "error": out.get("error"),
        },
        correlation_id=row.correlation_id,
    )
    evidence = create_evidence_node(
        db,
        tenant_id=ctx.tenant.id,
        node_type="ai_orchestration_ticket",
        signal_type="ai_orchestration.ticket.create",
        label=f"AI orchestration ticket {out.get('status', 'unknown')}",
        payload={
            "trace_id": row.id,
            "ticket_system": out.get("system"),
            "ticket_status": out.get("status"),
            "ticket_id": out.get("ticket_id"),
            "external_url": out.get("external_url"),
            "created_externally": bool(out.get("created_externally")),
            "error": out.get("error"),
            "routing_policy_id": row.routing_policy_id,
            "policy_route_id": row.policy_route_id,
            "audit_log_id": audit.id,
        },
        correlation_id=row.correlation_id,
    )
    db.commit()
    return TicketCreateResponse(**{**out, "audit_log_id": audit.id, "evidence_node_id": evidence.id})
