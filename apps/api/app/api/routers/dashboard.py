from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.user import User
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.dashboard.aggregator import (
    CommandCenterDataUnavailableError,
    get_command_center_dashboard_state,
    get_dashboard_notifications_state,
    get_pilot_health_state,
)


router = APIRouter(prefix="/dashboard", tags=["dashboard"])


class CommandCenterDashboardResponse(BaseModel):
    tenant_id: str
    generated_at: str
    filters_applied: dict[str, Any]
    view_scope: str
    risk_over_time: dict[str, Any]
    severity_distribution: dict[str, Any]
    exposure_score: dict[str, Any]
    active_incidents: dict[str, Any]
    runtime_heatmap: dict[str, Any]
    live_activity_feed: dict[str, Any]
    ai_action_control: dict[str, Any] = Field(default_factory=dict)
    users_view: dict[str, Any]
    agents_view: dict[str, Any]
    findings_alerts: dict[str, Any]
    attack_trace_view: dict[str, Any]
    quick_actions: list[dict[str, Any]] = Field(default_factory=list)
    surface_coverage_summary: dict[str, Any]
    mcp_tool_calls: dict[str, Any] = Field(default_factory=dict)
    agentic_browser_activity: dict[str, Any] = Field(default_factory=dict)
    intent_aware_activity: dict[str, Any] = Field(default_factory=dict)
    shadow_ai_summary: dict[str, Any]
    identity_risk: dict[str, Any]
    control_coverage: dict[str, Any]
    violations: dict[str, Any]
    simulations: dict[str, Any]
    remediation_actions: dict[str, Any]
    ai_exposure_scan: dict[str, Any]
    crq_summary: dict[str, Any]
    sla_metrics: dict[str, Any]
    recommendations: list[dict[str, Any]] = Field(default_factory=list)
    cve_exposure: dict[str, Any]
    external_risk_intelligence: dict[str, Any]
    available_filters: dict[str, Any]


class DashboardNotificationItemResponse(BaseModel):
    notification_id: str
    notification_type: str
    severity: str
    title: str
    summary: str
    created_at: str
    source_surface: str | None = None
    actor_user_id: str | None = None
    actor_label: str | None = None
    endpoint_id: str | None = None
    endpoint_label: str | None = None
    finding_id: str | None = None
    action_id: str | None = None
    correlation_id: str | None = None
    request_id: str | None = None
    control_mode: str | None = None
    decision_badge: str | None = None
    drilldowns: list[dict[str, Any]] = Field(default_factory=list)
    primary_drilldown: dict[str, Any] | None = None
    primary_drilldown_type: str | None = None
    investigation_link: str | None = None
    repeat_count: int | None = None
    link: str


class DashboardNotificationsResponse(BaseModel):
    tenant_id: str
    generated_at: str
    total: int
    critical_count: int
    high_count: int
    items: list[DashboardNotificationItemResponse] = Field(default_factory=list)


class PilotHealthResponse(BaseModel):
    tenant_id: str
    generated_at: str
    overall_status: str
    api_reachable: bool
    schema_health: dict[str, Any]
    policy_sync_health: dict[str, Any]
    telemetry_health: dict[str, Any]
    deployment_hardening: dict[str, Any] = Field(default_factory=dict)


class DecisionTuningActionRequest(BaseModel):
    action: str = Field(min_length=1, max_length=80)
    runtime_event_id: str | None = Field(default=None, max_length=128)
    finding_id: str | None = Field(default=None, max_length=128)
    justification: str | None = Field(default=None, max_length=500)


class DecisionTuningActionResponse(BaseModel):
    status: str
    audit_log_id: str
    explanation_id: str
    action: str
    requires_confirmation: bool = True


@router.get("/command-center", response_model=CommandCenterDashboardResponse)
def command_center_dashboard(
    time_window_hours: int = Query(default=24, ge=1, le=24 * 30),
    ai_system_id: str | None = None,
    severity: str | None = Query(default=None),
    intent_category: str | None = Query(default=None),
    input_sensitivity: str | None = Query(default=None),
    output_sensitivity: str | None = Query(default=None),
    action_alignment: str | None = Query(default=None),
    force_refresh: bool = False,
    ctx: TenantContext = Depends(require_permission("dashboard.view")),
    db: Session = Depends(get_db),
):
    try:
        payload = get_command_center_dashboard_state(
            db,
            tenant_id=ctx.tenant.id,
            role=ctx.role,
            time_window_hours=time_window_hours,
            ai_system_id=ai_system_id,
            severity=severity,
            intent_category=intent_category,
            input_sensitivity=input_sensitivity,
            output_sensitivity=output_sensitivity,
            action_alignment=action_alignment,
            force_refresh=force_refresh,
        )
    except CommandCenterDataUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return CommandCenterDashboardResponse.model_validate(payload)


@router.post("/decision-explanations/{explanation_id}/tuning-actions", response_model=DecisionTuningActionResponse)
def record_decision_explanation_tuning_action(
    explanation_id: str,
    request: DecisionTuningActionRequest,
    ctx: TenantContext = Depends(require_permission("dashboard.tune")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    normalized_action = request.action.strip().lower()
    allowed_actions = {
        "suggest_policy_narrowing",
        "suggest_policy_exception",
        "suggest_threshold_adjustment",
        "mark_expected_behavior",
    }
    if normalized_action not in allowed_actions:
        raise HTTPException(status_code=400, detail="Unsupported tuning action")

    runtime_event_id = str(request.runtime_event_id or "").strip()
    if runtime_event_id:
        runtime = db.scalar(
            select(RuntimeEvent).where(
                RuntimeEvent.tenant_id == ctx.tenant.id,
                RuntimeEvent.event_id == runtime_event_id,
            )
        )
        if runtime is None:
            raise HTTPException(status_code=404, detail="Runtime event not found")
        explanation = (runtime.metadata_json or {}).get("decision_explanation") or {}
        if explanation and explanation.get("explanation_id") != explanation_id:
            raise HTTPException(status_code=400, detail="Explanation does not match runtime event")

    audit = write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        actor_type="human",
        action="decision_explanation.tuning_action_requested",
        resource_type="decision_explanation",
        resource_id=explanation_id,
        payload={
            "action": normalized_action,
            "runtime_event_id": runtime_event_id or None,
            "finding_id": str(request.finding_id or "").strip() or None,
            "justification": str(request.justification or "").strip() or None,
            "requires_confirmation": True,
            "policy_mutated": False,
        },
    )
    db.commit()
    return DecisionTuningActionResponse(
        status="recorded",
        audit_log_id=audit.id,
        explanation_id=explanation_id,
        action=normalized_action,
        requires_confirmation=True,
    )


@router.get("/notifications", response_model=DashboardNotificationsResponse)
def dashboard_notifications(
    limit: int = Query(default=25, ge=1, le=100),
    lookback_hours: int = Query(default=24, ge=1, le=24 * 30),
    ctx: TenantContext = Depends(require_permission("dashboard.view")),
    db: Session = Depends(get_db),
):
    payload = get_dashboard_notifications_state(
        db,
        tenant_id=ctx.tenant.id,
        limit=limit,
        lookback_hours=lookback_hours,
    )
    return DashboardNotificationsResponse.model_validate(payload)


@router.get("/pilot-health", response_model=PilotHealthResponse)
def dashboard_pilot_health(
    ctx: TenantContext = Depends(require_permission("dashboard.view")),
    db: Session = Depends(get_db),
):
    payload = get_pilot_health_state(
        db,
        tenant_id=ctx.tenant.id,
    )
    return PilotHealthResponse.model_validate(payload)
