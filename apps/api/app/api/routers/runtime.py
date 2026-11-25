from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import asc, desc, select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.runtime_intelligence import RuntimeEvent, RuntimeGovernanceRecommendation, RuntimePattern
from app.db.session import get_db
from app.services.runtime_intelligence.context_graph_service import build_chain_tree, get_context_graph


router = APIRouter(prefix="/runtime", tags=["runtime"])

_KNOWN_BROWSER_CONTEXT_REASONS = frozenset({
    "input_node_replaced",
    "spa_route_change",
    "spa_route_replace",
    "tab_restore_or_popstate",
    "extension_context_invalidated",
})
_BROWSER_CONTEXT_REAL_DECISIONS = frozenset({
    "block", "blocked", "warn", "warned", "warning", "deny", "denied", "tamper", "tampered",
    "fail", "failed", "error", "errored", "degraded", "unhealthy",
    "prevent", "prevented", "redact", "modify", "step_up", "require_approval",
    "hold_for_approval", "approval_required",
})


class RuntimeContextGraphResponse(BaseModel):
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    risk_score: float
    context: dict[str, Any] | None = None


class RuntimePatternResponse(BaseModel):
    pattern_id: str
    type: str
    frequency: int
    severity: str
    affected_entities: list[dict[str, str]]
    created_at: datetime
    updated_at: datetime


class RuntimeRecommendationResponse(BaseModel):
    recommendation_id: str
    event_id: str
    ai_system_id: str | None = None
    recommendation_type: str
    reason_code: str
    priority: str
    payload: dict[str, Any]
    status: str
    created_at: datetime
    applied_at: datetime | None = None


class RuntimeEventResponse(BaseModel):
    event_id: str
    timestamp: datetime
    tenant_id: str
    source_surface: str
    ai_surface: str
    event_type: str
    action_type: str
    ai_system_id: str | None = None
    application: str | None = None
    user_id: str | None = None
    user_email: str | None = None
    machine_id: str | None = None
    device_name: str | None = None
    os_type: str | None = None
    browser_type: str | None = None
    agent_id: str | None = None
    identity_type: str
    provider: str | None = None
    model: str | None = None
    input_ref: str | None = None
    output_ref: str | None = None
    sensitivity_score: float | None = None
    policy_id: str | None = None
    policy_decision: str
    decision: str
    control_triggered: list[str]
    reason_code: str | None = None
    anomaly_score: float | None = None
    finding_id: str | None = None
    related_event_ids: list[str]
    evidence_node_ids: list[str]
    correlation_id: str | None = None
    chain_id: str | None = None
    context_id: str | None = None
    tool_name: str | None = None
    ai_client: str | None = None
    mcp_server_id: str | None = None
    mcp_tool_id: str | None = None
    session_id: str | None = None
    tool_category: str | None = None
    api_endpoint: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0
    created_at: datetime


class RuntimeTraceStepResponse(BaseModel):
    step_number: int
    event_id: str
    title: str
    description: str
    timestamp: datetime
    ai_surface: str
    action_type: str
    policy_decision: str
    controls_triggered: list[str]
    user_id: str | None = None
    agent_id: str | None = None
    machine_id: str | None = None
    finding_id: str | None = None
    action_available: bool = False


class RuntimeTraceResponse(BaseModel):
    trace_key: str
    trace_key_type: str
    event_count: int
    events: list[RuntimeEventResponse]
    steps: list[RuntimeTraceStepResponse]


class RuntimeSessionTraceResponse(BaseModel):
    session_id: str
    user_id: str | None = None
    agent_id: str | None = None
    ai_client: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    steps: list[RuntimeTraceStepResponse]
    findings: list[str]
    recommended_actions: list[str]


def _metadata_str(metadata: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = metadata.get(key)
        if value is None:
            continue
        normalized = str(value).strip()
        if normalized:
            return normalized
    return None


def _metadata_float(metadata: dict[str, Any], *keys: str) -> float | None:
    for key in keys:
        value = metadata.get(key)
        if value is None:
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return None


def _metadata_list(metadata: dict[str, Any], *keys: str) -> list[str]:
    values: list[str] = []
    for key in keys:
        raw = metadata.get(key)
        if not isinstance(raw, list):
            continue
        for item in raw:
            normalized = str(item).strip()
            if normalized and normalized not in values:
                values.append(normalized)
    return values


def _is_passive_browser_context_lifecycle(row: RuntimeEvent) -> bool:
    if str(row.source_surface or "").strip().lower() not in {"browser", "browser_extension"}:
        return False
    metadata = dict(row.metadata_json or {}) if isinstance(row.metadata_json, dict) else {}
    event_type = str(metadata.get("event_type") or row.event_type or "").strip().lower().replace("-", "_")
    if event_type != "context_invalidated":
        return False
    reason: str | None = None
    for key in ("reason", "reason_code", "action_taken", "event_type", "decision_reason"):
        raw_value = str(metadata.get(key) or "").strip().lower().replace("-", "_")
        if not raw_value:
            continue
        candidates = {raw_value}
        candidates.update(part.strip() for part in raw_value.split(":") if part.strip())
        reason = next((candidate for candidate in candidates if candidate in _KNOWN_BROWSER_CONTEXT_REASONS), None)
        if reason:
            break
    if reason is None:
        return False

    def _is_real(value: Any) -> bool:
        return str(value or "").strip().lower().replace("-", "_") in _BROWSER_CONTEXT_REAL_DECISIONS

    action_taken = str(metadata.get("action_taken") or "").strip().lower().replace("-", "_")
    if _is_real(action_taken.split(":", 1)[0]):
        return False
    for key in ("decision", "policy_decision", "final_decision"):
        if _is_real(metadata.get(key)):
            return False
    for key in ("intent_aware_decision", "pre_action_governance_check"):
        nested = metadata.get(key)
        if isinstance(nested, dict) and any(
            _is_real(nested.get(decision_key))
            for decision_key in ("decision", "policy_decision", "final_decision")
        ):
            return False
    status = str(metadata.get("status") or "").strip().lower().replace("-", "_")
    return not _is_real(status)


def _runtime_tool_name(row: RuntimeEvent, metadata: dict[str, Any]) -> str | None:
    name = str(metadata.get("tool_name") or "").strip() or None
    if not name:
        return None
    if str(row.source_surface or "").strip().lower() in {"browser", "browser_extension"}:
        explicit = bool(
            metadata.get("tool_call_id") or metadata.get("tool_invoked")
            or metadata.get("function_call_id")
            or str(metadata.get("action_type") or row.event_type or "").strip().lower() in {"tool_call", "mcp_tool_call", "mcp_tool_call_allowed", "mcp_tool_call_blocked", "mcp_tool_call_denied", "mcp_tool_call_requested"}
        )
        if not explicit:
            return None
    return name


def _is_primary_customer_activity(row: RuntimeEvent) -> bool:
    metadata = dict(row.metadata_json or {}) if isinstance(row.metadata_json, dict) else {}
    event_type = str(metadata.get("event_type") or row.event_type or "").strip().lower()
    if str(row.source_surface or "").strip().lower() not in {"browser", "browser_extension"}:
        return True
    if _is_passive_browser_context_lifecycle(row):
        return False
    source_action = str(metadata.get("action_taken") or "").strip().lower()
    source_decision = source_action.split(":", 1)[0]
    status = str(metadata.get("status") or "").strip().lower()
    if source_decision in {"warn", "warning", "block", "blocked", "deny", "denied", "require_approval", "hold_for_approval", "approval_required", "prevent", "prevented"}:
        return True
    if metadata.get("prevented") is True or metadata.get("healthy") is False:
        return True
    if status in {"degraded", "unhealthy", "failed", "error", "tampered", "warn", "warning", "blocked", "denied", "prevented"}:
        return True
    if event_type in {"prompt_drafted", "ai_domain_visit", "ai_app_opened", "agent_runtime_discovered"}:
        return False
    if event_type in {"extension_installed", "extension_connected", "policy_sync_success", "context_recovered"}:
        return False
    if event_type == "extension_health_status":
        return False
    return True


def _recommendation_impact_score(payload: dict[str, Any] | None) -> float:
    body = dict(payload or {})
    direct = body.get("decision_impact_score")
    if direct is not None:
        try:
            return float(direct)
        except (TypeError, ValueError):
            pass
    nested = body.get("decision_impact")
    if isinstance(nested, dict):
        nested_score = nested.get("decision_impact_score")
        try:
            return float(nested_score) if nested_score is not None else 0.0
        except (TypeError, ValueError):
            return 0.0
    return 0.0


def _runtime_event_response(row: RuntimeEvent) -> RuntimeEventResponse:
    metadata = dict(row.metadata_json or {}) if isinstance(row.metadata_json, dict) else {}
    decision = (
        str(metadata.get("decision") or metadata.get("final_decision") or "").strip().lower() or "unknown"
    )
    reason_code = str(metadata.get("reason_code") or metadata.get("reason") or "").strip() or None
    controls_triggered = [
        str(control_id).strip()
        for control_id in list(metadata.get("triggered_controls") or [])
        if str(control_id).strip()
    ]
    machine_id = (
        str(metadata.get("machine_id") or "").strip()
        or str(metadata.get("endpoint_id") or "").strip()
        or str(metadata.get("host_id") or "").strip()
        or None
    )
    browser_type = (
        str(metadata.get("browser_type") or "").strip()
        or str(metadata.get("browser") or "").strip()
        or None
    )
    application = (
        str(row.app_id or "").strip()
        or str(metadata.get("domain") or "").strip()
        or str(metadata.get("destination_domain") or "").strip()
        or str(metadata.get("tool_name") or "").strip()
        or None
    )
    model_name = (
        str(metadata.get("model_name") or "").strip()
        or str(metadata.get("model") or "").strip()
        or str(metadata.get("provider") or "").strip()
        or None
    )
    action_type = _metadata_str(metadata, "action_type", "operation") or row.event_type
    identity_type = _metadata_str(metadata, "identity_type")
    if not identity_type:
        identity_type = "agent" if row.agent_id else "user"
    policy_id = _metadata_str(metadata, "policy_id", "policy_version_id") or row.policy_version_id
    return RuntimeEventResponse(
        event_id=row.event_id,
        timestamp=row.created_at,
        tenant_id=row.tenant_id,
        source_surface=row.source_surface,
        ai_surface=_metadata_str(metadata, "ai_surface", "surface") or row.source_surface,
        event_type=row.event_type,
        action_type=action_type,
        ai_system_id=row.ai_system_id,
        application=application,
        user_id=row.user_id,
        user_email=_metadata_str(metadata, "user_email", "email"),
        machine_id=machine_id,
        device_name=_metadata_str(metadata, "device_name", "hostname", "host_name"),
        os_type=_metadata_str(metadata, "os_type", "os"),
        browser_type=browser_type,
        agent_id=row.agent_id,
        identity_type=identity_type,
        provider=_metadata_str(metadata, "provider", "model_provider", "provider_name"),
        model=model_name,
        input_ref=_metadata_str(metadata, "input_ref", "redacted_input_ref"),
        output_ref=_metadata_str(metadata, "output_ref", "redacted_output_ref"),
        sensitivity_score=_metadata_float(metadata, "sensitivity_score"),
        policy_id=policy_id,
        policy_decision=decision,
        decision=decision,
        control_triggered=controls_triggered,
        reason_code=reason_code,
        anomaly_score=_metadata_float(metadata, "anomaly_score"),
        finding_id=_metadata_str(metadata, "finding_id"),
        related_event_ids=_metadata_list(metadata, "related_event_ids"),
        evidence_node_ids=[str(node_id) for node_id in (row.evidence_node_ids or []) if str(node_id).strip()],
        correlation_id=row.correlation_id,
        chain_id=row.chain_id,
        context_id=row.context_id,
        tool_name=_runtime_tool_name(row, metadata),
        ai_client=(
            _metadata_str(metadata, "ai_client", "client", "client_name")
            or str(metadata.get("runtime_provider") or "").strip()
            or None
        ),
        mcp_server_id=_metadata_str(metadata, "mcp_server_id"),
        mcp_tool_id=_metadata_str(metadata, "mcp_tool_id"),
        session_id=_metadata_str(metadata, "session_id"),
        tool_category=str(metadata.get("tool_category") or "").strip() or None,
        api_endpoint=str(metadata.get("api_endpoint") or "").strip() or None,
        metadata=metadata,
        risk_score=float(row.risk_score or metadata.get("risk_score") or 0.0),
        created_at=row.created_at,
    )


def _trace_step_title(step_number: int, event: RuntimeEventResponse) -> str:
    action = event.action_type.replace("_", " ").strip().lower() or "activity"
    surface = event.ai_surface.replace("_", " ").strip().lower() or "runtime"
    if step_number == 1 and event.action_type == "prompt":
        return "Step 1: user entered prompt"
    if event.policy_decision in {"block", "redact", "warn", "step_up", "hold_for_approval", "require_approval"}:
        return f"Step {step_number}: {surface} intercepted {action}"
    if event.finding_id:
        return f"Step {step_number}: finding created"
    return f"Step {step_number}: {surface} recorded {action}"


def _trace_step_description(event: RuntimeEventResponse) -> str:
    actor = event.agent_id or event.user_id or "unknown identity"
    app = event.application or event.provider or event.ai_surface
    decision = event.policy_decision.replace("_", " ")
    if event.control_triggered:
        controls = ", ".join(event.control_triggered)
        return f"{actor} used {app}; policy decision was {decision}; controls triggered: {controls}."
    return f"{actor} used {app}; policy decision was {decision}."


def _trace_steps(events: list[RuntimeEventResponse]) -> list[RuntimeTraceStepResponse]:
    steps: list[RuntimeTraceStepResponse] = []
    for index, event in enumerate(events, start=1):
        steps.append(
            RuntimeTraceStepResponse(
                step_number=index,
                event_id=event.event_id,
                title=_trace_step_title(index, event),
                description=_trace_step_description(event),
                timestamp=event.timestamp,
                ai_surface=event.ai_surface,
                action_type=event.action_type,
                policy_decision=event.policy_decision,
                controls_triggered=event.control_triggered,
                user_id=event.user_id,
                agent_id=event.agent_id,
                machine_id=event.machine_id,
                finding_id=event.finding_id,
                action_available=event.policy_decision in {"block", "warn", "redact", "step_up", "hold_for_approval", "require_approval"}
                or bool(event.finding_id),
            )
        )
    return steps


@router.get("/patterns", response_model=ListEnvelope[RuntimePatternResponse])
def runtime_patterns(
    page: int = 1,
    page_size: int = 50,
    type_filter: str | None = None,
    severity: str | None = None,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    stmt = select(RuntimePattern).where(RuntimePattern.tenant_id == ctx.tenant.id)
    if type_filter:
        stmt = stmt.where(RuntimePattern.type == type_filter)
    if severity:
        stmt = stmt.where(RuntimePattern.severity == severity)
    rows = db.scalars(stmt.order_by(desc(RuntimePattern.updated_at))).all()
    dto_rows = [RuntimePatternResponse.model_validate(row, from_attributes=True) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[RuntimePatternResponse](items=page_items, total=total, page=safe_page, page_size=safe_page_size)


@router.get("/recommendations", response_model=ListEnvelope[RuntimeRecommendationResponse])
def runtime_recommendations(
    page: int = 1,
    page_size: int = 50,
    status_filter: str | None = None,
    recommendation_type: str | None = None,
    ai_system_id: str | None = None,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    stmt = select(RuntimeGovernanceRecommendation).where(RuntimeGovernanceRecommendation.tenant_id == ctx.tenant.id)
    if status_filter:
        stmt = stmt.where(RuntimeGovernanceRecommendation.status == status_filter)
    if recommendation_type:
        stmt = stmt.where(RuntimeGovernanceRecommendation.recommendation_type == recommendation_type)
    if ai_system_id:
        stmt = stmt.where(RuntimeGovernanceRecommendation.ai_system_id == ai_system_id)
    rows = db.scalars(stmt).all()
    rows = sorted(
        rows,
        key=lambda row: (
            _recommendation_impact_score(row.payload),
            row.created_at,
        ),
        reverse=True,
    )
    dto_rows = [RuntimeRecommendationResponse.model_validate(row, from_attributes=True) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[RuntimeRecommendationResponse](items=page_items, total=total, page=safe_page, page_size=safe_page_size)


@router.get("/events", response_model=ListEnvelope[RuntimeEventResponse])
def runtime_events(
    page: int = 1,
    page_size: int = 100,
    source_surface: str | None = None,
    event_type: str | None = None,
    agent_id: str | None = None,
    decision: str | None = None,
    ai_surface: str | None = None,
    ai_client: str | None = None,
    mcp_server_id: str | None = None,
    mcp_tool_id: str | None = None,
    tool_name: str | None = None,
    session_id: str | None = None,
    chain_id: str | None = None,
    correlation_id: str | None = None,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    stmt = select(RuntimeEvent).where(RuntimeEvent.tenant_id == ctx.tenant.id)
    if source_surface:
        stmt = stmt.where(RuntimeEvent.source_surface == source_surface)
    if event_type:
        stmt = stmt.where(RuntimeEvent.event_type == event_type)
    if agent_id:
        stmt = stmt.where(RuntimeEvent.agent_id == agent_id)
    if chain_id:
        stmt = stmt.where(RuntimeEvent.chain_id == chain_id)
    if correlation_id:
        stmt = stmt.where(RuntimeEvent.correlation_id == correlation_id)

    rows = db.scalars(stmt.order_by(desc(RuntimeEvent.created_at))).all()
    dto_rows = [_runtime_event_response(row) for row in rows]

    if ai_surface:
        ai_surface_filter = ai_surface.strip().lower()
        dto_rows = [row for row in dto_rows if str(row.ai_surface or "").strip().lower() == ai_surface_filter]
    if ai_client:
        ai_client_filter = ai_client.strip().lower()
        dto_rows = [row for row in dto_rows if str(row.ai_client or "").strip().lower() == ai_client_filter]
    if mcp_server_id:
        mcp_server_filter = mcp_server_id.strip().lower()
        dto_rows = [row for row in dto_rows if str(row.mcp_server_id or "").strip().lower() == mcp_server_filter]
    if mcp_tool_id:
        mcp_tool_filter = mcp_tool_id.strip().lower()
        dto_rows = [row for row in dto_rows if str(row.mcp_tool_id or "").strip().lower() == mcp_tool_filter]
    if tool_name:
        tool_filter = tool_name.strip().lower()
        dto_rows = [row for row in dto_rows if str(row.tool_name or "").strip().lower() == tool_filter]
    if session_id:
        session_filter = session_id.strip().lower()
        dto_rows = [row for row in dto_rows if str(row.session_id or "").strip().lower() == session_filter]
    if decision:
        decision_filter = decision.strip().lower()
        dto_rows = [row for row in dto_rows if row.decision.lower() == decision_filter]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[RuntimeEventResponse](items=page_items, total=total, page=safe_page, page_size=safe_page_size)


@router.get("/activities", response_model=ListEnvelope[RuntimeEventResponse])
def runtime_activities(
    page: int = 1,
    page_size: int = 100,
    source_surface: str | None = None,
    event_type: str | None = None,
    application: str | None = None,
    user_id: str | None = None,
    machine_id: str | None = None,
    browser_type: str | None = None,
    agent_id: str | None = None,
    decision: str | None = None,
    ai_surface: str | None = None,
    ai_client: str | None = None,
    mcp_server_id: str | None = None,
    mcp_tool_id: str | None = None,
    tool_name: str | None = None,
    session_id: str | None = None,
    chain_id: str | None = None,
    correlation_id: str | None = None,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    stmt = select(RuntimeEvent).where(RuntimeEvent.tenant_id == ctx.tenant.id)
    if source_surface:
        stmt = stmt.where(RuntimeEvent.source_surface == source_surface)
    if event_type:
        stmt = stmt.where(RuntimeEvent.event_type == event_type)
    if agent_id:
        stmt = stmt.where(RuntimeEvent.agent_id == agent_id)
    if user_id:
        stmt = stmt.where(RuntimeEvent.user_id == user_id)
    if chain_id:
        stmt = stmt.where(RuntimeEvent.chain_id == chain_id)
    if correlation_id:
        stmt = stmt.where(RuntimeEvent.correlation_id == correlation_id)

    rows = db.scalars(stmt.order_by(desc(RuntimeEvent.created_at))).all()
    dto_rows = [_runtime_event_response(row) for row in rows]
    primary_correlations = {
        row.correlation_id for row in rows
        if row.correlation_id and str((row.metadata_json or {}).get("event_type") or row.event_type or "").strip().lower()
        in {"prompt_blocked", "prompt_warned", "prompt_held", "prompt_submitted", "browser_automation_blocked"}
    }
    dto_rows = [
        dto for row, dto in zip(rows, dto_rows)
        if _is_primary_customer_activity(row)
        and not (
            str((row.metadata_json or {}).get("event_type") or row.event_type or "").strip().lower()
            in {"policy_blocked", "policy_warned"}
            and row.correlation_id in primary_correlations
        )
    ]

    if decision:
        decision_filter = decision.strip().lower()
        dto_rows = [row for row in dto_rows if row.decision.lower() == decision_filter]
    if ai_surface:
        ai_surface_filter = ai_surface.strip().lower()
        dto_rows = [row for row in dto_rows if str(row.ai_surface or "").strip().lower() == ai_surface_filter]
    if ai_client:
        ai_client_filter = ai_client.strip().lower()
        dto_rows = [row for row in dto_rows if str(row.ai_client or "").strip().lower() == ai_client_filter]
    if mcp_server_id:
        mcp_server_filter = mcp_server_id.strip().lower()
        dto_rows = [row for row in dto_rows if str(row.mcp_server_id or "").strip().lower() == mcp_server_filter]
    if mcp_tool_id:
        mcp_tool_filter = mcp_tool_id.strip().lower()
        dto_rows = [row for row in dto_rows if str(row.mcp_tool_id or "").strip().lower() == mcp_tool_filter]
    if tool_name:
        tool_filter = tool_name.strip().lower()
        dto_rows = [row for row in dto_rows if str(row.tool_name or "").strip().lower() == tool_filter]
    if session_id:
        session_filter = session_id.strip().lower()
        dto_rows = [row for row in dto_rows if str(row.session_id or "").strip().lower() == session_filter]
    if application:
        application_filter = application.strip().lower()
        dto_rows = [row for row in dto_rows if str(row.application or "").strip().lower() == application_filter]
    if machine_id:
        machine_filter = machine_id.strip().lower()
        dto_rows = [row for row in dto_rows if str(row.machine_id or "").strip().lower() == machine_filter]
    if browser_type:
        browser_filter = browser_type.strip().lower()
        dto_rows = [row for row in dto_rows if str(row.browser_type or "").strip().lower() == browser_filter]

    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[RuntimeEventResponse](items=page_items, total=total, page=safe_page, page_size=safe_page_size)


@router.get("/activities/{event_id}", response_model=RuntimeEventResponse)
def runtime_activity_detail(
    event_id: str,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == ctx.tenant.id,
            RuntimeEvent.event_id == event_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Runtime event not found")
    return _runtime_event_response(row)


@router.get("/users/{user_id}/activity", response_model=ListEnvelope[RuntimeEventResponse])
def runtime_user_activity(
    user_id: str,
    page: int = 1,
    page_size: int = 100,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(
        select(RuntimeEvent)
        .where(
            RuntimeEvent.tenant_id == ctx.tenant.id,
            RuntimeEvent.user_id == user_id,
        )
        .order_by(desc(RuntimeEvent.created_at))
    ).all()
    dto_rows = [_runtime_event_response(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[RuntimeEventResponse](items=page_items, total=total, page=safe_page, page_size=safe_page_size)


@router.get("/agents/{agent_id}/activity", response_model=ListEnvelope[RuntimeEventResponse])
def runtime_agent_activity(
    agent_id: str,
    page: int = 1,
    page_size: int = 100,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(
        select(RuntimeEvent)
        .where(
            RuntimeEvent.tenant_id == ctx.tenant.id,
            RuntimeEvent.agent_id == agent_id,
        )
        .order_by(desc(RuntimeEvent.created_at))
    ).all()
    dto_rows = [_runtime_event_response(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[RuntimeEventResponse](items=page_items, total=total, page=safe_page, page_size=safe_page_size)


@router.get("/assets/{asset_id}/activity", response_model=ListEnvelope[RuntimeEventResponse])
def runtime_asset_activity(
    asset_id: str,
    page: int = 1,
    page_size: int = 100,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(
        select(RuntimeEvent)
        .where(RuntimeEvent.tenant_id == ctx.tenant.id)
        .order_by(desc(RuntimeEvent.created_at))
        .limit(5000)
    ).all()
    asset_norm = asset_id.strip().lower()
    dto_rows = []
    for row in rows:
        metadata = dict(row.metadata_json or {}) if isinstance(row.metadata_json, dict) else {}
        related_ids = [
            str(row.ai_system_id or "").strip(),
            str(metadata.get("asset_id") or "").strip(),
            str(metadata.get("mcp_server_id") or "").strip(),
            str(metadata.get("mcp_tool_id") or "").strip(),
        ]
        if any(item and item.lower() == asset_norm for item in related_ids):
            dto_rows.append(_runtime_event_response(row))
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[RuntimeEventResponse](items=page_items, total=total, page=safe_page, page_size=safe_page_size)


@router.get("/sessions/{session_id}", response_model=RuntimeSessionTraceResponse)
def runtime_session_trace(
    session_id: str,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(
        select(RuntimeEvent)
        .where(RuntimeEvent.tenant_id == ctx.tenant.id)
        .order_by(asc(RuntimeEvent.created_at))
        .limit(10000)
    ).all()
    session_norm = session_id.strip().lower()
    events = []
    for row in rows:
        metadata = dict(row.metadata_json or {}) if isinstance(row.metadata_json, dict) else {}
        runtime_session = str(metadata.get("session_id") or "").strip().lower()
        if runtime_session == session_norm or str(row.context_id or "").strip().lower() == session_norm:
            events.append(_runtime_event_response(row))

    if not events:
        raise HTTPException(status_code=404, detail="Runtime session not found")

    start_time = min((event.timestamp for event in events), default=None)
    end_time = max((event.timestamp for event in events), default=None)
    findings = sorted({str(event.finding_id).strip() for event in events if str(event.finding_id or "").strip()})
    recommended_actions: list[str] = []
    for event in events:
        decision = str(event.policy_decision or "").strip().lower()
        if decision in {"block", "deny"}:
            recommended_actions.append("Block or isolate associated agent/user path and review MCP scope.")
        elif decision in {"warn", "redact"}:
            recommended_actions.append("Review tool-call arguments and tighten MCP policy guardrails.")
        elif decision in {"hold_for_approval", "require_approval"}:
            recommended_actions.append("Require explicit approval before continuing tool execution chain.")

    return RuntimeSessionTraceResponse(
        session_id=session_id,
        user_id=next((event.user_id for event in events if event.user_id), None),
        agent_id=next((event.agent_id for event in events if event.agent_id), None),
        ai_client=next((event.ai_client for event in events if event.ai_client), None),
        start_time=start_time,
        end_time=end_time,
        steps=_trace_steps(events),
        findings=findings,
        recommended_actions=sorted(set(recommended_actions)),
    )


@router.get("/trace/{event_id}", response_model=RuntimeTraceResponse)
def runtime_trace(
    event_id: str,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    anchor = db.scalar(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == ctx.tenant.id,
            RuntimeEvent.event_id == event_id,
        )
    )
    if anchor is None:
        raise HTTPException(status_code=404, detail="Runtime event not found")

    trace_key_type = "event_id"
    trace_key = anchor.event_id
    stmt = select(RuntimeEvent).where(RuntimeEvent.tenant_id == ctx.tenant.id)
    if str(anchor.chain_id or "").strip():
        trace_key_type = "chain_id"
        trace_key = str(anchor.chain_id)
        stmt = stmt.where(RuntimeEvent.chain_id == anchor.chain_id)
    elif str(anchor.context_id or "").strip():
        trace_key_type = "context_id"
        trace_key = str(anchor.context_id)
        stmt = stmt.where(RuntimeEvent.context_id == anchor.context_id)
    elif str(anchor.correlation_id or "").strip():
        trace_key_type = "correlation_id"
        trace_key = str(anchor.correlation_id)
        stmt = stmt.where(RuntimeEvent.correlation_id == anchor.correlation_id)
    else:
        stmt = stmt.where(RuntimeEvent.event_id == anchor.event_id)

    rows = db.scalars(stmt.order_by(asc(RuntimeEvent.created_at))).all()
    events = [_runtime_event_response(row) for row in rows]
    return RuntimeTraceResponse(
        trace_key=trace_key,
        trace_key_type=trace_key_type,
        event_count=len(events),
        events=events,
        steps=_trace_steps(events),
    )


@router.get("/context/{context_id}", response_model=RuntimeContextGraphResponse)
def runtime_context(
    context_id: str,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    return RuntimeContextGraphResponse.model_validate(
        get_context_graph(
            db,
            tenant_id=ctx.tenant.id,
            context_id=context_id,
        )
    )


@router.get("/chain/{chain_id}", response_model=RuntimeContextGraphResponse)
def runtime_chain(
    chain_id: str,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    return RuntimeContextGraphResponse.model_validate(
        build_chain_tree(
            db,
            tenant_id=ctx.tenant.id,
            chain_id=chain_id,
        )
    )


class RuntimeAgentChainResponse(BaseModel):
    agent_id: str
    chain_id: str | None = None
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    risk_score: float
    event_count: int = 0


@router.get("/chain", response_model=RuntimeAgentChainResponse)
def runtime_chain_by_agent(
    agent_id: str,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(
        select(RuntimeEvent)
        .where(
            RuntimeEvent.tenant_id == ctx.tenant.id,
            RuntimeEvent.agent_id == agent_id,
        )
        .order_by(desc(RuntimeEvent.created_at))
    ).all()
    selected_chain_id = next((str(row.chain_id).strip() for row in rows if str(row.chain_id or "").strip()), None)
    if not selected_chain_id:
        return RuntimeAgentChainResponse(
            agent_id=agent_id,
            chain_id=None,
            nodes=[],
            edges=[],
            risk_score=0.0,
            event_count=len(rows),
        )

    graph = build_chain_tree(
        db,
        tenant_id=ctx.tenant.id,
        chain_id=selected_chain_id,
    )
    chain_event_count = sum(1 for row in rows if str(row.chain_id or "").strip() == selected_chain_id)
    return RuntimeAgentChainResponse(
        agent_id=agent_id,
        chain_id=selected_chain_id,
        nodes=list(graph.get("nodes") or []),
        edges=list(graph.get("edges") or []),
        risk_score=float(graph.get("risk_score") or 0.0),
        event_count=chain_event_count,
    )
