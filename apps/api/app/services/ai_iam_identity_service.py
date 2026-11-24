from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from app.db.models.ai_iam import AgentActionBaseline, AgentIdentity, CapabilityToken
from app.db.models.finding import Finding
from app.db.models.monitoring import MonitoringSignal
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.simulation import SimulationRun
from app.services.ai_discovery.agent_security_service import (
    build_agent_attack_surface_map,
    compute_agent_blast_radius,
    get_agent_owasp_coverage,
)


PROTECTIVE_DECISIONS = {
    "block",
    "deny",
    "redact",
    "modify",
    "step_up",
    "require_approval",
    "hold_for_approval",
}

HIGH_RISK_CLASSIFICATIONS = {"sensitive", "protected", "restricted"}
MEDIUM_RISK_CLASSIFICATIONS = {"internal", "confidential"}

ANOMALY_SEVERITY_WEIGHT = {
    "low": 0.2,
    "med": 0.45,
    "medium": 0.45,
    "high": 0.75,
    "critical": 1.0,
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _to_utc(value: Any) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    if parsed != parsed:
        return default
    return parsed


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_dict(value: Any) -> dict[str, Any]:
    return dict(value or {}) if isinstance(value, dict) else {}


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, float(value)))


def _started_at(lookback_hours: int) -> datetime:
    safe_hours = max(1, min(24 * 180, int(lookback_hours or 24 * 30)))
    return _utc_now() - timedelta(hours=safe_hours)


def _event_metadata(event: RuntimeEvent) -> dict[str, Any]:
    return _safe_dict(event.metadata_json)


def _event_decision(event: RuntimeEvent) -> str:
    meta = _event_metadata(event)
    return (
        _safe_str(meta.get("final_decision") or meta.get("decision") or meta.get("enforcement_action") or "")
        .lower()
        or "unknown"
    )


def _event_reason(event: RuntimeEvent) -> str:
    meta = _event_metadata(event)
    return _safe_str(meta.get("reason") or meta.get("reason_code") or "").lower()


def _event_controls(event: RuntimeEvent) -> tuple[list[str], list[dict[str, Any]]]:
    meta = _event_metadata(event)
    triggered = [
        _safe_str(item)
        for item in list(meta.get("triggered_controls") or meta.get("related_control_ids") or [])
        if _safe_str(item)
    ]
    evaluated_raw = list(meta.get("evaluated_controls") or [])
    evaluated: list[dict[str, Any]] = [
        dict(item)
        for item in evaluated_raw
        if isinstance(item, dict)
    ]
    return triggered, evaluated


def _event_classification(event: RuntimeEvent) -> str:
    meta = _event_metadata(event)
    value = _safe_str(meta.get("data_classification") or meta.get("classification") or "").lower()
    if not value:
        value = _safe_str(meta.get("sensitive_detection", {}).get("classification") if isinstance(meta.get("sensitive_detection"), dict) else "").lower()
    return value or "unknown"


def _classification_weight(classification: str) -> float:
    token = _safe_str(classification).lower()
    if token in HIGH_RISK_CLASSIFICATIONS:
        return 1.0
    if token in MEDIUM_RISK_CLASSIFICATIONS:
        return 0.72
    if token == "public":
        return 0.2
    return 0.45


def _extract_host(value: str | None) -> str:
    raw = _safe_str(value).lower()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        host = _safe_str(parsed.hostname).lower()
        if host:
            return host
    return raw.split("/")[0].split(":")[0]


def _is_public_domain(host: str) -> bool:
    normalized = _safe_str(host).lower()
    if not normalized:
        return False
    return not (
        normalized in {"localhost", "127.0.0.1", "::1"}
        or normalized.endswith(".local")
        or normalized.endswith(".internal")
        or normalized.endswith(".corp")
    )


def _criticality_weight(action_scope: list[str] | None) -> float:
    scopes = [_safe_str(item).lower() for item in list(action_scope or []) if _safe_str(item)]
    if not scopes:
        return 0.35

    score = 0.0
    for scope in scopes:
        if scope == "*":
            score = max(score, 1.0)
        elif "admin" in scope or "delete" in scope or scope.endswith(".write"):
            score = max(score, 0.9)
        elif "run" in scope or "email_send" in scope or "tool." in scope:
            score = max(score, 0.75)
        elif scope.endswith(".read") or scope.startswith("read."):
            score = max(score, 0.35)
        else:
            score = max(score, 0.5)
    return _clamp(score, 0.0, 1.0)


def _find_agent_id_from_anomaly(payload: dict[str, Any]) -> str:
    direct = _safe_str(payload.get("agent_id"))
    if direct:
        return direct
    for entity in list(payload.get("related_entities") or []):
        if not isinstance(entity, dict):
            continue
        if _safe_str(entity.get("type")).lower() == "agent":
            ref = _safe_str(entity.get("id"))
            if ref:
                return ref
    return ""


def _simulation_outcome(row: SimulationRun) -> str:
    results = _safe_dict(row.results)
    raw = _safe_str(
        results.get("final_outcome")
        or results.get("result")
        or results.get("status")
        or results.get("execution_status")
    ).lower()
    if raw in {"pass", "fail", "partial", "not_executable"}:
        return raw
    if raw in {"failed", "error"}:
        return "fail"
    if raw in {"completed", "executed", "success"}:
        pass_rate = _safe_float(results.get("pass_rate"), 0.0)
        if pass_rate >= 0.99:
            return "pass"
    if _safe_int(results.get("total_runs"), 0) <= 0:
        return "not_executable"
    return "partial"


def _simulation_pass_rate(row: SimulationRun, outcome: str) -> float:
    results = _safe_dict(row.results)
    pass_rate = _safe_float(results.get("pass_rate"), -1.0)
    if pass_rate >= 0.0:
        return _clamp(pass_rate, 0.0, 1.0)
    return 1.0 if outcome == "pass" else 0.0


def _control_failure_score(events: list[RuntimeEvent]) -> tuple[float, int, int, list[str], list[str]]:
    evaluated_total = 0
    failed_total = 0
    triggered_controls: set[str] = set()
    missed_controls: set[str] = set()

    for event in events:
        decision = _event_decision(event)
        reason = _event_reason(event)
        event_risk = _safe_float(getattr(event, "risk_score", 0.0), 0.0)
        triggered, evaluated = _event_controls(event)
        for control_id in triggered:
            triggered_controls.add(control_id)

        evaluated_count = len(evaluated) if evaluated else (len(triggered) if triggered else 1)
        evaluated_total += evaluated_count

        if decision in PROTECTIVE_DECISIONS:
            continue

        high_risk_allow = decision in {"allow", "defer", "warn"} and event_risk >= 0.65
        explicit_miss = "miss" in reason or "bypass" in reason
        if high_risk_allow or explicit_miss:
            failure_count = max(1, len(triggered) or len(evaluated))
            failed_total += failure_count
            if triggered:
                for control_id in triggered:
                    missed_controls.add(control_id)
            else:
                missed_controls.add("POLICY_ENFORCEMENT_CONTROL")

    ratio = _clamp((failed_total / max(1, evaluated_total)), 0.0, 1.0)
    return ratio, failed_total, evaluated_total, sorted(triggered_controls), sorted(missed_controls)


def _privilege_score(agent: AgentIdentity, events: list[RuntimeEvent]) -> float:
    tools_count = len([item for item in list(agent.tool_registry or []) if _safe_str(item)])
    tools_component = _clamp(tools_count / 10.0, 0.0, 1.0)

    class_weights = [_classification_weight(_event_classification(event)) for event in events]
    data_component = max(class_weights) if class_weights else 0.45
    action_component = _criticality_weight(list(agent.action_scope or []))

    return _clamp((0.4 * tools_component) + (0.3 * data_component) + (0.3 * action_component), 0.0, 1.0)


def _behavior_anomaly_score(
    *,
    events: list[RuntimeEvent],
    anomaly_rows: list[MonitoringSignal],
    baselines: list[AgentActionBaseline],
) -> tuple[float, int]:
    if not anomaly_rows and not baselines:
        return 0.0, 0

    anomaly_weight_total = sum(
        ANOMALY_SEVERITY_WEIGHT.get(_safe_str(row.severity).lower(), 0.2)
        for row in anomaly_rows
    )
    anomaly_density = _clamp(
        anomaly_weight_total / max(1.5, (len(events) * 0.15) + 1.0),
        0.0,
        1.0,
    )

    baseline_drift = 0
    for row in baselines:
        threshold = max(5.0, _safe_float(row.baseline_rate_per_hour, 1.0) * 3.0)
        if _safe_float(row.current_window_count, 0.0) > threshold:
            baseline_drift += 1
    baseline_component = _clamp(baseline_drift / max(1, len(baselines)), 0.0, 1.0)

    frequency_component = _clamp(len(anomaly_rows) / 10.0, 0.0, 1.0)
    score = _clamp((0.6 * anomaly_density) + (0.2 * baseline_component) + (0.2 * frequency_component), 0.0, 1.0)
    return score, len(anomaly_rows)


def _exposure_score(agent: AgentIdentity, events: list[RuntimeEvent]) -> tuple[float, dict[str, Any]]:
    allowed_targets = [_safe_str(item).lower() for item in list(agent.external_system_access or []) if _safe_str(item)]
    external_component = _clamp(len(allowed_targets) / 8.0, 0.0, 1.0)

    observed_targets: set[str] = set()
    mcp_connection_count = 0
    internet_exposed_count = 0

    for event in events:
        meta = _event_metadata(event)
        target = _extract_host(
            _safe_str(meta.get("target_resource"))
            or _safe_str(meta.get("api_endpoint"))
            or _safe_str(meta.get("destination"))
        )
        if target:
            observed_targets.add(target)
            if _is_public_domain(target):
                internet_exposed_count += 1

        event_type = _safe_str(getattr(event, "event_type", "")).lower()
        tool_category = _safe_str(meta.get("tool_category") or "").lower()
        source_surface = _safe_str(getattr(event, "source_surface", "")).lower()
        if event_type == "mcp_authorize" or "mcp" in tool_category or source_surface == "connector":
            mcp_connection_count += 1

    internet_component = _clamp(len([item for item in observed_targets if _is_public_domain(item)]) / 10.0, 0.0, 1.0)
    mcp_component = _clamp(mcp_connection_count / max(10.0, float(len(events) or 1)), 0.0, 1.0)

    score = _clamp((0.45 * external_component) + (0.35 * internet_component) + (0.2 * mcp_component), 0.0, 1.0)
    return score, {
        "allowed_targets": sorted(set(allowed_targets))[:50],
        "observed_targets": sorted(observed_targets)[:50],
        "internet_exposed_count": int(internet_exposed_count),
        "mcp_connection_count": int(mcp_connection_count),
    }


def _simulation_failure_score(sim_runs: list[SimulationRun]) -> tuple[float, dict[str, Any]]:
    if not sim_runs:
        return 0.0, {
            "total_runs": 0,
            "pass": 0,
            "fail": 0,
            "partial": 0,
            "not_executable": 0,
            "pass_rate": 0.0,
        }

    buckets = Counter()
    weighted_failures = 0.0
    pass_accumulator = 0.0

    for row in sim_runs:
        outcome = _simulation_outcome(row)
        pass_rate = _simulation_pass_rate(row, outcome)
        buckets[outcome] += 1
        pass_accumulator += pass_rate
        if outcome == "fail":
            weighted_failures += 1.0
        elif outcome == "partial":
            weighted_failures += 0.6
        elif outcome == "not_executable":
            weighted_failures += 0.35

    total_runs = max(1, len(sim_runs))
    score = _clamp(weighted_failures / float(total_runs), 0.0, 1.0)
    return score, {
        "total_runs": int(len(sim_runs)),
        "pass": int(buckets.get("pass", 0)),
        "fail": int(buckets.get("fail", 0)),
        "partial": int(buckets.get("partial", 0)),
        "not_executable": int(buckets.get("not_executable", 0)),
        "pass_rate": round(_clamp(pass_accumulator / float(total_runs), 0.0, 1.0), 4),
    }


def _model_and_owner(events: list[RuntimeEvent]) -> tuple[str | None, str | None, list[str]]:
    model_counter: Counter[str] = Counter()
    owner_counter: Counter[str] = Counter()
    surfaces: set[str] = set()

    for event in events:
        meta = _event_metadata(event)
        model_name = _safe_str(meta.get("model_name") or meta.get("model") or "")
        if model_name:
            model_counter[model_name] += 1

        user_id = _safe_str(getattr(event, "user_id", "") or meta.get("user_id"))
        if user_id:
            owner_counter[user_id] += 1

        surface = _safe_str(getattr(event, "source_surface", "")).lower()
        if surface:
            surfaces.add(surface)

    dominant_model = model_counter.most_common(1)[0][0] if model_counter else None
    dominant_owner = owner_counter.most_common(1)[0][0] if owner_counter else None
    return dominant_model, dominant_owner, sorted(surfaces)


def _event_action_type(event: RuntimeEvent) -> str:
    meta = _event_metadata(event)
    return _safe_str(meta.get("action_type") or meta.get("operation") or event.event_type) or "unknown"


def _event_tool_name(event: RuntimeEvent) -> str:
    meta = _event_metadata(event)
    return _safe_str(meta.get("tool_name") or event.app_id)


def _recent_agent_actions(events: list[RuntimeEvent], *, limit: int = 20) -> list[dict[str, Any]]:
    rows = sorted(events, key=lambda row: _to_utc(row.created_at) or _utc_now(), reverse=True)[: max(1, limit)]
    out: list[dict[str, Any]] = []
    for row in rows:
        meta = _event_metadata(row)
        out.append(
            {
                "event_id": row.event_id,
                "timestamp": row.created_at.isoformat() if row.created_at else None,
                "action_type": _event_action_type(row),
                "application": _safe_str(row.app_id) or None,
                "tool_name": _event_tool_name(row) or None,
                "resource": _safe_str(meta.get("target_resource") or meta.get("api_endpoint") or meta.get("data_source")) or None,
                "decision": _event_decision(row),
                "risk_score": _safe_float(row.risk_score, 0.0),
                "finding_id": _safe_str(meta.get("finding_id")) or None,
            }
        )
    return out


def _agent_behavior_profile(
    *,
    agent_id: str,
    events: list[RuntimeEvent],
    baselines: list[AgentActionBaseline],
    anomaly_score: float,
) -> dict[str, Any]:
    normal_apps: set[str] = set()
    normal_tools: set[str] = set()
    normal_patterns: set[str] = set()
    baseline_rate = 0.0
    for row in baselines:
        baseline_rate += _safe_float(row.baseline_rate_per_hour, 0.0)
        normal_patterns.add(_safe_str(row.action))
        meta = _safe_dict(row.metadata_json)
        normal_apps.update(_safe_str(item) for item in list(meta.get("normal_apps") or []) if _safe_str(item))
        normal_tools.update(_safe_str(item) for item in list(meta.get("normal_tools") or []) if _safe_str(item))

    apps_seen = sorted({_safe_str(row.app_id) for row in events if _safe_str(row.app_id)})
    tools_seen = sorted({_event_tool_name(row) for row in events if _event_tool_name(row)})
    action_frequency = len(events)
    data_patterns = sorted(
        {
            _safe_str(
                _event_metadata(row).get("target_resource")
                or _event_metadata(row).get("api_endpoint")
                or _event_metadata(row).get("data_source")
            )
            for row in events
            if _safe_str(
                _event_metadata(row).get("target_resource")
                or _event_metadata(row).get("api_endpoint")
                or _event_metadata(row).get("data_source")
            )
        }
    )

    deviations: list[str] = []
    for app in apps_seen:
        if normal_apps and app not in normal_apps:
            deviations.append(f"new_app:{app}")
    for tool in tools_seen:
        if normal_tools and tool not in normal_tools:
            deviations.append(f"new_tool:{tool}")
    for row in baselines:
        threshold = max(5.0, _safe_float(row.baseline_rate_per_hour, 1.0) * 3.0)
        if _safe_float(row.current_window_count, 0.0) > threshold:
            deviations.append(f"frequency_spike:{_safe_str(row.action)}")

    return {
        "identity_id": agent_id,
        "identity_type": "agent",
        "baseline": {
            "normal_apps": sorted(normal_apps),
            "normal_tools": sorted(normal_tools),
            "normal_action_frequency": round(float(baseline_rate), 4),
            "normal_time_window": "hourly",
            "normal_data_access_patterns": sorted(normal_patterns),
        },
        "current_window": {
            "apps_seen": apps_seen,
            "tools_seen": tools_seen,
            "action_frequency": action_frequency,
            "data_access_patterns": data_patterns,
        },
        "deviations": sorted(set(deviations)),
        "anomaly_score": round(float(anomaly_score), 4),
    }


def _compute_identity_crq(
    *,
    risk_score: float,
    exposure_score: float,
    control_failure_score: float,
    simulation_failure_score: float,
    behavior_anomaly_score: float,
    blast_radius_score: float,
    tools_count: int,
    event_count: int,
    lookback_hours: int,
    anomaly_count: int,
    baseline_ale_hint: float = 0.0,
    residual_ale_hint: float = 0.0,
    loss_reduction_hint: float = 0.0,
) -> dict[str, float]:
    base_asset_value = (
        220_000.0
        + (float(tools_count) * 14_000.0)
        + (float(blast_radius_score) * 48_000.0)
        + (float(event_count) * 1_100.0)
    )

    exposure_factor = _clamp(0.18 + (0.58 * risk_score) + (0.24 * exposure_score), 0.05, 1.0)
    sle = max(25_000.0, base_asset_value * exposure_factor)

    annual_attempt_projection = _clamp(
        (float(max(1, event_count)) * 24.0 * 365.0) / float(max(1, lookback_hours)),
        1.0,
        200_000.0,
    )
    aro = _clamp(
        (annual_attempt_projection / 160.0)
        * (1.0 + simulation_failure_score)
        * (1.0 + min(1.5, float(anomaly_count) / 6.0)),
        0.05,
        24.0,
    )

    baseline_ale = sle * aro
    control_effectiveness = _clamp(
        1.0 - ((0.55 * control_failure_score) + (0.3 * simulation_failure_score) + (0.15 * behavior_anomaly_score)),
        0.05,
        0.95,
    )
    current_ale = baseline_ale * (1.0 - control_effectiveness)
    loss_reduction = max(0.0, baseline_ale - current_ale)

    if baseline_ale_hint > 0.0:
        baseline_ale = max(baseline_ale, baseline_ale_hint)
    if residual_ale_hint > 0.0:
        current_ale = max(current_ale, residual_ale_hint)
    if loss_reduction_hint > 0.0:
        loss_reduction = max(loss_reduction, loss_reduction_hint)

    remediation_cost = max(5_000.0, 12_000.0 + (tools_count * 950.0) + (blast_radius_score * 1_650.0))
    decision_impact_score = loss_reduction / remediation_cost

    return {
        "SLE": round(float(sle), 2),
        "ARO": round(float(aro), 4),
        "ALE": round(float(current_ale), 2),
        "baseline_ALE": round(float(baseline_ale), 2),
        "loss_reduction": round(float(loss_reduction), 2),
        "remediation_cost": round(float(remediation_cost), 2),
        "decision_impact_score": round(float(decision_impact_score), 4),
        "control_effectiveness": round(float(control_effectiveness), 4),
    }


def _simulation_rows_for_identity(
    db: Session,
    *,
    tenant_id: str,
    agent_id: str,
    started_at: datetime,
    limit: int = 800,
) -> list[SimulationRun]:
    rows = db.scalars(
        select(SimulationRun)
        .where(SimulationRun.tenant_id == tenant_id)
        .order_by(desc(SimulationRun.started_at))
        .limit(max(50, min(2000, int(limit))))
    ).all()

    out: list[SimulationRun] = []
    for row in rows:
        ts = _to_utc(getattr(row, "started_at", None))
        if ts is not None and ts < started_at:
            continue
        inputs_used = _safe_dict(getattr(row, "inputs_used", {}))
        results = _safe_dict(getattr(row, "results", {}))
        run_agent_id = _safe_str(inputs_used.get("agent_id") or results.get("agent_id"))
        if run_agent_id == agent_id:
            out.append(row)
    return out


def _anomaly_rows_for_identity(
    db: Session,
    *,
    tenant_id: str,
    agent_id: str,
    started_at: datetime,
) -> list[MonitoringSignal]:
    rows = db.scalars(
        select(MonitoringSignal).where(
            MonitoringSignal.tenant_id == tenant_id,
            MonitoringSignal.signal_type.like("ai_anomaly.%"),
            MonitoringSignal.created_at >= started_at,
        )
    ).all()

    out: list[MonitoringSignal] = []
    for row in rows:
        payload = _safe_dict(getattr(row, "payload", {}))
        if _find_agent_id_from_anomaly(payload) == agent_id:
            out.append(row)
    return out


def get_agent_identity_profile(
    db: Session,
    *,
    tenant_id: str,
    identity_id: str,
    lookback_hours: int = 24 * 30,
    include_graph_details: bool = True,
) -> dict[str, Any]:
    normalized_identity_id = _safe_str(identity_id)
    if not normalized_identity_id:
        raise ValueError("identity_id is required")

    agent = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.tenant_id == tenant_id,
            AgentIdentity.id == normalized_identity_id,
        )
    )
    if agent is None:
        raise ValueError("Identity not found")

    started_at = _started_at(lookback_hours)
    safe_lookback_hours = max(1, min(24 * 180, int(lookback_hours or 24 * 30)))

    events = db.scalars(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.agent_id == normalized_identity_id,
            RuntimeEvent.created_at >= started_at,
        )
    ).all()
    baselines = db.scalars(
        select(AgentActionBaseline).where(
            AgentActionBaseline.tenant_id == tenant_id,
            AgentActionBaseline.agent_identity_id == normalized_identity_id,
        )
    ).all()
    anomaly_rows = _anomaly_rows_for_identity(
        db,
        tenant_id=tenant_id,
        agent_id=normalized_identity_id,
        started_at=started_at,
    )
    simulation_rows = _simulation_rows_for_identity(
        db,
        tenant_id=tenant_id,
        agent_id=normalized_identity_id,
        started_at=started_at,
    )

    now = _utc_now()
    active_tokens = db.scalars(
        select(CapabilityToken).where(
            CapabilityToken.tenant_id == tenant_id,
            CapabilityToken.agent_identity_id == normalized_identity_id,
            CapabilityToken.revoked_at.is_(None),
            CapabilityToken.expires_at >= now,
        )
    ).all()

    token_scopes = sorted(
        {
            _safe_str(scope)
            for row in active_tokens
            for scope in list(row.scopes or [])
            if _safe_str(scope)
        }
    )
    next_expiry: datetime | None = None
    for row in active_tokens:
        expiry = _to_utc(getattr(row, "expires_at", None))
        if expiry is None:
            continue
        if next_expiry is None or expiry < next_expiry:
            next_expiry = expiry

    privilege_score = _privilege_score(agent, events)
    behavior_anomaly_score, anomaly_count = _behavior_anomaly_score(
        events=events,
        anomaly_rows=anomaly_rows,
        baselines=baselines,
    )
    control_failure_score, failed_controls, total_controls_evaluated, triggered_controls, missed_controls = _control_failure_score(events)
    exposure_score, exposure_context = _exposure_score(agent, events)
    simulation_failure_score, simulation_stats = _simulation_failure_score(simulation_rows)

    risk_score = _clamp(
        (0.24 * privilege_score)
        + (0.21 * behavior_anomaly_score)
        + (0.22 * control_failure_score)
        + (0.18 * exposure_score)
        + (0.15 * simulation_failure_score),
        0.0,
        1.0,
    )

    dominant_model, inferred_owner, observed_surfaces = _model_and_owner(events)

    blast_radius_score = _clamp((risk_score * 6.0) + (exposure_score * 2.0) + (privilege_score * 2.0), 0.0, 10.0)
    graph_summary: dict[str, Any] = {}
    owasp_summary: dict[str, Any] = {}
    blast_radius_payload: dict[str, Any] | None = None

    if include_graph_details:
        try:
            blast_radius_payload = compute_agent_blast_radius(
                db,
                tenant_id=tenant_id,
                agent_id=normalized_identity_id,
                lookback_hours=safe_lookback_hours,
            )
            blast_radius_score = _clamp(_safe_float(blast_radius_payload.get("risk_score"), 0.0), 0.0, 10.0)
        except Exception:
            blast_radius_payload = None

        try:
            attack_surface = build_agent_attack_surface_map(
                db,
                tenant_id=tenant_id,
                agent_id=normalized_identity_id,
                lookback_hours=safe_lookback_hours,
                max_edges=1500,
            )
            graph_summary = {
                "node_count": _safe_int(_safe_dict(attack_surface.get("stats")).get("node_count"), 0),
                "edge_count": _safe_int(_safe_dict(attack_surface.get("stats")).get("edge_count"), 0),
                "event_count": _safe_int(_safe_dict(attack_surface.get("stats")).get("event_count"), len(events)),
                "top_connections": list(attack_surface.get("top_connections") or [])[:20],
            }
        except Exception:
            graph_summary = {
                "node_count": 0,
                "edge_count": 0,
                "event_count": len(events),
                "top_connections": [],
            }

        try:
            owasp_coverage = get_agent_owasp_coverage(
                db,
                tenant_id=tenant_id,
                agent_id=normalized_identity_id,
                lookback_hours=safe_lookback_hours,
            )
            owasp_summary = {
                "total_categories": _safe_int(_safe_dict(owasp_coverage.get("summary")).get("total_categories"), 0),
                "runtime_active_categories": _safe_int(_safe_dict(owasp_coverage.get("summary")).get("runtime_active_categories"), 0),
                "simulation_active_categories": _safe_int(_safe_dict(owasp_coverage.get("summary")).get("simulation_active_categories"), 0),
                "controls_observed_count": _safe_int(_safe_dict(owasp_coverage.get("summary")).get("controls_observed_count"), 0),
                "failed_controls_by_framework": dict(owasp_coverage.get("failed_controls_by_framework") or {}),
            }
        except Exception:
            owasp_summary = {
                "total_categories": 0,
                "runtime_active_categories": 0,
                "simulation_active_categories": 0,
                "controls_observed_count": 0,
                "failed_controls_by_framework": {},
            }

    blast_financial = _safe_dict((blast_radius_payload or {}).get("financial_impact"))
    crq = _compute_identity_crq(
        risk_score=risk_score,
        exposure_score=exposure_score,
        control_failure_score=control_failure_score,
        simulation_failure_score=simulation_failure_score,
        behavior_anomaly_score=behavior_anomaly_score,
        blast_radius_score=blast_radius_score,
        tools_count=len([item for item in list(agent.tool_registry or []) if _safe_str(item)]),
        event_count=len(events),
        lookback_hours=safe_lookback_hours,
        anomaly_count=anomaly_count,
        baseline_ale_hint=_safe_float(blast_financial.get("baseline_ale_usd"), 0.0),
        residual_ale_hint=_safe_float(blast_financial.get("annualized_loss_expectancy_usd"), 0.0),
        loss_reduction_hint=_safe_float(blast_financial.get("loss_prevented_usd"), 0.0),
    )

    classification_counter: Counter[str] = Counter(_event_classification(event) for event in events)
    permissions_data = [item for item, _count in classification_counter.most_common(8) if _safe_str(item)]
    if not permissions_data:
        permissions_data = ["unknown"]

    effective_owner = inferred_owner or _safe_str(getattr(agent, "description", "")).split(" ")[0] or None
    recent_actions = _recent_agent_actions(events)
    tools_used = sorted({_event_tool_name(event) for event in events if _event_tool_name(event)})
    linked_finding_ids = sorted(
        {
            _safe_str(_event_metadata(event).get("finding_id"))
            for event in events
            if _safe_str(_event_metadata(event).get("finding_id"))
        }
    )
    finding_rows = db.scalars(
        select(Finding).where(
            Finding.tenant_id == tenant_id,
            Finding.agent_id == normalized_identity_id,
        )
    ).all()
    linked_finding_ids = sorted({*linked_finding_ids, *[_safe_str(row.finding_id) for row in finding_rows if _safe_str(row.finding_id)]})
    behavior_profile = _agent_behavior_profile(
        agent_id=normalized_identity_id,
        events=events,
        baselines=baselines,
        anomaly_score=behavior_anomaly_score,
    )

    identity_payload = {
        "identity_id": normalized_identity_id,
        "type": "agent",
        "owner": effective_owner,
        "model": dominant_model,
        "environment": sorted(set([*observed_surfaces, *[_safe_str(item) for item in list(agent.external_system_access or []) if _safe_str(item)] ]))[:40],
        "permissions": {
            "tools": sorted({_safe_str(item) for item in list(agent.tool_registry or []) if _safe_str(item)}),
            "data": permissions_data,
            "actions": sorted({_safe_str(item) for item in list(agent.action_scope or []) if _safe_str(item)}),
        },
        "token_scope": token_scopes,
        "expiry": (next_expiry.isoformat() if next_expiry else None),
        "status": _safe_str(getattr(agent, "status", "active")) or "active",
        "risk_score": round(float(risk_score), 4),
        "blast_radius_score": round(float(blast_radius_score), 4),
        "tools": tools_used,
        "recent_actions": recent_actions,
        "linked_findings": linked_finding_ids,
        "behavior_profile": behavior_profile,
        "crq": crq,
        "risk_components": {
            "privilege_score": round(float(privilege_score), 4),
            "behavior_anomaly_score": round(float(behavior_anomaly_score), 4),
            "control_failure_score": round(float(control_failure_score), 4),
            "exposure_score": round(float(exposure_score), 4),
            "simulation_failure_score": round(float(simulation_failure_score), 4),
        },
        "token_control": {
            "active_token_count": int(len(active_tokens)),
            "kill_switch_ready": True,
            "rotation_recommended": bool(next_expiry and (next_expiry - now).total_seconds() <= (24 * 3600)),
        },
        "anomalies": {
            "count": int(anomaly_count),
            "recent_high": int(
                len(
                    [
                        row
                        for row in anomaly_rows
                        if _safe_str(row.severity).lower() in {"high", "critical"}
                    ]
                )
            ),
        },
        "controls": {
            "triggered_controls": triggered_controls,
            "missed_controls": missed_controls,
            "failed_controls": int(failed_controls),
            "total_controls_evaluated": int(total_controls_evaluated),
            "effectiveness": crq.get("control_effectiveness", 0.0),
        },
        "simulation": simulation_stats,
        "exposure_context": exposure_context,
        "graph_summary": graph_summary,
        "owasp_summary": owasp_summary,
        "lookback_hours": safe_lookback_hours,
        "updated_at": _utc_now().isoformat(),
    }

    if blast_radius_payload is not None:
        identity_payload["blast_radius"] = blast_radius_payload

    return identity_payload


def list_agent_identity_profiles(
    db: Session,
    *,
    tenant_id: str,
    q: str | None = None,
    limit: int = 100,
    lookback_hours: int = 24 * 30,
) -> list[dict[str, Any]]:
    safe_limit = max(1, min(500, int(limit or 100)))
    stmt = select(AgentIdentity).where(AgentIdentity.tenant_id == tenant_id)
    if q:
        term = f"%{_safe_str(q).lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(AgentIdentity.id).like(term),
                func.lower(AgentIdentity.name).like(term),
                func.lower(AgentIdentity.status).like(term),
            )
        )
    rows = db.scalars(stmt.order_by(desc(AgentIdentity.updated_at)).limit(safe_limit)).all()

    out: list[dict[str, Any]] = []
    for row in rows:
        try:
            out.append(
                get_agent_identity_profile(
                    db,
                    tenant_id=tenant_id,
                    identity_id=row.id,
                    lookback_hours=lookback_hours,
                    include_graph_details=False,
                )
            )
        except Exception:
            continue
    return out


def get_agent_identity_financial_snapshot(
    db: Session,
    *,
    tenant_id: str,
    identity_id: str,
    lookback_hours: int = 24 * 30,
) -> dict[str, Any]:
    profile = get_agent_identity_profile(
        db,
        tenant_id=tenant_id,
        identity_id=identity_id,
        lookback_hours=lookback_hours,
        include_graph_details=False,
    )
    return {
        "identity_id": _safe_str(profile.get("identity_id")),
        "risk_score": _safe_float(profile.get("risk_score"), 0.0),
        "blast_radius_score": _safe_float(profile.get("blast_radius_score"), 0.0),
        "crq": _safe_dict(profile.get("crq")),
        "risk_components": _safe_dict(profile.get("risk_components")),
    }
