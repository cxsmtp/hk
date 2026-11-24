from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.models.ai_iam import AgentIdentity
from app.db.models.discovery import DiscoveryApplication
from app.db.models.monitoring import MonitoringSignal
from app.db.models.runtime_intelligence import RuntimeEvent, RuntimeGovernanceRecommendation
from app.services.ai_iam_service import track_behavior_anomaly
from app.services.audit_service import write_audit_log
from app.services.discovery_service import tool_key_for_name
from app.services.evidence_service import create_evidence_node
from app.services.runtime_intelligence.simulation_trigger_service import create_runtime_simulation_trigger
from app.services.runtime_intelligence.streaming import publish_runtime_update


SEVERITY_ORDER = {"low": 0, "med": 1, "high": 2, "critical": 3}

ANOMALY_CONTROL_IDS: dict[str, list[str]] = {
    "time_anomaly": ["AI_IDENTITY_BINDING", "PRIVILEGE_DRIFT_DETECTION"],
    "volume_anomaly": ["PRIVILEGE_DRIFT_DETECTION", "TOKEN_SCOPE_ENFORCEMENT"],
    "app_anomaly": ["SHADOW_AI_DETECTION", "POLICY_ENFORCEMENT_CONTROL"],
    "tool_anomaly": ["TOOL_CALL_VALIDATION", "AGENT_ACTION_AUTHORIZATION"],
    "data_extraction_anomaly": ["SENSITIVE_DATA_DETECTION", "PII_EXFILTRATION_PREVENTION", "CONTEXT_LEAKAGE_DETECTION"],
    "agent_behavior_anomaly": ["AGENT_ACTION_AUTHORIZATION", "CHAIN_OF_ACTION_VALIDATION", "NON_HUMAN_IDENTITY_CONTROL"],
}

ANOMALY_SIM_REASON: dict[str, str] = {
    "time_anomaly": "repeated_prompt_injection_attempts",
    "volume_anomaly": "repeated_sensitive_data_attempts",
    "app_anomaly": "unknown_ai_adoption_spike",
    "tool_anomaly": "repeated_tool_denials",
    "data_extraction_anomaly": "multi_tool_data_exposure",
    "agent_behavior_anomaly": "abnormal_agent_chains",
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_utc(value: datetime | None) -> datetime:
    if value is None:
        return _utcnow()
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


def _severity(value: str) -> str:
    normalized = _safe_str(value).lower()
    if normalized == "medium":
        return "med"
    if normalized in {"low", "med", "high", "critical"}:
        return normalized
    return "low"


def _event_metadata(event: RuntimeEvent) -> dict[str, Any]:
    return dict(event.metadata_json or {}) if isinstance(event.metadata_json, dict) else {}


def _event_app_name(event: RuntimeEvent, metadata: dict[str, Any]) -> str:
    for value in (
        metadata.get("domain"),
        event.app_id,
        metadata.get("tool_name"),
        metadata.get("provider"),
        metadata.get("model_provider"),
    ):
        candidate = _safe_str(value)
        if candidate:
            return candidate.lower()
    return "unknown_ai_app"


def _event_tool_name(metadata: dict[str, Any]) -> str | None:
    candidate = _safe_str(metadata.get("tool_name"))
    return candidate or None


def _event_action(event: RuntimeEvent, metadata: dict[str, Any]) -> str:
    return _safe_str(metadata.get("action_type") or event.event_type) or "unknown_action"


def _event_decision(metadata: dict[str, Any]) -> str:
    return _safe_str(metadata.get("decision") or metadata.get("final_decision")).lower() or "unknown"


def _find_historical_runtime_events(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    since: datetime,
    exclude_event_id: str,
) -> list[RuntimeEvent]:
    rows = db.scalars(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.user_id == user_id,
            RuntimeEvent.created_at >= since,
        )
    ).all()
    return [row for row in rows if _safe_str(row.event_id) != exclude_event_id]


def _time_and_volume_anomalies(
    *,
    event: RuntimeEvent,
    history: list[RuntimeEvent],
) -> list[dict[str, Any]]:
    if not history:
        return []
    anomalies: list[dict[str, Any]] = []
    now = _to_utc(event.created_at)
    total_hist = len(history)
    by_hour = Counter(_to_utc(row.created_at).hour for row in history)
    current_hour_ratio = by_hour.get(now.hour, 0) / max(1, total_hist)
    if total_hist >= 30 and current_hour_ratio <= 0.02:
        anomalies.append(
            {
                "type": "time_anomaly",
                "severity": "med",
                "reason": "Current usage time is outside learned user baseline.",
                "confidence": 0.76,
            }
        )

    one_hour_start = now - timedelta(hours=1)
    current_hour_count = sum(1 for row in history if _to_utc(row.created_at) >= one_hour_start) + 1
    avg_hourly = total_hist / max(1.0, (max(1.0, (now - (_to_utc(now) - timedelta(days=14))).total_seconds()) / 3600.0))
    if current_hour_count >= max(12, int(avg_hourly * 4.0)):
        severity = "high" if current_hour_count < 30 else "critical"
        anomalies.append(
            {
                "type": "volume_anomaly",
                "severity": severity,
                "reason": "Action volume exceeded user baseline in the current hour.",
                "confidence": 0.82 if severity == "high" else 0.9,
            }
        )
    return anomalies


def _app_and_tool_anomalies(
    *,
    event: RuntimeEvent,
    metadata: dict[str, Any],
    history: list[RuntimeEvent],
) -> list[dict[str, Any]]:
    if len(history) < 12:
        return []
    app_name = _event_app_name(event, metadata)
    tool_name = _event_tool_name(metadata)
    seen_apps = {_event_app_name(row, _event_metadata(row)) for row in history}
    seen_tools = {
        _event_tool_name(_event_metadata(row))
        for row in history
        if _event_tool_name(_event_metadata(row))
    }
    anomalies: list[dict[str, Any]] = []
    if app_name and app_name not in seen_apps:
        anomalies.append(
            {
                "type": "app_anomaly",
                "severity": "med",
                "reason": f"New AI application observed for identity baseline: {app_name}.",
                "confidence": 0.74,
            }
        )
    if tool_name and tool_name not in seen_tools:
        anomalies.append(
            {
                "type": "tool_anomaly",
                "severity": "med",
                "reason": f"New tool invocation observed for identity baseline: {tool_name}.",
                "confidence": 0.71,
            }
        )
    return anomalies


def _data_extraction_anomaly(
    *,
    event: RuntimeEvent,
    metadata: dict[str, Any],
) -> dict[str, Any] | None:
    decision = _event_decision(metadata)
    risk_score = _safe_float(event.risk_score, 0.0)
    input_signals = {str(item).strip().lower() for item in list(metadata.get("input_signal_types") or []) if str(item).strip()}
    sensitive_entities = list(metadata.get("sensitive_entities") or [])
    contains_sensitive = bool(metadata.get("contains_sensitive")) or bool(sensitive_entities)
    destination_external = bool(metadata.get("destination_is_external"))
    sensitive_signal_present = any(
        signal in input_signals
        for signal in {
            "sensitive_data_pattern",
            "sensitive_data_detected",
            "guardian.browser.sensitive_prompt_matched",
        }
    )
    if not contains_sensitive and not sensitive_signal_present:
        return None
    if decision in {"block", "deny", "denied"} and not destination_external:
        return None
    severity = "critical" if risk_score >= 0.9 else "high"
    return {
        "type": "data_extraction_anomaly",
        "severity": severity,
        "reason": "Sensitive data pattern detected in an action that was not fully denied before execution.",
        "confidence": 0.9 if severity == "critical" else 0.82,
    }


def _agent_behavior_anomaly(
    db: Session,
    *,
    event: RuntimeEvent,
    metadata: dict[str, Any],
) -> dict[str, Any] | None:
    if not _safe_str(event.agent_id):
        return None
    profile = track_behavior_anomaly(
        db,
        tenant_id=event.tenant_id,
        agent_identity_id=_safe_str(event.agent_id),
        action=_event_action(event, metadata),
        now=_to_utc(event.created_at),
    )
    if not bool(profile.get("is_anomaly")):
        return None
    return {
        "type": "agent_behavior_anomaly",
        "severity": "high",
        "reason": "Agent action frequency exceeded learned baseline.",
        "confidence": 0.86,
        "baseline": profile,
    }


def _related_entities(event: RuntimeEvent, metadata: dict[str, Any]) -> list[dict[str, str]]:
    entities: list[dict[str, str]] = []
    if _safe_str(event.user_id):
        entities.append({"type": "user", "id": _safe_str(event.user_id)})
    if _safe_str(event.agent_id):
        entities.append({"type": "agent", "id": _safe_str(event.agent_id)})
    app_name = _event_app_name(event, metadata)
    if app_name:
        entities.append({"type": "ai_app", "id": app_name})
    tool_name = _event_tool_name(metadata)
    if tool_name:
        entities.append({"type": "tool", "id": tool_name})
    endpoint_id = _safe_str(metadata.get("endpoint_id") or metadata.get("host_id"))
    if endpoint_id:
        entities.append({"type": "device", "id": endpoint_id})
    dedup: dict[tuple[str, str], dict[str, str]] = {}
    for row in entities:
        key = (_safe_str(row.get("type")).lower(), _safe_str(row.get("id")))
        if key[0] and key[1]:
            dedup[key] = {"type": key[0], "id": key[1]}
    return sorted(dedup.values(), key=lambda row: (row["type"], row["id"]))


def _auto_restrict_agent_if_needed(
    db: Session,
    *,
    tenant_id: str,
    agent_id: str,
    anomaly: dict[str, Any],
    event: RuntimeEvent,
) -> str | None:
    severity = _severity(anomaly.get("severity") or "low")
    if severity not in {"high", "critical"}:
        return None
    metadata = _event_metadata(event)
    if _is_owner_approved_read_only_mcp_session(metadata):
        return "session_bound_read_only_mcp_observed"
    row = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.tenant_id == tenant_id,
            AgentIdentity.id == agent_id,
        )
    )
    if row is None:
        return None
    if str(row.status or "").strip().lower() == "restricted":
        return "agent_already_restricted"

    existing_scope = [str(item) for item in list(row.action_scope or []) if str(item).strip()]
    reduced_scope = [
        item
        for item in existing_scope
        if item.lower().endswith(".read") or item.lower().startswith("read.") or item.lower() == "tool.read"
    ]
    row.status = "restricted"
    if reduced_scope:
        row.action_scope = sorted(set(reduced_scope))
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=None,
        actor_type="system",
        action="ai_iam.agent.auto_restricted",
        resource_type="agent_identity",
        resource_id=row.id,
        payload={
            "runtime_event_id": event.event_id,
            "reason": anomaly.get("reason"),
            "severity": severity,
            "new_action_scope": list(row.action_scope or []),
        },
        correlation_id=event.correlation_id,
    )
    return "agent_restricted"


def _is_owner_approved_read_only_mcp_session(metadata: dict[str, Any]) -> bool:
    """Keep HMAIR/Codex MCP acceptance probes visible without self-quarantine.

    This is intentionally narrow: the event must already be reduced to public
    data, have a valid persisted session, have valid session bounds, and carry
    an active purpose-bound permission whose allowed actions are read-only.
    Unknown agents, invalid sessions, non-public data, or write actions still
    follow the normal auto-restriction path.
    """

    if _safe_str(metadata.get("source_surface")).lower() not in {"gateway", "mcp", "api"}:
        return False
    classification = _safe_str(metadata.get("data_classification")).lower()
    if classification != "public":
        return False

    session_validation = metadata.get("session_validation")
    if not isinstance(session_validation, dict) or session_validation.get("valid") is not True:
        return False
    bounds = session_validation.get("bounds_enforcement")
    if not isinstance(bounds, dict) or bounds.get("valid") is not True:
        return False

    dynamic_permission = metadata.get("dynamic_permission")
    if not isinstance(dynamic_permission, dict):
        return False
    if _safe_str(dynamic_permission.get("status")).lower() != "active":
        return False
    if _safe_str(dynamic_permission.get("mode")).lower() not in {"block", "monitor", "warn", "approval"}:
        return False

    allowed_actions = dynamic_permission.get("allowed_actions")
    if not isinstance(allowed_actions, list):
        scope = dynamic_permission.get("scope")
        allowed_actions = scope.get("allowed_actions") if isinstance(scope, dict) else []
    normalized_actions = {_safe_str(item).lower() for item in allowed_actions if _safe_str(item)}
    if not normalized_actions:
        return False
    return normalized_actions.issubset({"file_read", "tool.read", "read", "read.pull_request"})


def _auto_block_discovery_app_if_needed(
    db: Session,
    *,
    tenant_id: str,
    app_name: str,
    anomaly: dict[str, Any],
    event: RuntimeEvent,
) -> str | None:
    severity = _severity(anomaly.get("severity") or "low")
    if severity != "critical":
        return None
    tool_key = tool_key_for_name(app_name)
    row = db.scalar(
        select(DiscoveryApplication).where(
            DiscoveryApplication.tenant_id == tenant_id,
            DiscoveryApplication.tool_key == tool_key,
        )
    )
    if row is None:
        return None
    if str(row.status or "").strip().lower() in {"blocked", "approved"}:
        return None
    row.status = "blocked"
    row.provisional_risk_tier = "CRITICAL"
    metadata = dict(row.metadata_json or {})
    metadata["auto_block_reason"] = anomaly.get("reason")
    metadata["auto_block_runtime_event_id"] = event.event_id
    metadata["auto_blocked_at"] = _utcnow().isoformat()
    row.metadata_json = metadata
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=None,
        actor_type="system",
        action="discovery.application.auto_blocked",
        resource_type="discovery_application",
        resource_id=row.id,
        payload={
            "runtime_event_id": event.event_id,
            "reason": anomaly.get("reason"),
            "severity": severity,
            "tool_key": tool_key,
        },
        correlation_id=event.correlation_id,
    )
    return "application_blocked"


def detect_and_enforce_runtime_anomalies(
    db: Session,
    *,
    event: RuntimeEvent,
) -> list[dict[str, Any]]:
    metadata = _event_metadata(event)
    anomalies: list[dict[str, Any]] = []
    if _safe_str(event.user_id):
        history = _find_historical_runtime_events(
            db,
            tenant_id=event.tenant_id,
            user_id=_safe_str(event.user_id),
            since=_to_utc(event.created_at) - timedelta(days=14),
            exclude_event_id=_safe_str(event.event_id),
        )
        anomalies.extend(_time_and_volume_anomalies(event=event, history=history))
        anomalies.extend(_app_and_tool_anomalies(event=event, metadata=metadata, history=history))
    else:
        history = []

    data_anomaly = _data_extraction_anomaly(event=event, metadata=metadata)
    if data_anomaly:
        anomalies.append(data_anomaly)
    agent_anomaly = _agent_behavior_anomaly(db, event=event, metadata=metadata)
    if agent_anomaly:
        anomalies.append(agent_anomaly)

    if not anomalies:
        return []

    app_name = _event_app_name(event, metadata)
    related_entities = _related_entities(event, metadata)
    crq = dict(metadata.get("crq") or {})
    ale = _safe_float(crq.get("annualized_loss_expectancy"), 0.0)

    persisted: list[dict[str, Any]] = []
    for idx, anomaly in enumerate(anomalies):
        anomaly_type = _safe_str(anomaly.get("type")) or "unknown_anomaly"
        severity = _severity(anomaly.get("severity") or "low")
        control_ids = list(ANOMALY_CONTROL_IDS.get(anomaly_type, []))
        confidence = _safe_float(anomaly.get("confidence"), 0.7)
        risk_increase = round(max(0.0, ale * confidence), 2)
        payload = {
            "runtime_event_id": event.event_id,
            "correlation_id": event.correlation_id,
            "user_id": _safe_str(event.user_id) or None,
            "agent_id": _safe_str(event.agent_id) or None,
            "app_name": app_name,
            "severity": severity,
            "reason": _safe_str(anomaly.get("reason")) or "Anomaly detected against baseline behavior.",
            "confidence": confidence,
            "related_entities": related_entities,
            "control_ids": control_ids,
            "potential_loss_usd": ale,
            "risk_increase_usd": risk_increase,
            "source_surface": event.source_surface,
            "action_type": _event_action(event, metadata),
            "decision": _event_decision(metadata),
            "index": idx,
        }
        signal = MonitoringSignal(
            tenant_id=event.tenant_id,
            ai_system_id=event.ai_system_id,
            signal_type=f"ai_anomaly.{anomaly_type}",
            severity=severity,
            payload=payload,
        )
        db.add(signal)
        db.flush()
        evidence = create_evidence_node(
            db,
            tenant_id=event.tenant_id,
            node_type="ai_anomaly",
            signal_type=f"ai_anomaly.{anomaly_type}",
            label=f"AI anomaly detected: {anomaly_type}",
            payload={
                **payload,
                "monitoring_signal_id": signal.id,
            },
            correlation_id=event.correlation_id,
        )
        payload["evidence_node_id"] = evidence.id

        recommendation = RuntimeGovernanceRecommendation(
            tenant_id=event.tenant_id,
            event_id=event.event_id,
            ai_system_id=event.ai_system_id,
            recommendation_type="identity_anomaly_response",
            reason_code=anomaly_type,
            priority=("high" if severity in {"high", "critical"} else "med"),
            payload={
                "anomaly_type": anomaly_type,
                "reason": payload["reason"],
                "control_ids": control_ids,
                "monitoring_signal_id": signal.id,
                "evidence_node_id": evidence.id,
                "risk_increase_usd": risk_increase,
                "recommended_action": "require_approval" if severity in {"high", "critical"} else "monitor",
            },
            status="proposed",
        )
        db.add(recommendation)
        db.flush()

        create_runtime_simulation_trigger(
            db,
            tenant_id=event.tenant_id,
            ai_system_id=event.ai_system_id,
            event_id=event.event_id,
            reason_code=ANOMALY_SIM_REASON.get(anomaly_type, "repeated_prompt_injection_attempts"),
            related_control_ids=control_ids,
            evidence_node_ids=[str(evidence.id)],
            correlation_id=event.correlation_id,
            recommended_action="Run targeted simulation pack for anomaly validation.",
        )

        enforcement_action = None
        if anomaly_type == "agent_behavior_anomaly" and _safe_str(event.agent_id):
            enforcement_action = _auto_restrict_agent_if_needed(
                db,
                tenant_id=event.tenant_id,
                agent_id=_safe_str(event.agent_id),
                anomaly=anomaly,
                event=event,
            )
        if anomaly_type in {"data_extraction_anomaly", "app_anomaly"} and app_name:
            maybe_action = _auto_block_discovery_app_if_needed(
                db,
                tenant_id=event.tenant_id,
                app_name=app_name,
                anomaly=anomaly,
                event=event,
            )
            enforcement_action = enforcement_action or maybe_action

        anomaly_record = {
            "signal_id": signal.id,
            "anomaly_type": anomaly_type,
            "severity": severity,
            "reason": payload["reason"],
            "confidence": confidence,
            "related_entities": related_entities,
            "control_ids": control_ids,
            "monitoring_signal_id": signal.id,
            "recommendation_id": recommendation.recommendation_id,
            "evidence_node_id": evidence.id,
            "risk_context": {
                "potential_loss_usd": ale,
                "risk_increase_usd": risk_increase,
            },
            "enforcement_action": enforcement_action or "none",
        }
        persisted.append(anomaly_record)
        try:
            publish_runtime_update(
                tenant_id=event.tenant_id,
                event_type="runtime.anomaly.detected",
                payload={
                    "runtime_event_id": event.event_id,
                    "correlation_id": event.correlation_id,
                    "anomaly_type": anomaly_type,
                    "severity": severity,
                    "confidence": confidence,
                    "enforcement_action": anomaly_record["enforcement_action"],
                    "monitoring_signal_id": signal.id,
                    "recommendation_id": recommendation.recommendation_id,
                },
            )
        except Exception:
            # Streaming remains non-blocking.
            pass

    return persisted


def list_recent_anomaly_events(
    db: Session,
    *,
    tenant_id: str,
    lookback_hours: int = 24 * 7,
    severity: str | None = None,
    user_id: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    safe_hours = max(1, min(24 * 90, int(lookback_hours or 24 * 7)))
    safe_limit = max(1, min(1000, int(limit or 200)))
    started_at = _utcnow() - timedelta(hours=safe_hours)
    stmt = select(MonitoringSignal).where(
        MonitoringSignal.tenant_id == tenant_id,
        MonitoringSignal.signal_type.like("ai_anomaly.%"),
        MonitoringSignal.created_at >= started_at,
    )
    if severity:
        stmt = stmt.where(MonitoringSignal.severity == _severity(severity))
    rows = db.scalars(stmt.order_by(desc(MonitoringSignal.created_at)).limit(safe_limit)).all()
    items: list[dict[str, Any]] = []
    for row in rows:
        payload = dict(row.payload or {}) if isinstance(row.payload, dict) else {}
        if user_id and _safe_str(payload.get("user_id")) != _safe_str(user_id):
            continue
        items.append(
            {
                "id": row.id,
                "signal_type": row.signal_type,
                "severity": _severity(row.severity),
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "payload": payload,
                "anomaly_type": row.signal_type.replace("ai_anomaly.", "", 1),
                "reason": _safe_str(payload.get("reason")) or "Anomaly detected",
                "confidence": _safe_float(payload.get("confidence"), 0.0),
                "related_entities": list(payload.get("related_entities") or []),
                "control_ids": list(payload.get("control_ids") or []),
                "runtime_event_id": _safe_str(payload.get("runtime_event_id")) or None,
                "monitoring_signal_id": _safe_str(payload.get("monitoring_signal_id")) or row.id,
                "risk_context": {
                    "potential_loss_usd": _safe_float(payload.get("potential_loss_usd"), 0.0),
                    "risk_increase_usd": _safe_float(payload.get("risk_increase_usd"), 0.0),
                },
            }
        )
    return items
