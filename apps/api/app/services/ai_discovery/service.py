from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.activity_audit import AIAction, AISession, DeploymentEndpoint, UserRegistry
from app.db.models.ai_iam import AgentIdentity
from app.db.models.discovery import DiscoveryApplication
from app.db.models.monitoring import MonitoringSignal
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.user import User
from app.services.ai_iam_service import auto_quarantine_agent_identity
from app.services.discovery_service import tool_key_for_name
from app.services.runtime_intelligence.streaming import publish_runtime_update


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


def _risk_level_from_event(*, severity: str | None, risk_score: float) -> str:
    normalized = str(severity or "").strip().lower()
    if normalized in {"critical"}:
        return "critical"
    if normalized in {"high"}:
        return "high"
    if normalized in {"med", "medium"}:
        return "med"
    if risk_score >= 0.9:
        return "critical"
    if risk_score >= 0.7:
        return "high"
    if risk_score >= 0.4:
        return "med"
    return "low"


def _provisional_tier_for_risk_level(risk_level: str) -> str:
    normalized = str(risk_level or "").strip().lower()
    if normalized == "critical":
        return "CRITICAL"
    if normalized == "high":
        return "HIGH"
    if normalized == "med":
        return "MEDIUM"
    return "LOW"


def _infer_vendor(metadata: dict[str, Any], *, app_name: str) -> str:
    provider = _safe_str(metadata.get("provider") or metadata.get("model_provider")).lower()
    name = _safe_str(app_name).lower()
    if "openai" in provider or "chatgpt" in name or "openai" in name:
        return "OpenAI"
    if "anthropic" in provider or "claude" in name:
        return "Anthropic"
    if "gemini" in name or "google" in provider or "google" in name:
        return "Google"
    if "microsoft" in provider or "copilot" in name:
        return "Microsoft"
    if "meta" in provider or "llama" in name:
        return "Meta"
    if provider:
        return provider.title()
    return "Unknown"


def _canonical_app_name(*, row: RuntimeEvent, metadata: dict[str, Any]) -> str:
    for value in (
        metadata.get("domain"),
        row.app_id,
        metadata.get("tool_name"),
        metadata.get("provider"),
        metadata.get("model_provider"),
        "unknown_ai_app",
    ):
        candidate = _safe_str(value)
        if candidate:
            return candidate.lower()
    return "unknown_ai_app"


def _source_surface(value: str | None) -> str:
    normalized = _safe_str(value).lower()
    if normalized in {"browser", "gateway", "connector", "dns", "proxy", "monitoring"}:
        return normalized
    if normalized in {"aiiam", "agent"}:
        return "agent"
    return "unknown"


def derive_ai_usage_event(*, row: RuntimeEvent) -> dict[str, Any]:
    metadata = dict(row.metadata_json or {}) if isinstance(row.metadata_json, dict) else {}
    risk_score = _safe_float(row.risk_score, 0.0)
    app_name = _canonical_app_name(row=row, metadata=metadata)
    endpoint_id = _safe_str(
        metadata.get("endpoint_id")
        or metadata.get("host_id")
        or metadata.get("device_id")
    ) or None

    action_type = _safe_str(metadata.get("action_type") or row.event_type) or "unknown_action"
    return {
        "user_id": _safe_str(row.user_id) or None,
        "device_id": endpoint_id,
        "browser_type": _safe_str(metadata.get("browser")) or None,
        "app_name": app_name,
        "model": _safe_str(metadata.get("model_name") or metadata.get("model_provider")) or None,
        "agent_id": _safe_str(row.agent_id) or None,
        "tool_used": _safe_str(metadata.get("tool_name")) or None,
        "timestamp": _to_utc(row.created_at),
        "action_type": action_type,
        "source_surface": _source_surface(row.source_surface),
        "risk_level": _risk_level_from_event(severity=row.severity, risk_score=risk_score),
        "risk_score": risk_score,
        "metadata": {
            "runtime_event_id": row.event_id,
            "correlation_id": row.correlation_id,
            "context_id": row.context_id,
            "chain_id": row.chain_id,
            "decision": _safe_str(metadata.get("decision") or metadata.get("final_decision")) or "unknown",
            "input_signal_types": list(metadata.get("input_signal_types") or []),
            "sensitive_entities": list(metadata.get("sensitive_entities") or []),
            "data_classification": _safe_str(metadata.get("data_classification")) or "unknown",
        },
    }


def _touch_discovery_application(
    db: Session,
    *,
    tenant_id: str,
    usage_event: dict[str, Any],
) -> tuple[DiscoveryApplication, bool]:
    app_name = _safe_str(usage_event.get("app_name")) or "unknown_ai_app"
    tool_key = tool_key_for_name(app_name)
    now = _to_utc(usage_event.get("timestamp") if isinstance(usage_event.get("timestamp"), datetime) else None)
    metadata_event = dict(usage_event.get("metadata") or {})
    source_surface = _safe_str(usage_event.get("source_surface")) or "unknown"
    risk_level = _safe_str(usage_event.get("risk_level")) or "low"

    runtime_user_id = _safe_str(usage_event.get("user_id")) or None
    resolved_owner_user_id = None
    if runtime_user_id:
        # DiscoveryApplication.owner_user_id references users.id. Runtime signals can include
        # non-platform identities, so we only set owner_user_id when the user exists locally.
        owner_row = db.get(User, runtime_user_id)
        if owner_row is not None:
            resolved_owner_user_id = runtime_user_id

    row = db.scalar(
        select(DiscoveryApplication).where(
            DiscoveryApplication.tenant_id == tenant_id,
            DiscoveryApplication.tool_key == tool_key,
        )
    )
    created = row is None
    if row is None:
        row = DiscoveryApplication(
            tenant_id=tenant_id,
            tool_key=tool_key,
            tool_name=app_name,
            vendor=_infer_vendor(metadata_event, app_name=app_name),
            status="discovered",
            owner_user_id=resolved_owner_user_id,
            provisional_risk_tier=_provisional_tier_for_risk_level(risk_level),
            first_seen_at=now,
            last_seen_at=now,
            metadata_json={},
        )
        db.add(row)
        db.flush()
    else:
        row.tool_name = app_name
        row.last_seen_at = max(_to_utc(row.last_seen_at), now)
        if not row.owner_user_id and resolved_owner_user_id:
            row.owner_user_id = resolved_owner_user_id
        if row.status not in {"approved", "blocked"}:
            existing_tier = _safe_str(row.provisional_risk_tier).upper() or "LOW"
            incoming_tier = _provisional_tier_for_risk_level(risk_level)
            tier_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            if tier_rank.get(incoming_tier, 0) > tier_rank.get(existing_tier, 0):
                row.provisional_risk_tier = incoming_tier

    payload = dict(row.metadata_json or {})
    source_counts = dict(payload.get("source_counts") or {})
    source_counts[source_surface] = int(source_counts.get(source_surface) or 0) + 1
    payload["source_counts"] = source_counts
    payload["last_action_type"] = _safe_str(usage_event.get("action_type")) or "unknown_action"
    payload["last_risk_level"] = risk_level
    payload["last_runtime_event_id"] = _safe_str(metadata_event.get("runtime_event_id")) or None
    payload["last_correlation_id"] = _safe_str(metadata_event.get("correlation_id")) or None

    models = {str(item) for item in list(payload.get("models") or []) if str(item).strip()}
    tools = {str(item) for item in list(payload.get("tools") or []) if str(item).strip()}
    users = {str(item) for item in list(payload.get("users") or []) if str(item).strip()}
    agents = {str(item) for item in list(payload.get("agents") or []) if str(item).strip()}
    devices = {str(item) for item in list(payload.get("devices") or []) if str(item).strip()}

    if _safe_str(usage_event.get("model")):
        models.add(_safe_str(usage_event.get("model")))
    if _safe_str(usage_event.get("tool_used")):
        tools.add(_safe_str(usage_event.get("tool_used")))
    if _safe_str(usage_event.get("user_id")):
        users.add(_safe_str(usage_event.get("user_id")))
    if _safe_str(usage_event.get("agent_id")):
        agents.add(_safe_str(usage_event.get("agent_id")))
    if _safe_str(usage_event.get("device_id")):
        devices.add(_safe_str(usage_event.get("device_id")))

    payload["models"] = sorted(models)[:80]
    payload["tools"] = sorted(tools)[:80]
    payload["users"] = sorted(users)[:200]
    payload["agents"] = sorted(agents)[:200]
    payload["devices"] = sorted(devices)[:200]
    row.metadata_json = payload
    db.flush()
    return row, created


def process_runtime_event_for_ai_discovery(
    db: Session,
    *,
    event: RuntimeEvent,
) -> dict[str, Any]:
    usage_event = derive_ai_usage_event(row=event)
    auto_quarantine_result: dict[str, Any] | None = None
    agent_hint = _safe_str(usage_event.get("agent_id")) or None
    if settings.ai_iam_auto_quarantine_new_agents and agent_hint:
        existing_agent = db.scalar(
            select(AgentIdentity).where(
                AgentIdentity.tenant_id == event.tenant_id,
                AgentIdentity.id == agent_hint,
            )
        )
        if existing_agent is None:
            auto_quarantine_result = auto_quarantine_agent_identity(
                db,
                tenant_id=event.tenant_id,
                discovered_agent_id=agent_hint,
                source_surface=_safe_str(usage_event.get("source_surface")) or "unknown",
                reason_code="runtime_discovery:new_agent_signal",
                ai_system_id=event.ai_system_id,
                actor_user_id=_safe_str(event.user_id) or None,
                metadata={
                    "runtime_event_id": event.event_id,
                    "event_type": event.event_type,
                    "risk_score": _safe_float(event.risk_score, 0.0),
                    "decision": _safe_str((usage_event.get("metadata") or {}).get("decision")),
                },
                correlation_id=_safe_str(event.correlation_id) or None,
            )

    app_row, created = _touch_discovery_application(
        db,
        tenant_id=event.tenant_id,
        usage_event=usage_event,
    )

    try:
        publish_runtime_update(
            tenant_id=event.tenant_id,
            event_type="runtime.discovery.updated",
            payload={
                "runtime_event_id": event.event_id,
                "tool_key": app_row.tool_key,
                "app_name": app_row.tool_name,
                "status": app_row.status,
                "provisional_risk_tier": app_row.provisional_risk_tier,
                "created": created,
                "source_surface": usage_event.get("source_surface"),
                "risk_level": usage_event.get("risk_level"),
                "auto_quarantine": {
                    "enabled": bool(settings.ai_iam_auto_quarantine_new_agents),
                    "created": bool((auto_quarantine_result or {}).get("created")),
                    "agent_id": _safe_str(getattr((auto_quarantine_result or {}).get("agent"), "id", None)) or None,
                    "reason": _safe_str((auto_quarantine_result or {}).get("reason")) or None,
                },
            },
        )
    except Exception:
        # Discovery streaming is strictly non-blocking.
        pass

    return {
        "usage_event": usage_event,
        "discovery_application_id": app_row.id,
        "tool_key": app_row.tool_key,
        "status": app_row.status,
        "created": created,
        "risk_tier": app_row.provisional_risk_tier,
        "auto_quarantine": {
            "enabled": bool(settings.ai_iam_auto_quarantine_new_agents),
            "created": bool((auto_quarantine_result or {}).get("created")),
            "agent_id": _safe_str(getattr((auto_quarantine_result or {}).get("agent"), "id", None)) or None,
            "reason": _safe_str((auto_quarantine_result or {}).get("reason")) or None,
        },
    }


def list_usage_events(
    db: Session,
    *,
    tenant_id: str,
    lookback_hours: int = 24 * 7,
    source_surface: str | None = None,
    user_id: str | None = None,
    page: int = 1,
    page_size: int = 100,
) -> dict[str, Any]:
    safe_hours = max(1, min(24 * 90, int(lookback_hours or 24 * 7)))
    safe_page = max(1, int(page or 1))
    safe_page_size = max(1, min(500, int(page_size or 100)))
    started_at = _utcnow() - timedelta(hours=safe_hours)

    stmt = select(RuntimeEvent).where(
        RuntimeEvent.tenant_id == tenant_id,
        RuntimeEvent.created_at >= started_at,
    )
    if source_surface:
        stmt = stmt.where(RuntimeEvent.source_surface == _source_surface(source_surface))
    if user_id:
        stmt = stmt.where(RuntimeEvent.user_id == str(user_id))
    rows = db.scalars(stmt.order_by(desc(RuntimeEvent.created_at))).all()
    items = [derive_ai_usage_event(row=row) for row in rows]
    total = len(items)
    start = (safe_page - 1) * safe_page_size
    end = start + safe_page_size
    return {
        "items": items[start:end],
        "total": total,
        "page": safe_page,
        "page_size": safe_page_size,
    }


def build_discovery_panel_state(
    db: Session,
    *,
    tenant_id: str,
    lookback_hours: int = 24 * 7,
) -> dict[str, Any]:
    safe_hours = max(1, min(24 * 90, int(lookback_hours or 24 * 7)))
    started_at = _utcnow() - timedelta(hours=safe_hours)

    runtime_rows = db.scalars(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.created_at >= started_at,
        )
    ).all()
    discovery_rows = db.scalars(
        select(DiscoveryApplication).where(DiscoveryApplication.tenant_id == tenant_id)
    ).all()

    usage_events = [derive_ai_usage_event(row=row) for row in runtime_rows]
    app_counter = Counter(_safe_str(item.get("app_name")) or "unknown_ai_app" for item in usage_events)
    surface_counter = Counter(_safe_str(item.get("source_surface")) or "unknown" for item in usage_events)
    risk_counter = Counter(_safe_str(item.get("risk_level")) or "low" for item in usage_events)

    day_buckets: dict[str, int] = defaultdict(int)
    for event in usage_events:
        ts = event.get("timestamp")
        bucket = _to_utc(ts if isinstance(ts, datetime) else None).strftime("%m-%d")
        day_buckets[bucket] += 1

    status_counter = Counter(str(row.status or "").strip().lower() or "unknown" for row in discovery_rows)
    shadow_count = status_counter.get("discovered", 0) + status_counter.get("monitoring", 0)

    return {
        "window_hours": safe_hours,
        "apps_detected": len(app_counter),
        "total_usage_events": len(usage_events),
        "shadow_ai_count": shadow_count,
        "approved_apps": status_counter.get("approved", 0),
        "blocked_apps": status_counter.get("blocked", 0),
        "source_breakdown": dict(surface_counter),
        "risk_breakdown": {
            "low": int(risk_counter.get("low", 0)),
            "med": int(risk_counter.get("med", 0)),
            "high": int(risk_counter.get("high", 0)),
            "critical": int(risk_counter.get("critical", 0)),
        },
        "usage_trend": [
            {"label": label, "count": count}
            for label, count in sorted(day_buckets.items(), key=lambda item: item[0])
        ],
        "top_apps": [
            {"app_name": app, "usage_count": count}
            for app, count in app_counter.most_common(12)
        ],
    }


def _anomaly_score_for_user(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
) -> tuple[float, int]:
    signals = db.scalars(
        select(MonitoringSignal).where(
            MonitoringSignal.tenant_id == tenant_id,
            MonitoringSignal.signal_type.like("ai_anomaly.%"),
            MonitoringSignal.created_at >= (_utcnow() - timedelta(days=7)),
        )
    ).all()
    user_signals = []
    for row in signals:
        payload = dict(row.payload or {}) if isinstance(row.payload, dict) else {}
        if _safe_str(payload.get("user_id")) == user_id:
            user_signals.append(row)
    if not user_signals:
        return 0.0, 0
    severity_weight = {"low": 1, "med": 2, "high": 3, "critical": 4}
    score = 0.0
    for row in user_signals:
        score += float(severity_weight.get(str(row.severity or "").strip().lower(), 1))
    normalized = min(100.0, (score / max(1, len(user_signals))) * 25.0)
    return round(normalized, 2), len(user_signals)


def list_identity_profiles(
    db: Session,
    *,
    tenant_id: str,
    q: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    safe_limit = max(1, min(500, int(limit or 100)))
    stmt = select(UserRegistry).where(UserRegistry.tenant_id == tenant_id)
    if q:
        term = f"%{str(q).strip().lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(UserRegistry.display_name).like(term),
                func.lower(UserRegistry.email).like(term),
                func.lower(UserRegistry.user_id).like(term),
            )
        )
    users = db.scalars(stmt.order_by(desc(UserRegistry.last_seen_at)).limit(safe_limit)).all()
    return [get_identity_profile(db, tenant_id=tenant_id, user_id=row.user_id) for row in users]


def get_identity_profile(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    lookback_hours: int = 24 * 30,
) -> dict[str, Any]:
    safe_hours = max(1, min(24 * 180, int(lookback_hours or 24 * 30)))
    started_at = _utcnow() - timedelta(hours=safe_hours)
    user_row = db.scalar(
        select(UserRegistry).where(
            UserRegistry.tenant_id == tenant_id,
            UserRegistry.user_id == user_id,
        )
    )
    if user_row is None:
        return {
            "user_id": user_id,
            "display_name": "",
            "email": "",
            "devices": [],
            "browsers": [],
            "ai_apps": [],
            "agents": [],
            "tools": [],
            "usage_patterns": {
                "window_hours": safe_hours,
                "usage_time_distribution": {},
                "frequency_per_day": {},
                "prompt_types": {},
                "tool_usage_patterns": {},
                "data_access_patterns": {},
            },
            "risk_score": 0.0,
            "anomaly_score": 0.0,
            "anomaly_count_7d": 0,
        }

    endpoints = db.scalars(
        select(DeploymentEndpoint).where(
            DeploymentEndpoint.tenant_id == tenant_id,
            DeploymentEndpoint.user_id == user_id,
        )
    ).all()
    sessions = db.scalars(
        select(AISession).where(
            AISession.tenant_id == tenant_id,
            AISession.user_id == user_id,
            AISession.start_time >= started_at,
        )
    ).all()
    actions = db.scalars(
        select(AIAction).where(
            AIAction.tenant_id == tenant_id,
            AIAction.user_id == user_id,
            AIAction.timestamp >= started_at,
        )
    ).all()

    by_hour: Counter[int] = Counter()
    by_day: Counter[str] = Counter()
    prompt_types: Counter[str] = Counter()
    tool_usage: Counter[str] = Counter()
    data_patterns: Counter[str] = Counter()

    app_set: set[str] = set()
    agent_set: set[str] = set()
    tool_set: set[str] = set()
    for action in actions:
        ts = _to_utc(action.timestamp)
        by_hour[int(ts.hour)] += 1
        by_day[ts.strftime("%Y-%m-%d")] += 1
        app_name = _safe_str(action.ai_app)
        if app_name:
            app_set.add(app_name)
        metadata = dict(action.metadata_json or {}) if isinstance(action.metadata_json, dict) else {}
        action_type = _safe_str(action.action_type) or "unknown"
        prompt_types[action_type] += 1
        tool_name = _safe_str(metadata.get("tool_name"))
        if tool_name:
            tool_usage[tool_name] += 1
            tool_set.add(tool_name)
        agent_id = _safe_str(metadata.get("agent_id") or metadata.get("actor_agent_id"))
        if agent_id:
            agent_set.add(agent_id)
        class_hint = _safe_str(action.data_classification) or "unknown"
        data_patterns[class_hint.lower()] += 1

    anomaly_score, anomaly_count = _anomaly_score_for_user(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
    )

    return {
        "user_id": user_row.user_id,
        "display_name": user_row.display_name,
        "email": user_row.email,
        "devices": sorted({_safe_str(endpoint.endpoint_id) for endpoint in endpoints if _safe_str(endpoint.endpoint_id)}),
        "browsers": sorted({_safe_str(endpoint.browser_type) for endpoint in endpoints if _safe_str(endpoint.browser_type)}),
        "ai_apps": sorted(app_set),
        "agents": sorted(agent_set),
        "tools": sorted(tool_set),
        "usage_patterns": {
            "window_hours": safe_hours,
            "usage_time_distribution": {str(hour): count for hour, count in sorted(by_hour.items())},
            "frequency_per_day": dict(sorted(by_day.items())),
            "prompt_types": dict(prompt_types.most_common(10)),
            "tool_usage_patterns": dict(tool_usage.most_common(20)),
            "data_access_patterns": dict(data_patterns),
            "session_count": len(sessions),
            "action_count": len(actions),
        },
        "risk_score": round(float(user_row.risk_score or 0.0), 4),
        "anomaly_score": anomaly_score,
        "anomaly_count_7d": anomaly_count,
    }
