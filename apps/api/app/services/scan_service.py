from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from threading import Thread
from typing import Any
from urllib.parse import quote, urlparse
from uuid import uuid4

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.observability import log_structured
from app.db.models.activity_audit import AIAction, AIActionAlert, DeploymentEndpoint, UserRegistry
from app.db.models.finding import Finding
from app.db.models.monitoring import MonitoringSignal
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.scan import ScanResult
from app.db.models.shadow_ai import ShadowAIEntity
from app.db.session import SessionLocal
from app.services.provider_catalog import resolve_provider
from app.services.audit_service import write_audit_log
from app.services.shadow_ai.discovery_engine import safe_process_runtime_event_for_shadow_discovery


ALLOWED_SCAN_TYPES = {"discovery", "user", "risk", "policy"}
ALLOWED_SCOPES = {"global", "user_id", "endpoint_id", "ai_app"}
OPEN_FINDING_STATUSES = {"open", "reviewing", "proposed", "pending"}
HIGH_RISK_SEVERITIES = {"high", "critical"}
STALLED_RUNNING_SCAN_SECONDS = 90
APPROVED_GOVERNANCE_STATES = {"approved", "active", "live"}
DEFAULT_SCAN_LOOKBACK_HOURS = 24 * 14
MIN_SCAN_LOOKBACK_HOURS = 1
MAX_SCAN_LOOKBACK_HOURS = 24 * 90
DEFAULT_SCAN_EVENT_LIMIT = 3000
MAX_SCAN_EVENT_LIMIT = 10000
SOURCE_SURFACES = {"browser", "gateway", "connector", "aiiam", "monitoring", "endpoint", "dns", "proxy", "foundry", "copilot"}
RISK_FROM_SEVERITY = {
    "low": 0.2,
    "med": 0.5,
    "medium": 0.5,
    "high": 0.8,
    "critical": 0.95,
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_scan_type(value: str | None) -> str:
    normalized = str(value or "").strip().lower() or "discovery"
    if normalized not in ALLOWED_SCAN_TYPES:
        raise ValueError(f"unsupported scan_type: {value}")
    return normalized


def _normalize_scope(value: str | None) -> str:
    normalized = str(value or "").strip().lower() or "global"
    if normalized not in ALLOWED_SCOPES:
        raise ValueError(f"unsupported scope: {value}")
    return normalized


def _scope_value(scope: str, parameters: dict[str, Any]) -> str | None:
    if scope == "global":
        return None
    if scope == "user_id":
        value = str(parameters.get("user_id") or parameters.get("id") or "").strip()
        return value or None
    if scope == "endpoint_id":
        value = str(parameters.get("endpoint_id") or parameters.get("id") or "").strip()
        return value or None
    if scope == "ai_app":
        value = str(parameters.get("ai_app") or parameters.get("domain") or parameters.get("name") or "").strip().lower()
        return value or None
    return None


def _as_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc).isoformat()
    return value.isoformat()


def _to_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _duration_ms(start: datetime | None, end: datetime | None) -> int | None:
    start_utc = _to_utc(start)
    if start_utc is None:
        return None
    end_utc = _to_utc(end) or _utcnow()
    delta = end_utc - start_utc
    return max(0, int(delta.total_seconds() * 1000))


def _build_scan_links(*, scope: str, scope_value: str | None, scan_id: str) -> dict[str, str]:
    user_query = f"?scan_id={scan_id}&filter=recently_discovered"
    endpoint_query = f"?scan_id={scan_id}&filter=recently_discovered"
    if scope == "user_id" and scope_value:
        user_query = f"?scan_id={scan_id}&user_id={scope_value}"
    if scope == "endpoint_id" and scope_value:
        endpoint_query = f"?scan_id={scan_id}&endpoint_id={scope_value}"
    shadow_query = f"?scan_id={scan_id}"
    if scope == "ai_app" and scope_value:
        shadow_query = f"?scan_id={scan_id}&ai_app={scope_value}"
    return {
        "new_ai_apps": f"/shadow-ai{shadow_query}&state=new" if "?" in shadow_query else f"/shadow-ai?scan_id={scan_id}&state=new",
        "unknown_tools": f"/shadow-ai{shadow_query}&state=unknown" if "?" in shadow_query else f"/shadow-ai?scan_id={scan_id}&state=unknown",
        "new_users": f"/ai-iam{user_query}",
        "new_endpoints": f"/ai-iam{endpoint_query}",
        "new_risks": f"/discovery/findings?scan_id={scan_id}&source=scan_delta",
        "alerts": f"/dashboard/command-center?scan_id={scan_id}&focus=alerts",
        "full_report": f"/shadow-ai?scan_id={scan_id}",
    }


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _extract_domain(value: Any) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = parsed.netloc or parsed.path
        host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if ":" in host:
            host = host.split(":", 1)[0]
        normalized = host.strip().strip(".").lower()
        return normalized or None
    except Exception:
        return None


def _scan_lookback_hours(parameters: dict[str, Any]) -> int:
    try:
        value = int(parameters.get("lookback_hours") or DEFAULT_SCAN_LOOKBACK_HOURS)
    except (TypeError, ValueError):
        value = DEFAULT_SCAN_LOOKBACK_HOURS
    return max(MIN_SCAN_LOOKBACK_HOURS, min(MAX_SCAN_LOOKBACK_HOURS, value))


def _scan_event_limit(parameters: dict[str, Any]) -> int:
    try:
        value = int(parameters.get("max_events") or DEFAULT_SCAN_EVENT_LIMIT)
    except (TypeError, ValueError):
        value = DEFAULT_SCAN_EVENT_LIMIT
    return max(100, min(MAX_SCAN_EVENT_LIMIT, value))


def _event_metadata(row: RuntimeEvent) -> dict[str, Any]:
    return dict(row.metadata_json or {}) if isinstance(row.metadata_json, dict) else {}


def _event_endpoint_id(metadata: dict[str, Any]) -> str | None:
    for key in ("endpoint_id", "host_id", "hostname"):
        value = str(metadata.get(key) or "").strip()
        if value:
            return value
    return None


def _scope_matches_text(scope_value: str, *values: Any) -> bool:
    target = _norm(scope_value)
    if not target:
        return True
    for value in values:
        text = _norm(value)
        if not text:
            continue
        domain = _extract_domain(text)
        if domain and target in {domain, _norm(domain)}:
            return True
        if target == text or target in text:
            return True
    return False


def _scope_matches_runtime_event(row: RuntimeEvent, *, metadata: dict[str, Any], scope: str, scope_value: str | None) -> bool:
    if scope == "global" or not scope_value:
        return True
    if scope == "user_id":
        return _norm(row.user_id) == _norm(scope_value)
    if scope == "endpoint_id":
        return _scope_matches_text(scope_value, _event_endpoint_id(metadata), metadata.get("host_id"), metadata.get("hostname"))
    if scope == "ai_app":
        return _scope_matches_text(
            scope_value,
            row.app_id,
            metadata.get("domain"),
            metadata.get("destination_domain"),
            metadata.get("request_domain"),
            metadata.get("queried_domain"),
            metadata.get("tool_name"),
            metadata.get("provider"),
            metadata.get("api_endpoint"),
        )
    return True


def _scope_matches_action(row: AIAction, *, metadata: dict[str, Any], scope: str, scope_value: str | None) -> bool:
    if scope == "global" or not scope_value:
        return True
    if scope == "user_id":
        return _norm(row.user_id) == _norm(scope_value)
    if scope == "endpoint_id":
        return _scope_matches_text(scope_value, row.endpoint_id, metadata.get("endpoint_id"), metadata.get("host_id"))
    if scope == "ai_app":
        return _scope_matches_text(scope_value, row.ai_app, metadata.get("domain"), metadata.get("tool_name"), metadata.get("api_endpoint"))
    return True


def _scope_matches_signal(payload: dict[str, Any], *, scope: str, scope_value: str | None) -> bool:
    if scope == "global" or not scope_value:
        return True
    if scope == "user_id":
        return _norm(payload.get("user_id")) == _norm(scope_value)
    if scope == "endpoint_id":
        return _scope_matches_text(scope_value, payload.get("endpoint_id"), payload.get("host_id"), payload.get("hostname"))
    if scope == "ai_app":
        return _scope_matches_text(
            scope_value,
            payload.get("domain"),
            payload.get("ai_tool"),
            payload.get("tool_name"),
            payload.get("provider"),
            payload.get("api_endpoint"),
            payload.get("url"),
        )
    return True


def _category_from_provider_type(provider_type: str | None) -> str:
    normalized = _norm(provider_type)
    if normalized in {"saas_ai", "embedded_copilot"}:
        return "chatbot"
    if normalized == "model_api":
        return "api"
    if normalized == "local_model":
        return "local_model"
    if normalized == "agent_framework":
        return "agent"
    return "unknown"


def _risk_from_severity(severity: str | None) -> float:
    return float(RISK_FROM_SEVERITY.get(_norm(severity), 0.0))


def _new_app_bucket(*, app_key: str, display_name: str, domain: str | None, category: str) -> dict[str, Any]:
    return {
        "asset_id": f"crawl::{app_key}",
        "name": display_name,
        "domain": domain or display_name,
        "category": category or "unknown",
        "confidence_score": 0.0,
        "risk_score": 0.0,
        "approved_status": "unknown",
        "status": "discovered",
        "usage_count": 0,
        "unique_users": 0,
        "endpoints_count": 0,
        "first_seen_at": None,
        "last_seen_at": None,
        "link": f"/shadow-ai?search={quote(display_name)}",
        "_users": set(),
        "_endpoints": set(),
        "_surfaces": set(),
        "_shadow_entity_ids": set(),
        "_timestamps": [],
    }


def _update_app_bucket(
    bucket: dict[str, Any],
    *,
    timestamp: datetime | None,
    user_id: str | None,
    endpoint_id: str | None,
    source_surface: str | None,
    risk_score: float,
    approved_status: str | None,
    shadow_entity_id: str | None,
) -> None:
    bucket["usage_count"] = int(bucket.get("usage_count") or 0) + 1
    bucket["risk_score"] = round(max(float(bucket.get("risk_score") or 0.0), float(risk_score or 0.0)), 4)
    if user_id and str(user_id).strip():
        bucket["_users"].add(str(user_id).strip())
    if endpoint_id and str(endpoint_id).strip():
        bucket["_endpoints"].add(str(endpoint_id).strip())
    if source_surface and str(source_surface).strip():
        bucket["_surfaces"].add(str(source_surface).strip().lower())
    if shadow_entity_id and str(shadow_entity_id).strip():
        bucket["_shadow_entity_ids"].add(str(shadow_entity_id).strip())
    if timestamp is not None:
        bucket["_timestamps"].append(_to_utc(timestamp) or timestamp)

    status_norm = _norm(approved_status)
    if status_norm == "approved":
        bucket["approved_status"] = "approved"
        bucket["status"] = "reconciled"
    elif status_norm in {"unapproved", "rejected", "restricted"} and bucket.get("approved_status") != "approved":
        bucket["approved_status"] = "unapproved"


def _finalize_confidence(bucket: dict[str, Any]) -> float:
    usage_count = int(bucket.get("usage_count") or 0)
    surfaces_count = len(bucket.get("_surfaces") or [])
    users_count = len(bucket.get("_users") or [])
    base = 0.25
    base += min(0.35, usage_count * 0.03)
    base += min(0.2, surfaces_count * 0.1)
    base += min(0.1, users_count * 0.03)
    if str(bucket.get("approved_status") or "").strip().lower() == "approved":
        base = max(base, 0.85)
    return round(min(0.99, base), 2)


def _run_active_runtime_crawl(
    db: Session,
    *,
    tenant_id: str,
    scope: str,
    scope_value: str | None,
    lookback_hours: int,
    max_events: int,
) -> tuple[list[RuntimeEvent], dict[str, Any]]:
    crawl_started_at = _utcnow()
    window_start = crawl_started_at - timedelta(hours=lookback_hours)
    raw_events = db.scalars(
        select(RuntimeEvent)
        .where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.created_at >= window_start,
        )
        .order_by(desc(RuntimeEvent.created_at))
        .limit(max_events * 2)
    ).all()

    filtered_events: list[RuntimeEvent] = []
    source_surfaces: set[str] = set()
    shadow_attempts = 0
    shadow_discoveries = 0
    for row in raw_events:
        metadata = _event_metadata(row)
        if not _scope_matches_runtime_event(row, metadata=metadata, scope=scope, scope_value=scope_value):
            continue
        filtered_events.append(row)
        source_surfaces.add(str(row.source_surface or "").strip().lower())
        try:
            shadow_attempts += 1
            if safe_process_runtime_event_for_shadow_discovery(db, event=row) is not None:
                shadow_discoveries += 1
        except Exception:
            continue
        if len(filtered_events) >= max_events:
            break

    crawl_finished_at = _utcnow()
    crawl_meta = {
        "mode": "active_runtime_crawl",
        "window_start": _as_iso(window_start),
        "window_end": _as_iso(crawl_finished_at),
        "lookback_hours": lookback_hours,
        "max_events": max_events,
        "runtime_events_considered": len(raw_events),
        "runtime_events_crawled": len(filtered_events),
        "shadow_discovery_attempts": shadow_attempts,
        "shadow_discovery_upserts": shadow_discoveries,
        "source_surfaces": sorted(item for item in source_surfaces if item),
        "crawl_duration_ms": _duration_ms(crawl_started_at, crawl_finished_at) or 0,
    }
    return filtered_events, crawl_meta


def _collect_snapshot(
    db: Session,
    *,
    tenant_id: str,
    scope: str,
    scope_value: str | None,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    lookback_hours = _scan_lookback_hours(parameters)
    max_events = _scan_event_limit(parameters)
    runtime_events, crawl_meta = _run_active_runtime_crawl(
        db,
        tenant_id=tenant_id,
        scope=scope,
        scope_value=scope_value,
        lookback_hours=lookback_hours,
        max_events=max_events,
    )
    window_start = _to_utc(_utcnow() - timedelta(hours=lookback_hours)) or _utcnow()

    app_buckets: dict[str, dict[str, Any]] = {}
    observed_user_ids: set[str] = set()
    observed_endpoint_ids: set[str] = set()

    def _upsert_app_from_signal(
        *,
        timestamp: datetime | None,
        source_surface: str | None,
        user_id: str | None,
        endpoint_id: str | None,
        ai_system_id: str | None,
        app_id: str | None,
        metadata: dict[str, Any],
        risk_score: float,
    ) -> None:
        provider_context = resolve_provider(
            {
                "domain": metadata.get("domain") or metadata.get("destination_domain") or metadata.get("request_domain") or app_id,
                "api_endpoint": metadata.get("api_endpoint"),
                "provider": metadata.get("provider") or metadata.get("model_provider"),
                "model_name": metadata.get("model_name"),
                "tool_name": metadata.get("tool_name") or metadata.get("ai_tool") or app_id,
                "process_name": metadata.get("process_name"),
            },
            source_surface=source_surface,
        )
        domain = (
            _extract_domain(metadata.get("domain"))
            or _extract_domain(metadata.get("destination_domain"))
            or _extract_domain(metadata.get("request_domain"))
            or _extract_domain(metadata.get("queried_domain"))
            or _extract_domain(app_id)
            or _extract_domain(metadata.get("api_endpoint"))
            or _extract_domain(metadata.get("url"))
        )
        display_name = (
            str(metadata.get("tool_name") or metadata.get("ai_tool") or "").strip()
            or domain
            or str(app_id or "").strip()
            or str(provider_context.get("provider_name") or "").strip()
            or "unknown_ai_app"
        )
        app_key = _norm(domain or display_name)
        if not app_key:
            return
        bucket = app_buckets.setdefault(
            app_key,
            _new_app_bucket(
                app_key=app_key,
                display_name=display_name,
                domain=domain,
                category=_category_from_provider_type(
                    str(metadata.get("provider_type") or provider_context.get("provider_type") or "")
                ),
            ),
        )
        governance_state = _norm(metadata.get("governance_state"))
        approved_status = "approved" if (ai_system_id and governance_state in APPROVED_GOVERNANCE_STATES) else metadata.get("approved_status")
        if ai_system_id and not approved_status:
            approved_status = "approved"
        _update_app_bucket(
            bucket,
            timestamp=timestamp,
            user_id=user_id,
            endpoint_id=endpoint_id,
            source_surface=source_surface,
            risk_score=risk_score,
            approved_status=str(approved_status or "unknown"),
            shadow_entity_id=str(metadata.get("shadow_ai_entity_id") or "").strip() or None,
        )

        if user_id and str(user_id).strip():
            observed_user_ids.add(str(user_id).strip())
        if endpoint_id and str(endpoint_id).strip():
            observed_endpoint_ids.add(str(endpoint_id).strip())

    for row in runtime_events:
        metadata = _event_metadata(row)
        _upsert_app_from_signal(
            timestamp=row.created_at,
            source_surface=row.source_surface,
            user_id=row.user_id,
            endpoint_id=_event_endpoint_id(metadata),
            ai_system_id=row.ai_system_id,
            app_id=row.app_id,
            metadata=metadata,
            risk_score=max(float(row.risk_score or 0.0), _risk_from_severity(row.severity)),
        )

    action_rows = db.scalars(
        select(AIAction)
        .where(
            AIAction.tenant_id == tenant_id,
            AIAction.timestamp >= window_start,
        )
        .order_by(desc(AIAction.timestamp))
        .limit(max_events * 2)
    ).all()
    filtered_action_ids: set[str] = set()
    for row in action_rows:
        metadata = dict(row.metadata_json or {}) if isinstance(row.metadata_json, dict) else {}
        if not _scope_matches_action(row, metadata=metadata, scope=scope, scope_value=scope_value):
            continue
        filtered_action_ids.add(str(row.action_id))
        _upsert_app_from_signal(
            timestamp=row.timestamp,
            source_surface=str(metadata.get("source_surface") or "browser"),
            user_id=row.user_id,
            endpoint_id=row.endpoint_id or str(metadata.get("endpoint_id") or "").strip() or None,
            ai_system_id=str(metadata.get("ai_system_id") or "").strip() or None,
            app_id=row.ai_app,
            metadata=metadata | {"tool_name": metadata.get("tool_name") or row.ai_app},
            risk_score=max(float(row.risk_score or 0.0), _risk_from_severity(metadata.get("severity"))),
        )

    signal_rows = db.scalars(
        select(MonitoringSignal)
        .where(
            MonitoringSignal.tenant_id == tenant_id,
            MonitoringSignal.created_at >= window_start,
        )
        .order_by(desc(MonitoringSignal.created_at))
        .limit(max_events * 2)
    ).all()
    for row in signal_rows:
        payload = dict(row.payload or {}) if isinstance(row.payload, dict) else {}
        if not _scope_matches_signal(payload, scope=scope, scope_value=scope_value):
            continue
        _upsert_app_from_signal(
            timestamp=row.created_at,
            source_surface=str(payload.get("source_surface") or "monitoring"),
            user_id=str(payload.get("user_id") or "").strip() or None,
            endpoint_id=str(payload.get("endpoint_id") or payload.get("host_id") or "").strip() or None,
            ai_system_id=row.ai_system_id,
            app_id=str(payload.get("domain") or payload.get("ai_tool") or "").strip() or None,
            metadata=payload,
            risk_score=max(_risk_from_severity(row.severity), _risk_from_severity(payload.get("severity"))),
        )

    shadow_rows = db.scalars(
        select(ShadowAIEntity).where(ShadowAIEntity.tenant_id == tenant_id)
    ).all()
    shadow_by_id = {str(row.id): row for row in shadow_rows if str(row.id).strip()}
    shadow_by_name = {_norm(row.canonical_name): row for row in shadow_rows if _norm(row.canonical_name)}

    app_items: list[dict[str, Any]] = []
    for key, bucket in app_buckets.items():
        matched_entity: ShadowAIEntity | None = None
        for candidate_id in bucket.get("_shadow_entity_ids") or set():
            matched_entity = shadow_by_id.get(str(candidate_id))
            if matched_entity is not None:
                break
        if matched_entity is None:
            matched_entity = shadow_by_name.get(_norm(bucket.get("name")))
        if matched_entity is None:
            matched_entity = shadow_by_name.get(_norm(bucket.get("domain")))

        if matched_entity is not None:
            bucket["asset_id"] = matched_entity.id
            bucket["name"] = matched_entity.canonical_name
            bucket["domain"] = matched_entity.canonical_name
            bucket["category"] = matched_entity.ai_type or bucket.get("category") or "unknown"
            bucket["approved_status"] = matched_entity.approved_status or bucket.get("approved_status") or "unknown"
            bucket["status"] = matched_entity.discovery_status or bucket.get("status") or "discovered"
            bucket["risk_score"] = round(
                max(float(bucket.get("risk_score") or 0.0), float(matched_entity.risk_score or 0.0)),
                4,
            )
            bucket["confidence_score"] = round(
                max(float(bucket.get("confidence_score") or 0.0), float(matched_entity.confidence_score or 0.0)),
                2,
            )
            bucket["link"] = f"/shadow-ai?entity_id={matched_entity.id}"

        bucket["confidence_score"] = round(
            max(float(bucket.get("confidence_score") or 0.0), _finalize_confidence(bucket)),
            2,
        )
        timestamps = [item for item in (bucket.get("_timestamps") or []) if isinstance(item, datetime)]
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None
        bucket["first_seen_at"] = _as_iso(first_seen)
        bucket["last_seen_at"] = _as_iso(last_seen)
        bucket["unique_users"] = len(bucket.get("_users") or set())
        bucket["endpoints_count"] = len(bucket.get("_endpoints") or set())
        app_items.append(
            {
                "asset_id": str(bucket.get("asset_id") or f"crawl::{key}"),
                "name": str(bucket.get("name") or bucket.get("domain") or key),
                "domain": str(bucket.get("domain") or bucket.get("name") or key),
                "category": str(bucket.get("category") or "unknown"),
                "confidence_score": float(bucket.get("confidence_score") or 0.0),
                "risk_score": float(bucket.get("risk_score") or 0.0),
                "approved_status": str(bucket.get("approved_status") or "unknown"),
                "status": str(bucket.get("status") or "discovered"),
                "first_seen_at": bucket.get("first_seen_at"),
                "last_seen_at": bucket.get("last_seen_at"),
                "unique_users": int(bucket.get("unique_users") or 0),
                "endpoints_count": int(bucket.get("endpoints_count") or 0),
                "usage_count": int(bucket.get("usage_count") or 0),
                "link": str(bucket.get("link") or f"/shadow-ai?search={quote(str(bucket.get('name') or key))}"),
            }
        )
    app_items = sorted(app_items, key=lambda item: (float(item.get("risk_score") or 0.0), int(item.get("usage_count") or 0)), reverse=True)

    if not observed_user_ids and scope == "user_id" and scope_value:
        observed_user_ids.add(scope_value)
    user_rows = db.scalars(
        select(UserRegistry).where(
            UserRegistry.tenant_id == tenant_id,
            UserRegistry.user_id.in_(sorted(observed_user_ids)),
        )
    ).all() if observed_user_ids else []
    user_by_id = {str(row.user_id): row for row in user_rows if str(row.user_id).strip()}
    user_items: list[dict[str, Any]] = []
    for user_id in sorted(observed_user_ids):
        row = user_by_id.get(user_id)
        if row is not None:
            user_items.append(
                {
                    "user_id": row.user_id,
                    "display_name": row.display_name,
                    "email": row.email,
                    "risk_score": float(row.risk_score or 0.0),
                    "violation_count": int(row.violation_count or 0),
                    "link": f"/ai-iam?user_id={row.user_id}",
                }
            )
        else:
            user_items.append(
                {
                    "user_id": user_id,
                    "display_name": user_id,
                    "email": "",
                    "risk_score": 0.0,
                    "violation_count": 0,
                    "link": f"/ai-iam?user_id={user_id}",
                }
            )

    if not observed_endpoint_ids and scope == "endpoint_id" and scope_value:
        observed_endpoint_ids.add(scope_value)
    endpoint_rows = db.scalars(
        select(DeploymentEndpoint).where(
            DeploymentEndpoint.tenant_id == tenant_id,
            DeploymentEndpoint.endpoint_id.in_(sorted(observed_endpoint_ids)),
        )
    ).all() if observed_endpoint_ids else []
    endpoint_by_id = {str(row.endpoint_id): row for row in endpoint_rows if str(row.endpoint_id).strip()}
    endpoint_items: list[dict[str, Any]] = []
    for endpoint_id in sorted(observed_endpoint_ids):
        row = endpoint_by_id.get(endpoint_id)
        if row is not None:
            endpoint_items.append(
                {
                    "endpoint_id": row.endpoint_id,
                    "hostname": row.hostname,
                    "browser_type": row.browser_type,
                    "os_type": row.os_type,
                    "status": row.status,
                    "user_id": row.user_id,
                    "last_seen_at": _as_iso(row.last_seen_at),
                    "link": f"/ai-iam?endpoint_id={row.endpoint_id}",
                }
            )
        else:
            endpoint_items.append(
                {
                    "endpoint_id": endpoint_id,
                    "hostname": endpoint_id,
                    "browser_type": None,
                    "os_type": None,
                    "status": "observed",
                    "user_id": None,
                    "last_seen_at": None,
                    "link": f"/ai-iam?endpoint_id={endpoint_id}",
                }
            )

    app_name_lookup = {_norm(item.get("name")) for item in app_items if _norm(item.get("name"))}
    app_domain_lookup = {_norm(item.get("domain")) for item in app_items if _norm(item.get("domain"))}
    finding_rows = db.scalars(
        select(Finding).where(
            Finding.tenant_id == tenant_id,
            Finding.status.in_(OPEN_FINDING_STATUSES),
            Finding.severity.in_(HIGH_RISK_SEVERITIES),
        )
    ).all()
    risk_items: list[dict[str, Any]] = []
    for row in finding_rows:
        if scope == "user_id" and scope_value and _norm(row.user_id) != _norm(scope_value):
            continue
        if scope == "ai_app" and scope_value:
            if not _scope_matches_text(scope_value, row.ai_tool):
                continue
        if app_name_lookup or app_domain_lookup:
            ai_tool_norm = _norm(row.ai_tool)
            if ai_tool_norm and ai_tool_norm not in app_name_lookup and ai_tool_norm not in app_domain_lookup:
                continue
        risk_items.append(
            {
                "finding_id": row.finding_id,
                "finding_type": row.finding_type,
                "severity": row.severity,
                "status": row.status,
                "ai_tool": row.ai_tool,
                "risk_category": row.risk_category,
                "last_seen_at": _as_iso(row.last_seen_at),
                "link": f"/discovery/findings?focus={row.finding_id}",
            }
        )

    alert_stmt = select(AIActionAlert).where(
        AIActionAlert.tenant_id == tenant_id,
        AIActionAlert.created_at >= window_start,
    )
    if scope == "user_id" and scope_value:
        alert_stmt = alert_stmt.where(AIActionAlert.user_id == scope_value)
    if scope == "endpoint_id" and scope_value:
        alert_stmt = alert_stmt.where(AIActionAlert.endpoint_id == scope_value)
    alert_rows = db.scalars(alert_stmt.order_by(desc(AIActionAlert.created_at)).limit(max_events * 2)).all()
    alert_items: list[dict[str, Any]] = []
    for row in alert_rows:
        if scope == "ai_app" and scope_value:
            if str(row.action_id) not in filtered_action_ids:
                continue
        alert_items.append(
            {
                "alert_id": row.id,
                "alert_type": row.alert_type,
                "severity": row.severity,
                "enforcement_action": row.enforcement_action,
                "action_id": row.action_id,
                "session_id": row.session_id,
                "user_id": row.user_id,
                "endpoint_id": row.endpoint_id,
                "finding_id": row.finding_id,
                "created_at": _as_iso(row.created_at),
                "link": f"/ai-iam?action_id={row.action_id}",
            }
        )

    unknown_apps = [
        item
        for item in app_items
        if str(item.get("approved_status") or "unknown").strip().lower() != "approved"
    ]

    return {
        "apps": app_items,
        "users": user_items,
        "endpoints": endpoint_items,
        "risks": risk_items,
        "alerts": alert_items,
        "unknown_apps": unknown_apps,
        "counts": {
            "apps": len(app_items),
            "users": len(user_items),
            "endpoints": len(endpoint_items),
            "risks": len(risk_items),
            "alerts": len(alert_items),
            "unknown_apps": len(unknown_apps),
        },
        "crawl": {
            **crawl_meta,
            "actions_considered": len(action_rows),
            "actions_in_scope": len(filtered_action_ids),
            "signals_considered": len(signal_rows),
        },
    }


def _index_rows(rows: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        item_key = str(row.get(key) or "").strip()
        if item_key:
            indexed[item_key] = row
    return indexed


def _compute_delta(
    *,
    current_snapshot: dict[str, Any],
    previous_snapshot: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    previous = previous_snapshot or {}
    prev_apps = _index_rows(list(previous.get("apps") or []), "asset_id")
    prev_users = _index_rows(list(previous.get("users") or []), "user_id")
    prev_endpoints = _index_rows(list(previous.get("endpoints") or []), "endpoint_id")
    prev_risks = _index_rows(list(previous.get("risks") or []), "finding_id")
    prev_alerts = _index_rows(list(previous.get("alerts") or []), "alert_id")

    apps_added = [row for row in current_snapshot.get("apps", []) if str(row.get("asset_id") or "") not in prev_apps]
    users_added = [row for row in current_snapshot.get("users", []) if str(row.get("user_id") or "") not in prev_users]
    endpoints_added = [
        row
        for row in current_snapshot.get("endpoints", [])
        if str(row.get("endpoint_id") or "") not in prev_endpoints
    ]
    risks_added = [row for row in current_snapshot.get("risks", []) if str(row.get("finding_id") or "") not in prev_risks]
    alerts_added = [row for row in current_snapshot.get("alerts", []) if str(row.get("alert_id") or "") not in prev_alerts]

    delta = {
        "apps_added": apps_added,
        "users_added": users_added,
        "endpoints_added": endpoints_added,
        "risks_added": risks_added,
        "alerts_added": alerts_added,
    }
    summary = {
        "new_ai_apps_detected": len(apps_added),
        "unknown_apps": int(current_snapshot.get("counts", {}).get("unknown_apps") or 0),
        "new_users_detected": len(users_added),
        "new_endpoints_detected": len(endpoints_added),
        "new_risks_identified": len(risks_added),
        "alerts_generated": len(alerts_added),
        "total_ai_apps": int(current_snapshot.get("counts", {}).get("apps") or 0),
    }
    return delta, summary


def _load_previous_snapshot(
    db: Session,
    *,
    tenant_id: str,
    scan_type: str,
    scope: str,
) -> dict[str, Any] | None:
    previous = db.scalar(
        select(ScanResult)
        .where(
            ScanResult.tenant_id == tenant_id,
            ScanResult.scan_type == scan_type,
            ScanResult.scope == scope,
            ScanResult.status == "completed",
        )
        .order_by(desc(ScanResult.start_time))
    )
    if previous is None:
        return None
    if isinstance(previous.snapshot_json, dict):
        return dict(previous.snapshot_json)
    return None


def _complete_scan(scan_id: str, *, db: Session | None = None) -> None:
    owns_session = db is None
    session = db or SessionLocal()
    try:
        row = session.scalar(select(ScanResult).where(ScanResult.scan_id == scan_id))
        if row is None:
            return
        scope = _normalize_scope(row.scope)
        params = dict(row.parameters_json or {})
        scope_value = _scope_value(scope, params)
        previous_snapshot = _load_previous_snapshot(
            session,
            tenant_id=row.tenant_id,
            scan_type=_normalize_scan_type(row.scan_type),
            scope=scope,
        )
        current_snapshot = _collect_snapshot(
            session,
            tenant_id=row.tenant_id,
            scope=scope,
            scope_value=scope_value,
            parameters=params,
        )
        delta, summary = _compute_delta(
            current_snapshot=current_snapshot,
            previous_snapshot=previous_snapshot,
        )
        row.summary_json = summary
        row.delta_json = delta
        row.snapshot_json = current_snapshot
        row.status = "completed"
        row.end_time = _utcnow()
        row.error_message = None
        write_audit_log(
            session,
            tenant_id=row.tenant_id,
            actor_user_id=row.triggered_by,
            actor_type=("human" if row.triggered_by else "system"),
            action="scan.completed",
            resource_type="scan_result",
            resource_id=row.id,
            payload={
                "scan_id": row.scan_id,
                "scan_type": row.scan_type,
                "scope": row.scope,
                "summary": summary,
            },
        )
        session.commit()
    except Exception as exc:  # pragma: no cover - defensive guard for background worker
        session.rollback()
        if owns_session:
            failure_db = SessionLocal()
            try:
                failed_row = failure_db.scalar(select(ScanResult).where(ScanResult.scan_id == scan_id))
                if failed_row is not None:
                    failed_row.status = "failed"
                    failed_row.end_time = _utcnow()
                    failed_row.error_message = str(exc)[:4000]
                    failure_db.commit()
            finally:
                failure_db.close()
        else:
            failed_row = session.scalar(select(ScanResult).where(ScanResult.scan_id == scan_id))
            if failed_row is not None:
                failed_row.status = "failed"
                failed_row.end_time = _utcnow()
                failed_row.error_message = str(exc)[:4000]
                session.commit()
        log_structured(
            "scan_execution_failed",
            module="scan_service",
            scan_id=scan_id,
            error=str(exc),
        )
    finally:
        if owns_session:
            session.close()


def launch_scan_worker(scan_id: str, *, db: Session | None = None) -> None:
    if os.getenv("PYTEST_CURRENT_TEST"):
        _complete_scan(scan_id, db=db)
        return
    worker = Thread(target=_complete_scan, args=(scan_id,), daemon=True, name=f"scan-worker-{scan_id}")
    worker.start()


def trigger_scan(
    db: Session,
    *,
    tenant_id: str,
    scan_type: str,
    scope: str,
    parameters: dict[str, Any] | None,
    triggered_by: str | None,
) -> tuple[ScanResult, bool]:
    normalized_type = _normalize_scan_type(scan_type)
    normalized_scope = _normalize_scope(scope)
    normalized_params = dict(parameters or {})
    if normalized_scope != "global" and _scope_value(normalized_scope, normalized_params) is None:
        raise ValueError(f"scope '{normalized_scope}' requires matching identifier in parameters")

    existing_running = db.scalar(
        select(ScanResult)
        .where(
            ScanResult.tenant_id == tenant_id,
            ScanResult.scan_type == normalized_type,
            ScanResult.scope == normalized_scope,
            ScanResult.status == "running",
            ScanResult.start_time >= (_utcnow() - timedelta(minutes=10)),
        )
        .order_by(desc(ScanResult.start_time))
    )
    if existing_running is not None:
        running_age_ms = _duration_ms(existing_running.start_time, None) or 0
        if running_age_ms > STALLED_RUNNING_SCAN_SECONDS * 1000:
            existing_running.status = "failed"
            existing_running.end_time = _utcnow()
            existing_running.error_message = (
                f"Scan auto-failed after running for {running_age_ms}ms without completion."
            )[:4000]
            write_audit_log(
                db,
                tenant_id=tenant_id,
                actor_user_id=triggered_by,
                actor_type=("human" if triggered_by else "system"),
                action="scan.stale_auto_failed",
                resource_type="scan_result",
                resource_id=existing_running.id,
                payload={
                    "scan_id": existing_running.scan_id,
                    "scan_type": normalized_type,
                    "scope": normalized_scope,
                    "running_age_ms": running_age_ms,
                },
            )
            db.flush()
        else:
            return existing_running, False

    scan_id = f"scan-{uuid4()}"
    row = ScanResult(
        tenant_id=tenant_id,
        scan_id=scan_id,
        scan_type=normalized_type,
        triggered_by=triggered_by,
        scope=normalized_scope,
        parameters_json=normalized_params,
        start_time=_utcnow(),
        status="running",
        summary_json={},
        delta_json={},
        snapshot_json={},
    )
    db.add(row)
    db.flush()
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=triggered_by,
        actor_type=("human" if triggered_by else "system"),
        action="scan.trigger",
        resource_type="scan_result",
        resource_id=row.id,
        payload={
            "scan_id": scan_id,
            "scan_type": normalized_type,
            "scope": normalized_scope,
            "parameters": normalized_params,
        },
    )
    return row, True


def serialize_scan_result(row: ScanResult | None) -> dict[str, Any]:
    if row is None:
        return {
            "scan_id": None,
            "status": "no_data",
            "scan_type": "discovery",
            "scope": "global",
            "last_scan_time": None,
            "summary": {
                "new_ai_apps_detected": 0,
                "unknown_apps": 0,
                "new_users_detected": 0,
                "new_endpoints_detected": 0,
                "new_risks_identified": 0,
                "alerts_generated": 0,
                "total_ai_apps": 0,
            },
            "delta": {
                "apps_added": [],
                "users_added": [],
                "endpoints_added": [],
                "risks_added": [],
                "alerts_added": [],
            },
            "links": _build_scan_links(scope="global", scope_value=None, scan_id="latest"),
            "duration_ms": None,
            "data_source": "active_runtime_crawl",
            "crawl_meta": {
                "mode": "active_runtime_crawl",
                "runtime_events_considered": 0,
                "runtime_events_crawled": 0,
                "shadow_discovery_upserts": 0,
            },
            "snapshot_counts": {
                "apps": 0,
                "users": 0,
                "endpoints": 0,
                "risks": 0,
                "alerts": 0,
                "unknown_apps": 0,
            },
        }

    params = dict(row.parameters_json or {})
    scope_raw = str(row.scope or "global").strip().lower()
    scope = scope_raw if scope_raw in ALLOWED_SCOPES else "global"
    scope_value = _scope_value(scope, params)
    return {
        "scan_id": row.scan_id,
        "status": str(row.status or "unknown").strip().lower() or "unknown",
        "scan_type": str(row.scan_type or "discovery").strip().lower() or "discovery",
        "scope": scope,
        "scope_value": scope_value,
        "last_scan_time": _as_iso(row.end_time or row.start_time),
        "started_at": _as_iso(row.start_time),
        "ended_at": _as_iso(row.end_time),
        "summary": dict(row.summary_json or {}),
        "delta": dict(row.delta_json or {}),
        "error": str(row.error_message or "").strip() or None,
        "links": _build_scan_links(scope=scope, scope_value=scope_value, scan_id=row.scan_id),
        "duration_ms": _duration_ms(row.start_time, row.end_time),
        "data_source": str(((row.snapshot_json or {}).get("crawl") or {}).get("mode") or "active_runtime_crawl"),
        "crawl_meta": dict((row.snapshot_json or {}).get("crawl") or {}),
        "snapshot_counts": {
            "apps": int(((row.snapshot_json or {}).get("counts") or {}).get("apps") or 0),
            "users": int(((row.snapshot_json or {}).get("counts") or {}).get("users") or 0),
            "endpoints": int(((row.snapshot_json or {}).get("counts") or {}).get("endpoints") or 0),
            "risks": int(((row.snapshot_json or {}).get("counts") or {}).get("risks") or 0),
            "alerts": int(((row.snapshot_json or {}).get("counts") or {}).get("alerts") or 0),
            "unknown_apps": int(((row.snapshot_json or {}).get("counts") or {}).get("unknown_apps") or 0),
        },
    }


def get_scan_by_id(db: Session, *, tenant_id: str, scan_id: str) -> ScanResult | None:
    return db.scalar(
        select(ScanResult).where(
            ScanResult.tenant_id == tenant_id,
            ScanResult.scan_id == scan_id,
        )
    )


def get_latest_scan(db: Session, *, tenant_id: str) -> ScanResult | None:
    return db.scalar(
        select(ScanResult)
        .where(ScanResult.tenant_id == tenant_id)
        .order_by(desc(ScanResult.start_time))
    )
