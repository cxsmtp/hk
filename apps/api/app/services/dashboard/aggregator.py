from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from threading import Lock
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import and_, desc, func, or_, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.activity_audit import AIAction, AIActionAlert, DeploymentEndpoint, PromptPayload, UserRegistry
from app.db.models.ai_iam import AgentIdentity
from app.db.models.ai_system import AISystem
from app.db.models.enforcement import EnforcementEvent
from app.db.models.finding import Finding
from app.db.models.job_run import ScheduledJobRun
from app.db.models.monitoring import DriftAlert, MonitoringSignal
from app.db.models.maturity import ControlMaturity
from app.db.models.policy import ApprovalRequest
from app.db.models.remediation import RemediationAction
from app.db.models.runtime_intelligence import RuntimeEvent, RuntimeGovernanceRecommendation
from app.db.models.scan import ScanResult
from app.db.models.shadow_ai import ShadowAIEntity, ShadowAISignal
from app.db.models.simulation import SimulationRun
from app.db.models.snapshot import AuditorSnapshot
from app.services.dashboard.recommendations import generate_dashboard_recommendations
from app.services.deployment_hardening_service import evaluate_deployment_hardening
from app.services.external_risk_intel import get_summary as get_external_risk_summary
from app.services.scan_service import serialize_scan_result
from app.services.schema_health_service import evaluate_schema_health


# Command Center polling runs every ~8s in the UI. Keep a longer cache window so
# polls do not repeatedly trigger full recomputation under SQLite write pressure.
CACHE_TTL_SECONDS = 30
CACHE_STALE_GRACE_SECONDS = 120
NOTIFICATIONS_CACHE_TTL_SECONDS = 8
PILOT_HEALTH_CACHE_TTL_SECONDS = 10
SUPPORTED_SEVERITIES = {"low", "med", "medium", "high", "critical"}
SUPPORTED_INTENT_SENSITIVITIES = {"none", "low", "medium", "high", "critical"}
SUPPORTED_ACTION_ALIGNMENTS = {"aligned", "suspicious", "out_of_scope", "unknown"}
DECISION_BUCKETS = ("allow", "warn", "block", "require_approval", "hold")
SOURCE_SURFACES = ("browser", "gateway", "connector", "aiiam", "monitoring", "endpoint", "dns", "proxy", "foundry", "copilot")
CONTROL_MODE_BUCKETS = (
    "inline_prevented",
    "inline_allowed",
    "warned",
    "shadow_would_block",
    "detected_only",
    "telemetry_only",
    "external_required",
    "external_action_triggered",
    "incomplete",
)
CONTROL_MODE_PRIORITY: dict[str, int] = {
    "inline_prevented": 90,
    "warned": 80,
    "external_action_triggered": 75,
    "external_required": 70,
    "shadow_would_block": 60,
    "detected_only": 50,
    "telemetry_only": 40,
    "inline_allowed": 30,
    "incomplete": 10,
}
SURFACE_MATRIX_DEFINITIONS: tuple[dict[str, Any], ...] = (
    {
        "id": "browser",
        "label": "Browser AI",
        "surface_type": "Browser Extension",
        "coverage": "Inline prompt, paste, upload, output and browser action control",
        "default_mode": "inline_prevented",
        "primary_control": "Business purpose, sensitive data, justification, Shadow AI",
        "proof_label": "Inline browser extension decisions",
        "drilldown": "/runtime-intelligence/activity-map?surface=browser",
    },
    {
        "id": "mcp",
        "label": "MCP / Developer Tools",
        "surface_type": "MCP Gateway",
        "coverage": "Tool-call authorization, parameter inspection, fingerprint drift",
        "default_mode": "inline_prevented",
        "primary_control": "Block write/admin/secret calls; bind approvals to tool metadata",
        "proof_label": "MCP tool calls and parameters",
        "drilldown": "/ai-iam?surface=mcp",
    },
    {
        "id": "gateway_sdk",
        "label": "LLM Gateway / SDK",
        "surface_type": "Gateway + App Embed",
        "coverage": "Model-call policy, prompt/response evidence and API trace",
        "default_mode": "inline_allowed",
        "primary_control": "Same authorize_ai_action spine for custom apps and SDK calls",
        "proof_label": "Gateway or SDK model calls",
        "drilldown": "/gateway",
    },
    {
        "id": "foundry",
        "label": "Microsoft Foundry",
        "surface_type": "Foundry / Azure AI",
        "coverage": "Project, agent, model, tool and data-source trace when connected",
        "default_mode": "external_required",
        "primary_control": "Inline only when routed through Hawk Gateway; telemetry otherwise",
        "proof_label": "Foundry project/agent/model telemetry",
        "drilldown": "/surface-coverage#foundry",
    },
    {
        "id": "copilot",
        "label": "Microsoft Copilot",
        "surface_type": "M365 Copilot / Copilot Studio",
        "coverage": "Copilot activity, Studio agents, connectors, OAuth/app permissions",
        "default_mode": "telemetry_only",
        "primary_control": "Graph/Purview/Entra evidence with external remediation actions",
        "proof_label": "M365/Copilot Studio telemetry",
        "drilldown": "/surface-coverage#copilot",
    },
    {
        "id": "desktop_proxy",
        "label": "Desktop / Local Proxy",
        "surface_type": "SWG / Local AI Proxy",
        "coverage": "Desktop AI and native app coverage when routed through proxy/SWG",
        "default_mode": "telemetry_only",
        "primary_control": "Telemetry now; inline prevention requires proxy/SWG path",
        "proof_label": "Endpoint/proxy/local telemetry",
        "drilldown": "/surface-coverage#desktop",
    },
)
NOTIFICATION_TYPE_PRIORITY: dict[str, int] = {
    "activity_alert": 5,
    "finding": 4,
    "discovery_signal": 4,
    "enforcement_event": 3,
    "scan_delta": 2,
    "scan_status": 1,
}

_CACHE_LOCK = Lock()
_CACHE: dict[str, dict[str, Any]] = {}
_NOTIFICATIONS_CACHE_LOCK = Lock()
_NOTIFICATIONS_CACHE: dict[str, dict[str, Any]] = {}
_PILOT_HEALTH_CACHE_LOCK = Lock()
_PILOT_HEALTH_CACHE: dict[str, dict[str, Any]] = {}
_COMPUTE_LOCKS_GUARD = Lock()
_COMPUTE_LOCKS: dict[str, Lock] = {}


class CommandCenterDataUnavailableError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandCenterFilters:
    tenant_id: str
    time_window_hours: int
    ai_system_id: str | None
    severity: str | None
    intent_category: str | None
    input_sensitivity: str | None
    output_sensitivity: str | None
    action_alignment: str | None
    role: str
    force_refresh: bool

    @property
    def cache_key(self) -> str:
        return "|".join(
            [
                self.tenant_id,
                str(self.time_window_hours),
                self.ai_system_id or "",
                self.severity or "",
                self.intent_category or "",
                self.input_sensitivity or "",
                self.output_sensitivity or "",
                self.action_alignment or "",
                self.role,
            ]
        )


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    return None


def _to_datetime_any(value: Any) -> datetime | None:
    parsed = _to_datetime(value)
    if parsed is not None:
        return parsed
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt
    return None


def _normalize_severity(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value or "").strip().lower()
    if normalized == "medium":
        normalized = "med"
    if normalized not in SUPPORTED_SEVERITIES:
        return None
    return normalized


def _severity_weight(value: str | None) -> int:
    normalized = _normalize_severity(value) or "low"
    return {
        "low": 1,
        "med": 2,
        "high": 3,
        "critical": 4,
    }.get(normalized, 1)


def _is_open_status(value: str | None) -> bool:
    normalized = str(value or "").strip().lower()
    return normalized in {"open", "reviewing", "pending", "proposed"}


def _is_full_access(role: str) -> bool:
    return str(role or "").strip().lower() in {"owner", "admin"}


def _decision_from_runtime_event(row: RuntimeEvent) -> str:
    metadata = dict(row.metadata_json or {}) if isinstance(row.metadata_json, dict) else {}
    candidates = [
        metadata.get("decision"),
        metadata.get("final_decision"),
        metadata.get("recommended_action"),
    ]
    for candidate in candidates:
        decision = str(candidate or "").strip().lower()
        if not decision:
            continue
        if "block" in decision or "deny" in decision:
            return "block"
        if "warn" in decision or "redact" in decision:
            return "warn"
        if "approval" in decision or "hold" in decision:
            return "require_approval"
        if "allow" in decision:
            return "allow"
    severity = str(row.severity or "").strip().lower()
    if severity in {"critical", "high"}:
        return "block"
    if severity in {"med", "medium"}:
        return "warn"
    return "allow"


def _pilot_decision_badge(row: RuntimeEvent) -> str:
    metadata = _coerce_dict(row.metadata_json)
    ai_action = _coerce_dict(metadata.get("ai_action"))
    ai_policy = _coerce_dict(ai_action.get("policy"))
    ai_evidence = _coerce_dict(ai_action.get("evidence"))
    evidence_status = str(metadata.get("evidence_status") or metadata.get("finding_evidence_status") or "").strip().lower()
    ai_evidence_status = str(ai_evidence.get("evidence_status") or "").strip().lower()
    if evidence_status == "incomplete" or ai_evidence_status == "incomplete":
        return "Incomplete"

    badge = str(metadata.get("decision_badge") or ai_policy.get("decision_badge") or "").strip().lower()
    control_mode = str(metadata.get("control_mode") or ai_policy.get("control_mode") or "").strip().lower()
    decision = _decision_from_runtime_event(row)

    if control_mode in {"inline_prevented", "pre_action_blocked"} or "prevent" in badge or "block" in badge:
        return "Prevented"
    if control_mode in {"inline_warn", "warned"} or "warn" in badge or decision == "warn":
        return "Warned"
    if control_mode == "detected_only" or "detected" in badge:
        return "Detected-only"
    if decision == "allow":
        return "Allowed"
    if decision == "block":
        return "Prevented"
    return "Detected-only"


def _within_window(row_dt: datetime | None, *, started_at: datetime) -> bool:
    if row_dt is None:
        return False
    return row_dt >= started_at


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    if parsed != parsed:  # NaN guard
        return default
    return parsed


def _coerce_dict(value: Any) -> dict[str, Any]:
    return dict(value or {}) if isinstance(value, dict) else {}


def _coerce_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _is_sqlite_lock_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return "database is locked" in message or "database table is locked" in message


def _is_sqlite_missing_column_error(exc: Exception, column_name: str) -> bool:
    message = str(exc).lower()
    return "no such column" in message and str(column_name or "").strip().lower() in message


def _repair_findings_runtime_columns(db: Session) -> bool:
    if not db.bind or db.bind.dialect.name != "sqlite":
        return False
    changed = False
    try:
        has_findings = db.execute(
            text("SELECT 1 FROM sqlite_master WHERE type='table' AND name='findings' LIMIT 1")
        ).scalar()
        if not has_findings:
            return False

        rows = db.execute(text("PRAGMA table_info(findings)")).all()
        columns = {str(row[1]) for row in rows if len(row) > 1}
        if "agent_id" not in columns:
            db.execute(text("ALTER TABLE findings ADD COLUMN agent_id VARCHAR(64)"))
            changed = True
        if "machine_id" not in columns:
            db.execute(text("ALTER TABLE findings ADD COLUMN machine_id VARCHAR(128)"))
            changed = True
        if "related_event_ids" not in columns:
            db.execute(text("ALTER TABLE findings ADD COLUMN related_event_ids JSON NOT NULL DEFAULT '[]'"))
            changed = True

        db.execute(text("CREATE INDEX IF NOT EXISTS idx_findings_tenant_agent ON findings (tenant_id, agent_id)"))
        db.execute(text("CREATE INDEX IF NOT EXISTS idx_findings_tenant_machine ON findings (tenant_id, machine_id)"))
        db.commit()
        return changed
    except Exception:  # noqa: BLE001
        db.rollback()
        return False


def _impact_value(payload: dict[str, Any], key: str, default: float = 0.0) -> float:
    direct = payload.get(key)
    if direct is not None:
        return _safe_float(direct, default)
    nested = _coerce_dict(payload.get("decision_impact"))
    if key in nested:
        return _safe_float(nested.get(key), default)
    breakdown = _coerce_dict(nested.get("breakdown"))
    if key in breakdown:
        return _safe_float(breakdown.get(key), default)
    return default


def _cache_lookup(cache_key: str, *, allow_stale: bool = False) -> dict[str, Any] | None:
    with _CACHE_LOCK:
        entry = _CACHE.get(cache_key)
        if not entry:
            return None
        expires_at = _to_datetime(entry.get("expires_at"))
        if not expires_at:
            _CACHE.pop(cache_key, None)
            return None
        now = _utcnow()
        if expires_at <= now:
            if allow_stale and (expires_at + timedelta(seconds=CACHE_STALE_GRACE_SECONDS)) > now:
                return dict(entry.get("payload") or {})
            _CACHE.pop(cache_key, None)
            return None
        return dict(entry.get("payload") or {})


def _cache_store(cache_key: str, payload: dict[str, Any]) -> None:
    with _CACHE_LOCK:
        _CACHE[cache_key] = {
            "payload": dict(payload),
            "expires_at": _utcnow() + timedelta(seconds=CACHE_TTL_SECONDS),
        }


def _pilot_health_cache_lookup(cache_key: str) -> dict[str, Any] | None:
    with _PILOT_HEALTH_CACHE_LOCK:
        entry = _PILOT_HEALTH_CACHE.get(cache_key)
        if not entry:
            return None
        expires_at = _to_datetime(entry.get("expires_at"))
        if not expires_at or expires_at <= _utcnow():
            _PILOT_HEALTH_CACHE.pop(cache_key, None)
            return None
        return dict(entry.get("payload") or {})


def _pilot_health_cache_store(cache_key: str, payload: dict[str, Any]) -> None:
    with _PILOT_HEALTH_CACHE_LOCK:
        _PILOT_HEALTH_CACHE[cache_key] = {
            "payload": dict(payload),
            "expires_at": _utcnow() + timedelta(seconds=PILOT_HEALTH_CACHE_TTL_SECONDS),
        }


def _notifications_cache_lookup(cache_key: str) -> dict[str, Any] | None:
    with _NOTIFICATIONS_CACHE_LOCK:
        entry = _NOTIFICATIONS_CACHE.get(cache_key)
        if not entry:
            return None
        expires_at = _to_datetime(entry.get("expires_at"))
        if not expires_at or expires_at <= _utcnow():
            _NOTIFICATIONS_CACHE.pop(cache_key, None)
            return None
        return dict(entry.get("payload") or {})


def _notifications_cache_store(cache_key: str, payload: dict[str, Any]) -> None:
    with _NOTIFICATIONS_CACHE_LOCK:
        _NOTIFICATIONS_CACHE[cache_key] = {
            "payload": dict(payload),
            "expires_at": _utcnow() + timedelta(seconds=NOTIFICATIONS_CACHE_TTL_SECONDS),
        }


def _compute_lock_for(cache_key: str) -> Lock:
    with _COMPUTE_LOCKS_GUARD:
        lock = _COMPUTE_LOCKS.get(cache_key)
        if lock is None:
            lock = Lock()
            _COMPUTE_LOCKS[cache_key] = lock
        return lock


def _strict_pilot_dashboard_mode_enabled() -> bool:
    return bool(settings.pilot_mode) and not bool(settings.demo_mode)


def _empty_command_center_payload(
    *,
    tenant_id: str,
    role: str,
    time_window_hours: int,
    ai_system_id: str | None,
    severity: str | None,
    intent_category: str | None = None,
    input_sensitivity: str | None = None,
    output_sensitivity: str | None = None,
    action_alignment: str | None = None,
    ai_system_options: list[dict[str, Any]],
) -> dict[str, Any]:
    now = _utcnow()
    started_at = now - timedelta(hours=max(1, int(time_window_hours or 24)))
    return {
        "tenant_id": tenant_id,
        "generated_at": now.isoformat(),
        "filters_applied": {
            "time_window_hours": time_window_hours,
            "ai_system_id": ai_system_id,
            "severity": severity,
            "intent_category": intent_category,
            "input_sensitivity": input_sensitivity,
            "output_sensitivity": output_sensitivity,
            "action_alignment": action_alignment,
        },
        "view_scope": "full" if _is_full_access(role) else "scoped",
        "risk_over_time": _build_risk_over_time([], started_at=started_at, time_window_hours=time_window_hours),
        "severity_distribution": _build_severity_distribution([]),
        "exposure_score": _build_exposure_score(findings=[], shadow_entities=[], runtime_events=[], cve_summary={"critical": 0, "high": 0}),
        "active_incidents": _build_active_incidents(findings=[], drift_alerts=[], remediation_actions=[]),
        "runtime_heatmap": _build_runtime_heatmap([]),
        "live_activity_feed": _build_live_activity_feed([]),
        "ai_action_control": _build_ai_action_control_summary([]),
        "users_view": _build_users_view([]),
        "agents_view": _build_agents_view(agents=[], events=[], findings=[]),
        "findings_alerts": _build_findings_alerts([]),
        "attack_trace_view": _build_attack_trace_view([]),
        "quick_actions": _build_quick_actions(),
        "surface_coverage_summary": _build_surface_coverage_summary([]),
        "mcp_tool_calls": _build_mcp_tool_calls_summary([], []),
        "agentic_browser_activity": _build_agentic_browser_activity_summary([], []),
        "intent_aware_activity": _build_intent_aware_activity_summary([]),
        "shadow_ai_summary": _build_shadow_ai_summary([], []),
        "identity_risk": _build_identity_risk(agents=[], runtime_events=[]),
        "control_coverage": _build_control_coverage([]),
        "violations": _build_violations([], started_at=started_at),
        "simulations": _build_simulations([], started_at=started_at),
        "remediation_actions": _build_remediation_actions([]),
        "ai_exposure_scan": {
            "scan_id": None,
            "status": "no_data",
            "scan_type": "discovery",
            "scope": "global",
            "scope_value": None,
            "last_scan_time": None,
            "started_at": None,
            "ended_at": None,
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
            "links": {
                "new_ai_apps": "/shadow-ai?state=new",
                "unknown_tools": "/shadow-ai?state=unknown",
                "new_users": "/ai-iam?filter=recently_discovered",
                "new_endpoints": "/ai-iam?filter=recently_discovered",
                "new_risks": "/discovery/findings?source=scan_delta",
                "alerts": "/dashboard/command-center?focus=alerts",
                "full_report": "/shadow-ai",
            },
            "error": None,
        },
        "crq_summary": _build_crq_summary([]),
        "sla_metrics": _build_sla_metrics(approvals=[], findings=[], job_runs=[], auditor_snapshots=[]),
        "recommendations": [],
        "cve_exposure": {
            "open_count": 0,
            "critical": 0,
            "high": 0,
            "drilldown": "/monitoring",
        },
        "external_risk_intelligence": {
            "critical_risks": 0,
            "high_or_critical_risks": 0,
            "known_exploited_items": 0,
            "affected_assets": 0,
            "new_risks_since_last_sync": 0,
            "simulations_recommended": 0,
            "remediation_pending": 0,
            "sync_status": "no_data",
            "last_sync_at": None,
            "source_health": [],
            "coverage_by_source": {},
            "total_ale_usd": 0.0,
            "total_residual_risk_usd": 0.0,
            "drilldown": "/monitoring?focus=external-risk",
        },
        "available_filters": {
            "time_window_hours": [24, 72, 168, 336, 720],
            "severity": ["all", "low", "med", "high", "critical"],
            "ai_systems": ai_system_options,
            "intent_categories": [],
            "input_sensitivities": ["none", "low", "medium", "high", "critical"],
            "output_sensitivities": ["none", "low", "medium", "high", "critical"],
            "action_alignments": ["aligned", "suspicious", "out_of_scope", "unknown"],
        },
    }


def _load_ai_systems(db: Session, *, tenant_id: str) -> list[AISystem]:
    return db.scalars(select(AISystem).where(AISystem.tenant_id == tenant_id)).all()


def _load_runtime_events(
    db: Session,
    *,
    tenant_id: str,
    started_at: datetime,
    ai_system_id: str | None,
) -> list[RuntimeEvent]:
    stmt = select(RuntimeEvent).where(
        RuntimeEvent.tenant_id == tenant_id,
        RuntimeEvent.created_at >= started_at,
    )
    if ai_system_id:
        stmt = stmt.where(RuntimeEvent.ai_system_id == ai_system_id)
    return db.scalars(stmt.order_by(desc(RuntimeEvent.created_at)).limit(5000)).all()


def _load_findings(
    db: Session,
    *,
    tenant_id: str,
    started_at: datetime,
    ai_system_id: str | None,
    severity: str | None,
) -> list[Finding]:
    def _query() -> list[Finding]:
        stmt = select(Finding).where(
            Finding.tenant_id == tenant_id,
            or_(
                Finding.created_at >= started_at,
                Finding.updated_at >= started_at,
            ),
        )
        if ai_system_id:
            stmt = stmt.where(Finding.ai_system_id == ai_system_id)
        if severity:
            stmt = stmt.where(func.lower(Finding.severity) == severity)
        return db.scalars(stmt.order_by(desc(Finding.updated_at)).limit(1200)).all()

    try:
        return _query()
    except OperationalError as exc:
        if _is_sqlite_missing_column_error(exc, "findings.agent_id"):
            db.rollback()
            if _repair_findings_runtime_columns(db):
                return _query()
        raise


def _build_risk_over_time(
    events: list[RuntimeEvent],
    *,
    started_at: datetime,
    time_window_hours: int,
) -> dict[str, Any]:
    bucket_count = 12
    step_hours = max(1, int(round(time_window_hours / bucket_count)))
    points: list[dict[str, Any]] = []
    for idx in range(bucket_count):
        bucket_start = started_at + timedelta(hours=idx * step_hours)
        bucket_end = bucket_start + timedelta(hours=step_hours)
        bucket_rows = [
            row
            for row in events
            if _within_window(_to_datetime(row.created_at), started_at=bucket_start)
            and _to_datetime(row.created_at) < bucket_end
        ]
        if bucket_rows:
            score = sum(float(row.risk_score or 0.0) for row in bucket_rows) / len(bucket_rows)
        else:
            score = 0.0
        points.append(
            {
                "label": bucket_start.strftime("%m-%d %H:%M"),
                "risk_score": round(float(score), 4),
                "event_count": len(bucket_rows),
            }
        )
    return {
        "points": points,
        "drilldown": "/runtime-intelligence/overview",
    }


def _build_severity_distribution(findings: list[Finding]) -> dict[str, Any]:
    counter = {"low": 0, "med": 0, "high": 0, "critical": 0}
    for row in findings:
        sev = _normalize_severity(row.severity) or "low"
        counter[sev] = int(counter.get(sev, 0)) + 1
    total = sum(counter.values())
    return {
        "counts": counter,
        "total": total,
        "drilldown": "/discovery/findings",
    }


def _build_exposure_score(
    *,
    findings: list[Finding],
    shadow_entities: list[ShadowAIEntity],
    runtime_events: list[RuntimeEvent],
    cve_summary: dict[str, Any],
) -> dict[str, Any]:
    high_findings = 0
    critical_findings = 0
    for row in findings:
        if not _is_open_status(row.status):
            continue
        sev = _normalize_severity(row.severity) or "low"
        if sev == "high":
            high_findings += 1
        if sev == "critical":
            critical_findings += 1
    shadow_high = sum(
        1
        for row in shadow_entities
        if (str(row.provisional_risk_tier or "").strip().upper() in {"HIGH", "CRITICAL"})
    )
    blocked_events = sum(1 for row in runtime_events if _decision_from_runtime_event(row) == "block")
    cve_critical = int(cve_summary.get("critical") or 0)
    cve_high = int(cve_summary.get("high") or 0)

    weighted = (
        (critical_findings * 12)
        + (high_findings * 7)
        + (shadow_high * 6)
        + (blocked_events * 2)
        + (cve_critical * 12)
        + (cve_high * 7)
    )
    score = max(0, min(100, weighted))
    return {
        "score": float(score),
        "components": {
            "critical_findings": critical_findings,
            "high_findings": high_findings,
            "shadow_high_risk": shadow_high,
            "blocked_events": blocked_events,
            "cve_critical": cve_critical,
            "cve_high": cve_high,
        },
        "drilldown": "/analytics",
    }


def _build_active_incidents(
    *,
    findings: list[Finding],
    drift_alerts: list[DriftAlert],
    remediation_actions: list[RemediationAction],
) -> dict[str, Any]:
    open_findings = [row for row in findings if _is_open_status(row.status)]
    high_critical = [
        row
        for row in open_findings
        if (_normalize_severity(row.severity) or "low") in {"high", "critical"}
    ]
    open_drift = [row for row in drift_alerts if str(row.status or "").lower() in {"open", "active"}]
    open_remediations = [
        row
        for row in remediation_actions
        if str(row.status or "").lower() in {"proposed", "failed"}
    ]
    return {
        "total": len(open_findings) + len(open_drift) + len(open_remediations),
        "open_findings": len(open_findings),
        "high_critical_findings": len(high_critical),
        "open_drift_alerts": len(open_drift),
        "open_remediation_actions": len(open_remediations),
        "drilldown": "/discovery/findings",
    }


def _build_runtime_heatmap(events: list[RuntimeEvent]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for surface in SOURCE_SURFACES:
        decision_counts = {key: 0 for key in DECISION_BUCKETS}
        surface_rows = [row for row in events if str(row.source_surface or "").strip().lower() == surface]
        for event in surface_rows:
            decision = _decision_from_runtime_event(event)
            if decision not in decision_counts:
                decision = "hold"
            decision_counts[decision] += 1
        rows.append(
            {
                "surface": surface,
                "counts": decision_counts,
                "total": sum(decision_counts.values()),
            }
        )
    return {
        "rows": rows,
        "drilldown": "/runtime-intelligence/activity-map",
    }


def _runtime_metadata(row: RuntimeEvent) -> dict[str, Any]:
    return dict(row.metadata_json or {}) if isinstance(row.metadata_json, dict) else {}


def _runtime_machine_id(row: RuntimeEvent) -> str | None:
    metadata = _runtime_metadata(row)
    return (
        str(metadata.get("machine_id") or "").strip()
        or str(metadata.get("endpoint_id") or "").strip()
        or str(metadata.get("host_id") or "").strip()
        or None
    )


def _runtime_action_type(row: RuntimeEvent) -> str:
    metadata = _runtime_metadata(row)
    return str(metadata.get("action_type") or metadata.get("operation") or row.event_type or "unknown").strip()


def _runtime_tool_name(row: RuntimeEvent) -> str | None:
    metadata = _runtime_metadata(row)
    return str(metadata.get("tool_name") or "").strip() or None


def _runtime_finding_id(row: RuntimeEvent) -> str | None:
    metadata = _runtime_metadata(row)
    return str(metadata.get("finding_id") or "").strip() or None


def _runtime_surface(row: RuntimeEvent) -> str:
    metadata = _runtime_metadata(row)
    return _normalize_source_surface(str(metadata.get("ai_surface") or row.source_surface or "monitoring"))


def _runtime_control_mode(row: RuntimeEvent) -> str:
    metadata = _runtime_metadata(row)
    ai_action = _coerce_dict(metadata.get("ai_action"))
    policy = _coerce_dict(ai_action.get("policy"))
    raw = str(policy.get("control_mode") or metadata.get("control_mode") or "").strip().lower()
    aliases = {
        "pre_action_blocked": "inline_prevented",
        "prevented": "inline_prevented",
        "blocked_inline": "inline_prevented",
        "inline_warn": "warned",
        "warn": "warned",
        "detect_only": "detected_only",
        "external_needed": "external_required",
    }
    raw = aliases.get(raw, raw)
    if raw in CONTROL_MODE_BUCKETS:
        return raw

    surface = _command_center_surface_bucket(row)
    decision = _decision_from_runtime_event(row)
    if decision == "block":
        if surface in {"browser", "mcp", "gateway_sdk"}:
            return "inline_prevented"
        if surface in {"foundry", "copilot"}:
            return "external_required"
        return "detected_only"
    if decision in {"warn", "require_approval", "hold"}:
        return "warned"
    if decision == "allow":
        if surface in {"browser", "mcp", "gateway_sdk"}:
            return "inline_allowed"
        return "telemetry_only"
    return "incomplete"


def _command_center_surface_bucket(row: RuntimeEvent) -> str:
    metadata = _runtime_metadata(row)
    values = {
        _runtime_surface(row),
        _normalize_source_surface(str(row.source_surface or "")),
        _normalize_source_surface(str(row.event_type or "")),
        _normalize_source_surface(str(metadata.get("surface") or "")),
        _normalize_source_surface(str(metadata.get("source_surface") or "")),
        _normalize_source_surface(str(metadata.get("action_type") or "")),
        _normalize_source_surface(str(metadata.get("operation") or "")),
    }
    values = {value for value in values if value}

    if values & {"browser", "browser_extension", "agentic_browser", "chatgpt", "claude", "gemini", "perplexity"}:
        return "browser"

    has_mcp_context = bool(
        str(metadata.get("mcp_server_id") or "").strip()
        or str(metadata.get("mcp_tool_id") or "").strip()
        or str(metadata.get("mcp_tool_name") or "").strip()
        or str(metadata.get("tool_name") or "").strip()
    )
    if has_mcp_context or values & {"mcp", "developer_mcp", "mcp_gateway", "mcp_tool_call", "tool_call"}:
        return "mcp"

    if values & {"foundry", "azure_ai_foundry", "azure_foundry", "microsoft_foundry"}:
        return "foundry"
    if values & {"copilot", "m365_copilot", "copilot_studio", "microsoft_copilot", "teams_copilot"}:
        return "copilot"
    if values & {"gateway", "llm_gateway", "sdk", "api", "azure_openai", "openai", "model_call", "gateway_model_call"}:
        return "gateway_sdk"
    if values & {"desktop", "desktop_ai", "local", "local_proxy", "swg", "endpoint", "proxy"}:
        return "desktop_proxy"
    if "connector" in values or "saas" in values:
        return "copilot" if str(row.app_id or "").strip().lower() in {"m365 copilot", "copilot studio"} else "desktop_proxy"
    return "unknown"


def _runtime_event_card(row: RuntimeEvent) -> dict[str, Any]:
    metadata = _runtime_metadata(row)
    ai_action = _coerce_dict(metadata.get("ai_action"))
    decision_explanation = _coerce_dict(metadata.get("decision_explanation") or ai_action.get("decision_explanation"))
    ai_policy = _coerce_dict(ai_action.get("policy"))
    ai_evidence = _coerce_dict(ai_action.get("evidence"))
    ai_surface = _coerce_dict(ai_action.get("surface"))
    intent_context = _coerce_dict(metadata.get("intent_context"))
    input_context = _coerce_dict(metadata.get("input_content_context"))
    output_context = _coerce_dict(metadata.get("output_context"))
    alignment_context = _coerce_dict(metadata.get("action_alignment_result"))
    destination_context = _coerce_dict(metadata.get("destination_context"))
    action_id = str(ai_action.get("action_id") or row.event_id or "").strip()
    finding_id = _runtime_finding_id(row)
    return {
        "event_id": row.event_id,
        "timestamp": row.created_at.isoformat() if row.created_at else None,
        "user_id": row.user_id,
        "user_email": str(metadata.get("user_email") or "").strip() or None,
        "agent_id": row.agent_id,
        "machine_id": _runtime_machine_id(row),
        "ai_surface": _runtime_surface(row),
        "source_surface": row.source_surface,
        "application": str(ai_surface.get("application") or row.app_id or metadata.get("application") or metadata.get("domain") or "").strip() or None,
        "action_type": _runtime_action_type(row),
        "tool_name": _runtime_tool_name(row),
        "policy_decision": _decision_from_runtime_event(row),
        "ai_action_id": action_id or None,
        "control_mode": str(ai_policy.get("control_mode") or metadata.get("control_mode") or "").strip() or None,
        "decision_badge": _pilot_decision_badge(row),
        "decision_explanation": decision_explanation or None,
        "evidence_status": str(ai_evidence.get("evidence_status") or metadata.get("evidence_status") or "").strip() or None,
        "intent_category": str(metadata.get("intent_category") or intent_context.get("intent_category") or "").strip() or None,
        "input_sensitivity": str(metadata.get("input_sensitivity") or input_context.get("sensitivity_level") or "").strip() or None,
        "output_sensitivity": str(metadata.get("output_sensitivity") or output_context.get("output_sensitivity") or "").strip() or None,
        "action_alignment": str(metadata.get("action_alignment") or alignment_context.get("alignment") or "").strip() or None,
        "destination_trust_level": str(destination_context.get("trust_level") or metadata.get("destination_trust_level") or "").strip() or None,
        "controls_triggered": [
            str(item).strip()
            for item in list(metadata.get("triggered_controls") or [])
            if str(item).strip()
        ],
        "risk_score": float(row.risk_score or 0.0),
        "finding_id": finding_id,
        "trace_url": f"/runtime-intelligence/context-graph?event_id={row.event_id}",
        "action_trace_url": f"/runtime-intelligence/action-trace/{action_id}" if action_id else None,
        "action_graph_url": f"/runtime-intelligence/action-graph/{action_id}" if action_id else None,
        "finding_url": f"/findings/{finding_id}" if finding_id else None,
        "finding_traceability_url": f"/findings/{finding_id}/traceability" if finding_id else None,
    }


def _normalized_dashboard_filter(value: str | None, *, supported: set[str] | None = None) -> str | None:
    normalized = str(value or "").strip().lower()
    if not normalized or normalized == "all":
        return None
    normalized = re.sub(r"[^a-z0-9_:\-.]+", "_", normalized).strip("_")
    if not normalized:
        return None
    if supported is not None and normalized not in supported:
        return None
    return normalized


def _runtime_intent_filter_fields(row: RuntimeEvent) -> dict[str, str]:
    card = _runtime_event_card(row)
    return {
        "intent_category": str(card.get("intent_category") or "").strip().lower(),
        "input_sensitivity": str(card.get("input_sensitivity") or "none").strip().lower() or "none",
        "output_sensitivity": str(card.get("output_sensitivity") or "none").strip().lower() or "none",
        "action_alignment": str(card.get("action_alignment") or "unknown").strip().lower() or "unknown",
    }


def _runtime_event_matches_intent_filters(
    row: RuntimeEvent,
    *,
    intent_category: str | None,
    input_sensitivity: str | None,
    output_sensitivity: str | None,
    action_alignment: str | None,
) -> bool:
    fields = _runtime_intent_filter_fields(row)
    if intent_category and fields["intent_category"] != intent_category:
        return False
    if input_sensitivity and fields["input_sensitivity"] != input_sensitivity:
        return False
    if output_sensitivity and fields["output_sensitivity"] != output_sensitivity:
        return False
    if action_alignment and fields["action_alignment"] != action_alignment:
        return False
    return True


def _filter_runtime_events_for_command_center(events: list[RuntimeEvent], filters: CommandCenterFilters) -> list[RuntimeEvent]:
    if not any([filters.intent_category, filters.input_sensitivity, filters.output_sensitivity, filters.action_alignment]):
        return events
    return [
        row
        for row in events
        if _runtime_event_matches_intent_filters(
            row,
            intent_category=filters.intent_category,
            input_sensitivity=filters.input_sensitivity,
            output_sensitivity=filters.output_sensitivity,
            action_alignment=filters.action_alignment,
        )
    ]


def _build_runtime_intent_filter_options(events: list[RuntimeEvent]) -> dict[str, list[str]]:
    intent_categories: set[str] = set()
    input_sensitivities: set[str] = set()
    output_sensitivities: set[str] = set()
    action_alignments: set[str] = set()
    for row in events:
        fields = _runtime_intent_filter_fields(row)
        if fields["intent_category"]:
            intent_categories.add(fields["intent_category"])
        input_sensitivities.add(fields["input_sensitivity"])
        output_sensitivities.add(fields["output_sensitivity"])
        action_alignments.add(fields["action_alignment"])

    sensitivity_order = ["none", "low", "medium", "high", "critical"]
    alignment_order = ["aligned", "suspicious", "out_of_scope", "unknown"]
    return {
        "intent_categories": sorted(intent_categories),
        "input_sensitivities": [item for item in sensitivity_order if item in input_sensitivities] or sensitivity_order,
        "output_sensitivities": [item for item in sensitivity_order if item in output_sensitivities] or sensitivity_order,
        "action_alignments": [item for item in alignment_order if item in action_alignments] or alignment_order,
    }


def _build_live_activity_feed(events: list[RuntimeEvent]) -> dict[str, Any]:
    items = [_runtime_event_card(row) for row in sorted(events, key=lambda item: item.created_at, reverse=True)[:50]]
    return {
        "items": items,
        "total": len(events),
        "drilldown": "/runtime-intelligence",
    }


def _ai_action_metadata(row: AIAction) -> dict[str, Any]:
    return _coerce_dict(row.metadata_json)


def _ai_action_control_mode(row: AIAction) -> str:
    metadata = _ai_action_metadata(row)
    ai_action = _coerce_dict(metadata.get("ai_action"))
    policy = _coerce_dict(ai_action.get("policy"))
    raw = str(policy.get("control_mode") or metadata.get("control_mode") or "").strip().lower()
    if raw == "pre_action_blocked":
        raw = "inline_prevented"
    if raw == "inline_warn":
        raw = "warned"
    if raw in CONTROL_MODE_BUCKETS:
        return raw

    enforcement = str(row.enforcement_action or "").strip().lower()
    if enforcement in {"blocked", "block", "deny", "denied"}:
        return "inline_prevented"
    if enforcement in {"warned", "warn"}:
        return "warned"
    if enforcement in {"detected", "detect_only", "logged"}:
        return "detected_only"
    if enforcement in {"allowed", "allow"}:
        return "inline_allowed"
    return "incomplete"


def _ai_action_evidence_status(row: AIAction) -> str:
    metadata = _ai_action_metadata(row)
    ai_action = _coerce_dict(metadata.get("ai_action"))
    evidence = _coerce_dict(ai_action.get("evidence"))
    raw = str(evidence.get("evidence_status") or metadata.get("evidence_status") or "").strip().lower()
    if raw in {"valid", "complete"}:
        return "complete"
    if raw in {"broken", "unchecked", "incomplete"}:
        return raw
    evidence_refs = _coerce_list(evidence.get("evidence_refs")) or _coerce_list(metadata.get("evidence_refs"))
    return "complete" if evidence_refs else "incomplete"


def _build_ai_action_control_summary(actions: list[AIAction]) -> dict[str, Any]:
    control_mode_counts = {mode: 0 for mode in CONTROL_MODE_BUCKETS}
    evidence_status_counts = {"complete": 0, "incomplete": 0, "unchecked": 0, "broken": 0}
    high_risk_actions = 0
    review_required = 0
    top_actions: list[dict[str, Any]] = []

    sorted_actions = sorted(
        actions,
        key=lambda row: (float(row.risk_score or 0.0), _to_datetime(row.timestamp) or datetime.min.replace(tzinfo=timezone.utc)),
        reverse=True,
    )
    for row in sorted_actions:
        control_mode = _ai_action_control_mode(row)
        evidence_status = _ai_action_evidence_status(row)
        control_mode_counts[control_mode] = int(control_mode_counts.get(control_mode) or 0) + 1
        evidence_status_counts[evidence_status] = int(evidence_status_counts.get(evidence_status) or 0) + 1
        risk_score = float(row.risk_score or 0.0)
        if risk_score >= 0.75:
            high_risk_actions += 1
        if str(row.enforcement_action or "").strip().lower() in {"review", "require_approval", "held", "hold"}:
            review_required += 1
        if len(top_actions) < 10:
            top_actions.append(
                {
                    "action_id": row.action_id,
                    "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                    "user_id": row.user_id,
                    "endpoint_id": row.endpoint_id,
                    "session_id": row.session_id,
                    "ai_app": row.ai_app,
                    "action_type": row.action_type,
                    "policy_triggered": row.policy_triggered,
                    "enforcement_action": row.enforcement_action,
                    "control_mode": control_mode,
                    "evidence_status": evidence_status,
                    "risk_score": risk_score,
                    "correlation_id": row.correlation_id,
                    "action_trace_url": f"/runtime-intelligence/action-trace/{row.action_id}",
                    "action_graph_url": f"/runtime-intelligence/action-graph/{row.action_id}",
                }
            )

    return {
        "total_actions": len(actions),
        "control_mode_counts": control_mode_counts,
        "evidence_status_counts": evidence_status_counts,
        "high_risk_actions": high_risk_actions,
        "review_required": review_required,
        "top_actions": top_actions,
        "drilldown": "/runtime-intelligence/actions",
    }


def _build_users_view(events: list[RuntimeEvent]) -> dict[str, Any]:
    by_user: dict[str, dict[str, Any]] = {}
    for row in events:
        user_id = str(row.user_id or "").strip()
        if not user_id:
            continue
        metadata = _runtime_metadata(row)
        item = by_user.setdefault(
            user_id,
            {
                "user_id": user_id,
                "user_email": str(metadata.get("user_email") or "").strip() or None,
                "machine_ids": set(),
                "browsers": set(),
                "connected_apps": set(),
                "active_agent_ids": set(),
                "ai_activity_count": 0,
                "risk_score": 0.0,
                "last_seen": None,
            },
        )
        machine_id = _runtime_machine_id(row)
        browser_type = str(metadata.get("browser_type") or metadata.get("browser") or "").strip().lower()
        app = str(row.app_id or metadata.get("application") or metadata.get("domain") or "").strip()
        if machine_id:
            item["machine_ids"].add(machine_id)
        if browser_type:
            item["browsers"].add(browser_type)
        if app:
            item["connected_apps"].add(app)
        if str(row.agent_id or "").strip():
            item["active_agent_ids"].add(str(row.agent_id).strip())
        item["ai_activity_count"] += 1
        item["risk_score"] = max(float(item["risk_score"] or 0.0), float(row.risk_score or 0.0))
        if row.created_at and (not item["last_seen"] or row.created_at.isoformat() > str(item["last_seen"])):
            item["last_seen"] = row.created_at.isoformat()

    items: list[dict[str, Any]] = []
    for item in by_user.values():
        items.append(
            {
                **item,
                "machine_ids": sorted(item["machine_ids"]),
                "browsers": sorted(item["browsers"]),
                "connected_apps": sorted(item["connected_apps"]),
                "active_agent_ids": sorted(item["active_agent_ids"]),
            }
        )
    return {
        "items": sorted(items, key=lambda item: (float(item.get("risk_score") or 0.0), str(item.get("last_seen") or "")), reverse=True)[:50],
        "total": len(items),
        "drilldown": "/ai-iam?view=users",
    }


def _build_agents_view(*, agents: list[AgentIdentity], events: list[RuntimeEvent], findings: list[Finding]) -> dict[str, Any]:
    agent_lookup = {str(agent.id): agent for agent in agents}
    finding_ids_by_agent: dict[str, set[str]] = {}
    for finding in findings:
        agent_id = str(finding.agent_id or "").strip()
        if agent_id and str(finding.finding_id or "").strip():
            finding_ids_by_agent.setdefault(agent_id, set()).add(str(finding.finding_id))

    by_agent: dict[str, dict[str, Any]] = {}
    for row in events:
        agent_id = str(row.agent_id or "").strip()
        if not agent_id:
            continue
        item = by_agent.setdefault(
            agent_id,
            {
                "agent_id": agent_id,
                "name": getattr(agent_lookup.get(agent_id), "name", agent_id),
                "owner": row.user_id,
                "status": getattr(agent_lookup.get(agent_id), "status", "observed"),
                "recent_actions": [],
                "tools_used": set(),
                "apps_touched": set(),
                "risk_score": 0.0,
                "anomaly_flag": False,
                "linked_findings": finding_ids_by_agent.get(agent_id, set()),
            },
        )
        action = _runtime_event_card(row)
        item["recent_actions"].append(action)
        if action.get("tool_name"):
            item["tools_used"].add(action["tool_name"])
        if action.get("application"):
            item["apps_touched"].add(action["application"])
        item["risk_score"] = max(float(item["risk_score"] or 0.0), float(row.risk_score or 0.0))
        if action.get("finding_id"):
            item["linked_findings"].add(action["finding_id"])
        item["anomaly_flag"] = bool(item["anomaly_flag"] or float(row.risk_score or 0.0) >= 0.8)

    items: list[dict[str, Any]] = []
    for item in by_agent.values():
        item["recent_actions"] = sorted(item["recent_actions"], key=lambda action: str(action.get("timestamp") or ""), reverse=True)[:10]
        item["tools_used"] = sorted(item["tools_used"])
        item["apps_touched"] = sorted(item["apps_touched"])
        item["linked_findings"] = sorted(item["linked_findings"])
        items.append(item)
    return {
        "items": sorted(items, key=lambda item: float(item.get("risk_score") or 0.0), reverse=True)[:50],
        "total": len(items),
        "registered_agents": len(agents),
        "drilldown": "/ai-iam?view=agents",
    }


def _build_findings_alerts(findings: list[Finding]) -> dict[str, Any]:
    rows = sorted(findings, key=lambda row: row.last_seen_at or row.updated_at, reverse=True)[:50]
    items: list[dict[str, Any]] = []
    for row in rows:
        link = f"/discovery/findings/{row.finding_id}"
        drilldowns = _notification_drilldowns(
            link=link,
            finding_id=row.finding_id,
            action_id=None,
            agent_id=row.agent_id,
            chain_id=_notification_chain_id(finding=row),
        )
        primary = _notification_primary_drilldown(drilldowns)
        items.append(
            {
                "finding_id": row.finding_id,
                "timestamp": (row.last_seen_at or row.updated_at).isoformat()
                if (row.last_seen_at or row.updated_at)
                else None,
                "severity": row.severity,
                "finding_type": row.finding_type,
                "user_id": row.user_id,
                "agent_id": row.agent_id,
                "machine_id": row.machine_id,
                "app": row.ai_tool,
                "ai_surface": row.source_surface,
                "policy_id": row.policy_version_id,
                "control_ids": list(row.related_control_ids or []),
                "related_event_ids": list(row.related_event_ids or []),
                "recommended_actions": [row.recommended_action] if str(row.recommended_action or "").strip() else [],
                "link": link,
                "drilldowns": drilldowns,
                "primary_drilldown": primary,
                "primary_drilldown_type": primary.get("type") if primary else None,
                "investigation_link": primary.get("href") if primary else link,
            }
        )
    return {
        "items": items,
        "total": len(findings),
        "drilldown": "/discovery/findings",
    }


def _build_surface_coverage_summary(events: list[RuntimeEvent]) -> dict[str, Any]:
    surfaces = (
        "browser",
        "saas",
        "gateway",
        "api",
        "agent",
        "local",
        "desktop",
        "connector",
        "endpoint",
        "monitoring",
        "foundry",
        "copilot",
    )
    payload: dict[str, dict[str, Any]] = {
        surface: {"event_count": 0, "blocked": 0, "warned": 0, "apps": set(), "agents": set(), "users": set()}
        for surface in surfaces
    }
    matrix_payload: dict[str, dict[str, Any]] = {
        str(definition["id"]): {
            "definition": definition,
            "event_count": 0,
            "blocked": 0,
            "warned": 0,
            "apps": set(),
            "agents": set(),
            "users": set(),
            **{mode: 0 for mode in CONTROL_MODE_BUCKETS},
        }
        for definition in SURFACE_MATRIX_DEFINITIONS
    }
    matrix_totals = {"event_count": 0, **{mode: 0 for mode in CONTROL_MODE_BUCKETS}}

    for row in events:
        surface = _runtime_surface(row)
        item = payload.setdefault(surface, {"event_count": 0, "blocked": 0, "warned": 0, "apps": set(), "agents": set(), "users": set()})
        decision = _decision_from_runtime_event(row)
        item["event_count"] += 1
        if decision == "block":
            item["blocked"] += 1
        if decision in {"warn", "require_approval"}:
            item["warned"] += 1
        if str(row.app_id or "").strip():
            item["apps"].add(str(row.app_id).strip())
        if str(row.agent_id or "").strip():
            item["agents"].add(str(row.agent_id).strip())
        if str(row.user_id or "").strip():
            item["users"].add(str(row.user_id).strip())

        matrix_surface = _command_center_surface_bucket(row)
        matrix_item = matrix_payload.get(matrix_surface)
        if matrix_item:
            control_mode = _runtime_control_mode(row)
            matrix_item["event_count"] += 1
            matrix_item[control_mode] = int(matrix_item.get(control_mode) or 0) + 1
            matrix_totals["event_count"] += 1
            matrix_totals[control_mode] = int(matrix_totals.get(control_mode) or 0) + 1
            if decision == "block":
                matrix_item["blocked"] += 1
            if decision in {"warn", "require_approval"}:
                matrix_item["warned"] += 1
            if str(row.app_id or "").strip():
                matrix_item["apps"].add(str(row.app_id).strip())
            if str(row.agent_id or "").strip():
                matrix_item["agents"].add(str(row.agent_id).strip())
            if str(row.user_id or "").strip():
                matrix_item["users"].add(str(row.user_id).strip())

    surface_rows: list[dict[str, Any]] = []
    for definition in SURFACE_MATRIX_DEFINITIONS:
        surface_id = str(definition["id"])
        item = matrix_payload[surface_id]
        observed_modes = [
            mode
            for mode in CONTROL_MODE_BUCKETS
            if int(item.get(mode) or 0) > 0
        ]
        current_mode = (
            max(observed_modes, key=lambda mode: CONTROL_MODE_PRIORITY.get(mode, 0))
            if observed_modes
            else str(definition["default_mode"])
        )
        if int(item["event_count"]) == 0:
            status = "not_seen"
        elif int(item.get("inline_prevented") or 0) or int(item.get("inline_allowed") or 0) or int(item.get("warned") or 0):
            status = "active_inline"
        elif int(item.get("external_action_triggered") or 0):
            status = "external_action_triggered"
        elif int(item.get("external_required") or 0):
            status = "external_required"
        elif int(item.get("telemetry_only") or 0) or int(item.get("detected_only") or 0):
            status = "telemetry_only"
        else:
            status = "incomplete"

        surface_rows.append(
            {
                "id": surface_id,
                "label": definition["label"],
                "surface_type": definition["surface_type"],
                "coverage": definition["coverage"],
                "primary_control": definition["primary_control"],
                "proof_label": definition["proof_label"],
                "drilldown": definition["drilldown"],
                "current_mode": current_mode,
                "dominant_control_mode": current_mode,
                "status": status,
                "event_count": int(item["event_count"]),
                "blocked": int(item["blocked"]),
                "warned": int(item["warned"]),
                "apps": sorted(item["apps"]),
                "agents": sorted(item["agents"]),
                "users": sorted(item["users"]),
                "mode_counts": {mode: int(item.get(mode) or 0) for mode in CONTROL_MODE_BUCKETS},
                **{mode: int(item.get(mode) or 0) for mode in CONTROL_MODE_BUCKETS},
            }
        )

    return {
        "surfaces": {
            surface: {
                "event_count": int(item["event_count"]),
                "blocked": int(item["blocked"]),
                "warned": int(item["warned"]),
                "apps": sorted(item["apps"]),
                "agents": sorted(item["agents"]),
                "users": sorted(item["users"]),
            }
            for surface, item in payload.items()
        },
        "surface_rows": surface_rows,
        "totals": {key: int(value) for key, value in matrix_totals.items()},
        "drilldown": "/runtime-intelligence/activity-map",
    }


def _build_mcp_tool_calls_summary(events: list[RuntimeEvent], findings: list[Finding]) -> dict[str, Any]:
    mcp_events: list[RuntimeEvent] = []
    for row in events:
        metadata = _coerce_dict(row.metadata_json)
        action_type = str(metadata.get("action_type") or metadata.get("operation") or row.event_type or "").strip().lower()
        ai_surface = str(metadata.get("ai_surface") or metadata.get("surface") or "").strip().lower()
        has_mcp_context = bool(
            str(metadata.get("mcp_server_id") or "").strip()
            or str(metadata.get("mcp_tool_id") or "").strip()
            or action_type.startswith("mcp_")
            or ai_surface == "mcp_tool_call"
        )
        if has_mcp_context:
            mcp_events.append(row)

    active_servers: set[str] = set()
    active_clients: set[str] = set()
    blocked_calls = 0
    high_risk_calls = 0
    today_calls = 0
    for row in mcp_events:
        metadata = _coerce_dict(row.metadata_json)
        server_id = str(metadata.get("mcp_server_id") or row.app_id or "").strip()
        if server_id:
            active_servers.add(server_id)
        client = str(metadata.get("ai_client") or metadata.get("client") or metadata.get("client_name") or "").strip()
        if client:
            active_clients.add(client)
        decision = _decision_from_runtime_event(row)
        if decision in {"block", "deny"}:
            blocked_calls += 1
        if float(row.risk_score or 0.0) >= 0.8 or str(row.severity or "").strip().lower() in {"high", "critical"}:
            high_risk_calls += 1
        action = str(metadata.get("action_type") or metadata.get("operation") or row.event_type or "").strip().lower()
        if action in {
            "mcp_tool_call_requested",
            "mcp_tool_call_allowed",
            "mcp_tool_call_blocked",
            "mcp_tool_call_approved",
            "mcp_tool_call_denied",
            "mcp_tool_result_returned",
        }:
            today_calls += 1

    shadow_servers = 0
    permission_drift_findings = 0
    unapproved_clients_tools = 0
    for row in findings:
        finding_type = str(row.finding_type or "").strip().upper()
        if finding_type == "SHADOW_MCP_SERVER":
            shadow_servers += 1
        if finding_type == "MCP_PERMISSION_DRIFT":
            permission_drift_findings += 1
        if finding_type in {"UNAPPROVED_AI_CLIENT", "UNAPPROVED_MCP_TOOL"}:
            unapproved_clients_tools += 1

    return {
        "active_mcp_servers": len(active_servers),
        "shadow_mcp_servers": shadow_servers,
        "active_ai_clients": len(active_clients),
        "tool_calls_today": today_calls,
        "blocked_tool_calls": blocked_calls,
        "high_risk_tool_calls": high_risk_calls,
        "permission_drift_findings": permission_drift_findings,
        "unapproved_clients_or_tools": unapproved_clients_tools,
        "drilldown": "/runtime-intelligence/activity-map?surface=mcp_tool_call",
    }


def _build_agentic_browser_activity_summary(events: list[RuntimeEvent], findings: list[Finding]) -> dict[str, Any]:
    agentic_events: list[RuntimeEvent] = []
    for row in events:
        metadata = _coerce_dict(row.metadata_json)
        ai_action = _coerce_dict(metadata.get("ai_action"))
        ai_surface_payload = _coerce_dict(ai_action.get("surface"))
        event_type = str(row.event_type or "").strip().lower()
        operation = str(metadata.get("operation") or metadata.get("action_type") or "").strip().lower()
        ai_surface = str(ai_surface_payload.get("surface_type") or metadata.get("ai_surface") or "").strip().lower()
        if (
            event_type == "browser_automation_action"
            or "browser_automation" in operation
            or ai_surface == "agentic_browser"
        ):
            agentic_events.append(row)

    blocked_actions = 0
    warned_events = 0
    detected_only_events = 0
    scope_violations = 0
    high_risk_actions_blocked = 0
    decision_badge_breakdown = {
        "Prevented": 0,
        "Warned": 0,
        "Allowed": 0,
        "Detected-only": 0,
        "Incomplete": 0,
    }
    top_domains: dict[str, int] = {}
    top_suspected_tools: dict[str, int] = {}

    for row in agentic_events:
        metadata = _coerce_dict(row.metadata_json)
        ai_action = _coerce_dict(metadata.get("ai_action"))
        ai_policy = _coerce_dict(ai_action.get("policy"))
        ai_surface_payload = _coerce_dict(ai_action.get("surface"))
        ai_action_payload = _coerce_dict(ai_action.get("action"))
        decision = _decision_from_runtime_event(row)
        action_risk = str(ai_action_payload.get("action_risk") or metadata.get("action_risk") or "").strip().lower()
        decision_badge = str(ai_policy.get("decision_badge") or metadata.get("decision_badge") or "").strip().lower()
        control_mode = str(ai_policy.get("control_mode") or metadata.get("control_mode") or "").strip().lower()
        pilot_badge = _pilot_decision_badge(row)
        domain = str(ai_surface_payload.get("domain") or row.app_id or metadata.get("domain") or metadata.get("application") or "").strip().lower()
        source_vendor = str(metadata.get("source_vendor") or "").strip()
        suspected_tool = str(metadata.get("suspected_tool") or "").strip()

        decision_badge_breakdown[pilot_badge] = int(decision_badge_breakdown.get(pilot_badge) or 0) + 1
        if decision in {"block", "deny"}:
            blocked_actions += 1
            if action_risk == "high":
                high_risk_actions_blocked += 1
        if decision == "warn":
            warned_events += 1
        if control_mode == "detected_only":
            detected_only_events += 1
        if decision_badge == "scope violation" or "scope_violation" in str(metadata.get("reason") or "").lower():
            scope_violations += 1
        if domain:
            top_domains[domain] = int(top_domains.get(domain) or 0) + 1
        tool_or_vendor = suspected_tool or source_vendor
        if tool_or_vendor:
            top_suspected_tools[tool_or_vendor] = int(top_suspected_tools.get(tool_or_vendor) or 0) + 1

    finding_type_counter: dict[str, int] = {}
    for row in findings:
        finding_type = str(row.finding_type or "").strip().upper()
        if finding_type in {
            "BROWSER_AUTOMATION_DETECTED",
            "BROWSER_AGENT_SCOPE_VIOLATION",
            "HIGH_RISK_BROWSER_AUTOMATION_ACTION",
            "LOCAL_AGENT_BROWSER_AUTOMATION_SUSPECTED",
            "AUTOMATION_ON_BLOCKED_DOMAIN",
            "AUTOMATION_PURCHASE_ACTION_BLOCKED",
            "AUTOMATION_FORM_SUBMIT_BLOCKED",
            "AUTOMATION_FILE_UPLOAD_BLOCKED",
            "AGENT_USING_AUTHENTICATED_BROWSER",
            "AGENTIC_BROWSER_DETECTED",
            "AI_ACTION_BOUNDARY_VIOLATION",
        }:
            finding_type_counter[finding_type] = int(finding_type_counter.get(finding_type) or 0) + 1

    return {
        "automation_events_today": len(agentic_events),
        "blocked_automation_actions": blocked_actions,
        "warned_automation_events": warned_events,
        "prevented_events": decision_badge_breakdown["Prevented"],
        "allowed_events": decision_badge_breakdown["Allowed"],
        "detected_only_events": detected_only_events,
        "incomplete_events": decision_badge_breakdown["Incomplete"],
        "decision_badge_breakdown": decision_badge_breakdown,
        "scope_violations": scope_violations,
        "high_risk_actions_blocked": high_risk_actions_blocked,
        "top_domains_with_automation": [
            {"domain": domain, "count": count}
            for domain, count in sorted(top_domains.items(), key=lambda item: item[1], reverse=True)[:5]
        ],
        "top_suspected_tools_or_vendors": [
            {"label": label, "count": count}
            for label, count in sorted(top_suspected_tools.items(), key=lambda item: item[1], reverse=True)[:5]
        ],
        "finding_breakdown": finding_type_counter,
        "drilldown": "/runtime-intelligence/activity-map?surface=agentic_browser",
    }


def _build_intent_aware_activity_summary(events: list[RuntimeEvent]) -> dict[str, Any]:
    intent_events: list[RuntimeEvent] = []
    for row in events:
        metadata = _runtime_metadata(row)
        if (
            isinstance(metadata.get("intent_aware_decision"), dict)
            or isinstance(metadata.get("intent_context"), dict)
            or str(metadata.get("intent_category") or "").strip()
        ):
            intent_events.append(row)

    blocked_sensitive_inputs = 0
    blocked_output_copies = 0
    intent_scope_violations = 0
    sales_outreach_data_violations = 0
    shadow_would_block = 0
    allowed_research = 0
    badge_breakdown = {
        "Prevented": 0,
        "Warned": 0,
        "Allowed": 0,
        "Detected-only": 0,
        "Incomplete": 0,
    }
    sensitive_destinations: dict[str, int] = {}

    for row in intent_events:
        metadata = _runtime_metadata(row)
        intent_context = _coerce_dict(metadata.get("intent_context"))
        input_context = _coerce_dict(metadata.get("input_content_context"))
        output_context = _coerce_dict(metadata.get("output_context"))
        alignment_context = _coerce_dict(metadata.get("action_alignment_result"))
        destination_context = _coerce_dict(metadata.get("destination_context"))
        intent_decision = _coerce_dict(metadata.get("intent_aware_decision"))
        decision = str(intent_decision.get("decision") or _decision_from_runtime_event(row)).strip().lower()
        would_decision = str(intent_decision.get("would_decision") or decision).strip().lower()
        finding_type = str(intent_decision.get("finding_type") or metadata.get("finding_type") or "").strip().upper()
        intent_category = str(intent_context.get("intent_category") or metadata.get("intent_category") or "").strip().lower()
        action_type = str(metadata.get("action_type") or row.event_type or "").strip().lower()
        input_sensitivity = str(input_context.get("sensitivity_level") or metadata.get("input_sensitivity") or "none").strip().lower()
        output_sensitivity = str(output_context.get("output_sensitivity") or metadata.get("output_sensitivity") or "none").strip().lower()
        trust_level = str(destination_context.get("trust_level") or metadata.get("destination_trust_level") or "unknown").strip().lower()
        alignment = str(alignment_context.get("alignment") or metadata.get("action_alignment") or "").strip().lower()

        if decision == "allow" and would_decision == "block":
            badge = "Detected-only"
        elif decision in {"block", "deny"}:
            badge = "Prevented"
        elif decision == "warn":
            badge = "Warned"
        else:
            badge = _pilot_decision_badge(row)
        badge_breakdown[badge] = int(badge_breakdown.get(badge) or 0) + 1

        if (
            decision == "allow"
            and would_decision == "allow"
            and action_type in {"prompt_submit", "browse", "page_view", "navigate", "search", "read_content"}
            and intent_category in {"company_lookup", "public_research", "market_research", "competitor_research"}
        ):
            allowed_research += 1
        if decision == "block" and input_sensitivity in {"medium", "high", "critical"}:
            blocked_sensitive_inputs += 1
        if finding_type == "AI_OUTPUT_COPY_BLOCKED" and (decision == "block" or would_decision == "block"):
            blocked_output_copies += 1
        if alignment == "out_of_scope" or finding_type == "INTENT_ACTION_SCOPE_VIOLATION":
            intent_scope_violations += 1
        if finding_type in {"BUSINESS_EMAIL_DATA_TO_AI", "CRM_DATA_TO_PUBLIC_AI", "CUSTOMER_CONTACT_DATA_TO_AI"}:
            sales_outreach_data_violations += 1
        if decision == "allow" and would_decision == "block":
            shadow_would_block += 1
        if trust_level == "public_ai" and (input_sensitivity in {"medium", "high", "critical"} or output_sensitivity in {"medium", "high", "critical"}):
            sensitive_destinations[trust_level] = int(sensitive_destinations.get(trust_level) or 0) + 1

    return {
        "intent_aware_actions": len(intent_events),
        "allowed_research": allowed_research,
        "blocked_sensitive_inputs": blocked_sensitive_inputs,
        "blocked_output_copies": blocked_output_copies,
        "intent_scope_violations": intent_scope_violations,
        "sales_outreach_data_violations": sales_outreach_data_violations,
        "shadow_would_block": shadow_would_block,
        "top_sensitive_destinations": [
            {"trust_level": trust_level, "count": count}
            for trust_level, count in sorted(sensitive_destinations.items(), key=lambda item: item[1], reverse=True)[:5]
        ],
        "badge_breakdown": badge_breakdown,
        "drilldown": "/runtime-intelligence/activity-map?filter=intent-aware",
    }


def _build_attack_trace_view(events: list[RuntimeEvent]) -> dict[str, Any]:
    if not events:
        return {"trace_key": None, "trace_key_type": None, "steps": [], "event_count": 0}
    anchor = max(events, key=lambda row: float(row.risk_score or 0.0))
    trace_key = str(anchor.chain_id or anchor.context_id or anchor.correlation_id or anchor.event_id)
    trace_key_type = "chain_id" if anchor.chain_id else "context_id" if anchor.context_id else "correlation_id" if anchor.correlation_id else "event_id"
    rows = [
        row
        for row in events
        if (
            (trace_key_type == "chain_id" and row.chain_id == trace_key)
            or (trace_key_type == "context_id" and row.context_id == trace_key)
            or (trace_key_type == "correlation_id" and row.correlation_id == trace_key)
            or (trace_key_type == "event_id" and row.event_id == trace_key)
        )
    ]
    rows = sorted(rows, key=lambda row: row.created_at)
    return {
        "trace_key": trace_key,
        "trace_key_type": trace_key_type,
        "event_count": len(rows),
        "steps": [
            {
                "step_number": index,
                "event_id": row.event_id,
                "title": f"Step {index}: {_runtime_surface(row)} {_runtime_action_type(row).replace('_', ' ')}",
                "timestamp": row.created_at.isoformat() if row.created_at else None,
                "policy_decision": _decision_from_runtime_event(row),
                "controls_triggered": _runtime_event_card(row)["controls_triggered"],
                "user_id": row.user_id,
                "agent_id": row.agent_id,
                "machine_id": _runtime_machine_id(row),
                "finding_id": _runtime_finding_id(row),
            }
            for index, row in enumerate(rows, start=1)
        ],
        "drilldown": f"/runtime-intelligence/context-graph?trace_key={trace_key}",
    }


def _build_quick_actions() -> list[dict[str, Any]]:
    return [
        {"action": "block_user", "label": "Block user", "api": "/runtime-control/users/{user_id}/block"},
        {"action": "revoke_token", "label": "Revoke token", "api": "/ai-iam/tokens/{token_id}/revoke"},
        {"action": "disable_agent", "label": "Disable agent", "api": "/ai-iam/agents/{agent_id}"},
        {"action": "block_tool", "label": "Block tool", "api": "/runtime-control/tools/{tool_id}/block"},
        {"action": "isolate", "label": "Kill switch", "api": "/ai-iam/agents/{agent_id}/kill-switch"},
        {"action": "enforce_strict_policy", "label": "Enforce strict policy", "api": "/policies"},
        {"action": "require_approval", "label": "Require approval", "api": "/agui/policy-overrides"},
        {"action": "route_finding", "label": "Route finding", "api": "/findings/{finding_id}/assign-owner"},
    ]


def _build_shadow_ai_summary(
    entities: list[ShadowAIEntity],
    signals: list[ShadowAISignal],
) -> dict[str, Any]:
    status_counts = {"discovered": 0, "reconciled": 0, "promoted": 0, "rejected": 0}
    surface_counts: dict[str, int] = {surface: 0 for surface in SOURCE_SURFACES}
    for row in entities:
        status = str(row.discovery_status or "").strip().lower()
        if status in status_counts:
            status_counts[status] += 1
        for surface in (row.source_surfaces or []):
            normalized = str(surface or "").strip().lower()
            if normalized:
                surface_counts[normalized] = int(surface_counts.get(normalized, 0)) + 1

    top_entities = sorted(
        entities,
        key=lambda row: (float(row.confidence_score or 0.0), _to_datetime(row.last_seen) or datetime.min.replace(tzinfo=timezone.utc)),
        reverse=True,
    )[:8]

    signal_breakdown: dict[str, int] = {}
    for signal in signals:
        surface = str(signal.source_surface or "").strip().lower() or "unknown"
        signal_breakdown[surface] = int(signal_breakdown.get(surface, 0)) + 1

    return {
        "total_entities": len(entities),
        "high_risk_entities": sum(
            1 for row in entities if str(row.provisional_risk_tier or "").strip().upper() in {"HIGH", "CRITICAL"}
        ),
        "status_counts": status_counts,
        "surface_counts": surface_counts,
        "signal_breakdown": signal_breakdown,
        "top_entities": [
            {
                "id": row.id,
                "canonical_name": row.canonical_name,
                "confidence_score": float(row.confidence_score or 0.0),
                "provisional_risk_tier": row.provisional_risk_tier,
                "discovery_status": row.discovery_status,
                "linked_ai_system_id": row.linked_ai_system_id,
                "last_seen": row.last_seen.isoformat() if _to_datetime(row.last_seen) else None,
                "source_surfaces": [str(item) for item in (row.source_surfaces or []) if str(item).strip()],
            }
            for row in top_entities
        ],
        "drilldown": "/shadow-ai",
    }


def _build_identity_risk(
    *,
    agents: list[AgentIdentity],
    runtime_events: list[RuntimeEvent],
) -> dict[str, Any]:
    agent_events = [row for row in runtime_events if str(row.agent_id or "").strip()]
    by_agent: dict[str, dict[str, Any]] = {}
    for event in agent_events:
        agent_id = str(event.agent_id or "").strip()
        decision = _decision_from_runtime_event(event)
        row = by_agent.setdefault(
            agent_id,
            {"actions": 0, "blocked": 0, "warn": 0, "risk_sum": 0.0, "risk_count": 0},
        )
        row["actions"] += 1
        if decision == "block":
            row["blocked"] += 1
        elif decision == "warn":
            row["warn"] += 1
        row["risk_sum"] += float(event.risk_score or 0.0)
        row["risk_count"] += 1

    agent_lookup = {str(agent.id): agent for agent in agents}
    top_agents = sorted(
        by_agent.items(),
        key=lambda item: (
            int(item[1]["blocked"]),
            int(item[1]["warn"]),
            float(item[1]["risk_sum"]) / max(1, int(item[1]["risk_count"])),
        ),
        reverse=True,
    )[:10]
    return {
        "total_agents": len(agents),
        "active_agents": sum(1 for row in agents if str(row.status or "").strip().lower() == "active"),
        "risky_agents": sum(1 for _, stats in by_agent.items() if int(stats["blocked"]) > 0 or int(stats["warn"]) >= 2),
        "top_agents": [
            {
                "agent_id": agent_id,
                "agent_name": (agent_lookup.get(agent_id).name if agent_lookup.get(agent_id) else agent_id),
                "status": (agent_lookup.get(agent_id).status if agent_lookup.get(agent_id) else "unknown"),
                "max_chain_depth": (agent_lookup.get(agent_id).max_chain_depth if agent_lookup.get(agent_id) else None),
                "actions": int(stats["actions"]),
                "blocked": int(stats["blocked"]),
                "warn": int(stats["warn"]),
                "avg_risk_score": round(float(stats["risk_sum"]) / max(1, int(stats["risk_count"])), 4),
            }
            for agent_id, stats in top_agents
        ],
        "drilldown": "/ai-iam",
    }


def _build_control_coverage(maturity_rows: list[ControlMaturity]) -> dict[str, Any]:
    if not maturity_rows:
        return {
            "average_maturity": 0.0,
            "average_technical_enforcement": 0.0,
            "average_simulation_pass_rate": 0.0,
            "average_coverage_score": 0.0,
            "status_counts": {},
            "lowest_controls": [],
            "drilldown": "/validation/coverage",
        }
    avg_maturity = sum(float(row.maturity_score or 0.0) for row in maturity_rows) / len(maturity_rows)
    avg_tech = sum(float(row.technical_enforcement_score or 0.0) for row in maturity_rows) / len(maturity_rows)
    avg_sim = sum(float(row.simulation_pass_rate or 0.0) for row in maturity_rows) / len(maturity_rows)
    avg_cov = sum(float(row.coverage_score or 0.0) for row in maturity_rows) / len(maturity_rows)
    status_counts: dict[str, int] = {}
    for row in maturity_rows:
        status = str(row.status or "").strip().lower() or "unknown"
        status_counts[status] = int(status_counts.get(status, 0)) + 1
    lowest = sorted(maturity_rows, key=lambda row: float(row.maturity_score or 0.0))[:8]
    return {
        "average_maturity": round(avg_maturity, 4),
        "average_technical_enforcement": round(avg_tech, 4),
        "average_simulation_pass_rate": round(avg_sim, 4),
        "average_coverage_score": round(avg_cov, 4),
        "status_counts": status_counts,
        "lowest_controls": [
            {
                "control_id": row.control_id,
                "maturity_score": float(row.maturity_score or 0.0),
                "technical_enforcement_score": float(row.technical_enforcement_score or 0.0),
                "simulation_pass_rate": float(row.simulation_pass_rate or 0.0),
                "coverage_score": float(row.coverage_score or 0.0),
                "status": row.status,
            }
            for row in lowest
        ],
        "drilldown": "/validation/coverage",
    }


def _build_violations(findings: list[Finding], *, started_at: datetime) -> dict[str, Any]:
    window_rows = [
        row for row in findings if _within_window(_to_datetime(row.updated_at) or _to_datetime(row.created_at), started_at=started_at)
    ]
    open_rows = [row for row in findings if _is_open_status(row.status)]
    high_critical_open = [
        row
        for row in open_rows
        if (_normalize_severity(row.severity) or "low") in {"high", "critical"}
    ]
    sorted_rows = sorted(
        window_rows,
        key=lambda row: (
            _severity_weight(row.severity),
            int(row.occurrence_count or 1),
            _to_datetime(row.last_seen_at) or datetime.min.replace(tzinfo=timezone.utc),
        ),
        reverse=True,
    )
    items: list[dict[str, Any]] = []
    for row in sorted_rows[:20]:
        link = f"/discovery/findings/{row.finding_id}"
        action_id = str(row.related_runtime_event_id or "").strip() or None
        chain_id = _notification_chain_id(finding=row)
        drilldowns = _notification_drilldowns(
            finding_id=row.finding_id,
            action_id=action_id,
            agent_id=str(row.agent_id or "").strip() or None,
            chain_id=chain_id,
            link=link,
        )
        primary = _notification_primary_drilldown(drilldowns)
        items.append(
            {
                "finding_id": row.finding_id,
                "finding_type": row.finding_type,
                "severity": row.severity,
                "status": row.status,
                "ai_tool": row.ai_tool,
                "risk_category": row.risk_category,
                "occurrence_count": int(row.occurrence_count or 1),
                "last_seen_at": row.last_seen_at.isoformat() if _to_datetime(row.last_seen_at) else None,
                "recommended_action": row.recommended_action,
                "source_surface": row.source_surface,
                "ai_system_id": row.ai_system_id,
                "drilldown": link,
                "drilldowns": drilldowns,
                "primary_drilldown": primary,
                "primary_drilldown_type": primary.get("type") if primary else None,
                "investigation_link": primary.get("href") if primary else link,
            }
        )

    return {
        "count": len(window_rows),
        "open_count": len(open_rows),
        "high_critical_open_count": len(high_critical_open),
        "items": items,
        "drilldown": "/discovery/findings",
    }


def _build_simulations(
    runs: list[SimulationRun],
    *,
    started_at: datetime,
) -> dict[str, Any]:
    window_runs = [
        row
        for row in runs
        if _within_window(_to_datetime(row.started_at), started_at=started_at)
    ]
    pass_count = 0
    fail_count = 0
    recent_items: list[dict[str, Any]] = []
    sorted_runs = sorted(window_runs, key=lambda row: _to_datetime(row.started_at) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    for row in sorted_runs:
        result = str((row.results or {}).get("result") or "").strip().lower()
        pass_rate = float((row.results or {}).get("pass_rate") or 0.0)
        if result == "pass":
            pass_count += 1
        elif result == "fail":
            fail_count += 1
        recent_items.append(
            {
                "run_id": row.id,
                "simulation_id": row.simulation_id,
                "ai_system_id": row.ai_system_id,
                "result": result or "unknown",
                "pass_rate": pass_rate,
                "mode": row.mode,
                "started_at": row.started_at.isoformat() if _to_datetime(row.started_at) else None,
                "finished_at": row.finished_at.isoformat() if _to_datetime(row.finished_at) else None,
            }
        )
    total = len(window_runs)
    fail_rate = (float(fail_count) / total * 100.0) if total else 0.0
    return {
        "total_runs": total,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "fail_rate_percent": round(fail_rate, 2),
        "recent_runs": recent_items[:20],
        "drilldown": "/simulations",
    }


def _build_remediation_actions(actions: list[RemediationAction]) -> dict[str, Any]:
    status_counts: dict[str, int] = {}
    for row in actions:
        status = str(row.status or "").strip().lower() or "unknown"
        status_counts[status] = int(status_counts.get(status, 0)) + 1
    sorted_rows = sorted(
        actions,
        key=lambda row: _to_datetime(row.created_at) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return {
        "status_counts": status_counts,
        "items": [
            {
                "id": row.id,
                "remediation_type": row.remediation_type,
                "target_type": row.target_type,
                "target_id": row.target_id,
                "source_trigger_type": row.source_trigger_type,
                "status": row.status,
                "risk_level": row.risk_level,
                "action_mode": row.action_mode,
                "requires_approval": bool(row.requires_approval),
                "created_at": row.created_at.isoformat() if _to_datetime(row.created_at) else None,
                "applied_at": row.applied_at.isoformat() if _to_datetime(row.applied_at) else None,
            }
            for row in sorted_rows[:25]
        ],
        "drilldown": "/auditor",
    }


def _build_sla_metrics(
    *,
    approvals: list[ApprovalRequest],
    findings: list[Finding],
    job_runs: list[ScheduledJobRun],
    auditor_snapshots: list[AuditorSnapshot],
) -> dict[str, Any]:
    now = _utcnow()
    pending = [row for row in approvals if str(row.status or "").strip().lower() == "pending"]
    overdue = []
    age_minutes = []
    for row in pending:
        created = _to_datetime(row.created_at)
        if created is None:
            continue
        age = max(0.0, (now - created).total_seconds() / 60.0)
        age_minutes.append(age)
        sla_limit = float(row.sla_minutes or 60)
        if age > sla_limit:
            overdue.append(row)

    high_open = [
        row
        for row in findings
        if _is_open_status(row.status) and (_normalize_severity(row.severity) or "low") in {"high", "critical"}
    ]
    high_overdue = [
        row
        for row in high_open
        if (_to_datetime(row.first_seen_at) and (now - _to_datetime(row.first_seen_at)).total_seconds() > 72 * 3600)
    ]
    recent_jobs = [
        row
        for row in job_runs
        if _within_window(_to_datetime(row.started_at), started_at=now - timedelta(hours=24))
    ]
    job_success_rate = (
        (sum(1 for row in recent_jobs if str(row.status or "").lower() == "success") / len(recent_jobs)) * 100.0
        if recent_jobs
        else 100.0
    )

    latest_snapshot = None
    if auditor_snapshots:
        latest_snapshot = max(
            (_to_datetime(row.created_at) for row in auditor_snapshots if _to_datetime(row.created_at)),
            default=None,
        )

    return {
        "approval_pending": len(pending),
        "approval_overdue": len(overdue),
        "mean_approval_age_minutes": round(sum(age_minutes) / len(age_minutes), 2) if age_minutes else 0.0,
        "high_open_findings": len(high_open),
        "high_overdue_findings": len(high_overdue),
        "job_success_rate_24h": round(job_success_rate, 2),
        "auditor_snapshot_count": len(auditor_snapshots),
        "latest_auditor_snapshot_at": latest_snapshot.isoformat() if latest_snapshot else None,
        "drilldown": "/ops/jobs",
    }


def _build_cve_summary(signals: list[MonitoringSignal]) -> dict[str, Any]:
    cve_rows = []
    for row in signals:
        signal_type = str(row.signal_type or "").strip().lower()
        if signal_type.startswith("cve.") or signal_type.startswith("vulnerability.") or "cve" in signal_type or "vuln" in signal_type:
            cve_rows.append(row)
    critical = sum(1 for row in cve_rows if _normalize_severity(row.severity) == "critical")
    high = sum(1 for row in cve_rows if _normalize_severity(row.severity) == "high")
    return {
        "open_count": len(cve_rows),
        "critical": critical,
        "high": high,
        "drilldown": "/monitoring",
    }


def _build_crq_summary(rows: list[RuntimeGovernanceRecommendation]) -> dict[str, Any]:
    scored_rows: list[dict[str, Any]] = []
    total_estimated_risk_reduction = 0.0
    total_decision_impact = 0.0
    total_base_risk = 0.0
    total_confidence = 0.0
    total_impact_value = 0.0
    total_probability = 0.0

    for row in rows:
        payload = _coerce_dict(row.payload)
        decision_impact = _coerce_dict(payload.get("decision_impact"))
        score = _impact_value(payload, "decision_impact_score")
        estimated_risk_reduction = _impact_value(payload, "estimated_risk_reduction")
        base_risk = _impact_value(payload, "base_risk")
        confidence = _impact_value(payload, "confidence")
        if confidence <= 0:
            confidence = _safe_float(payload.get("confidence_score"), 0.0)
        urgency_multiplier = _impact_value(payload, "urgency_multiplier")
        control_effectiveness = _impact_value(payload, "control_effectiveness")
        impact_value = _impact_value(payload, "impact_value")
        probability = _impact_value(payload, "probability_score")
        action = str(payload.get("action") or decision_impact.get("action") or row.recommendation_type).strip()

        if (
            score <= 0.0
            and estimated_risk_reduction <= 0.0
            and base_risk <= 0.0
            and impact_value <= 0.0
        ):
            continue

        row_payload = {
            "recommendation_id": row.recommendation_id,
            "recommendation_type": row.recommendation_type,
            "ai_system_id": row.ai_system_id,
            "action": action or "policy_adjustment",
            "decision_impact_score": round(score, 2),
            "estimated_risk_reduction": round(estimated_risk_reduction, 2),
            "base_risk": round(base_risk, 2),
            "confidence": round(confidence, 4),
            "urgency_multiplier": round(urgency_multiplier, 2),
            "control_effectiveness": round(control_effectiveness, 4),
            "impact_value": round(impact_value, 2),
            "probability_score": round(probability, 4),
            "reasoning": _coerce_list(decision_impact.get("reasoning")),
            "created_at": row.created_at.isoformat() if _to_datetime(row.created_at) else None,
        }
        scored_rows.append(row_payload)
        total_estimated_risk_reduction += float(estimated_risk_reduction)
        total_decision_impact += float(score)
        total_base_risk += float(base_risk)
        total_confidence += float(confidence)
        total_impact_value += float(impact_value)
        total_probability += float(probability)

    if not scored_rows:
        return {
            "recommendation_count": len(rows),
            "scored_recommendation_count": 0,
            "total_base_risk_usd": 0.0,
            "risk_exposure_usd": 0.0,
            "total_estimated_risk_reduction_usd": 0.0,
            "risk_reduced_usd": 0.0,
            "at_risk_if_ignored_usd": 0.0,
            "residual_risk_usd": 0.0,
            "average_decision_impact_score": 0.0,
            "average_base_risk_usd": 0.0,
            "average_confidence": 0.0,
            "average_impact_value_usd": 0.0,
            "average_probability_score": 0.0,
            "top_action": "none",
            "top_recommendation": None,
            "financial_impact_explanation": "No CRQ-scored runtime recommendations in the selected window.",
            "drilldown": "/runtime-intelligence/recommendations",
        }

    top_recommendation = max(scored_rows, key=lambda item: float(item.get("decision_impact_score") or 0.0))
    avg_count = float(len(scored_rows))
    top_action = str(top_recommendation.get("action") or "policy_adjustment")
    explanation = (
        f"Top action '{top_action}' has impact score {float(top_recommendation.get('decision_impact_score') or 0.0):,.2f}, "
        f"estimated reduction ${float(top_recommendation.get('estimated_risk_reduction') or 0.0):,.2f}, "
        f"and confidence {float(top_recommendation.get('confidence') or 0.0) * 100.0:.1f}%."
    )

    return {
        "recommendation_count": len(rows),
        "scored_recommendation_count": len(scored_rows),
        "total_base_risk_usd": round(total_base_risk, 2),
        "risk_exposure_usd": round(total_base_risk, 2),
        "total_estimated_risk_reduction_usd": round(total_estimated_risk_reduction, 2),
        "risk_reduced_usd": round(total_estimated_risk_reduction, 2),
        "at_risk_if_ignored_usd": round(total_base_risk, 2),
        "residual_risk_usd": round(max(total_base_risk - total_estimated_risk_reduction, 0.0), 2),
        "average_decision_impact_score": round(total_decision_impact / avg_count, 2),
        "average_base_risk_usd": round(total_base_risk / avg_count, 2),
        "average_confidence": round(total_confidence / avg_count, 4),
        "average_impact_value_usd": round(total_impact_value / avg_count, 2),
        "average_probability_score": round(total_probability / avg_count, 4),
        "top_action": top_action,
        "top_recommendation": top_recommendation,
        "financial_impact_explanation": explanation,
        "drilldown": "/runtime-intelligence/recommendations",
    }


def _build_ai_system_options(ai_systems: list[AISystem]) -> list[dict[str, Any]]:
    return [
        {
            "id": row.id,
            "name": row.name,
            "risk_tier": row.risk_tier,
            "status": row.status,
        }
        for row in sorted(ai_systems, key=lambda item: str(item.name or "").lower())
    ]


def _build_ai_exposure_scan(db: Session, *, tenant_id: str) -> dict[str, Any]:
    row = db.scalar(
        select(ScanResult)
        .where(ScanResult.tenant_id == tenant_id)
        .order_by(desc(ScanResult.start_time))
    )
    payload = serialize_scan_result(row)
    summary = dict(payload.get("summary") or {})
    delta = dict(payload.get("delta") or {})
    links = dict(payload.get("links") or {})
    return {
        "scan_id": payload.get("scan_id"),
        "status": payload.get("status") or "no_data",
        "scan_type": payload.get("scan_type") or "discovery",
        "scope": payload.get("scope") or "global",
        "scope_value": payload.get("scope_value"),
        "last_scan_time": payload.get("last_scan_time"),
        "started_at": payload.get("started_at"),
        "ended_at": payload.get("ended_at"),
        "summary": {
            "new_ai_apps_detected": int(summary.get("new_ai_apps_detected") or 0),
            "unknown_apps": int(summary.get("unknown_apps") or 0),
            "new_users_detected": int(summary.get("new_users_detected") or 0),
            "new_endpoints_detected": int(summary.get("new_endpoints_detected") or 0),
            "new_risks_identified": int(summary.get("new_risks_identified") or 0),
            "alerts_generated": int(summary.get("alerts_generated") or 0),
            "total_ai_apps": int(summary.get("total_ai_apps") or 0),
        },
        "delta": {
            "apps_added": list(delta.get("apps_added") or []),
            "users_added": list(delta.get("users_added") or []),
            "endpoints_added": list(delta.get("endpoints_added") or []),
            "risks_added": list(delta.get("risks_added") or []),
            "alerts_added": list(delta.get("alerts_added") or []),
        },
        "links": {
            "new_ai_apps": str(links.get("new_ai_apps") or "/shadow-ai?state=new"),
            "unknown_tools": str(links.get("unknown_tools") or "/shadow-ai?state=unknown"),
            "new_users": str(links.get("new_users") or "/ai-iam?filter=recently_discovered"),
            "new_endpoints": str(links.get("new_endpoints") or "/ai-iam?filter=recently_discovered"),
            "new_risks": str(links.get("new_risks") or "/discovery/findings?source=scan_delta"),
            "alerts": str(links.get("alerts") or "/dashboard/command-center?focus=alerts"),
            "full_report": str(links.get("full_report") or "/shadow-ai"),
        },
        "error": payload.get("error"),
    }


def _notification_time(value: Any) -> datetime:
    parsed = _to_datetime(value)
    if parsed is not None:
        return parsed
    if isinstance(value, str) and value.strip():
        raw = value.strip()
        try:
            if raw.endswith("Z"):
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
            parsed_raw = datetime.fromisoformat(raw)
            if parsed_raw.tzinfo is None:
                return parsed_raw.replace(tzinfo=timezone.utc)
            return parsed_raw.astimezone(timezone.utc)
        except ValueError:
            pass
    return datetime.min.replace(tzinfo=timezone.utc)


def _notification_actor_label(
    *,
    user_id: str | None,
    registry_lookup: dict[str, UserRegistry],
) -> str | None:
    if not user_id:
        return None
    row = registry_lookup.get(user_id)
    if row is None:
        return user_id
    if str(row.display_name or "").strip() and str(row.email or "").strip():
        return f"{row.display_name} ({row.email})"
    if str(row.display_name or "").strip():
        return str(row.display_name)
    if str(row.email or "").strip():
        return str(row.email)
    return user_id


def _notification_endpoint_label(endpoint: DeploymentEndpoint | None, endpoint_id: str | None) -> str | None:
    if endpoint is None:
        return endpoint_id
    hostname = str(endpoint.hostname or "").strip()
    browser = str(endpoint.browser_type or "").strip()
    os_type = str(endpoint.os_type or "").strip()
    if hostname and browser and os_type:
        return f"{hostname} · {browser}/{os_type}"
    if hostname and browser:
        return f"{hostname} · {browser}"
    if hostname:
        return hostname
    return endpoint.endpoint_id


def _truncate(value: str | None, *, max_len: int = 200) -> str:
    text = str(value or "").strip()
    if len(text) <= max_len:
        return text
    return f"{text[:max_len-1]}…"


def _normalize_source_surface(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"browser_extension", "browser"}:
        return "browser"
    if normalized in {"connector", "gateway", "monitoring", "agent", "endpoint", "dns", "proxy"}:
        return normalized
    return normalized or "monitoring"


def _is_local_like_domain(value: str | None) -> bool:
    domain = str(value or "").strip().lower()
    if not domain:
        return False
    if domain in {"localhost", "127.0.0.1", "::1"}:
        return True
    return domain.endswith((".localhost", ".local", ".internal", ".corp", ".lan"))


_HAWK_CONTROL_PLANE_PATH_PREFIXES = (
    "/ai-iam",
    "/auditor",
    "/dashboard",
    "/discovery",
    "/policies",
    "/runtime-intelligence",
)
_HAWK_CONTROL_PLANE_MARKERS = (
    "ai control plane",
    "ai iam",
    "control plane",
    "discovery findings",
    "governance review",
    "notification hub",
    "policy version",
    "runtime intelligence",
    "shadow ai",
)


def _is_hawk_control_plane_signal(payload: dict[str, Any], domain: str) -> bool:
    raw_url = str(payload.get("url") or "").strip()
    parsed = urlparse(raw_url) if raw_url else None
    host = str(parsed.hostname if parsed and parsed.hostname else domain or "").strip().lower()
    if not _is_local_like_domain(host):
        return False

    title = str(payload.get("page_title") or "").strip().lower()
    if "ai control plane" in title:
        return True

    try:
        port = str(parsed.port if parsed and parsed.port else "").strip()
    except ValueError:
        port = ""
    path = str(parsed.path if parsed else "").strip().lower() or "/"
    is_control_plane_path = any(path == prefix or path.startswith(f"{prefix}/") for prefix in _HAWK_CONTROL_PLANE_PATH_PREFIXES)
    if port not in {"", "3000"} or not is_control_plane_path:
        return False

    marker_text = "\n".join(
        str(payload.get(key) or "")
        for key in ("page_title", "summary", "description", "prompt_preview_redacted")
    ).lower()
    marker_count = sum(1 for marker in _HAWK_CONTROL_PLANE_MARKERS if marker in marker_text)
    return marker_count >= 2


_PILOT_NOISE_EVENT_TYPES = {
    "api_health",
    "api_readiness",
    "browser_heartbeat",
    "component_health",
    "component_heartbeat",
    "endpoint_heartbeat",
    "extension_health_status",
    "extension_heartbeat",
    "extension_status",
    "gateway_health",
    "health_check",
    "heartbeat",
    "internal_check",
    "keepalive",
    "liveness_check",
    "policy_sync_status",
    "policy_sync_health",
    "readiness_check",
    "scheduler_heartbeat",
    "service_health",
    "telemetry_health",
    "worker_heartbeat",
}
_PILOT_NOISE_SIGNAL_TYPES = {
    "api.health",
    "browser.extension_heartbeat",
    "browser.extension_health_status",
    "browser.policy_sync_status",
    "browser.telemetry_health",
    "endpoint.heartbeat",
    "endpoint.health",
    "gateway.health",
    "monitoring.heartbeat",
    "service.health",
}
_INTERNAL_NOISE_FINDING_TYPES = {
    "api_health",
    "browser_heartbeat",
    "component_health",
    "endpoint_heartbeat",
    "extension_health_status",
    "extension_heartbeat",
    "gateway_health",
    "health_check",
    "heartbeat",
    "internal_check",
    "liveness_check",
    "policy_sync_health",
    "policy_sync_status",
    "readiness_check",
    "scheduler_heartbeat",
    "service_health",
    "telemetry_health",
    "worker_heartbeat",
}
_INTERNAL_NOISE_TEXT_MARKERS = (
    "beat check",
    "heartbeat",
    "health check",
    "internal check",
    "keepalive",
    "liveness check",
    "policy sync",
    "readiness check",
    "scheduler heartbeat",
    "service health",
    "telemetry health",
    "worker heartbeat",
)
_CUSTOMER_ALERT_TEXT_MARKERS = (
    "approval",
    "block",
    "confidential",
    "credential",
    "deny",
    "emirates id",
    "external",
    "github",
    "mcp",
    "personal account",
    "prompt",
    "repository",
    "secret",
    "sensitive",
    "upload",
    "warn",
)
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
_PLACEHOLDER_AI_LABELS = {
    "",
    "unknown",
    "unknown_ai",
    "unknown_ai_app",
    "unknown_ai_entity",
    "unknown_ai_system",
    "unknown_tool",
    "extension.local",
    "hawk_extension",
    "browser_extension",
    "localhost",
    "127.0.0.1",
}


def _is_placeholder_ai_label(value: Any) -> bool:
    token = str(value or "").strip().lower()
    return token in _PLACEHOLDER_AI_LABELS or token.startswith("unknown_")


def _contains_internal_noise_marker(*values: Any) -> bool:
    text = " ".join(str(value or "").strip().lower().replace("_", " ") for value in values if value is not None)
    return bool(text) and any(marker in text for marker in _INTERNAL_NOISE_TEXT_MARKERS)


def _contains_customer_alert_marker(*values: Any) -> bool:
    text = " ".join(str(value or "").strip().lower().replace("_", " ") for value in values if value is not None)
    return bool(text) and any(marker in text for marker in _CUSTOMER_ALERT_TEXT_MARKERS)


def _is_passive_browser_context_lifecycle(
    metadata: dict[str, Any], *, source_surface: str | None,
) -> bool:
    if str(source_surface or "").strip().lower() not in {"browser", "browser_extension"}:
        return False
    event_type = str(metadata.get("event_type") or "").strip().lower().replace("-", "_")
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


def _is_passive_browser_history(metadata: dict[str, Any], *, source_surface: str | None, for_finding: bool = False) -> bool:
    if str(source_surface or "").strip().lower() not in {"browser", "browser_extension"}:
        return False
    event_type = str(metadata.get("event_type") or "").strip().lower()
    if _is_passive_browser_context_lifecycle(metadata, source_surface=source_surface):
        return True
    if event_type in {"prompt_drafted", "extension_installed", "extension_connected", "policy_sync_success", "context_recovered"}:
        return True
    if event_type in {"ai_domain_visit", "ai_app_opened"}:
        return True
    if event_type == "agent_runtime_discovered":
        return not for_finding
    if event_type == "extension_health_status":
        status = str(metadata.get("status") or metadata.get("action_taken") or "").strip().lower()
        return metadata.get("healthy") is True or status in {"healthy", "ok", "connected"}
    return False


def _is_passive_browser_action(
    action: AIAction | None, signal: MonitoringSignal | None = None, *, for_finding: bool = False,
) -> bool:
    if action is None:
        return False
    metadata = dict(action.metadata_json or {}) if isinstance(action.metadata_json, dict) else {}
    if metadata.get("healthy") is False:
        return False
    signal_payload = signal.payload if signal is not None and isinstance(signal.payload, dict) else {}
    ai_action = metadata.get("ai_action") if isinstance(metadata.get("ai_action"), dict) else {}
    source_surface = str(
        metadata.get("source_surface") or ai_action.get("source_surface")
        or signal_payload.get("source_surface") or ""
    ).strip().lower()
    if _is_passive_browser_history(metadata, source_surface=source_surface, for_finding=for_finding):
        return True
    return _is_passive_browser_history(signal_payload, source_surface=source_surface, for_finding=for_finding)


def _is_proven_false_browser_pattern(
    db: Session, row: Finding, runtime_lookup: dict[str, RuntimeEvent],
) -> bool:
    related_ids = [str(item) for item in (row.related_event_ids or []) if str(item).strip()]
    if len(related_ids) < 2:
        return False
    events = [runtime_lookup.get(event_id) for event_id in related_ids]
    if any(event is None or str(event.source_surface or "").lower() != "browser" for event in events):
        return False
    finding_type = str(row.finding_type or "").strip().lower()
    if finding_type in {"unusual_tool_sequences", "unusual_tool_sequence"}:
        from app.services.runtime_intelligence.runtime_correlation_service import _tool_fingerprint

        return all(not _tool_fingerprint(event) for event in events)
    if finding_type == "repeated_prompt_injection_attempts":
        from app.services.runtime_intelligence.runtime_correlation_service import _is_prompt_block_like, _repeat_threshold, _scope_match

        anchor = max(events, key=lambda event: event.created_at)
        window_minutes = max(5, int(settings.runtime_intelligence_correlation_window_minutes))
        scoped_window = db.scalars(
            select(RuntimeEvent).where(
                RuntimeEvent.tenant_id == row.tenant_id,
                RuntimeEvent.created_at >= anchor.created_at - timedelta(minutes=window_minutes),
                RuntimeEvent.created_at <= anchor.created_at,
            )
        ).all()
        distinct_actions = {
            str(candidate.correlation_id or candidate.event_id)
            for candidate in scoped_window
            if _is_prompt_block_like(candidate) and _scope_match(candidate, anchor)
        }
        return len(distinct_actions) < _repeat_threshold()
    if finding_type == "unknown_ai_adoption_spike":
        profiles = []
        for event in events:
            metadata = dict(event.metadata_json or {}) if isinstance(event.metadata_json, dict) else {}
            if str(metadata.get("event_type") or event.event_type or "").strip().lower() != "agent_runtime_discovered":
                return False
            agent = str(event.agent_id or metadata.get("agent_id") or metadata.get("agent_name") or "").strip().lower()
            if not agent:
                return False
            profiles.append((
                agent,
                str(event.app_id or metadata.get("domain") or "").strip().lower(),
                str(metadata.get("model_name") or "").strip().lower(),
                str(metadata.get("runtime_provider") or "").strip().lower(),
                tuple(sorted(str(value).strip().lower() for value in (metadata.get("detected_tools") or []) if str(value).strip())),
                tuple(sorted(str(value).strip().lower() for value in (metadata.get("detected_actions") or []) if str(value).strip())),
                tuple(sorted(str(value).strip().lower() for value in (metadata.get("detected_privileges") or []) if str(value).strip())),
            ))
        return len(set(profiles)) == 1
    return False


def _is_pilot_noise_finding(row: Finding) -> bool:
    finding_type = str(row.finding_type or "").strip().lower()
    risk_category = str(row.risk_category or "").strip().lower()
    ai_tool = str(row.ai_tool or "").strip().lower()
    source_surface = str(row.source_surface or "").strip().lower()
    decision = str(row.decision or "").strip().lower()
    recommended_action = str(row.recommended_action or "").strip().lower()

    if finding_type in _PILOT_NOISE_EVENT_TYPES or finding_type in _INTERNAL_NOISE_FINDING_TYPES:
        return True
    if (
        source_surface in {"internal", "monitoring", "scheduler", "worker"}
        and _contains_internal_noise_marker(finding_type, risk_category, recommended_action)
        and not _contains_customer_alert_marker(finding_type, risk_category, recommended_action)
    ):
        return True
    if source_surface == "monitoring" and finding_type == "unregistered_ai_system" and _is_placeholder_ai_label(ai_tool):
        return True
    if finding_type == "unregistered_ai_system" and "runtime trigger referenced unknown ai system" in recommended_action:
        return True
    if finding_type in {"unusual_tool_sequences", "unusual_tool_sequence"}:
        if _is_placeholder_ai_label(ai_tool):
            return True
        if "action_alignment:unknown" in risk_category and decision in {"", "allow", "allowed"}:
            return True
    if finding_type in {"shadow_ai_discovered", "unknown_ai_detected"} and _is_placeholder_ai_label(ai_tool):
        return True
    return False


def _is_pilot_noise_monitoring_signal(
    *,
    payload: dict[str, Any],
    event_type: str,
    signal_type: str,
    domain: str,
    discovery_hint: str | None,
) -> bool:
    if event_type in _PILOT_NOISE_EVENT_TYPES or signal_type in _PILOT_NOISE_SIGNAL_TYPES:
        return True
    if (
        _contains_internal_noise_marker(
            event_type,
            signal_type,
            payload.get("status"),
            payload.get("message"),
            payload.get("summary"),
            payload.get("reason"),
        )
        and not _contains_customer_alert_marker(
            event_type,
            signal_type,
            payload.get("status"),
            payload.get("message"),
            payload.get("summary"),
            payload.get("reason"),
        )
    ):
        return True
    if domain in {"extension.local", "hawk_extension", "browser_extension"}:
        return True
    if _is_hawk_control_plane_signal(payload, domain):
        return True
    if event_type == "unknown_ai_detected" and _is_local_like_domain(domain) and not discovery_hint:
        return True
    return False


def _extract_discovery_hint(signal_types: list[str]) -> str | None:
    for item in signal_types:
        if item.startswith("discovery_hint:"):
            return item.split(":", 1)[1] or None
    return None


def _split_reason_codes(value: str | None) -> list[str]:
    raw = str(value or "").strip().lower()
    if not raw:
        return []
    tokens: list[str] = []
    for part in re.split(r"[,\|]", raw):
        normalized = re.sub(r"[^a-z0-9._:-]+", "_", part.strip()).strip("_")
        if normalized:
            tokens.append(normalized)
    unique: list[str] = []
    for token in tokens:
        if token not in unique:
            unique.append(token)
    return unique


def _reason_label(
    reason_codes: list[str],
    *,
    action_type: str | None,
) -> str:
    joined = " ".join(reason_codes)

    def _contains(*needles: str) -> bool:
        return any(any(needle in code for needle in needles) for code in reason_codes) or any(
            needle in joined for needle in needles
        )

    if _contains("prompt_injection", "jailbreak", "prompt_risk_forced_block"):
        return "prompt injection"
    if _contains("sensitive_file_upload", "file_upload", "upload", "ocr_sensitive_upload"):
        return "sensitive file upload"
    if _contains("copy_paste", "clipboard", "paste", "external_transfer"):
        return "sensitive copy/paste"
    if _contains("sensitive_data_pattern", "sensitive_data_detected", "pii", "credit_card", "emirates_id"):
        if str(action_type or "").strip().lower() in {"upload", "file_upload"}:
            return "sensitive file upload"
        if str(action_type or "").strip().lower() == "copy_paste":
            return "sensitive copy/paste"
        return "sensitive prompt"
    if _contains("unregistered_ai_system", "unknown_ai"):
        return "unregistered AI system usage"
    if _contains("tool_not_allowed", "unauthorized_tool", "denied_tool_action"):
        return "unauthorized tool usage"
    if _contains("domain_is_blocked", "blocked_domain", "domain_blocked"):
        return "blocked domain access"
    if reason_codes:
        return reason_codes[0].replace("_", " ").replace(".", " ").replace(":", " ").strip()
    if str(action_type or "").strip().lower() == "copy_paste":
        return "policy violation on copy/paste"
    if str(action_type or "").strip().lower() in {"upload", "file_upload"}:
        return "policy violation on file upload"
    return "policy violation"


def _notification_control_mode_for_action(action: AIAction | None) -> str | None:
    if action is None or not isinstance(action.metadata_json, dict):
        return None
    metadata = _coerce_dict(action.metadata_json)
    ai_action = _coerce_dict(metadata.get("ai_action"))
    ai_policy = _coerce_dict(ai_action.get("policy"))
    return str(ai_policy.get("control_mode") or metadata.get("control_mode") or "").strip() or None


def _notification_decision_badge_for_action(action: AIAction | None) -> str | None:
    if action is None or not isinstance(action.metadata_json, dict):
        return None
    metadata = _coerce_dict(action.metadata_json)
    ai_action = _coerce_dict(metadata.get("ai_action"))
    ai_policy = _coerce_dict(ai_action.get("policy"))
    return str(ai_policy.get("decision_badge") or metadata.get("decision_badge") or "").strip() or None


def _notification_nested_string(source: Any, keys: tuple[str, ...]) -> str | None:
    if source is None:
        return None
    current: Any = source
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    value = str(current or "").strip()
    return value or None


def _notification_chain_id(
    *,
    action: AIAction | None = None,
    finding: Finding | None = None,
    payload: dict[str, Any] | None = None,
    correlation_id: str | None = None,
) -> str | None:
    candidates: list[str | None] = []
    if payload:
        candidates.extend(
            [
                str(payload.get("chain_id") or "").strip() or None,
                _notification_nested_string(payload, ("ai_action", "chain", "chain_id")),
                _notification_nested_string(payload, ("chain", "chain_id")),
            ]
        )
    if action is not None and isinstance(action.metadata_json, dict):
        metadata = _coerce_dict(action.metadata_json)
        candidates.extend(
            [
                _notification_nested_string(metadata, ("ai_action", "chain", "chain_id")),
                _notification_nested_string(metadata, ("chain", "chain_id")),
                str(metadata.get("chain_id") or "").strip() or None,
            ]
        )
    if finding is not None:
        candidates.extend(
            [
                str(getattr(finding, "related_runtime_event_id", "") or "").strip() or None,
                str(getattr(finding, "ai_action_id", "") or "").strip() or None,
            ]
        )
        for trace_id in getattr(finding, "related_trace_ids", None) or []:
            candidates.append(str(trace_id or "").strip() or None)
        for event_id in getattr(finding, "related_event_ids", None) or []:
            candidates.append(str(event_id or "").strip() or None)
    candidates.append(str(correlation_id or "").strip() or None)

    for candidate in candidates:
        if not candidate:
            continue
        if candidate.startswith(("chain_", "chn_")):
            return candidate
        if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", candidate, re.I):
            return candidate
    return None


def _notification_drilldowns(
    *,
    finding_id: str | None = None,
    action_id: str | None = None,
    agent_id: str | None = None,
    chain_id: str | None = None,
    link: str | None = None,
) -> list[dict[str, Any]]:
    drilldowns: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, label: str, href: str | None, enabled: bool = True) -> None:
        if not href:
            return
        key = (kind, href)
        if key in seen:
            return
        seen.add(key)
        drilldowns.append({"type": kind, "label": label, "href": href, "enabled": enabled})

    if action_id:
        quoted = action_id.replace("/", "%2F")
        add("action_graph", "Action Graph", f"/runtime-intelligence/action-graph/{quoted}")
        add("action_trace", "Action Trace", f"/runtime-intelligence/action-trace/{quoted}")
    if chain_id:
        quoted = chain_id.replace("/", "%2F")
        add("chain_graph", "Chain Graph", f"/runtime-intelligence/chains/{quoted}/graph")
        add("chain_evidence", "Chain Evidence", f"/runtime-intelligence/chains/{quoted}/evidence")
    if agent_id:
        add("agent_touchpoints", "Agent Touchpoints", f"/ai-iam/agents/{agent_id}")
    if finding_id:
        quoted = finding_id.replace("/", "%2F")
        add("finding_detail", "Finding Detail", f"/discovery/findings/{quoted}")
        add("traceability", "Traceability", f"/discovery/findings/{quoted}#traceability")
        add("evidence", "Evidence", f"/discovery/findings/{quoted}#evidence")
    if link:
        add("default", "Open Alert", link)
    return drilldowns


NOTIFICATION_PRIMARY_DRILLDOWN_PRIORITY = (
    "chain_graph",
    "action_graph",
    "chain_evidence",
    "evidence",
    "traceability",
    "finding_detail",
    "agent_touchpoints",
    "action_trace",
    "default",
)


def _notification_primary_drilldown(drilldowns: list[dict[str, Any]]) -> dict[str, Any] | None:
    enabled = [
        item
        for item in drilldowns
        if item.get("enabled", True) is not False and str(item.get("href") or "").strip()
    ]
    if not enabled:
        return None

    def rank(item: dict[str, Any]) -> int:
        drilldown_type = str(item.get("type") or "").strip()
        try:
            return NOTIFICATION_PRIMARY_DRILLDOWN_PRIORITY.index(drilldown_type)
        except ValueError:
            return len(NOTIFICATION_PRIMARY_DRILLDOWN_PRIORITY)

    return sorted(enabled, key=rank)[0]


def _attach_notification_investigation_link(item: dict[str, Any]) -> dict[str, Any]:
    drilldowns = item.get("drilldowns")
    if not isinstance(drilldowns, list):
        drilldowns = []
        item["drilldowns"] = drilldowns
    primary = _notification_primary_drilldown(drilldowns)
    if primary:
        item["primary_drilldown"] = primary
        item["primary_drilldown_type"] = primary.get("type")
        item["investigation_link"] = primary.get("href")
    else:
        item["primary_drilldown"] = None
        item["primary_drilldown_type"] = None
        item["investigation_link"] = item.get("link") or "/discovery/findings"
    return item


def _notification_dedupe_key(item: dict[str, Any]) -> str:
    notification_type = str(item.get("notification_type") or "").strip().lower()
    finding_id = str(item.get("finding_id") or "").strip()
    action_id = str(item.get("action_id") or "").strip()
    correlation_id = str(item.get("correlation_id") or "").strip()
    request_id = str(item.get("request_id") or "").strip()
    source_surface = str(item.get("source_surface") or "").strip().lower()
    title = str(item.get("title") or "").strip().lower()
    actor_user_id = str(item.get("actor_user_id") or "").strip().lower()
    endpoint_id = str(item.get("endpoint_id") or "").strip().lower()
    link = str(item.get("link") or "").strip().lower()

    if notification_type in {"activity_alert", "enforcement_event"} and correlation_id:
        return f"corr:{correlation_id}"
    if finding_id:
        return f"finding:{finding_id}"
    if action_id:
        return f"action:{action_id}"
    if notification_type == "enforcement_event" and request_id:
        return f"request:{request_id}"
    if notification_type.startswith("scan:") or notification_type in {"scan_delta", "scan_status"}:
        return str(item.get("notification_id") or f"{notification_type}:{request_id}:{correlation_id}")
    if notification_type == "discovery_signal":
        return f"discovery:{source_surface}:{title}:{actor_user_id}:{endpoint_id}:{link}"
    created_minute = _notification_time(item.get("created_at")).strftime("%Y%m%d%H%M")
    return f"{notification_type}:{source_surface}:{title}:{created_minute}"


def _notification_rank(item: dict[str, Any]) -> tuple[int, int, int, int, datetime]:
    return (
        NOTIFICATION_TYPE_PRIORITY.get(str(item.get("notification_type") or "").strip().lower(), 0),
        _severity_weight(str(item.get("severity") or "")),
        1 if str(item.get("finding_id") or "").strip() else 0,
        1 if str(item.get("action_id") or "").strip() else 0,
        _notification_time(item.get("created_at")),
    )


def _merge_notification(preferred: dict[str, Any], alternate: dict[str, Any]) -> dict[str, Any]:
    merged = dict(preferred)
    preferred_count = int(preferred.get("repeat_count") or 1)
    alternate_count = int(alternate.get("repeat_count") or 1)
    merged["repeat_count"] = preferred_count + alternate_count
    for key, value in alternate.items():
        if key not in merged:
            merged[key] = value
            continue
        if merged.get(key) in (None, "", [], {}):
            merged[key] = value

    preferred_summary = str(preferred.get("summary") or "").strip()
    alternate_summary = str(alternate.get("summary") or "").strip()
    if len(alternate_summary) > len(preferred_summary):
        merged["summary"] = alternate_summary
    if not str(merged.get("link") or "").strip():
        merged["link"] = alternate.get("link")
    existing_drilldowns = merged.get("drilldowns") if isinstance(merged.get("drilldowns"), list) else []
    alternate_drilldowns = alternate.get("drilldowns") if isinstance(alternate.get("drilldowns"), list) else []
    if alternate_drilldowns:
        seen = {
            (str(item.get("type") or ""), str(item.get("href") or ""))
            for item in existing_drilldowns
            if isinstance(item, dict)
        }
        merged_drilldowns = list(existing_drilldowns)
        for drilldown in alternate_drilldowns:
            if not isinstance(drilldown, dict):
                continue
            key = (str(drilldown.get("type") or ""), str(drilldown.get("href") or ""))
            if key in seen:
                continue
            seen.add(key)
            merged_drilldowns.append(drilldown)
        merged["drilldowns"] = merged_drilldowns
    return merged


def _dedupe_notifications(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for item in items:
        key = _notification_dedupe_key(item)
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = item
            continue
        if _notification_rank(item) > _notification_rank(existing):
            deduped[key] = _merge_notification(item, existing)
        else:
            deduped[key] = _merge_notification(existing, item)
    return list(deduped.values())


def get_dashboard_notifications_state(
    db: Session,
    *,
    tenant_id: str,
    limit: int = 25,
    lookback_hours: int = 24,
) -> dict[str, Any]:
    normalized_limit = max(1, min(100, int(limit or 25)))
    normalized_lookback_hours = max(1, min(24 * 30, int(lookback_hours or 24)))
    notifications_cache_key = f"{tenant_id}|{normalized_limit}|{normalized_lookback_hours}"
    cached = _notifications_cache_lookup(notifications_cache_key)
    if cached is not None:
        return cached
    started_at = _utcnow() - timedelta(hours=normalized_lookback_hours)
    lookback = normalized_limit * 4
    alert_rows = db.scalars(
        select(AIActionAlert)
        .where(
            AIActionAlert.tenant_id == tenant_id,
            AIActionAlert.created_at >= started_at,
        )
        .order_by(desc(AIActionAlert.created_at))
    ).all()
    action_ids = [row.action_id for row in alert_rows if str(row.action_id or "").strip()]
    action_lookup: dict[str, AIAction] = {}
    if action_ids:
        action_lookup = {
            row.action_id: row
            for row in db.scalars(
                select(AIAction).where(
                    AIAction.tenant_id == tenant_id,
                    AIAction.action_id.in_(action_ids),
                )
            ).all()
        }
    signal_ids = [
        action.monitoring_signal_id for action in action_lookup.values()
        if str(action.monitoring_signal_id or "").strip()
    ]
    linked_signal_lookup: dict[str, MonitoringSignal] = {}
    if signal_ids:
        linked_signal_lookup = {
            row.id: row for row in db.scalars(
                select(MonitoringSignal).where(
                    MonitoringSignal.tenant_id == tenant_id,
                    MonitoringSignal.id.in_(signal_ids),
                )
            ).all()
        }
    alert_rows = [
        row for row in alert_rows
        if not _is_passive_browser_action(
            action_lookup.get(row.action_id),
            linked_signal_lookup.get(str(getattr(action_lookup.get(row.action_id), "monitoring_signal_id", "") or "")),
        )
    ][:lookback]
    action_ids = [row.action_id for row in alert_rows if str(row.action_id or "").strip()]
    prompt_lookup: dict[str, PromptPayload] = {}
    if action_ids:
        prompt_lookup = {
            row.action_id: row
            for row in db.scalars(
                select(PromptPayload).where(PromptPayload.action_id.in_(action_ids))
            ).all()
        }

    monitoring_rows = db.scalars(
        select(MonitoringSignal)
        .where(
            MonitoringSignal.tenant_id == tenant_id,
            MonitoringSignal.created_at >= started_at,
        )
        .order_by(desc(MonitoringSignal.created_at))
    ).all()

    user_ids = {
        str(row.user_id)
        for row in alert_rows
        if str(row.user_id or "").strip()
    }
    user_ids.update(
        str(row.user_id)
        for row in action_lookup.values()
        if str(row.user_id or "").strip()
    )
    for row in monitoring_rows:
        payload = row.payload if isinstance(row.payload, dict) else {}
        user_id = str(payload.get("user_id") or "").strip()
        if user_id:
            user_ids.add(user_id)
    user_lookup: dict[str, UserRegistry] = {}
    if user_ids:
        user_lookup = {
            row.user_id: row
            for row in db.scalars(
                select(UserRegistry).where(
                    UserRegistry.tenant_id == tenant_id,
                    UserRegistry.user_id.in_(sorted(user_ids)),
                )
            ).all()
        }

    endpoint_ids = {
        str(row.endpoint_id)
        for row in alert_rows
        if str(row.endpoint_id or "").strip()
    }
    endpoint_ids.update(
        str(row.endpoint_id)
        for row in action_lookup.values()
        if str(row.endpoint_id or "").strip()
    )
    for row in monitoring_rows:
        payload = row.payload if isinstance(row.payload, dict) else {}
        endpoint_id = str(payload.get("endpoint_id") or "").strip()
        if endpoint_id:
            endpoint_ids.add(endpoint_id)
    endpoint_lookup: dict[str, DeploymentEndpoint] = {}
    if endpoint_ids:
        endpoint_lookup = {
            row.endpoint_id: row
            for row in db.scalars(
                select(DeploymentEndpoint).where(
                    DeploymentEndpoint.tenant_id == tenant_id,
                    DeploymentEndpoint.endpoint_id.in_(sorted(endpoint_ids)),
                )
            ).all()
        }

    def _load_notification_findings() -> list[Finding]:
        return db.scalars(
            select(Finding)
            .where(
                Finding.tenant_id == tenant_id,
                Finding.status.in_(["open", "reviewing", "pending", "proposed"]),
                or_(
                    and_(Finding.last_seen_at.is_not(None), Finding.last_seen_at >= started_at),
                    and_(Finding.last_seen_at.is_(None), Finding.created_at >= started_at),
                ),
            )
            .order_by(desc(Finding.last_seen_at))
        ).all()

    try:
        finding_rows = _load_notification_findings()
    except OperationalError as exc:
        if _is_sqlite_missing_column_error(exc, "findings.agent_id"):
            db.rollback()
            if _repair_findings_runtime_columns(db):
                finding_rows = _load_notification_findings()
            else:
                raise
        else:
            raise

    related_runtime_ids = [
        event_id
        for row in finding_rows
        for event_id in [row.related_runtime_event_id, *(row.related_event_ids or [])]
        if str(event_id or "").strip()
    ]
    related_runtime_lookup: dict[str, RuntimeEvent] = {}
    if related_runtime_ids:
        related_runtime_lookup = {
            row.event_id: row for row in db.scalars(
                select(RuntimeEvent).where(
                    RuntimeEvent.tenant_id == tenant_id,
                    RuntimeEvent.event_id.in_(related_runtime_ids),
                )
            ).all()
        }
    finding_ids = [row.finding_id for row in finding_rows]
    finding_action_lookup: dict[str, AIAction] = {}
    if finding_ids:
        for action in db.scalars(
            select(AIAction).where(
                AIAction.tenant_id == tenant_id,
                AIAction.finding_id.in_(finding_ids),
            )
        ).all():
            finding_action_lookup.setdefault(str(action.finding_id), action)
    finding_rows = [
        row for row in finding_rows
        if not (
            (
                (linked_runtime := related_runtime_lookup.get(str(row.related_runtime_event_id or ""))) is not None
                and _is_passive_browser_history(
                    dict(linked_runtime.metadata_json or {}),
                    source_surface=linked_runtime.source_surface,
                    for_finding=True,
                )
            )
            or _is_passive_browser_action(finding_action_lookup.get(row.finding_id), for_finding=True)
            or _is_proven_false_browser_pattern(db, row, related_runtime_lookup)
        )
    ]

    enforcement_rows = db.scalars(
        select(EnforcementEvent)
        .where(
            EnforcementEvent.tenant_id == tenant_id,
            EnforcementEvent.timestamp >= started_at,
            EnforcementEvent.final_decision.in_(["block", "warn", "require_approval", "hold_for_approval", "require_justification", "deny"]),
        )
        .order_by(desc(EnforcementEvent.timestamp))
        .limit(lookback)
    ).all()

    notifications: list[dict[str, Any]] = []
    linked_findings: set[str] = set()

    for row in alert_rows:
        action = action_lookup.get(row.action_id)
        severity = _normalize_severity(row.severity) or "med"
        app_label = str((action.ai_app if action else "") or "AI surface").strip() or "AI surface"
        enforcement_action = str(row.enforcement_action or (action.enforcement_action if action else "") or "warned").strip().lower()
        action_type = str((action.action_type if action else "") or "").strip().lower()
        reason_codes = _split_reason_codes(str(row.policy_reason or row.alert_type or "policy_violation"))
        reason_label = _reason_label(reason_codes, action_type=action_type)
        title = f"{enforcement_action.replace('_', ' ').title()} {reason_label} on {app_label}"
        summary_seed = str(row.policy_reason or row.alert_type or "Policy-triggered action").strip()
        prompt_hint = ""
        prompt_payload = prompt_lookup.get(row.action_id)
        if prompt_payload is not None:
            storage_mode = str(prompt_payload.storage_mode or "").strip().lower()
            if storage_mode == "hashed_only":
                prompt_hint = "Prompt stored as hash only"
            else:
                prompt_candidate = str(
                    (prompt_payload.raw_prompt if storage_mode == "full" else prompt_payload.redacted_prompt)
                    or prompt_payload.redacted_prompt
                    or ""
                ).strip()
                if prompt_candidate:
                    prompt_hint = f"Prompt: {prompt_candidate}"
        summary = _truncate(
            " · ".join(
                part
                for part in [
                    f"Alert: {reason_label}",
                    summary_seed if summary_seed.lower() != reason_label.lower() else "",
                    prompt_hint,
                ]
                if part
            ),
            max_len=180,
        )
        source_surface = None
        if action is not None and isinstance(action.metadata_json, dict):
            source_surface = str(action.metadata_json.get("source_surface") or "").strip().lower() or None
        if not source_surface:
            source_surface = "browser"
        control_mode = _notification_control_mode_for_action(action)
        decision_badge = _notification_decision_badge_for_action(action)
        if row.finding_id:
            linked_findings.add(row.finding_id)
        action_metadata = _coerce_dict(action.metadata_json) if action is not None and isinstance(action.metadata_json, dict) else {}
        alert_agent_id = str(action_metadata.get("agent_id") or "").strip() or _notification_nested_string(action_metadata, ("ai_action", "actor", "agent_id"))
        alert_chain_id = _notification_chain_id(action=action, correlation_id=action.correlation_id if action else None)
        notification_link = (
            f"/discovery/findings?focus={row.finding_id}"
            if row.finding_id
            else (
                f"/interaction-security?correlation_id={action.correlation_id}"
                if action is not None and str(action.correlation_id or "").strip()
                else "/ai-iam"
            )
        )
        notifications.append(
            {
                "notification_id": f"activity:{row.id}",
                "notification_type": "activity_alert",
                "severity": severity,
                "title": title,
                "summary": summary,
                "created_at": _notification_time(row.created_at).isoformat(),
                "source_surface": source_surface,
                "actor_user_id": row.user_id,
                "actor_label": _notification_actor_label(user_id=row.user_id, registry_lookup=user_lookup),
                "endpoint_id": row.endpoint_id,
                "endpoint_label": _notification_endpoint_label(endpoint_lookup.get(str(row.endpoint_id or "")), row.endpoint_id),
                "finding_id": row.finding_id,
                "action_id": row.action_id,
                "correlation_id": action.correlation_id if action else None,
                "request_id": None,
                "control_mode": control_mode,
                "decision_badge": decision_badge,
                "drilldowns": _notification_drilldowns(
                    finding_id=row.finding_id,
                    action_id=row.action_id,
                    agent_id=alert_agent_id,
                    chain_id=alert_chain_id,
                    link=notification_link,
                ),
                "link": notification_link,
            }
        )

    for row in finding_rows:
        if row.finding_id in linked_findings:
            continue
        if _is_pilot_noise_finding(row):
            continue
        severity = _normalize_severity(row.severity) or "med"
        title = f"Finding: {str(row.finding_type or 'policy_violation').replace('_', ' ')}"
        summary = str(row.recommended_action or f"{row.ai_tool} requires review").strip()
        tool_hint = str(row.ai_tool or "").strip()
        if tool_hint and tool_hint.lower() not in summary.lower():
            summary = f"{summary} · Tool: {tool_hint}"
        summary = _truncate(summary, max_len=180)
        finding_link = f"/discovery/findings?focus={row.finding_id}"
        finding_chain_id = _notification_chain_id(finding=row)
        notifications.append(
            {
                "notification_id": f"finding:{row.finding_id}",
                "notification_type": "finding",
                "severity": severity,
                "title": title,
                "summary": summary,
                "created_at": _notification_time(row.last_seen_at).isoformat(),
                "source_surface": str(row.source_surface or "").strip().lower() or None,
                "actor_user_id": row.user_id,
                "actor_label": _notification_actor_label(user_id=row.user_id, registry_lookup=user_lookup),
                "endpoint_id": None,
                "endpoint_label": None,
                "finding_id": row.finding_id,
                "action_id": None,
                "correlation_id": None,
                "request_id": None,
                "control_mode": getattr(row, "control_mode", None),
                "decision_badge": getattr(row, "decision_badge", None),
                "drilldowns": _notification_drilldowns(
                    finding_id=row.finding_id,
                    action_id=getattr(row, "ai_action_id", None),
                    agent_id=getattr(row, "agent_id", None),
                    chain_id=finding_chain_id,
                    link=finding_link,
                ),
                "link": finding_link,
            }
        )

    for row in enforcement_rows:
        decision = str(row.final_decision or "").strip().lower()
        if not decision:
            continue
        if decision not in {"block", "warn", "require_approval", "hold_for_approval", "require_justification", "deny"}:
            continue
        severity = "critical" if decision in {"block", "deny"} else ("high" if "approval" in decision or "hold" in decision else "med")
        title = f"Gateway {decision.replace('_', ' ').upper()} decision"
        summary = _truncate(
            " · ".join(
                [
                    f"Actor {row.actor_type}:{row.actor_id}",
                    f"Request {row.request_id}",
                ]
            ),
            max_len=180,
        )
        notifications.append(
            {
                "notification_id": f"enforcement:{row.id}",
                "notification_type": "enforcement_event",
                "severity": severity,
                "title": title,
                "summary": summary,
                "created_at": _notification_time(row.timestamp).isoformat(),
                "source_surface": "gateway",
                "actor_user_id": None,
                "actor_label": f"{row.actor_type}:{row.actor_id}",
                "endpoint_id": None,
                "endpoint_label": None,
                "finding_id": None,
                "action_id": None,
                "correlation_id": row.correlation_id,
                "request_id": row.request_id,
                "control_mode": "inline_prevented" if decision in {"block", "deny"} else "warned",
                "decision_badge": decision,
                "drilldowns": _notification_drilldowns(
                    chain_id=_notification_chain_id(correlation_id=row.correlation_id),
                    link=f"/interaction-security?request_id={row.request_id}",
                ),
                "link": f"/interaction-security?request_id={row.request_id}",
            }
        )

    for row in monitoring_rows:
        payload = row.payload if isinstance(row.payload, dict) else {}
        event_type = str(payload.get("event_type") or "").strip().lower()
        signal_type = str(row.signal_type or "").strip().lower()
        domain = str(payload.get("domain") or payload.get("ai_tool") or "").strip().lower()
        agent_id = str(payload.get("agent_id") or "").strip() or None
        agent_name = str(payload.get("agent_name") or "").strip() or None
        model_name = str(payload.get("model_name") or "").strip() or None
        runtime_provider = str(payload.get("runtime_provider") or "").strip() or None
        detected_tools = [str(item).strip() for item in (payload.get("detected_tools") or []) if str(item).strip()]
        detected_actions = [str(item).strip() for item in (payload.get("detected_actions") or []) if str(item).strip()]
        detected_privileges = [str(item).strip() for item in (payload.get("detected_privileges") or []) if str(item).strip()]
        if (
            (event_type == "agent_runtime_discovered" or signal_type == "shadow_ai.browser_agent_runtime_discovered")
            and _is_hawk_control_plane_signal(payload, domain)
        ):
            continue
        signal_types = [
            str(item).strip().lower()
            for item in (payload.get("input_signal_types") or [])
            if str(item).strip()
        ]
        discovery_hint = _extract_discovery_hint(signal_types)
        if _is_pilot_noise_monitoring_signal(
            payload=payload,
            event_type=event_type,
            signal_type=signal_type,
            domain=domain,
            discovery_hint=discovery_hint,
        ):
            continue
        is_discovery_event = (
            event_type in {"unknown_ai_detected", "ai_domain_visit"}
            or signal_type == "browser.ai_domain_visit"
            or signal_type.startswith("shadow_ai.")
            or discovery_hint in {"local_agent_runtime", "agentic_keyword"}
        )
        if not is_discovery_event:
            continue

        if event_type == "ai_domain_visit" and not (_is_local_like_domain(domain) or discovery_hint):
            continue

        if event_type == "agent_runtime_discovered" or signal_type == "shadow_ai.browser_agent_runtime_discovered":
            title = f"Discovery: local agent runtime on {domain or 'local runtime'}"
        elif event_type == "unknown_ai_detected" or signal_type.startswith("shadow_ai."):
            title = f"Discovery: unknown AI usage on {domain or 'unknown domain'}"
        elif _is_local_like_domain(domain) or discovery_hint == "local_agent_runtime":
            title = f"Discovery: local agent runtime on {domain or 'local runtime'}"
        else:
            title = f"Discovery signal on {domain or 'unknown domain'}"

        summary_parts = [
            f"Signal: {event_type or signal_type or 'browser_signal'}",
            f"Action: {str(payload.get('action_taken') or 'monitor').strip().lower()}",
        ]
        if discovery_hint:
            summary_parts.append(f"Hint: {discovery_hint}")
        if agent_name:
            summary_parts.append(f"Agent: {agent_name}")
        if model_name:
            summary_parts.append(f"Model: {model_name}")
        if runtime_provider:
            summary_parts.append(f"Runtime: {runtime_provider}")
        if detected_tools:
            summary_parts.append(f"Tools: {', '.join(detected_tools[:3])}")
        if detected_actions:
            summary_parts.append(f"Actions: {', '.join(detected_actions[:3])}")
        if detected_privileges:
            summary_parts.append(f"Privileges: {', '.join(detected_privileges[:3])}")

        user_id = str(payload.get("user_id") or "").strip() or None
        endpoint_id = str(payload.get("endpoint_id") or "").strip() or None
        source_surface = _normalize_source_surface(str(payload.get("source_surface") or "monitoring"))
        notification_link = (
            f"/ai-iam?agent_id={agent_id}"
            if agent_id
            else (f"/shadow-ai?domain={domain}" if domain else "/shadow-ai")
        )
        signal_chain_id = _notification_chain_id(payload=payload, correlation_id=str(payload.get("correlation_id") or "").strip() or None)

        notifications.append(
            {
                "notification_id": f"signal:{row.id}",
                "notification_type": "discovery_signal",
                "severity": _normalize_severity(row.severity) or "med",
                "title": title,
                "summary": _truncate(" · ".join(summary_parts), max_len=260),
                "created_at": _notification_time(row.created_at).isoformat(),
                "source_surface": source_surface,
                "actor_user_id": user_id,
                "actor_label": _notification_actor_label(user_id=user_id, registry_lookup=user_lookup),
                "endpoint_id": endpoint_id,
                "endpoint_label": _notification_endpoint_label(endpoint_lookup.get(endpoint_id or ""), endpoint_id),
                "finding_id": None,
                "action_id": None,
                "correlation_id": str(payload.get("correlation_id") or "").strip() or None,
                "request_id": None,
                "control_mode": "detected_only",
                "decision_badge": "discovery",
                "drilldowns": _notification_drilldowns(
                    agent_id=agent_id,
                    chain_id=signal_chain_id,
                    link=notification_link,
                ),
                "link": notification_link,
            }
        )

    latest_scan = db.scalar(
        select(ScanResult)
        .where(
            ScanResult.tenant_id == tenant_id,
            ScanResult.start_time >= started_at,
        )
        .order_by(desc(ScanResult.start_time))
    )
    if latest_scan is not None:
        scan_payload = serialize_scan_result(latest_scan)
        scan_summary = dict(scan_payload.get("summary") or {})
        scan_status = str(scan_payload.get("status") or "").strip().lower() or "unknown"
        scan_link = str((scan_payload.get("links") or {}).get("full_report") or "/shadow-ai")
        scan_time = scan_payload.get("last_scan_time") or scan_payload.get("started_at")

        if scan_status == "running":
            notifications.append(
                {
                    "notification_id": f"scan:{latest_scan.scan_id}:running",
                    "notification_type": "scan_status",
                    "severity": "med",
                    "title": "AI Exposure scan running",
                    "summary": "Discovery/risk scan is in progress. New deltas will appear once complete.",
                    "created_at": _notification_time(scan_time).isoformat(),
                    "source_surface": "monitoring",
                    "actor_user_id": latest_scan.triggered_by,
                    "actor_label": _notification_actor_label(user_id=latest_scan.triggered_by, registry_lookup=user_lookup),
                    "endpoint_id": None,
                    "endpoint_label": None,
                    "finding_id": None,
                    "action_id": None,
                    "correlation_id": latest_scan.scan_id,
                    "request_id": latest_scan.scan_id,
                    "link": scan_link,
                }
            )
        elif scan_status == "failed":
            notifications.append(
                {
                    "notification_id": f"scan:{latest_scan.scan_id}:failed",
                    "notification_type": "scan_status",
                    "severity": "high",
                    "title": "AI Exposure scan failed",
                    "summary": _truncate(str(scan_payload.get("error") or "Scan execution failed"), max_len=180),
                    "created_at": _notification_time(scan_time).isoformat(),
                    "source_surface": "monitoring",
                    "actor_user_id": latest_scan.triggered_by,
                    "actor_label": _notification_actor_label(user_id=latest_scan.triggered_by, registry_lookup=user_lookup),
                    "endpoint_id": None,
                    "endpoint_label": None,
                    "finding_id": None,
                    "action_id": None,
                    "correlation_id": latest_scan.scan_id,
                    "request_id": latest_scan.scan_id,
                    "link": scan_link,
                }
            )
        elif scan_status == "completed":
            unknown_apps = int(scan_summary.get("unknown_apps") or 0)
            new_risks = int(scan_summary.get("new_risks_identified") or 0)
            alerts_generated = int(scan_summary.get("alerts_generated") or 0)
            if unknown_apps > 0 or new_risks > 0 or alerts_generated > 0:
                severity = "critical" if new_risks > 0 else ("high" if unknown_apps > 0 else "med")
                summary = (
                    f"+{int(scan_summary.get('new_ai_apps_detected') or 0)} apps · "
                    f"{unknown_apps} unknown · "
                    f"+{new_risks} new risks · "
                    f"+{alerts_generated} alerts"
                )
                notifications.append(
                    {
                        "notification_id": f"scan:{latest_scan.scan_id}:delta",
                        "notification_type": "scan_delta",
                        "severity": severity,
                        "title": "AI Exposure scan delta detected",
                        "summary": summary,
                        "created_at": _notification_time(scan_time).isoformat(),
                        "source_surface": "monitoring",
                        "actor_user_id": latest_scan.triggered_by,
                        "actor_label": _notification_actor_label(user_id=latest_scan.triggered_by, registry_lookup=user_lookup),
                        "endpoint_id": None,
                        "endpoint_label": None,
                        "finding_id": None,
                        "action_id": None,
                        "correlation_id": latest_scan.scan_id,
                        "request_id": latest_scan.scan_id,
                        "link": scan_link,
                    }
                )

    notifications = [_attach_notification_investigation_link(item) for item in _dedupe_notifications(notifications)]
    notifications = sorted(
        notifications,
        key=lambda item: (
            _notification_time(item.get("created_at")),
            _severity_weight(item.get("severity")),
        ),
        reverse=True,
    )
    items = notifications[:normalized_limit]

    payload = {
        "tenant_id": tenant_id,
        "generated_at": _utcnow().isoformat(),
        "total": len(items),
        "critical_count": sum(1 for row in items if (_normalize_severity(str(row.get("severity") or "")) or "low") == "critical"),
        "high_count": sum(1 for row in items if (_normalize_severity(str(row.get("severity") or "")) or "low") == "high"),
        "items": items,
    }
    _notifications_cache_store(notifications_cache_key, payload)
    return payload


def get_command_center_dashboard_state(
    db: Session,
    *,
    tenant_id: str,
    role: str,
    time_window_hours: int = 24,
    ai_system_id: str | None = None,
    severity: str | None = None,
    intent_category: str | None = None,
    input_sensitivity: str | None = None,
    output_sensitivity: str | None = None,
    action_alignment: str | None = None,
    force_refresh: bool = False,
) -> dict[str, Any]:
    normalized_hours = max(1, min(24 * 30, int(time_window_hours or 24)))
    normalized_severity = _normalize_severity(severity)
    normalized_intent_category = _normalized_dashboard_filter(intent_category)
    normalized_input_sensitivity = _normalized_dashboard_filter(input_sensitivity, supported=SUPPORTED_INTENT_SENSITIVITIES)
    normalized_output_sensitivity = _normalized_dashboard_filter(output_sensitivity, supported=SUPPORTED_INTENT_SENSITIVITIES)
    normalized_action_alignment = _normalized_dashboard_filter(action_alignment, supported=SUPPORTED_ACTION_ALIGNMENTS)
    filters = CommandCenterFilters(
        tenant_id=tenant_id,
        time_window_hours=normalized_hours,
        ai_system_id=(str(ai_system_id).strip() or None) if ai_system_id else None,
        severity=normalized_severity,
        intent_category=normalized_intent_category,
        input_sensitivity=normalized_input_sensitivity,
        output_sensitivity=normalized_output_sensitivity,
        action_alignment=normalized_action_alignment,
        role=str(role or "viewer").lower(),
        force_refresh=bool(force_refresh),
    )

    compute_lock = _compute_lock_for(filters.cache_key)
    if not filters.force_refresh:
        cached = _cache_lookup(filters.cache_key)
        if cached is not None:
            return cached
        if compute_lock.locked():
            stale = _cache_lookup(filters.cache_key, allow_stale=True)
            if stale is not None:
                return stale
            if _strict_pilot_dashboard_mode_enabled():
                raise CommandCenterDataUnavailableError(
                    "Command Center snapshot unavailable while refresh is in progress. "
                    "Retry in a few seconds."
                )
            try:
                ai_system_options = _build_ai_system_options(_load_ai_systems(db, tenant_id=tenant_id))
            except Exception:  # noqa: BLE001
                ai_system_options = []
            return _empty_command_center_payload(
                tenant_id=tenant_id,
                role=filters.role,
                time_window_hours=filters.time_window_hours,
                ai_system_id=filters.ai_system_id,
                severity=filters.severity,
                intent_category=filters.intent_category,
                input_sensitivity=filters.input_sensitivity,
                output_sensitivity=filters.output_sensitivity,
                action_alignment=filters.action_alignment,
                ai_system_options=ai_system_options,
            )

    with compute_lock:
        if not filters.force_refresh:
            cached = _cache_lookup(filters.cache_key)
            if cached is not None:
                return cached

        started_at = _utcnow() - timedelta(hours=filters.time_window_hours)
        ai_systems: list[AISystem] = []
        sqlite_timeout_to_restore: int | None = None
        if db.bind and db.bind.dialect.name == "sqlite":
            sqlite_timeout_to_restore = max(1000, int(settings.sqlite_busy_timeout_ms or 8000))
            configured_fast_timeout_ms = int(settings.sqlite_dashboard_fast_timeout_ms or 500)
            fast_timeout_ms = min(
                sqlite_timeout_to_restore,
                max(100, configured_fast_timeout_ms),
            )
            try:
                db.execute(text(f"PRAGMA busy_timeout={fast_timeout_ms};"))
            except Exception:  # noqa: BLE001
                sqlite_timeout_to_restore = None

        try:
            ai_systems = _load_ai_systems(db, tenant_id=tenant_id)
            runtime_events = _load_runtime_events(
                db,
                tenant_id=tenant_id,
                started_at=started_at,
                ai_system_id=filters.ai_system_id,
            )
            ai_action_stmt = select(AIAction).where(
                AIAction.tenant_id == tenant_id,
                AIAction.timestamp >= started_at,
            )
            ai_actions = db.scalars(ai_action_stmt.order_by(desc(AIAction.timestamp)).limit(1200)).all()
            runtime_filter_options = _build_runtime_intent_filter_options(runtime_events)
            runtime_events = _filter_runtime_events_for_command_center(runtime_events, filters)
            findings = _load_findings(
                db,
                tenant_id=tenant_id,
                started_at=started_at,
                ai_system_id=filters.ai_system_id,
                severity=filters.severity,
            )
            shadow_stmt = select(ShadowAIEntity).where(ShadowAIEntity.tenant_id == tenant_id)
            if filters.ai_system_id:
                shadow_stmt = shadow_stmt.where(
                    or_(
                        ShadowAIEntity.linked_ai_system_id == filters.ai_system_id,
                        ShadowAIEntity.linked_ai_system_id.is_(None),
                    )
                )
            shadow_entities = db.scalars(shadow_stmt.order_by(desc(ShadowAIEntity.last_seen)).limit(1200)).all()
            shadow_entity_ids = [row.id for row in shadow_entities]
            shadow_signals: list[ShadowAISignal] = []
            if shadow_entity_ids:
                shadow_signals = db.scalars(
                    select(ShadowAISignal).where(
                        ShadowAISignal.tenant_id == tenant_id,
                        ShadowAISignal.shadow_ai_entity_id.in_(shadow_entity_ids),
                    )
                ).all()
            agents = db.scalars(select(AgentIdentity).where(AgentIdentity.tenant_id == tenant_id)).all()
            maturity_stmt = select(ControlMaturity).where(ControlMaturity.tenant_id == tenant_id)
            if filters.ai_system_id:
                maturity_stmt = maturity_stmt.where(ControlMaturity.ai_system_id == filters.ai_system_id)
            maturity_rows = db.scalars(maturity_stmt).all()
            simulation_stmt = select(SimulationRun).where(
                SimulationRun.tenant_id == tenant_id,
                SimulationRun.started_at >= started_at,
            )
            if filters.ai_system_id:
                simulation_stmt = simulation_stmt.where(SimulationRun.ai_system_id == filters.ai_system_id)
            simulation_runs = db.scalars(simulation_stmt.order_by(desc(SimulationRun.started_at)).limit(1000)).all()
            remediation_rows = db.scalars(
                select(RemediationAction).where(RemediationAction.tenant_id == tenant_id).order_by(desc(RemediationAction.created_at)).limit(500)
            ).all()
            recommendation_stmt = select(RuntimeGovernanceRecommendation).where(
                RuntimeGovernanceRecommendation.tenant_id == tenant_id,
                RuntimeGovernanceRecommendation.created_at >= started_at,
            )
            if filters.ai_system_id:
                recommendation_stmt = recommendation_stmt.where(RuntimeGovernanceRecommendation.ai_system_id == filters.ai_system_id)
            runtime_recommendations = db.scalars(
                recommendation_stmt.order_by(desc(RuntimeGovernanceRecommendation.created_at)).limit(1200)
            ).all()
            drift_stmt = select(DriftAlert).where(DriftAlert.tenant_id == tenant_id)
            if filters.ai_system_id:
                drift_stmt = drift_stmt.where(
                    or_(
                        DriftAlert.ai_system_id == filters.ai_system_id,
                        DriftAlert.ai_system_id.is_(None),
                    )
                )
            drift_alerts = db.scalars(drift_stmt.order_by(desc(DriftAlert.updated_at)).limit(300)).all()
            monitoring_signals = db.scalars(
                select(MonitoringSignal).where(
                    MonitoringSignal.tenant_id == tenant_id,
                    MonitoringSignal.created_at >= started_at,
                ).order_by(desc(MonitoringSignal.created_at)).limit(1200)
            ).all()
            approval_stmt = select(ApprovalRequest).where(ApprovalRequest.tenant_id == tenant_id)
            if filters.ai_system_id:
                approval_stmt = approval_stmt.where(
                    or_(
                        ApprovalRequest.ai_system_id == filters.ai_system_id,
                        ApprovalRequest.ai_system_id.is_(None),
                    )
                )
            approvals = db.scalars(approval_stmt.order_by(desc(ApprovalRequest.created_at)).limit(500)).all()
            job_runs = db.scalars(
                select(ScheduledJobRun).where(ScheduledJobRun.tenant_id == tenant_id).order_by(desc(ScheduledJobRun.started_at)).limit(500)
            ).all()
            snapshot_stmt = select(AuditorSnapshot).where(AuditorSnapshot.tenant_id == tenant_id)
            if filters.ai_system_id:
                snapshot_stmt = snapshot_stmt.where(
                    or_(
                        AuditorSnapshot.ai_system_id == filters.ai_system_id,
                        AuditorSnapshot.ai_system_id.is_(None),
                    )
                )
            auditor_snapshots = db.scalars(snapshot_stmt.order_by(desc(AuditorSnapshot.created_at)).limit(300)).all()

            cve_summary = _build_cve_summary(monitoring_signals)
            try:
                external_risk_intelligence = get_external_risk_summary(
                    db,
                    tenant_id=tenant_id,
                    lookback_hours=filters.time_window_hours,
                )
            except Exception as exc:  # noqa: BLE001
                external_risk_intelligence = {
                    "critical_risks": 0,
                    "high_or_critical_risks": 0,
                    "known_exploited_items": 0,
                    "affected_assets": 0,
                    "new_risks_since_last_sync": 0,
                    "simulations_recommended": 0,
                    "remediation_pending": 0,
                    "sync_status": "failed",
                    "last_sync_at": None,
                    "source_health": [],
                    "coverage_by_source": {},
                    "total_ale_usd": 0.0,
                    "total_residual_risk_usd": 0.0,
                    "drilldown": "/monitoring?focus=external-risk",
                    "error": f"summary_unavailable:{type(exc).__name__}",
                }
            risk_over_time = _build_risk_over_time(runtime_events, started_at=started_at, time_window_hours=filters.time_window_hours)
            severity_distribution = _build_severity_distribution(findings)
            exposure_score = _build_exposure_score(
                findings=findings,
                shadow_entities=shadow_entities,
                runtime_events=runtime_events,
                cve_summary=cve_summary,
            )
            active_incidents = _build_active_incidents(
                findings=findings,
                drift_alerts=drift_alerts,
                remediation_actions=remediation_rows,
            )
            runtime_heatmap = _build_runtime_heatmap(runtime_events)
            shadow_ai_summary = _build_shadow_ai_summary(shadow_entities, shadow_signals)
            identity_risk = _build_identity_risk(agents=agents, runtime_events=runtime_events)
            live_activity_feed = _build_live_activity_feed(runtime_events)
            ai_action_control = _build_ai_action_control_summary(ai_actions)
            users_view = _build_users_view(runtime_events)
            agents_view = _build_agents_view(agents=agents, events=runtime_events, findings=findings)
            findings_alerts = _build_findings_alerts(findings)
            surface_coverage_summary = _build_surface_coverage_summary(runtime_events)
            mcp_tool_calls = _build_mcp_tool_calls_summary(runtime_events, findings)
            agentic_browser_activity = _build_agentic_browser_activity_summary(runtime_events, findings)
            intent_aware_activity = _build_intent_aware_activity_summary(runtime_events)
            attack_trace_view = _build_attack_trace_view(runtime_events)
            quick_actions = _build_quick_actions()
            control_coverage = _build_control_coverage(maturity_rows)
            violations = _build_violations(findings, started_at=started_at)
            simulations = _build_simulations(simulation_runs, started_at=started_at)
            remediation_actions = _build_remediation_actions(remediation_rows)
            crq_summary = _build_crq_summary(runtime_recommendations)
            sla_metrics = _build_sla_metrics(
                approvals=approvals,
                findings=findings,
                job_runs=job_runs,
                auditor_snapshots=auditor_snapshots,
            )
            ai_exposure_scan = _build_ai_exposure_scan(db, tenant_id=tenant_id)

            recommendations = generate_dashboard_recommendations(
                violations=violations,
                risk_trend=risk_over_time,
                simulations=simulations,
                cve_exposure=cve_summary,
                shadow_ai_summary=shadow_ai_summary,
                remediation_actions=remediation_actions,
                sla_metrics=sla_metrics,
            )

            view_scope = "full" if _is_full_access(filters.role) else "scoped"
            if view_scope != "full":
                for item in identity_risk.get("top_agents", []):
                    item.pop("agent_name", None)

            payload = {
                "tenant_id": tenant_id,
                "generated_at": _utcnow().isoformat(),
                "filters_applied": {
                    "time_window_hours": filters.time_window_hours,
                    "ai_system_id": filters.ai_system_id,
                    "severity": filters.severity,
                    "intent_category": filters.intent_category,
                    "input_sensitivity": filters.input_sensitivity,
                    "output_sensitivity": filters.output_sensitivity,
                    "action_alignment": filters.action_alignment,
                },
                "view_scope": view_scope,
                "risk_over_time": risk_over_time,
                "severity_distribution": severity_distribution,
                "exposure_score": exposure_score,
                "active_incidents": active_incidents,
                "runtime_heatmap": runtime_heatmap,
                "live_activity_feed": live_activity_feed,
                "ai_action_control": ai_action_control,
                "users_view": users_view,
                "agents_view": agents_view,
                "findings_alerts": findings_alerts,
                "attack_trace_view": attack_trace_view,
                "quick_actions": quick_actions,
                "surface_coverage_summary": surface_coverage_summary,
                "mcp_tool_calls": mcp_tool_calls,
                "agentic_browser_activity": agentic_browser_activity,
                "intent_aware_activity": intent_aware_activity,
                "shadow_ai_summary": shadow_ai_summary,
                "identity_risk": identity_risk,
                "control_coverage": control_coverage,
                "violations": violations,
                "simulations": simulations,
                "remediation_actions": remediation_actions,
                "ai_exposure_scan": ai_exposure_scan,
                "crq_summary": crq_summary,
                "sla_metrics": sla_metrics,
                "recommendations": recommendations,
                "cve_exposure": cve_summary,
                "external_risk_intelligence": external_risk_intelligence,
                "available_filters": {
                    "time_window_hours": [24, 72, 168, 336, 720],
                    "severity": ["all", "low", "med", "high", "critical"],
                    "ai_systems": _build_ai_system_options(ai_systems),
                    **runtime_filter_options,
                },
            }

            _cache_store(filters.cache_key, payload)
            return payload
        except OperationalError as exc:
            if _is_sqlite_lock_error(exc):
                db.rollback()
                stale = _cache_lookup(filters.cache_key, allow_stale=True) or _cache_lookup(filters.cache_key)
                if stale is not None:
                    return stale
                if _strict_pilot_dashboard_mode_enabled():
                    raise CommandCenterDataUnavailableError(
                        "Command Center data is temporarily unavailable due to database lock contention."
                    ) from exc
                return _empty_command_center_payload(
                    tenant_id=tenant_id,
                    role=filters.role,
                    time_window_hours=filters.time_window_hours,
                    ai_system_id=filters.ai_system_id,
                    severity=filters.severity,
                    ai_system_options=_build_ai_system_options(ai_systems),
                )
            raise
        finally:
            if sqlite_timeout_to_restore is not None:
                try:
                    db.execute(text(f"PRAGMA busy_timeout={sqlite_timeout_to_restore};"))
                except Exception:  # noqa: BLE001
                    pass


def get_pilot_health_state(db: Session, *, tenant_id: str) -> dict[str, Any]:
    cache_key = f"pilot_health|{tenant_id}"
    cached = _pilot_health_cache_lookup(cache_key)
    if cached is not None:
        return cached

    now = _utcnow()
    schema_error: str | None = None
    try:
        schema_report = evaluate_schema_health(db)
    except Exception as exc:  # noqa: BLE001
        schema_report = None
        schema_error = f"schema_health_failed:{type(exc).__name__}"

    latest_extension_signal = db.scalar(
        select(MonitoringSignal)
        .where(
            MonitoringSignal.tenant_id == tenant_id,
            MonitoringSignal.signal_type == "browser.extension_health_status",
        )
        .order_by(desc(MonitoringSignal.created_at))
        .limit(1)
    )
    extension_payload = (
        dict(latest_extension_signal.payload or {})
        if latest_extension_signal is not None and isinstance(latest_extension_signal.payload, dict)
        else {}
    )
    extension_signal_ts = _to_datetime(getattr(latest_extension_signal, "created_at", None))
    last_sync_at = _to_datetime_any(extension_payload.get("last_sync_at"))
    policy_version = str(extension_payload.get("policy_version") or "").strip() or None
    queue_depth = int(extension_payload.get("telemetry_queue_depth") or 0)
    last_extension_error = str(extension_payload.get("last_error") or "").strip() or None
    extension_healthy = bool(extension_payload.get("healthy", False))

    policy_sync_status = "missing"
    if latest_extension_signal is not None:
        if not extension_healthy or last_extension_error:
            policy_sync_status = "degraded"
        else:
            sync_reference = last_sync_at or extension_signal_ts
            if sync_reference is None:
                policy_sync_status = "stale"
            else:
                age_seconds = max(0, int((now - sync_reference).total_seconds()))
                policy_sync_status = "ok" if age_seconds <= 300 else "stale"

    latest_browser_runtime_at = db.scalar(
        select(func.max(RuntimeEvent.created_at)).where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.source_surface.in_(["browser", "browser_extension"]),
        )
    )
    runtime_last_seen = _to_datetime_any(latest_browser_runtime_at)
    telemetry_reference_points = [
        point for point in (runtime_last_seen, extension_signal_ts, last_sync_at) if point is not None
    ]
    latest_browser_telemetry_at = max(telemetry_reference_points) if telemetry_reference_points else None
    telemetry_status = "missing"
    telemetry_lag_seconds: int | None = None
    if latest_browser_telemetry_at is not None:
        telemetry_lag_seconds = max(0, int((now - latest_browser_telemetry_at).total_seconds()))
        if telemetry_lag_seconds <= 120:
            telemetry_status = "ok"
        elif telemetry_lag_seconds <= 600:
            telemetry_status = "stale"
        else:
            telemetry_status = "delayed"

    schema_health_payload = (
        {
            "healthy": bool(schema_report.healthy),
            "missing_tables": list(schema_report.missing_tables),
            "missing_columns": list(schema_report.missing_columns),
            "pending_migrations": list(schema_report.pending_migrations),
            "notes": list(schema_report.notes),
        }
        if schema_report is not None
        else {
            "healthy": False,
            "missing_tables": [],
            "missing_columns": [],
            "pending_migrations": [],
            "notes": [schema_error or "schema_unavailable"],
        }
    )
    api_reachable = True
    schema_ok = bool(schema_health_payload.get("healthy"))
    policy_ok = policy_sync_status == "ok"
    telemetry_ok = telemetry_status in {"ok", "stale"}
    deployment_hardening = evaluate_deployment_hardening(extension_payload, expected_tenant_id=tenant_id)
    hardening_ok = str(deployment_hardening.get("status") or "") == "ok"
    hardening_failed = str(deployment_hardening.get("status") or "") == "failed"
    overall_status = "ok" if (api_reachable and schema_ok and policy_ok and telemetry_ok and hardening_ok) else "degraded"
    if hardening_failed:
        overall_status = "degraded"

    payload = {
        "tenant_id": tenant_id,
        "generated_at": now.isoformat(),
        "overall_status": overall_status,
        "api_reachable": api_reachable,
        "schema_health": schema_health_payload,
        "policy_sync_health": {
            "status": policy_sync_status,
            "policy_version": policy_version,
            "last_sync_at": (last_sync_at or extension_signal_ts).isoformat() if (last_sync_at or extension_signal_ts) else None,
            "telemetry_queue_depth": queue_depth,
            "last_error": last_extension_error,
        },
        "telemetry_health": {
            "status": telemetry_status,
            "latest_browser_event_at": latest_browser_telemetry_at.isoformat() if latest_browser_telemetry_at else None,
            "lag_seconds": telemetry_lag_seconds,
        },
        "deployment_hardening": deployment_hardening,
    }
    _pilot_health_cache_store(cache_key, payload)
    return payload
