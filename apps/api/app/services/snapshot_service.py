from __future__ import annotations

from collections import Counter, defaultdict
import csv
import hashlib
import io
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.models.ai_system import AISystem
from app.db.models.activity_audit import AIAction, AISession, DeploymentEndpoint, PromptPayload, UserRegistry
from app.db.models.audit import AuditLog
from app.db.models.enforcement import EnforcementEvent
from app.db.models.evidence import EvidenceEdge, EvidenceNode
from app.db.models.finding import Finding
from app.db.models.knowledge_base import KBControl, KBFramework
from app.db.models.maturity import ConflictResolution, ControlConflict, ControlMaturity
from app.db.models.monitoring import DriftAlert, MonitoringSignal
from app.db.models.policy import ApprovalRequest
from app.db.models.runtime_intelligence import (
    RuntimeBehaviorEdge,
    RuntimeEvent,
    RuntimeGovernanceRecommendation,
    RuntimeSimulationTrigger,
)
from app.db.models.shadow_ai import ShadowAIEntity, ShadowAIUsage
from app.db.models.simulation import Control, SimulationRun, SimulationScheduleDecision
from app.db.models.snapshot import AuditorSnapshot
from app.db.models.user import User
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node
from app.services.executive_report_service import build_executive_report, render_executive_report_pdf
from app.services.governance_guard import enforce as enforce_governance
from app.services.maturity_service import get_maturity_score_explanation
from app.services.privacy_sanitizer import HASHED_ONLY, sanitize_privacy_payload
from app.services.runtime_intelligence import RUNTIME_FINDING_TYPES


DOCKER_DEFAULT_ARTIFACT_DIR = Path("/artifacts")
DEV_DEFAULT_ARTIFACT_DIR = Path("./artifacts")
AUDITOR_EVIDENCE_EDGE_LIMIT = 5_000


def _running_in_docker() -> bool:
    return Path("/.dockerenv").exists()


def _resolve_artifact_dir() -> Path:
    configured = os.getenv("ARTIFACT_DIR")
    if configured:
        base_dir = Path(configured).expanduser()
    elif _running_in_docker():
        base_dir = DOCKER_DEFAULT_ARTIFACT_DIR
    else:
        base_dir = DEV_DEFAULT_ARTIFACT_DIR

    if base_dir.is_absolute():
        return base_dir
    return (Path.cwd() / base_dir).resolve()


def _ensure_artifact_dir() -> Path:
    artifact_dir = _resolve_artifact_dir()
    try:
        artifact_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(f"Failed to create artifact directory '{artifact_dir}': {exc}") from exc

    probe_file = artifact_dir / ".artifact_write_probe"
    try:
        probe_file.write_text("ok", encoding="utf-8")
        probe_file.unlink(missing_ok=True)
    except OSError as exc:
        raise RuntimeError(f"Artifact directory '{artifact_dir}' is not writable: {exc}") from exc
    return artifact_dir


def ensure_artifact_storage_writable() -> Path:
    return _ensure_artifact_dir()


def _resolve_artifact_path(artifact_path: str, *, artifact_dir: Path | None = None) -> Path:
    root = artifact_dir or _ensure_artifact_dir()
    raw_path = Path(artifact_path)
    resolved = (raw_path if raw_path.is_absolute() else (root / raw_path)).resolve()
    root_resolved = root.resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError("Artifact path is outside configured artifact directory") from exc
    return resolved


def resolve_artifact_file_path(artifact_path: str) -> Path:
    return _resolve_artifact_path(artifact_path)


def artifact_relative_path(artifact_path: str) -> str:
    artifact_dir = _ensure_artifact_dir()
    resolved = _resolve_artifact_path(artifact_path, artifact_dir=artifact_dir)
    return str(resolved.relative_to(artifact_dir))


def artifact_download_url(snapshot_id: str) -> str:
    return f"/auditor/snapshots/{snapshot_id}/download"


def artifact_named_download_url(snapshot_id: str, artifact_name: str) -> str:
    return f"/auditor/snapshots/{snapshot_id}/artifacts/{artifact_name}"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_payload_sha256(payload: dict[str, Any]) -> str:
    return _sha256_hex(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    )


def _artifact_values_from_snapshot(snapshot: AuditorSnapshot) -> set[str]:
    values = {str(snapshot.artifact_path or "").strip()}
    payload = snapshot.payload if isinstance(snapshot.payload, dict) else {}
    artifacts = payload.get("artifacts") if isinstance(payload.get("artifacts"), dict) else {}
    for value in artifacts.values():
        if isinstance(value, str) and value.strip():
            values.add(value.strip())
    return {value for value in values if value}


def cleanup_auditor_artifacts(
    db: Session,
    *,
    retention_days: int = 90,
    tenant_id: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    retention_days = max(1, int(retention_days))
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=retention_days)
    artifact_dir = _ensure_artifact_dir()

    snapshot_query = select(AuditorSnapshot).where(AuditorSnapshot.created_at >= cutoff)
    if tenant_id:
        snapshot_query = snapshot_query.where(AuditorSnapshot.tenant_id == tenant_id)
    protected_paths: set[Path] = set()
    for snapshot in db.scalars(snapshot_query).all():
        for value in _artifact_values_from_snapshot(snapshot):
            try:
                protected_paths.add(_resolve_artifact_path(value, artifact_dir=artifact_dir))
            except ValueError:
                continue

    deleted: list[str] = []
    retained: list[str] = []
    errors: list[dict[str, str]] = []
    cutoff_ts = cutoff.timestamp()
    for path in artifact_dir.iterdir():
        if not path.is_file() or path.name.startswith("."):
            continue
        relative = str(path.relative_to(artifact_dir))
        if path.resolve() in protected_paths or path.stat().st_mtime >= cutoff_ts:
            retained.append(relative)
            continue
        if dry_run:
            deleted.append(relative)
            continue
        try:
            path.unlink()
            deleted.append(relative)
        except OSError as exc:
            errors.append({"path": relative, "error": str(exc)})

    return {
        "retention_days": retention_days,
        "cutoff": cutoff.isoformat(),
        "dry_run": dry_run,
        "deleted": deleted,
        "retained_count": len(retained),
        "error_count": len(errors),
        "errors": errors,
    }


def _is_runtime_correlated_finding(finding_type: str | None) -> bool:
    return str(finding_type or "").strip() in RUNTIME_FINDING_TYPES


def _maturity_implementation_state(*, technical: float, simulation_pass_rate: float, coverage: float, maturity: float, status: str) -> str:
    normalized_status = str(status or "").strip().lower()
    if normalized_status == "contested":
        return "partial"
    if maturity >= 0.75 and technical >= 0.7 and simulation_pass_rate >= 0.6 and coverage >= 0.4:
        return "implemented"
    if maturity >= 0.35 or technical >= 0.4 or coverage >= 0.25:
        return "partial"
    return "not_implemented"


def _maturity_implementation_reasoning(
    *,
    technical: float,
    simulation_pass_rate: float,
    coverage: float,
    maturity: float,
    status: str,
) -> list[str]:
    state = _maturity_implementation_state(
        technical=technical,
        simulation_pass_rate=simulation_pass_rate,
        coverage=coverage,
        maturity=maturity,
        status=status,
    )
    parts = [
        f"technical_enforcement_score={technical:.2f}",
        f"simulation_pass_rate={simulation_pass_rate:.2f}",
        f"coverage_score={coverage:.2f}",
        f"maturity_score={maturity:.2f}",
    ]
    if str(status or "").strip().lower() == "contested":
        parts.append("status=contested requires adjudication")
    parts.append(f"classification={state}")
    return parts


def _frameworks_from_control(
    *,
    control: Control | None,
    kb_frameworks_by_control: dict[str, list[str]],
    control_id: str,
) -> list[str]:
    names: set[str] = set()
    if control is not None:
        for item in (control.mapped_framework_refs or []):
            if isinstance(item, dict):
                name = str(item.get("framework") or "").strip()
                if name:
                    names.add(name)
            else:
                text = str(item).strip()
                if text:
                    names.add(text)
    for name in (kb_frameworks_by_control.get(control_id) or []):
        cleaned = str(name).strip()
        if cleaned:
            names.add(cleaned)
    if not names:
        return ["UNMAPPED"]
    return sorted(names)


def _pdf_renderer_available() -> bool:
    return True


def _parse_export_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def _safe_prompt_for_export(
    payload: PromptPayload | None,
    *,
    reveal_redacted_for_hashed_only: bool = False,
) -> dict[str, Any] | None:
    if payload is None:
        return None
    storage_mode = str(payload.storage_mode or "redacted").strip().lower()
    redacted = str(payload.redacted_prompt or "")
    raw = str(payload.raw_prompt or "") if payload.raw_prompt is not None else None
    if storage_mode == "hashed_only":
        # Hashed-only is an irreversible privacy boundary. Historical rows may
        # still contain a redacted derivative, but no export tier may reveal
        # it. Keep the argument for response-shape compatibility only.
        del reveal_redacted_for_hashed_only
        prompt = HASHED_ONLY
        redacted = HASHED_ONLY
        raw = None
    else:
        prompt = raw if storage_mode == "full" and raw else redacted
    return {
        "storage_mode": storage_mode,
        "prompt": prompt,
        "raw_prompt": raw if storage_mode == "full" else None,
        "redacted_prompt": redacted,
        "prompt_hash": payload.prompt_hash,
        "pii_detected": bool(payload.pii_detected),
        "sensitive_entities": list(payload.sensitive_entities or []),
    }


_PILOT_REPORT_STABLE_METADATA_KEYS = {
    "email",
    "display_name",
    "department",
    "role",
    "endpoint_id",
    "hostname",
    "user_email",
    "user_display_name",
    "user_department",
    "user_role",
    "ai_app",
    "domain",
    "action_type",
    "decision",
    "control_mode",
    "surface",
    "source_surface",
    "finding_type",
    "evidence_bundle_id",
    "decision_explanation_id",
    "trace_id",
    "submitted_by",
    "justification_status",
    "os_version",
    "browser_version",
    "extension_version",
}


def _restore_pilot_report_identity_fields(safe_row: Any, source_row: Any) -> None:
    if not isinstance(safe_row, dict) or not isinstance(source_row, dict):
        return
    for key in _PILOT_REPORT_STABLE_METADATA_KEYS:
        if key in source_row:
            safe_row[key] = source_row.get(key)


def _restore_pilot_report_identity_list(safe_rows: Any, source_rows: Any) -> None:
    if not isinstance(safe_rows, list) or not isinstance(source_rows, list):
        return
    for safe_row, source_row in zip(safe_rows, source_rows, strict=False):
        _restore_pilot_report_identity_fields(safe_row, source_row)


def _sanitize_pilot_user_activity_for_export(pilot_user_activity: dict[str, Any]) -> dict[str, Any]:
    safe = sanitize_privacy_payload(pilot_user_activity)
    if not isinstance(safe, dict):
        return {}

    source_users = list(pilot_user_activity.get("users") or [])
    safe_users = safe.get("users")
    if isinstance(safe_users, list):
        for safe_user, source_user in zip(safe_users, source_users, strict=False):
            _restore_pilot_report_identity_fields(safe_user, source_user)
            _restore_pilot_report_identity_list(safe_user.get("devices"), source_user.get("devices"))
            _restore_pilot_report_identity_list(
                safe_user.get("action_control_ledger"),
                source_user.get("action_control_ledger"),
            )
            _restore_pilot_report_identity_list(safe_user.get("justifications"), source_user.get("justifications"))
    _restore_pilot_report_identity_list(
        safe.get("action_control_ledger"),
        pilot_user_activity.get("action_control_ledger"),
    )
    _restore_pilot_report_identity_list(safe.get("app_usage_summary"), pilot_user_activity.get("app_usage_summary"))
    _restore_pilot_report_identity_list(
        safe.get("device_activity_rollup"),
        pilot_user_activity.get("device_activity_rollup"),
    )
    return safe


def _sanitize_executive_pilot_activity_for_export(executive_pilot_activity: dict[str, Any]) -> dict[str, Any]:
    safe = sanitize_privacy_payload(executive_pilot_activity)
    if not isinstance(safe, dict):
        return {}

    _restore_pilot_report_identity_list(safe.get("users"), executive_pilot_activity.get("users"))
    _restore_pilot_report_identity_list(safe.get("prompt_evidence"), executive_pilot_activity.get("prompt_evidence"))
    _restore_pilot_report_identity_list(safe.get("user_risk_rollup"), executive_pilot_activity.get("user_risk_rollup"))
    _restore_pilot_report_identity_list(
        safe.get("detailed_violations"),
        executive_pilot_activity.get("detailed_violations"),
    )
    _restore_pilot_report_identity_list(
        safe.get("action_control_ledger"),
        executive_pilot_activity.get("action_control_ledger"),
    )
    _restore_pilot_report_identity_list(
        safe.get("app_usage_summary"),
        executive_pilot_activity.get("app_usage_summary"),
    )
    _restore_pilot_report_identity_list(
        safe.get("device_activity_rollup"),
        executive_pilot_activity.get("device_activity_rollup"),
    )
    _restore_pilot_report_identity_list(
        safe.get("per_user_violation_report"),
        executive_pilot_activity.get("per_user_violation_report"),
    )
    safe_user_reports = safe.get("per_user_violation_report")
    source_user_reports = executive_pilot_activity.get("per_user_violation_report")
    if isinstance(safe_user_reports, list) and isinstance(source_user_reports, list):
        for safe_row, source_row in zip(safe_user_reports, source_user_reports, strict=False):
            if not isinstance(safe_row, dict) or not isinstance(source_row, dict):
                continue
            for key in ("devices", "action_samples", "violation_samples", "justification_samples"):
                _restore_pilot_report_identity_list(safe_row.get(key), source_row.get(key))
    _restore_pilot_report_identity_list(
        safe.get("justification_evidence"),
        executive_pilot_activity.get("justification_evidence"),
    )
    return safe


def _reportable_action_app(action: AIAction) -> str:
    return str(action.ai_app or _action_domain(action) or "unknown_ai_tool").strip()


def _action_domain(action: AIAction) -> str | None:
    metadata = action.metadata_json if isinstance(action.metadata_json, dict) else {}
    for key in ("domain", "destination_domain", "request_domain", "page_domain"):
        value = str(metadata.get(key) or "").strip()
        if value:
            return value[:255]
    return None


def _action_metadata(action: AIAction) -> dict[str, Any]:
    return action.metadata_json if isinstance(action.metadata_json, dict) else {}


def _metadata_string(metadata: dict[str, Any], *keys: str, max_len: int = 255) -> str | None:
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, dict):
            continue
        text = str(value or "").strip()
        if text:
            return text[:max_len]
    return None


def _metadata_nested_string(metadata: dict[str, Any], parent_key: str, *keys: str, max_len: int = 1000) -> str | None:
    parent = metadata.get(parent_key)
    if not isinstance(parent, dict):
        return None
    return _metadata_string(parent, *keys, max_len=max_len)


def _action_justification_summary(
    action: AIAction,
    *,
    prompt_preview: str | None = None,
) -> dict[str, Any] | None:
    metadata = _action_metadata(action)
    justification = (
        _metadata_string(
            metadata,
            "justification",
            "justification_text",
            "business_justification",
            "business_reason",
            "review_reason",
            max_len=1000,
        )
        or _metadata_nested_string(metadata, "justification", "text", "reason", "business_reason", max_len=1000)
        or _metadata_nested_string(metadata, "review", "justification", "reason", "business_reason", max_len=1000)
    )
    status = (
        _metadata_string(
            metadata,
            "justification_status",
            "justification_decision",
            "review_status",
            "final_decision",
            max_len=128,
        )
        or _metadata_nested_string(metadata, "justification", "status", "decision", max_len=128)
        or _executive_decision_bucket(action.enforcement_action)
    )
    has_justification_signal = any(
        value
        for value in (
            justification,
            metadata.get("justification"),
            metadata.get("justification_required"),
            metadata.get("justification_decision"),
            metadata.get("review_status"),
        )
    )
    if not has_justification_signal and str(action.enforcement_action or "").lower() not in {
        "require_justification",
        "justification_required",
        "review",
        "review_required",
        "step_up",
    }:
        return None
    return {
        "action_id": action.action_id,
        "runtime_event_id": _action_runtime_event_id(action),
        "timestamp": action.timestamp,
        "ai_app": action.ai_app or _reportable_action_app(action),
        "ai_model": action.ai_model,
        "domain": _action_domain(action),
        "action_type": action.action_type,
        "decision": _executive_decision_bucket(action.enforcement_action),
        "enforcement_action": action.enforcement_action,
        "control_mode": _action_control_mode(action),
        "policy_triggered": action.policy_triggered,
        "justification": justification or "[not provided]",
        "justification_status": status,
        "submitted_by": _metadata_string(metadata, "justification_user_email", "submitted_by", "actor_email", "user_email", max_len=255),
        "submitted_at": _metadata_string(metadata, "justification_submitted_at", "submitted_at", max_len=128),
        "prompt_preview": prompt_preview or "",
        "evidence_bundle_id": _metadata_string(metadata, "evidence_bundle_id", "evidence_id"),
        "decision_explanation_id": _metadata_string(metadata, "decision_explanation_id", "explanation_id"),
        "trace_id": _metadata_string(metadata, "trace_id", "correlation_trace_id") or action.correlation_id,
    }


def _action_runtime_event_id(action: AIAction) -> str | None:
    metadata = _action_metadata(action)
    return str(action.runtime_event_id or metadata.get("runtime_event_id") or "").strip() or None


def _action_control_mode(action: AIAction) -> str:
    metadata = _action_metadata(action)
    nested_policy = metadata.get("policy") if isinstance(metadata.get("policy"), dict) else {}
    explicit = _metadata_string(metadata, "control_mode") or _metadata_string(nested_policy, "control_mode")
    if explicit:
        return explicit
    decision = str(action.enforcement_action or "").strip().lower()
    if decision in {"blocked", "block", "denied", "deny", "prevented"}:
        return "inline_prevented"
    if decision in {"warned", "warn", "warning"}:
        return "warned"
    if decision in {"allowed", "allow"}:
        return "inline_allowed"
    return "detected_only"


def _action_surface(action: AIAction, session: AISession | None) -> str:
    metadata = _action_metadata(action)
    return (
        _metadata_string(metadata, "surface_type", "source_surface", "surface")
        or (str(session.source_surface).strip() if session and str(session.source_surface or "").strip() else None)
        or "unknown"
    )


def _prompt_preview_for_violation(user_row: dict[str, Any], finding: dict[str, Any]) -> str:
    related_event_ids = {str(item).strip() for item in finding.get("related_event_ids") or [] if str(item or "").strip()}
    related_runtime_event_id = str(finding.get("related_runtime_event_id") or "").strip()
    if related_runtime_event_id:
        related_event_ids.add(related_runtime_event_id)
    prompts = list(user_row.get("prompts_entered") or [])
    for prompt in prompts:
        metadata_event_id = str(prompt.get("runtime_event_id") or "").strip()
        if metadata_event_id and metadata_event_id in related_event_ids:
            return str(prompt.get("prompt") or prompt.get("redacted_prompt") or "").strip()
    finding_app = str(finding.get("application") or finding.get("ai_tool") or "").strip().lower()
    for prompt in prompts:
        if finding_app and str(prompt.get("ai_app") or "").strip().lower() == finding_app:
            return str(prompt.get("prompt") or prompt.get("redacted_prompt") or "").strip()
    if prompts:
        return str(prompts[0].get("prompt") or prompts[0].get("redacted_prompt") or "").strip()
    return ""


def _executive_decision_bucket(value: Any) -> str:
    token = str(value or "").strip().lower()
    if token in {"block", "blocked", "deny", "denied", "prevented", "inline_prevented"}:
        return "blocked"
    if token in {"warn", "warned", "warning"}:
        return "warned"
    if token in {"allow", "allowed", "inline_allowed"}:
        return "allowed"
    if token in {"review", "require_justification", "justification_required", "held"}:
        return "review"
    if token:
        return token[:64]
    return "unknown"


def _pilot_report_device_samples(user_row: dict[str, Any], *, limit: int = 5) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    for device in list(user_row.get("devices") or [])[:limit]:
        samples.append(
            {
                "endpoint_id": device.get("endpoint_id"),
                "hostname": device.get("hostname"),
                "device_type": device.get("device_type"),
                "os": device.get("os_name") or device.get("os_type"),
                "os_version": device.get("os_version"),
                "browser": device.get("browser_name") or device.get("browser_type"),
                "browser_version": device.get("browser_version"),
                "extension_name": device.get("extension_name"),
                "extension_version": device.get("extension_version"),
                "last_seen_at": device.get("last_seen_at"),
            }
        )
    return samples


def _pilot_report_action_samples(user_row: dict[str, Any], *, limit: int = 5) -> list[dict[str, Any]]:
    ledger_by_action_id = {
        str(row.get("action_id")): row
        for row in list(user_row.get("action_control_ledger") or [])
        if str(row.get("action_id") or "").strip()
    }
    samples: list[dict[str, Any]] = []
    for prompt in list(user_row.get("prompts_entered") or [])[:limit]:
        action_id = str(prompt.get("action_id") or "").strip()
        ledger = ledger_by_action_id.get(action_id) or {}
        samples.append(
            {
                "action_id": prompt.get("action_id"),
                "runtime_event_id": prompt.get("runtime_event_id"),
                "timestamp": prompt.get("timestamp"),
                "ai_app": prompt.get("ai_app"),
                "ai_model": prompt.get("ai_model"),
                "domain": ledger.get("domain"),
                "action_type": prompt.get("action_type"),
                "decision": ledger.get("decision") or _executive_decision_bucket(prompt.get("enforcement_action")),
                "control_mode": ledger.get("control_mode"),
                "enforcement_action": prompt.get("enforcement_action"),
                "policy_triggered": prompt.get("policy_triggered"),
                "storage_mode": prompt.get("storage_mode"),
                "prompt_preview": prompt.get("prompt") or prompt.get("redacted_prompt") or "",
                "prompt_hash": prompt.get("prompt_hash"),
                "sensitive_entities": prompt.get("sensitive_entities") or [],
                "finding_id": ledger.get("finding_id"),
                "finding_type": ledger.get("finding_type"),
                "evidence_bundle_id": ledger.get("evidence_bundle_id"),
                "decision_explanation_id": ledger.get("decision_explanation_id"),
                "trace_id": ledger.get("trace_id"),
            }
        )
    return samples


def _pilot_report_violation_samples(user_row: dict[str, Any], *, limit: int = 5) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    for finding in list(user_row.get("violations") or [])[:limit]:
        samples.append(
            {
                "finding_id": finding.get("finding_id"),
                "finding_type": finding.get("finding_type"),
                "severity": finding.get("severity"),
                "decision": finding.get("decision"),
                "ai_tool": finding.get("ai_tool"),
                "application": finding.get("application"),
                "policy_id": finding.get("policy_id"),
                "related_runtime_event_id": finding.get("related_runtime_event_id"),
                "related_event_ids": finding.get("related_event_ids") or [],
                "recommended_action": finding.get("recommended_action"),
                "last_seen_at": finding.get("last_seen_at"),
                "prompt_preview": _prompt_preview_for_violation(user_row, finding),
            }
        )
    return samples


def _pilot_report_justification_samples(user_row: dict[str, Any], *, limit: int = 5) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    for justification in list(user_row.get("justifications") or [])[:limit]:
        samples.append(
            {
                "action_id": justification.get("action_id"),
                "runtime_event_id": justification.get("runtime_event_id"),
                "timestamp": justification.get("timestamp"),
                "ai_app": justification.get("ai_app"),
                "domain": justification.get("domain"),
                "action_type": justification.get("action_type"),
                "decision": justification.get("decision"),
                "control_mode": justification.get("control_mode"),
                "policy_triggered": justification.get("policy_triggered"),
                "justification": justification.get("justification"),
                "justification_status": justification.get("justification_status"),
                "submitted_by": justification.get("submitted_by"),
                "submitted_at": justification.get("submitted_at"),
                "prompt_preview": justification.get("prompt_preview"),
                "evidence_bundle_id": justification.get("evidence_bundle_id"),
                "decision_explanation_id": justification.get("decision_explanation_id"),
                "trace_id": justification.get("trace_id"),
            }
        )
    return samples


def _pilot_report_evidence_refs(user_row: dict[str, Any], *, limit: int = 12) -> list[str]:
    refs: list[str] = []
    seen: set[str] = set()
    for row in [
        *list(user_row.get("action_control_ledger") or []),
        *list(user_row.get("justifications") or []),
        *list(user_row.get("violations") or []),
    ]:
        for key in ("evidence_bundle_id", "evidence_node_id", "decision_explanation_id", "trace_id"):
            value = str(row.get(key) or "").strip() if isinstance(row, dict) else ""
            if value and value not in seen:
                seen.add(value)
                refs.append(value)
            if len(refs) >= limit:
                return refs
    return refs


def _build_executive_pilot_activity_section(pilot_user_activity: dict[str, Any]) -> dict[str, Any]:
    users = list(pilot_user_activity.get("users") or [])
    action_control_ledger = list(pilot_user_activity.get("action_control_ledger") or [])
    control_mode_breakdown = dict(
        pilot_user_activity.get("control_mode_breakdown") or Counter(str(row.get("control_mode") or "unknown") for row in action_control_ledger)
    )
    app_usage_summary = list(pilot_user_activity.get("app_usage_summary") or [])
    device_activity_rollup = list(pilot_user_activity.get("device_activity_rollup") or [])
    prompt_evidence: list[dict[str, Any]] = []
    detailed_violations: list[dict[str, Any]] = []
    justification_evidence: list[dict[str, Any]] = []
    tool_rollups: dict[str, dict[str, Any]] = {}
    decision_breakdown: dict[str, int] = defaultdict(int)
    prompt_storage_breakdown: dict[str, int] = defaultdict(int)
    action_type_breakdown: dict[str, int] = defaultdict(int)
    user_risk_rollup: list[dict[str, Any]] = []
    per_user_violation_report: list[dict[str, Any]] = []

    for user_row in users:
        user_identity = {
            "user_id": user_row.get("user_id"),
            "email": user_row.get("email"),
            "display_name": user_row.get("display_name"),
            "department": user_row.get("department"),
            "role": user_row.get("role"),
        }
        primary_device = next(iter(user_row.get("devices") or []), {})
        user_key = str(user_row.get("email") or user_row.get("display_name") or user_row.get("user_id") or "unknown")
        user_blocked_count = 0
        user_warned_count = 0
        for tool_row in list(user_row.get("ai_tools_visited") or []):
            tool = str(tool_row.get("tool") or tool_row.get("domain") or "unknown_ai_tool").strip() or "unknown_ai_tool"
            current = tool_rollups.setdefault(
                tool,
                {
                    "tool": tool,
                    "domain": tool_row.get("domain"),
                    "visit_count": 0,
                    "blocked_count": 0,
                    "warned_count": 0,
                    "_users": set(),
                },
            )
            current["visit_count"] += int(tool_row.get("visit_count") or 0)
            current["blocked_count"] += int(tool_row.get("blocked_count") or 0)
            current["warned_count"] += int(tool_row.get("warned_count") or 0)
            current["_users"].add(user_key)
            user_blocked_count += int(tool_row.get("blocked_count") or 0)
            user_warned_count += int(tool_row.get("warned_count") or 0)

        for prompt in list(user_row.get("prompts_entered") or [])[:25]:
            decision_bucket = _executive_decision_bucket(prompt.get("enforcement_action"))
            decision_breakdown[decision_bucket] += 1
            prompt_storage_breakdown[str(prompt.get("storage_mode") or "unknown")] += 1
            action_type_breakdown[str(prompt.get("action_type") or "unknown")] += 1
            prompt_evidence.append(
                {
                    **user_identity,
                    "endpoint_id": primary_device.get("endpoint_id"),
                    "hostname": primary_device.get("hostname"),
                    "browser": primary_device.get("browser_name") or primary_device.get("browser_type"),
                    "action_id": prompt.get("action_id"),
                    "runtime_event_id": prompt.get("runtime_event_id"),
                    "timestamp": prompt.get("timestamp"),
                    "ai_app": prompt.get("ai_app"),
                    "ai_model": prompt.get("ai_model"),
                    "action_type": prompt.get("action_type"),
                    "enforcement_action": prompt.get("enforcement_action"),
                    "policy_triggered": prompt.get("policy_triggered"),
                    "storage_mode": prompt.get("storage_mode"),
                    "prompt": prompt.get("prompt"),
                    "prompt_hash": prompt.get("prompt_hash"),
                    "sensitive_entities": prompt.get("sensitive_entities") or [],
                }
            )
        for finding in list(user_row.get("violations") or [])[:50]:
            detailed_violations.append(
                {
                    **user_identity,
                    "endpoint_id": primary_device.get("endpoint_id"),
                    "hostname": primary_device.get("hostname"),
                    "browser": primary_device.get("browser_name") or primary_device.get("browser_type"),
                    "finding_id": finding.get("finding_id"),
                    "finding_type": finding.get("finding_type"),
                    "severity": finding.get("severity"),
                    "decision": finding.get("decision"),
                    "ai_tool": finding.get("ai_tool"),
                    "application": finding.get("application"),
                    "policy_id": finding.get("policy_id"),
                    "related_runtime_event_id": finding.get("related_runtime_event_id"),
                    "related_event_ids": finding.get("related_event_ids") or [],
                    "recommended_action": finding.get("recommended_action"),
                    "last_seen_at": finding.get("last_seen_at"),
                    "prompt_preview": _prompt_preview_for_violation(user_row, finding),
                }
            )
        for justification in list(user_row.get("justifications") or [])[:50]:
            justification_evidence.append(
                {
                    **user_identity,
                    "endpoint_id": primary_device.get("endpoint_id"),
                    "hostname": primary_device.get("hostname"),
                    "browser": primary_device.get("browser_name") or primary_device.get("browser_type"),
                    "action_id": justification.get("action_id"),
                    "runtime_event_id": justification.get("runtime_event_id"),
                    "timestamp": justification.get("timestamp"),
                    "ai_app": justification.get("ai_app"),
                    "domain": justification.get("domain"),
                    "action_type": justification.get("action_type"),
                    "decision": justification.get("decision"),
                    "control_mode": justification.get("control_mode"),
                    "policy_triggered": justification.get("policy_triggered"),
                    "justification": justification.get("justification"),
                    "justification_status": justification.get("justification_status"),
                    "submitted_by": justification.get("submitted_by"),
                    "submitted_at": justification.get("submitted_at"),
                    "prompt_preview": justification.get("prompt_preview"),
                    "evidence_bundle_id": justification.get("evidence_bundle_id"),
                    "decision_explanation_id": justification.get("decision_explanation_id"),
                    "trace_id": justification.get("trace_id"),
                }
            )
        user_risk_rollup.append(
            {
                **user_identity,
                "device_count": len(list(user_row.get("devices") or [])),
                "prompt_count": len(list(user_row.get("prompts_entered") or [])),
                "justification_count": len(list(user_row.get("justifications") or [])),
                "shadow_ai_usage_count": len(list(user_row.get("shadow_ai_usage") or [])),
                "violation_count": len(list(user_row.get("violations") or [])),
                "blocked_count": user_blocked_count,
                "warned_count": user_warned_count,
                "risk_score": user_row.get("risk_score"),
            }
        )
        top_user_tools = sorted(
            list(user_row.get("ai_tools_visited") or []),
            key=lambda item: (-int(item.get("visit_count") or 0), str(item.get("tool") or "")),
        )
        per_user_violation_report.append(
            {
                **user_identity,
                "device_count": len(list(user_row.get("devices") or [])),
                "prompt_count": len(list(user_row.get("prompts_entered") or [])),
                "justification_count": len(list(user_row.get("justifications") or [])),
                "violation_count": len(list(user_row.get("violations") or [])),
                "blocked_count": user_blocked_count,
                "warned_count": user_warned_count,
                "top_ai_tools": [str(item.get("tool") or item.get("domain") or "") for item in top_user_tools[:5]],
                "risk_score": user_row.get("risk_score"),
                "devices": _pilot_report_device_samples(user_row),
                "action_samples": _pilot_report_action_samples(user_row),
                "violation_samples": _pilot_report_violation_samples(user_row),
                "justification_samples": _pilot_report_justification_samples(user_row),
                "evidence_refs": _pilot_report_evidence_refs(user_row),
            }
        )

    top_ai_tools = []
    for item in tool_rollups.values():
        users_seen = item.pop("_users", set())
        item["unique_users"] = len(users_seen)
        top_ai_tools.append(item)
    top_ai_tools.sort(key=lambda item: (-int(item.get("visit_count") or 0), str(item.get("tool") or "")))
    user_risk_rollup.sort(
        key=lambda item: (
            -int(item.get("violation_count") or 0),
            -int(item.get("blocked_count") or 0),
            str(item.get("email") or item.get("display_name") or ""),
        )
    )
    per_user_violation_report.sort(
        key=lambda item: (
            -int(item.get("violation_count") or 0),
            -int(item.get("blocked_count") or 0),
            str(item.get("email") or item.get("display_name") or ""),
        )
    )

    return {
        "user_count": pilot_user_activity.get("user_count", 0),
        "endpoint_count": pilot_user_activity.get("endpoint_count", 0),
        "prompt_count": pilot_user_activity.get("prompt_count", 0),
        "justification_count": pilot_user_activity.get("justification_count", 0),
        "violation_count": pilot_user_activity.get("violation_count", 0),
        "shadow_ai_asset_count": pilot_user_activity.get("shadow_ai_asset_count", 0),
        "top_ai_tools": top_ai_tools[:25],
        "decision_breakdown": dict(decision_breakdown),
        "control_mode_breakdown": control_mode_breakdown,
        "prompt_storage_breakdown": dict(prompt_storage_breakdown),
        "action_type_breakdown": dict(action_type_breakdown),
        "user_risk_rollup": user_risk_rollup[:50],
        "per_user_violation_report": per_user_violation_report[:50],
        "app_usage_summary": app_usage_summary[:25],
        "device_activity_rollup": device_activity_rollup[:25],
        "action_control_ledger": action_control_ledger[:150],
        "users": users[:12],
        "prompt_evidence": prompt_evidence[:100],
        "justification_evidence": justification_evidence[:100],
        "detailed_violations": detailed_violations[:100],
    }


def _pilot_endpoint_extension_name(endpoint: DeploymentEndpoint | None) -> str | None:
    if endpoint is None:
        return None
    metadata = endpoint.metadata_json if isinstance(endpoint.metadata_json, dict) else {}
    name = str(metadata.get("extension_name") or "").strip()
    if name and name.lower() not in {"unknown", "extension:unknown", "unknown_extension"}:
        return name[:128]
    if str(endpoint.extension_version or "").strip():
        return "AI Control Plane - Discovery & Guard"
    return None


def _pilot_endpoint_browser_name(endpoint: DeploymentEndpoint | None) -> str | None:
    token = str(getattr(endpoint, "browser_type", "") or "").strip().lower()
    if token == "chrome":
        return "Chrome"
    if token == "edge":
        return "Microsoft Edge"
    if token == "firefox":
        return "Firefox"
    if token == "safari":
        return "Safari"
    if token:
        return token.replace("_", " ").title()
    return None


def _pilot_endpoint_os_name(endpoint: DeploymentEndpoint | None) -> str | None:
    token = str(getattr(endpoint, "os_type", "") or "").strip().lower()
    if token == "mac":
        return "macOS"
    if token == "windows":
        return "Windows"
    if token == "linux":
        return "Linux"
    if token:
        return token.replace("_", " ").title()
    return None


def _build_pilot_user_activity_report(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    start_at: datetime | None,
    end_at: datetime | None,
) -> dict[str, Any]:
    action_query = select(AIAction).where(AIAction.tenant_id == tenant_id)
    action_query = _apply_time_window(action_query, AIAction.timestamp, start=start_at, end=end_at)
    actions = db.scalars(action_query.order_by(desc(AIAction.timestamp)).limit(3000)).all()

    action_ids = [row.action_id for row in actions]
    prompt_rows = (
        db.scalars(select(PromptPayload).where(PromptPayload.action_id.in_(action_ids))).all()
        if action_ids
        else []
    )
    prompt_by_action = {row.action_id: row for row in prompt_rows}

    session_ids = {str(row.session_id) for row in actions if str(row.session_id or "").strip()}
    session_query = select(AISession).where(AISession.tenant_id == tenant_id)
    if session_ids:
        session_query = session_query.where(AISession.session_id.in_(session_ids))
    session_query = _apply_time_window(session_query, AISession.start_time, start=start_at, end=end_at)
    sessions = db.scalars(session_query.order_by(desc(AISession.start_time)).limit(2000)).all()
    session_by_id = {row.session_id: row for row in sessions}

    user_ids = {
        str(value)
        for row in [*actions, *sessions]
        for value in [getattr(row, "user_id", None)]
        if str(value or "").strip()
    }
    endpoint_ids = {
        str(value)
        for row in [*actions, *sessions]
        for value in [getattr(row, "endpoint_id", None)]
        if str(value or "").strip()
    }

    finding_query = select(Finding).where(Finding.tenant_id == tenant_id)
    if ai_system_id:
        finding_query = finding_query.where(Finding.ai_system_id == ai_system_id)
    finding_query = _apply_time_window(finding_query, Finding.last_seen_at, start=start_at, end=end_at)
    finding_rows = db.scalars(finding_query.order_by(desc(Finding.last_seen_at)).limit(2000)).all()
    for row in finding_rows:
        if str(row.user_id or "").strip():
            user_ids.add(str(row.user_id))
        if str(row.machine_id or "").strip():
            endpoint_ids.add(str(row.machine_id))

    usage_query = select(ShadowAIUsage).where(ShadowAIUsage.tenant_id == tenant_id)
    usage_query = _apply_time_window(usage_query, ShadowAIUsage.timestamp, start=start_at, end=end_at)
    shadow_usages = db.scalars(usage_query.order_by(desc(ShadowAIUsage.timestamp)).limit(3000)).all()
    for row in shadow_usages:
        if str(row.user_id or "").strip():
            user_ids.add(str(row.user_id))
        if str(row.endpoint_id or "").strip():
            endpoint_ids.add(str(row.endpoint_id))

    entity_ids = [row.asset_id for row in shadow_usages if str(row.asset_id or "").strip()]
    shadow_entities = (
        db.scalars(select(ShadowAIEntity).where(ShadowAIEntity.tenant_id == tenant_id, ShadowAIEntity.id.in_(entity_ids))).all()
        if entity_ids
        else []
    )
    shadow_entity_by_id = {row.id: row for row in shadow_entities}

    endpoint_rows = (
        db.scalars(
            select(DeploymentEndpoint).where(
                DeploymentEndpoint.tenant_id == tenant_id,
                DeploymentEndpoint.endpoint_id.in_(sorted(endpoint_ids)),
            )
        ).all()
        if endpoint_ids
        else []
    )
    endpoint_by_id = {row.endpoint_id: row for row in endpoint_rows}

    registry_rows = (
        db.scalars(select(UserRegistry).where(UserRegistry.tenant_id == tenant_id, UserRegistry.user_id.in_(sorted(user_ids)))).all()
        if user_ids
        else []
    )
    registry_by_user = {row.user_id: row for row in registry_rows}
    user_rows = db.scalars(select(User).where(User.id.in_(sorted(user_ids)))).all() if user_ids else []
    user_by_id = {row.id: row for row in user_rows}

    findings_by_runtime_event: dict[str, Finding] = {}
    findings_by_user_app: dict[tuple[str | None, str], Finding] = {}
    for finding in finding_rows:
        related_ids = {
            str(item).strip()
            for item in list(finding.related_event_ids or [])
            if str(item or "").strip()
        }
        if str(finding.related_runtime_event_id or "").strip():
            related_ids.add(str(finding.related_runtime_event_id).strip())
        for event_id in related_ids:
            findings_by_runtime_event.setdefault(event_id, finding)
        app_key = str(finding.application or finding.ai_tool or "").strip().lower()
        if app_key:
            findings_by_user_app.setdefault((finding.user_id, app_key), finding)

    action_control_ledger: list[dict[str, Any]] = []
    for action in actions:
        metadata = _action_metadata(action)
        user_id = str(action.user_id or "").strip()
        registry = registry_by_user.get(user_id)
        user = user_by_id.get(user_id)
        endpoint = endpoint_by_id.get(str(action.endpoint_id or ""))
        session = session_by_id.get(action.session_id)
        prompt = _safe_prompt_for_export(
            prompt_by_action.get(action.action_id),
            reveal_redacted_for_hashed_only=True,
        ) or {}
        runtime_event_id = _action_runtime_event_id(action)
        finding = findings_by_runtime_event.get(runtime_event_id or "")
        if finding is None:
            app_key = str(action.ai_app or "").strip().lower()
            finding = findings_by_user_app.get((action.user_id, app_key))
        surface = _action_surface(action, session)
        action_control_ledger.append(
            {
                "action_id": action.action_id,
                "timestamp": action.timestamp,
                "user_id": action.user_id,
                "email": (registry.email if registry else None) or (user.email if user else None),
                "display_name": (registry.display_name if registry else None) or (user.full_name if user else None),
                "department": registry.department if registry else None,
                "role": registry.role if registry else None,
                "endpoint_id": action.endpoint_id,
                "hostname": endpoint.hostname if endpoint else None,
                "device_type": endpoint.device_type if endpoint else None,
                "os_type": endpoint.os_type if endpoint else None,
                "os_name": _pilot_endpoint_os_name(endpoint),
                "os_version": endpoint.os_version if endpoint else None,
                "browser_type": endpoint.browser_type if endpoint else None,
                "browser_name": _pilot_endpoint_browser_name(endpoint),
                "browser_version": endpoint.browser_version if endpoint else None,
                "extension_name": _pilot_endpoint_extension_name(endpoint),
                "extension_version": endpoint.extension_version if endpoint else None,
                "session_id": action.session_id,
                "surface": surface,
                "source_surface": surface,
                "ai_app": action.ai_app or _reportable_action_app(action),
                "ai_model": action.ai_model,
                "domain": _action_domain(action),
                "action_type": action.action_type,
                "decision": _executive_decision_bucket(action.enforcement_action),
                "enforcement_action": action.enforcement_action,
                "control_mode": _action_control_mode(action),
                "policy_triggered": action.policy_triggered,
                "data_classification": action.data_classification,
                "sensitivity_score": float(action.sensitivity_score or 0.0),
                "risk_score": float(action.risk_score or 0.0),
                "prompt_preview": prompt.get("prompt") or prompt.get("redacted_prompt") or "",
                "raw_prompt": None,
                "prompt_hash": prompt.get("prompt_hash"),
                "storage_mode": prompt.get("storage_mode"),
                "sensitive_entities": prompt.get("sensitive_entities") or [],
                "runtime_event_id": runtime_event_id,
                "monitoring_signal_id": action.monitoring_signal_id,
                "audit_log_id": action.audit_log_id,
                "evidence_node_id": action.evidence_node_id,
                "evidence_bundle_id": _metadata_string(metadata, "evidence_bundle_id", "evidence_id"),
                "decision_explanation_id": _metadata_string(metadata, "decision_explanation_id", "explanation_id"),
                "trace_id": _metadata_string(metadata, "trace_id", "correlation_trace_id") or action.correlation_id,
                "finding_id": finding.finding_id if finding else action.finding_id,
                "finding_type": finding.finding_type if finding else None,
                "severity": finding.severity if finding else None,
                "recommended_action": finding.recommended_action if finding else None,
                "correlation_id": action.correlation_id,
            }
        )

    control_mode_breakdown = dict(Counter(row.get("control_mode") or "unknown" for row in action_control_ledger))
    app_rollups: dict[tuple[str, str], dict[str, Any]] = {}
    device_rollups: dict[str, dict[str, Any]] = {}
    for row in action_control_ledger:
        app_key = (str(row.get("ai_app") or "unknown_ai_tool"), str(row.get("domain") or ""))
        app_row = app_rollups.setdefault(
            app_key,
            {
                "ai_app": app_key[0],
                "domain": app_key[1] or None,
                "action_count": 0,
                "blocked_count": 0,
                "warned_count": 0,
                "review_count": 0,
                "_users": set(),
                "_control_modes": Counter(),
            },
        )
        app_row["action_count"] += 1
        app_row["_users"].add(row.get("user_id") or row.get("email") or "unknown")
        app_row["_control_modes"][row.get("control_mode") or "unknown"] += 1
        if row.get("decision") == "blocked":
            app_row["blocked_count"] += 1
        elif row.get("decision") == "warned":
            app_row["warned_count"] += 1
        elif row.get("decision") == "review":
            app_row["review_count"] += 1

        device_key = str(row.get("endpoint_id") or row.get("hostname") or "unknown_endpoint")
        device_row = device_rollups.setdefault(
            device_key,
            {
                "endpoint_id": row.get("endpoint_id"),
                "hostname": row.get("hostname"),
                "os_name": row.get("os_name"),
                "browser_name": row.get("browser_name"),
                "extension_name": row.get("extension_name"),
                "user_email": row.get("email"),
                "action_count": 0,
                "blocked_count": 0,
                "warned_count": 0,
                "_control_modes": Counter(),
            },
        )
        device_row["action_count"] += 1
        device_row["_control_modes"][row.get("control_mode") or "unknown"] += 1
        if row.get("decision") == "blocked":
            device_row["blocked_count"] += 1
        elif row.get("decision") == "warned":
            device_row["warned_count"] += 1

    app_usage_summary = []
    for row in app_rollups.values():
        users_seen = row.pop("_users", set())
        modes = row.pop("_control_modes", Counter())
        row["unique_users"] = len(users_seen)
        row["control_modes"] = dict(modes)
        app_usage_summary.append(row)
    app_usage_summary.sort(key=lambda item: (-int(item.get("action_count") or 0), str(item.get("ai_app") or "")))

    device_activity_rollup = []
    for row in device_rollups.values():
        modes = row.pop("_control_modes", Counter())
        row["control_modes"] = dict(modes)
        device_activity_rollup.append(row)
    device_activity_rollup.sort(
        key=lambda item: (-int(item.get("action_count") or 0), str(item.get("hostname") or item.get("endpoint_id") or ""))
    )

    users: list[dict[str, Any]] = []
    for user_id in sorted(user_ids):
        registry = registry_by_user.get(user_id)
        user = user_by_id.get(user_id)
        user_actions = [row for row in actions if row.user_id == user_id]
        user_sessions = [row for row in sessions if row.user_id == user_id]
        user_findings = [row for row in finding_rows if row.user_id == user_id]
        user_shadow_usage = [row for row in shadow_usages if row.user_id == user_id]
        user_ledger = [row for row in action_control_ledger if row.get("user_id") == user_id]
        user_endpoint_ids = {
            str(value)
            for row in [*user_actions, *user_sessions, *user_shadow_usage]
            for value in [getattr(row, "endpoint_id", None)]
            if str(value or "").strip()
        }
        for finding in user_findings:
            if str(finding.machine_id or "").strip():
                user_endpoint_ids.add(str(finding.machine_id))

        tools: dict[str, dict[str, Any]] = {}
        for action in user_actions:
            tool = _reportable_action_app(action)
            current = tools.setdefault(
                tool,
                {"tool": tool, "domain": _action_domain(action), "visit_count": 0, "blocked_count": 0, "warned_count": 0},
            )
            current["visit_count"] += 1
            if str(action.enforcement_action or "").lower() in {"blocked", "block", "denied", "deny"}:
                current["blocked_count"] += 1
            if str(action.enforcement_action or "").lower() in {"warned", "warn"}:
                current["warned_count"] += 1

        prompt_exports = []
        justification_exports = []
        for action in user_actions:
            prompt = _safe_prompt_for_export(
                prompt_by_action.get(action.action_id),
                reveal_redacted_for_hashed_only=True,
            )
            prompt_preview = ""
            if prompt is not None:
                prompt_preview = str(prompt.get("prompt") or prompt.get("redacted_prompt") or "")
                prompt_exports.append(
                    {
                        "action_id": action.action_id,
                        "runtime_event_id": action.runtime_event_id
                        or (
                            str((action.metadata_json or {}).get("runtime_event_id") or "").strip()
                            if isinstance(action.metadata_json, dict)
                            else None
                        ),
                        "timestamp": action.timestamp,
                        "ai_app": action.ai_app,
                        "ai_model": action.ai_model,
                        "action_type": action.action_type,
                        "enforcement_action": action.enforcement_action,
                        "policy_triggered": action.policy_triggered,
                        **prompt,
                    }
                )
            justification = _action_justification_summary(action, prompt_preview=prompt_preview)
            if justification is not None:
                justification_exports.append(
                    {
                        "user_id": user_id,
                        "email": (registry.email if registry else None) or (user.email if user else None),
                        "display_name": (registry.display_name if registry else None) or (user.full_name if user else None),
                        "department": registry.department if registry else None,
                        "role": registry.role if registry else None,
                        **justification,
                    }
                )

        users.append(
            {
                "user_id": user_id,
                "email": (registry.email if registry else None) or (user.email if user else None),
                "display_name": (registry.display_name if registry else None) or (user.full_name if user else None),
                "department": registry.department if registry else None,
                "role": registry.role if registry else None,
                "risk_score": float(registry.risk_score or 0.0) if registry else None,
                "violation_count": len(user_findings),
                "devices": [
                    {
                        "endpoint_id": endpoint_id,
                        "user_id": user_id,
                        "user_email": (registry.email if registry else None) or (user.email if user else None),
                        "user_display_name": (registry.display_name if registry else None) or (user.full_name if user else None),
                        "user_department": registry.department if registry else None,
                        "user_role": registry.role if registry else None,
                        "hostname": endpoint_by_id.get(endpoint_id).hostname if endpoint_by_id.get(endpoint_id) else None,
                        "device_type": endpoint_by_id.get(endpoint_id).device_type if endpoint_by_id.get(endpoint_id) else None,
                        "os_type": endpoint_by_id.get(endpoint_id).os_type if endpoint_by_id.get(endpoint_id) else None,
                        "os_name": _pilot_endpoint_os_name(endpoint_by_id.get(endpoint_id)),
                        "os_version": endpoint_by_id.get(endpoint_id).os_version if endpoint_by_id.get(endpoint_id) else None,
                        "browser_type": endpoint_by_id.get(endpoint_id).browser_type if endpoint_by_id.get(endpoint_id) else None,
                        "browser_name": _pilot_endpoint_browser_name(endpoint_by_id.get(endpoint_id)),
                        "browser_version": endpoint_by_id.get(endpoint_id).browser_version if endpoint_by_id.get(endpoint_id) else None,
                        "extension_name": _pilot_endpoint_extension_name(endpoint_by_id.get(endpoint_id)),
                        "extension_version": endpoint_by_id.get(endpoint_id).extension_version if endpoint_by_id.get(endpoint_id) else None,
                        "last_seen_at": endpoint_by_id.get(endpoint_id).last_seen_at if endpoint_by_id.get(endpoint_id) else None,
                    }
                    for endpoint_id in sorted(user_endpoint_ids)
                ],
                "ai_tools_visited": sorted(tools.values(), key=lambda item: (-int(item["visit_count"]), item["tool"]))[:50],
                "shadow_ai_usage": [
                    {
                        "asset_id": usage.asset_id,
                        "name": shadow_entity_by_id.get(usage.asset_id).canonical_name if shadow_entity_by_id.get(usage.asset_id) else None,
                        "domain": (usage.metadata_json or {}).get("domain")
                        if isinstance(usage.metadata_json, dict)
                        else None,
                        "interaction_type": usage.interaction_type,
                        "sensitivity_detected": bool(usage.sensitivity_detected),
                        "policy_triggered": usage.policy_triggered,
                        "timestamp": usage.timestamp,
                    }
                    for usage in user_shadow_usage[:100]
                ],
                "prompts_entered": prompt_exports[:100],
                "justifications": justification_exports[:100],
                "action_control_ledger": user_ledger[:100],
                "violations": [
                    {
                        "finding_id": finding.finding_id,
                        "finding_type": finding.finding_type,
                        "severity": finding.severity,
                        "decision": finding.decision,
                        "ai_tool": finding.ai_tool,
                        "application": finding.application,
                        "policy_id": finding.policy_id,
                        "related_event_ids": list(finding.related_event_ids or []),
                        "related_runtime_event_id": finding.related_runtime_event_id,
                        "occurrence_count": finding.occurrence_count,
                        "recommended_action": finding.recommended_action,
                        "last_seen_at": finding.last_seen_at,
                    }
                    for finding in user_findings[:100]
                ],
            }
        )

    shadow_entities_summary = [
        {
            "asset_id": entity.id,
            "name": entity.canonical_name,
            "approved_status": entity.approved_status,
            "risk_score": entity.risk_score,
            "usage_count": entity.usage_count,
            "unique_users": entity.unique_users,
            "endpoints_count": entity.endpoints_count,
            "source_surfaces": list(entity.source_surfaces or []),
        }
        for entity in shadow_entities[:500]
    ]
    return {
        "user_count": len(users),
        "endpoint_count": len(endpoint_by_id),
        "prompt_count": sum(len(row["prompts_entered"]) for row in users),
        "justification_count": sum(len(row["justifications"]) for row in users),
        "violation_count": sum(len(row["violations"]) for row in users),
        "shadow_ai_asset_count": len({row["asset_id"] for row in shadow_entities_summary}),
        "action_control_ledger": action_control_ledger[:500],
        "control_mode_breakdown": control_mode_breakdown,
        "app_usage_summary": app_usage_summary[:100],
        "device_activity_rollup": device_activity_rollup[:100],
        "users": users,
        "shadow_ai_assets": shadow_entities_summary,
    }
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def _apply_time_window(query: Any, column: Any, *, start: datetime | None, end: datetime | None) -> Any:
    if start is not None:
        query = query.where(column >= start)
    if end is not None:
        query = query.where(column <= end)
    return query


def _validate_ai_system_tenant(db: Session, *, tenant_id: str, ai_system_id: str | None) -> None:
    if not ai_system_id:
        return
    row = db.scalar(
        select(AISystem).where(
            AISystem.id == ai_system_id,
            AISystem.tenant_id == tenant_id,
        )
    )
    if not row:
        raise ValueError("AI system not found for tenant")


def create_auditor_snapshot(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    trigger_type: str,
    payload: dict[str, Any],
    actor_user_id: str | None,
    artifact_hash: str | None = None,
    artifact_relative_path: str | None = None,
) -> AuditorSnapshot:
    enforce_governance(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        action="auditor.snapshot.create",
        route="/auditor/snapshot",
        module="snapshot_service",
        tenant_scope=ai_system_id is None,
    )
    _validate_ai_system_tenant(db, tenant_id=tenant_id, ai_system_id=ai_system_id)
    payload = dict(payload or {})
    if "onprem_evidence_references" not in payload:
        payload["onprem_evidence_references"] = _collect_onprem_evidence_references(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
        )

    artifact_dir = _ensure_artifact_dir()
    if artifact_relative_path:
        file_path = _resolve_artifact_path(artifact_relative_path, artifact_dir=artifact_dir)
        if not file_path.exists():
            raise ValueError(f"Artifact file does not exist: {artifact_relative_path}")
        stored_artifact_path = str(file_path.relative_to(artifact_dir))
        try:
            artifact_bytes = file_path.read_bytes()
        except OSError as exc:
            raise RuntimeError(f"Failed to read artifact file '{file_path}': {exc}") from exc
        resolved_hash = artifact_hash or _sha256_hex(artifact_bytes)
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        stored_artifact_path = f"snapshot_{tenant_id}_{ai_system_id or 'all'}_{stamp}.json"
        file_path = artifact_dir / stored_artifact_path
        serialized_payload = json.dumps(payload, indent=2, sort_keys=True)
        try:
            file_path.write_text(serialized_payload, encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"Failed to write snapshot artifact '{file_path}': {exc}") from exc
        resolved_hash = artifact_hash or _sha256_hex(serialized_payload.encode("utf-8"))

    snap = AuditorSnapshot(
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        trigger_type=trigger_type,
        artifact_path=stored_artifact_path,
        artifact_hash=resolved_hash,
        payload=payload,
    )
    db.add(snap)
    db.flush()

    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="system",
        action="auditor.snapshot.create",
        resource_type="auditor_snapshot",
        resource_id=snap.id,
        payload={"trigger_type": trigger_type, "artifact_path": stored_artifact_path, "artifact_hash": resolved_hash},
    )
    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="auditor_snapshot",
        signal_type="auditor.snapshot.created",
        label=f"Auditor snapshot created: {snap.id}",
        payload={
            "snapshot_id": snap.id,
            "ai_system_id": ai_system_id,
            "trigger_type": trigger_type,
            "artifact_path": stored_artifact_path,
            "artifact_hash": resolved_hash,
        },
    )
    return snap


def _latest_approval_by_ai_system(approvals: list[ApprovalRequest]) -> dict[str, ApprovalRequest]:
    by_system: dict[str, ApprovalRequest] = {}
    for approval in approvals:
        current = by_system.get(approval.ai_system_id)
        if not current or approval.created_at > current.created_at:
            by_system[approval.ai_system_id] = approval
    return by_system


def _latest_event_by_ai_system(events: list[EnforcementEvent]) -> dict[str, EnforcementEvent]:
    by_system: dict[str, EnforcementEvent] = {}
    for event in events:
        current = by_system.get(event.ai_system_id)
        if not current or event.timestamp > current.timestamp:
            by_system[event.ai_system_id] = event
    return by_system


def _collect_onprem_evidence_references(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    onprem_rows = db.scalars(
        select(EvidenceNode)
        .where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.node_type.in_(["onprem_evidence_bundle", "onprem_signal"]),
        )
        .order_by(desc(EvidenceNode.created_at))
        .limit(limit)
    ).all()
    onprem_refs: list[dict[str, Any]] = []
    for node in onprem_rows:
        payload = node.payload if isinstance(node.payload, dict) else {}
        payload_ai_system_id = str(payload.get("ai_system_id") or "").strip()
        source_metadata = payload.get("source_metadata") if isinstance(payload.get("source_metadata"), dict) else {}
        source_ai_system_id = str(source_metadata.get("ai_system_id") or "").strip()
        if ai_system_id and ai_system_id not in {payload_ai_system_id, source_ai_system_id}:
            continue
        onprem_refs.append(
            {
                "node_id": node.id,
                "node_type": node.node_type,
                "signal_type": node.signal_type,
                "label": node.label,
                "timestamp": node.created_at.isoformat() if node.created_at else None,
                "gateway_id": payload.get("gateway_id"),
                "bundle_id": payload.get("bundle_id"),
                "path": "/trust-center/evidence/nodes",
            }
        )
    return onprem_refs


def _collect_bounded_evidence_edges(
    db: Session,
    *,
    tenant_id: str,
    linked_node_ids: set[str],
    limit: int = AUDITOR_EVIDENCE_EDGE_LIMIT,
) -> tuple[list[EvidenceEdge], bool]:
    """Return a bounded outgoing evidence subgraph for selected export nodes.

    The tenant evidence graph can contain millions of edges. Audit exports use
    the selected evidence nodes as their authoritative roots and include only a
    recent, bounded set of outgoing relationships from those roots. Fetching one
    extra row makes truncation explicit without hydrating the complete graph.
    """
    bounded_limit = max(1, int(limit))
    if not linked_node_ids:
        return [], False
    rows = db.scalars(
        select(EvidenceEdge)
        .where(
            EvidenceEdge.tenant_id == tenant_id,
            EvidenceEdge.from_node_id.in_(sorted(linked_node_ids)),
        )
        .order_by(desc(EvidenceEdge.created_at), EvidenceEdge.id.desc())
        .limit(bounded_limit + 1)
    ).all()
    return list(rows[:bounded_limit]), len(rows) > bounded_limit


def build_control_posture_views(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None = None,
) -> dict[str, list[dict[str, Any]]]:
    maturity_query = select(ControlMaturity).where(ControlMaturity.tenant_id == tenant_id)
    if ai_system_id:
        maturity_query = maturity_query.where(ControlMaturity.ai_system_id == ai_system_id)
    maturities = db.scalars(maturity_query).all()
    if not maturities:
        return {"framework": [], "domain": [], "ai_system": []}

    control_ids = sorted({str(row.control_id).strip() for row in maturities if str(row.control_id).strip()})
    ai_system_ids = sorted({str(row.ai_system_id).strip() for row in maturities if str(row.ai_system_id).strip()})

    controls = db.scalars(
        select(Control).where(
            Control.id.in_(control_ids) if control_ids else Control.id == "__none__",
            Control.tenant_id == tenant_id,
        )
    ).all()
    controls_by_id = {str(row.id): row for row in controls}

    ai_systems = db.scalars(
        select(AISystem).where(
            AISystem.tenant_id == tenant_id,
            AISystem.id.in_(ai_system_ids) if ai_system_ids else AISystem.id == "__none__",
        )
    ).all()
    ai_system_names = {str(row.id): str(row.name or row.id) for row in ai_systems}

    kb_framework_rows = db.execute(
        select(KBControl.id, KBFramework.name)
        .join(KBFramework, KBFramework.id == KBControl.framework_id)
        .where(KBControl.id.in_(control_ids) if control_ids else KBControl.id == "__none__")
    ).all()
    kb_frameworks_by_control: dict[str, list[str]] = defaultdict(list)
    for control_id, framework_name in kb_framework_rows:
        kb_frameworks_by_control[str(control_id)].append(str(framework_name))

    base_rows: list[dict[str, Any]] = []
    for row in maturities:
        control_id = str(row.control_id)
        control = controls_by_id.get(control_id)
        domain = str(control.category).strip() if control is not None and str(control.category).strip() else "unknown"
        frameworks = _frameworks_from_control(
            control=control,
            kb_frameworks_by_control=kb_frameworks_by_control,
            control_id=control_id,
        )
        implementation_state = _maturity_implementation_state(
            technical=float(row.technical_enforcement_score),
            simulation_pass_rate=float(row.simulation_pass_rate),
            coverage=float(row.coverage_score),
            maturity=float(row.maturity_score),
            status=str(row.status or ""),
        )
        base_rows.append(
            {
                "ai_system_id": row.ai_system_id,
                "ai_system_name": ai_system_names.get(str(row.ai_system_id), str(row.ai_system_id)),
                "control_id": control_id,
                "control_name": str(control.name) if control is not None else control_id,
                "domain": domain,
                "frameworks": frameworks,
                "implementation_state": implementation_state,
                "status": row.status,
                "maturity_score": float(row.maturity_score),
                "confidence_score": float(row.confidence_score),
            }
        )

    def _init_bucket(group_key: str, group_label: str) -> dict[str, Any]:
        return {
            "group_key": group_key,
            "group_label": group_label,
            "controls_total": 0,
            "implemented_controls": 0,
            "partial_controls": 0,
            "not_implemented_controls": 0,
            "avg_maturity_score": 0.0,
            "avg_confidence_score": 0.0,
            "ai_system_count": 0,
            "_maturity_sum": 0.0,
            "_confidence_sum": 0.0,
            "_control_ids": set(),
            "_ai_system_ids": set(),
        }

    def _finalize(buckets: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for key, bucket in buckets.items():
            total = max(1, int(bucket["controls_total"]))
            rows.append(
                {
                    "group_key": key,
                    "group_label": bucket["group_label"],
                    "controls_total": int(bucket["controls_total"]),
                    "implemented_controls": int(bucket["implemented_controls"]),
                    "partial_controls": int(bucket["partial_controls"]),
                    "not_implemented_controls": int(bucket["not_implemented_controls"]),
                    "avg_maturity_score": float(bucket["_maturity_sum"]) / float(total),
                    "avg_confidence_score": float(bucket["_confidence_sum"]) / float(total),
                    "ai_system_count": len(bucket["_ai_system_ids"]),
                    "control_ids": sorted(bucket["_control_ids"]),
                }
            )
        rows.sort(key=lambda row: row["group_label"])
        return rows

    framework_buckets: dict[str, dict[str, Any]] = {}
    domain_buckets: dict[str, dict[str, Any]] = {}
    ai_system_buckets: dict[str, dict[str, Any]] = {}

    for row in base_rows:
        state = row["implementation_state"]
        ai_id = str(row["ai_system_id"])
        control_id = str(row["control_id"])

        for framework in row["frameworks"]:
            bucket = framework_buckets.setdefault(framework, _init_bucket(framework, framework))
            bucket["controls_total"] += 1
            bucket["_maturity_sum"] += float(row["maturity_score"])
            bucket["_confidence_sum"] += float(row["confidence_score"])
            bucket["_control_ids"].add(control_id)
            bucket["_ai_system_ids"].add(ai_id)
            if state == "implemented":
                bucket["implemented_controls"] += 1
            elif state == "partial":
                bucket["partial_controls"] += 1
            else:
                bucket["not_implemented_controls"] += 1

        domain = str(row["domain"])
        domain_bucket = domain_buckets.setdefault(domain, _init_bucket(domain, domain))
        domain_bucket["controls_total"] += 1
        domain_bucket["_maturity_sum"] += float(row["maturity_score"])
        domain_bucket["_confidence_sum"] += float(row["confidence_score"])
        domain_bucket["_control_ids"].add(control_id)
        domain_bucket["_ai_system_ids"].add(ai_id)
        if state == "implemented":
            domain_bucket["implemented_controls"] += 1
        elif state == "partial":
            domain_bucket["partial_controls"] += 1
        else:
            domain_bucket["not_implemented_controls"] += 1

        ai_label = str(row["ai_system_name"] or ai_id)
        ai_bucket = ai_system_buckets.setdefault(ai_id, _init_bucket(ai_id, ai_label))
        ai_bucket["controls_total"] += 1
        ai_bucket["_maturity_sum"] += float(row["maturity_score"])
        ai_bucket["_confidence_sum"] += float(row["confidence_score"])
        ai_bucket["_control_ids"].add(control_id)
        ai_bucket["_ai_system_ids"].add(ai_id)
        if state == "implemented":
            ai_bucket["implemented_controls"] += 1
        elif state == "partial":
            ai_bucket["partial_controls"] += 1
        else:
            ai_bucket["not_implemented_controls"] += 1

    return {
        "framework": _finalize(framework_buckets),
        "domain": _finalize(domain_buckets),
        "ai_system": _finalize(ai_system_buckets),
    }


def export_audit_artifacts(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    period_start: str,
    period_end: str,
) -> dict[str, Any]:
    _validate_ai_system_tenant(db, tenant_id=tenant_id, ai_system_id=ai_system_id)
    start_at = _parse_export_datetime(period_start)
    end_at = _parse_export_datetime(period_end)

    artifact_dir = _ensure_artifact_dir()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_relative_path = f"audit_export_{tenant_id}_{stamp}.json"
    csv_relative_path = f"audit_export_{tenant_id}_{stamp}.csv"
    json_path = artifact_dir / json_relative_path
    csv_path = artifact_dir / csv_relative_path

    maturity_query = select(ControlMaturity).where(ControlMaturity.tenant_id == tenant_id)
    if ai_system_id:
        maturity_query = maturity_query.where(ControlMaturity.ai_system_id == ai_system_id)
    maturities = db.scalars(maturity_query.order_by(ControlMaturity.ai_system_id.asc(), ControlMaturity.control_id.asc())).all()

    event_query = select(EnforcementEvent).where(EnforcementEvent.tenant_id == tenant_id)
    if ai_system_id:
        event_query = event_query.where(EnforcementEvent.ai_system_id == ai_system_id)
    event_query = _apply_time_window(event_query, EnforcementEvent.timestamp, start=start_at, end=end_at)
    events = db.scalars(event_query.order_by(desc(EnforcementEvent.timestamp)).limit(500)).all()

    approval_query = select(ApprovalRequest).where(ApprovalRequest.tenant_id == tenant_id)
    if ai_system_id:
        approval_query = approval_query.where(ApprovalRequest.ai_system_id == ai_system_id)
    approval_query = _apply_time_window(approval_query, ApprovalRequest.created_at, start=start_at, end=end_at)
    approvals = db.scalars(approval_query.order_by(desc(ApprovalRequest.created_at)).limit(500)).all()

    conflict_query = select(ControlConflict).where(ControlConflict.tenant_id == tenant_id)
    if ai_system_id:
        conflict_query = conflict_query.where(ControlConflict.ai_system_id == ai_system_id)
    conflict_query = _apply_time_window(conflict_query, ControlConflict.detected_at, start=start_at, end=end_at)
    conflicts = db.scalars(conflict_query.order_by(desc(ControlConflict.detected_at)).limit(500)).all()
    conflict_ids = [str(row.id) for row in conflicts if str(row.id).strip()]
    conflict_resolution_query = select(ConflictResolution).where(ConflictResolution.tenant_id == tenant_id)
    if ai_system_id:
        conflict_resolution_query = conflict_resolution_query.where(ConflictResolution.ai_system_id == ai_system_id)
    conflict_resolution_query = _apply_time_window(
        conflict_resolution_query,
        ConflictResolution.created_at,
        start=start_at,
        end=end_at,
    )
    if conflict_ids:
        conflict_resolution_query = conflict_resolution_query.where(
            (ConflictResolution.conflict_id.in_(conflict_ids)) | (ConflictResolution.conflict_id.is_(None))
        )
    conflict_resolutions = db.scalars(conflict_resolution_query.order_by(desc(ConflictResolution.created_at)).limit(500)).all()

    findings_query = select(Finding).where(Finding.tenant_id == tenant_id)
    if ai_system_id:
        findings_query = findings_query.where(Finding.ai_system_id == ai_system_id)
    findings_query = _apply_time_window(findings_query, Finding.last_seen_at, start=start_at, end=end_at)
    findings = db.scalars(findings_query.order_by(desc(Finding.last_seen_at)).limit(1000)).all()

    runtime_event_query = select(RuntimeEvent).where(RuntimeEvent.tenant_id == tenant_id)
    if ai_system_id:
        runtime_event_query = runtime_event_query.where(RuntimeEvent.ai_system_id == ai_system_id)
    runtime_event_query = _apply_time_window(runtime_event_query, RuntimeEvent.created_at, start=start_at, end=end_at)
    runtime_events = db.scalars(runtime_event_query.order_by(desc(RuntimeEvent.created_at)).limit(1000)).all()
    runtime_event_ids = [str(row.event_id) for row in runtime_events if str(row.event_id).strip()]

    runtime_edge_query = select(RuntimeBehaviorEdge).where(RuntimeBehaviorEdge.tenant_id == tenant_id)
    if ai_system_id:
        runtime_edge_query = runtime_edge_query.where(RuntimeBehaviorEdge.ai_system_id == ai_system_id)
    if runtime_event_ids:
        runtime_edge_query = runtime_edge_query.where(RuntimeBehaviorEdge.event_id.in_(runtime_event_ids))
    runtime_edge_query = _apply_time_window(runtime_edge_query, RuntimeBehaviorEdge.created_at, start=start_at, end=end_at)
    runtime_behavior_edges = db.scalars(runtime_edge_query.order_by(desc(RuntimeBehaviorEdge.created_at)).limit(2000)).all()

    runtime_trigger_query = select(RuntimeSimulationTrigger).where(RuntimeSimulationTrigger.tenant_id == tenant_id)
    if ai_system_id:
        runtime_trigger_query = runtime_trigger_query.where(RuntimeSimulationTrigger.ai_system_id == ai_system_id)
    runtime_trigger_query = _apply_time_window(
        runtime_trigger_query,
        RuntimeSimulationTrigger.created_at,
        start=start_at,
        end=end_at,
    )
    runtime_triggers = db.scalars(runtime_trigger_query.order_by(desc(RuntimeSimulationTrigger.created_at)).limit(1000)).all()

    runtime_reco_query = select(RuntimeGovernanceRecommendation).where(RuntimeGovernanceRecommendation.tenant_id == tenant_id)
    if ai_system_id:
        runtime_reco_query = runtime_reco_query.where(RuntimeGovernanceRecommendation.ai_system_id == ai_system_id)
    runtime_reco_query = _apply_time_window(
        runtime_reco_query,
        RuntimeGovernanceRecommendation.created_at,
        start=start_at,
        end=end_at,
    )
    runtime_recommendations = db.scalars(runtime_reco_query.order_by(desc(RuntimeGovernanceRecommendation.created_at)).limit(1000)).all()

    drift_alert_query = select(DriftAlert).where(DriftAlert.tenant_id == tenant_id)
    if ai_system_id:
        drift_alert_query = drift_alert_query.where(DriftAlert.ai_system_id == ai_system_id)
    drift_alert_query = _apply_time_window(drift_alert_query, DriftAlert.created_at, start=start_at, end=end_at)
    drift_alerts = db.scalars(drift_alert_query.order_by(desc(DriftAlert.created_at)).limit(1000)).all()

    schedule_decision_query = select(SimulationScheduleDecision).where(SimulationScheduleDecision.tenant_id == tenant_id)
    if ai_system_id:
        schedule_decision_query = schedule_decision_query.where(SimulationScheduleDecision.target_ai_system_id == ai_system_id)
    schedule_decision_query = _apply_time_window(
        schedule_decision_query,
        SimulationScheduleDecision.scheduled_at,
        start=start_at,
        end=end_at,
    )
    schedule_decisions = db.scalars(schedule_decision_query.order_by(desc(SimulationScheduleDecision.scheduled_at)).limit(1000)).all()

    simulation_run_query = select(SimulationRun).where(SimulationRun.tenant_id == tenant_id)
    if ai_system_id:
        simulation_run_query = simulation_run_query.where(SimulationRun.ai_system_id == ai_system_id)
    simulation_run_query = _apply_time_window(simulation_run_query, SimulationRun.started_at, start=start_at, end=end_at)
    simulation_runs = db.scalars(simulation_run_query.order_by(desc(SimulationRun.started_at)).limit(1000)).all()

    governance_audit_query = (
        select(AuditLog)
        .where(
            AuditLog.tenant_id == tenant_id,
            (AuditLog.action.like("ai_system.%")) | (AuditLog.action.like("governance.%")),
        )
    )
    governance_audit_query = _apply_time_window(governance_audit_query, AuditLog.created_at, start=start_at, end=end_at)
    governance_audit_rows = db.scalars(governance_audit_query.order_by(desc(AuditLog.created_at)).limit(1000)).all()
    if ai_system_id:
        filtered_governance_rows: list[AuditLog] = []
        for row in governance_audit_rows:
            payload = row.payload if isinstance(row.payload, dict) else {}
            payload_ai_system_id = str(payload.get("ai_system_id") or "").strip()
            if (row.resource_type == "ai_system" and row.resource_id == ai_system_id) or payload_ai_system_id == ai_system_id:
                filtered_governance_rows.append(row)
        governance_audit_rows = filtered_governance_rows

    posture_views = build_control_posture_views(db, tenant_id=tenant_id, ai_system_id=ai_system_id)

    explanations: list[dict[str, Any]] = []
    for maturity in maturities:
        try:
            explanations.append(
                get_maturity_score_explanation(
                    db,
                    tenant_id=tenant_id,
                    ai_system_id=maturity.ai_system_id,
                    control_id=maturity.control_id,
                )
            )
        except ValueError:
            continue

    linked_node_ids: set[str] = set()
    for event in events:
        for node_id in (event.evidence_nodes_created or []):
            if node_id:
                linked_node_ids.add(str(node_id))
    for finding in findings:
        for node_id in (finding.evidence_node_ids or []):
            if node_id:
                linked_node_ids.add(str(node_id))
    for conflict in conflicts:
        for node_id in (conflict.evidence_node_ids or []):
            if node_id:
                linked_node_ids.add(str(node_id))
    for trigger in runtime_triggers:
        for node_id in (trigger.evidence_node_ids or []):
            if node_id:
                linked_node_ids.add(str(node_id))
    for recommendation in runtime_recommendations:
        payload = recommendation.payload if isinstance(recommendation.payload, dict) else {}
        for node_id in (payload.get("evidence_node_ids") or []):
            if node_id:
                linked_node_ids.add(str(node_id))
    for edge in runtime_behavior_edges:
        if edge.evidence_node_id:
            linked_node_ids.add(str(edge.evidence_node_id))
    for explanation in explanations:
        for node in ((explanation.get("evidence_links") or {}).get("evidence_nodes") or []):
            node_id = node.get("node_id")
            if node_id:
                linked_node_ids.add(str(node_id))

    evidence_nodes = db.scalars(
        select(EvidenceNode).where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.id.in_(linked_node_ids) if linked_node_ids else EvidenceNode.id == "__none__",
        )
    ).all()
    evidence_links = [
        {
            "node_id": node.id,
            "signal_type": node.signal_type,
            "label": node.label,
            "timestamp": node.created_at,
            "path": "/trust-center/evidence/nodes",
        }
        for node in evidence_nodes
    ]

    onprem_refs = _collect_onprem_evidence_references(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
    )
    evidence_links = [*evidence_links, *onprem_refs]

    monitoring_evidence_query = select(EvidenceNode).where(
        EvidenceNode.tenant_id == tenant_id,
        EvidenceNode.node_type.in_(
            [
                "monitoring_signal",
                "integration_signal",
                "connector_pull",
                "remediation_candidate",
            ]
        )
    )
    monitoring_evidence_query = _apply_time_window(
        monitoring_evidence_query,
        EvidenceNode.created_at,
        start=start_at,
        end=end_at,
    )
    monitoring_evidence_rows = db.scalars(monitoring_evidence_query.order_by(desc(EvidenceNode.created_at)).limit(500)).all()
    monitoring_refs: list[dict[str, Any]] = []
    for node in monitoring_evidence_rows:
        payload = node.payload if isinstance(node.payload, dict) else {}
        payload_ai_system_id = str(payload.get("ai_system_id") or "").strip()
        if ai_system_id and payload_ai_system_id and payload_ai_system_id != ai_system_id:
            continue
        monitoring_refs.append(
            {
                "node_id": node.id,
                "node_type": node.node_type,
                "signal_type": node.signal_type,
                "label": node.label,
                "timestamp": node.created_at,
                "path": "/monitoring/connectors",
            }
        )
    evidence_links = [*evidence_links, *monitoring_refs]

    monitoring_signal_query = select(MonitoringSignal).where(MonitoringSignal.tenant_id == tenant_id)
    if ai_system_id:
        monitoring_signal_query = monitoring_signal_query.where(MonitoringSignal.ai_system_id == ai_system_id)
    monitoring_signal_query = _apply_time_window(monitoring_signal_query, MonitoringSignal.created_at, start=start_at, end=end_at)
    monitoring_signal_rows = db.scalars(monitoring_signal_query.order_by(desc(MonitoringSignal.created_at)).limit(1000)).all()
    runtime_monitoring_rows = [row for row in monitoring_signal_rows if str(row.signal_type or "").startswith("runtime_intelligence.")]
    latest_monitoring_signal_at = monitoring_signal_rows[0].created_at if monitoring_signal_rows else None

    control_status_rows = [
        {
            "ai_system_id": maturity.ai_system_id,
            "control_id": maturity.control_id,
            "status": maturity.status,
            "confidence_score": maturity.confidence_score,
            "maturity_score": maturity.maturity_score,
            "technical_enforcement_score": maturity.technical_enforcement_score,
            "simulation_pass_rate": maturity.simulation_pass_rate,
            "coverage_score": maturity.coverage_score,
            "confidence_inputs": maturity.confidence_inputs,
        }
        for maturity in maturities
    ]

    runtime_correlated_findings = [row for row in findings if _is_runtime_correlated_finding(row.finding_type)]
    behavior_graph_references = [
        {
            "edge_id": edge.id,
            "event_id": edge.event_id,
            "ai_system_id": edge.ai_system_id,
            "relationship_type": edge.relationship_type,
            "source_node_type": edge.source_node_type,
            "source_node_id": edge.source_node_id,
            "target_node_type": edge.target_node_type,
            "target_node_id": edge.target_node_id,
            "evidence_node_id": edge.evidence_node_id,
            "created_at": edge.created_at,
            "path": f"/runtime-intelligence/graph/{edge.ai_system_id}" if edge.ai_system_id else "/runtime-intelligence/events",
        }
        for edge in runtime_behavior_edges
    ]
    need_to_know_attempts: list[dict[str, Any]] = []
    for row in runtime_events:
        metadata = row.metadata_json if isinstance(row.metadata_json, dict) else {}
        disclosure = metadata.get("knowledge_disclosure_event") if isinstance(metadata.get("knowledge_disclosure_event"), dict) else {}
        if not disclosure:
            continue
        need_decision = metadata.get("need_to_know_decision") if isinstance(metadata.get("need_to_know_decision"), dict) else {}
        knowledge_asset_ids = [
            str(item).strip()
            for item in (disclosure.get("knowledge_asset_ids") or metadata.get("knowledge_asset_ids") or [])
            if str(item).strip()
        ]
        need_to_know_attempts.append(
            {
                "runtime_event_id": row.event_id,
                "user_id": disclosure.get("user_id") or row.user_id,
                "agent_id": disclosure.get("agent_id") or row.agent_id,
                "ai_system_id": disclosure.get("ai_system_id") or row.ai_system_id,
                "prompt_intent": disclosure.get("prompt_intent") or metadata.get("original_intent"),
                "knowledge_asset_ids": knowledge_asset_ids,
                "sensitivity_domain": disclosure.get("sensitivity_domain") or metadata.get("sensitivity_domain"),
                "decision": disclosure.get("decision") or need_decision.get("decision") or row.decision,
                "policy_id": disclosure.get("policy_id") or need_decision.get("policy_id") or row.policy_version_id,
                "evidence_refs": list(disclosure.get("evidence_refs") or need_decision.get("evidence_refs") or []),
                "correlation_id": row.correlation_id,
                "created_at": row.created_at,
                "path": "/runtime-intelligence/events",
            }
        )
    need_to_know_domains = sorted(
        {
            str(item.get("sensitivity_domain") or "").strip().lower()
            for item in need_to_know_attempts
            if str(item.get("sensitivity_domain") or "").strip()
        }
    )
    need_to_know_report = {
        "protected_domain_count": len(need_to_know_domains),
        "disclosure_attempt_count": len(need_to_know_attempts),
        "blocked_or_restricted_count": sum(
            1
            for item in need_to_know_attempts
            if str(item.get("decision") or "").strip().lower() in {"block", "redact", "step_up", "hold_for_approval"}
        ),
        "protected_domains": need_to_know_domains,
        "ai_system_ids": sorted(
            {
                str(item.get("ai_system_id") or "").strip()
                for item in need_to_know_attempts
                if str(item.get("ai_system_id") or "").strip()
            }
        ),
        "user_ids": sorted(
            {
                str(item.get("user_id") or "").strip()
                for item in need_to_know_attempts
                if str(item.get("user_id") or "").strip()
            }
        ),
        "agent_ids": sorted(
            {
                str(item.get("agent_id") or "").strip()
                for item in need_to_know_attempts
                if str(item.get("agent_id") or "").strip()
            }
        ),
        "disclosure_attempts": need_to_know_attempts[:500],
    }
    pilot_user_activity = _build_pilot_user_activity_report(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        start_at=start_at,
        end_at=end_at,
    )
    runtime_section = {
        "runtime_event_count": len(runtime_events),
        "runtime_correlated_finding_count": len(runtime_correlated_findings),
        "behavior_graph_edge_count": len(runtime_behavior_edges),
        "runtime_trigger_count": len(runtime_triggers),
        "runtime_governance_recommendation_count": len(runtime_recommendations),
        "behavior_graph_references": behavior_graph_references[:500],
        "runtime_events": [
            {
                "event_id": row.event_id,
                "source_surface": row.source_surface,
                "event_type": row.event_type,
                "ai_system_id": row.ai_system_id,
                "severity": row.severity,
                "correlation_id": row.correlation_id,
                "created_at": row.created_at,
                "path": "/runtime-intelligence/events",
            }
            for row in runtime_events[:500]
        ],
        "runtime_triggers": [
            {
                "trigger_id": row.trigger_id,
                "event_id": row.event_id,
                "reason_code": row.reason_code,
                "target_pack": row.target_pack,
                "status": row.status,
                "schedule_decision_id": row.schedule_decision_id,
                "related_control_ids": row.related_control_ids,
                "created_at": row.created_at,
                "path": "/runtime-intelligence/triggers",
            }
            for row in runtime_triggers[:500]
        ],
        "runtime_governance_recommendations": [
            {
                "recommendation_id": row.recommendation_id,
                "event_id": row.event_id,
                "recommendation_type": row.recommendation_type,
                "reason_code": row.reason_code,
                "priority": row.priority,
                "status": row.status,
                "created_at": row.created_at,
                "applied_at": row.applied_at,
                "path": "/runtime-intelligence/recommendations",
            }
            for row in runtime_recommendations[:500]
        ],
    }

    findings_rows = [
        {
            "finding_id": row.finding_id,
            "source_surface": row.source_surface,
            "finding_type": row.finding_type,
            "risk_category": row.risk_category,
            "severity": row.severity,
            "status": row.status,
            "ai_system_id": row.ai_system_id,
            "ai_tool": row.ai_tool,
            "occurrence_count": row.occurrence_count,
            "related_control_ids": row.related_control_ids,
            "evidence_node_ids": row.evidence_node_ids,
            "last_seen_at": row.last_seen_at,
            "path": "/findings",
        }
        for row in findings
    ]

    monitoring_section = {
        "monitoring_signal_count": len(monitoring_signal_rows),
        "drift_alert_count": len(drift_alerts),
        "monitoring_signals": [
            {
                "signal_id": row.id,
                "signal_type": row.signal_type,
                "severity": row.severity,
                "ai_system_id": row.ai_system_id,
                "created_at": row.created_at,
                "path": "/monitoring/signals",
            }
            for row in monitoring_signal_rows[:500]
        ],
        "drift_alerts": [
            {
                "drift_alert_id": row.id,
                "title": row.title,
                "status": row.status,
                "details": row.details,
                "ai_system_id": row.ai_system_id,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
                "path": "/monitoring/drift-alerts",
            }
            for row in drift_alerts[:500]
        ],
    }

    validation_section = {
        "simulation_schedule_decision_count": len(schedule_decisions),
        "simulation_run_count": len(simulation_runs),
        "simulation_trigger_history": [
            {
                "schedule_decision_id": row.id,
                "reason_code": row.reason_code,
                "target_ai_system_id": row.target_ai_system_id,
                "target_control_ids": row.target_control_ids,
                "status": row.status,
                "scheduled_at": row.scheduled_at,
                "started_at": row.started_at,
                "finished_at": row.finished_at,
                "scheduled_simulation_ids": row.scheduled_simulation_ids,
                "simulation_run_ids": row.simulation_run_ids,
                "path": "/simulations/runs",
            }
            for row in schedule_decisions[:500]
        ],
        "simulation_outcomes": [
            {
                "simulation_run_id": row.id,
                "simulation_id": row.simulation_id,
                "ai_system_id": row.ai_system_id,
                "mode": row.mode,
                "started_at": row.started_at,
                "finished_at": row.finished_at,
                "result": (row.results or {}).get("result"),
                "controls_impacted": row.controls_impacted,
                "path": "/simulations/runs",
            }
            for row in simulation_runs[:500]
        ],
    }

    executive_pilot_activity = _build_executive_pilot_activity_section(pilot_user_activity)
    safe_pilot_user_activity = _sanitize_pilot_user_activity_for_export(pilot_user_activity)
    safe_executive_pilot_activity = _sanitize_executive_pilot_activity_for_export(executive_pilot_activity)

    executive_report = build_executive_report(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        period_start=period_start,
        period_end=period_end,
        findings=findings,
        runtime_events=runtime_events,
    )
    executive_sections = dict(executive_report.get("sections") or {})
    executive_sections["pilot_user_activity"] = executive_pilot_activity
    executive_report["sections"] = executive_sections
    executive_summary = dict(executive_report.get("summary") or {})
    executive_summary["pilot_prompt_count"] = pilot_user_activity.get("prompt_count", 0)
    executive_summary["pilot_violation_count"] = pilot_user_activity.get("violation_count", 0)
    executive_summary["pilot_shadow_ai_asset_count"] = pilot_user_activity.get("shadow_ai_asset_count", 0)
    executive_report["summary"] = executive_summary

    governance_state_changes = [
        {
            "audit_log_id": row.id,
            "action": row.action,
            "resource_type": row.resource_type,
            "resource_id": row.resource_id,
            "created_at": row.created_at,
            "correlation_id": row.correlation_id,
            "payload": row.payload if isinstance(row.payload, dict) else {},
            "path": "/trust-center/audit-logs",
        }
        for row in governance_audit_rows
    ]

    json_payload = {
        "tenant_id": tenant_id,
        "ai_system_id": ai_system_id,
        "period_start": period_start,
        "period_end": period_end,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "control_status": control_status_rows,
        "maturity_explanations": explanations,
        "evidence_links": evidence_links,
        "onprem_evidence_references": onprem_refs,
        "continuous_monitoring_inputs": {
            "monitoring_signal_count": len(monitoring_signal_rows),
            "runtime_intelligence_signal_count": len(runtime_monitoring_rows),
            "monitoring_evidence_count": len(monitoring_refs),
            "latest_monitoring_signal_at": latest_monitoring_signal_at.isoformat() if latest_monitoring_signal_at else None,
        },
        "runtime_intelligence_inputs": runtime_section,
        "need_to_know_report": need_to_know_report,
        "pilot_user_activity": pilot_user_activity,
        "monitoring_inputs": monitoring_section,
        "validation_inputs": validation_section,
        "findings": findings_rows,
        "control_posture_views": posture_views,
        "governance_state_changes": governance_state_changes,
        "executive_report": executive_report,
        "approval_decisions": [
            {
                "approval_id": approval.id,
                "ai_system_id": approval.ai_system_id,
                "status": approval.status,
                "decision": approval.decision,
                "required_roles": approval.required_roles,
                "sla_minutes": approval.sla_minutes,
                "default_if_timeout": approval.default_if_timeout,
                "created_at": approval.created_at,
                "decided_at": approval.decided_at,
                "enforcement_event_id": approval.enforcement_event_id,
            }
            for approval in approvals
        ],
        "enforcement_events": [
            {
                "event_id": event.id,
                "ai_system_id": event.ai_system_id,
                "request_id": event.request_id,
                "final_decision": event.final_decision,
                "policy_version_id": event.policy_version_id,
                "timestamp": event.timestamp,
                "controls_impacted": event.controls_impacted,
                "evidence_nodes_created": event.evidence_nodes_created,
            }
            for event in events
        ],
        "conflicts": [
            {
                "conflict_id": conflict.id,
                "ai_system_id": conflict.ai_system_id,
                "control_id": conflict.control_id,
                "status": conflict.status,
                "reason": conflict.reason,
                "positive_signals": conflict.positive_signals,
                "negative_signals": conflict.negative_signals,
                "detected_at": conflict.detected_at,
                "resolved_at": conflict.resolved_at,
                "resolution_decision": conflict.resolution_decision,
                "resolution_notes": conflict.resolution_notes,
                "details": conflict.details,
                "audit_log_id": conflict.audit_log_id,
                "evidence_node_ids": conflict.evidence_node_ids,
            }
            for conflict in conflicts
        ],
        "conflict_resolutions": [
            {
                "resolution_id": row.id,
                "conflict_id": row.conflict_id,
                "ai_system_id": row.ai_system_id,
                "control_id": row.control_id,
                "chosen_evidence_id": row.chosen_evidence_id,
                "discarded_evidence_ids": row.discarded_evidence_ids,
                "reason": row.reason,
                "created_at": row.created_at,
            }
            for row in conflict_resolutions
        ],
    }

    json_payload = sanitize_privacy_payload(json_payload)
    json_payload["pilot_user_activity"] = safe_pilot_user_activity
    json_executive_report = json_payload.get("executive_report")
    if isinstance(json_executive_report, dict):
        json_executive_sections = dict(json_executive_report.get("sections") or {})
        json_executive_sections["pilot_user_activity"] = safe_executive_pilot_activity
        json_executive_report["sections"] = json_executive_sections
    json_bytes = json.dumps(json_payload, indent=2, default=str).encode("utf-8")
    try:
        json_path.write_bytes(json_bytes)
    except OSError as exc:
        raise RuntimeError(f"Failed to write JSON artifact '{json_path}': {exc}") from exc

    explanation_by_key = {
        (row["ai_system_id"], row["control_id"]): row
        for row in explanations
    }
    latest_approval_by_system = _latest_approval_by_ai_system(approvals)
    latest_event_by_system = _latest_event_by_ai_system(events)

    conflict_by_control: dict[tuple[str, str], ControlConflict] = {}
    for conflict in conflicts:
        key = (conflict.ai_system_id, conflict.control_id)
        current = conflict_by_control.get(key)
        if not current or conflict.detected_at > current.detected_at:
            conflict_by_control[key] = conflict

    csv_buffer = io.StringIO()
    writer = csv.DictWriter(
        csv_buffer,
        fieldnames=[
            "ai_system_id",
            "control_id",
            "control_status",
            "implementation_state",
            "implementation_reason",
            "domain",
            "frameworks",
            "confidence_score",
            "maturity_score",
            "technical_enforcement_score",
            "simulation_pass_rate",
            "coverage_score",
            "evidence_count",
            "latest_approval_decision",
            "latest_enforcement_decision",
            "conflict_state",
        ],
    )
    writer.writeheader()

    for maturity in maturities:
        key = (maturity.ai_system_id, maturity.control_id)
        explanation = explanation_by_key.get(key, {})
        explanation_evidence = ((explanation.get("evidence_links") or {}).get("evidence_nodes") or [])
        latest_approval = latest_approval_by_system.get(maturity.ai_system_id)
        latest_event = latest_event_by_system.get(maturity.ai_system_id)
        conflict = conflict_by_control.get(key)
        implementation_state = str(
            explanation.get("implementation_state")
            or _maturity_implementation_state(
                technical=float(maturity.technical_enforcement_score),
                simulation_pass_rate=float(maturity.simulation_pass_rate),
                coverage=float(maturity.coverage_score),
                maturity=float(maturity.maturity_score),
                status=str(maturity.status or ""),
            )
        )
        implementation_reason = "; ".join(
            list(
                explanation.get("implementation_reasoning")
                or _maturity_implementation_reasoning(
                    technical=float(maturity.technical_enforcement_score),
                    simulation_pass_rate=float(maturity.simulation_pass_rate),
                    coverage=float(maturity.coverage_score),
                    maturity=float(maturity.maturity_score),
                    status=str(maturity.status or ""),
                )
            )
        )
        domain = str(explanation.get("domain") or "unknown")
        frameworks = ",".join([str(item).strip() for item in (explanation.get("frameworks") or []) if str(item).strip()])

        writer.writerow(
            {
                "ai_system_id": maturity.ai_system_id,
                "control_id": maturity.control_id,
                "control_status": maturity.status,
                "implementation_state": implementation_state,
                "implementation_reason": implementation_reason,
                "domain": domain,
                "frameworks": frameworks,
                "confidence_score": round(maturity.confidence_score, 6),
                "maturity_score": round(maturity.maturity_score, 6),
                "technical_enforcement_score": round(maturity.technical_enforcement_score, 6),
                "simulation_pass_rate": round(maturity.simulation_pass_rate, 6),
                "coverage_score": round(maturity.coverage_score, 6),
                "evidence_count": len(explanation_evidence),
                "latest_approval_decision": (latest_approval.decision if latest_approval else None),
                "latest_enforcement_decision": (latest_event.final_decision if latest_event else None),
                "conflict_state": (conflict.status if conflict else "none"),
            }
        )

    csv_bytes = csv_buffer.getvalue().encode("utf-8")
    try:
        csv_path.write_bytes(csv_bytes)
    except OSError as exc:
        raise RuntimeError(f"Failed to write CSV artifact '{csv_path}': {exc}") from exc

    evidence_pack_relative_path = f"audit_evidence_pack_{tenant_id}_{stamp}.json"
    evidence_pack_path = artifact_dir / evidence_pack_relative_path
    edge_rows, evidence_edges_truncated = _collect_bounded_evidence_edges(
        db,
        tenant_id=tenant_id,
        linked_node_ids=linked_node_ids,
    )
    evidence_pack_payload = {
        "tenant_id": tenant_id,
        "ai_system_id": ai_system_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_nodes": [
            {
                "node_id": node.id,
                "node_type": node.node_type,
                "signal_type": node.signal_type,
                "label": node.label,
                "payload": sanitize_privacy_payload(node.payload if isinstance(node.payload, dict) else {}),
                "correlation_id": node.correlation_id,
                "created_at": node.created_at,
            }
            for node in evidence_nodes
        ],
        "evidence_edges": [
            {
                "edge_id": row.id,
                "from_node_id": row.from_node_id,
                "to_node_id": row.to_node_id,
                "edge_type": row.edge_type,
                "payload": sanitize_privacy_payload(row.payload if isinstance(row.payload, dict) else {}),
                "created_at": row.created_at,
            }
            for row in edge_rows
        ],
        "runtime_behavior_references": behavior_graph_references[:500],
    }
    evidence_pack_payload = sanitize_privacy_payload(evidence_pack_payload)
    evidence_pack_payload["integrity"] = {
        "integrity_status": "valid",
        "hash_algorithm": "sha256",
        "payload_sha256": _canonical_payload_sha256(evidence_pack_payload),
        "evidence_node_count": len(evidence_pack_payload.get("evidence_nodes") or []),
        "evidence_edge_count": len(evidence_pack_payload.get("evidence_edges") or []),
        "evidence_edge_limit": AUDITOR_EVIDENCE_EDGE_LIMIT,
        "evidence_edges_truncated": evidence_edges_truncated,
        "evidence_edge_scope": "outgoing_from_selected_evidence",
        "runtime_behavior_reference_count": len(evidence_pack_payload.get("runtime_behavior_references") or []),
        "redaction_policy": "privacy_sanitizer",
    }
    evidence_pack_bytes = json.dumps(evidence_pack_payload, indent=2, default=str).encode("utf-8")
    try:
        evidence_pack_path.write_bytes(evidence_pack_bytes)
    except OSError as exc:
        raise RuntimeError(f"Failed to write evidence-pack artifact '{evidence_pack_path}': {exc}") from exc

    pdf_ready_relative_path = f"audit_pdf_ready_{tenant_id}_{stamp}.json"
    pdf_ready_path = artifact_dir / pdf_ready_relative_path
    pdf_relative_path = f"audit_executive_report_{tenant_id}_{stamp}.pdf"
    pdf_path = artifact_dir / pdf_relative_path
    renderer_available = _pdf_renderer_available()
    pdf_ready_payload = {
        "tenant_id": tenant_id,
        "ai_system_id": ai_system_id,
        "title": "Automated Auditor Continuous Proof Pack",
        "subtitle": "PDF-ready data model",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "renderer_available": renderer_available,
        "renderer": "simple_pdf",
        "summary": {
            "findings_count": len(findings_rows),
            "runtime_event_count": len(runtime_events),
            "drift_alert_count": len(drift_alerts),
            "simulation_run_count": len(simulation_runs),
            "governance_change_count": len(governance_state_changes),
            "open_conflict_count": len([row for row in conflicts if str(row.status) == "open"]),
        },
        "posture_views": posture_views,
        "sections": {
            "runtime_intelligence": runtime_section,
            "pilot_user_activity": pilot_user_activity,
            "monitoring": monitoring_section,
            "validation": validation_section,
            "governance": {"state_changes": governance_state_changes},
            "executive_report": executive_report,
        },
        "artifact_links": {
            "json": json_relative_path,
            "csv": csv_relative_path,
            "evidence_pack": evidence_pack_relative_path,
            "pdf": pdf_relative_path,
        },
    }
    pdf_ready_payload = sanitize_privacy_payload(pdf_ready_payload)
    pdf_ready_sections = pdf_ready_payload.get("sections")
    if isinstance(pdf_ready_sections, dict):
        pdf_ready_sections["pilot_user_activity"] = safe_pilot_user_activity
        pdf_ready_executive_report = pdf_ready_sections.get("executive_report")
        if isinstance(pdf_ready_executive_report, dict):
            pdf_ready_executive_sections = dict(pdf_ready_executive_report.get("sections") or {})
            pdf_ready_executive_sections["pilot_user_activity"] = safe_executive_pilot_activity
            pdf_ready_executive_report["sections"] = pdf_ready_executive_sections
    pdf_ready_bytes = json.dumps(pdf_ready_payload, indent=2, default=str).encode("utf-8")
    try:
        pdf_ready_path.write_bytes(pdf_ready_bytes)
    except OSError as exc:
        raise RuntimeError(f"Failed to write PDF-ready artifact '{pdf_ready_path}': {exc}") from exc

    try:
        render_executive_report_pdf(executive_report, output_path=pdf_path)
        pdf_bytes = pdf_path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"Failed to write executive PDF artifact '{pdf_path}': {exc}") from exc

    artifact_hashes = {
        "json": _sha256_hex(json_bytes),
        "csv": _sha256_hex(csv_bytes),
        "evidence_pack": _sha256_hex(evidence_pack_bytes),
        "pdf_ready_model": _sha256_hex(pdf_ready_bytes),
        "pdf": _sha256_hex(pdf_bytes),
    }
    artifact_hash = _sha256_hex(json.dumps(artifact_hashes, sort_keys=True).encode("utf-8"))
    return {
        "json": json_relative_path,
        "csv": csv_relative_path,
        "evidence_pack": evidence_pack_relative_path,
        "pdf_ready_model": pdf_ready_relative_path,
        "pdf": pdf_relative_path,
        "artifact_hashes": artifact_hashes,
        "pdf_renderer": "simple_pdf",
        "pdf_renderer_available": renderer_available,
        "json_relative_path": json_relative_path,
        "csv_relative_path": csv_relative_path,
        "evidence_pack_relative_path": evidence_pack_relative_path,
        "pdf_ready_relative_path": pdf_ready_relative_path,
        "pdf_relative_path": pdf_relative_path,
        "hash": artifact_hash,
    }
