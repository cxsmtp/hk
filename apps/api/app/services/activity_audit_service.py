from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import re
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.orm import Session

from app.api.envelopes import paginate_rows
from app.core.config import settings
from app.core.control_engine.canonical_action import maybe_dual_write_canonical_action
from app.db.models.activity_audit import AIAction, AIActionAlert, AISession, DeploymentEndpoint, PromptPayload, UserRegistry
from app.db.models.user import User, UserTenantRole
from app.services.hmair.discovery_context_provider import DiscoveryContextProvider
from app.services.user_visibility_service import project_prompt_payload


ALLOWED_STORAGE_MODES = {"full", "redacted", "hashed_only"}
ENFORCEMENT_ACTION_MAP = {
    "allow": "allowed",
    "allowed": "allowed",
    "approve": "allowed",
    "approved": "allowed",
    "warn": "warned",
    "warning": "warned",
    "warned": "warned",
    "redact": "modified",
    "modify": "modified",
    "modified": "modified",
    "block": "blocked",
    "blocked": "blocked",
    "deny": "blocked",
    "denied": "blocked",
    "hold": "held",
    "held": "held",
    "require_approval": "held",
    "hold_for_approval": "held",
    "require_justification": "held",
}
NEGATIVE_ENFORCEMENT_ACTIONS = {"blocked", "warned", "modified", "held"}
ALERT_TYPE_MAX_LENGTH = 128
ACTION_ID_MAX_LENGTH = 64
AI_APP_MAX_LENGTH = 255
AI_MODEL_MAX_LENGTH = 255
DATA_CLASSIFICATION_MAX_LENGTH = 32
POLICY_TRIGGERED_MAX_LENGTH = 255
SEVERITY_RISK_BASE = {
    "low": 0.2,
    "med": 0.5,
    "medium": 0.5,
    "high": 0.8,
    "critical": 0.95,
}
DEPLOYMENT_ENDPOINT_SHORT_FIELD_MAX_LENGTH = 64

EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\-\s().]{7,}\d)(?!\d)")
# Record ids and hex digests are kept as they are (a UUID's digit run is not a phone number).
IDENTIFIER_RE = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{32,})(?![0-9A-Fa-f])"
)
ISO_DATETIME_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}"
    r"(?:[T ][0-2]\d:[0-5]\d(?::[0-5]\d(?:\.\d{1,6})?)?(?:Z|[+-][0-2]\d:?[0-5]\d)?)?\b"
)
CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
API_KEY_RE = re.compile(r"(?i)\b(?:api[_-]?key|secret|private[_ -]?key|token)\b[\s:=]{0,3}[A-Za-z0-9_\-]{6,}")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _to_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str) and value.strip():
        raw = value.strip()
        try:
            if raw.endswith("Z"):
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
            parsed = datetime.fromisoformat(raw)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            return _now()
    return _now()


def _bounded_endpoint_string(value: Any, *, max_length: int = DEPLOYMENT_ENDPOINT_SHORT_FIELD_MAX_LENGTH) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    return text[:max_length]


def _normalize_surface(value: Any, *, fallback: str = "browser") -> str:
    normalized = str(value or fallback).strip().lower()
    return normalized or fallback


def _normalize_enforcement_action(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return "allowed"
    if normalized in ENFORCEMENT_ACTION_MAP:
        return ENFORCEMENT_ACTION_MAP[normalized]
    if "block" in normalized or "deny" in normalized:
        return "blocked"
    if "warn" in normalized:
        return "warned"
    if "hold" in normalized or "approval" in normalized or "justification" in normalized:
        return "held"
    if "mod" in normalized or "redact" in normalized:
        return "modified"
    return "allowed"


def _nested_value(source: Any, *path: str) -> Any:
    current = source
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _first_present(*values: Any) -> Any:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return None


def _is_placeholder_app(value: Any) -> bool:
    token = str(value or "").strip().lower()
    return token in {"", "unknown", "desktop-native", "desktop_native", "native", "endpoint-agent", "endpoint_agent"}


def _host_from_url(value: Any) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    parsed = urlparse(raw)
    if parsed.netloc:
        return parsed.netloc.lower()
    return None


def _derive_source_surface(body: dict[str, Any]) -> Any:
    metadata = body.get("metadata") if isinstance(body.get("metadata"), dict) else {}
    body_surface = _first_present(body.get("source_surface"), body.get("source_surface_type"), body.get("surface"))
    evidence_surface = _first_present(
        metadata.get("source_surface"),
        _nested_value(metadata, "ai_action", "surface", "source_surface"),
        _nested_value(metadata, "policy_snapshot", "assigned_scope", "source_surface"),
    )
    if str(body_surface or "").strip().lower() in {"endpoint_agent", "endpoint-agent", "desktop-native"} and evidence_surface:
        return evidence_surface
    return _first_present(
        body_surface,
        evidence_surface,
    )


def _derive_ai_app(body: dict[str, Any]) -> tuple[str | None, str | None]:
    metadata = body.get("metadata") if isinstance(body.get("metadata"), dict) else {}
    candidates = (
        body.get("ai_app"),
        body.get("domain"),
        body.get("destination_domain"),
        body.get("application"),
        _nested_value(metadata, "ai_action", "surface", "application"),
        _nested_value(metadata, "ai_action", "surface", "domain"),
        _nested_value(metadata, "context", "page_context", "domain"),
        _nested_value(metadata, "context", "app_context", "app_domain"),
        _nested_value(metadata, "context", "app_context", "app_name"),
        _nested_value(metadata, "policy_snapshot", "assigned_scope", "application"),
        _nested_value(metadata, "policy_snapshot", "assigned_scope", "domain"),
        _host_from_url(body.get("url") or body.get("active_url") or body.get("tab_url")),
        _host_from_url(_nested_value(metadata, "ai_action", "surface", "url")),
        _host_from_url(_nested_value(metadata, "context", "page_context", "url")),
        _host_from_url(_nested_value(metadata, "device_context", "url")),
    )
    fallback: Any = None
    for candidate in candidates:
        if candidate is None:
            continue
        fallback = fallback or candidate
        if not _is_placeholder_app(candidate):
            return _display_app_value(candidate)
    return _display_app_value(fallback)


def _derive_enforcement_action(body: dict[str, Any]) -> str:
    metadata = body.get("metadata") if isinstance(body.get("metadata"), dict) else {}
    explicit = _first_present(body.get("enforcement_action"), body.get("action_taken"), body.get("decision"))
    governance_mode = _first_present(body.get("governance_enforcement_mode"), metadata.get("governance_enforcement_mode"))
    shadow_decision = _first_present(
        _nested_value(metadata, "authorization_kernel_v2_shadow", "v2", "decision"),
        _nested_value(metadata, "ai_action", "policy", "decision"),
    )
    explicit_normalized = _normalize_enforcement_action(explicit)
    governance_normalized = _normalize_enforcement_action(governance_mode)
    shadow_normalized = _normalize_enforcement_action(shadow_decision)
    # Record the execution outcome when one was supplied. A shadow comparison
    # or desired governance mode does not prove that the action was blocked.
    if explicit:
        return explicit_normalized
    if governance_normalized == "blocked" or shadow_normalized == "blocked":
        return "blocked"
    if governance_mode:
        return governance_normalized
    if shadow_decision:
        return shadow_normalized
    return "allowed"


def _alert_type_for_action(policy_triggered: Any, action_type: Any) -> str:
    """Keep alert type compact; full reason-code lists belong in policy_reason."""
    raw = str(policy_triggered or "").strip()
    first_reason = next((part.strip() for part in raw.split(",") if part.strip()), "")
    normalized = first_reason or str(action_type or "policy_event").strip() or "policy_event"
    return normalized[:ALERT_TYPE_MAX_LENGTH]


def _normalize_device_type(value: Any) -> str | None:
    normalized = str(value or "").strip().lower()
    if normalized in {"laptop", "desktop", "vm"}:
        return normalized
    return None


def _normalize_os_type(value: Any) -> str | None:
    normalized = str(value or "").strip().lower()
    if normalized in {"mac", "windows", "linux"}:
        return normalized
    if normalized in {"macos", "darwin"}:
        return "mac"
    if normalized in {"win", "win32"}:
        return "windows"
    return None


def _normalize_browser_type(value: Any) -> str | None:
    normalized = str(value or "").strip().lower()
    if normalized in {"chrome", "edge", "firefox", "safari"}:
        return normalized
    return None


def _display_extension_name(value: Any, *, fallback_source_surface: Any = None, extension_version: Any = None) -> str | None:
    token = str(value or "").strip()
    if token and token.lower() not in {"unknown", "unknown_extension", "extension:unknown"}:
        return token[:128]
    source_surface = str(fallback_source_surface or "").strip().lower()
    if str(extension_version or "").strip() or source_surface in {"browser", "browser_extension"}:
        return "AI Control Plane - Discovery & Guard"
    return None


def _display_browser_name(value: Any) -> str | None:
    token = str(value or "").strip().lower()
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


def _display_os_name(value: Any) -> str | None:
    token = str(value or "").strip().lower()
    if token == "mac":
        return "macOS"
    if token == "windows":
        return "Windows"
    if token == "linux":
        return "Linux"
    if token:
        return token.replace("_", " ").title()
    return None


def _derive_endpoint_id(
    *,
    tenant_id: str,
    user_id: str | None,
    browser_profile: str | None,
    browser_type: str | None,
    extension_version: str | None,
    fallback_seed: str | None = None,
    explicit_endpoint_id: str | None = None,
) -> str:
    if explicit_endpoint_id and explicit_endpoint_id.strip():
        return explicit_endpoint_id.strip()[:64]
    seed = "|".join(
        [
            tenant_id,
            str(user_id or "anonymous"),
            str(browser_profile or "default"),
            str(browser_type or "unknown"),
            str(extension_version or "unknown"),
            str(fallback_seed or ""),
        ]
    )
    return f"ep_{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:28]}"


def _build_endpoint_collision_seed(*, explicit_endpoint_id: str | None, device_context: dict[str, Any]) -> str:
    # Keep fallback deterministic across events for the same tenant/device identity.
    # Avoid per-event inputs (for example correlation_id) to prevent endpoint fragmentation.
    parts = [
        str(explicit_endpoint_id or "").strip().lower(),
        str(device_context.get("browser_profile") or "default").strip().lower(),
        str(device_context.get("browser_type") or "").strip().lower(),
        str(device_context.get("extension_version") or "").strip().lower(),
        str(device_context.get("hostname") or "").strip().lower(),
        str(device_context.get("device_type") or "").strip().lower(),
        str(device_context.get("os_type") or "").strip().lower(),
        str(device_context.get("os_version") or "").strip().lower(),
    ]
    return "|".join(parts)


def _redact_prompt(value: str) -> str:
    text = str(value or "")
    if not text:
        return ""
    preserved: dict[str, str] = {}

    def preserve_datetime(match: re.Match[str]) -> str:
        token = f"__HAWK_ISO_DATETIME_{len(preserved)}__"
        preserved[token] = match.group(0)
        return token

    text = IDENTIFIER_RE.sub(preserve_datetime, text)
    text = ISO_DATETIME_RE.sub(preserve_datetime, text)
    text = EMAIL_RE.sub("[email]", text)
    text = PHONE_RE.sub("[phone]", text)
    text = CC_RE.sub("[credit_card]", text)
    text = API_KEY_RE.sub("[secret]", text)
    for token, original in preserved.items():
        text = text.replace(token, original)
    return text


def _prompt_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_bounded_text(value: Any, *, max_len: int) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if len(text) <= max_len:
        return text
    return text[:max_len]


def _safe_data_classification(value: Any) -> tuple[str | None, str | None]:
    """Return a schema-safe classification without silently changing its meaning.

    A classification that does not fit the canonical activity field is not a
    trusted class. Preserve only a digest for audit correlation and treat it as
    unknown so downstream policy/reporting cannot mistake a truncated label for
    a recognized data class.
    """
    text = str(value or "").strip()
    if not text:
        return None, None
    if len(text) <= DATA_CLASSIFICATION_MAX_LENGTH:
        return text, None
    return "unknown", _prompt_hash(text)


def _display_app_value(value: Any, *, max_len: int = AI_APP_MAX_LENGTH) -> tuple[str | None, str | None]:
    raw = str(value or "").strip()
    if not raw:
        return None, None
    lowered = raw.lower()
    if lowered.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        host = (parsed.netloc or "").lower()
        if host:
            return host[:max_len], raw
    if len(raw) <= max_len:
        return raw, None
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"value:{digest}"[:max_len], raw


def _extract_sensitive_entities(detection_result: dict[str, Any] | None) -> list[str]:
    if not isinstance(detection_result, dict):
        return []
    entities: list[str] = []
    for item in detection_result.get("entities") or []:
        if isinstance(item, dict):
            entity_name = str(item.get("entity_type") or "").strip().lower()
            if entity_name:
                entities.append(entity_name)
    return sorted(set(entities))


def _resolve_prompt_storage_mode(
    *,
    requested_mode: str | None,
    sensitivity_score: float,
    pii_detected: bool,
) -> str:
    high_threshold = float(getattr(settings, "prompt_logging_high_sensitivity_threshold", 0.75))
    if sensitivity_score >= high_threshold:
        return "hashed_only"

    requested = str(requested_mode or "").strip().lower()
    if requested in ALLOWED_STORAGE_MODES:
        mode = requested
    else:
        medium_threshold = float(getattr(settings, "prompt_logging_medium_sensitivity_threshold", 0.35))
        mode = "full"
        if sensitivity_score >= high_threshold:
            mode = "hashed_only"
        elif sensitivity_score >= medium_threshold:
            mode = "redacted"
        if pii_detected and mode == "full":
            mode = "redacted"
    allow_sensitive_raw = bool(getattr(settings, "prompt_logging_allow_sensitive_raw", False))
    if pii_detected and mode == "full" and not allow_sensitive_raw:
        return "redacted"
    return mode


def _severity_for_action(enforcement_action: str, risk_score: float, explicit: str | None = None) -> str:
    severity = str(explicit or "").strip().lower()
    if severity in {"low", "med", "medium", "high", "critical"}:
        return "med" if severity == "medium" else severity
    if enforcement_action == "blocked":
        return "high"
    if enforcement_action in {"warned", "held", "modified"}:
        return "med"
    if risk_score >= 0.9:
        return "critical"
    if risk_score >= 0.7:
        return "high"
    if risk_score >= 0.4:
        return "med"
    return "low"


def _compute_risk_score(
    *,
    explicit: float | None,
    sensitivity_score: float,
    enforcement_action: str,
    severity: str | None,
) -> float:
    if explicit is not None:
        try:
            return max(0.0, min(1.0, float(explicit)))
        except (TypeError, ValueError):
            pass
    base = max(0.0, min(1.0, float(sensitivity_score)))
    severity_base = SEVERITY_RISK_BASE.get(str(severity or "").strip().lower(), 0.0)
    enforcement_base = {
        "allowed": 0.1,
        "warned": 0.5,
        "modified": 0.55,
        "held": 0.65,
        "blocked": 0.85,
    }.get(enforcement_action, 0.1)
    return max(base, severity_base, enforcement_base)


def _extract_device_context(payload: dict[str, Any] | None) -> dict[str, Any]:
    body = dict(payload or {})
    nested = body.get("device_context")
    if isinstance(nested, dict):
        for key, value in nested.items():
            body.setdefault(key, value)

    browser_type = _normalize_browser_type(body.get("browser_type") or body.get("browser"))
    return {
        "endpoint_id": str(body.get("endpoint_id") or body.get("device_id") or body.get("installation_id") or "").strip() or None,
        "hostname": str(body.get("hostname") or "").strip() or None,
        "device_type": _normalize_device_type(body.get("device_type")),
        "os_type": _normalize_os_type(body.get("os_type") or body.get("os")),
        "os_version": _bounded_endpoint_string(body.get("os_version")),
        "browser_type": browser_type,
        "browser_version": _bounded_endpoint_string(body.get("browser_version")),
        "extension_version": _bounded_endpoint_string(body.get("extension_version")),
        "ip_address": _bounded_endpoint_string(body.get("ip_address")),
        "location": str(body.get("location") or "").strip() or None,
        "browser_profile": str(body.get("browser_profile") or "default").strip() or "default",
        "status": str(body.get("status") or "active").strip().lower() or "active",
        "metadata": {
            "source_surface": body.get("source_surface") or "browser_extension",
            "raw_os_version": str(body.get("os_version") or "").strip() or None,
            "raw_browser_version": str(body.get("browser_version") or "").strip() or None,
            "raw_extension_version": str(body.get("extension_version") or "").strip() or None,
            "extension_name": _display_extension_name(
                body.get("extension_name") or body.get("extension_display_name"),
                fallback_source_surface=body.get("source_surface") or "browser_extension",
                extension_version=body.get("extension_version"),
            ),
            "user_agent": body.get("user_agent"),
            "tab_url": body.get("url") or body.get("active_url"),
            "page_title": body.get("page_title"),
        },
    }


def _extract_session_context(payload: dict[str, Any] | None) -> dict[str, Any]:
    body = dict(payload or {})
    ai_app, raw_ai_app = _derive_ai_app(body)
    ai_model = _safe_bounded_text(body.get("ai_model") or body.get("model_name") or body.get("model"), max_len=AI_MODEL_MAX_LENGTH)
    metadata = {
        "platform_mode": body.get("platform_mode"),
        "policy_version": body.get("policy_version"),
        "source_surface": _derive_source_surface(body),
    }
    if raw_ai_app:
        metadata["raw_ai_app"] = raw_ai_app
        metadata["ai_app_compacted"] = True
    return {
        "session_id": str(body.get("session_id") or "").strip() or None,
        "source_surface": _normalize_surface(_derive_source_surface(body), fallback="browser"),
        "ai_app": ai_app,
        "ai_model": ai_model,
        "correlation_id": str(body.get("correlation_id") or "").strip() or None,
        "timestamp": _to_datetime(body.get("timestamp")),
        "metadata": metadata,
    }


def _extract_action_context(payload: dict[str, Any] | None) -> dict[str, Any]:
    body = dict(payload or {})
    action_type = str(body.get("action_type") or "").strip().lower()
    if not action_type:
        source_event_type = str(body.get("event_type") or "").strip().lower()
        if "clipboard" in source_event_type or "copy" in source_event_type or "paste" in source_event_type:
            action_type = "copy_paste"
        elif "upload" in source_event_type:
            action_type = "upload"
        elif "output" in source_event_type or "response" in source_event_type:
            action_type = "response"
        elif "tool" in source_event_type:
            action_type = "tool_call"
        else:
            action_type = "prompt_input"

    sensitivity_score = float(body.get("sensitivity_score") or body.get("sensitive_confidence_score") or 0.0)
    enforcement_action = _derive_enforcement_action(body)
    risk_score = _compute_risk_score(
        explicit=body.get("risk_score"),
        sensitivity_score=sensitivity_score,
        enforcement_action=enforcement_action,
        severity=str(body.get("severity") or ""),
    )
    ai_app, raw_ai_app = _derive_ai_app(body)
    action_metadata = dict(body.get("metadata") or {}) if isinstance(body.get("metadata"), dict) else {}
    if raw_ai_app:
        action_metadata.setdefault("raw_ai_app", raw_ai_app)
        action_metadata["ai_app_compacted"] = True
    data_classification, data_classification_hash = _safe_data_classification(
        body.get("data_classification") or body.get("source_classification_hint")
    )
    if data_classification_hash:
        action_metadata["data_classification_compacted"] = True
        action_metadata["data_classification_hash"] = data_classification_hash

    return {
        "action_id": _safe_bounded_text(body.get("action_id"), max_len=ACTION_ID_MAX_LENGTH),
        "timestamp": _to_datetime(body.get("timestamp")),
        "action_type": action_type,
        "ai_app": ai_app,
        "ai_model": _safe_bounded_text(body.get("ai_model") or body.get("model_name") or body.get("model"), max_len=AI_MODEL_MAX_LENGTH),
        "data_classification": data_classification,
        "sensitivity_score": max(0.0, min(1.0, sensitivity_score)),
        "policy_triggered": _safe_bounded_text(
            body.get("policy_triggered") or body.get("reason_code"),
            max_len=POLICY_TRIGGERED_MAX_LENGTH,
        ),
        "enforcement_action": enforcement_action,
        "semantic_drift_score": float(body.get("semantic_drift_score") or 0.0),
        "risk_score": risk_score,
        "severity": _severity_for_action(enforcement_action, risk_score, str(body.get("severity") or "")),
        "correlation_id": str(body.get("correlation_id") or "").strip() or None,
        "runtime_event_id": str(body.get("runtime_event_id") or "").strip() or None,
        "monitoring_signal_id": str(body.get("monitoring_signal_id") or "").strip() or None,
        "audit_log_id": str(body.get("audit_log_id") or "").strip() or None,
        "evidence_node_id": str(body.get("evidence_node_id") or "").strip() or None,
        "finding_id": str(body.get("finding_id") or "").strip() or None,
        "prompt_raw": str(body.get("raw_prompt") or body.get("prompt_raw") or body.get("prompt_text") or "").strip() or None,
        "prompt_preview_redacted": str(
            body.get("prompt_preview_redacted") or body.get("copied_text_preview_redacted") or ""
        ).strip()
        or None,
        "storage_mode": str(body.get("storage_mode") or body.get("prompt_storage_mode") or "").strip().lower() or None,
        "sensitive_detection": dict(body.get("sensitive_detection") or {}) if isinstance(body.get("sensitive_detection"), dict) else {},
        "metadata": action_metadata,
    }


def _discovery_asset_binding(metadata: dict[str, Any]) -> str | None:
    """Read only the dedicated Discovery binding; generic asset IDs are untrusted."""
    direct = metadata.get("discovery_asset_ref")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()
    return None


def _stored_discovery_asset_binding(context: dict[str, Any]) -> str | None:
    binding = context.get("ai_asset_ref")
    if not isinstance(binding, str) or not binding.startswith("discovery_asset:"):
        return None
    return binding if binding.removeprefix("discovery_asset:") else None


def _bound_discovery_context(metadata: dict[str, Any]) -> tuple[dict[str, Any], str] | None:
    """Return only an existing, usable Discovery projection for an idempotent action update."""
    context = metadata.get("discovery_context")
    if not isinstance(context, dict) or context.get("status") not in {"partial", "available"}:
        return None
    binding = _stored_discovery_asset_binding(context)
    if binding is None:
        return None
    return dict(context), binding


def _trusted_discovery_actor_reference(metadata: dict[str, Any]) -> str | None:
    """Only tenant-keyed metadata references may narrow Discovery usage context."""
    for key in ("actor_ref", "actor_reference_hash"):
        candidate = metadata.get(key)
        if isinstance(candidate, str) and re.fullmatch(r"[0-9a-fA-F]{64}", candidate.strip()):
            return candidate.strip().casefold()
    return None


def _attach_discovery_context(
    db: Session,
    *,
    tenant_id: str,
    user_id: str | None,
    action_context: dict[str, Any],
    action_metadata: dict[str, Any],
    existing_metadata: dict[str, Any] | None = None,
) -> None:
    """Attach Discovery projection after policy material exists; never affect persistence."""
    if not settings.discovery_context_provider:
        return
    request_metadata = dict(action_context.get("metadata") or {})
    existing = dict(existing_metadata or {})
    retained_context = _bound_discovery_context(existing)
    asset = retained_context[1] if retained_context is not None else _discovery_asset_binding(request_metadata)
    try:
        with db.begin_nested():
            context = DiscoveryContextProvider(db).get_context_for_ai_action(
                tenant=tenant_id,
                actor=_trusted_discovery_actor_reference(request_metadata),
                asset=asset,
                runtime=request_metadata.get("runtime_ref"),
                application=action_context.get("ai_app"),
                tool=request_metadata.get("tool") or request_metadata.get("tool_name"),
                model=action_context.get("ai_model"),
                provider=request_metadata.get("provider"),
                identity=request_metadata.get("identity_ref"),
                as_of=action_context.get("timestamp"),
            )
    except Exception:
        action_metadata["discovery_context"] = (
            retained_context[0]
            if retained_context is not None
            else {"status": "unknown", "limitations": ["provider_error"]}
        )
        return
    if retained_context is not None:
        retained_projection, retained_binding = retained_context
        refreshed_binding = _stored_discovery_asset_binding(context) if isinstance(context, dict) else None
        if (
            not isinstance(context, dict)
            or context.get("status") not in {"partial", "available"}
            or refreshed_binding != retained_binding
        ):
            action_metadata["discovery_context"] = retained_projection
            return
    action_metadata["discovery_context"] = context


def _upsert_user_registry(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    deployment_surface: str,
    risk_score: float,
    violation_increment: int,
    timestamp: datetime,
) -> UserRegistry:
    registry = db.scalar(
        select(UserRegistry).where(
            UserRegistry.tenant_id == tenant_id,
            UserRegistry.user_id == user_id,
        )
    )
    user_row = db.get(User, user_id)
    role_row = db.scalar(
        select(UserTenantRole).where(
            UserTenantRole.user_id == user_id,
            UserTenantRole.tenant_id == tenant_id,
        )
    )
    if registry is None:
        registry = UserRegistry(
            tenant_id=tenant_id,
            user_id=user_id,
            display_name=str(getattr(user_row, "full_name", "") or ""),
            email=str(getattr(user_row, "email", "") or ""),
            department=None,
            role=str(getattr(role_row, "role", "") or "") or None,
            status=("active" if bool(getattr(user_row, "is_active", True)) else "inactive"),
            risk_score=max(0.0, min(1.0, float(risk_score))),
            violation_count=max(0, int(violation_increment)),
            deployment_surfaces=[deployment_surface] if deployment_surface else [],
            first_seen_at=timestamp,
            last_seen_at=timestamp,
        )
        db.add(registry)
        db.flush()
        return registry

    if user_row is not None:
        registry.display_name = str(getattr(user_row, "full_name", "") or registry.display_name or "")
        registry.email = str(getattr(user_row, "email", "") or registry.email or "")
        registry.status = "active" if bool(getattr(user_row, "is_active", True)) else "inactive"
    if role_row is not None:
        registry.role = str(getattr(role_row, "role", "") or registry.role or "")
    registry.last_seen_at = timestamp
    registry.risk_score = max(float(registry.risk_score or 0.0), max(0.0, min(1.0, float(risk_score))))
    if violation_increment > 0:
        registry.violation_count = int(registry.violation_count or 0) + violation_increment
    surfaces = set(str(item).strip() for item in (registry.deployment_surfaces or []) if str(item).strip())
    if deployment_surface:
        surfaces.add(deployment_surface)
    registry.deployment_surfaces = sorted(surfaces)
    db.flush()
    return registry


def _upsert_endpoint(
    db: Session,
    *,
    tenant_id: str,
    user_id: str | None,
    device_context: dict[str, Any],
    correlation_id: str | None,
    timestamp: datetime,
) -> DeploymentEndpoint:
    explicit_endpoint_id = str(device_context.get("endpoint_id") or "").strip() or None
    endpoint_id = _derive_endpoint_id(
        tenant_id=tenant_id,
        user_id=user_id,
        browser_profile=str(device_context.get("browser_profile") or "default"),
        browser_type=str(device_context.get("browser_type") or ""),
        extension_version=str(device_context.get("extension_version") or ""),
        fallback_seed=correlation_id,
        explicit_endpoint_id=explicit_endpoint_id,
    )
    endpoint = db.get(DeploymentEndpoint, endpoint_id)
    if endpoint is not None and endpoint.tenant_id != tenant_id:
        endpoint_id = _derive_endpoint_id(
            tenant_id=tenant_id,
            user_id=user_id,
            browser_profile=str(device_context.get("browser_profile") or "default"),
            browser_type=str(device_context.get("browser_type") or ""),
            extension_version=str(device_context.get("extension_version") or ""),
            fallback_seed=_build_endpoint_collision_seed(
                explicit_endpoint_id=explicit_endpoint_id,
                device_context=device_context,
            ),
            explicit_endpoint_id=None,
        )
        endpoint = db.get(DeploymentEndpoint, endpoint_id)
    if endpoint is None:
        endpoint = DeploymentEndpoint(
            endpoint_id=endpoint_id,
            tenant_id=tenant_id,
            user_id=user_id,
            hostname=device_context.get("hostname"),
            device_type=device_context.get("device_type"),
            os_type=device_context.get("os_type"),
            os_version=_bounded_endpoint_string(device_context.get("os_version")),
            browser_type=device_context.get("browser_type"),
            browser_version=_bounded_endpoint_string(device_context.get("browser_version")),
            extension_version=_bounded_endpoint_string(device_context.get("extension_version")),
            ip_address=_bounded_endpoint_string(device_context.get("ip_address")),
            location=device_context.get("location"),
            first_seen_at=timestamp,
            last_seen_at=timestamp,
            status=str(device_context.get("status") or "active"),
            metadata_json=device_context.get("metadata") or {},
        )
        db.add(endpoint)
        db.flush()
        return endpoint

    endpoint.user_id = endpoint.user_id or user_id
    endpoint.hostname = str(device_context.get("hostname") or endpoint.hostname or "").strip() or endpoint.hostname
    endpoint.device_type = device_context.get("device_type") or endpoint.device_type
    endpoint.os_type = device_context.get("os_type") or endpoint.os_type
    endpoint.os_version = _bounded_endpoint_string(device_context.get("os_version") or endpoint.os_version) or endpoint.os_version
    endpoint.browser_type = device_context.get("browser_type") or endpoint.browser_type
    endpoint.browser_version = _bounded_endpoint_string(device_context.get("browser_version") or endpoint.browser_version) or endpoint.browser_version
    endpoint.extension_version = (
        _bounded_endpoint_string(device_context.get("extension_version") or endpoint.extension_version) or endpoint.extension_version
    )
    endpoint.ip_address = _bounded_endpoint_string(device_context.get("ip_address") or endpoint.ip_address) or endpoint.ip_address
    endpoint.location = str(device_context.get("location") or endpoint.location or "").strip() or endpoint.location
    endpoint.status = str(device_context.get("status") or endpoint.status or "active").strip().lower() or "active"
    endpoint.last_seen_at = timestamp
    merged_metadata = dict(endpoint.metadata_json or {})
    merged_metadata.update({k: v for k, v in (device_context.get("metadata") or {}).items() if v is not None})
    endpoint.metadata_json = merged_metadata
    db.flush()
    return endpoint


def _resolve_session(
    db: Session,
    *,
    tenant_id: str,
    user_id: str | None,
    endpoint_id: str,
    session_context: dict[str, Any],
    risk_score: float,
) -> AISession:
    requested_session_id = str(session_context.get("session_id") or "").strip() or None
    timestamp = _to_datetime(session_context.get("timestamp"))
    source_surface = str(session_context.get("source_surface") or "browser").strip().lower() or "browser"
    ai_app = str(session_context.get("ai_app") or "").strip() or None
    ai_model = str(session_context.get("ai_model") or "").strip() or None
    correlation_id = str(session_context.get("correlation_id") or "").strip() or None

    if requested_session_id:
        existing = db.get(AISession, requested_session_id)
        if existing is not None and existing.tenant_id == tenant_id:
            existing.user_id = existing.user_id or user_id
            existing.endpoint_id = existing.endpoint_id or endpoint_id
            existing.ai_app = ai_app or existing.ai_app
            existing.ai_model = ai_model or existing.ai_model
            existing.end_time = timestamp
            existing.total_actions = int(existing.total_actions or 0)
            existing.risk_score = max(float(existing.risk_score or 0.0), float(risk_score or 0.0))
            if correlation_id and not existing.correlation_id:
                existing.correlation_id = correlation_id
            db.flush()
            return existing
        if existing is not None and existing.tenant_id != tenant_id:
            requested_session_id = None

    recent_cutoff = timestamp - timedelta(hours=8)
    existing_recent = db.scalar(
        select(AISession)
        .where(
            AISession.tenant_id == tenant_id,
            AISession.user_id == user_id,
            AISession.endpoint_id == endpoint_id,
            AISession.source_surface == source_surface,
            AISession.ai_app == ai_app,
            AISession.start_time >= recent_cutoff,
            AISession.status == "active",
        )
        .order_by(desc(AISession.start_time))
        .limit(1)
    )
    if existing_recent is not None:
        existing_recent.end_time = timestamp
        existing_recent.ai_model = ai_model or existing_recent.ai_model
        existing_recent.risk_score = max(float(existing_recent.risk_score or 0.0), float(risk_score or 0.0))
        if correlation_id and not existing_recent.correlation_id:
            existing_recent.correlation_id = correlation_id
        db.flush()
        return existing_recent

    new_session = AISession(
        session_id=requested_session_id or f"sess_{uuid4().hex}",
        tenant_id=tenant_id,
        user_id=user_id,
        endpoint_id=endpoint_id,
        source_surface=source_surface,
        ai_app=ai_app,
        ai_model=ai_model,
        start_time=timestamp,
        end_time=timestamp,
        total_actions=0,
        risk_score=float(risk_score or 0.0),
        status="active",
        correlation_id=correlation_id,
        metadata_json=dict(session_context.get("metadata") or {}),
    )
    db.add(new_session)
    db.flush()
    return new_session


@dataclass
class ActivityAuditRecord:
    user_registry_id: str | None
    endpoint_id: str
    session_id: str
    action_id: str
    alert_id: str | None
    prompt_storage_mode: str | None


def _upsert_prompt_payload_for_action(
    db: Session,
    *,
    action: AIAction,
    action_context: dict[str, Any],
) -> str | None:
    prompt_storage_mode: str | None = None
    prompt_raw = str(action_context.get("prompt_raw") or "").strip()
    prompt_preview_redacted = str(action_context.get("prompt_preview_redacted") or "").strip()
    sensitive_detection = (
        dict(action_context.get("sensitive_detection") or {})
        if isinstance(action_context.get("sensitive_detection"), dict)
        else {}
    )
    entities = _extract_sensitive_entities(sensitive_detection)
    pii_detected = bool(sensitive_detection.get("contains_sensitive")) or bool(entities)
    if not prompt_raw and not prompt_preview_redacted:
        return None

    prompt_storage_mode = _resolve_prompt_storage_mode(
        requested_mode=action_context.get("storage_mode"),
        sensitivity_score=float(action.sensitivity_score or 0.0),
        pii_detected=pii_detected,
    )
    source_prompt = prompt_raw or prompt_preview_redacted
    redacted_prompt = _redact_prompt(prompt_preview_redacted or source_prompt)
    raw_prompt = None
    if prompt_storage_mode == "full":
        raw_prompt = prompt_raw or source_prompt
    elif prompt_storage_mode == "hashed_only":
        # A hashed-only policy must not retain even a redacted content
        # derivative. The hash and typed sensitivity metadata are the only
        # durable prompt evidence in this mode.
        redacted_prompt = "[hashed_only]"

    existing_prompt = db.get(PromptPayload, action.action_id)
    if existing_prompt is not None:
        existing_prompt.raw_prompt = raw_prompt
        existing_prompt.redacted_prompt = redacted_prompt or "[redacted]"
        existing_prompt.pii_detected = pii_detected
        existing_prompt.sensitive_entities = entities
        existing_prompt.storage_mode = prompt_storage_mode
        existing_prompt.prompt_hash = _prompt_hash(source_prompt)
        db.flush()
        return prompt_storage_mode

    prompt_payload = PromptPayload(
        action_id=action.action_id,
        raw_prompt=raw_prompt,
        redacted_prompt=redacted_prompt or "[redacted]",
        pii_detected=pii_detected,
        sensitive_entities=entities,
        storage_mode=prompt_storage_mode,
        prompt_hash=_prompt_hash(source_prompt),
    )
    db.add(prompt_payload)
    db.flush()
    return prompt_storage_mode


def record_activity_event(
    db: Session,
    *,
    tenant_id: str,
    user_id: str | None,
    payload: dict[str, Any],
) -> ActivityAuditRecord:
    device_context = _extract_device_context(payload)
    session_context = _extract_session_context(payload)
    action_context = _extract_action_context(payload)
    timestamp = _to_datetime(action_context.get("timestamp"))
    action_id = str(action_context.get("action_id") or action_context.get("runtime_event_id") or f"act_{uuid4().hex}")

    endpoint = _upsert_endpoint(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        device_context=device_context,
        correlation_id=str(action_context.get("correlation_id") or ""),
        timestamp=timestamp,
    )

    session = _resolve_session(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        endpoint_id=endpoint.endpoint_id,
        session_context=session_context,
        risk_score=float(action_context.get("risk_score") or 0.0),
    )

    enforcement_action = str(action_context.get("enforcement_action") or "allowed")
    risk_score = float(action_context.get("risk_score") or 0.0)
    violation_increment = 1 if enforcement_action in NEGATIVE_ENFORCEMENT_ACTIONS else 0
    registry = None
    if user_id:
        registry = _upsert_user_registry(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            deployment_surface=str(session_context.get("source_surface") or "browser"),
            risk_score=risk_score,
            violation_increment=violation_increment,
            timestamp=timestamp,
        )

    action_metadata = dict(action_context.get("metadata") or {})
    if not settings.discovery_context_provider:
        action_metadata.pop("discovery_context", None)
    if (
        settings.canonical_ai_action_dual_write_enabled
        or (
            settings.authorization_kernel_v2_enabled
            and settings.authorization_kernel_shadow_compare_enabled
        )
    ) and action_context.get("runtime_event_id"):
        from app.db.models.runtime_intelligence import RuntimeEvent

        runtime_row = db.get(RuntimeEvent, str(action_context["runtime_event_id"]))
        if runtime_row is not None and runtime_row.tenant_id == tenant_id:
            runtime_metadata = dict(runtime_row.metadata_json or {})
            canonical_v1 = dict(runtime_metadata.get("canonical_ai_action_v1") or {})
            if canonical_v1:
                action_metadata["canonical_ai_action_v1"] = canonical_v1
                action_metadata["canonical_ai_action_hash"] = runtime_metadata.get("canonical_ai_action_hash")
            shadow_comparison = dict(runtime_metadata.get("authorization_kernel_v2_shadow") or {})
            if shadow_comparison:
                action_metadata["authorization_kernel_v2_shadow"] = shadow_comparison
            shadow_health = dict(runtime_metadata.get("authorization_kernel_v2_shadow_health") or {})
            if shadow_health:
                action_metadata["authorization_kernel_v2_shadow_health"] = shadow_health
    if bool(
        payload.get("suppress_ai_action")
        or action_context.get("suppress_ai_action")
        or action_metadata.get("suppress_ai_action")
    ):
        db.flush()
        return ActivityAuditRecord(
            user_registry_id=registry.id if registry else None,
            endpoint_id=endpoint.endpoint_id,
            session_id=session.session_id,
            action_id="",
            alert_id=None,
            prompt_storage_mode=None,
        )

    ai_action = dict(action_metadata.get("ai_action") or {})
    if not ai_action:
        from app.services.ai_iam_service import build_ai_action_record

        build_metadata = dict(payload or {})
        build_metadata.update(action_metadata)
        build_metadata.setdefault("action_type", action_context.get("action_type"))
        build_metadata.setdefault("action_risk", action_context.get("severity"))
        build_metadata.setdefault("policy_id", action_context.get("policy_triggered"))
        build_metadata.setdefault("policy_version", payload.get("policy_version") if isinstance(payload, dict) else None)
        build_metadata.setdefault("machine_id", payload.get("machine_id") if isinstance(payload, dict) else None)
        build_metadata.setdefault("endpoint_id", endpoint.endpoint_id)
        build_metadata.setdefault("browser_type", device_context.get("browser_type"))
        build_metadata.setdefault("application", action_context.get("ai_app"))
        ai_action = build_ai_action_record(
            tenant_id=tenant_id,
            action_id=action_id,
            timestamp=timestamp.isoformat(),
            source_surface=str(session_context.get("source_surface") or payload.get("source_surface") or "unknown"),
            event_type=str(payload.get("event_type") or action_context.get("action_type") or "ai_action"),
            user_id=user_id,
            agent_id=str(build_metadata.get("agent_id") or "").strip() or None,
            ai_system_id=str(build_metadata.get("ai_system_id") or "").strip() or None,
            app_id=str(action_context.get("ai_app") or "").strip() or None,
            machine_id=str(build_metadata.get("machine_id") or endpoint.endpoint_id or "").strip() or None,
            browser_type=str(device_context.get("browser_type") or "").strip() or None,
            application=str(action_context.get("ai_app") or "").strip() or None,
            policy_version_id=str(build_metadata.get("policy_version") or build_metadata.get("policy_version_id") or "").strip() or None,
            decision=enforcement_action,
            evidence_node_ids=[str(action_context.get("evidence_node_id"))] if action_context.get("evidence_node_id") else [],
            correlation_id=action_context.get("correlation_id"),
            context_id=session.session_id,
            metadata=build_metadata,
            finding_id=action_context.get("finding_id"),
        )
    action_metadata.update(
        {
            "ai_action": ai_action,
            "control_mode": dict(ai_action.get("policy") or {}).get("control_mode"),
            "policy_snapshot": dict(ai_action.get("policy_snapshot") or {}),
            "decision_explanation": dict(ai_action.get("decision_explanation") or {}),
            "evidence_bundle": dict(ai_action.get("evidence_bundle") or {}),
        }
    )
    if settings.canonical_ai_action_dual_write_enabled:
        canonical_v1 = dict(action_metadata.get("canonical_ai_action_v1") or {})
        if canonical_v1:
            action_metadata = maybe_dual_write_canonical_action(
                action_metadata,
                canonical_action=canonical_v1,
                enabled=True,
            )

    existing_action = db.get(AIAction, action_id)
    _attach_discovery_context(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        action_context=action_context,
        action_metadata=action_metadata,
        existing_metadata=(dict(existing_action.metadata_json or {}) if existing_action is not None else None),
    )
    if existing_action is not None:
        existing_metadata = dict(existing_action.metadata_json or {})
        if existing_metadata.get("ai_action") and not dict(action_context.get("metadata") or {}).get("ai_action"):
            for canonical_key in (
                "ai_action",
                "control_mode",
                "policy_snapshot",
                "decision_explanation",
                "evidence_bundle",
                "canonical_ai_action_v1",
                "canonical_ai_action_hash",
            ):
                if canonical_key in existing_metadata:
                    action_metadata[canonical_key] = existing_metadata[canonical_key]
        existing_action.session_id = existing_action.session_id or session.session_id
        existing_action.user_id = existing_action.user_id or user_id
        existing_action.endpoint_id = existing_action.endpoint_id or endpoint.endpoint_id
        existing_action.runtime_event_id = existing_action.runtime_event_id or action_context.get("runtime_event_id")
        existing_action.monitoring_signal_id = existing_action.monitoring_signal_id or action_context.get("monitoring_signal_id")
        existing_action.audit_log_id = existing_action.audit_log_id or action_context.get("audit_log_id")
        existing_action.evidence_node_id = existing_action.evidence_node_id or action_context.get("evidence_node_id")
        existing_action.finding_id = existing_action.finding_id or action_context.get("finding_id")
        existing_action.timestamp = timestamp
        existing_action.action_type = str(action_context.get("action_type") or existing_action.action_type or "prompt_input")
        existing_action.ai_app = action_context.get("ai_app") or existing_action.ai_app
        existing_action.ai_model = action_context.get("ai_model") or existing_action.ai_model
        existing_action.data_classification = action_context.get("data_classification") or existing_action.data_classification
        existing_action.sensitivity_score = max(
            float(existing_action.sensitivity_score or 0.0),
            max(0.0, min(1.0, float(action_context.get("sensitivity_score") or 0.0))),
        )
        existing_action.policy_triggered = action_context.get("policy_triggered") or existing_action.policy_triggered
        existing_action.enforcement_action = enforcement_action or existing_action.enforcement_action
        existing_action.semantic_drift_score = max(
            float(existing_action.semantic_drift_score or 0.0),
            max(0.0, min(1.0, float(action_context.get("semantic_drift_score") or 0.0))),
        )
        existing_action.risk_score = max(float(existing_action.risk_score or 0.0), max(0.0, min(1.0, risk_score)))
        existing_action.correlation_id = action_context.get("correlation_id") or existing_action.correlation_id
        merged_metadata = existing_metadata
        merged_metadata.update(action_metadata)
        existing_action.metadata_json = merged_metadata
        prompt_storage_mode = _upsert_prompt_payload_for_action(
            db,
            action=existing_action,
            action_context=action_context,
        )
        db.flush()
        return ActivityAuditRecord(
            user_registry_id=registry.id if registry else None,
            endpoint_id=endpoint.endpoint_id,
            session_id=session.session_id,
            action_id=existing_action.action_id,
            alert_id=None,
            prompt_storage_mode=prompt_storage_mode,
        )

    action = AIAction(
        action_id=action_id,
        tenant_id=tenant_id,
        session_id=session.session_id,
        user_id=user_id,
        endpoint_id=endpoint.endpoint_id,
        runtime_event_id=action_context.get("runtime_event_id"),
        monitoring_signal_id=action_context.get("monitoring_signal_id"),
        audit_log_id=action_context.get("audit_log_id"),
        evidence_node_id=action_context.get("evidence_node_id"),
        finding_id=action_context.get("finding_id"),
        timestamp=timestamp,
        action_type=str(action_context.get("action_type") or "prompt_input"),
        ai_app=action_context.get("ai_app"),
        ai_model=action_context.get("ai_model"),
        data_classification=action_context.get("data_classification"),
        sensitivity_score=max(0.0, min(1.0, float(action_context.get("sensitivity_score") or 0.0))),
        policy_triggered=action_context.get("policy_triggered"),
        enforcement_action=enforcement_action,
        semantic_drift_score=max(0.0, min(1.0, float(action_context.get("semantic_drift_score") or 0.0))),
        risk_score=max(0.0, min(1.0, risk_score)),
        correlation_id=action_context.get("correlation_id"),
        metadata_json=action_metadata,
    )
    db.add(action)
    db.flush()

    session.total_actions = int(session.total_actions or 0) + 1
    session.end_time = max(_to_datetime(session.end_time), timestamp) if session.end_time else timestamp
    session.risk_score = max(float(session.risk_score or 0.0), float(action.risk_score or 0.0))
    db.flush()

    prompt_storage_mode = _upsert_prompt_payload_for_action(
        db,
        action=action,
        action_context=action_context,
    )

    alert_id: str | None = None
    if enforcement_action in NEGATIVE_ENFORCEMENT_ACTIONS or action.finding_id:
        alert = AIActionAlert(
            tenant_id=tenant_id,
            action_id=action.action_id,
            session_id=session.session_id,
            user_id=user_id,
            endpoint_id=endpoint.endpoint_id,
            finding_id=action.finding_id,
            alert_type=_alert_type_for_action(action.policy_triggered, action.action_type),
            severity=_severity_for_action(
                enforcement_action,
                float(action.risk_score or 0.0),
                str(action_context.get("severity") or ""),
            ),
            policy_reason=str(action.policy_triggered or ""),
            enforcement_action=enforcement_action,
        )
        db.add(alert)
        db.flush()
        alert_id = alert.id

    return ActivityAuditRecord(
        user_registry_id=registry.id if registry else None,
        endpoint_id=endpoint.endpoint_id,
        session_id=session.session_id,
        action_id=action.action_id,
        alert_id=alert_id,
        prompt_storage_mode=prompt_storage_mode,
    )


def _serialize_prompt_payload(row: PromptPayload | None) -> dict[str, Any]:
    return project_prompt_payload(row)


def _serialize_alert(row: AIActionAlert) -> dict[str, Any]:
    return {
        "alert_id": row.id,
        "action_id": row.action_id,
        "session_id": row.session_id,
        "user_id": row.user_id,
        "endpoint_id": row.endpoint_id,
        "finding_id": row.finding_id,
        "alert_type": row.alert_type,
        "severity": row.severity,
        "policy_reason": row.policy_reason,
        "enforcement_action": row.enforcement_action,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def _serialize_action(
    row: AIAction,
    *,
    prompt_payload: PromptPayload | None,
    alerts: list[AIActionAlert],
) -> dict[str, Any]:
    return {
        "action_id": row.action_id,
        "session_id": row.session_id,
        "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        "action_type": row.action_type,
        "ai_app": row.ai_app,
        "ai_model": row.ai_model,
        "data_classification": row.data_classification,
        "sensitivity_score": float(row.sensitivity_score or 0.0),
        "policy_triggered": row.policy_triggered,
        "enforcement_action": row.enforcement_action,
        "semantic_drift_score": float(row.semantic_drift_score or 0.0),
        "risk_score": float(row.risk_score or 0.0),
        "correlation_id": row.correlation_id,
        "runtime_event_id": row.runtime_event_id,
        "monitoring_signal_id": row.monitoring_signal_id,
        "audit_log_id": row.audit_log_id,
        "evidence_node_id": row.evidence_node_id,
        "finding_id": row.finding_id,
        "metadata": dict(row.metadata_json or {}),
        "prompt_payload": _serialize_prompt_payload(prompt_payload),
        "alerts": [_serialize_alert(item) for item in alerts],
    }


def _serialize_session(row: AISession) -> dict[str, Any]:
    return {
        "session_id": row.session_id,
        "user_id": row.user_id,
        "endpoint_id": row.endpoint_id,
        "source_surface": row.source_surface,
        "ai_app": row.ai_app,
        "ai_model": row.ai_model,
        "start_time": row.start_time.isoformat() if row.start_time else None,
        "end_time": row.end_time.isoformat() if row.end_time else None,
        "total_actions": int(row.total_actions or 0),
        "risk_score": float(row.risk_score or 0.0),
        "correlation_id": row.correlation_id,
        "metadata": dict(row.metadata_json or {}),
    }


def _load_user_identity_map(db: Session, *, tenant_id: str, user_ids: list[str | None]) -> dict[str, dict[str, Any]]:
    clean_ids = sorted({str(value) for value in user_ids if str(value or "").strip()})
    if not clean_ids:
        return {}
    registries = db.scalars(
        select(UserRegistry).where(
            UserRegistry.tenant_id == tenant_id,
            UserRegistry.user_id.in_(clean_ids),
        )
    ).all()
    users = db.scalars(select(User).where(User.id.in_(clean_ids))).all()
    registry_by_user = {row.user_id: row for row in registries}
    user_by_id = {row.id: row for row in users}

    identity_by_user: dict[str, dict[str, Any]] = {}
    for user_id in clean_ids:
        registry = registry_by_user.get(user_id)
        user = user_by_id.get(user_id)
        identity_by_user[user_id] = {
            "user_email": (registry.email if registry else None) or (user.email if user else None),
            "user_display_name": (registry.display_name if registry else None) or (user.full_name if user else None),
            "user_department": registry.department if registry else None,
            "user_role": registry.role if registry else None,
        }
    return identity_by_user


def _serialize_endpoint(row: DeploymentEndpoint, *, user_identity: dict[str, Any] | None = None) -> dict[str, Any]:
    metadata = dict(row.metadata_json or {})
    extension_name = _display_extension_name(
        metadata.get("extension_name"),
        fallback_source_surface=metadata.get("source_surface"),
        extension_version=row.extension_version,
    )
    identity = dict(user_identity or {})
    return {
        "endpoint_id": row.endpoint_id,
        "user_id": row.user_id,
        "user_email": identity.get("user_email"),
        "user_display_name": identity.get("user_display_name"),
        "user_department": identity.get("user_department"),
        "user_role": identity.get("user_role"),
        "hostname": row.hostname,
        "device_type": row.device_type,
        "os_type": row.os_type,
        "os_name": _display_os_name(row.os_type),
        "os_version": row.os_version,
        "browser_type": row.browser_type,
        "browser_name": _display_browser_name(row.browser_type),
        "browser_version": row.browser_version,
        "extension_name": extension_name,
        "extension_version": row.extension_version,
        "ip_address": row.ip_address,
        "location": row.location,
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "status": row.status,
        "metadata": metadata,
    }


def _serialize_user_registry(
    row: UserRegistry,
    *,
    primary_endpoint: DeploymentEndpoint | None = None,
    ai_activity_count: int | None = None,
) -> dict[str, Any]:
    return {
        "user_id": row.user_id,
        "display_name": row.display_name,
        "email": row.email,
        "department": row.department,
        "role": row.role,
        "status": row.status,
        "risk_score": float(row.risk_score or 0.0),
        "machine_id": (primary_endpoint.endpoint_id if primary_endpoint else None),
        "browser_type": (primary_endpoint.browser_type if primary_endpoint else None),
        "last_seen": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "ai_activity_count": int(ai_activity_count or 0),
        "violation_count": int(row.violation_count or 0),
        "deployment_surfaces": list(row.deployment_surfaces or []),
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
    }


def _runtime_user_profile_context(
    db: Session,
    *,
    tenant_id: str,
    user_ids: list[str],
) -> dict[str, dict[str, Any]]:
    normalized_user_ids = sorted({str(item).strip() for item in user_ids if str(item).strip()})
    if not normalized_user_ids:
        return {}
    from app.db.models.runtime_intelligence import RuntimeEvent

    rows = db.scalars(
        select(RuntimeEvent)
        .where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.user_id.in_(normalized_user_ids),
        )
        .order_by(desc(RuntimeEvent.created_at))
        .limit(5000)
    ).all()
    context: dict[str, dict[str, Any]] = {
        user_id: {
            "machine_ids": set(),
            "browsers": set(),
            "connected_apps": set(),
            "active_agent_ids": set(),
            "ai_activity_count": 0,
            "oauth_relationships": {},
        }
        for user_id in normalized_user_ids
    }
    for row in rows:
        user_id = str(row.user_id or "").strip()
        if not user_id or user_id not in context:
            continue
        metadata = dict(row.metadata_json or {}) if isinstance(row.metadata_json, dict) else {}
        machine_id = (
            str(metadata.get("machine_id") or "").strip()
            or str(metadata.get("endpoint_id") or "").strip()
            or str(metadata.get("host_id") or "").strip()
        )
        browser_type = str(metadata.get("browser_type") or metadata.get("browser") or "").strip().lower()
        app = (
            str(row.app_id or "").strip()
            or str(metadata.get("application") or "").strip()
            or str(metadata.get("domain") or "").strip()
            or str(metadata.get("tool_name") or "").strip()
        )
        agent_id = str(row.agent_id or "").strip()
        if machine_id:
            context[user_id]["machine_ids"].add(machine_id)
        if browser_type:
            context[user_id]["browsers"].add(browser_type)
        if app:
            context[user_id]["connected_apps"].add(app)
        if agent_id:
            context[user_id]["active_agent_ids"].add(agent_id)
        context[user_id]["ai_activity_count"] = int(context[user_id]["ai_activity_count"]) + 1

        oauth_relationships = meta_relationships if isinstance((meta_relationships := metadata.get("oauth_relationships")), list) else []
        if not oauth_relationships:
            oauth_app = metadata.get("oauth_app") if isinstance(metadata.get("oauth_app"), dict) else {}
            oauth_app_id = str(oauth_app.get("app_id") or oauth_app.get("client_id") or "").strip()
            if oauth_app_id:
                oauth_relationships = [
                    {
                        "user_id": user_id,
                        "app_id": oauth_app_id,
                        "scopes": list(oauth_app.get("scopes") or []),
                        "anomaly_flag": bool(metadata.get("abnormal_access_pattern") or metadata.get("anomaly_flag")),
                    }
                ]
        for relationship in oauth_relationships:
            if not isinstance(relationship, dict):
                continue
            relationship_user_id = str(relationship.get("user_id") or user_id).strip()
            if relationship_user_id != user_id:
                continue
            relationship_app_id = str(relationship.get("app_id") or "").strip()
            if not relationship_app_id:
                continue
            scopes = sorted(
                {
                    str(scope).strip()
                    for scope in (relationship.get("scopes") or [])
                    if str(scope).strip()
                }
            )
            anomaly_flag = bool(
                relationship.get("anomaly_flag")
                or metadata.get("abnormal_access_pattern")
                or metadata.get("anomaly_flag")
                or metadata.get("unprotected_secrets_accessed")
            )
            existing = context[user_id]["oauth_relationships"].get(relationship_app_id)
            if isinstance(existing, dict):
                existing_scopes = set(str(scope).strip() for scope in (existing.get("scopes") or []) if str(scope).strip())
                existing_scopes.update(scopes)
                existing["scopes"] = sorted(existing_scopes)
                existing["anomaly_flag"] = bool(existing.get("anomaly_flag")) or anomaly_flag
            else:
                context[user_id]["oauth_relationships"][relationship_app_id] = {
                    "user_id": relationship_user_id,
                    "app_id": relationship_app_id,
                    "scopes": scopes,
                    "anomaly_flag": anomaly_flag,
                }

    endpoint_rows = db.scalars(
        select(DeploymentEndpoint).where(
            DeploymentEndpoint.tenant_id == tenant_id,
            DeploymentEndpoint.user_id.in_(normalized_user_ids),
        )
    ).all()
    for endpoint in endpoint_rows:
        user_id = str(endpoint.user_id or "").strip()
        if not user_id or user_id not in context:
            continue
        if str(endpoint.endpoint_id or "").strip():
            context[user_id]["machine_ids"].add(str(endpoint.endpoint_id).strip())
        if str(endpoint.browser_type or "").strip():
            context[user_id]["browsers"].add(str(endpoint.browser_type).strip().lower())

    return {
        user_id: {
            "machine_ids": sorted(values["machine_ids"]),
            "browsers": sorted(values["browsers"]),
            "connected_apps": sorted(values["connected_apps"]),
            "active_agent_ids": sorted(values["active_agent_ids"]),
            "ai_activity_count": int(values["ai_activity_count"]),
            "oauth_relationships": sorted(
                [
                    {
                        "user_id": str(item.get("user_id") or user_id),
                        "app_id": str(item.get("app_id") or ""),
                        "scopes": sorted(
                            {
                                str(scope).strip()
                                for scope in (item.get("scopes") or [])
                                if str(scope).strip()
                            }
                        ),
                        "anomaly_flag": bool(item.get("anomaly_flag")),
                    }
                    for item in (values.get("oauth_relationships") or {}).values()
                    if isinstance(item, dict) and str(item.get("app_id") or "").strip()
                ],
                key=lambda row: str(row.get("app_id") or "").lower(),
            ),
        }
        for user_id, values in context.items()
    }


def _latest_endpoints_by_user(
    db: Session,
    *,
    tenant_id: str,
    user_ids: list[str],
) -> dict[str, DeploymentEndpoint]:
    normalized_user_ids = sorted({str(item).strip() for item in user_ids if str(item).strip()})
    if not normalized_user_ids:
        return {}
    rows = db.scalars(
        select(DeploymentEndpoint)
        .where(
            DeploymentEndpoint.tenant_id == tenant_id,
            DeploymentEndpoint.user_id.in_(normalized_user_ids),
        )
        .order_by(DeploymentEndpoint.user_id.asc(), desc(DeploymentEndpoint.last_seen_at))
    ).all()
    out: dict[str, DeploymentEndpoint] = {}
    for row in rows:
        user_id = str(row.user_id or "").strip()
        if not user_id:
            continue
        if user_id not in out:
            out[user_id] = row
    return out


def _activity_counts_by_user(
    db: Session,
    *,
    tenant_id: str,
    user_ids: list[str],
) -> dict[str, int]:
    normalized_user_ids = sorted({str(item).strip() for item in user_ids if str(item).strip()})
    if not normalized_user_ids:
        return {}
    rows = db.execute(
        select(AIAction.user_id, func.count(AIAction.action_id))
        .where(
            AIAction.tenant_id == tenant_id,
            AIAction.user_id.in_(normalized_user_ids),
        )
        .group_by(AIAction.user_id)
    ).all()
    return {str(user_id): int(count or 0) for user_id, count in rows if str(user_id or "").strip()}


def get_user_timeline(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    action_type: str | None = None,
    enforcement_action: str | None = None,
    severity: str | None = None,
    page: int = 1,
    page_size: int = 200,
) -> dict[str, Any]:
    registry = db.scalar(
        select(UserRegistry).where(
            UserRegistry.tenant_id == tenant_id,
            UserRegistry.user_id == user_id,
        )
    )
    endpoints = db.scalars(
        select(DeploymentEndpoint)
        .where(
            DeploymentEndpoint.tenant_id == tenant_id,
            DeploymentEndpoint.user_id == user_id,
        )
        .order_by(desc(DeploymentEndpoint.last_seen_at))
    ).all()
    sessions = db.scalars(
        select(AISession)
        .where(
            AISession.tenant_id == tenant_id,
            AISession.user_id == user_id,
        )
        .order_by(desc(AISession.start_time))
    ).all()

    action_stmt = select(AIAction).where(
        AIAction.tenant_id == tenant_id,
        AIAction.user_id == user_id,
    )
    if action_type:
        action_stmt = action_stmt.where(AIAction.action_type == action_type)
    if enforcement_action:
        action_stmt = action_stmt.where(AIAction.enforcement_action == _normalize_enforcement_action(enforcement_action))

    all_actions = db.scalars(action_stmt.order_by(desc(AIAction.timestamp))).all()
    if severity:
        severity_filter = str(severity).strip().lower()
        all_actions = [
            row
            for row in all_actions
            if _severity_for_action(
                str(row.enforcement_action or ""),
                float(row.risk_score or 0.0),
                None,
            )
            == severity_filter
        ]
    page_items, total, safe_page, safe_page_size = paginate_rows(all_actions, page=page, page_size=page_size)
    action_ids = [row.action_id for row in page_items]
    prompt_by_action = {
        item.action_id: item
        for item in db.scalars(select(PromptPayload).where(PromptPayload.action_id.in_(action_ids))).all()
    } if action_ids else {}
    alerts = []
    if action_ids:
        alerts = db.scalars(
            select(AIActionAlert)
            .where(
                AIActionAlert.tenant_id == tenant_id,
                AIActionAlert.action_id.in_(action_ids),
            )
            .order_by(desc(AIActionAlert.created_at))
        ).all()
    alerts_by_action: dict[str, list[AIActionAlert]] = {}
    for item in alerts:
        alerts_by_action.setdefault(item.action_id, []).append(item)

    action_rows = [
        _serialize_action(row, prompt_payload=prompt_by_action.get(row.action_id), alerts=alerts_by_action.get(row.action_id, []))
        for row in page_items
    ]

    ordered_timeline = sorted(
        [
            {
                "timestamp": item.get("timestamp"),
                "kind": "action",
                "action": item,
            }
            for item in action_rows
        ],
        key=lambda item: str(item.get("timestamp") or ""),
        reverse=True,
    )
    policy_signals = sorted(
        {
            signal
            for row in page_items
            for signal in str(row.policy_triggered or "").split(",")
            if signal.strip()
        }
    )

    endpoint_identity_by_user = _load_user_identity_map(
        db,
        tenant_id=tenant_id,
        user_ids=[item.user_id for item in endpoints],
    )

    return {
        "user": _serialize_user_registry(registry) if registry else None,
        "devices": [
            _serialize_endpoint(item, user_identity=endpoint_identity_by_user.get(str(item.user_id or "")))
            for item in endpoints
        ],
        "sessions": [_serialize_session(item) for item in sessions],
        "actions": action_rows,
        "alerts": [_serialize_alert(item) for item in alerts],
        "policies_triggered": policy_signals,
        "timeline": ordered_timeline,
        "total_actions": total,
        "page": safe_page,
        "page_size": safe_page_size,
    }


def get_endpoint_timeline(
    db: Session,
    *,
    tenant_id: str,
    endpoint_id: str,
    action_type: str | None = None,
    enforcement_action: str | None = None,
    severity: str | None = None,
    page: int = 1,
    page_size: int = 200,
) -> dict[str, Any]:
    endpoint = db.scalar(
        select(DeploymentEndpoint).where(
            DeploymentEndpoint.tenant_id == tenant_id,
            DeploymentEndpoint.endpoint_id == endpoint_id,
        )
    )
    if endpoint is None:
        return {
            "device": None,
            "user": None,
            "sessions": [],
            "actions": [],
            "alerts": [],
            "policies_triggered": [],
            "timeline": [],
            "total_actions": 0,
            "page": max(1, int(page)),
            "page_size": max(1, int(page_size)),
        }

    registry = None
    if endpoint.user_id:
        registry = db.scalar(
            select(UserRegistry).where(
                UserRegistry.tenant_id == tenant_id,
                UserRegistry.user_id == endpoint.user_id,
            )
        )

    sessions = db.scalars(
        select(AISession)
        .where(
            AISession.tenant_id == tenant_id,
            AISession.endpoint_id == endpoint_id,
        )
        .order_by(desc(AISession.start_time))
    ).all()

    action_stmt = select(AIAction).where(
        AIAction.tenant_id == tenant_id,
        AIAction.endpoint_id == endpoint_id,
    )
    if action_type:
        action_stmt = action_stmt.where(AIAction.action_type == action_type)
    if enforcement_action:
        action_stmt = action_stmt.where(AIAction.enforcement_action == _normalize_enforcement_action(enforcement_action))

    all_actions = db.scalars(action_stmt.order_by(desc(AIAction.timestamp))).all()
    if severity:
        severity_filter = str(severity).strip().lower()
        all_actions = [
            row
            for row in all_actions
            if _severity_for_action(str(row.enforcement_action or ""), float(row.risk_score or 0.0), None) == severity_filter
        ]
    page_items, total, safe_page, safe_page_size = paginate_rows(all_actions, page=page, page_size=page_size)
    action_ids = [row.action_id for row in page_items]
    prompt_by_action = {
        item.action_id: item
        for item in db.scalars(select(PromptPayload).where(PromptPayload.action_id.in_(action_ids))).all()
    } if action_ids else {}
    alerts = []
    if action_ids:
        alerts = db.scalars(
            select(AIActionAlert)
            .where(
                AIActionAlert.tenant_id == tenant_id,
                AIActionAlert.action_id.in_(action_ids),
            )
            .order_by(desc(AIActionAlert.created_at))
        ).all()
    alerts_by_action: dict[str, list[AIActionAlert]] = {}
    for item in alerts:
        alerts_by_action.setdefault(item.action_id, []).append(item)

    action_rows = [
        _serialize_action(row, prompt_payload=prompt_by_action.get(row.action_id), alerts=alerts_by_action.get(row.action_id, []))
        for row in page_items
    ]

    ordered_timeline = sorted(
        [{"timestamp": item.get("timestamp"), "kind": "action", "action": item} for item in action_rows],
        key=lambda item: str(item.get("timestamp") or ""),
        reverse=True,
    )
    policy_signals = sorted(
        {
            signal
            for row in page_items
            for signal in str(row.policy_triggered or "").split(",")
            if signal.strip()
        }
    )

    endpoint_identity_by_user = _load_user_identity_map(
        db,
        tenant_id=tenant_id,
        user_ids=[endpoint.user_id],
    )

    return {
        "device": _serialize_endpoint(endpoint, user_identity=endpoint_identity_by_user.get(str(endpoint.user_id or ""))),
        "user": _serialize_user_registry(registry) if registry else None,
        "sessions": [_serialize_session(item) for item in sessions],
        "actions": action_rows,
        "alerts": [_serialize_alert(item) for item in alerts],
        "policies_triggered": policy_signals,
        "timeline": ordered_timeline,
        "total_actions": total,
        "page": safe_page,
        "page_size": safe_page_size,
    }


def list_user_registry(
    db: Session,
    *,
    tenant_id: str,
    q: str | None = None,
    page: int = 1,
    page_size: int = 100,
) -> dict[str, Any]:
    stmt = select(UserRegistry).where(UserRegistry.tenant_id == tenant_id)
    query = str(q or "").strip().lower()
    if query:
        stmt = stmt.where(
            or_(
                func.lower(UserRegistry.email).contains(query),
                func.lower(UserRegistry.display_name).contains(query),
                func.lower(UserRegistry.role).contains(query),
            )
        )
    rows = db.scalars(stmt.order_by(desc(UserRegistry.last_seen_at))).all()
    page_items, total, safe_page, safe_page_size = paginate_rows(rows, page=page, page_size=page_size)
    page_user_ids = [str(item.user_id or "").strip() for item in page_items if str(item.user_id or "").strip()]
    endpoints_by_user = _latest_endpoints_by_user(
        db,
        tenant_id=tenant_id,
        user_ids=page_user_ids,
    )
    action_counts = _activity_counts_by_user(
        db,
        tenant_id=tenant_id,
        user_ids=page_user_ids,
    )
    runtime_context = _runtime_user_profile_context(
        db,
        tenant_id=tenant_id,
        user_ids=page_user_ids,
    )
    items: list[dict[str, Any]] = []
    for item in page_items:
        user_id = str(item.user_id)
        serialized = _serialize_user_registry(
            item,
            primary_endpoint=endpoints_by_user.get(user_id),
            ai_activity_count=max(action_counts.get(user_id, 0), int(runtime_context.get(user_id, {}).get("ai_activity_count", 0))),
        )
        serialized.update(runtime_context.get(user_id, {}))
        items.append(serialized)
    return {
        "items": items,
        "total": total,
        "page": safe_page,
        "page_size": safe_page_size,
    }


def get_user_registry_entry(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    action_limit: int = 20,
) -> dict[str, Any] | None:
    normalized_user_id = str(user_id or "").strip()
    if not normalized_user_id:
        return None
    registry = db.scalar(
        select(UserRegistry).where(
            UserRegistry.tenant_id == tenant_id,
            UserRegistry.user_id == normalized_user_id,
        )
    )
    if registry is None:
        return None

    endpoint_map = _latest_endpoints_by_user(
        db,
        tenant_id=tenant_id,
        user_ids=[normalized_user_id],
    )
    action_counts = _activity_counts_by_user(
        db,
        tenant_id=tenant_id,
        user_ids=[normalized_user_id],
    )
    endpoint = endpoint_map.get(normalized_user_id)
    runtime_context = _runtime_user_profile_context(
        db,
        tenant_id=tenant_id,
        user_ids=[normalized_user_id],
    ).get(normalized_user_id, {})

    action_rows = db.scalars(
        select(AIAction)
        .where(
            AIAction.tenant_id == tenant_id,
            AIAction.user_id == normalized_user_id,
        )
        .order_by(desc(AIAction.timestamp))
        .limit(max(1, min(100, int(action_limit))))
    ).all()
    action_ids = [row.action_id for row in action_rows if str(row.action_id or "").strip()]
    prompt_by_action = (
        {
            item.action_id: item
            for item in db.scalars(select(PromptPayload).where(PromptPayload.action_id.in_(action_ids))).all()
        }
        if action_ids
        else {}
    )
    alert_rows = (
        db.scalars(
            select(AIActionAlert)
            .where(
                AIActionAlert.tenant_id == tenant_id,
                AIActionAlert.action_id.in_(action_ids),
            )
            .order_by(desc(AIActionAlert.created_at))
        ).all()
        if action_ids
        else []
    )
    alerts_by_action: dict[str, list[AIActionAlert]] = {}
    for alert in alert_rows:
        alerts_by_action.setdefault(alert.action_id, []).append(alert)

    serialized_user = _serialize_user_registry(
        registry,
        primary_endpoint=endpoint,
        ai_activity_count=max(
            action_counts.get(normalized_user_id, 0),
            int(runtime_context.get("ai_activity_count", 0)),
        ),
    )
    serialized_user.update(runtime_context)

    return {
        "user": serialized_user,
        "machine_id": endpoint.endpoint_id if endpoint else None,
        "browser_type": endpoint.browser_type if endpoint else None,
        "last_seen": registry.last_seen_at.isoformat() if registry.last_seen_at else None,
        "ai_activity_count": int(serialized_user.get("ai_activity_count") or 0),
        "recent_actions": [
            _serialize_action(
                row,
                prompt_payload=prompt_by_action.get(row.action_id),
                alerts=alerts_by_action.get(row.action_id, []),
            )
            for row in action_rows
        ],
    }


def list_deployment_endpoints(
    db: Session,
    *,
    tenant_id: str,
    q: str | None = None,
    user_id: str | None = None,
    page: int = 1,
    page_size: int = 100,
) -> dict[str, Any]:
    stmt = select(DeploymentEndpoint).where(DeploymentEndpoint.tenant_id == tenant_id)
    if user_id:
        stmt = stmt.where(DeploymentEndpoint.user_id == user_id)
    query = str(q or "").strip().lower()
    if query:
        stmt = stmt.where(
            or_(
                func.lower(DeploymentEndpoint.endpoint_id).contains(query),
                func.lower(DeploymentEndpoint.hostname).contains(query),
                func.lower(DeploymentEndpoint.browser_type).contains(query),
            )
        )
    rows = db.scalars(stmt.order_by(desc(DeploymentEndpoint.last_seen_at))).all()
    page_items, total, safe_page, safe_page_size = paginate_rows(rows, page=page, page_size=page_size)
    endpoint_identity_by_user = _load_user_identity_map(
        db,
        tenant_id=tenant_id,
        user_ids=[item.user_id for item in page_items],
    )
    return {
        "items": [
            _serialize_endpoint(item, user_identity=endpoint_identity_by_user.get(str(item.user_id or "")))
            for item in page_items
        ],
        "total": total,
        "page": safe_page,
        "page_size": safe_page_size,
    }


def search_activity_audit(
    db: Session,
    *,
    tenant_id: str,
    user: str | None = None,
    device: str | None = None,
    ai_app: str | None = None,
    prompt_keyword: str | None = None,
    alert_type: str | None = None,
    runtime_event_id: str | None = None,
    page: int = 1,
    page_size: int = 100,
) -> dict[str, Any]:
    stmt = (
        select(AIAction)
        .join(AISession, AISession.session_id == AIAction.session_id)
        .join(
            DeploymentEndpoint,
            and_(
                DeploymentEndpoint.endpoint_id == AIAction.endpoint_id,
                DeploymentEndpoint.tenant_id == AIAction.tenant_id,
            ),
            isouter=True,
        )
        .join(
            UserRegistry,
            and_(
                UserRegistry.user_id == AIAction.user_id,
                UserRegistry.tenant_id == AIAction.tenant_id,
            ),
            isouter=True,
        )
        .where(AIAction.tenant_id == tenant_id)
    )
    if runtime_event_id:
        stmt = stmt.where(AIAction.runtime_event_id == str(runtime_event_id).strip())
    user_query = str(user or "").strip().lower()
    if user_query:
        stmt = stmt.where(
            or_(
                func.lower(UserRegistry.email).contains(user_query),
                func.lower(UserRegistry.display_name).contains(user_query),
                func.lower(AIAction.user_id).contains(user_query),
            )
        )
    device_query = str(device or "").strip().lower()
    if device_query:
        stmt = stmt.where(
            or_(
                func.lower(DeploymentEndpoint.endpoint_id).contains(device_query),
                func.lower(DeploymentEndpoint.hostname).contains(device_query),
            )
        )
    ai_app_query = str(ai_app or "").strip().lower()
    if ai_app_query:
        stmt = stmt.where(func.lower(AIAction.ai_app).contains(ai_app_query))

    actions = db.scalars(stmt.order_by(desc(AIAction.timestamp))).all()
    action_ids = [item.action_id for item in actions]

    prompt_by_action = {
        item.action_id: item
        for item in db.scalars(select(PromptPayload).where(PromptPayload.action_id.in_(action_ids))).all()
    } if action_ids else {}
    alerts = []
    if action_ids:
        alerts = db.scalars(
            select(AIActionAlert).where(
                AIActionAlert.tenant_id == tenant_id,
                AIActionAlert.action_id.in_(action_ids),
            )
        ).all()
    alerts_by_action: dict[str, list[AIActionAlert]] = {}
    for item in alerts:
        alerts_by_action.setdefault(item.action_id, []).append(item)

    prompt_query = str(prompt_keyword or "").strip().lower()
    alert_query = str(alert_type or "").strip().lower()
    filtered: list[AIAction] = []
    for row in actions:
        prompt_row = prompt_by_action.get(row.action_id)
        action_alerts = alerts_by_action.get(row.action_id, [])
        if prompt_query:
            redacted = str(getattr(prompt_row, "redacted_prompt", "") or "").lower()
            if prompt_query not in redacted:
                continue
        if alert_query:
            if not any(alert_query in str(item.alert_type or "").lower() for item in action_alerts):
                continue
        filtered.append(row)

    page_items, total, safe_page, safe_page_size = paginate_rows(filtered, page=page, page_size=page_size)
    page_action_ids = [row.action_id for row in page_items]
    return {
        "items": [
            _serialize_action(
                row,
                prompt_payload=prompt_by_action.get(row.action_id),
                alerts=[item for item in alerts_by_action.get(row.action_id, [])],
            )
            for row in page_items
        ],
        "total": total,
        "page": safe_page,
        "page_size": safe_page_size,
        "query": {
            "user": user,
            "device": device,
            "ai_app": ai_app,
            "prompt_keyword": prompt_keyword,
            "alert_type": alert_type,
            "runtime_event_id": runtime_event_id,
        },
    }
