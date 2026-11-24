from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlparse
from uuid import uuid4

from sqlalchemy import and_, desc, select
from sqlalchemy.orm import Session

from app.core.control_engine.canonical_action import ControlPathEvidence
from app.core.control_engine import map_generic_decision
from app.db.models.activity_audit import AIAction, AIActionAlert, AISession, DeploymentEndpoint, PromptPayload, UserRegistry
from app.db.models.policy import PolicyVersion
from app.db.models.runtime_intelligence import RuntimeEvent
from app.services.activity_audit_service import get_user_timeline, record_activity_event
from app.services.ai_graph.service import build_unified_ai_graph
from app.services.evidence_service import create_evidence_node
from app.services.findings_service import generate_unprotected_path_finding
from app.services.privacy_sanitizer import sanitize_privacy_payload
from app.services.runtime_intelligence.runtime_event_normalizer import ingest_runtime_event
from app.services.runtime_intelligence.schemas import RuntimeEventIngestPayload
from app.services.sensitive_data_detection_service import classify_data, detect_sensitive_data, detection_signal_types


SURFACE_TO_RUNTIME_SOURCE = {
    "browser": "browser",
    "saas": "connector",
    "connector": "connector",
    "desktop": "endpoint",
    "endpoint": "endpoint",
    "developer_tool": "gateway",
    "dev_tool": "gateway",
    "gateway": "gateway",
    "sdk": "sdk",
    "agent": "aiiam",
    "aiiam": "aiiam",
    "foundry": "foundry",
    "microsoft_foundry": "foundry",
    "azure_ai_foundry": "foundry",
    "copilot": "copilot",
    "m365_copilot": "copilot",
    "office_copilot": "copilot",
    "copilot_studio": "copilot",
}

KNOWN_AI_HINTS = (
    "chatgpt",
    "openai",
    "azure openai",
    "azure_openai",
    "azure ai foundry",
    "azure_ai_foundry",
    "microsoft foundry",
    "microsoft_foundry",
    "foundry",
    "anthropic",
    "claude",
    "gemini",
    "copilot",
    "copilot studio",
    "copilot_studio",
    "m365 copilot",
    "m365_copilot",
    "llm",
    "prompt",
    "codex",
    "mistral",
)

SENSITIVE_QUERY_KEYS = {
    "token",
    "access_token",
    "api_key",
    "apikey",
    "secret",
    "password",
    "auth",
    "authorization",
}

SURFACE_METADATA_DENYLIST = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "bypass_confirmed",
    "bypass_detection",
    "bypass_observed",
    "content",
    "hawk_validated_bypass_observation",
    "password",
    "prompt",
    "prompt_or_content",
    "raw_content",
    "raw_prompt",
    "refresh_token",
    "secret",
    "token",
}

SENSITIVE_PATH_MARKERS = {
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "credential",
    "password",
    "private_key",
    "secret",
    "session_token",
    "token",
}

UNPROTECTED_RAW_MATERIAL_KEYS = {
    "args",
    "arguments",
    "content",
    "input",
    "kwargs",
    "messages",
    "original_intent",
    "output",
    "parameters",
    "prompt",
    "prompt_or_content",
    "prompt_raw",
    "prompt_text",
    "raw_content",
    "raw_prompt",
    "request_body",
    "response_body",
    "tool_args",
    "tool_arguments",
}

UNPROTECTED_AUTHORITY_KEYS = {
    "activity_audit_managed_by_source",
    "ai_action",
    "authorization_coverage",
    "bypass_confirmed",
    "bypass_detection",
    "bypass_observed",
    "canonical_ai_action_v1",
    "control_decision",
    "control_mode",
    "decision",
    "decision_receipt",
    "decision_receipt_verified",
    "deployment_coverage",
    "deployment_surface_id",
    "deployment_surface_row_id",
    "enforcement_path",
    "evidence_coverage",
    "execution_evidence_verified",
    "execution_observed",
    "execution_receipt",
    "final_decision",
    "gateway_bypass_detected",
    "gateway_id",
    "gateway_routed",
    "hawk_validated_bypass_observation",
    "identity_binding_state",
    "input_signal_types",
    "policy_evaluation",
    "policy_snapshot",
    "reason_code",
    "reason_codes",
    "receipt",
    "receipts",
    "mcp_server_id",
    "sdk_registration_id",
    "triggered_controls",
}

VALIDATED_BYPASS_OBSERVATION_KEY = "hawk_validated_bypass_observation"

APP_ALIAS_TO_DOMAIN = {
    "slack": "slack.com",
    "slack desktop": "slack.com",
    "slack_desktop": "slack.com",
    "o365": "outlook.office.com",
    "office365": "outlook.office.com",
    "microsoft_365": "outlook.office.com",
    "entra": "login.microsoftonline.com",
    "entra_id": "login.microsoftonline.com",
    "microsoft_entra": "login.microsoftonline.com",
    "outlook": "outlook.office.com",
    "outlook desktop": "outlook.office.com",
    "outlook_desktop": "outlook.office.com",
    "teams": "teams.microsoft.com",
    "onedrive": "onedrive.live.com",
    "sharepoint": "sharepoint.com",
    "onedrive_sharepoint": "sharepoint.com",
    "office_apps": "office.com",
    "word": "office.com",
    "excel": "office.com",
    "powerpoint": "office.com",
    "microsoft_defender": "security.microsoft.com",
    "azure_openai": "api.openai.azure.com",
    "azure_ai_foundry": "ai.azure.com",
    "microsoft_foundry": "ai.azure.com",
    "foundry": "ai.azure.com",
    "m365_copilot": "copilot.microsoft.com",
    "office_copilot": "copilot.microsoft.com",
    "copilot_studio": "copilotstudio.microsoft.com",
    "power_platform": "powerplatform.microsoft.com",
    "google_workspace": "workspace.google.com",
    "gmail": "mail.google.com",
    "gdrive": "drive.google.com",
    "google_drive": "drive.google.com",
    "chatgpt": "chatgpt.com",
    "claude": "claude.ai",
    "gemini": "gemini.google.com",
    "vs code": "vscode",
    "visual studio code": "vscode",
    "vscode": "vscode",
    "ide": "ide",
    "ides": "ide",
    "github desktop": "github_desktop",
    "github_desktop": "github_desktop",
    "codex cli": "api.openai.com",
    "codex_cli": "api.openai.com",
    "terminal": "terminal",
    "terminals": "terminal",
    "openai_sdk": "api.openai.com",
    "langchain": "api.openai.com",
}

APP_ALIAS_TO_KEY = {
    "slack": "slack",
    "slack desktop": "slack_desktop",
    "slack_desktop": "slack_desktop",
    "outlook": "outlook",
    "outlook desktop": "outlook_desktop",
    "outlook_desktop": "outlook_desktop",
    "teams": "teams",
    "microsoft_365": "microsoft_365",
    "o365": "microsoft_365",
    "office365": "microsoft_365",
    "entra": "entra_id",
    "entra_id": "entra_id",
    "microsoft_entra": "entra_id",
    "vs code": "vscode",
    "visual studio code": "vscode",
    "vscode": "vscode",
    "ide": "ide",
    "ides": "ide",
    "github desktop": "github_desktop",
    "github_desktop": "github_desktop",
    "codex cli": "codex_cli",
    "codex_cli": "codex_cli",
    "terminal": "terminal",
    "terminals": "terminal",
    "chatgpt": "chatgpt",
    "claude": "claude",
    "gemini": "gemini",
    "azure_openai": "azure_openai",
    "azure_ai_foundry": "microsoft_foundry",
    "microsoft_foundry": "microsoft_foundry",
    "foundry": "microsoft_foundry",
    "m365_copilot": "m365_copilot",
    "office_copilot": "m365_copilot",
    "copilot_studio": "copilot_studio",
    "openai_sdk": "openai_sdk",
    "langchain": "langchain",
}

SEVERITY_BY_DECISION = {
    "allow": "low",
    "warn": "med",
    "block": "high",
}

ENFORCEMENT_ACTION_BY_DECISION = {
    "allow": "allowed",
    "warn": "warned",
    "block": "blocked",
}


def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _to_datetime(value: Any) -> datetime:
    token = _safe_str(value)
    if not token:
        return datetime.now(timezone.utc)
    try:
        parsed = datetime.fromisoformat(token.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _redacted_preview(value: str) -> str:
    text = _safe_str(value)
    if not text:
        return ""
    if len(text) <= 12:
        return "[redacted]"
    return f"{text[:6]}...{text[-6:]}"


def _safe_surface_metadata(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    metadata: dict[str, Any] = {}
    for key, item in value.items():
        normalized_key = _safe_str(key)
        if (
            not normalized_key
            or _normalized_metadata_key(normalized_key) in SURFACE_METADATA_DENYLIST
        ):
            continue
        metadata[normalized_key] = item
    return metadata


def _normalize_surface(value: str | None) -> tuple[str, str]:
    raw = _safe_str(value).lower() or "saas"
    runtime_source = SURFACE_TO_RUNTIME_SOURCE.get(raw, "connector")
    return raw, runtime_source


def _application_key(app: str) -> str:
    raw = _safe_str(app).lower()
    if not raw:
        return "unknown_app"
    if raw in APP_ALIAS_TO_KEY:
        return APP_ALIAS_TO_KEY[raw]
    return raw.replace("-", "_").replace(" ", "_")


def _normalize_app_domain(*, app: str, app_domain: str, url: str) -> str:
    if app_domain:
        return app_domain
    parsed = urlparse(url) if url else None
    if parsed and _safe_str(parsed.hostname):
        return _safe_str(parsed.hostname).lower()
    app_lower = app.lower()
    alias = APP_ALIAS_TO_DOMAIN.get(app_lower) or APP_ALIAS_TO_DOMAIN.get(_application_key(app_lower))
    if alias:
        return alias
    return app_lower


def _transport_is_secure(event: dict[str, Any]) -> tuple[bool, str | None]:
    transport = dict(event.get("transport") or {}) if isinstance(event.get("transport"), dict) else {}
    if not transport:
        return True, None

    endpoint_url = _safe_str(event.get("api_endpoint") or event.get("url") or transport.get("endpoint_url"))
    tls_version = _safe_str(transport.get("tls_version")).lower()
    scheme = _safe_str(transport.get("scheme")).lower()
    require_tls = bool(transport.get("require_tls", True))
    require_mtls = bool(transport.get("require_mtls", False))
    mtls_enabled = bool(transport.get("mtls_enabled", False))
    require_cert_pinning = bool(transport.get("require_cert_pinning", False))
    cert_pinned = bool(transport.get("cert_pinned", False))

    parsed = urlparse(endpoint_url) if endpoint_url else None
    host = _safe_str(parsed.hostname if parsed else "").lower()
    is_localhost = host in {"localhost", "127.0.0.1", "::1"}

    if require_tls and endpoint_url and not is_localhost:
        resolved_scheme = scheme or _safe_str(parsed.scheme if parsed else "").lower()
        if resolved_scheme != "https":
            return False, "transport_tls_required"
        if tls_version and tls_version not in {"1.3", "tls1.3", "tlsv1.3", "tls_1_3"}:
            return False, "transport_tls_1_3_required"

    if require_mtls and not mtls_enabled:
        return False, "transport_mtls_required"
    if require_cert_pinning and not cert_pinned:
        return False, "transport_certificate_pinning_required"

    if endpoint_url and parsed and parsed.query:
        for key, _value in parse_qsl(parsed.query, keep_blank_values=True):
            token = _safe_str(key).lower()
            if token in SENSITIVE_QUERY_KEYS or any(marker in token for marker in ("secret", "token", "auth", "password")):
                return False, "transport_sensitive_query_param"
    return True, None


def _contains_sensitive_path_marker(value: str) -> bool:
    decoded = unquote(value).strip()
    normalized = decoded.lower().replace("-", "_")
    return any(marker in normalized for marker in SENSITIVE_PATH_MARKERS)


def _normalized_metadata_key(value: Any) -> str:
    text = _safe_str(value)
    text = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", text)
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    return re.sub(r"[^a-zA-Z0-9]+", "_", text).strip("_").lower()


def _is_unprotected_raw_material_key(value: Any) -> bool:
    normalized = _normalized_metadata_key(value)
    return (
        normalized in UNPROTECTED_RAW_MATERIAL_KEYS
        or normalized.endswith(
            (
                "_arguments",
                "_args",
                "_kwargs",
                "_prompt",
                "_prompt_or_content",
                "_prompt_raw",
                "_prompt_text",
            )
        )
    )


def _find_unprotected_request_material(value: Any, *, depth: int = 0) -> Any:
    if depth > 6:
        return None
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = _normalized_metadata_key(key)
            if (
                normalized
                in {
                    "args",
                    "arguments",
                    "kwargs",
                    "parameters",
                    "request_body",
                    "tool_args",
                    "tool_arguments",
                }
                or normalized.endswith(("_arguments", "_args", "_kwargs"))
            ):
                return item
        for item in value.values():
            found = _find_unprotected_request_material(item, depth=depth + 1)
            if found is not None:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_unprotected_request_material(item, depth=depth + 1)
            if found is not None:
                return found
    return None


def _looks_like_sensitive_path_segment(value: str) -> bool:
    decoded = unquote(value).strip()
    if _contains_sensitive_path_marker(decoded):
        return True
    if len(decoded) < 32 or not re.fullmatch(r"[A-Za-z0-9._~+/=-]+", decoded):
        return False
    character_classes = sum(
        bool(re.search(pattern, decoded))
        for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[-._~+/=]")
    )
    return character_classes >= 3


def _normalize_structural_route_path(value: str) -> str:
    """Collapse RFC-style dot segments before hashing or displaying a route."""

    raw_path = value or "/"
    segments: list[str] = []
    for segment in raw_path.split("/"):
        decoded = unquote(segment)
        if decoded == ".":
            continue
        if decoded == "..":
            if segments and not (len(segments) == 1 and segments[0] == ""):
                segments.pop()
            continue
        segments.append(segment)
    normalized = "/".join(segments)
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    return normalized or "/"


def _canonical_unprotected_route(value: Any) -> tuple[str, str] | None:
    """Return a safe route display and opaque hash; never persist raw secret material."""

    raw = _safe_str(value)
    if not raw:
        return None
    try:
        parsed = urlparse(raw)
        scheme = _safe_str(parsed.scheme).lower()
        hostname = _safe_str(parsed.hostname).lower()
        parsed_port = parsed.port
    except ValueError:
        return None
    if scheme not in {"http", "https"} or not hostname:
        return None
    safe_hostname = f"[{hostname}]" if ":" in hostname else hostname
    port = f":{parsed_port}" if parsed_port is not None else ""
    raw_path = _normalize_structural_route_path(parsed.path or "/")
    hash_material = f"{scheme}://{safe_hostname}{port}{raw_path}"
    safe_segments: list[str] = []
    redact_next_segment = False
    for segment in raw_path.split("/"):
        contains_marker = _contains_sensitive_path_marker(segment)
        should_redact = (
            redact_next_segment
            or contains_marker
            or _looks_like_sensitive_path_segment(segment)
        )
        safe_segments.append(
            f"[redacted-{hashlib.sha256(segment.encode('utf-8')).hexdigest()[:12]}]"
            if should_redact and segment
            else segment
        )
        if segment:
            redact_next_segment = bool(contains_marker)
    safe_path = "/".join(safe_segments) or "/"
    display = f"{scheme}://{safe_hostname}{port}{safe_path}"[:512]
    return display, hashlib.sha256(hash_material.encode("utf-8")).hexdigest()


def _sanitize_unprotected_metadata_urls(value: Any, *, depth: int = 0) -> Any:
    """Apply standard privacy filtering, then canonicalize every nested URL."""

    if depth == 0:
        value = sanitize_privacy_payload(value)
    if depth > 6:
        return "[omitted:max_depth]"
    if isinstance(value, dict):
        return {
            str(key): _sanitize_unprotected_metadata_urls(item, depth=depth + 1)
            for key, item in value.items()
            if not _is_unprotected_raw_material_key(key)
            and _normalized_metadata_key(key) not in UNPROTECTED_AUTHORITY_KEYS
        }
    if isinstance(value, list):
        return [
            _sanitize_unprotected_metadata_urls(item, depth=depth + 1)
            for item in value
        ]
    if isinstance(value, str) and value.strip().lower().startswith(("http://", "https://")):
        canonical = _canonical_unprotected_route(value)
        return canonical[0] if canonical is not None else "[redacted]"
    return value


def _observed_unprotected_route(
    *,
    event: dict[str, Any],
    normalized_surface: str,
    action_type: str,
    bypass_detected: bool,
) -> tuple[str, str, str] | None:
    """Classify explicit monitor-mode LLM/MCP telemetry using existing surface fields."""

    if not bypass_detected:
        return None
    if normalized_surface not in {"developer_tool", "dev_tool", "endpoint", "desktop"}:
        return None
    if _safe_str(event.get("platform_mode")).lower() not in {"monitor", "monitor_only", "telemetry_only"}:
        return None
    canonical = _canonical_unprotected_route(event.get("api_endpoint") or event.get("url"))
    if canonical is None:
        return None
    route, path_fingerprint = canonical
    tool_name = _safe_str(event.get("tool"))
    if action_type == "tool_call" and tool_name:
        return "mcp", route, path_fingerprint
    if (
        action_type == "api_call"
        and not tool_name
        and _safe_str(event.get("provider"))
        and _safe_str(event.get("model"))
    ):
        return "llm", route, path_fingerprint
    return None


def _detect_ai_usage(event: dict[str, Any], prompt_or_content: str) -> bool:
    explicit = event.get("ai_usage_detected")
    if isinstance(explicit, bool):
        return explicit

    app = _safe_str(event.get("app")).lower()
    model = _safe_str(event.get("model")).lower()
    endpoint = _safe_str(event.get("api_endpoint") or event.get("url")).lower()
    action_type = _safe_str(event.get("action_type")).lower()
    text = f"{app} {model} {endpoint} {_safe_str(prompt_or_content).lower()}"

    if any(hint in text for hint in KNOWN_AI_HINTS):
        return True
    if action_type in {"prompt_input", "tool_call", "api_call", "response"} and bool(_safe_str(prompt_or_content)):
        return True
    return False


def _derive_decision_from_runtime(metadata: dict[str, Any], default: str) -> str:
    control_decision = dict(metadata.get("control_decision") or {}) if isinstance(metadata.get("control_decision"), dict) else {}
    generic_control_decision = _safe_str(control_decision.get("decision")).lower()
    if generic_control_decision:
        return map_generic_decision(
            generic_control_decision,
            mapping={
                "allow": "allow",
                "alert": "warn",
                "modify": "warn",
                "step_up": "warn",
                "block": "block",
            },
            default=default,
        )

    policy_decision = _safe_str(dict(metadata.get("policy_evaluation") or {}).get("decision")).lower()
    if policy_decision in {"deny"}:
        return "block"
    if policy_decision in {"modify", "step_up", "defer"}:
        return "warn"
    if policy_decision in {"allow"}:
        return "allow"
    return default


def _policy_triggered(metadata: dict[str, Any]) -> str | None:
    reason_code = _safe_str(metadata.get("reason_code"))
    if reason_code:
        return reason_code
    reason_codes = metadata.get("reason_codes")
    if isinstance(reason_codes, list):
        for item in reason_codes:
            token = _safe_str(item)
            if token:
                return token
    triggered_controls = metadata.get("triggered_controls")
    if isinstance(triggered_controls, list):
        for item in triggered_controls:
            token = _safe_str(item)
            if token:
                return token
    return None


def _risk_score_for_event(*, sensitivity_score: float, ai_usage_detected: bool, gateway_bypass: bool, explicit: Any) -> float:
    if explicit is not None:
        try:
            return max(0.0, min(1.0, float(explicit)))
        except (TypeError, ValueError):
            pass
    base = 0.12
    if ai_usage_detected:
        base += 0.25
    base += float(max(0.0, min(1.0, sensitivity_score))) * 0.45
    if gateway_bypass:
        base += 0.28
    return round(max(0.0, min(1.0, base)), 4)


def _resolve_runtime_policy_version_id(
    db: Session,
    *,
    tenant_id: str,
    reported_policy_version: Any,
    unprotected_route_observed: bool,
) -> tuple[str | None, dict[str, Any]]:
    reported = _safe_str(reported_policy_version)
    if not reported:
        if unprotected_route_observed:
            return None, {}
        reported = "surface_control_plane_v1"

    row_id = db.scalar(
        select(PolicyVersion.id).where(
            PolicyVersion.id == reported,
            PolicyVersion.tenant_id == tenant_id,
        )
    )
    if row_id:
        return row_id, {"reported_policy_version_id": reported}

    return None, {
        "reported_policy_version_id": reported,
        "policy_version_binding_state": "unresolved",
    }


def ingest_surface_event(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    event: dict[str, Any],
) -> dict[str, Any]:
    raw_surface = _safe_str(event.get("surface") or "saas")
    normalized_surface, runtime_source = _normalize_surface(raw_surface)
    app = _safe_str(event.get("app") or "unknown_app")
    application_key = _application_key(app)
    app_domain = _normalize_app_domain(
        app=app,
        app_domain=_safe_str(event.get("app_domain")),
        url=_safe_str(event.get("url")),
    )
    action_type = _safe_str(event.get("action_type") or event.get("event_type") or "prompt_input").lower()
    prompt_or_content = _safe_str(event.get("prompt_or_content") or event.get("prompt") or event.get("content"))
    correlation_id = _safe_str(event.get("correlation_id")) or str(uuid4())
    timestamp = _to_datetime(event.get("timestamp"))
    user_id = _safe_str(event.get("user_id")) or actor_user_id
    agent_id = _safe_str(event.get("agent_id")) or None
    device_id = _safe_str(event.get("device_id") or event.get("endpoint_id") or event.get("installation_id")) or None
    session_id = _safe_str(event.get("session_id")) or correlation_id
    gateway_routed = bool(event.get("gateway_routed", False))

    sensitivity = detect_sensitive_data(
        text_inputs=[prompt_or_content] if prompt_or_content else [],
        file_meta=list(event.get("file_meta") or []) if isinstance(event.get("file_meta"), list) else [],
        source=f"{normalized_surface}:{app}",
        destination=app_domain,
        user_id=user_id or None,
        agent_id=agent_id or None,
        correlation_id=correlation_id,
    )
    sensitivity_score = float(sensitivity.get("confidence_score") or 0.0)
    contains_sensitive = bool(sensitivity.get("contains_sensitive"))
    ai_usage_detected = _detect_ai_usage(event, prompt_or_content)
    data_classification = classify_data(
        detection_result=sensitivity,
        classification_hint=_safe_str(event.get("data_classification") or event.get("source_classification_hint")) or None,
    )

    transport_allowed, transport_reason = _transport_is_secure(event)
    bypass_detected = bool(
        ai_usage_detected
        and normalized_surface in {"developer_tool", "dev_tool", "endpoint", "desktop"}
        and action_type in {"prompt_input", "api_call", "tool_call", "response"}
        and not gateway_routed
    )
    unprotected_route_observation = _observed_unprotected_route(
        event=event,
        normalized_surface=normalized_surface,
        action_type=action_type,
        bypass_detected=bypass_detected,
    )
    unprotected_route_kind = (
        unprotected_route_observation[0] if unprotected_route_observation is not None else None
    )
    unprotected_route = (
        unprotected_route_observation[1] if unprotected_route_observation is not None else None
    )
    unprotected_path_fingerprint = (
        unprotected_route_observation[2] if unprotected_route_observation is not None else None
    )
    unprotected_route_observed = unprotected_route_observation is not None
    if unprotected_route_observed:
        runtime_source = "endpoint"
    identity_binding_state = (
        "authenticated_self"
        if actor_user_id and user_id == actor_user_id
        else "attributed_by_authenticated_observer"
        if actor_user_id and user_id
        else "unknown"
    )
    bounded_sensitive_entities = [
        {
            "entity_type": _safe_str(item.get("entity_type"))[:64],
            "confidence": float(item.get("confidence") or 0.0),
            "source": _safe_str(item.get("source"))[:64] or None,
        }
        for item in list(sensitivity.get("entities") or [])
        if isinstance(item, dict) and _safe_str(item.get("entity_type"))
    ]
    persisted_sensitivity = (
        {
            "contains_sensitive": contains_sensitive,
            "entities": bounded_sensitive_entities,
            "confidence_score": sensitivity_score,
            "context": {
                "source": f"{normalized_surface}:{app}"[:255],
                "destination": app_domain[:255] or None,
                "agent_id": agent_id,
                "user_id": user_id or None,
                "correlation_id": correlation_id,
            },
            "ocr": {
                "files_processed": len(list(event.get("file_meta") or []))
                if isinstance(event.get("file_meta"), list)
                else 0,
            },
        }
        if unprotected_route_observed
        else sensitivity
    )

    decision_hint = _safe_str(event.get("decision_hint")).lower()
    reason_code = _safe_str(event.get("reason_code")) or None
    if unprotected_route_observed:
        decision_hint = "warn"
        reason_code = f"unprotected_{unprotected_route_kind}_route_observed"
    elif not decision_hint:
        if not transport_allowed:
            decision_hint = "block"
            reason_code = transport_reason or "transport_security_policy_failed"
        elif bypass_detected:
            decision_hint = "block"
            reason_code = "gateway_bypass_detected"
        elif contains_sensitive and normalized_surface == "browser" and ai_usage_detected:
            decision_hint = "block"
            reason_code = reason_code or "sensitive_data_detected"
        elif contains_sensitive:
            decision_hint = "warn"
            reason_code = reason_code or "sensitive_data_detected"
        else:
            decision_hint = "allow"
            reason_code = reason_code or "policy_allow"

    input_signal_types = {
        _safe_str(item) for item in list(event.get("input_signal_types") or []) if _safe_str(item)
    }
    input_signal_types.update(detection_signal_types(sensitivity))
    if bypass_detected:
        input_signal_types.add("gateway_bypass_detected")
    if not transport_allowed:
        input_signal_types.add("transport_policy_violation")
    if ai_usage_detected:
        input_signal_types.add("ai_usage_detected")
    surface_control_ids: list[str] = []
    if unprotected_route_observed:
        surface_control_ids.append("SHADOW_AI_DETECTION")
    elif bypass_detected:
        surface_control_ids.append("GATEWAY_ENFORCEMENT")
    if not transport_allowed:
        surface_control_ids.append("TRANSPORT_SECURITY_CONTROL")
    if contains_sensitive:
        surface_control_ids.append("SENSITIVE_DATA_DETECTION")
    if ai_usage_detected:
        surface_control_ids.append("AI_USAGE_CONTROL")

    risk_score = _risk_score_for_event(
        sensitivity_score=sensitivity_score,
        ai_usage_detected=ai_usage_detected,
        gateway_bypass=bypass_detected or (not transport_allowed),
        explicit=event.get("risk_score"),
    )
    raw_surface_metadata = (
        dict(event.get("metadata") or {})
        if isinstance(event.get("metadata"), dict)
        else {}
    )
    surface_metadata = _safe_surface_metadata(raw_surface_metadata)
    if unprotected_route_observed:
        surface_metadata = _sanitize_unprotected_metadata_urls(surface_metadata)
    transport_metadata = (
        dict(event.get("transport") or {})
        if isinstance(event.get("transport"), dict)
        else {}
    )
    if unprotected_route_observed:
        transport_metadata = _sanitize_unprotected_metadata_urls(transport_metadata)
    prompt_material_hash = (
        hashlib.sha256(prompt_or_content.encode("utf-8")).hexdigest()
        if unprotected_route_observed and prompt_or_content
        else None
    )
    raw_parameter_material = (
        event.get("parameters")
        or event.get("tool_arguments")
        or event.get("request_body")
        or _find_unprotected_request_material(raw_surface_metadata)
        or {}
    )
    server_parameter_hash = hashlib.sha256(
        json.dumps(
            raw_parameter_material,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()

    enforcement_path = "observed_unprotected_route" if unprotected_route_observed else "hawk_ai_gateway"
    policy_version_id, policy_version_metadata = _resolve_runtime_policy_version_id(
        db,
        tenant_id=tenant_id,
        reported_policy_version=event.get("policy_version"),
        unprotected_route_observed=unprotected_route_observed,
    )
    runtime_payload = RuntimeEventIngestPayload(
        tenant_id=tenant_id,
        source_surface=runtime_source,  # type: ignore[arg-type]
        event_type=_safe_str(event.get("event_type")) or f"{normalized_surface}.{app}.{action_type}",
        ai_system_id=_safe_str(event.get("ai_system_id")) or None,
        app_id=app_domain,
        user_id=user_id or None,
        agent_id=agent_id,
        risk_tier=_safe_str(event.get("risk_tier")) or None,
        policy_version_id=policy_version_id,
        governance_version=_safe_str(event.get("governance_version")) or None,
        severity=SEVERITY_BY_DECISION.get(decision_hint, "low"),
        confidence_tier=_safe_str(event.get("confidence_tier")) or None,
        evidence_node_ids=[_safe_str(item) for item in list(event.get("evidence_node_ids") or []) if _safe_str(item)],
        correlation_id=correlation_id,
        context_id=session_id,
        chain_id=_safe_str(event.get("chain_id")) or session_id,
        parent_action_id=_safe_str(event.get("parent_action_id")) or None,
        entity_type=("agent" if agent_id else ("user" if user_id else "tool")),
        entity_id=(agent_id or user_id or app_domain),
        risk_score=risk_score,
        model_provider=_safe_str(event.get("provider") or event.get("model_provider")) or None,
        provider=_safe_str(event.get("provider")) or None,
        model_name=_safe_str(event.get("model")) or None,
        model_version=_safe_str(event.get("model_version")) or None,
        tool_name=_safe_str(event.get("tool") or app) or None,
        tool_category=_safe_str(event.get("tool_category") or normalized_surface) or None,
        api_endpoint=(
            unprotected_route
            if unprotected_route_observed
            else (_safe_str(event.get("api_endpoint")) or None)
        ),
        data_source=_safe_str(event.get("data_source") or normalized_surface) or None,
        response_size=(int(event.get("response_size")) if event.get("response_size") is not None else None),
        chain_depth=(int(event.get("chain_depth")) if event.get("chain_depth") is not None else None),
        parent_agent_id=_safe_str(event.get("parent_agent_id")) or None,
        metadata={
            **surface_metadata,
            **policy_version_metadata,
            "surface": normalized_surface,
            "source_surface": runtime_source,
            "ai_surface": normalized_surface,
            "activity_audit_managed_by_source": True,
            "app": app,
            "application_key": application_key,
            "gateway_routed": gateway_routed,
            "gateway_bypass_detected": bypass_detected,
            VALIDATED_BYPASS_OBSERVATION_KEY: unprotected_route_observed,
            "enforcement_path": enforcement_path,
            **(
                {
                    "control_mode": "post_execution",
                    "authorization_coverage": "not_covered",
                    "deployment_coverage": "not_covered",
                    "execution_observed": True,
                    "authenticated_observer_user_id": actor_user_id,
                    "identity_binding_state": identity_binding_state,
                    "prompt_present": bool(prompt_or_content),
                    "prompt_material_hash": prompt_material_hash,
                    "request_material_present": bool(raw_parameter_material),
                    "request_material_hash": (
                        server_parameter_hash if raw_parameter_material else None
                    ),
                }
                if unprotected_route_observed
                else {}
            ),
            "decision": decision_hint,
            "final_decision": decision_hint,
            "reason_code": reason_code,
            "reason_codes": sorted(input_signal_types),
            "input_signal_types": sorted(input_signal_types),
            "triggered_controls": surface_control_ids,
            "action_type": action_type,
            "operation": action_type,
            "original_intent": (
                None
                if unprotected_route_observed
                else (_safe_str(event.get("prompt_preview_redacted")) or _safe_str(prompt_or_content) or None)
            ),
            "prompt_preview_redacted": (
                None
                if unprotected_route_observed
                else (_safe_str(event.get("prompt_preview_redacted")) or _redacted_preview(prompt_or_content) or None)
            ),
            "contains_sensitive": contains_sensitive,
            "sensitive_confidence_score": sensitivity_score,
            "sensitive_entities": (
                bounded_sensitive_entities
                if unprotected_route_observed
                else list(sensitivity.get("entities") or [])
            ),
            "data_classification": data_classification,
            "ai_usage_detected": ai_usage_detected,
            "transport": transport_metadata,
            "transport_allowed": transport_allowed,
            "transport_failure_reason": transport_reason,
            "device_id": device_id,
            "endpoint_id": device_id,
            "hostname": _safe_str(event.get("hostname")) or None,
            "device_type": _safe_str(event.get("device_type")) or None,
            "os_type": _safe_str(event.get("os_type")) or None,
            "os_version": _safe_str(event.get("os_version")) or None,
            "browser": _safe_str(event.get("browser")) or None,
            "browser_version": _safe_str(event.get("browser_version")) or None,
            "extension_version": _safe_str(event.get("extension_version")) or None,
            "location": _safe_str(event.get("location")) or None,
            "platform_mode": _safe_str(event.get("platform_mode")) or "enforce",
            "metadata": surface_metadata,
        },
    )
    row = ingest_runtime_event(
        db,
        payload=runtime_payload,
        canonical_control_path=(
            ControlPathEvidence(telemetry_observation=True)
            if unprotected_route_observed
            else None
        ),
        trusted_pre_action_governance_check=(
            None
            if unprotected_route_observed
            else {"action": {"parameter_hash": server_parameter_hash}}
        ),
    )
    if row is None:
        return {
            "user_id": user_id or None,
            "app": app,
            "device_id": device_id,
            "prompt_or_content": (
                None
                if unprotected_route_observed
                else (_safe_str(event.get("prompt_preview_redacted")) or _redacted_preview(prompt_or_content) or None)
            ),
            "sensitivity_score": round(sensitivity_score, 4),
            "ai_usage_detected": ai_usage_detected,
            "policy_triggered": reason_code,
            "decision": "warn",
            "timestamp": timestamp.isoformat(),
            "surface": normalized_surface,
            "runtime_event_id": None,
            "audit_action_id": None,
            "alert_id": None,
            "control_ids": [],
            "enforcement_path": enforcement_path,
            "status": "runtime_intelligence_disabled",
            "application_key": application_key,
            "content_preview": (
                None
                if unprotected_route_observed
                else (_safe_str(event.get("prompt_preview_redacted")) or _redacted_preview(prompt_or_content) or None)
            ),
            "gateway_routed": gateway_routed,
            "gateway_bypass_detected": bypass_detected,
            "trace_url": None,
            "remediation_suggestion": "Runtime intelligence is disabled; enable it to trace this event.",
        }

    metadata = dict(row.metadata_json or {}) if isinstance(row.metadata_json, dict) else {}
    final_decision = _derive_decision_from_runtime(metadata, default=decision_hint or "allow")
    if unprotected_route_observed:
        final_decision = "warn"
    if normalized_surface in {"saas", "connector"} and decision_hint == "warn" and final_decision == "block":
        final_decision = "warn"
    policy_triggered = (
        f"unprotected_{unprotected_route_kind}_route_observed"
        if unprotected_route_observed
        else (_policy_triggered(metadata) or reason_code)
    )
    metadata["decision"] = final_decision
    metadata["final_decision"] = final_decision
    if unprotected_route_observed:
        metadata.update(
            {
                "control_mode": "post_execution",
                "authorization_coverage": "not_covered",
                "deployment_coverage": "not_covered",
                "enforcement_path": enforcement_path,
                "execution_observed": True,
                "gateway_routed": False,
                "gateway_bypass_detected": True,
                VALIDATED_BYPASS_OBSERVATION_KEY: True,
                "identity_binding_state": identity_binding_state,
                "reason_code": policy_triggered,
                "triggered_controls": ["SHADOW_AI_DETECTION"],
            }
        )
    if policy_triggered and not _safe_str(metadata.get("reason_code")):
        metadata["reason_code"] = policy_triggered
    if not list(metadata.get("triggered_controls") or []) and surface_control_ids:
        metadata["triggered_controls"] = surface_control_ids
    row.metadata_json = metadata
    row.decision = final_decision
    row.severity = SEVERITY_BY_DECISION.get(final_decision, row.severity or "low")
    db.flush()

    if (
        unprotected_route is not None
        and unprotected_route_kind is not None
        and unprotected_path_fingerprint is not None
    ):
        path_fingerprint = unprotected_path_fingerprint
        is_mcp_route = unprotected_route_kind == "mcp"
        tool_name = _safe_str(event.get("tool"))[:128] or None
        evidence = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="unprotected_path_observation",
            signal_type=f"unprotected_path.{unprotected_route_kind}",
            label=(
                "Observed direct MCP route outside Hawk MCP Gateway"
                if is_mcp_route
                else "Observed direct LLM route outside Hawk AI Gateway"
            ),
            payload={
                "runtime_event_id": row.event_id,
                "route_kind": unprotected_route_kind,
                "route": unprotected_route,
                "path_fingerprint": path_fingerprint,
                "user_id": user_id or None,
                "authenticated_observer_user_id": actor_user_id,
                "identity_binding_state": (
                    identity_binding_state
                ),
                "agent_id": agent_id,
                "machine_id": device_id,
                "app": app[:128],
                "provider": _safe_str(event.get("provider"))[:128] or None,
                "model": _safe_str(event.get("model"))[:128] or None,
                "tool": tool_name,
                "gateway_routed": False,
                "control_mode": "post_execution",
                "authorization_coverage": "not_covered",
                "deployment_coverage": "not_covered",
                "observed_at": row.created_at.isoformat(),
            },
            correlation_id=row.correlation_id,
        )
        row.evidence_node_ids = sorted({*list(row.evidence_node_ids or []), evidence.id})
        finding = generate_unprotected_path_finding(
            db,
            tenant_id=tenant_id,
            source_surface=row.source_surface,
            finding_type=(
                "UNPROTECTED_MCP_ROUTE"
                if is_mcp_route
                else "UNPROTECTED_LLM_ROUTE"
            ),
            ai_tool=(tool_name or app[:128]) if is_mcp_route else app[:128],
            application=unprotected_route,
            provider=_safe_str(event.get("provider"))[:128] or None,
            tool_name=tool_name,
            path_fingerprint=path_fingerprint,
            user_id=user_id or None,
            agent_id=agent_id,
            machine_id=device_id,
            policy_version_id=row.policy_version_id,
            evidence_node_id=evidence.id,
            runtime_event_id=row.event_id,
            recommended_action=(
                (
                    "Route this direct MCP path through Hawk MCP Gateway to add pre-execution authorization; "
                    "current evidence is post-execution monitoring only."
                )
                if is_mcp_route
                else (
                    "Route this direct LLM path through Hawk AI Gateway to add pre-execution authorization; "
                    "current evidence is post-execution monitoring only."
                )
            ),
        )
        metadata = {
            **metadata,
            "finding_id": finding.finding_id,
            "unprotected_path_evidence_node_id": evidence.id,
        }
        row.metadata_json = metadata
        db.flush()

    action_context = {
        "endpoint_id": device_id,
        "hostname": _safe_str(event.get("hostname")) or None,
        "device_type": _safe_str(event.get("device_type")) or None,
        "os_type": _safe_str(event.get("os_type")) or None,
        "os_version": _safe_str(event.get("os_version")) or None,
        "browser": _safe_str(event.get("browser")) or None,
        "browser_version": _safe_str(event.get("browser_version")) or None,
        "extension_version": _safe_str(event.get("extension_version")) or None,
        "location": _safe_str(event.get("location")) or None,
        "source_surface": normalized_surface,
        "session_id": session_id,
        "action_id": row.event_id,
        "timestamp": row.created_at.isoformat(),
        "action_type": action_type,
        "ai_app": app_domain,
        "ai_model": _safe_str(event.get("model")) or None,
        "data_classification": data_classification,
        "sensitivity_score": sensitivity_score,
        "policy_triggered": policy_triggered,
        "enforcement_action": ENFORCEMENT_ACTION_BY_DECISION.get(final_decision, "allowed"),
        "risk_score": float(row.risk_score or risk_score),
        "correlation_id": correlation_id,
        "runtime_event_id": row.event_id,
        "evidence_node_id": (_safe_str((row.evidence_node_ids or [None])[-1]) if row.evidence_node_ids else None),
        "finding_id": _safe_str(metadata.get("finding_id")) or None,
        "prompt_raw": None if unprotected_route_observed else (prompt_or_content or None),
        "prompt_preview_redacted": (
            None
            if unprotected_route_observed
            else (_safe_str(event.get("prompt_preview_redacted")) or _redacted_preview(prompt_or_content) or None)
        ),
        "storage_mode": _safe_str(event.get("prompt_storage_mode")) or None,
        "sensitive_detection": persisted_sensitivity,
        "metadata": {
            "source": _safe_str(dict(event.get("metadata") or {}).get("source")) or None,
            "surface": normalized_surface,
            "source_surface": runtime_source,
            "app": app,
            "application_key": application_key,
            "event_type": row.event_type,
            "transport_allowed": transport_allowed,
            "gateway_routed": gateway_routed,
            "gateway_bypass_detected": bypass_detected,
            "ai_usage_detected": ai_usage_detected,
            "triggered_controls": list(metadata.get("triggered_controls") or surface_control_ids),
            "reason_code": policy_triggered,
            **(
                {
                    VALIDATED_BYPASS_OBSERVATION_KEY: True,
                    "activity_audit_managed_by_source": True,
                    "control_mode": "post_execution",
                    "enforcement_path": enforcement_path,
                    "identity_binding_state": identity_binding_state,
                }
                if unprotected_route_observed
                else {}
            ),
        },
    }
    activity_record = record_activity_event(
        db,
        tenant_id=tenant_id,
        user_id=user_id or None,
        payload=action_context,
    )

    return {
        "user_id": user_id or None,
        "app": app,
        "application_key": application_key,
        "device_id": device_id,
        "prompt_or_content": (
            None
            if unprotected_route_observed
            else (_safe_str(event.get("prompt_preview_redacted")) or _redacted_preview(prompt_or_content) or None)
        ),
        "content_preview": (
            None
            if unprotected_route_observed
            else (_safe_str(event.get("prompt_preview_redacted")) or _redacted_preview(prompt_or_content) or None)
        ),
        "sensitivity_score": round(sensitivity_score, 4),
        "ai_usage_detected": ai_usage_detected,
        "policy_triggered": policy_triggered,
        "decision": final_decision,
        "timestamp": row.created_at.isoformat(),
        "surface": normalized_surface,
        "runtime_event_id": row.event_id,
        "audit_action_id": activity_record.action_id,
        "alert_id": activity_record.alert_id,
        "control_ids": list(metadata.get("triggered_controls") or surface_control_ids),
        "enforcement_path": enforcement_path,
        "gateway_routed": gateway_routed,
        "gateway_bypass_detected": bypass_detected,
        "trace_url": f"/surface-coverage/alerts/{activity_record.alert_id}" if activity_record.alert_id else f"/runtime/trace/{row.event_id}",
        "remediation_suggestion": (
            (
                "Route this direct MCP path through Hawk MCP Gateway; current evidence is post-execution monitoring only."
                if unprotected_route_kind == "mcp"
                else "Route this direct LLM path through Hawk AI Gateway; current evidence is post-execution monitoring only."
            )
            if unprotected_route_observed
            else "Route this AI traffic through Hawk AI Gateway and tighten policy for this surface."
            if bypass_detected
            else (
                "Review policy scope and evidence for this AI interaction."
                if final_decision in {"warn", "block"}
                else "Continue monitoring."
            )
        ),
        "session_id": activity_record.session_id,
        "endpoint_id": activity_record.endpoint_id,
    }


def _promote_surface_timeline_fields(timeline: dict[str, Any]) -> dict[str, Any]:
    """Expose surface-control fields at the timeline action top level."""
    promoted = dict(timeline or {})
    actions: list[dict[str, Any]] = []
    for item in list(promoted.get("actions") or []):
        if not isinstance(item, dict):
            continue
        row = dict(item)
        metadata = dict(row.get("metadata") or {}) if isinstance(row.get("metadata"), dict) else {}
        row["source_surface"] = (
            _safe_str(row.get("source_surface"))
            or _safe_str(metadata.get("surface"))
            or _safe_str(metadata.get("source_surface"))
            or None
        )
        row["application_key"] = (
            _safe_str(row.get("application_key"))
            or _safe_str(metadata.get("application_key"))
            or _application_key(_safe_str(metadata.get("app") or row.get("ai_app")))
        )
        row["gateway_routed"] = bool(metadata.get("gateway_routed", False))
        row["gateway_bypass_detected"] = bool(metadata.get("gateway_bypass_detected", False))
        row["ai_usage_detected"] = bool(metadata.get("ai_usage_detected", False))
        if "content_preview" not in row:
            prompt_payload = row.get("prompt_payload")
            prompt_data = dict(prompt_payload or {}) if isinstance(prompt_payload, dict) else {}
            row["content_preview"] = (
                _safe_str(prompt_data.get("redacted_prompt"))
                or _safe_str(metadata.get("prompt_preview_redacted"))
                or None
            )
        actions.append(row)
    promoted["actions"] = actions
    return promoted


def get_identity_unified_view(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    lookback_hours: int = 24 * 7,
) -> dict[str, Any]:
    timeline = get_user_timeline(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        page=1,
        page_size=200,
    )
    timeline = _promote_surface_timeline_fields(timeline)
    graph = build_unified_ai_graph(
        db,
        tenant_id=tenant_id,
        lookback_hours=lookback_hours,
        user_id=user_id,
    )
    user_row = db.scalar(
        select(UserRegistry).where(
            UserRegistry.tenant_id == tenant_id,
            UserRegistry.user_id == user_id,
        )
    )
    return {
        "identity": {
            "user_id": user_id,
            "display_name": _safe_str(getattr(user_row, "display_name", "")) or None,
            "email": _safe_str(getattr(user_row, "email", "")) or None,
            "risk_score": float(getattr(user_row, "risk_score", 0.0) or 0.0),
            "violation_count": int(getattr(user_row, "violation_count", 0) or 0),
            "deployment_surfaces": list(getattr(user_row, "deployment_surfaces", []) or []),
        },
        "timeline": timeline,
        "graph": graph,
    }


def list_unified_alerts(
    db: Session,
    *,
    tenant_id: str,
    user_id: str | None = None,
    app: str | None = None,
    severity: str | None = None,
    surface: str | None = None,
) -> list[dict[str, Any]]:
    stmt = select(AIActionAlert).where(AIActionAlert.tenant_id == tenant_id)
    if user_id:
        stmt = stmt.where(AIActionAlert.user_id == user_id)
    if severity:
        stmt = stmt.where(AIActionAlert.severity == _safe_str(severity).lower())
    alerts = db.scalars(stmt.order_by(desc(AIActionAlert.created_at)).limit(1000)).all()
    if not alerts:
        return []

    action_ids = [_safe_str(item.action_id) for item in alerts if _safe_str(item.action_id)]
    actions = db.scalars(
        select(AIAction).where(
            AIAction.tenant_id == tenant_id,
            AIAction.action_id.in_(action_ids),
        )
    ).all()
    action_by_id = {item.action_id: item for item in actions}
    prompt_rows = db.scalars(select(PromptPayload).where(PromptPayload.action_id.in_(action_ids))).all()
    prompt_by_action = {item.action_id: item for item in prompt_rows}

    out: list[dict[str, Any]] = []
    for row in alerts:
        action = action_by_id.get(row.action_id)
        if action is None:
            continue
        metadata = dict(action.metadata_json or {}) if isinstance(action.metadata_json, dict) else {}
        action_surface = _safe_str(metadata.get("source_surface") or metadata.get("surface")).lower() or "unknown"
        action_app = _safe_str(action.ai_app or metadata.get("app") or metadata.get("domain"))
        if app and _safe_str(app).lower() not in action_app.lower():
            continue
        if surface and _safe_str(surface).lower() != action_surface:
            continue
        prompt_row = prompt_by_action.get(action.action_id)
        source_token = _safe_str(dict(metadata.get("metadata") or {}).get("source")).lower()
        if not source_token and action_app in {"outlook", "teams", "onedrive", "sharepoint", "word", "excel", "powerpoint", "azure_openai"}:
            source_token = "microsoft"
        if not source_token and "openai.azure.com" in action_app:
            source_token = "azure_openai"
        elif source_token.startswith("microsoft") or source_token in {"office_copilot", "azure_openai"}:
            source_token = "microsoft"
        out.append(
            {
                "alert_id": row.id,
                "action_id": action.action_id,
                "user_id": row.user_id,
                "device_id": action.endpoint_id,
                "app": action_app,
                "surface": action_surface,
                "severity": row.severity,
                "alert_type": row.alert_type,
                "policy_reason": row.policy_reason,
                "decision": action.enforcement_action,
                "timestamp": row.created_at.isoformat() if row.created_at else None,
                "prompt_preview_redacted": _safe_str(getattr(prompt_row, "redacted_prompt", "")) or None,
                "source": source_token or None,
            }
        )
    return out


def get_unified_alert_trace(
    db: Session,
    *,
    tenant_id: str,
    alert_id: str,
) -> dict[str, Any] | None:
    alert = db.scalar(
        select(AIActionAlert).where(
            AIActionAlert.tenant_id == tenant_id,
            AIActionAlert.id == alert_id,
        )
    )
    if alert is None:
        return None

    action = db.scalar(
        select(AIAction).where(
            AIAction.tenant_id == tenant_id,
            AIAction.action_id == alert.action_id,
        )
    )
    if action is None:
        return None

    session = db.scalar(
        select(AISession).where(
            AISession.tenant_id == tenant_id,
            AISession.session_id == action.session_id,
        )
    )
    endpoint = None
    if action.endpoint_id:
        endpoint = db.scalar(
            select(DeploymentEndpoint).where(
                DeploymentEndpoint.tenant_id == tenant_id,
                DeploymentEndpoint.endpoint_id == action.endpoint_id,
            )
        )
    prompt_payload = db.scalar(select(PromptPayload).where(PromptPayload.action_id == action.action_id))
    metadata = dict(action.metadata_json or {}) if isinstance(action.metadata_json, dict) else {}
    return {
        "alert": {
            "alert_id": alert.id,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "policy_reason": alert.policy_reason,
            "enforcement_action": alert.enforcement_action,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
        },
        "trace": {
            "user_id": action.user_id,
            "app": action.ai_app,
            "device_id": action.endpoint_id,
            "surface": _safe_str(metadata.get("source_surface") or metadata.get("surface")) or None,
            "prompt": {
                "storage_mode": _safe_str(getattr(prompt_payload, "storage_mode", "")) or None,
                "raw_prompt": getattr(prompt_payload, "raw_prompt", None),
                "redacted_prompt": getattr(prompt_payload, "redacted_prompt", None),
                "pii_detected": bool(getattr(prompt_payload, "pii_detected", False)),
            },
            "control_triggered": list(metadata.get("triggered_controls") or []),
            "decision": action.enforcement_action,
            "timestamp": action.timestamp.isoformat() if action.timestamp else None,
            "runtime_event_id": action.runtime_event_id,
            "monitoring_signal_id": action.monitoring_signal_id,
            "finding_id": action.finding_id,
            "evidence_node_id": action.evidence_node_id,
            "session_id": action.session_id,
            "session": {
                "source_surface": _safe_str(getattr(session, "source_surface", "")) or None if session else None,
                "ai_model": _safe_str(getattr(session, "ai_model", "")) or None if session else None,
                "start_time": session.start_time.isoformat() if session and session.start_time else None,
                "end_time": session.end_time.isoformat() if session and session.end_time else None,
            },
            "endpoint": {
                "hostname": _safe_str(getattr(endpoint, "hostname", "")) or None if endpoint else None,
                "device_type": _safe_str(getattr(endpoint, "device_type", "")) or None if endpoint else None,
                "os_type": _safe_str(getattr(endpoint, "os_type", "")) or None if endpoint else None,
                "browser_type": _safe_str(getattr(endpoint, "browser_type", "")) or None if endpoint else None,
            },
            "remediation_suggestion": (
                "Tighten policy scope and require approval for this surface/app combination."
                if action.enforcement_action in {"warned", "blocked", "held", "modified"}
                else "Continue monitoring."
            ),
        },
    }
