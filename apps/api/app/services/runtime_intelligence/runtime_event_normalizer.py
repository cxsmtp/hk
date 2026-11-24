from __future__ import annotations

import math
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.observability import log_structured
from app.core.provenance import project_runtime_provenance_id
from app.core.response_control import normalize_response_control_coverage
from app.core.control_engine import AIAction, evaluate_control_engine, normalize_control_ids as normalize_engine_control_ids
from app.core.control_engine.canonical_action import (
    ALLOWED_CONTROL_MODES,
    CanonicalProjectionError,
    ControlPathEvidence,
    adapt_existing_hawk_action,
    gateway_control_path_evidence,
    maybe_dual_write_canonical_action,
)
from app.core.control_engine.authorization import (
    adapt_authorization_request,
    apply_authorization_rollout,
    is_enforcement_selected,
    validate_precomputed_authorization_metadata,
)
from app.db.models.activity_audit import AIAction as ActivityAIAction
from app.db.models.control_coverage import DeploymentSurface
from app.db.models.enforcement import EnforcementEvent
from app.db.models.monitoring import MonitoringSignal
from app.db.models.policy import PolicyVersion
from app.db.models.runtime_intelligence import RuntimeEvent as RuntimeEventRow
from app.db.models.runtime_intelligence import RuntimeGovernanceRecommendation
from app.db.models.user import UserTenantRole
from app.services.ai_iam_service import build_ai_action_record, control_mode_for_pre_action_decision
from app.services.ai_anomaly import detect_and_enforce_runtime_anomalies
from app.services.ai_discovery import process_runtime_event_for_ai_discovery
from app.services.audit_service import write_audit_log
from app.services.activity_audit_service import record_activity_event
from app.services.control_graph_service import infer_runtime_control_mapping, normalize_control_ids
from app.services.control_coverage.source_resolution import (
    runtime_surface_source_id,
)
from app.services.crq_service import compute_runtime_crq_update
from app.services.evidence_service import create_evidence_node, link_evidence_nodes
from app.services.findings_service import generate_runtime_intelligence_finding
from app.services.provider_catalog import resolve_provider
from app.services.runtime_intelligence.behavior_graph_service import build_behavior_graph_for_event
from app.services.runtime_intelligence.context_graph_service import build_context_graph_for_event
from app.services.runtime_intelligence.runtime_correlation_service import correlate_runtime_event, governance_recommendations_for_candidate
from app.services.runtime_intelligence.runtime_pattern_service import upsert_runtime_pattern
from app.services.runtime_intelligence.runtime_risk_scoring import score_runtime_risk
from app.services.runtime_intelligence.schemas import RuntimeEventIngestPayload
from app.services.runtime_intelligence.semantic_drift_service import compose_action_summary, compute_semantic_drift
from app.services.runtime_intelligence.simulation_trigger_service import create_runtime_simulation_trigger
from app.services.runtime_intelligence.streaming import publish_runtime_update
from app.services.shadow_ai.discovery_engine import safe_process_runtime_event_for_shadow_discovery


ALLOWED_SOURCE_SURFACES = {
    "browser",
    "gateway",
    "connector",
    "aiiam",
    "monitoring",
    "endpoint",
    "dns",
    "proxy",
    "desktop_app",
    "foundry",
    "copilot",
    "sdk",
    "internal_mcp",
}
ALLOWED_ENTITY_TYPES = {"user", "agent", "tool", "ai_system"}
SEVERITY_BY_DECISION = {
    "allow": "low",
    "warn": "med",
    "redact": "med",
    "hold_for_approval": "high",
    "block": "high",
}

STRICT_CONTROL_MODES = ALLOWED_CONTROL_MODES

MCP_DECISION_TO_ACTION_TYPE = {
    "allow": "mcp_tool_call_allowed",
    "warn": "mcp_tool_call_allowed",
    "redact": "mcp_tool_call_allowed",
    "hold_for_approval": "mcp_tool_call_requested",
    "require_approval": "mcp_tool_call_requested",
    "step_up": "mcp_tool_call_requested",
    "deny": "mcp_tool_call_denied",
    "block": "mcp_tool_call_blocked",
}

BROWSER_TOOL_VENDOR_MAP: dict[str, str] = {
    "claude": "Anthropic",
    "claude_web": "Anthropic",
    "claude_cowork": "Anthropic",
    "claude_code": "Anthropic",
    "chatgpt": "OpenAI",
    "atlas": "OpenAI",
    "openai": "OpenAI",
    "perplexity": "Perplexity",
    "comet": "Perplexity",
    "gemini": "Google",
    "codex": "Codex",
    "cursor": "Cursor",
    "browser_mcp": "Custom",
    "custom": "Custom",
    "unknown": "Unknown",
}


def _uniq(values: list[Any]) -> list[str]:
    return sorted({str(item).strip() for item in values if str(item).strip()})


def _safe_fk_text(value: Any) -> str | None:
    token = str(value or "").strip()
    if not token:
        return None
    if token.lower() in {"none", "null", "undefined", "unmapped"}:
        return None
    return token


def _resolve_policy_version_fk(
    db: Session,
    *,
    tenant_id: str,
    reported_policy_version_id: Any,
    metadata: dict[str, Any],
) -> str | None:
    candidate = _safe_fk_text(reported_policy_version_id)
    if candidate is None:
        return None
    exists = db.scalar(
        select(PolicyVersion.id).where(
            PolicyVersion.tenant_id == tenant_id,
            PolicyVersion.id == candidate,
        )
    )
    if exists:
        metadata["policy_version_binding_state"] = "bound"
        return str(exists)
    metadata["reported_policy_version_id"] = candidate
    metadata["policy_version_binding_state"] = "unresolved"
    log_structured(
        "reported_runtime_policy_version_unresolved",
        module="runtime_event_normalizer",
        tenant_id=tenant_id,
        reported_policy_version_id=candidate,
    )
    return None


def _normalize_source_surface(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in ALLOWED_SOURCE_SURFACES:
        raise ValueError(f"unsupported source_surface: {value}")
    return normalized


def _normalize_severity(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized == "medium":
        return "med"
    if normalized not in {"low", "med", "high", "critical"}:
        return None
    return normalized


def _normalize_entity_type(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized not in ALLOWED_ENTITY_TYPES:
        return None
    return normalized


def _to_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def project_browser_attachment_metadata(file_meta: Any) -> dict[str, Any]:
    """Keep structural upload evidence without persisting file content or names."""
    files = [item for item in file_meta if isinstance(item, dict)] if isinstance(file_meta, list) else []
    attachments: list[dict[str, Any]] = []
    for item in files[:100]:
        safe: dict[str, Any] = {}
        mime = _bounded_text(item.get("mime_type"), max_len=128)
        if mime and "/" in mime:
            safe["mime_type"] = mime
        size = _to_int(item.get("size") if item.get("size") is not None else item.get("size_bytes"))
        if size is not None and size >= 0:
            safe["size"] = size
        for key in ("id", "file_id", "sha256", "content_hash"):
            value = _bounded_text(item.get(key), max_len=256)
            if value:
                safe[key] = value
        attachments.append(safe)
    return {"attachment_count": len(files), "attachments": attachments} if files else {}


def _to_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed):
        return None
    return parsed


def _normalized_text(value: Any) -> str | None:
    token = str(value or "").strip()
    return token or None


def _bounded_text(value: Any, *, max_len: int) -> str | None:
    token = _normalized_text(value)
    if token is None:
        return None
    return token[:max_len]


def _tenant_internal_user_id(db: Session, *, tenant_id: str, user_id: Any, metadata: dict[str, Any]) -> str | None:
    candidate = _normalized_text(user_id)
    if candidate is None:
        return None
    exists = db.scalar(
        select(UserTenantRole.user_id).where(
            UserTenantRole.tenant_id == tenant_id,
            UserTenantRole.user_id == candidate,
        )
    )
    if exists:
        return str(exists)
    metadata.setdefault("source_user_ref", candidate)
    metadata.setdefault("source_user_ref_status", "unresolved_external")
    return None


def _display_app_text(value: Any, *, max_len: int = 255) -> str | None:
    token = _normalized_text(value)
    if token is None:
        return None
    lowered = token.lower()
    if lowered.startswith(("http://", "https://")):
        parsed = urlparse(token)
        host = str(parsed.netloc or "").strip().lower()
        if host:
            return host[:max_len]
    return token[:max_len]


def _pick_confidence_tier(guardian_results: list[dict[str, Any]]) -> str | None:
    ordered = ["clear_positive", "ambiguous", "clear_negative"]
    observed = {
        str(item.get("confidence_tier") or "").strip().lower()
        for item in guardian_results
        if isinstance(item, dict)
    }
    for tier in ordered:
        if tier in observed:
            return tier
    return None


def _normalize_mcp_server_id(value: Any) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    normalized = raw.replace("https://", "").replace("http://", "").strip().rstrip("/")
    return normalized or None


def _mcp_action_type_for_decision(decision: str) -> str:
    normalized = str(decision or "").strip().lower()
    if normalized in MCP_DECISION_TO_ACTION_TYPE:
        return MCP_DECISION_TO_ACTION_TYPE[normalized]
    return "mcp_tool_call_requested"


def _strict_gateway_control_mode(
    *,
    event_type: str,
    decision: str,
    meta: dict[str, Any],
    meta_block: dict[str, Any],
    trace: dict[str, Any],
) -> str:
    ai_action = meta.get("ai_action") if isinstance(meta.get("ai_action"), dict) else {}
    ai_action_policy = ai_action.get("policy") if isinstance(ai_action.get("policy"), dict) else {}
    candidates = [
        meta_block.get("control_mode"),
        meta.get("control_mode"),
        trace.get("control_mode"),
        ai_action_policy.get("control_mode"),
    ]
    for candidate in candidates:
        normalized = str(candidate or "").strip().lower()
        if normalized in STRICT_CONTROL_MODES:
            return normalized

    inline_surface = str(event_type or "").strip().lower() in {"llm_intercept", "mcp_authorize"}
    return control_mode_for_pre_action_decision(decision, inline=inline_surface)


def _gateway_can_prevent_execution(*, event_type: str, control_mode: str) -> bool:
    if str(event_type or "").strip().lower() not in {"llm_intercept", "mcp_authorize"}:
        return False
    return str(control_mode or "").strip().lower() in {
        "inline_prevented",
        "inline_allowed",
        "warned",
        "external_required",
        "shadow_would_block",
    }


def _normalize_browser_suspected_tool(value: Any) -> str | None:
    token = str(value or "").strip()
    if not token:
        return None
    normalized = token.lower().replace(" ", "_").replace("-", "_")
    if "claude" in normalized:
        return "Claude"
    if "chatgpt" in normalized or normalized == "atlas":
        return "ChatGPT" if normalized != "atlas" else "Atlas"
    if "perplexity" in normalized or normalized == "comet":
        return "Perplexity" if normalized != "comet" else "Comet"
    if "gemini" in normalized:
        return "Gemini"
    if "codex" in normalized:
        return "Codex"
    if "mcp" in normalized:
        return "Browser MCP"
    if normalized in {"unknown", "suspected_local_agent"}:
        return "Unknown"
    return token


def _source_vendor_for_browser_tool(value: Any) -> str:
    token = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
    if not token:
        return "Unknown"
    for key, vendor in BROWSER_TOOL_VENDOR_MAP.items():
        if key in token:
            return vendor
    return "Unknown"


def _browser_control_mode(decision: str, *, automation_suspected: bool) -> str:
    normalized = str(decision or "").strip().lower()
    if normalized in {"block", "deny"}:
        return "inline_prevented"
    if normalized in {"warn", "alert"}:
        return "warned"
    if automation_suspected:
        return "detected_only"
    return "telemetry_only"


def _browser_decision_badge(decision: str, *, scope_violation: bool = False, automation_suspected: bool = False) -> str:
    if scope_violation:
        return "Scope Violation"
    normalized = str(decision or "").strip().lower()
    if normalized in {"block", "deny"}:
        return "Blocked Action"
    if normalized in {"warn", "alert"}:
        return "Warned Automation"
    if automation_suspected:
        return "Detected-only"
    return "Allowed Browsing"


def _canonical_enforcement_event_bundle(
    *,
    event_id: str,
    tenant_id: str,
    source_surface: str,
    event_type: str,
    ai_system_id: str | None,
    app_id: str | None,
    user_id: str | None,
    agent_id: str | None,
    metadata: dict[str, Any],
    correlation_id: str | None,
    created_at: str,
    context_id: str | None,
    chain_id: str | None,
    parent_action_id: str | None,
    entity_type: str | None,
    entity_id: str | None,
    risk_score: float | None,
) -> dict[str, Any]:
    action_type = str(metadata.get("action_type") or event_type or "unknown_action").strip() or "unknown_action"
    data_classification = (
        str(
            metadata.get("data_classification")
            or metadata.get("source_classification_hint")
            or metadata.get("classification")
            or "unknown"
        ).strip()
        or "unknown"
    )
    domain = (
        str(metadata.get("domain") or metadata.get("destination_domain") or metadata.get("request_domain") or "").strip() or None
    )
    if not domain and app_id:
        domain = str(app_id).strip() or None

    return {
        "event_id": event_id,
        "tenant_id": tenant_id,
        "source_surface": source_surface,
        "action_type": action_type,
        "ai_system_id": ai_system_id,
        "app_id": app_id,
        "user_id": user_id,
        "agent_id": agent_id,
        "provider_id": str(metadata.get("provider_id") or "").strip() or None,
        "provider_name": str(metadata.get("provider") or metadata.get("model_provider") or "").strip() or None,
        "provider_type": str(metadata.get("provider_type") or "").strip() or None,
        "shadow_ai_entity_id": str(metadata.get("shadow_ai_entity_id") or "").strip() or None,
        "model_name": str(metadata.get("model_name") or "").strip() or None,
        "tool_name": str(metadata.get("tool_name") or "").strip() or None,
        "host_id": str(metadata.get("host_id") or "").strip() or None,
        "domain": domain,
        "api_endpoint": str(metadata.get("api_endpoint") or "").strip() or None,
        "process_name": str(metadata.get("process_name") or "").strip() or None,
        "data_classification": data_classification,
        "correlation_id": (correlation_id or event_id),
        "context_id": context_id,
        "chain_id": chain_id,
        "parent_action_id": parent_action_id,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "risk_score": float(risk_score or 0.0),
        "created_at": created_at,
    }


def _action_source_surface(source_surface: str) -> str:
    normalized = str(source_surface or "").strip().lower()
    if normalized == "gateway":
        return "api"
    if normalized == "aiiam":
        return "agent"
    if normalized in {"endpoint", "dns", "proxy", "monitoring", "foundry", "copilot"}:
        return "connector"
    if normalized == "desktop_app":
        return "agent"
    if normalized in {"browser", "api", "connector", "agent"}:
        return normalized
    return "api"


def _authorization_surface(*, source_surface: str, event_type: str) -> str | None:
    surface = str(source_surface or "").strip().lower()
    event = str(event_type or "").strip().lower()
    if surface == "gateway":
        return "mcp_gateway" if "mcp" in event else "llm_gateway"
    if surface == "aiiam":
        return "runtime_control"
    if surface == "browser":
        return "browser"
    if surface in {"sdk", "api"}:
        return "sdk"
    if surface == "internal_mcp":
        return "internal_mcp"
    return None


def _canonical_action_from_row(*, row: RuntimeEventRow, metadata: dict[str, Any]) -> dict[str, Any]:
    data_entities = _uniq(
        [
            metadata.get("data_source"),
            metadata.get("target_resource"),
            metadata.get("api_endpoint"),
            metadata.get("domain"),
            metadata.get("destination_domain"),
            metadata.get("source_domain"),
            *list(metadata.get("sensitive_entities") or []),
        ]
    )
    return {
        "action_id": row.event_id,
        "source_surface": _action_source_surface(row.source_surface),
        "user_id": row.user_id,
        "agent_id": row.agent_id,
        "model": str(metadata.get("model_name") or metadata.get("model_provider") or metadata.get("provider") or "").strip() or None,
        "tool": str(metadata.get("tool_name") or row.app_id or "").strip() or None,
        "operation": str(metadata.get("action_type") or row.event_type or "unknown_action").strip() or "unknown_action",
        "data_entities": data_entities,
        "timestamp": row.created_at.isoformat(),
    }


def _policy_classification_and_decision(
    *,
    metadata: dict[str, Any],
    risk_score: float,
) -> tuple[str, str]:
    decision = str(metadata.get("decision") or metadata.get("final_decision") or "").strip().lower()
    if decision in {"block", "deny"}:
        return "forbidden", "deny"
    if decision in {"redact", "modify"}:
        return "context_deny", "modify"
    if decision in {"warn"}:
        return "context_deny", "modify"
    if decision in {"require_justification", "require_approval", "step_up"}:
        return "defer", "step_up"
    if decision in {"hold_for_approval", "defer"}:
        return "defer", "defer"
    if decision in {"allow"}:
        if float(risk_score) >= 0.75:
            return "context_deny", "step_up"
        return "context_allow", "allow"
    if float(risk_score) >= 0.8:
        return "forbidden", "deny"
    if float(risk_score) >= 0.5:
        return "context_deny", "modify"
    return "defer", "defer"


def _enforcement_status_for_metadata(*, source_surface: str, metadata: dict[str, Any]) -> str:
    provider_catalog = dict(metadata.get("provider_catalog") or {}) if isinstance(metadata.get("provider_catalog"), dict) else {}
    if provider_catalog:
        if bool(provider_catalog.get("enforcement_supported_for_source")):
            return "enforced"
        mode = str(provider_catalog.get("surface_policy_mode") or "").strip().lower()
        if mode in {"monitoring_only", "unsupported"}:
            return "simulated"
    return "enforced" if source_surface in {"browser", "gateway", "aiiam", "desktop_app"} else "simulated"


def _runtime_receipt(
    *,
    row: RuntimeEventRow,
    metadata: dict[str, Any],
    canonical_action: dict[str, Any],
    classification: str,
    policy_decision: str,
    enforcement_status: str,
    semantic_drift: dict[str, Any],
) -> dict[str, Any]:
    return {
        "action": canonical_action,
        "context": {
            "session_id": row.context_id,
            "context_id": row.context_id,
            "chain_id": row.chain_id,
            "parent_action_id": row.parent_action_id,
            "semantic_drift": semantic_drift,
            "risk_signals": _uniq(
                [
                    metadata.get("reason_code"),
                    metadata.get("reason"),
                    *list(metadata.get("input_signal_types") or []),
                    *list(metadata.get("reason_codes") or []),
                    *list(metadata.get("risk_labels") or []),
                ]
            ),
        },
        "identity": {
            "human_id": row.user_id,
            "agent_id": row.agent_id,
            "roles": list(metadata.get("roles") or []),
            "privilege_scope": list(metadata.get("privilege_scope") or metadata.get("scopes") or []),
            "trust_level": str(metadata.get("trust_level") or metadata.get("governance_state") or "unknown"),
        },
        "decision": {
            "classification": classification,
            "decision": policy_decision,
            "upstream_decision": str(metadata.get("decision") or metadata.get("final_decision") or "").strip().lower() or None,
            "simulated_outcome": bool(enforcement_status == "simulated"),
        },
        "enforcement_status": enforcement_status,
        "timestamp": row.created_at.isoformat(),
    }


def _activity_audit_payload_from_runtime_event(
    *,
    row: RuntimeEventRow,
    metadata: dict[str, Any],
    runtime_node_id: str | None,
    runtime_receipt_audit_id: str | None,
) -> dict[str, Any]:
    canonical_action = dict(metadata.get("canonical_action") or {})
    ai_action = dict(metadata.get("ai_action") or {})
    decision = (
        str(metadata.get("decision") or metadata.get("final_decision") or row.decision or "").strip().lower()
        or str(dict(metadata.get("policy_evaluation") or {}).get("decision") or "").strip().lower()
        or "allow"
    )
    endpoint_id = (
        str(metadata.get("endpoint_id") or "").strip()
        or str(metadata.get("device_id") or "").strip()
        or str(metadata.get("machine_id") or row.machine_id or "").strip()
        or None
    )
    sensitivity_score = (
        _to_float(metadata.get("sensitivity_score"))
        if _to_float(metadata.get("sensitivity_score")) is not None
        else _to_float(dict(metadata.get("risk_components") or {}).get("sensitivity_score"))
    )
    if sensitivity_score is None:
        sensitivity_score = 1.0 if bool(metadata.get("contains_sensitive")) else 0.0
    semantic_drift = dict(metadata.get("semantic_drift") or {}) if isinstance(metadata.get("semantic_drift"), dict) else {}
    data_classification = (
        str(
            metadata.get("data_classification")
            or metadata.get("source_classification_hint")
            or metadata.get("classification")
            or "unknown"
        ).strip()
        or "unknown"
    )
    prompt_preview = str(
        metadata.get("prompt_preview_redacted")
        or metadata.get("redacted_prompt")
        or metadata.get("original_intent")
        or ""
    ).strip()
    sensitive_entities = [str(item).strip().lower() for item in list(metadata.get("sensitive_entities") or []) if str(item).strip()]
    sensitive_confidence = _to_float(
        metadata.get("sensitive_confidence")
    )
    sensitive_detection = {
        "contains_sensitive": bool(metadata.get("contains_sensitive")) or bool(sensitive_entities),
        "entities": [{"entity_type": item} for item in sorted(set(sensitive_entities))],
        "confidence_score": (
            sensitive_confidence
            if sensitive_confidence is not None
            else (1.0 if sensitive_entities else 0.0)
        ),
    }
    return {
        "action_id": row.event_id,
        "runtime_event_id": row.event_id,
        "timestamp": row.created_at.isoformat(),
        "source_surface": row.source_surface,
        "action_type": str(canonical_action.get("operation") or metadata.get("action_type") or row.event_type).strip()
        or row.event_type,
        "ai_app": row.application or row.app_id or canonical_action.get("tool"),
        "ai_model": canonical_action.get("model") or metadata.get("model_name") or metadata.get("model_provider"),
        "data_classification": data_classification,
        "sensitivity_score": float(max(0.0, min(1.0, float(sensitivity_score or 0.0)))),
        "policy_triggered": ",".join([str(item) for item in list(metadata.get("triggered_controls") or []) if str(item).strip()])
        or str(ai_action.get("policy_triggered") or "").strip()
        or None,
        "enforcement_action": decision,
        "semantic_drift_score": float(semantic_drift.get("drift_score") or 0.0),
        "risk_score": float(row.risk_score or metadata.get("risk_score") or 0.0),
        "correlation_id": row.correlation_id,
        "audit_log_id": runtime_receipt_audit_id,
        "evidence_node_id": runtime_node_id,
        "finding_id": str(metadata.get("finding_id") or "").strip() or None,
        "prompt_preview_redacted": prompt_preview,
        "sensitive_detection": sensitive_detection,
        "storage_mode": "hashed_only" if sensitive_detection["contains_sensitive"] and float(sensitivity_score or 0.0) >= 0.75 else None,
        "endpoint_id": endpoint_id,
        "hostname": str(metadata.get("hostname") or "").strip() or None,
        "device_type": str(metadata.get("device_type") or "").strip() or None,
        "os_type": str(metadata.get("os_type") or metadata.get("os") or "").strip() or None,
        "os_version": str(metadata.get("os_version") or "").strip() or None,
        "browser": str(metadata.get("browser") or metadata.get("browser_type") or row.browser_type or "").strip() or None,
        "browser_type": str(metadata.get("browser_type") or metadata.get("browser") or row.browser_type or "").strip() or None,
        "browser_version": str(metadata.get("browser_version") or "").strip() or None,
        "extension_version": str(metadata.get("extension_version") or "").strip() or None,
        "ip_address": str(metadata.get("ip_address") or "").strip() or None,
        "location": str(metadata.get("location") or "").strip() or None,
        "session_id": row.context_id,
        "ai_session_id": row.context_id,
        "ai_model": canonical_action.get("model") or metadata.get("model_name") or metadata.get("model_provider"),
        "metadata": {
            "agent_id": row.agent_id,
            "tool_name": metadata.get("tool_name"),
            "model_name": metadata.get("model_name"),
            "model_provider": metadata.get("model_provider"),
            "source_surface": row.source_surface,
            "runtime_event_id": row.event_id,
            "chain_id": row.chain_id,
            "parent_action_id": row.parent_action_id,
            "response_control_coverage": normalize_response_control_coverage(
                metadata.get("response_control_coverage")
            ),
            "provenance": dict(metadata.get("provenance") or {}),
            "canonical_action": canonical_action,
            "ai_action": ai_action,
            "control_mode": dict(ai_action.get("policy") or {}).get("control_mode") or metadata.get("control_mode"),
            "policy_snapshot": dict(ai_action.get("policy_snapshot") or {}),
            "decision_explanation": dict(ai_action.get("decision_explanation") or metadata.get("decision_explanation") or {}),
            "evidence_bundle": dict(ai_action.get("evidence_bundle") or {}),
            "canonical_ai_action_v1": dict(metadata.get("canonical_ai_action_v1") or {}),
            "canonical_ai_action_hash": metadata.get("canonical_ai_action_hash"),
            "deployment_linkage_verified": (
                metadata.get("deployment_linkage_verified") is True
            ),
            "authorization_kernel_v2_shadow": dict(metadata.get("authorization_kernel_v2_shadow") or {}),
            "authorization_kernel_v2_shadow_health": dict(
                metadata.get("authorization_kernel_v2_shadow_health") or {}
            ),
            "enforcement_status": metadata.get("enforcement_status"),
            "crq": dict(metadata.get("crq") or {}),
            "anomaly_events": list(metadata.get("anomaly_events") or []),
        },
    }


def _link_source_evidence_to_runtime_node(
    db: Session,
    *,
    tenant_id: str,
    source_evidence_node_ids: list[str],
    runtime_node_id: str,
) -> None:
    for node_id in source_evidence_node_ids:
        try:
            link_evidence_nodes(
                db,
                tenant_id=tenant_id,
                from_node_id=node_id,
                to_node_id=runtime_node_id,
                edge_type="runtime_normalized_from",
                payload={},
            )
        except Exception:
            continue


def _safe_publish_runtime_update(
    *,
    tenant_id: str,
    event_type: str,
    payload: dict[str, Any],
) -> None:
    try:
        publish_runtime_update(
            tenant_id=tenant_id,
            event_type=event_type,
            payload=payload,
        )
    except Exception:
        # Streaming is strictly non-blocking and must never impact runtime processing.
        return


def ingest_runtime_event(
    db: Session,
    *,
    payload: RuntimeEventIngestPayload,
    canonical_control_path: ControlPathEvidence | None = None,
    trusted_pre_action_governance_check: dict[str, Any] | None = None,
) -> RuntimeEventRow | None:
    if not settings.runtime_intelligence_enabled:
        return None

    source_surface = _normalize_source_surface(payload.source_surface)
    severity = _normalize_severity(payload.severity)
    event_type = str(payload.event_type or "").strip()
    if not event_type:
        raise ValueError("event_type is required")

    metadata = dict(payload.metadata or {})
    if "response_control_coverage" in metadata:
        metadata["response_control_coverage"] = normalize_response_control_coverage(
            metadata.get("response_control_coverage")
        )
    entity_type = _normalize_entity_type(payload.entity_type or metadata.get("entity_type"))
    entity_id = (
        str(payload.entity_id).strip()
        if payload.entity_id is not None and str(payload.entity_id).strip()
        else (str(metadata.get("entity_id")).strip() if str(metadata.get("entity_id") or "").strip() else None)
    )
    context_id = (
        str(payload.context_id).strip()
        if payload.context_id is not None and str(payload.context_id).strip()
        else (str(metadata.get("context_id")).strip() if str(metadata.get("context_id") or "").strip() else None)
    )
    raw_chain_id = (
        payload.chain_id
        if payload.chain_id is not None
        else metadata.get("chain_id")
    )
    raw_parent_action_id = (
        payload.parent_action_id
        if payload.parent_action_id is not None
        else metadata.get("parent_action_id")
    )
    provenance_domain = f"runtime:{source_surface}"
    chain_provenance = project_runtime_provenance_id(
        raw_chain_id,
        tenant_id=payload.tenant_id,
        domain=provenance_domain,
        field_name="chain_id",
    )
    parent_action_provenance = project_runtime_provenance_id(
        raw_parent_action_id,
        tenant_id=payload.tenant_id,
        domain=provenance_domain,
        field_name="parent_action_id",
    )
    chain_id = chain_provenance["projection"]
    parent_action_id = (
        parent_action_provenance["projection"]
        if parent_action_provenance["authoritative"]
        else None
    )
    metadata["provenance"] = {
        "chain_id": chain_provenance,
        "parent_action_id": parent_action_provenance,
    }
    if chain_id is not None:
        metadata["chain_id"] = chain_id
    else:
        metadata.pop("chain_id", None)
    if parent_action_id is not None:
        metadata["parent_action_id"] = parent_action_id
    else:
        metadata.pop("parent_action_id", None)
    internal_user_id = _tenant_internal_user_id(
        db,
        tenant_id=payload.tenant_id,
        user_id=payload.user_id,
        metadata=metadata,
    )
    if not entity_type or not entity_id:
        if payload.agent_id:
            entity_type = "agent"
            entity_id = str(payload.agent_id).strip()
        elif internal_user_id:
            entity_type = "user"
            entity_id = internal_user_id
        elif payload.tool_name:
            entity_type = "tool"
            entity_id = str(payload.tool_name).strip()
        elif payload.ai_system_id:
            entity_type = "ai_system"
            entity_id = str(payload.ai_system_id).strip()

    model_provider = (
        str(payload.model_provider).strip()
        if payload.model_provider is not None and str(payload.model_provider).strip()
        else (str(payload.provider).strip() if payload.provider is not None and str(payload.provider).strip() else None)
    )
    for key, value in {
        "action_type": (str(metadata.get("action_type") or event_type).strip() or event_type),
        "model_provider": model_provider,
        "provider": (str(payload.provider).strip() if payload.provider is not None and str(payload.provider).strip() else model_provider),
        "model_name": payload.model_name,
        "model_version": payload.model_version,
        "tool_name": payload.tool_name,
        "tool_category": payload.tool_category,
        "api_endpoint": payload.api_endpoint,
        "data_source": payload.data_source,
        "response_size": _to_int(payload.response_size),
        "chain_depth": payload.chain_depth,
        "parent_agent_id": payload.parent_agent_id,
    }.items():
        if value is not None:
            metadata[key] = value
    if not str(metadata.get("machine_id") or "").strip():
        machine_hint = (
            str(metadata.get("endpoint_id") or "").strip()
            or str(metadata.get("host_id") or "").strip()
            or None
        )
        if machine_hint:
            metadata["machine_id"] = machine_hint
    if not str(metadata.get("browser_type") or "").strip():
        browser_hint = str(metadata.get("browser") or "").strip() or None
        if browser_hint:
            metadata["browser_type"] = browser_hint

    provider_resolution = resolve_provider(
        {
            **metadata,
            "domain": metadata.get("domain") or payload.app_id,
            "app_id": payload.app_id,
            "provider": payload.provider,
            "model_provider": payload.model_provider,
            "model_name": payload.model_name,
            "tool_name": payload.tool_name,
            "api_endpoint": payload.api_endpoint,
        },
        source_surface=source_surface,
    )
    if bool(provider_resolution.get("catalog_match")):
        metadata["catalog_match"] = True
    explicit_browser_invocation = bool(
        metadata.get("tool_call_id") or metadata.get("tool_invoked") or metadata.get("function_call_id")
        or any(marker in event_type.lower() for marker in ("tool_call", "function_call", "mcp_authorize"))
    )
    if source_surface == "browser" and not explicit_browser_invocation:
        metadata.pop("tool_name", None)
    for key, value in {
        "provider_id": provider_resolution.get("provider_id"),
        "provider_type": provider_resolution.get("provider_type"),
        "provider": provider_resolution.get("provider_name"),
        "model_provider": metadata.get("model_provider") or provider_resolution.get("provider_name"),
        "tool_name": (
            metadata.get("tool_name") or provider_resolution.get("canonical_tool_name")
            if source_surface != "browser" or explicit_browser_invocation else None
        ),
        "domain": metadata.get("domain") or provider_resolution.get("domain") or payload.app_id,
    }.items():
        if value is None:
            continue
        if not str(metadata.get(key) or "").strip():
            metadata[key] = value
    metadata["provider_catalog"] = {
        "catalog_match": bool(provider_resolution.get("catalog_match")),
        "provider_id": provider_resolution.get("provider_id"),
        "provider_name": provider_resolution.get("provider_name"),
        "provider_type": provider_resolution.get("provider_type"),
        "confidence_hint": provider_resolution.get("confidence_hint"),
        "matched_on": list(provider_resolution.get("matched_on") or []),
        "trust_level": provider_resolution.get("trust_level"),
        "default_risk_hint": provider_resolution.get("default_risk_hint"),
        "surface_policy_mode": provider_resolution.get("surface_policy_mode"),
        "enforcement_supported_for_source": bool(provider_resolution.get("enforcement_supported_for_source")),
        "monitoring_only_for_source": bool(provider_resolution.get("monitoring_only_for_source")),
        "behavior_profile": provider_resolution.get("behavior_profile"),
        "provider_capability": dict(provider_resolution.get("provider_capability") or {}),
    }

    evidence_ids = _uniq(payload.evidence_node_ids)
    machine_id = (
        _normalized_text(metadata.get("machine_id"))
        or _normalized_text(metadata.get("endpoint_id"))
        or _normalized_text(metadata.get("host_id"))
    )
    browser_type = _normalized_text(metadata.get("browser_type")) or _normalized_text(metadata.get("browser"))
    application = (
        _normalized_text(metadata.get("application"))
        or _normalized_text(metadata.get("domain"))
        or _normalized_text(payload.app_id)
        or _normalized_text(provider_resolution.get("domain"))
        or _normalized_text(metadata.get("tool_name"))
    )
    raw_application = application
    application = _display_app_text(application, max_len=255)
    if raw_application and application and raw_application != application:
        metadata.setdefault("raw_application", raw_application)
        metadata["application_compacted"] = True
    if application and not _normalized_text(metadata.get("application")):
        metadata["application"] = application
    decision = (
        _normalized_text(metadata.get("decision"))
        or _normalized_text(metadata.get("final_decision"))
    )
    if decision:
        decision = decision.lower()
    policy_version_id = _resolve_policy_version_fk(
        db,
        tenant_id=payload.tenant_id,
        reported_policy_version_id=payload.policy_version_id,
        metadata=metadata,
    )
    row = RuntimeEventRow(
        tenant_id=payload.tenant_id,
        source_surface=source_surface,
        event_type=_bounded_text(event_type, max_len=128) or "runtime_event",
        ai_system_id=(str(payload.ai_system_id).strip() if payload.ai_system_id else None),
        app_id=_bounded_text(
            (
                str(payload.app_id).strip()
            if payload.app_id and str(payload.app_id).strip()
            else (str(provider_resolution.get("domain") or "").strip() or None)
            ),
            max_len=128,
        ),
        user_id=internal_user_id,
        machine_id=_bounded_text(machine_id, max_len=128),
        browser_type=_bounded_text(browser_type, max_len=32),
        application=application,
        agent_id=_bounded_text(payload.agent_id, max_len=64),
        decision=_bounded_text(decision, max_len=32),
        risk_tier=_bounded_text(payload.risk_tier, max_len=16),
        policy_version_id=policy_version_id,
        governance_version=_bounded_text(payload.governance_version, max_len=64),
        severity=_bounded_text(severity, max_len=16),
        confidence_tier=_bounded_text(str(payload.confidence_tier).strip().lower() if payload.confidence_tier else None, max_len=32),
        evidence_node_ids=evidence_ids,
        correlation_id=_bounded_text(payload.correlation_id, max_len=64),
        context_id=_bounded_text(context_id, max_len=64),
        chain_id=chain_id,
        parent_action_id=parent_action_id,
        entity_type=entity_type,
        entity_id=_bounded_text(entity_id, max_len=128),
        risk_score=(float(payload.risk_score) if payload.risk_score is not None else 0.0),
        metadata_json=metadata,
    )
    db.add(row)
    db.flush()
    if not row.correlation_id:
        # Preserve deterministic traceability even when upstream source omits correlation id.
        row.correlation_id = row.event_id
        db.flush()
    if not row.context_id:
        row.context_id = row.correlation_id or row.event_id
    if not row.chain_id:
        row.chain_id = row.context_id
    db.flush()

    # Context graph and risk aggregation are post-enforcement enrichment and stay non-blocking.
    try:
        build_context_graph_for_event(db, event=row)
        db.flush()
    except Exception as exc:  # pragma: no cover - defensive non-blocking guard
        log_structured(
            "runtime_context_graph_enrichment_failed",
            tenant_id=row.tenant_id,
            runtime_event_id=row.event_id,
            source_surface=row.source_surface,
            event_type=row.event_type,
            correlation_id=row.correlation_id,
            error=str(exc),
        )
    metadata = dict(row.metadata_json or {}) if isinstance(row.metadata_json, dict) else {}
    original_intent = str(
        metadata.get("original_intent")
        or metadata.get("input_context_summary")
        or metadata.get("intent")
        or metadata.get("prompt_preview_redacted")
        or ""
    ).strip() or None
    current_action_summary = compose_action_summary(event_type=row.event_type, metadata=metadata)
    semantic_drift = compute_semantic_drift(
        original_intent=original_intent,
        current_action=current_action_summary,
    )
    metadata["semantic_drift"] = semantic_drift
    if original_intent and not str(metadata.get("original_intent") or "").strip():
        metadata["original_intent"] = original_intent

    canonical_bundle = _canonical_enforcement_event_bundle(
        event_id=row.event_id,
        tenant_id=row.tenant_id,
        source_surface=source_surface,
        event_type=event_type,
        ai_system_id=row.ai_system_id,
        app_id=row.app_id,
        user_id=row.user_id,
        agent_id=row.agent_id,
        metadata=metadata,
        correlation_id=row.correlation_id,
        created_at=row.created_at.isoformat(),
        context_id=row.context_id,
        chain_id=row.chain_id,
        parent_action_id=row.parent_action_id,
        entity_type=row.entity_type,
        entity_id=row.entity_id,
        risk_score=row.risk_score,
    )
    canonical_action = _canonical_action_from_row(row=row, metadata=metadata)
    metadata["canonical_action"] = canonical_action
    metadata["action"] = canonical_action
    classification, policy_decision = _policy_classification_and_decision(
        metadata=metadata,
        risk_score=float(row.risk_score or 0.0),
    )
    enforcement_status = _enforcement_status_for_metadata(
        source_surface=row.source_surface,
        metadata=metadata,
    )
    metadata["policy_evaluation"] = {
        "classification": classification,
        "decision": policy_decision,
        "simulated": enforcement_status == "simulated",
        "reason": (
            "simulated_due_to_surface_coverage"
            if enforcement_status == "simulated"
            else "enforced_on_available_surface"
        ),
    }
    # Preserve only controls explicitly asserted by the authoritative source for
    # authorization. Inferred observability mappings describe coverage and must
    # not be reinterpreted as policy violations by the v2 kernel.
    authorization_policy_triggers = normalize_engine_control_ids(
        list(metadata.get("triggered_controls") or [])
    )
    control_mapping = infer_runtime_control_mapping(
        event_type=row.event_type,
        metadata=metadata,
        source_surface=row.source_surface,
    )
    mapped_triggered_controls = normalize_control_ids(list(control_mapping.get("triggered_controls") or []))
    mapped_missed_controls = normalize_control_ids(list(control_mapping.get("missed_controls") or []))
    mapped_risk_tags = _uniq(list(control_mapping.get("risk_tags") or []))
    control_engine_hints = normalize_engine_control_ids(
        [
            *list(mapped_triggered_controls),
            *list(metadata.get("triggered_controls") or []),
            *list(metadata.get("related_control_ids") or []),
        ]
    )
    control_decision = evaluate_control_engine(
        AIAction(
            action_id=row.event_id,
            user_id=row.user_id,
            endpoint_id=str(metadata.get("endpoint_id") or metadata.get("host_id") or "").strip() or None,
            ai_app=(canonical_action.get("tool") or row.app_id),
            model=canonical_action.get("model"),
            prompt=str(metadata.get("original_intent") or metadata.get("prompt_preview_redacted") or "").strip() or None,
            metadata={
                "source_surface": row.source_surface,
                "action_type": canonical_action.get("operation"),
                "reason_code": metadata.get("reason_code"),
                "reason_codes": list(metadata.get("reason_codes") or []),
                "input_signal_types": list(metadata.get("input_signal_types") or []),
                "contains_sensitive": bool(metadata.get("contains_sensitive")),
                "data_classification": canonical_bundle.get("data_classification") or metadata.get("data_classification"),
                "destination_domain": canonical_bundle.get("domain"),
                "destination_is_external": bool(metadata.get("destination_is_external")),
                "governance_status": str(metadata.get("governance_state") or metadata.get("governance_status") or "UNKNOWN"),
                "triggered_controls": control_engine_hints,
            },
            source_surface=row.source_surface,
        ),
        base_decision=str(metadata.get("decision") or metadata.get("final_decision") or policy_decision or "").strip().lower() or None,
        hinted_control_ids=control_engine_hints,
    )
    metadata["control_decision"] = control_decision.to_dict()
    metadata["triggered_controls"] = normalize_control_ids(
        [*mapped_triggered_controls, *list(control_decision.triggered_controls or [])]
    )
    metadata["missed_controls"] = normalize_control_ids(
        [*mapped_missed_controls, *[row.control_id for row in control_decision.evaluated_controls if not row.triggered]]
    )
    metadata["risk_tags"] = _uniq([*mapped_risk_tags, *list(control_decision.risk_tags or [])])
    try:
        crq_payload = compute_runtime_crq_update(
            event_id=row.event_id,
            control_ids=list(metadata.get("triggered_controls") or metadata.get("missed_controls") or []),
            severity=row.severity,
            decision=str(metadata.get("decision") or metadata.get("final_decision") or policy_decision or "").strip().lower(),
            risk_score=float(row.risk_score or 0.0),
            risk_tags=list(metadata.get("risk_tags") or []),
            lookback_hours=24,
        )
    except Exception as exc:  # pragma: no cover - non-blocking enrichment
        log_structured(
            "runtime_crq_update_failed",
            module="runtime_event_normalizer",
            tenant_id=row.tenant_id,
            event_id=row.event_id,
            error=str(exc),
        )
        crq_payload = {}
    if crq_payload:
        metadata["crq"] = crq_payload
        metadata["risk_likelihood"] = float(crq_payload.get("likelihood") or 0.0)
        metadata["annualized_loss_expectancy"] = float(crq_payload.get("annualized_loss_expectancy") or 0.0)
        metadata["risk_reduction_estimate"] = float(crq_payload.get("risk_reduction") or 0.0)
    metadata["enforcement_status"] = enforcement_status
    metadata["runtime_receipt"] = _runtime_receipt(
        row=row,
        metadata=metadata,
        canonical_action=canonical_action,
        classification=classification,
        policy_decision=policy_decision,
        enforcement_status=enforcement_status,
        semantic_drift=semantic_drift,
    )
    metadata["normalized_enforcement_event"] = canonical_bundle
    resolved_surface = db.scalar(
        select(DeploymentSurface)
        .where(
            DeploymentSurface.tenant_id == row.tenant_id,
            DeploymentSurface.source_kind == "runtime_observation",
            DeploymentSurface.source_id == runtime_surface_source_id(row),
        )
        .limit(1)
    )
    inline_deployment_path = bool(
        canonical_control_path is not None
        and canonical_control_path.inline_pre_execution
    )
    server_control_mode = control_mode_for_pre_action_decision(
        row.decision
        or str(
            metadata.get("decision")
            or metadata.get("final_decision")
            or ""
        ).strip().lower(),
        inline=inline_deployment_path,
    )
    if resolved_surface is not None:
        deployment_linkage = {
            "verified": True,
            "deployment_instance_id": resolved_surface.id,
            "technical_surface_type": resolved_surface.surface_type,
            "deployment_family": resolved_surface.deployment_family,
            "collector_id": "runtime-event-normalizer",
            "authorization_path": (
                "inline_pre_execution"
                if inline_deployment_path
                else "telemetry_observation"
            ),
            "control_mode": server_control_mode,
            "evidence_capability_at_decision_time": (
                resolved_surface.evidence_capability
            ),
        }
    else:
        deployment_linkage = {
            "verified": False,
            "deployment_instance_id": None,
            "technical_surface_type": "unknown",
            "deployment_family": "unknown",
            "collector_id": None,
            "authorization_path": "unknown",
            "control_mode": "incomplete",
            "evidence_capability_at_decision_time": "unknown",
        }
    trusted_pre_action_governance_check = dict(
        trusted_pre_action_governance_check or {}
    )
    if canonical_control_path is not None:
        trusted_pre_action_governance_check["control_mode"] = (
            server_control_mode
        )
    trusted_pre_action_governance_check["deployment"] = deployment_linkage
    ai_action = build_ai_action_record(
        tenant_id=row.tenant_id,
        action_id=row.event_id,
        timestamp=row.created_at.isoformat(),
        source_surface=row.source_surface,
        event_type=row.event_type,
        user_id=row.user_id,
        agent_id=row.agent_id,
        ai_system_id=row.ai_system_id,
        app_id=row.app_id,
        machine_id=row.machine_id,
        browser_type=row.browser_type,
        application=row.application,
        policy_version_id=row.policy_version_id,
        decision=row.decision or str(metadata.get("decision") or metadata.get("final_decision") or "").strip().lower(),
        evidence_node_ids=evidence_ids,
        correlation_id=row.correlation_id,
        context_id=row.context_id,
        chain_id=row.chain_id,
        parent_action_id=row.parent_action_id,
        metadata=metadata,
        finding_id=str(metadata.get("finding_id") or "").strip() or None,
        trusted_pre_action_governance_check=trusted_pre_action_governance_check,
    )
    metadata["ai_action"] = ai_action
    metadata["deployment_linkage_verified"] = (
        ai_action["deployment"].get("deployment_instance_id") is not None
    )
    metadata["decision_explanation"] = ai_action.get("decision_explanation")
    canonical_dual_write_enabled = bool(settings.canonical_ai_action_dual_write_enabled)
    authorization_surface = _authorization_surface(
        source_surface=row.source_surface,
        event_type=row.event_type,
    )
    canonical_v1: dict[str, Any] = {}
    if canonical_dual_write_enabled:
        try:
            canonical_v1 = adapt_existing_hawk_action(
                ai_action,
                source_surface=row.source_surface,
                event_type=row.event_type,
                path_evidence=canonical_control_path,
            )
            metadata = maybe_dual_write_canonical_action(
                metadata,
                canonical_action=canonical_v1,
                enabled=True,
            )
        except Exception as exc:
            raise CanonicalProjectionError("canonical RuntimeEvent projection failed") from exc
    elif settings.authorization_kernel_v2_enabled and authorization_surface:
        try:
            canonical_v1 = adapt_existing_hawk_action(
                ai_action,
                source_surface=row.source_surface,
                event_type=row.event_type,
                path_evidence=canonical_control_path,
            )
        except Exception:
            metadata["authorization_kernel_v2_shadow_health"] = {
                "schema_version": "2.0",
                "status": "error",
                "error_code": "canonical_projection_failed",
            }
    selected_authorization_surface = bool(
        authorization_surface
        and settings.authorization_kernel_v2_enabled
        and is_enforcement_selected(
            tenant_id=row.tenant_id,
            surface=authorization_surface,
            settings_obj=settings,
        )
    )
    if selected_authorization_surface:
        # Selected adapters evaluate once before the side effect. Only the
        # server-trusted pre-action object may carry that result into telemetry.
        metadata.pop("authorization_kernel_v2_shadow", None)
        metadata.pop("authorization_kernel_v2_shadow_health", None)
        trusted_precomputed = (
            trusted_pre_action_governance_check.get("authorization_kernel_v2_precomputed")
            if isinstance(trusted_pre_action_governance_check, dict)
            else None
        )
        trusted_policy = (
            dict(trusted_pre_action_governance_check.get("policy") or {})
            if isinstance(trusted_pre_action_governance_check, dict)
            and isinstance(trusted_pre_action_governance_check.get("policy"), dict)
            else {}
        )
        try:
            if not isinstance(trusted_precomputed, dict):
                raise ValueError("selected authorization metadata is missing")
            validated_precomputed = validate_precomputed_authorization_metadata(
                trusted_precomputed,
                expected_action_id=str(
                    trusted_pre_action_governance_check.get("action_id") or ""
                ).strip(),
                expected_policy_snapshot_id=str(
                    trusted_policy.get("policy_snapshot_id")
                    or row.policy_version_id
                    or row.governance_version
                    or ""
                ).strip(),
            )
            metadata.update(validated_precomputed)
        except Exception:
            metadata["authorization_kernel_v2_shadow_health"] = {
                "schema_version": "2.0",
                "status": "error",
                "error_code": "precomputed_authorization_invalid",
            }
    if (
        canonical_v1
        and authorization_surface
        and settings.authorization_kernel_v2_enabled
        and settings.authorization_kernel_shadow_compare_enabled
        and not is_enforcement_selected(
            tenant_id=row.tenant_id,
            surface=authorization_surface,
            settings_obj=settings,
        )
    ):
        try:
            legacy_decision = str(
                metadata.get("decision")
                or metadata.get("final_decision")
                or row.decision
                or dict(canonical_v1.get("policy") or {}).get("decision")
                or "allow"
            ).strip().lower()
            legacy_policy_snapshot_id = str(
                row.policy_version_id
                or row.governance_version
                or dict(canonical_v1.get("policy") or {}).get("policy_snapshot_id")
                or "legacy-runtime-policy"
            ).strip()
            authorization_request = adapt_authorization_request(
                canonical_v1,
                collector_id=f"runtime-normalizer:{authorization_surface}",
                policy_snapshot_id=legacy_policy_snapshot_id,
                policy_profile={
                    "base_decision": legacy_decision,
                    "matched_rules": list(metadata.get("triggered_controls") or []),
                    "triggered_controls": authorization_policy_triggers,
                    "dependencies_healthy": True,
                    "cache_ttl": 0,
                    "degraded_behavior": "block",
                },
                path_evidence=canonical_control_path or ControlPathEvidence(telemetry_observation=True),
                expected_surface=authorization_surface,
            )
            rollout = apply_authorization_rollout(
                metadata=metadata,
                request=authorization_request,
                legacy_decision=legacy_decision,
                legacy_reason=str(metadata.get("reason_code") or metadata.get("reason") or "legacy_runtime_decision"),
                legacy_control_mode=str(
                    dict(canonical_v1.get("policy") or {}).get("control_mode")
                    or metadata.get("control_mode")
                    or "incomplete"
                ),
                legacy_policy_snapshot_id=legacy_policy_snapshot_id,
                settings_obj=settings,
            )
            # This hook is intentionally shadow-only. Authoritative adapters must
            # call apply_authorization_rollout before their side effect.
            metadata = rollout.metadata
            metadata["authorization_kernel_v2_shadow_health"] = {
                "schema_version": "2.0",
                "status": "ok",
                "error_code": None,
            }
        except Exception:
            metadata["authorization_kernel_v2_shadow_health"] = {
                "schema_version": "2.0",
                "status": "error",
                "error_code": "authorization_evaluation_failed",
            }
    row.metadata_json = metadata
    db.flush()

    runtime_receipt_audit_id: str | None = None
    try:
        audit_entry = write_audit_log(
            db,
            tenant_id=row.tenant_id,
            actor_user_id=row.user_id,
            actor_type=("agent" if row.agent_id else ("human" if row.user_id else "system")),
            action="runtime.receipt.generated",
            resource_type="runtime_event",
            resource_id=row.event_id,
            payload={
                "canonical_action": canonical_action,
                "policy_evaluation": dict(metadata.get("policy_evaluation") or {}),
                "enforcement_status": enforcement_status,
                "context_id": row.context_id,
                "chain_id": row.chain_id,
            },
            correlation_id=row.correlation_id,
        )
        runtime_receipt_audit_id = audit_entry.id
        metadata["runtime_receipt_audit_log_id"] = audit_entry.id
        row.metadata_json = metadata
        db.flush()
    except Exception as exc:  # pragma: no cover - defensive non-blocking guard
        log_structured(
            "runtime_receipt_audit_write_failed",
            tenant_id=row.tenant_id,
            runtime_event_id=row.event_id,
            source_surface=row.source_surface,
            event_type=row.event_type,
            correlation_id=row.correlation_id,
            error=str(exc),
        )

    runtime_node = create_evidence_node(
        db,
        tenant_id=payload.tenant_id,
        node_type="runtime_event",
        signal_type=f"runtime.{source_surface}.{row.event_type}",
        label=f"Runtime event {row.event_type}",
        payload={
            "runtime_event_id": row.event_id,
            "source_surface": source_surface,
            "event_type": row.event_type,
            "ai_system_id": row.ai_system_id,
            "app_id": row.app_id,
            "canonical_action": canonical_action,
            "policy_evaluation": dict(metadata.get("policy_evaluation") or {}),
            "enforcement_status": enforcement_status,
            "semantic_drift": dict(metadata.get("semantic_drift") or {}),
            "triggered_controls": list(metadata.get("triggered_controls") or []),
            "missed_controls": list(metadata.get("missed_controls") or []),
            "risk_tags": list(metadata.get("risk_tags") or []),
            "crq": dict(metadata.get("crq") or {}),
            "ai_action": dict(metadata.get("ai_action") or {}),
            "receipt_audit_log_id": runtime_receipt_audit_id,
        },
        correlation_id=row.correlation_id,
    )

    _link_source_evidence_to_runtime_node(
        db,
        tenant_id=payload.tenant_id,
        source_evidence_node_ids=evidence_ids,
        runtime_node_id=runtime_node.id,
    )
    row.evidence_node_ids = _uniq([*evidence_ids, runtime_node.id])
    db.flush()

    if bool(metadata.get("activity_audit_managed_by_source")) and not canonical_dual_write_enabled:
        try:
            activity_action = db.get(ActivityAIAction, row.event_id)
            if activity_action is None:
                activity_action = db.scalar(
                    select(ActivityAIAction).where(
                        ActivityAIAction.tenant_id == row.tenant_id,
                        ActivityAIAction.runtime_event_id == row.event_id,
                    )
                )
            if activity_action is None and row.correlation_id:
                activity_action = db.scalar(
                    select(ActivityAIAction)
                    .where(
                        ActivityAIAction.tenant_id == row.tenant_id,
                        ActivityAIAction.correlation_id == row.correlation_id,
                    )
                    .order_by(ActivityAIAction.timestamp.desc())
                )
            if activity_action is not None:
                action_metadata = dict(activity_action.metadata_json or {})
                action_metadata.update(
                    {
                        "ai_action": dict(metadata.get("ai_action") or {}),
                        "control_mode": dict((metadata.get("ai_action") or {}).get("policy") or {}).get("control_mode")
                        or metadata.get("control_mode"),
                        "policy_snapshot": dict((metadata.get("ai_action") or {}).get("policy_snapshot") or {}),
                        "decision_explanation": dict(metadata.get("decision_explanation") or {}),
                        "evidence_bundle": dict((metadata.get("ai_action") or {}).get("evidence_bundle") or {}),
                        "canonical_ai_action_v1": dict(metadata.get("canonical_ai_action_v1") or {}),
                        "canonical_ai_action_hash": metadata.get("canonical_ai_action_hash"),
                        "deployment_linkage_verified": (
                            metadata.get("deployment_linkage_verified") is True
                        ),
                        "provenance": dict(metadata.get("provenance") or {}),
                        "authorization_kernel_v2_shadow": dict(
                            metadata.get("authorization_kernel_v2_shadow") or {}
                        ),
                        "authorization_kernel_v2_shadow_health": dict(
                            metadata.get("authorization_kernel_v2_shadow_health") or {}
                        ),
                    }
                )
                activity_action.metadata_json = action_metadata
                db.flush()
        except Exception as exc:  # pragma: no cover - non-blocking enrichment
            log_structured(
                "runtime_activity_audit_source_managed_update_failed",
                tenant_id=row.tenant_id,
                runtime_event_id=row.event_id,
                source_surface=row.source_surface,
                event_type=row.event_type,
                correlation_id=row.correlation_id,
                error=str(exc),
            )
        metadata["activity_audit"] = {"managed_by_source": True}
        row.metadata_json = metadata
        db.flush()
    else:
        try:
            activity_record = record_activity_event(
                db,
                tenant_id=row.tenant_id,
                user_id=row.user_id,
                payload=_activity_audit_payload_from_runtime_event(
                    row=row,
                    metadata=metadata,
                    runtime_node_id=runtime_node.id,
                    runtime_receipt_audit_id=runtime_receipt_audit_id,
                ),
            )
            metadata["activity_audit"] = {
                "action_id": activity_record.action_id,
                "session_id": activity_record.session_id,
                "endpoint_id": activity_record.endpoint_id,
                "alert_id": activity_record.alert_id,
                "prompt_storage_mode": activity_record.prompt_storage_mode,
            }
            row.metadata_json = metadata
            db.flush()
            if canonical_dual_write_enabled:
                activity_action = db.get(ActivityAIAction, activity_record.action_id)
                activity_metadata = (
                    dict(activity_action.metadata_json or {})
                    if activity_action is not None and isinstance(activity_action.metadata_json, dict)
                    else {}
                )
                if (
                    activity_action is None
                    or activity_action.runtime_event_id != row.event_id
                    or activity_metadata.get("canonical_ai_action_v1")
                    != metadata.get("canonical_ai_action_v1")
                    or activity_metadata.get("canonical_ai_action_hash")
                    != metadata.get("canonical_ai_action_hash")
                ):
                    raise CanonicalProjectionError("canonical activity projection did not match RuntimeEvent")
        except Exception as exc:  # pragma: no cover - defensive non-blocking guard
            if canonical_dual_write_enabled:
                if isinstance(exc, CanonicalProjectionError):
                    raise
                raise CanonicalProjectionError("canonical activity projection failed") from exc
            log_structured(
                "runtime_activity_audit_record_failed",
                tenant_id=row.tenant_id,
                runtime_event_id=row.event_id,
                source_surface=row.source_surface,
                event_type=row.event_type,
                correlation_id=row.correlation_id,
                error=str(exc),
            )

    operational_telemetry = bool(metadata.get("operational_telemetry"))
    suppress_shadow_ai = operational_telemetry or bool(metadata.get("suppress_shadow_ai"))
    suppress_ai_discovery = operational_telemetry or bool(metadata.get("suppress_ai_discovery"))
    suppress_anomaly_detection = operational_telemetry or bool(metadata.get("suppress_anomaly_detection"))

    if suppress_shadow_ai:
        shadow_result = None
    else:
        try:
            shadow_result = safe_process_runtime_event_for_shadow_discovery(db, event=row)
        except Exception as exc:  # pragma: no cover - defensive non-blocking guard
            log_structured(
                "shadow_ai_discovery_processing_failed",
                tenant_id=row.tenant_id,
                runtime_event_id=row.event_id,
                source_surface=row.source_surface,
                event_type=row.event_type,
                correlation_id=row.correlation_id,
                error=str(exc),
            )
            shadow_result = None
    if shadow_result is not None:
        metadata.update(
            {
                "shadow_ai_entity_id": shadow_result.entity_id,
                "shadow_ai_signal_id": shadow_result.signal_id,
                "shadow_ai_confidence_score": shadow_result.confidence_score,
                "shadow_ai_confidence_level": shadow_result.confidence_level,
                "shadow_ai_risk_tier": shadow_result.risk_tier,
                "shadow_ai_finding_id": shadow_result.finding_id,
            }
        )
        if not row.ai_system_id and shadow_result.ai_system_id:
            row.ai_system_id = shadow_result.ai_system_id
        row.metadata_json = metadata
        db.flush()

    if suppress_ai_discovery:
        discovery_result = None
    else:
        try:
            discovery_result = process_runtime_event_for_ai_discovery(
                db,
                event=row,
            )
        except Exception as exc:  # pragma: no cover - defensive non-blocking guard
            log_structured(
                "ai_discovery_processing_failed",
                tenant_id=row.tenant_id,
                runtime_event_id=row.event_id,
                source_surface=row.source_surface,
                event_type=row.event_type,
                correlation_id=row.correlation_id,
                error=str(exc),
            )
            discovery_result = None
    if discovery_result is not None:
        metadata["ai_discovery"] = {
            "discovery_application_id": discovery_result.get("discovery_application_id"),
            "tool_key": discovery_result.get("tool_key"),
            "status": discovery_result.get("status"),
            "created": bool(discovery_result.get("created")),
            "risk_tier": discovery_result.get("risk_tier"),
        }
        row.metadata_json = metadata
        db.flush()

    if suppress_anomaly_detection:
        anomaly_events = []
    else:
        try:
            anomaly_events = detect_and_enforce_runtime_anomalies(
                db,
                event=row,
            )
        except Exception as exc:  # pragma: no cover - defensive non-blocking guard
            log_structured(
                "ai_anomaly_detection_failed",
                tenant_id=row.tenant_id,
                runtime_event_id=row.event_id,
                source_surface=row.source_surface,
                event_type=row.event_type,
                correlation_id=row.correlation_id,
                error=str(exc),
            )
            anomaly_events = []
    if anomaly_events:
        metadata["anomaly_events"] = list(anomaly_events)
        row.metadata_json = metadata
        db.flush()
        _safe_publish_runtime_update(
            tenant_id=row.tenant_id,
            event_type="runtime.anomaly.summary",
            payload={
                "event_id": row.event_id,
                "correlation_id": row.correlation_id,
                "anomaly_count": len(anomaly_events),
                "anomaly_types": [str(item.get("anomaly_type") or "") for item in anomaly_events],
                "enforcement_actions": [str(item.get("enforcement_action") or "none") for item in anomaly_events],
                "created_at": row.created_at.isoformat(),
            },
        )

    _safe_publish_runtime_update(
        tenant_id=row.tenant_id,
        event_type="runtime.activity.created",
        payload={
            "event_id": row.event_id,
            "source_surface": row.source_surface,
            "event_type": row.event_type,
            "ai_system_id": row.ai_system_id,
            "agent_id": row.agent_id,
            "user_id": row.user_id,
            "chain_id": row.chain_id,
            "context_id": row.context_id,
            "correlation_id": row.correlation_id,
            "severity": row.severity,
            "risk_score": float(row.risk_score or 0.0),
            "decision": str(metadata.get("decision") or metadata.get("final_decision") or "").strip().lower() or "unknown",
            "policy_decision": str(
                dict(metadata.get("policy_evaluation") or {}).get("decision") or ""
            ).strip().lower()
            or "defer",
            "enforcement_status": str(metadata.get("enforcement_status") or "enforced"),
            "created_at": row.created_at.isoformat(),
        },
    )
    if row.chain_id or row.context_id:
        _safe_publish_runtime_update(
            tenant_id=row.tenant_id,
            event_type="runtime.chain.updated",
            payload={
                "event_id": row.event_id,
                "chain_id": row.chain_id,
                "context_id": row.context_id,
                "parent_action_id": row.parent_action_id,
                "agent_id": row.agent_id,
                "entity_type": row.entity_type,
                "entity_id": row.entity_id,
                "correlation_id": row.correlation_id,
                "created_at": row.created_at.isoformat(),
            },
        )

    finding_ids: list[str] = []
    related_controls: list[str] = []

    try:
        candidates = correlate_runtime_event(db, event=row)
    except Exception as exc:  # pragma: no cover - defensive non-blocking guard
        log_structured(
            "runtime_intelligence_correlation_failed",
            event_id=row.event_id,
            tenant_id=row.tenant_id,
            error=str(exc),
        )
        candidates = []

    for candidate in candidates:
        risk = score_runtime_risk(
            event={
                "severity": candidate.severity,
                "chain_depth": metadata.get("chain_depth"),
                "governance_state": metadata.get("governance_state"),
                "data_classification": metadata.get("data_classification"),
                "response_size": metadata.get("response_size"),
            },
            repeated_event_count=candidate.repeated_count,
            governance_state=str(metadata.get("governance_state") or "unknown"),
            asymmetry_signal=(candidate.finding_type == "asymmetry_risk_spike"),
            chain_depth=metadata.get("chain_depth"),
            data_classification=metadata.get("data_classification"),
        )

        ai_tool = (
            str(row.app_id or "").strip()
            or str(metadata.get("tool_name") or "").strip()
            or str(metadata.get("model_name") or "").strip()
            or str(metadata.get("model_provider") or "").strip()
            or str(metadata.get("provider") or "").strip()
            or "runtime_signal"
        )
        candidate_related_controls = normalize_control_ids(list(candidate.related_control_ids or []))
        if not candidate_related_controls:
            candidate_related_controls = normalize_control_ids(list(metadata.get("triggered_controls") or []))
        finding = generate_runtime_intelligence_finding(
            db,
            tenant_id=row.tenant_id,
            source_surface=row.source_surface,
            ai_tool=ai_tool,
            ai_system_id=row.ai_system_id,
            user_id=row.user_id,
            agent_id=row.agent_id,
            machine_id=(
                str(metadata.get("machine_id") or "").strip()
                or str(metadata.get("endpoint_id") or "").strip()
                or None
            ),
            policy_version_id=row.policy_version_id,
            finding_type=candidate.finding_type,
            risk_category=candidate.risk_category,
            severity=risk.suggested_severity,
            reason_code=candidate.reason_code,
            repeated_count=candidate.repeated_count,
            evidence_node_ids=_uniq([*row.evidence_node_ids, *candidate.evidence_node_ids]),
            related_event_ids=[row.event_id],
            related_control_ids=candidate_related_controls,
            recommended_action=candidate.recommended_action,
        )
        if finding is not None:
            finding_ids.append(finding.finding_id)
        pattern = upsert_runtime_pattern(
            db,
            event=row,
            candidate=candidate,
            severity=risk.suggested_severity,
        )
        _safe_publish_runtime_update(
            tenant_id=row.tenant_id,
            event_type="runtime.pattern.detected",
            payload={
                "pattern_id": pattern.pattern_id,
                "type": pattern.type,
                "frequency": int(pattern.frequency or 0),
                "severity": pattern.severity,
                "affected_entities": list(pattern.affected_entities or []),
                "event_id": row.event_id,
                "ai_system_id": row.ai_system_id,
                "correlation_id": row.correlation_id,
            },
        )
        _safe_publish_runtime_update(
            tenant_id=row.tenant_id,
            event_type="runtime.risk.updated",
            payload={
                "event_id": row.event_id,
                "ai_system_id": row.ai_system_id,
                "chain_id": row.chain_id,
                "context_id": row.context_id,
                "finding_type": candidate.finding_type,
                "reason_code": candidate.reason_code,
                "risk_score": float(risk.risk_score) / 100.0,
                "suggested_severity": risk.suggested_severity,
                "recommended_action": risk.recommended_action,
                "crq": dict(metadata.get("crq") or {}),
                "correlation_id": row.correlation_id,
            },
        )

        monitoring_signal = MonitoringSignal(
            tenant_id=row.tenant_id,
            ai_system_id=row.ai_system_id,
            signal_type=f"runtime_intelligence.{candidate.finding_type}",
            severity=risk.suggested_severity,
            payload={
                "runtime_event_id": row.event_id,
                "finding_type": candidate.finding_type,
                "reason_code": candidate.reason_code,
                "risk_score": risk.risk_score,
                "risk_reasoning": risk.reasoning,
                "recommended_action": risk.recommended_action,
                "evidence_node_ids": _uniq([*row.evidence_node_ids, *candidate.evidence_node_ids]),
                "related_control_ids": candidate_related_controls,
                "triggered_controls": list(metadata.get("triggered_controls") or []),
                "missed_controls": list(metadata.get("missed_controls") or []),
                "risk_tags": list(metadata.get("risk_tags") or []),
                "crq": dict(metadata.get("crq") or {}),
                "correlation_id": row.correlation_id,
            },
        )
        db.add(monitoring_signal)

        related_controls.extend(candidate_related_controls)

        create_runtime_simulation_trigger(
            db,
            tenant_id=row.tenant_id,
            ai_system_id=row.ai_system_id,
            event_id=row.event_id,
            reason_code=candidate.reason_code,
            related_control_ids=candidate_related_controls,
            evidence_node_ids=row.evidence_node_ids,
            correlation_id=row.correlation_id,
            recommended_action=candidate.recommended_action,
        )

        recommendations = governance_recommendations_for_candidate(
            event=row,
            candidate=candidate,
            db=db,
            risk_score=risk.risk_score,
            pattern=pattern,
        )
        for recommendation in recommendations:
            recommendation_payload = dict(recommendation.payload or {})
            recommendation_payload.update(
                {
                    "risk_score": risk.risk_score,
                    "risk_severity": risk.suggested_severity,
                    "risk_reasoning": risk.reasoning,
                    "related_control_ids": candidate_related_controls,
                    "evidence_node_ids": _uniq([*row.evidence_node_ids, *candidate.evidence_node_ids]),
                }
            )
            recommendation_row = RuntimeGovernanceRecommendation(
                tenant_id=row.tenant_id,
                event_id=row.event_id,
                ai_system_id=row.ai_system_id,
                recommendation_type=recommendation.recommendation_type,
                reason_code=recommendation.reason_code,
                priority=recommendation.priority,
                payload=recommendation_payload,
                status="proposed",
            )
            db.add(recommendation_row)
            db.flush()
            try:
                from app.services.remediation import propose_remediation_from_runtime_recommendation

                propose_remediation_from_runtime_recommendation(
                    db,
                    recommendation=recommendation_row,
                    context={
                        "reason_code": recommendation_row.reason_code,
                        "related_control_ids": list(candidate_related_controls or []),
                        "evidence_node_ids": _uniq([*row.evidence_node_ids, *candidate.evidence_node_ids]),
                        "finding_type": candidate.finding_type,
                    },
                )
            except Exception as exc:  # pragma: no cover - non-blocking remediation enrichment
                log_structured(
                    "runtime_remediation_proposal_failed",
                    module="runtime_event_normalizer",
                    tenant_id=row.tenant_id,
                    event_id=row.event_id,
                    recommendation_id=recommendation_row.recommendation_id,
                    error=str(exc),
                )
            _safe_publish_runtime_update(
                tenant_id=row.tenant_id,
                event_type="runtime.recommendation.created",
                payload={
                    "recommendation_id": recommendation_row.recommendation_id,
                    "event_id": row.event_id,
                    "ai_system_id": row.ai_system_id,
                    "recommendation_type": recommendation_row.recommendation_type,
                    "reason_code": recommendation_row.reason_code,
                    "priority": recommendation_row.priority,
                    "status": recommendation_row.status,
                    "correlation_id": row.correlation_id,
                    "created_at": recommendation_row.created_at.isoformat() if recommendation_row.created_at else None,
                },
            )

    build_behavior_graph_for_event(
        db,
        event=row,
        finding_ids=finding_ids,
        related_control_ids=_uniq(related_controls),
    )
    db.flush()
    return row


def ingest_from_gateway_enforcement(
    db: Session,
    *,
    event: EnforcementEvent,
) -> RuntimeEventRow | None:
    meta = dict(event.final_actions or {}) if isinstance(event.final_actions, dict) else {}
    meta_block = dict(meta.get("_meta") or {}) if isinstance(meta.get("_meta"), dict) else {}
    trace = dict(meta.get("_trace") or {}) if isinstance(meta.get("_trace"), dict) else {}
    # `_trace` is assembled by the server enforcement path. The same object at
    # the caller-visible top level remains telemetry only and is not authority.
    trusted_pre_action_governance_check = (
        dict(trace.get("pre_action_governance_check") or {})
        if isinstance(trace.get("pre_action_governance_check"), dict)
        else None
    )
    session_validation = (
        dict(trace.get("session_validation") or {})
        if isinstance(trace.get("session_validation"), dict)
        else (
            dict(meta.get("session") or {})
            if isinstance(meta.get("session"), dict)
            else (
                dict(meta_block.get("session_validation") or {})
                if isinstance(meta_block.get("session_validation"), dict)
                else {}
            )
        )
    )
    dynamic_permission = (
        dict(trace.get("dynamic_permission") or {})
        if isinstance(trace.get("dynamic_permission"), dict)
        else (
            dict(meta.get("dynamic_permission") or {})
            if isinstance(meta.get("dynamic_permission"), dict)
            else (
                dict(meta_block.get("dynamic_permission") or {})
                if isinstance(meta_block.get("dynamic_permission"), dict)
                else {}
            )
        )
    )
    anomaly_score = (
        _to_float(trace.get("anomaly_score"))
        if _to_float(trace.get("anomaly_score")) is not None
        else (
            _to_float(meta.get("anomaly_score"))
            if _to_float(meta.get("anomaly_score")) is not None
            else _to_float(meta_block.get("anomaly_score"))
        )
    )
    over_scoped_flag = bool(
        meta.get("over_scoped_flag")
        or meta_block.get("over_scoped_flag")
        or (meta.get("mcp", {}).get("over_scoped_flag") if isinstance(meta.get("mcp"), dict) else False)
    )
    new_system_access_detected = bool(
        meta.get("new_system_access_detected")
        or meta_block.get("new_system_access_detected")
        or (meta.get("mcp", {}).get("new_system_access_detected") if isinstance(meta.get("mcp"), dict) else False)
    )
    privilege_escalation_detected = bool(
        meta.get("privilege_escalation_detected")
        or meta_block.get("privilege_escalation_detected")
        or (meta.get("mcp", {}).get("privilege_escalation_detected") if isinstance(meta.get("mcp"), dict) else False)
    )
    abnormal_tool_usage_detected = bool(
        meta.get("abnormal_tool_usage_detected")
        or meta_block.get("abnormal_tool_usage_detected")
        or (meta.get("mcp", {}).get("abnormal_tool_usage_detected") if isinstance(meta.get("mcp"), dict) else False)
    )

    decision = str(event.final_decision or "allow").strip().lower()
    event_type = "mcp_authorize" if str(event.input_context_summary or "").strip().lower() == "mcp_authorize" else "llm_intercept"
    control_mode = _strict_gateway_control_mode(
        event_type=event_type,
        decision=decision,
        meta=meta,
        meta_block=meta_block,
        trace=trace,
    )
    mcp_action = dict(meta.get("mcp") or {}) if isinstance(meta.get("mcp"), dict) else {}
    mcp_server_id = _normalize_mcp_server_id(
        trace.get("mcp_server_id")
        or mcp_action.get("mcp_server_id")
        or (
            dynamic_permission.get("context", {}).get("target_host")
            if isinstance(dynamic_permission.get("context"), dict)
            else None
        )
        or trace.get("api_endpoint")
    )
    mcp_tool_name = (
        str(trace.get("tool_name") or mcp_action.get("tool_name") or mcp_action.get("action") or "").strip() or None
    )
    mcp_tool_id = str(trace.get("mcp_tool_id") or mcp_action.get("mcp_tool_id") or mcp_tool_name or "").strip() or None
    ai_client = (
        str(trace.get("ai_client") or mcp_action.get("ai_client") or meta_block.get("ai_client") or "").strip() or None
    )
    app_id = (mcp_server_id or "mcp_gateway") if event_type == "mcp_authorize" else "llm_gateway"
    correlation_id = str(event.correlation_id or "").strip() or None
    request_id = str(event.request_id or "").strip() or None
    context_id = (
        str(meta_block.get("context_id") or "").strip()
        or str(trace.get("context_id") or "").strip()
        or correlation_id
        or request_id
    )
    chain_id = (
        str(meta_block.get("chain_id") or "").strip()
        or str(trace.get("chain_id") or "").strip()
        or request_id
        or correlation_id
        or context_id
    )
    parent_action_id = (
        str(trace.get("parent_action_id") or "").strip()
        or str(meta_block.get("parent_action_id") or "").strip()
        or (
            str(meta.get("mcp", {}).get("parent_action_id") or "").strip()
            if isinstance(meta.get("mcp"), dict)
            else ""
        )
        or None
    )
    actor_type = str(event.actor_type or "").strip().lower()
    entity_type = "agent" if actor_type == "agent" else "user"
    entity_id = str(event.actor_id or "").strip() or None

    control_ids = normalize_control_ids(
        [
            str(item.get("control_id"))
            for item in (event.controls_impacted or [])
            if isinstance(item, dict) and str(item.get("control_id") or "").strip()
        ]
    )

    payload = RuntimeEventIngestPayload(
        tenant_id=event.tenant_id,
        source_surface="gateway",
        event_type=event_type,
        ai_system_id=event.ai_system_id,
        app_id=app_id,
        user_id=event.actor_id if str(event.actor_type or "").lower() == "human" else None,
        agent_id=event.actor_id if str(event.actor_type or "").lower() == "agent" else None,
        risk_tier=str(meta_block.get("risk_tier") or "").strip() or None,
        policy_version_id=event.policy_version_id,
        governance_version=str(meta_block.get("governance_version") or "").strip() or None,
        severity=SEVERITY_BY_DECISION.get(decision, "low"),
        confidence_tier=_pick_confidence_tier([item for item in (event.guardian_results or []) if isinstance(item, dict)]),
        evidence_node_ids=[str(node_id) for node_id in (event.evidence_nodes_created or []) if str(node_id).strip()],
        correlation_id=correlation_id,
        context_id=context_id,
        chain_id=chain_id,
        parent_action_id=parent_action_id,
        entity_type=entity_type,
        entity_id=entity_id,
        risk_score=anomaly_score,
        model_provider=(
            str(
                trace.get("provider")
                or meta_block.get("model_provider")
                or meta_block.get("provider")
                or meta.get("provider")
                or ""
            ).strip()
            or None
        ),
        provider=(
            str(trace.get("provider") or meta_block.get("provider") or meta.get("provider") or "").strip() or None
        ),
        model_name=(str(trace.get("model") or meta_block.get("model_name") or meta.get("model_name") or "").strip() or None),
        model_version=(str(trace.get("model_version") or meta_block.get("model_version") or "").strip() or None),
        tool_name=(
            str(
                mcp_tool_name
                or trace.get("tool_name")
                or (meta.get("mcp", {}).get("tool_name") if isinstance(meta.get("mcp"), dict) else None)
                or (meta.get("mcp", {}).get("action") if isinstance(meta.get("mcp"), dict) else None)
                or meta.get("tool_name")
                or ""
            ).strip()
            or None
        ),
        tool_category=(
            str(
                trace.get("tool_category")
                or (meta.get("mcp", {}).get("tool_category") if isinstance(meta.get("mcp"), dict) else None)
                or meta.get("tool_category")
                or ""
            ).strip()
            or None
        ),
        api_endpoint=(
            str(
                trace.get("api_endpoint")
                or meta.get("api_endpoint")
                or ("/gateway/mcp/authorize" if event_type == "mcp_authorize" else "/gateway/llm/intercept")
            ).strip()
            or None
        ),
        data_source=(str(trace.get("data_source") or meta.get("data_source") or meta_block.get("data_source") or "").strip() or None),
        response_size=_to_int(meta.get("response_size") or meta_block.get("response_size")),
        chain_depth=(
            _to_int(trace.get("chain_depth"))
            if _to_int(trace.get("chain_depth")) is not None
            else _to_int(meta.get("mcp", {}).get("chain_depth") if isinstance(meta.get("mcp"), dict) else None)
        ),
        parent_agent_id=(
            str(
                trace.get("parent_agent_id")
                or (meta.get("mcp", {}).get("parent_agent_id") if isinstance(meta.get("mcp"), dict) else None)
                or meta_block.get("parent_agent_id")
                or ""
            ).strip()
            or None
        ),
        metadata={
            "decision": decision,
            "operational_telemetry": bool(meta.get("operational_telemetry")),
            "reason": (meta.get("mcp", {}).get("reason") if isinstance(meta.get("mcp"), dict) else None),
            "original_intent": str(event.input_context_summary or "").strip() or None,
            "action_type": (
                _mcp_action_type_for_decision(decision)
                if event_type == "mcp_authorize"
                else ("prompt" if event_type == "llm_intercept" else event_type)
            ),
            "operation": (
                "mcp_tool_call"
                if event_type == "mcp_authorize"
                else ("prompt_submission" if event_type == "llm_intercept" else event_type)
            ),
            "ai_surface": ("mcp_tool_call" if event_type == "mcp_authorize" else "gateway"),
            "identity_type": ("agent" if str(event.actor_type or "").strip().lower() == "agent" else "user"),
            "ai_client": ai_client,
            "mcp_server_id": mcp_server_id,
            "mcp_tool_id": mcp_tool_id,
            "tool_name": mcp_tool_name,
            "tool_arguments_ref": str(trace.get("redacted_input_ref") or trace.get("prompt_hash") or "").strip() or None,
            "tool_result_ref": str(trace.get("redacted_output_ref") or trace.get("response_hash") or "").strip() or None,
            "control_mode": control_mode,
            "response_control_coverage": normalize_response_control_coverage(
                trace.get("response_control_coverage")
            ),
            "can_prevent_execution": _gateway_can_prevent_execution(
                event_type=event_type,
                control_mode=control_mode,
            ),
            "target_resource": (
                str(meta.get("mcp", {}).get("resource") or "").strip()
                if isinstance(meta.get("mcp"), dict)
                else None
            ),
            "input_signal_types": [
                str(threat)
                for item in (event.guardian_results or [])
                if isinstance(item, dict)
                for threat in (item.get("threat_types") or [])
            ],
            "risk_labels": list(meta.get("asymmetry_signal", {}).get("risk_labels") or []) if isinstance(meta.get("asymmetry_signal"), dict) else [],
            "related_control_ids": control_ids,
            "governance_state": str(meta_block.get("governance_state") or "unknown"),
            "governance_source": str(meta_block.get("governance_source") or "").strip() or None,
            "governance_enforcement_mode": str(meta_block.get("governance_enforcement_mode") or "").strip() or None,
            "context_id": context_id,
            "chain_id": chain_id,
            "parent_action_id": parent_action_id,
            "capability_token_id": trace.get("capability_token_id"),
            "delegation_edge_id": trace.get("delegation_edge_id"),
            "entity_type": entity_type,
            "entity_id": entity_id,
            "model_provider": str(
                trace.get("provider")
                or meta_block.get("model_provider")
                or meta_block.get("provider")
                or meta.get("provider")
                or ""
            ).strip()
            or None,
            "provider": str(trace.get("provider") or meta_block.get("provider") or meta.get("provider") or "").strip() or None,
            "model_name": str(trace.get("model") or meta_block.get("model_name") or meta.get("model_name") or "").strip() or None,
            "model_version": str(trace.get("model_version") or meta_block.get("model_version") or "").strip() or None,
            "tool_name": str(
                mcp_tool_name
                or trace.get("tool_name")
                or (meta.get("mcp", {}).get("tool_name") if isinstance(meta.get("mcp"), dict) else None)
                or (meta.get("mcp", {}).get("action") if isinstance(meta.get("mcp"), dict) else None)
                or meta.get("tool_name")
                or ""
            ).strip()
            or None,
            "tool_category": (
                str(
                    trace.get("tool_category")
                    or (meta.get("mcp", {}).get("tool_category") if isinstance(meta.get("mcp"), dict) else None)
                    or meta.get("tool_category")
                    or ""
                ).strip()
                or None
            ),
            "api_endpoint": str(
                trace.get("api_endpoint")
                or meta.get("api_endpoint")
                or ("/gateway/mcp/authorize" if event_type == "mcp_authorize" else "/gateway/llm/intercept")
            ).strip()
            or None,
            "mcp_server_id": mcp_server_id,
            "mcp_tool_id": mcp_tool_id,
            "ai_client": ai_client,
            "data_source": str(trace.get("data_source") or meta.get("data_source") or meta_block.get("data_source") or "").strip() or None,
            "data_classification": str(meta_block.get("data_classification") or meta.get("data_classification") or "").strip() or None,
            "contains_sensitive": bool(
                trace.get("contains_sensitive")
                if trace.get("contains_sensitive") is not None
                else meta_block.get("contains_sensitive")
            ),
            "sensitive_confidence_score": (
                _to_float(trace.get("sensitive_confidence_score"))
                if trace.get("sensitive_confidence_score") is not None
                else (
                    _to_float(meta_block.get("sensitive_confidence_score"))
                    if meta_block.get("sensitive_confidence_score") is not None
                    else None
                )
            ),
            "sensitive_entities": list(
                trace.get("sensitive_entities")
                or meta_block.get("sensitive_entities")
                or []
            ),
            "knowledge_asset_ids": list(
                trace.get("knowledge_asset_ids")
                or meta_block.get("knowledge_asset_ids")
                or []
            ),
            "sensitivity_domain": (
                str(trace.get("sensitivity_domain") or meta_block.get("sensitivity_domain") or "").strip()
                or None
            ),
            "need_to_know_decision": (
                dict(trace.get("need_to_know_decision") or meta_block.get("need_to_know_decision") or {})
                if isinstance(trace.get("need_to_know_decision") or meta_block.get("need_to_know_decision"), dict)
                else {}
            ),
            "knowledge_disclosure_event": (
                dict(trace.get("knowledge_disclosure_event") or meta_block.get("knowledge_disclosure_event") or {})
                if isinstance(
                    trace.get("knowledge_disclosure_event") or meta_block.get("knowledge_disclosure_event"),
                    dict,
                )
                else {}
            ),
            "response_size": _to_int(meta.get("response_size") or meta_block.get("response_size")),
            "chain_depth": (
                _to_int(trace.get("chain_depth"))
                if _to_int(trace.get("chain_depth")) is not None
                else _to_int(meta.get("mcp", {}).get("chain_depth") if isinstance(meta.get("mcp"), dict) else None)
            ),
            "parent_agent_id": (
                str(
                    trace.get("parent_agent_id")
                    or (meta.get("mcp", {}).get("parent_agent_id") if isinstance(meta.get("mcp"), dict) else None)
                    or meta_block.get("parent_agent_id")
                    or ""
                ).strip()
                or None
            ),
            "prompt_hash": str(trace.get("prompt_hash") or meta_block.get("prompt_hash") or "").strip() or None,
            "response_hash": str(trace.get("response_hash") or meta_block.get("response_hash") or "").strip() or None,
            "governance_version": str(trace.get("governance_version") or meta_block.get("governance_version") or "").strip() or None,
            "session_id": (
                str(trace.get("session_id") or "").strip()
                or str((meta.get("mcp", {}).get("session_id") if isinstance(meta.get("mcp"), dict) else "")).strip()
                or str(session_validation.get("session_id") or "").strip()
                or None
            ),
            "initiating_user_id": (
                str(trace.get("initiating_user_id") or "").strip()
                or str(session_validation.get("initiating_user_id") or "").strip()
                or None
            ),
            "session_expiry": (
                str(trace.get("session_expiry") or "").strip()
                or str(session_validation.get("expiry") or "").strip()
                or None
            ),
            "session_validation": session_validation,
            "dynamic_permission": dynamic_permission,
            "pre_action_governance_check": (
                dict(trace.get("pre_action_governance_check") or {})
                if isinstance(trace.get("pre_action_governance_check"), dict)
                else (
                    dict(meta.get("pre_action_governance_check") or {})
                    if isinstance(meta.get("pre_action_governance_check"), dict)
                    else {}
                )
            ),
            "decision_badge": str(trace.get("decision_badge") or meta.get("decision_badge") or "").strip() or None,
            "anomaly_score": anomaly_score,
            "over_scoped_flag": over_scoped_flag,
            "new_system_access_detected": new_system_access_detected,
            "privilege_escalation_detected": privilege_escalation_detected,
            "abnormal_tool_usage_detected": abnormal_tool_usage_detected,
            "known_systems": list(
                (
                    dynamic_permission.get("context")
                    if isinstance(dynamic_permission.get("context"), dict)
                    else {}
                ).get("connected_systems")
                or []
            ),
        },
    )
    return ingest_runtime_event(
        db,
        payload=payload,
        trusted_pre_action_governance_check=trusted_pre_action_governance_check,
        canonical_control_path=gateway_control_path_evidence(
            request_stage=str(trace.get("request_stage") or "").strip() or None,
            event_type=event_type,
            decision=decision,
        ),
    )


def ingest_from_browser_signal(
    db: Session,
    *,
    tenant_id: str,
    payload: dict[str, Any],
    ai_system_id: str | None,
    evidence_node_id: str | None,
    monitoring_signal_id: str | None,
    trusted_pre_action_governance_check: dict[str, Any] | None = None,
) -> RuntimeEventRow | None:
    domain = str(payload.get("domain") or "").strip() or None
    source_event_type = str(payload.get("event_type") or "browser_event").strip().lower()
    action_taken = str(payload.get("action_taken") or "").strip().lower()
    decision = (action_taken.split(":", 1)[0] if action_taken else "").strip().lower() or None
    if decision not in {"allow", "warn", "block", "deny"}:
        if source_event_type == "browser_automation_blocked":
            decision = "block"
        elif source_event_type in {"browser_automation_detected", "browser_automation_action"}:
            decision = "warn"
        else:
            decision = None
    runtime_event_type = (
        "browser_automation_action"
        if source_event_type in {"browser_automation_action", "browser_automation_detected", "browser_automation_blocked"}
        else source_event_type
    )
    automation_suspected = bool(payload.get("automation_suspected")) or source_event_type.startswith("browser_automation")
    suspected_tool = _normalize_browser_suspected_tool(payload.get("suspected_tool"))
    source_vendor = _source_vendor_for_browser_tool(suspected_tool)
    action_type = str(payload.get("action_type") or runtime_event_type).strip().lower()
    action_risk = str(payload.get("action_risk") or "").strip().lower() or None
    scope_violation = "scope_violation" in action_taken
    decision_badge = str(payload.get("decision_badge") or "").strip() or _browser_decision_badge(
        str(decision or ""),
        scope_violation=scope_violation,
        automation_suspected=automation_suspected,
    )
    control_mode = str(payload.get("control_mode") or "").strip() or _browser_control_mode(
        str(decision or ""),
        automation_suspected=automation_suspected,
    )
    agent_id = str(payload.get("agent_id") or "").strip() or None
    correlation_id = str(payload.get("correlation_id") or "").strip() or None
    context_id = str(payload.get("context_id") or "").strip() or correlation_id
    chain_id = str(payload.get("chain_id") or "").strip() or context_id
    parent_action_id = str(payload.get("parent_action_id") or "").strip() or None
    entity_id = str(payload.get("user_id") or "").strip() or (domain or None)
    entity_type = "user" if str(payload.get("user_id") or "").strip() else ("tool" if domain else None)

    incoming_surface = str(payload.get("source_surface") or "browser").strip().lower().replace("_", "-")
    runtime_source_surface = "endpoint" if incoming_surface == "endpoint-agent" else "browser"
    runtime_payload = RuntimeEventIngestPayload(
        tenant_id=tenant_id,
        source_surface=runtime_source_surface,
        event_type=runtime_event_type,
        ai_system_id=ai_system_id,
        app_id=domain,
        user_id=str(payload.get("user_id") or "").strip() or None,
        agent_id=agent_id,
        risk_tier=None,
        policy_version_id=_safe_fk_text(payload.get("policy_version")),
        governance_version=None,
        severity=_normalize_severity(str(payload.get("severity") or "").strip()) or SEVERITY_BY_DECISION.get(decision or "", "low"),
        confidence_tier=str(payload.get("tier") or "").strip().lower() or None,
        evidence_node_ids=_uniq([
            evidence_node_id,
            *[str(node_id) for node_id in (payload.get("evidence_node_ids") or []) if str(node_id).strip()],
        ]),
        correlation_id=correlation_id,
        context_id=context_id,
        chain_id=chain_id,
        parent_action_id=parent_action_id,
        entity_type=entity_type,
        entity_id=entity_id,
        model_provider=str(payload.get("model_provider") or payload.get("provider") or "").strip() or None,
        provider=str(payload.get("provider") or "").strip() or None,
        model_name=str(payload.get("model_name") or "").strip() or None,
        model_version=str(payload.get("model_version") or "").strip() or None,
        tool_name=(
            str(payload.get("tool_name") or "").strip() or None
            if payload.get("tool_call_id") or payload.get("tool_invoked") or payload.get("function_call_id")
            or source_event_type in {"tool_call", "mcp_tool_call", "mcp_tool_call_allowed", "mcp_tool_call_blocked", "mcp_tool_call_denied", "mcp_tool_call_requested"}
            else None
        ),
        tool_category=str(
            payload.get("tool_category")
            or ("agent_runtime" if source_event_type == "agent_runtime_discovered" else "browser_interaction")
        ).strip() or None,
        api_endpoint=str(payload.get("url") or "").strip() or None,
        data_source=str(payload.get("data_source") or "").strip() or None,
        response_size=_to_int(payload.get("response_size")),
        chain_depth=None,
        parent_agent_id=str(payload.get("parent_agent_id") or "").strip() or None,
        metadata={
            "event_type": source_event_type,
            "action_taken": payload.get("action_taken"),
            "status": payload.get("status"),
            "healthy": payload.get("healthy"),
            "normalized_event_type": runtime_event_type,
            "decision": decision,
            "decision_badge": decision_badge,
            "control_mode": control_mode,
            "pre_action_governance_check": (
                dict(payload.get("pre_action_governance_check") or {})
                if isinstance(payload.get("pre_action_governance_check"), dict)
                else {}
            ),
            "intent_context": dict(payload.get("intent_context") or {})
            if isinstance(payload.get("intent_context"), dict)
            else {},
            "input_content_context": dict(payload.get("input_content_context") or {})
            if isinstance(payload.get("input_content_context"), dict)
            else {},
            "output_context": dict(payload.get("output_context") or {})
            if isinstance(payload.get("output_context"), dict)
            else {},
            "action_alignment_result": dict(payload.get("action_alignment_result") or {})
            if isinstance(payload.get("action_alignment_result"), dict)
            else {},
            "intent_aware_decision": dict(payload.get("intent_aware_decision") or {})
            if isinstance(payload.get("intent_aware_decision"), dict)
            else {},
            "destination_context": dict(payload.get("destination_context") or {})
            if isinstance(payload.get("destination_context"), dict)
            else {},
            "destination_app_name": str(payload.get("destination_app_name") or "").strip() or None,
            "destination_domain": str(payload.get("destination_domain") or "").strip() or None,
            "source_domain": str(payload.get("source_domain") or "").strip() or None,
            "intent_aware_evidence_summary": dict(payload.get("intent_aware_evidence_summary") or {})
            if isinstance(payload.get("intent_aware_evidence_summary"), dict)
            else {},
            "intent_category": str(payload.get("intent_category") or "").strip() or None,
            "intent_confidence": _to_float(payload.get("intent_confidence")),
            "business_context": str(payload.get("business_context") or "").strip() or None,
            "input_sensitivity": str(payload.get("input_sensitivity") or "").strip() or None,
            "output_sensitivity": str(payload.get("output_sensitivity") or "").strip() or None,
            "action_alignment": str(payload.get("action_alignment") or "").strip() or None,
            "matched_indicators": list(payload.get("matched_indicators") or []),
            "copy_export_control_applied": bool(payload.get("copy_export_control_applied")),
            "decision_reason": str(payload.get("decision_reason") or "").strip() or None,
            "operation": (
                "paste"
                if "paste" in source_event_type
                else (
                    "browser_automation"
                    if "automation" in runtime_event_type
                    else ("prompt_submission" if "prompt" in source_event_type else "browser_interaction")
                )
            ),
            "action_type": action_type,
            **project_browser_attachment_metadata(payload.get("file_meta")),
            "action_risk": action_risk,
            "operational_telemetry": bool(payload.get("operational_telemetry")),
            "suppress_shadow_ai": bool(payload.get("suppress_shadow_ai")),
            "suppress_ai_discovery": bool(payload.get("suppress_ai_discovery")),
            "suppress_anomaly_detection": bool(payload.get("suppress_anomaly_detection")),
            "suppress_live_activity": bool(payload.get("suppress_live_activity")),
            "suppress_ai_action": bool(payload.get("suppress_ai_action")),
            "original_intent": str(payload.get("prompt_preview_redacted") or payload.get("page_title") or "").strip() or None,
            "page_title": payload.get("page_title"),
            "url": payload.get("url"),
            "browser": payload.get("browser"),
            "browser_type": payload.get("browser_type") or payload.get("browser"),
            "browser_profile": payload.get("browser_profile"),
            "browser_version": payload.get("browser_version"),
            "extension_version": payload.get("extension_version"),
            "user_email": str(payload.get("user_email") or "").strip() or None,
            "source_user_ref": str(payload.get("source_user_ref") or "").strip() or None,
            "source_user_ref_status": str(payload.get("source_user_ref_status") or "").strip() or None,
            "endpoint_id": payload.get("endpoint_id"),
            "machine_id": payload.get("machine_id") or payload.get("endpoint_id"),
            "session_id": payload.get("session_id"),
            "hostname": payload.get("hostname"),
            "device_type": payload.get("device_type"),
            "os_type": payload.get("os_type"),
            "os_version": payload.get("os_version"),
            "ip_address": payload.get("ip_address"),
            "location": payload.get("location"),
            "source_surface": payload.get("source_surface") or "browser_extension",
            "ai_surface": "agentic_browser" if runtime_event_type == "browser_automation_action" else "browser",
            "risk_category": payload.get("risk_category"),
            "input_signal_types": list(payload.get("input_signal_types") or []),
            "reason_codes": list(payload.get("reason_codes") or []),
            "monitoring_signal_id": monitoring_signal_id,
            "context_id": context_id,
            "chain_id": chain_id,
            "parent_action_id": parent_action_id,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "data_classification": payload.get("data_classification"),
            "contains_sensitive": bool(payload.get("contains_sensitive"))
            if payload.get("contains_sensitive") is not None
            else None,
            "sensitive_confidence_score": payload.get("sensitive_confidence_score"),
            "sensitive_entities": list(payload.get("sensitive_entities") or []),
            "reason": str(payload.get("reason") or "").strip() or None,
            "automation_source": str(payload.get("automation_source") or "").strip() or None,
            "scope_domain": str(payload.get("scope_domain") or "").strip() or None,
            "current_domain": str(payload.get("current_domain") or domain or "").strip() or None,
            "current_url": str(payload.get("current_url") or payload.get("url") or "").strip() or None,
            "governance_state": payload.get("governance_state") or "unknown",
            "model_provider": str(payload.get("model_provider") or payload.get("provider") or "").strip() or None,
            "tool_category": str(payload.get("tool_category") or "browser_interaction").strip() or None,
            "data_source": str(payload.get("data_source") or "").strip() or None,
            "response_size": _to_int(payload.get("response_size")),
            "agent_id": agent_id,
            "agent_name": str(payload.get("agent_name") or "").strip() or None,
            "runtime_provider": str(payload.get("runtime_provider") or "").strip() or None,
            "agent_environment": str(payload.get("agent_environment") or "").strip() or None,
            "detected_tools": list(payload.get("detected_tools") or []),
            "detected_actions": list(payload.get("detected_actions") or []),
            "detected_privileges": list(payload.get("detected_privileges") or []),
            "agent_runtime_profile": dict(payload.get("agent_runtime_profile") or {})
            if isinstance(payload.get("agent_runtime_profile"), dict)
            else {},
            "integration_transports": list(payload.get("integration_transports") or []),
            "active_integration_transport": str(payload.get("active_integration_transport") or "unknown"),
            "control_binding": dict(payload.get("control_binding") or {})
            if isinstance(payload.get("control_binding"), dict)
            else {},
            "control_binding_state": str(payload.get("control_binding_state") or "unknown"),
            "evidence_basis": str(payload.get("evidence_basis") or "unknown"),
            "automation_suspected": bool(payload.get("automation_suspected"))
            if payload.get("automation_suspected") is not None
            else None,
            "automation_confidence": _to_float(payload.get("automation_confidence")),
            "suspected_tool": str(payload.get("suspected_tool") or "").strip() or None,
            "source_vendor": source_vendor,
            "automation_indicators": list(payload.get("automation_indicators") or []),
            "parent_agent_id": str(payload.get("parent_agent_id") or "").strip() or None,
            "application": str(payload.get("application") or domain or "").strip() or None,
            "endpoint_audio_posture": (
                dict(payload.get("endpoint_audio_posture") or {})
                if isinstance(payload.get("endpoint_audio_posture"), dict)
                else {}
            ),
            "raw_audio_captured": payload.get("raw_audio_captured"),
            "audio_content_captured": payload.get("audio_content_captured"),
            "endpoint_audio_signal_basis": str(payload.get("endpoint_audio_signal_basis") or "").strip() or None,
            "microphone_permission_state": str(payload.get("microphone_permission_state") or "").strip() or None,
            "microphone_revocation_available": payload.get("microphone_revocation_available"),
            "microphone_control_authority": str(payload.get("microphone_control_authority") or "").strip() or None,
            "microphone_control_mode": str(payload.get("microphone_control_mode") or "").strip() or None,
            "microphone_control_requirements": list(payload.get("microphone_control_requirements") or []),
            "local_process_control_available": payload.get("local_process_control_available"),
            "activity_audit_managed_by_source": True,
        },
    )
    return ingest_runtime_event(
        db,
        payload=runtime_payload,
        trusted_pre_action_governance_check=trusted_pre_action_governance_check,
        canonical_control_path=(
            ControlPathEvidence(
                collector_inline_capable=True,
                inline_pre_execution=True,
                execution_prevented=True,
            )
            if source_event_type in {"prompt_blocked", "browser_automation_blocked"}
            and decision in {"block", "deny"}
            else None
        ),
    )


def ingest_from_browser_interaction_eval(
    db: Session,
    *,
    tenant_id: str,
    domain: str | None,
    ai_system_id: str | None,
    result: dict[str, Any],
) -> RuntimeEventRow | None:
    decision = str(result.get("decision") or "").strip().lower() or None
    correlation_id = str(result.get("correlation_id") or "").strip() or None
    context_id = str(result.get("context_id") or "").strip() or correlation_id
    chain_id = str(result.get("chain_id") or "").strip() or context_id
    parent_action_id = str(result.get("parent_action_id") or "").strip() or None
    decision_badge = _browser_decision_badge(str(decision or ""), automation_suspected=False)
    control_mode = _browser_control_mode(str(decision or ""), automation_suspected=False)
    source_surface = _normalize_source_surface(str(result.get("source_surface") or "browser"))
    user_id = str(result.get("user_id") or "").strip() or None
    machine_id = str(result.get("machine_id") or result.get("endpoint_id") or "").strip() or None
    browser_type = str(result.get("browser_type") or result.get("browser") or "").strip() or None
    application = str(result.get("application") or domain or "").strip() or None
    entity_type = "user" if user_id else ("tool" if str(domain or "").strip() else None)
    entity_id = user_id or (str(domain).strip() if domain else None)
    attachment_summary = result.get("attachment_summary") if isinstance(result.get("attachment_summary"), dict) else {}
    projected_attachments = project_browser_attachment_metadata(attachment_summary.get("attachments"))
    if projected_attachments:
        projected_attachments["attachment_count"] = max(
            len(projected_attachments["attachments"]),
            _to_int(attachment_summary.get("attachment_count")) or 0,
        )
    payload = RuntimeEventIngestPayload(
        tenant_id=tenant_id,
        source_surface=source_surface,
        event_type="browser_interaction_eval",
        ai_system_id=ai_system_id,
        app_id=(str(domain).strip() if domain else None),
        user_id=user_id,
        agent_id=None,
        risk_tier=None,
        policy_version_id=_safe_fk_text(result.get("policy_version")),
        governance_version=None,
        severity=SEVERITY_BY_DECISION.get(decision or "", "low"),
        confidence_tier=str(result.get("tier") or "").strip().lower() or None,
        evidence_node_ids=[str(result.get("evidence_node_id") or "").strip()],
        correlation_id=correlation_id,
        context_id=context_id,
        chain_id=chain_id,
        parent_action_id=parent_action_id,
        entity_type=entity_type,
        entity_id=entity_id,
        model_provider=str(result.get("model_provider") or result.get("provider") or "").strip() or None,
        provider=None,
        model_name=None,
        model_version=str(result.get("model_version") or "").strip() or None,
        tool_name=None,
        tool_category=str(result.get("tool_category") or "browser_interaction").strip() or "browser_interaction",
        api_endpoint=None,
        data_source=str(result.get("data_source") or "").strip() or None,
        response_size=_to_int(result.get("response_size")),
        chain_depth=None,
        parent_agent_id=str(result.get("parent_agent_id") or "").strip() or None,
        metadata={
            "decision": decision,
            "operation": str(result.get("operation") or "browser_interaction").strip() or "browser_interaction",
            "action_type": str(result.get("action_type") or "prompt_submitted").strip() or "prompt_submitted",
            **projected_attachments,
            "action_risk": "low",
            "decision_badge": decision_badge,
            "control_mode": control_mode,
            "intent_context": dict(result.get("intent_context") or {})
            if isinstance(result.get("intent_context"), dict)
            else {},
            "input_content_context": dict(result.get("input_content_context") or {})
            if isinstance(result.get("input_content_context"), dict)
            else {},
            "output_context": dict(result.get("output_context") or {})
            if isinstance(result.get("output_context"), dict)
            else {},
            "action_alignment_result": dict(result.get("action_alignment_result") or {})
            if isinstance(result.get("action_alignment_result"), dict)
            else {},
            "intent_aware_decision": dict(result.get("intent_aware_decision") or {})
            if isinstance(result.get("intent_aware_decision"), dict)
            else {},
            "business_purpose_decision": dict(result.get("business_purpose_decision") or {})
            if isinstance(result.get("business_purpose_decision"), dict)
            else {},
            "intent_category": str(result.get("intent_category") or "").strip() or None,
            "intent_confidence": _to_float(result.get("intent_confidence")),
            "business_context": str(result.get("business_context") or "").strip() or None,
            "input_sensitivity": str(result.get("input_sensitivity") or "").strip() or None,
            "output_sensitivity": str(result.get("output_sensitivity") or "").strip() or None,
            "action_alignment": str(result.get("action_alignment") or "").strip() or None,
            "matched_indicators": list(result.get("matched_indicators") or []),
            "copy_export_control_applied": bool(result.get("copy_export_control_applied")),
            "decision_reason": str(result.get("decision_reason") or "").strip() or None,
            "original_intent": str(result.get("prompt_preview_redacted") or "").strip() or None,
            "url": str(result.get("url") or "").strip() or None,
            "page_title": str(result.get("page_title") or "").strip() or None,
            "reason_codes": list(result.get("reason_codes") or []),
            "input_signal_types": list(result.get("input_signal_types") or []),
            "application": application,
            "browser_type": browser_type,
            "browser": str(result.get("browser") or "").strip() or None,
            "machine_id": machine_id,
            "endpoint_id": str(result.get("endpoint_id") or "").strip() or None,
            "user_email": str(result.get("user_email") or "").strip() or None,
            "browser_profile": result.get("browser_profile"),
            "extension_version": result.get("extension_version"),
            "context_id": context_id,
            "chain_id": chain_id,
            "parent_action_id": parent_action_id,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "governance_state": "unknown",
            "tool_category": "browser_interaction",
            "data_source": str(result.get("data_source") or "").strip() or None,
            "response_size": _to_int(result.get("response_size")),
            "parent_agent_id": str(result.get("parent_agent_id") or "").strip() or None,
            "source_surface": source_surface,
            "ai_surface": str(result.get("ai_surface") or source_surface).strip() or source_surface,
            "desktop_guard": dict(result.get("desktop_guard") or {})
            if isinstance(result.get("desktop_guard"), dict)
            else {},
            "activity_audit_managed_by_source": True,
        },
    )
    return ingest_runtime_event(
        db,
        payload=payload,
        canonical_control_path=ControlPathEvidence(
            inline_pre_execution=True,
        ),
    )


def ingest_from_connector_signal(
    db: Session,
    *,
    signal: MonitoringSignal,
    evidence_node_id: str | None = None,
) -> RuntimeEventRow | None:
    meta = dict(signal.payload or {}) if isinstance(signal.payload, dict) else {}
    if not str(meta.get("operation") or "").strip():
        meta["operation"] = "connector_signal"
    if not str(meta.get("original_intent") or "").strip():
        meta["original_intent"] = str(meta.get("intent") or "").strip() or None
    app_id = (
        str(meta.get("ai_tool") or "").strip()
        or str(meta.get("tool") or "").strip()
        or str(meta.get("domain") or "").strip()
        or str(meta.get("provider_key") or "").strip()
        or None
    )

    source_surface = str(meta.get("source_surface") or "connector").strip().lower() or "connector"
    if source_surface not in ALLOWED_SOURCE_SURFACES:
        source_surface = "connector"
    correlation_id = str(meta.get("correlation_id") or "").strip() or None
    context_id = str(meta.get("context_id") or "").strip() or correlation_id or signal.id
    chain_id = str(meta.get("chain_id") or "").strip() or context_id
    parent_action_id = str(meta.get("parent_action_id") or "").strip() or None
    entity_type = _normalize_entity_type(str(meta.get("entity_type") or "").strip().lower() or None)
    entity_id = str(meta.get("entity_id") or "").strip() or None
    if not entity_type or not entity_id:
        if str(meta.get("agent_id") or "").strip():
            entity_type = "agent"
            entity_id = str(meta.get("agent_id") or "").strip()
        elif str(meta.get("user_id") or "").strip():
            entity_type = "user"
            entity_id = str(meta.get("user_id") or "").strip()
        elif str(meta.get("tool_name") or meta.get("ai_tool") or "").strip():
            entity_type = "tool"
            entity_id = str(meta.get("tool_name") or meta.get("ai_tool") or "").strip()
        elif signal.ai_system_id:
            entity_type = "ai_system"
            entity_id = str(signal.ai_system_id).strip()

    payload = RuntimeEventIngestPayload(
        tenant_id=signal.tenant_id,
        source_surface=source_surface,  # connector, endpoint, dns, proxy, monitoring
        event_type=str(signal.signal_type or "connector.signal"),
        ai_system_id=signal.ai_system_id,
        app_id=app_id,
        user_id=str(meta.get("user_id") or "").strip() or None,
        agent_id=str(meta.get("agent_id") or "").strip() or None,
        risk_tier=str(meta.get("risk_tier") or "").strip() or None,
        policy_version_id=_safe_fk_text(meta.get("policy_version")),
        governance_version=str(meta.get("governance_version") or "").strip() or None,
        severity=_normalize_severity(signal.severity) or "low",
        confidence_tier=str(meta.get("confidence_tier") or "").strip().lower() or None,
        evidence_node_ids=_uniq([
            evidence_node_id,
            *[str(node_id) for node_id in (meta.get("evidence_node_ids") or []) if str(node_id).strip()],
        ]),
        correlation_id=correlation_id,
        context_id=context_id,
        chain_id=chain_id,
        parent_action_id=parent_action_id,
        entity_type=entity_type,
        entity_id=entity_id,
        model_provider=str(meta.get("model_provider") or meta.get("provider") or meta.get("provider_key") or "").strip() or None,
        provider=str(meta.get("provider") or meta.get("provider_key") or "").strip() or None,
        model_name=str(meta.get("model_name") or "").strip() or None,
        model_version=str(meta.get("model_version") or "").strip() or None,
        tool_name=str(meta.get("tool_name") or meta.get("ai_tool") or "").strip() or None,
        tool_category=str(meta.get("tool_category") or "").strip() or None,
        api_endpoint=str(meta.get("api_endpoint") or "").strip() or None,
        data_source=str(meta.get("data_source") or "").strip() or None,
        response_size=_to_int(meta.get("response_size") or meta.get("bytes_received") or meta.get("bytes_sent")),
        chain_depth=meta.get("chain_depth"),
        parent_agent_id=str(meta.get("parent_agent_id") or "").strip() or None,
        metadata=meta,
    )
    return ingest_runtime_event(db, payload=payload)


def ingest_from_ai_iam_event(
    db: Session,
    *,
    tenant_id: str,
    event_type: str,
    ai_system_id: str | None,
    user_id: str | None,
    agent_id: str | None,
    severity: str | None,
    evidence_node_ids: list[str] | None,
    correlation_id: str | None,
    risk_score: float | None = None,
    metadata: dict[str, Any] | None = None,
    trusted_pre_action_governance_check: dict[str, Any] | None = None,
) -> RuntimeEventRow | None:
    metadata = dict(metadata or {})
    normalized_event_type = str(event_type or "").strip().lower()
    normalized_tool_category = str(metadata.get("tool_category") or "").strip().lower()
    normalized_action = str(metadata.get("action") or "").strip().lower()
    looks_like_mcp = bool(
        normalized_event_type.startswith("mcp")
        or normalized_tool_category.startswith("mcp")
        or normalized_action.startswith("mcp.")
        or "/gateway/mcp/authorize" in str(metadata.get("api_endpoint") or "").strip().lower()
    )
    if looks_like_mcp:
        decision = str(metadata.get("decision") or "").strip().lower() or "allow"
        metadata["ai_surface"] = "mcp_tool_call"
        metadata["action_type"] = _mcp_action_type_for_decision(decision)
        metadata["operation"] = "mcp_tool_call"
        metadata["identity_type"] = "agent" if str(agent_id or "").strip() else "service"
        if not str(metadata.get("mcp_server_id") or "").strip():
            metadata["mcp_server_id"] = _normalize_mcp_server_id(
                metadata.get("api_endpoint")
                or metadata.get("resource")
                or metadata.get("target_resource")
            )
        if not str(metadata.get("mcp_tool_id") or "").strip():
            metadata["mcp_tool_id"] = str(metadata.get("tool_name") or metadata.get("action") or "").strip() or None
        if not str(metadata.get("ai_client") or "").strip():
            metadata["ai_client"] = str(metadata.get("runtime_provider") or metadata.get("client_name") or "").strip() or None
    if not str(metadata.get("operation") or "").strip():
        metadata["operation"] = "agent_action"
    if not str(metadata.get("original_intent") or "").strip():
        metadata["original_intent"] = str(metadata.get("intent") or "").strip() or None
    context_id = str(metadata.get("context_id") or "").strip() or correlation_id
    chain_id = str(metadata.get("chain_id") or "").strip() or context_id
    parent_action_id = str(metadata.get("parent_action_id") or "").strip() or None
    entity_type = _normalize_entity_type(str(metadata.get("entity_type") or "").strip().lower() or None)
    entity_id = str(metadata.get("entity_id") or "").strip() or None
    if not entity_type or not entity_id:
        if str(agent_id or "").strip():
            entity_type = "agent"
            entity_id = str(agent_id).strip()
        elif str(user_id or "").strip():
            entity_type = "user"
            entity_id = str(user_id).strip()
        elif ai_system_id:
            entity_type = "ai_system"
            entity_id = str(ai_system_id).strip()

    payload = RuntimeEventIngestPayload(
        tenant_id=tenant_id,
        source_surface="aiiam",
        event_type=event_type,
        ai_system_id=ai_system_id,
        app_id="ai_iam",
        user_id=user_id,
        agent_id=agent_id,
        risk_tier=None,
        policy_version_id=None,
        governance_version=None,
        severity=_normalize_severity(severity) or "med",
        confidence_tier=None,
        evidence_node_ids=_uniq(list(evidence_node_ids or [])),
        correlation_id=correlation_id,
        context_id=context_id,
        chain_id=chain_id,
        parent_action_id=parent_action_id,
        entity_type=entity_type,
        entity_id=entity_id,
        risk_score=risk_score,
        model_provider=str(metadata.get("model_provider") or "").strip() or None,
        provider=None,
        model_name=str(metadata.get("model_name") or "").strip() or None,
        model_version=str(metadata.get("model_version") or "").strip() or None,
        tool_name=str(metadata.get("action") or "").strip() or None,
        tool_category=str(metadata.get("tool_category") or "agent_action").strip() or None,
        api_endpoint=str(metadata.get("api_endpoint") or "").strip() or None,
        data_source=str(metadata.get("data_source") or "").strip() or None,
        response_size=_to_int(metadata.get("response_size")),
        chain_depth=metadata.get("chain_depth"),
        parent_agent_id=str(metadata.get("parent_agent_id") or "").strip() or None,
        metadata=metadata,
    )
    return ingest_runtime_event(
        db,
        payload=payload,
        trusted_pre_action_governance_check=trusted_pre_action_governance_check,
    )
