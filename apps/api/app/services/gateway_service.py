from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse
from uuid import NAMESPACE_URL, uuid4, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.control_engine import AIAction, evaluate_control_engine, map_generic_decision
from app.core.control_engine.canonical_action import CanonicalProjectionError
from app.core.config import settings
from app.core.observability import get_correlation_id, log_structured
from app.db.models.activity_audit import AISession
from app.db.models.ai_system import AISystem
from app.db.models.enforcement import EnforcementEvent
from app.db.models.monitoring import MonitoringSignal
from app.db.models.policy import ApprovalRequest
from app.services.ai_iam_service import (
    action_category_for,
    action_risk_for,
    authority_host_matches,
    authority_value_matches,
    auto_quarantine_agent_identity,
    build_decision_explanation,
    build_pre_action_governance_check,
    control_mode_for_pre_action_decision,
    decision_badge_for_control_mode,
    evaluate_need_to_know_policy,
    evaluate_purpose_bound_permission,
    narrow_authority_values,
    purpose_confirmation_required,
    resolve_persisted_purpose_bound_permission,
    track_behavior_anomaly,
    validate_capability_token,
)
from app.services.agentic_action_integrity_service import evaluate_mcp_tool_call_integrity
from app.services.instruction_tool_provenance import InstructionToolProvenanceService
from app.services.audit_service import write_audit_log
from app.services.delegation_chain_authority_service import (
    DelegationChainDepthResult,
    resolve_persisted_delegation_chain_depth,
)
from app.services.evidence_service import create_evidence_node, link_evidence_nodes
from app.services.findings_service import (
    generate_from_asymmetry_signal,
    generate_from_enforcement_event,
)
from app.services.enforcement_routing_service import route_enforcement
from app.services.enforcement_payload_crypto_service import encrypt_enforcement_prompt
from app.services.guardian_contract_service import load_policy_guardian_contracts
from app.services.guardian_policy_engine import canonical_guardian_policy, evaluate_guardian_policies
from app.services.guardians.confidence_tiering import (
    CONFIDENCE_TIER_AMBIGUOUS,
    CONFIDENCE_TIER_CLEAR_NEGATIVE,
    classify_confidence_tier,
    detect_asymmetry_signal,
    run_ambiguous_arbiter,
)
from app.services.guardians.threat_detectors import evaluate_threat_detectors
from app.services.detection.profile import with_tenant_profile
from app.services.guardians.threat_registry import (
    get_threat_registry,
    guardian_contract_to_threat_types,
)
from app.services.guardians.v2_evaluator import evaluate_v2_guardians, load_applicable_v2_bindings
from app.services.governance_guard import GOVERNANCE_VERSION, enforce as enforce_governance
from app.services.governance_resolution import resolve_ai_system_status
from app.services.github_repository_access_service import evaluate_github_repository_mutation
from app.services.maturity_service import recalculate_control_maturity
from app.services.mcp_session_service import validate_persisted_mcp_session
from app.services.platform_mode_service import (
    PLATFORM_MODE_DISCOVERY,
    get_tenant_platform_mode,
    is_explicitly_critical,
)
from app.services.policy_scope_service import resolve_scoped_policy_decision
from app.services.policy_service import get_latest_policy_for_ai_system
from app.services.privacy_sanitizer import (
    redact_sensitive_text,
    sanitize_privacy_payload,
    strip_url_query,
)
from app.services.sensitive_data_detection_service import (
    classify_data,
    detect_sensitive_data,
    detection_signal_types,
)
from app.services.workflow_policy_service import (
    evaluate_workflow_policy,
    load_workflow_policy,
)


AGGREGATION_PRECEDENCE = [
    "block",
    "hold_for_approval",
    "redact",
    "warn",
    "allow",
]

RISK_TIER_STRICTNESS = {
    "MINIMAL": 0,
    "LIMITED": 1,
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "RESTRICTED": 2,
    "CRITICAL": 2,
    "PROHIBITED": 2,
}
INTERNAL_ENDPOINT_HINTS = {"localhost", "127.0.0.1", "0.0.0.0", "internal", "intranet", "corp", "acme.ai"}  # nosec B104 - names to recognise, not a bind address

PROVIDER_ALIASES = {
    "openai": "openai",
    "anthropic": "anthropic",
    "claude": "anthropic",
    "gemini": "gemini",
    "mistral": "mistral",
    "ollama": "oss_local",
    "oss": "oss_local",
    "local": "oss_local",
    "local_model": "oss_local",
    "llama_cpp": "oss_local",
    "llama.cpp": "oss_local",
    "custom": "custom",
    "azure_openai": "azure_openai",
    "azure-openai": "azure_openai",
}

def _get_value(payload: dict[str, Any], field: str) -> Any:
    parts = field.split(".")
    current: Any = payload
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _hash_text(value: str | None) -> str:
    text = value or ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _bounded_enforcement_event_request_id(*, tenant_id: str, request_id: str) -> str:
    """Keep externally supplied correlation IDs out of the legacy 36-character event key.

    Endpoint brokers use a namespaced request identifier that is deliberately
    longer than a UUID.  It remains the source correlation ID in evidence and
    audit records, while this deterministic UUID is used only by the legacy,
    unique ``EnforcementEvent.request_id`` column.
    """

    source_request_id = str(request_id).strip()
    if len(source_request_id) <= 36:
        return source_request_id
    return str(
        uuid5(
            NAMESPACE_URL,
            f"hawk.enforcement-event.mcp:{tenant_id}:{source_request_id}",
        )
    )


def _normalize_provider(value: str | None) -> str | None:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return None
    return PROVIDER_ALIASES.get(normalized, normalized)


def _provider_classification(provider: str | None, model_name: str | None) -> tuple[str, bool]:
    normalized_provider = _normalize_provider(provider) or ""
    normalized_model = str(model_name or "").strip().lower()
    model_tokens = (
        "mistral",
        "mixtral",
        "llama",
        "qwen",
        "deepseek",
        "phi-",
        "phi3",
        "phi4",
        "gemma",
        "rwkv",
    )
    is_open_source = normalized_provider in {"mistral", "oss_local"} or any(token in normalized_model for token in model_tokens)
    if is_open_source:
        return "open_source", True
    if normalized_provider == "custom":
        return "custom", False
    return "managed", False


def _normalized_optional(value: str | None) -> str | None:
    text = str(value or "").strip()
    return text or None


def _normalized_string_list(values: Any) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        tokens = [token.strip() for token in re.split(r"[,\s]+", values) if token.strip()]
        return sorted(set(tokens))
    if isinstance(values, (list, tuple, set)):
        out = {str(item).strip() for item in values if str(item).strip()}
        return sorted(out)
    return []


def _extract_tool_usage_field(tool_usage_meta: dict[str, Any] | list[dict[str, Any]] | None, field: str) -> Any:
    if isinstance(tool_usage_meta, dict):
        return tool_usage_meta.get(field)
    if isinstance(tool_usage_meta, list):
        for item in tool_usage_meta:
            if isinstance(item, dict) and item.get(field) is not None:
                return item.get(field)
    return None


def _normalized_lower_set(values: list[str] | None) -> set[str]:
    return {str(item).strip().lower() for item in (values or []) if str(item).strip()}


def _intersect_authority_lists(*sources: list[str]) -> list[str]:
    effective: list[str] | None = None
    for source in sources:
        values = [str(item).strip().lower() for item in source if str(item).strip()]
        if not values:
            continue
        if effective is None:
            effective = list(dict.fromkeys(values))
            continue
        effective = narrow_authority_values(effective, values)
    return effective or []


def _authority_allows(value: str | None, allowed: list[str], *, domain: bool = False) -> bool:
    if not allowed:
        return True
    if domain:
        return authority_host_matches(value, allowed)
    return authority_value_matches(value, allowed)


def _to_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_optional_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return _to_utc(value)
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    return _to_utc(parsed)


def _extract_host_hint(*, resource: str | None, api_endpoint: str | None) -> str | None:
    candidates = [str(api_endpoint or "").strip(), str(resource or "").strip()]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            if "://" in candidate:
                parsed = urlparse(candidate)
                host = str(parsed.hostname or "").strip().lower()
                if host:
                    return host
            normalized = candidate.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].split(":", 1)[0].strip().lower()
            if normalized:
                return normalized
        except Exception:
            continue
    return None


def _risk_level_for_score(score: float) -> str:
    normalized = max(0.0, min(1.0, float(score)))
    if normalized >= 0.85:
        return "critical"
    if normalized >= 0.65:
        return "high"
    if normalized >= 0.4:
        return "medium"
    return "low"


def _classify_trace_data(
    *,
    prompt: str | None,
    response_text: str | None,
    context_summary: str | None = None,
    attachments_meta: list[dict[str, Any]] | None = None,
) -> tuple[str, dict[str, Any]]:
    detection = detect_sensitive_data(
        text_inputs=[
            str(prompt or ""),
            str(response_text or ""),
            str(context_summary or ""),
        ],
        file_meta=[item for item in (attachments_meta or []) if isinstance(item, dict)],
        source="api",
        destination="external_api",
    )
    detected = classify_data(
        detection_result=detection,
        classification_hint=None,
        allow_unknown=True,
    )
    if detected == "protected":
        return "sensitive", detection
    if detected in {"internal", "public"}:
        return detected, detection
    return "unknown", detection


def _normalize_tool_usage_meta(
    value: dict[str, Any] | list[dict[str, Any]] | None,
) -> dict[str, Any] | list[dict[str, Any]] | None:
    if isinstance(value, dict):
        return {str(k): v for k, v in value.items() if str(k).strip()}
    if isinstance(value, list):
        out: list[dict[str, Any]] = []
        for item in value:
            if isinstance(item, dict):
                row = {str(k): v for k, v in item.items() if str(k).strip()}
                if row:
                    out.append(row)
        return out or None
    return None


def _mcp_persistence_view(
    value: Any,
    *,
    resource: str,
    api_endpoint: str | None,
    parameters: dict[str, Any] | list[Any] | None,
    tool_usage_meta: dict[str, Any] | list[dict[str, Any]] | None,
) -> Any:
    resource_text = str(resource or "").strip()
    resource_ref = f"sha256:{_hash_text(resource_text)}" if resource_text else None
    endpoint_text = str(api_endpoint or "").strip()
    safe_endpoint = strip_url_query(endpoint_text) if endpoint_text else None
    parameter_hash = (
        _hash_text(
            json.dumps(
                parameters,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
        )
        if parameters is not None
        else None
    )
    parameter_keys = (
        sorted(str(key)[:128] for key in parameters)[:128]
        if isinstance(parameters, dict)
        else []
    )
    parameter_values = _bounded_mcp_parameter_strings(parameters)
    tool_summary = {
        "mcp_server_id": _normalized_optional(
            _extract_tool_usage_field(tool_usage_meta, "mcp_server_id")
        ),
        "tool_version": _normalized_optional(
            _extract_tool_usage_field(tool_usage_meta, "tool_version")
        ),
        "tool_fingerprint_id": _normalized_optional(
            _extract_tool_usage_field(tool_usage_meta, "tool_fingerprint_id")
        ),
        "parameter_keys": parameter_keys,
        "parameter_hash": parameter_hash,
        "parameter_count": (
            len(parameters)
            if isinstance(parameters, (dict, list))
            else 0
        ),
        "target_resource_ref": resource_ref,
        "data_destination": strip_url_query(
            _extract_tool_usage_field(tool_usage_meta, "data_destination")
            or safe_endpoint
            or ""
        )
        or None,
    }

    def visit(item: Any, *, key: str = "", depth: int = 0) -> Any:
        if depth > 8:
            return "[omitted:max_depth]"
        normalized_key = str(key or "").strip().lower().replace("-", "_")
        if normalized_key == "tool_usage_meta":
            return tool_summary
        if normalized_key in {"parameters", "arguments", "args"}:
            return {
                "parameter_keys": parameter_keys,
                "parameter_hash": parameter_hash,
                "parameter_count": tool_summary["parameter_count"],
            }
        if isinstance(item, dict):
            return {
                str(item_key)[:128]: visit(
                    item_value,
                    key=str(item_key),
                    depth=depth + 1,
                )
                for item_key, item_value in list(item.items())[:256]
            }
        if isinstance(item, (list, tuple, set)):
            return [
                visit(item_value, key=key, depth=depth + 1)
                for item_value in list(item)[:256]
            ]
        if item is None or isinstance(item, (bool, int, float)):
            return item
        text = str(item)
        if (
            normalized_key == "id"
            or normalized_key.endswith("_id")
            or normalized_key.endswith("_ids")
            or normalized_key.endswith("_hash")
        ):
            return f"{text[:1024]}...[truncated]" if len(text) > 1024 else text
        if normalized_key in {"resource", "target_resource"}:
            return resource_ref
        if normalized_key in {
            "api_endpoint",
            "data_destination",
            "url",
            "current_url",
            "target_url",
        }:
            return strip_url_query(text)
        if resource_text:
            text = text.replace(resource_text, resource_ref or "[hashed_only]")
        if endpoint_text:
            text = text.replace(endpoint_text, safe_endpoint or "[redacted]")
        for parameter_value in parameter_values:
            text = text.replace(parameter_value, "[redacted:parameter]")
        if text.startswith(("http://", "https://")):
            text = strip_url_query(text)
        return redact_sensitive_text(text, max_len=512)

    return sanitize_privacy_payload(visit(value))


def _bounded_mcp_parameter_strings(
    parameters: dict[str, Any] | list[Any] | None,
) -> list[str]:
    found: list[str] = []

    def collect(value: Any, *, depth: int = 0) -> None:
        if depth > 6 or len(found) >= 128:
            return
        if isinstance(value, dict):
            for nested in list(value.values())[:128]:
                collect(nested, depth=depth + 1)
            return
        if isinstance(value, list):
            for nested in value[:128]:
                collect(nested, depth=depth + 1)
            return
        if isinstance(value, str) and len(value) >= 8:
            found.append(value[:1024])

    collect(parameters)
    return sorted(set(found), key=len, reverse=True)


def _decision_to_monitoring_severity(decision: str) -> str:
    normalized = str(decision or "").strip().lower()
    if normalized in {"block", "hold_for_approval"}:
        return "high"
    if normalized in {"warn", "redact"}:
        return "med"
    return "low"


def _build_gateway_trace_payload(
    *,
    correlation_id: str | None,
    request_id: str,
    policy_version_id: str | None,
    provider: str | None,
    model_name: str | None,
    model_version: str | None,
    prompt: str | None,
    response_text: str | None,
    context_summary: str | None,
    tool_name: str | None,
    tool_category: str | None,
    api_endpoint: str | None,
    data_source: str | None,
    tool_usage_meta: dict[str, Any] | list[dict[str, Any]] | None,
    attachments_meta: list[dict[str, Any]] | None = None,
    context_id: str | None = None,
    chain_id: str | None = None,
    chain_depth: int | None = None,
    parent_action_id: str | None = None,
    parent_agent_id: str | None = None,
    session_id: str | None = None,
    initiating_user_id: str | None = None,
    session_expiry: str | None = None,
    session_validation: dict[str, Any] | None = None,
    dynamic_permission: dict[str, Any] | None = None,
    anomaly_score: float | None = None,
) -> dict[str, Any]:
    provider_class, open_source_hint = _provider_classification(provider, model_name)
    data_classification, detection_result = _classify_trace_data(
        prompt=prompt,
        response_text=response_text,
        context_summary=context_summary,
        attachments_meta=attachments_meta,
    )
    return {
        "correlation_id": correlation_id,
        "request_id": request_id,
        "governance_version": GOVERNANCE_VERSION,
        "policy_version_id": policy_version_id,
        "provider": _normalize_provider(provider),
        "model": _normalized_optional(model_name),
        "model_version": _normalized_optional(model_version),
        "provider_class": provider_class,
        "open_source_model_hint": open_source_hint,
        "deployment_model_hint": ("local_or_oss" if open_source_hint else ("custom_api" if provider_class == "custom" else "managed_api")),
        "prompt_hash": _hash_text(prompt),
        "response_hash": (_hash_text(response_text) if response_text is not None else None),
        "tool_name": _normalized_optional(tool_name),
        "tool_category": _normalized_optional(tool_category),
        "api_endpoint": _normalized_optional(api_endpoint),
        "data_source": _normalized_optional(data_source),
        "data_classification": data_classification,
        "contains_sensitive": bool(detection_result.get("contains_sensitive")),
        "sensitive_confidence_score": float(detection_result.get("confidence_score") or 0.0),
        "sensitive_entities": list(detection_result.get("entities") or []),
        "sensitive_detection": detection_result,
        "sensitive_signal_types": detection_signal_types(detection_result),
        "tool_usage_meta": _normalize_tool_usage_meta(tool_usage_meta),
        "context_id": _normalized_optional(context_id),
        "chain_id": _normalized_optional(chain_id),
        "chain_depth": chain_depth,
        "parent_action_id": _normalized_optional(parent_action_id),
        "parent_agent_id": _normalized_optional(parent_agent_id),
        "session_id": _normalized_optional(session_id),
        "initiating_user_id": _normalized_optional(initiating_user_id),
        "session_expiry": _normalized_optional(session_expiry),
        "session_validation": dict(session_validation or {}),
        "dynamic_permission": dict(dynamic_permission or {}),
        "anomaly_score": (float(anomaly_score) if anomaly_score is not None else None),
    }


def _extract_need_to_know_identity(attachments_meta: list[dict[str, Any]] | None) -> dict[str, Any]:
    for item in attachments_meta or []:
        if not isinstance(item, dict):
            continue
        marker = str(item.get("type") or item.get("kind") or "").strip().lower()
        if marker in {"identity_context", "actor_identity", "ai_identity"}:
            return dict(item)
    return {}


def _extract_knowledge_assets(attachments_meta: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    for item in attachments_meta or []:
        if not isinstance(item, dict):
            continue
        marker = str(item.get("type") or item.get("kind") or "").strip().lower()
        if marker in {"knowledge_asset", "knowledge_source", "rag_source", "data_source"}:
            assets.append(dict(item))
    return assets


def _extract_need_to_know_policies(policy) -> list[dict[str, Any]]:
    if policy is None:
        return []
    defaults = dict(policy.enforcement_defaults or {}) if isinstance(policy.enforcement_defaults, dict) else {}
    candidates = defaults.get("need_to_know_policies") or defaults.get("need_to_know_policy") or []
    if isinstance(candidates, dict):
        return [dict(candidates)]
    if isinstance(candidates, list):
        return [dict(item) for item in candidates if isinstance(item, dict)]
    return []


def _need_to_know_gateway_decision(decision: str) -> str:
    normalized = str(decision or "allow").strip().lower()
    if normalized == "step_up":
        return "hold_for_approval"
    if normalized in {"allow", "redact", "block", "warn", "hold_for_approval"}:
        return normalized
    return "block"


def _evaluate_need_to_know_gateway(
    *,
    policy,
    actor_type: str,
    actor_id: str,
    context_summary: str,
    attachments_meta: list[dict[str, Any]],
    trace_payload: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None, list[dict[str, Any]]]:
    assets = _extract_knowledge_assets(attachments_meta)
    policies = _extract_need_to_know_policies(policy)
    if not assets or not policies:
        return {}, None, []

    identity = _extract_need_to_know_identity(attachments_meta)
    identity.setdefault("identity_type", "agent" if str(actor_type or "").strip().lower() == "agent" else "user")
    identity.setdefault("user_id", actor_id if str(actor_type or "").strip().lower() == "human" else None)
    identity.setdefault("agent_id", actor_id if str(actor_type or "").strip().lower() == "agent" else None)
    prompt_intent = str(context_summary or "").strip().lower() or None
    business_context = str(identity.get("business_context") or identity.get("context") or context_summary or "").strip() or None

    decisions: list[dict[str, Any]] = []
    for asset in assets:
        for need_policy in policies:
            decision = evaluate_need_to_know_policy(
                policy=need_policy,
                identity=identity,
                knowledge_asset=asset,
                prompt_intent=prompt_intent,
                business_context=business_context,
            )
            if decision.get("reason") == "need_to_know_policy_not_applicable":
                continue
            decisions.append(decision)

    if not decisions:
        return {}, None, assets

    gateway_decision = _aggregate_guardian_decisions([_need_to_know_gateway_decision(str(item.get("decision"))) for item in decisions])
    selected = next(
        (item for item in decisions if _need_to_know_gateway_decision(str(item.get("decision"))) == gateway_decision),
        decisions[0],
    )
    knowledge_asset_ids = sorted(
        {
            str(asset.get("asset_id") or asset.get("id") or "").strip()
            for asset in assets
            if str(asset.get("asset_id") or asset.get("id") or "").strip()
        }
    )
    sensitivity_domains = sorted(
        {
            str(asset.get("sensitivity_domain") or asset.get("domain") or "").strip().lower()
            for asset in assets
            if str(asset.get("sensitivity_domain") or asset.get("domain") or "").strip()
        }
    )
    disclosure_event = {
        "event_id": str(trace_payload.get("request_id") or ""),
        "user_id": identity.get("user_id"),
        "agent_id": identity.get("agent_id"),
        "ai_system_id": trace_payload.get("ai_system_id"),
        "prompt_intent": prompt_intent,
        "knowledge_asset_ids": knowledge_asset_ids,
        "sensitivity_domain": str(selected.get("sensitivity_domain") or (sensitivity_domains[0] if sensitivity_domains else "")).strip() or None,
        "decision": selected.get("decision"),
        "policy_id": selected.get("policy_id"),
        "evidence_refs": list(selected.get("evidence_refs") or []),
    }
    trace_payload["knowledge_asset_ids"] = knowledge_asset_ids
    trace_payload["sensitivity_domain"] = disclosure_event["sensitivity_domain"]
    trace_payload["need_to_know_decision"] = selected
    trace_payload["knowledge_disclosure_event"] = disclosure_event
    trace_payload["knowledge_assets"] = [
        {
            "asset_id": asset.get("asset_id") or asset.get("id"),
            "source_type": asset.get("source_type"),
            "owner": asset.get("owner"),
            "sensitivity_label": asset.get("sensitivity_label"),
            "allowed_groups": list(asset.get("allowed_groups") or []),
            "connected_ai_systems": list(asset.get("connected_ai_systems") or []),
            "exposure_score": asset.get("exposure_score"),
        }
        for asset in assets
    ]
    guardian = {
        "guardian_contract_id": str(selected.get("policy_id") or "need_to_know_policy"),
        "guardian_id": "need_to_know_guard",
        "decision": gateway_decision,
        "confidence": 1.0,
        "confidence_tier": "clear_positive",
        "arbiter_invoked": False,
        "matched_conditions": list(selected.get("reason", "").split(",")) if selected.get("reason") else [],
        "threat_types": ["knowledge_exposure_risk"] if gateway_decision != "allow" else [],
        "actions_taken": {
            "reason_code": str(selected.get("reason") or ""),
            "need_to_know_decision": selected,
            "knowledge_asset_ids": knowledge_asset_ids,
            "sensitivity_domain": disclosure_event["sensitivity_domain"],
        },
    }
    return selected, guardian, assets


def _apply_provider_enforcement_overlay(
    *,
    platform_mode: str,
    decision: str,
    trace_payload: dict[str, Any],
) -> tuple[str, dict[str, Any] | None]:
    normalized_decision = str(decision or "allow").strip().lower() or "allow"
    provider_class = str(trace_payload.get("provider_class") or "managed").strip().lower()
    open_source_hint = bool(trace_payload.get("open_source_model_hint"))
    mode = str(platform_mode or "enforce").strip().lower()

    if provider_class == "managed" and not open_source_hint:
        return normalized_decision, None
    if normalized_decision == "block":
        return normalized_decision, None

    if mode == PLATFORM_MODE_DISCOVERY:
        target_decision = "warn" if normalized_decision == "allow" else normalized_decision
    else:
        if open_source_hint:
            target_decision = "hold_for_approval" if normalized_decision in {"allow", "warn", "redact"} else normalized_decision
        else:
            target_decision = "warn" if normalized_decision == "allow" else normalized_decision

    if target_decision == normalized_decision:
        return normalized_decision, None

    reason_code = (
        "open_source_model_requires_approval"
        if open_source_hint and target_decision == "hold_for_approval"
        else "custom_provider_requires_review"
    )
    return target_decision, {
        "reason_code": reason_code,
        "from_decision": normalized_decision,
        "to_decision": target_decision,
        "provider": trace_payload.get("provider"),
        "model_name": trace_payload.get("model"),
        "provider_class": provider_class,
        "open_source_model_hint": open_source_hint,
    }


def _sensitive_destination_context(trace_payload: dict[str, Any]) -> tuple[str, str]:
    endpoint = str(trace_payload.get("api_endpoint") or "").strip().lower()
    if not endpoint:
        return "external_api", "unknown"

    host = endpoint
    if "://" in endpoint:
        host = endpoint.split("://", 1)[1]
    host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    host = host.split(":", 1)[0].strip(".")
    if host.startswith("www."):
        host = host[4:]

    for hint in INTERNAL_ENDPOINT_HINTS:
        if host == hint or host.endswith(f".{hint}"):
            return "internal_system", "trusted"
    return "external_api", "untrusted"


def _map_guardian_to_gateway_decision(decision: str) -> str:
    normalized = str(decision or "allow").strip().lower() or "allow"
    if normalized in {"require_approval", "require_justification"}:
        return "hold_for_approval"
    if normalized in {"allow", "warn", "block", "redact", "hold_for_approval"}:
        return normalized
    return "allow"


def _map_workflow_to_gateway_decision(decision: str) -> str:
    normalized = str(decision or "allow").strip().lower() or "allow"
    if normalized == "hold":
        return "hold_for_approval"
    if normalized in {"allow", "warn", "block"}:
        return normalized
    return "allow"


def _map_control_engine_gateway_decision(decision: str, *, fallback: str = "allow") -> str:
    return map_generic_decision(
        decision,
        mapping={
            "allow": "allow",
            "alert": "warn",
            "modify": "redact",
            "step_up": "hold_for_approval",
            "block": "block",
        },
        default=fallback,
    )


def _map_scoped_gateway_decision(decision: str | None, *, fallback: str = "allow") -> str:
    return map_generic_decision(
        decision or "",
        mapping={
            "allow": "allow",
            "warn": "warn",
            "alert": "warn",
            "modify": "redact",
            "redact": "redact",
            "require_justification": "hold_for_approval",
            "require_approval": "hold_for_approval",
            "hold_for_approval": "hold_for_approval",
            "step_up": "hold_for_approval",
            "step-up": "hold_for_approval",
            "block": "block",
            "deny": "block",
        },
        default=fallback,
    )


def _augment_control_impacts(
    control_impacts: list[dict[str, Any]],
    *,
    triggered_controls: list[str],
) -> list[dict[str, Any]]:
    existing = {str(item.get("control_id") or "").strip() for item in control_impacts if str(item.get("control_id") or "").strip()}
    out = list(control_impacts)
    for control_id in triggered_controls:
        token = str(control_id or "").strip()
        if not token or token in existing:
            continue
        out.append({"control_id": token, "delta": -0.12})
        existing.add(token)
    return out


def _apply_sensitive_policy_overlay(
    *,
    platform_mode: str,
    decision: str,
    trace_payload: dict[str, Any],
) -> tuple[str, dict[str, Any] | None]:
    if not bool(trace_payload.get("contains_sensitive")):
        return decision, None

    destination_type, trust_level = _sensitive_destination_context(trace_payload)
    policies = [
        canonical_guardian_policy(
            policy_id="guardian.gateway.sensitive_external_block",
            policy_name="Sensitive Data To External AI",
            policy_version="1.0.0",
            tenant_id="*",
            scope={"ai_system_ids": ["*"], "agent_ids": ["*"], "user_groups": ["*"], "environments": ["prod", "staging", "dev"]},
            conditions={
                "source": {"type": "api", "classification": "sensitive"},
                "destination": {"type": "external_api", "trust_level": "untrusted"},
                "action": {"type": "prompt"},
                "data": {"contains_sensitive": True},
            },
            decision={"mode": "block", "confidence_threshold": 0.8, "strictness": "high"},
            framework_mapping={
                "nist_ai_rmf": ["GV.RM", "MP.AI"],
                "iso_42001": ["A.8", "A.12"],
                "eu_ai_act": ["risk_management", "data_governance"],
                "owasp_genai": ["LLM01", "LLM06"],
                "mitre_atlas": ["AML.TA0001"],
                "control_ids": ["CTRL-DLP-001", "CTRL-INPUT-001"],
            },
            metadata={"active": True, "finding_type": "sensitive_data_external_transfer_attempt"},
        ),
        canonical_guardian_policy(
            policy_id="guardian.gateway.sensitive_internal_warn",
            policy_name="Sensitive Data To Internal AI",
            policy_version="1.0.0",
            tenant_id="*",
            scope={"ai_system_ids": ["*"], "agent_ids": ["*"], "user_groups": ["*"], "environments": ["prod", "staging", "dev"]},
            conditions={
                "source": {"type": "api", "classification": "sensitive"},
                "destination": {"type": "internal_system", "trust_level": "trusted"},
                "action": {"type": "prompt"},
                "data": {"contains_sensitive": True},
            },
            decision={"mode": "warn", "confidence_threshold": 0.7, "strictness": "medium"},
            framework_mapping={
                "nist_ai_rmf": ["GV.RM", "ME.AI"],
                "iso_42001": ["A.5", "A.8"],
                "eu_ai_act": ["risk_management", "human_oversight"],
                "owasp_genai": ["LLM06"],
                "mitre_atlas": ["AML.TA0004"],
                "control_ids": ["CTRL-DLP-001"],
            },
            metadata={"active": True, "finding_type": "sensitive_data_internal_ai_transfer"},
        ),
    ]
    policy_decision = evaluate_guardian_policies(
        policies=policies,
        context={
            "source_type": "api",
            "source_classification": "sensitive",
            "destination_type": destination_type,
            "destination_trust_level": trust_level,
            "action_type": "prompt",
            "contains_sensitive": True,
            "text": str(trace_payload.get("extracted_text_preview_redacted") or ""),
            "environment": "prod",
        },
        default_decision="allow",
    )

    overlay_decision = _map_guardian_to_gateway_decision(policy_decision.decision)
    if platform_mode == PLATFORM_MODE_DISCOVERY and overlay_decision == "block":
        overlay_decision = "warn"

    if _aggregate_guardian_decisions([decision, overlay_decision]) == decision:
        return decision, None
    return overlay_decision, {
        "reason_code": policy_decision.reason_code,
        "policy_id": str((policy_decision.policy or {}).get("policy_id") or "guardian.gateway.sensitive"),
        "from_decision": decision,
        "to_decision": overlay_decision,
        "destination_type": destination_type,
        "trust_level": trust_level,
        "contains_sensitive": True,
        "sensitive_confidence_score": float(trace_payload.get("sensitive_confidence_score") or 0.0),
        "sensitive_entities": list(trace_payload.get("sensitive_entities") or []),
    }


def _emit_gateway_monitoring_signal(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    event_id: str,
    request_id: str,
    correlation_id: str | None,
    final_decision: str,
    policy_version_id: str | None,
    evidence_node_ids: list[str],
    trace_payload: dict[str, Any],
) -> None:
    payload = {
        "event_id": event_id,
        "request_id": request_id,
        "correlation_id": correlation_id,
        "decision": final_decision,
        "policy_version_id": policy_version_id,
        "evidence_node_ids": [str(node_id) for node_id in (evidence_node_ids or []) if str(node_id).strip()],
        "provider": trace_payload.get("provider"),
        "model_name": trace_payload.get("model"),
        "model_version": trace_payload.get("model_version"),
        "prompt_hash": trace_payload.get("prompt_hash"),
        "response_hash": trace_payload.get("response_hash"),
        "tool_name": trace_payload.get("tool_name"),
        "tool_category": trace_payload.get("tool_category"),
        "api_endpoint": trace_payload.get("api_endpoint"),
        "data_source": trace_payload.get("data_source"),
        "data_classification": trace_payload.get("data_classification"),
        "contains_sensitive": trace_payload.get("contains_sensitive"),
        "sensitive_confidence_score": trace_payload.get("sensitive_confidence_score"),
        "sensitive_entities": trace_payload.get("sensitive_entities"),
        "chain_depth": trace_payload.get("chain_depth"),
        "workflow_policy_id": trace_payload.get("workflow_policy_id"),
        "violation_reason": trace_payload.get("violation_reason"),
        "governance_version": trace_payload.get("governance_version"),
    }
    db.add(
        MonitoringSignal(
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            signal_type="gateway.enforcement.event",
            severity=_decision_to_monitoring_severity(final_decision),
            payload=payload,
        )
    )


def _match_condition(payload: dict[str, Any], condition: dict[str, Any]) -> bool:
    field = condition.get("field", "")
    operator = condition.get("operator")
    expected = condition.get("value")
    case_sensitive = bool(condition.get("case_sensitive", False))

    actual = _get_value(payload, field)

    if operator == "contains":
        actual_s = _as_text(actual)
        expected_s = _as_text(expected)
        if not case_sensitive:
            actual_s = actual_s.lower()
            expected_s = expected_s.lower()
        return expected_s in actual_s

    if operator == "regex":
        actual_s = _as_text(actual)
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            return re.search(str(expected), actual_s, flags=flags) is not None
        except re.error:
            return False

    if operator == "in":
        if isinstance(expected, list):
            return actual in expected
        return False

    if operator == "gt":
        try:
            return float(actual) > float(expected)
        except (TypeError, ValueError):
            return False

    if operator == "lt":
        try:
            return float(actual) < float(expected)
        except (TypeError, ValueError):
            return False

    if operator == "equals":
        return actual == expected

    if operator == "not_equals":
        return actual != expected

    return False


def _normalize_conditions(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        conditions = value.get("conditions")
        if isinstance(conditions, list):
            return [item for item in conditions if isinstance(item, dict)]
    return []


def risk_tier_strictness_level(risk_tier: str) -> int:
    return RISK_TIER_STRICTNESS.get(str(risk_tier).upper(), 0)


def _aggregate_guardian_decisions(decisions: list[str]) -> str:
    observed = set(decisions)
    for decision in AGGREGATION_PRECEDENCE:
        if decision in observed:
            return decision
    return "allow"


def _apply_threat_detectors(
    *,
    final_decision: str,
    guardian_results: list[dict[str, Any]],
    final_actions: dict[str, Any],
    prompt: Any = None,
    context_summary: Any = None,
    tool_output: Any = None,
    response_text: Any = None,
    rag_context: Any = None,
    surface: str = "llm",
) -> str:
    """Additively fold OWASP/ATLAS threat-detector findings into the decision.

    Runs alongside the existing guardians. A clean payload returns ``[]`` and so
    never changes an existing decision; a detected threat escalates via the same
    ``_aggregate_guardian_decisions`` precedence used everywhere else.
    """
    try:
        detector_guardians = evaluate_threat_detectors(
            prompt=prompt,
            context_summary=context_summary,
            tool_output=tool_output,
            response_text=response_text,
            rag_context=rag_context if rag_context is not None else context_summary,
            surface=surface,
        )
    except Exception:  # noqa: BLE001 - detectors must never break the gateway
        return final_decision

    for detector_guardian in detector_guardians:
        final_decision = _aggregate_guardian_decisions(
            [final_decision, str(detector_guardian.get("decision", "allow"))]
        )
        guardian_results.append(detector_guardian)

    if detector_guardians:
        def _frameworks(key: str) -> list[str]:
            return sorted(
                {
                    str(g.get("framework_refs", {}).get(key))
                    for g in detector_guardians
                    if g.get("framework_refs", {}).get(key)
                }
            )

        final_actions["threat_detectors"] = {
            "triggered": [g.get("guardian_id") for g in detector_guardians],
            "threat_types": sorted(
                {t for g in detector_guardians for t in (g.get("threat_types") or [])}
            ),
            "frameworks": {
                "owasp_llm": _frameworks("owasp_llm"),
                "owasp_agentic": _frameworks("owasp_agentic"),
                "mitre_atlas": _frameworks("mitre_atlas"),
            },
        }
    return final_decision


def _collect_threat_types(guardian_results: list[dict[str, Any]]) -> list[str]:
    out: set[str] = set()
    for row in guardian_results:
        for threat in row.get("threat_types") or []:
            candidate = str(threat).strip().lower()
            if candidate:
                out.add(candidate)
    return sorted(out)


def _highest_ticket_severity(guardian_results: list[dict[str, Any]]) -> str | None:
    rank = {"low": 0, "med": 1, "medium": 1, "high": 2, "critical": 3}
    best: tuple[int, str] | None = None
    for row in guardian_results:
        actions_taken = row.get("actions_taken") if isinstance(row.get("actions_taken"), dict) else {}
        ticket = actions_taken.get("create_ticket") if isinstance(actions_taken, dict) else {}
        severity = str((ticket or {}).get("severity") or "").strip().lower()
        if severity not in rank:
            continue
        score = rank[severity]
        normalized = "med" if severity == "medium" else severity
        if best is None or score > best[0]:
            best = (score, normalized)
    return best[1] if best else None


def _apply_discovery_mode_decision_override(
    *,
    platform_mode: str,
    final_decision: str,
    guardian_results: list[dict[str, Any]],
    final_actions: dict[str, Any],
    risk_tier: str,
    reason_hint: str | None = None,
) -> tuple[str, list[dict[str, Any]], dict[str, Any]]:
    actions_out = dict(final_actions or {})
    guardians_out = [dict(item) for item in guardian_results]

    if platform_mode != PLATFORM_MODE_DISCOVERY:
        actions_out["platform_mode_override"] = {
            "platform_mode": "enforce",
            "override_applied": False,
            "reason": "enforce_mode",
        }
        return final_decision, guardians_out, actions_out

    threat_types = _collect_threat_types(guardians_out)
    severity_hint = _highest_ticket_severity(guardians_out)
    critical = is_explicitly_critical(
        risk_tier=risk_tier,
        threat_types=threat_types,
        severity_hint=severity_hint,
        reason_hint=reason_hint,
    )

    if final_decision == "block" and not critical:
        for row in guardians_out:
            if str(row.get("decision")).strip().lower() != "block":
                continue
            row["original_decision"] = "block"
            row["decision"] = "warn"
            actions_taken = dict(row.get("actions_taken") or {})
            actions_taken["monitor"] = {"enabled": True, "mode": PLATFORM_MODE_DISCOVERY}
            row["actions_taken"] = actions_taken

        actions_out["monitor"] = {"enabled": True, "mode": PLATFORM_MODE_DISCOVERY}
        actions_out["platform_mode_override"] = {
            "platform_mode": PLATFORM_MODE_DISCOVERY,
            "override_applied": True,
            "from_decision": "block",
            "to_decision": "warn",
            "reason": "non_critical_discovery_mode",
            "threat_types": threat_types,
        }
        return "warn", guardians_out, actions_out

    actions_out["platform_mode_override"] = {
        "platform_mode": PLATFORM_MODE_DISCOVERY,
        "override_applied": False,
        "reason": "critical_threat" if critical else "no_block_decision",
        "threat_types": threat_types,
    }
    return final_decision, guardians_out, actions_out


def _tighten_decision_for_strictness(decision: str, *, outcome: str, strictness_level: int) -> str:
    level = max(0, min(2, strictness_level))
    if level == 0:
        return decision

    adjusted = decision

    if outcome == "uncertain":
        if level >= 1 and adjusted == "warn":
            adjusted = "hold_for_approval"
        if level >= 2 and adjusted in {"allow", "warn", "redact"}:
            adjusted = "hold_for_approval"

    if outcome == "fail":
        if level >= 1 and adjusted == "warn":
            adjusted = "redact"
        if level >= 2 and adjusted == "redact":
            adjusted = "hold_for_approval"

    return adjusted


def evaluate_guardians(
    *,
    payload: dict[str, Any],
    guardians: list[dict[str, Any]],
    strictness_level: int,
) -> tuple[list[dict[str, Any]], str, dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    guardian_results: list[dict[str, Any]] = []
    final_actions: dict[str, Any] = {}
    control_impacts: list[dict[str, Any]] = []
    approval_requirements: list[dict[str, Any]] = []

    prompt_lower = _as_text(payload.get("prompt", {}).get("text") or payload.get("prompt", "")).lower()
    context_lower = _as_text(payload.get("context", {}).get("summary") or payload.get("context_summary", "")).lower()

    for guardian in guardians:
        guardian_contract_id = str(guardian.get("guardian_contract_id") or guardian.get("guardian_id") or str(uuid4()))
        if not guardian.get("enabled", False):
            guardian_results.append(
                {
                    "guardian_contract_id": guardian_contract_id,
                    "guardian_id": guardian.get("guardian_id"),
                    "decision": "allow",
                    "confidence": 1.0,
                    "confidence_tier": "clear_negative",
                    "arbiter_invoked": False,
                    "matched_conditions": [],
                    "threat_types": guardian_contract_to_threat_types(
                        str(guardian_contract_id or guardian.get("guardian_id") or "")
                    ),
                    "actions_taken": {"disabled": True},
                }
            )
            continue

        trigger_conditions = _normalize_conditions(guardian.get("trigger_conditions"))
        block_conditions = _normalize_conditions(guardian.get("block_conditions"))
        matched_trigger_conditions = [cond.get("field", "unknown") for cond in trigger_conditions if _match_condition(payload, cond)]
        matched_block_conditions = [cond.get("field", "unknown") for cond in block_conditions if _match_condition(payload, cond)]
        matched_conditions = [*matched_block_conditions, *matched_trigger_conditions]

        eval_config = guardian.get("legacy_evaluation") or {}
        method = eval_config.get("method", "rules")
        threshold = float(eval_config.get("confidence_threshold", 0.5))
        decision_map = guardian.get("legacy_decision") or {}

        if matched_block_conditions:
            base_confidence = 0.99
            outcome = "fail"
            base_decision = "block"
        elif matched_trigger_conditions:
            base_confidence = 0.9 if method == "rules" else 0.78
            outcome = "fail"
            base_decision = decision_map.get("on_fail", "block")
        else:
            base_confidence = 0.2 if method == "rules" else 0.55
            uncertain_hint = "maybe" in prompt_lower or "unclear" in context_lower
            outcome = "uncertain" if method in {"model_stub", "hybrid"} and uncertain_hint and base_confidence < threshold else "pass"
            if outcome == "uncertain":
                base_decision = decision_map.get("on_uncertain", "warn")
            else:
                base_decision = decision_map.get("on_pass", "allow")

        confidence_tier = classify_confidence_tier(
            confidence=base_confidence,
            threshold=threshold,
            trigger_matched=bool(matched_trigger_conditions),
            block_matched=bool(matched_block_conditions),
        )
        confidence = base_confidence
        arbiter_invoked = False
        arbiter_result: dict[str, Any] | None = None
        if confidence_tier == CONFIDENCE_TIER_AMBIGUOUS:
            arbiter_invoked = True
            arbiter_result = run_ambiguous_arbiter(
                payload=payload,
                guardian_contract_id=guardian_contract_id,
                matched_conditions=matched_conditions,
                threshold=threshold,
            )
            confidence_tier = str(arbiter_result["tier"])
            confidence = float(arbiter_result["confidence"])
            if confidence_tier == CONFIDENCE_TIER_CLEAR_NEGATIVE:
                outcome = "pass"
                base_decision = decision_map.get("on_pass", "allow")
            else:
                if matched_block_conditions:
                    outcome = "fail"
                    base_decision = "block"
                elif matched_trigger_conditions:
                    outcome = "fail"
                    base_decision = decision_map.get("on_fail", "block")
                else:
                    outcome = "uncertain"
                    base_decision = decision_map.get("on_uncertain", "warn")

        decision = _tighten_decision_for_strictness(
            base_decision,
            outcome=outcome,
            strictness_level=strictness_level,
        )
        threat_types = guardian_contract_to_threat_types(
            str(guardian_contract_id or guardian.get("guardian_id") or "")
        )

        actions_cfg = guardian.get("mandatory_actions") or {}
        escalation_cfg = guardian.get("escalation_path") or {}
        actions_taken: dict[str, Any] = {}

        if decision in {"redact", "block", "hold_for_approval", "warn"}:
            redact_cfg = actions_cfg.get("redact") or {}
            if redact_cfg:
                actions_taken["redact"] = redact_cfg
            mutate_cfg = actions_cfg.get("mutate_output") or {}
            if mutate_cfg.get("enabled"):
                actions_taken["mutate_output"] = mutate_cfg
            notify_cfg = actions_cfg.get("notify") or {}
            if notify_cfg.get("channels"):
                actions_taken["notify"] = notify_cfg
            ticket_cfg = actions_cfg.get("create_ticket") or {}
            if ticket_cfg:
                actions_taken["create_ticket"] = ticket_cfg
            if escalation_cfg:
                actions_taken["escalation_path"] = escalation_cfg

        if outcome == "fail":
            impact = guardian.get("legacy_control_impact") or {}
            evidence_requirements = guardian.get("evidence_requirements") or {}
            framework_mappings = guardian.get("framework_mappings") or {}
            linked_controls = list(evidence_requirements.get("link_to_controls") or [])
            if not linked_controls:
                linked_controls = list(framework_mappings.get("control_ids") or [])
            for control_id in linked_controls:
                control_impacts.append(
                    {
                        "control_id": control_id,
                        "delta": float(impact.get("maturity_delta_on_fail", 0.0)),
                    }
                )

            if decision == "hold_for_approval":
                approval_cfg = (escalation_cfg.get("approval_workflow") if isinstance(escalation_cfg, dict) else None) or guardian.get("legacy_approval_workflow") or {
                    "required_roles": ["owner", "admin"],
                    "sla_minutes": 30,
                    "default_if_timeout": "block",
                }
                approval_requirements.append(
                    {
                        "guardian_contract_id": guardian_contract_id,
                        "guardian_id": guardian.get("guardian_id"),
                        "required_roles": approval_cfg.get("required_roles", ["owner", "admin"]),
                        "sla_minutes": approval_cfg.get("sla_minutes", 30),
                        "default_if_timeout": approval_cfg.get("default_if_timeout", "block"),
                    }
                )

        guardian_results.append(
            {
                "guardian_contract_id": guardian_contract_id,
                "guardian_id": guardian.get("guardian_id"),
                "decision": decision,
                "base_decision": base_decision,
                "confidence": round(confidence, 4),
                "confidence_tier": confidence_tier,
                "arbiter_invoked": arbiter_invoked,
                "arbiter_reason": (arbiter_result or {}).get("reason"),
                "outcome": outcome,
                "strictness_level_applied": strictness_level,
                "matched_conditions": matched_conditions,
                "threat_types": threat_types,
                "actions_taken": actions_taken,
            }
        )
        if actions_taken:
            final_actions[guardian_contract_id] = actions_taken

    final_decision = _aggregate_guardian_decisions([row["decision"] for row in guardian_results])
    return guardian_results, final_decision, final_actions, control_impacts, approval_requirements


def get_guardian_enforcement_matrix(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    actor_type: str,
) -> dict[str, Any]:
    ai_system = db.scalar(
        select(AISystem).where(
            AISystem.id == ai_system_id,
            AISystem.tenant_id == tenant_id,
        )
    )
    if not ai_system:
        raise ValueError("AI system not found for tenant")

    policy = get_latest_policy_for_ai_system(db, tenant_id, ai_system, actor_type)
    strictness_level = risk_tier_strictness_level(ai_system.risk_tier)

    guardians = []
    if policy:
        for guardian in load_policy_guardian_contracts(db, policy_version=policy):
            impact = guardian.get("legacy_control_impact") or {}
            evidence_requirements = guardian.get("evidence_requirements") or {}
            framework_mappings = guardian.get("framework_mappings") or {}
            guardians.append(
                {
                    "guardian_contract_id": guardian.get("guardian_contract_id"),
                    "guardian_id": guardian.get("guardian_id"),
                    "description": guardian.get("name", ""),
                    "enabled": bool(guardian.get("enabled", False)),
                    "threat_types": guardian_contract_to_threat_types(
                        str(guardian.get("guardian_contract_id") or guardian.get("guardian_id") or "")
                    ),
                    "triggers": {"conditions": guardian.get("trigger_conditions", [])},
                    "block_conditions": guardian.get("block_conditions") or [],
                    "thresholds": guardian.get("legacy_evaluation") or {"method": "rules", "confidence_threshold": 0.0},
                    "actions": guardian.get("mandatory_actions") or {},
                    "mapped_controls": (evidence_requirements.get("link_to_controls") or framework_mappings.get("control_ids") or []),
                    "control_impact_deltas": {
                        "maturity_delta_on_fail": float(impact.get("maturity_delta_on_fail", 0.0)),
                        "enforcement_strictness_increase": int(impact.get("enforcement_strictness_increase", 0)),
                        "increase_simulation_frequency": bool(impact.get("increase_simulation_frequency", False)),
                    },
                }
            )

    return {
        "tenant_id": tenant_id,
        "ai_system_id": ai_system_id,
        "risk_tier": ai_system.risk_tier,
        "strictness_level": strictness_level,
        "policy_version_id": policy.id if policy else None,
        "threat_type_registry": get_threat_registry(),
        "guardians": guardians,
    }


def _gateway_control_ids(
    guardian_results: list[dict[str, Any]],
    control_impacts: list[dict[str, Any]],
) -> list[str]:
    control_ids = {str(item.get("control_id")) for item in control_impacts if item.get("control_id")}
    for result in guardian_results:
        actions = result.get("actions_taken") or {}
        for control_id in actions.get("triggered_controls") or []:
            if str(control_id).strip():
                control_ids.add(str(control_id))
        for control_id in result.get("mapped_controls") or []:
            if str(control_id).strip():
                control_ids.add(str(control_id))
    return sorted(control_ids)


def _gateway_decision_reason(
    guardian_results: list[dict[str, Any]],
    *,
    fallback: str,
) -> str:
    reason_codes: list[str] = []
    for result in guardian_results:
        actions = result.get("actions_taken") or {}
        reason = actions.get("reason_code") or result.get("guardian_id") or result.get("guardian_contract_id")
        if reason and str(reason).strip():
            reason_codes.append(str(reason))
    if reason_codes:
        return ", ".join(dict.fromkeys(reason_codes))
    return fallback


def _build_gateway_action_control_envelope(
    *,
    tenant_id: str,
    ai_system_id: str,
    actor_type: str,
    actor_id: str,
    request_id: str,
    final_decision: str,
    policy_version_id: str | None,
    platform_mode: str | None,
    strictness_level: int | None,
    trace_payload: dict[str, Any],
    guardian_results: list[dict[str, Any]],
    control_impacts: list[dict[str, Any]],
    evidence_node_ids: list[str],
) -> dict[str, Any]:
    control_mode = control_mode_for_pre_action_decision(final_decision, inline=True)
    actor_type_normalized = str(actor_type or "unknown").strip().lower() or "unknown"
    is_human = actor_type_normalized == "human"
    chain_id = trace_payload.get("chain_id") or request_id
    evidence_status = "valid" if evidence_node_ids else "unchecked"
    action_category = "execute" if trace_payload.get("tool_name") else action_category_for("gateway_model_call")
    policy_snapshot_id = policy_version_id or "gateway-policy-unversioned"
    control_ids = _gateway_control_ids(guardian_results, control_impacts)

    ai_action = {
        "action_id": request_id,
        "tenant_id": tenant_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": {
            "identity_id": actor_id,
            "identity_type": actor_type_normalized,
            "user_id": actor_id if is_human else None,
            "agent_id": actor_id if actor_type_normalized == "agent" else trace_payload.get("parent_agent_id"),
            "session_id": trace_payload.get("session_id"),
            "machine_id": None,
            "device_id": None,
            "acting_on_behalf_of_user_id": trace_payload.get("initiating_user_id"),
        },
        "authority": {
            "authority_type": "user_session" if is_human else "delegated_agent",
            "authority_owner": actor_id,
            "standing_privilege": "unknown",
            "delegation_chain": [
                item
                for item in [
                    trace_payload.get("parent_agent_id"),
                    actor_id,
                ]
                if item
            ],
        },
        "surface": {
            "surface_type": "gateway",
            "application": trace_payload.get("data_source") or "llm_gateway",
            "provider": trace_payload.get("provider"),
            "model": trace_payload.get("model"),
            "domain": None,
            "url": trace_payload.get("api_endpoint"),
            "asset_id": ai_system_id,
            "environment": "unknown",
        },
        "intent": {
            "declared_intent": None,
            "inferred_intent": trace_payload.get("workflow_policy_id") or "gateway_model_call",
            "intent_category": "llm_model_call",
            "intent_confidence": "medium",
            "action_alignment": "unknown",
        },
        "action": {
            "action_type": "gateway_model_call",
            "action_category": action_category,
            "action_risk": action_risk_for("gateway_model_call"),
            "target_resource": trace_payload.get("api_endpoint") or trace_payload.get("model"),
            "tool_name": trace_payload.get("tool_name"),
            "parameters_ref": request_id,
            "input_ref": trace_payload.get("prompt_hash"),
            "output_ref": trace_payload.get("response_hash"),
        },
        "context": {
            "input_sensitivity": trace_payload.get("data_classification"),
            "output_sensitivity": trace_payload.get("response_data_classification"),
            "destination_trust_level": _sensitive_destination_context(trace_payload)[1],
            "automation_suspected": bool(trace_payload.get("tool_usage_meta")),
            "transaction_detected": False,
            "context_integrity_status": "unchecked",
            "approval_status": "pending" if final_decision == "hold_for_approval" else "not_required",
            "secret_detected": "secret" in {str(item).lower() for item in (trace_payload.get("sensitive_signal_types") or [])},
            "mcp_tool_used": False,
            "repo_action_detected": False,
        },
        "policy": {
            "policy_ids": [policy_snapshot_id],
            "control_ids": control_ids,
            "policy_snapshot_id": policy_snapshot_id,
            "decision": final_decision,
            "decision_reason": _gateway_decision_reason(guardian_results, fallback="gateway_policy_evaluation"),
            "control_mode": control_mode,
            "decision_badge": decision_badge_for_control_mode(control_mode),
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "platform_mode": platform_mode,
            "strictness_level": strictness_level,
        },
        "evidence": {
            "evidence_refs": list(evidence_node_ids or []),
            "evidence_bundle_id": f"gateway:{chain_id}:{request_id}",
            "trace_id": trace_payload.get("correlation_id") or request_id,
            "integrity_status": evidence_status,
            "evidence_status": evidence_status,
        },
        "chain": {
            "chain_id": chain_id,
            "parent_action_id": trace_payload.get("parent_action_id"),
            "root_action_id": chain_id,
            "previous_action_id": trace_payload.get("parent_action_id"),
            "delegation_depth": trace_payload.get("chain_depth") or 0,
            "source_agent_id": trace_payload.get("parent_agent_id"),
            "destination_agent_id": actor_id if actor_type_normalized == "agent" else None,
            "source_trust_level": "unknown",
            "destination_trust_level": "unknown",
            "source_context_type": "system",
            "taint_status": "unknown",
            "chain_integrity_status": "unknown",
            "chain_risk_score": None,
        },
        "finding_id": None,
    }
    decision_explanation = build_decision_explanation(ai_action)
    ai_action["decision_explanation_id"] = decision_explanation.get("explanation_id")
    return {
        "control_mode": control_mode,
        "ai_action": ai_action,
        "decision_explanation": decision_explanation,
    }


@with_tenant_profile
def llm_intercept(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    actor_type: str,
    actor_id: str,
    request_id: str,
    prompt: str,
    context_summary: str,
    attachments_meta: list[dict[str, Any]],
    tool_output: str | None,
    audit_actor_user_id: str | None,
    response_text: str | None = None,
    provider: str | None = None,
    model_name: str | None = None,
    model_version: str | None = None,
    tool_name: str | None = None,
    tool_category: str | None = None,
    api_endpoint: str | None = None,
    data_source: str | None = None,
    tool_usage_meta: dict[str, Any] | list[dict[str, Any]] | None = None,
    context_id: str | None = None,
    chain_id: str | None = None,
    chain_depth: int | None = None,
    parent_action_id: str | None = None,
    parent_agent_id: str | None = None,
) -> dict[str, Any]:
    governance_minimal_mode = bool(settings.gateway_intercept_minimal_mode)
    governance_check = enforce_governance(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        action="gateway.llm.intercept",
        route="/gateway/llm/intercept",
        module="gateway_service",
        commit_logs=(not governance_minimal_mode),
        emit_logs=(not governance_minimal_mode),
    )
    correlation_id = get_correlation_id()
    resolved_context_id = _normalized_optional(context_id) or _normalized_optional(correlation_id) or request_id
    resolved_chain_id = _normalized_optional(chain_id) or request_id
    resolved_parent_action_id = _normalized_optional(parent_action_id)
    governance_status = {
        "status": governance_check.status or governance_check.governance_state,
        "enforcement_mode": governance_check.enforcement_mode,
        "source": governance_check.source,
    }

    # Ultra-fast demo path: avoid additional policy/governance DB reads while preserving
    # deterministic control-engine evaluation and safe allow/block behavior.
    if governance_minimal_mode:
        evaluated_output = tool_output if tool_output is not None else response_text
        trace_payload = _build_gateway_trace_payload(
            correlation_id=correlation_id,
            request_id=request_id,
            policy_version_id=None,
            provider=provider,
            model_name=model_name,
            model_version=model_version,
            prompt=prompt,
            response_text=evaluated_output,
            context_summary=context_summary,
            tool_name=tool_name,
            tool_category=tool_category,
            api_endpoint=(api_endpoint or "/gateway/llm/intercept"),
            data_source=data_source,
            tool_usage_meta=tool_usage_meta,
            attachments_meta=attachments_meta,
            context_id=resolved_context_id,
            chain_id=resolved_chain_id,
            chain_depth=chain_depth,
            parent_action_id=resolved_parent_action_id,
            parent_agent_id=parent_agent_id,
        )

        destination_type, _trust_level = _sensitive_destination_context(trace_payload)
        control_decision = evaluate_control_engine(
            AIAction(
                action_id=request_id,
                user_id=(actor_id if str(actor_type).strip().lower() == "human" else None),
                ai_app=(trace_payload.get("provider") or trace_payload.get("data_source") or trace_payload.get("api_endpoint")),
                model=(trace_payload.get("model") or trace_payload.get("model_version")),
                prompt=prompt,
                metadata={
                    "source_surface": "gateway",
                    "action_type": "prompt",
                    "contains_sensitive": bool(trace_payload.get("contains_sensitive")),
                    "data_classification": str(trace_payload.get("data_classification") or "unknown"),
                    "destination_domain": str(trace_payload.get("api_endpoint") or ""),
                    "destination_is_external": destination_type == "external_api",
                    "governance_status": str(governance_status.get("status") or "UNKNOWN"),
                    "chain_depth": chain_depth,
                },
                source_surface="gateway",
            ),
            base_decision="allow",
            hinted_control_ids=[],
        )
        final_decision = _map_control_engine_gateway_decision(
            control_decision.decision,
            fallback="allow",
        )
        control_impacts = _augment_control_impacts(
            [],
            triggered_controls=list(control_decision.triggered_controls),
        )

        final_decision, provider_overlay = _apply_provider_enforcement_overlay(
            platform_mode="enforce",
            decision=final_decision,
            trace_payload=trace_payload,
        )
        sensitive_overlay_decision, sensitive_overlay = _apply_sensitive_policy_overlay(
            platform_mode="enforce",
            decision=final_decision,
            trace_payload=trace_payload,
        )
        if sensitive_overlay is not None:
            final_decision = _aggregate_guardian_decisions([final_decision, sensitive_overlay_decision])

        guardian_results: list[dict[str, Any]] = [
            {
                "guardian_contract_id": "control_engine.gateway.minimal",
                "guardian_id": "control_engine",
                "decision": final_decision,
                "confidence": 1.0,
                "confidence_tier": "clear_positive",
                "arbiter_invoked": False,
                "matched_conditions": ["central_control_engine"],
                "threat_types": list(control_decision.risk_tags or []),
                "actions_taken": {
                    "reason_code": "control_engine_minimal_mode",
                    "dominant_control": control_decision.dominant_control,
                    "triggered_controls": list(control_decision.triggered_controls),
                    "total_risk_score": control_decision.total_risk_score,
                },
            }
        ]
        final_actions: dict[str, Any] = {
            "control_decision": control_decision.to_dict(),
        }
        if provider_overlay is not None:
            guardian_results.append(
                {
                    "guardian_contract_id": "provider_surface_guard",
                    "guardian_id": "provider_surface_guard",
                    "decision": final_decision,
                    "confidence": 0.95,
                    "confidence_tier": "clear_positive",
                    "arbiter_invoked": False,
                    "matched_conditions": ["provider_classification"],
                    "threat_types": ["unknown_ai_model_usage"] if bool(provider_overlay.get("open_source_model_hint")) else ["provider_review"],
                    "actions_taken": {
                        "reason_code": provider_overlay.get("reason_code"),
                        "provider": provider_overlay.get("provider"),
                        "model_name": provider_overlay.get("model_name"),
                    },
                    "provider_overlay": provider_overlay,
                }
            )
            final_actions["provider_overlay"] = provider_overlay
        if sensitive_overlay is not None:
            guardian_results.append(
                {
                    "guardian_contract_id": str(sensitive_overlay.get("policy_id") or "guardian.gateway.sensitive_data"),
                    "guardian_id": "sensitive_data_guard",
                    "decision": final_decision,
                    "confidence": max(0.8, float(trace_payload.get("sensitive_confidence_score") or 0.8)),
                    "confidence_tier": "clear_positive",
                    "arbiter_invoked": False,
                    "matched_conditions": ["data.contains_sensitive", "destination.trust_level"],
                    "threat_types": ["sensitive_data_leakage"],
                    "actions_taken": {
                        "reason_code": sensitive_overlay.get("reason_code"),
                        "contains_sensitive": True,
                        "sensitive_entities": list(sensitive_overlay.get("sensitive_entities") or []),
                    },
                    "sensitive_overlay": sensitive_overlay,
                }
            )
            final_actions["sensitive_data_overlay"] = sensitive_overlay

        final_decision = _apply_threat_detectors(
            final_decision=final_decision,
            guardian_results=guardian_results,
            final_actions=final_actions,
            prompt=prompt,
            context_summary=context_summary,
            tool_output=tool_output,
            response_text=evaluated_output,
            surface="llm",
        )

        final_actions["_meta"] = {
            "policy_version_id": None,
            "risk_tier": governance_check.risk_tier,
            "strictness_level": risk_tier_strictness_level(str(governance_check.risk_tier or "MEDIUM")),
            "platform_mode": "enforce",
            "governance_state": governance_status.get("status"),
            "governance_source": governance_status.get("source"),
            "governance_enforcement_mode": governance_status.get("enforcement_mode"),
            "contract_mode": "minimal",
            "resolved_contract_mode": "minimal",
            "provider": trace_payload.get("provider"),
            "model_name": trace_payload.get("model"),
            "model_version": trace_payload.get("model_version"),
            "prompt_hash": trace_payload.get("prompt_hash"),
            "response_hash": trace_payload.get("response_hash"),
            "tool_name": trace_payload.get("tool_name"),
            "tool_category": trace_payload.get("tool_category"),
            "api_endpoint": trace_payload.get("api_endpoint"),
            "data_source": trace_payload.get("data_source"),
            "data_classification": trace_payload.get("data_classification"),
            "contains_sensitive": trace_payload.get("contains_sensitive"),
            "sensitive_confidence_score": trace_payload.get("sensitive_confidence_score"),
            "sensitive_entities": trace_payload.get("sensitive_entities"),
            "workflow_policy_id": None,
            "violation_reason": None,
            "governance_version": trace_payload.get("governance_version"),
            "chain_depth": trace_payload.get("chain_depth"),
            "context_id": trace_payload.get("context_id"),
            "chain_id": trace_payload.get("chain_id"),
            "parent_action_id": trace_payload.get("parent_action_id"),
            "parent_agent_id": trace_payload.get("parent_agent_id"),
            "enforcement_routing": {"engine": "minimal", "route": "gateway_direct"},
            "triggered_controls": list(control_decision.triggered_controls),
            "dominant_control": control_decision.dominant_control,
            "control_decision_reasoning": control_decision.reasoning,
            "control_decision_total_risk": control_decision.total_risk_score,
            "risk_tags": list(control_decision.risk_tags),
        }
        final_actions["_trace"] = trace_payload
        action_control = _build_gateway_action_control_envelope(
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            actor_type=actor_type,
            actor_id=actor_id,
            request_id=request_id,
            final_decision=final_decision,
            policy_version_id=None,
            platform_mode="enforce",
            strictness_level=risk_tier_strictness_level(str(governance_check.risk_tier or "MEDIUM")),
            trace_payload=trace_payload,
            guardian_results=guardian_results,
            control_impacts=control_impacts,
            evidence_node_ids=[],
        )
        final_actions["ai_action"] = action_control["ai_action"]
        final_actions["decision_explanation"] = action_control["decision_explanation"]
        return {
            "event_id": request_id,
            "request_id": request_id,
            "final_decision": final_decision,
            "control_mode": action_control["control_mode"],
            "ai_action": action_control["ai_action"],
            "decision_explanation": action_control["decision_explanation"],
            "guardian_results": guardian_results,
            "final_actions": final_actions,
            "evidence_nodes_created": [],
            "controls_impacted": control_impacts,
            "policy_version_id": None,
            "strictness_level": risk_tier_strictness_level(str(governance_check.risk_tier or "MEDIUM")),
            "platform_mode": "enforce",
            "audit_log_id": None,
            "approval_request_ids": [],
            "trace": trace_payload,
            "minimal_mode": True,
        }

    ai_system = db.scalar(
        select(AISystem).where(
            AISystem.id == ai_system_id,
            AISystem.tenant_id == tenant_id,
        )
    )
    if not ai_system:
        raise ValueError("AI system not found for tenant")

    policy = get_latest_policy_for_ai_system(db, tenant_id, ai_system, actor_type)
    policy_version_id = policy.id if policy else None
    workflow_policy = load_workflow_policy(policy)
    guardians_v1 = []
    default_decision = "allow"
    strictness_level = risk_tier_strictness_level(ai_system.risk_tier)
    requested_contract_mode = str(settings.enforcement_contract_mode or "v1").strip().lower()
    if requested_contract_mode not in {"v1", "hybrid", "v2"}:
        requested_contract_mode = "v1"
    resolved_contract_mode = "v1"
    v2_bindings: list[dict[str, Any]] = []

    if policy:
        guardians_v1 = load_policy_guardian_contracts(db, policy_version=policy)
        default_decision = (policy.enforcement_defaults or {}).get("default_decision", "allow")

    evaluated_output = tool_output if tool_output is not None else response_text
    payload = {
        "prompt": {"text": prompt},
        "context": {"summary": context_summary, "rag": context_summary},
        "context_summary": context_summary,
        "attachments_meta": attachments_meta,
        "tool_output": evaluated_output,
        "response_text": response_text,
    }

    if requested_contract_mode in {"hybrid", "v2"}:
        v2_bindings = load_applicable_v2_bindings(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            policy_version_id=policy_version_id,
        )

    if requested_contract_mode == "v2":
        resolved_contract_mode = "v2"
        guardian_results, evaluated_decision, final_actions, control_impacts, approval_requirements = evaluate_v2_guardians(
            payload=payload,
            bindings=v2_bindings,
            strictness_level=strictness_level,
        )
        final_decision = evaluated_decision if guardian_results else default_decision
    elif requested_contract_mode == "hybrid" and v2_bindings:
        resolved_contract_mode = "v2"
        guardian_results, evaluated_decision, final_actions, control_impacts, approval_requirements = evaluate_v2_guardians(
            payload=payload,
            bindings=v2_bindings,
            strictness_level=strictness_level,
        )
        final_decision = evaluated_decision if guardian_results else default_decision
    else:
        resolved_contract_mode = "v1"
        guardian_results, evaluated_decision, final_actions, control_impacts, approval_requirements = evaluate_guardians(
            payload=payload,
            guardians=guardians_v1,
            strictness_level=strictness_level,
        )
        final_decision = evaluated_decision if guardians_v1 else default_decision

    platform_mode = get_tenant_platform_mode(db, tenant_id=tenant_id)
    final_decision, guardian_results, final_actions = _apply_discovery_mode_decision_override(
        platform_mode=platform_mode,
        final_decision=final_decision,
        guardian_results=guardian_results,
        final_actions=final_actions,
        risk_tier=ai_system.risk_tier,
    )

    trace_payload = _build_gateway_trace_payload(
        correlation_id=correlation_id,
        request_id=request_id,
        policy_version_id=policy_version_id,
        provider=provider,
        model_name=model_name,
        model_version=model_version,
        prompt=prompt,
        response_text=evaluated_output,
        context_summary=context_summary,
        tool_name=tool_name,
        tool_category=tool_category,
        api_endpoint=(api_endpoint or "/gateway/llm/intercept"),
        data_source=data_source,
        tool_usage_meta=tool_usage_meta,
        attachments_meta=attachments_meta,
        context_id=resolved_context_id,
        chain_id=resolved_chain_id,
        chain_depth=chain_depth,
        parent_action_id=resolved_parent_action_id,
        parent_agent_id=parent_agent_id,
    )
    trace_payload["ai_system_id"] = ai_system_id
    final_decision, provider_overlay = _apply_provider_enforcement_overlay(
        platform_mode=platform_mode,
        decision=final_decision,
        trace_payload=trace_payload,
    )
    if provider_overlay is not None:
        guardian_results.append(
            {
                "guardian_contract_id": "provider_surface_guard",
                "guardian_id": "provider_surface_guard",
                "decision": final_decision,
                "confidence": 0.95,
                "confidence_tier": "clear_positive",
                "arbiter_invoked": False,
                "matched_conditions": ["provider_classification"],
                "threat_types": ["unknown_ai_model_usage"] if bool(provider_overlay.get("open_source_model_hint")) else ["provider_review"],
                "actions_taken": {
                    "reason_code": provider_overlay.get("reason_code"),
                    "provider": provider_overlay.get("provider"),
                    "model_name": provider_overlay.get("model_name"),
                },
                "provider_overlay": provider_overlay,
            }
        )
        final_actions["provider_overlay"] = provider_overlay
    sensitive_overlay_decision, sensitive_overlay = _apply_sensitive_policy_overlay(
        platform_mode=platform_mode,
        decision=final_decision,
        trace_payload=trace_payload,
    )
    if sensitive_overlay is not None:
        final_decision = _aggregate_guardian_decisions([final_decision, sensitive_overlay_decision])
        guardian_results.append(
            {
                "guardian_contract_id": str(sensitive_overlay.get("policy_id") or "guardian.gateway.sensitive_data"),
                "guardian_id": "sensitive_data_guard",
                "decision": final_decision,
                "confidence": max(0.8, float(trace_payload.get("sensitive_confidence_score") or 0.8)),
                "confidence_tier": "clear_positive",
                "arbiter_invoked": False,
                "matched_conditions": ["data.contains_sensitive", "destination.trust_level"],
                "threat_types": ["sensitive_data_leakage"],
                "actions_taken": {
                    "reason_code": sensitive_overlay.get("reason_code"),
                    "contains_sensitive": True,
                    "sensitive_entities": list(sensitive_overlay.get("sensitive_entities") or []),
                },
                "sensitive_overlay": sensitive_overlay,
            }
        )
        final_actions["sensitive_data_overlay"] = sensitive_overlay

    need_to_know_decision, need_to_know_guardian, _knowledge_assets = _evaluate_need_to_know_gateway(
        policy=policy,
        actor_type=actor_type,
        actor_id=actor_id,
        context_summary=context_summary,
        attachments_meta=attachments_meta,
        trace_payload=trace_payload,
    )
    if need_to_know_guardian is not None:
        final_decision = _aggregate_guardian_decisions([final_decision, str(need_to_know_guardian["decision"])])
        guardian_results.append(need_to_know_guardian)
        if str(need_to_know_guardian.get("decision") or "").strip().lower() != "allow":
            control_impacts = _augment_control_impacts(control_impacts, triggered_controls=["CTRL-AI-IAM-NTK"])
        final_actions["need_to_know"] = {
            "decision": need_to_know_decision,
            "knowledge_asset_ids": list(trace_payload.get("knowledge_asset_ids") or []),
            "sensitivity_domain": trace_payload.get("sensitivity_domain"),
        }

    final_decision = _apply_threat_detectors(
        final_decision=final_decision,
        guardian_results=guardian_results,
        final_actions=final_actions,
        prompt=prompt,
        context_summary=context_summary,
        tool_output=tool_output,
        response_text=evaluated_output,
        surface="llm",
    )

    workflow_evaluation = evaluate_workflow_policy(
        workflow_policy,
        agent_id=(parent_agent_id or (actor_id if str(actor_type).lower() == "agent" else None)),
        tool_name=(trace_payload.get("tool_name") or tool_name),
        chain_depth=chain_depth,
        data_classification=str(trace_payload.get("data_classification") or "unknown"),
        available_control_ids=[str(item.get("control_id")) for item in control_impacts if item.get("control_id")],
    )
    workflow_decision = _map_workflow_to_gateway_decision(workflow_evaluation.decision)
    trace_payload["workflow_policy_id"] = workflow_evaluation.workflow_policy_id
    trace_payload["violation_reason"] = workflow_evaluation.violation_reason
    if workflow_evaluation.violation_reason:
        final_decision = _aggregate_guardian_decisions([final_decision, workflow_decision])
        guardian_results.append(
            {
                "guardian_contract_id": str(workflow_evaluation.workflow_policy_id or "workflow_policy"),
                "guardian_id": "workflow_policy_guard",
                "decision": workflow_decision,
                "confidence": 1.0,
                "confidence_tier": "clear_positive",
                "arbiter_invoked": False,
                "matched_conditions": list(workflow_evaluation.matched_violations or []),
                "threat_types": ["workflow_policy_violation"],
                "actions_taken": {
                    "workflow_policy_id": workflow_evaluation.workflow_policy_id,
                    "violation_reason": workflow_evaluation.violation_reason,
                    "matched_violations": list(workflow_evaluation.matched_violations or []),
                },
            }
        )
    final_actions["workflow_policy"] = {
        "workflow_policy_id": workflow_evaluation.workflow_policy_id,
        "violation_reason": workflow_evaluation.violation_reason,
        "matched_violations": list(workflow_evaluation.matched_violations or []),
        "decision": workflow_decision,
    }
    scoped_policy = resolve_scoped_policy_decision(
        db,
        tenant_id=tenant_id,
        policy_version_id=policy_version_id,
        context={
            "actor_type": str(actor_type or "human"),
            "actor_user_id": (audit_actor_user_id or (actor_id if str(actor_type).strip().lower() == "human" else None)),
            "actor_role": None,
            "actor_department": None,
            "agent_id": (actor_id if str(actor_type).strip().lower() == "agent" else parent_agent_id),
            "endpoint_id": _normalized_optional(trace_payload.get("endpoint_id")),
            "source_surface": "gateway",
            "action_type": ("tool_call" if _normalized_optional(tool_name) else "prompt_input"),
            "operation": ("tool_execution" if _normalized_optional(tool_name) else "prompt_submission"),
            "domain": trace_payload.get("api_endpoint"),
            "tool_name": _normalized_optional(tool_name) or trace_payload.get("tool_name") or trace_payload.get("data_source"),
            "provider": trace_payload.get("provider"),
            "model": trace_payload.get("model"),
            "ai_system_id": ai_system_id,
            "data_classification": trace_payload.get("data_classification"),
            "contains_sensitive": bool(trace_payload.get("contains_sensitive")),
            "risk_tier": ai_system.risk_tier,
        },
    )
    final_actions["scoped_policy"] = scoped_policy.to_dict()
    hard_block_active = final_decision == "block" and any(
        str(item.get("actions_taken", {}).get("reason_code") or "").strip().lower()
        in {"sensitive_data_detected", "guardian.browser.sensitive_prompt_matched"}
        for item in guardian_results
        if isinstance(item, dict)
    )
    if scoped_policy.matched:
        scoped_decision = _map_scoped_gateway_decision(scoped_policy.decision, fallback=final_decision)
        if (
            AGGREGATION_PRECEDENCE.index(scoped_decision) < AGGREGATION_PRECEDENCE.index(final_decision)
            or (
                AGGREGATION_PRECEDENCE.index(scoped_decision) > AGGREGATION_PRECEDENCE.index(final_decision)
                and not hard_block_active
            )
        ):
            final_decision = scoped_decision
            guardian_results.append(
                {
                    "guardian_contract_id": str(scoped_policy.rule_id or "scoped_policy"),
                    "guardian_id": "scoped_policy",
                    "decision": final_decision,
                    "confidence": 1.0,
                    "confidence_tier": "clear_positive",
                    "arbiter_invoked": False,
                    "matched_conditions": list(scoped_policy.matched_selectors or []),
                    "threat_types": ["policy_scope_override"],
                    "actions_taken": {
                        "reason_code": str(scoped_policy.reason_code or "scoped_policy_matched"),
                        "explanation": str(scoped_policy.explanation or ""),
                        "policy_version_id": str(scoped_policy.policy_version_id or policy_version_id or ""),
                    },
                }
            )
    hinted_controls = [
        str(item.get("control_id") or "").strip()
        for item in control_impacts
        if str(item.get("control_id") or "").strip()
    ]
    if final_decision in {"warn", "redact", "hold_for_approval", "block"}:
        hinted_controls.append("POLICY_ENFORCEMENT_CONTROL")
    control_decision = evaluate_control_engine(
        AIAction(
            action_id=request_id,
            user_id=(actor_id if str(actor_type).strip().lower() == "human" else None),
            ai_app=(trace_payload.get("provider") or trace_payload.get("data_source") or trace_payload.get("api_endpoint")),
            model=(trace_payload.get("model") or trace_payload.get("model_version")),
            prompt=prompt,
            metadata={
                "source_surface": "gateway",
                "action_type": "prompt",
                "decision": final_decision,
                "reason_codes": [
                    str(item.get("actions_taken", {}).get("reason_code") or item.get("reason") or "")
                    for item in guardian_results
                    if isinstance(item, dict)
                ],
                "input_signal_types": [
                    str(item)
                    for row in guardian_results
                    for item in (row.get("threat_types") or [])
                    if str(item).strip()
                ],
                "contains_sensitive": bool(trace_payload.get("contains_sensitive")),
                "data_classification": str(trace_payload.get("data_classification") or "unknown"),
                "destination_domain": str(trace_payload.get("api_endpoint") or ""),
                "destination_is_external": _sensitive_destination_context(trace_payload)[0] == "external_api",
                "governance_status": str(governance_status.get("status") or "UNKNOWN"),
                "chain_depth": chain_depth,
                "triggered_controls": hinted_controls,
            },
            source_surface="gateway",
        ),
        base_decision=final_decision,
        hinted_control_ids=hinted_controls,
    )
    control_engine_gateway_decision = _map_control_engine_gateway_decision(
        control_decision.decision,
        fallback=final_decision,
    )
    if _aggregate_guardian_decisions([final_decision, control_engine_gateway_decision]) != final_decision:
        final_decision = _aggregate_guardian_decisions([final_decision, control_engine_gateway_decision])
        guardian_results.append(
            {
                "guardian_contract_id": "control_engine.gateway",
                "guardian_id": "control_engine",
                "decision": final_decision,
                "confidence": 1.0,
                "confidence_tier": "clear_positive",
                "arbiter_invoked": False,
                "matched_conditions": ["central_control_engine"],
                "threat_types": list(control_decision.risk_tags or []),
                "actions_taken": {
                    "reason_code": "control_engine_escalation",
                    "dominant_control": control_decision.dominant_control,
                    "triggered_controls": list(control_decision.triggered_controls),
                    "total_risk_score": control_decision.total_risk_score,
                },
            }
        )
        final_actions["control_engine_escalation"] = True
    final_actions["control_decision"] = control_decision.to_dict()
    control_impacts = _augment_control_impacts(
        control_impacts,
        triggered_controls=list(control_decision.triggered_controls),
    )
    # Discovery mode is the final authority for non-critical monitor-only
    # operation. Reconcile again after overlays and the central control engine
    # so a later escalation cannot silently undo the tenant mode contract.
    final_decision, guardian_results, final_actions = _apply_discovery_mode_decision_override(
        platform_mode=platform_mode,
        final_decision=final_decision,
        guardian_results=guardian_results,
        final_actions=final_actions,
        risk_tier=ai_system.risk_tier,
    )
    routing = route_enforcement(
        {
            "policy_id": policy_version_id or "none",
            "policy_version": (policy.version if policy is not None else "none"),
        },
        {
            "event_id": request_id,
            "tenant_id": tenant_id,
            "source_surface": "gateway",
            "action_type": "prompt",
            "ai_system_id": ai_system_id,
            "agent_id": None,
            "data_classification": trace_payload.get("data_classification"),
            "correlation_id": correlation_id,
            "context_id": resolved_context_id,
            "chain_id": resolved_chain_id,
            "parent_action_id": resolved_parent_action_id,
        },
    )

    # Demo-safe fast path: preserve deterministic policy/control evaluation while
    # skipping heavy persistence fan-out that can stall under local SQLite contention.
    if settings.gateway_intercept_minimal_mode:
        final_actions_with_meta = dict(final_actions)
        final_actions_with_meta["_meta"] = {
            "policy_version_id": policy_version_id,
            "risk_tier": ai_system.risk_tier,
            "strictness_level": strictness_level,
            "platform_mode": platform_mode,
            "governance_state": governance_status.get("status"),
            "governance_source": governance_status.get("source"),
            "governance_enforcement_mode": governance_status.get("enforcement_mode"),
            "contract_mode": requested_contract_mode,
            "resolved_contract_mode": resolved_contract_mode,
            "provider": trace_payload.get("provider"),
            "model_name": trace_payload.get("model"),
            "model_version": trace_payload.get("model_version"),
            "prompt_hash": trace_payload.get("prompt_hash"),
            "response_hash": trace_payload.get("response_hash"),
            "tool_name": trace_payload.get("tool_name"),
            "tool_category": trace_payload.get("tool_category"),
            "api_endpoint": trace_payload.get("api_endpoint"),
            "data_source": trace_payload.get("data_source"),
            "data_classification": trace_payload.get("data_classification"),
            "contains_sensitive": trace_payload.get("contains_sensitive"),
            "sensitive_confidence_score": trace_payload.get("sensitive_confidence_score"),
            "sensitive_entities": trace_payload.get("sensitive_entities"),
            "knowledge_asset_ids": trace_payload.get("knowledge_asset_ids"),
            "sensitivity_domain": trace_payload.get("sensitivity_domain"),
            "need_to_know_decision": trace_payload.get("need_to_know_decision"),
            "knowledge_disclosure_event": trace_payload.get("knowledge_disclosure_event"),
            "workflow_policy_id": trace_payload.get("workflow_policy_id"),
            "violation_reason": trace_payload.get("violation_reason"),
            "governance_version": trace_payload.get("governance_version"),
            "chain_depth": trace_payload.get("chain_depth"),
            "context_id": trace_payload.get("context_id"),
            "chain_id": trace_payload.get("chain_id"),
            "parent_action_id": trace_payload.get("parent_action_id"),
            "parent_agent_id": trace_payload.get("parent_agent_id"),
            "enforcement_routing": routing,
            "triggered_controls": list(control_decision.triggered_controls),
            "dominant_control": control_decision.dominant_control,
            "control_decision_reasoning": control_decision.reasoning,
            "control_decision_total_risk": control_decision.total_risk_score,
            "risk_tags": list(control_decision.risk_tags),
        }
        final_actions_with_meta["_trace"] = trace_payload
        action_control = _build_gateway_action_control_envelope(
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            actor_type=actor_type,
            actor_id=actor_id,
            request_id=request_id,
            final_decision=final_decision,
            policy_version_id=policy_version_id,
            platform_mode=platform_mode,
            strictness_level=strictness_level,
            trace_payload=trace_payload,
            guardian_results=guardian_results,
            control_impacts=control_impacts,
            evidence_node_ids=[],
        )
        final_actions_with_meta["ai_action"] = action_control["ai_action"]
        final_actions_with_meta["decision_explanation"] = action_control["decision_explanation"]
        return {
            "event_id": request_id,
            "request_id": request_id,
            "final_decision": final_decision,
            "control_mode": action_control["control_mode"],
            "ai_action": action_control["ai_action"],
            "decision_explanation": action_control["decision_explanation"],
            "guardian_results": guardian_results,
            "final_actions": final_actions_with_meta,
            "evidence_nodes_created": [],
            "controls_impacted": control_impacts,
            "policy_version_id": policy_version_id,
            "strictness_level": strictness_level,
            "platform_mode": platform_mode,
            "audit_log_id": None,
            "approval_request_ids": [],
            "trace": trace_payload,
            "minimal_mode": True,
        }

    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=audit_actor_user_id,
        actor_type=actor_type,
        action="guardian_eval",
        resource_type="ai_system",
        resource_id=ai_system_id,
        payload={
            "request_id": request_id,
            "contract_mode": requested_contract_mode,
            "resolved_contract_mode": resolved_contract_mode,
            "policy_version_id": policy_version_id,
            "strictness_level": strictness_level,
            "platform_mode": platform_mode,
            "v1_guardian_count": len(guardians_v1),
            "v2_binding_count": len(v2_bindings),
            "guardian_results_count": len(guardian_results),
            "decision": final_decision,
            "workflow_policy_id": trace_payload.get("workflow_policy_id"),
            "violation_reason": trace_payload.get("violation_reason"),
            "enforcement_routing": routing,
            "trace": trace_payload,
        },
        correlation_id=correlation_id,
    )

    root_node = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="enforcement_event",
        signal_type="gateway.llm.intercept",
        label=f"LLM intercept {request_id}",
        payload={
            "ai_system_id": ai_system_id,
            "actor_id": actor_id,
            "policy_version_id": policy_version_id,
            "strictness_level": strictness_level,
            "platform_mode": platform_mode,
            "contract_mode": requested_contract_mode,
            "resolved_contract_mode": resolved_contract_mode,
            "workflow_policy_id": trace_payload.get("workflow_policy_id"),
            "violation_reason": trace_payload.get("violation_reason"),
            "enforcement_routing": routing,
            "trace": trace_payload,
        },
    )
    evidence_node_ids = [root_node.id]

    asymmetry_signal = detect_asymmetry_signal(
        prompt=prompt,
        tool_output=evaluated_output,
        attachments_meta=attachments_meta,
        small_prompt_threshold_chars=settings.asymmetry_small_prompt_threshold_chars,
        large_output_threshold_chars=settings.asymmetry_large_output_threshold_chars,
        output_ratio_threshold=settings.asymmetry_output_ratio_threshold,
        tool_call_threshold=settings.asymmetry_tool_call_threshold,
    )
    asymmetry_node_id: str | None = None
    if asymmetry_signal.get("triggered"):
        asymmetry_node = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="asymmetry_signal",
            signal_type="guardian.output_asymmetry.detected",
            label=f"Asymmetry heuristic {request_id}",
            payload={
                **asymmetry_signal,
                "ai_system_id": ai_system_id,
                "actor_id": actor_id,
                "policy_version_id": policy_version_id,
                "strictness_level": strictness_level,
            },
        )
        link_evidence_nodes(
            db,
            tenant_id=tenant_id,
            from_node_id=root_node.id,
            to_node_id=asymmetry_node.id,
            edge_type="flags",
            payload={
                "request_id": request_id,
                "signal_type": "guardian.output_asymmetry.detected",
            },
        )
        evidence_node_ids.append(asymmetry_node.id)
        asymmetry_node_id = asymmetry_node.id

    for result in guardian_results:
        guardian_contract_id = result.get("guardian_contract_id")
        guardian_id = result.get("guardian_id", "unknown")
        evidence_node_type = str(result.get("evidence_node_type") or "guardian_enforcement")
        evidence_signal_type = "guardian_enforcement_v2" if evidence_node_type == "guardian_enforcement_v2" else "guardian_enforcement"
        node = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type=evidence_node_type,
            signal_type=evidence_signal_type,
            label=f"Guardian {guardian_id} -> {result['decision']}",
            payload={
                **result,
                "guardian_contract_id": guardian_contract_id,
                "policy_version_id": policy_version_id,
                "contract_mode": requested_contract_mode,
                "resolved_contract_mode": resolved_contract_mode,
                "trace": trace_payload,
            },
        )
        link_evidence_nodes(
            db,
            tenant_id=tenant_id,
            from_node_id=root_node.id,
            to_node_id=node.id,
            edge_type="generated",
            payload={
                "request_id": request_id,
                "guardian_contract_id": guardian_contract_id,
                "contract_mode": requested_contract_mode,
                "resolved_contract_mode": resolved_contract_mode,
            },
        )
        evidence_node_ids.append(node.id)

    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=audit_actor_user_id,
        actor_type=actor_type,
        action="gateway.llm.intercept",
        resource_type="ai_system",
        resource_id=ai_system_id,
        payload={
            "request_id": request_id,
            "final_decision": final_decision,
            "guardian_results_count": len(guardian_results),
            "policy_version_id": policy_version_id,
            "strictness_level": strictness_level,
            "platform_mode": platform_mode,
            "contract_mode": requested_contract_mode,
            "resolved_contract_mode": resolved_contract_mode,
            "workflow_policy_id": trace_payload.get("workflow_policy_id"),
            "violation_reason": trace_payload.get("violation_reason"),
            "enforcement_routing": routing,
            "trace": trace_payload,
        },
        correlation_id=correlation_id,
    )

    final_actions_with_meta = dict(final_actions)
    if asymmetry_signal.get("triggered"):
        final_actions_with_meta["asymmetry_signal"] = {
            "risk_labels": asymmetry_signal.get("risk_labels", []),
            "simulation_schedule_hint": asymmetry_signal.get("simulation_schedule_hint"),
            "recommended_simulation_categories": asymmetry_signal.get("recommended_simulation_categories", []),
        }
    final_actions_with_meta["_meta"] = {
        "policy_version_id": policy_version_id,
        "risk_tier": ai_system.risk_tier,
        "strictness_level": strictness_level,
        "platform_mode": platform_mode,
        "governance_state": governance_status.get("status"),
        "governance_source": governance_status.get("source"),
        "governance_enforcement_mode": governance_status.get("enforcement_mode"),
        "contract_mode": requested_contract_mode,
        "resolved_contract_mode": resolved_contract_mode,
        "provider": trace_payload.get("provider"),
        "model_name": trace_payload.get("model"),
        "model_version": trace_payload.get("model_version"),
        "prompt_hash": trace_payload.get("prompt_hash"),
        "response_hash": trace_payload.get("response_hash"),
        "tool_name": trace_payload.get("tool_name"),
        "tool_category": trace_payload.get("tool_category"),
        "api_endpoint": trace_payload.get("api_endpoint"),
        "data_source": trace_payload.get("data_source"),
        "data_classification": trace_payload.get("data_classification"),
        "contains_sensitive": trace_payload.get("contains_sensitive"),
        "sensitive_confidence_score": trace_payload.get("sensitive_confidence_score"),
        "sensitive_entities": trace_payload.get("sensitive_entities"),
        "knowledge_asset_ids": trace_payload.get("knowledge_asset_ids"),
        "sensitivity_domain": trace_payload.get("sensitivity_domain"),
        "need_to_know_decision": trace_payload.get("need_to_know_decision"),
        "knowledge_disclosure_event": trace_payload.get("knowledge_disclosure_event"),
        "workflow_policy_id": trace_payload.get("workflow_policy_id"),
        "violation_reason": trace_payload.get("violation_reason"),
        "governance_version": trace_payload.get("governance_version"),
        "chain_depth": trace_payload.get("chain_depth"),
        "context_id": trace_payload.get("context_id"),
        "chain_id": trace_payload.get("chain_id"),
        "parent_action_id": trace_payload.get("parent_action_id"),
        "parent_agent_id": trace_payload.get("parent_agent_id"),
        "enforcement_routing": routing,
        "triggered_controls": list(control_decision.triggered_controls),
        "dominant_control": control_decision.dominant_control,
        "control_decision_reasoning": control_decision.reasoning,
        "control_decision_total_risk": control_decision.total_risk_score,
        "risk_tags": list(control_decision.risk_tags),
    }
    final_actions_with_meta["_trace"] = trace_payload
    action_control = _build_gateway_action_control_envelope(
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=request_id,
        final_decision=final_decision,
        policy_version_id=policy_version_id,
        platform_mode=platform_mode,
        strictness_level=strictness_level,
        trace_payload=trace_payload,
        guardian_results=guardian_results,
        control_impacts=control_impacts,
        evidence_node_ids=evidence_node_ids,
    )
    final_actions_with_meta["ai_action"] = action_control["ai_action"]
    final_actions_with_meta["decision_explanation"] = action_control["decision_explanation"]

    event = EnforcementEvent(
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        ai_system_id=ai_system_id,
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=request_id,
        timestamp=datetime.now(timezone.utc),
        input_prompt=encrypt_enforcement_prompt(prompt),
        input_context_summary=context_summary,
        input_attachments_meta=attachments_meta,
        guardian_results=guardian_results,
        final_decision=final_decision,
        final_actions=final_actions_with_meta,
        evidence_nodes_created=evidence_node_ids,
        controls_impacted=control_impacts,
        policy_version_id=policy_version_id,
        audit_log_id=audit.id,
    )
    db.add(event)
    db.flush()

    _emit_gateway_monitoring_signal(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        event_id=event.id,
        request_id=request_id,
        correlation_id=correlation_id,
        final_decision=final_decision,
        policy_version_id=policy_version_id,
        evidence_node_ids=evidence_node_ids,
        trace_payload=trace_payload,
    )

    approval_requests: list[str] = []
    if final_decision == "hold_for_approval" and approval_requirements:
        for requirement in approval_requirements:
            req = ApprovalRequest(
                tenant_id=tenant_id,
                enforcement_event_id=event.id,
                ai_system_id=ai_system_id,
                request_payload={
                    "request_id": request_id,
                    "guardian_id": requirement["guardian_id"],
                    "guardian_contract_id": requirement.get("guardian_contract_id"),
                    "prompt": prompt,
                },
                required_roles=requirement["required_roles"],
                sla_minutes=int(requirement["sla_minutes"]),
                default_if_timeout=str(requirement.get("default_if_timeout", "block")),
                status="pending",
            )
            db.add(req)
            db.flush()
            approval_requests.append(req.id)

    impacted_control_ids = sorted({item.get("control_id") for item in control_impacts if item.get("control_id")})
    if impacted_control_ids:
        recalculate_control_maturity(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            control_ids=impacted_control_ids,
            reason=f"enforcement_event:{event.id}:{final_decision}",
        )

    generate_from_enforcement_event(db, event=event)
    if asymmetry_node_id:
        generate_from_asymmetry_signal(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            evidence_node_id=asymmetry_node_id,
            risk_labels=[str(label) for label in (asymmetry_signal.get("risk_labels") or [])],
            policy_version_id=policy_version_id,
        )

    if settings.runtime_intelligence_schedule_simulations and not str(request_id).startswith("sim-"):
        from app.services.simulation_scheduler_service import (
            schedule_for_asymmetry_spike,
            schedule_for_repeated_enforcement_blocks,
        )

        if asymmetry_node_id:
            schedule_for_asymmetry_spike(
                db,
                tenant_id=tenant_id,
                ai_system_id=ai_system_id,
                evidence_node_id=asymmetry_node_id,
                risk_labels=[str(label) for label in (asymmetry_signal.get("risk_labels") or [])],
                actor_user_id=audit_actor_user_id,
            )
        if final_decision == "block":
            schedule_for_repeated_enforcement_blocks(
                db,
                tenant_id=tenant_id,
                ai_system_id=ai_system_id,
                actor_user_id=audit_actor_user_id,
            )

    try:
        from app.services.runtime_intelligence.runtime_event_normalizer import ingest_from_gateway_enforcement

        ingest_from_gateway_enforcement(db, event=event)
    except Exception as exc:  # pragma: no cover - non-blocking runtime enrichment
        if isinstance(exc, CanonicalProjectionError):
            raise
        log_structured(
            "runtime_intelligence_ingest_failed",
            module="gateway_service",
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            request_id=request_id,
            correlation_id=correlation_id,
            error=str(exc),
        )

    return {
        "event_id": event.id,
        "request_id": request_id,
        "final_decision": final_decision,
        "control_mode": action_control["control_mode"],
        "ai_action": action_control["ai_action"],
        "decision_explanation": action_control["decision_explanation"],
        "guardian_results": guardian_results,
        "final_actions": final_actions_with_meta,
        "evidence_nodes_created": evidence_node_ids,
        "controls_impacted": control_impacts,
        "policy_version_id": policy_version_id,
        "strictness_level": strictness_level,
        "platform_mode": platform_mode,
        "audit_log_id": audit.id,
        "approval_request_ids": approval_requests,
        "trace": trace_payload,
    }


@with_tenant_profile
def mcp_authorize(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    actor_id: str,
    capability_token: str,
    action: str,
    resource: str,
    chain_depth: int,
    request_id: str,
    audit_actor_user_id: str | None,
    provider: str | None = None,
    model_name: str | None = None,
    model_version: str | None = None,
    tool_name: str | None = None,
    tool_category: str | None = None,
    api_endpoint: str | None = None,
    data_source: str | None = None,
    tool_usage_meta: dict[str, Any] | list[dict[str, Any]] | None = None,
    context_id: str | None = None,
    chain_id: str | None = None,
    parent_action_id: str | None = None,
    parent_agent_id: str | None = None,
    session_id: str | None = None,
    initiating_user_id: str | None = None,
    session_context: dict[str, Any] | None = None,
    dynamic_permission: dict[str, Any] | None = None,
) -> dict[str, Any]:
    claimed_chain_depth = int(chain_depth)
    derived_chain_depth: int | None = None
    enforce_governance(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        action="gateway.mcp.authorize",
        route="/gateway/mcp/authorize",
        module="gateway_service",
        commit_logs=True,
    )
    governance_status = resolve_ai_system_status(
        ai_system_id,
        {
            "db": db,
            "tenant_id": tenant_id,
            "route": "/gateway/mcp/authorize",
            "module": "gateway_service",
            "source_hint": "trust_center",
        },
    )
    correlation_id = get_correlation_id()
    enforcement_event_request_id = _bounded_enforcement_event_request_id(
        tenant_id=tenant_id,
        request_id=request_id,
    )
    resolved_context_id = _normalized_optional(context_id) or _normalized_optional(correlation_id) or request_id
    resolved_chain_id = _normalized_optional(chain_id) or request_id
    resolved_parent_action_id = _normalized_optional(parent_action_id)
    ai_system = db.scalar(
        select(AISystem).where(
            AISystem.id == ai_system_id,
            AISystem.tenant_id == tenant_id,
        )
    )
    if not ai_system:
        raise ValueError("AI system not found for tenant")
    policy = get_latest_policy_for_ai_system(db, tenant_id, ai_system, "agent")
    policy_version_id = policy.id if policy else None
    workflow_policy = load_workflow_policy(policy)

    allowed, reason, token_row, agent, effective_scopes = validate_capability_token(
        db,
        tenant_id=tenant_id,
        raw_token=capability_token,
        required_scope=action,
        chain_depth=1,
    )
    chain_authority: DelegationChainDepthResult | None = None
    depth_authority_reason = reason
    if token_row is not None:
        chain_authority = resolve_persisted_delegation_chain_depth(
            db,
            tenant_id=tenant_id,
            agent_id=str(actor_id or "").strip(),
            capability_token_id=token_row.id,
            claimed_chain_depth=claimed_chain_depth,
            claimed_parent_agent_id=parent_agent_id,
            parent_action_id=resolved_parent_action_id,
            chain_id=resolved_chain_id,
            ai_system_id=ai_system_id,
            required_action=action,
        )
        derived_chain_depth = chain_authority.derived_depth
        chain_depth = derived_chain_depth or 1
        allowed, reason, token_row, agent, effective_scopes = validate_capability_token(
            db,
            tenant_id=tenant_id,
            raw_token=capability_token,
            required_scope=action,
            chain_depth=chain_depth,
        )
        if not chain_authority.allowed:
            allowed = False
            reason = chain_authority.reason_code
        depth_authority_reason = chain_authority.reason_code
    auto_quarantine_result: dict[str, Any] | None = None
    actor_agent_id_hint = _normalized_optional(actor_id)
    if (
        settings.ai_iam_auto_quarantine_new_agents
        and not allowed
        and agent is None
        and actor_agent_id_hint
        and reason in {"token_not_found", "agent_not_found"}
    ):
        auto_quarantine_result = auto_quarantine_agent_identity(
            db,
            tenant_id=tenant_id,
            discovered_agent_id=actor_agent_id_hint,
            source_surface="gateway",
            reason_code=f"mcp_authorize:{reason}",
            ai_system_id=ai_system_id,
            actor_user_id=audit_actor_user_id,
            metadata={
                "action": action,
                "resource": resource,
                "provider": provider,
                "model_name": model_name,
                "tool_name": tool_name,
                "api_endpoint": api_endpoint,
                "chain_depth": chain_depth,
                "request_id": request_id,
            },
            correlation_id=correlation_id,
        )
    quarantined_agent = (auto_quarantine_result or {}).get("agent")
    resolved_agent_identity_id = _normalized_optional((agent.id if agent else None) or getattr(quarantined_agent, "id", None))
    now = datetime.now(timezone.utc)
    normalized_session_context = dict(session_context or {})
    caller_dynamic_permission = dict(dynamic_permission or {})
    purpose_authority = resolve_persisted_purpose_bound_permission(
        db,
        tenant_id=tenant_id,
        user_id=audit_actor_user_id,
        agent_id=resolved_agent_identity_id,
        caller_permission=caller_dynamic_permission,
        now=now,
    )
    normalized_dynamic_permission = dict(purpose_authority.get("permission") or {})
    resolved_session_id = (
        _normalized_optional(session_id)
        or _normalized_optional(normalized_session_context.get("session_id"))
    )
    authenticated_user_id = _normalized_optional(audit_actor_user_id)
    if settings.mcp_persisted_sessions_required:
        persisted_session = validate_persisted_mcp_session(
            db,
            tenant_id=tenant_id,
            authenticated_user_id=authenticated_user_id,
            ai_system_id=ai_system_id,
            agent_id=resolved_agent_identity_id,
            capability_token_id=_normalized_optional(getattr(token_row, "id", None)),
            session_id=resolved_session_id,
            initiating_user_id=initiating_user_id,
            caller_context=normalized_session_context,
            purpose_permission_id=_normalized_optional(purpose_authority.get("session_id")),
            purpose_permission=(
                dict(purpose_authority.get("permission") or {})
                if isinstance(purpose_authority.get("permission"), dict)
                else None
            ),
            now=now,
        )
        session_row = persisted_session.get("session")
        normalized_session_context = dict(persisted_session.get("context") or {})
        initiating_user_from_session = _normalized_optional(persisted_session.get("initiating_user_id"))
        session_expiry_dt = persisted_session.get("expires_at")
        session_valid = bool(persisted_session.get("valid"))
        session_reason = str(persisted_session.get("reason") or "agent_session_not_found")
    else:
        session_row = db.get(AISession, resolved_session_id) if resolved_session_id else None
        if session_row is not None and str(session_row.tenant_id or "").strip() != tenant_id:
            session_row = None
        persisted_session_user_id = _normalized_optional(getattr(session_row, "user_id", None))
        caller_user_hint = (
            _normalized_optional(initiating_user_id)
            or _normalized_optional(normalized_session_context.get("initiating_user_id"))
            or _normalized_optional(normalized_session_context.get("user_id"))
        )
        initiating_user_from_session = authenticated_user_id or persisted_session_user_id
        server_expiry_candidates = [
            value
            for value in (
                _parse_optional_datetime(getattr(session_row, "end_time", None)),
                _parse_optional_datetime(getattr(token_row, "expires_at", None)),
            )
            if value is not None
        ]
        session_expiry_dt = (
            min(server_expiry_candidates)
            if server_expiry_candidates
            else (now + timedelta(minutes=max(1, int(getattr(settings, "access_token_expire_minutes", 30)))))
        )
        caller_expiry = (
            _parse_optional_datetime(normalized_dynamic_permission.get("expiry"))
            or _parse_optional_datetime(normalized_session_context.get("expiry"))
        )
        if caller_expiry is not None:
            session_expiry_dt = min(session_expiry_dt, caller_expiry)

        session_reason = "allow"
        session_valid = True
        if not resolved_session_id:
            session_valid = False
            session_reason = "agent_session_required"
        elif session_expiry_dt is not None and session_expiry_dt <= now:
            session_valid = False
            session_reason = "agent_session_expired"
        elif session_row is not None and str(session_row.status or "").strip().lower() not in {"active", ""}:
            session_valid = False
            session_reason = "agent_session_inactive"
        elif authenticated_user_id and caller_user_hint and caller_user_hint != authenticated_user_id:
            session_valid = False
            session_reason = "agent_session_user_mismatch"

        session_bound_agent = (
            _normalized_optional(normalized_session_context.get("agent_id"))
            or _normalized_optional(normalized_dynamic_permission.get("identity_id"))
            or _normalized_optional(_normalized_optional((getattr(session_row, "metadata_json", {}) or {}).get("agent_id")) if isinstance(getattr(session_row, "metadata_json", {}), dict) else None)
        )
        if session_valid and session_bound_agent and resolved_agent_identity_id and session_bound_agent != resolved_agent_identity_id:
            session_valid = False
            session_reason = "agent_session_agent_mismatch"

        if (
            session_valid
            and session_row is not None
            and initiating_user_from_session
            and _normalized_optional(getattr(session_row, "user_id", None))
            and initiating_user_from_session != _normalized_optional(getattr(session_row, "user_id", None))
        ):
            session_valid = False
            session_reason = "agent_session_user_mismatch"

    session_floor_required = bool(settings.mcp_persisted_sessions_required)
    session_bound_actions = _normalized_string_list(normalized_session_context.get("allowed_actions"))
    session_bound_tools = _normalized_string_list(normalized_session_context.get("allowed_tools"))
    session_bound_systems = _normalized_string_list(normalized_session_context.get("connected_systems"))
    session_bound_resources = _normalized_string_list(
        normalized_session_context.get("allowed_resources")
    )
    session_bound_data = _normalized_string_list(normalized_session_context.get("allowed_data_scope"))
    session_bound_depth = (
        int(normalized_session_context.get("max_chain_depth"))
        if isinstance(normalized_session_context.get("max_chain_depth"), int)
        and not isinstance(normalized_session_context.get("max_chain_depth"), bool)
        else None
    )
    session_floor_valid = bool(session_valid) if session_floor_required else True
    session_floor_reason = session_reason if session_floor_required and not session_valid else "allow"

    purpose_tools = _normalized_string_list(normalized_dynamic_permission.get("allowed_tools"))
    agent_tools = _normalized_string_list(getattr(agent, "tool_registry", [])) if agent is not None else []
    allowed_tools = _intersect_authority_lists(agent_tools, purpose_tools)
    if session_floor_required and session_valid:
        allowed_tools = (
            narrow_authority_values(allowed_tools, session_bound_tools)
            if session_bound_tools
            else []
        )

    purpose_actions = _normalized_string_list(normalized_dynamic_permission.get("allowed_actions"))
    token_actions = _normalized_string_list(effective_scopes or [])
    agent_actions = _normalized_string_list(getattr(agent, "action_scope", [])) if agent is not None else []
    allowed_actions = _intersect_authority_lists(token_actions, agent_actions, purpose_actions)
    if session_floor_required and session_valid:
        allowed_actions = (
            narrow_authority_values(allowed_actions, session_bound_actions)
            if session_bound_actions
            else []
        )

    allowed_data_scope = _normalized_string_list(normalized_dynamic_permission.get("allowed_data_scope"))
    if session_floor_required and session_valid:
        allowed_data_scope = (
            narrow_authority_values(allowed_data_scope, session_bound_data)
            if session_bound_data
            else []
        )
    purpose_scope = (
        dict(normalized_dynamic_permission.get("scope") or {})
        if isinstance(normalized_dynamic_permission.get("scope"), dict)
        else {}
    )
    purpose_resources = _normalized_string_list(
        normalized_dynamic_permission.get("allowed_resources")
        or purpose_scope.get("allowed_resources")
    )
    allowed_resources = list(purpose_resources)
    if session_floor_required and session_valid:
        allowed_resources = (
            narrow_authority_values(
                allowed_resources,
                session_bound_resources,
                kind="resource",
            )
            if session_bound_resources
            else []
        )
    data_scope_hint = (
        _normalized_optional(normalized_session_context.get("data_classification"))
        or _normalized_optional(normalized_dynamic_permission.get("data_classification"))
        or "unknown"
    )

    if session_floor_required and session_valid:
        if not session_bound_actions or not _authority_allows(action, session_bound_actions):
            session_floor_valid = False
            session_floor_reason = "agent_session_action_scope_denied"
        actual_tool_name = _normalized_optional(tool_name) or _normalized_optional(action)
        if session_floor_valid and (
            not session_bound_tools or not _authority_allows(actual_tool_name, session_bound_tools)
        ):
            session_floor_valid = False
            session_floor_reason = "agent_session_tool_scope_denied"
        if session_floor_valid and (
            not session_bound_data or not _authority_allows(data_scope_hint, session_bound_data)
        ):
            session_floor_valid = False
            session_floor_reason = "agent_session_data_scope_denied"
        if session_floor_valid and (
            not session_bound_resources
            or not _authority_allows(resource, session_bound_resources)
        ):
            session_floor_valid = False
            session_floor_reason = "agent_session_resource_scope_denied"

    dynamic_reason = "allow"
    dynamic_valid = bool(purpose_authority.get("valid"))
    if not dynamic_valid:
        dynamic_reason = str(purpose_authority.get("reason") or "persisted_purpose_permission_required")
    if session_valid and dynamic_valid and allowed_actions:
        action_allow = _normalized_lower_set(allowed_actions)
        normalized_action = str(action or "").strip().lower()
        if normalized_action not in action_allow and "*" not in action_allow:
            dynamic_valid = False
            dynamic_reason = "dynamic_action_scope_denied"
    if session_valid and dynamic_valid and purpose_actions and not _authority_allows(action, purpose_actions):
        dynamic_valid = False
        dynamic_reason = "dynamic_action_scope_denied"
    if session_valid and dynamic_valid and allowed_tools and _normalized_optional(tool_name):
        tool_allow = _normalized_lower_set(allowed_tools)
        normalized_tool = str(tool_name or "").strip().lower()
        if normalized_tool not in tool_allow and "*" not in tool_allow:
            dynamic_valid = False
            dynamic_reason = "dynamic_tool_scope_denied"
    normalized_tool_name = _normalized_optional(tool_name)
    if session_valid and dynamic_valid and normalized_tool_name and not _authority_allows(normalized_tool_name, agent_tools):
        dynamic_valid = False
        dynamic_reason = "agent_tool_registry_denied"
    if session_valid and dynamic_valid and normalized_tool_name and purpose_tools and not _authority_allows(
        normalized_tool_name,
        purpose_tools,
    ):
        dynamic_valid = False
        dynamic_reason = "dynamic_tool_scope_denied"
    if session_valid and dynamic_valid and allowed_data_scope:
        scope_allow = _normalized_lower_set(allowed_data_scope)
        if str(data_scope_hint or "").strip().lower() not in scope_allow and "*" not in scope_allow:
            dynamic_valid = False
            dynamic_reason = "dynamic_data_scope_denied"
    resource_authority_required = session_floor_required or bool(purpose_resources)
    if session_valid and dynamic_valid and resource_authority_required and (
        not allowed_resources or not _authority_allows(resource, allowed_resources)
    ):
        dynamic_valid = False
        dynamic_reason = "dynamic_resource_scope_denied"

    purpose_depth = (
        int(normalized_dynamic_permission.get("context", {}).get("max_chain_depth"))
        if isinstance(normalized_dynamic_permission.get("context"), dict)
        and str(normalized_dynamic_permission.get("context", {}).get("max_chain_depth") or "").strip().isdigit()
        else None
    )
    depth_authorities = [
        int(value)
        for value in (
            getattr(agent, "max_chain_depth", None),
            getattr(token_row, "chain_depth", None),
            purpose_depth,
            (session_bound_depth if session_floor_required and session_valid else None),
        )
        if value is not None
    ]
    chain_depth_limit = min(depth_authorities) if depth_authorities else max(1, int(chain_depth or 1))
    privilege_escalation_detected = bool(int(chain_depth or 0) > max(1, int(chain_depth_limit or 1)))
    if session_floor_required and session_valid and session_bound_depth is not None and int(chain_depth or 0) > session_bound_depth:
        session_floor_valid = False
        session_floor_reason = "agent_session_chain_depth_exceeded"

    target_host = _extract_host_hint(resource=resource, api_endpoint=api_endpoint)
    purpose_systems = _normalized_string_list(
        normalized_dynamic_permission.get("connected_systems")
        or (
            normalized_dynamic_permission.get("context", {}).get("connected_systems")
            if isinstance(normalized_dynamic_permission.get("context"), dict)
            else []
        )
    )
    if not purpose_systems:
        purpose_systems = _normalized_string_list(purpose_scope.get("allowed_domains"))
    agent_systems = (
        _normalized_string_list(getattr(agent, "external_system_access", [])) if agent is not None else []
    )
    known_systems = _intersect_authority_lists(agent_systems, purpose_systems)
    if session_floor_required and session_valid:
        known_systems = (
            narrow_authority_values(known_systems, session_bound_systems, kind="domain")
            if session_bound_systems
            else []
        )
    normalized_known_systems = _normalized_lower_set(known_systems)
    new_system_access_detected = bool(
        target_host
        and normalized_known_systems
        and not authority_host_matches(target_host, normalized_known_systems)
    )
    if session_valid and dynamic_valid and target_host and not _authority_allows(
        target_host,
        agent_systems,
        domain=True,
    ):
        dynamic_valid = False
        dynamic_reason = "agent_system_scope_denied"
    if session_valid and dynamic_valid and target_host and purpose_systems and not _authority_allows(
        target_host,
        purpose_systems,
        domain=True,
    ):
        dynamic_valid = False
        dynamic_reason = "dynamic_system_scope_denied"
    if session_floor_required and session_valid and target_host and (
        not session_bound_systems
        or not _authority_allows(target_host, session_bound_systems, domain=True)
    ):
        session_floor_valid = False
        session_floor_reason = "agent_session_destination_scope_denied"
    if session_floor_required and session_valid and not session_floor_valid:
        dynamic_valid = False
        dynamic_reason = session_floor_reason

    abnormal_tool_usage = bool(
        _normalized_optional(tool_name)
        and agent is not None
        and _normalized_string_list(getattr(agent, "tool_registry", []))
        and str(tool_name or "").strip().lower() not in _normalized_lower_set(_normalized_string_list(getattr(agent, "tool_registry", [])))
    )

    anomaly_score = 0.0
    anomaly_reasons: list[str] = []
    if not session_valid:
        anomaly_score += 0.55
        anomaly_reasons.append(session_reason)
    if privilege_escalation_detected:
        anomaly_score += 0.35
        anomaly_reasons.append("agent_privilege_escalation_detected")
    if not dynamic_valid:
        anomaly_score += 0.3
        anomaly_reasons.append(dynamic_reason)
    if new_system_access_detected:
        anomaly_score += 0.2
        anomaly_reasons.append("new_system_access_detected")
    if abnormal_tool_usage:
        anomaly_score += 0.2
        anomaly_reasons.append("abnormal_tool_usage_detected")
    anomaly_score = max(0.0, min(1.0, round(float(anomaly_score), 4)))

    if allowed and not session_valid:
        allowed = False
        reason = session_reason
    if allowed and not dynamic_valid:
        allowed = False
        reason = dynamic_reason
    if allowed and privilege_escalation_detected:
        allowed = False
        reason = "agent_privilege_escalation_detected"

    session_validation = {
        "session_id": resolved_session_id,
        "valid": bool(session_valid),
        "reason": session_reason,
        "bounds_enforcement": {
            "required": session_floor_required,
            "valid": bool(session_floor_valid),
            "reason": session_floor_reason,
            "max_chain_depth": session_bound_depth,
            "allowed_actions": session_bound_actions,
            "allowed_tools": session_bound_tools,
            "connected_systems": session_bound_systems,
            "allowed_resources": session_bound_resources,
            "allowed_data_scope": session_bound_data,
        },
        "initiating_user_id": initiating_user_from_session,
        "start_time": (
            _to_utc(getattr(session_row, "start_time")).isoformat()
            if session_row is not None and getattr(session_row, "start_time", None) is not None
            else now.isoformat()
        ),
        "expiry": session_expiry_dt.isoformat() if session_expiry_dt is not None else None,
        "context": normalized_session_context,
    }
    effective_purpose_scope = dict(purpose_scope)
    effective_purpose_context = (
        dict(normalized_dynamic_permission.get("context") or {})
        if isinstance(normalized_dynamic_permission.get("context"), dict)
        else {}
    )
    if agent_systems or purpose_systems:
        effective_purpose_context["connected_systems"] = known_systems
    dynamic_permission_record = {
        "identity_id": (resolved_agent_identity_id or actor_id),
        "permission_id": _normalized_optional(normalized_dynamic_permission.get("permission_id")),
        "identity_type": _normalized_optional(normalized_dynamic_permission.get("identity_type")) or "agent",
        "purpose": dict(normalized_dynamic_permission.get("purpose") or {}) if isinstance(normalized_dynamic_permission.get("purpose"), dict) else {},
        "scope": effective_purpose_scope,
        "constraints": dict(normalized_dynamic_permission.get("constraints") or {}) if isinstance(normalized_dynamic_permission.get("constraints"), dict) else {},
        "status": _normalized_optional(normalized_dynamic_permission.get("status")) or "active",
        "mode": _normalized_optional(normalized_dynamic_permission.get("mode")) or "block",
        "allowed_tools": allowed_tools,
        "allowed_resources": allowed_resources,
        "allowed_data_scope": allowed_data_scope,
        "allowed_actions": allowed_actions,
        "effective_scope": {
            "allowed_actions": allowed_actions,
            "allowed_tools": allowed_tools,
            "allowed_resources": allowed_resources,
            "connected_systems": known_systems,
            "max_chain_depth": max(1, int(chain_depth_limit or 1)),
        },
        "context": {
            **effective_purpose_context,
            "resource": _normalized_optional(resource),
            "api_endpoint": _normalized_optional(api_endpoint),
            "target_host": target_host,
            "max_chain_depth": max(1, int(chain_depth_limit or 1)),
            "session_id": resolved_session_id,
            "request_context": normalized_session_context,
        },
        "expiry": session_expiry_dt.isoformat() if session_expiry_dt is not None else None,
        "risk_level": _risk_level_for_score(anomaly_score),
    }
    purpose_permission = dynamic_permission_record if (
        dynamic_permission_record.get("permission_id")
        or dynamic_permission_record.get("purpose")
        or dynamic_permission_record.get("scope")
    ) else None
    resolved_action_category = action_category_for(action)
    resolved_action_risk = action_risk_for(
        action,
        environment=str(
            normalized_dynamic_permission.get("environment")
            or dynamic_permission_record.get("context", {}).get("environment")
            or normalized_session_context.get("environment")
            or "prod"
        ),
    )
    if not purpose_authority.get("valid"):
        purpose_reason = str(purpose_authority.get("reason") or "persisted_purpose_permission_required")
        purpose_result = {
            "decision": "block",
            "reason": purpose_reason,
            "purpose_bound_permission_id": None,
            "violations": [purpose_reason],
            "mode": "block",
            "allowed": False,
        }
    elif purpose_permission:
        purpose_result = evaluate_purpose_bound_permission(
            permission=purpose_permission,
            action_type=action,
            action_category=resolved_action_category,
            action_risk=resolved_action_risk,
            tool_name=(tool_name or action),
            target_resource=resource,
            domain=target_host,
            environment=str(
                normalized_dynamic_permission.get("environment")
                or dynamic_permission_record.get("context", {}).get("environment")
                or normalized_session_context.get("environment")
                or "prod"
            ),
            current_action_count=1,
        )
    else:
        purpose_result = {
            "decision": "allow",
            "reason": "no_purpose_bound_permission_provided",
            "violations": [],
            "matched_scope": {},
            "permission_id": None,
        }
    purpose_confirmation_pending = bool(
        purpose_permission
        and purpose_authority.get("valid")
        and purpose_result.get("decision") == "allow"
        and purpose_confirmation_required(
            purpose_permission,
            action_type=action,
            action_category=resolved_action_category,
            action_risk=resolved_action_risk,
        )
    )
    if purpose_confirmation_pending:
        purpose_result = {
            **purpose_result,
            "decision": "require_approval",
            "reason": "purpose_confirmation_required",
            "violations": ["purpose_confirmation_required"],
            "allowed": False,
        }
    if purpose_result["decision"] == "block":
        anomaly_score = max(anomaly_score, 0.65)
        if allowed:
            allowed = False
            reason = str(purpose_result.get("reason") or "action_outside_purpose_scope")
        if str(purpose_result.get("reason") or "").strip() not in anomaly_reasons:
            anomaly_reasons.append(str(purpose_result.get("reason") or "action_outside_purpose_scope"))
    over_scoped_flag = bool(
        ("*" in _normalized_lower_set(allowed_actions))
        or ("*" in _normalized_lower_set(allowed_tools))
        or (len(known_systems) >= 8)
        or (not dynamic_valid)
        or bool(purpose_result.get("violations"))
        or privilege_escalation_detected
        or new_system_access_detected
    )

    decision = "allow" if allowed else "block"
    if purpose_confirmation_pending and decision == "allow":
        decision = "hold_for_approval"
        reason = "purpose_confirmation_required"
    platform_mode = get_tenant_platform_mode(db, tenant_id=tenant_id)
    mcp_guardian_results = [
        {
            "guardian_id": "mcp_scope_guard",
            "decision": decision,
            "confidence": 1.0,
            "matched_conditions": [reason],
            "actions_taken": {
                "reason": reason,
                "effective_scopes": effective_scopes,
                "session_validation": session_validation,
                "dynamic_permission": dynamic_permission_record,
            },
            "threat_types": [],
        }
    ]
    if not session_valid:
        mcp_guardian_results.append(
            {
                "guardian_id": "agent_session_guard",
                "decision": "block",
                "confidence": 1.0,
                "matched_conditions": [session_reason],
                "actions_taken": {
                    "session_id": resolved_session_id,
                    "session_validation": session_validation,
                    "initiating_user_id": initiating_user_from_session,
                },
                "threat_types": ["agent_session_anomaly"],
            }
        )
    if not dynamic_valid or over_scoped_flag or privilege_escalation_detected or new_system_access_detected:
        mcp_guardian_results.append(
            {
                "guardian_id": "dynamic_permission_guard",
                "decision": ("block" if (not dynamic_valid or privilege_escalation_detected) else "warn"),
                "confidence": max(0.7, anomaly_score),
                "matched_conditions": [
                    *([dynamic_reason] if not dynamic_valid else []),
                    *(["agent_privilege_escalation_detected"] if privilege_escalation_detected else []),
                    *(["new_system_access_detected"] if new_system_access_detected else []),
                ],
                "actions_taken": {
                    "dynamic_permission": dynamic_permission_record,
                    "over_scoped_flag": over_scoped_flag,
                    "known_systems": known_systems,
                    "target_host": target_host,
                },
                "threat_types": ["agent_over_scope_risk"],
            }
        )
    if bool((auto_quarantine_result or {}).get("created")) and resolved_agent_identity_id:
        mcp_guardian_results.append(
            {
                "guardian_id": "auto_quarantine_guard",
                "decision": "block",
                "confidence": 1.0,
                "matched_conditions": ["new_agent_detected", "auto_quarantine_enabled"],
                "actions_taken": {
                    "agent_id": resolved_agent_identity_id,
                    "status": "quarantined",
                    "reason": "newly discovered agent auto-quarantined pending approval",
                },
                "threat_types": ["unknown_agent_identity"],
            }
        )
    decision, mcp_guardian_results, mcp_final_actions = _apply_discovery_mode_decision_override(
        platform_mode=platform_mode,
        final_decision=decision,
        guardian_results=mcp_guardian_results,
        final_actions={
            "mcp": {"reason": reason, "effective_scopes": effective_scopes},
            "session": session_validation,
            "dynamic_permission": dynamic_permission_record,
            "anomaly_score": anomaly_score,
        },
        risk_tier=ai_system.risk_tier,
        reason_hint=reason,
    )
    if anomaly_score >= 0.85 and decision in {"allow", "warn", "redact", "hold_for_approval"}:
        decision = "block"
        mcp_guardian_results.append(
            {
                "guardian_id": "runtime_anomaly_guard",
                "decision": "block",
                "confidence": anomaly_score,
                "matched_conditions": sorted(set(anomaly_reasons)),
                "actions_taken": {
                    "anomaly_score": anomaly_score,
                    "session_validation": session_validation,
                    "dynamic_permission": dynamic_permission_record,
                },
                "threat_types": ["agent_session_anomaly", "agent_over_scope_risk"],
            }
        )
    elif anomaly_score >= 0.65 and decision in {"allow", "warn"}:
        decision = "hold_for_approval"
        mcp_guardian_results.append(
            {
                "guardian_id": "runtime_anomaly_guard",
                "decision": "hold_for_approval",
                "confidence": anomaly_score,
                "matched_conditions": sorted(set(anomaly_reasons)),
                "actions_taken": {
                    "anomaly_score": anomaly_score,
                    "session_validation": session_validation,
                    "dynamic_permission": dynamic_permission_record,
                },
                "threat_types": ["agent_session_anomaly", "agent_over_scope_risk"],
            }
        )
    elif anomaly_score >= 0.45 and decision == "allow":
        decision = "warn"
        mcp_guardian_results.append(
            {
                "guardian_id": "runtime_anomaly_guard",
                "decision": "warn",
                "confidence": anomaly_score,
                "matched_conditions": sorted(set(anomaly_reasons)),
                "actions_taken": {
                    "anomaly_score": anomaly_score,
                    "session_validation": session_validation,
                    "dynamic_permission": dynamic_permission_record,
                },
                "threat_types": ["agent_session_anomaly", "agent_over_scope_risk"],
            }
        )
    if chain_authority is not None and not chain_authority.allowed:
        allowed = False
        decision = "block"
        reason = chain_authority.reason_code
        mcp_guardian_results.append(
            {
                "guardian_id": "persisted_delegation_chain_guard",
                "decision": "block",
                "confidence": 1.0,
                "matched_conditions": [chain_authority.reason_code],
                "actions_taken": {
                    "claimed_chain_depth": chain_authority.claimed_depth,
                    "derived_chain_depth": chain_authority.derived_depth,
                    "claimed_parent_action_id": resolved_parent_action_id,
                    "derived_parent_agent_id": chain_authority.parent_agent_id,
                    "delegation_ids": list(chain_authority.delegation_ids),
                },
                "threat_types": ["delegation_chain_authority_mismatch"],
            }
        )
    if reason == "allow" and anomaly_reasons:
        reason = anomaly_reasons[0]
    mcp_final_actions["session"] = session_validation
    mcp_final_actions["dynamic_permission"] = dynamic_permission_record
    mcp_final_actions["anomaly_score"] = anomaly_score
    mcp_final_actions["over_scoped_flag"] = over_scoped_flag
    mcp_final_actions["new_system_access_detected"] = new_system_access_detected
    mcp_final_actions["privilege_escalation_detected"] = privilege_escalation_detected
    mcp_final_actions["abnormal_tool_usage_detected"] = abnormal_tool_usage
    evidence_node_ids: list[str] = []
    trace_payload = _build_gateway_trace_payload(
        correlation_id=correlation_id,
        request_id=request_id,
        policy_version_id=policy_version_id,
        provider=provider,
        model_name=model_name,
        model_version=model_version,
        prompt=f"MCP action={action} resource={resource}",
        response_text=None,
        context_summary="mcp_authorize",
        tool_name=(tool_name or action),
        tool_category=(tool_category or "mcp_authorization"),
        api_endpoint=(api_endpoint or "/gateway/mcp/authorize"),
        data_source=data_source,
        tool_usage_meta=tool_usage_meta,
        attachments_meta=[],
        context_id=resolved_context_id,
        chain_id=resolved_chain_id,
        chain_depth=chain_depth,
        parent_action_id=resolved_parent_action_id,
        parent_agent_id=resolved_agent_identity_id,
        session_id=resolved_session_id,
        initiating_user_id=initiating_user_from_session,
        session_expiry=session_validation.get("expiry"),
        session_validation=session_validation,
        dynamic_permission=dynamic_permission_record,
        anomaly_score=anomaly_score,
    )
    trace_payload.update(
        {
            "chain_depth": derived_chain_depth,
            "claimed_chain_depth": claimed_chain_depth,
            "derived_chain_depth": derived_chain_depth,
            "chain_depth_authority_reason": depth_authority_reason,
            "claimed_parent_agent_id": _normalized_optional(parent_agent_id),
            "derived_parent_agent_id": (
                chain_authority.parent_agent_id if chain_authority is not None else None
            ),
            "delegation_ids": (
                list(chain_authority.delegation_ids) if chain_authority is not None else []
            ),
            "capability_token_id": (token_row.id if token_row is not None else None),
            "delegation_edge_id": (
                chain_authority.delegation_ids[0]
                if chain_authority is not None and chain_authority.delegation_ids
                else None
            ),
            "persisted_delegation_depth_claims": (
                list(chain_authority.stored_depths) if chain_authority is not None else []
            ),
        }
    )
    decision, provider_overlay = _apply_provider_enforcement_overlay(
        platform_mode=platform_mode,
        decision=decision,
        trace_payload=trace_payload,
    )
    if provider_overlay is not None:
        mcp_guardian_results.append(
            {
                "guardian_id": "provider_surface_guard",
                "decision": decision,
                "confidence": 0.95,
                "matched_conditions": [str(provider_overlay.get("reason_code") or "provider_overlay")],
                "actions_taken": {
                    "reason_code": provider_overlay.get("reason_code"),
                    "provider": provider_overlay.get("provider"),
                    "model_name": provider_overlay.get("model_name"),
                },
                "threat_types": ["unknown_ai_model_usage"] if bool(provider_overlay.get("open_source_model_hint")) else ["provider_review"],
                "provider_overlay": provider_overlay,
            }
        )
        mcp_final_actions["provider_overlay"] = provider_overlay
    sensitive_overlay_decision, sensitive_overlay = _apply_sensitive_policy_overlay(
        platform_mode=platform_mode,
        decision=decision,
        trace_payload=trace_payload,
    )
    if sensitive_overlay is not None:
        decision = _aggregate_guardian_decisions([decision, sensitive_overlay_decision])
        mcp_guardian_results.append(
            {
                "guardian_id": "sensitive_data_guard",
                "decision": decision,
                "confidence": max(0.8, float(trace_payload.get("sensitive_confidence_score") or 0.8)),
                "matched_conditions": ["data.contains_sensitive", "destination.trust_level"],
                "actions_taken": {
                    "reason_code": sensitive_overlay.get("reason_code"),
                    "contains_sensitive": True,
                    "sensitive_entities": list(sensitive_overlay.get("sensitive_entities") or []),
                },
                "threat_types": ["sensitive_data_leakage"],
                "sensitive_overlay": sensitive_overlay,
            }
        )
        mcp_final_actions["sensitive_data_overlay"] = sensitive_overlay
    mcp_integrity = evaluate_mcp_tool_call_integrity(
        db,
        tenant_id=tenant_id,
        chain_id=resolved_chain_id,
        action_id=request_id,
        agent_id=(resolved_agent_identity_id or actor_id),
        action=action,
        resource=resource,
        tool_name=(tool_name or action),
        tool_version=_normalized_optional(_extract_tool_usage_field(tool_usage_meta, "tool_version")),
        tool_fingerprint_id=_normalized_optional(
            _extract_tool_usage_field(tool_usage_meta, "tool_fingerprint_id")
        ),
        mcp_server_id=_normalized_optional(_extract_tool_usage_field(tool_usage_meta, "mcp_server_id")),
        api_endpoint=api_endpoint,
        parameters=_extract_tool_usage_field(tool_usage_meta, "parameters"),
        current_decision=decision,
    )
    mcp_integrity_decision = str(mcp_integrity.get("decision") or "allow")
    mapped_mcp_integrity_decision = (
        "hold_for_approval" if mcp_integrity_decision == "require_approval" else mcp_integrity_decision
    )
    if mapped_mcp_integrity_decision != "allow":
        prior_decision = decision
        decision = _aggregate_guardian_decisions([prior_decision, mapped_mcp_integrity_decision])
        if AGGREGATION_PRECEDENCE.index(mapped_mcp_integrity_decision) < AGGREGATION_PRECEDENCE.index(
            prior_decision
        ):
            reason = (
                "mcp_integrity:"
                + ",".join(str(item) for item in (mcp_integrity.get("risk_factors") or [])[:4])
            )
        mcp_guardian_results.append(
            {
                "guardian_id": "mcp_tool_integrity_guard",
                "decision": decision,
                "confidence": 0.95,
                "matched_conditions": list(mcp_integrity.get("risk_factors") or []),
                "actions_taken": {
                    "mcp_server_id": mcp_integrity.get("mcp_server_id"),
                    "tool_name": mcp_integrity.get("tool_name"),
                    "tool_version": mcp_integrity.get("tool_version"),
                    "trust_status": mcp_integrity.get("trust_status"),
                    "control_mode": mcp_integrity.get("control_mode"),
                    "evidence_bundle_id": mcp_integrity.get("evidence_bundle_id"),
                },
                "threat_types": list(mcp_integrity.get("finding_types") or ["mcp_tool_integrity_risk"]),
            }
        )
    if mcp_integrity.get("evidence_bundle_id"):
        evidence_node_ids.append(str(mcp_integrity["evidence_bundle_id"]))
    mcp_final_actions["mcp_integrity"] = mcp_integrity
    trace_payload["mcp_integrity"] = mcp_integrity
    if str(action or "").upper().startswith("REPOSITORY_"):
        repository_parameters = _extract_tool_usage_field(tool_usage_meta, "parameters")
        repository_parameters = repository_parameters if isinstance(repository_parameters, dict) else {}
        repository_guard = evaluate_github_repository_mutation(
            db,
            tenant_id=tenant_id,
            action=action,
            resource=resource,
            branch=_normalized_optional(repository_parameters.get("branch")),
            actor_id=actor_id,
            ai_system_id=ai_system_id,
            provider=provider,
            model=model_name,
            agent_id=resolved_agent_identity_id or actor_id,
            tool_fingerprint_id=_normalized_optional(_extract_tool_usage_field(tool_usage_meta, "tool_fingerprint_id")),
            tool_schema_fingerprint=_normalized_optional(_extract_tool_usage_field(tool_usage_meta, "tool_schema_fingerprint")),
            change_digest=_normalized_optional(repository_parameters.get("change_digest")),
            approval_binding_id=_normalized_optional(repository_parameters.get("approval_binding_id")),
        )
        repository_guard_decision = str(repository_guard["decision"]).lower()
        if repository_guard_decision == "hold_for_approval":
            repository_guard_decision = "hold_for_approval"
        decision = _aggregate_guardian_decisions([decision, repository_guard_decision])
        mcp_guardian_results.append(
            {
                "guardian_id": "github_repository_identity_guard",
                "decision": repository_guard_decision,
                "confidence": 1.0,
                "matched_conditions": [str(repository_guard.get("reason") or "repository_guard")],
                "actions_taken": {"repository_id": repository_guard.get("repository_id")},
                "threat_types": ["repository_authorization"],
            }
        )
        mcp_final_actions["github_repository_guard"] = repository_guard
        trace_payload["github_repository_guard"] = repository_guard
    tool_provenance_path: dict[str, Any] = {}
    requested_tool_binding_id = _normalized_optional(
        _extract_tool_usage_field(tool_usage_meta, "tool_binding_id")
    )
    if requested_tool_binding_id:
        try:
            tool_provenance_path = InstructionToolProvenanceService(
                db,
                signing_provider=db.info.get("phase5_signing_provider"),
            ).action_reference_projection(
                tenant_id=tenant_id,
                binding_id=requested_tool_binding_id,
                action_id=request_id,
                tool_name=(tool_name or action),
                tool_fingerprint_id=_normalized_optional(
                    _extract_tool_usage_field(tool_usage_meta, "material_fingerprint")
                ),
            )
        except (PermissionError, ValueError):
            decision = "block"
            reason = "tool_principal_binding_mismatch"
            mcp_guardian_results.append(
                {
                    "guardian_id": "tool_principal_binding_guard",
                    "decision": "block",
                    "confidence": 1.0,
                    "matched_conditions": ["tool_principal_binding_mismatch"],
                    "actions_taken": {"tool_binding_id": requested_tool_binding_id},
                    "threat_types": ["mcp_tool_identity_mismatch"],
                }
            )
    if tool_provenance_path:
        mcp_final_actions["tool_provenance"] = tool_provenance_path
        trace_payload["tool_provenance"] = tool_provenance_path
    workflow_evaluation = evaluate_workflow_policy(
        workflow_policy,
        agent_id=(resolved_agent_identity_id or actor_id),
        tool_name=(trace_payload.get("tool_name") or tool_name or action),
        chain_depth=chain_depth,
        data_classification=str(trace_payload.get("data_classification") or "unknown"),
        available_control_ids=["CTRL-AI-IAM-001"],
    )
    workflow_decision = _map_workflow_to_gateway_decision(workflow_evaluation.decision)
    trace_payload["workflow_policy_id"] = workflow_evaluation.workflow_policy_id
    trace_payload["violation_reason"] = workflow_evaluation.violation_reason
    if workflow_evaluation.violation_reason:
        decision = _aggregate_guardian_decisions([decision, workflow_decision])
        mcp_guardian_results.append(
            {
                "guardian_id": "workflow_policy_guard",
                "decision": workflow_decision,
                "confidence": 1.0,
                "matched_conditions": list(workflow_evaluation.matched_violations or []),
                "actions_taken": {
                    "workflow_policy_id": workflow_evaluation.workflow_policy_id,
                    "violation_reason": workflow_evaluation.violation_reason,
                    "matched_violations": list(workflow_evaluation.matched_violations or []),
                },
                "threat_types": ["workflow_policy_violation"],
            }
        )
    mcp_final_actions["workflow_policy"] = {
        "workflow_policy_id": workflow_evaluation.workflow_policy_id,
        "violation_reason": workflow_evaluation.violation_reason,
        "matched_violations": list(workflow_evaluation.matched_violations or []),
        "decision": workflow_decision,
    }
    scoped_policy = resolve_scoped_policy_decision(
        db,
        tenant_id=tenant_id,
        policy_version_id=policy_version_id,
        context={
            "actor_type": "agent",
            "actor_user_id": audit_actor_user_id,
            "actor_role": None,
            "actor_department": None,
            "agent_id": (resolved_agent_identity_id or actor_id),
            "endpoint_id": _normalized_optional(trace_payload.get("endpoint_id")),
            "source_surface": "gateway",
            "action_type": "agent_action",
            "operation": action,
            "domain": trace_payload.get("api_endpoint"),
            "tool_name": (tool_name or action),
            "provider": trace_payload.get("provider"),
            "model": trace_payload.get("model"),
            "ai_system_id": ai_system_id,
            "data_classification": trace_payload.get("data_classification"),
            "contains_sensitive": bool(trace_payload.get("contains_sensitive")),
            "risk_tier": ai_system.risk_tier,
        },
    )
    mcp_final_actions["scoped_policy"] = scoped_policy.to_dict()
    hard_block_active = (not allowed) or purpose_confirmation_pending
    if scoped_policy.matched:
        scoped_decision = _map_scoped_gateway_decision(scoped_policy.decision, fallback=decision)
        if (
            AGGREGATION_PRECEDENCE.index(scoped_decision) < AGGREGATION_PRECEDENCE.index(decision)
            or (AGGREGATION_PRECEDENCE.index(scoped_decision) > AGGREGATION_PRECEDENCE.index(decision) and not hard_block_active)
        ):
            decision = scoped_decision
            mcp_guardian_results.append(
                {
                    "guardian_id": "scoped_policy",
                    "decision": decision,
                    "confidence": 1.0,
                    "matched_conditions": list(scoped_policy.matched_selectors or []),
                    "actions_taken": {
                        "reason_code": str(scoped_policy.reason_code or "scoped_policy_matched"),
                        "explanation": str(scoped_policy.explanation or ""),
                        "policy_version_id": str(scoped_policy.policy_version_id or policy_version_id or ""),
                    },
                    "threat_types": ["policy_scope_override"],
                }
            )
    mcp_hinted_controls: list[str] = []
    if not allowed:
        mcp_hinted_controls.extend(
            [
                "AGENT_ACTION_AUTHORIZATION",
                "TOOL_CALL_VALIDATION",
                "TOKEN_SCOPE_ENFORCEMENT",
                "POLICY_ENFORCEMENT_CONTROL",
            ]
        )
    elif decision in {"warn", "hold_for_approval", "block", "redact"}:
        mcp_hinted_controls.append("POLICY_ENFORCEMENT_CONTROL")
    if not session_valid:
        mcp_hinted_controls.extend(["AI_IDENTITY_BINDING", "NON_HUMAN_IDENTITY_CONTROL"])
    if over_scoped_flag or privilege_escalation_detected:
        mcp_hinted_controls.extend(["PRIVILEGE_DRIFT_DETECTION", "AGENT_ACTION_AUTHORIZATION"])
    if new_system_access_detected:
        mcp_hinted_controls.extend(["TOKEN_SCOPE_ENFORCEMENT", "CHAIN_OF_ACTION_VALIDATION"])
    if str(governance_status.get("status") or "").upper() == "UNKNOWN":
        mcp_hinted_controls.extend(["AI_SYSTEM_INVENTORY_CONTROL", "SHADOW_AI_DETECTION"])
    mcp_control_decision = evaluate_control_engine(
        AIAction(
            action_id=request_id,
            user_id=None,
            ai_app=str(ai_system_id or "").strip() or None,
            model=(trace_payload.get("model") or trace_payload.get("model_version")),
            prompt=f"MCP action={action} resource={resource}",
            metadata={
                "source_surface": "agent",
                "action_type": "agent_action",
                "decision": decision,
                "reason_code": reason,
                "input_signal_types": [str(reason), str(action), str(resource)],
                "data_classification": str(trace_payload.get("data_classification") or "unknown"),
                "governance_status": str(governance_status.get("status") or "UNKNOWN"),
                "chain_depth": chain_depth,
                "triggered_controls": mcp_hinted_controls,
            },
            source_surface="agent",
        ),
        base_decision=decision,
        hinted_control_ids=mcp_hinted_controls,
    )
    mcp_engine_gateway_decision = _map_control_engine_gateway_decision(
        mcp_control_decision.decision,
        fallback=decision,
    )
    if _aggregate_guardian_decisions([decision, mcp_engine_gateway_decision]) != decision:
        decision = _aggregate_guardian_decisions([decision, mcp_engine_gateway_decision])
        mcp_guardian_results.append(
            {
                "guardian_id": "control_engine",
                "decision": decision,
                "confidence": 1.0,
                "matched_conditions": ["central_control_engine"],
                "actions_taken": {
                    "reason_code": "control_engine_escalation",
                    "dominant_control": mcp_control_decision.dominant_control,
                    "triggered_controls": list(mcp_control_decision.triggered_controls),
                    "total_risk_score": mcp_control_decision.total_risk_score,
                },
                "threat_types": list(mcp_control_decision.risk_tags or []),
            }
        )
    mcp_final_actions["control_decision"] = mcp_control_decision.to_dict()
    decision = _apply_threat_detectors(
        final_decision=decision,
        guardian_results=mcp_guardian_results,
        final_actions=mcp_final_actions,
        prompt=" ".join(str(part) for part in [action, resource, tool_name] if part),
        tool_output=tool_usage_meta,
        surface="mcp",
    )
    routing = route_enforcement(
        {"policy_id": (policy_version_id or "mcp_authorize"), "policy_version": (policy.version if policy else "v1")},
        {
            "event_id": request_id,
            "tenant_id": tenant_id,
            "source_surface": "agent",
            "action_type": "agent_action",
            "ai_system_id": ai_system_id,
            "agent_id": (resolved_agent_identity_id or actor_id),
            "data_classification": trace_payload.get("data_classification"),
            "correlation_id": correlation_id,
            "context_id": resolved_context_id,
            "chain_id": resolved_chain_id,
            "parent_action_id": resolved_parent_action_id,
        },
    )

    if chain_authority is not None and not chain_authority.allowed:
        decision = "block"
        reason = chain_authority.reason_code
    elif derived_chain_depth is None:
        decision = "block"
        reason = depth_authority_reason

    effective_purpose_result = dict(purpose_result)
    if effective_purpose_result.get("decision") == "allow" and decision not in {"allow", ""}:
        effective_purpose_result.update(
            {
                "decision": "shadow_would_block" if dynamic_permission_record.get("mode") == "shadow" else decision,
                "reason": reason or effective_purpose_result.get("reason") or "policy_enforced",
                "violations": list(effective_purpose_result.get("violations") or [reason or decision]),
            }
        )
    workflow_risk_context = {
        "workflow_id": resolved_chain_id or resolved_context_id or request_id,
        "previous_action_count": 0,
        "cumulative_risk_score": max(
            float(anomaly_score or 0.0),
            0.65 if effective_purpose_result.get("decision") in {"block", "shadow_would_block"} else 0.0,
        ),
        "scope_drift_score": 0.6 if new_system_access_detected or bool(effective_purpose_result.get("violations")) else 0.0,
        "privilege_escalation_score": 0.7 if privilege_escalation_detected else 0.0,
        "recent_violations_count": 1 if effective_purpose_result.get("decision") in {"block", "shadow_would_block"} else 0,
        "risk_drivers": sorted(
            {
                *[str(item) for item in (effective_purpose_result.get("violations") or []) if str(item).strip()],
                *[str(item) for item in anomaly_reasons if str(item).strip()],
            }
        ),
    }
    mcp_parameters = _extract_tool_usage_field(tool_usage_meta, "parameters")
    server_parameter_hash = (
        _hash_text(
            json.dumps(
                mcp_parameters,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
        )
        if mcp_parameters is not None
        else None
    )
    persisted_kernel_policy = (
        dict((policy.enforcement_defaults or {}).get("authorization_kernel_v2") or {})
        if policy is not None
        and isinstance(policy.enforcement_defaults, dict)
        and isinstance((policy.enforcement_defaults or {}).get("authorization_kernel_v2"), dict)
        else {}
    )
    expected_parameter_hashes = persisted_kernel_policy.get("mcp_expected_parameter_hashes")
    expected_parameter_hash = (
        _normalized_optional(expected_parameter_hashes.get(tool_name or action))
        if isinstance(expected_parameter_hashes, dict)
        else None
    )

    raw_resource = resource
    raw_api_endpoint = api_endpoint
    raw_tool_usage_meta = tool_usage_meta

    def persistence_view(value: Any) -> Any:
        return _mcp_persistence_view(
            value,
            resource=raw_resource,
            api_endpoint=raw_api_endpoint,
            parameters=mcp_parameters,
            tool_usage_meta=raw_tool_usage_meta,
        )

    trace_payload = persistence_view(trace_payload)
    mcp_final_actions = persistence_view(mcp_final_actions)
    mcp_guardian_results = persistence_view(mcp_guardian_results)
    session_validation = persistence_view(session_validation)
    dynamic_permission_record = persistence_view(dynamic_permission_record)
    normalized_session_context = persistence_view(normalized_session_context)
    purpose_permission = persistence_view(purpose_permission)
    effective_purpose_result = persistence_view(effective_purpose_result)
    workflow_risk_context = persistence_view(workflow_risk_context)
    effective_scopes = persistence_view(effective_scopes)
    routing = persistence_view(routing)
    reason = persistence_view(reason)
    resource = persistence_view({"resource": raw_resource})["resource"]
    api_endpoint = persistence_view({"api_endpoint": raw_api_endpoint})[
        "api_endpoint"
    ]
    tool_usage_meta = persistence_view(
        {"tool_usage_meta": raw_tool_usage_meta}
    )["tool_usage_meta"]

    pre_action_governance_check = build_pre_action_governance_check(
        tenant_id=tenant_id,
        action_id=request_id,
        source_event_id=None,
        actor={
            "identity_id": resolved_agent_identity_id or actor_id,
            "identity_type": "agent",
            "agent_id": resolved_agent_identity_id or actor_id,
            "session_id": resolved_session_id,
            "acting_on_behalf_of_user_id": initiating_user_from_session,
        },
        authority={
            "authority_type": "delegated_agent" if resolved_session_id else "api_key",
            "authority_owner": initiating_user_from_session,
            "authority_source": "mcp_authorize",
            "auth_strength": "session_bound" if session_valid else "weak_or_missing_session",
            "standing_privilege": not bool(purpose_permission),
            "permission_scope": list(effective_scopes or []),
            "verified": bool(allowed and token_row is not None and session_valid),
        },
        purpose_permission=purpose_permission,
        purpose_result=effective_purpose_result,
        surface={
            "surface_type": "mcp",
            "application": tool_name or resource,
            "provider": provider,
            "model": model_name,
            "mcp_server_id": mcp_integrity.get("mcp_server_id"),
            "domain": target_host,
            "url": api_endpoint,
            "asset_id": ai_system_id,
            "environment": str(normalized_session_context.get("environment") or "prod"),
            "asset_status": str(governance_status.get("status") or "UNKNOWN").lower(),
        },
        action={
            "action_type": "tool_execution",
            "action_category": resolved_action_category,
            "operation": action,
            "action_risk": resolved_action_risk,
            "target_resource": resource,
            "data_destination": (
                _normalized_optional(
                    _extract_tool_usage_field(tool_usage_meta, "data_destination")
                )
                or _normalized_optional(api_endpoint)
                or target_host
            ),
            "tool_name": tool_name or action,
            "mcp_server": target_host,
            "tool_version": mcp_integrity.get("tool_version"),
            "tool_fingerprint_id": mcp_integrity.get("tool_fingerprint_id"),
            "parameter_hash": server_parameter_hash,
            "expected_parameter_hash": expected_parameter_hash,
            "side_effect_class": resolved_action_category,
            "persistent_side_effect": resolved_action_category != "read",
        },
        workflow_risk_context=workflow_risk_context,
        policy_snapshot_id=policy_version_id or "mcp_authorize",
        policy_ids=[policy_version_id or "AI_ACTION_BOUNDARY_CONTROL"],
        control_ids=list(mcp_control_decision.triggered_controls),
        evidence_refs=[],
        trace_id=correlation_id or request_id,
        inline=True,
    )
    if tool_provenance_path:
        pre_action_governance_check["path_evidence"] = tool_provenance_path
    from app.core.control_engine.authorization import (
        apply_trusted_pre_action_rollout,
        authorization_rollout_persistence_metadata,
    )

    v2_rollout = apply_trusted_pre_action_rollout(
        tenant_id=tenant_id,
        surface="mcp_gateway",
        action_id=request_id,
        chain_id=resolved_chain_id,
        collector_id="mcp-gateway-authorize",
        trusted_pre_action_governance_check=pre_action_governance_check,
        legacy_decision=decision,
        legacy_reason=reason or "mcp_gateway_authorize",
        legacy_control_mode=control_mode_for_pre_action_decision(decision, inline=True),
        policy_snapshot_id=policy_version_id or "mcp_authorize",
        settings_obj=settings,
    )
    if (
        v2_rollout.enforced
        and settings.native_control_framework
        and settings.trusted_control_selector
    ):
        from app.services.native_control.selection_service import (
            apply_native_selection_to_rollout,
        )

        v2_rollout = apply_native_selection_to_rollout(
            db,
            rollout=v2_rollout,
            settings_obj=settings,
        )
    if v2_rollout.enforced:
        pre_action_governance_check["authorization_kernel_v2_precomputed"] = (
            authorization_rollout_persistence_metadata(v2_rollout)
        )
        if settings.decision_execution_receipts_enabled:
            from app.services.receipt_service import (
                create_decision_receipt_from_authorization,
                record_execution_incomplete,
                record_execution_unknown,
            )

            if v2_rollout.request is None or v2_rollout.v2_response is None:
                raise RuntimeError("selected authorization result lacks receipt material")
            decision_receipt, _ = create_decision_receipt_from_authorization(
                db,
                request=v2_rollout.request,
                response=v2_rollout.v2_response,
                settings_obj=settings,
            )
            if decision_receipt is not None:
                pre_action_governance_check["decision_receipt_id"] = decision_receipt.receipt_id
                integrity = (
                    record_execution_unknown(
                        db,
                        tenant_id=tenant_id,
                        decision_receipt_id=decision_receipt.receipt_id,
                        settings_obj=settings,
                    )
                    if v2_rollout.authoritative_decision in {"allow", "warn", "redact"}
                    else record_execution_incomplete(
                        db,
                        tenant_id=tenant_id,
                        decision_receipt_id=decision_receipt.receipt_id,
                        settings_obj=settings,
                    )
                )
                pre_action_governance_check["execution_integrity_result_id"] = integrity.result_id
        decision = {
            "allow": "allow",
            "warn": "warn",
            "redact": "redact",
            "review": "hold_for_approval",
            "require_approval": "hold_for_approval",
            "require_second_approval": "hold_for_approval",
            "block": "block",
        }.get(v2_rollout.authoritative_decision, "block")
        reason = v2_rollout.v2_response.reason if v2_rollout.v2_response else "authorization_kernel_v2"
        pre_action_governance_check["policy"]["decision"] = decision
        pre_action_governance_check["policy"]["reason"] = reason
        pre_action_governance_check["control_mode"] = control_mode_for_pre_action_decision(decision, inline=True)
        mcp_final_actions["authorization_kernel_v2"] = {
            "decision": decision,
            "reason_hash": _hash_text(reason),
        }
    mcp_final_actions["pre_action_governance_check"] = pre_action_governance_check
    mcp_final_actions["control_mode"] = pre_action_governance_check["control_mode"]
    mcp_final_actions["decision_badge"] = decision_badge_for_control_mode(pre_action_governance_check["control_mode"])
    trace_payload["pre_action_governance_check"] = pre_action_governance_check
    trace_payload["control_mode"] = pre_action_governance_check["control_mode"]
    trace_payload["decision_badge"] = mcp_final_actions["decision_badge"]

    root_node = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="mcp_authorization",
        signal_type="gateway.mcp.authorize",
        label=f"MCP auth {request_id}",
        payload={
            "action": action,
            "resource": resource,
            "decision": decision,
            "reason": reason,
            "effective_scopes": effective_scopes,
            "workflow_policy_id": trace_payload.get("workflow_policy_id"),
            "violation_reason": trace_payload.get("violation_reason"),
            "enforcement_routing": routing,
            "trace": trace_payload,
            "pre_action_governance_check": pre_action_governance_check,
            "control_mode": pre_action_governance_check["control_mode"],
            "decision_badge": mcp_final_actions["decision_badge"],
        },
    )
    evidence_node_ids.append(root_node.id)
    pre_action_governance_check["evidence"]["evidence_refs"] = [root_node.id]
    mcp_final_actions["pre_action_governance_check"] = pre_action_governance_check
    trace_payload["pre_action_governance_check"] = pre_action_governance_check

    anomaly = None
    if agent is not None:
        anomaly = track_behavior_anomaly(
            db,
            tenant_id=tenant_id,
            agent_identity_id=agent.id,
            action=action,
        )
        if anomaly.get("is_anomaly"):
            anomaly_node = create_evidence_node(
                db,
                tenant_id=tenant_id,
                node_type="behavior_anomaly",
                signal_type="ai_iam.behavior.anomaly",
                label=f"Agent anomaly {agent.id}:{action}",
                payload={
                    "agent_id": agent.id,
                    "action": action,
                    "baseline_rate_per_hour": anomaly.get("baseline_rate_per_hour"),
                    "current_window_count": anomaly.get("current_window_count"),
                    "spike_threshold": anomaly.get("spike_threshold"),
                },
            )
            link_evidence_nodes(
                db,
                tenant_id=tenant_id,
                from_node_id=root_node.id,
                to_node_id=anomaly_node.id,
                edge_type="flags",
                payload={"request_id": request_id},
            )
            evidence_node_ids.append(anomaly_node.id)
            write_audit_log(
                db,
                tenant_id=tenant_id,
                actor_user_id=audit_actor_user_id,
                actor_type="system",
                action="ai_iam.behavior_anomaly",
                resource_type="agent_identity",
                resource_id=agent.id,
                payload={
                    "request_id": request_id,
                    "action": action,
                    "baseline_rate_per_hour": anomaly.get("baseline_rate_per_hour"),
                    "current_window_count": anomaly.get("current_window_count"),
                    "spike_threshold": anomaly.get("spike_threshold"),
                },
                correlation_id=correlation_id,
            )

    mcp_final_actions["auto_quarantine"] = {
        "enabled": bool(settings.ai_iam_auto_quarantine_new_agents),
        "created": bool((auto_quarantine_result or {}).get("created")),
        "reason": _normalized_optional((auto_quarantine_result or {}).get("reason")),
        "agent_id": resolved_agent_identity_id,
        "evidence_node_id": (auto_quarantine_result or {}).get("evidence_node_id"),
        "audit_log_id": (auto_quarantine_result or {}).get("audit_log_id"),
    }

    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=audit_actor_user_id,
        actor_type="agent",
        action="gateway.mcp.authorize",
        resource_type="ai_system",
        resource_id=ai_system_id,
        payload={
            "request_id": request_id,
            "enforcement_event_request_id": enforcement_event_request_id,
            "action": action,
            "resource": resource,
            "decision": decision,
            "reason": reason,
            "agent_id": resolved_agent_identity_id,
            "effective_scopes": effective_scopes,
            "behavior_anomaly": anomaly,
            "auto_quarantine": mcp_final_actions.get("auto_quarantine"),
            "platform_mode": platform_mode,
            "workflow_policy_id": trace_payload.get("workflow_policy_id"),
            "violation_reason": trace_payload.get("violation_reason"),
            "enforcement_routing": routing,
            "trace": trace_payload,
        },
        correlation_id=correlation_id,
    )

    event = EnforcementEvent(
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        ai_system_id=ai_system_id,
        actor_type="agent",
        actor_id=actor_id,
        request_id=enforcement_event_request_id,
        timestamp=datetime.now(timezone.utc),
        input_prompt=encrypt_enforcement_prompt(f"MCP action={action} resource={resource}"),
        input_context_summary="mcp_authorize",
        input_attachments_meta=[],
        guardian_results=mcp_guardian_results,
        final_decision=decision,
        final_actions={
            **mcp_final_actions,
            "mcp": {
                "reason": reason,
                "source_request_id": request_id,
                "enforcement_event_request_id": enforcement_event_request_id,
                "effective_scopes": effective_scopes,
                "behavior_anomaly": anomaly,
                "action": action,
                "resource": resource,
                "tool_name": (tool_name or action),
                "tool_category": (tool_category or "mcp_authorization"),
                "api_endpoint": (api_endpoint or "/gateway/mcp/authorize"),
                "data_source": data_source,
                "context_id": resolved_context_id,
                "chain_id": resolved_chain_id,
                "chain_depth": derived_chain_depth,
                "claimed_chain_depth": claimed_chain_depth,
                "derived_chain_depth": derived_chain_depth,
                "chain_depth_authority_reason": depth_authority_reason,
                "claimed_parent_agent_id": _normalized_optional(parent_agent_id),
                "parent_action_id": resolved_parent_action_id,
                "session_id": resolved_session_id,
                "session_validation": session_validation,
                "dynamic_permission": dynamic_permission_record,
                "pre_action_governance_check": pre_action_governance_check,
                "control_mode": pre_action_governance_check["control_mode"],
                "decision_badge": mcp_final_actions["decision_badge"],
                "anomaly_score": anomaly_score,
                "over_scoped_flag": over_scoped_flag,
                "new_system_access_detected": new_system_access_detected,
                "privilege_escalation_detected": privilege_escalation_detected,
                "abnormal_tool_usage_detected": abnormal_tool_usage,
            },
            "_meta": {
                "platform_mode": platform_mode,
                "governance_state": governance_status.get("status"),
                "governance_source": governance_status.get("source"),
                "governance_enforcement_mode": governance_status.get("enforcement_mode"),
                "provider": trace_payload.get("provider"),
                "model_name": trace_payload.get("model"),
                "model_version": trace_payload.get("model_version"),
                "prompt_hash": trace_payload.get("prompt_hash"),
                "response_hash": trace_payload.get("response_hash"),
                "tool_name": trace_payload.get("tool_name"),
                "tool_category": trace_payload.get("tool_category"),
                "api_endpoint": trace_payload.get("api_endpoint"),
                "data_source": trace_payload.get("data_source"),
                "data_classification": trace_payload.get("data_classification"),
                "contains_sensitive": trace_payload.get("contains_sensitive"),
                "sensitive_confidence_score": trace_payload.get("sensitive_confidence_score"),
                "sensitive_entities": trace_payload.get("sensitive_entities"),
                "workflow_policy_id": trace_payload.get("workflow_policy_id"),
                "violation_reason": trace_payload.get("violation_reason"),
                "governance_version": trace_payload.get("governance_version"),
                "chain_depth": trace_payload.get("chain_depth"),
                "context_id": trace_payload.get("context_id"),
                "chain_id": trace_payload.get("chain_id"),
                "parent_action_id": trace_payload.get("parent_action_id"),
                "parent_agent_id": trace_payload.get("parent_agent_id"),
                "session_id": trace_payload.get("session_id"),
                "initiating_user_id": trace_payload.get("initiating_user_id"),
                "session_expiry": trace_payload.get("session_expiry"),
                "session_validation": trace_payload.get("session_validation"),
                "dynamic_permission": trace_payload.get("dynamic_permission"),
                "anomaly_score": trace_payload.get("anomaly_score"),
                "over_scoped_flag": over_scoped_flag,
                "new_system_access_detected": new_system_access_detected,
                "privilege_escalation_detected": privilege_escalation_detected,
                "abnormal_tool_usage_detected": abnormal_tool_usage,
                "enforcement_routing": routing,
                "triggered_controls": list(mcp_control_decision.triggered_controls),
                "dominant_control": mcp_control_decision.dominant_control,
                "control_decision_reasoning": mcp_control_decision.reasoning,
                "control_decision_total_risk": mcp_control_decision.total_risk_score,
                "risk_tags": list(mcp_control_decision.risk_tags),
            },
            "_trace": trace_payload,
        },
        evidence_nodes_created=evidence_node_ids,
        controls_impacted=_augment_control_impacts(
            [{"control_id": "CTRL-AI-IAM-001", "delta": 0.0 if allowed else -0.2}],
            triggered_controls=list(mcp_control_decision.triggered_controls),
        ),
        policy_version_id=policy_version_id,
        audit_log_id=audit.id,
    )
    db.add(event)
    db.flush()

    _emit_gateway_monitoring_signal(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        event_id=event.id,
        request_id=request_id,
        correlation_id=correlation_id,
        final_decision=decision,
        policy_version_id=policy_version_id,
        evidence_node_ids=evidence_node_ids,
        trace_payload=trace_payload,
    )

    recalculate_control_maturity(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        control_ids=[item["control_id"] for item in event.controls_impacted if item.get("control_id")],
        reason=f"mcp_authorize:{event.id}:{decision}",
    )
    generate_from_enforcement_event(db, event=event)
    if (
        settings.runtime_intelligence_schedule_simulations
        and decision == "block"
        and not str(request_id).startswith("sim-")
    ):
        from app.services.simulation_scheduler_service import schedule_for_repeated_enforcement_blocks

        schedule_for_repeated_enforcement_blocks(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            actor_user_id=audit_actor_user_id,
        )

    primary_runtime_event_id: str | None = None
    try:
        from app.services.runtime_intelligence.runtime_event_normalizer import (
            ingest_from_ai_iam_event,
            ingest_from_gateway_enforcement,
        )

        primary_runtime_event = ingest_from_gateway_enforcement(db, event=event)
        if primary_runtime_event is not None:
            primary_runtime_event_id = primary_runtime_event.event_id
        ingest_from_ai_iam_event(
            db,
            tenant_id=tenant_id,
            event_type="aiiam.token_validation",
            ai_system_id=ai_system_id,
            user_id=None,
            agent_id=resolved_agent_identity_id,
            severity=("high" if decision == "block" else "med"),
            evidence_node_ids=evidence_node_ids,
            correlation_id=correlation_id,
            metadata={
                "decision": decision,
                "reason": reason,
                "action": action,
                "resource": resource,
                "chain_depth": derived_chain_depth,
                "claimed_chain_depth": claimed_chain_depth,
                "derived_chain_depth": derived_chain_depth,
                "chain_depth_authority_reason": depth_authority_reason,
                "claimed_parent_agent_id": _normalized_optional(parent_agent_id),
                "derived_parent_agent_id": (
                    chain_authority.parent_agent_id if chain_authority is not None else None
                ),
                "delegation_ids": (
                    list(chain_authority.delegation_ids) if chain_authority is not None else []
                ),
                "capability_token_id": (token_row.id if token_row is not None else None),
                "delegation_edge_id": (
                    chain_authority.delegation_ids[0]
                    if chain_authority is not None and chain_authority.delegation_ids
                    else None
                ),
                "context_id": resolved_context_id,
                "chain_id": resolved_chain_id,
                "parent_action_id": resolved_parent_action_id,
                "effective_scopes": effective_scopes,
                "behavior_anomaly": anomaly,
                "auto_quarantine": mcp_final_actions.get("auto_quarantine"),
                "provider": trace_payload.get("provider"),
                "model_provider": trace_payload.get("provider"),
                "model_name": trace_payload.get("model"),
                "model_version": trace_payload.get("model_version"),
                "tool_name": trace_payload.get("tool_name"),
                "tool_category": trace_payload.get("tool_category"),
                "api_endpoint": trace_payload.get("api_endpoint"),
                "data_source": trace_payload.get("data_source"),
                "context_id": trace_payload.get("context_id"),
                "chain_id": trace_payload.get("chain_id"),
                "parent_action_id": trace_payload.get("parent_action_id"),
                "parent_agent_id": trace_payload.get("parent_agent_id"),
                "contains_sensitive": trace_payload.get("contains_sensitive"),
                "sensitive_confidence_score": trace_payload.get("sensitive_confidence_score"),
                "sensitive_entities": trace_payload.get("sensitive_entities"),
                "session_id": resolved_session_id,
                "session_validation": session_validation,
                "dynamic_permission": dynamic_permission_record,
                "anomaly_score": anomaly_score,
                "over_scoped_flag": over_scoped_flag,
                "new_system_access_detected": new_system_access_detected,
                "privilege_escalation_detected": privilege_escalation_detected,
                "abnormal_tool_usage_detected": abnormal_tool_usage,
            },
        )
    except Exception as exc:  # pragma: no cover - non-blocking runtime enrichment
        if isinstance(exc, CanonicalProjectionError):
            raise
        log_structured(
            "runtime_intelligence_ingest_failed",
            module="gateway_service",
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            request_id=request_id,
            correlation_id=correlation_id,
            error=str(exc),
        )

    decision_receipt_id = str(
        pre_action_governance_check.get("decision_receipt_id") or ""
    ).strip()
    if decision_receipt_id and primary_runtime_event_id:
        from app.services.canonical_evidence_bundle_service import (
            link_bundle_to_runtime_projections,
        )

        link_bundle_to_runtime_projections(
            db,
            tenant_id=tenant_id,
            decision_receipt_id=decision_receipt_id,
            settings_obj=settings,
            runtime_event_id=primary_runtime_event_id,
        )

    return {
        "decision": decision,
        "reason": reason,
        "event_id": event.id,
        "runtime_event_id": primary_runtime_event_id,
        "policy_version_id": policy_version_id,
        "workflow_policy_id": trace_payload.get("workflow_policy_id"),
        "violation_reason": trace_payload.get("violation_reason"),
        "platform_mode": platform_mode,
        "effective_scopes": effective_scopes,
        "behavior_anomaly": anomaly,
        "evidence_nodes_created": evidence_node_ids,
        "token_id": token_row.id if token_row else None,
        "agent_id": resolved_agent_identity_id,
        "auto_quarantine": mcp_final_actions.get("auto_quarantine"),
        "session": session_validation,
        "dynamic_permission": dynamic_permission_record,
        "anomaly_score": anomaly_score,
        "over_scoped_flag": over_scoped_flag,
        "new_system_access_detected": new_system_access_detected,
        "privilege_escalation_detected": privilege_escalation_detected,
        "abnormal_tool_usage_detected": abnormal_tool_usage,
        "pre_action_governance_check": pre_action_governance_check,
        "control_mode": pre_action_governance_check["control_mode"],
        "decision_badge": mcp_final_actions["decision_badge"],
        "trace": trace_payload,
    }
