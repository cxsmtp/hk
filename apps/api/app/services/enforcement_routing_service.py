from __future__ import annotations

from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node


CRITICAL_ACTION_TYPES = {
    "prompt",
    "prompt_submission",
    "copy_paste",
    "data_transfer_check",
    "api_call",
    "llm_intercept",
    "mcp_authorize",
    "agent_action",
    "tool_execution",
}


def _normalized_optional(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def normalize_enforcement_event(event: dict[str, Any]) -> dict[str, Any]:
    source_surface = str(
        event.get("source_surface")
        or event.get("source")
        or event.get("source_type")
        or ""
    ).strip().lower()
    if source_surface == "browser_extension":
        source_surface = "browser"
    if source_surface == "aiiam":
        source_surface = "agent"
    if source_surface in {"monitoring", "endpoint", "dns", "proxy"}:
        source_surface = "connector"
    if source_surface not in {"browser", "api", "gateway", "connector", "agent"}:
        source_surface = "gateway"

    event_id = _normalized_optional(event.get("event_id")) or str(uuid4())
    correlation_id = _normalized_optional(event.get("correlation_id")) or event_id
    action_type = (
        _normalized_optional(event.get("action_type"))
        or _normalized_optional(event.get("event_type"))
        or _normalized_optional(event.get("signal_type"))
        or "unknown_action"
    )
    data_classification = (
        _normalized_optional(event.get("data_classification"))
        or _normalized_optional(event.get("source_classification_hint"))
        or _normalized_optional(event.get("classification"))
        or "unknown"
    )

    return {
        "event_id": event_id,
        "tenant_id": _normalized_optional(event.get("tenant_id")) or "unknown_tenant",
        "source_surface": source_surface,
        "action_type": action_type,
        "ai_system_id": _normalized_optional(event.get("ai_system_id")),
        "agent_id": _normalized_optional(event.get("agent_id")),
        "data_classification": data_classification,
        "correlation_id": correlation_id,
    }


def route_enforcement(policy: dict[str, Any] | None, event: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_enforcement_event(event)
    source_surface = normalized["source_surface"]

    if source_surface == "browser":
        route_target = "browser_extension"
        fallback_target = "gateway"
        route_chain = ["browser_extension", "gateway"]
    elif source_surface in {"api", "gateway"}:
        route_target = "gateway"
        fallback_target = "fail_secure"
        route_chain = ["gateway", "fail_secure"]
    elif source_surface == "connector":
        route_target = "connector_pipeline"
        fallback_target = None
        route_chain = ["connector_pipeline"]
    elif source_surface == "agent":
        route_target = "agent_pipeline"
        fallback_target = "fail_secure"
        route_chain = ["ai_iam", "gateway", "fail_secure"]
    else:
        route_target = "gateway"
        fallback_target = "fail_secure"
        route_chain = ["gateway", "fail_secure"]

    return {
        "policy_id": _normalized_optional((policy or {}).get("policy_id")) or "none",
        "policy_version": _normalized_optional((policy or {}).get("policy_version")) or "none",
        "route_target": route_target,
        "fallback_target": fallback_target,
        "route_chain": route_chain,
        "normalized_event": normalized,
    }


def is_critical_action(normalized_event: dict[str, Any]) -> bool:
    action_type = str(normalized_event.get("action_type") or "").strip().lower()
    if action_type in CRITICAL_ACTION_TYPES:
        return True
    classification = str(normalized_event.get("data_classification") or "").strip().lower()
    return classification in {"sensitive", "protected"}


def fallback_decision_for_gateway_failure(
    *,
    platform_mode: str,
    normalized_event: dict[str, Any],
) -> dict[str, str]:
    critical = is_critical_action(normalized_event)
    mode = str(platform_mode or "enforce").strip().lower()
    if critical or mode != "discovery":
        return {
            "decision": "block",
            "reason_code": "gateway_enforcement_failure_fail_secure",
            "recommended_action": "block_and_investigate_enforcement_path",
        }
    return {
        "decision": "warn",
        "reason_code": "gateway_enforcement_failure_discovery_warn",
        "recommended_action": "monitor_and_recover_gateway_path",
    }


def record_routing_failure(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    routing: dict[str, Any],
    stage: str,
    error: str,
    fallback_applied: str | None,
) -> tuple[str | None, str | None]:
    normalized_event = dict(routing.get("normalized_event") or {})
    correlation_id = _normalized_optional(normalized_event.get("correlation_id"))
    audit_id: str | None = None
    evidence_id: str | None = None
    payload = {
        "stage": stage,
        "error": error,
        "route_target": routing.get("route_target"),
        "fallback_target": routing.get("fallback_target"),
        "fallback_applied": fallback_applied,
        "policy_id": routing.get("policy_id"),
        "policy_version": routing.get("policy_version"),
        "normalized_event": normalized_event,
    }
    try:
        audit = write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            actor_type="system",
            action="enforcement.routing.failure",
            resource_type="enforcement_event",
            resource_id=str(normalized_event.get("event_id") or str(uuid4())),
            payload=payload,
            correlation_id=correlation_id,
        )
        audit_id = audit.id
    except Exception:
        audit_id = None

    try:
        node = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="enforcement_routing_failure",
            signal_type="enforcement.routing.failure",
            label=f"Routing failure at {stage}",
            payload=payload,
            correlation_id=correlation_id,
        )
        evidence_id = node.id
    except Exception:
        evidence_id = None

    return audit_id, evidence_id
