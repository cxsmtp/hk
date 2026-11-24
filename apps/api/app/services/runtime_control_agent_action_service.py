from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.control_engine import AIAction, evaluate_control_engine, map_generic_decision
from app.core.control_engine.canonical_action import CanonicalProjectionError
from app.core.config import settings
from app.core.observability import log_structured
from app.db.models.ai_iam import AgentIdentity, CapabilityToken
from app.db.models.monitoring import MonitoringSignal
from app.services.ai_iam_service import (
    action_category_for,
    action_risk_for,
    authority_value_matches,
    build_intent_aware_evidence_summary,
    build_pre_action_governance_check,
    classify_input_content_context,
    classify_intent_context,
    control_mode_for_pre_action_decision,
    decision_badge_for_control_mode,
    compute_agent_identity_risk_score,
    evaluate_action_alignment,
    evaluate_intent_aware_action_control,
    evaluate_purpose_bound_permission,
    purpose_confirmation_required,
    resolve_persisted_purpose_bound_permission,
    track_behavior_anomaly,
    validate_capability_token,
)
from app.services.ai_iam_identity_service import get_agent_identity_financial_snapshot
from app.services.audit_service import write_audit_log
from app.services.delegation_chain_authority_service import (
    DelegationChainDepthResult,
    resolve_persisted_delegation_chain_depth,
)
from app.services.enforcement_routing_service import (
    fallback_decision_for_gateway_failure,
    record_routing_failure,
    route_enforcement,
)
from app.services.evidence_service import create_evidence_node, link_evidence_nodes
from app.services.findings_service import generate_agent_action_finding, generate_unregistered_ai_system_finding
from app.services.guardian_policy_engine import evaluate_agent_action_policy
from app.services.governance_resolution import resolve_ai_system_status
from app.services.platform_mode_service import get_tenant_platform_mode
from app.services.sensitive_data_detection_service import (
    classify_data,
    detect_sensitive_data,
    detection_signal_types,
)


ALLOWED_ACTION_TYPES = {"api_call", "email_send", "db_query", "tool_execution"}

SEVERITY_BY_DECISION = {
    "allow": "low",
    "warn": "med",
    "block": "high",
    "require_approval": "high",
}


def _agent_decision_rank(decision: str) -> int:
    normalized = str(decision or "").strip().lower()
    if normalized == "block":
        return 4
    if normalized == "require_approval":
        return 3
    if normalized == "warn":
        return 2
    return 1


def _map_control_engine_agent_decision(decision: str, *, fallback: str = "allow") -> str:
    return map_generic_decision(
        decision,
        mapping={
            "allow": "allow",
            "alert": "warn",
            "modify": "warn",
            "step_up": "require_approval",
            "block": "block",
        },
        default=fallback,
    )

@dataclass
class AgentActionDecision:
    decision: str
    reason_code: str
    explanation: str
    recommended_action: str
    severity: str
    data_classification: str
    policy: dict[str, Any] | None = None


def _normalize_action_type(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in ALLOWED_ACTION_TYPES else "tool_execution"


def _normalize_domainish(value: str | None) -> str | None:
    raw = str(value or "").strip().lower()
    return raw or None


def _extract_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, sort_keys=True, ensure_ascii=True)
        except Exception:
            return str(value)
    return str(value)


def _classify_payload_with_detection(
    input_context: dict[str, Any],
    *,
    ai_system_id: str | None,
    agent_id: str,
    user_id: str | None,
    correlation_id: str | None,
) -> tuple[str, dict[str, Any]]:
    hints = [
        str(input_context.get("classification") or "").strip().lower(),
        str(input_context.get("data_classification") or "").strip().lower(),
        str(input_context.get("policy_tag") or "").strip().lower(),
    ]
    for hint in hints:
        if hint in {"sensitive", "protected"}:
            return "sensitive", {"contains_sensitive": True, "entities": [], "confidence_score": 1.0}
        if hint in {"internal", "confidential"}:
            return "internal", {"contains_sensitive": False, "entities": [], "confidence_score": 0.7}
        if hint in {"public"}:
            return "public", {"contains_sensitive": False, "entities": [], "confidence_score": 0.7}

    file_meta = [item for item in (input_context.get("file_meta") or []) if isinstance(item, dict)]
    text_chunks = [
        _extract_text(input_context.get("prompt")),
        _extract_text(input_context.get("payload")),
        _extract_text(input_context.get("arguments")),
        _extract_text(input_context.get("response")),
        _extract_text(input_context.get("tool_input")),
    ]
    detection = detect_sensitive_data(
        text_inputs=[chunk for chunk in text_chunks if chunk],
        file_meta=file_meta,
        source="agent",
        destination=str(input_context.get("api_endpoint") or input_context.get("target_resource") or "external_api"),
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        user_id=user_id,
        correlation_id=correlation_id,
    )
    detected = classify_data(
        detection_result=detection,
        classification_hint=str(input_context.get("data_classification") or input_context.get("classification") or ""),
        allow_unknown=True,
    )
    if detected == "protected":
        return "sensitive", detection
    if detected == "internal":
        return "internal", detection
    if detected == "public":
        return "public", detection
    return "unknown", detection


def _required_scope_for_action(action_type: str, tool_name: str | None) -> str:
    normalized_tool = str(tool_name or "").strip().lower()
    if action_type == "db_query":
        return "tool.read"
    if action_type == "email_send":
        return "tool.email_send"
    if action_type == "api_call":
        return "tool.run"
    if normalized_tool in {"browser", "web", "web_browser"}:
        return "tool.read"
    if normalized_tool:
        return f"tool.{normalized_tool}"
    return "tool.run"


def _scope_allowed(agent: AgentIdentity, *, action_type: str, required_scope: str) -> bool:
    allowed = {str(item).strip().lower() for item in (agent.action_scope or []) if str(item).strip()}
    if not allowed:
        return True
    normalized_action = str(action_type).strip().lower()
    normalized_scope = str(required_scope).strip().lower()
    return "*" in allowed or normalized_action in allowed or normalized_scope in allowed


def _tool_allowed(agent: AgentIdentity, tool_name: str | None) -> bool:
    normalized_tool = str(tool_name or "").strip().lower()
    if not normalized_tool:
        return True
    registry = {str(item).strip().lower() for item in (agent.tool_registry or []) if str(item).strip()}
    if not registry:
        return True
    return "*" in registry or normalized_tool in registry


def _target_allowed(agent: AgentIdentity, target_resource: str | None) -> bool:
    normalized_target = _normalize_domainish(target_resource)
    if not normalized_target:
        return True
    allowed_targets = {
        str(item).strip().lower() for item in (agent.external_system_access or []) if str(item).strip()
    }
    if not allowed_targets:
        return True
    if "*" in allowed_targets:
        return True
    if "browser" in allowed_targets and normalized_target.startswith(("http://", "https://")):
        return True
    return any(normalized_target == allowed or normalized_target.endswith(f".{allowed}") for allowed in allowed_targets)


def _decide_agent_action(
    *,
    governance_status: dict[str, str],
    platform_mode: str,
    token_valid: bool,
    token_reason: str,
    agent_matches_token: bool,
    action_scope_ok: bool,
    tool_ok: bool,
    target_ok: bool,
    chain_depth_ok: bool,
    action_type: str,
    data_classification: str,
) -> AgentActionDecision:
    engine_decision = evaluate_agent_action_policy(
        governance_status=governance_status,
        platform_mode=platform_mode,
        token_valid=token_valid,
        token_reason=token_reason,
        agent_matches_token=agent_matches_token,
        action_scope_ok=action_scope_ok,
        tool_ok=tool_ok,
        target_ok=target_ok,
        chain_depth_ok=chain_depth_ok,
        action_type=action_type,
        data_classification=data_classification,
    )
    severity = SEVERITY_BY_DECISION.get(
        engine_decision.decision,
        engine_decision.severity if engine_decision.severity in {"low", "med", "high"} else "med",
    )
    return AgentActionDecision(
        decision=engine_decision.decision,
        reason_code=engine_decision.reason_code,
        explanation=engine_decision.explanation,
        recommended_action=engine_decision.recommended_action,
        severity=severity,
        data_classification=data_classification,
        policy=engine_decision.policy,
    )


def evaluate_agent_action_and_record(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    agent_id = str(payload.get("agent_id") or "").strip()
    if not agent_id:
        raise ValueError("agent_id is required")

    action_type = _normalize_action_type(payload.get("action_type"))
    tool_name = str(payload.get("tool_name") or "").strip() or None
    target_resource = str(payload.get("target_resource") or "").strip() or None
    input_context = dict(payload.get("input_context") or {})
    claimed_chain_depth = max(1, int(payload.get("chain_depth") or 1))
    derived_chain_depth: int | None = None
    chain_depth = 1
    chain_id = str(payload.get("chain_id") or "").strip() or None
    policy_version = str(payload.get("policy_version") or "none").strip() or "none"
    parent_action_id = str(payload.get("parent_action_id") or "").strip() or None
    correlation_id = str(payload.get("correlation_id") or "").strip() or None
    if not chain_id:
        chain_id = correlation_id or f"agent-chain:{agent_id}"

    ai_system_id = str(payload.get("ai_system_id") or "").strip() or None
    platform_mode = str(payload.get("platform_mode") or "").strip().lower()
    if platform_mode not in {"discovery", "enforce"}:
        platform_mode = get_tenant_platform_mode(db, tenant_id=tenant_id)

    capability_token = str(payload.get("capability_token") or "").strip()
    if not capability_token:
        raise ValueError("capability_token is required")

    governance_status = resolve_ai_system_status(
        ai_system_id,
        {
            "db": db,
            "tenant_id": tenant_id,
            "source_hint": "trust_center",
            "route": "/runtime-control/agent-action-intercept",
            "module": "runtime_control",
        },
    )

    agent = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == agent_id,
            AgentIdentity.tenant_id == tenant_id,
        )
    )
    if agent is None:
        raise ValueError("agent_id not found")

    required_scope = _required_scope_for_action(action_type, tool_name)
    token_valid, token_reason, token_row, token_agent, effective_scopes = validate_capability_token(
        db,
        tenant_id=tenant_id,
        raw_token=capability_token,
        required_scope=required_scope,
        chain_depth=1,
    )
    chain_authority: DelegationChainDepthResult | None = None
    chain_depth_authority_reason = token_reason
    if token_row is not None:
        chain_authority = resolve_persisted_delegation_chain_depth(
            db,
            tenant_id=tenant_id,
            agent_id=agent.id,
            capability_token_id=token_row.id,
            claimed_chain_depth=claimed_chain_depth,
            claimed_parent_agent_id=(
                str(payload.get("parent_agent_id") or input_context.get("parent_agent_id") or "").strip() or None
            ),
            parent_action_id=parent_action_id,
            chain_id=chain_id,
            ai_system_id=ai_system_id,
            required_action=required_scope,
        )
        derived_chain_depth = chain_authority.derived_depth
        chain_depth = derived_chain_depth or 1
        token_valid, token_reason, token_row, token_agent, effective_scopes = validate_capability_token(
            db,
            tenant_id=tenant_id,
            raw_token=capability_token,
            required_scope=required_scope,
            chain_depth=chain_depth,
        )
        if not chain_authority.allowed:
            token_valid = False
            token_reason = chain_authority.reason_code
        chain_depth_authority_reason = chain_authority.reason_code
    agent_matches_token = bool(token_agent is not None and token_agent.id == agent.id)

    action_scope_ok = _scope_allowed(agent, action_type=action_type, required_scope=required_scope)
    tool_ok = _tool_allowed(agent, tool_name)
    target_ok = _target_allowed(agent, target_resource)
    chain_depth_ok = chain_depth <= int(agent.max_chain_depth)
    behavior_anomaly = track_behavior_anomaly(
        db,
        tenant_id=tenant_id,
        agent_identity_id=agent.id,
        action=f"{action_type}:{tool_name or 'generic'}",
    )

    data_classification, detection_result = _classify_payload_with_detection(
        input_context,
        ai_system_id=ai_system_id,
        agent_id=agent.id,
        user_id=actor_user_id,
        correlation_id=correlation_id,
    )
    routing = route_enforcement(
        {
            "policy_id": "agent_action_control",
            "policy_version": policy_version or "none",
        },
        {
            "event_id": str(payload.get("event_id") or ""),
            "tenant_id": tenant_id,
            "source_surface": "agent",
            "action_type": "agent_action",
            "ai_system_id": ai_system_id,
            "agent_id": agent.id,
            "data_classification": data_classification,
            "correlation_id": correlation_id,
        },
    )
    routing_fallback_audit_id: str | None = None
    routing_fallback_evidence_id: str | None = None
    try:
        decision = _decide_agent_action(
            governance_status=governance_status,
            platform_mode=platform_mode,
            token_valid=token_valid,
            token_reason=token_reason,
            agent_matches_token=agent_matches_token,
            action_scope_ok=action_scope_ok,
            tool_ok=tool_ok,
            target_ok=target_ok,
            chain_depth_ok=chain_depth_ok,
            action_type=action_type,
            data_classification=data_classification,
        )
    except Exception as exc:
        fallback = fallback_decision_for_gateway_failure(
            platform_mode=platform_mode,
            normalized_event=dict(routing.get("normalized_event") or {}),
        )
        routing_fallback_audit_id, routing_fallback_evidence_id = record_routing_failure(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            routing=routing,
            stage="runtime_control.agent_action",
            error=str(exc),
            fallback_applied="fail_secure",
        )
        decision = AgentActionDecision(
            decision="block",
            reason_code=str(fallback["reason_code"]),
            explanation="Agent enforcement evaluation failed. Applied fail-secure block.",
            recommended_action=str(fallback["recommended_action"]),
            severity="high",
            data_classification=data_classification,
            policy=None,
        )

    if bool(behavior_anomaly.get("is_anomaly")) and decision.decision in {"allow", "warn"}:
        decision = AgentActionDecision(
            decision="require_approval",
            reason_code="agent_behavior_anomaly_requires_approval",
            explanation="Agent behavior exceeded baseline activity thresholds. Step-up approval required while identity risk is assessed.",
            recommended_action="investigate_agent_identity",
            severity="high",
            data_classification=data_classification,
            policy=decision.policy,
        )

    hinted_controls: list[str] = []
    if str(governance_status.get("status") or "").upper() == "UNKNOWN":
        hinted_controls.extend(["AI_SYSTEM_INVENTORY_CONTROL", "SHADOW_AI_DETECTION"])
    if decision.decision in {"warn", "block", "require_approval"}:
        hinted_controls.append("POLICY_ENFORCEMENT_CONTROL")
    if decision.reason_code in {
        "agent_action_scope_denied",
        "capability_token_invalid",
        "agent_token_mismatch",
        "delegation_chain_token_agent_mismatch",
        "tool_not_allowed",
    }:
        hinted_controls.append("AGENT_ACTION_AUTHORIZATION")
    if decision.reason_code in {"tool_not_allowed", "target_not_allowed"}:
        hinted_controls.append("TOOL_CALL_VALIDATION")
    if decision.reason_code in {"chain_depth_exceeded", "delegation_chain_depth_mismatch"}:
        hinted_controls.append("CHAIN_OF_ACTION_VALIDATION")
    if bool(behavior_anomaly.get("is_anomaly")):
        hinted_controls.append("PRIVILEGE_DRIFT_DETECTION")

    control_decision = evaluate_control_engine(
        AIAction(
            action_id=str(correlation_id or payload.get("event_id") or f"agent_action:{agent.id}"),
            user_id=actor_user_id,
            endpoint_id=str(payload.get("endpoint_id") or "").strip() or None,
            ai_app=(str(ai_system_id or "").strip() or None),
            model=str(input_context.get("model_name") or input_context.get("model") or "").strip() or None,
            prompt=_extract_text(input_context.get("prompt") or input_context.get("payload")),
            metadata={
                "source_surface": "agent",
                "action_type": "agent_action",
                "reason_code": decision.reason_code,
                "input_signal_types": [
                    "agent_action",
                    f"action_type:{action_type}",
                    decision.reason_code,
                    f"data_classification:{data_classification}",
                    *detection_signal_types(detection_result),
                ],
                "contains_sensitive": bool(detection_result.get("contains_sensitive")),
                "data_classification": data_classification,
                "governance_status": str(governance_status.get("status") or "UNKNOWN"),
                "triggered_controls": hinted_controls,
            },
            source_surface="agent",
        ),
        base_decision=decision.decision,
        hinted_control_ids=hinted_controls,
    )
    mapped_control_decision = _map_control_engine_agent_decision(control_decision.decision, fallback=decision.decision)
    if _agent_decision_rank(mapped_control_decision) > _agent_decision_rank(decision.decision):
        decision = AgentActionDecision(
            decision=mapped_control_decision,
            reason_code="control_engine_escalation",
            explanation="Central control engine escalated agent action decision.",
            recommended_action="investigate_agent_identity",
            severity=("high" if mapped_control_decision in {"block", "require_approval"} else "med"),
            data_classification=data_classification,
            policy=decision.policy,
        )

    identity_risk = compute_agent_identity_risk_score(
        token_valid=token_valid,
        token_reason=token_reason,
        agent_matches_token=agent_matches_token,
        action_scope_ok=action_scope_ok,
        tool_ok=tool_ok,
        target_ok=target_ok,
        chain_depth_ok=chain_depth_ok,
        data_classification=data_classification,
        behavior_anomaly=behavior_anomaly,
    )
    identity_risk_score = float(identity_risk.get("risk_score") or 0.0)
    identity_risk_level = str(identity_risk.get("risk_level") or "medium").strip().lower() or "medium"
    identity_risk_reasoning = [
        str(item).strip() for item in (identity_risk.get("risk_reasoning") or []) if str(item).strip()
    ]
    delegated_flow = bool(parent_action_id or str(input_context.get("parent_agent_id") or "").strip())
    delegation_misuse = delegated_flow and decision.reason_code in {
        "agent_token_mismatch",
        "delegation_chain_token_agent_mismatch",
        "scope_denied",
        "scope_reduced_denied",
        "agent_action_scope_denied",
        "chain_depth_exceeded",
        "delegation_chain_depth_mismatch",
    }
    privilege_drift_detected = bool(behavior_anomaly.get("is_anomaly"))
    caller_purpose_permission = input_context.get("purpose_bound_permission")
    purpose_authority = resolve_persisted_purpose_bound_permission(
        db,
        tenant_id=tenant_id,
        user_id=actor_user_id,
        agent_id=(agent.id if agent_matches_token else None),
        caller_permission=caller_purpose_permission,
    )
    purpose_permission = purpose_authority.get("permission")
    resolved_action_category = action_category_for(action_type)
    resolved_action_risk = action_risk_for(action_type, environment=str(input_context.get("environment") or "prod"))
    purpose_result = (
        evaluate_purpose_bound_permission(
            permission=purpose_permission,
            action_type=action_type,
            action_category=resolved_action_category,
            action_risk=resolved_action_risk,
            tool_name=tool_name,
            target_resource=target_resource,
            domain=target_resource,
            environment=str(input_context.get("environment") or "prod"),
            current_action_count=int(behavior_anomaly.get("current_window_count") or 1),
        )
        if purpose_authority.get("valid")
        else {
            "decision": "block",
            "reason": str(purpose_authority.get("reason") or "persisted_purpose_permission_required"),
            "purpose_bound_permission_id": None,
            "violations": [str(purpose_authority.get("reason") or "persisted_purpose_permission_required")],
            "mode": "block",
            "allowed": False,
        }
    )
    if purpose_authority.get("valid") and purpose_permission:
        purpose_scope = (
            dict(purpose_permission.get("scope") or {})
            if isinstance(purpose_permission.get("scope"), dict)
            else {}
        )
        purpose_context = (
            dict(purpose_permission.get("context") or {})
            if isinstance(purpose_permission.get("context"), dict)
            else {}
        )
        allowed_data_scopes = [
            str(item).strip().lower()
            for item in (
                purpose_scope.get("allowed_data_scopes")
                or purpose_permission.get("allowed_data_scope")
                or []
            )
            if str(item).strip()
        ]
        if allowed_data_scopes and not authority_value_matches(data_classification, allowed_data_scopes):
            purpose_result = {
                **purpose_result,
                "decision": "block",
                "reason": "purpose_data_scope_denied",
                "violations": ["purpose_data_scope_denied"],
                "allowed": False,
            }
        purpose_max_depth = purpose_context.get("max_chain_depth")
        if purpose_max_depth is not None and chain_depth > int(purpose_max_depth):
            purpose_result = {
                **purpose_result,
                "decision": "block",
                "reason": "purpose_chain_depth_exceeded",
                "violations": ["purpose_chain_depth_exceeded"],
                "allowed": False,
            }
        if purpose_result.get("decision") == "allow" and purpose_confirmation_required(
            purpose_permission,
            action_type=action_type,
            action_category=resolved_action_category,
            action_risk=resolved_action_risk,
        ):
            purpose_result = {
                **purpose_result,
                "decision": "require_approval",
                "reason": "purpose_confirmation_required",
                "violations": ["purpose_confirmation_required"],
                "allowed": False,
            }

    purpose_reason = str(purpose_result.get("reason") or "action_outside_purpose_scope")
    purpose_parity_violation = purpose_reason in {
        "purpose_data_scope_denied",
        "purpose_chain_depth_exceeded",
    }
    if purpose_result["decision"] == "block" and (
        decision.decision in {"allow", "warn"} or purpose_parity_violation
    ):
        decision = AgentActionDecision(
            decision="block",
            reason_code=purpose_reason,
            explanation="Agent action is outside the active purpose-bound permission.",
            recommended_action="Review the agent purpose-bound permission and retry with scoped authority.",
            severity="high",
            data_classification=data_classification,
            policy=decision.policy,
        )
    elif purpose_result["decision"] == "require_approval" and decision.decision in {"allow", "warn"}:
        decision = AgentActionDecision(
            decision="require_approval",
            reason_code="purpose_confirmation_required",
            explanation="The persisted purpose authority requires a server-verified human approval artifact.",
            recommended_action="Obtain approval bound to the canonical action before retrying.",
            severity="high",
            data_classification=data_classification,
            policy=decision.policy,
        )
    elif purpose_result["decision"] == "shadow_would_block" and decision.decision == "allow":
        decision = AgentActionDecision(
            decision="allow",
            reason_code=str(purpose_result.get("reason") or "shadow_would_block"),
            explanation="Shadow action-boundary policy would have blocked this action.",
            recommended_action="Review shadow policy before moving it to enforce mode.",
            severity="med",
            data_classification=data_classification,
            policy=decision.policy,
        )

    intent_text = " ".join(
        item
        for item in [
            str(input_context.get("declared_intent") or ""),
            str(input_context.get("prompt_preview_redacted") or input_context.get("input_summary") or ""),
            str(tool_name or ""),
            str(target_resource or ""),
        ]
        if str(item or "").strip()
    )
    explicit_attempted_action = str(
        input_context.get("attempted_action")
        or input_context.get("intent_action_type")
        or input_context.get("action_name")
        or ""
    ).strip().lower()
    intent_action_type = explicit_attempted_action or (
        "send_email"
        if "mail" in str(tool_name or "").lower() or "email" in str(action_type or "").lower()
        else (
            "export_contacts"
            if "export" in str(action_type or "").lower() or "contact" in intent_text.lower()
            else (
                "browse"
                if action_type == "tool_execution" and str(tool_name or "").strip().lower() in {"browser", "web", "web_browser"}
                else action_type
            )
        )
    )
    intent_context = classify_intent_context(
        declared_intent=str(input_context.get("declared_intent") or input_context.get("intent") or "").strip() or None,
        text=intent_text,
        action_type=intent_action_type,
        business_context=str(input_context.get("business_context") or "").strip() or None,
    )
    input_content_context = classify_input_content_context(str(input_context.get("prompt_preview_redacted") or ""))
    output_context: dict[str, Any] = {}
    action_alignment_result = evaluate_action_alignment(
        intent_context=intent_context,
        action_type=intent_action_type,
        input_content_context=input_content_context,
        output_context=output_context,
    )
    intent_policy = dict(input_context.get("intent_policy") or {}) if isinstance(input_context.get("intent_policy"), dict) else {}
    if not intent_policy:
        intent_policy = {"policy_id": "INTENT_AWARE_AI_ACTION_CONTROL", "mode": "block"}
    intent_aware_decision = evaluate_intent_aware_action_control(
        intent_context=intent_context,
        input_content_context=input_content_context,
        output_context=output_context,
        action_alignment_result=action_alignment_result,
        action_type=intent_action_type,
        policy=intent_policy,
    )
    if intent_aware_decision.get("decision") == "block" and decision.decision in {"allow", "warn", "require_approval", "block"}:
        decision = AgentActionDecision(
            decision="block",
            reason_code=str(intent_aware_decision.get("decision_reason") or "intent_action_scope_violation"),
            explanation="Agent action is outside the declared or inferred intent boundary.",
            recommended_action="Review the declared agent intent and require a scoped approval before retrying this action.",
            severity="high",
            data_classification=data_classification,
            policy=decision.policy,
        )
        purpose_result = {
            **purpose_result,
            "decision": "block",
            "reason": str(intent_aware_decision.get("decision_reason") or "intent_action_scope_violation"),
            "violations": list(purpose_result.get("violations") or ["intent_action_scope_violation"]),
        }

    if (
        chain_authority is not None
        and not chain_authority.allowed
        and str(governance_status.get("reason") or "").strip() != "ai_system_not_registered"
    ):
        decision = AgentActionDecision(
            decision="block",
            reason_code=chain_authority.reason_code,
            explanation="Persisted delegation-chain authority could not be verified.",
            recommended_action="Repair or revoke the persisted delegation chain before retrying.",
            severity="high",
            data_classification=data_classification,
            policy=decision.policy,
        )
    elif (
        derived_chain_depth is None
        and str(governance_status.get("reason") or "").strip() != "ai_system_not_registered"
    ):
        decision = AgentActionDecision(
            decision="block",
            reason_code=chain_depth_authority_reason,
            explanation="Capability-token authority could not be resolved to a persisted delegation chain.",
            recommended_action="Present a valid token bound to the persisted agent authority.",
            severity="high",
            data_classification=data_classification,
            policy=decision.policy,
        )
    if str(governance_status.get("reason") or "").strip() == "ai_system_not_registered":
        decision = AgentActionDecision(
            decision="block",
            reason_code="unregistered_ai_system",
            explanation="AI system is not registered for this tenant.",
            recommended_action="Register and approve the AI system before retrying.",
            severity="high",
            data_classification=data_classification,
            policy=decision.policy,
        )

    provider = str(input_context.get("provider") or input_context.get("model_provider") or "").strip() or None
    model_name = str(input_context.get("model_name") or input_context.get("model") or "").strip() or None
    model_version = str(input_context.get("model_version") or "").strip() or None
    api_endpoint = str(input_context.get("api_endpoint") or "").strip() or None
    effective_purpose_result = dict(purpose_result)
    if effective_purpose_result.get("decision") == "allow" and decision.decision not in {"allow", ""}:
        effective_purpose_result.update(
            {
                "decision": decision.decision,
                "reason": decision.reason_code,
                "violations": list(effective_purpose_result.get("violations") or [decision.reason_code]),
            }
        )
    runtime_parameters = (
        input_context.get("parameters")
        or input_context.get("payload")
        or payload.get("parameters")
        or {}
    )
    runtime_parameter_hash = hashlib.sha256(
        json.dumps(runtime_parameters, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()
    runtime_tool_fingerprint = hashlib.sha256(
        json.dumps(
            {
                "tool_name": tool_name,
                "model_version": model_version,
                "api_endpoint": api_endpoint,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()
    pre_action_governance_check = build_pre_action_governance_check(
        tenant_id=tenant_id,
        action_id=str(payload.get("event_id") or correlation_id or f"agent:{agent.id}:{action_type}"),
        source_event_id=str(payload.get("event_id") or "").strip() or None,
        actor={
            "identity_id": agent.id,
            "identity_type": "agent",
            "user_id": actor_user_id,
            "agent_id": agent.id,
            "agent_name": agent.name,
            "session_id": str(input_context.get("session_id") or payload.get("session_id") or "").strip() or None,
            "machine_id": str(payload.get("machine_id") or payload.get("endpoint_id") or "").strip() or None,
            "acting_on_behalf_of_user_id": actor_user_id,
        },
        authority={
            "authority_type": "delegated_agent",
            "authority_owner": actor_user_id,
            "authority_source": "capability_token",
            "auth_strength": "capability_token_valid" if token_valid else token_reason,
            "standing_privilege": not bool(purpose_permission),
            "verified": bool(token_valid),
        },
        purpose_permission=purpose_permission,
        purpose_result=effective_purpose_result,
        surface={
            "surface_type": "agent",
            "application": tool_name or target_resource or "agent_action",
            "provider": provider,
            "model": model_name,
            "domain": target_resource,
            "url": api_endpoint,
            "asset_id": ai_system_id,
            "environment": str(input_context.get("environment") or "prod"),
            "asset_status": str(governance_status.get("status") or "UNKNOWN").lower(),
        },
        action={
            "action_type": action_type,
            "action_category": resolved_action_category,
            "action_risk": resolved_action_risk,
            "target_resource": target_resource,
            "tool_name": tool_name,
            "tool_version": model_version or "runtime",
            "tool_fingerprint_id": runtime_tool_fingerprint,
            "parameter_hash": runtime_parameter_hash,
        },
        workflow_risk_context={
            "workflow_id": chain_id,
            "previous_action_count": max(0, int(behavior_anomaly.get("current_window_count") or 1) - 1),
            "cumulative_risk_score": identity_risk_score,
            "scope_drift_score": 0.7 if not target_ok or bool(effective_purpose_result.get("violations")) else 0.0,
            "privilege_escalation_score": 0.6 if delegation_misuse or not chain_depth_ok else 0.0,
            "recent_violations_count": 1 if decision.decision in {"block", "require_approval"} else 0,
            "risk_drivers": [
                *list(effective_purpose_result.get("violations") or []),
                *identity_risk_reasoning,
            ],
        },
        policy_snapshot_id=policy_version,
        policy_ids=[str((decision.policy or {}).get("policy_id") or "AI_ACTION_BOUNDARY_CONTROL")],
        control_ids=list(control_decision.triggered_controls or ["AI_ACTION_BOUNDARY_CONTROL"]),
        evidence_refs=[],
        trace_id=correlation_id,
        inline=True,
    )
    from app.core.control_engine.authorization import (
        apply_trusted_pre_action_rollout,
        authorization_rollout_persistence_metadata,
    )

    v2_rollout = apply_trusted_pre_action_rollout(
        tenant_id=tenant_id,
        surface="runtime_control",
        action_id=str(payload.get("event_id") or correlation_id or f"agent:{agent.id}:{action_type}"),
        chain_id=chain_id,
        collector_id="runtime-control-agent-action",
        trusted_pre_action_governance_check=pre_action_governance_check,
        legacy_decision=decision.decision,
        legacy_reason=decision.reason_code,
        legacy_control_mode=control_mode_for_pre_action_decision(decision.decision, inline=True),
        policy_snapshot_id=policy_version,
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
        mapped_v2_decision = {
            "allow": "allow",
            "warn": "warn",
            "redact": "warn",
            "review": "require_approval",
            "require_approval": "require_approval",
            "require_second_approval": "require_approval",
            "block": "block",
        }.get(v2_rollout.authoritative_decision, "block")
        v2_reason = v2_rollout.v2_response.reason if v2_rollout.v2_response else "authorization_kernel_v2"
        decision = AgentActionDecision(
            decision=mapped_v2_decision,
            reason_code=f"authorization_kernel_v2:{v2_reason}",
            explanation="The server-selected authorization kernel evaluated this action before execution.",
            recommended_action="Use an approved identity, target, tool version, and parameter binding.",
            severity=SEVERITY_BY_DECISION.get(mapped_v2_decision, "high"),
            data_classification=data_classification,
            policy=decision.policy,
        )
        pre_action_governance_check["policy"]["decision"] = mapped_v2_decision
        pre_action_governance_check["policy"]["reason"] = v2_reason
        pre_action_governance_check["control_mode"] = control_mode_for_pre_action_decision(
            mapped_v2_decision,
            inline=True,
        )

    destination_context = {
        "resource": target_resource,
        "application": tool_name or target_resource or "agent_action",
        "trust_level": str(input_context.get("destination_trust_level") or "unknown"),
        "control_mode": "runtime_control",
    }
    intent_aware_evidence_summary = build_intent_aware_evidence_summary(
        intent_context=intent_context,
        input_content_context=input_content_context,
        output_context=output_context,
        action_alignment_result=action_alignment_result,
        intent_aware_decision=intent_aware_decision,
        action_type=str(input_context.get("attempted_action") or input_context.get("intent_action_type") or action_type),
        action_risk=action_risk_for(str(input_context.get("attempted_action") or input_context.get("intent_action_type") or action_type)),
        destination_context=destination_context,
        policy_snapshot={
            "policy_id": str(intent_policy.get("policy_id") or "INTENT_AWARE_AI_ACTION_CONTROL"),
            "policy_version": policy_version,
            "mode": str(intent_policy.get("mode") or "block"),
        },
        control_mode="runtime_control",
    )

    signal_payload = {
        "event_type": "agent_action_intercept",
        "action_taken": decision.decision,
        "action_type": action_type,
        "tool_name": tool_name,
        "target_resource": target_resource,
        "chain_depth": derived_chain_depth,
        "claimed_chain_depth": claimed_chain_depth,
        "derived_chain_depth": derived_chain_depth,
        "chain_depth_authority_reason": chain_depth_authority_reason,
        "claimed_parent_agent_id": (
            str(payload.get("parent_agent_id") or input_context.get("parent_agent_id") or "").strip() or None
        ),
        "derived_parent_agent_id": (
            chain_authority.parent_agent_id if chain_authority is not None else None
        ),
        "delegation_ids": (
            list(chain_authority.delegation_ids) if chain_authority is not None else []
        ),
        "persisted_delegation_depth_claims": (
            list(chain_authority.stored_depths) if chain_authority is not None else []
        ),
        "chain_id": chain_id,
        "parent_action_id": parent_action_id,
        "agent_id": agent.id,
        "ai_system_id": ai_system_id,
        "policy_version": policy_version,
        "platform_mode": platform_mode,
        "reason_code": decision.reason_code,
        "explanation": decision.explanation,
        "recommended_action": decision.recommended_action,
        "governance_state": governance_status.get("status"),
        "governance_reason": governance_status.get("reason"),
        "governance_enforcement_mode": governance_status.get("enforcement_mode"),
        "token_id": (token_row.id if token_row is not None else None),
        "effective_scopes": effective_scopes,
        "data_classification": data_classification,
        "provider": provider,
        "model_provider": provider,
        "model_name": model_name,
        "model_version": model_version,
        "api_endpoint": api_endpoint,
        "correlation_id": correlation_id,
        "context_id": (correlation_id or chain_id),
        "chain_id": chain_id,
        "parent_action_id": parent_action_id,
        "entity_type": "agent",
        "entity_id": agent.id,
        "source_surface": "agent_runtime_control",
        "input_signal_types": [
            "agent_action",
            f"action_type:{action_type}",
            decision.reason_code,
            f"data_classification:{data_classification}",
            "intent_aware_ai_action_control",
            f"intent_category:{intent_context.get('intent_category')}",
            f"input_sensitivity:{input_content_context.get('sensitivity_level')}",
            f"action_alignment:{action_alignment_result.get('alignment')}",
            f"finding_type:{intent_aware_decision.get('finding_type')}",
            *detection_signal_types(detection_result),
        ],
        "contains_sensitive": bool(detection_result.get("contains_sensitive")),
        "sensitive_confidence_score": float(detection_result.get("confidence_score") or 0.0),
        "sensitive_entities": list(detection_result.get("entities") or []),
        "sensitive_detection": detection_result,
        "guardian_policy_id": str((decision.policy or {}).get("policy_id") or ""),
        "guardian_policy_version": str((decision.policy or {}).get("policy_version") or ""),
        "guardian_framework_mapping": dict((decision.policy or {}).get("framework_mapping") or {}),
        "enforcement_routing": routing,
        "routing_fallback_audit_id": routing_fallback_audit_id,
        "routing_fallback_evidence_id": routing_fallback_evidence_id,
        "behavior_anomaly": behavior_anomaly,
        "identity_risk_score": identity_risk_score,
        "identity_risk_level": identity_risk_level,
        "identity_risk_reasoning": identity_risk_reasoning,
        "privilege_drift_detected": privilege_drift_detected,
        "delegation_misuse": delegation_misuse,
        "triggered_controls": list(control_decision.triggered_controls),
        "evaluated_controls": [item.to_dict() for item in control_decision.evaluated_controls],
        "dominant_control": control_decision.dominant_control,
        "control_decision_reasoning": control_decision.reasoning,
        "control_decision_total_risk": control_decision.total_risk_score,
        "risk_tags": list(control_decision.risk_tags),
        "pre_action_governance_check": pre_action_governance_check,
        "control_mode": pre_action_governance_check["control_mode"],
        "decision_badge": decision_badge_for_control_mode(pre_action_governance_check["control_mode"]),
        "intent_context": intent_context,
        "input_content_context": input_content_context,
        "output_context": output_context,
        "action_alignment_result": action_alignment_result,
        "intent_aware_decision": intent_aware_decision,
        "intent_category": intent_context.get("intent_category"),
        "intent_confidence": intent_context.get("intent_confidence"),
        "business_context": intent_context.get("business_context"),
        "input_sensitivity": input_content_context.get("sensitivity_level"),
        "output_sensitivity": output_context.get("output_sensitivity"),
        "action_alignment": action_alignment_result.get("alignment"),
        "destination_context": destination_context,
        "intent_aware_evidence_summary": intent_aware_evidence_summary,
        "matched_indicators": list(intent_aware_decision.get("matched_indicators") or []),
        "copy_export_control_applied": bool(intent_aware_decision.get("copy_export_control_applied")),
        "decision_reason": intent_aware_decision.get("decision_reason"),
    }
    monitoring_signal = MonitoringSignal(
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        signal_type="runtime_control.agent_action_intercept",
        severity=decision.severity,
        payload=signal_payload,
    )
    db.add(monitoring_signal)
    db.flush()

    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="runtime_control.agent_action_intercept",
        resource_type="monitoring_signal",
        resource_id=monitoring_signal.id,
        payload={
            "agent_id": agent.id,
            "ai_system_id": ai_system_id,
            "action_type": action_type,
            "tool_name": tool_name,
            "target_resource": target_resource,
            "decision": decision.decision,
            "reason_code": decision.reason_code,
            "policy_version": policy_version,
            "platform_mode": platform_mode,
            "chain_id": chain_id,
            "parent_action_id": parent_action_id,
            "data_classification": data_classification,
            "contains_sensitive": bool(detection_result.get("contains_sensitive")),
            "sensitive_confidence_score": float(detection_result.get("confidence_score") or 0.0),
            "sensitive_entities": list(detection_result.get("entities") or []),
            "enforcement_routing": routing,
            "routing_fallback_audit_id": routing_fallback_audit_id,
            "routing_fallback_evidence_id": routing_fallback_evidence_id,
            "guardian_policy_id": str((decision.policy or {}).get("policy_id") or ""),
            "guardian_policy_version": str((decision.policy or {}).get("policy_version") or ""),
            "behavior_anomaly": behavior_anomaly,
            "identity_risk_score": identity_risk_score,
            "identity_risk_level": identity_risk_level,
            "identity_risk_reasoning": identity_risk_reasoning,
            "privilege_drift_detected": privilege_drift_detected,
            "delegation_misuse": delegation_misuse,
            "triggered_controls": list(control_decision.triggered_controls),
            "dominant_control": control_decision.dominant_control,
            "control_decision_reasoning": control_decision.reasoning,
            "control_decision_total_risk": control_decision.total_risk_score,
            "risk_tags": list(control_decision.risk_tags),
            "intent_context": intent_context,
            "input_content_context": input_content_context,
            "output_context": output_context,
            "action_alignment_result": action_alignment_result,
            "intent_aware_decision": intent_aware_decision,
            "intent_category": intent_context.get("intent_category"),
            "intent_confidence": intent_context.get("intent_confidence"),
            "business_context": intent_context.get("business_context"),
            "input_sensitivity": input_content_context.get("sensitivity_level"),
            "output_sensitivity": output_context.get("output_sensitivity"),
            "action_alignment": action_alignment_result.get("alignment"),
            "matched_indicators": list(intent_aware_decision.get("matched_indicators") or []),
            "copy_export_control_applied": bool(intent_aware_decision.get("copy_export_control_applied")),
            "decision_reason": intent_aware_decision.get("decision_reason"),
            "destination_context": destination_context,
            "intent_aware_evidence_summary": intent_aware_evidence_summary,
        },
        correlation_id=correlation_id,
    )
    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="agent_action_intercept",
        signal_type="runtime_control.agent_action_intercept",
        label=f"Agent action {action_type} -> {decision.decision}",
        payload={
            "monitoring_signal_id": monitoring_signal.id,
            "agent_id": agent.id,
            "ai_system_id": ai_system_id,
            "action_type": action_type,
            "tool_name": tool_name,
            "target_resource": target_resource,
            "decision": decision.decision,
            "reason_code": decision.reason_code,
            "data_classification": data_classification,
            "chain_id": chain_id,
            "parent_action_id": parent_action_id,
            "contains_sensitive": bool(detection_result.get("contains_sensitive")),
            "sensitive_confidence_score": float(detection_result.get("confidence_score") or 0.0),
            "sensitive_entities": list(detection_result.get("entities") or []),
            "guardian_policy_id": str((decision.policy or {}).get("policy_id") or ""),
            "guardian_policy_version": str((decision.policy or {}).get("policy_version") or ""),
            "guardian_framework_mapping": dict((decision.policy or {}).get("framework_mapping") or {}),
            "enforcement_routing": routing,
            "routing_fallback_audit_id": routing_fallback_audit_id,
            "routing_fallback_evidence_id": routing_fallback_evidence_id,
            "behavior_anomaly": behavior_anomaly,
            "identity_risk_score": identity_risk_score,
            "identity_risk_level": identity_risk_level,
            "identity_risk_reasoning": identity_risk_reasoning,
            "privilege_drift_detected": privilege_drift_detected,
            "delegation_misuse": delegation_misuse,
            "triggered_controls": list(control_decision.triggered_controls),
            "dominant_control": control_decision.dominant_control,
            "control_decision_reasoning": control_decision.reasoning,
            "control_decision_total_risk": control_decision.total_risk_score,
            "risk_tags": list(control_decision.risk_tags),
            "pre_action_governance_check": pre_action_governance_check,
            "control_mode": pre_action_governance_check["control_mode"],
            "decision_badge": decision_badge_for_control_mode(pre_action_governance_check["control_mode"]),
            "intent_context": intent_context,
            "input_content_context": input_content_context,
            "output_context": output_context,
            "action_alignment_result": action_alignment_result,
            "intent_aware_decision": intent_aware_decision,
            "intent_category": intent_context.get("intent_category"),
            "intent_confidence": intent_context.get("intent_confidence"),
            "business_context": intent_context.get("business_context"),
            "input_sensitivity": input_content_context.get("sensitivity_level"),
            "output_sensitivity": output_context.get("output_sensitivity"),
            "action_alignment": action_alignment_result.get("alignment"),
            "matched_indicators": list(intent_aware_decision.get("matched_indicators") or []),
            "copy_export_control_applied": bool(intent_aware_decision.get("copy_export_control_applied")),
            "decision_reason": intent_aware_decision.get("decision_reason"),
            "destination_context": destination_context,
            "intent_aware_evidence_summary": intent_aware_evidence_summary,
        },
        correlation_id=correlation_id,
    )
    pre_action_governance_check["evidence"]["evidence_refs"] = [evidence.id]
    evidence.payload = {
        **dict(evidence.payload or {}),
        "pre_action_governance_check": pre_action_governance_check,
    }
    signal_payload["pre_action_governance_check"] = pre_action_governance_check
    monitoring_signal.payload = {
        **dict(monitoring_signal.payload or {}),
        "pre_action_governance_check": pre_action_governance_check,
    }
    anomaly_evidence = None
    if bool(behavior_anomaly.get("is_anomaly")):
        anomaly_evidence = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="behavior_anomaly",
            signal_type="ai_iam.behavior.anomaly",
            label=f"Agent anomaly {agent.id}:{action_type}",
            payload={
                "agent_id": agent.id,
                "action_type": action_type,
                "tool_name": tool_name,
                "baseline_rate_per_hour": behavior_anomaly.get("baseline_rate_per_hour"),
                "current_window_count": behavior_anomaly.get("current_window_count"),
                "spike_threshold": behavior_anomaly.get("spike_threshold"),
                "identity_risk_score": identity_risk_score,
                "identity_risk_level": identity_risk_level,
                "identity_risk_reasoning": identity_risk_reasoning,
            },
            correlation_id=correlation_id,
        )
        link_evidence_nodes(
            db,
            tenant_id=tenant_id,
            from_node_id=evidence.id,
            to_node_id=anomaly_evidence.id,
            edge_type="flags",
            payload={"reason": "agent_behavior_anomaly"},
        )

    event_evidence_ids = [evidence.id]
    if anomaly_evidence is not None:
        event_evidence_ids.append(anomaly_evidence.id)

    related_controls = [
        str(item).strip()
        for item in ((decision.policy or {}).get("framework_mapping") or {}).get("control_ids", ["CTRL-AI-IAM-001", "CTRL-TENANT-ISO-001"])
        if str(item).strip()
    ]
    related_controls = list(
        dict.fromkeys(
            [
                *related_controls,
                *list(control_decision.triggered_controls or []),
            ]
        )
    )
    finding = None
    if decision.reason_code == "unregistered_ai_system":
        finding = generate_unregistered_ai_system_finding(
            db,
            tenant_id=tenant_id,
            source_surface="aiiam",
            ai_tool=tool_name or action_type,
            requested_ai_system_id=ai_system_id,
            policy_version_id=policy_version,
            evidence_node_ids=event_evidence_ids,
            related_control_ids=related_controls,
            recommended_action="Unregistered AI system invoked by agent action. Route to governance before execution.",
        )
    elif decision.decision in {"warn", "block", "require_approval"}:
        finding = generate_agent_action_finding(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            agent_id=agent.id,
            action_type=action_type,
            tool_name=tool_name,
            target_resource=target_resource,
            decision=decision.decision,
            reason_code=decision.reason_code,
            policy_version_id=policy_version,
            evidence_node_ids=event_evidence_ids,
            recommended_action=decision.recommended_action,
            related_control_ids=related_controls,
        )
    if finding is not None:
        try:
            from app.services.remediation import propose_remediation_from_finding

            occurrence_count = int(finding.occurrence_count or 1)
            repeat_threshold = max(1, int(settings.runtime_intelligence_repeat_threshold or 3))
            trigger_bucket = 1 + ((occurrence_count - 1) // repeat_threshold)
            propose_remediation_from_finding(
                db,
                finding=finding,
                source_trigger_type="guardian_violation",
                context={
                    "finding_id": finding.finding_id,
                    "finding_type": finding.finding_type,
                    "reason_code": decision.reason_code,
                    "occurrence_count": occurrence_count,
                    "related_control_ids": related_controls,
                    "evidence_node_ids": event_evidence_ids,
                    "agent_id": agent.id,
                    "target_type": "agent",
                    "target_id": agent.id,
                    "tool_name": tool_name,
                    "target_resource": target_resource,
                    "ai_system_id": ai_system_id,
                    "identity_risk_score": identity_risk_score,
                    "identity_risk_level": identity_risk_level,
                    "identity_risk_reasoning": identity_risk_reasoning,
                    "privilege_drift_detected": privilege_drift_detected,
                    "behavior_anomaly": bool(behavior_anomaly.get("is_anomaly")),
                    "delegation_misuse": delegation_misuse,
                    "source_trigger_id": f"{finding.finding_id}:repeat_bucket:{trigger_bucket}",
                },
            )
        except Exception as exc:  # pragma: no cover - non-blocking remediation enrichment
            log_structured(
                "agent_action_remediation_proposal_failed",
                module="runtime_control_agent_action_service",
                tenant_id=tenant_id,
                agent_id=agent.id,
                finding_id=finding.finding_id,
                error=str(exc),
            )

    runtime_event_id: str | None = None
    try:
        from app.services.runtime_intelligence.runtime_event_normalizer import ingest_from_ai_iam_event

        runtime_row = ingest_from_ai_iam_event(
            db,
            tenant_id=tenant_id,
            event_type="agent_action_intercept",
            ai_system_id=ai_system_id,
            user_id=actor_user_id,
            agent_id=agent.id,
            severity=decision.severity,
            evidence_node_ids=event_evidence_ids,
            correlation_id=correlation_id,
            risk_score=identity_risk_score,
            trusted_pre_action_governance_check=pre_action_governance_check,
            metadata={
                "action": action_type,
                "decision": decision.decision,
                "reason": decision.reason_code,
                "tool_name": tool_name,
                "target_resource": target_resource,
                "chain_depth": derived_chain_depth,
                "claimed_chain_depth": claimed_chain_depth,
                "derived_chain_depth": derived_chain_depth,
                "chain_depth_authority_reason": chain_depth_authority_reason,
                "claimed_parent_agent_id": (
                    str(payload.get("parent_agent_id") or input_context.get("parent_agent_id") or "").strip() or None
                ),
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
                "chain_id": chain_id,
                "context_id": (correlation_id or chain_id),
                "parent_action_id": parent_action_id,
                "entity_type": "agent",
                "entity_id": agent.id,
                "effective_scopes": effective_scopes,
                "governance_state": governance_status.get("status"),
                "governance_enforcement_mode": governance_status.get("enforcement_mode"),
                "data_classification": data_classification,
                "contains_sensitive": bool(detection_result.get("contains_sensitive")),
                "sensitive_confidence_score": float(detection_result.get("confidence_score") or 0.0),
                "sensitive_entities": list(detection_result.get("entities") or []),
                "behavior_anomaly": behavior_anomaly,
                "identity_risk_score": identity_risk_score,
                "identity_risk_level": identity_risk_level,
                "identity_risk_reasoning": identity_risk_reasoning,
                "privilege_drift_detected": privilege_drift_detected,
                "delegation_misuse": delegation_misuse,
                "provider": provider,
                "model_provider": provider,
                "model_name": model_name,
                "model_version": model_version,
                "tool_category": "agent_action",
                "api_endpoint": api_endpoint,
                "parent_agent_id": str(input_context.get("parent_agent_id") or "").strip() or None,
                "enforcement_routing": routing,
                "routing_fallback_audit_id": routing_fallback_audit_id,
                "routing_fallback_evidence_id": routing_fallback_evidence_id,
                "triggered_controls": list(control_decision.triggered_controls),
                "dominant_control": control_decision.dominant_control,
                "control_decision_reasoning": control_decision.reasoning,
                "control_decision_total_risk": control_decision.total_risk_score,
                "risk_tags": list(control_decision.risk_tags),
                "pre_action_governance_check": pre_action_governance_check,
                "control_mode": pre_action_governance_check["control_mode"],
                "decision_badge": decision_badge_for_control_mode(pre_action_governance_check["control_mode"]),
                "intent_context": intent_context,
                "input_content_context": input_content_context,
                "output_context": output_context,
                "action_alignment_result": action_alignment_result,
                "intent_aware_decision": intent_aware_decision,
                "intent_category": intent_context.get("intent_category"),
                "intent_confidence": intent_context.get("intent_confidence"),
                "business_context": intent_context.get("business_context"),
                "input_sensitivity": input_content_context.get("sensitivity_level"),
                "output_sensitivity": output_context.get("output_sensitivity"),
                "action_alignment": action_alignment_result.get("alignment"),
                "matched_indicators": list(intent_aware_decision.get("matched_indicators") or []),
                "copy_export_control_applied": bool(intent_aware_decision.get("copy_export_control_applied")),
                "decision_reason": intent_aware_decision.get("decision_reason"),
            },
        )
        runtime_event_id = runtime_row.event_id if runtime_row is not None else None
    except Exception as exc:  # pragma: no cover - non-blocking runtime enrichment
        if isinstance(exc, CanonicalProjectionError):
            raise
        log_structured(
            "runtime_intelligence_ingest_failed",
            module="runtime_control_agent_action_service",
            tenant_id=tenant_id,
            event_type="agent_action_intercept",
            correlation_id=correlation_id,
            error=str(exc),
        )

    identity_financial = {
        "identity_id": agent.id,
        "risk_score": identity_risk_score,
        "blast_radius_score": 0.0,
        "crq": {},
        "risk_components": {},
    }
    try:
        identity_financial = get_agent_identity_financial_snapshot(
            db,
            tenant_id=tenant_id,
            identity_id=agent.id,
            lookback_hours=24 * 30,
        )
    except Exception as exc:  # pragma: no cover - non-blocking enrichment
        log_structured(
            "agent_identity_financial_snapshot_failed",
            module="runtime_control_agent_action_service",
            tenant_id=tenant_id,
            agent_id=agent.id,
            correlation_id=correlation_id,
            error=str(exc),
        )

    return {
        "decision": decision.decision,
        "reason_code": decision.reason_code,
        "explanation": decision.explanation,
        "recommended_action": decision.recommended_action,
        "approval_required": decision.decision == "require_approval",
        "audit_log_id": audit.id,
        "evidence_node_id": evidence.id,
        "finding_id": (finding.finding_id if finding is not None else None),
        "runtime_event_id": runtime_event_id,
        "chain_id": chain_id,
        "policy_version": policy_version,
        "platform_mode": platform_mode,
        "ai_system_id": ai_system_id,
        "agent_id": agent.id,
        "token_id": (token_row.id if token_row is not None else None),
        "identity_risk_score": float(identity_financial.get("risk_score") or identity_risk_score),
        "identity_risk_level": identity_risk_level,
        "identity_risk_reasoning": identity_risk_reasoning,
        "identity_blast_radius_score": float(identity_financial.get("blast_radius_score") or 0.0),
        "identity_crq": dict(identity_financial.get("crq") or {}),
        "identity_risk_components": dict(identity_financial.get("risk_components") or {}),
        "pre_action_governance_check": pre_action_governance_check,
        "control_mode": pre_action_governance_check["control_mode"],
        "decision_badge": decision_badge_for_control_mode(pre_action_governance_check["control_mode"]),
        "at": datetime.now(timezone.utc).isoformat(),
    }
