from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import TYPE_CHECKING, Any

from sqlalchemy.orm import Session

from app.core.control_engine import AIAction, evaluate_control_engine
from app.core.observability import get_correlation_id
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node
from app.services.action_integrity.execution_authority import install_generic_seam_authority, invoke_final_seam
from app.services.llm_gateway_secure.data_minimizer import (
    HIDDEN_INSTRUCTION_PATTERNS,
    minimization_mode,
    minimize_prompts,
    MaskingSession,
    ReversibleMaskingPolicy,
)
from app.services.llm_gateway_secure.prompt_registry import get_prompt_template_metadata
from app.services.llm_gateway_secure.schemas import (
    GuardOutcome,
    SecureCallContext,
    SecureModelCallResult,
    StoredDecisionSeamAuthority,
)
from app.services.llm_gateway_secure.transport_security import validate_transport_security
from app.services.runtime_intelligence.decision_impact_scoring import score_runtime_recommendation_impact
from app.services.sensitive_data_detection_service import detect_sensitive_data
from app.services.privacy_sanitizer import redact_sensitive_text

if TYPE_CHECKING:
    from app.services.brain.providers.base import LLMProvider


_PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+all\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"dan\s+mode", re.IGNORECASE),
    re.compile(r"override\s+policy", re.IGNORECASE),
    re.compile(
        r"(?:decompose|break(?:\s+down)?|split).{0,80}(?:prompt|request|payload|instructions?).{0,80}(?:into|as).{0,40}(?:steps?|parts?|chunks?)",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"(?:step[\s-]?by[\s-]?step|one\s+step\s+at\s+a\s+time).{0,120}(?:bypass|evade|avoid|circumvent|sidestep).{0,48}(?:policy|guard(?:rail)?s?|filter|detection|safety)",
        re.IGNORECASE | re.DOTALL,
    ),
]

_UNSAFE_OUTPUT_PATTERNS = [
    re.compile(r"BEGIN\s+(RSA|OPENSSH|EC)\s+PRIVATE\s+KEY", re.IGNORECASE),
    re.compile(r"password\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"api[_-]?key\s*[:=]\s*\S+", re.IGNORECASE),
]

_PROVIDER_COST_PER_1K_EST: dict[str, float] = {
    "openai": 0.02,
    "gpt": 0.02,
    "claude": 0.018,
    "anthropic": 0.018,
    "gemini": 0.01,
    "llama": 0.006,
    "oss_local": 0.006,
    "custom": 0.015,
    "mistral": 0.008,
    "azure_openai": 0.02,
}

_SENSITIVE_ENTITY_COLLECTION_KEYS = {
    "entities",
    "redaction_verification_entities",
    "sensitive_entities",
}


class ProviderStageError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("Model provider execution failed.")


def _invoke_provider_text(
    *,
    delegate: LLMProvider,
    system_prompt: str,
    user_prompt: str,
) -> str:
    provider_failed = False
    output: Any = None
    try:
        output = delegate.generate_text(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )
    except Exception:
        provider_failed = True
    if provider_failed or not isinstance(output, str):
        raise ProviderStageError() from None
    return output


def _invoke_provider_json(
    *,
    delegate: LLMProvider,
    system_prompt: str,
    user_prompt: str,
    json_schema: dict[str, Any],
) -> Any:
    provider_failed = False
    output: Any = None
    try:
        output = delegate.generate_json(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            json_schema=json_schema,
        )
    except Exception:
        provider_failed = True
    if provider_failed:
        raise ProviderStageError() from None
    return output


def _hash_text(value: str | None) -> str:
    text = value or ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class PreparedProviderPayload:
    system_prompt: str
    user_prompt: str
    prompt_material_hash: str
    material_hash: str
    call_material: dict[str, Any]
    minimizer_meta: dict[str, Any]
    response_schema: dict[str, Any] | None = field(default=None, repr=False, compare=False)
    masking_session: MaskingSession | None = field(default=None, repr=False, compare=False)


def _provider_call_material(
    *,
    system_prompt: str,
    user_prompt: str,
    provider: str,
    model: str,
    tool_context: list[str],
    response_schema_hash: str | None = None,
) -> dict[str, Any]:
    if len(tool_context or []) > 64:
        raise ValueError("tool_context exceeds maximum items")
    normalized_tools = [
        {
            "redacted": redact_sensitive_text(str(item or "").strip(), max_len=256),
            "material_hash": _hash_text(str(item or "").strip()),
        }
        for item in list(tool_context or [])
        if str(item or "").strip()
    ]
    material = {
        "call_material_schema": "1.0",
        "prompt_material_hash": _hash_text(f"{system_prompt}\n{user_prompt}"),
        "provider": _normalized_provider(provider),
        "model": str(model or "").strip(),
        "tool_context": normalized_tools,
    }
    if response_schema_hash is not None:
        material["response_schema_hash"] = response_schema_hash
    return material


def prepare_provider_payload(
    *,
    system_prompt: str,
    user_prompt: str,
    context: SecureCallContext,
    provider: str,
    model: str,
    tool_context: list[str] | None = None,
    response_schema: dict[str, Any] | None = None,
) -> PreparedProviderPayload:
    profile = dict(context.customer_policy_profile or {})
    mode = minimization_mode(data_sensitivity=context.data_sensitivity, policy_profile=profile)
    masking_policy = ReversibleMaskingPolicy.from_scope(profile.get("reversible_masking"))
    masking_session = MaskingSession(masking_policy) if masking_policy.enabled else None
    try:
        minimized_system, minimized_user, minimizer_meta = minimize_prompts(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            mode=mode,
            masking_session=masking_session,
        )
    except BaseException:
        if masking_session is not None:
            masking_session.destroy()
        raise
    private_response_schema: dict[str, Any] | None = None
    response_schema_hash: str | None = None
    if response_schema is not None:
        if not isinstance(response_schema, dict):
            if masking_session is not None:
                masking_session.destroy()
            raise ValueError("response schema must be an object")
        try:
            canonical_schema = _canonical_json(response_schema)
            private_response_schema = json.loads(canonical_schema)
        except (TypeError, ValueError, json.JSONDecodeError):
            if masking_session is not None:
                masking_session.destroy()
            raise ValueError("response schema must be JSON serializable") from None
        response_schema_hash = _hash_text(canonical_schema)
    call_material = _provider_call_material(
        system_prompt=minimized_system,
        user_prompt=minimized_user,
        provider=provider,
        model=model,
        tool_context=list(tool_context if tool_context is not None else context.tool_calls or []),
        response_schema_hash=response_schema_hash,
    )
    return PreparedProviderPayload(
        system_prompt=minimized_system,
        user_prompt=minimized_user,
        prompt_material_hash=call_material["prompt_material_hash"],
        material_hash=_hash_text(_compact_json(call_material)),
        call_material=call_material,
        minimizer_meta=minimizer_meta,
        response_schema=private_response_schema,
        masking_session=masking_session,
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _compact_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    except Exception:
        return "{}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalized_provider(value: str) -> str:
    token = str(value or "").strip().lower()
    if token in {"openai", "chatgpt", "gpt"}:
        return "openai"
    if token in {"anthropic", "claude"}:
        return "claude"
    if token in {"gemini"}:
        return "gemini"
    if token in {"llama", "oss", "local", "ollama", "oss_local"}:
        return "llama"
    if token in {"azure_openai", "azure-openai"}:
        return "azure_openai"
    return token


def _entity_type_counts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    counts: dict[str, int] = {}
    for item in value:
        if not isinstance(item, dict):
            continue
        entity_type = str(
            item.get("entity_type") or item.get("type") or "unknown"
        ).strip().lower()[:64]
        if not entity_type:
            entity_type = "unknown"
        raw_count = item.get("count")
        count = (
            int(raw_count)
            if isinstance(raw_count, int)
            and not isinstance(raw_count, bool)
            and raw_count > 0
            else 1
        )
        counts[entity_type] = counts.get(entity_type, 0) + count
    return [
        {"entity_type": entity_type, "count": counts[entity_type]}
        for entity_type in sorted(counts)
    ]


def _guard_trace_persistence_view(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            if key == "value_preview":
                continue
            if key in _SENSITIVE_ENTITY_COLLECTION_KEYS and isinstance(item, list):
                out[key] = _entity_type_counts(item)
            else:
                out[key] = _guard_trace_persistence_view(item)
        return out
    if isinstance(value, list):
        return [_guard_trace_persistence_view(item) for item in value]
    return value


def _route_policy_guard(*, context: SecureCallContext, provider: str) -> GuardOutcome:
    violations: list[str] = []
    checks: list[str] = []

    normalized_provider = _normalized_provider(provider)
    profile = dict(context.customer_policy_profile or {})

    checks.append("cost_ceiling")
    estimated_cost = float(_PROVIDER_COST_PER_1K_EST.get(normalized_provider, 0.025))
    if float(context.cost_ceiling_usd or 0.0) > 0.0 and estimated_cost > float(context.cost_ceiling_usd):
        violations.append("cost_ceiling_exceeded")

    checks.append("provider_allowlist")
    provider_allowlist = profile.get("provider_allowlist")
    if isinstance(provider_allowlist, list) and provider_allowlist:
        normalized_allow = {str(item).strip().lower() for item in provider_allowlist if str(item).strip()}
        if normalized_provider not in normalized_allow:
            violations.append("provider_not_allowlisted")

    checks.append("residency_policy")
    if context.residency_required:
        allowed_regions = profile.get("allowed_regions")
        if isinstance(allowed_regions, list) and allowed_regions:
            normalized_regions = {str(item).strip().lower() for item in allowed_regions if str(item).strip()}
            if str(context.region_requirement or context.customer_region or "global").strip().lower() not in normalized_regions:
                violations.append("region_not_allowed")

    checks.append("sensitivity_to_provider")
    if context.data_sensitivity in {"sensitive", "restricted"}:
        blocked = profile.get("blocked_sensitive_providers")
        if isinstance(blocked, list) and blocked:
            blocked_set = {str(item).strip().lower() for item in blocked if str(item).strip()}
            if normalized_provider in blocked_set:
                violations.append("provider_blocked_for_sensitive_data")

    if violations:
        return GuardOutcome(
            passed=False,
            reason="routing_policy_rejected",
            details={
                "checks": checks,
                "violations": violations,
                "provider": normalized_provider,
                "cost_per_1k_est": estimated_cost,
            },
        )
    return GuardOutcome(
        passed=True,
        reason="routing_policy_ok",
        details={
            "checks": checks,
            "violations": [],
            "provider": normalized_provider,
            "cost_per_1k_est": estimated_cost,
        },
    )


def _tool_call_guard(*, context: SecureCallContext) -> GuardOutcome:
    profile = dict(context.customer_policy_profile or {})
    requested = [str(item).strip().lower() for item in (context.tool_calls or []) if str(item).strip()]
    if not requested:
        return GuardOutcome(passed=True, reason="tool_call_guard_not_applicable", details={"requested_tools": []})

    allowed_tools = profile.get("allowed_tools")
    if isinstance(allowed_tools, list) and allowed_tools:
        allow_set = {str(item).strip().lower() for item in allowed_tools if str(item).strip()}
        disallowed = [item for item in requested if item not in allow_set]
        if disallowed:
            return GuardOutcome(
                passed=False,
                reason="tool_not_authorized",
                details={
                    "requested_tools": requested,
                    "disallowed_tools": disallowed,
                },
            )

    high_risk_markers = ("shell", "sudo", "terminal", "db_admin", "filesystem")
    if not bool(profile.get("allow_high_risk_tools")):
        risky = [item for item in requested if any(marker in item for marker in high_risk_markers)]
        if risky:
            return GuardOutcome(
                passed=False,
                reason="high_risk_tool_requires_approval",
                details={"requested_tools": requested, "risky_tools": risky},
            )

    return GuardOutcome(
        passed=True,
        reason="tool_call_guard_ok",
        details={"requested_tools": requested},
    )


def _pre_call_guard(
    *,
    context: SecureCallContext,
    system_prompt: str,
    user_prompt: str,
) -> GuardOutcome:
    text = f"{system_prompt}\n{user_prompt}".strip()
    detection = detect_sensitive_data(text_inputs=[text], correlation_id="secure-gateway-pre")

    matches: list[str] = []
    for pattern in _PROMPT_INJECTION_PATTERNS:
        if pattern.search(text):
            matches.append(pattern.pattern)

    violations: list[str] = []
    actions: list[str] = []

    if matches:
        actions.append("prompt_injection_detected")
        if context.data_sensitivity in {"sensitive", "restricted"}:
            violations.append("prompt_injection_blocked")

    contains_sensitive = bool(detection.get("contains_sensitive"))
    if contains_sensitive and context.data_sensitivity == "restricted":
        allow_raw = bool((context.customer_policy_profile or {}).get("allow_raw_restricted_prompt_data"))
        if not allow_raw:
            violations.append("restricted_sensitive_payload_requires_redaction")

    if violations:
        return GuardOutcome(
            passed=False,
            reason="pre_call_policy_rejected",
            details={
                "violations": violations,
                "actions": actions,
                "prompt_injection_matches": matches,
                "sensitive_detected": contains_sensitive,
                "sensitive_entities": list(detection.get("entities") or []),
            },
        )

    return GuardOutcome(
        passed=True,
        reason="pre_call_guard_ok",
        details={
            "violations": [],
            "actions": actions,
            "prompt_injection_matches": matches,
            "sensitive_detected": contains_sensitive,
            "sensitive_entities": list(detection.get("entities") or []),
        },
    )


def _post_call_guard(*, context: SecureCallContext, response_text: str) -> GuardOutcome:
    detection = detect_sensitive_data(text_inputs=[response_text], correlation_id="secure-gateway-post")
    matches: list[str] = []
    for pattern in _UNSAFE_OUTPUT_PATTERNS:
        if pattern.search(response_text):
            matches.append(pattern.pattern)
    for pattern in HIDDEN_INSTRUCTION_PATTERNS:
        if pattern.search(response_text):
            matches.append(pattern.pattern)

    actions: list[str] = []
    violations: list[str] = []

    if matches:
        actions.append("unsafe_output_detected")

    if bool(detection.get("contains_sensitive")) and context.data_sensitivity in {"sensitive", "restricted"}:
        action = str((context.customer_policy_profile or {}).get("post_call_sensitive_action") or "redact").strip().lower()
        if context.data_sensitivity == "restricted" or action == "block":
            violations.append("post_call_sensitive_output_blocked")
        else:
            actions.append("post_call_sensitive_output_redacted")

    if violations:
        return GuardOutcome(
            passed=False,
            reason="post_call_policy_rejected",
            details={
                "violations": violations,
                "actions": actions,
                "unsafe_output_matches": matches,
                "sensitive_detected": bool(detection.get("contains_sensitive")),
                "sensitive_entities": list(detection.get("entities") or []),
                "redaction_applied": False,
            },
        )

    return GuardOutcome(
        passed=True,
        reason="post_call_guard_ok",
        details={
            "violations": [],
            "actions": actions,
            "unsafe_output_matches": matches,
            "sensitive_detected": bool(detection.get("contains_sensitive")),
            "sensitive_entities": list(detection.get("entities") or []),
            "redaction_applied": False,
        },
    )


def _apply_verified_post_call_redaction(
    *,
    response_text: str,
    post_call_guard: GuardOutcome,
) -> tuple[str, GuardOutcome]:
    actions = list(post_call_guard.details.get("actions") or [])
    if "post_call_sensitive_output_redacted" not in actions:
        return response_text, post_call_guard

    redacted_text = redact_sensitive_text(
        response_text,
        max_len=max(1, len(response_text)),
    )
    verification = detect_sensitive_data(
        text_inputs=[redacted_text],
        correlation_id="secure-gateway-post-redaction-verification",
    )
    if redacted_text == response_text or bool(verification.get("contains_sensitive")):
        safe_actions = [
            action
            for action in actions
            if action != "post_call_sensitive_output_redacted"
        ]
        safe_actions.append("post_call_sensitive_output_redaction_unverified")
        violations = list(post_call_guard.details.get("violations") or [])
        violations.append("post_call_sensitive_output_redaction_unverified")
        return response_text, GuardOutcome(
            passed=False,
            reason="post_call_policy_rejected",
            details={
                **post_call_guard.details,
                "actions": safe_actions,
                "violations": violations,
                "redaction_applied": False,
                "redaction_verification_entities": list(
                    verification.get("entities") or []
                ),
            },
        )

    return redacted_text, GuardOutcome(
        passed=True,
        reason=post_call_guard.reason,
        details={
            **post_call_guard.details,
            "redaction_applied": True,
            "redaction_verification_entities": [],
        },
    )


def _merge_pre_guards(*, raw_guard: GuardOutcome, minimized_guard: GuardOutcome) -> GuardOutcome:
    raw_violations = list(raw_guard.details.get("violations") or [])
    minimized_violations = list(minimized_guard.details.get("violations") or [])
    violations = [*raw_violations, *[item for item in minimized_violations if item not in raw_violations]]
    if violations:
        return GuardOutcome(
            passed=False,
            reason="pre_call_policy_rejected",
            details={
                "violations": violations,
                "raw_guard": raw_guard.details,
                "minimized_guard": minimized_guard.details,
            },
        )
    return GuardOutcome(
        passed=True,
        reason="pre_call_guard_ok",
        details={
            "violations": [],
            "raw_guard": raw_guard.details,
            "minimized_guard": minimized_guard.details,
        },
    )


def _build_trace(
    *,
    context: SecureCallContext,
    provider: str,
    model: str,
    model_version: str,
    input_hash: str,
    redacted_input_ref: str,
    response_hash: str,
    redacted_output_ref: str,
    retrieval_sources: list[str],
    pre_call_guard: GuardOutcome,
    post_call_guard: GuardOutcome,
    latency_ms: int,
    cost_estimate: float,
    correlation_id: str | None,
) -> dict[str, Any]:
    template_meta = get_prompt_template_metadata(context.task_type)

    recommendation_type = "tighten_policy" if not post_call_guard.passed or not pre_call_guard.passed else "alert_only"
    crq = score_runtime_recommendation_impact(
        recommendation_type=recommendation_type,
        severity=context.risk_tier,
        repeated_count=1,
        pattern_frequency=1,
        metadata={
            "data_classification": context.data_sensitivity,
            "exposure_level": 0.8 if context.data_sensitivity in {"sensitive", "restricted"} else 0.35,
            "system_criticality": context.risk_tier,
            "event_created_at": _now_iso(),
        },
        cross_session={"is_long_term_pattern": False},
    ).as_dict()

    return {
        "trace_id": f"llm-sec-{_hash_text(f'{provider}:{model}:{input_hash}:{response_hash}')[:16]}",
        "timestamp": _now_iso(),
        "task_type": context.task_type,
        "provider": provider,
        "model": model,
        "model_version": model_version,
        "prompt_template_id": context.prompt_template_id or str(template_meta.get("template_id") or ""),
        "prompt_template_version": context.prompt_template_version or str(template_meta.get("template_version") or ""),
        "input_hash": input_hash,
        "redacted_input_ref": redacted_input_ref,
        "retrieval_sources": retrieval_sources,
        "tool_calls": list(context.tool_calls or []),
        "policy_applied": context.policy_applied,
        "sensitivity_level": context.data_sensitivity,
        "routing_decision": {
            "risk_tier": context.risk_tier,
            "cost_ceiling_usd": context.cost_ceiling_usd,
            "region_requirement": context.region_requirement,
            "residency_requirement": context.residency_requirement,
            "residency_required": context.residency_required,
            "customer_region": context.customer_region,
            "customer_policy_profile": dict(context.customer_policy_profile or {}),
        },
        "response_hash": response_hash,
        "redacted_output_ref": redacted_output_ref,
        "latency_ms": latency_ms,
        "cost_estimate": round(float(cost_estimate), 6),
        "pre_call_guard": {
            "passed": pre_call_guard.passed,
            "reason": pre_call_guard.reason,
            "details": _guard_trace_persistence_view(pre_call_guard.details),
        },
        "post_call_guard": {
            "passed": post_call_guard.passed,
            "reason": post_call_guard.reason,
            "details": _guard_trace_persistence_view(post_call_guard.details),
        },
        "decision_impact": crq,
        "correlation_id": correlation_id,
    }


def _persist_trace(
    db: Session | None,
    *,
    tenant_id: str | None,
    actor_user_id: str | None,
    correlation_id: str | None,
    trace: dict[str, Any],
) -> tuple[str | None, str | None]:
    if db is None or not tenant_id:
        return None, None

    persisted_trace = _guard_trace_persistence_view(trace)
    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human" if actor_user_id else "system",
        action="llm_gateway_secure.call",
        resource_type="llm_provider",
        resource_id=str(trace.get("provider") or "unknown"),
        payload={
            "task_type": str(persisted_trace.get("task_type") or ""),
            "trace_id": persisted_trace.get("trace_id"),
            "provider": persisted_trace.get("provider"),
            "model": persisted_trace.get("model"),
            "prompt_template_id": persisted_trace.get("prompt_template_id"),
            "prompt_template_version": persisted_trace.get("prompt_template_version"),
            "policy_applied": persisted_trace.get("policy_applied"),
            "sensitivity_level": persisted_trace.get("sensitivity_level"),
            "pre_call_guard": persisted_trace.get("pre_call_guard"),
            "post_call_guard": persisted_trace.get("post_call_guard"),
        },
        correlation_id=correlation_id,
    )

    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="llm_call_trace",
        signal_type="llm_gateway_secure.call",
        label=f"LLM secure call {trace.get('provider')}:{trace.get('model')}",
        payload={
            **persisted_trace,
            "audit_log_id": audit.id,
        },
        correlation_id=correlation_id,
    )
    return audit.id, evidence.id


def _control_decision(
    *,
    provider: str,
    model: str,
    user_prompt: str,
    context: SecureCallContext,
    pre_guard: GuardOutcome,
) -> dict[str, Any]:
    decision_hint = "allow" if pre_guard.passed else "block"
    signal_types = ["llm_gateway_secure"]
    if pre_guard.details.get("prompt_injection_matches"):
        signal_types.append("prompt_injection")
    if pre_guard.details.get("sensitive_detected"):
        signal_types.append("sensitive_data")

    control = evaluate_control_engine(
        AIAction(
            action_id=f"llm_secure:{_hash_text(user_prompt)[:12]}",
            user_id=None,
            ai_app=provider,
            model=model,
            prompt=user_prompt,
            metadata={
                "source_surface": "gateway",
                "action_type": "prompt",
                "decision": decision_hint,
                "input_signal_types": signal_types,
                "data_classification": context.data_sensitivity,
                "contains_sensitive": bool(pre_guard.details.get("sensitive_detected")),
            },
            source_surface="gateway",
        ),
        base_decision=decision_hint,
    )
    return control.to_dict()


def _fail_result(*, reason: str, pre_call_guard: GuardOutcome, trace: dict[str, Any]) -> SecureModelCallResult:
    return SecureModelCallResult(
        blocked=True,
        block_reason=reason,
        output_text=None,
        output_json=None,
        pre_call_guard={
            "passed": pre_call_guard.passed,
            "reason": pre_call_guard.reason,
            "details": pre_call_guard.details,
        },
        post_call_guard={"passed": False, "reason": reason, "details": {"blocked": True}},
        trace=trace,
    )


def secure_generate_json(
    *,
    delegate: LLMProvider,
    provider: str,
    model: str,
    model_version: str,
    system_prompt: str,
    user_prompt: str,
    json_schema: dict[str, Any],
    context: SecureCallContext,
    db: Session | None = None,
    tenant_id: str | None = None,
    actor_user_id: str | None = None,
    correlation_id: str | None = None,
    stored_decision_authority: StoredDecisionSeamAuthority | None = None,
) -> SecureModelCallResult:
    corr = correlation_id or get_correlation_id()
    profile = dict(context.customer_policy_profile or {})

    transport_guard = validate_transport_security(provider=provider, policy_profile=profile)
    route_guard = _route_policy_guard(context=context, provider=provider)
    tool_guard = _tool_call_guard(context=context)

    raw_pre_guard = _pre_call_guard(context=context, system_prompt=system_prompt, user_prompt=user_prompt)
    mode = minimization_mode(data_sensitivity=context.data_sensitivity, policy_profile=profile)
    minimized_system, minimized_user, minimizer_meta = minimize_prompts(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        mode=mode,
    )
    minimized_pre_guard = _pre_call_guard(context=context, system_prompt=minimized_system, user_prompt=minimized_user)
    pre_guard = _merge_pre_guards(raw_guard=raw_pre_guard, minimized_guard=minimized_pre_guard)
    control_decision = _control_decision(
        provider=provider,
        model=model,
        user_prompt=minimized_user,
        context=context,
        pre_guard=pre_guard,
    )

    input_hash = _hash_text(f"{system_prompt}\n{user_prompt}")
    redacted_input_ref = _hash_text(f"{minimized_system}\n{minimized_user}")

    pre_violations: list[str] = []
    for guard in [transport_guard, route_guard, tool_guard, pre_guard]:
        if not guard.passed:
            pre_violations.append(guard.reason)

    if pre_violations:
        trace = _build_trace(
            context=context,
            provider=provider,
            model=model,
            model_version=model_version,
            input_hash=input_hash,
            redacted_input_ref=redacted_input_ref,
            response_hash="",
            redacted_output_ref="",
            retrieval_sources=list(context.retrieval_sources or []),
            pre_call_guard=GuardOutcome(
                passed=False,
                reason="pre_call_policy_rejected",
                details={
                    "violations": pre_violations,
                    "transport_guard": transport_guard.details,
                    "routing_guard": route_guard.details,
                    "tool_guard": tool_guard.details,
                    "policy_guard": pre_guard.details,
                    "minimizer": minimizer_meta,
                    "control_decision": control_decision,
                },
            ),
            post_call_guard=GuardOutcome(passed=False, reason="not_executed", details={}),
            latency_ms=0,
            cost_estimate=0.0,
            correlation_id=corr,
        )
        audit_log_id, evidence_node_id = _persist_trace(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=corr,
            trace=trace,
        )
        trace.update({"audit_log_id": audit_log_id, "evidence_node_id": evidence_node_id})
        return _fail_result(reason="pre_call_policy_rejected", pre_call_guard=pre_guard, trace=trace)

    started = datetime.now(timezone.utc)
    authority = stored_decision_authority
    install_generic_seam_authority(
        db, tenant_id=tenant_id, seam_ref="llm.provider.json",
        action_id=authority.action_id if authority else f"llm-json:{input_hash[:48]}",
        chain_id=authority.chain_id if authority else corr,
        actor_principal=authority.actor_principal if authority else f"user:{actor_user_id or 'unknown'}",
        executing_principal="service:llm-gateway", operation="model_generate_json",
        tool_or_service_ref=f"{provider}:{model}", parameter_hash=authority.parameter_hash if authority else input_hash,
        target_ref=authority.target_ref if authority else f"model:{provider}:{model}",
        decision_receipt_id=authority.decision_receipt_id if authority else None,
    )
    raw_output = invoke_final_seam(
        db,
        seam_ref="llm.provider.json",
        executor=lambda: _invoke_provider_json(
            delegate=delegate,
            system_prompt=minimized_system,
            user_prompt=minimized_user,
            json_schema=json_schema,
        ),
    )
    latency_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    if not isinstance(raw_output, dict):
        raw_output = {"value": raw_output}

    response_payload = _compact_json(raw_output)
    post_guard = _post_call_guard(context=context, response_text=response_payload)
    controlled_response_payload, post_guard = _apply_verified_post_call_redaction(
        response_text=response_payload,
        post_call_guard=post_guard,
    )

    response_hash = _hash_text(response_payload)
    redacted_output_ref = _hash_text(controlled_response_payload)

    controlled_output: dict[str, Any] | None = None
    if post_guard.passed:
        try:
            parsed_output = json.loads(controlled_response_payload)
        except (TypeError, ValueError):
            parsed_output = None
        if isinstance(parsed_output, dict):
            controlled_output = parsed_output
        else:
            post_guard = GuardOutcome(
                passed=False,
                reason="post_call_policy_rejected",
                details={
                    **post_guard.details,
                    "violations": [
                        *list(post_guard.details.get("violations") or []),
                        "post_call_redacted_output_invalid",
                    ],
                    "redaction_applied": False,
                },
            )

    if not post_guard.passed:
        trace = _build_trace(
            context=context,
            provider=provider,
            model=model,
            model_version=model_version,
            input_hash=input_hash,
            redacted_input_ref=redacted_input_ref,
            response_hash=response_hash,
            redacted_output_ref=redacted_output_ref,
            retrieval_sources=list(context.retrieval_sources or []),
            pre_call_guard=pre_guard,
            post_call_guard=post_guard,
            latency_ms=latency_ms,
            cost_estimate=float(_PROVIDER_COST_PER_1K_EST.get(_normalized_provider(provider), 0.02)),
            correlation_id=corr,
        )
        audit_log_id, evidence_node_id = _persist_trace(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=corr,
            trace=trace,
        )
        trace.update({"audit_log_id": audit_log_id, "evidence_node_id": evidence_node_id})
        return SecureModelCallResult(
            blocked=True,
            block_reason="post_call_policy_rejected",
            output_text=None,
            output_json=None,
            pre_call_guard={"passed": pre_guard.passed, "reason": pre_guard.reason, "details": pre_guard.details},
            post_call_guard={"passed": post_guard.passed, "reason": post_guard.reason, "details": post_guard.details},
            trace=trace,
        )

    trace = _build_trace(
        context=context,
        provider=provider,
        model=model,
        model_version=model_version,
        input_hash=input_hash,
        redacted_input_ref=redacted_input_ref,
        response_hash=response_hash,
        redacted_output_ref=redacted_output_ref,
        retrieval_sources=list(context.retrieval_sources or []),
        pre_call_guard=GuardOutcome(
            passed=True,
            reason="ok",
            details={
                "transport_guard": transport_guard.details,
                "routing_guard": route_guard.details,
                "tool_guard": tool_guard.details,
                "policy_guard": pre_guard.details,
                "minimizer": minimizer_meta,
                "control_decision": control_decision,
            },
        ),
        post_call_guard=post_guard,
        latency_ms=latency_ms,
        cost_estimate=float(_PROVIDER_COST_PER_1K_EST.get(_normalized_provider(provider), 0.02)),
        correlation_id=corr,
    )
    audit_log_id, evidence_node_id = _persist_trace(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        correlation_id=corr,
        trace=trace,
    )
    trace.update({"audit_log_id": audit_log_id, "evidence_node_id": evidence_node_id})

    return SecureModelCallResult(
        blocked=False,
        block_reason=None,
        output_text=None,
        output_json=controlled_output,
        pre_call_guard={
            "passed": True,
            "reason": "ok",
            "details": dict(trace.get("pre_call_guard", {}).get("details") or {}),
        },
        post_call_guard={
            "passed": post_guard.passed,
            "reason": post_guard.reason,
            "details": post_guard.details,
        },
        trace=trace,
    )


def secure_generate_text(
    *,
    delegate: LLMProvider,
    provider: str,
    model: str,
    model_version: str,
    system_prompt: str,
    user_prompt: str,
    context: SecureCallContext,
    db: Session | None = None,
    tenant_id: str | None = None,
    actor_user_id: str | None = None,
    correlation_id: str | None = None,
    prepared_payload: PreparedProviderPayload | None = None,
    response_schema: dict[str, Any] | None = None,
    stored_decision_authority: StoredDecisionSeamAuthority | None = None,
) -> SecureModelCallResult:
    corr = correlation_id or get_correlation_id()
    profile = dict(context.customer_policy_profile or {})

    transport_guard = validate_transport_security(provider=provider, policy_profile=profile)
    route_guard = _route_policy_guard(context=context, provider=provider)
    tool_guard = _tool_call_guard(context=context)

    raw_pre_guard = _pre_call_guard(context=context, system_prompt=system_prompt, user_prompt=user_prompt)
    prepared = prepared_payload or prepare_provider_payload(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        context=context,
        provider=provider,
        model=model,
        tool_context=list(context.tool_calls or []),
        response_schema=response_schema,
    )
    if prepared_payload is not None and response_schema is not None:
        try:
            requested_schema_hash = _hash_text(_canonical_json(response_schema))
            prepared_schema_hash = (
                _hash_text(_canonical_json(prepared.response_schema))
                if prepared.response_schema is not None else None
            )
        except (TypeError, ValueError):
            raise ValueError("response schema must be JSON serializable") from None
        if requested_schema_hash != prepared_schema_hash:
            raise ValueError("prepared response schema hash is invalid")
    minimized_system = prepared.system_prompt
    minimized_user = prepared.user_prompt
    minimizer_meta = prepared.minimizer_meta
    expected_call_material = _provider_call_material(
        system_prompt=minimized_system,
        user_prompt=minimized_user,
        provider=provider,
        model=model,
        tool_context=list(context.tool_calls or []),
        response_schema_hash=(
            _hash_text(_canonical_json(prepared.response_schema))
            if prepared.response_schema is not None else None
        ),
    )
    if (
        prepared.prompt_material_hash != _hash_text(f"{minimized_system}\n{minimized_user}")
        or prepared.call_material != expected_call_material
        or prepared.material_hash != _hash_text(_compact_json(expected_call_material))
    ):
        raise ValueError("prepared provider payload hash is invalid")

    minimized_pre_guard = _pre_call_guard(context=context, system_prompt=minimized_system, user_prompt=minimized_user)
    pre_guard = _merge_pre_guards(raw_guard=raw_pre_guard, minimized_guard=minimized_pre_guard)
    control_decision = _control_decision(
        provider=provider,
        model=model,
        user_prompt=minimized_user,
        context=context,
        pre_guard=pre_guard,
    )

    input_hash = _hash_text(f"{system_prompt}\n{user_prompt}")
    redacted_input_ref = prepared.material_hash

    pre_violations: list[str] = []
    for guard in [transport_guard, route_guard, tool_guard, pre_guard]:
        if not guard.passed:
            pre_violations.append(guard.reason)

    if pre_violations:
        trace = _build_trace(
            context=context,
            provider=provider,
            model=model,
            model_version=model_version,
            input_hash=input_hash,
            redacted_input_ref=redacted_input_ref,
            response_hash="",
            redacted_output_ref="",
            retrieval_sources=list(context.retrieval_sources or []),
            pre_call_guard=GuardOutcome(
                passed=False,
                reason="pre_call_policy_rejected",
                details={
                    "violations": pre_violations,
                    "transport_guard": transport_guard.details,
                    "routing_guard": route_guard.details,
                    "tool_guard": tool_guard.details,
                    "policy_guard": pre_guard.details,
                    "minimizer": minimizer_meta,
                    "control_decision": control_decision,
                },
            ),
            post_call_guard=GuardOutcome(passed=False, reason="not_executed", details={}),
            latency_ms=0,
            cost_estimate=0.0,
            correlation_id=corr,
        )
        audit_log_id, evidence_node_id = _persist_trace(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=corr,
            trace=trace,
        )
        trace.update({"audit_log_id": audit_log_id, "evidence_node_id": evidence_node_id})
        return _fail_result(reason="pre_call_policy_rejected", pre_call_guard=pre_guard, trace=trace)

    started = datetime.now(timezone.utc)
    authority = stored_decision_authority
    install_generic_seam_authority(
        db, tenant_id=tenant_id, seam_ref="llm.provider.text",
        action_id=authority.action_id if authority else f"llm-text:{input_hash[:48]}",
        chain_id=authority.chain_id if authority else corr,
        actor_principal=authority.actor_principal if authority else f"user:{actor_user_id or 'unknown'}",
        executing_principal="service:llm-gateway", operation="model_generate_text",
        tool_or_service_ref=f"{provider}:{model}", parameter_hash=authority.parameter_hash if authority else input_hash,
        target_ref=authority.target_ref if authority else f"model:{provider}:{model}",
        decision_receipt_id=authority.decision_receipt_id if authority else None,
    )
    if prepared.response_schema is None:
        raw_output_text = invoke_final_seam(
            db,
            seam_ref="llm.provider.text",
            executor=lambda: _invoke_provider_text(
                delegate=delegate,
                system_prompt=minimized_system,
                user_prompt=minimized_user,
            ),
        )
    else:
        raw_structured_output = invoke_final_seam(
            db,
            seam_ref="llm.provider.text",
            executor=lambda: _invoke_provider_json(
                delegate=delegate,
                system_prompt=minimized_system,
                user_prompt=minimized_user,
                json_schema=prepared.response_schema or {},
            ),
        )
        if not isinstance(raw_structured_output, dict):
            raise ProviderStageError() from None
        try:
            raw_output_text = _canonical_json(raw_structured_output)
        except (TypeError, ValueError):
            raise ProviderStageError() from None
    latency_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)

    post_guard = _post_call_guard(context=context, response_text=raw_output_text)
    controlled_output_text, post_guard = _apply_verified_post_call_redaction(
        response_text=raw_output_text,
        post_call_guard=post_guard,
    )
    response_hash = _hash_text(raw_output_text)
    redacted_output_ref = _hash_text(controlled_output_text)

    final_text = controlled_output_text
    if not post_guard.passed:
        final_text = "Response blocked by secure output policy."

    trace = _build_trace(
        context=context,
        provider=provider,
        model=model,
        model_version=model_version,
        input_hash=input_hash,
        redacted_input_ref=redacted_input_ref,
        response_hash=response_hash,
        redacted_output_ref=redacted_output_ref,
        retrieval_sources=list(context.retrieval_sources or []),
        pre_call_guard=GuardOutcome(
            passed=True,
            reason="ok",
            details={
                "transport_guard": transport_guard.details,
                "routing_guard": route_guard.details,
                "tool_guard": tool_guard.details,
                "policy_guard": pre_guard.details,
                "minimizer": minimizer_meta,
                "control_decision": control_decision,
            },
        ),
        post_call_guard=post_guard,
        latency_ms=latency_ms,
        cost_estimate=float(_PROVIDER_COST_PER_1K_EST.get(_normalized_provider(provider), 0.02)),
        correlation_id=corr,
    )

    audit_log_id, evidence_node_id = _persist_trace(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        correlation_id=corr,
        trace=trace,
    )
    trace.update({"audit_log_id": audit_log_id, "evidence_node_id": evidence_node_id})

    return SecureModelCallResult(
        blocked=not post_guard.passed,
        block_reason=("post_call_policy_rejected" if not post_guard.passed else None),
        output_text=final_text,
        output_json=None,
        pre_call_guard={"passed": True, "reason": "ok", "details": trace.get("pre_call_guard", {})},
        post_call_guard={
            "passed": post_guard.passed,
            "reason": post_guard.reason,
            "details": post_guard.details,
        },
        trace=trace,
    )
