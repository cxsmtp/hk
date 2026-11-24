from __future__ import annotations

import hashlib
import base64
import json
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.control_engine import AIAction, evaluate_control_engine, map_generic_decision
from app.core.config import settings
from app.core.observability import get_correlation_id
from app.core.provenance import (
    is_authoritative_provenance_id,
    validate_authoritative_provenance_id,
)
from app.core.response_control import (
    ResponseControlCoverage,
    normalize_response_control_coverage,
)
from app.db.models.ai_system import AISystem
from app.db.models.enforcement import EnforcementEvent
from app.db.models.policy import PolicyVersion, TenantSectorProfile
from app.db.models.user import User, UserTenantRole
from app.services.audit_service import write_audit_log
from app.services.brain.providers.provider_factory import get_provider
from app.services.evidence_service import create_evidence_node, link_evidence_nodes
from app.services.enforcement_payload_crypto_service import encrypt_enforcement_prompt
from app.services.findings_service import generate_from_enforcement_event
from app.services.governance_guard import GOVERNANCE_VERSION, enforce as enforce_governance
from app.services.ai_iam_service import build_ai_action_record, control_mode_for_pre_action_decision
from app.services.llm_gateway_secure import (
    ProviderStageError,
    SecureCallContext,
    StoredDecisionSeamAuthority,
    prepare_provider_payload,
    secure_generate_text,
)
from app.services.llm_gateway_secure.data_minimizer import ReversibleMaskingPolicy, MaskingSession
from app.services.llm_gateway_secure.document_codec import (
    DOCX_MIME,
    PDF_MIME,
    DocumentCodecError,
    parse_document,
    render_document,
    safe_download_name,
    serialize_transform,
    validate_draft_response,
    validate_transform_edits_response,
)
from app.services.policy_service import evaluate_business_purpose_boundary


DECISION_PRECEDENCE = ["block", "hold_for_approval", "redact", "warn", "allow"]
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
GUARDIAN_CONTROL_MAP = {
    "prompt_guardian": "CTRL-INPUT-001",
    "data_guardian": "CTRL-DLP-001",
    "tool_guardian": "CTRL-TOOL-001",
    "output_guardian": "CTRL-OUTPUT-001",
}
PROVIDER_ALIASES = {
    "openai": "openai",
    "anthropic": "anthropic",
    "claude": "anthropic",
    "gemini": "gemini",
    "mistral": "mistral",
    "custom": "custom",
    "oss": "oss_local",
    "local": "oss_local",
    "ollama": "oss_local",
    "llama_cpp": "oss_local",
    "llama.cpp": "oss_local",
    "azure_openai": "azure_openai",
    "azure-openai": "azure_openai",
}

REVERSIBLE_MASKING_SYSTEM_INSTRUCTION = (
    "Gateway-generated opaque identifiers refer to sensitive values retained only by the gateway. "
    "These identifiers contain no underlying value. Preserve each identifier character-for-character "
    "when using supplied facts, including repetitions. Never infer or invent its hidden value. "
    "Existing instructions and safety requirements continue to apply."
)

def _document_response_schema(mode: str) -> dict[str, Any]:
    if mode == "transform":
        edit_variants = [
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "id": {"type": "string"},
                    "text": {"type": "string"},
                },
                "required": ["id", "text"],
            },
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "id": {"type": "string"},
                    "rows": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"type": "string"},
                        },
                    },
                },
                "required": ["id", "rows"],
            },
        ]
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": {"edits": {"type": "array", "items": {"anyOf": edit_variants}}},
            "required": ["edits"],
        }

    variants: list[dict[str, Any]] = []

    def variant(kind: str, properties: dict[str, Any], required: list[str]) -> None:
        branch_properties = {"kind": {"enum": [kind]}, **properties}
        variants.append({
            "type": "object",
            "additionalProperties": False,
            "properties": branch_properties,
            "required": required,
        })

    variant("paragraph", {"text": {"type": "string"}}, ["kind", "text"])
    variant(
        "heading",
        {"level": {"type": "integer", "enum": [1, 2, 3, 4, 5, 6]}, "text": {"type": "string"}},
        ["kind", "level", "text"],
    )
    variant(
        "list",
        {"list_type": {"type": "string", "enum": ["bullet", "number"]}, "text": {"type": "string"}},
        ["kind", "list_type", "text"],
    )
    variant(
        "table",
        {
            "rows": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string"},
                },
            },
        },
        ["kind", "rows"],
    )
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "blocks": {"type": "array", "items": {"anyOf": variants}},
        },
        "required": ["blocks"],
    }

PROMPT_BLOCK_PATTERNS = (
    re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"dan\s+mode", re.IGNORECASE),
    re.compile(r"override\s+policy", re.IGNORECASE),
)
DATA_SENSITIVE_PATTERNS = (
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    re.compile(
        r"\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*[^\s,;]+",
        re.IGNORECASE,
    ),
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
)
TOOL_RISK_KEYWORDS = ("shell", "terminal", "bash", "powershell", "filesystem", "sudo", "db_admin")
OUTPUT_BLOCK_PATTERNS = (
    re.compile(r"BEGIN\s+(?:RSA|OPENSSH|EC)\s+PRIVATE\s+KEY", re.IGNORECASE),
    re.compile(r"password\s*[:=]\s*\S+", re.IGNORECASE),
)
OUTPUT_REDACT_PATTERNS = (
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    re.compile(r"api[_-]?key", re.IGNORECASE),
)


def _hash_text(value: str | None) -> str:
    text = value or ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _validate_optional_provenance_id(value: str | None, *, field_name: str) -> str | None:
    if value is None:
        return None
    return validate_authoritative_provenance_id(value, field_name=field_name)


def _effective_chain_id(
    *,
    chain_id: str | None,
    client_request_id: str | None,
    generated_default: str,
) -> str:
    explicit = _validate_optional_provenance_id(chain_id, field_name="chain_id")
    if explicit is not None:
        return explicit
    compatibility_id = str(client_request_id or "")
    if is_authoritative_provenance_id(compatibility_id):
        return compatibility_id
    return generated_default


def _risk_strictness_level(risk_tier: str | None) -> int:
    return RISK_TIER_STRICTNESS.get(str(risk_tier or "").upper(), 0)


def _sensitivity_from_risk_tier(risk_tier: str | None) -> str:
    normalized = str(risk_tier or "").strip().upper()
    if normalized in {"RESTRICTED", "CRITICAL", "PROHIBITED"}:
        return "restricted"
    if normalized in {"HIGH", "MEDIUM"}:
        return "sensitive"
    return "internal"


def _aggregate_decision(decisions: list[str]) -> str:
    observed = {str(item or "allow").strip().lower() for item in decisions}
    for decision in DECISION_PRECEDENCE:
        if decision in observed:
            return decision
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


def _augment_control_impacts(
    controls_impacted: list[dict[str, Any]],
    *,
    triggered_controls: list[str],
) -> list[dict[str, Any]]:
    existing = {str(item.get("control_id") or "").strip() for item in controls_impacted if str(item.get("control_id") or "").strip()}
    out = list(controls_impacted)
    for control_id in triggered_controls:
        token = str(control_id or "").strip()
        if not token or token in existing:
            continue
        out.append({"control_id": token, "delta": -0.12})
        existing.add(token)
    return out


def _tighten_decision(decision: str, *, strictness_level: int) -> str:
    normalized = str(decision or "allow").strip().lower()
    if strictness_level <= 0:
        return normalized
    if strictness_level >= 2 and normalized in {"warn", "redact"}:
        return "block"
    if strictness_level >= 1 and normalized == "warn":
        return "redact"
    return normalized


def _safe_actor_user_id(actor_type: str, actor_id: str) -> str | None:
    if str(actor_type).strip().lower() != "human":
        return None
    candidate = str(actor_id or "").strip()
    if len(candidate) == 36:
        return candidate
    return None


def _business_purpose_gateway_decision(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return {
        "allow": "allow",
        "warn": "warn",
        "shadow": "warn",
        "shadow_would_block": "warn",
        "review": "hold_for_approval",
        "require_justification": "hold_for_approval",
        "require_approval": "hold_for_approval",
        "block": "block",
    }.get(normalized, "block")


def _bounded_business_purpose_summary(result: dict[str, Any]) -> dict[str, Any]:
    purpose = (
        dict(result.get("business_purpose") or {})
        if isinstance(result.get("business_purpose"), dict)
        else {}
    )
    control_ids = [
        str(item).strip()[:96]
        for item in list(result.get("control_ids") or [])[:16]
        if str(item).strip()
    ]
    return {
        "decision": _business_purpose_gateway_decision(result.get("decision")),
        "reason": str(result.get("reason") or "business_purpose_unknown")[:128],
        "policy_id": str(result.get("policy_id") or "business_purpose_boundary")[:128],
        "control_ids": control_ids,
        "business_function": str(purpose.get("business_function") or "unknown")[:96],
        "purpose_category": str(purpose.get("purpose_category") or "unknown")[:96],
        "purpose_status": str(purpose.get("purpose_status") or "unknown")[:64],
    }


def _resolve_gateway_actor(
    db: Session,
    *,
    tenant_id: str,
    trusted_actor_user_id: str | None,
    claimed_actor_type: str,
    claimed_actor_id: str,
) -> tuple[str, str, str | None]:
    trusted_user_id = str(trusted_actor_user_id or "").strip()
    claimed_type = str(claimed_actor_type or "").strip().lower()
    claimed_id = str(claimed_actor_id or "").strip()
    claimed_ref = (
        f"sha256:{_hash_text(claimed_id)}"
        if claimed_id and (claimed_type != "human" or claimed_id != trusted_user_id)
        else None
    )
    if trusted_user_id:
        trusted_user = db.scalar(
            select(User)
            .join(UserTenantRole, UserTenantRole.user_id == User.id)
            .where(
                User.id == trusted_user_id,
                UserTenantRole.tenant_id == tenant_id,
            )
        )
        if trusted_user is None:
            raise ValueError("Authenticated user authority was not found for tenant")
        return "human", trusted_user.id, claimed_ref
    return "system", "unverified_gateway_caller", claimed_ref


def _resolve_provider_name(provider: str) -> str:
    normalized = str(provider or "").strip().lower()
    provider_name = PROVIDER_ALIASES.get(normalized)
    if not provider_name:
        supported = ", ".join(sorted(set(PROVIDER_ALIASES)))
        raise ValueError(f"Unsupported provider '{provider}'. Supported: {supported}")
    if provider_name == "azure_openai":
        base_url = settings.openai_base_url or settings.llm_base_url
        if not str(base_url or "").strip():
            raise ValueError("azure_openai requires OPENAI_BASE_URL or LLM_BASE_URL")
    return provider_name


def _load_provider(provider: str, model_override: str | None):
    resolved = _resolve_provider_name(provider)
    provider_for_factory = "openai" if resolved in {"azure_openai", "mistral", "custom", "oss_local"} else resolved
    provider_instance = get_provider(provider_for_factory)
    if model_override and hasattr(provider_instance, "model"):
        provider_instance.model = model_override
    model_name = str(getattr(provider_instance, "model", model_override or "") or "")
    return provider_instance, resolved, model_name


def _resolve_context(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    policy_version_id: str,
    actor_type: str,
) -> tuple[AISystem, PolicyVersion, int]:
    ai_system = db.scalar(
        select(AISystem).where(
            AISystem.id == ai_system_id,
            AISystem.tenant_id == tenant_id,
        )
    )
    if ai_system is None:
        raise ValueError("AI system not found for tenant")

    policy_version = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.id == policy_version_id,
            PolicyVersion.tenant_id == tenant_id,
        )
    )
    if policy_version is None:
        raise ValueError("Policy version not found for tenant")

    scope = policy_version.scope or {}
    tiers = scope.get("applies_to_risk_tiers") or []
    if tiers and ai_system.risk_tier not in tiers:
        raise ValueError("Policy scope does not apply to AI system risk tier")

    ai_ids = scope.get("applies_to_ai_system_ids")
    if ai_ids and ai_system.id not in ai_ids:
        raise ValueError("Policy scope does not include ai_system_id")

    actor_types = scope.get("applies_to_actor_types")
    if actor_types and actor_type not in actor_types:
        raise ValueError("Policy scope does not include actor_type")

    return ai_system, policy_version, _risk_strictness_level(ai_system.risk_tier)


def _find_pattern_matches(patterns: tuple[re.Pattern[str], ...], text: str) -> list[str]:
    matches: list[str] = []
    for pattern in patterns:
        if pattern.search(text):
            matches.append(pattern.pattern)
    return matches


def _guardian_result(
    *,
    guardian_id: str,
    stage: str,
    decision: str,
    confidence: float,
    matched_conditions: list[str],
    reason: str,
    actions_taken: dict[str, Any] | None = None,
    threat_types: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "guardian_contract_id": guardian_id,
        "guardian_id": guardian_id,
        "version": "dm3",
        "stage": stage,
        "decision": decision,
        "confidence": round(float(confidence), 4),
        "matched_conditions": matched_conditions,
        "reason": reason,
        "actions_taken": actions_taken or {},
        "threat_types": threat_types or [],
    }


def evaluate_pre_request_guardians(
    *,
    prompt: str,
    context_summary: str,
    tool_context: list[str],
    strictness_level: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    controls_impacted: list[dict[str, Any]] = []
    prompt_matches = _find_pattern_matches(PROMPT_BLOCK_PATTERNS, f"{prompt}\n{context_summary}")
    prompt_decision = _tighten_decision("block" if prompt_matches else "allow", strictness_level=strictness_level)
    prompt_result = _guardian_result(
        guardian_id="prompt_guardian",
        stage="pre_request",
        decision=prompt_decision,
        confidence=0.99 if prompt_matches else 0.98,
        matched_conditions=prompt_matches,
        reason="prompt_injection_detected" if prompt_matches else "clean_prompt",
        actions_taken={"block": bool(prompt_matches)},
        threat_types=["prompt_injection"] if prompt_matches else [],
    )

    data_matches = _find_pattern_matches(DATA_SENSITIVE_PATTERNS, prompt)
    data_decision = _tighten_decision("redact" if data_matches else "allow", strictness_level=strictness_level)
    data_result = _guardian_result(
        guardian_id="data_guardian",
        stage="pre_request",
        decision=data_decision,
        confidence=0.94 if data_matches else 0.99,
        matched_conditions=data_matches,
        reason="sensitive_data_detected" if data_matches else "no_sensitive_data_detected",
        actions_taken={"redact_prompt": bool(data_matches)},
        threat_types=["sensitive_data_leakage"] if data_matches else [],
    )

    tool_matches: list[str] = []
    normalized_tool_context = [str(item or "").strip().lower() for item in (tool_context or []) if str(item or "").strip()]
    for item in normalized_tool_context:
        if any(keyword in item for keyword in TOOL_RISK_KEYWORDS):
            tool_matches.append(item)
    base_tool_decision = "warn" if tool_matches else "allow"
    tool_decision = _tighten_decision(base_tool_decision, strictness_level=strictness_level)
    tool_result = _guardian_result(
        guardian_id="tool_guardian",
        stage="pre_request",
        decision=tool_decision,
        confidence=0.9 if tool_matches else 0.99,
        matched_conditions=tool_matches,
        reason="risky_tool_context" if tool_matches else "tool_guard_not_relevant",
        actions_taken={"tool_context_present": bool(normalized_tool_context)},
        threat_types=["tool_output_injection"] if tool_matches else [],
    )

    results = [prompt_result, data_result, tool_result]
    for result in results:
        control_id = GUARDIAN_CONTROL_MAP.get(result["guardian_id"])
        if not control_id:
            continue
        if result["decision"] == "allow":
            continue
        delta = -0.1
        if result["decision"] == "redact":
            delta = -0.15
        if result["decision"] == "block":
            delta = -0.25
        controls_impacted.append({"control_id": control_id, "delta": delta})
    return results, controls_impacted


def evaluate_post_response_guardian(
    *,
    response_text: str,
    strictness_level: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    controls_impacted: list[dict[str, Any]] = []
    block_matches = _find_pattern_matches(OUTPUT_BLOCK_PATTERNS, response_text)
    redact_matches = _find_pattern_matches(OUTPUT_REDACT_PATTERNS, response_text)
    if block_matches:
        base_decision = "block"
        matches = block_matches
        reason = "output_critical_leak_detected"
        confidence = 0.99
        threat_types = ["sensitive_data_leakage"]
    elif redact_matches:
        base_decision = "redact"
        matches = redact_matches
        reason = "output_sensitive_data_detected"
        confidence = 0.95
        threat_types = ["sensitive_data_leakage"]
    else:
        base_decision = "allow"
        matches = []
        reason = "output_clean"
        confidence = 0.99
        threat_types = []

    decision = _tighten_decision(base_decision, strictness_level=strictness_level)
    result = _guardian_result(
        guardian_id="output_guardian",
        stage="post_response",
        decision=decision,
        confidence=confidence,
        matched_conditions=matches,
        reason=reason,
        actions_taken={"mutate_output": decision in {"redact", "block"}},
        threat_types=threat_types,
    )
    if decision != "allow":
        controls_impacted.append(
            {
                "control_id": GUARDIAN_CONTROL_MAP["output_guardian"],
                "delta": -0.15 if decision == "redact" else -0.25,
            }
        )
    return [result], controls_impacted


def _redact_prompt_for_request(prompt: str) -> str:
    redacted = prompt
    for pattern in DATA_SENSITIVE_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def mutate_output_restricted(*, response_text: str, final_decision: str) -> str:
    decision = str(final_decision or "").strip().lower()
    if decision in {"redact", "block", "hold_for_approval"}:
        return "Response restricted by Output Guardian policy."
    return response_text


def _build_trace_payload(
    *,
    ai_system_id: str,
    actor_type: str,
    actor_id: str,
    provider: str,
    model: str,
    prompt_hash: str,
    response_hash: str | None,
    policy_version_id: str,
    request_stage: str,
    client_request_id: str | None,
    chain_id: str,
    parent_action_id: str | None,
    response_control_coverage: ResponseControlCoverage | str,
    final_decision: str,
    controls_impacted: list[dict[str, Any]],
    authoritative_action_id: str | None = None,
) -> dict[str, Any]:
    trace_id = str(authoritative_action_id or client_request_id or uuid4())
    normalized_actor_type = str(actor_type or "").strip().lower()
    controls_triggered = [
        str(item.get("control_id") or "").strip()
        for item in (controls_impacted or [])
        if isinstance(item, dict) and str(item.get("control_id") or "").strip()
    ]
    control_mode = control_mode_for_pre_action_decision(final_decision, inline=True)
    evidence_required = str(final_decision or "").strip().lower() != "allow"
    return {
        "trace_id": trace_id,
        "user_id": _safe_actor_user_id(actor_type, actor_id),
        "agent_id": str(actor_id or "").strip() if normalized_actor_type == "agent" else None,
        "machine_id": None,
        "app": "llm_gateway",
        "application": "llm_gateway",
        "surface_type": "gateway",
        "action_type": "gateway_model_call",
        "provider": provider,
        "model": model,
        "prompt_template_id": None,
        "input_hash": prompt_hash,
        "redacted_input_ref": f"sha256:{prompt_hash}" if prompt_hash else None,
        "policy_applied": policy_version_id,
        "policy_snapshot_id": policy_version_id,
        "decision": final_decision,
        "control_mode": control_mode,
        "controls_triggered": sorted(set(controls_triggered)),
        "output_hash": response_hash,
        "redacted_output_ref": f"sha256:{response_hash}" if response_hash else None,
        "decision_explanation_ref": f"decision:{trace_id}",
        "evidence_required": evidence_required,
        "latency": 0.0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ai_system_id": ai_system_id,
        "identity_type": "agent" if normalized_actor_type == "agent" else ("service" if normalized_actor_type == "system" else "user"),
        "prompt_hash": prompt_hash,
        "response_hash": response_hash,
        "governance_version": GOVERNANCE_VERSION,
        "policy_version_id": policy_version_id,
        "request_stage": request_stage,
        "client_request_id": client_request_id,
        "chain_id": chain_id,
        "parent_action_id": parent_action_id,
        "response_control_coverage": normalize_response_control_coverage(
            response_control_coverage
        ),
        "correlation_id": get_correlation_id(),
    }


def _persist_gateway_enforcement_event(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    actor_type: str,
    actor_id: str,
    request_stage: str,
    client_request_id: str | None,
    prompt: str,
    context_summary: str,
    attachments_meta: list[dict[str, Any]],
    guardian_results: list[dict[str, Any]],
    final_decision: str,
    final_actions: dict[str, Any],
    controls_impacted: list[dict[str, Any]],
    policy_version_id: str,
    trace_payload: dict[str, Any],
) -> dict[str, Any]:
    correlation_id = get_correlation_id()
    signal_type = f"llm_gateway.{request_stage}"

    root_node = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="llm_gateway_enforcement",
        signal_type=signal_type,
        label=f"LLM Gateway {request_stage} {client_request_id or 'generated'}",
        payload={
            "ai_system_id": ai_system_id,
            "policy_version_id": policy_version_id,
            "final_decision": final_decision,
            "trace": trace_payload,
        },
        correlation_id=correlation_id,
    )
    evidence_node_ids = [root_node.id]

    for row in guardian_results:
        guardian_node = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="llm_gateway_guardian",
            signal_type=f"llm_gateway.guardian.{row['guardian_id']}",
            label=f"{row['guardian_id']} => {row['decision']}",
            payload={
                **row,
                "policy_version_id": policy_version_id,
                "trace": trace_payload,
            },
            correlation_id=correlation_id,
        )
        link_evidence_nodes(
            db,
            tenant_id=tenant_id,
            from_node_id=root_node.id,
            to_node_id=guardian_node.id,
            edge_type="generated",
            payload={"request_stage": request_stage},
        )
        evidence_node_ids.append(guardian_node.id)

    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=_safe_actor_user_id(actor_type, actor_id),
        actor_type=actor_type,
        action=signal_type,
        resource_type="ai_system",
        resource_id=ai_system_id,
        payload={
            "request_stage": request_stage,
            "client_request_id": client_request_id,
            "final_decision": final_decision,
            "policy_version_id": policy_version_id,
            "trace": trace_payload,
            "guardian_results_count": len(guardian_results),
        },
        correlation_id=correlation_id,
    )

    event_request_id = str(uuid4())
    # Runtime shadow discovery consumes the server's governance state. Without
    # this snapshot it interprets an approved gateway action as unknown usage
    # and can immediately restrict the registered AI system.
    ai_system = db.get(AISystem, ai_system_id)
    governance_state = str((ai_system.metadata_json or {}).get("governance_state") or "unknown") if ai_system else "unknown"
    event = EnforcementEvent(
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        ai_system_id=ai_system_id,
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=event_request_id,
        timestamp=datetime.now(timezone.utc),
        input_prompt=encrypt_enforcement_prompt(prompt),
        input_context_summary=context_summary,
        input_attachments_meta=attachments_meta,
        guardian_results=guardian_results,
        final_decision=final_decision,
        final_actions={**final_actions, "_meta": {"governance_state": governance_state}, "_trace": trace_payload},
        evidence_nodes_created=evidence_node_ids,
        controls_impacted=controls_impacted,
        policy_version_id=policy_version_id,
        audit_log_id=audit.id,
    )
    db.add(event)
    db.flush()

    finding = generate_from_enforcement_event(db, event=event)
    runtime_event_id: str | None = None
    from app.services.runtime_intelligence.runtime_event_normalizer import ingest_from_gateway_enforcement

    runtime_event = ingest_from_gateway_enforcement(db, event=event)
    if runtime_event is not None:
        runtime_event_id = runtime_event.event_id
        trace_payload["runtime_event_id"] = runtime_event_id
        persisted_final_actions = dict(event.final_actions or {})
        persisted_trace = dict(persisted_final_actions.get("_trace") or {})
        persisted_trace["runtime_event_id"] = runtime_event_id
        persisted_final_actions["_trace"] = persisted_trace
        persisted_final_actions["runtime_event_id"] = runtime_event_id
        event.final_actions = persisted_final_actions
        runtime_metadata = dict(runtime_event.metadata_json or {})
        runtime_metadata["runtime_event_id"] = runtime_event_id
        runtime_event.metadata_json = runtime_metadata
        db.flush()
    return {
        "event_id": event.id,
        "request_id": event.request_id,
        "audit_log_id": audit.id,
        "evidence_node_ids": evidence_node_ids,
        "finding_id": finding.finding_id if finding is not None else None,
        "correlation_id": correlation_id,
        "runtime_event_id": runtime_event_id,
        "chain_id": str(trace_payload.get("chain_id") or ""),
        "parent_action_id": trace_payload.get("parent_action_id"),
        "response_control_coverage": normalize_response_control_coverage(
            trace_payload.get("response_control_coverage")
        ),
    }


def _build_action_control_envelope(
    *,
    tenant_id: str,
    ai_system_id: str,
    actor_type: str,
    actor_id: str,
    request_stage: str,
    client_request_id: str | None,
    provider: str,
    model: str,
    final_decision: str,
    controls_impacted: list[dict[str, Any]],
    policy_version_id: str,
    trace_payload: dict[str, Any],
    persisted: dict[str, Any],
    prompt_hash: str | None,
    response_hash: str | None,
    context_summary: str,
    authoritative_action_id: str | None = None,
    trusted_pre_action_governance_check: dict[str, Any] | None = None,
) -> dict[str, Any]:
    control_ids = sorted(
        {
            str(item.get("control_id") or "").strip()
            for item in (controls_impacted or [])
            if isinstance(item, dict) and str(item.get("control_id") or "").strip()
        }
    )
    normalized_actor_type = str(actor_type or "").strip().lower()
    user_id = str(actor_id or "").strip() if normalized_actor_type == "human" else None
    agent_id = str(actor_id or "").strip() if normalized_actor_type == "agent" else None
    action_id = str(
        authoritative_action_id
        or client_request_id
        or persisted.get("event_id")
        or uuid4()
    )
    ai_action = build_ai_action_record(
        tenant_id=tenant_id,
        action_id=action_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        source_surface="gateway",
        event_type="gateway_model_call",
        user_id=user_id,
        agent_id=agent_id,
        ai_system_id=ai_system_id,
        application="llm_gateway",
        policy_version_id=policy_version_id,
        decision=final_decision,
        evidence_node_ids=list(persisted.get("evidence_node_ids") or []),
        correlation_id=str(persisted.get("correlation_id") or trace_payload.get("correlation_id") or ""),
        chain_id=str(trace_payload.get("chain_id") or trace_payload.get("trace_id") or action_id),
        parent_action_id=(
            str(trace_payload.get("parent_action_id"))
            if trace_payload.get("parent_action_id")
            else None
        ),
        metadata={
            "action_type": "gateway_model_call",
            "provider": provider,
            "model_name": model,
            "application": "llm_gateway",
            "api_endpoint": f"/llm-gateway/{request_stage}",
            "request_stage": request_stage,
            "prompt_hash": prompt_hash,
            "output_ref": f"sha256:{response_hash}" if response_hash else None,
            "response_hash": response_hash,
            "response_control_coverage": normalize_response_control_coverage(
                trace_payload.get("response_control_coverage")
            ),
            "data_classification": "sensitive" if final_decision in {"block", "redact", "hold_for_approval"} else "internal",
            "input_sensitivity": "sensitive" if final_decision in {"block", "redact", "hold_for_approval"} else "internal",
            "output_sensitivity": "sensitive" if response_hash and final_decision in {"block", "redact", "hold_for_approval"} else None,
            "triggered_controls": control_ids,
            "reason": "llm_gateway_policy_decision",
            "business_context": context_summary,
            "business_purpose": (
                dict(trace_payload.get("business_purpose") or {})
                if isinstance(trace_payload.get("business_purpose"), dict)
                else {}
            ),
            "gateway_trace": {
                "trace_id": trace_payload.get("trace_id"),
                "request_stage": request_stage,
                "policy_version_id": policy_version_id,
                "chain_id": trace_payload.get("chain_id"),
                "parent_action_id": trace_payload.get("parent_action_id"),
                "response_control_coverage": normalize_response_control_coverage(
                    trace_payload.get("response_control_coverage")
                ),
            },
        },
        finding_id=str(persisted.get("finding_id") or "") or None,
        trusted_pre_action_governance_check=trusted_pre_action_governance_check,
    )
    return {
        "control_mode": ai_action["policy"]["control_mode"],
        "decision_badge": ai_action["policy"]["decision_badge"],
        "ai_action": ai_action,
        "decision_explanation": ai_action["decision_explanation"],
        "policy_snapshot": ai_action["policy_snapshot"],
        "evidence_bundle": ai_action["evidence_bundle"],
    }


def gateway_request_only(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    policy_version_id: str,
    provider: str,
    model: str | None,
    actor_type: str,
    actor_id: str,
    trusted_actor_user_id: str | None,
    client_request_id: str | None,
    chain_id: str | None = None,
    parent_action_id: str | None = None,
    prompt: str,
    context_summary: str,
    attachments_meta: list[dict[str, Any]],
    tool_context: list[str],
) -> dict[str, Any]:
    request_action_id = str(uuid4())
    effective_actor_type, effective_actor_id, claimed_actor_correlation_ref = (
        _resolve_gateway_actor(
            db,
            tenant_id=tenant_id,
            trusted_actor_user_id=trusted_actor_user_id,
            claimed_actor_type=actor_type,
            claimed_actor_id=actor_id,
        )
    )
    effective_chain_id = _effective_chain_id(
        chain_id=chain_id,
        client_request_id=None,
        generated_default=request_action_id,
    )
    effective_parent_action_id = _validate_optional_provenance_id(
        parent_action_id,
        field_name="parent_action_id",
    )
    enforce_governance(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        action="llm_gateway.request",
        route="/llm-gateway/request",
        module="llm_gateway_service",
    )
    ai_system, _, strictness_level = _resolve_context(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        policy_version_id=policy_version_id,
        actor_type=effective_actor_type,
    )
    _, resolved_provider, resolved_model = _load_provider(provider, model)
    pre_results, pre_controls = evaluate_pre_request_guardians(
        prompt=prompt,
        context_summary=context_summary,
        tool_context=tool_context,
        strictness_level=strictness_level,
    )
    final_decision = _aggregate_decision([item["decision"] for item in pre_results])
    control_decision = evaluate_control_engine(
        AIAction(
            action_id=request_action_id,
            user_id=(
                effective_actor_id
                if effective_actor_type == "human"
                else None
            ),
            ai_app=resolved_provider,
            model=(model or resolved_model),
            prompt=prompt,
            metadata={
                "source_surface": "gateway",
                "action_type": "prompt",
                "decision": final_decision,
                "reason_codes": [str(item.get("reason") or "") for item in pre_results if isinstance(item, dict)],
                "input_signal_types": [str(tag) for item in pre_results for tag in (item.get("threat_types") or [])],
                "contains_sensitive": any(str(item.get("guardian_id") or "") == "data_guardian" and item.get("decision") != "allow" for item in pre_results),
                "data_classification": "sensitive" if any(str(item.get("guardian_id") or "") == "data_guardian" and item.get("decision") != "allow" for item in pre_results) else "unknown",
                "triggered_controls": [str(item.get("control_id") or "") for item in pre_controls],
            },
            source_surface="gateway",
        ),
        base_decision=final_decision,
        hinted_control_ids=[str(item.get("control_id") or "") for item in pre_controls],
    )
    mapped_engine_decision = _map_control_engine_gateway_decision(control_decision.decision, fallback=final_decision)
    if _aggregate_decision([final_decision, mapped_engine_decision]) != final_decision:
        final_decision = _aggregate_decision([final_decision, mapped_engine_decision])
        pre_results.append(
            {
                "guardian_contract_id": "control_engine.llm_gateway.request",
                "guardian_id": "control_engine",
                "decision": final_decision,
                "confidence": 1.0,
                "matched_conditions": ["central_control_engine"],
                "reason": "control_engine_escalation",
                "actions_taken": {
                    "dominant_control": control_decision.dominant_control,
                    "triggered_controls": list(control_decision.triggered_controls),
                    "total_risk_score": control_decision.total_risk_score,
                },
                "threat_types": list(control_decision.risk_tags or []),
            }
        )
    pre_controls = _augment_control_impacts(
        pre_controls,
        triggered_controls=list(control_decision.triggered_controls),
    )
    prompt_hash = _hash_text(prompt)
    from app.core.control_engine.authorization import (
        apply_trusted_pre_action_rollout,
        authorization_rollout_persistence_metadata,
    )

    pre_action_governance_check = {
        "action_id": request_action_id,
        "policy": {
            "policy_snapshot_id": policy_version_id,
            "control_ids": list(control_decision.triggered_controls or []),
        },
        "actor": {
            "identity_id": (
                effective_actor_id if effective_actor_type == "human" else None
            ),
            "identity_type": (
                "human" if effective_actor_type == "human" else "service"
            ),
            "user_id": (
                effective_actor_id if effective_actor_type == "human" else None
            ),
        },
        "authority": {
            "authority_type": (
                "authenticated_user"
                if effective_actor_type == "human"
                else "unverified_caller"
            ),
            "authority_source": (
                "tenant_context"
                if effective_actor_type == "human"
                else "legacy_service_contract"
            ),
            "verified": effective_actor_type == "human",
        },
        "surface": {
            "surface_type": "llm_gateway",
            "application": "llm_gateway",
            "provider": resolved_provider,
            "model": resolved_model,
            "asset_status": "approved",
            "environment": "prod",
        },
        "action": {
            "action_type": "prompt",
            "action_risk": str(ai_system.risk_tier or "unknown").lower(),
            "target_resource": resolved_provider,
        },
    }
    v2_rollout = apply_trusted_pre_action_rollout(
        tenant_id=tenant_id,
        surface="llm_gateway",
        action_id=request_action_id,
        chain_id=effective_chain_id,
        collector_id="llm-gateway-request",
        trusted_pre_action_governance_check=pre_action_governance_check,
        legacy_decision=final_decision,
        legacy_reason="llm_gateway_pre_request",
        legacy_control_mode=("inline_prevented" if final_decision == "block" else "inline_allowed"),
        policy_snapshot_id=policy_version_id,
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
            trusted_provider=resolved_provider,
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
        final_decision = {
            "allow": "allow",
            "warn": "warn",
            "redact": "redact",
            "review": "hold_for_approval",
            "require_approval": "hold_for_approval",
            "require_second_approval": "hold_for_approval",
            "block": "block",
        }.get(v2_rollout.authoritative_decision, "block")
        pre_results.append(
            {
                "guardian_id": "authorization_kernel_v2",
                "decision": final_decision,
                "confidence": 1.0,
                "reason": v2_rollout.v2_response.reason if v2_rollout.v2_response else "authorization_kernel_v2",
                "matched_conditions": ["server_selected_rollout"],
                "actions_taken": {},
                "threat_types": [],
            }
        )
    # This value is assigned by the server-owned gateway path after the
    # authorization rollout.  It is never read from caller metadata.
    pre_action_governance_check["control_mode"] = control_mode_for_pre_action_decision(
        final_decision,
        inline=True,
    )
    trace_payload = _build_trace_payload(
        ai_system_id=ai_system.id,
        actor_type=effective_actor_type,
        actor_id=effective_actor_id,
        provider=resolved_provider,
        model=resolved_model,
        prompt_hash=prompt_hash,
        response_hash=None,
        policy_version_id=policy_version_id,
        request_stage="request",
        client_request_id=client_request_id,
        chain_id=effective_chain_id,
        parent_action_id=effective_parent_action_id,
        response_control_coverage="request_only",
        final_decision=final_decision,
        controls_impacted=pre_controls,
        authoritative_action_id=request_action_id,
    )
    trace_payload["pre_action_governance_check"] = pre_action_governance_check
    if claimed_actor_correlation_ref:
        trace_payload["claimed_actor_correlation_ref"] = claimed_actor_correlation_ref

    persisted = _persist_gateway_enforcement_event(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system.id,
        actor_type=effective_actor_type,
        actor_id=effective_actor_id,
        request_stage="request",
        client_request_id=client_request_id,
        prompt=prompt,
        context_summary=context_summary,
        attachments_meta=attachments_meta,
        guardian_results=pre_results,
        final_decision=final_decision,
        final_actions={
            "stage": "request",
            "strictness_level": strictness_level,
            "control_decision": control_decision.to_dict(),
            "operational_telemetry": True,
            "response_control_coverage": "request_only",
        },
        controls_impacted=pre_controls,
        policy_version_id=policy_version_id,
        trace_payload=trace_payload,
    )
    mutated_prompt_preview = _redact_prompt_for_request(prompt) if final_decision in {"redact", "warn"} else None
    action_control = _build_action_control_envelope(
        tenant_id=tenant_id,
        ai_system_id=ai_system.id,
        actor_type=effective_actor_type,
        actor_id=effective_actor_id,
        request_stage="request",
        client_request_id=client_request_id,
        provider=resolved_provider,
        model=resolved_model,
        final_decision=final_decision,
        controls_impacted=pre_controls,
        policy_version_id=policy_version_id,
        trace_payload=trace_payload,
        persisted=persisted,
        prompt_hash=prompt_hash,
        response_hash=None,
        context_summary=context_summary,
        authoritative_action_id=request_action_id,
        trusted_pre_action_governance_check={
            "control_mode": pre_action_governance_check["control_mode"],
        },
    )
    return {
        **persisted,
        **action_control,
        "final_decision": final_decision,
        "guardian_results": pre_results,
        "prompt_hash": prompt_hash,
        "response_hash": None,
        "provider": resolved_provider,
        "model": resolved_model,
        "gateway_trace": trace_payload,
        "response_control_coverage": "request_only",
        "chain_id": effective_chain_id,
        "parent_action_id": effective_parent_action_id,
        "allowed": final_decision not in {"block", "hold_for_approval"},
        "mutated_prompt_preview": mutated_prompt_preview,
    }


def gateway_response_only(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    policy_version_id: str,
    provider: str,
    model: str | None,
    actor_type: str,
    actor_id: str,
    trusted_actor_user_id: str | None,
    client_request_id: str | None,
    chain_id: str | None = None,
    parent_action_id: str | None = None,
    prompt: str | None,
    response_text: str,
    context_summary: str,
    attachments_meta: list[dict[str, Any]],
) -> dict[str, Any]:
    response_action_id = str(uuid4())
    effective_actor_type, effective_actor_id, claimed_actor_correlation_ref = (
        _resolve_gateway_actor(
            db,
            tenant_id=tenant_id,
            trusted_actor_user_id=trusted_actor_user_id,
            claimed_actor_type=actor_type,
            claimed_actor_id=actor_id,
        )
    )
    effective_chain_id = _effective_chain_id(
        chain_id=chain_id,
        client_request_id=None,
        generated_default=response_action_id,
    )
    effective_parent_action_id = _validate_optional_provenance_id(
        parent_action_id,
        field_name="parent_action_id",
    )
    enforce_governance(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        action="llm_gateway.response",
        route="/llm-gateway/response",
        module="llm_gateway_service",
    )
    ai_system, _, strictness_level = _resolve_context(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        policy_version_id=policy_version_id,
        actor_type=effective_actor_type,
    )
    _, resolved_provider, resolved_model = _load_provider(provider, model)

    post_results, post_controls = evaluate_post_response_guardian(
        response_text=response_text,
        strictness_level=strictness_level,
    )
    final_decision = _aggregate_decision([item["decision"] for item in post_results])
    control_decision = evaluate_control_engine(
        AIAction(
            action_id=response_action_id,
            user_id=(
                effective_actor_id
                if effective_actor_type == "human"
                else None
            ),
            ai_app=resolved_provider,
            model=(model or resolved_model),
            prompt=(prompt or response_text),
            metadata={
                "source_surface": "gateway",
                "action_type": "response",
                "decision": final_decision,
                "reason_codes": [str(item.get("reason") or "") for item in post_results if isinstance(item, dict)],
                "input_signal_types": [str(tag) for item in post_results for tag in (item.get("threat_types") or [])],
                "contains_sensitive": any(str(item.get("guardian_id") or "") == "output_guardian" and item.get("decision") in {"redact", "block"} for item in post_results),
                "data_classification": "sensitive" if any(str(item.get("guardian_id") or "") == "output_guardian" and item.get("decision") in {"redact", "block"} for item in post_results) else "unknown",
                "triggered_controls": [str(item.get("control_id") or "") for item in post_controls],
            },
            source_surface="gateway",
        ),
        base_decision=final_decision,
        hinted_control_ids=[str(item.get("control_id") or "") for item in post_controls],
    )
    mapped_engine_decision = _map_control_engine_gateway_decision(control_decision.decision, fallback=final_decision)
    if _aggregate_decision([final_decision, mapped_engine_decision]) != final_decision:
        final_decision = _aggregate_decision([final_decision, mapped_engine_decision])
        post_results.append(
            {
                "guardian_contract_id": "control_engine.llm_gateway.response",
                "guardian_id": "control_engine",
                "decision": final_decision,
                "confidence": 1.0,
                "matched_conditions": ["central_control_engine"],
                "reason": "control_engine_escalation",
                "actions_taken": {
                    "dominant_control": control_decision.dominant_control,
                    "triggered_controls": list(control_decision.triggered_controls),
                    "total_risk_score": control_decision.total_risk_score,
                },
                "threat_types": list(control_decision.risk_tags or []),
            }
        )
    post_controls = _augment_control_impacts(
        post_controls,
        triggered_controls=list(control_decision.triggered_controls),
    )
    prompt_hash = _hash_text(prompt)
    response_hash = _hash_text(response_text)
    trace_payload = _build_trace_payload(
        ai_system_id=ai_system.id,
        actor_type=effective_actor_type,
        actor_id=effective_actor_id,
        provider=resolved_provider,
        model=resolved_model,
        prompt_hash=prompt_hash,
        response_hash=response_hash,
        policy_version_id=policy_version_id,
        request_stage="response",
        client_request_id=client_request_id,
        chain_id=effective_chain_id,
        parent_action_id=effective_parent_action_id,
        response_control_coverage="post_execution",
        final_decision=final_decision,
        controls_impacted=post_controls,
        authoritative_action_id=response_action_id,
    )
    if claimed_actor_correlation_ref:
        trace_payload["claimed_actor_correlation_ref"] = claimed_actor_correlation_ref
    controlled_response = mutate_output_restricted(response_text=response_text, final_decision=final_decision)

    persisted = _persist_gateway_enforcement_event(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system.id,
        actor_type=effective_actor_type,
        actor_id=effective_actor_id,
        request_stage="response",
        client_request_id=client_request_id,
        prompt=prompt or "",
        context_summary=context_summary or "llm_gateway_response",
        attachments_meta=attachments_meta,
        guardian_results=post_results,
        final_decision=final_decision,
        final_actions={
            "stage": "response",
            "strictness_level": strictness_level,
            "output_mutation_applied": controlled_response != response_text,
            "control_decision": control_decision.to_dict(),
            "response_control_coverage": "post_execution",
        },
        controls_impacted=post_controls,
        policy_version_id=policy_version_id,
        trace_payload=trace_payload,
    )
    action_control = _build_action_control_envelope(
        tenant_id=tenant_id,
        ai_system_id=ai_system.id,
        actor_type=effective_actor_type,
        actor_id=effective_actor_id,
        request_stage="response",
        client_request_id=client_request_id,
        provider=resolved_provider,
        model=resolved_model,
        final_decision=final_decision,
        controls_impacted=post_controls,
        policy_version_id=policy_version_id,
        trace_payload=trace_payload,
        persisted=persisted,
        prompt_hash=prompt_hash,
        response_hash=response_hash,
        context_summary=context_summary or "llm_gateway_response",
        authoritative_action_id=response_action_id,
        trusted_pre_action_governance_check={
            "control_mode": control_mode_for_pre_action_decision(final_decision, inline=True),
        },
    )
    return {
        **persisted,
        **action_control,
        "final_decision": final_decision,
        "guardian_results": post_results,
        "prompt_hash": prompt_hash,
        "response_hash": response_hash,
        "provider": resolved_provider,
        "model": resolved_model,
        "gateway_trace": trace_payload,
        "response_control_coverage": "post_execution",
        "chain_id": effective_chain_id,
        "parent_action_id": effective_parent_action_id,
        "controlled_response": controlled_response,
    }


def _build_user_prompt(messages: list[dict[str, str]], *, masking_safe_headers: bool = False) -> str:
    parts: list[str] = []
    for message in messages:
        role = str(message.get("role") or "user").strip().lower()
        content = str(message.get("content") or "").strip()
        if not content:
            continue
        if role == "system":
            continue
        if masking_safe_headers:
            parts.append(f"[{role}]\n{content}")
        else:
            parts.append(f"{role}: {content}")
    if parts:
        return "\n".join(parts)
    return ""


def _gateway_chat_complete_impl(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    policy_version_id: str,
    provider: str,
    model: str | None,
    actor_type: str,
    actor_id: str,
    trusted_actor_user_id: str | None,
    client_request_id: str | None,
    chain_id: str | None = None,
    parent_action_id: str | None = None,
    system_prompt: str | None,
    messages: list[dict[str, str]],
    context_summary: str,
    attachments_meta: list[dict[str, Any]],
    tool_context: list[str],
    _masking_sessions: list[MaskingSession],
    _response_validator: Callable[[str], Any] | None = None,
    _response_schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # A caller request ID is correlation metadata, not an action, chain, trace,
    # receipt, or idempotency identity. Every invocation gets a fresh action ID.
    chat_action_id = str(uuid4())
    effective_chain_id = _effective_chain_id(
        chain_id=chain_id,
        client_request_id=None,
        generated_default=chat_action_id,
    )
    effective_parent_action_id = _validate_optional_provenance_id(
        parent_action_id,
        field_name="parent_action_id",
    )
    authenticated_user_id = str(trusted_actor_user_id or "").strip()
    if not authenticated_user_id:
        raise ValueError("Authenticated user authority is required for provider execution")
    authenticated_user = db.scalar(
        select(User).where(User.id == authenticated_user_id)
    )
    if authenticated_user is None:
        raise ValueError("Authenticated user authority was not found")
    effective_actor_type = "human"
    effective_actor_id = authenticated_user_id
    claimed_actor_correlation_ref = (
        f"sha256:{_hash_text(str(actor_id or '').strip())}"
        if str(actor_id or "").strip() and str(actor_id or "").strip() != authenticated_user_id
        else None
    )
    if len(tool_context or []) > 64:
        raise ValueError("tool_context exceeds maximum items")
    enforce_governance(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        action="llm_gateway.chat.complete",
        route="/llm-gateway/chat/complete",
        module="llm_gateway_service",
        emit_logs=not settings.decision_execution_receipts_enabled,
    )
    ai_system, policy_version, strictness_level = _resolve_context(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        policy_version_id=policy_version_id,
        actor_type=effective_actor_type,
    )
    user_prompt = _build_user_prompt(messages)
    if not user_prompt:
        raise ValueError("At least one non-system message with content is required")

    sector_profile = db.scalar(
        select(TenantSectorProfile)
        .where(TenantSectorProfile.tenant_id == tenant_id)
        .order_by(TenantSectorProfile.updated_at.desc())
    )
    if (
        sector_profile is not None
        and str(sector_profile.sector or "").strip().lower() == "banking"
    ):
        purpose_result = evaluate_business_purpose_boundary(
            db,
            tenant_id=tenant_id,
            user_id=authenticated_user_id,
            email=authenticated_user.email,
            prompt_text=user_prompt,
            action_type="gateway_model_call",
            destination_domain=PROVIDER_ALIASES.get(
                str(provider or "").strip().lower(),
                str(provider or "").strip().lower(),
            ),
            destination_trust_level="approved_ai",
            source_surface="gateway",
        )
        purpose_summary = _bounded_business_purpose_summary(purpose_result)
    else:
        purpose_summary = {
            "decision": "allow",
            "reason": "banking_business_purpose_not_applicable",
            "policy_id": "business_purpose_boundary",
            "control_ids": [],
            "business_function": "unknown",
            "purpose_category": "not_applicable",
            "purpose_status": "not_applicable",
        }
    provider_instance, resolved_provider, resolved_model = _load_provider(provider, model)
    pre_results, pre_controls = evaluate_pre_request_guardians(
        prompt=user_prompt,
        context_summary=context_summary,
        tool_context=tool_context,
        strictness_level=strictness_level,
    )
    pre_results.append(
        _guardian_result(
            guardian_id="business_purpose_boundary",
            stage="pre_request",
            decision=str(purpose_summary["decision"]),
            confidence=1.0,
            matched_conditions=[str(purpose_summary["reason"])],
            reason=str(purpose_summary["reason"]),
            actions_taken={
                "policy_id": purpose_summary["policy_id"],
                "business_function": purpose_summary["business_function"],
                "purpose_category": purpose_summary["purpose_category"],
            },
            threat_types=(
                []
                if purpose_summary["decision"] == "allow"
                else ["business_purpose_boundary"]
            ),
        )
    )
    pre_controls = _augment_control_impacts(
        pre_controls,
        triggered_controls=list(purpose_summary["control_ids"]),
    )
    pre_decision = _aggregate_decision([item["decision"] for item in pre_results])
    scope = dict(policy_version.scope or {}) if isinstance(policy_version.scope, dict) else {}
    security_profile = (
        dict(scope.get("llm_gateway_security") or {})
        if isinstance(scope.get("llm_gateway_security"), dict)
        else {}
    )
    masking_policy = ReversibleMaskingPolicy.from_scope(security_profile.get("reversible_masking"))
    effective_prompt = (
        _redact_prompt_for_request(user_prompt)
        if pre_decision in {"redact", "warn"} and not masking_policy.enabled
        else user_prompt
    )
    if masking_policy.enabled:
        effective_prompt = _build_user_prompt(messages, masking_safe_headers=True)
    for key in [
        "provider_allowlist", "allow_raw_restricted_prompt_data",
        "post_call_sensitive_action", "allow_insecure_localhost_http", "require_tls_1_3",
        "allowed_regions", "minimization_mode", "allow_high_risk_tools", "allowed_tools",
    ]:
        if key in scope and key not in security_profile:
            security_profile[key] = scope.get(key)
    secure_context = SecureCallContext(
        task_type="llm_gateway_chat_complete",
        data_sensitivity=_sensitivity_from_risk_tier(ai_system.risk_tier),
        risk_tier=str(ai_system.risk_tier or "medium").strip().lower() or "medium",
        cost_ceiling_usd=float(scope.get("llm_cost_ceiling_usd") or 0.25),
        customer_region=str(scope.get("customer_region") or "global"),
        region_requirement=str(scope.get("region_requirement") or scope.get("residency_region") or "global"),
        residency_requirement=str(scope.get("residency_requirement") or ""),
        residency_required=bool(scope.get("residency_required")),
        customer_policy_profile=security_profile,
        policy_applied=str(policy_version.id),
        policy_version=str(policy_version.id),
        governance_version=GOVERNANCE_VERSION,
        prompt_template_id="hawk.llm_gateway.chat.complete",
        prompt_template_version="v1",
        retrieval_sources=[],
        tool_calls=list(tool_context or []),
    )
    outbound_system_prompt = system_prompt or "You are a governed enterprise AI assistant."
    if masking_policy.enabled:
        outbound_system_prompt = (
            f"{outbound_system_prompt}\n\n{REVERSIBLE_MASKING_SYSTEM_INSTRUCTION}"
        )
    prepared_provider_payload = prepare_provider_payload(
        system_prompt=outbound_system_prompt,
        user_prompt=effective_prompt,
        context=secure_context,
        provider=resolved_provider,
        model=str(model or resolved_model or ""),
        tool_context=list(tool_context or []),
        response_schema=_response_schema,
    )
    if prepared_provider_payload.masking_session is not None:
        _masking_sessions.append(prepared_provider_payload.masking_session)
    receipt_context: dict[str, Any] | None = None
    from app.core.control_engine.authorization import apply_trusted_pre_action_rollout

    chat_pre_action_governance_check = {
        "action_id": chat_action_id,
        "actor": {
            "identity_id": authenticated_user_id,
            "identity_type": "human",
            "user_id": authenticated_user_id,
        },
        "authority": {
            "authority_type": "authenticated_user",
            "authority_source": "tenant_context",
            "verified": True,
        },
        "surface": {
            "application": "llm_gateway",
            "provider": resolved_provider,
            "model": resolved_model,
            "asset_status": "approved",
            "environment": "prod",
        },
        "action": {
            "action_type": "prompt",
            "action_risk": str(ai_system.risk_tier or "unknown").lower(),
            "tool_name": "llm.generate",
            "tool_version": str(model or resolved_model or "unknown"),
            "tool_fingerprint_id": _hash_text(
                f"{resolved_provider}:{model or resolved_model or 'unknown'}"
            ),
            # Bind authorization to the exact post-transformation bytes sent
            # to the provider, never to the original prompt.
            "parameter_hash": prepared_provider_payload.material_hash,
            "target_resource": resolved_provider,
            "data_destination": resolved_provider,
            "side_effect_class": "external_provider_call",
        },
        "policy": {
            "policy_snapshot_id": policy_version_id,
            "control_ids": [str(item.get("control_id") or "") for item in pre_controls],
        },
    }
    chat_rollout = apply_trusted_pre_action_rollout(
        tenant_id=tenant_id,
        surface="llm_gateway",
        action_id=chat_action_id,
        chain_id=effective_chain_id,
        collector_id="llm-gateway-chat-complete",
        trusted_pre_action_governance_check=chat_pre_action_governance_check,
        legacy_decision=pre_decision,
        legacy_reason="llm_gateway_chat_pre_request",
        legacy_control_mode=("inline_prevented" if pre_decision == "block" else "inline_allowed"),
        policy_snapshot_id=policy_version_id,
        settings_obj=settings,
    )
    if (
        chat_rollout.enforced
        and settings.native_control_framework
        and settings.trusted_control_selector
    ):
        from app.services.native_control.selection_service import (
            apply_native_selection_to_rollout,
        )

        chat_rollout = apply_native_selection_to_rollout(
            db,
            rollout=chat_rollout,
            settings_obj=settings,
            trusted_provider=resolved_provider,
        )
    if chat_rollout.enforced:
        prepared_input_prompt = effective_prompt
        pre_decision = {
            "allow": "allow",
            "warn": "warn",
            "redact": "redact",
            "review": "hold_for_approval",
            "require_approval": "hold_for_approval",
            "require_second_approval": "hold_for_approval",
            "block": "block",
        }.get(chat_rollout.authoritative_decision, "block")
        effective_prompt = (
            _redact_prompt_for_request(user_prompt)
            if pre_decision in {"redact", "warn"} and not masking_policy.enabled
            else (_build_user_prompt(messages, masking_safe_headers=True) if masking_policy.enabled else user_prompt)
        )
        if effective_prompt != prepared_input_prompt:
            if prepared_provider_payload.masking_session is not None:
                prepared_provider_payload.masking_session.destroy()
            prepared_provider_payload = prepare_provider_payload(
                system_prompt=outbound_system_prompt,
                user_prompt=effective_prompt,
                context=secure_context,
                provider=resolved_provider,
                model=str(model or resolved_model or ""),
                tool_context=list(tool_context or []),
                response_schema=_response_schema,
            )
            if prepared_provider_payload.masking_session is not None:
                _masking_sessions.append(prepared_provider_payload.masking_session)
        chat_pre_action_governance_check["action"]["parameter_hash"] = prepared_provider_payload.material_hash
        pre_results.append(
            _guardian_result(
                guardian_id="authorization_kernel_v2",
                stage="pre_request",
                decision=pre_decision,
                confidence=1.0,
                matched_conditions=["server_selected_rollout"],
                reason=(chat_rollout.v2_response.reason if chat_rollout.v2_response else "evaluation_failed"),
                actions_taken={},
                threat_types=[],
            )
        )
        if settings.decision_execution_receipts_enabled:
            from app.services.receipt_service import persist_pre_execution_decision_isolated

            if chat_rollout.request is None or chat_rollout.v2_response is None:
                raise RuntimeError("selected authorization result lacks receipt material")
            receipt_request = chat_rollout.request.model_copy(
                update={
                    "parameters": {
                        **dict(chat_rollout.request.parameters),
                        "parameter_hash": prepared_provider_payload.material_hash,
                    }
                }
            )
            receipt_response = chat_rollout.v2_response
            minimizer_fields = list(
                prepared_provider_payload.minimizer_meta.get("redacted_fields") or []
            )
            if effective_prompt != user_prompt or minimizer_fields:
                transformations = tuple(
                    dict.fromkeys(
                        [
                            *receipt_response.transformations,
                            *(["pre_request_prompt_redaction"] if effective_prompt != user_prompt else []),
                            *[f"secure_minimizer:{field}" for field in minimizer_fields],
                        ]
                    )
                )
                receipt_response = receipt_response.model_copy(
                    update={"transformations": transformations}
                )
            decision_receipt, receipt_canonical = persist_pre_execution_decision_isolated(
                db,
                request=receipt_request,
                response=receipt_response,
                settings_obj=settings,
            )
            if decision_receipt is not None:
                receipt_context = {
                    "decision_receipt_id": decision_receipt.receipt_id,
                    "canonical_action": receipt_canonical,
                }
                from app.db.models.native_control import NativeControlSelection
                from app.services.action_integrity.canonical_v2 import domain_hash
                from app.services.action_integrity.execution_authority import (
                    build_trusted_execution_action,
                    current_rollout_configuration,
                )
                from app.services.action_integrity.lifecycle_persistence import (
                    persist_decision_receipt_v2_extension,
                )
                from app.services.action_integrity.signing import KmsHsmSigningKeyProvider
                from app.services.action_integrity.stored_authority import (
                    require_current_profile_selection_v1,
                )

                rollout_mode, policy_epoch = current_rollout_configuration(
                    db,
                    tenant_id=tenant_id,
                )
                if rollout_mode == "AUTHORITATIVE":
                    control_selection_id = str(
                        receipt_request.path_evidence.get("native_control_selection_id") or ""
                    )
                    if not control_selection_id:
                        raise PermissionError(
                            "authoritative LLM execution requires a selected native control path"
                        )
                    signing_provider = db.info.get("phase5_signing_provider") or KmsHsmSigningKeyProvider()
                    profile_selection = require_current_profile_selection_v1(
                        db,
                        provider=signing_provider,
                        tenant_id=tenant_id,
                        now=decision_receipt.issued_at,
                    )
                    native_selection = db.scalar(
                        select(NativeControlSelection).where(
                            NativeControlSelection.tenant_id == tenant_id,
                            NativeControlSelection.selection_id == control_selection_id,
                            NativeControlSelection.action_id == chat_action_id,
                        )
                    )
                    if native_selection is None:
                        raise PermissionError(
                            "authoritative LLM execution requires the stored native control selection"
                        )
                    phase5_action = build_trusted_execution_action(
                        tenant_id=tenant_id,
                        action_id=chat_action_id,
                        chain_id=effective_chain_id,
                        actor_principal=f"user:{authenticated_user_id or 'unknown'}",
                        executing_principal="service:llm-gateway",
                        operation="model_generate_text",
                        tool_or_service_ref=f"{resolved_provider}:{model or resolved_model}",
                        tool_fingerprint=domain_hash(
                            "hawk:closed-seam-fingerprint:v1",
                            {
                                "seam": "llm.provider.text",
                                "tool": f"{resolved_provider}:{model or resolved_model}",
                            },
                        ),
                        parameter_hash=prepared_provider_payload.material_hash,
                        target_ref=f"model:{resolved_provider}:{model or resolved_model}",
                        policy_epoch=policy_epoch,
                        approval_requirement="not_required",
                        policy_version_id="phase5:persisted-rollout",
                        now=decision_receipt.issued_at,
                    )
                    phase5_action.update(
                        domain_profile_ref=profile_selection.profile_id,
                        domain_profile_hash=profile_selection.profile_content_hash,
                        control_plan_id=native_selection.control_plan_id,
                        control_plan_digest=native_selection.control_plan_digest,
                    )
                    persist_decision_receipt_v2_extension(
                        db,
                        provider=signing_provider,
                        receipt=decision_receipt,
                        action=phase5_action,
                        profile_selection_id=profile_selection.selection_id,
                        profile_selection_hash=profile_selection.selection_hash,
                        control_selection_id=native_selection.selection_id,
                    )
                    db.flush()
                    db.commit()
                    receipt_context["stored_decision_authority"] = StoredDecisionSeamAuthority(
                        decision_receipt_id=decision_receipt.receipt_id,
                        action_id=chat_action_id,
                        chain_id=effective_chain_id,
                        actor_principal=f"user:{authenticated_user_id or 'unknown'}",
                        parameter_hash=prepared_provider_payload.material_hash,
                        target_ref=f"model:{resolved_provider}:{model or resolved_model}",
                    )

    if settings.decision_execution_receipts_enabled:
        # The durable pre-execution receipt must win the write lock before governance telemetry.
        enforce_governance(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            action="llm_gateway.chat.complete",
            route="/llm-gateway/chat/complete",
            module="llm_gateway_service",
            emit_logs=True,
        )

    provider_invoked = pre_decision not in {"block", "hold_for_approval"}
    raw_response = ""
    secure_gateway_trace: dict[str, Any] = {}
    secure_gateway_blocked = False
    provider_executed = False
    post_results: list[dict[str, Any]] = []
    post_controls: list[dict[str, Any]] = []
    execution_attempt_id = str(uuid4())
    if provider_invoked:
        provider_stage_failed = False
        try:
            secure_result = secure_generate_text(
            delegate=provider_instance,
            provider=resolved_provider,
            model=(model or resolved_model),
            model_version=str(model or resolved_model or ""),
            system_prompt=outbound_system_prompt,
            user_prompt=effective_prompt,
            context=secure_context,
            db=db,
            tenant_id=tenant_id,
            actor_user_id=authenticated_user_id,
            correlation_id=get_correlation_id(),
            prepared_payload=prepared_provider_payload,
            stored_decision_authority=(
                receipt_context.get("stored_decision_authority") if receipt_context else None
            ),
        )
        except Exception:
            provider_stage_failed = True
            if receipt_context:
                from app.services.receipt_service import queue_post_execution_receipt

                queue_post_execution_receipt(
                    db,
                    tenant_id=tenant_id,
                    decision_receipt_id=receipt_context["decision_receipt_id"],
                    actual_canonical_action=receipt_context["canonical_action"],
                    execution_status="failure",
                    collector_id="llm-gateway-provider",
                    settings_obj=settings,
                    execution_attempt_id=execution_attempt_id,
                )
        if provider_stage_failed:
            raise ProviderStageError() from None
        secure_gateway_trace = dict(secure_result.trace or {})
        secure_gateway_blocked = bool(secure_result.blocked)
        if secure_result.blocked and str(secure_result.block_reason or "").strip().lower() == "pre_call_policy_rejected":
            provider_invoked = False
            all_threat_types = list(secure_result.pre_call_guard.get("details", {}).get("actions", []) or [])
            pre_results.append(
                _guardian_result(
                    guardian_id="secure_gateway",
                    stage="pre_request",
                    decision="block",
                    confidence=1.0,
                    matched_conditions=list(secure_result.pre_call_guard.get("details", {}).get("violations", []) or []),
                    reason=str(secure_result.block_reason or "pre_call_policy_rejected"),
                    actions_taken={"blocked": True},
                    threat_types=all_threat_types,
                )
            )
            pre_controls = _augment_control_impacts(pre_controls, triggered_controls=["POLICY_ENFORCEMENT_CONTROL"])
        else:
            provider_executed = True
            raw_response = str(secure_result.output_text or "")
            post_results, post_controls = evaluate_post_response_guardian(
                response_text=raw_response,
                strictness_level=strictness_level,
            )
            if secure_result.blocked:
                post_results.append(
                    _guardian_result(
                        guardian_id="secure_gateway",
                        stage="post_response",
                        decision="block",
                        confidence=1.0,
                        matched_conditions=list(secure_result.post_call_guard.get("details", {}).get("violations", []) or []),
                        reason=str(secure_result.block_reason or "post_call_policy_rejected"),
                        actions_taken={"blocked": True},
                        threat_types=list(secure_result.post_call_guard.get("details", {}).get("actions", []) or []),
                    )
                )
                post_controls = _augment_control_impacts(post_controls, triggered_controls=["POLICY_ENFORCEMENT_CONTROL"])

    if receipt_context:
        from app.services.receipt_service import queue_post_execution_receipt

        queue_post_execution_receipt(
            db,
            tenant_id=tenant_id,
            decision_receipt_id=receipt_context["decision_receipt_id"],
            actual_canonical_action=receipt_context["canonical_action"],
            execution_status=("success" if provider_executed else None),
            collector_id="llm-gateway-provider",
            settings_obj=settings,
            execution_attempt_id=execution_attempt_id,
        )
        secure_gateway_trace["decision_receipt_id"] = receipt_context["decision_receipt_id"]

    all_results = [*pre_results, *post_results]
    final_decision = _aggregate_decision([item["decision"] for item in all_results])
    combined_controls = [*pre_controls, *post_controls]
    control_decision = evaluate_control_engine(
        AIAction(
            action_id=chat_action_id,
            user_id=authenticated_user_id,
            ai_app=resolved_provider,
            model=(model or resolved_model),
            prompt=effective_prompt,
            metadata={
                "source_surface": "gateway",
                "action_type": "prompt",
                "decision": final_decision,
                "reason_codes": [str(item.get("reason") or "") for item in all_results if isinstance(item, dict)],
                "input_signal_types": [str(tag) for item in all_results for tag in (item.get("threat_types") or [])],
                "contains_sensitive": any(str(item.get("guardian_id") or "") in {"data_guardian", "output_guardian"} and item.get("decision") in {"redact", "block"} for item in all_results),
                "data_classification": "sensitive" if any(str(item.get("guardian_id") or "") in {"data_guardian", "output_guardian"} and item.get("decision") in {"redact", "block"} for item in all_results) else "unknown",
                "triggered_controls": [str(item.get("control_id") or "") for item in combined_controls],
            },
            source_surface="gateway",
        ),
        base_decision=final_decision,
        hinted_control_ids=[str(item.get("control_id") or "") for item in combined_controls],
    )
    mapped_engine_decision = _map_control_engine_gateway_decision(control_decision.decision, fallback=final_decision)
    if _aggregate_decision([final_decision, mapped_engine_decision]) != final_decision:
        final_decision = _aggregate_decision([final_decision, mapped_engine_decision])
        all_results.append(
            {
                "guardian_contract_id": "control_engine.llm_gateway.chat_complete",
                "guardian_id": "control_engine",
                "decision": final_decision,
                "confidence": 1.0,
                "matched_conditions": ["central_control_engine"],
                "reason": "control_engine_escalation",
                "actions_taken": {
                    "dominant_control": control_decision.dominant_control,
                    "triggered_controls": list(control_decision.triggered_controls),
                    "total_risk_score": control_decision.total_risk_score,
                },
                "threat_types": list(control_decision.risk_tags or []),
            }
        )
    combined_controls = _augment_control_impacts(
        combined_controls,
        triggered_controls=list(control_decision.triggered_controls),
    )
    prompt_hash = _hash_text(effective_prompt)
    response_hash = _hash_text(raw_response) if raw_response else None
    controlled_response = mutate_output_restricted(response_text=raw_response, final_decision=final_decision)
    if _response_validator is not None and provider_executed and final_decision in {"allow", "warn"} and not secure_gateway_blocked:
        _response_validator(controlled_response)
    masking_session = prepared_provider_payload.masking_session
    masking_facts: dict[str, Any] = {
        "enabled": masking_policy.enabled,
        "applied": False,
        "restored": False,
        "entity_type_counts": {},
        "mapping_destroyed": True,
    }
    if masking_session is not None:
        masking_facts.update(masking_session.metadata())
        masking_facts["mapping_destroyed"] = True
        if (
            authenticated_user_id
            and masking_policy.restore_to_authenticated_caller
            and not secure_gateway_blocked
            and final_decision in {"allow", "warn"}
            and provider_executed
        ):
            restored_response = masking_session.restore(controlled_response)
            masking_facts["restored"] = restored_response != controlled_response
            controlled_response = restored_response
    response_control_coverage: ResponseControlCoverage
    secure_post_guard_details = dict(
        dict(secure_gateway_trace.get("post_call_guard") or {}).get("details") or {}
    )
    secure_post_violations = {
        str(item)
        for item in list(secure_post_guard_details.get("violations") or [])
    }
    redaction_declared = "post_call_sensitive_output_redacted" in {
        str(item)
        for item in list(secure_post_guard_details.get("actions") or [])
    }
    secure_post_control_verified = (
        "post_call_sensitive_output_redaction_unverified"
        not in secure_post_violations
        and (
            not redaction_declared
            or secure_post_guard_details.get("redaction_applied") is True
        )
    )
    if provider_executed and post_results and secure_post_control_verified:
        response_control_coverage = "complete"
    elif not provider_invoked:
        response_control_coverage = "request_only"
    else:
        response_control_coverage = "unknown"
    trace_payload = _build_trace_payload(
        ai_system_id=ai_system.id,
        actor_type=effective_actor_type,
        actor_id=effective_actor_id,
        provider=resolved_provider,
        model=resolved_model,
        prompt_hash=prompt_hash,
        response_hash=response_hash,
        policy_version_id=policy_version_id,
        request_stage="chat.complete",
        client_request_id=client_request_id,
        chain_id=effective_chain_id,
        parent_action_id=effective_parent_action_id,
        response_control_coverage=response_control_coverage,
        final_decision=final_decision,
        controls_impacted=combined_controls,
        authoritative_action_id=chat_action_id,
    )
    trace_payload["business_purpose"] = purpose_summary
    trace_payload["reversible_masking"] = masking_facts
    if claimed_actor_correlation_ref:
        trace_payload["claimed_actor_correlation_ref"] = claimed_actor_correlation_ref
    if secure_gateway_trace:
        trace_payload["secure_gateway"] = {
            "trace_id": secure_gateway_trace.get("trace_id"),
            "audit_log_id": secure_gateway_trace.get("audit_log_id"),
            "evidence_node_id": secure_gateway_trace.get("evidence_node_id"),
            "blocked": secure_gateway_blocked,
            "pre_call_guard": secure_gateway_trace.get("pre_call_guard"),
            "post_call_guard": secure_gateway_trace.get("post_call_guard"),
        }
    chat_pre_action_governance_check["control_mode"] = control_mode_for_pre_action_decision(
        final_decision,
        inline=True,
    )
    persisted = _persist_gateway_enforcement_event(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system.id,
        actor_type=effective_actor_type,
        actor_id=effective_actor_id,
        request_stage="chat.complete",
        client_request_id=client_request_id,
        prompt=effective_prompt,
        context_summary=context_summary,
        attachments_meta=attachments_meta,
        guardian_results=all_results,
        final_decision=final_decision,
        final_actions={
            "stage": "chat.complete",
            "strictness_level": strictness_level,
            "provider_invoked": provider_invoked,
            "output_mutation_applied": controlled_response != raw_response,
            "pre_request_decision": pre_decision,
            "control_decision": control_decision.to_dict(),
            "response_control_coverage": response_control_coverage,
        },
        controls_impacted=combined_controls,
        policy_version_id=policy_version_id,
        trace_payload=trace_payload,
    )
    if receipt_context and persisted.get("runtime_event_id"):
        from app.services.canonical_evidence_bundle_service import (
            link_bundle_to_runtime_projections,
        )

        link_bundle_to_runtime_projections(
            db,
            tenant_id=tenant_id,
            decision_receipt_id=receipt_context["decision_receipt_id"],
            settings_obj=settings,
            runtime_event_id=str(persisted["runtime_event_id"]),
        )
    action_control = _build_action_control_envelope(
        tenant_id=tenant_id,
        ai_system_id=ai_system.id,
        actor_type=effective_actor_type,
        actor_id=effective_actor_id,
        request_stage="chat.complete",
        client_request_id=client_request_id,
        provider=resolved_provider,
        model=resolved_model,
        final_decision=final_decision,
        controls_impacted=combined_controls,
        policy_version_id=policy_version_id,
        trace_payload=trace_payload,
        persisted=persisted,
        prompt_hash=prompt_hash,
        response_hash=response_hash,
        context_summary=context_summary,
        authoritative_action_id=chat_action_id,
        trusted_pre_action_governance_check={
            "control_mode": chat_pre_action_governance_check["control_mode"],
        },
    )
    return {
        **persisted,
        **action_control,
        "final_decision": final_decision,
        "guardian_results": all_results,
        "prompt_hash": prompt_hash,
        "response_hash": response_hash,
        "provider": resolved_provider,
        "model": resolved_model,
        "gateway_trace": trace_payload,
        "response_control_coverage": response_control_coverage,
        "chain_id": effective_chain_id,
        "parent_action_id": effective_parent_action_id,
        "completion": controlled_response if provider_invoked else "Request blocked by pre-request guardian policy.",
        "provider_invoked": provider_invoked,
    }


def gateway_chat_complete(db: Session, **kwargs: Any) -> dict[str, Any]:
    sessions: list[MaskingSession] = []
    try:
        return _gateway_chat_complete_impl(db, _masking_sessions=sessions, **kwargs)
    finally:
        for session in sessions:
            session.destroy()


def gateway_document_complete(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    policy_version_id: str,
    provider: str,
    model: str | None,
    trusted_actor_user_id: str,
    client_request_id: str | None,
    chain_id: str | None,
    parent_action_id: str | None,
    mode: str,
    output_format: str,
    instruction: str,
    file_bytes: bytes | None,
    file_name: str | None,
    mime_type: str | None,
) -> dict[str, Any]:
    if mode not in {"draft", "transform"} or output_format not in {"pdf", "docx"}:
        raise DocumentCodecError("unsupported_document_operation")
    if bool(file_bytes) != (mode == "transform"):
        raise DocumentCodecError("invalid_document_operation")
    if not instruction.strip() or len(instruction) > 10000:
        raise DocumentCodecError("document_instruction_limit")
    _system, policy_version, _strictness = _resolve_context(
        db, tenant_id=tenant_id, ai_system_id=ai_system_id,
        policy_version_id=policy_version_id, actor_type="human",
    )
    scope = policy_version.scope if isinstance(policy_version.scope, dict) else {}
    security = scope.get("llm_gateway_security") if isinstance(scope.get("llm_gateway_security"), dict) else {}
    masking_policy = ReversibleMaskingPolicy.from_scope(security.get("reversible_masking"))
    if not masking_policy.enabled or not masking_policy.documents_enabled or not masking_policy.restore_to_authenticated_caller:
        raise DocumentCodecError("documents_not_enabled")
    source = None
    expected = None
    if mode == "transform":
        source = parse_document(
            file_bytes or b"", file_name=file_name or "", mime_type=mime_type or "",
            max_bytes=masking_policy.max_document_bytes,
            max_pages=masking_policy.max_document_pages,
            max_chars=masking_policy.max_text_chars,
        )
        user_content, expected = serialize_transform(
            source, instruction=instruction, nonce=secrets.token_hex(12),
        )
    else:
        user_content = json.dumps({"mode": "draft", "instruction": instruction}, ensure_ascii=False, separators=(",", ":"))
    if len(user_content) > masking_policy.max_text_chars:
        raise DocumentCodecError("document_text_limit")

    def validate_masked(response: str) -> None:
        if expected is not None:
            validate_transform_edits_response(response, expected=expected, max_chars=masking_policy.max_text_chars)
        else:
            validate_draft_response(response, max_chars=masking_policy.max_text_chars)

    if expected is not None:
        system_instruction = (
            "Return only a JSON object with one key, edits. Each edit must contain an existing block id and either "
            "replacement text or replacement table rows. Return exactly one edit for every supplied id. "
            "For text edits preserve the supplied block kind, heading level, and list type; for table edits preserve "
            "the supplied table dimensions. The gateway rebuilds the original order and structure. No markdown fences "
            "or extra keys."
        )
    else:
        system_instruction = (
            "Return only a JSON object with one key, blocks. Each block is a heading "
            "(kind, level 1-6, text), paragraph (kind, text), list (kind, list_type bullet or number, text), "
            "or table (kind, rows of text cells). No markdown fences or extra keys. "
            "For draft create a concise complete document."
        )
    result = gateway_chat_complete(
        db, tenant_id=tenant_id, ai_system_id=ai_system_id,
        policy_version_id=policy_version_id, provider=provider, model=model,
        actor_type="human", actor_id=trusted_actor_user_id,
        trusted_actor_user_id=trusted_actor_user_id, client_request_id=client_request_id,
        chain_id=chain_id, parent_action_id=parent_action_id,
        system_prompt=system_instruction,
        messages=[{"role": "user", "content": user_content}],
        context_summary=f"document {mode}",
        attachments_meta=([{"format": source.format, "page_count": source.page_count, "block_count": len(source.blocks)}] if source else []),
        tool_context=[], _response_validator=validate_masked,
        _response_schema=_document_response_schema(mode),
    )
    if result["final_decision"] not in {"allow", "warn"} or not result["provider_invoked"]:
        raise DocumentCodecError("document_policy_blocked")
    if expected is not None:
        reconstructed = validate_transform_edits_response(
            result["completion"], expected=expected, max_chars=masking_policy.max_text_chars,
        )
    else:
        reconstructed = validate_draft_response(result["completion"], max_chars=masking_policy.max_text_chars)
    data = render_document(reconstructed, output_format=output_format, max_bytes=masking_policy.max_document_bytes)
    page_count = None
    if output_format == "pdf":
        import fitz
        with fitz.open(stream=data, filetype="pdf") as pdf:
            page_count = len(pdf)
            if page_count > masking_policy.max_document_pages:
                raise DocumentCodecError("document_page_limit")
    trace_masking = result.get("gateway_trace", {}).get("reversible_masking") or {}
    masking_facts = {
        "enabled": bool(trace_masking.get("enabled")),
        "applied": bool(trace_masking.get("applied")),
        "restored": bool(trace_masking.get("restored")),
        "entity_type_counts": {
            str(kind): int(count)
            for kind, count in dict(trace_masking.get("entity_type_counts") or {}).items()
        },
        "mapping_destroyed": bool(trace_masking.get("mapping_destroyed")),
    }
    event = db.get(EnforcementEvent, result["event_id"])
    if event is not None:
        actions = dict(event.final_actions or {})
        actions["document"] = {"format": output_format, "block_count": len(reconstructed.blocks)}
        event.final_actions = actions
    return {
        "file_name": safe_download_name(output_format),
        "media_type": PDF_MIME if output_format == "pdf" else DOCX_MIME,
        "content_base64": base64.b64encode(data).decode("ascii"),
        "document": {"format": output_format, "page_count": page_count, "block_count": len(reconstructed.blocks)},
        "hawk": {
            "final_decision": result["final_decision"],
            "provider_invoked": result["provider_invoked"],
            "response_control_coverage": result["response_control_coverage"],
            "reversible_masking": masking_facts,
        },
    }
