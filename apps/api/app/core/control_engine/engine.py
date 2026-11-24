from __future__ import annotations

from typing import Any

from app.core.control_engine.schemas import AIAction, ControlDecision, ControlResult


GENERIC_DECISION_ORDER = {
    "allow": 0,
    "alert": 1,
    "modify": 2,
    "step_up": 3,
    "block": 4,
}

LEGACY_TO_GENERIC_DECISION = {
    "allow": "allow",
    "warn": "alert",
    "alert": "alert",
    "redact": "modify",
    "modify": "modify",
    "step_up": "step_up",
    "hold_for_approval": "step_up",
    "hold": "step_up",
    "require_approval": "step_up",
    "require_justification": "step_up",
    "block": "block",
    "deny": "block",
    "denied": "block",
}

DEFAULT_EVALUATION_CONTROLS = {
    "POLICY_ENFORCEMENT_CONTROL",
}

LEGACY_CONTROL_ALIASES = {
    "CTRL-INPUT-001": "PROMPT_INJECTION_DETECTION",
    "CTRL-DLP-001": "PII_EXFILTRATION_PREVENTION",
    "CTRL-TENANT-ISO-001": "POLICY_ENFORCEMENT_CONTROL",
    "CTRL-AI-IAM-001": "AGENT_ACTION_AUTHORIZATION",
    "CTRL-TOOL-001": "TOOL_CALL_VALIDATION",
    "CTRL-OUTPUT-001": "MODEL_OUTPUT_VALIDATION",
    "OCR_BASED_EXTRACTION_CONTROL": "OCR_DATA_EXTRACTION_CONTROL",
    "CROSS_AGENT_BOUNDARY_CONTROL": "CHAIN_OF_ACTION_VALIDATION",
    "RISK_CLASSIFICATION_CONTROL": "POLICY_ENFORCEMENT_CONTROL",
}

CONTROL_SEVERITY_WEIGHT = {
    "PROMPT_INJECTION_DETECTION": 5.0,
    "JAILBREAK_DETECTION": 5.0,
    "SENSITIVE_DATA_DETECTION": 4.0,
    "PII_EXFILTRATION_PREVENTION": 5.0,
    "FILE_UPLOAD_INSPECTION": 4.0,
    "OCR_DATA_EXTRACTION_CONTROL": 4.0,
    "RAG_POISONING_DETECTION": 5.0,
    "MODEL_OUTPUT_VALIDATION": 4.0,
    "MODEL_ACCESS_CONTROL": 4.0,
    "SHADOW_AI_DETECTION": 3.5,
    "AI_SYSTEM_INVENTORY_CONTROL": 4.0,
    "AI_IDENTITY_BINDING": 4.0,
    "NON_HUMAN_IDENTITY_CONTROL": 4.0,
    "TOKEN_SCOPE_ENFORCEMENT": 4.0,
    "PRIVILEGE_DRIFT_DETECTION": 4.0,
    "TOOL_CALL_VALIDATION": 4.5,
    "AGENT_ACTION_AUTHORIZATION": 5.0,
    "CHAIN_OF_ACTION_VALIDATION": 4.5,
    "CONTEXT_LEAKAGE_DETECTION": 4.0,
    "POLICY_ENFORCEMENT_CONTROL": 3.0,
}

CONTROL_RISK_TAGS = {
    "PROMPT_INJECTION_DETECTION": ["prompt_injection", "prompt_decomposition", "jailbreak"],
    "JAILBREAK_DETECTION": ["jailbreak", "policy_bypass"],
    "SENSITIVE_DATA_DETECTION": ["sensitive_data", "pii_exposure"],
    "PII_EXFILTRATION_PREVENTION": ["data_exfiltration", "pii_exposure"],
    "FILE_UPLOAD_INSPECTION": ["file_exfiltration", "sensitive_upload"],
    "OCR_DATA_EXTRACTION_CONTROL": ["ocr_sensitive_data", "hidden_payload"],
    "RAG_POISONING_DETECTION": ["rag_poisoning", "model_poisoning"],
    "MODEL_OUTPUT_VALIDATION": ["unsafe_output", "context_leakage"],
    "MODEL_ACCESS_CONTROL": ["unsanctioned_model_access", "shadow_ai"],
    "SHADOW_AI_DETECTION": ["shadow_ai", "unknown_ai"],
    "AI_SYSTEM_INVENTORY_CONTROL": ["unknown_ai", "governance_gap"],
    "AI_IDENTITY_BINDING": ["identity_abuse"],
    "NON_HUMAN_IDENTITY_CONTROL": ["identity_abuse", "agent_abuse"],
    "TOKEN_SCOPE_ENFORCEMENT": ["unauthorized_action", "token_sprawl"],
    "PRIVILEGE_DRIFT_DETECTION": ["privilege_drift"],
    "TOOL_CALL_VALIDATION": ["tool_misuse", "unauthorized_action"],
    "AGENT_ACTION_AUTHORIZATION": ["agent_abuse", "unauthorized_action"],
    "CHAIN_OF_ACTION_VALIDATION": ["chain_abuse", "multi_step_attack", "prompt_decomposition"],
    "CONTEXT_LEAKAGE_DETECTION": ["context_leakage", "data_exfiltration"],
    "POLICY_ENFORCEMENT_CONTROL": ["policy_violation", "governance_gap"],
}

CONTROL_TRIGGER_HINTS = {
    "PROMPT_INJECTION_DETECTION": (
        "prompt_injection",
        "prompt_decomposition",
        "jailbreak",
        "ignore previous",
        "override policy",
        "dan mode",
        "break down the prompt to bypass",
        "step by step to avoid detection",
    ),
    "JAILBREAK_DETECTION": ("jailbreak", "policy_bypass", "bypass safeguards"),
    "SENSITIVE_DATA_DETECTION": ("sensitive_data", "sensitive_entity", "contains_sensitive", "pii"),
    "PII_EXFILTRATION_PREVENTION": ("exfiltration", "sensitive_data_pattern", "pii", "credit_card", "emirates_id"),
    "FILE_UPLOAD_INSPECTION": ("file_upload", "upload", "attachment"),
    "OCR_DATA_EXTRACTION_CONTROL": ("ocr", "image", "pdf", "scan"),
    "RAG_POISONING_DETECTION": ("rag_poisoning", "poisoning"),
    "MODEL_OUTPUT_VALIDATION": ("output_injection", "unsafe_output", "response_guard"),
    "MODEL_ACCESS_CONTROL": ("model_access", "unsupported_provider", "unknown_provider", "open_source_model_hint"),
    "SHADOW_AI_DETECTION": ("shadow_ai", "unknown_ai", "unsanctioned"),
    "AI_SYSTEM_INVENTORY_CONTROL": ("unregistered_ai_system", "unknown_ai", "governance"),
    "AI_IDENTITY_BINDING": ("identity", "impersonation"),
    "NON_HUMAN_IDENTITY_CONTROL": ("service_identity", "capability_token", "agent_token_mismatch"),
    "TOKEN_SCOPE_ENFORCEMENT": ("scope", "token", "authorization"),
    "PRIVILEGE_DRIFT_DETECTION": ("privilege_drift", "anomaly"),
    "TOOL_CALL_VALIDATION": ("tool", "tool_not_allowed", "tool_misuse"),
    "AGENT_ACTION_AUTHORIZATION": ("agent_action_scope_denied", "capability_token_invalid", "agent_token_mismatch"),
    "CHAIN_OF_ACTION_VALIDATION": ("chain_depth", "delegation", "chain", "prompt_decomposition", "step_by_step_bypass"),
    "CONTEXT_LEAKAGE_DETECTION": ("context_leakage", "cross_context"),
    "POLICY_ENFORCEMENT_CONTROL": ("policy", "guardian", "violation"),
}

CRITICAL_OVERRIDE_CONTROLS = {
    "PROMPT_INJECTION_DETECTION",
    "AGENT_ACTION_AUTHORIZATION",
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _norm(value: Any) -> str:
    return _text(value).lower()


def normalize_control_id(control_id: str) -> str:
    token = _text(control_id).upper()
    if not token:
        return ""
    alias = LEGACY_CONTROL_ALIASES.get(token)
    if alias:
        return alias
    return token


def normalize_control_ids(control_ids: list[str] | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in list(control_ids or []):
        normalized = normalize_control_id(item)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out.append(normalized)
    return out


def _to_generic(decision: str | None) -> str:
    token = _norm(decision)
    return LEGACY_TO_GENERIC_DECISION.get(token, "allow")


def _generic_rank(decision: str | None) -> int:
    return GENERIC_DECISION_ORDER.get(_to_generic(decision), 0)


def merge_with_base_decision(base_decision: str | None, evaluated_decision: str) -> str:
    base_generic = _to_generic(base_decision)
    eval_generic = _to_generic(evaluated_decision)
    return eval_generic if _generic_rank(eval_generic) >= _generic_rank(base_generic) else base_generic


def map_generic_decision(generic_decision: str, *, mapping: dict[str, str], default: str = "allow") -> str:
    normalized = _to_generic(generic_decision)
    return _text(mapping.get(normalized) or default) or default


def _collect_signal_tokens(ai_action: AIAction) -> list[str]:
    metadata = dict(ai_action.metadata or {})
    tokens: list[str] = []
    for key in [
        "reason",
        "reason_code",
        "decision",
        "final_decision",
        "violation_reason",
        "destination_domain",
        "destination_app_name",
        "source_surface",
        "action_type",
        "data_classification",
        "governance_status",
        "governance_state",
        "classification",
    ]:
        value = _norm(metadata.get(key))
        if value:
            tokens.append(value)
    for key in ["reason_codes", "risk_tags", "risk_labels", "input_signal_types", "triggered_controls", "policy_tags"]:
        raw = metadata.get(key)
        if isinstance(raw, list):
            tokens.extend([_norm(item) for item in raw if _text(item)])
        elif isinstance(raw, str) and _text(raw):
            tokens.append(_norm(raw))
    if _text(ai_action.prompt):
        tokens.append(_norm(ai_action.prompt))
    if _text(ai_action.ai_app):
        tokens.append(_norm(ai_action.ai_app))
    if _text(ai_action.model):
        tokens.append(_norm(ai_action.model))
    return [item for item in tokens if item]


def _contains_sensitive(ai_action: AIAction) -> bool:
    metadata = dict(ai_action.metadata or {})
    classification = _norm(metadata.get("data_classification"))
    if classification in {"sensitive", "restricted"}:
        return True
    if bool(metadata.get("contains_sensitive")):
        return True
    return any("sensitive_entity" in _norm(item) for item in list(metadata.get("input_signal_types") or []))


def _is_unknown_ai(ai_action: AIAction) -> bool:
    metadata = dict(ai_action.metadata or {})
    governance_state = _norm(metadata.get("governance_status") or metadata.get("governance_state"))
    if governance_state in {"unknown", "unregistered_ai_system"}:
        return True
    return any(
        token in _norm(metadata.get("reason_code")) or token in _norm(metadata.get("reason"))
        for token in ("unknown_ai", "unregistered_ai_system", "shadow_ai")
    )


def select_controls_for_action(
    ai_action: AIAction,
    *,
    hinted_control_ids: list[str] | None = None,
) -> list[str]:
    metadata = dict(ai_action.metadata or {})
    source_surface = _norm(ai_action.source_surface or metadata.get("source_surface"))
    action_type = _norm(metadata.get("action_type") or metadata.get("operation") or "prompt")
    contains_sensitive = _contains_sensitive(ai_action)
    unknown_ai = _is_unknown_ai(ai_action)
    controls: list[str] = list(DEFAULT_EVALUATION_CONTROLS)

    if source_surface in {"browser", "gateway", "api"}:
        controls.extend(["PROMPT_INJECTION_DETECTION", "MODEL_OUTPUT_VALIDATION", "CONTEXT_LEAKAGE_DETECTION"])
    if source_surface in {"gateway", "api"}:
        controls.append("MODEL_ACCESS_CONTROL")
    if source_surface in {"agent", "aiiam"}:
        controls.extend(
            [
                "AGENT_ACTION_AUTHORIZATION",
                "TOOL_CALL_VALIDATION",
                "CHAIN_OF_ACTION_VALIDATION",
                "TOKEN_SCOPE_ENFORCEMENT",
                "PRIVILEGE_DRIFT_DETECTION",
                "NON_HUMAN_IDENTITY_CONTROL",
            ]
        )
    if source_surface in {"connector", "monitoring", "endpoint", "dns", "proxy"}:
        controls.extend(["SHADOW_AI_DETECTION", "AI_SYSTEM_INVENTORY_CONTROL"])

    if action_type in {"upload", "file_upload", "upload_file"} or bool(ai_action.file) or bool(metadata.get("file_meta")):
        controls.extend(["FILE_UPLOAD_INSPECTION", "OCR_DATA_EXTRACTION_CONTROL"])
    if action_type in {"tool_execution", "api_call"}:
        controls.append("TOOL_CALL_VALIDATION")
    if action_type in {"agent_action"}:
        controls.append("AGENT_ACTION_AUTHORIZATION")

    if contains_sensitive:
        controls.extend(["SENSITIVE_DATA_DETECTION", "PII_EXFILTRATION_PREVENTION"])
    if unknown_ai:
        controls.extend(["AI_SYSTEM_INVENTORY_CONTROL", "SHADOW_AI_DETECTION"])

    controls.extend(normalize_control_ids(hinted_control_ids))
    return normalize_control_ids(controls)


def _is_explicitly_triggered(control_id: str, hinted_controls: set[str]) -> bool:
    return normalize_control_id(control_id) in hinted_controls


def _matches_hints(control_id: str, signal_tokens: list[str]) -> bool:
    hints = CONTROL_TRIGGER_HINTS.get(control_id, ())
    if not hints:
        return False
    for hint in hints:
        hint_token = _norm(hint)
        for token in signal_tokens:
            if not hint_token:
                continue
            if token == hint_token:
                return True
            if token.startswith(f"{hint_token}:") or token.endswith(f":{hint_token}") or f":{hint_token}:" in token:
                return True
            # Allow substring-style matching only for richer patterns so
            # generic hints like "agent" do not trigger broad false positives.
            if (" " in hint_token or "_" in hint_token or "-" in hint_token) and hint_token in token:
                return True
    return False


def evaluate_control_engine(
    ai_action: AIAction,
    *,
    base_decision: str | None = None,
    hinted_control_ids: list[str] | None = None,
    evidence_refs: list[str] | None = None,
) -> ControlDecision:
    metadata = dict(ai_action.metadata or {})
    candidate_controls = select_controls_for_action(ai_action, hinted_control_ids=hinted_control_ids)
    hinted = set(normalize_control_ids([*list(hinted_control_ids or []), *list(metadata.get("triggered_controls") or [])]))
    signal_tokens = _collect_signal_tokens(ai_action)
    contains_sensitive = _contains_sensitive(ai_action)
    action_type = _norm(metadata.get("action_type") or metadata.get("operation"))
    destination_external = bool(metadata.get("destination_is_external"))

    results: list[ControlResult] = []
    for control_id in candidate_controls:
        severity_weight = float(CONTROL_SEVERITY_WEIGHT.get(control_id, 3.0))
        explicitly_triggered = _is_explicitly_triggered(control_id, hinted)
        hint_triggered = _matches_hints(control_id, signal_tokens)
        contextual_triggered = False
        if control_id == "PII_EXFILTRATION_PREVENTION":
            contextual_triggered = contains_sensitive and (
                destination_external
                or action_type in {"copy_paste", "upload", "file_upload", "api_call", "email_send"}
            )
        elif control_id == "FILE_UPLOAD_INSPECTION":
            contextual_triggered = (
                bool(metadata.get("file_contains_sensitive"))
                or (
                    contains_sensitive
                    and (action_type in {"upload", "file_upload", "upload_file"} or bool(ai_action.file) or bool(metadata.get("file_meta")))
                )
            )
        elif control_id == "OCR_DATA_EXTRACTION_CONTROL":
            contextual_triggered = bool(metadata.get("ocr_sensitive_detected")) or (
                contains_sensitive and bool(metadata.get("file_meta") or ai_action.file)
            )
        elif control_id == "AGENT_ACTION_AUTHORIZATION":
            # Do not treat every agent action as unauthorized. This control
            # should trigger only when authorization mismatch/denial signals
            # are present.
            auth_signal = _norm(metadata.get("authorization_result"))
            scope_violation = bool(metadata.get("agent_scope_violation")) or bool(metadata.get("capability_token_invalid"))
            contextual_triggered = auth_signal in {"deny", "denied", "block", "blocked"} or scope_violation
        elif control_id == "AI_SYSTEM_INVENTORY_CONTROL":
            contextual_triggered = _is_unknown_ai(ai_action)
        elif control_id == "SENSITIVE_DATA_DETECTION":
            contextual_triggered = contains_sensitive
        elif control_id == "POLICY_ENFORCEMENT_CONTROL":
            contextual_triggered = False

        triggered = bool(explicitly_triggered or hint_triggered or contextual_triggered)
        if explicitly_triggered:
            confidence = 0.98
            reason = "Explicit signal mapped to control."
        elif hint_triggered:
            confidence = 0.86
            reason = "Control trigger hints matched action context."
        elif contextual_triggered:
            confidence = 0.72
            reason = "Control triggered by deterministic contextual rule."
        else:
            confidence = 0.08
            reason = "Control evaluated; no triggering conditions observed."

        risk_score = round((confidence * severity_weight) if triggered else 0.0, 4)
        results.append(
            ControlResult(
                control_id=control_id,
                triggered=triggered,
                confidence_score=round(confidence, 4),
                severity_weight=round(severity_weight, 2),
                risk_score=risk_score,
                reasoning=reason,
                evidence_refs=list(evidence_refs or []),
                risk_tags=list(CONTROL_RISK_TAGS.get(control_id, [])),
            )
        )

    triggered_results = [row for row in results if row.triggered]
    triggered_controls = [row.control_id for row in triggered_results]
    total_risk = round(sum(row.risk_score for row in results), 4)
    dominant = None
    if triggered_results:
        dominant = max(triggered_results, key=lambda row: (row.risk_score, row.severity_weight)).control_id
    else:
        dominant = max(results, key=lambda row: (row.severity_weight, row.confidence_score)).control_id if results else None

    if any(row.control_id in CRITICAL_OVERRIDE_CONTROLS for row in triggered_results):
        evaluated_decision = "block"
    elif total_risk >= 7.0:
        evaluated_decision = "block"
    elif total_risk >= 3.5:
        evaluated_decision = "step_up" if contains_sensitive or _norm(ai_action.source_surface) in {"agent", "aiiam"} else "modify"
    elif total_risk >= 1.5:
        evaluated_decision = "alert"
    else:
        evaluated_decision = "allow"

    merged_decision = merge_with_base_decision(base_decision, evaluated_decision)
    risk_tags = sorted({tag for row in triggered_results for tag in row.risk_tags})
    reasoning_parts = [
        f"{len(triggered_controls)} controls triggered",
        f"total_risk_score={total_risk}",
        f"base_decision={_to_generic(base_decision)}",
        f"final_decision={merged_decision}",
    ]
    if dominant:
        reasoning_parts.append(f"dominant_control={dominant}")

    return ControlDecision(
        action_id=ai_action.action_id,
        decision=merged_decision,
        total_risk_score=total_risk,
        triggered_controls=triggered_controls,
        evaluated_controls=results,
        dominant_control=dominant,
        reasoning="; ".join(reasoning_parts),
        evidence_refs=list(evidence_refs or []),
        risk_tags=risk_tags,
    )
