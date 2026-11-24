from __future__ import annotations

from typing import Any


CONFIDENCE_TIER_CLEAR_NEGATIVE = "clear_negative"
CONFIDENCE_TIER_AMBIGUOUS = "ambiguous"
CONFIDENCE_TIER_CLEAR_POSITIVE = "clear_positive"


def classify_confidence_tier(
    *,
    confidence: float,
    threshold: float,
    trigger_matched: bool,
    block_matched: bool,
) -> str:
    normalized_threshold = max(0.0, min(1.0, float(threshold)))
    normalized_confidence = max(0.0, min(1.0, float(confidence)))
    lower = normalized_threshold * 0.5
    upper = max(normalized_threshold, 0.7)

    if block_matched:
        return CONFIDENCE_TIER_CLEAR_POSITIVE
    if trigger_matched and normalized_confidence >= upper:
        return CONFIDENCE_TIER_CLEAR_POSITIVE
    if not trigger_matched and normalized_confidence <= lower:
        return CONFIDENCE_TIER_CLEAR_NEGATIVE
    return CONFIDENCE_TIER_AMBIGUOUS


def _extract_prompt_text(payload: dict[str, Any]) -> str:
    prompt_value = payload.get("prompt")
    if isinstance(prompt_value, dict):
        return str(prompt_value.get("text") or "")
    return str(prompt_value or "")


def _extract_context_text(payload: dict[str, Any]) -> str:
    context_value = payload.get("context")
    if isinstance(context_value, dict):
        return str(context_value.get("summary") or "")
    return str(payload.get("context_summary") or "")


def run_ambiguous_arbiter(
    *,
    payload: dict[str, Any],
    guardian_contract_id: str,
    matched_conditions: list[str],
    threshold: float,
) -> dict[str, Any]:
    prompt = _extract_prompt_text(payload).lower()
    context = _extract_context_text(payload).lower()
    tool_output = str(payload.get("tool_output") or "").lower()
    combined = f"{prompt} {context} {tool_output}"

    suspicious_keywords = (
        "ignore previous",
        "bypass",
        "disable",
        "system prompt",
        "api key",
        "password",
        "secret",
        "admin",
        "override",
        "execute",
    )
    keyword_hits = sum(1 for keyword in suspicious_keywords if keyword in combined)

    positive_bias = len(matched_conditions) + keyword_hits
    if positive_bias >= 2:
        return {
            "tier": CONFIDENCE_TIER_CLEAR_POSITIVE,
            "confidence": max(0.72, float(threshold)),
            "reason": "arbiter_positive_signal",
            "guardian_contract_id": guardian_contract_id,
            "keyword_hits": keyword_hits,
        }

    return {
        "tier": CONFIDENCE_TIER_CLEAR_NEGATIVE,
        "confidence": min(0.35, max(0.0, float(threshold) - 0.1)),
        "reason": "arbiter_negative_signal",
        "guardian_contract_id": guardian_contract_id,
        "keyword_hits": keyword_hits,
    }


def _extract_tool_call_count(attachments_meta: list[dict[str, Any]]) -> int:
    total = 0
    for item in attachments_meta:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("tool_call_count"), int):
            total += max(0, int(item.get("tool_call_count")))
            continue
        if isinstance(item.get("tool_calls"), list):
            total += len(item.get("tool_calls") or [])
            continue
        if str(item.get("type") or "").strip().lower() == "tool_call":
            total += 1
    return total


def detect_asymmetry_signal(
    *,
    prompt: str,
    tool_output: str | None,
    attachments_meta: list[dict[str, Any]],
    small_prompt_threshold_chars: int,
    large_output_threshold_chars: int,
    output_ratio_threshold: float,
    tool_call_threshold: int,
) -> dict[str, Any]:
    prompt_text = str(prompt or "").strip()
    output_text = str(tool_output or "").strip()
    prompt_chars = len(prompt_text)
    output_chars = len(output_text)
    tool_call_count = _extract_tool_call_count(attachments_meta)

    safe_prompt_chars = max(1, prompt_chars)
    output_to_prompt_ratio = round(output_chars / safe_prompt_chars, 4)

    prompt_is_small = prompt_chars <= max(1, int(small_prompt_threshold_chars))
    output_is_large = output_chars >= max(1, int(large_output_threshold_chars))
    ratio_is_large = output_to_prompt_ratio >= float(output_ratio_threshold)
    tool_calls_are_high = tool_call_count >= max(1, int(tool_call_threshold))

    triggered = prompt_is_small and ((output_is_large and ratio_is_large) or tool_calls_are_high)

    risk_labels: list[str] = []
    if triggered:
        risk_labels.append("output_asymmetry")
    if tool_calls_are_high:
        risk_labels.append("agent_chain_abuse")

    return {
        "triggered": triggered,
        "risk_labels": risk_labels,
        "simulation_schedule_hint": "increase_frequency" if triggered else "none",
        "recommended_simulation_categories": (
            ["output_injection", "agent_misuse"] if triggered else []
        ),
        "prompt_chars": prompt_chars,
        "output_chars": output_chars,
        "output_to_prompt_ratio": output_to_prompt_ratio,
        "tool_call_count": tool_call_count,
        "thresholds": {
            "small_prompt_threshold_chars": int(small_prompt_threshold_chars),
            "large_output_threshold_chars": int(large_output_threshold_chars),
            "output_ratio_threshold": float(output_ratio_threshold),
            "tool_call_threshold": int(tool_call_threshold),
        },
    }
