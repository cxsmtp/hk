from __future__ import annotations

import re
from typing import Any

from app.core.config import settings


_TOKEN_PATTERN = re.compile(r"[a-z0-9_]+")
_STOP_WORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "in",
    "is",
    "it",
    "of",
    "on",
    "or",
    "that",
    "the",
    "to",
    "with",
}


def _tokenize(value: str | None) -> set[str]:
    text = str(value or "").strip().lower()
    if not text:
        return set()
    tokens = {token for token in _TOKEN_PATTERN.findall(text) if token and token not in _STOP_WORDS}
    return tokens


def _jaccard_similarity(left: set[str], right: set[str]) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    union = left | right
    if not union:
        return 1.0
    return float(len(left & right)) / float(len(union))


def compose_action_summary(*, event_type: str, metadata: dict[str, Any]) -> str:
    fragments: list[str] = []
    for key in (
        "action_type",
        "operation",
        "tool_name",
        "tool_category",
        "api_endpoint",
        "target_resource",
        "data_source",
        "domain",
        "reason_code",
        "reason",
    ):
        value = str(metadata.get(key) or "").strip()
        if value:
            fragments.append(value)
    if not fragments:
        fragments.append(str(event_type or "unknown_action").strip() or "unknown_action")
    return " | ".join(fragments)


def compute_semantic_drift(
    *,
    original_intent: str | None,
    current_action: str | None,
    threshold: float | None = None,
) -> dict[str, Any]:
    intent_tokens = _tokenize(original_intent)
    action_tokens = _tokenize(current_action)
    active_threshold = float(threshold if threshold is not None else settings.runtime_semantic_drift_threshold)

    similarity = _jaccard_similarity(intent_tokens, action_tokens)
    drift_score = 1.0 - similarity
    threshold_breach = bool(drift_score >= active_threshold)

    return {
        "original_intent": str(original_intent or "").strip() or None,
        "current_action": str(current_action or "").strip() or None,
        "similarity": round(similarity, 4),
        "drift_score": round(drift_score, 4),
        "threshold": round(active_threshold, 4),
        "threshold_breach": threshold_breach,
        "available": bool(intent_tokens and action_tokens),
    }
