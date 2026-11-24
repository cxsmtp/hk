from __future__ import annotations

from typing import Literal


ResponseControlCoverage = Literal[
    "complete",
    "partial",
    "request_only",
    "post_execution",
    "unknown",
]
RESPONSE_CONTROL_COVERAGE_ORDER: tuple[ResponseControlCoverage, ...] = (
    "complete",
    "partial",
    "request_only",
    "post_execution",
    "unknown",
)
RESPONSE_CONTROL_COVERAGE_VALUES = frozenset(RESPONSE_CONTROL_COVERAGE_ORDER)


def normalize_response_control_coverage(value: object) -> ResponseControlCoverage:
    normalized = str(value or "").strip().lower()
    if normalized in RESPONSE_CONTROL_COVERAGE_VALUES:
        return normalized  # type: ignore[return-value]
    return "unknown"
