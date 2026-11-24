from __future__ import annotations

from typing import Any

from app.services.runtime_intelligence.schemas import RuntimeRiskScore


SEVERITY_BASE_SCORE = {
    "low": 20,
    "med": 40,
    "medium": 40,
    "high": 65,
    "critical": 85,
}


def _normalize_severity(value: str | None) -> str:
    normalized = str(value or "low").strip().lower()
    if normalized == "medium":
        return "med"
    if normalized not in {"low", "med", "high", "critical"}:
        return "low"
    return normalized


def _suggested_severity(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "med"
    return "low"


def score_runtime_risk(
    *,
    event: dict[str, Any],
    repeated_event_count: int = 1,
    governance_state: str | None = None,
    asymmetry_signal: bool = False,
    chain_depth: int | None = None,
    data_classification: str | None = None,
) -> RuntimeRiskScore:
    severity = _normalize_severity(str(event.get("severity") or "low"))
    score = int(SEVERITY_BASE_SCORE.get(severity, 20))
    reasoning: list[str] = [f"base_severity={severity}"]

    repeats = max(1, int(repeated_event_count))
    if repeats > 1:
        bump = min(25, (repeats - 1) * 5)
        score += bump
        reasoning.append(f"repeat_count={repeats}")

    governance = str(governance_state or event.get("governance_state") or "unknown").strip().lower()
    if governance in {"blocked", "rejected"}:
        score += 15
        reasoning.append(f"governance_state={governance}")
    elif governance not in {"approved", "active", "live"}:
        score += 10
        reasoning.append(f"governance_state={governance or 'unknown'}")

    resolved_chain_depth = chain_depth if chain_depth is not None else event.get("chain_depth")
    try:
        depth = int(resolved_chain_depth) if resolved_chain_depth is not None else None
    except (TypeError, ValueError):
        depth = None
    if depth is not None and depth >= 5:
        score += 15
        reasoning.append(f"chain_depth={depth}")
    elif depth is not None and depth >= 3:
        score += 10
        reasoning.append(f"chain_depth={depth}")

    if asymmetry_signal:
        score += 15
        reasoning.append("asymmetry_signal=true")

    classification = str(data_classification or event.get("data_classification") or "").strip().lower()
    if classification in {"sensitive", "confidential", "restricted", "regulated"}:
        score += 10
        reasoning.append(f"data_classification={classification}")

    response_size = event.get("response_size")
    try:
        response_size_int = int(response_size) if response_size is not None else None
    except (TypeError, ValueError):
        response_size_int = None
    if response_size_int is not None and response_size_int >= 1_000_000:
        score += 5
        reasoning.append("response_size=large")

    score = max(0, min(100, int(score)))
    suggested = _suggested_severity(score)

    if score >= 85:
        recommendation = "route_to_review"
    elif score >= 65:
        recommendation = "escalate_risk_tier"
    elif score >= 40:
        recommendation = "monitor_and_validate"
    else:
        recommendation = "monitor_only"

    return RuntimeRiskScore(
        risk_score=score,
        suggested_severity=suggested,
        recommended_action=recommendation,
        reasoning=reasoning,
    )
