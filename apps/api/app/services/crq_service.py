from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _text(value: Any) -> str:
    return str(value or "").strip()


def _text_lower(value: Any) -> str:
    return _text(value).lower()


SEVERITY_IMPACT_USD: dict[str, float] = {
    "low": 75_000.0,
    "med": 180_000.0,
    "medium": 180_000.0,
    "high": 620_000.0,
    "critical": 2_250_000.0,
}

CATEGORY_IMPACT_MULTIPLIER: dict[str, float] = {
    "identity": 1.15,
    "data": 1.45,
    "model": 1.25,
    "interaction": 1.1,
    "agent": 1.3,
    "governance": 1.2,
}

RISK_TAG_IMPACT_HINT: dict[str, float] = {
    "pii_exposure": 1.3,
    "data_exfiltration": 1.4,
    "sensitive_data": 1.2,
    "shadow_ai": 1.2,
    "unknown_ai": 1.2,
    "prompt_injection": 1.1,
    "jailbreak": 1.1,
    "model_integrity": 1.25,
    "rag_poisoning": 1.2,
    "agent_abuse": 1.25,
    "chain_abuse": 1.25,
    "policy_violation": 1.15,
}

SEVERITY_EXPOSURE_FACTOR: dict[str, float] = {
    "low": 0.25,
    "med": 0.45,
    "medium": 0.45,
    "high": 0.7,
    "critical": 0.9,
}

REMEDIATION_EFFECTIVENESS: dict[str, float] = {
    "policy_tighten": 0.72,
    "permission_reduce": 0.68,
    "connector_disable": 0.86,
    "source_quarantine": 0.84,
    "require_step_up": 0.52,
    "agent_suspend": 0.8,
    "kill_switch": 0.92,
    "trust_center_escalation": 0.58,
    "ticket_create": 0.12,
}

REMEDIATION_COST_USD: dict[str, float] = {
    "policy_tighten": 8_500.0,
    "permission_reduce": 12_000.0,
    "connector_disable": 18_000.0,
    "source_quarantine": 16_000.0,
    "require_step_up": 9_000.0,
    "agent_suspend": 20_000.0,
    "kill_switch": 28_000.0,
    "trust_center_escalation": 14_000.0,
    "ticket_create": 2_000.0,
}


@dataclass(frozen=True)
class RiskEvent:
    event_id: str
    control_id: str
    threat_type: str
    asset: str
    likelihood: float
    impact: float
    frequency: float
    exposure_factor: float
    annualized_loss_expectancy: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "control_id": self.control_id,
            "threat_type": self.threat_type,
            "asset": self.asset,
            "likelihood": round(self.likelihood, 4),
            "impact": round(self.impact, 2),
            "frequency": round(self.frequency, 4),
            "exposure_factor": round(self.exposure_factor, 4),
            "annualized_loss_expectancy": round(self.annualized_loss_expectancy, 2),
        }


def _severity_key(value: Any) -> str:
    token = _text_lower(value)
    if token in {"med", "medium"}:
        return "medium"
    if token in {"critical", "high", "low"}:
        return token
    return "medium"


def _category_key(value: Any) -> str:
    token = _text_lower(value)
    return token if token in CATEGORY_IMPACT_MULTIPLIER else "governance"


def _impact_multiplier_from_tags(risk_tags: list[str] | None) -> float:
    multiplier = 1.0
    for tag in list(risk_tags or []):
        hint = RISK_TAG_IMPACT_HINT.get(_text_lower(tag))
        if hint:
            multiplier = max(multiplier, hint)
    return multiplier


def _default_event_id(prefix: str, control_id: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"{prefix}:{control_id}:{timestamp}"


def _control_effectiveness(
    *,
    simulation_pass_rate_percent: float,
    trigger_count: int,
    miss_count: int,
) -> float:
    pass_ratio = _clamp(simulation_pass_rate_percent / 100.0, 0.0, 1.0)
    denominator = max(1, trigger_count + miss_count)
    miss_ratio = _clamp(miss_count / denominator, 0.0, 1.0)
    effectiveness = 0.22 + (0.73 * pass_ratio) - (0.32 * miss_ratio)
    return _clamp(effectiveness, 0.03, 0.95)


def _dynamic_likelihood(
    *,
    trigger_count: int,
    miss_count: int,
    observed_event_count: int,
) -> float:
    observed = max(1, observed_event_count)
    trigger_ratio = _clamp(trigger_count / observed, 0.0, 1.0)
    miss_ratio = _clamp(miss_count / max(1, trigger_count + miss_count), 0.0, 1.0)
    repeated_boost = _clamp(max(0, trigger_count - 3) / 25.0, 0.0, 0.2)
    likelihood = 0.1 + (0.55 * trigger_ratio) + (0.25 * miss_ratio) + repeated_boost
    return _clamp(likelihood, 0.02, 0.99)


def _annualized_frequency(
    *,
    trigger_count: int,
    lookback_hours: int,
) -> float:
    if trigger_count <= 0:
        return 1.0
    normalized_hours = max(1, lookback_hours)
    projected = (trigger_count * 24.0 * 365.0) / float(normalized_hours)
    return _clamp(projected, 1.0, 250_000.0)


def _risk_level_multiplier(risk_level: str) -> float:
    return {
        "low": 0.8,
        "medium": 1.0,
        "med": 1.0,
        "high": 1.25,
        "critical": 1.55,
    }.get(_text_lower(risk_level), 1.0)


def compute_control_crq_profile(
    *,
    control_id: str,
    category: str,
    severity: str,
    risk_tags: list[str] | None = None,
    trigger_count: int = 0,
    miss_count: int = 0,
    observed_event_count: int = 1,
    lookback_hours: int = 24,
    simulation_pass_rate_percent: float = 0.0,
    threat_type: str | None = None,
    asset: str | None = None,
    event_id: str | None = None,
) -> dict[str, Any]:
    severity_key = _severity_key(severity)
    category_key = _category_key(category)

    base_impact = SEVERITY_IMPACT_USD.get(severity_key, SEVERITY_IMPACT_USD["medium"])
    base_impact *= CATEGORY_IMPACT_MULTIPLIER.get(category_key, 1.0)
    base_impact *= _impact_multiplier_from_tags(risk_tags)
    impact = _clamp(base_impact, 10_000.0, 15_000_000.0)

    exposure_factor = SEVERITY_EXPOSURE_FACTOR.get(severity_key, 0.45)
    likelihood = _dynamic_likelihood(
        trigger_count=max(0, trigger_count),
        miss_count=max(0, miss_count),
        observed_event_count=max(1, observed_event_count),
    )
    frequency = _annualized_frequency(
        trigger_count=max(0, trigger_count),
        lookback_hours=max(1, lookback_hours),
    )
    risk_if_exploited = impact * exposure_factor
    baseline_ale = likelihood * risk_if_exploited * frequency
    control_effectiveness = _control_effectiveness(
        simulation_pass_rate_percent=max(0.0, simulation_pass_rate_percent),
        trigger_count=max(0, trigger_count),
        miss_count=max(0, miss_count),
    )
    current_ale = max(0.0, baseline_ale * (1.0 - control_effectiveness))
    risk_reduction = max(0.0, baseline_ale - current_ale)
    confidence = _clamp(
        0.45
        + (0.25 * _clamp(simulation_pass_rate_percent / 100.0, 0.0, 1.0))
        + (0.20 * _clamp(trigger_count / 20.0, 0.0, 1.0))
        + (0.10 * (1.0 - _clamp(miss_count / max(1, trigger_count + miss_count), 0.0, 1.0))),
        0.05,
        0.99,
    )

    risk_event = RiskEvent(
        event_id=_text(event_id) or _default_event_id("control", control_id),
        control_id=control_id,
        threat_type=_text(threat_type) or _text_lower((risk_tags or [category_key])[0] if (risk_tags or []) else category_key),
        asset=_text(asset) or category_key,
        likelihood=likelihood,
        impact=risk_if_exploited,
        frequency=frequency,
        exposure_factor=exposure_factor,
        annualized_loss_expectancy=current_ale,
    )
    cost_to_fix = max(1.0, current_ale * 0.12)
    priority_score = risk_reduction / cost_to_fix

    return {
        "risk_event": risk_event.as_dict(),
        "risk_if_exploited": round(risk_if_exploited, 2),
        "likelihood": round(likelihood, 4),
        "annualized_loss_expectancy": round(current_ale, 2),
        "control_risk_profile": {
            "control_id": control_id,
            "baseline_risk": round(baseline_ale, 2),
            "current_risk": round(current_ale, 2),
            "risk_reduction": round(risk_reduction, 2),
            "confidence": round(confidence, 4),
        },
        "decision_score": {
            "risk_reduction": round(risk_reduction, 2),
            "cost_to_fix": round(cost_to_fix, 2),
            "priority_score": round(priority_score, 4),
        },
        "financials": {
            "risk_exposure_usd": round(current_ale, 2),
            "risk_reduced_usd": round(risk_reduction, 2),
            "at_risk_if_ignored_usd": round(baseline_ale, 2),
        },
    }


def compute_simulation_crq(
    *,
    simulation_run_id: str,
    control_ids: list[str],
    category: str,
    severity: str,
    final_outcome: str,
    pass_rate: float,
    iterations: int,
) -> dict[str, Any]:
    severity_key = _severity_key(severity)
    category_key = _category_key(category)
    impact = _clamp(
        SEVERITY_IMPACT_USD.get(severity_key, SEVERITY_IMPACT_USD["medium"])
        * CATEGORY_IMPACT_MULTIPLIER.get(category_key, 1.0),
        10_000.0,
        15_000_000.0,
    )
    outcome = _text_lower(final_outcome)
    pass_ratio = _clamp(pass_rate, 0.0, 1.0)

    likelihood_by_outcome = {
        "pass": 0.2,
        "fail": 0.82,
        "partial": 0.58,
        "not_executable": 0.66,
    }
    exposure_by_outcome = {
        "pass": 0.24,
        "fail": 0.92,
        "partial": 0.64,
        "not_executable": 0.78,
    }
    likelihood = _clamp(
        likelihood_by_outcome.get(outcome, 0.6) + ((1.0 - pass_ratio) * 0.1),
        0.02,
        0.99,
    )
    exposure_factor = _clamp(exposure_by_outcome.get(outcome, 0.7), 0.05, 0.99)
    frequency = _clamp(float(max(1, iterations)) * 12.0, 1.0, 100_000.0)
    risk_if_exploited = impact * exposure_factor
    ale = likelihood * risk_if_exploited * frequency
    baseline_ale = _clamp(max(likelihood, 0.45) * impact * frequency, 0.0, 50_000_000.0)

    if outcome == "pass":
        current_ale = min(ale, baseline_ale * 0.3)
        outcome_impact = "reduced_risk"
    elif outcome == "fail":
        current_ale = max(ale, baseline_ale * 1.2)
        outcome_impact = "increased_exposure"
    elif outcome == "partial":
        current_ale = max(ale, baseline_ale * 0.75)
        outcome_impact = "partially_reduced_risk"
    else:
        current_ale = baseline_ale
        outcome_impact = "execution_unavailable"

    risk_delta = baseline_ale - current_ale
    return {
        "simulation_run_id": simulation_run_id,
        "control_ids": list({str(item).strip() for item in control_ids if str(item).strip()}),
        "risk_if_exploited": round(risk_if_exploited, 2),
        "likelihood": round(likelihood, 4),
        "frequency": round(frequency, 4),
        "exposure_factor": round(exposure_factor, 4),
        "annualized_loss_expectancy": round(current_ale, 2),
        "baseline_ale": round(baseline_ale, 2),
        "current_ale": round(current_ale, 2),
        "risk_reduction": round(max(0.0, risk_delta), 2),
        "increased_exposure": round(max(0.0, -risk_delta), 2),
        "outcome_impact": outcome_impact,
    }


def compute_remediation_crq(
    *,
    remediation_type: str,
    risk_level: str,
    related_control_ids: list[str] | None,
    current_ale: float | None = None,
    baseline_ale: float | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context_payload = dict(context or {})
    normalized_type = _text_lower(remediation_type)
    effectiveness = REMEDIATION_EFFECTIVENESS.get(normalized_type, 0.35)
    cost_to_fix = REMEDIATION_COST_USD.get(normalized_type, 10_000.0)

    context_crq = dict(context_payload.get("crq") or {})
    context_current = _to_float(context_crq.get("current_ale"), 0.0) or _to_float(context_crq.get("annualized_loss_expectancy"), 0.0)
    context_baseline = _to_float(context_crq.get("baseline_ale"), 0.0) or _to_float(context_crq.get("at_risk_if_ignored_usd"), 0.0)

    resolved_current_ale = _to_float(current_ale, 0.0) or context_current
    resolved_baseline_ale = _to_float(baseline_ale, 0.0) or context_baseline
    if resolved_current_ale <= 0.0:
        fallback = SEVERITY_IMPACT_USD.get(_severity_key(risk_level), SEVERITY_IMPACT_USD["medium"])
        resolved_current_ale = fallback * _risk_level_multiplier(risk_level)
    if resolved_baseline_ale <= 0.0:
        resolved_baseline_ale = max(resolved_current_ale, resolved_current_ale * 1.35)

    estimated_risk_reduction = resolved_current_ale * effectiveness
    new_ale = max(0.0, resolved_current_ale - estimated_risk_reduction)
    priority_score = estimated_risk_reduction / max(cost_to_fix, 1.0)

    return {
        "related_control_ids": [str(item).strip() for item in (related_control_ids or []) if str(item).strip()],
        "control_improved": bool(related_control_ids),
        "baseline_ale": round(resolved_baseline_ale, 2),
        "current_ale": round(resolved_current_ale, 2),
        "new_ALE": round(new_ale, 2),
        "estimated_risk_reduction": round(estimated_risk_reduction, 2),
        "decision_score": {
            "risk_reduction": round(estimated_risk_reduction, 2),
            "cost_to_fix": round(cost_to_fix, 2),
            "priority_score": round(priority_score, 4),
        },
    }


def compute_runtime_crq_update(
    *,
    event_id: str,
    control_ids: list[str],
    severity: str | None,
    decision: str | None,
    risk_score: float | None = None,
    risk_tags: list[str] | None = None,
    lookback_hours: int = 24,
) -> dict[str, Any]:
    normalized_controls = [str(item).strip() for item in (control_ids or []) if str(item).strip()]
    if not normalized_controls:
        return {
            "event_id": event_id,
            "control_ids": [],
            "likelihood": 0.0,
            "annualized_loss_expectancy": 0.0,
            "risk_reduction": 0.0,
            "financials": {"risk_exposure_usd": 0.0, "risk_reduced_usd": 0.0, "at_risk_if_ignored_usd": 0.0},
            "control_profiles": [],
        }

    severity_key = _severity_key(severity)
    decision_token = _text_lower(decision)
    score = _clamp(_to_float(risk_score, 0.0), 0.0, 1.0)
    trigger_multiplier = max(1, _to_int(score * 8.0, 1))
    miss_multiplier = 1 if decision_token in {"allow", "defer"} and (risk_tags or []) else 0
    if decision_token in {"block", "deny", "redact", "modify", "step_up", "hold_for_approval"}:
        trigger_multiplier += 1

    rows: list[dict[str, Any]] = []
    likelihood_values: list[float] = []
    current_ale = 0.0
    baseline_ale = 0.0
    risk_reduction = 0.0
    for control_id in normalized_controls:
        profile = compute_control_crq_profile(
            control_id=control_id,
            category="governance",
            severity=severity_key,
            risk_tags=list(risk_tags or []),
            trigger_count=trigger_multiplier,
            miss_count=miss_multiplier,
            observed_event_count=max(trigger_multiplier + miss_multiplier, 1),
            lookback_hours=max(1, lookback_hours),
            simulation_pass_rate_percent=(95.0 if decision_token in {"block", "deny"} else 65.0),
            threat_type=(list(risk_tags or ["policy_violation"])[0] if list(risk_tags or []) else "policy_violation"),
            asset="runtime_event",
            event_id=f"{event_id}:{control_id}",
        )
        rows.append(profile)
        likelihood_values.append(_to_float(profile.get("likelihood"), 0.0))
        control_risk_profile = dict(profile.get("control_risk_profile") or {})
        current_ale += _to_float(control_risk_profile.get("current_risk"), 0.0)
        baseline_ale += _to_float(control_risk_profile.get("baseline_risk"), 0.0)
        risk_reduction += _to_float(control_risk_profile.get("risk_reduction"), 0.0)

    financials = aggregate_financials(rows)
    return {
        "event_id": event_id,
        "control_ids": normalized_controls,
        "likelihood": round(max(likelihood_values) if likelihood_values else 0.0, 4),
        "annualized_loss_expectancy": round(current_ale, 2),
        "baseline_ale": round(baseline_ale, 2),
        "risk_reduction": round(risk_reduction, 2),
        "financials": financials,
        "control_profiles": rows,
    }


def aggregate_financials(rows: list[dict[str, Any]]) -> dict[str, float]:
    risk_exposure = 0.0
    risk_reduced = 0.0
    at_risk_if_ignored = 0.0
    for row in rows:
        financials = dict(row.get("financials") or {})
        risk_exposure += _to_float(financials.get("risk_exposure_usd"), 0.0)
        risk_reduced += _to_float(financials.get("risk_reduced_usd"), 0.0)
        at_risk_if_ignored += _to_float(financials.get("at_risk_if_ignored_usd"), 0.0)
    return {
        "risk_exposure_usd": round(risk_exposure, 2),
        "risk_reduced_usd": round(risk_reduced, 2),
        "at_risk_if_ignored_usd": round(at_risk_if_ignored, 2),
    }
