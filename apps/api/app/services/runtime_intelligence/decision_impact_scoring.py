from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any


# CRQ data models (bounded deterministic defaults; all USD).
DATA_SENSITIVITY_VALUE_RANGES: dict[str, tuple[float, float]] = {
    "pii": (100.0, 200.0),
    "financial": (200.0, 500.0),
    "credentials": (50_000.0, 500_000.0),
    "ip": (500_000.0, 5_000_000.0),
    "generic": (25.0, 75.0),
}

INDUSTRY_BASELINES: dict[str, float] = {
    "healthcare": 7_400_000.0,
    "finance": 5_500_000.0,
    "tech": 4_700_000.0,
    "default": 4_400_000.0,
}

REGULATORY_BASE_BY_LEVEL: dict[str, float] = {
    "none": 0.0,
    "low": 50_000.0,
    "medium": 500_000.0,
    "med": 500_000.0,
    "high": 2_000_000.0,
}

# Critical regulatory risk is % revenue and capped by industry baseline multiple.
DEFAULT_CRITICAL_REGULATORY_PERCENT = 0.04
CRITICAL_REGULATORY_INDUSTRY_CAP_MULTIPLIER = 2.0

SYSTEM_CRITICALITY_MULTIPLIER = {
    "low": 0.6,
    "medium": 1.0,
    "med": 1.0,
    "high": 1.4,
    "critical": 1.8,
}

DEFAULT_RECORD_COUNT = 100
MAX_RECORD_COUNT = 5_000_000

# Midpoint effectiveness within requested bounded ranges.
CONTROL_EFFECTIVENESS_BY_ACTION = {
    "block_external_ai": 0.90,      # 0.85 - 0.95
    "restrict_permissions": 0.70,   # 0.60 - 0.80
    "revoke_keys": 0.80,            # 0.70 - 0.90
    "run_simulation": 0.30,         # 0.20 - 0.40
    "alert_only": 0.08,             # 0.05 - 0.10
}

RECOMMENDATION_ACTION_MAP = {
    "move_to_blocked": "block_external_ai",
    "escalate_risk_tier": "restrict_permissions",
    "tighten_policy": "restrict_permissions",
    "tighten_tool_permissions": "restrict_permissions",
    "route_to_review": "run_simulation",
    "assign_owner": "alert_only",
}

def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_label(value: Any, *, default: str = "unknown") -> str:
    text = str(value or "").strip().lower()
    return text or default


def _parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        if raw.endswith("z"):
            raw = f"{raw[:-1]}+00:00"
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class DecisionImpactResult:
    action: str
    decision_impact_score: float
    estimated_risk_reduction: float
    base_risk: float
    confidence: float
    urgency_multiplier: float
    control_effectiveness: float
    probability_score: float
    impact_value: float
    data_component: float
    regulatory_component: float
    industry_component: float
    data_category: str
    industry: str
    reasoning: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "decision_impact_score": round(self.decision_impact_score, 2),
            "estimated_risk_reduction": round(self.estimated_risk_reduction, 2),
            "base_risk": round(self.base_risk, 2),
            "confidence": round(self.confidence, 4),
            "urgency_multiplier": round(self.urgency_multiplier, 2),
            "control_effectiveness": round(self.control_effectiveness, 4),
            "probability_score": round(self.probability_score, 4),
            "impact_value": round(self.impact_value, 2),
            "breakdown": {
                "probability": round(self.probability_score, 4),
                "impact_value": round(self.impact_value, 2),
                "regulatory_component": round(self.regulatory_component, 2),
                "data_component": round(self.data_component, 2),
                "industry_component": round(self.industry_component, 2),
                "data_category": self.data_category,
                "industry": self.industry,
            },
            "reasoning": list(self.reasoning),
        }


def _canonical_data_category(value: str) -> str:
    normalized = _normalize_label(value, default="generic")
    if normalized in {"pii", "personal_data", "personal"}:
        return "pii"
    if normalized in {"financial", "payment", "banking"}:
        return "financial"
    if normalized in {"credentials", "credential", "secret", "key", "api_key"}:
        return "credentials"
    if normalized in {"ip", "intellectual_property", "source_code", "proprietary"}:
        return "ip"
    if normalized in {"public", "unknown", "internal", "sensitive", "confidential", "restricted", "regulated"}:
        return "generic" if normalized in {"public", "unknown", "internal"} else "pii"
    return "generic"


def _industry_key(value: Any) -> str:
    normalized = _normalize_label(value, default="default")
    if normalized in {"healthcare", "health", "pharma", "medical"}:
        return "healthcare"
    if normalized in {"finance", "financial_services", "banking", "bfsi"}:
        return "finance"
    if normalized in {"tech", "technology", "software", "saas"}:
        return "tech"
    return "default"


def _category_value_per_record(category: str, explicit_value: Any | None = None) -> float:
    low, high = DATA_SENSITIVITY_VALUE_RANGES.get(category, DATA_SENSITIVITY_VALUE_RANGES["generic"])
    if explicit_value is None:
        return (low + high) / 2.0
    parsed = _safe_float(explicit_value, (low + high) / 2.0)
    return _clamp(parsed, low, high)


def _regulatory_component(
    *,
    regulatory_penalty_level: str,
    annual_revenue: float,
    regulatory_percentage: float,
    industry_baseline: float,
) -> tuple[float, list[str]]:
    reasons: list[str] = []
    level = _normalize_label(regulatory_penalty_level, default="none")
    if level == "critical":
        revenue_component = max(0.0, annual_revenue) * _clamp(regulatory_percentage, 0.0, 1.0)
        capped = min(revenue_component, industry_baseline * CRITICAL_REGULATORY_INDUSTRY_CAP_MULTIPLIER)
        reasons.append(f"regulatory_level=critical")
        reasons.append(f"regulatory_revenue_component_usd={revenue_component:.2f}")
        reasons.append(f"regulatory_cap_usd={(industry_baseline * CRITICAL_REGULATORY_INDUSTRY_CAP_MULTIPLIER):.2f}")
        return capped, reasons
    value = REGULATORY_BASE_BY_LEVEL.get(level, REGULATORY_BASE_BY_LEVEL["none"])
    reasons.append(f"regulatory_level={level}")
    return value, reasons


def _impact_value(
    *,
    records: int,
    data_category: str,
    data_sensitivity_value: float | None,
    regulatory_penalty_level: str,
    annual_revenue: float,
    regulatory_percentage: float,
    industry: str,
    system_criticality: str,
) -> tuple[float, float, float, float, list[str]]:
    reasons: list[str] = []
    records_count = max(1, min(MAX_RECORD_COUNT, int(records or DEFAULT_RECORD_COUNT)))
    category_value = _category_value_per_record(data_category, data_sensitivity_value)
    data_component = records_count * category_value

    industry_baseline = INDUSTRY_BASELINES.get(industry, INDUSTRY_BASELINES["default"])
    criticality_multiplier = SYSTEM_CRITICALITY_MULTIPLIER.get(_normalize_label(system_criticality, default="medium"), 1.0)
    industry_component = industry_baseline * criticality_multiplier

    regulatory_component, regulatory_reasons = _regulatory_component(
        regulatory_penalty_level=regulatory_penalty_level,
        annual_revenue=annual_revenue,
        regulatory_percentage=regulatory_percentage,
        industry_baseline=industry_baseline,
    )
    reasons.extend(regulatory_reasons)

    # Formula from requirement:
    # impact_value = (records × data_sensitivity_value) + regulatory_risk + (industry_baseline × system_criticality_multiplier)
    uncapped = data_component + regulatory_component + industry_component
    industry_cap = industry_baseline * 3.0
    impact = _clamp(uncapped, 0.0, industry_cap)

    reasons.extend(
        [
            f"records={records_count}",
            f"data_category={data_category}",
            f"data_sensitivity_value_per_record={category_value:.2f}",
            f"data_component_usd={data_component:.2f}",
            f"industry={industry}",
            f"industry_baseline_usd={industry_baseline:.2f}",
            f"system_criticality_multiplier={criticality_multiplier:.2f}",
            f"industry_component_usd={industry_component:.2f}",
            f"regulatory_component_usd={regulatory_component:.2f}",
            f"impact_uncapped_usd={uncapped:.2f}",
            f"industry_cap_usd={industry_cap:.2f}",
        ]
    )
    return impact, data_component, regulatory_component, industry_component, reasons


def _probability_score(
    *,
    repeated_count: int,
    pattern_frequency: int,
    cve_exploitability: float,
    simulation_failures: int,
    exposure_level: float,
) -> tuple[float, list[str]]:
    reasons: list[str] = []
    runtime_repetition = _clamp(max(repeated_count, pattern_frequency, 1) / 10.0, 0.0, 1.0)
    simulation_component = _clamp(simulation_failures / 5.0, 0.0, 1.0)
    cve_component = _clamp(cve_exploitability, 0.0, 1.0)
    exposure_component = _clamp(exposure_level, 0.0, 1.0)

    reasons.extend(
        [
            f"runtime_repetition={runtime_repetition:.2f}",
            f"simulation_failure_component={simulation_component:.2f}",
            f"cve_exploitability_component={cve_component:.2f}",
            f"exposure_level_component={exposure_component:.2f}",
        ]
    )

    # Deterministic weighted model as requested.
    probability = (
        0.35 * runtime_repetition
        + 0.20 * simulation_component
        + 0.25 * cve_component
        + 0.20 * exposure_component
    )
    return _clamp(probability, 0.0, 1.0), reasons


def _confidence_score(
    *,
    mcp_output_confidence: float,
    signal_correlation: float,
    simulation_validation: float,
) -> tuple[float, list[str]]:
    reasons = [
        f"mcp_output_confidence={mcp_output_confidence:.2f}",
        f"signal_correlation={signal_correlation:.2f}",
        f"simulation_validation={simulation_validation:.2f}",
    ]
    confidence = (
        0.40 * _clamp(mcp_output_confidence, 0.0, 1.0)
        + 0.40 * _clamp(signal_correlation, 0.0, 1.0)
        + 0.20 * _clamp(simulation_validation, 0.0, 1.0)
    )
    return _clamp(confidence, 0.0, 1.0), reasons


def _urgency_multiplier(
    *,
    active_attack: bool,
    active_session: bool,
    recent: bool,
) -> tuple[float, str]:
    if active_attack:
        return 1.5, "active_attack"
    if active_session:
        return 1.3, "active_session"
    if recent:
        return 1.1, "recent_activity"
    return 1.0, "baseline"


def _map_recommendation_action(recommendation_type: str, fallback_action: str | None = None) -> str:
    mapped = RECOMMENDATION_ACTION_MAP.get(_normalize_label(recommendation_type, default=""), "")
    if mapped:
        return mapped
    if fallback_action:
        return _normalize_label(fallback_action, default="alert_only")
    return "alert_only"


def score_runtime_recommendation_impact(
    *,
    recommendation_type: str,
    severity: str,
    repeated_count: int,
    pattern_frequency: int,
    metadata: dict[str, Any] | None,
    cross_session: dict[str, Any] | None,
) -> DecisionImpactResult:
    metadata = dict(metadata or {})
    cross_session = dict(cross_session or {})
    reasons: list[str] = []

    action = _map_recommendation_action(recommendation_type)
    control_effectiveness = CONTROL_EFFECTIVENESS_BY_ACTION.get(action, CONTROL_EFFECTIVENESS_BY_ACTION["alert_only"])
    reasons.append(f"action={action}")
    reasons.append(f"control_effectiveness={control_effectiveness:.2f}")

    data_classification = _normalize_label(
        metadata.get("data_classification")
        or metadata.get("classification")
        or metadata.get("source_classification_hint"),
        default="unknown",
    )
    data_category = _canonical_data_category(data_classification)
    industry = _industry_key(metadata.get("industry"))
    exposure_level = _safe_float(metadata.get("exposure_level"), 0.45)
    if data_category in {"credentials", "ip"}:
        exposure_level = max(exposure_level, 0.85)
    elif data_category in {"pii", "financial"}:
        exposure_level = max(exposure_level, 0.7)
    reasons.append(f"mapped_data_category={data_category}")
    reasons.append(f"mapped_industry={industry}")

    probability, probability_reasons = _probability_score(
        repeated_count=max(1, repeated_count),
        pattern_frequency=max(1, pattern_frequency),
        cve_exploitability=_safe_float(metadata.get("cve_exploitability"), 0.0),
        simulation_failures=_safe_int(metadata.get("simulation_failures"), 0),
        exposure_level=exposure_level,
    )
    reasons.extend(probability_reasons)

    impact_value, data_component, regulatory_component, industry_component, impact_reasons = _impact_value(
        records=_safe_int(metadata.get("record_count") or metadata.get("records"), DEFAULT_RECORD_COUNT),
        data_category=data_category,
        data_sensitivity_value=metadata.get("data_sensitivity_value"),
        regulatory_penalty_level=_normalize_label(metadata.get("regulatory_penalty_level"), default="none"),
        annual_revenue=_safe_float(metadata.get("annual_revenue"), 0.0),
        regulatory_percentage=_safe_float(metadata.get("regulatory_percentage"), DEFAULT_CRITICAL_REGULATORY_PERCENT),
        industry=industry,
        system_criticality=_normalize_label(
            metadata.get("system_criticality") or metadata.get("system_importance") or metadata.get("business_criticality"),
            default="medium",
        ),
    )
    reasons.extend(impact_reasons)

    base_risk = probability * impact_value
    reasons.append(f"base_risk_usd={base_risk:.2f}")

    risk_reduction = base_risk * control_effectiveness
    reasons.append(f"risk_reduction_usd={risk_reduction:.2f}")

    evidence_count = len([str(item).strip() for item in (metadata.get("evidence_node_ids") or []) if str(item).strip()])
    correlation_score = _clamp(
        0.45
        + 0.25 * _clamp(max(1, repeated_count) / 5.0, 0.0, 1.0)
        + 0.20 * _clamp(max(1, pattern_frequency) / 8.0, 0.0, 1.0)
        + 0.10 * _clamp(evidence_count / 3.0, 0.0, 1.0),
        0.0,
        1.0,
    )

    mcp_output_confidence = _safe_float(
        metadata.get("mcp_output_confidence"),
        _safe_float(metadata.get("confidence_score"), 0.65),
    )
    simulation_validation = _safe_float(
        metadata.get("simulation_validation_score"),
        0.5 + _clamp(_safe_int(metadata.get("simulation_failures"), 0) / 10.0, 0.0, 0.3),
    )
    confidence, confidence_reasons = _confidence_score(
        mcp_output_confidence=mcp_output_confidence,
        signal_correlation=correlation_score,
        simulation_validation=simulation_validation,
    )
    reasons.extend(confidence_reasons)

    now = datetime.now(timezone.utc)
    event_time = _parse_timestamp(metadata.get("event_created_at") or metadata.get("created_at"))
    if event_time is None:
        recent = bool(cross_session.get("is_long_term_pattern")) is False
    else:
        recent = event_time >= now - timedelta(hours=24)

    active_attack = bool(metadata.get("active_attack")) or _normalize_label(severity, default="low") in {"high", "critical"}
    active_session = bool(metadata.get("active_session")) or bool(metadata.get("chain_id"))
    urgency_multiplier, urgency_reason = _urgency_multiplier(
        active_attack=active_attack,
        active_session=active_session,
        recent=recent,
    )
    reasons.append(f"urgency={urgency_reason}")
    reasons.append(f"urgency_multiplier={urgency_multiplier:.2f}")

    decision_impact_score = risk_reduction * confidence * urgency_multiplier
    reasons.append(f"decision_impact_score={decision_impact_score:.2f}")

    return DecisionImpactResult(
        action=action,
        decision_impact_score=decision_impact_score,
        estimated_risk_reduction=risk_reduction,
        base_risk=base_risk,
        confidence=confidence,
        urgency_multiplier=urgency_multiplier,
        control_effectiveness=control_effectiveness,
        probability_score=probability,
        impact_value=impact_value,
        data_component=data_component,
        regulatory_component=regulatory_component,
        industry_component=industry_component,
        data_category=data_category,
        industry=industry,
        reasoning=reasons,
    )
