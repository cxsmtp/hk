from __future__ import annotations

from app.services.runtime_intelligence.decision_impact_scoring import score_runtime_recommendation_impact


def test_high_impact_high_likelihood_scores_higher_than_low_signal_action() -> None:
    high = score_runtime_recommendation_impact(
        recommendation_type="move_to_blocked",
        severity="critical",
        repeated_count=7,
        pattern_frequency=9,
        metadata={
            "data_classification": "ip",
            "record_count": 2,
            "industry": "healthcare",
            "system_criticality": "critical",
            "regulatory_penalty_level": "high",
            "annual_revenue": 100_000_000.0,
            "cve_exploitability": 0.9,
            "simulation_failures": 4,
            "mcp_output_confidence": 0.95,
            "simulation_validation_score": 0.9,
            "active_attack": True,
        },
        cross_session={"is_long_term_pattern": True, "escalation_level": 2},
    )
    low = score_runtime_recommendation_impact(
        recommendation_type="assign_owner",
        severity="low",
        repeated_count=1,
        pattern_frequency=1,
        metadata={
            "data_classification": "public",
            "record_count": 10,
            "industry": "default",
            "system_criticality": "low",
            "business_criticality": "low",
            "regulatory_penalty_level": "none",
            "system_importance": "low",
            "cve_exploitability": 0.0,
            "simulation_failures": 0,
            "mcp_output_confidence": 0.55,
            "simulation_validation_score": 0.45,
            "active_attack": False,
        },
        cross_session={"is_long_term_pattern": False, "escalation_level": 0},
    )

    assert high.decision_impact_score > low.decision_impact_score
    assert high.base_risk > low.base_risk
    assert high.estimated_risk_reduction > low.estimated_risk_reduction


def test_low_confidence_reduces_decision_impact_score() -> None:
    common = dict(
        recommendation_type="escalate_risk_tier",
        severity="high",
        repeated_count=4,
        pattern_frequency=5,
        metadata={
            "data_classification": "pii",
            "record_count": 1_000,
            "industry": "finance",
            "system_criticality": "high",
            "regulatory_penalty_level": "medium",
            "annual_revenue": 80_000_000.0,
            "cve_exploitability": 0.6,
            "simulation_failures": 2,
            "simulation_validation_score": 0.7,
            "active_attack": True,
        },
        cross_session={"is_long_term_pattern": True, "escalation_level": 1},
    )
    high_conf = score_runtime_recommendation_impact(
        **{
            **common,
            "metadata": {
                **common["metadata"],
                "mcp_output_confidence": 0.9,
            },
        }
    )
    low_conf = score_runtime_recommendation_impact(
        **{
            **common,
            "metadata": {
                **common["metadata"],
                "mcp_output_confidence": 0.2,
            },
        }
    )

    assert high_conf.confidence > low_conf.confidence
    assert high_conf.decision_impact_score > low_conf.decision_impact_score


def test_alert_only_actions_rank_low() -> None:
    alert = score_runtime_recommendation_impact(
        recommendation_type="assign_owner",
        severity="high",
        repeated_count=5,
        pattern_frequency=6,
        metadata={
            "data_classification": "financial",
            "record_count": 2_500,
            "industry": "finance",
            "system_criticality": "high",
            "regulatory_penalty_level": "high",
            "annual_revenue": 120_000_000.0,
            "mcp_output_confidence": 0.85,
            "simulation_validation_score": 0.8,
            "active_attack": True,
        },
        cross_session={"is_long_term_pattern": True},
    )
    restrictive = score_runtime_recommendation_impact(
        recommendation_type="move_to_blocked",
        severity="high",
        repeated_count=5,
        pattern_frequency=6,
        metadata={
            "data_classification": "financial",
            "record_count": 2_500,
            "industry": "finance",
            "system_criticality": "high",
            "regulatory_penalty_level": "high",
            "annual_revenue": 120_000_000.0,
            "mcp_output_confidence": 0.85,
            "simulation_validation_score": 0.8,
            "active_attack": True,
        },
        cross_session={"is_long_term_pattern": True},
    )

    assert alert.action == "alert_only"
    assert restrictive.action == "block_external_ai"
    assert restrictive.control_effectiveness > alert.control_effectiveness
    assert restrictive.decision_impact_score > alert.decision_impact_score


def test_cve_exploitability_increases_base_risk() -> None:
    low_cve = score_runtime_recommendation_impact(
        recommendation_type="tighten_policy",
        severity="high",
        repeated_count=4,
        pattern_frequency=4,
        metadata={
            "data_classification": "sensitive",
            "record_count": 500,
            "industry": "tech",
            "system_criticality": "medium",
            "regulatory_penalty_level": "low",
            "annual_revenue": 30_000_000.0,
            "cve_exploitability": 0.0,
            "mcp_output_confidence": 0.8,
        },
        cross_session={},
    )
    high_cve = score_runtime_recommendation_impact(
        recommendation_type="tighten_policy",
        severity="high",
        repeated_count=4,
        pattern_frequency=4,
        metadata={
            "data_classification": "sensitive",
            "record_count": 500,
            "industry": "tech",
            "system_criticality": "medium",
            "regulatory_penalty_level": "low",
            "annual_revenue": 30_000_000.0,
            "cve_exploitability": 1.0,
            "mcp_output_confidence": 0.8,
        },
        cross_session={},
    )

    assert high_cve.base_risk > low_cve.base_risk
    assert high_cve.probability_score > low_cve.probability_score


def test_simulation_validation_increases_confidence() -> None:
    weak = score_runtime_recommendation_impact(
        recommendation_type="route_to_review",
        severity="med",
        repeated_count=3,
        pattern_frequency=3,
        metadata={
            "data_classification": "internal",
            "record_count": 250,
            "industry": "default",
            "system_criticality": "medium",
            "regulatory_penalty_level": "none",
            "annual_revenue": 20_000_000.0,
            "mcp_output_confidence": 0.65,
            "simulation_validation_score": 0.2,
        },
        cross_session={},
    )
    strong = score_runtime_recommendation_impact(
        recommendation_type="route_to_review",
        severity="med",
        repeated_count=3,
        pattern_frequency=3,
        metadata={
            "data_classification": "internal",
            "record_count": 250,
            "industry": "default",
            "system_criticality": "medium",
            "regulatory_penalty_level": "none",
            "annual_revenue": 20_000_000.0,
            "mcp_output_confidence": 0.65,
            "simulation_validation_score": 0.9,
        },
        cross_session={},
    )

    assert strong.confidence > weak.confidence
    assert strong.decision_impact_score > weak.decision_impact_score
    assert isinstance(strong.as_dict()["reasoning"], list)


def test_pii_breach_produces_higher_impact_than_generic_data() -> None:
    pii = score_runtime_recommendation_impact(
        recommendation_type="tighten_policy",
        severity="med",
        repeated_count=2,
        pattern_frequency=2,
        metadata={
            "data_classification": "pii",
            "record_count": 4_000,
            "industry": "default",
            "system_criticality": "medium",
            "regulatory_penalty_level": "low",
            "annual_revenue": 15_000_000.0,
            "mcp_output_confidence": 0.7,
        },
        cross_session={},
    )
    generic = score_runtime_recommendation_impact(
        recommendation_type="tighten_policy",
        severity="med",
        repeated_count=2,
        pattern_frequency=2,
        metadata={
            "data_classification": "public",
            "record_count": 4_000,
            "industry": "default",
            "system_criticality": "medium",
            "regulatory_penalty_level": "low",
            "annual_revenue": 15_000_000.0,
            "mcp_output_confidence": 0.7,
        },
        cross_session={},
    )
    assert pii.impact_value > generic.impact_value
    pii_breakdown = pii.as_dict()["breakdown"]
    assert float(pii_breakdown["data_component"]) > float(generic.as_dict()["breakdown"]["data_component"])


def test_high_value_systems_produce_higher_scores() -> None:
    low_value = score_runtime_recommendation_impact(
        recommendation_type="escalate_risk_tier",
        severity="high",
        repeated_count=3,
        pattern_frequency=3,
        metadata={
            "data_classification": "financial",
            "record_count": 1_000,
            "industry": "tech",
            "system_criticality": "low",
            "regulatory_penalty_level": "low",
            "annual_revenue": 10_000_000.0,
            "mcp_output_confidence": 0.8,
            "active_attack": True,
        },
        cross_session={},
    )
    high_value = score_runtime_recommendation_impact(
        recommendation_type="escalate_risk_tier",
        severity="high",
        repeated_count=3,
        pattern_frequency=3,
        metadata={
            "data_classification": "financial",
            "record_count": 1_000,
            "industry": "healthcare",
            "system_criticality": "critical",
            "regulatory_penalty_level": "critical",
            "annual_revenue": 350_000_000.0,
            "mcp_output_confidence": 0.8,
            "active_attack": True,
        },
        cross_session={},
    )
    assert high_value.impact_value > low_value.impact_value
    assert high_value.decision_impact_score > low_value.decision_impact_score


def test_output_contains_required_crq_breakdown_fields() -> None:
    result = score_runtime_recommendation_impact(
        recommendation_type="move_to_blocked",
        severity="high",
        repeated_count=3,
        pattern_frequency=4,
        metadata={
            "data_classification": "credentials",
            "record_count": 2,
            "industry": "finance",
            "system_criticality": "high",
            "regulatory_penalty_level": "medium",
            "annual_revenue": 55_000_000.0,
            "mcp_output_confidence": 0.82,
            "simulation_validation_score": 0.72,
        },
        cross_session={},
    ).as_dict()
    assert "decision_impact_score" in result
    assert "estimated_risk_reduction" in result
    assert "base_risk" in result
    breakdown = result["breakdown"]
    assert "probability" in breakdown
    assert "impact_value" in breakdown
    assert "regulatory_component" in breakdown
    assert "data_component" in breakdown
