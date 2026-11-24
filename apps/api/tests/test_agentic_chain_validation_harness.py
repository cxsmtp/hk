from __future__ import annotations

from app.services.agentic_chain_validation_harness import (
    DEFENSE_MODES,
    SCENARIOS,
    calculate_metrics,
    run_scenario,
    run_scenario_library,
)


def test_agentic_chain_scenario_library_has_required_safe_coverage():
    assert len(SCENARIOS) >= 12
    assert DEFENSE_MODES == [
        "no_defense",
        "prompt_guardrail_only",
        "approval_only",
        "jit_identity_only",
        "hawk_chain_integrity",
    ]

    scenario_ids = {scenario.scenario_id for scenario in SCENARIOS}
    assert {
        "ACI-002",
        "ACI-003",
        "ACI-006",
        "ACI-007",
        "ACI-008",
        "ACI-010",
        "ACI-014",
    } <= scenario_ids

    serialized = "\n".join(str(scenario.__dict__) for scenario in SCENARIOS).lower()
    assert "simulated_" in serialized
    assert "sk-live" not in serialized
    assert "password=" not in serialized
    assert "private key" not in serialized


def test_each_scenario_runs_across_all_defense_modes_with_chain_report():
    reports = run_scenario_library()

    assert len(reports) == len(SCENARIOS) * len(DEFENSE_MODES)
    assert {report.defense_mode for report in reports} == set(DEFENSE_MODES)
    assert all(report.chain_id.startswith("aci-chain-") for report in reports)
    assert all(report.evidence_bundle_link for report in reports)
    assert all(report.graph_timeline_link for report in reports)
    assert all(report.audit_completeness_score >= 0 for report in reports)
    assert all(report.policy_latency_ms >= 0 for report in reports)


def test_hawk_chain_integrity_blocks_or_escalates_risky_chain_and_records_expected_findings():
    report = run_scenario("ACI-003", "hawk_chain_integrity")

    assert report.scenario_id == "ACI-003"
    assert report.result in {"blocked", "escalated"}
    assert report.pass_fail == "pass"
    assert report.control_mode in {"inline_prevented", "external_required"}
    assert "APPROVAL_EXECUTION_DRIFT" in report.findings
    assert report.policy_decision in {"block", "require_approval", "require_second_approval"}
    assert report.chain_risk_score >= 0.7


def test_weaker_defenses_miss_chain_level_approval_drift_that_hawk_catches():
    weak = run_scenario("ACI-003", "approval_only")
    hawk = run_scenario("ACI-003", "hawk_chain_integrity")

    assert weak.result == "missed"
    assert weak.pass_fail == "fail"
    assert hawk.pass_fail == "pass"
    assert hawk.audit_completeness_score > weak.audit_completeness_score


def test_metrics_compare_hawk_against_weaker_modes():
    reports = run_scenario_library()
    metrics = calculate_metrics(reports)

    assert metrics["total_scenarios"] >= 12
    assert metrics["total_runs"] == len(SCENARIOS) * len(DEFENSE_MODES)
    assert metrics["approval_drift_detection_rate"] > 0
    assert metrics["delegation_risk_detection_rate"] > 0
    assert metrics["jit_scope_mismatch_detection_rate"] > 0
    assert metrics["deferred_side_effect_detection_rate"] > 0
    assert metrics["taint_preservation_accuracy"] > 0
    assert metrics["chain_control_uplift"] > 0
    assert 0 <= metrics["false_positive_rate"] <= 1
    assert 0 <= metrics["false_negative_rate"] <= 1
