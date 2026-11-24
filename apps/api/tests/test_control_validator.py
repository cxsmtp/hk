from __future__ import annotations

from app.services.control_validator import evaluate_final_outcome, evaluate_iteration_outcome


def test_iteration_outcome_not_executable_when_all_steps_unavailable() -> None:
    out = evaluate_iteration_outcome(
        assertions=[],
        failed_assertions=[],
        has_unavailable_steps=True,
        all_steps_unavailable=True,
    )
    assert out["result"] == "not_executable"
    assert out["confidence"] == 0.35


def test_iteration_outcome_fail_from_observed_assertion_failure() -> None:
    out = evaluate_iteration_outcome(
        assertions=[
            {
                "assertion_id": "a1",
                "on_fail": {"severity": "critical"},
            }
        ],
        failed_assertions=["a1"],
        has_unavailable_steps=False,
        all_steps_unavailable=False,
    )
    assert out["result"] == "fail"
    assert out["severity"] == "critical"
    assert out["confidence"] == 1.0


def test_final_outcome_partial_for_mixed_executed_and_unavailable() -> None:
    outcome = evaluate_final_outcome(
        outcome_counts={"pass": 1, "fail": 0, "partial": 0, "not_executable": 1},
        evidence_requirement_failures=[],
        run_count=2,
    )
    assert outcome == "partial"


def test_final_outcome_fail_when_evidence_requirements_missing() -> None:
    outcome = evaluate_final_outcome(
        outcome_counts={"pass": 1, "fail": 0, "partial": 0, "not_executable": 0},
        evidence_requirement_failures=["missing_required_signal_types(test)"],
        run_count=1,
    )
    assert outcome == "fail"

