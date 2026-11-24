from __future__ import annotations

from typing import Any


def evaluate_iteration_outcome(
    *,
    assertions: list[dict[str, Any]],
    failed_assertions: list[str],
    has_unavailable_steps: bool,
    all_steps_unavailable: bool,
) -> dict[str, Any]:
    if all_steps_unavailable:
        result = "not_executable"
    elif failed_assertions:
        result = "fail"
    elif has_unavailable_steps:
        result = "partial"
    else:
        result = "pass"

    severity = _severity_from_failures(assertions=assertions, failed_assertions=failed_assertions)
    if result == "not_executable" and severity == "low":
        severity = "med"
    reasoning = {
        "pass": "All executable steps completed and assertions matched observed outputs.",
        "fail": "One or more assertions failed against observed execution outputs.",
        "partial": "Some steps executed, but unsupported steps reduced validation completeness.",
        "not_executable": "Simulation steps are not executable on currently wired execution surfaces.",
    }.get(result, "Simulation evaluation completed.")
    confidence = {"pass": 1.0, "fail": 1.0, "partial": 0.75, "not_executable": 0.35}.get(result, 0.5)
    return {
        "result": result,
        "severity": severity,
        "evaluator_reasoning": reasoning,
        "confidence": confidence,
    }


def evaluate_final_outcome(
    *,
    outcome_counts: dict[str, int],
    evidence_requirement_failures: list[str],
    run_count: int,
) -> str:
    if int(outcome_counts.get("not_executable") or 0) == int(run_count):
        return "not_executable"
    if not evidence_requirement_failures and int(outcome_counts.get("pass") or 0) == int(run_count):
        return "pass"
    if (
        int(outcome_counts.get("fail") or 0) > 0
        and int(outcome_counts.get("pass") or 0) == 0
        and int(outcome_counts.get("partial") or 0) == 0
    ):
        return "fail"
    if (
        int(outcome_counts.get("partial") or 0) > 0
        or int(outcome_counts.get("not_executable") or 0) > 0
        or (int(outcome_counts.get("fail") or 0) > 0 and int(outcome_counts.get("pass") or 0) > 0)
    ):
        return "partial"
    if evidence_requirement_failures:
        return "fail"
    return "fail"


def _severity_from_failures(*, assertions: list[dict[str, Any]], failed_assertions: list[str]) -> str:
    if not failed_assertions:
        return "low"
    severity_rank = {"low": 0, "med": 1, "medium": 1, "high": 2, "critical": 3}
    rank = 0
    failed = {str(item) for item in failed_assertions}
    for assertion in assertions:
        assertion_id = str(assertion.get("assertion_id") or "").strip()
        if assertion_id not in failed:
            continue
        raw = str((assertion.get("on_fail") or {}).get("severity") or "med").strip().lower()
        rank = max(rank, severity_rank.get(raw, 1))
    reverse = {0: "low", 1: "med", 2: "high", 3: "critical"}
    return reverse.get(rank, "med")

