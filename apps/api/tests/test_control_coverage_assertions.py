from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.core.control_coverage import CoverageDimension, CoverageReason, CoverageState
from app.services.control_coverage.assertion_evaluators import (
    PathEvidence,
    evaluate_all,
    evaluate_authorization,
    evaluate_bypass,
    evaluate_deployment,
    evaluate_discovery,
    evaluate_evidence,
    evaluate_identity,
    evaluate_runtime,
)


def test_monitor_only_never_covers_authorization() -> None:
    result = evaluate_authorization(PathEvidence(execution_observed=True, control_mode="telemetry_only"))
    assert result.state is CoverageState.NOT_COVERED
    assert result.reason is CoverageReason.MONITOR_ONLY_SURFACE


def test_inline_requires_verified_decision_receipt() -> None:
    result = evaluate_authorization(PathEvidence(execution_observed=True, control_mode="inline_prevented"))
    assert result.state is CoverageState.UNKNOWN
    verified = evaluate_authorization(
        PathEvidence(
            execution_observed=True,
            control_mode="inline_prevented",
            decision_receipt_verified=True,
        )
    )
    assert verified.state is CoverageState.COVERED
    assert verified.reason is CoverageReason.VERIFIED_INLINE_DECISION


@pytest.mark.parametrize("control_mode", ["telemetry_only", "detected_only", "external_required", "post_execution", "monitor_only"])
def test_observed_non_inline_modes_are_not_covered(control_mode: str) -> None:
    result = evaluate_authorization(PathEvidence(execution_observed=True, control_mode=control_mode))
    assert result.state is CoverageState.NOT_COVERED


def test_event_without_verifiable_execution_proof_is_not_covered() -> None:
    result = evaluate_evidence(PathEvidence(execution_observed=True, execution_evidence_verified=False))
    assert result.state is CoverageState.NOT_COVERED
    assert result.reason is CoverageReason.MISSING_EXECUTION_PROOF


def test_detected_bypass_covers_detection_not_authorization() -> None:
    evidence = PathEvidence(
        execution_observed=True,
        control_mode="detected_only",
        bypass_detector_operational=True,
        bypass_observed=True,
    )
    assert evaluate_bypass(evidence).state is CoverageState.COVERED
    assert evaluate_bypass(evidence).reason is CoverageReason.BYPASS_OBSERVED
    assert evaluate_authorization(evidence).state is CoverageState.NOT_COVERED


def test_observed_bypass_without_operational_detector_is_not_covered() -> None:
    result = evaluate_bypass(PathEvidence(bypass_observed=True))
    assert result.state is CoverageState.NOT_COVERED
    assert result.reason is CoverageReason.BYPASS_OBSERVED


def test_conflict_and_staleness_are_unknown_for_every_dimension() -> None:
    for result in evaluate_all(PathEvidence(conflicting=True)).values():
        assert result.state is CoverageState.UNKNOWN
        assert result.reason is CoverageReason.CONFLICTING_EVIDENCE
    for result in evaluate_all(PathEvidence(stale=True)).values():
        assert result.state is CoverageState.UNKNOWN
        assert result.reason is CoverageReason.STALE_EVIDENCE


def test_each_dimension_requires_its_own_evidence() -> None:
    evidence = PathEvidence(
        discovery_current=True,
        identity_verified=True,
        execution_observed=True,
        control_mode="inline_allowed",
        decision_receipt_verified=True,
        execution_evidence_verified=True,
        surface_mapped=True,
        surface_health="healthy",
        surface_control_capable=True,
        runtime_known=True,
        runtime_governed=True,
        bypass_detector_operational=True,
    )
    results = evaluate_all(evidence)
    assert set(results) == set(CoverageDimension)
    assert all(result.state is CoverageState.COVERED for result in results.values())


@pytest.mark.parametrize(
    ("evaluator", "evidence", "reason"),
    [
        (evaluate_discovery, PathEvidence(confirmed_unmanaged=True), CoverageReason.CONFIRMED_UNMANAGED_PATH),
        (evaluate_identity, PathEvidence(identity_confirmed_unbound=True), CoverageReason.MISSING_IDENTITY_BINDING),
        (
            evaluate_deployment,
            PathEvidence(surface_mapped=True, surface_health="offline"),
            CoverageReason.SURFACE_OFFLINE,
        ),
        (
            evaluate_deployment,
            PathEvidence(surface_mapped=True, surface_health="healthy", surface_monitor_only=True),
            CoverageReason.MONITOR_ONLY_SURFACE,
        ),
        (evaluate_runtime, PathEvidence(runtime_confirmed_unmanaged=True), CoverageReason.RUNTIME_UNMANAGED),
    ],
)
def test_confirmed_gaps_are_not_covered(evaluator, evidence: PathEvidence, reason: CoverageReason) -> None:
    result = evaluator(evidence)
    assert result.state is CoverageState.NOT_COVERED
    assert result.reason is reason


def test_unverified_conditions_remain_unknown() -> None:
    results = evaluate_all(PathEvidence())
    assert results[CoverageDimension.DEPLOYMENT].reason is CoverageReason.SURFACE_CAPABILITY_UNKNOWN
    assert all(result.state is CoverageState.UNKNOWN for result in results.values())


def test_decision_carries_only_supplied_evidence_and_times() -> None:
    now = datetime.now(timezone.utc)
    result = evaluate_discovery(
        PathEvidence(
            discovery_current=True,
            evidence_refs=("runtime_event:event-1",),
            observed_at=now,
            valid_until=now,
        )
    )
    assert result.evidence_refs == ("runtime_event:event-1",)
    assert result.observed_at == now
    assert result.valid_until == now
