from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.services.hmair.adv.contracts import (
    DiscoveryStage,
    VerificationOutcome,
    VerificationTaskResult,
)
from app.services.hmair.adv.state_machine import (
    ADVStateConflict,
    ADVStateMachine,
)


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)


def test_adv_contracts_expose_only_the_approved_stages_and_outcomes() -> None:
    assert tuple(item.value for item in DiscoveryStage) == (
        "observed",
        "candidate",
        "hypothesis",
        "verification",
        "verified",
        "continuously_validated",
    )
    assert tuple(item.value for item in VerificationOutcome) == (
        "verified",
        "failed",
        "contradicted",
        "unsupported",
        "unknown",
    )


def test_required_unsupported_never_promotes_verified() -> None:
    projection = ADVStateMachine().project(
        has_observation=True,
        has_candidate=True,
        has_hypothesis=True,
        has_open_episode=True,
        assertion_current=False,
        required_outcomes=(
            VerificationOutcome.VERIFIED,
            VerificationOutcome.UNSUPPORTED,
        ),
        blocking_drift=False,
        next_validation_at=None,
    )
    assert projection.stage is DiscoveryStage.VERIFICATION
    assert "required_source_unsupported" in projection.limitations


@pytest.mark.parametrize(
    ("outcome", "limitation"),
    (
        (VerificationOutcome.FAILED, "required_verification_failed"),
        (VerificationOutcome.CONTRADICTED, "required_verification_contradicted"),
        (VerificationOutcome.UNKNOWN, "required_verification_unknown"),
    ),
)
def test_every_non_verified_required_outcome_blocks_promotion(
    outcome: VerificationOutcome,
    limitation: str,
) -> None:
    projection = ADVStateMachine().project(
        has_observation=True,
        has_candidate=True,
        has_hypothesis=True,
        has_open_episode=True,
        assertion_current=False,
        required_outcomes=(VerificationOutcome.VERIFIED, outcome),
        blocking_drift=False,
        next_validation_at=None,
    )
    assert projection.stage is DiscoveryStage.VERIFICATION
    assert limitation in projection.limitations


def test_all_required_verified_promotes_only_to_verified_without_current_schedule() -> None:
    projection = ADVStateMachine().project(
        has_observation=True,
        has_candidate=True,
        has_hypothesis=True,
        has_open_episode=True,
        assertion_current=True,
        required_outcomes=(VerificationOutcome.VERIFIED,),
        blocking_drift=False,
        next_validation_at=None,
    )
    assert projection.stage is DiscoveryStage.VERIFIED
    assert projection.limitations == ("continuous_validation_not_scheduled",)


def test_current_assertion_and_future_schedule_are_continuously_validated() -> None:
    projection = ADVStateMachine().project(
        has_observation=True,
        has_candidate=True,
        has_hypothesis=True,
        has_open_episode=True,
        assertion_current=True,
        required_outcomes=(VerificationOutcome.VERIFIED,),
        blocking_drift=False,
        next_validation_at=NOW + timedelta(hours=1),
        evaluated_at=NOW,
    )
    assert projection.stage is DiscoveryStage.CONTINUOUSLY_VALIDATED
    assert projection.limitations == ()


@pytest.mark.parametrize(
    ("facts", "expected"),
    (
        ({}, None),
        ({"has_observation": True}, DiscoveryStage.OBSERVED),
        (
            {"has_observation": True, "has_candidate": True},
            DiscoveryStage.CANDIDATE,
        ),
        (
            {
                "has_observation": True,
                "has_candidate": True,
                "has_hypothesis": True,
            },
            DiscoveryStage.HYPOTHESIS,
        ),
    ),
)
def test_projection_stops_at_the_earliest_unproven_stage(
    facts: dict[str, bool],
    expected: DiscoveryStage | None,
) -> None:
    projection = ADVStateMachine().project(
        has_observation=facts.get("has_observation", False),
        has_candidate=facts.get("has_candidate", False),
        has_hypothesis=facts.get("has_hypothesis", False),
        has_open_episode=False,
        assertion_current=False,
        required_outcomes=(),
        blocking_drift=False,
        next_validation_at=None,
    )
    assert projection.stage is expected


@pytest.mark.parametrize(
    ("source", "target"),
    (
        (DiscoveryStage.OBSERVED, DiscoveryStage.HYPOTHESIS),
        (DiscoveryStage.CANDIDATE, DiscoveryStage.VERIFICATION),
        (DiscoveryStage.HYPOTHESIS, DiscoveryStage.VERIFIED),
        (DiscoveryStage.VERIFICATION, DiscoveryStage.CONTINUOUSLY_VALIDATED),
    ),
)
def test_forward_stage_skips_are_rejected(
    source: DiscoveryStage,
    target: DiscoveryStage,
) -> None:
    with pytest.raises(ADVStateConflict, match="cannot skip"):
        ADVStateMachine.validate_transition(source, target)


def test_task_result_requires_timezone_aware_ordered_times() -> None:
    result = VerificationTaskResult(
        requirement_id="endpoint_identity",
        task_id="00000000-0000-0000-0000-000000000001",
        outcome=VerificationOutcome.VERIFIED,
        evidence_node_ids=("evidence-1",),
        observed_at=NOW,
        validated_at=NOW + timedelta(seconds=1),
    )
    assert result.observed_at.tzinfo == timezone.utc
    with pytest.raises(ValidationError, match="invalid HMAIR contract"):
        VerificationTaskResult(
            requirement_id="endpoint_identity",
            task_id="00000000-0000-0000-0000-000000000001",
            outcome=VerificationOutcome.UNKNOWN,
            evidence_node_ids=(),
            observed_at=datetime(2026, 8, 20, 12, 0),
            validated_at=NOW,
        )
    with pytest.raises(ValidationError, match="invalid HMAIR contract"):
        VerificationTaskResult(
            requirement_id="endpoint_identity",
            task_id="00000000-0000-0000-0000-000000000001",
            outcome=VerificationOutcome.UNKNOWN,
            evidence_node_ids=(),
            observed_at=NOW,
            validated_at=NOW - timedelta(seconds=1),
        )
