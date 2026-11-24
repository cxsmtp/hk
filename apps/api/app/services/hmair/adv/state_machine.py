from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from app.services.hmair.adv.contracts import (
    ADVStateProjection,
    DiscoveryStage,
    VerificationOutcome,
)


class ADVStateConflict(RuntimeError):
    """The requested discovery lifecycle transition is not evidence-backed."""


_ORDER = tuple(DiscoveryStage)

_OUTCOME_LIMITATIONS = {
    VerificationOutcome.FAILED: "required_verification_failed",
    VerificationOutcome.CONTRADICTED: "required_verification_contradicted",
    VerificationOutcome.UNSUPPORTED: "required_source_unsupported",
    VerificationOutcome.UNKNOWN: "required_verification_unknown",
}


class ADVStateMachine:
    """Project the earliest discovery stage supported by retained facts."""

    @staticmethod
    def validate_transition(source: DiscoveryStage, target: DiscoveryStage) -> None:
        source_index = _ORDER.index(source)
        target_index = _ORDER.index(target)
        if target_index == source_index or target_index == source_index + 1:
            return
        if (
            target_index < source_index
            and target in {DiscoveryStage.HYPOTHESIS, DiscoveryStage.VERIFICATION}
        ):
            return
        if target_index > source_index + 1:
            raise ADVStateConflict(
                f"discovery lifecycle cannot skip from {source.value} to {target.value}"
            )
        raise ADVStateConflict(
            f"unsupported discovery lifecycle transition from {source.value} "
            f"to {target.value}"
        )

    def project(
        self,
        *,
        has_observation: bool,
        has_candidate: bool,
        has_hypothesis: bool,
        has_open_episode: bool,
        assertion_current: bool,
        required_outcomes: Iterable[VerificationOutcome],
        blocking_drift: bool,
        next_validation_at: datetime | None,
        evaluated_at: datetime | None = None,
    ) -> ADVStateProjection:
        at = evaluated_at or datetime.now(timezone.utc)
        if at.tzinfo is None or at.utcoffset() is None:
            raise ADVStateConflict("lifecycle evaluation time must be timezone-aware")
        at = at.astimezone(timezone.utc)

        if not has_observation:
            return ADVStateProjection(stage=None, limitations=("no_observation",), evaluated_at=at)
        if not has_candidate:
            return ADVStateProjection(
                stage=DiscoveryStage.OBSERVED,
                limitations=("candidate_not_established",),
                evaluated_at=at,
            )
        if not has_hypothesis:
            return ADVStateProjection(
                stage=DiscoveryStage.CANDIDATE,
                limitations=("hypothesis_not_established",),
                evaluated_at=at,
            )
        if not has_open_episode:
            return ADVStateProjection(
                stage=DiscoveryStage.HYPOTHESIS,
                limitations=("verification_not_started",),
                evaluated_at=at,
            )

        outcomes = tuple(required_outcomes)
        limitations = tuple(
            sorted(
                {
                    _OUTCOME_LIMITATIONS[item]
                    for item in outcomes
                    if item is not VerificationOutcome.VERIFIED
                }
            )
        )
        if not outcomes:
            limitations = ("required_verification_missing",)
        if blocking_drift:
            limitations = tuple(sorted(set(limitations) | {"blocking_drift_unresolved"}))
        if limitations:
            return ADVStateProjection(
                stage=DiscoveryStage.VERIFICATION,
                limitations=limitations,
                evaluated_at=at,
            )
        if not assertion_current:
            return ADVStateProjection(
                stage=DiscoveryStage.VERIFICATION,
                limitations=("verification_assertion_not_current",),
                evaluated_at=at,
            )
        if next_validation_at is None:
            return ADVStateProjection(
                stage=DiscoveryStage.VERIFIED,
                limitations=("continuous_validation_not_scheduled",),
                evaluated_at=at,
            )
        if next_validation_at.tzinfo is None or next_validation_at.utcoffset() is None:
            raise ADVStateConflict("next validation time must be timezone-aware")
        if next_validation_at.astimezone(timezone.utc) <= at:
            return ADVStateProjection(
                stage=DiscoveryStage.VERIFICATION,
                limitations=("verification_expired",),
                evaluated_at=at,
            )
        return ADVStateProjection(
            stage=DiscoveryStage.CONTINUOUSLY_VALIDATED,
            limitations=(),
            evaluated_at=at,
        )


__all__ = ["ADVStateConflict", "ADVStateMachine"]
