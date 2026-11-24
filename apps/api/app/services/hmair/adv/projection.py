from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.discovery_verification import (
    DiscoveryVerificationAssertion,
    DiscoveryVerificationEpisode,
    DiscoveryVerificationPolicy,
    DiscoveryVerificationPolicyRequirement,
    DiscoveryVerificationResult,
)
from app.db.models.evidence_resolution import (
    DiscoveryAIEcosystem,
    DiscoveryHypothesisEvaluation,
)
from app.services.hmair.adv.assertions import evaluate_requirements, stored_utc
from app.services.hmair.adv.contracts import DiscoveryStage, VerificationOutcome
from app.services.hmair.adv.state_machine import ADVStateMachine


class VerificationProjectionConflict(RuntimeError):
    """An ecosystem verification projection is unavailable."""


@dataclass(frozen=True)
class EcosystemVerificationProjection:
    ecosystem_id: str
    stage: DiscoveryStage
    limitations: tuple[str, ...]
    required_outcomes: tuple[VerificationOutcome, ...]
    optional_outcomes: tuple[VerificationOutcome, ...]
    assertion_id: str | None
    assertion_current: bool
    last_validation_at: datetime | None
    next_validation_at: datetime | None
    verification_coverage: float
    verification_quality: float | None
    evidence_quality: float | None
    collector_diversity: int
    erg_evaluation_id: str | None
    confidence: float | None


class VerificationProjectionService:
    def get(
        self,
        db: Session,
        *,
        tenant_id: str,
        ecosystem_id: str,
        evaluated_at: datetime,
    ) -> EcosystemVerificationProjection:
        if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
            raise VerificationProjectionConflict("projection time must be timezone-aware")
        at = evaluated_at.astimezone(timezone.utc)
        ecosystem = db.scalar(
            select(DiscoveryAIEcosystem)
            .where(
                DiscoveryAIEcosystem.tenant_id == tenant_id,
                DiscoveryAIEcosystem.ecosystem_id == ecosystem_id,
            )
            .order_by(DiscoveryAIEcosystem.resolution_version.desc())
        )
        if ecosystem is None:
            raise VerificationProjectionConflict("verification ecosystem is unavailable")
        episode = db.scalar(
            select(DiscoveryVerificationEpisode)
            .where(
                DiscoveryVerificationEpisode.tenant_id == tenant_id,
                DiscoveryVerificationEpisode.ecosystem_id == ecosystem_id,
            )
            .order_by(DiscoveryVerificationEpisode.episode_sequence.desc())
        )
        if episode is None:
            state = ADVStateMachine().project(
                has_observation=True, has_candidate=True, has_hypothesis=True,
                has_open_episode=False, assertion_current=False,
                required_outcomes=(), blocking_drift=False,
                next_validation_at=None, evaluated_at=at,
            )
            return EcosystemVerificationProjection(
                ecosystem_id=ecosystem_id, stage=state.stage or DiscoveryStage.HYPOTHESIS,
                limitations=state.limitations, required_outcomes=(), optional_outcomes=(),
                assertion_id=None, assertion_current=False,
                last_validation_at=None, next_validation_at=None,
                verification_coverage=0.0, verification_quality=None,
                evidence_quality=ecosystem.evidence_quality,
                collector_diversity=0, erg_evaluation_id=None,
                confidence=ecosystem.confidence,
            )
        policy = db.get(DiscoveryVerificationPolicy, episode.policy_record_id)
        evaluation = db.get(DiscoveryHypothesisEvaluation, episode.hypothesis_evaluation_id)
        if policy is None or evaluation is None or policy.tenant_id != tenant_id or evaluation.tenant_id != tenant_id:
            raise VerificationProjectionConflict("verification projection authority is unavailable")
        requirements = tuple(
            db.scalars(
                select(DiscoveryVerificationPolicyRequirement)
                .where(
                    DiscoveryVerificationPolicyRequirement.tenant_id == tenant_id,
                    DiscoveryVerificationPolicyRequirement.policy_record_id == policy.policy_record_id,
                )
                .order_by(DiscoveryVerificationPolicyRequirement.requirement_id)
            ).all()
        )
        results = tuple(
            db.scalars(
                select(DiscoveryVerificationResult).where(
                    DiscoveryVerificationResult.tenant_id == tenant_id,
                    DiscoveryVerificationResult.episode_id == episode.episode_id,
                )
            ).all()
        )
        requirement_evaluations = evaluate_requirements(
            requirements=requirements, results=results, evaluated_at=at
        )
        required = tuple(item for item in requirement_evaluations if item.requirement.required)
        optional = tuple(item for item in requirement_evaluations if not item.requirement.required)
        assertion = db.scalar(
            select(DiscoveryVerificationAssertion)
            .where(
                DiscoveryVerificationAssertion.tenant_id == tenant_id,
                DiscoveryVerificationAssertion.ecosystem_id == ecosystem_id,
            )
            .order_by(DiscoveryVerificationAssertion.assertion_sequence.desc())
        )
        assertion_current = bool(
            assertion is not None
            and assertion.conclusion == "verified"
            and stored_utc(assertion.valid_from) <= at < stored_utc(assertion.valid_until)
            and required
            and all(item.outcome is VerificationOutcome.VERIFIED for item in required)
        )
        next_validation_at = None
        if assertion_current and assertion is not None:
            deadlines = [
                stored_utc(assertion.valid_until),
                stored_utc(assertion.valid_from)
                + timedelta(seconds=policy.rescan_interval_seconds),
            ]
            results_by_id = {item.result_id: item for item in results}
            for item in required:
                deadlines.extend(
                    stored_utc(results_by_id[result_id].expires_at)
                    for result_id in item.current_result_ids
                    if result_id in results_by_id
                )
            next_validation_at = min(deadlines)
        state = ADVStateMachine().project(
            has_observation=True, has_candidate=True, has_hypothesis=True,
            has_open_episode=True, assertion_current=assertion_current,
            required_outcomes=tuple(item.outcome for item in required),
            blocking_drift=False, next_validation_at=next_validation_at,
            evaluated_at=at,
        )
        coverage = (
            sum(item.outcome is VerificationOutcome.VERIFIED for item in required)
            / len(required)
            if required else 0.0
        )
        return EcosystemVerificationProjection(
            ecosystem_id=ecosystem_id,
            stage=state.stage or DiscoveryStage.HYPOTHESIS,
            limitations=tuple(sorted(set(state.limitations) | set(assertion.limitations_json if assertion else ()))),
            required_outcomes=tuple(item.outcome for item in required),
            optional_outcomes=tuple(item.outcome for item in optional),
            assertion_id=assertion.assertion_id if assertion else None,
            assertion_current=assertion_current,
            last_validation_at=stored_utc(assertion.issued_at) if assertion else None,
            next_validation_at=next_validation_at,
            verification_coverage=coverage,
            verification_quality=assertion.verification_quality if assertion else None,
            evidence_quality=evaluation.evidence_quality,
            collector_diversity=assertion.source_diversity if assertion else 0,
            erg_evaluation_id=evaluation.evaluation_id,
            confidence=evaluation.effective_confidence,
        )


__all__ = [
    "EcosystemVerificationProjection",
    "VerificationProjectionConflict",
    "VerificationProjectionService",
]
