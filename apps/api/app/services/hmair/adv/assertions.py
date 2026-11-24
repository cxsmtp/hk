from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.discovery_verification import (
    DiscoveryVerificationAssertion,
    DiscoveryVerificationEpisode,
    DiscoveryVerificationEvent,
    DiscoveryVerificationPolicy,
    DiscoveryVerificationPolicyRequirement,
    DiscoveryVerificationResult,
)
from app.db.models.evidence_resolution import DiscoveryHypothesisEvaluation
from app.services.hmair.adv.contracts import VerificationOutcome
from app.services.hmair.contracts import canonical_json_bytes


class VerificationAssertionConflict(RuntimeError):
    """A verification assertion cannot be derived from retained evidence."""


def stored_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise VerificationAssertionConflict("verification assertion time must be timezone-aware")
    return value.astimezone(timezone.utc)


def _digest(material: dict[str, object], domain: bytes) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(material)).hexdigest()


@dataclass(frozen=True)
class RequirementEvaluation:
    requirement: DiscoveryVerificationPolicyRequirement
    outcome: VerificationOutcome
    verified_count: int
    current_result_ids: tuple[str, ...]


def evaluate_requirements(
    *,
    requirements: tuple[DiscoveryVerificationPolicyRequirement, ...],
    results: tuple[DiscoveryVerificationResult, ...],
    evaluated_at: datetime,
) -> tuple[RequirementEvaluation, ...]:
    at = _utc(evaluated_at)
    evaluations: list[RequirementEvaluation] = []
    for requirement in requirements:
        current = tuple(
            item
            for item in results
            if item.requirement_record_id == requirement.requirement_record_id
            and stored_utc(item.expires_at) > at
        )
        outcomes = {
            item.outcome
            for item in current
            if item.outcome not in {"verified", "contradicted"}
            or (
                item.integrity_state == "verified"
                and item.freshness == "fresh"
            )
        }
        verified_count = sum(
            1
            for item in current
            if item.outcome == "verified"
            and item.satisfies_requirement
            and item.integrity_state == "verified"
            and item.freshness == "fresh"
        )
        if "contradicted" in outcomes:
            outcome = VerificationOutcome.CONTRADICTED
        elif verified_count >= requirement.minimum_result_count:
            outcome = VerificationOutcome.VERIFIED
        elif "failed" in outcomes:
            outcome = VerificationOutcome.FAILED
        elif "unsupported" in outcomes:
            outcome = VerificationOutcome.UNSUPPORTED
        else:
            outcome = VerificationOutcome.UNKNOWN
        evaluations.append(
            RequirementEvaluation(
                requirement=requirement,
                outcome=outcome,
                verified_count=verified_count,
                current_result_ids=tuple(sorted(item.result_id for item in current)),
            )
        )
    return tuple(evaluations)


class VerificationAssertionEngine:
    def evaluate(
        self,
        db: Session,
        *,
        tenant_id: str,
        episode_id: str,
        evaluated_at: datetime,
        idempotency_key: str,
    ) -> DiscoveryVerificationAssertion:
        at = _utc(evaluated_at)
        episode = db.scalar(
            select(DiscoveryVerificationEpisode).where(
                DiscoveryVerificationEpisode.tenant_id == tenant_id,
                DiscoveryVerificationEpisode.episode_id == episode_id,
            )
        )
        if episode is None:
            raise VerificationAssertionConflict("verification episode is unavailable")
        policy = db.scalar(
            select(DiscoveryVerificationPolicy).where(
                DiscoveryVerificationPolicy.tenant_id == tenant_id,
                DiscoveryVerificationPolicy.policy_record_id == episode.policy_record_id,
            )
        )
        evaluation = db.scalar(
            select(DiscoveryHypothesisEvaluation).where(
                DiscoveryHypothesisEvaluation.tenant_id == tenant_id,
                DiscoveryHypothesisEvaluation.evaluation_id
                == episode.hypothesis_evaluation_id,
            )
        )
        if policy is None or evaluation is None:
            raise VerificationAssertionConflict("verification authority is unavailable")
        requirements = tuple(
            db.scalars(
                select(DiscoveryVerificationPolicyRequirement)
                .where(
                    DiscoveryVerificationPolicyRequirement.tenant_id == tenant_id,
                    DiscoveryVerificationPolicyRequirement.policy_record_id
                    == policy.policy_record_id,
                )
                .order_by(DiscoveryVerificationPolicyRequirement.requirement_id)
            ).all()
        )
        results = tuple(
            db.scalars(
                select(DiscoveryVerificationResult).where(
                    DiscoveryVerificationResult.tenant_id == tenant_id,
                    DiscoveryVerificationResult.episode_id == episode_id,
                )
            ).all()
        )
        requirement_evaluations = evaluate_requirements(
            requirements=requirements,
            results=results,
            evaluated_at=at,
        )
        required = tuple(item for item in requirement_evaluations if item.requirement.required)
        optional = tuple(item for item in requirement_evaluations if not item.requirement.required)
        required_verified = sum(item.outcome is VerificationOutcome.VERIFIED for item in required)
        optional_verified = sum(item.outcome is VerificationOutcome.VERIFIED for item in optional)
        source_groups = {
            item.requirement.independence_group
            for item in requirement_evaluations
            if item.outcome is VerificationOutcome.VERIFIED
        }
        limitations: set[str] = set()
        if not required:
            limitations.add("required_verification_policy_empty")
        for item in required:
            if item.outcome is not VerificationOutcome.VERIFIED:
                limitations.add(
                    f"required:{item.requirement.requirement_id}:{item.outcome.value}"
                )
        confidence = evaluation.effective_confidence
        if confidence is None or confidence < policy.minimum_confidence:
            limitations.add("erg_confidence_below_policy")
        if evaluation.evidence_quality is None or evaluation.evidence_quality < policy.minimum_evidence_quality:
            limitations.add("erg_evidence_quality_below_policy")
        if len(source_groups) < policy.minimum_source_diversity:
            limitations.add("verification_source_diversity_below_policy")
        if any(item.outcome is VerificationOutcome.CONTRADICTED for item in required):
            conclusion = "contradicted"
        elif not limitations and required_verified == len(required):
            conclusion = "verified"
        else:
            conclusion = "incomplete"
        verification_quality = required_verified / len(required) if required else None
        material: dict[str, object] = {
            "tenant_id": tenant_id,
            "episode_id": episode_id,
            "ecosystem_id": episode.ecosystem_id,
            "erg_evaluation_id": evaluation.evaluation_id,
            "erg_evaluation_input_digest": evaluation.input_digest,
            "policy_record_id": policy.policy_record_id,
            "policy_input_digest": policy.input_digest,
            "requirement_results": [
                {
                    "requirement_record_id": item.requirement.requirement_record_id,
                    "outcome": item.outcome.value,
                    "verified_count": item.verified_count,
                    "current_result_ids": item.current_result_ids,
                }
                for item in requirement_evaluations
            ],
            "conclusion": conclusion,
            "evaluated_at": at.isoformat(),
            "limitations": sorted(limitations),
        }
        input_digest = _digest(material, b"hawk:discovery:verification-assertion:v1")
        existing = db.scalar(
            select(DiscoveryVerificationAssertion).where(
                DiscoveryVerificationAssertion.tenant_id == tenant_id,
                DiscoveryVerificationAssertion.idempotency_key == idempotency_key,
            )
        )
        if existing is not None:
            if existing.input_digest != input_digest:
                raise VerificationAssertionConflict("verification assertion idempotency conflict")
            return existing
        predecessor = db.scalar(
            select(DiscoveryVerificationAssertion)
            .where(
                DiscoveryVerificationAssertion.tenant_id == tenant_id,
                DiscoveryVerificationAssertion.ecosystem_id == episode.ecosystem_id,
            )
            .order_by(DiscoveryVerificationAssertion.assertion_sequence.desc())
        )
        sequence = 1 if predecessor is None else predecessor.assertion_sequence + 1
        valid_until = min(
            stored_utc(episode.expires_at),
            at + timedelta(seconds=policy.assertion_ttl_seconds),
        )
        if valid_until <= at:
            conclusion = "expired"
            limitations.add("verification_episode_expired")
        assertion = DiscoveryVerificationAssertion(
            assertion_id=str(uuid4()), tenant_id=tenant_id,
            ecosystem_id=episode.ecosystem_id,
            ecosystem_record_id=episode.ecosystem_record_id,
            episode_id=episode_id, erg_evaluation_id=evaluation.evaluation_id,
            policy_record_id=policy.policy_record_id,
            predecessor_assertion_id=predecessor.assertion_id if predecessor else None,
            assertion_sequence=sequence, conclusion=conclusion,
            required_requirement_count=len(required),
            required_verified_count=required_verified,
            optional_requirement_count=len(optional),
            optional_verified_count=optional_verified,
            source_diversity=len(source_groups),
            evidence_quality=evaluation.evidence_quality,
            verification_quality=verification_quality,
            issued_at=at, valid_from=at, valid_until=valid_until,
            invalidated_at=None, methodology_version="1.0.0",
            limitations_json=sorted(limitations),
            contradictions_json=[
                item.requirement.requirement_id
                for item in requirement_evaluations
                if item.outcome is VerificationOutcome.CONTRADICTED
            ],
            idempotency_key=idempotency_key, input_digest=input_digest,
        )
        db.add(assertion)
        db.flush()
        event_type = {
            "verified": "verification_passed",
            "contradicted": "verification_contradicted",
            "expired": "verification_expired",
        }.get(conclusion, "verification_failed")
        event_material = {
            "assertion_input_digest": assertion.input_digest,
            "event_type": event_type,
        }
        db.add(
            DiscoveryVerificationEvent(
                event_id=str(uuid4()), tenant_id=tenant_id,
                ecosystem_id=episode.ecosystem_id,
                ecosystem_record_id=episode.ecosystem_record_id,
                episode_id=episode_id, assertion_id=assertion.assertion_id,
                event_type=event_type, occurred_at=at,
                actor_id="adv-assertion-engine", actor_type="system",
                evidence_node_ids_json=sorted(
                    {
                        evidence_id
                        for result in results
                        for evidence_id in result.evidence_node_ids_json
                    }
                ),
                before_json={},
                after_json={
                    "conclusion": conclusion,
                    "required_verified": required_verified,
                    "required_total": len(required),
                },
                reason="Derived verification assertion from current evidence",
                idempotency_key=f"{idempotency_key}:event",
                input_digest=_digest(
                    event_material, b"hawk:discovery:verification-event:v1"
                ),
            )
        )
        db.flush()
        return assertion


__all__ = [
    "RequirementEvaluation",
    "VerificationAssertionConflict",
    "VerificationAssertionEngine",
    "evaluate_requirements",
    "stored_utc",
]
