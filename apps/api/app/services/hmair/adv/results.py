from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
import hashlib
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models.discovery_resolution import DiscoveryVerificationTask
from app.db.models.discovery_verification import (
    DiscoveryVerificationAttempt,
    DiscoveryVerificationEpisode,
    DiscoveryVerificationPolicyRequirement,
    DiscoveryVerificationResult,
)
from app.db.models.evidence import EvidenceNode
from app.db.models.evidence_resolution import DiscoveryCollectorQualitySnapshot
from app.services.hmair.adv.contracts import VerificationOutcome, VerificationTaskResult
from app.services.hmair.contracts import canonical_json_bytes


class VerificationResultConflict(RuntimeError):
    """A verification result is untrusted, inconsistent, or replayed differently."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise VerificationResultConflict("verification result time must be timezone-aware")
    return value.astimezone(timezone.utc)


def _stored_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _digest(material: dict[str, object], domain: bytes) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(material)).hexdigest()


class VerificationResultValidator:
    def accept(
        self,
        db: Session,
        *,
        tenant_id: str,
        task_id: str,
        worker_id: str,
        outcome: VerificationOutcome,
        evidence_node_ids: Sequence[str],
        observed_at: datetime,
        validated_at: datetime,
        limitations: Sequence[str],
        idempotency_key: str,
        execution_state: str = "completed",
        collector_integrity_ref: str | None = None,
    ) -> DiscoveryVerificationResult:
        if execution_state not in {"completed", "transport_failed"}:
            raise VerificationResultConflict("verification execution state is invalid")
        if execution_state == "transport_failed" and outcome is not VerificationOutcome.UNKNOWN:
            raise VerificationResultConflict("transport failure may only produce Unknown")
        if not idempotency_key or len(idempotency_key) > 128:
            raise VerificationResultConflict("verification result idempotency key is invalid")
        if len(limitations) > 32 or any(
            type(item) is not str or not item or len(item) > 255
            for item in limitations
        ):
            raise VerificationResultConflict("verification result limitations are invalid")
        evidence_ids = tuple(evidence_node_ids)
        if len(evidence_ids) > 32 or len(set(evidence_ids)) != len(evidence_ids):
            raise VerificationResultConflict("verification evidence references are invalid")
        if outcome in {VerificationOutcome.VERIFIED, VerificationOutcome.CONTRADICTED} and not evidence_ids:
            raise VerificationResultConflict("verified or contradicted result requires evidence")
        observed = _utc(observed_at)
        validated = _utc(validated_at)
        try:
            VerificationTaskResult(
                requirement_id="pending-task-binding",
                task_id=task_id,
                outcome=outcome,
                evidence_node_ids=evidence_ids,
                observed_at=observed,
                validated_at=validated,
                limitations=tuple(limitations),
            )
        except ValidationError as exc:
            raise VerificationResultConflict("verification result contract is invalid") from exc
        task = db.scalar(
            select(DiscoveryVerificationTask).where(
                DiscoveryVerificationTask.tenant_id == tenant_id,
                DiscoveryVerificationTask.task_id == task_id,
            )
        )
        if task is None:
            raise VerificationResultConflict("verification task is unavailable")
        if task.verification_episode_id is None or task.verification_requirement_id is None:
            raise VerificationResultConflict("verification task is not ADV-bound")
        requirement = db.scalar(
            select(DiscoveryVerificationPolicyRequirement).where(
                DiscoveryVerificationPolicyRequirement.tenant_id == tenant_id,
                DiscoveryVerificationPolicyRequirement.requirement_record_id
                == task.verification_requirement_id,
            )
        )
        if requirement is None:
            raise VerificationResultConflict("verification requirement is unavailable")
        episode = db.scalar(
            select(DiscoveryVerificationEpisode).where(
                DiscoveryVerificationEpisode.tenant_id == tenant_id,
                DiscoveryVerificationEpisode.episode_id
                == task.verification_episode_id,
            )
        )
        if (
            episode is None
            or episode.policy_record_id != requirement.policy_record_id
            or task.method not in set(requirement.accepted_methods_json)
            or task.scope_json.get("ecosystem_id") != episode.ecosystem_id
            or task.scope_json.get("requirement_id") != requirement.requirement_id
        ):
            raise VerificationResultConflict(
                "verification task authority binding is invalid"
            )
        material: dict[str, object] = {
            "tenant_id": tenant_id,
            "task_id": task_id,
            "episode_id": task.verification_episode_id,
            "requirement_record_id": requirement.requirement_record_id,
            "worker_id": worker_id,
            "execution_state": execution_state,
            "outcome": outcome.value,
            "evidence_node_ids": list(evidence_ids),
            "observed_at": observed.isoformat(),
            "validated_at": validated.isoformat(),
            "limitations": list(limitations),
            "collector_integrity_ref": collector_integrity_ref,
        }
        input_digest = _digest(material, b"hawk:discovery:verification-result:v1")
        existing = db.scalar(
            select(DiscoveryVerificationResult).where(
                DiscoveryVerificationResult.tenant_id == tenant_id,
                DiscoveryVerificationResult.idempotency_key == idempotency_key,
            )
        )
        if existing is not None:
            if existing.input_digest != input_digest:
                raise VerificationResultConflict("verification result idempotency conflict")
            return existing
        if task.status != "claimed" or task.claimed_by != worker_id:
            raise VerificationResultConflict("verification worker is not authorized")
        if validated > _stored_utc(task.expires_at):
            raise VerificationResultConflict("verification result is stale")
        collector_id: str | None = None
        if worker_id.startswith("collector:"):
            collector_id = worker_id.removeprefix("collector:")
        if not collector_id or len(collector_id) > 128:
            raise VerificationResultConflict(
                "verification worker collector identity is invalid"
            )
        collector_integrity: DiscoveryCollectorQualitySnapshot | None = None
        if collector_integrity_ref is not None:
            collector_integrity = db.scalar(
                select(DiscoveryCollectorQualitySnapshot).where(
                    DiscoveryCollectorQualitySnapshot.tenant_id == tenant_id,
                    DiscoveryCollectorQualitySnapshot.snapshot_id
                    == collector_integrity_ref,
                )
            )
            if collector_integrity is None:
                raise VerificationResultConflict(
                    "collector integrity reference is unavailable"
                )
            if collector_integrity.collector_id != collector_id:
                raise VerificationResultConflict(
                    "collector integrity does not match the claimed worker"
                )
            if (
                collector_integrity.signature_state != "verified"
                or collector_integrity.freshness != "fresh"
                or collector_integrity.quality is None
                or _stored_utc(collector_integrity.calculated_at) > validated
                or _stored_utc(collector_integrity.calculated_at)
                <= observed - timedelta(seconds=requirement.maximum_age_seconds)
            ):
                raise VerificationResultConflict(
                    "collector integrity is not currently verified"
                )
        if evidence_ids:
            rows = tuple(
                db.scalars(
                    select(EvidenceNode).where(
                        EvidenceNode.tenant_id == tenant_id,
                        EvidenceNode.id.in_(evidence_ids),
                    )
                ).all()
            )
            if len(rows) != len(evidence_ids):
                raise VerificationResultConflict("verification evidence is unavailable")
        last_result = db.scalar(
            select(DiscoveryVerificationResult)
            .where(
                DiscoveryVerificationResult.tenant_id == tenant_id,
                DiscoveryVerificationResult.requirement_record_id
                == requirement.requirement_record_id,
            )
            .order_by(DiscoveryVerificationResult.result_sequence.desc())
        )
        result_sequence = 1 if last_result is None else last_result.result_sequence + 1
        attempt_sequence = int(
            db.scalar(
                select(func.count(DiscoveryVerificationAttempt.attempt_id)).where(
                    DiscoveryVerificationAttempt.tenant_id == tenant_id,
                    DiscoveryVerificationAttempt.task_id == task_id,
                )
            )
            or 0
        ) + 1
        output_digest = _digest(
            {
                "outcome": outcome.value,
                "evidence_node_ids": list(evidence_ids),
                "limitations": list(limitations),
                "collector_integrity_ref": collector_integrity_ref,
            },
            b"hawk:discovery:verification-attempt-output:v1",
        )
        attempt = DiscoveryVerificationAttempt(
            attempt_id=str(uuid4()), tenant_id=tenant_id,
            episode_id=task.verification_episode_id, task_id=task_id,
            attempt_sequence=attempt_sequence, worker_id=worker_id,
            collector_id=collector_id,
            collector_integrity_ref=collector_integrity_ref,
            execution_state=execution_state,
            started_at=observed, completed_at=validated,
            latency_ms=max(0, int((validated - observed).total_seconds() * 1000)),
            output_digest=output_digest, limitations_json=list(limitations),
            idempotency_key=f"{idempotency_key}:attempt",
            input_digest=_digest(
                {
                    "task_input_digest": task.input_digest,
                    "worker_id": worker_id,
                    "execution_state": execution_state,
                    "observed_at": observed.isoformat(),
                    "validated_at": validated.isoformat(),
                },
                b"hawk:discovery:verification-attempt:v1",
            ),
        )
        expires = validated + timedelta(seconds=requirement.maximum_age_seconds)
        integrity_state = "verified" if collector_integrity is not None else "unknown"
        result_limitations = list(limitations)
        if integrity_state != "verified" and outcome in {
            VerificationOutcome.VERIFIED,
            VerificationOutcome.CONTRADICTED,
        }:
            result_limitations.append("collector_integrity_unverified")
        effective_outcome = (
            outcome
            if integrity_state == "verified"
            or outcome not in {
                VerificationOutcome.VERIFIED,
                VerificationOutcome.CONTRADICTED,
            }
            else VerificationOutcome.UNKNOWN
        )
        result = DiscoveryVerificationResult(
            result_id=str(uuid4()), tenant_id=tenant_id,
            episode_id=task.verification_episode_id,
            requirement_record_id=requirement.requirement_record_id,
            task_id=task_id, attempt_id=attempt.attempt_id,
            predecessor_result_id=last_result.result_id if last_result else None,
            result_sequence=result_sequence, outcome=effective_outcome.value,
            evidence_node_ids_json=list(evidence_ids), source_identity=worker_id,
            collector_id=attempt.collector_id,
            integrity_state=integrity_state,
            freshness="fresh",
            satisfies_requirement=(
                effective_outcome is VerificationOutcome.VERIFIED
                and integrity_state == "verified"
            ),
            observed_at=observed, validated_at=validated, expires_at=expires,
            limitations_json=result_limitations, methodology_version="1.0.0",
            idempotency_key=idempotency_key, input_digest=input_digest,
        )
        db.add_all((attempt, result))
        task.status = "succeeded" if execution_state == "completed" else "failed"
        task.completed_at = validated
        task.result_evidence_node_id = evidence_ids[0] if evidence_ids else None
        db.flush()
        return result


__all__ = ["VerificationResultConflict", "VerificationResultValidator"]
