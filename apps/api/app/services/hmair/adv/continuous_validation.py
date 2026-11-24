from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models.discovery_resolution import DiscoveryVerificationTask
from app.db.models.discovery_verification import (
    DiscoveryVerificationAssertion,
    DiscoveryVerificationEpisode,
    DiscoveryVerificationEvent,
    DiscoveryVerificationPolicy,
    DiscoveryVerificationPolicyRequirement,
    DiscoveryVerificationResult,
)
from app.services.hmair.adv.assertions import (
    VerificationAssertionEngine,
    stored_utc,
)
from app.services.hmair.adv.planner import VerificationPlan, VerificationPlanner
from app.services.hmair.contracts import canonical_json_bytes


class ContinuousValidationConflict(RuntimeError):
    """Continuous validation work cannot be safely scheduled."""


SUPPORTED_DRIFT_CATEGORIES = frozenset(
    {
        "capability_drift", "dependency_drift", "marketplace_drift",
        "configuration_drift", "permission_drift", "identity_drift",
        "usage_drift", "model_drift", "provider_drift",
        "repository_drift", "runtime_drift", "network_drift",
        "relationship_drift",
    }
)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ContinuousValidationConflict("continuous validation time must be timezone-aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class DueVerification:
    ecosystem_id: str
    episode: DiscoveryVerificationEpisode
    assertion: DiscoveryVerificationAssertion | None
    reason: str
    due_at: datetime


class ContinuousValidationService:
    def evaluate_ready(
        self,
        db: Session,
        *,
        tenant_id: str,
        evaluated_at: datetime,
        limit: int = 100,
    ) -> tuple[DiscoveryVerificationAssertion, ...]:
        at = _utc(evaluated_at)
        if not 1 <= limit <= 500:
            raise ContinuousValidationConflict("assertion evaluation limit is invalid")
        episodes = tuple(
            db.scalars(
                select(DiscoveryVerificationEpisode)
                .where(DiscoveryVerificationEpisode.tenant_id == tenant_id)
                .order_by(
                    DiscoveryVerificationEpisode.started_at,
                    DiscoveryVerificationEpisode.episode_id,
                )
                .limit(limit * 4)
            ).all()
        )
        assertions: list[DiscoveryVerificationAssertion] = []
        for episode in episodes:
            existing = db.scalar(
                select(DiscoveryVerificationAssertion.assertion_id).where(
                    DiscoveryVerificationAssertion.tenant_id == tenant_id,
                    DiscoveryVerificationAssertion.episode_id == episode.episode_id,
                )
            )
            if existing is not None:
                continue
            active = db.scalar(
                select(DiscoveryVerificationTask.task_id).where(
                    DiscoveryVerificationTask.tenant_id == tenant_id,
                    DiscoveryVerificationTask.verification_episode_id
                    == episode.episode_id,
                    DiscoveryVerificationTask.status.in_(("pending", "claimed")),
                )
            )
            if active is not None:
                continue
            task_count = int(
                db.scalar(
                    select(func.count(DiscoveryVerificationTask.task_id)).where(
                        DiscoveryVerificationTask.tenant_id == tenant_id,
                        DiscoveryVerificationTask.verification_episode_id
                        == episode.episode_id,
                    )
                )
                or 0
            )
            result_count = int(
                db.scalar(
                    select(func.count(DiscoveryVerificationResult.result_id)).where(
                        DiscoveryVerificationResult.tenant_id == tenant_id,
                        DiscoveryVerificationResult.episode_id == episode.episode_id,
                    )
                )
                or 0
            )
            if task_count == 0 and result_count == 0:
                continue
            assertions.append(
                VerificationAssertionEngine().evaluate(
                    db,
                    tenant_id=tenant_id,
                    episode_id=episode.episode_id,
                    evaluated_at=at,
                    idempotency_key=f"adv:auto-assertion:{episode.episode_id}",
                )
            )
            if len(assertions) >= limit:
                break
        return tuple(assertions)

    def list_due(
        self,
        db: Session,
        *,
        tenant_id: str,
        evaluated_at: datetime,
        limit: int = 100,
    ) -> tuple[DueVerification, ...]:
        at = _utc(evaluated_at)
        if not 1 <= limit <= 500:
            raise ContinuousValidationConflict("continuous validation limit is invalid")
        ecosystem_ids = tuple(
            db.scalars(
                select(DiscoveryVerificationEpisode.ecosystem_id)
                .where(DiscoveryVerificationEpisode.tenant_id == tenant_id)
                .distinct()
            ).all()
        )
        due: list[DueVerification] = []
        for ecosystem_id in ecosystem_ids:
            episode = db.scalar(
                select(DiscoveryVerificationEpisode)
                .where(
                    DiscoveryVerificationEpisode.tenant_id == tenant_id,
                    DiscoveryVerificationEpisode.ecosystem_id == ecosystem_id,
                )
                .order_by(DiscoveryVerificationEpisode.episode_sequence.desc())
            )
            if episode is None:
                continue
            active_task = db.scalar(
                select(DiscoveryVerificationTask.task_id).where(
                    DiscoveryVerificationTask.tenant_id == tenant_id,
                    DiscoveryVerificationTask.verification_episode_id == episode.episode_id,
                    DiscoveryVerificationTask.status.in_(("pending", "claimed")),
                )
            )
            if active_task is not None:
                continue
            assertion = db.scalar(
                select(DiscoveryVerificationAssertion)
                .where(
                    DiscoveryVerificationAssertion.tenant_id == tenant_id,
                    DiscoveryVerificationAssertion.ecosystem_id == ecosystem_id,
                )
                .order_by(DiscoveryVerificationAssertion.assertion_sequence.desc())
            )
            if assertion is None:
                episode_expiry = stored_utc(episode.expires_at)
                if episode_expiry <= at:
                    due.append(
                        DueVerification(
                            ecosystem_id=ecosystem_id, episode=episode,
                            assertion=None, reason="episode_expired", due_at=episode_expiry,
                        )
                    )
                continue
            policy = db.scalar(
                select(DiscoveryVerificationPolicy).where(
                    DiscoveryVerificationPolicy.tenant_id == tenant_id,
                    DiscoveryVerificationPolicy.policy_record_id == assertion.policy_record_id,
                )
            )
            if policy is None:
                continue
            validity_end = stored_utc(assertion.valid_until)
            rescan_due = stored_utc(assertion.valid_from) + timedelta(
                seconds=policy.rescan_interval_seconds
            )
            requirements = tuple(
                db.scalars(
                    select(DiscoveryVerificationPolicyRequirement).where(
                        DiscoveryVerificationPolicyRequirement.tenant_id == tenant_id,
                        DiscoveryVerificationPolicyRequirement.policy_record_id
                        == assertion.policy_record_id,
                    )
                ).all()
            )
            results = tuple(
                db.scalars(
                    select(DiscoveryVerificationResult).where(
                        DiscoveryVerificationResult.tenant_id == tenant_id,
                        DiscoveryVerificationResult.episode_id == assertion.episode_id,
                    )
                ).all()
            )
            required_records = {
                item.requirement_record_id for item in requirements if item.required
            }
            latest_results: dict[str, DiscoveryVerificationResult] = {}
            for result in results:
                if result.requirement_record_id not in required_records:
                    continue
                current = latest_results.get(result.requirement_record_id)
                if current is None or result.result_sequence > current.result_sequence:
                    latest_results[result.requirement_record_id] = result
            required_evidence_deadlines = [
                stored_utc(item.expires_at) for item in latest_results.values()
            ]
            deadline = min(validity_end, rescan_due, *required_evidence_deadlines)
            if deadline <= at:
                due.append(
                    DueVerification(
                        ecosystem_id=ecosystem_id, episode=episode,
                        assertion=assertion,
                        reason=("assertion_expired" if validity_end <= at else "rescan_due"),
                        due_at=deadline,
                    )
                )
        due.sort(key=lambda item: (item.due_at, item.ecosystem_id))
        return tuple(due[:limit])

    def schedule_due(
        self,
        db: Session,
        *,
        tenant_id: str,
        evaluated_at: datetime,
        limit: int = 100,
    ) -> tuple[VerificationPlan, ...]:
        at = _utc(evaluated_at)
        plans: list[VerificationPlan] = []
        for item in self.list_due(
            db, tenant_id=tenant_id, evaluated_at=at, limit=limit
        ):
            source = item.assertion.assertion_id if item.assertion else item.episode.episode_id
            key = f"adv:revalidation:{item.ecosystem_id}:{source}:{item.due_at.isoformat()}"
            plan = VerificationPlanner().start(
                db,
                tenant_id=tenant_id,
                ecosystem_id=item.ecosystem_id,
                hypothesis_evaluation_id=item.episode.hypothesis_evaluation_id,
                environment=item.episode.environment,
                trigger="scheduled_revalidation",
                trigger_event_id=None,
                triggered_at=at,
                idempotency_key=key,
            )
            self._record_schedule_event(
                db,
                plan=plan,
                assertion=item.assertion,
                event_type=(
                    "verification_expired"
                    if item.reason in {"assertion_expired", "episode_expired"}
                    else "verification_updated"
                ),
                occurred_at=at,
                source_reference=source,
            )
            plans.append(plan)
        return tuple(plans)

    def schedule_for_drift(
        self,
        db: Session,
        *,
        tenant_id: str,
        ecosystem_id: str,
        hypothesis_evaluation_id: str,
        environment: str,
        drift_event_id: str,
        triggered_at: datetime,
        drift_category: str = "capability_drift",
    ) -> VerificationPlan:
        at = _utc(triggered_at)
        if not drift_event_id or len(drift_event_id) > 128:
            raise ContinuousValidationConflict("drift event identity is invalid")
        if drift_category not in SUPPORTED_DRIFT_CATEGORIES:
            raise ContinuousValidationConflict("drift category is unsupported")
        plan = VerificationPlanner().start(
            db,
            tenant_id=tenant_id,
            ecosystem_id=ecosystem_id,
            hypothesis_evaluation_id=hypothesis_evaluation_id,
            environment=environment,
            trigger="drift",
            trigger_event_id=drift_event_id,
            triggered_at=at,
            idempotency_key=(
                f"adv:drift:{ecosystem_id}:{drift_category}:{drift_event_id}"
            ),
        )
        self._record_schedule_event(
            db,
            plan=plan,
            assertion=None,
            event_type="verification_updated",
            occurred_at=at,
            source_reference=f"{drift_category}:{drift_event_id}",
        )
        return plan

    @staticmethod
    def _record_schedule_event(
        db: Session,
        *,
        plan: VerificationPlan,
        assertion: DiscoveryVerificationAssertion | None,
        event_type: str,
        occurred_at: datetime,
        source_reference: str,
    ) -> DiscoveryVerificationEvent:
        key = f"{plan.episode.idempotency_key}:schedule-event"
        material: dict[str, object] = {
            "episode_input_digest": plan.episode.input_digest,
            "assertion_id": assertion.assertion_id if assertion else None,
            "event_type": event_type,
            "source_reference": source_reference,
            "occurred_at": occurred_at.isoformat(),
        }
        digest = hashlib.sha256(
            b"hawk:discovery:verification-schedule-event:v1"
            + canonical_json_bytes(material)
        ).hexdigest()
        existing = db.scalar(
            select(DiscoveryVerificationEvent).where(
                DiscoveryVerificationEvent.tenant_id == plan.episode.tenant_id,
                DiscoveryVerificationEvent.idempotency_key == key,
            )
        )
        if existing is not None:
            if existing.input_digest != digest:
                raise ContinuousValidationConflict("schedule event idempotency conflict")
            return existing
        event = DiscoveryVerificationEvent(
            event_id=str(uuid4()), tenant_id=plan.episode.tenant_id,
            ecosystem_id=plan.episode.ecosystem_id,
            ecosystem_record_id=plan.episode.ecosystem_record_id,
            episode_id=plan.episode.episode_id,
            assertion_id=assertion.assertion_id if assertion else None,
            event_type=event_type, occurred_at=occurred_at,
            actor_id="adv-continuous-validation", actor_type="system",
            evidence_node_ids_json=[], before_json={"source": source_reference},
            after_json={"episode_id": plan.episode.episode_id},
            reason="Scheduled evidence-backed ecosystem revalidation",
            idempotency_key=key, input_digest=digest,
        )
        db.add(event)
        db.flush()
        return event


__all__ = [
    "ContinuousValidationConflict",
    "ContinuousValidationService",
    "DueVerification",
    "SUPPORTED_DRIFT_CATEGORIES",
]
