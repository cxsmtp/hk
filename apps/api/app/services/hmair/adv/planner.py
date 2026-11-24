from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models.discovery_canonical import DiscoveryCollector
from app.db.models.discovery_resolution import DiscoveryVerificationTask
from app.db.models.discovery_verification import (
    DiscoveryVerificationEpisode,
    DiscoveryVerificationEvent,
    DiscoveryVerificationPolicyRequirement,
    DiscoveryVerificationResult,
)
from app.db.models.evidence_resolution import (
    DiscoveryAIEcosystem,
    DiscoveryHypothesisEvaluation,
    DiscoveryHypothesisEvaluationEdge,
)
from app.services.hmair.adv.policy import (
    VerificationPolicyConflict,
    VerificationPolicyResolver,
)
from app.services.hmair.contracts import canonical_json_bytes
from app.services.hmair.verification_service import enqueue_verification_task


class VerificationPlanningConflict(RuntimeError):
    """An ADV episode cannot be created from the supplied authorities."""


_COLLECTOR_METHODS = {
    "endpoint": {"endpoint_metadata", "process_metadata", "package_metadata", "runtime_metadata"},
    "network": {"network_metadata"},
    "repository": {"repository_metadata"},
    "cloud": {"cloud_metadata", "model_metadata"},
    "identity": {"identity_metadata", "owner_directory"},
    "saas": {"saas_admin_metadata"},
    "mcp": {"mcp_metadata"},
    "usage": {"usage_aggregate"},
}


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise VerificationPlanningConflict("verification episode time must be timezone-aware")
    return value.astimezone(timezone.utc)


def _digest(material: dict[str, object], domain: bytes) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(material)).hexdigest()


def _available_methods(db: Session, *, tenant_id: str) -> frozenset[str]:
    methods: set[str] = set()
    rows = db.scalars(
        select(DiscoveryCollector).where(
            DiscoveryCollector.tenant_id == tenant_id,
            DiscoveryCollector.health == "healthy",
        )
    ).all()
    for row in rows:
        methods.update(_COLLECTOR_METHODS.get(row.collector_type, set()))
    return frozenset(methods)


@dataclass(frozen=True)
class VerificationPlan:
    episode: DiscoveryVerificationEpisode
    tasks: tuple[DiscoveryVerificationTask, ...]
    unsupported_results: tuple[DiscoveryVerificationResult, ...]
    required_requirement_ids: tuple[str, ...]
    task_requirement_ids: tuple[str, ...]
    unsupported_requirement_ids: tuple[str, ...]


@dataclass(frozen=True)
class InitialVerificationPlanning:
    plans: tuple[VerificationPlan, ...]
    limitations: tuple[str, ...]


class VerificationPlanner:
    def start(
        self,
        db: Session,
        *,
        tenant_id: str,
        ecosystem_id: str,
        hypothesis_evaluation_id: str,
        environment: str,
        trigger: str,
        triggered_at: datetime,
        idempotency_key: str,
        trigger_event_id: str | None = None,
    ) -> VerificationPlan:
        at = _utc(triggered_at)
        if not trigger or len(trigger) > 64 or not idempotency_key or len(idempotency_key) > 128:
            raise VerificationPlanningConflict("verification episode identity is invalid")
        evaluation = db.scalar(
            select(DiscoveryHypothesisEvaluation).where(
                DiscoveryHypothesisEvaluation.tenant_id == tenant_id,
                DiscoveryHypothesisEvaluation.evaluation_id == hypothesis_evaluation_id,
            )
        )
        if evaluation is None:
            raise VerificationPlanningConflict("verification hypothesis evaluation is unavailable")
        ecosystem = db.scalar(
            select(DiscoveryAIEcosystem)
            .where(
                DiscoveryAIEcosystem.tenant_id == tenant_id,
                DiscoveryAIEcosystem.ecosystem_id == ecosystem_id,
            )
            .order_by(DiscoveryAIEcosystem.resolution_version.desc())
        )
        if ecosystem is None:
            raise VerificationPlanningConflict("verification ecosystem is unavailable")
        selection = VerificationPolicyResolver().resolve(
            db,
            tenant_id=tenant_id,
            ecosystem_class=ecosystem.ecosystem_class,
            environment=environment,
            at=at,
        )
        evaluation_edges = tuple(
            db.scalars(
                select(DiscoveryHypothesisEvaluationEdge).where(
                    DiscoveryHypothesisEvaluationEdge.tenant_id == tenant_id,
                    DiscoveryHypothesisEvaluationEdge.evaluation_id == evaluation.evaluation_id,
                )
            ).all()
        )
        graph_digest = _digest(
            {
                "evaluation_id": evaluation.evaluation_id,
                "evaluation_input_digest": evaluation.input_digest,
                "graph_edge_ids": sorted(item.graph_edge_id for item in evaluation_edges),
            },
            b"hawk:discovery:verification-graph-input:v1",
        )
        evidence_digest = _digest(
            {
                "evaluation_id": evaluation.evaluation_id,
                "evaluation_edge_ids": sorted(item.evaluation_edge_id for item in evaluation_edges),
            },
            b"hawk:discovery:verification-evidence-input:v1",
        )
        material: dict[str, object] = {
            "tenant_id": tenant_id,
            "ecosystem_id": ecosystem_id,
            "ecosystem_record_id": ecosystem.ecosystem_record_id,
            "hypothesis_evaluation_id": evaluation.evaluation_id,
            "policy_record_id": selection.policy.policy_record_id,
            "policy_digest": selection.policy.input_digest,
            "graph_input_digest": graph_digest,
            "evidence_input_digest": evidence_digest,
            "environment": environment,
            "trigger": trigger,
            "trigger_event_id": trigger_event_id,
            "triggered_at": at.isoformat(),
        }
        input_digest = _digest(material, b"hawk:discovery:verification-episode:v1")
        existing = db.scalar(
            select(DiscoveryVerificationEpisode).where(
                DiscoveryVerificationEpisode.tenant_id == tenant_id,
                DiscoveryVerificationEpisode.idempotency_key == idempotency_key,
            )
        )
        if existing is not None:
            if existing.input_digest != input_digest:
                raise VerificationPlanningConflict("verification episode idempotency conflict")
            return self._projection(db, existing, selection.required_requirement_ids)

        predecessor = db.scalar(
            select(DiscoveryVerificationEpisode)
            .where(
                DiscoveryVerificationEpisode.tenant_id == tenant_id,
                DiscoveryVerificationEpisode.ecosystem_id == ecosystem_id,
            )
            .order_by(DiscoveryVerificationEpisode.episode_sequence.desc())
        )
        sequence = 1 if predecessor is None else predecessor.episode_sequence + 1
        expiry = at + timedelta(seconds=min(selection.policy.assertion_ttl_seconds, 604800))
        episode = DiscoveryVerificationEpisode(
            episode_id=str(uuid4()), tenant_id=tenant_id,
            ecosystem_id=ecosystem_id,
            ecosystem_record_id=ecosystem.ecosystem_record_id,
            hypothesis_evaluation_id=evaluation.evaluation_id,
            policy_record_id=selection.policy.policy_record_id,
            environment=environment,
            episode_sequence=sequence,
            predecessor_episode_id=predecessor.episode_id if predecessor else None,
            trigger=trigger, trigger_event_id=trigger_event_id,
            graph_input_digest=graph_digest,
            evidence_input_digest=evidence_digest,
            policy_digest=selection.policy.input_digest,
            started_at=at,
            due_at=at + timedelta(seconds=min(300, selection.policy.rescan_interval_seconds)),
            expires_at=expiry,
            limitations_json=[], idempotency_key=idempotency_key,
            input_digest=input_digest,
        )
        db.add(episode)
        db.flush()

        available = _available_methods(db, tenant_id=tenant_id)
        for requirement in selection.requirements:
            method = next(
                (item for item in requirement.accepted_methods_json if item in available),
                None,
            )
            requirement_key = f"{idempotency_key}:requirement:{requirement.requirement_id}"
            if method is None:
                predecessor_result = db.scalar(
                    select(DiscoveryVerificationResult)
                    .where(
                        DiscoveryVerificationResult.tenant_id == tenant_id,
                        DiscoveryVerificationResult.requirement_record_id
                        == requirement.requirement_record_id,
                    )
                    .order_by(DiscoveryVerificationResult.result_sequence.desc())
                )
                db.add(
                    DiscoveryVerificationResult(
                        result_id=str(uuid4()), tenant_id=tenant_id,
                        episode_id=episode.episode_id,
                        requirement_record_id=requirement.requirement_record_id,
                        task_id=None, attempt_id=None,
                        predecessor_result_id=(
                            predecessor_result.result_id if predecessor_result else None
                        ),
                        result_sequence=(
                            predecessor_result.result_sequence + 1
                            if predecessor_result else 1
                        ), outcome="unsupported",
                        evidence_node_ids_json=[], source_identity="planner:no_eligible_collector",
                        collector_id=None, integrity_state="unknown", freshness="fresh",
                        satisfies_requirement=False, observed_at=at, validated_at=at,
                        expires_at=min(
                            expiry, at + timedelta(seconds=requirement.maximum_age_seconds)
                        ),
                        limitations_json=["accepted_verification_method_unavailable"],
                        methodology_version="1.0.0",
                        idempotency_key=f"{requirement_key}:unsupported",
                        input_digest=_digest(
                            {
                                "episode_input_digest": input_digest,
                                "requirement_record_id": requirement.requirement_record_id,
                                "outcome": "unsupported",
                            },
                            b"hawk:discovery:verification-result:v1",
                        ),
                    )
                )
                continue
            enqueue_verification_task(
                db,
                tenant_id=tenant_id,
                hypothesis_id=evaluation.hypothesis_id,
                task_type=requirement.task_type,
                method=method,
                scope={
                    "ecosystem_id": ecosystem_id,
                    "requirement_id": requirement.requirement_id,
                    "evidence_class": requirement.evidence_class,
                },
                rate_limit_key=f"adv:{ecosystem_id}:{requirement.requirement_id}",
                priority=80 if requirement.required else 50,
                max_attempts=3,
                expires_at=min(
                    expiry, at + timedelta(seconds=requirement.maximum_age_seconds)
                ),
                idempotency_key=requirement_key,
                now=at,
                verification_episode_id=episode.episode_id,
                verification_requirement_id=requirement.requirement_record_id,
                task_contract_version="adv-1.0.0",
            )
        event_material: dict[str, object] = {
            "episode_input_digest": episode.input_digest,
            "event_type": "verification_started",
            "required_requirement_ids": list(selection.required_requirement_ids),
        }
        db.add(
            DiscoveryVerificationEvent(
                event_id=str(uuid4()), tenant_id=tenant_id,
                ecosystem_id=ecosystem_id,
                ecosystem_record_id=ecosystem.ecosystem_record_id,
                episode_id=episode.episode_id, assertion_id=None,
                event_type="verification_started", occurred_at=at,
                actor_id="adv-verification-planner", actor_type="system",
                evidence_node_ids_json=[], before_json={},
                after_json={
                    "episode_id": episode.episode_id,
                    "policy_record_id": selection.policy.policy_record_id,
                    "required_requirement_ids": list(
                        selection.required_requirement_ids
                    ),
                },
                reason="Started policy-derived autonomous verification",
                idempotency_key=f"{idempotency_key}:started-event",
                input_digest=_digest(
                    event_material,
                    b"hawk:discovery:verification-start-event:v1",
                ),
            )
        )
        db.flush()
        return self._projection(db, episode, selection.required_requirement_ids)

    @staticmethod
    def _projection(
        db: Session,
        episode: DiscoveryVerificationEpisode,
        required_requirement_ids: tuple[str, ...],
    ) -> VerificationPlan:
        tasks = tuple(
            db.scalars(
                select(DiscoveryVerificationTask)
                .where(
                    DiscoveryVerificationTask.tenant_id == episode.tenant_id,
                    DiscoveryVerificationTask.verification_episode_id == episode.episode_id,
                )
                .order_by(DiscoveryVerificationTask.task_id)
            ).all()
        )
        results = tuple(
            db.scalars(
                select(DiscoveryVerificationResult)
                .where(
                    DiscoveryVerificationResult.tenant_id == episode.tenant_id,
                    DiscoveryVerificationResult.episode_id == episode.episode_id,
                    DiscoveryVerificationResult.outcome == "unsupported",
                )
                .order_by(DiscoveryVerificationResult.result_id)
            ).all()
        )
        requirement_ids = {
            item.requirement_record_id: item.requirement_id
            for item in db.scalars(
                select(DiscoveryVerificationPolicyRequirement).where(
                    DiscoveryVerificationPolicyRequirement.tenant_id == episode.tenant_id,
                    DiscoveryVerificationPolicyRequirement.policy_record_id == episode.policy_record_id,
                )
            ).all()
        }
        return VerificationPlan(
            episode=episode,
            tasks=tasks,
            unsupported_results=results,
            required_requirement_ids=required_requirement_ids,
            task_requirement_ids=tuple(
                requirement_ids[item.verification_requirement_id]
                for item in tasks
                if item.verification_requirement_id in requirement_ids
            ),
            unsupported_requirement_ids=tuple(
                requirement_ids[item.requirement_record_id]
                for item in results
                if item.requirement_record_id in requirement_ids
            ),
        )


class InitialVerificationCoordinator:
    """Bind newly resolved ERG ecosystems to their exact evaluation and policy."""

    def plan_resolved_outcomes(
        self,
        db: Session,
        *,
        tenant_id: str,
        outcomes: Sequence[Mapping[str, object]],
        environment: str,
        triggered_at: datetime,
        idempotency_prefix: str,
    ) -> InitialVerificationPlanning:
        at = _utc(triggered_at)
        if (
            not environment
            or environment != environment.strip()
            or len(environment) > 64
            or not idempotency_prefix
            or len(idempotency_prefix) > 80
            or len(outcomes) > 256
        ):
            raise VerificationPlanningConflict(
                "autonomous verification planning input is invalid"
            )
        plans: list[VerificationPlan] = []
        limitations: set[str] = set()
        seen: set[tuple[str, str]] = set()
        for outcome in outcomes:
            evaluation_id = outcome.get("evaluation_id")
            ecosystem_ids = outcome.get("ecosystem_ids", ())
            if (
                type(evaluation_id) is not str
                or not evaluation_id
                or len(evaluation_id) > 36
                or not isinstance(ecosystem_ids, (list, tuple))
                or len(ecosystem_ids) > 128
            ):
                raise VerificationPlanningConflict(
                    "autonomous resolution outcome is invalid"
                )
            for ecosystem_id in ecosystem_ids:
                if (
                    type(ecosystem_id) is not str
                    or not ecosystem_id
                    or len(ecosystem_id) > 36
                ):
                    raise VerificationPlanningConflict(
                        "autonomous ecosystem identity is invalid"
                    )
                binding = (evaluation_id, ecosystem_id)
                if binding in seen:
                    continue
                seen.add(binding)
                key_digest = _digest(
                    {
                        "idempotency_prefix": idempotency_prefix,
                        "evaluation_id": evaluation_id,
                        "ecosystem_id": ecosystem_id,
                    },
                    b"hawk:discovery:verification-auto-plan:v1",
                )
                try:
                    plans.append(
                        VerificationPlanner().start(
                            db,
                            tenant_id=tenant_id,
                            ecosystem_id=ecosystem_id,
                            hypothesis_evaluation_id=evaluation_id,
                            environment=environment,
                            trigger="ecosystem_resolved",
                            triggered_at=at,
                            idempotency_key=f"adv:auto:{key_digest}",
                        )
                    )
                except VerificationPolicyConflict as exc:
                    if str(exc) != "no applicable verification policy":
                        raise
                    limitations.add(f"verification_policy_unavailable:{ecosystem_id}")
        return InitialVerificationPlanning(
            plans=tuple(plans), limitations=tuple(sorted(limitations))
        )


__all__ = [
    "InitialVerificationCoordinator",
    "InitialVerificationPlanning",
    "VerificationPlan",
    "VerificationPlanner",
    "VerificationPlanningConflict",
]
