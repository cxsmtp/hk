from __future__ import annotations

from datetime import datetime, timezone

from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.capability_inference import DiscoveryCapabilityInferenceRun
from app.db.models.evidence_resolution import (
    DiscoveryHypothesisEvaluation,
    DiscoveryHypothesisEvaluationEdge,
)
from app.services.hmair.cie.contracts import CapabilityInferenceOptions
from app.services.hmair.cie.pipeline import CapabilityInferencePipeline
from app.services.hmair.contracts import StrictContract
from app.services.hmair.adv.planner import InitialVerificationCoordinator
from app.services.hmair.erg.ecosystem_resolver import EcosystemResolver
from app.services.hmair.erg.evidence_resolution_graph import EvidenceResolutionGraph
from app.services.hmair.erg.hypothesis_engine import HypothesisEngine


class EvidenceResolutionPipelineResult(StrictContract):
    inference_run_id: str
    evidence_node_id: str
    graph_edge_ids: tuple[str, ...] = Field(max_length=10000)
    evaluation_ids: tuple[str, ...] = Field(max_length=256)
    outcomes: tuple[dict, ...] = Field(max_length=256)
    verification_episode_ids: tuple[str, ...] = Field(default=(), max_length=256)
    verification_limitations: tuple[str, ...] = Field(default=(), max_length=256)


class EvidenceResolutionPipelineConflict(RuntimeError):
    """A replay key was reused for materially different pipeline input."""


def _stored_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class EvidenceResolutionPipeline:
    """One caller-owned transaction from observations to ERG outcomes."""

    def run(
        self,
        db: Session,
        *,
        tenant_id: str,
        observation_ids: tuple[str, ...],
        evaluated_at: datetime,
        idempotency_key: str,
        verification_environment: str = "production",
    ) -> EvidenceResolutionPipelineResult:
        if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
            raise ValueError("ERG pipeline evaluation time must be timezone-aware")
        evaluated_at = evaluated_at.astimezone(timezone.utc)
        if not observation_ids or len(set(observation_ids)) != len(observation_ids):
            raise ValueError("ERG pipeline observations must be a non-empty unique set")
        if not idempotency_key or len(idempotency_key) > 80:
            raise ValueError("ERG pipeline idempotency key is invalid")
        if (
            not verification_environment
            or verification_environment != verification_environment.strip()
            or len(verification_environment) > 64
        ):
            raise ValueError("ERG verification environment is invalid")
        sorted_observations = tuple(sorted(observation_ids))
        cie_idempotency_key = f"{idempotency_key}:cie"
        existing_run = db.scalar(
            select(DiscoveryCapabilityInferenceRun).where(
                DiscoveryCapabilityInferenceRun.tenant_id == tenant_id,
                DiscoveryCapabilityInferenceRun.idempotency_key == cie_idempotency_key,
            )
        )
        if existing_run is not None:
            if tuple(existing_run.observation_ids_json) != sorted_observations:
                raise EvidenceResolutionPipelineConflict(
                    "ERG pipeline idempotency key was reused with different observations"
                )
            evaluated_at = _stored_utc(existing_run.validated_at)
        hypothesis_prefix = f"{idempotency_key}:hypothesis"
        persisted_evaluations = tuple(
            item
            for item in db.scalars(
                select(DiscoveryHypothesisEvaluation)
                .where(
                    DiscoveryHypothesisEvaluation.tenant_id == tenant_id,
                    DiscoveryHypothesisEvaluation.inference_run_id
                    == existing_run.inference_run_id,
                )
                .order_by(
                    DiscoveryHypothesisEvaluation.candidate_ecosystem_class,
                    DiscoveryHypothesisEvaluation.evaluation_id,
                )
            )
            if item.idempotency_key.startswith(f"{hypothesis_prefix}:")
        ) if existing_run is not None else ()
        if persisted_evaluations:
            graph_edge_ids = tuple(
                sorted(
                    {
                        link.graph_edge_id
                        for link in db.scalars(
                            select(DiscoveryHypothesisEvaluationEdge).where(
                                DiscoveryHypothesisEvaluationEdge.tenant_id == tenant_id,
                                DiscoveryHypothesisEvaluationEdge.evaluation_id.in_(
                                    tuple(item.evaluation_id for item in persisted_evaluations)
                                ),
                            )
                        )
                    }
                )
            )
            outcomes = tuple(
                EcosystemResolver().resolve(
                    db,
                    tenant_id=tenant_id,
                    evaluation_id=evaluation.evaluation_id,
                    evidence_node_id=existing_run.evidence_node_id,
                    evaluated_at=_stored_utc(evaluation.validated_at),
                    idempotency_key=f"{idempotency_key}:resolve:{index}",
                )
                for index, evaluation in enumerate(persisted_evaluations)
            )
            outcome_payloads = tuple(item.model_dump(mode="json") for item in outcomes)
            verification = InitialVerificationCoordinator().plan_resolved_outcomes(
                db,
                tenant_id=tenant_id,
                outcomes=outcome_payloads,
                environment=verification_environment,
                triggered_at=evaluated_at,
                idempotency_prefix=idempotency_key,
            )
            return EvidenceResolutionPipelineResult(
                inference_run_id=existing_run.inference_run_id,
                evidence_node_id=existing_run.evidence_node_id,
                graph_edge_ids=graph_edge_ids,
                evaluation_ids=tuple(
                    item.evaluation_id for item in persisted_evaluations
                ),
                outcomes=outcome_payloads,
                verification_episode_ids=tuple(
                    item.episode.episode_id for item in verification.plans
                ),
                verification_limitations=verification.limitations,
            )
        inference = CapabilityInferencePipeline().run(
            db,
            tenant_id=tenant_id,
            observation_ids=sorted_observations,
            validated_at=evaluated_at,
            idempotency_key=cie_idempotency_key,
            options=CapabilityInferenceOptions(
                genome=True,
                marketplace=True,
                dependency_graph=True,
                drift=True,
            ),
        )
        graph_edge_ids = EvidenceResolutionGraph.connected_current_edge_ids(
            db,
            tenant_id=tenant_id,
            seed_edge_ids=inference.graph.edge_ids,
        )
        evaluations = HypothesisEngine().evaluate(
            db,
            tenant_id=tenant_id,
            inference_run_id=inference.inference_run_id,
            graph_edge_ids=graph_edge_ids,
            evaluated_at=evaluated_at,
            idempotency_prefix=hypothesis_prefix,
        )
        outcomes = tuple(
            EcosystemResolver().resolve(
                db,
                tenant_id=tenant_id,
                evaluation_id=evaluation.evaluation_id,
                evidence_node_id=inference.evidence_node_id,
                evaluated_at=evaluated_at,
                idempotency_key=f"{idempotency_key}:resolve:{index}",
            )
            for index, evaluation in enumerate(evaluations)
        )
        outcome_payloads = tuple(item.model_dump(mode="json") for item in outcomes)
        verification = InitialVerificationCoordinator().plan_resolved_outcomes(
            db,
            tenant_id=tenant_id,
            outcomes=outcome_payloads,
            environment=verification_environment,
            triggered_at=evaluated_at,
            idempotency_prefix=idempotency_key,
        )
        db.flush()
        return EvidenceResolutionPipelineResult(
            inference_run_id=inference.inference_run_id,
            evidence_node_id=inference.evidence_node_id,
            graph_edge_ids=graph_edge_ids,
            evaluation_ids=tuple(item.evaluation_id for item in evaluations),
            outcomes=outcome_payloads,
            verification_episode_ids=tuple(
                item.episode.episode_id for item in verification.plans
            ),
            verification_limitations=verification.limitations,
        )


__all__ = [
    "EvidenceResolutionPipeline",
    "EvidenceResolutionPipelineConflict",
    "EvidenceResolutionPipelineResult",
]
