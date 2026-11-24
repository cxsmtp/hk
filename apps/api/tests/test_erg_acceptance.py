from __future__ import annotations

from datetime import timedelta

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.models.discovery_canonical import DiscoveryObservation
from app.db.models.discovery_resolution import DiscoveryResolutionGraphEdge
from app.db.models.evidence_resolution import (
    DiscoveryAIEcosystem,
    DiscoveryHypothesisEvaluation,
    DiscoveryEcosystemResolutionEvent,
)
from app.db.session import Base
from app.services.hmair.erg.ecosystem_resolver import EcosystemResolver
from app.services.hmair.erg.evidence_resolution_graph import EvidenceResolutionGraph
from app.services.hmair.erg.hypothesis_engine import HypothesisEngine
from app.services.hmair.erg.pipeline import EvidenceResolutionPipeline
from app.services.hmair.resolution_graph_service import create_graph_node
from test_erg_hypotheses import NOW, _graph_edges, _inference
from test_phase2_asset_resolution_service import _seed


def _db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine, autoflush=False, expire_on_commit=False)


def test_unknown_executable_remains_competing_evidence_until_thresholds_are_met() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-acceptance-unknown")
        run_id = _inference(db, tenant_id=seed["tenant_id"], evidence_node_id=seed["node_id"])
        evaluations = HypothesisEngine().evaluate(
            db,
            tenant_id=seed["tenant_id"],
            inference_run_id=run_id,
            graph_edge_ids=_graph_edges(db, seed),
            evaluated_at=NOW,
            idempotency_prefix="erg-acceptance-unknown",
        )
        assert {item.candidate_ecosystem_class for item in evaluations} == {
            "coding",
            "retrieval_augmented_generation",
        }
        outcomes = tuple(
            EcosystemResolver().resolve(
                db,
                tenant_id=seed["tenant_id"],
                evaluation_id=evaluation.evaluation_id,
                evidence_node_id=seed["node_id"],
                evaluated_at=NOW,
                idempotency_key=f"erg-acceptance-resolution-{index}",
            )
            for index, evaluation in enumerate(evaluations)
        )
        assert all(outcome.mutated is False for outcome in outcomes)
        assert all(outcome.recommendation == "manual_review" for outcome in outcomes)
        assert tuple(db.scalars(select(DiscoveryAIEcosystem))) == ()
    finally:
        db.close()
        db.bind.dispose()


def test_operational_pipeline_runs_observation_through_cie_hypothesis_and_resolution() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-acceptance-pipeline")
        observation = db.scalar(
            select(DiscoveryObservation).where(
                DiscoveryObservation.tenant_id == seed["tenant_id"],
                DiscoveryObservation.observation_id == seed["observation_id"],
            )
        )
        observation.capability_hints_json = ["filesystem_read"]
        result = EvidenceResolutionPipeline().run(
            db,
            tenant_id=seed["tenant_id"],
            observation_ids=(seed["observation_id"],),
            evaluated_at=NOW,
            idempotency_key="erg-operational-pipeline",
        )
        assert result.inference_run_id
        assert result.graph_edge_ids
        assert result.evaluation_ids
        assert result.outcomes
        assert all(item["mutated"] is False for item in result.outcomes)
        assert {
            item.action
            for item in db.scalars(select(DiscoveryEcosystemResolutionEvent))
        } <= {"manual_review", "unknown"}
    finally:
        db.close()
        db.bind.dispose()


def test_operational_pipeline_replay_is_exact_and_does_not_append_evaluations() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-acceptance-replay")
        observation = db.scalar(
            select(DiscoveryObservation).where(
                DiscoveryObservation.tenant_id == seed["tenant_id"],
                DiscoveryObservation.observation_id == seed["observation_id"],
            )
        )
        observation.capability_hints_json = ["filesystem_read"]
        first = EvidenceResolutionPipeline().run(
            db,
            tenant_id=seed["tenant_id"],
            observation_ids=(seed["observation_id"],),
            evaluated_at=NOW,
            idempotency_key="erg-operational-replay",
        )
        counts_before = (
            db.scalar(select(func.count()).select_from(DiscoveryHypothesisEvaluation)),
            db.scalar(select(func.count()).select_from(DiscoveryEcosystemResolutionEvent)),
        )

        replay = EvidenceResolutionPipeline().run(
            db,
            tenant_id=seed["tenant_id"],
            observation_ids=(seed["observation_id"],),
            evaluated_at=NOW + timedelta(minutes=10),
            idempotency_key="erg-operational-replay",
        )
        counts_after = (
            db.scalar(select(func.count()).select_from(DiscoveryHypothesisEvaluation)),
            db.scalar(select(func.count()).select_from(DiscoveryEcosystemResolutionEvent)),
        )

        assert replay == first
        assert counts_after == counts_before
    finally:
        db.close()
        db.bind.dispose()


def test_operational_pipeline_includes_existing_connected_erg_evidence() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-acceptance-connected")
        observation = db.scalar(
            select(DiscoveryObservation).where(
                DiscoveryObservation.tenant_id == seed["tenant_id"],
                DiscoveryObservation.observation_id == seed["observation_id"],
            )
        )
        observation.capability_hints_json = ["filesystem_read"]
        first = EvidenceResolutionPipeline().run(
            db,
            tenant_id=seed["tenant_id"],
            observation_ids=(seed["observation_id"],),
            evaluated_at=NOW,
            idempotency_key="erg-operational-connected-first",
        )
        first_edge = db.get(DiscoveryResolutionGraphEdge, first.graph_edge_ids[0])
        runtime = create_graph_node(
            db,
            tenant_id=seed["tenant_id"],
            node_class="runtime",
            subject_reference="runtime:existing-connected-context",
            idempotency_key="erg-existing-connected-runtime",
        )
        existing = EvidenceResolutionGraph().append_edge_evaluation(
            db,
            tenant_id=seed["tenant_id"],
            from_node_id=first_edge.to_node_id,
            to_node_id=runtime.graph_node_id,
            edge_type="runs_on",
            evidence_node_id=first.evidence_node_id,
            collector_id=f"collector-erg-acceptance-connected",
            base_confidence=0.9,
            relationship_weight=1.0,
            observation_quality=0.9,
            collector_quality=0.9,
            source_surface="endpoint",
            signal_class="runtime",
            verification_state="verified",
            freshness="fresh",
            contradiction_state="none",
            first_observed_at=NOW,
            last_observed_at=NOW,
            last_validated_at=NOW,
            relationship_rule_id="runtime-context-v1",
            relationship_rule_version="1.0.0",
            idempotency_key="erg-existing-connected-edge",
        )

        second = EvidenceResolutionPipeline().run(
            db,
            tenant_id=seed["tenant_id"],
            observation_ids=(seed["observation_id"],),
            evaluated_at=NOW,
            idempotency_key="erg-operational-connected-second",
        )

        assert existing.edge_id in second.graph_edge_ids
        assert set(first.graph_edge_ids) < set(second.graph_edge_ids)
    finally:
        db.close()
        db.bind.dispose()
