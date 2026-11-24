from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.models.capability_inference import (
    DiscoveryCapabilityEvidence,
    DiscoveryCapabilityInferenceRun,
)
from app.db.models.evidence_resolution import DiscoveryHypothesisEvaluation
from app.db.session import Base
from app.services.hmair.erg.evidence_resolution_graph import EvidenceResolutionGraph
from app.services.hmair.erg.hypothesis_engine import (
    HypothesisEngine,
    HypothesisEvaluationConflict,
)
from app.services.hmair.resolution_graph_service import create_graph_edge, create_graph_node
from test_phase2_asset_resolution_service import _seed


NOW = datetime(2026, 8, 16, 12, 0, tzinfo=timezone.utc)


def _db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine, autoflush=False, expire_on_commit=False)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _inference(
    db: Session,
    *,
    tenant_id: str,
    evidence_node_id: str,
    coding_confidence: float = 0.88,
    include_retrieval: bool = True,
) -> str:
    run_id = "00000000-0000-0000-0000-000000000601"
    db.add(
        DiscoveryCapabilityInferenceRun(
            inference_run_id=run_id,
            tenant_id=tenant_id,
            evidence_node_id=evidence_node_id,
            subject_reference_hash=_sha("unknown-executable"),
            observation_ids_json=["unknown-executable"],
            engine_version="2.0.0",
            catalog_version="2.0.0",
            ruleset_version="2.0.0",
            run_sequence=1,
            supersedes_run_id=None,
            recommended_asset_type="unknown_ai_workload",
            recommended_ecosystem="unknown",
            first_observed_at=NOW,
            last_observed_at=NOW,
            validated_at=NOW,
            limitations_json=[],
            idempotency_key="unknown-executable-run",
            input_digest=_sha("run-input"),
            output_digest=_sha("run-output"),
        )
    )
    evidence_rows = [("code_generation", "developer", "coding", coding_confidence)]
    if include_retrieval:
        evidence_rows.append(("retrieval", "data", "retrieval_augmented_generation", 0.81))
    for index, (capability, family, ecosystem, confidence) in enumerate(
        evidence_rows,
        start=1,
    ):
        db.add(
            DiscoveryCapabilityEvidence(
                capability_evidence_id=f"00000000-0000-0000-0000-00000000061{index}",
                tenant_id=tenant_id,
                inference_run_id=run_id,
                capability_id=capability,
                family=family,
                rule_id=f"{capability}-rule",
                rule_version="1.0.0",
                calibration_version="1.0.0",
                confidence=confidence,
                supporting_signal_ids_json=[f"signal-{index}"],
                conflicting_signal_ids_json=[],
                unknown_predicates_json=[],
                source_diversity=2,
                freshness="fresh",
                verification_state="inferred",
                last_validated_at=NOW,
                explanation=f"Evidence supports {capability}",
                limitations_json=[],
                recommended_asset_type="unknown_ai_workload",
                recommended_ecosystem=ecosystem,
                evidence_digest=_sha(f"capability-{index}"),
            )
        )
    db.flush()
    return run_id


def _graph_edges(db: Session, seed: dict[str, str]) -> tuple[str, str]:
    subject = create_graph_node(
        db,
        tenant_id=seed["tenant_id"],
        node_class="process",
        subject_reference="process:unknown-executable",
        idempotency_key="unknown-process",
    )
    repository = create_graph_node(
        db,
        tenant_id=seed["tenant_id"],
        node_class="repository",
        subject_reference="repository:opaque",
        idempotency_key="unknown-repository",
    )
    database = create_graph_node(
        db,
        tenant_id=seed["tenant_id"],
        node_class="database",
        subject_reference="database:vector-store",
        idempotency_key="unknown-database",
    )
    graph = EvidenceResolutionGraph()
    ids = []
    for index, (target, surface) in enumerate(((repository, "repository"), (database, "cloud"))):
        row = graph.append_edge_evaluation(
            db,
            tenant_id=seed["tenant_id"],
            from_node_id=subject.graph_node_id,
            to_node_id=target.graph_node_id,
            edge_type="connected_to",
            evidence_node_id=seed["node_id"],
            collector_id=f"collector-{seed['tenant_id'].removeprefix('tenant-')}",
            base_confidence=0.96,
            relationship_weight=1.0,
            observation_quality=0.99,
            collector_quality=0.99,
            source_surface=surface,
            signal_class="relationship",
            verification_state="verified",
            freshness="fresh",
            contradiction_state="none",
            first_observed_at=NOW,
            last_observed_at=NOW,
            last_validated_at=NOW,
            relationship_rule_id="strong-runtime-repository-v1",
            relationship_rule_version="1.0.0",
            idempotency_key=f"unknown-edge-{index}",
        )
        ids.append(row.edge_id)
    return tuple(ids)  # type: ignore[return-value]


def test_unknown_executable_keeps_competing_hypotheses_and_appends_history() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-hypothesis")
        run_id = _inference(db, tenant_id=seed["tenant_id"], evidence_node_id=seed["node_id"])
        edges = _graph_edges(db, seed)
        engine = HypothesisEngine()

        first = engine.evaluate(
            db,
            tenant_id=seed["tenant_id"],
            inference_run_id=run_id,
            graph_edge_ids=edges,
            evaluated_at=NOW,
            idempotency_prefix="hypothesis-pass-one",
        )
        assert {item.candidate_ecosystem_class for item in first} == {
            "coding",
            "retrieval_augmented_generation",
        }
        assert len({item.hypothesis_id for item in first}) == 2

        exact_replay = engine.evaluate(
            db,
            tenant_id=seed["tenant_id"],
            inference_run_id=run_id,
            graph_edge_ids=edges,
            evaluated_at=NOW,
            idempotency_prefix="hypothesis-pass-one",
        )
        assert tuple(item.evaluation_id for item in exact_replay) == tuple(
            item.evaluation_id for item in first
        )
        assert len(tuple(db.scalars(select(DiscoveryHypothesisEvaluation)))) == 2
        with pytest.raises(HypothesisEvaluationConflict, match="idempotency conflict"):
            engine.evaluate(
                db,
                tenant_id=seed["tenant_id"],
                inference_run_id=run_id,
                graph_edge_ids=edges,
                evaluated_at=NOW + timedelta(minutes=1),
                idempotency_prefix="hypothesis-pass-one",
            )

        second = engine.evaluate(
            db,
            tenant_id=seed["tenant_id"],
            inference_run_id=run_id,
            graph_edge_ids=edges,
            evaluated_at=NOW,
            idempotency_prefix="hypothesis-pass-two",
        )
        assert all(item.evaluation_sequence == 2 for item in second)
        assert {item.predecessor_evaluation_id for item in second} == {
            item.evaluation_id for item in first
        }
        rows = tuple(db.scalars(select(DiscoveryHypothesisEvaluation)))
        assert len(rows) == 4
    finally:
        db.close()
        db.bind.dispose()


def test_confirmed_contradiction_never_auto_resolves() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-contradiction")
        run_id = _inference(db, tenant_id=seed["tenant_id"], evidence_node_id=seed["node_id"])
        edge_ids = _graph_edges(db, seed)
        edge = db.get(DiscoveryResolutionGraphEdge, edge_ids[0])
        contradiction = EvidenceResolutionGraph().append_edge_evaluation(
            db,
            tenant_id=seed["tenant_id"],
            from_node_id=edge.from_node_id,
            to_node_id=edge.to_node_id,
            edge_type=edge.edge_type,
            evidence_node_id=seed["node_id"],
            collector_id=edge.collector_id,
            base_confidence=edge.base_confidence,
            relationship_weight=edge.relationship_weight,
            observation_quality=edge.observation_quality_factor,
            collector_quality=edge.collector_quality_factor,
            source_surface=edge.source_surface,
            signal_class=edge.signal_class,
            verification_state=edge.verification_state,
            freshness=edge.freshness,
            contradiction_state="confirmed",
            first_observed_at=NOW,
            last_observed_at=NOW,
            last_validated_at=NOW,
            relationship_rule_id=edge.relationship_rule_id,
            relationship_rule_version=edge.relationship_rule_version,
            idempotency_key="confirmed-contradiction-successor",
            predecessor_edge_id=edge.edge_id,
        )
        current_edge_ids = tuple(
            contradiction.edge_id if item == edge.edge_id else item for item in edge_ids
        )
        rows = HypothesisEngine().evaluate(
            db,
            tenant_id=seed["tenant_id"],
            inference_run_id=run_id,
            graph_edge_ids=current_edge_ids,
            evaluated_at=NOW,
            idempotency_prefix="contradiction-pass",
        )
        assert rows
        assert {item.recommended_action for item in rows} == {"manual_review"}
    finally:
        db.close()
        db.bind.dispose()


def test_unknown_quality_is_never_replaced_with_perfect_evidence() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-quality-unknown")
        run_id = _inference(
            db, tenant_id=seed["tenant_id"], evidence_node_id=seed["node_id"]
        )
        process = create_graph_node(
            db,
            tenant_id=seed["tenant_id"],
            node_class="process",
            subject_reference="process:legacy-unknown-quality",
            idempotency_key="legacy-unknown-quality-process",
        )
        repository = create_graph_node(
            db,
            tenant_id=seed["tenant_id"],
            node_class="repository",
            subject_reference="repository:legacy-unknown-quality",
            idempotency_key="legacy-unknown-quality-repository",
        )
        edge = create_graph_edge(
            db,
            tenant_id=seed["tenant_id"],
            from_node_id=process.graph_node_id,
            to_node_id=repository.graph_node_id,
            edge_type="connected_to",
            evidence_node_id=seed["node_id"],
            confidence=0.99,
            verification_state="verified",
            freshness="fresh",
            contradiction_state="none",
            first_observed_at=NOW,
            last_observed_at=NOW,
            idempotency_key="legacy-unknown-quality-edge",
        )

        evaluations = HypothesisEngine().evaluate(
            db,
            tenant_id=seed["tenant_id"],
            inference_run_id=run_id,
            graph_edge_ids=(edge.edge_id,),
            evaluated_at=NOW,
            idempotency_prefix="unknown-quality-evaluation",
        )

        assert evaluations
        assert all(item.effective_confidence is None for item in evaluations)
        assert all(item.evidence_quality is None for item in evaluations)
        assert all("evidence_quality_unknown" in item.limitations_json for item in evaluations)
    finally:
        db.close()
        db.bind.dispose()


def test_expired_evidence_decays_and_cannot_auto_resolve() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-expired-evidence")
        run_id = _inference(
            db, tenant_id=seed["tenant_id"], evidence_node_id=seed["node_id"]
        )
        evaluations = HypothesisEngine().evaluate(
            db,
            tenant_id=seed["tenant_id"],
            inference_run_id=run_id,
            graph_edge_ids=_graph_edges(db, seed),
            evaluated_at=NOW + timedelta(days=181),
            idempotency_prefix="expired-evidence-evaluation",
        )

        assert evaluations
        assert all(item.recommended_action == "manual_review" for item in evaluations)
        assert all(
            item.effective_confidence is None or item.effective_confidence <= 0.25
            for item in evaluations
        )
        assert all("expired_evidence" in item.limitations_json for item in evaluations)
    finally:
        db.close()
        db.bind.dispose()
