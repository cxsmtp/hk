from __future__ import annotations

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.models.discovery_resolution import DiscoveryResolutionGraphEdge
from app.db.models.evidence_resolution import DiscoveryEcosystemMembership
from app.db.session import Base
from app.services.hmair.erg.ecosystem_resolver import EcosystemResolver
from app.services.hmair.erg.hypothesis_engine import HypothesisEngine
from app.services.hmair.erg.resolution_history import ResolutionHistory
from app.services.hmair.erg.evidence_resolution_graph import EvidenceResolutionGraph
from app.services.hmair.resolution_graph_service import create_graph_node
from test_erg_hypotheses import NOW, _inference
from test_phase2_asset_resolution_service import _seed


def _db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine, autoflush=False, expire_on_commit=False)


def _qualified_coding_edges(
    db: Session,
    seed: dict[str, str],
    *,
    strong_relationship: bool,
) -> tuple[str, ...]:
    process = create_graph_node(
        db,
        tenant_id=seed["tenant_id"],
        node_class="process",
        subject_reference="process:qualified-coding-agent",
        idempotency_key=f"qualified-process:{strong_relationship}",
    )
    graph = EvidenceResolutionGraph()
    edge_ids: list[str] = []
    for index, (node_class, surface) in enumerate(
        (("repository", "repository"), ("runtime", "endpoint"), ("tool", "network"))
    ):
        target = create_graph_node(
            db,
            tenant_id=seed["tenant_id"],
            node_class=node_class,
            subject_reference=f"{node_class}:qualified-coding-agent",
            idempotency_key=f"qualified-{node_class}:{strong_relationship}",
        )
        edge = graph.append_edge_evaluation(
            db,
            tenant_id=seed["tenant_id"],
            from_node_id=process.graph_node_id,
            to_node_id=target.graph_node_id,
            edge_type="supports",
            evidence_node_id=seed["node_id"],
            collector_id=f"collector-{seed['tenant_id'].removeprefix('tenant-')}",
            base_confidence=1.0,
            relationship_weight=1.0,
            observation_quality=1.0,
            collector_quality=1.0,
            source_surface=surface,
            signal_class=node_class,
            verification_state="verified",
            freshness="fresh",
            contradiction_state="none",
            first_observed_at=NOW,
            last_observed_at=NOW,
            last_validated_at=NOW,
            relationship_rule_id=(
                "strong-runtime-repository-v1"
                if strong_relationship
                else "capability-support-v1"
            ),
            relationship_rule_version="1.0.0",
            idempotency_key=f"qualified-edge-{index}:{strong_relationship}",
        )
        edge_ids.append(edge.edge_id)
    return tuple(edge_ids)


def test_resolver_creates_only_at_exact_threshold_with_two_sources_and_anchors() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-resolver")
        run_id = _inference(
            db,
            tenant_id=seed["tenant_id"],
            evidence_node_id=seed["node_id"],
            coding_confidence=1.0,
            include_retrieval=False,
        )
        edges = _qualified_coding_edges(db, seed, strong_relationship=False)
        evaluation = HypothesisEngine().evaluate(
            db,
            tenant_id=seed["tenant_id"],
            inference_run_id=run_id,
            graph_edge_ids=edges,
            evaluated_at=NOW,
            idempotency_prefix="resolver-pass",
        )[0]
        assert evaluation.recommended_action == "create_ecosystem"
        outcome = EcosystemResolver().resolve(
            db,
            tenant_id=seed["tenant_id"],
            evaluation_id=evaluation.evaluation_id,
            evidence_node_id=seed["node_id"],
            evaluated_at=NOW,
            idempotency_key="resolver-create",
        )
        assert outcome.recommendation == "create_ecosystem"
        assert outcome.mutated is True
        assert len(outcome.ecosystem_ids) == 1
        assert outcome.explanation["create_threshold"] == 0.90
    finally:
        db.close()
        db.bind.dispose()


def test_resolver_keeps_confirmed_contradictions_in_manual_review() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-resolver-review")
        run_id = _inference(
            db,
            tenant_id=seed["tenant_id"],
            evidence_node_id=seed["node_id"],
            coding_confidence=1.0,
            include_retrieval=False,
        )
        edges = _qualified_coding_edges(db, seed, strong_relationship=True)
        first_edge = db.get(DiscoveryResolutionGraphEdge, edges[0])
        contradiction = EvidenceResolutionGraph().append_edge_evaluation(
            db,
            tenant_id=seed["tenant_id"],
            from_node_id=first_edge.from_node_id,
            to_node_id=first_edge.to_node_id,
            edge_type=first_edge.edge_type,
            evidence_node_id=seed["node_id"],
            collector_id=first_edge.collector_id,
            base_confidence=first_edge.base_confidence,
            relationship_weight=first_edge.relationship_weight,
            observation_quality=first_edge.observation_quality_factor,
            collector_quality=first_edge.collector_quality_factor,
            source_surface=first_edge.source_surface,
            signal_class=first_edge.signal_class,
            verification_state=first_edge.verification_state,
            freshness=first_edge.freshness,
            contradiction_state="confirmed",
            first_observed_at=NOW,
            last_observed_at=NOW,
            last_validated_at=NOW,
            relationship_rule_id=first_edge.relationship_rule_id,
            relationship_rule_version=first_edge.relationship_rule_version,
            idempotency_key="resolver-confirmed-contradiction",
            predecessor_edge_id=first_edge.edge_id,
        )
        current_edges = tuple(
            contradiction.edge_id if edge_id == first_edge.edge_id else edge_id
            for edge_id in edges
        )
        evaluation = HypothesisEngine().evaluate(
            db,
            tenant_id=seed["tenant_id"],
            inference_run_id=run_id,
            graph_edge_ids=current_edges,
            evaluated_at=NOW,
            idempotency_prefix="resolver-review",
        )[0]
        assert evaluation.recommended_action == "manual_review"
        outcome = EcosystemResolver().resolve(
            db,
            tenant_id=seed["tenant_id"],
            evaluation_id=evaluation.evaluation_id,
            evidence_node_id=seed["node_id"],
            evaluated_at=NOW,
            idempotency_key="resolver-review-outcome",
        )
        assert outcome.recommendation == "manual_review"
        assert outcome.mutated is False
        assert outcome.ecosystem_ids == ()
        assert "unresolved_confirmed_contradiction" in outcome.limitations
    finally:
        db.close()
        db.bind.dispose()


def test_resolver_attaches_only_to_an_explicit_existing_ecosystem() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-resolver-attach")
        run_id = _inference(
            db,
            tenant_id=seed["tenant_id"],
            evidence_node_id=seed["node_id"],
            coding_confidence=1.0,
            include_retrieval=False,
        )
        edges = _qualified_coding_edges(db, seed, strong_relationship=True)
        evaluation = HypothesisEngine().evaluate(
            db,
            tenant_id=seed["tenant_id"],
            inference_run_id=run_id,
            graph_edge_ids=edges,
            evaluated_at=NOW,
            idempotency_prefix="resolver-attach",
        )[0]
        assert evaluation.recommended_action == "attach_observation"
        anchor_node_id = db.get(DiscoveryResolutionGraphEdge, edges[0]).from_node_id
        existing = ResolutionHistory().create_ecosystem(
            db,
            tenant_id=seed["tenant_id"],
            canonical_name="Existing coding ecosystem",
            ecosystem_class=evaluation.candidate_ecosystem_class,
            graph_node_ids=(anchor_node_id,),
            evidence_node_id=seed["node_id"],
            confidence=0.96,
            evidence_quality=0.96,
            operator_id="owner-1",
            operator_role="owner",
            reason="Existing strong anchor",
            occurred_at=NOW,
            idempotency_key="resolver-attach-existing",
        )

        outcome = EcosystemResolver().resolve(
            db,
            tenant_id=seed["tenant_id"],
            evaluation_id=evaluation.evaluation_id,
            evidence_node_id=seed["node_id"],
            evaluated_at=NOW,
            idempotency_key="resolver-attach-outcome",
            target_ecosystem_id=existing.ecosystem_ids[0],
        )

        assert outcome.recommendation == "attach_observation"
        assert outcome.mutated is True
        assert outcome.ecosystem_ids == existing.ecosystem_ids
        active = tuple(
            db.scalars(
                select(DiscoveryEcosystemMembership).where(
                    DiscoveryEcosystemMembership.tenant_id == seed["tenant_id"],
                    DiscoveryEcosystemMembership.ecosystem_id == existing.ecosystem_ids[0],
                    DiscoveryEcosystemMembership.membership_state == "active",
                )
            )
        )
        assert {item.graph_node_id for item in active} == {
            node_id
            for edge_id in edges
            for node_id in (
                db.get(DiscoveryResolutionGraphEdge, edge_id).from_node_id,
                db.get(DiscoveryResolutionGraphEdge, edge_id).to_node_id,
            )
        }
    finally:
        db.close()
        db.bind.dispose()
