from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.session import Base
from app.services.hmair.erg.evidence_resolution_graph import (
    ERGGraphConflict,
    ERGGraphScopeError,
    EvidenceResolutionGraph,
)
from app.services.hmair.resolution_graph_service import create_graph_node
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


def _edge_kwargs(seed: dict[str, str], from_id: str, to_id: str) -> dict:
    return {
        "tenant_id": seed["tenant_id"],
        "from_node_id": from_id,
        "to_node_id": to_id,
        "edge_type": "supports",
        "evidence_node_id": seed["node_id"],
        "collector_id": f"collector-{seed['tenant_id'].removeprefix('tenant-')}",
        "base_confidence": 0.9,
        "relationship_weight": 1.0,
        "observation_quality": 0.9,
        "collector_quality": 0.9,
        "source_surface": "endpoint",
        "signal_class": "capability",
        "verification_state": "verified",
        "freshness": "fresh",
        "contradiction_state": "none",
        "first_observed_at": NOW,
        "last_observed_at": NOW,
        "last_validated_at": NOW,
        "relationship_rule_id": "capability-support-v1",
        "relationship_rule_version": "1.0.0",
        "idempotency_key": "erg-edge-a",
    }


def test_successor_edge_preserves_history_and_current_projection() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-graph")
        observation = create_graph_node(
            db,
            tenant_id=seed["tenant_id"],
            node_class="observation",
            subject_reference="observation:opaque-a",
            idempotency_key="erg-observation-a",
        )
        capability = create_graph_node(
            db,
            tenant_id=seed["tenant_id"],
            node_class="capability",
            subject_reference="capability:filesystem_read",
            idempotency_key="erg-capability-a",
        )
        graph = EvidenceResolutionGraph()
        first = graph.append_edge_evaluation(
            db, **_edge_kwargs(seed, observation.graph_node_id, capability.graph_node_id)
        )
        successor_kwargs = _edge_kwargs(seed, observation.graph_node_id, capability.graph_node_id)
        successor_kwargs.update(
            predecessor_edge_id=first.edge_id,
            base_confidence=0.6,
            freshness="stale",
            idempotency_key="erg-edge-b",
        )
        second = graph.append_edge_evaluation(db, **successor_kwargs)
        assert first.edge_sequence == 1
        assert second.edge_sequence == 2
        assert second.predecessor_edge_id == first.edge_id
        assert second.confidence < first.confidence
        projection = graph.current_graph(db, tenant_id=seed["tenant_id"])
        assert projection.current_edge_ids == (second.edge_id,)
        assert projection.historical_edge_ids == (first.edge_id,)
        assert set(projection.node_ids) == {
            observation.graph_node_id,
            capability.graph_node_id,
        }
    finally:
        db.close()
        db.bind.dispose()


def test_conflicting_successor_and_cross_tenant_are_rejected() -> None:
    db = _db()
    try:
        first_seed = _seed(db, suffix="erg-a")
        second_seed = _seed(db, suffix="erg-b")
        first_node = create_graph_node(
            db, tenant_id=first_seed["tenant_id"], node_class="observation",
            subject_reference="observation:first", idempotency_key="node-first",
        )
        second_node = create_graph_node(
            db, tenant_id=first_seed["tenant_id"], node_class="capability",
            subject_reference="capability:inference", idempotency_key="node-second",
        )
        foreign = create_graph_node(
            db, tenant_id=second_seed["tenant_id"], node_class="capability",
            subject_reference="capability:foreign", idempotency_key="node-foreign",
        )
        graph = EvidenceResolutionGraph()
        first = graph.append_edge_evaluation(
            db, **_edge_kwargs(first_seed, first_node.graph_node_id, second_node.graph_node_id)
        )
        successor = _edge_kwargs(first_seed, first_node.graph_node_id, second_node.graph_node_id)
        successor.update(predecessor_edge_id=first.edge_id, idempotency_key="successor-one")
        graph.append_edge_evaluation(db, **successor)
        successor["idempotency_key"] = "successor-two"
        with pytest.raises(ERGGraphConflict):
            graph.append_edge_evaluation(db, **successor)

        cross = _edge_kwargs(first_seed, first_node.graph_node_id, foreign.graph_node_id)
        cross["idempotency_key"] = "cross-tenant"
        with pytest.raises(ERGGraphScopeError):
            graph.append_edge_evaluation(db, **cross)
    finally:
        db.close()
        db.bind.dispose()


def test_product_or_cooccurrence_rules_cannot_create_resolved_match() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-match")
        first = create_graph_node(
            db, tenant_id=seed["tenant_id"], node_class="application",
            subject_reference="application:opaque-a", idempotency_key="application-a",
        )
        second = create_graph_node(
            db, tenant_id=seed["tenant_id"], node_class="ai_ecosystem",
            subject_reference="ecosystem:opaque-b", idempotency_key="ecosystem-b",
        )
        material = _edge_kwargs(seed, first.graph_node_id, second.graph_node_id)
        material.update(
            edge_type="resolved_match",
            relationship_rule_id="product-name-cooccurrence-v1",
            idempotency_key="bad-resolved-match",
        )
        with pytest.raises(ERGGraphScopeError, match="accepted strong relationship"):
            EvidenceResolutionGraph().append_edge_evaluation(db, **material)
    finally:
        db.close()
        db.bind.dispose()


def test_connected_current_edges_include_existing_erg_context_but_not_disconnected_edges() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-connected")
        nodes = tuple(
            create_graph_node(
                db,
                tenant_id=seed["tenant_id"],
                node_class=node_class,
                subject_reference=f"{node_class}:connected-{index}",
                idempotency_key=f"connected-node-{index}",
            )
            for index, node_class in enumerate(
                ("observation", "capability", "runtime", "application", "provider"),
                start=1,
            )
        )
        graph = EvidenceResolutionGraph()
        edge_ids = []
        for index, (source, target) in enumerate(
            ((nodes[0], nodes[1]), (nodes[1], nodes[2]), (nodes[3], nodes[4]))
        ):
            material = _edge_kwargs(seed, source.graph_node_id, target.graph_node_id)
            material["idempotency_key"] = f"connected-edge-{index}"
            edge_ids.append(graph.append_edge_evaluation(db, **material).edge_id)

        connected = graph.connected_current_edge_ids(
            db,
            tenant_id=seed["tenant_id"],
            seed_edge_ids=(edge_ids[0],),
        )

        assert set(connected) == {edge_ids[0], edge_ids[1]}
        assert edge_ids[2] not in connected
    finally:
        db.close()
        db.bind.dispose()
