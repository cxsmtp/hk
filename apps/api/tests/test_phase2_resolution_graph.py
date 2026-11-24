from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.models.ai_asset import DiscoveryAIAsset
from app.db.models.discovery_resolution import (
    DiscoveryAssetHypothesis,
    DiscoveryHypothesisTransition,
    DiscoveryResolutionGraphEdge,
    DiscoveryResolutionGraphNode,
)
from app.db.models.evidence import EvidenceNode
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.hmair.hypothesis_service import (
    HypothesisConflict,
    create_hypothesis,
    transition_hypothesis,
)
from app.services.hmair.resolution_graph_service import (
    ResolutionGraphScopeError,
    create_graph_edge,
    create_graph_node,
)


NOW = datetime(2026, 8, 15, 10, 0, tzinfo=timezone.utc)


@pytest.fixture
def db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine, autoflush=False, expire_on_commit=False)
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        engine.dispose()


def _seed_tenant(db: Session, suffix: str) -> tuple[str, str]:
    tenant_id = f"tenant-{suffix}"
    evidence_node_id = str(uuid4())
    db.add(Tenant(id=tenant_id, name=f"Tenant {suffix}", slug=f"tenant-{suffix}"))
    db.flush()
    db.add(
        EvidenceNode(
            id=evidence_node_id,
            tenant_id=tenant_id,
            correlation_id=f"phase2-{suffix}",
            node_type="bundle",
            signal_type="discovery.metadata",
            label="Privacy-safe discovery evidence",
            payload={"classification": "metadata_only"},
        )
    )
    db.flush()
    return tenant_id, evidence_node_id


def test_hypothesis_lifecycle_is_evidence_backed_and_append_audited(db: Session) -> None:
    tenant_id, evidence_id = _seed_tenant(db, "a")
    hypothesis = create_hypothesis(
        db,
        tenant_id=tenant_id,
        hypothesis_type="unknown_ai_workload",
        label="Unknown local inference process",
        candidate_key_hash="a" * 64,
        confidence=0.55,
        verification_state="inferred",
        freshness="fresh",
        contradiction_state="none",
        evidence_node_id=evidence_id,
        observed_at=NOW,
        idempotency_key="hypothesis-a",
    )
    replay = create_hypothesis(
        db,
        tenant_id=tenant_id,
        hypothesis_type="unknown_ai_workload",
        label="Unknown local inference process",
        candidate_key_hash="a" * 64,
        confidence=0.55,
        verification_state="inferred",
        freshness="fresh",
        contradiction_state="none",
        evidence_node_id=evidence_id,
        observed_at=NOW,
        idempotency_key="hypothesis-a",
    )
    assert replay.hypothesis_id == hypothesis.hypothesis_id
    assert hypothesis.state == "observed"

    for target, key in (
        ("hypothesized", "transition-1"),
        ("verifying", "transition-2"),
        ("confirmed", "transition-3"),
    ):
        transition_hypothesis(
            db,
            tenant_id=tenant_id,
            hypothesis_id=hypothesis.hypothesis_id,
            target_state=target,
            evidence_node_id=evidence_id,
            actor_id="phase2-verifier",
            reason=f"Evidence supports {target}",
            idempotency_key=key,
        )

    assert hypothesis.state == "confirmed"
    assert hypothesis.verification_state == "verified"
    assert db.scalar(
        select(func.count(DiscoveryHypothesisTransition.transition_id))
    ) == 4
    with pytest.raises(HypothesisConflict):
        transition_hypothesis(
            db,
            tenant_id=tenant_id,
            hypothesis_id=hypothesis.hypothesis_id,
            target_state="rejected",
            evidence_node_id=evidence_id,
            actor_id="phase2-verifier",
            reason="A terminal fact cannot be rewritten",
            idempotency_key="transition-invalid",
        )


def test_graph_rejects_cross_tenant_and_preserves_uncertain_edges(db: Session) -> None:
    first_tenant, first_evidence = _seed_tenant(db, "a")
    second_tenant, second_evidence = _seed_tenant(db, "b")
    observation_node = create_graph_node(
        db,
        tenant_id=first_tenant,
        node_class="observation",
        subject_reference="observation:opaque-a",
        idempotency_key="node-observation",
    )
    destination_node = create_graph_node(
        db,
        tenant_id=first_tenant,
        node_class="network_destination",
        subject_reference="destination:fingerprint-a",
        idempotency_key="node-destination",
    )
    foreign_node = create_graph_node(
        db,
        tenant_id=second_tenant,
        node_class="identity",
        subject_reference="identity:fingerprint-b",
        idempotency_key="node-foreign",
    )

    edge = create_graph_edge(
        db,
        tenant_id=first_tenant,
        from_node_id=observation_node.graph_node_id,
        to_node_id=destination_node.graph_node_id,
        edge_type="possibly_same_as",
        evidence_node_id=first_evidence,
        confidence=0.45,
        verification_state="inferred",
        freshness="fresh",
        contradiction_state="none",
        first_observed_at=NOW,
        last_observed_at=NOW,
        idempotency_key="edge-a",
    )
    assert edge.edge_type == "possibly_same_as"
    assert edge.verification_state == "inferred"
    with pytest.raises(ResolutionGraphScopeError):
        create_graph_edge(
            db,
            tenant_id=first_tenant,
            from_node_id=observation_node.graph_node_id,
            to_node_id=foreign_node.graph_node_id,
            edge_type="used_by",
            evidence_node_id=second_evidence,
            confidence=0.5,
            verification_state="inferred",
            freshness="fresh",
            contradiction_state="none",
            first_observed_at=NOW,
            last_observed_at=NOW,
            idempotency_key="edge-cross-tenant",
        )
    assert db.scalar(select(func.count(DiscoveryResolutionGraphEdge.edge_id))) == 1

