from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.models.discovery_resolution import DiscoveryResolutionGraphEdge
from app.db.session import Base
from app.services.hmair.cie.contracts import (
    CIESignalType,
    CapabilityEvaluation,
    CapabilityInferenceResult,
    NormalizedCapabilitySignal,
)
from app.services.hmair.cie.graph_service import CapabilityGraphService
from test_phase2_asset_resolution_service import _seed


NOW = datetime(2026, 8, 16, 9, 0, tzinfo=timezone.utc)


def _db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine, autoflush=False, expire_on_commit=False)


def _signal(observation_id: str) -> NormalizedCapabilitySignal:
    return NormalizedCapabilitySignal(
        signal_id="signal-a",
        tenant_id="tenant-cie-graph",
        observation_id=observation_id,
        collector_id="collector-cie-graph",
        source="endpoint",
        signal_type=CIESignalType.FILESYSTEM,
        timestamp=NOW,
        confidence=0.9,
        attributes={},
        facts=("capability:filesystem_read",),
        relationship_hints=(),
        evidence_reference="evidence://signal-a",
        evidence_hash="a" * 64,
        freshness="fresh",
        verification_state="partially_verified",
        source_trust="strong",
        contradiction_state="none",
        product_hint="renamed-ai-client",
    )


def _result(observation_id: str) -> CapabilityInferenceResult:
    return CapabilityInferenceResult(
        subject_reference_hash="b" * 64,
        observation_ids=(observation_id,),
        evaluations=(
            CapabilityEvaluation(
                capability_id="filesystem_read",
                family="infrastructure",
                rule_id="observed-filesystem_read-v1",
                rule_version="1.0.0",
                calibration_version="conservative-caps-v1",
                confidence=0.7,
                supporting_signal_ids=("signal-a",),
                conflicting_signal_ids=(),
                unknown_predicates=("usage_context",),
                source_diversity=1,
                freshness="fresh",
                verification_state="partially_verified",
                last_validated_at=NOW,
                explanation="File metadata supports read capability.",
                limitations=("single_source_only",),
                recommended_asset_type="unknown_ai_candidate",
                recommended_ecosystem="infrastructure",
            ),
        ),
        product_explanations=(),
        recommended_asset_type="unknown_ai_candidate",
        recommended_ecosystem="infrastructure",
        engine_version="cie-engine-1.0.0",
        catalog_version="2026.08.16.1",
        ruleset_version="2026.08.16.1",
        first_observed_at=NOW,
        last_observed_at=NOW,
        validated_at=NOW,
        limitations=(),
    )


def test_graph_projects_evidence_to_capability_without_product_identity_edges() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="cie-graph")
        projection = CapabilityGraphService().project(
            db,
            tenant_id=seed["tenant_id"],
            evidence_node_id=seed["node_id"],
            result=_result(seed["observation_id"]),
            signals=(_signal(seed["observation_id"]),),
        )
        assert len(projection.node_ids) == 2
        assert len(projection.edge_ids) == 1
        assert projection.dependency_refs == ()
        assert "no_explicit_dependency_evidence" in projection.limitations
        assert all("renamed-ai-client" not in item for item in projection.node_ids)
        edge = db.get(DiscoveryResolutionGraphEdge, projection.edge_ids[0])
        assert edge.source_surface == "endpoint"
        assert edge.collector_id == "collector-cie-graph"
    finally:
        db.close()
        db.bind.dispose()
