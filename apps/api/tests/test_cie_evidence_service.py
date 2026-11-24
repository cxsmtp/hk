from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.models.capability_inference import (
    DiscoveryCapabilityEvidence,
    DiscoveryCapabilityInferenceRun,
)
from app.db.session import Base
from app.services.hmair.cie.contracts import CapabilityEvaluation, CapabilityInferenceResult
from app.services.hmair.cie.evidence_service import (
    CIEPersistenceConflict,
    CIEPersistenceScopeError,
    CapabilityEvidenceService,
)
from test_phase2_asset_resolution_service import _seed


NOW = datetime(2026, 8, 16, 9, 0, tzinfo=timezone.utc)


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
        session.close()
        engine.dispose()


def _result(observation_id: str, *, confidence: float = 0.9) -> CapabilityInferenceResult:
    evaluation = CapabilityEvaluation(
        capability_id="filesystem_read",
        family="infrastructure",
        rule_id="observed-filesystem_read-v1",
        rule_version="1.0.0",
        calibration_version="conservative-caps-v1",
        confidence=confidence,
        supporting_signal_ids=("signal-a",),
        conflicting_signal_ids=(),
        unknown_predicates=("usage_context",),
        source_diversity=1,
        freshness="fresh",
        verification_state="partially_verified",
        last_validated_at=NOW,
        explanation="Direct file metadata supports read capability.",
        limitations=("single_source_only",),
        recommended_asset_type="unknown_ai_candidate",
        recommended_ecosystem="infrastructure",
    )
    return CapabilityInferenceResult(
        subject_reference_hash="a" * 64,
        observation_ids=(observation_id,),
        evaluations=(evaluation,),
        product_explanations=(),
        recommended_asset_type="unknown_ai_candidate",
        recommended_ecosystem="infrastructure",
        engine_version="cie-engine-1.0.0",
        catalog_version="2026.08.16.1",
        ruleset_version="2026.08.16.1",
        first_observed_at=NOW,
        last_observed_at=NOW,
        validated_at=NOW,
        limitations=("genome_disabled",),
    )


def test_persistence_is_append_only_tenant_scoped_and_idempotent(db: Session) -> None:
    seed = _seed(db, suffix="cie")
    service = CapabilityEvidenceService()
    first, evidence = service.persist_result(
        db,
        tenant_id=seed["tenant_id"],
        evidence_node_id=seed["node_id"],
        result=_result(seed["observation_id"]),
        idempotency_key="cie-run-a",
    )
    replay, replay_evidence = service.persist_result(
        db,
        tenant_id=seed["tenant_id"],
        evidence_node_id=seed["node_id"],
        result=_result(seed["observation_id"]),
        idempotency_key="cie-run-a",
    )
    assert replay.inference_run_id == first.inference_run_id
    assert replay_evidence[0].capability_evidence_id == evidence[0].capability_evidence_id
    assert db.scalar(select(func.count(DiscoveryCapabilityInferenceRun.inference_run_id))) == 1
    assert db.scalar(select(func.count(DiscoveryCapabilityEvidence.capability_evidence_id))) == 1

    with pytest.raises(CIEPersistenceConflict):
        service.persist_result(
            db,
            tenant_id=seed["tenant_id"],
            evidence_node_id=seed["node_id"],
            result=_result(seed["observation_id"], confidence=0.4),
            idempotency_key="cie-run-a",
        )


def test_persistence_rejects_cross_tenant_bundle_or_observation(db: Session) -> None:
    first = _seed(db, suffix="cie-a")
    second = _seed(db, suffix="cie-b")
    with pytest.raises(CIEPersistenceScopeError):
        CapabilityEvidenceService().persist_result(
            db,
            tenant_id=first["tenant_id"],
            evidence_node_id=second["node_id"],
            result=_result(first["observation_id"]),
            idempotency_key="cross-bundle",
        )
    with pytest.raises(CIEPersistenceScopeError):
        CapabilityEvidenceService().persist_result(
            db,
            tenant_id=first["tenant_id"],
            evidence_node_id=first["node_id"],
            result=_result(second["observation_id"]),
            idempotency_key="cross-observation",
        )

