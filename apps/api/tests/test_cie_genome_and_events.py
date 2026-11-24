from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.session import Base
from app.services.hmair.cie.contracts import (
    CapabilityEvaluation,
    CapabilityGenomeContext,
    CapabilityInferenceResult,
)
from app.services.hmair.cie.evidence_service import CapabilityEvidenceService
from app.services.hmair.cie.event_service import CapabilityEventService
from app.services.hmair.cie.genome_service import CapabilityGenomeService
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


def _evaluation(capability_id: str, confidence: float) -> CapabilityEvaluation:
    return CapabilityEvaluation(
        capability_id=capability_id,
        family="infrastructure",
        rule_id=f"observed-{capability_id}-v1",
        rule_version="1.0.0",
        calibration_version="conservative-caps-v1",
        confidence=confidence,
        supporting_signal_ids=(f"signal-{capability_id}",),
        conflicting_signal_ids=(),
        unknown_predicates=(),
        source_diversity=2,
        freshness="fresh",
        verification_state="partially_verified",
        last_validated_at=NOW,
        explanation=f"Evidence supports {capability_id}.",
        limitations=(),
        recommended_asset_type="unknown_ai_candidate",
        recommended_ecosystem="infrastructure",
    )


def _result(observation_id: str, evaluations: tuple[CapabilityEvaluation, ...]) -> CapabilityInferenceResult:
    return CapabilityInferenceResult(
        subject_reference_hash="a" * 64,
        observation_ids=(observation_id,),
        evaluations=evaluations,
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


def test_genome_is_canonical_idempotent_and_drift_is_append_only() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="cie-genome")
        first_result = _result(seed["observation_id"], (_evaluation("filesystem_read", 0.8),))
        first_run, _ = CapabilityEvidenceService().persist_result(
            db,
            tenant_id=seed["tenant_id"],
            evidence_node_id=seed["node_id"],
            result=first_result,
            idempotency_key="genome-run-1",
        )
        genome_service = CapabilityGenomeService()
        first = genome_service.persist_snapshot(
            db,
            tenant_id=seed["tenant_id"],
            run=first_run,
            result=first_result,
            context=CapabilityGenomeContext(
                dependencies=("package:alpha",),
                permissions=(), reachability=(), usage=(), models=(), providers=(),
                runtime=("python",), data=(), marketplace=("market:a",), identity=(),
            ),
        )
        replay = genome_service.persist_snapshot(
            db,
            tenant_id=seed["tenant_id"],
            run=first_run,
            result=first_result,
            context=CapabilityGenomeContext(
                dependencies=("package:alpha",),
                permissions=(), reachability=(), usage=(), models=(), providers=(),
                runtime=("python",), data=(), marketplace=("market:a",), identity=(),
            ),
        )
        assert replay.genome_id == first.genome_id

        second_result = _result(
            seed["observation_id"],
            (
                _evaluation("filesystem_read", 0.9),
                _evaluation("filesystem_write", 0.7),
            ),
        )
        second_run, _ = CapabilityEvidenceService().persist_result(
            db,
            tenant_id=seed["tenant_id"],
            evidence_node_id=seed["node_id"],
            result=second_result,
            idempotency_key="genome-run-2",
        )
        second = genome_service.persist_snapshot(
            db,
            tenant_id=seed["tenant_id"],
            run=second_run,
            result=second_result,
            context=CapabilityGenomeContext(
                dependencies=("package:beta", "package:alpha"),
                permissions=(), reachability=(), usage=(), models=(), providers=(),
                runtime=("python",), data=(), marketplace=("market:b",), identity=(),
            ),
        )
        events = CapabilityEventService().record_drift(
            db,
            tenant_id=seed["tenant_id"],
            previous=first,
            current=second,
            evidence_references=(seed["node_id"],),
            occurred_at=NOW,
        )
        assert second.genome_version == 2
        assert second.supersedes_genome_id == first.genome_id
        event_types = {item.event_type for item in events}
        assert {
            "capability_added",
            "confidence_changed",
            "dependency_added",
            "marketplace_changed",
            "genome_changed",
        } <= event_types
        assert "dependency_removed" not in event_types
    finally:
        db.close()
        db.bind.dispose()


def test_reordering_genome_context_does_not_create_a_new_snapshot() -> None:
    context = CapabilityGenomeContext(
        dependencies=("b", "a", "a"),
        permissions=(), reachability=(), usage=(), models=(), providers=(),
        runtime=(), data=(), marketplace=(), identity=(),
    )
    assert context.dependencies == ("a", "b")

