from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.session import Base
from app.services.hmair.erg.evidence_quality import EvidenceQualitySnapshots
from test_phase2_asset_resolution_service import _seed


NOW = datetime(2026, 8, 16, 16, 0, tzinfo=timezone.utc)


def _db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine, autoflush=False, expire_on_commit=False)


def test_quality_snapshots_are_exposed_idempotent_and_unknown_when_incomplete() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-quality")
        service = EvidenceQualitySnapshots()
        collector = service.record_collector(
            db,
            tenant_id=seed["tenant_id"],
            collector_id="collector-erg-quality",
            input_count=100,
            validated_count=95,
            freshness="fresh",
            signature_state="verified",
            calculated_at=NOW,
            idempotency_key="collector-quality",
        )
        assert collector.quality == 0.95
        assert collector.input_summary_json == {
            "input_count": 100,
            "validated_count": 95,
            "validation_ratio": 0.95,
        }
        assert service.record_collector(
            db,
            tenant_id=seed["tenant_id"],
            collector_id="collector-erg-quality",
            input_count=100,
            validated_count=95,
            freshness="fresh",
            signature_state="verified",
            calculated_at=NOW,
            idempotency_key="collector-quality",
        ).snapshot_id == collector.snapshot_id

        observation = service.record_observation(
            db,
            tenant_id=seed["tenant_id"],
            observation_id=seed["observation_id"],
            collector_quality_snapshot_id=collector.snapshot_id,
            factors={
                "completeness": 0.98,
                "provenance": 1.0,
                "schema_validation": 0.97,
            },
            freshness="fresh",
            signature_state="verified",
            validation_state="verified",
            calculated_at=NOW,
            idempotency_key="observation-quality",
        )
        assert observation.quality == 0.95
        assert observation.quality_factors_json["calculation"] == "minimum"

        unknown = service.record_observation(
            db,
            tenant_id=seed["tenant_id"],
            observation_id=seed["observation_id"],
            collector_quality_snapshot_id=collector.snapshot_id,
            factors={"completeness": None, "provenance": 1.0},
            freshness="unknown",
            signature_state="unknown",
            validation_state="unknown",
            calculated_at=NOW,
            idempotency_key="observation-quality-unknown",
        )
        assert unknown.quality is None
        assert "quality_factor_unknown" in unknown.limitations_json
    finally:
        db.close()
        db.bind.dispose()
