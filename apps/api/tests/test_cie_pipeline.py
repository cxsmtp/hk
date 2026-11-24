from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.models.discovery_canonical import DiscoveryObservation
from app.db.session import Base
from app.services.hmair.cie.contracts import CapabilityInferenceOptions
from app.services.hmair.cie.pipeline import CapabilityInferencePipeline
from test_phase2_asset_resolution_service import _seed


NOW = datetime(2026, 8, 16, 9, 0, tzinfo=timezone.utc)


def test_pipeline_runs_pre_asset_inference_in_one_session() -> None:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    db = Session(engine, autoflush=False, expire_on_commit=False)
    try:
        seed = _seed(db, suffix="cie-pipeline")
        observation = db.scalar(
            select(DiscoveryObservation).where(
                DiscoveryObservation.tenant_id == seed["tenant_id"],
                DiscoveryObservation.observation_id == seed["observation_id"],
            )
        )
        observation.capability_hints_json = ["filesystem_read"]
        result = CapabilityInferencePipeline().run(
            db,
            tenant_id=seed["tenant_id"],
            observation_ids=(seed["observation_id"],),
            validated_at=NOW,
            idempotency_key="pipeline-a",
            options=CapabilityInferenceOptions(
                genome=True,
                marketplace=False,
                dependency_graph=True,
                drift=True,
            ),
        )
        assert result.inference.recommended_asset_type == "unknown_ai_candidate"
        assert any(
            item.capability_id == "filesystem_read"
            for item in result.inference.evaluations
        )
        assert result.genome_id
        assert result.event_ids
        assert result.graph.edge_ids
    finally:
        db.close()
        engine.dispose()

