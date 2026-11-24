from __future__ import annotations

from datetime import datetime, timezone
from time import perf_counter

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.models.ai_asset import DiscoveryAIAsset
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.control_coverage.discovery_coverage import calculate_discovery_coverage
from app.services.control_graph_service import project_discovery_coverage_relationships
from app.services.findings_service import discovery_coverage_gap_candidates


NOW = datetime(2026, 8, 15, 14, 0, tzinfo=timezone.utc)


def _db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine, autoflush=False, expire_on_commit=False)


def _assets(db: Session, *, tenant_id: str, count: int, name_prefix: str) -> None:
    db.add(Tenant(id=tenant_id, name=tenant_id, slug=tenant_id))
    db.flush()
    db.add_all(
        DiscoveryAIAsset(
            asset_id=f"{tenant_id}-asset-{index:05d}",
            tenant_id=tenant_id,
            asset_type="agent",
            canonical_name=f"{name_prefix}-{index}",
            provider=None,
            product=None,
            framework=None,
            version=None,
            deployment_family="endpoint",
            technical_surface="runtime",
            environment="production",
            approved_status="unknown",
            lifecycle_status="unknown",
            shadow_ai_status="unknown",
            first_seen_at=NOW,
            last_seen_at=NOW,
            resolution_confidence=0.0,
            evidence_bundle_id=f"evidence-{tenant_id}-{index:05d}",
            projection_version=1,
        )
        for index in range(count)
    )
    db.flush()


def test_discovery_coverage_hard_fails_cross_tenant_projection_leakage() -> None:
    db = _db()
    try:
        _assets(db, tenant_id="tenant-a", count=11, name_prefix="tenant-a-secret")
        _assets(db, tenant_id="tenant-b", count=7, name_prefix="tenant-b-secret")

        projection = calculate_discovery_coverage(
            db, tenant_id="tenant-a", now=NOW
        )
        serialized = repr(projection)

        assert projection.denominator.known_assets == 11
        assert all(
            asset_id.startswith("tenant-a-")
            for dimension in projection.dimensions.values()
            for asset_id in (
                *dimension.covered_asset_ids,
                *dimension.not_covered_asset_ids,
                *dimension.unknown_asset_ids,
            )
        )
        assert "tenant-b-secret" not in serialized
        assert "tenant-b-asset" not in serialized
    finally:
        db.close()
        db.bind.dispose()


def test_1000_asset_projection_is_linear_bounded_and_does_not_expose_names() -> None:
    db = _db()
    try:
        _assets(
            db,
            tenant_id="tenant-scale",
            count=1000,
            name_prefix="sk-live-secret-value-must-not-project",
        )
        started = perf_counter()
        projection = calculate_discovery_coverage(
            db, tenant_id="tenant-scale", now=NOW
        )
        relationships = project_discovery_coverage_relationships(projection)
        candidates = discovery_coverage_gap_candidates(projection)
        elapsed_ms = (perf_counter() - started) * 1000.0

        assert projection.denominator.status == "inferred"
        assert projection.denominator.known_assets == 1000
        assert projection.dimensions["discovery"].unknown_count == 1000
        assert projection.dimensions["identity"].not_covered_count == 1000
        assert projection.dimensions["usage"].not_covered_count == 1000
        assert projection.dimensions["authorization"].unknown_count == 1000
        assert projection.dimensions["evidence"].unknown_count == 1000
        assert projection.dimensions["containment"].unknown_count == 1000
        assert projection.dimensions["bypass_detection"].unknown_count == 1000
        assert len(relationships) == 7000
        assert len(candidates) == 7000
        assert elapsed_ms < 5000.0
        assert "sk-live-secret-value" not in repr(relationships)
        assert "sk-live-secret-value" not in repr(candidates)
        assert all(item["authorization_effect"] == "none" for item in relationships)
        assert all(item["auto_persist"] is False for item in candidates)
    finally:
        db.close()
        db.bind.dispose()


def test_unknown_enterprise_denominator_never_produces_a_numeric_score() -> None:
    db = _db()
    try:
        _assets(db, tenant_id="tenant-unknown", count=3, name_prefix="asset")
        projection = calculate_discovery_coverage(
            db, tenant_id="tenant-unknown", now=NOW
        )
        assert projection.denominator.enterprise_denominator_complete is False
        assert {item.score for item in projection.dimensions.values()} == {None}
        assert {
            item.score_withheld_reason for item in projection.dimensions.values()
        } == {"enterprise_denominator_not_established"}
    finally:
        db.close()
        db.bind.dispose()
