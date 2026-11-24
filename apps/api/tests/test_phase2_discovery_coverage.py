from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.models.discovery_canonical import DiscoveryScan
from app.db.session import Base
from app.services.control_coverage.discovery_coverage import calculate_discovery_coverage
from app.services.hmair.attribution_service import link_identity
from app.services.hmair.evidence_claim_service import persist_evidence_claim
from app.services.hmair.reachability_service import assert_reachability
from app.services.hmair.usage_service import persist_usage_fact
from test_phase2_asset_resolution_service import NOW, _asset, _claim_payload, _seed


def _db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine, autoflush=False, expire_on_commit=False)


def _covered_asset(db: Session, *, suffix: str = "coverage") -> tuple[dict[str, str], str]:
    seed = _seed(db, suffix=suffix)
    asset = _asset(db, seed)
    persist_evidence_claim(
        db,
        tenant_id=seed["tenant_id"],
        payload=_claim_payload(
            seed,
            subject_observation_id=None,
            subject_asset_id=asset.asset_id,
            idempotency_key=f"asset-coverage-{suffix}",
        ),
    )
    link_identity(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        identity_type="workload_identity",
        identity_reference_hash="1" * 64,
        access_state="active",
        evidence_node_id=seed["node_id"],
        confidence=0.9,
        verification_state="verified",
        usage_proven=True,
        first_observed_at=NOW,
        last_observed_at=NOW,
        idempotency_key=f"identity-coverage-{suffix}",
    )
    persist_usage_fact(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        actor_type="workload",
        actor_reference_hash="2" * 64,
        usage_state="active",
        event_count=5,
        first_observed_at=NOW,
        last_observed_at=NOW,
        source_surface="endpoint",
        evidence_node_id=seed["node_id"],
        confidence=0.9,
        verification_state="verified",
        freshness="fresh",
        telemetry_complete=True,
        methodology_id="tenant-usage-v1",
        limitations=(),
        idempotency_key=f"usage-coverage-{suffix}",
    )
    assert_reachability(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        target_category="model",
        target_reference_hash="3" * 64,
        reachability_state="verified",
        evidence_node_id=seed["node_id"],
        confidence=0.9,
        verification_state="verified",
        freshness="fresh",
        observed_usage=True,
        first_observed_at=NOW,
        last_observed_at=NOW,
        limitations=(),
        idempotency_key=f"reachability-coverage-{suffix}",
    )
    db.flush()
    return seed, asset.asset_id


def test_discovery_coverage_exposes_counts_but_withholds_scores_without_enterprise_denominator() -> None:
    db = _db()
    try:
        seed, asset_id = _covered_asset(db)
        result = calculate_discovery_coverage(
            db, tenant_id=seed["tenant_id"], now=NOW
        )

        assert result.denominator.status == "inferred"
        assert result.denominator.enterprise_denominator_complete is False
        assert result.denominator.known_assets == 1
        assert tuple(result.dimensions) == (
            "discovery",
            "identity",
            "usage",
            "authorization",
            "evidence",
            "containment",
            "bypass_detection",
        )
        for name in ("discovery", "identity", "usage", "evidence"):
            dimension = result.dimensions[name]
            assert dimension.covered_asset_ids == (asset_id,)
            assert dimension.score is None
            assert dimension.score_withheld_reason == "enterprise_denominator_not_established"
            assert dimension.methodology
            assert dimension.evidence_refs
        for name in ("authorization", "containment"):
            assert result.dimensions[name].not_covered_asset_ids == (asset_id,)
        assert result.dimensions["bypass_detection"].unknown_asset_ids == (asset_id,)
    finally:
        db.close()
        db.bind.dispose()


def test_enterprise_score_requires_explicit_fresh_complete_denominator() -> None:
    db = _db()
    try:
        seed, asset_id = _covered_asset(db, suffix="coverage-complete")
        scan = db.scalar(
            select(DiscoveryScan).where(
                DiscoveryScan.tenant_id == seed["tenant_id"]
            )
        )
        assert scan is not None
        scan.status = "complete"
        scan.completed_at = NOW
        scan.coverage_summary_json = {
            "confidence": "verified",
            "freshness": "fresh",
            "unsupported": [],
            "unknown": [],
            "denominator_complete": True,
            "enterprise_denominator_complete": True,
            "denominator_source": "authoritative_inventory_snapshot",
        }
        db.flush()

        result = calculate_discovery_coverage(
            db, tenant_id=seed["tenant_id"], now=NOW
        )

        assert result.denominator.status == "known"
        assert result.denominator.enterprise_denominator_complete is True
        assert result.denominator.evidence_ref == f"discovery_scan:{scan.scan_id}"
        for name in ("discovery", "identity", "usage", "evidence"):
            assert result.dimensions[name].covered_asset_ids == (asset_id,)
            assert result.dimensions[name].score == 100.0
            assert result.dimensions[name].score_withheld_reason is None
        for name in ("authorization", "containment", "bypass_detection"):
            assert result.dimensions[name].score == 0.0
            assert result.dimensions[name].score_withheld_reason is None
    finally:
        db.close()
        db.bind.dispose()


def test_missing_signals_are_uncovered_or_unknown_without_cross_tenant_leakage() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="coverage-gaps")
        asset = _asset(db, seed)
        other, _ = _covered_asset(db, suffix="coverage-other")
        db.flush()

        result = calculate_discovery_coverage(
            db, tenant_id=seed["tenant_id"], now=NOW
        )

        assert result.denominator.known_assets == 1
        assert result.dimensions["discovery"].unknown_asset_ids == (asset.asset_id,)
        for name in ("identity", "usage"):
            assert result.dimensions[name].not_covered_asset_ids == (asset.asset_id,)
            assert all(other["tenant_id"] not in ref for ref in result.dimensions[name].evidence_refs)
        for name in ("evidence", "authorization", "containment", "bypass_detection"):
            assert result.dimensions[name].unknown_asset_ids == (asset.asset_id,)
            assert all(other["tenant_id"] not in ref for ref in result.dimensions[name].evidence_refs)
    finally:
        db.close()
        db.bind.dispose()
