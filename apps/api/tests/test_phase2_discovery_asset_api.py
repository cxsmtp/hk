from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.routers.discovery_assets import (
    get_asset_context,
    get_asset_detail,
    list_assets,
)
from app.api.routers.discovery_ecosystems import (
    get_discovery_coverage,
    get_estate_summary,
    list_discovery_findings,
    list_ecosystems,
    list_unknown_ai,
)
from app.db.models import *  # noqa: F401,F403
from app.db.session import Base
from app.services.hmair.discovery_finding_service import upsert_discovery_finding
from app.services.hmair.shadow_classification_service import (
    persist_shadow_classification,
)
from app.services.hmair.usage_service import persist_usage_fact
from test_phase2_asset_resolution_service import _asset, _seed


NOW = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)


def _db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine, autoflush=False, expire_on_commit=False)


def _ctx(tenant_id: str) -> SimpleNamespace:
    return SimpleNamespace(tenant=SimpleNamespace(id=tenant_id), user=None)


def _forbidden_context_keys(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            if key.casefold() in {
                "allow", "block", "decision", "authorized", "authorization"
            }:
                found.add(key)
            found |= _forbidden_context_keys(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            found |= _forbidden_context_keys(nested)
    return found


def _seed_intelligence(db: Session, *, suffix: str = "api") -> tuple[dict[str, str], str]:
    seed = _seed(db, suffix=suffix)
    asset = _asset(db, seed)
    asset.provider = "azure"
    asset.product = "foundry"
    asset.environment = "production"
    asset.approved_status = "unapproved"
    persist_usage_fact(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        actor_type="workload",
        actor_reference_hash="a" * 64,
        usage_state="active",
        event_count=12,
        first_observed_at=NOW - timedelta(days=3),
        last_observed_at=NOW,
        source_surface="cloud",
        evidence_node_id=seed["node_id"],
        confidence=0.9,
        verification_state="verified",
        freshness="fresh",
        telemetry_complete=True,
        methodology_id="tenant-policy-v1",
        limitations=(),
        idempotency_key=f"usage-{suffix}",
    )
    persist_shadow_classification(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        management_class="unmanaged",
        shadow_type="unmanaged_agent",
        severity="high",
        confidence=0.9,
        verification_state="verified",
        evidence_node_ids=(seed["node_id"],),
        first_observed_at=NOW,
        last_observed_at=NOW,
        methodology_id="phase2-shadow-v1",
        limitations=(),
        idempotency_key=f"shadow-{suffix}",
    )
    upsert_discovery_finding(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        finding_type="unmanaged_agent",
        severity="high",
        confidence=0.9,
        verification_state="verified",
        evidence_node_ids=(seed["node_id"],),
        first_seen_at=NOW,
        last_seen_at=NOW,
        remediation="Register the agent and assign an owner.",
        verification_action="Verify owner, model, tools, and runtime.",
        coverage_impact="Unmanaged agent authorization coverage is unknown.",
        dedupe_key=f"finding-{suffix}",
    )
    db.flush()
    return seed, asset.asset_id


def test_asset_intelligence_api_is_tenant_safe_and_progressive() -> None:
    db = _db()
    try:
        seed, asset_id = _seed_intelligence(db, suffix="primary-api")
        other, _ = _seed_intelligence(db, suffix="other-api")
        response = list_assets(
            asset_type=None,
            shadow_status=None,
            usage_state=None,
            verification_state=None,
            search=None,
            page=1,
            page_size=50,
            ctx=_ctx(seed["tenant_id"]),
            db=db,
        )
        assert response.total == 1
        item = response.items[0]
        assert item.asset_id == asset_id
        assert item.usage_state == "active"
        assert item.findings_open == 1
        assert item.shadow_type == "unmanaged_agent"
        assert other["tenant_id"] != seed["tenant_id"]

        detail = get_asset_detail(asset_id, ctx=_ctx(seed["tenant_id"]), db=db)
        assert detail.asset.asset_id == asset_id
        assert detail.usage[0].actor_type == "workload"
        assert detail.findings[0].coverage_impact.endswith("unknown.")

        context = get_asset_context(asset_id, ctx=_ctx(seed["tenant_id"]), db=db)
        assert context["asset"]["asset_id"] == asset_id
        assert context["usage"][0]["usage_state"] == "active"
        assert _forbidden_context_keys(context) == set()
    finally:
        db.close()
        db.bind.dispose()


def test_estate_ecosystems_unknowns_and_findings_use_canonical_assets() -> None:
    db = _db()
    try:
        seed, asset_id = _seed_intelligence(db, suffix="estate-api")
        ctx = _ctx(seed["tenant_id"])
        summary = get_estate_summary(ctx=ctx, db=db)
        assert summary.assets_total == 1
        assert summary.active_assets == 1
        assert summary.shadow_assets == 1
        assert summary.unknown_denominator is True

        ecosystems = list_ecosystems(page=1, page_size=50, ctx=ctx, db=db)
        assert ecosystems.total == 1
        assert ecosystems.items[0].provider == "azure"
        assert ecosystems.items[0].asset_ids == [asset_id]

        unknowns = list_unknown_ai(page=1, page_size=50, ctx=ctx, db=db)
        assert unknowns.total == 0

        findings = list_discovery_findings(
            status_filter=None,
            severity=None,
            page=1,
            page_size=50,
            ctx=ctx,
            db=db,
        )
        assert findings.total == 1
        assert findings.items[0].asset_id == asset_id

        coverage = get_discovery_coverage(ctx=ctx, db=db)
        assert coverage.denominator.status == "inferred"
        assert coverage.denominator.enterprise_denominator_complete is False
        assert coverage.dimensions["discovery"].score is None
        assert coverage.dimensions["usage"].covered_count == 1
    finally:
        db.close()
        db.bind.dispose()


def test_unknown_ai_queue_projects_unresolved_legacy_shadow_inventory_without_cross_tenant_leakage() -> None:
    db = _db()
    try:
        tenant_id = "legacy-shadow-tenant"
        db.add_all(
            [
                ShadowAIEntity(
                    tenant_id=tenant_id,
                    canonical_name="observed-legacy-ai.example",
                    discovery_status="discovered",
                    approved_status="unknown",
                    confidence_score=0.72,
                    ai_type="ai_application",
                    first_seen=NOW - timedelta(days=2),
                    last_seen=NOW,
                ),
                ShadowAIEntity(
                    tenant_id="other-tenant",
                    canonical_name="other-tenant-ai.example",
                    discovery_status="discovered",
                    approved_status="unknown",
                    confidence_score=0.99,
                    ai_type="ai_application",
                    first_seen=NOW,
                    last_seen=NOW,
                ),
                ShadowAIEntity(
                    tenant_id=tenant_id,
                    canonical_name="already-approved-ai.example",
                    discovery_status="promoted",
                    approved_status="approved",
                    confidence_score=0.99,
                    ai_type="ai_application",
                    first_seen=NOW,
                    last_seen=NOW,
                ),
            ]
        )
        db.flush()

        response = list_unknown_ai(page=1, page_size=50, ctx=_ctx(tenant_id), db=db)

        assert response.total == 1
        item = response.items[0]
        assert item.subject_kind == "legacy_shadow_entity"
        assert item.label == "observed-legacy-ai.example"
        assert item.probable_type == "ai_application"
        assert item.confidence == 0.72
        assert item.verification_state == "unknown"
        assert item.freshness == "unknown"
        assert item.evidence_node_id.startswith("legacy-shadow-ai-entity:")
        assert "legacy Shadow AI record" in item.required_action
    finally:
        db.close()
        db.bind.dispose()
