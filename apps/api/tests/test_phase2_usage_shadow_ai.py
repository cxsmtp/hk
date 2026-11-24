from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.models.discovery_intelligence import (
    DiscoveryAssetFinding,
    DiscoveryAssetUsageFact,
    DiscoveryShadowClassification,
)
from app.db.session import Base
from app.services.hmair.discovery_finding_service import upsert_discovery_finding
from app.services.hmair.shadow_classification_service import (
    classify_management_context,
    classify_shadow_ai,
    persist_shadow_classification,
)
from app.services.hmair.usage_service import (
    UsageMethodology,
    classify_usage,
    persist_usage_fact,
)
from test_phase2_asset_resolution_service import _asset, _seed


NOW = datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)


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


def test_usage_methodology_is_explicit_and_never_invents_activity() -> None:
    methodology = UsageMethodology(
        active_window_days=30,
        historical_after_days=90,
        occasional_max_events=5,
        high_usage_min_events=100,
        methodology_id="tenant-policy-v1",
    )
    assert classify_usage(
        event_count=0,
        first_observed_at=None,
        last_observed_at=None,
        telemetry_complete=False,
        now=NOW,
        methodology=methodology,
    ).state == "unknown"
    assert classify_usage(
        event_count=0,
        first_observed_at=None,
        last_observed_at=None,
        telemetry_complete=True,
        now=NOW,
        methodology=methodology,
    ).state == "never_observed"
    assert classify_usage(
        event_count=3,
        first_observed_at=NOW - timedelta(days=2),
        last_observed_at=NOW - timedelta(days=1),
        telemetry_complete=True,
        now=NOW,
        methodology=methodology,
    ).state == "occasional"
    assert classify_usage(
        event_count=25,
        first_observed_at=NOW - timedelta(days=20),
        last_observed_at=NOW - timedelta(days=1),
        telemetry_complete=True,
        now=NOW,
        methodology=methodology,
    ).state == "active"
    assert classify_usage(
        event_count=100,
        first_observed_at=NOW - timedelta(days=20),
        last_observed_at=NOW - timedelta(hours=1),
        telemetry_complete=True,
        now=NOW,
        methodology=methodology,
    ).state == "high_usage"
    historical = classify_usage(
        event_count=9,
        first_observed_at=NOW - timedelta(days=180),
        last_observed_at=NOW - timedelta(days=120),
        telemetry_complete=True,
        now=NOW,
        methodology=methodology,
    )
    assert historical.state == "historical"
    assert historical.methodology["historical_after_days"] == 90


def test_usage_fact_preserves_actor_truth_and_replay(db: Session) -> None:
    seed = _seed(db, suffix="usage")
    asset = _asset(db, seed)
    first = persist_usage_fact(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        actor_type="service",
        actor_reference_hash="a" * 64,
        usage_state="active",
        event_count=12,
        first_observed_at=NOW - timedelta(days=3),
        last_observed_at=NOW,
        source_surface="api_gateway",
        evidence_node_id=seed["node_id"],
        confidence=0.92,
        verification_state="verified",
        freshness="fresh",
        telemetry_complete=True,
        methodology_id="tenant-policy-v1",
        limitations=(),
        idempotency_key="usage-service-a",
    )
    replay = persist_usage_fact(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        actor_type="service",
        actor_reference_hash="a" * 64,
        usage_state="active",
        event_count=12,
        first_observed_at=NOW - timedelta(days=3),
        last_observed_at=NOW,
        source_surface="api_gateway",
        evidence_node_id=seed["node_id"],
        confidence=0.92,
        verification_state="verified",
        freshness="fresh",
        telemetry_complete=True,
        methodology_id="tenant-policy-v1",
        limitations=(),
        idempotency_key="usage-service-a",
    )
    assert replay.usage_fact_id == first.usage_fact_id
    assert first.actor_type == "service"
    assert first.actor_reference_hash == "a" * 64
    assert db.scalar(select(func.count(DiscoveryAssetUsageFact.usage_fact_id))) == 1

    with pytest.raises(ValueError):
        persist_usage_fact(
            db,
            tenant_id=seed["tenant_id"],
            asset_id=asset.asset_id,
            actor_type="human",
            actor_reference_hash="b" * 64,
            usage_state="active",
            event_count=12,
            first_observed_at=NOW - timedelta(days=3),
            last_observed_at=NOW,
            source_surface="browser",
            evidence_node_id=seed["node_id"],
            confidence=0.92,
            verification_state="verified",
            freshness="fresh",
            telemetry_complete=True,
            methodology_id="tenant-policy-v1",
            limitations=(),
            idempotency_key="usage-service-a",
        )


def test_personal_and_enterprise_classification_requires_corroboration() -> None:
    assert classify_management_context(
        evidence={"provider_account_type": "personal"}
    ).classification == "unknown"
    assert classify_management_context(
        evidence={
            "provider_account_type": "personal",
            "managed_device": True,
            "independent_sources": ("browser", "endpoint"),
        }
    ).classification == "personal"
    assert classify_management_context(
        evidence={
            "enterprise_sso": True,
            "provider_managed_tenant": True,
            "independent_sources": ("identity", "provider_admin"),
        }
    ).classification == "enterprise_managed"
    assert classify_management_context(
        evidence={
            "license_assigned": True,
            "independent_sources": ("identity",),
        }
    ).classification == "unknown"


def test_shadow_classification_handles_false_positives_and_unknowns() -> None:
    dormant = classify_shadow_ai(
        asset_type="sdk",
        approved_status="unknown",
        management_class="unknown",
        usage_state="never_observed",
        observed_signals=("dormant_dependency",),
        owner_state="unknown",
        capabilities=(),
    )
    assert dormant.shadow_type is None
    assert dormant.severity == "none"

    static_domain = classify_shadow_ai(
        asset_type="unknown_ai_candidate",
        approved_status="unknown",
        management_class="unknown",
        usage_state="unknown",
        observed_signals=("static_domain_only",),
        owner_state="unknown",
        capabilities=(),
    )
    assert static_domain.shadow_type is None
    assert static_domain.verification_state == "unknown"

    direct_model = classify_shadow_ai(
        asset_type="model_endpoint",
        approved_status="unapproved",
        management_class="unmanaged",
        usage_state="active",
        observed_signals=("direct_model_api", "endpoint_process"),
        owner_state="unknown",
        capabilities=("customer_data_access",),
    )
    assert direct_model.shadow_type == "direct_model_api"
    assert direct_model.severity == "high"
    assert direct_model.confidence > 0.8

    renamed_agent = classify_shadow_ai(
        asset_type="unknown_ai_candidate",
        approved_status="unapproved",
        management_class="unmanaged",
        usage_state="active",
        observed_signals=("model_traffic", "mcp_config", "running_process"),
        owner_state="unknown",
        capabilities=("tool_execution",),
    )
    assert renamed_agent.shadow_type == "unknown_ai_workload"
    assert "verification" in renamed_agent.required_action


def test_shadow_classification_and_finding_are_evidence_bound_and_deduplicated(
    db: Session,
) -> None:
    seed = _seed(db, suffix="shadow")
    asset = _asset(db, seed)
    classification = persist_shadow_classification(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        management_class="personal",
        shadow_type="personal_ai_on_managed_device",
        severity="medium",
        confidence=0.91,
        verification_state="verified",
        evidence_node_ids=(seed["node_id"],),
        first_observed_at=NOW,
        last_observed_at=NOW,
        methodology_id="phase2-shadow-v1",
        limitations=(),
        idempotency_key="shadow-classification-a",
    )
    assert classification.asset_id == asset.asset_id

    finding = upsert_discovery_finding(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        finding_type="personal_ai_on_managed_device",
        severity="medium",
        confidence=0.91,
        verification_state="verified",
        evidence_node_ids=(seed["node_id"],),
        first_seen_at=NOW,
        last_seen_at=NOW,
        remediation="Move the user to an approved enterprise AI workspace.",
        verification_action="Confirm account and device binding.",
        coverage_impact="Personal workspace activity is outside enterprise authorization.",
        dedupe_key="shadow-personal-a",
    )
    replay = upsert_discovery_finding(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        finding_type="personal_ai_on_managed_device",
        severity="medium",
        confidence=0.91,
        verification_state="verified",
        evidence_node_ids=(seed["node_id"],),
        first_seen_at=NOW,
        last_seen_at=NOW,
        remediation="Move the user to an approved enterprise AI workspace.",
        verification_action="Confirm account and device binding.",
        coverage_impact="Personal workspace activity is outside enterprise authorization.",
        dedupe_key="shadow-personal-a",
    )
    assert replay.finding_id == finding.finding_id
    assert replay.occurrence_count == 2
    assert db.scalar(select(func.count(DiscoveryAssetFinding.finding_id))) == 1
    assert db.scalar(
        select(func.count(DiscoveryShadowClassification.classification_id))
    ) == 1

