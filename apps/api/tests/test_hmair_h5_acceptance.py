from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.services.hmair.governance_contracts import (
    H5_CHANGE_EVENT_TYPES,
    H5_CONTROL_COVERAGE_DIMENSIONS,
    H5_FINDING_CATALOG,
    H5_REACHABILITY_STATES,
    H5_SHADOW_STATES,
    H5_USAGE_STATES,
    AcceptedGovernanceClaim,
    GovernanceAssetSnapshot,
    IncrementalAssetDigest,
)
from app.services.hmair.governance_projection_service import (
    classify_h5_shadow,
    build_h5_usage_views,
    derive_h5_change_events,
    project_accepted_claim_relationships,
    project_h5_reachability,
    project_h5_usage,
)
from app.services.hmair.continuous_enrichment_service import (
    create_incremental_rescan_from_plan,
    plan_incremental_enrichment,
)
from app.services.control_coverage.discovery_coverage import (
    calculate_discovery_coverage,
)
from app.services.hmair.discovery_finding_service import (
    upsert_h5_discovery_finding,
)
from app.services.hmair.evidence_claim_service import persist_evidence_claim
from test_phase2_asset_resolution_service import _claim_payload
from test_phase2_discovery_coverage import _covered_asset, _db
from app.db.models.discovery_canonical import DiscoveryScan
from sqlalchemy import select


NOW = datetime(2026, 9, 11, 8, 0, tzinfo=timezone.utc)
TENANT = "tenant-h5"
ASSET = "asset-h5"
EVIDENCE = ("evidence_node:node-h5",)


def test_h5_exact_closed_vocabularies() -> None:
    assert H5_USAGE_STATES == (
        "no_usage_observed",
        "historical_usage",
        "active_usage",
        "high_frequency_usage",
        "service_usage",
        "unknown_usage",
    )
    assert H5_SHADOW_STATES == (
        "approved",
        "approved_but_uncontrolled",
        "known_unapproved",
        "suspected_shadow",
        "confirmed_shadow",
        "personal_account",
        "owner_unknown",
        "unknown",
    )
    assert H5_REACHABILITY_STATES == (
        "configured", "observed", "inferred", "simulated", "blocked", "unknown"
    )
    assert H5_CONTROL_COVERAGE_DIMENSIONS == (
        "discovery",
        "identity",
        "usage",
        "authorization",
        "evidence",
        "containment",
        "bypass_detection",
    )
    assert H5_CHANGE_EVENT_TYPES == (
        "AI_ASSET_DISCOVERED",
        "AI_ASSET_CHANGED",
        "AI_ASSET_BECAME_ACTIVE",
        "AI_ASSET_OWNER_CHANGED",
        "AI_CAPABILITY_ADDED",
        "AI_USAGE_INCREASED",
        "AI_IDENTITY_CHANGED",
        "AI_REACHABILITY_CHANGED",
        "AI_FINGERPRINT_DRIFT",
        "SHADOW_AI_CONFIRMED",
        "CONTROL_COVERAGE_REDUCED",
    )
    assert tuple(H5_FINDING_CATALOG) == (
        "SHADOW_AI_CONFIRMED",
        "SUSPECTED_SHADOW_AI",
        "AI_ASSET_OWNER_UNKNOWN",
        "AI_USAGE_IDENTITY_UNKNOWN",
        "UNAPPROVED_AI_SAAS",
        "PERSONAL_AI_ACCOUNT",
        "UNAPPROVED_DEVELOPER_AI",
        "UNKNOWN_MCP_SERVER",
        "UNKNOWN_AI_RUNTIME",
        "UNPROTECTED_LLM_ROUTE",
        "UNPROTECTED_MCP_ROUTE",
        "AI_ENABLED_DATABASE_UNGOVERNED",
        "AI_ASSET_USAGE_WITHOUT_AUTHORIZATION",
        "AI_FINGERPRINT_DRIFT",
        "HIGH_RISK_AI_CAPABILITY_DISCOVERED",
        "DISCOVERY_SOURCE_STALE",
        "AI_ESTATE_BLIND_SPOT",
    )
    assert all(item.remediation and item.coverage_impact for item in H5_FINDING_CATALOG.values())


def test_usage_projection_preserves_scope_and_never_invents_activity() -> None:
    no_use = project_h5_usage(
        tenant_id=TENANT,
        asset_id=ASSET,
        legacy_usage_state="never_observed",
        actor_type="human",
        actor_reference_hash="1" * 64,
        event_count=0,
        first_observed_at=None,
        last_observed_at=None,
        telemetry_complete=True,
        business_unit_reference_hash="2" * 64,
        geography="AE-DU",
        environment="production",
        account_class="enterprise",
        governance_class="sanctioned",
        window_start=NOW - timedelta(days=30),
        window_end=NOW,
        evidence_refs=EVIDENCE,
        confidence=0.9,
    )
    assert no_use.state == "no_usage_observed"
    assert no_use.event_count == 0
    assert no_use.business_unit_reference_hash == "2" * 64
    assert no_use.geography == "AE-DU"

    service_use = project_h5_usage(
        tenant_id=TENANT,
        asset_id=ASSET,
        legacy_usage_state="active",
        actor_type="workload",
        actor_reference_hash="3" * 64,
        event_count=12,
        first_observed_at=NOW - timedelta(days=2),
        last_observed_at=NOW,
        telemetry_complete=True,
        business_unit_reference_hash=None,
        geography="unknown",
        environment="production",
        account_class="unknown",
        governance_class="unknown",
        window_start=NOW - timedelta(days=30),
        window_end=NOW,
        evidence_refs=EVIDENCE,
        confidence=0.8,
    )
    assert service_use.state == "service_usage"
    assert service_use.actor_class == "service_agent"

    views = build_h5_usage_views(
        tenant_id=TENANT, projections=(no_use, service_use)
    )
    assert views.assets_by_actor[0].asset_ids == (ASSET,)
    assert views.actors_by_asset[0].actor_reference_hashes == (
        "1" * 64,
        "3" * 64,
    )
    assert {
        aggregate.dimension for aggregate in views.aggregates
    } == {
        "business_unit",
        "geography",
        "environment",
        "time_window",
        "account_class",
        "governance_class",
        "actor_class",
    }

    unknown = project_h5_usage(
        tenant_id=TENANT,
        asset_id=ASSET,
        legacy_usage_state="active",
        actor_type="human",
        actor_reference_hash="4" * 64,
        event_count=1,
        first_observed_at=NOW,
        last_observed_at=NOW,
        telemetry_complete=False,
        business_unit_reference_hash=None,
        geography="unknown",
        environment="unknown",
        account_class="unknown",
        governance_class="unknown",
        window_start=NOW - timedelta(days=1),
        window_end=NOW,
        evidence_refs=EVIDENCE,
        confidence=0.3,
    )
    assert unknown.state == "unknown_usage"


@pytest.mark.parametrize(
    ("expected", "overrides"),
    (
        ("approved", {"approval_state": "approved", "control_state": "current"}),
        ("approved_but_uncontrolled", {"approval_state": "approved", "control_state": "gap"}),
        ("known_unapproved", {"approval_state": "unapproved", "observed_usage": False}),
        ("suspected_shadow", {"approval_state": "unapproved", "observed_usage": True, "independent_sources": ("endpoint",)}),
        ("confirmed_shadow", {"approval_state": "unapproved", "observed_usage": True, "independent_sources": ("endpoint", "gateway")}),
        ("personal_account", {"account_class": "personal", "observed_usage": True}),
        ("owner_unknown", {"owner_state": "unknown"}),
        ("unknown", {}),
    ),
)
def test_shadow_classification_is_explainable(expected: str, overrides: dict[str, object]) -> None:
    values: dict[str, object] = {
        "approval_state": "unknown",
        "control_state": "unknown",
        "owner_state": "known",
        "account_class": "unknown",
        "observed_usage": False,
        "independent_sources": (),
    }
    values.update(overrides)
    result = classify_h5_shadow(
        tenant_id=TENANT,
        asset_id=ASSET,
        evidence_refs=EVIDENCE,
        confidence=0.8,
        **values,
    )
    assert result.state == expected
    assert result.explanation
    assert result.change_condition
    assert result.evidence_refs == EVIDENCE


def test_reachability_keeps_six_states_and_control_capability_independent() -> None:
    for state in H5_REACHABILITY_STATES:
        projection = project_h5_reachability(
            tenant_id=TENANT,
            asset_id=ASSET,
            target_type="source_repository",
            target_reference_hash="5" * 64,
            state=state,
            source_surface="runtime",
            observed_usage=state == "observed",
            control_capability="inline" if state == "blocked" else "monitor_only",
            first_seen_at=NOW,
            last_seen_at=NOW,
            evidence_refs=EVIDENCE,
            confidence=0.9,
            limitations=(),
        )
        assert projection.state == state
        assert projection.control_capability in {
            "inline", "warn_only", "monitor_only", "external_required", "unknown"
        }
    # StrictContract deliberately sanitizes internal validator text.
    with pytest.raises(ValueError):
        project_h5_reachability(
            tenant_id=TENANT,
            asset_id=ASSET,
            target_type="source_repository",
            target_reference_hash="5" * 64,
            state="configured",
            source_surface="runtime",
            observed_usage=True,
            control_capability="monitor_only",
            first_seen_at=NOW,
            last_seen_at=NOW,
            evidence_refs=EVIDENCE,
            confidence=0.9,
            limitations=(),
        )


def _snapshot(**updates: object) -> GovernanceAssetSnapshot:
    values: dict[str, object] = {
        "tenant_id": TENANT,
        "asset_id": ASSET,
        "active": False,
        "owner_reference_hash": None,
        "identity_reference_hash": None,
        "capability_ids": (),
        "usage_count": 0,
        "reachability_digest": "0" * 64,
        "fingerprint_digest": "1" * 64,
        "shadow_state": "unknown",
        "coverage_states": tuple((name, "unknown") for name in H5_CONTROL_COVERAGE_DIMENSIONS),
        "evidence_refs": EVIDENCE,
        "observed_at": NOW,
    }
    values.update(updates)
    return GovernanceAssetSnapshot(**values)


def test_change_projection_emits_only_the_eleven_required_types() -> None:
    discovered = derive_h5_change_events(previous=None, current=_snapshot())
    assert tuple(item.event_type for item in discovered) == ("AI_ASSET_DISCOVERED",)

    previous = _snapshot()
    current = _snapshot(
        active=True,
        owner_reference_hash="6" * 64,
        identity_reference_hash="7" * 64,
        capability_ids=("model_inference",),
        usage_count=10,
        reachability_digest="8" * 64,
        fingerprint_digest="9" * 64,
        shadow_state="confirmed_shadow",
        coverage_states=(
            ("discovery", "not_covered"),
            *tuple((name, "unknown") for name in H5_CONTROL_COVERAGE_DIMENSIONS[1:]),
        ),
        observed_at=NOW + timedelta(minutes=1),
    )
    events = derive_h5_change_events(previous=previous, current=current)
    assert {item.event_type for item in events} == set(H5_CHANGE_EVENT_TYPES) - {
        "AI_ASSET_DISCOVERED"
    }
    assert all(item.evidence_refs == EVIDENCE for item in events)
    assert len({item.input_digest for item in events}) == len(events)


def test_only_accepted_canonical_claims_become_graph_relationships() -> None:
    accepted = AcceptedGovernanceClaim(
        tenant_id=TENANT,
        claim_id="claim-1",
        subject_asset_id=ASSET,
        target_type="mcp_server",
        target_reference_hash="a" * 64,
        relationship_type="reaches",
        admission_state="accepted",
        evidence_state="inferred",
        freshness="fresh",
        source_surface="runtime",
        evidence_refs=EVIDENCE,
        confidence=0.75,
        first_seen_at=NOW,
        last_seen_at=NOW,
    )
    rejected = accepted.model_copy(
        update={"claim_id": "claim-2", "admission_state": "rejected"}
    )
    relationships = project_accepted_claim_relationships(
        tenant_id=TENANT, claims=(accepted, rejected)
    )
    assert len(relationships) == 1
    assert relationships[0].evidence_state == "inferred"
    assert relationships[0].authorization_effect == "none"
    assert "raw_prompt" not in relationships[0].model_dump_json()

    other = accepted.model_copy(update={"tenant_id": "tenant-other"})
    with pytest.raises(ValueError, match="tenant scope"):
        project_accepted_claim_relationships(tenant_id=TENANT, claims=(other,))


def test_existing_control_coverage_exposes_all_seven_h5_dimensions() -> None:
    db = _db()
    try:
        seed, asset_id = _covered_asset(db, suffix="h5-seven-dimensions")
        for index, claim_type in enumerate(
            ("authorization_inline", "containment_control", "bypass_detection"),
            start=1,
        ):
            persist_evidence_claim(
                db,
                tenant_id=seed["tenant_id"],
                payload=_claim_payload(
                    seed,
                    claim_type=claim_type,
                    subject_observation_id=None,
                    subject_asset_id=asset_id,
                    idempotency_key=f"h5-coverage-{index}",
                ),
            )
        result = calculate_discovery_coverage(
            db, tenant_id=seed["tenant_id"], now=NOW
        )
        assert tuple(result.dimensions) == H5_CONTROL_COVERAGE_DIMENSIONS
        assert result.methodology_version == "discovery-coverage/2.0"
        assert all(
            dimension.covered_asset_ids == (asset_id,)
            for dimension in result.dimensions.values()
        )
        assert all(dimension.score is None for dimension in result.dimensions.values())
    finally:
        db.close()
        db.bind.dispose()


def test_h5_findings_use_the_existing_tenant_scoped_lifecycle() -> None:
    db = _db()
    try:
        seed, asset_id = _covered_asset(db, suffix="h5-finding")
        finding = upsert_h5_discovery_finding(
            db,
            tenant_id=seed["tenant_id"],
            asset_id=asset_id,
            finding_type="UNKNOWN_MCP_SERVER",
            confidence=0.8,
            verification_state="partially_verified",
            evidence_node_ids=(seed["node_id"],),
            first_seen_at=NOW,
            last_seen_at=NOW,
            dedupe_key="h5-unknown-mcp",
        )
        assert finding.finding_type == "UNKNOWN_MCP_SERVER"
        assert finding.remediation == H5_FINDING_CATALOG["UNKNOWN_MCP_SERVER"].remediation
        with pytest.raises(ValueError, match="approved catalog"):
            upsert_h5_discovery_finding(
                db,
                tenant_id=seed["tenant_id"],
                asset_id=asset_id,
                finding_type="INVENTED_FINDING",
                confidence=0.8,
                verification_state="partially_verified",
                evidence_node_ids=(seed["node_id"],),
                first_seen_at=NOW,
                last_seen_at=NOW,
                dedupe_key="h5-invalid",
            )
    finally:
        db.close()
        db.bind.dispose()


def test_incremental_enrichment_is_bounded_idempotent_and_skips_unchanged_assets() -> None:
    current = tuple(
        IncrementalAssetDigest(
            asset_id=f"asset-{index}", input_digest=f"{index:064x}"
        )
        for index in range(4)
    )
    previous = (
        IncrementalAssetDigest(asset_id="asset-0", input_digest=f"{0:064x}"),
        IncrementalAssetDigest(asset_id="asset-1", input_digest="f" * 64),
    )
    first = plan_incremental_enrichment(
        tenant_id=TENANT,
        current=current,
        previous=previous,
        requested_at=NOW,
        limit=2,
    )
    second = plan_incremental_enrichment(
        tenant_id=TENANT,
        current=current,
        previous=previous,
        requested_at=NOW,
        limit=2,
    )
    assert first == second
    assert first.selected_asset_ids == ("asset-1", "asset-2")
    assert first.remaining_changed == 1
    assert first.unchanged_asset_ids == ("asset-0",)
    assert first.scan_type == "incremental"
    assert len(first.cursor_digest) == 64
    assert len(first.idempotency_key) <= 128


def test_incremental_plan_reuses_the_existing_scan_lifecycle() -> None:
    db = _db()
    try:
        seed, asset_id = _covered_asset(db, suffix="h5-incremental")
        source = db.scalar(
            select(DiscoveryScan).where(
                DiscoveryScan.tenant_id == seed["tenant_id"]
            )
        )
        assert source is not None
        plan = plan_incremental_enrichment(
            tenant_id=seed["tenant_id"],
            current=(
                IncrementalAssetDigest(asset_id=asset_id, input_digest="a" * 64),
            ),
            previous=(
                IncrementalAssetDigest(asset_id=asset_id, input_digest="b" * 64),
            ),
            requested_at=NOW,
            limit=10,
        )
        result = create_incremental_rescan_from_plan(
            db,
            tenant_id=seed["tenant_id"],
            source_scan_id=source.scan_id,
            plan=plan,
            requested_by=None,
        )
        assert result.created is True
        assert result.scan.scan_type == "incremental"
        assert result.scan.rescan_of_scan_id == source.scan_id
        assert result.scan.scope_json["changed_asset_count"] == 1
        assert len(result.scan.scope_json["changed_assets_digest"]) == 64
        assert len(result.scan.scope_json["source_scan_hash"]) == 64

        replay = create_incremental_rescan_from_plan(
            db,
            tenant_id=seed["tenant_id"],
            source_scan_id=source.scan_id,
            plan=plan,
            requested_by=None,
        )
        assert replay.created is False
        assert replay.scan.scan_id == result.scan.scan_id
    finally:
        db.close()
        db.bind.dispose()


def test_h5_contracts_reject_raw_or_secret_material() -> None:
    with pytest.raises(Exception):
        AcceptedGovernanceClaim.model_validate(
            {
                "tenant_id": TENANT,
                "claim_id": "claim-secret",
                "subject_asset_id": ASSET,
                "target_type": "api",
                "target_reference_hash": "a" * 64,
                "relationship_type": "reaches",
                "admission_state": "accepted",
                "evidence_state": "observed",
                "freshness": "fresh",
                "source_surface": "runtime",
                "evidence_refs": EVIDENCE,
                "confidence": 0.8,
                "first_seen_at": NOW,
                "last_seen_at": NOW,
                "raw_prompt": "must never enter the graph",
            }
        )
