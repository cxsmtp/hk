from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import NAMESPACE_URL, uuid5

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.models.activity_audit import AIAction, AISession
from app.db.models.discovery_resolution import (
    DiscoveryResolutionGraphEdge,
    DiscoveryResolutionGraphNode,
)
from app.db.models.discovery_intelligence import DiscoveryShadowClassification
from app.db.models.evidence import DecisionReceipt
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.discovery_attribution import (
    DiscoveryAssetIdentityLink,
    DiscoveryAssetReachability,
)
from app.db.session import Base
from app.services.hmair.capability_assertion_service import persist_capability_assertion
from app.services.hmair.contracts import AICapabilityAssertionCreate
from app.services.hmair.evidence_claim_service import persist_evidence_claim
from app.services.hmair.exposure.contracts import (
    ExposureDimension,
    ExposureExtent,
    VerificationStatus,
)
from app.services.hmair.exposure.input_assembler import ExposureInputAssembler
from app.services.hmair.exposure.reasoning_service import ExposureReasoningService
from app.services.hmair.exposure.source_reader import (
    ExposureAssetUnavailable,
    ExposureSourceReader,
    _erg_state,
)
from app.services.control_coverage.path_projection import (
    runtime_event_candidate,
    upsert_path,
)
from test_phase2_asset_resolution_service import (
    NOW as SEED_NOW,
    _asset,
    _claim_payload,
    _seed,
)


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)


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


def _seed_asset_sources(db: Session, *, suffix: str):
    seed = _seed(db, suffix=suffix)
    asset = _asset(db, seed)
    claim = persist_evidence_claim(
        db,
        tenant_id=seed["tenant_id"],
        payload=_claim_payload(
            seed,
            subject_observation_id=None,
            subject_asset_id=asset.asset_id,
            idempotency_key=f"exposure-claim-{suffix}",
            observed_at=SEED_NOW,
        ),
    )
    capability = persist_capability_assertion(
        db,
        tenant_id=seed["tenant_id"],
        payload=AICapabilityAssertionCreate(
            asset_id=asset.asset_id,
            source_observation_id=seed["observation_id"],
            evidence_claim_id=claim.claim_id,
            name="filesystem_write",
            state="observed",
            confidence=0.93,
            first_observed_at=NOW,
            last_observed_at=NOW,
            extractor_version="exposure-test-v1",
            supersedes_capability_id=None,
        ),
    )
    capability.verification_state = "verified"
    capability.freshness = "fresh"
    reachability = DiscoveryAssetReachability(
        reachability_id=f"reachability-{suffix}",
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        target_category="filesystem",
        target_reference_hash="a" * 64,
        reachability_state="verified",
        evidence_node_id=seed["node_id"],
        confidence=0.91,
        verification_state="verified",
        freshness="fresh",
        observed_usage=True,
        first_observed_at=NOW,
        last_observed_at=NOW,
        limitations_json=[],
        idempotency_key=f"reachability-{suffix}",
        input_digest="b" * 64,
    )
    identity = DiscoveryAssetIdentityLink(
        identity_link_id=f"identity-{suffix}",
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        identity_type="workload_identity",
        identity_reference_hash="c" * 64,
        access_state="active",
        evidence_node_id=seed["node_id"],
        confidence=0.89,
        verification_state="verified",
        usage_proven=True,
        first_observed_at=NOW,
        last_observed_at=NOW,
        idempotency_key=f"identity-{suffix}",
        input_digest="d" * 64,
    )
    db.add_all([reachability, identity])
    db.flush()
    return seed, asset, capability


def _seed_exact_action_path(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    evidence_node_id: str,
    evidence_bundle_id: str,
    action_id: str,
    extra_source_refs: tuple[str, ...] = (),
) -> tuple[AIAction, ControlCoveragePath]:
    session = AISession(
        session_id=f"session-{action_id}",
        tenant_id=tenant_id,
        source_surface="runtime",
        ai_app="Synthetic governed runtime",
        ai_model="test-model",
        start_time=NOW,
        total_actions=1,
        risk_score=0.0,
        status="active",
        metadata_json={},
    )
    action = AIAction(
        action_id=action_id,
        tenant_id=tenant_id,
        session_id=session.session_id,
        evidence_node_id=evidence_node_id,
        evidence_bundle_id=evidence_bundle_id,
        timestamp=NOW,
        action_type="file_write",
        ai_app="Synthetic governed runtime",
        ai_model="test-model",
        data_classification="restricted",
        sensitivity_score=1.0,
        enforcement_action="blocked",
        semantic_drift_score=0.0,
        risk_score=1.0,
        metadata_json={"discovery_asset_ref": asset_id},
    )
    path = ControlCoveragePath(
        tenant_id=tenant_id,
        path_key=str(uuid5(NAMESPACE_URL, f"path:{tenant_id}:{action_id}")),
        key_version="1.0",
        asset_ref=f"discovery_asset:{asset_id}",
        identity_type="service_identity",
        identity_ref=f"service_identity:{action_id}",
        runtime_ref="model:test-model",
        deployment_surface_id=None,
        deployment_surface_ref="source_surface:runtime",
        destination_type="resource",
        destination_ref=f"resource:{action_id}",
        lifecycle_status="active",
        source_refs=[f"ai_action:{action_id}", *extra_source_refs],
        first_seen_at=NOW,
        last_seen_at=NOW,
    )
    db.add_all([session, action, path])
    db.flush()
    return action, path


def test_reader_returns_only_exact_tenant_asset_sources(db: Session) -> None:
    seed, asset, capability = _seed_asset_sources(db, suffix="primary")
    other, _, _ = _seed_asset_sources(db, suffix="other")

    snapshot = ExposureSourceReader().read(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        as_of=NOW,
    )

    assert snapshot.asset.asset_id == asset.asset_id
    assert capability.capability_id in snapshot.source_ids
    assert all(item.tenant_id == seed["tenant_id"] for item in snapshot.raw_sources)
    assert other["tenant_id"] != seed["tenant_id"]


def test_reader_normalizes_persisted_mcp_capability_case_for_catalog_matching(
    db: Session,
) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="mcp-selector")
    claim = persist_evidence_claim(
        db,
        tenant_id=seed["tenant_id"],
        payload=_claim_payload(
            seed,
            subject_observation_id=None,
            subject_asset_id=asset.asset_id,
            idempotency_key="exposure-mcp-selector-claim",
            observed_at=SEED_NOW,
        ),
    )
    capability = persist_capability_assertion(
        db,
        tenant_id=seed["tenant_id"],
        payload=AICapabilityAssertionCreate(
            asset_id=asset.asset_id,
            source_observation_id=seed["observation_id"],
            evidence_claim_id=claim.claim_id,
            name="MCP_client",
            state="observed",
            confidence=0.93,
            first_observed_at=NOW,
            last_observed_at=NOW,
            extractor_version="exposure-test-v1",
            supersedes_capability_id=None,
        ),
    )
    capability.verification_state = "verified"
    capability.freshness = "fresh"
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )

    mcp = next(
        item
        for item in snapshot.raw_sources
        if item.source_id == capability.capability_id
    )
    assert mcp.state == "mcp_client"


def test_cross_tenant_asset_is_tenant_safe_unavailable(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="scope-a")
    other, _, _ = _seed_asset_sources(db, suffix="scope-b")
    with pytest.raises(ExposureAssetUnavailable, match="asset is unavailable"):
        ExposureSourceReader().read(
            db,
            tenant_id=other["tenant_id"],
            asset_id=asset.asset_id,
            as_of=NOW,
        )
    assert seed["tenant_id"] != other["tenant_id"]


def test_name_only_action_is_not_bound_to_asset(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="name-only")
    session = AISession(
        session_id="session-name-only",
        tenant_id=seed["tenant_id"],
        source_surface="browser",
        ai_app=asset.canonical_name,
        ai_model="same-display-name-only",
        start_time=NOW,
        total_actions=1,
        risk_score=1.0,
        status="active",
        metadata_json={},
    )
    action = AIAction(
        action_id="unbound-name-only-action",
        tenant_id=seed["tenant_id"],
        session_id=session.session_id,
        timestamp=NOW,
        action_type="file_write",
        ai_app=asset.canonical_name,
        ai_model="same-display-name-only",
        data_classification="restricted",
        sensitivity_score=1.0,
        enforcement_action="blocked",
        semantic_drift_score=0.0,
        risk_score=1.0,
        metadata_json={},
    )
    db.add_all([session, action])
    db.flush()
    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    assert action.action_id not in snapshot.source_ids
    assert all(item.dimension is not ExposureDimension.AI_ACTION for item in snapshot.raw_sources)


def test_reader_enforces_per_authority_bound_and_reports_truncation(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="bounded")
    db.add(
        DiscoveryAssetReachability(
            reachability_id="reachability-bounded-second",
            tenant_id=seed["tenant_id"],
            asset_id=asset.asset_id,
            target_category="internet",
            target_reference_hash="e" * 64,
            reachability_state="observed",
            evidence_node_id=seed["node_id"],
            confidence=0.8,
            verification_state="partially_verified",
            freshness="fresh",
            observed_usage=False,
            first_observed_at=NOW,
            last_observed_at=NOW,
            limitations_json=[],
            idempotency_key="reachability-bounded-second",
            input_digest="f" * 64,
        )
    )
    db.flush()
    statements: list[str] = []

    def record_query(
        _connection,
        _cursor,
        statement: str,
        _parameters,
        _context,
        _executemany: bool,
    ) -> None:
        if "discovery_asset_reachability" in statement.casefold():
            statements.append(statement)

    engine = db.get_bind()
    event.listen(engine, "before_cursor_execute", record_query)
    try:
        snapshot = ExposureSourceReader(max_records_per_authority=1).read(
            db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
        )
    finally:
        event.remove(engine, "before_cursor_execute", record_query)
    reachability = [
        item for item in snapshot.raw_sources
        if item.dimension is ExposureDimension.REACHABILITY
    ]
    assert len(reachability) == 1
    assert snapshot.truncated is True
    assert statements
    assert all(" LIMIT " in statement.upper() for statement in statements)


def test_exact_erg_permission_edge_is_bound_to_asset(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="erg-permission")
    asset_node_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:asset"))
    permission_node_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:permission"))
    edge_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:permission-edge"))
    db.add_all(
        [
            DiscoveryResolutionGraphNode(
                graph_node_id=asset_node_id,
                tenant_id=seed["tenant_id"],
                node_class="ai_asset",
                subject_reference=asset.asset_id,
                idempotency_key=f"asset-node-{asset.asset_id}",
                input_digest="1" * 64,
                created_at=NOW,
            ),
            DiscoveryResolutionGraphNode(
                graph_node_id=permission_node_id,
                tenant_id=seed["tenant_id"],
                node_class="permission",
                subject_reference="write",
                idempotency_key=f"permission-node-{asset.asset_id}",
                input_digest="2" * 64,
                created_at=NOW,
            ),
        ]
    )
    db.flush()
    db.add(
        DiscoveryResolutionGraphEdge(
            edge_id=edge_id,
            tenant_id=seed["tenant_id"],
            from_node_id=asset_node_id,
            to_node_id=permission_node_id,
            edge_type="accesses",
            evidence_node_id=seed["node_id"],
            collector_id="identity-collector",
            source_surface="identity",
            signal_class="permission",
            base_confidence=0.9,
            observation_quality_factor=1.0,
            collector_quality_factor=1.0,
            confidence=0.9,
            relationship_weight=1.0,
            relationship_rule_id="permission-binding",
            relationship_rule_version="1.0.0",
            decay_policy_id="permission-freshness",
            decay_policy_version="1.0.0",
            verification_state="verified",
            freshness="fresh",
            contradiction_state="none",
            first_observed_at=NOW,
            last_observed_at=NOW,
            last_validated_at=NOW,
            edge_schema_version="1.0",
            edge_sequence=1,
            predecessor_edge_id=None,
            idempotency_key=f"permission-edge-{asset.asset_id}",
            input_digest="3" * 64,
        )
    )
    db.flush()
    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    permission = [
        item for item in snapshot.raw_sources
        if item.dimension is ExposureDimension.PERMISSION
    ]
    assert [item.source_id for item in permission] == [edge_id]
    assert permission[0].state == "write"
    assert permission[0].related_source_refs == (f"erg_node:{permission_node_id}",)


def test_oversized_persisted_source_refs_are_bounded_and_withhold_exact_results(
    db: Session,
) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="bounded-source-refs")
    db.add(
        DiscoveryShadowClassification(
            classification_id=str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:shadow")),
            tenant_id=seed["tenant_id"],
            asset_id=asset.asset_id,
            management_class="unmanaged",
            shadow_type="unknown_ai_workload",
            severity="high",
            confidence=0.9,
            verification_state="verified",
            primary_evidence_node_id=seed["node_id"],
            evidence_node_ids_json=[f"e{index:02d}" for index in range(65)],
            first_observed_at=NOW,
            last_observed_at=NOW,
            methodology_id="shadow-test/1.0",
            limitations_json=[],
            idempotency_key=f"bounded-source-refs-{asset.asset_id}",
            input_digest="5" * 64,
        )
    )
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    projection = ExposureReasoningService().project(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    shadow = next(
        item for item in snapshot.raw_sources
        if item.source_type == "shadow_classification"
    )

    assert len(shadow.evidence_refs) == 64
    assert snapshot.truncated is True
    assert projection.truncated is True
    assert all(item.extent is ExposureExtent.UNKNOWN for item in projection.exposures)


def test_unrecognized_asset_governance_is_unknown_not_verified_authority(
    db: Session,
) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="malformed-governance")
    asset.approved_status = "malformed_governance"
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    projection = ExposureReasoningService().project(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    governance = next(
        item for item in snapshot.raw_sources
        if item.source_type == "discovery_asset"
        and item.dimension is ExposureDimension.GOVERNANCE
    )

    assert snapshot.asset.governance_state == "unknown"
    assert governance.state == "unknown"
    assert governance.verification_status is VerificationStatus.UNKNOWN
    assert "unrecognized_governance_state" in governance.limitations
    assert all(item.extent is ExposureExtent.UNKNOWN for item in projection.exposures)


def test_non_authoritative_erg_relationship_cannot_create_permission_authority(
    db: Session,
) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="erg-non-authoritative")
    asset_node_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:na-asset"))
    permission_node_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:na-permission"))
    edge_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:na-edge"))
    db.add_all(
        [
            DiscoveryResolutionGraphNode(
                graph_node_id=asset_node_id,
                tenant_id=seed["tenant_id"],
                node_class="ai_asset",
                subject_reference=asset.asset_id,
                idempotency_key=f"na-asset-{asset.asset_id}",
                input_digest="c" * 64,
                created_at=NOW,
            ),
            DiscoveryResolutionGraphNode(
                graph_node_id=permission_node_id,
                tenant_id=seed["tenant_id"],
                node_class="permission",
                subject_reference="admin",
                idempotency_key=f"na-permission-{asset.asset_id}",
                input_digest="d" * 64,
                created_at=NOW,
            ),
        ]
    )
    db.flush()
    db.add(
        DiscoveryResolutionGraphEdge(
            edge_id=edge_id,
            tenant_id=seed["tenant_id"],
            from_node_id=asset_node_id,
            to_node_id=permission_node_id,
            edge_type="contradicts",
            evidence_node_id=seed["node_id"],
            collector_id="erg-collector",
            source_surface="erg",
            signal_class="permission",
            base_confidence=0.99,
            observation_quality_factor=1.0,
            collector_quality_factor=1.0,
            confidence=0.99,
            relationship_weight=1.0,
            relationship_rule_id="non-authoritative-test",
            relationship_rule_version="1.0.0",
            decay_policy_id="freshness",
            decay_policy_version="1.0.0",
            verification_state="verified",
            freshness="fresh",
            contradiction_state="none",
            first_observed_at=NOW,
            last_observed_at=NOW,
            last_validated_at=NOW,
            edge_schema_version="1.0",
            edge_sequence=1,
            predecessor_edge_id=None,
            idempotency_key=f"na-edge-{asset.asset_id}",
            input_digest="e" * 64,
        )
    )
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )

    assert edge_id not in snapshot.source_ids
    assert all(
        not (
            item.dimension is ExposureDimension.PERMISSION
            and item.state == "admin"
        )
        for item in snapshot.raw_sources
    )


def test_historical_erg_predecessor_cannot_retain_verified_permission(
    db: Session,
) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="erg-current-tip")
    asset_node_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:tip-asset"))
    permission_node_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:tip-permission"))
    predecessor_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:tip-predecessor"))
    successor_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:tip-successor"))
    later = NOW + timedelta(minutes=1)
    db.add_all(
        [
            DiscoveryResolutionGraphNode(
                graph_node_id=asset_node_id,
                tenant_id=seed["tenant_id"],
                node_class="ai_asset",
                subject_reference=asset.asset_id,
                idempotency_key=f"tip-asset-{asset.asset_id}",
                input_digest="1" * 64,
                created_at=NOW,
            ),
            DiscoveryResolutionGraphNode(
                graph_node_id=permission_node_id,
                tenant_id=seed["tenant_id"],
                node_class="permission",
                subject_reference="admin",
                idempotency_key=f"tip-permission-{asset.asset_id}",
                input_digest="2" * 64,
                created_at=NOW,
            ),
        ]
    )
    db.flush()
    common = {
        "tenant_id": seed["tenant_id"],
        "from_node_id": asset_node_id,
        "to_node_id": permission_node_id,
        "edge_type": "accesses",
        "evidence_node_id": seed["node_id"],
        "collector_id": "erg-collector",
        "source_surface": "erg",
        "signal_class": "permission",
        "base_confidence": 0.9,
        "observation_quality_factor": 1.0,
        "collector_quality_factor": 1.0,
        "relationship_weight": 1.0,
        "relationship_rule_id": "permission-binding",
        "relationship_rule_version": "1.0.0",
        "decay_policy_id": "freshness",
        "decay_policy_version": "1.0.0",
        "first_observed_at": NOW,
        "edge_schema_version": "1.0",
    }
    db.add(
        DiscoveryResolutionGraphEdge(
            **common,
            edge_id=predecessor_id,
            confidence=0.9,
            verification_state="verified",
            freshness="fresh",
            contradiction_state="none",
            last_observed_at=NOW,
            last_validated_at=NOW,
            edge_sequence=1,
            predecessor_edge_id=None,
            idempotency_key=f"tip-predecessor-{asset.asset_id}",
            input_digest="3" * 64,
        )
    )
    db.flush()
    db.add(
        DiscoveryResolutionGraphEdge(
            **common,
            edge_id=successor_id,
            confidence=0.0,
            verification_state="unknown",
            freshness="fresh",
            contradiction_state="unknown",
            last_observed_at=later,
            last_validated_at=later,
            edge_sequence=2,
            predecessor_edge_id=predecessor_id,
            idempotency_key=f"tip-successor-{asset.asset_id}",
            input_digest="4" * 64,
        )
    )
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=later
    )
    permission = tuple(
        item for item in snapshot.raw_sources
        if item.dimension is ExposureDimension.PERMISSION
    )

    assert predecessor_id not in snapshot.source_ids
    assert [item.source_id for item in permission] == [successor_id]
    assert permission[0].verification_status is VerificationStatus.UNKNOWN


def test_malformed_erg_timestamp_is_isolated_and_projection_stays_safe(
    db: Session,
) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="erg-malformed-clock")
    asset_node_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:clock-asset"))
    permission_node_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:clock-permission"))
    edge_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:clock-edge"))
    db.add_all(
        [
            DiscoveryResolutionGraphNode(
                graph_node_id=asset_node_id,
                tenant_id=seed["tenant_id"],
                node_class="ai_asset",
                subject_reference=asset.asset_id,
                idempotency_key=f"clock-asset-{asset.asset_id}",
                input_digest="5" * 64,
                created_at=NOW,
            ),
            DiscoveryResolutionGraphNode(
                graph_node_id=permission_node_id,
                tenant_id=seed["tenant_id"],
                node_class="permission",
                subject_reference="admin",
                idempotency_key=f"clock-permission-{asset.asset_id}",
                input_digest="6" * 64,
                created_at=NOW,
            ),
        ]
    )
    db.flush()
    db.add(
        DiscoveryResolutionGraphEdge(
            edge_id=edge_id,
            tenant_id=seed["tenant_id"],
            from_node_id=asset_node_id,
            to_node_id=permission_node_id,
            edge_type="accesses",
            evidence_node_id=seed["node_id"],
            collector_id="erg-collector",
            source_surface="erg",
            signal_class="permission",
            base_confidence=0.9,
            observation_quality_factor=1.0,
            collector_quality_factor=1.0,
            confidence=0.9,
            relationship_weight=1.0,
            relationship_rule_id="malformed-clock",
            relationship_rule_version="1.0.0",
            decay_policy_id="freshness",
            decay_policy_version="1.0.0",
            verification_state="verified",
            freshness="fresh",
            contradiction_state="none",
            first_observed_at=NOW - timedelta(minutes=1),
            last_observed_at=NOW,
            last_validated_at=NOW - timedelta(minutes=1),
            edge_schema_version="1.0",
            edge_sequence=1,
            predecessor_edge_id=None,
            idempotency_key=f"clock-edge-{asset.asset_id}",
            input_digest="7" * 64,
        )
    )
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    assert snapshot.truncated is True
    assert "evidence_resolution_graph" in snapshot.failed_authorities
    assert edge_id not in snapshot.source_ids

    projection = ExposureReasoningService().project(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    assert projection.calculation_status.value == "partial"
    assert projection.truncated is True
    assert all(item.extent is ExposureExtent.UNKNOWN for item in projection.exposures)


def test_erg_state_projects_only_reviewed_markers_not_raw_subject_material() -> None:
    raw_secret = "api-key-value-that-must-never-enter-the-exposure-projection"
    assert _erg_state("provider", raw_secret) == "provider_observed"
    assert _erg_state("permission", raw_secret) == "permission_observed"
    assert raw_secret not in _erg_state("provider", raw_secret)


def test_historical_read_excludes_future_validations_and_evaluations(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="future-validation")
    action, path = _seed_exact_action_path(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        evidence_node_id=seed["node_id"],
        evidence_bundle_id=asset.evidence_bundle_id,
        action_id="future-validation-action",
    )
    asset_node_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:future-asset"))
    permission_node_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:future-permission"))
    db.add_all(
        [
            DiscoveryResolutionGraphNode(
                graph_node_id=asset_node_id,
                tenant_id=seed["tenant_id"],
                node_class="ai_asset",
                subject_reference=asset.asset_id,
                idempotency_key=f"future-asset-{asset.asset_id}",
                input_digest="8" * 64,
                created_at=NOW - timedelta(minutes=1),
            ),
            DiscoveryResolutionGraphNode(
                graph_node_id=permission_node_id,
                tenant_id=seed["tenant_id"],
                node_class="permission",
                subject_reference="write",
                idempotency_key=f"future-permission-{asset.asset_id}",
                input_digest="9" * 64,
                created_at=NOW - timedelta(minutes=1),
            ),
        ]
    )
    db.flush()
    future_edge_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:future-edge"))
    db.add_all(
        [
            DiscoveryResolutionGraphEdge(
                edge_id=future_edge_id,
                tenant_id=seed["tenant_id"],
                from_node_id=asset_node_id,
                to_node_id=permission_node_id,
                edge_type="accesses",
                evidence_node_id=seed["node_id"],
                collector_id="future-collector",
                source_surface="identity",
                signal_class="permission",
                base_confidence=0.9,
                observation_quality_factor=1.0,
                collector_quality_factor=1.0,
                confidence=0.9,
                relationship_weight=1.0,
                relationship_rule_id="future-binding",
                relationship_rule_version="1.0.0",
                decay_policy_id="future-freshness",
                decay_policy_version="1.0.0",
                verification_state="verified",
                freshness="fresh",
                contradiction_state="none",
                first_observed_at=NOW - timedelta(minutes=1),
                last_observed_at=NOW - timedelta(minutes=1),
                last_validated_at=NOW + timedelta(minutes=1),
                edge_schema_version="1.0",
                edge_sequence=1,
                predecessor_edge_id=None,
                idempotency_key=f"future-edge-{asset.asset_id}",
                input_digest="a" * 64,
            ),
            ControlCoverageAssertion(
                id=str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:future-assertion")),
                tenant_id=seed["tenant_id"],
                path_id=str(path.id),
                dimension="authorization",
                state="covered",
                reason_code="future_evaluation",
                explanation="This evaluation had not happened at the requested clock.",
                methodology_version="1.0",
                evaluator_version="1.0",
                evidence_refs=[seed["node_id"]],
                source_watermark="b" * 64,
                observed_at=NOW - timedelta(minutes=1),
                evaluated_at=NOW + timedelta(minutes=1),
                valid_until=NOW + timedelta(days=1),
            ),
        ]
    )
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )

    assert future_edge_id not in snapshot.source_ids
    assert all(
        item.source_type != "control_coverage_assertion"
        for item in snapshot.raw_sources
    )
    assert action.action_id in snapshot.source_ids


def test_only_latest_coverage_assertion_version_is_current_authority(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="coverage-current-version")
    _, path = _seed_exact_action_path(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        evidence_node_id=seed["node_id"],
        evidence_bundle_id=asset.evidence_bundle_id,
        action_id="coverage-version-action",
    )
    later = NOW + timedelta(minutes=1)
    old_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:coverage-old"))
    current_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:coverage-current"))
    db.add_all(
        [
            ControlCoverageAssertion(
                id=old_id,
                tenant_id=seed["tenant_id"],
                path_id=str(path.id),
                dimension="authorization",
                state="covered",
                reason_code="old_methodology",
                explanation="Superseded coverage assertion.",
                methodology_version="1.0",
                evaluator_version="1.0",
                evidence_refs=[seed["node_id"]],
                source_watermark="1" * 64,
                observed_at=NOW,
                evaluated_at=NOW,
                valid_until=later + timedelta(days=1),
            ),
            ControlCoverageAssertion(
                id=current_id,
                tenant_id=seed["tenant_id"],
                path_id=str(path.id),
                dimension="authorization",
                state="not_covered",
                reason_code="current_methodology",
                explanation="Current coverage assertion.",
                methodology_version="2.0",
                evaluator_version="2.0",
                evidence_refs=[seed["node_id"]],
                source_watermark="2" * 64,
                observed_at=later,
                evaluated_at=later,
                valid_until=later + timedelta(days=1),
            ),
        ]
    )
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=later
    )
    assertions = tuple(
        item for item in snapshot.raw_sources
        if item.source_type == "control_coverage_assertion"
        and item.state.startswith("authorization:")
    )

    assert [item.source_id for item in assertions] == [current_id]
    assert assertions[0].state == "authorization:not_covered"


def test_malformed_coverage_timestamp_is_isolated_and_projection_stays_safe(
    db: Session,
) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="coverage-malformed-clock")
    _, path = _seed_exact_action_path(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        evidence_node_id=seed["node_id"],
        evidence_bundle_id=asset.evidence_bundle_id,
        action_id="coverage-malformed-clock-action",
    )
    assertion_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:malformed-clock"))
    db.add(
        ControlCoverageAssertion(
            id=assertion_id,
            tenant_id=seed["tenant_id"],
            path_id=str(path.id),
            dimension="authorization",
            state="covered",
            reason_code="malformed_timestamp_order",
            explanation="Malformed persisted timestamp order must be isolated.",
            methodology_version="1.0",
            evaluator_version="1.0",
            evidence_refs=[seed["node_id"]],
            source_watermark="3" * 64,
            observed_at=NOW,
            evaluated_at=NOW - timedelta(minutes=1),
            valid_until=NOW + timedelta(days=1),
        )
    )
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    assert snapshot.truncated is True
    assert "control_coverage" in snapshot.failed_authorities
    assert assertion_id not in snapshot.source_ids

    projection = ExposureReasoningService().project(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    assert projection.calculation_status.value == "partial"
    assert projection.truncated is True
    assert all(item.extent is ExposureExtent.UNKNOWN for item in projection.exposures)


def test_malformed_coverage_evidence_refs_are_discarded_without_disclosure(
    db: Session,
) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="coverage-malformed-evidence")
    _, path = _seed_exact_action_path(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        evidence_node_id=seed["node_id"],
        evidence_bundle_id=asset.evidence_bundle_id,
        action_id="coverage-malformed-evidence-action",
    )
    assertion_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:malformed-evidence"))
    db.add(
        ControlCoverageAssertion(
            id=assertion_id,
            tenant_id=seed["tenant_id"],
            path_id=str(path.id),
            dimension="authorization",
            state="covered",
            reason_code="malformed_evidence",
            explanation="Malformed evidence must not cross the projection boundary.",
            methodology_version="1.0",
            evaluator_version="1.0",
            evidence_refs=[
                seed["node_id"],
                {"access_token": "must-never-leave-storage"},
                "x" * 256,
                "",
            ],
            source_watermark="4" * 64,
            observed_at=NOW,
            evaluated_at=NOW,
            valid_until=NOW + timedelta(days=1),
        )
    )
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    assertion = next(item for item in snapshot.raw_sources if item.source_id == assertion_id)
    assert assertion.evidence_refs == (seed["node_id"],)
    assert snapshot.truncated is True
    assert "must-never-leave-storage" not in snapshot.model_dump_json()


def test_malformed_runtime_event_evidence_refs_are_discarded_without_disclosure(
    db: Session,
) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="runtime-malformed-evidence")
    event = RuntimeEvent(
        event_id="runtime-malformed-evidence-event",
        tenant_id=seed["tenant_id"],
        source_surface="runtime",
        event_type="filesystem_write",
        application="Synthetic governed runtime",
        decision="allow",
        evidence_node_ids=[
            seed["node_id"],
            {"access_token": "runtime-secret-must-not-leak"},
            "y" * 256,
        ],
        evidence_bundle_id=asset.evidence_bundle_id,
        metadata_json={"discovery_asset_ref": asset.asset_id},
        created_at=NOW,
    )
    db.add(event)
    db.flush()
    path = upsert_path(
        db,
        tenant_id=seed["tenant_id"],
        candidate=runtime_event_candidate(event),
        observed_at=NOW,
    )
    assert f"runtime_event:{event.event_id}" in path.source_refs

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    runtime_factors = tuple(
        item
        for item in snapshot.raw_sources
        if item.source_type == "runtime_event_path_context"
        and item.source_id == event.event_id
    )
    assert runtime_factors
    assert all(
        set(item.evidence_refs).issubset({seed["node_id"], asset.evidence_bundle_id})
        for item in runtime_factors
    )
    assert snapshot.truncated is True
    assert "runtime-secret-must-not-leak" not in snapshot.model_dump_json()


def test_malformed_path_source_refs_are_discarded_and_force_partial_unknown(
    db: Session,
) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="path-malformed-source-refs")
    action, mixed_path = _seed_exact_action_path(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        evidence_node_id=seed["node_id"],
        evidence_bundle_id=asset.evidence_bundle_id,
        action_id="path-malformed-mixed-action",
    )
    _, invalid_container_path = _seed_exact_action_path(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        evidence_node_id=seed["node_id"],
        evidence_bundle_id=asset.evidence_bundle_id,
        action_id="path-malformed-container-action",
    )
    mixed_path.source_refs = [
        f"ai_action:{action.action_id}",
        {"access_token": "path-secret-must-not-leak"},
        "p" * 256,
        "",
    ]
    invalid_container_path.source_refs = {"secret": "container-secret-must-not-leak"}
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    assert snapshot.truncated is True
    assert action.action_id in snapshot.source_ids
    serialized = snapshot.model_dump_json()
    assert "path-secret-must-not-leak" not in serialized
    assert "container-secret-must-not-leak" not in serialized

    projection = ExposureReasoningService().project(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    assert projection.calculation_status.value == "partial"
    assert projection.truncated is True
    assert all(item.extent is ExposureExtent.UNKNOWN for item in projection.exposures)


def test_source_limitations_report_presence_without_copying_raw_material(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="safe-limitations")
    reachability = db.scalar(
        select(DiscoveryAssetReachability).where(
            DiscoveryAssetReachability.tenant_id == seed["tenant_id"],
            DiscoveryAssetReachability.asset_id == asset.asset_id,
        )
    )
    assert reachability is not None
    reachability.limitations_json = ["password=raw-value-must-not-leave-source"]
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    serialized = snapshot.model_dump_json()
    assert "raw-value-must-not-leave-source" not in serialized
    projected = [
        item
        for item in snapshot.raw_sources
        if item.source_type == "discovery_reachability"
    ]
    assert projected[0].limitations == ("reachability_source_limitations_present",)


def test_exact_action_bound_decision_receipt_is_included(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="receipt")
    action, path = _seed_exact_action_path(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        evidence_node_id=seed["node_id"],
        evidence_bundle_id=asset.evidence_bundle_id,
        action_id="exact-blocked-action",
    )
    receipt_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:receipt"))
    db.add(
        DecisionReceipt(
            receipt_id=receipt_id,
            schema_version="1.0",
            tenant_id=seed["tenant_id"],
            action_id="exact-blocked-action",
            chain_id="chain-receipt",
            canonical_action_hash="4" * 64,
            actor_hash="5" * 64,
            authority_hash="6" * 64,
            purpose_hash="7" * 64,
            tool_fingerprint="tool:write",
            parameter_hash="8" * 64,
            target_resource_hash="9" * 64,
            destination_hash="a" * 64,
            side_effect_class="persistent_side_effect",
            approval_binding_hash="b" * 64,
            approval_binding_id=None,
            policy_snapshot_id="policy-v1",
            decision="block",
            control_mode="inline",
            transformations=[],
            expires_at=NOW,
            issued_at=NOW,
            signature="c" * 64,
            signing_key_id="decision-key-v1",
            collector_id="native-control",
            canonical_action_evidence_node_id=seed["node_id"],
            policy_snapshot_evidence_node_id=None,
            evidence_bundle_id=asset.evidence_bundle_id,
            evidence_node_id=seed["node_id"],
            idempotency_key="d" * 64,
        )
    )
    db.flush()
    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    actions = [
        item for item in snapshot.raw_sources
        if item.dimension is ExposureDimension.AI_ACTION
    ]
    assert [item.source_id for item in actions] == [receipt_id]
    assert actions[0].state == "block:inline"
    assert action.action_id == "exact-blocked-action"
    assert actions[0].related_source_refs == (f"control_coverage_path:{path.id}",)


def test_receipt_shared_by_more_than_64_paths_is_withheld_not_rejected(
    db: Session,
) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="receipt-path-overflow")
    action, _path = _seed_exact_action_path(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        evidence_node_id=seed["node_id"],
        evidence_bundle_id=asset.evidence_bundle_id,
        action_id="receipt-path-overflow-action",
    )
    for index in range(64):
        db.add(
            ControlCoveragePath(
                tenant_id=seed["tenant_id"],
                path_key=str(uuid5(NAMESPACE_URL, f"receipt-overflow-path:{index}")),
                key_version="1.0",
                asset_ref=f"discovery_asset:{asset.asset_id}",
                identity_type="service_identity",
                identity_ref=f"service_identity:overflow-{index}",
                runtime_ref="model:test-model",
                deployment_surface_id=None,
                deployment_surface_ref="source_surface:runtime",
                destination_type="resource",
                destination_ref=f"resource:overflow-{index}",
                lifecycle_status="active",
                source_refs=[f"ai_action:{action.action_id}"],
                first_seen_at=NOW,
                last_seen_at=NOW,
            )
        )
    receipt_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:overflow-receipt"))
    db.add(
        DecisionReceipt(
            receipt_id=receipt_id,
            schema_version="1.0",
            tenant_id=seed["tenant_id"],
            action_id=action.action_id,
            chain_id="chain-overflow",
            canonical_action_hash="4" * 64,
            actor_hash="5" * 64,
            authority_hash="6" * 64,
            purpose_hash="7" * 64,
            tool_fingerprint="tool:write",
            parameter_hash="8" * 64,
            target_resource_hash="9" * 64,
            destination_hash="a" * 64,
            side_effect_class="persistent_side_effect",
            approval_binding_hash="b" * 64,
            approval_binding_id=None,
            policy_snapshot_id="policy-v1",
            decision="block",
            control_mode="inline",
            transformations=[],
            expires_at=NOW + timedelta(minutes=5),
            issued_at=NOW,
            signature="c" * 64,
            signing_key_id="decision-key-v1",
            collector_id="native-control",
            canonical_action_evidence_node_id=seed["node_id"],
            policy_snapshot_evidence_node_id=None,
            evidence_bundle_id=asset.evidence_bundle_id,
            evidence_node_id=seed["node_id"],
            idempotency_key="f" * 64,
        )
    )
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    receipt = next(item for item in snapshot.raw_sources if item.source_id == receipt_id)

    assert receipt.related_source_refs == ()
    assert "path_binding_cardinality_exceeded" in receipt.limitations
    assert snapshot.truncated is True


def test_many_paths_with_shared_actions_return_bounded_partial_snapshot(
    db: Session,
) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="expanded-source-bound")
    session = AISession(
        session_id="session-expanded-source-bound",
        tenant_id=seed["tenant_id"],
        source_surface="runtime",
        ai_app="Synthetic governed runtime",
        ai_model="test-model",
        start_time=NOW,
        total_actions=20,
        risk_score=0.0,
        status="active",
        metadata_json={},
    )
    actions = tuple(
        AIAction(
            action_id=f"expanded-action-{index:02d}",
            tenant_id=seed["tenant_id"],
            session_id=session.session_id,
            evidence_node_id=seed["node_id"],
            evidence_bundle_id=asset.evidence_bundle_id,
            timestamp=NOW,
            action_type="file_write",
            ai_app="Synthetic governed runtime",
            ai_model="test-model",
            data_classification="restricted",
            sensitivity_score=1.0,
            enforcement_action="observed",
            semantic_drift_score=0.0,
            risk_score=0.0,
            metadata_json={"discovery_asset_ref": asset.asset_id},
        )
        for index in range(20)
    )
    db.add_all([session, *actions])
    for index in range(180):
        db.add(
            ControlCoveragePath(
                tenant_id=seed["tenant_id"],
                path_key=str(uuid5(NAMESPACE_URL, f"expanded-source-path:{index}")),
                key_version="1.0",
                asset_ref=f"discovery_asset:{asset.asset_id}",
                identity_type="service_identity",
                identity_ref=f"service_identity:expanded-{index}",
                runtime_ref="model:test-model",
                deployment_surface_id=None,
                deployment_surface_ref="source_surface:runtime",
                destination_type="resource",
                destination_ref=f"resource:expanded-{index}",
                lifecycle_status="active",
                source_refs=[f"ai_action:{item.action_id}" for item in actions],
                first_seen_at=NOW,
                last_seen_at=NOW,
            )
        )
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    projection = ExposureReasoningService(
        source_reader=ExposureSourceReader()
    ).project(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )

    assert len(snapshot.raw_sources) <= 4000
    assert snapshot.truncated is True
    assert projection.calculation_status.value == "partial"
    assert projection.truncated is True
    assert all(item.extent is ExposureExtent.UNKNOWN for item in projection.exposures)


def test_unrelated_receipt_sharing_bundle_is_not_bound_to_action_path(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="receipt-cross-path")
    _, path = _seed_exact_action_path(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        evidence_node_id=seed["node_id"],
        evidence_bundle_id=asset.evidence_bundle_id,
        action_id="path-action",
    )
    unrelated_receipt_id = str(
        uuid5(NAMESPACE_URL, f"{asset.asset_id}:unrelated-receipt")
    )
    db.add(
        DecisionReceipt(
            receipt_id=unrelated_receipt_id,
            schema_version="1.0",
            tenant_id=seed["tenant_id"],
            action_id="different-action",
            chain_id="different-chain",
            canonical_action_hash="4" * 64,
            actor_hash="5" * 64,
            authority_hash="6" * 64,
            purpose_hash="7" * 64,
            tool_fingerprint="tool:write",
            parameter_hash="8" * 64,
            target_resource_hash="9" * 64,
            destination_hash="a" * 64,
            side_effect_class="persistent_side_effect",
            approval_binding_hash="b" * 64,
            approval_binding_id=None,
            policy_snapshot_id="policy-v1",
            decision="allow",
            control_mode="inline",
            transformations=[],
            expires_at=NOW + timedelta(minutes=5),
            issued_at=NOW,
            signature="c" * 64,
            signing_key_id="decision-key-v1",
            collector_id="native-control",
            canonical_action_evidence_node_id=seed["node_id"],
            policy_snapshot_evidence_node_id=None,
            evidence_bundle_id=asset.evidence_bundle_id,
            evidence_node_id=seed["node_id"],
            idempotency_key="e" * 64,
        )
    )
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )

    assert unrelated_receipt_id not in snapshot.source_ids
    path_ref = f"control_coverage_path:{path.id}"
    assert all(
        not (item.source_id == unrelated_receipt_id and path_ref in item.related_source_refs)
        for item in snapshot.raw_sources
    )


def test_input_digest_is_order_independent_and_source_complete(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="digest")
    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    assembler = ExposureInputAssembler()
    one = assembler.assemble(snapshot)
    two = assembler.assemble(
        snapshot.model_copy(update={"raw_sources": tuple(reversed(snapshot.raw_sources))})
    )
    assert one.input_digest == two.input_digest
    assert one.factors == two.factors
    assert set(one.source_ids) == set(snapshot.source_ids)


def test_missing_permission_is_unknown_not_absent(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="permission")
    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    assembled = ExposureInputAssembler().assemble(snapshot)
    permissions = [
        item for item in assembled.factors if item.dimension is ExposureDimension.PERMISSION
    ]
    assert len(permissions) == 1
    assert permissions[0].state == "unknown"
    assert permissions[0].source_type == "missing_authority"


def test_production_runtime_path_is_resolved_and_bound_to_exact_asset(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="production-path")
    runtime_event = RuntimeEvent(
        event_id="runtime-event-production-path",
        tenant_id=seed["tenant_id"],
        source_surface="runtime",
        event_type="filesystem_write",
        application="Synthetic governed runtime",
        decision="allow",
        evidence_node_ids=[seed["node_id"]],
        evidence_bundle_id=asset.evidence_bundle_id,
        metadata_json={
            "discovery_asset_ref": asset.asset_id,
            "service_identity_id": "service-production-path",
            "destination_host": "internal.example.test",
            "provider": "synthetic",
            "model": "test-model",
        },
        created_at=NOW,
    )
    db.add(runtime_event)
    db.flush()
    path = upsert_path(
        db,
        tenant_id=seed["tenant_id"],
        candidate=runtime_event_candidate(runtime_event),
        observed_at=NOW,
    )

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    path_ref = f"control_coverage_path:{path.id}"
    bound = tuple(
        item for item in snapshot.raw_sources
        if path_ref in item.related_source_refs
    )
    assert {item.dimension for item in bound} >= {
        ExposureDimension.CAPABILITY,
        ExposureDimension.IDENTITY,
        ExposureDimension.REACHABILITY,
        ExposureDimension.RUNTIME,
    }
    assert any(item.state == "filesystem_write" for item in bound)


def test_shared_evidence_never_cross_binds_two_exact_paths(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="shared-evidence-paths")
    permission_node_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:shared-permission"))
    permission_edge_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:shared-edge"))
    _, first_path = _seed_exact_action_path(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        evidence_node_id=seed["node_id"],
        evidence_bundle_id=asset.evidence_bundle_id,
        action_id="shared-path-action-one",
        extra_source_refs=(f"erg_node:{permission_node_id}",),
    )
    _, second_path = _seed_exact_action_path(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        evidence_node_id=seed["node_id"],
        evidence_bundle_id=asset.evidence_bundle_id,
        action_id="shared-path-action-two",
    )
    asset_node_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:shared-asset"))
    db.add_all(
        [
            DiscoveryResolutionGraphNode(
                graph_node_id=asset_node_id,
                tenant_id=seed["tenant_id"],
                node_class="ai_asset",
                subject_reference=asset.asset_id,
                idempotency_key=f"shared-asset-node-{asset.asset_id}",
                input_digest="1" * 64,
                created_at=NOW,
            ),
            DiscoveryResolutionGraphNode(
                graph_node_id=permission_node_id,
                tenant_id=seed["tenant_id"],
                node_class="permission",
                subject_reference="write",
                idempotency_key=f"shared-permission-node-{asset.asset_id}",
                input_digest="2" * 64,
                created_at=NOW,
            ),
        ]
    )
    db.flush()
    db.add(
        DiscoveryResolutionGraphEdge(
            edge_id=permission_edge_id,
            tenant_id=seed["tenant_id"],
            from_node_id=asset_node_id,
            to_node_id=permission_node_id,
            edge_type="accesses",
            evidence_node_id=seed["node_id"],
            collector_id="identity-collector",
            source_surface="identity",
            signal_class="permission",
            base_confidence=0.9,
            observation_quality_factor=1.0,
            collector_quality_factor=1.0,
            confidence=0.9,
            relationship_weight=1.0,
            relationship_rule_id="permission-binding",
            relationship_rule_version="1.0.0",
            decay_policy_id="permission-freshness",
            decay_policy_version="1.0.0",
            verification_state="verified",
            freshness="fresh",
            contradiction_state="none",
            first_observed_at=NOW,
            last_observed_at=NOW,
            last_validated_at=NOW,
            edge_schema_version="1.0",
            edge_sequence=1,
            predecessor_edge_id=None,
            idempotency_key=f"shared-permission-edge-{asset.asset_id}",
            input_digest="3" * 64,
        )
    )
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    permission = next(
        item for item in snapshot.raw_sources if item.source_id == permission_edge_id
    )

    assert f"control_coverage_path:{first_path.id}" in permission.related_source_refs
    assert f"control_coverage_path:{second_path.id}" not in permission.related_source_refs


def test_many_exact_paths_keep_asset_and_surface_projection_bounded(db: Session) -> None:
    seed, asset, capability = _seed_asset_sources(db, suffix="many-paths")
    asset.approved_status = "approved"
    surface = DeploymentSurface(
        tenant_id=seed["tenant_id"],
        source_kind="endpoint",
        source_id="many-paths-surface",
        name="Many paths surface",
        surface_type="endpoint",
        deployment_mode="managed",
        deployment_family="endpoint",
        hosting_mode="on_premises",
        environment="test",
        provider="hawk",
        region=None,
        status="active",
        feature_flag=None,
        capability_profile={},
        capability_sources=[],
        control_capability="inline",
        evidence_capability="complete",
        containment_capability="direct",
        bypass_detection_capability="supported",
        health_status="healthy",
        health_reason="verified_test_fixture",
        first_seen_at=NOW,
        last_seen_at=NOW,
        last_heartbeat_at=NOW,
        last_health_check_at=NOW,
        policy_bundle_version="policy-v1",
        collector_version="test-v1",
        metadata_json={},
    )
    db.add(surface)
    db.flush()
    shared_capability_ref = f"discovery_capability:{capability.capability_id}"
    paths = []
    for index in range(65):
        path = ControlCoveragePath(
            tenant_id=seed["tenant_id"],
            path_key=str(uuid5(NAMESPACE_URL, f"many-paths:{asset.asset_id}:{index}")),
            key_version="1.0",
            asset_ref=f"discovery_asset:{asset.asset_id}",
            identity_type="service_identity",
            identity_ref=f"service_identity:many-paths-{index}",
            runtime_ref="model:test-model",
            deployment_surface_id=surface.id,
            deployment_surface_ref="endpoint:many-paths-surface",
            destination_type="resource",
            destination_ref=f"resource:many-paths-{index}",
            lifecycle_status="active",
            source_refs=[shared_capability_ref],
            first_seen_at=NOW,
            last_seen_at=NOW,
        )
        db.add(path)
        paths.append(path)
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    surface_sources = tuple(
        item for item in snapshot.raw_sources if item.source_type == "deployment_surface"
    )
    asset_sources = tuple(
        item for item in snapshot.raw_sources if item.source_type == "discovery_asset"
    )
    capability_source = next(
        item for item in snapshot.raw_sources if item.source_id == capability.capability_id
    )

    assert len(surface_sources) == 65
    assert all(len(item.related_source_refs) == 1 for item in surface_sources)
    assert all(
        not any(ref.startswith("control_coverage_path:") for ref in item.related_source_refs)
        for item in asset_sources
    )
    assert not any(
        ref.startswith("control_coverage_path:")
        for ref in capability_source.related_source_refs
    )
    assert "path_binding_cardinality_exceeded" in capability_source.limitations
    ExposureInputAssembler().assemble(snapshot)
    projection = ExposureReasoningService().project(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    assert projection.asset_id == asset.asset_id
    assert all(item.extent is ExposureExtent.UNKNOWN for item in projection.exposures)


def test_future_deployment_heartbeat_cannot_create_as_of_containment_authority(
    db: Session,
) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="surface-future-heartbeat")
    surface = DeploymentSurface(
        tenant_id=seed["tenant_id"],
        source_kind="endpoint",
        source_id="future-heartbeat-surface",
        name="Future heartbeat surface",
        surface_type="endpoint",
        deployment_mode="managed",
        deployment_family="endpoint",
        hosting_mode="on_premises",
        environment="test",
        provider="hawk",
        region=None,
        status="active",
        feature_flag=None,
        capability_profile={},
        capability_sources=[],
        control_capability="inline",
        evidence_capability="complete",
        containment_capability="direct",
        bypass_detection_capability="supported",
        health_status="healthy",
        health_reason="future_evidence_must_not_apply",
        first_seen_at=NOW,
        last_seen_at=NOW,
        last_heartbeat_at=NOW + timedelta(minutes=1),
        last_health_check_at=None,
        policy_bundle_version="policy-v1",
        collector_version="test-v1",
        metadata_json={},
    )
    db.add(surface)
    db.flush()
    _, path = _seed_exact_action_path(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        evidence_node_id=seed["node_id"],
        evidence_bundle_id=asset.evidence_bundle_id,
        action_id="future-heartbeat-action",
    )
    path.deployment_surface_id = surface.id
    path.deployment_surface_ref = "endpoint:future-heartbeat-surface"
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    assert all(
        not (
            item.source_type == "deployment_surface"
            and item.source_id == str(surface.id)
        )
        for item in snapshot.raw_sources
    )


def test_one_authority_failure_isolated_as_partial_source_snapshot(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed, asset, capability = _seed_asset_sources(db, suffix="authority-failure")
    original = db.scalars

    def flaky_scalars(statement, *args, **kwargs):  # type: ignore[no-untyped-def]
        if "discovery_asset_reachability" in str(statement).casefold():
            raise SQLAlchemyError("simulated reachability authority failure")
        return original(statement, *args, **kwargs)

    monkeypatch.setattr(db, "scalars", flaky_scalars)
    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    assert snapshot.failed_authorities == ("discovery_reachability",)
    assert capability.capability_id in snapshot.source_ids


def test_potential_reachability_never_becomes_verified_positive_reach(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="potential-reach")
    reachability = db.scalar(
        select(DiscoveryAssetReachability).where(
            DiscoveryAssetReachability.tenant_id == seed["tenant_id"],
            DiscoveryAssetReachability.asset_id == asset.asset_id,
        )
    )
    assert reachability is not None
    reachability.reachability_state = "potential"
    reachability.verification_state = "verified"
    reachability.freshness = "fresh"
    db.flush()
    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    projected = next(
        item for item in snapshot.raw_sources
        if item.source_type == "discovery_reachability"
    )
    assert projected.verification_status.value == "unknown"


def test_reported_freshness_is_clamped_by_observation_age(db: Session) -> None:
    seed, asset, capability = _seed_asset_sources(db, suffix="freshness-clamp")
    snapshot = ExposureSourceReader().read(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        as_of=NOW + timedelta(days=200),
    )
    projected = next(
        item for item in snapshot.raw_sources
        if item.source_id == capability.capability_id
    )
    assert projected.freshness.value == "expired"


def test_future_source_observations_are_excluded_from_historical_clock(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="future-source")
    future_id = "reachability-future-source-later"
    db.add(
        DiscoveryAssetReachability(
            reachability_id=future_id,
            tenant_id=seed["tenant_id"],
            asset_id=asset.asset_id,
            target_category="internet",
            target_reference_hash="e" * 64,
            reachability_state="verified",
            evidence_node_id=seed["node_id"],
            confidence=0.96,
            verification_state="verified",
            freshness="fresh",
            observed_usage=True,
            first_observed_at=NOW + timedelta(hours=1),
            last_observed_at=NOW + timedelta(hours=1),
            limitations_json=[],
            idempotency_key=future_id,
            input_digest="f" * 64,
        )
    )
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    assert future_id not in snapshot.source_ids


def test_expired_receipt_never_projects_as_current_evidence(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="expired-receipt")
    _, path = _seed_exact_action_path(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        evidence_node_id=seed["node_id"],
        evidence_bundle_id=asset.evidence_bundle_id,
        action_id="expired-action",
    )
    receipt_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:expired-receipt"))
    db.add(
        DecisionReceipt(
            receipt_id=receipt_id,
            schema_version="1.0",
            tenant_id=seed["tenant_id"],
            action_id="expired-action",
            chain_id="expired-chain",
            canonical_action_hash="4" * 64,
            actor_hash="5" * 64,
            authority_hash="6" * 64,
            purpose_hash="7" * 64,
            tool_fingerprint="tool:write",
            parameter_hash="8" * 64,
            target_resource_hash="9" * 64,
            destination_hash="a" * 64,
            side_effect_class="persistent_side_effect",
            approval_binding_hash="b" * 64,
            approval_binding_id=None,
            policy_snapshot_id="policy-v1",
            decision="allow",
            control_mode="inline",
            transformations=[],
            expires_at=NOW - timedelta(seconds=1),
            issued_at=NOW - timedelta(minutes=1),
            signature="c" * 64,
            signing_key_id="decision-key-v1",
            collector_id="native-control",
            canonical_action_evidence_node_id=seed["node_id"],
            policy_snapshot_evidence_node_id=None,
            evidence_bundle_id=asset.evidence_bundle_id,
            evidence_node_id=seed["node_id"],
            idempotency_key="d" * 64,
        )
    )
    db.flush()

    snapshot = ExposureSourceReader().read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    receipt = next(item for item in snapshot.raw_sources if item.source_id == receipt_id)
    assert receipt.freshness.value == "expired"
    assert receipt.related_source_refs == (f"control_coverage_path:{path.id}",)


def test_same_display_name_never_cross_binds_a_stable_asset_path(db: Session) -> None:
    first, first_asset, _ = _seed_asset_sources(db, suffix="path-collision-a")
    second_asset = DiscoveryAIAsset(
        asset_id=str(uuid5(NAMESPACE_URL, "exposure-path-collision-second-asset")),
        tenant_id=first["tenant_id"],
        asset_type=first_asset.asset_type,
        canonical_name=first_asset.canonical_name,
        provider=first_asset.provider,
        product=first_asset.product,
        framework=first_asset.framework,
        version=first_asset.version,
        deployment_family=first_asset.deployment_family,
        technical_surface=first_asset.technical_surface,
        environment=first_asset.environment,
        approved_status=first_asset.approved_status,
        lifecycle_status=first_asset.lifecycle_status,
        shadow_ai_status=first_asset.shadow_ai_status,
        first_seen_at=NOW,
        last_seen_at=NOW,
        resolution_confidence=first_asset.resolution_confidence,
        evidence_bundle_id=first_asset.evidence_bundle_id,
        projection_version=1,
    )
    db.add(second_asset)
    db.flush()
    runtime_event = RuntimeEvent(
        event_id="runtime-event-path-collision",
        tenant_id=first["tenant_id"],
        source_surface="runtime",
        event_type="filesystem_write",
        application=first_asset.canonical_name,
        evidence_node_ids=[first["node_id"]],
        evidence_bundle_id=second_asset.evidence_bundle_id,
        metadata_json={"discovery_asset_ref": second_asset.asset_id},
        created_at=NOW,
    )
    db.add(runtime_event)
    db.flush()
    path = upsert_path(
        db,
        tenant_id=first["tenant_id"],
        candidate=runtime_event_candidate(runtime_event),
        observed_at=NOW,
    )
    snapshot = ExposureSourceReader().read(
        db,
        tenant_id=first["tenant_id"],
        asset_id=first_asset.asset_id,
        as_of=NOW,
    )
    path_ref = f"control_coverage_path:{path.id}"
    assert all(path_ref not in item.related_source_refs for item in snapshot.raw_sources)


def test_latest_capability_per_name_is_selected_before_authority_limit(db: Session) -> None:
    seed, asset, old_write = _seed_asset_sources(db, suffix="capability-latest")
    old_write.first_observed_at = NOW - timedelta(minutes=2)
    old_write.last_observed_at = NOW - timedelta(minutes=2)
    claim_id = old_write.evidence_claim_id
    latest_write = persist_capability_assertion(
        db,
        tenant_id=seed["tenant_id"],
        payload=AICapabilityAssertionCreate(
            asset_id=asset.asset_id,
            source_observation_id=seed["observation_id"],
            evidence_claim_id=claim_id,
            name="filesystem_write",
            state="configured",
            confidence=0.95,
            first_observed_at=NOW - timedelta(minutes=2),
            last_observed_at=NOW,
            extractor_version="exposure-test-v2",
            supersedes_capability_id=old_write.capability_id,
        ),
    )
    latest_write.verification_state = "verified"
    latest_write.freshness = "fresh"
    read_capability = persist_capability_assertion(
        db,
        tenant_id=seed["tenant_id"],
        payload=AICapabilityAssertionCreate(
            asset_id=asset.asset_id,
            source_observation_id=seed["observation_id"],
            evidence_claim_id=claim_id,
            name="filesystem_read",
            state="observed",
            confidence=0.94,
            first_observed_at=NOW,
            last_observed_at=NOW,
            extractor_version="exposure-test-v1",
            supersedes_capability_id=None,
        ),
    )
    read_capability.verification_state = "verified"
    read_capability.freshness = "fresh"
    db.flush()

    snapshot = ExposureSourceReader(max_records_per_authority=2).read(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    capabilities = {
        item.source_id: item.state
        for item in snapshot.raw_sources
        if item.source_type == "discovery_capability"
    }
    assert capabilities == {
        latest_write.capability_id: "filesystem_write",
        read_capability.capability_id: "filesystem_read",
    }
    assert old_write.capability_id not in capabilities


def test_verified_production_path_reaches_material_without_fallback_poisoning(
    db: Session,
) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="production-material")
    asset.approved_status = "approved"
    runtime_event = RuntimeEvent(
        event_id="runtime-event-production-material",
        tenant_id=seed["tenant_id"],
        source_surface="runtime",
        event_type="filesystem_write",
        application="Synthetic governed runtime",
        decision="allow",
        evidence_node_ids=[seed["node_id"]],
        evidence_bundle_id=asset.evidence_bundle_id,
        metadata_json={
            "discovery_asset_ref": asset.asset_id,
            "service_identity_id": "service-production-material",
            "destination_host": "internal.example.test",
        },
        created_at=NOW,
    )
    db.add(runtime_event)
    db.flush()
    path = upsert_path(
        db,
        tenant_id=seed["tenant_id"],
        candidate=runtime_event_candidate(runtime_event),
        observed_at=NOW,
    )
    asset_node_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:material-asset"))
    permission_node_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:material-permission"))
    permission_edge_id = str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:material-edge"))
    db.add_all(
        [
            DiscoveryResolutionGraphNode(
                graph_node_id=asset_node_id,
                tenant_id=seed["tenant_id"],
                node_class="ai_asset",
                subject_reference=asset.asset_id,
                idempotency_key=f"material-asset-{asset.asset_id}",
                input_digest="4" * 64,
                created_at=NOW,
            ),
            DiscoveryResolutionGraphNode(
                graph_node_id=permission_node_id,
                tenant_id=seed["tenant_id"],
                node_class="permission",
                subject_reference="write",
                idempotency_key=f"material-permission-{asset.asset_id}",
                input_digest="5" * 64,
                created_at=NOW,
            ),
        ]
    )
    db.flush()
    db.add_all(
        [
            DiscoveryResolutionGraphEdge(
                edge_id=permission_edge_id,
                tenant_id=seed["tenant_id"],
                from_node_id=asset_node_id,
                to_node_id=permission_node_id,
                edge_type="accesses",
                evidence_node_id=seed["node_id"],
                collector_id="identity-collector",
                source_surface="identity",
                signal_class="permission",
                base_confidence=0.9,
                observation_quality_factor=1.0,
                collector_quality_factor=1.0,
                confidence=0.9,
                relationship_weight=1.0,
                relationship_rule_id="permission-binding",
                relationship_rule_version="1.0.0",
                decay_policy_id="permission-freshness",
                decay_policy_version="1.0.0",
                verification_state="verified",
                freshness="fresh",
                contradiction_state="none",
                first_observed_at=NOW,
                last_observed_at=NOW,
                last_validated_at=NOW,
                edge_schema_version="1.0",
                edge_sequence=1,
                predecessor_edge_id=None,
                idempotency_key=f"material-edge-{asset.asset_id}",
                input_digest="6" * 64,
            ),
            ControlCoverageAssertion(
                id=str(uuid5(NAMESPACE_URL, f"{asset.asset_id}:material-coverage")),
                tenant_id=seed["tenant_id"],
                path_id=str(path.id),
                dimension="authorization",
                state="not_covered",
                reason_code="verified_test_gap",
                explanation="Verified path-specific authorization gap.",
                methodology_version="1.0",
                evaluator_version="1.0",
                evidence_refs=[seed["node_id"]],
                source_watermark="7" * 64,
                observed_at=NOW,
                evaluated_at=NOW,
                valid_until=NOW + timedelta(days=1),
            ),
        ]
    )
    db.flush()

    projection = ExposureReasoningService().project(
        db, tenant_id=seed["tenant_id"], asset_id=asset.asset_id, as_of=NOW
    )
    coding = next(item for item in projection.exposures if item.category_id == "coding_exposure")
    assert coding.extent is ExposureExtent.MATERIAL, coding.model_dump_json(indent=2)
    assert coding.verification_status.value == "verified"
    assert all(
        item.source_type not in {"control_coverage_path", "runtime_event_path_context"}
        for item in coding.contributors
        if item.dimension
        in {
            ExposureDimension.CAPABILITY,
            ExposureDimension.IDENTITY,
            ExposureDimension.REACHABILITY,
        }
    )
