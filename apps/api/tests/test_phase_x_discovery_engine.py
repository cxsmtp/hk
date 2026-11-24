from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.models.ai_asset import DiscoveryAIAsset, DiscoveryEvidenceClaim
from app.db.models.discovery_canonical import DiscoveryObservation, DiscoveryScan
from app.db.models.evidence import EvidenceEdge, EvidenceNode
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.jobs import hmair_discovery_jobs
from app.api.routers.discovery_ecosystems import get_ecosystem
from app.services.hmair.collector_facade import CollectorFacade
from app.services.hmair.collector_sdk import (
    CollectorHealthReport,
    CollectorRecord,
    ConnectivityResult,
    DiscoveryTargetView,
    ScopeItem,
)
from app.services.hmair.contracts import (
    CollectorDeclaration,
    DiscoveryObservationInput,
    DiscoveryTargetType,
)
from app.services.hmair.ecosystem_resolution_service import resolve_ai_ecosystems
from app.services.hmair.evidence_fusion_service import (
    EvidenceFusionScopeError,
    fuse_observations,
    fuse_scan_observations,
)
from app.services.hmair.normalization_service import normalize_observation
from app.services.hmair.resolution_graph_service import (
    create_graph_edge,
    create_graph_node,
)


NOW = datetime(2026, 8, 15, 15, 0, tzinfo=timezone.utc)


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


def _input_observation() -> DiscoveryObservationInput:
    return DiscoveryObservationInput(
        observation_id="observation-facade",
        scan_id="00000000-0000-4000-8000-000000000001",
        collector_id="endpoint-primary",
        collector_type="endpoint",
        collector_version="2.0",
        target_id="endpoint-group-a",
        source_surface="endpoint",
        subject_reference="device-fingerprint-a",
        observation_type="running_process",
        normalized_signal={"process_family": "local_ai_runtime"},
        observed_at=NOW,
        candidate_asset_type="runtime",
        observed_state="observed",
        identifiers={"runtime_name": "local-runtime-a"},
        attributes={"version": "1.0"},
        configuration_summary={},
        usage_summary={},
        capability_hints=("model_inference",),
        identity_hints=(),
        relationship_hints=(),
        evidence_reference="evidence://endpoint/a",
        evidence_hash="a" * 64,
        signature_status="verified",
        confidence=0.9,
        freshness="fresh",
        verification_state="verified",
        source_trust="strong",
        collection_scope={"scope_type": "endpoint_group"},
        parser_version="2.0.0",
        schema_version="2.0",
        evidence_mode="direct",
        evidence_mutability="immutable",
        contradiction_state="none",
        contradiction_references=(),
        sensitivity="metadata",
        redaction_status="not_required",
    )


class _FacadeCollector:
    declaration = CollectorDeclaration(
        collector_id="endpoint-primary",
        collector_type="endpoint",
        version="2.0",
        supported_targets=(DiscoveryTargetType.ENDPOINT_GROUP,),
        active_capabilities=(),
        passive_capabilities=("inventory",),
        permissions_required=("endpoint.metadata.read",),
        sensitive_data_accessed=(),
        health="healthy",
        last_success_at=NOW,
        last_failure_at=None,
        data_residency="tenant-local",
        control_capability="monitor_only",
        schema_version="2.0",
        limitations=("metadata-only",),
        declaration_hash="b" * 64,
    )

    def validate_configuration(self, configuration: Mapping[str, object]) -> None:
        assert configuration == {"profile": "safe"}

    def test_connectivity(self, target: DiscoveryTargetView) -> ConnectivityResult:
        assert target.target_id == "endpoint-group-a"
        return ConnectivityResult(
            reachable=True,
            status="available",
            checked_at=NOW,
            safe_message="connected",
        )

    def enumerate_scope(self, target: DiscoveryTargetView) -> tuple[ScopeItem, ...]:
        return (
            ScopeItem(
                scope_id="scope-a",
                scope_type="endpoint_group",
                permitted_methods=("collect_inventory", "collect_usage"),
            ),
        )

    def _record(self, kind: str) -> tuple[CollectorRecord, ...]:
        return (
            CollectorRecord(
                record_type=kind,
                source_reference=f"scope-a:{kind}",
                observed_at=NOW,
                safe_summary="metadata-only",
            ),
        )

    def collect_inventory(self, scope: ScopeItem) -> tuple[CollectorRecord, ...]:
        return self._record("inventory")

    def collect_configuration(self, scope: ScopeItem) -> tuple[CollectorRecord, ...]:
        return self._record("configuration")

    def collect_usage(self, scope: ScopeItem) -> tuple[CollectorRecord, ...]:
        return self._record("usage")

    def collect_identity_hints(self, scope: ScopeItem) -> tuple[CollectorRecord, ...]:
        return self._record("identity")

    def collect_relationship_hints(self, scope: ScopeItem) -> tuple[CollectorRecord, ...]:
        return self._record("relationship")

    def emit_observations(self) -> tuple[DiscoveryObservationInput, ...]:
        return (_input_observation(),)

    def report_health(self) -> CollectorHealthReport:
        return CollectorHealthReport(
            health="healthy", checked_at=NOW, safe_message="healthy"
        )

    def report_limitations(self) -> tuple[str, ...]:
        return ("metadata-only",)


def test_collector_facade_exposes_compact_observation_only_contract() -> None:
    facade = CollectorFacade(_FacadeCollector())
    target = DiscoveryTargetView(
        target_id="endpoint-group-a",
        target_type="endpoint_group",
        identifier="managed-endpoints-a",
        environment="production",
        owner_hint=None,
        credentials_reference="vault-ref-a",
        permitted_methods=("collect_inventory", "collect_usage"),
        exclusions=(),
        rate_limit=100,
        active_scan_allowed=False,
        sensitive_scope=False,
        last_scanned_at=None,
    )

    assert facade.validate({"profile": "safe"}) is None
    scopes = facade.enumerate(target)
    collection_result = facade.collect(scopes[0])
    observations = facade.observe()

    assert collection_result is None
    assert observations == (_input_observation(),)
    assert facade.health().health == "healthy"
    assert facade.limitations() == ("metadata-only",)
    assert facade.schema_version() == "2.0"
    assert not hasattr(facade, "create_asset")


def _observation_row(
    *,
    tenant_id: str,
    observation_id: str,
    source_surface: str,
    evidence_mode: str = "direct",
    contradiction_state: str = "none",
    confidence: float = 0.9,
) -> DiscoveryObservation:
    return DiscoveryObservation(
        observation_id=observation_id,
        tenant_id=tenant_id,
        assignment_id=f"assignment-{observation_id}",
        scan_id=f"scan-{observation_id}",
        collector_id=f"collector-{source_surface}",
        collector_type=source_surface,
        collector_version="2.0",
        target_id=f"target-{source_surface}",
        source_surface=source_surface,
        subject_reference=f"subject-{observation_id}",
        normalized_signal_json={"provider_family": "openai"},
        observed_at=NOW,
        received_at=NOW,
        observation_type="ai_endpoint_observation",
        candidate_asset_type="model_endpoint",
        observed_state="observed",
        identifiers_json={"endpoint_fingerprint": observation_id},
        attributes_json={"environment": "production"},
        configuration_summary_json={},
        usage_summary_json={},
        capability_hints_json=["model_inference"],
        identity_hints_json=[],
        relationship_hints_json=[],
        evidence_reference=f"evidence://{source_surface}/{observation_id}",
        evidence_hash=("c" if source_surface == "browser" else "d") * 64,
        signature_status="verified",
        confidence=confidence,
        freshness="fresh",
        verification_state="verified",
        source_trust="strong",
        collection_scope_json={"surface": source_surface},
        parser_version="2.0.0",
        schema_version="2.0",
        evidence_mode=evidence_mode,
        evidence_mutability="immutable",
        contradiction_state=contradiction_state,
        contradiction_references_json=(
            ["evidence://conflict/1"] if contradiction_state != "none" else []
        ),
        sensitivity="metadata",
        redaction_status="not_required",
        idempotency_key=("e" + observation_id.encode().hex())[:64].ljust(64, "e"),
        payload_digest=("f" + observation_id.encode().hex())[:64].ljust(64, "f"),
    )


def test_normalization_is_deterministic_and_does_not_infer_or_merge() -> None:
    row = _observation_row(
        tenant_id="tenant-a",
        observation_id="observation-a",
        source_surface="browser",
        contradiction_state="unresolved",
        confidence=0.73,
    )
    row.identifiers_json = {
        "ExecutablePath": r"C:\\Program Files\\Cursor\\.\\Cursor.exe",
        "user_email": "  Analyst@Example.COM ",
        "provider_family": "Azure OpenAI",
    }
    row.normalized_signal_json = {
        "model_name": " GPT-4o ",
        "application": "Cursor IDE",
        "framework": " Semantic Kernel ",
        "sdk_name": " Azure AI SDK ",
        "runtime_version": " 1.2.03 ",
    }
    row.configuration_summary_json = {
        "Model Settings": {"Deployment Name": "prod-gpt4o"},
    }

    first = normalize_observation(row)
    second = normalize_observation(row)

    assert first == second
    assert first.observation_id == "observation-a"
    assert first.confidence == 0.73
    assert first.contradiction_state == "unresolved"
    assert first.normalization_digest == second.normalization_digest
    assert first.asset_id is None
    assert first.inferred_relationships == ()
    assert first.comparison_material == {
        "applications": ("cursor_ide",),
        "configurations": (
            "model_settings",
            "model_settings.deployment_name",
        ),
        "frameworks": ("semantic_kernel",),
        "identities": ("analyst@example.com",),
        "models": ("gpt_4o",),
        "paths": ("C:/Program Files/Cursor/Cursor.exe",),
        "providers": ("azure_openai",),
        "sdks": ("azure_ai_sdk",),
        "versions": ("1.2.03",),
    }


def test_evidence_fusion_is_tenant_safe_idempotent_append_only_and_asset_neutral(
    db: Session,
) -> None:
    db.add_all(
        [
            Tenant(id="tenant-a", name="Tenant A", slug="tenant-a"),
            Tenant(id="tenant-b", name="Tenant B", slug="tenant-b"),
        ]
    )
    db.flush()
    seed_node = EvidenceNode(
        id=str(uuid4()),
        tenant_id="tenant-a",
        correlation_id="seed",
        node_type="bundle",
        signal_type="discovery.seed",
        label="Seed asset evidence",
        payload={"classification": "metadata_only"},
    )
    db.add(seed_node)
    db.flush()
    db.add(
        DiscoveryAIAsset(
            asset_id="asset-existing",
            tenant_id="tenant-a",
            asset_type="model_endpoint",
            canonical_name="Existing endpoint",
            provider="openai",
            product="api",
            framework=None,
            version=None,
            deployment_family="cloud",
            technical_surface="model_endpoint",
            environment="production",
            approved_status="unknown",
            lifecycle_status="unknown",
            shadow_ai_status="unknown",
            first_seen_at=NOW,
            last_seen_at=NOW,
            resolution_confidence=0.8,
            evidence_bundle_id=seed_node.id,
            projection_version=1,
        )
    )
    observations = (
        _observation_row(
            tenant_id="tenant-a",
            observation_id="observation-browser",
            source_surface="browser",
        ),
        _observation_row(
            tenant_id="tenant-a",
            observation_id="observation-cloud",
            source_surface="cloud",
            evidence_mode="inferred",
            contradiction_state="unresolved",
            confidence=0.6,
        ),
        _observation_row(
            tenant_id="tenant-b",
            observation_id="observation-foreign",
            source_surface="cloud",
        ),
    )
    db.add_all(observations)
    db.flush()
    asset_count = int(db.scalar(select(func.count(DiscoveryAIAsset.asset_id))) or 0)

    bundle = fuse_observations(
        db,
        tenant_id="tenant-a",
        observation_ids=("observation-cloud", "observation-browser"),
    )
    replay = fuse_observations(
        db,
        tenant_id="tenant-a",
        observation_ids=("observation-browser", "observation-cloud"),
    )

    assert replay.bundle_id == bundle.bundle_id
    assert bundle.source_surfaces == ("browser", "cloud")
    assert bundle.direct_observation_count == 1
    assert bundle.inferred_observation_count == 1
    assert bundle.contradiction_state == "unresolved"
    assert bundle.confidence_facts == (0.6, 0.9)
    assert db.scalar(select(func.count(DiscoveryAIAsset.asset_id))) == asset_count
    assert db.scalar(
        select(func.count(EvidenceEdge.id)).where(
            EvidenceEdge.tenant_id == "tenant-a",
            EvidenceEdge.edge_type == "bundle_member",
        )
    ) == 2
    assert db.scalar(
        select(func.count(DiscoveryEvidenceClaim.claim_id)).where(
            DiscoveryEvidenceClaim.tenant_id == "tenant-a"
        )
    ) == 2

    with pytest.raises(EvidenceFusionScopeError):
        fuse_observations(
            db,
            tenant_id="tenant-a",
            observation_ids=("observation-foreign",),
        )

    old_bundle_count = int(
        db.scalar(
            select(func.count(EvidenceNode.id)).where(
                EvidenceNode.tenant_id == "tenant-a",
                EvidenceNode.signal_type == "discovery.evidence_fusion",
            )
        )
        or 0
    )
    db.add(
        _observation_row(
            tenant_id="tenant-a",
            observation_id="observation-runtime",
            source_surface="runtime",
        )
    )
    db.flush()
    newer = fuse_observations(
        db,
        tenant_id="tenant-a",
        observation_ids=(
            "observation-browser",
            "observation-cloud",
            "observation-runtime",
        ),
    )
    assert newer.bundle_id != bundle.bundle_id
    assert db.scalar(
        select(func.count(EvidenceNode.id)).where(
            EvidenceNode.tenant_id == "tenant-a",
            EvidenceNode.signal_type == "discovery.evidence_fusion",
        )
    ) == old_bundle_count + 1


def test_scan_evidence_pointer_advances_without_deleting_prior_bundle(
    db: Session,
) -> None:
    db.add(Tenant(id="tenant-scan", name="Tenant Scan", slug="tenant-scan"))
    db.flush()
    db.add(
        DiscoveryScan(
            scan_id="scan-phase-x",
            tenant_id="tenant-scan",
            name="Phase X evidence scan",
            requested_by=None,
            scan_type="targeted",
            scope_json={"mode": "metadata_only"},
            safety_profile="metadata_only",
            request_idempotency_key="phase-x-scan",
            request_digest="a" * 64,
            status="running",
            dry_run=False,
            started_at=NOW,
            completed_at=None,
            cancelled_at=None,
            observations_count=0,
            assets_created=0,
            assets_updated=0,
            assets_unresolved=0,
            warnings_json=[],
            errors_json=[],
            coverage_summary_json={},
            evidence_bundle_id=None,
            rescan_of_scan_id=None,
        )
    )
    first_row = _observation_row(
        tenant_id="tenant-scan",
        observation_id="scan-observation-a",
        source_surface="endpoint",
    )
    first_row.scan_id = "scan-phase-x"
    db.add(first_row)
    db.flush()

    first = fuse_scan_observations(
        db, tenant_id="tenant-scan", scan_id="scan-phase-x"
    )
    second_row = _observation_row(
        tenant_id="tenant-scan",
        observation_id="scan-observation-b",
        source_surface="cloud",
    )
    second_row.scan_id = "scan-phase-x"
    db.add(second_row)
    db.flush()
    second = fuse_scan_observations(
        db, tenant_id="tenant-scan", scan_id="scan-phase-x"
    )

    assert first.bundle_id != second.bundle_id
    scan = db.get(DiscoveryScan, "scan-phase-x")
    assert scan is not None
    assert scan.evidence_bundle_id == second.bundle_id
    assert db.scalar(
        select(func.count(EvidenceNode.id)).where(
            EvidenceNode.tenant_id == "tenant-scan",
            EvidenceNode.id.in_((first.bundle_id, second.bundle_id)),
        )
    ) == 2


def test_assignment_persistence_fuses_the_exact_scan_when_flag_is_enabled(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    ingest = Mock(return_value=SimpleNamespace(scan_id="scan-a"))
    fuse = Mock()
    finalize = Mock()
    monkeypatch.setattr(
        hmair_discovery_jobs,
        "settings",
        SimpleNamespace(hmair_fingerprinting=True),
    )
    monkeypatch.setattr(hmair_discovery_jobs, "ingest_observation", ingest)
    monkeypatch.setattr(
        hmair_discovery_jobs, "fuse_scan_observations", fuse
    )
    monkeypatch.setattr(
        hmair_discovery_jobs, "finalize_assignment", finalize
    )

    hmair_discovery_jobs._persist_in_execution(
        db,
        tenant_id="tenant-a",
        assignment_id="assignment-a",
        observations=(object(), object()),
    )

    assert ingest.call_count == 2
    fuse.assert_called_once_with(
        db, tenant_id="tenant-a", scan_id="scan-a"
    )
    finalize.assert_called_once_with(
        db,
        tenant_id="tenant-a",
        assignment_id="assignment-a",
        status="complete",
        observations_count=2,
    )


def _asset(db: Session, *, asset_id: str, evidence_id: str) -> DiscoveryAIAsset:
    row = DiscoveryAIAsset(
        asset_id=asset_id,
        tenant_id="tenant-ecosystem",
        asset_type="agent",
        canonical_name=asset_id,
        provider="azure",
        product="foundry",
        framework=None,
        version=None,
        deployment_family="cloud",
        technical_surface="runtime",
        environment="production",
        approved_status="unknown",
        lifecycle_status="active",
        shadow_ai_status="unknown",
        first_seen_at=NOW,
        last_seen_at=NOW,
        resolution_confidence=0.9,
        evidence_bundle_id=evidence_id,
        projection_version=1,
    )
    db.add(row)
    return row


def test_ecosystems_require_verified_graph_relationships_not_matching_labels(
    db: Session,
) -> None:
    db.add(Tenant(id="tenant-ecosystem", name="Tenant E", slug="tenant-e"))
    db.flush()
    evidence = EvidenceNode(
        id=str(uuid4()),
        tenant_id="tenant-ecosystem",
        correlation_id="ecosystem-proof",
        node_type="bundle",
        signal_type="discovery.relationship",
        label="Relationship evidence",
        payload={"classification": "metadata_only"},
    )
    db.add(evidence)
    db.flush()
    for asset_id in ("asset-a", "asset-b", "asset-c"):
        _asset(db, asset_id=asset_id, evidence_id=evidence.id)
    db.flush()
    nodes = {
        asset_id: create_graph_node(
            db,
            tenant_id="tenant-ecosystem",
            node_class="ai_asset",
            subject_reference=f"asset:{asset_id}",
            idempotency_key=f"phase-x-node-{asset_id}",
        )
        for asset_id in ("asset-a", "asset-b", "asset-c")
    }
    create_graph_edge(
        db,
        tenant_id="tenant-ecosystem",
        from_node_id=nodes["asset-a"].graph_node_id,
        to_node_id=nodes["asset-b"].graph_node_id,
        edge_type="calls",
        evidence_node_id=evidence.id,
        confidence=0.88,
        verification_state="verified",
        freshness="fresh",
        contradiction_state="none",
        first_observed_at=NOW,
        last_observed_at=NOW,
        idempotency_key="phase-x-edge-a-b",
    )
    create_graph_edge(
        db,
        tenant_id="tenant-ecosystem",
        from_node_id=nodes["asset-b"].graph_node_id,
        to_node_id=nodes["asset-c"].graph_node_id,
        edge_type="depends_on",
        evidence_node_id=evidence.id,
        confidence=0.7,
        verification_state="inferred",
        freshness="fresh",
        contradiction_state="none",
        first_observed_at=NOW,
        last_observed_at=NOW,
        idempotency_key="phase-x-edge-b-c-inferred",
    )

    first = resolve_ai_ecosystems(db, tenant_id="tenant-ecosystem")
    second = resolve_ai_ecosystems(db, tenant_id="tenant-ecosystem")

    assert first == second
    assert [row.asset_ids for row in first] == [
        ("asset-a", "asset-b"),
        ("asset-c",),
    ]
    assert first[0].confidence == 0.88
    assert first[0].evidence_refs == (evidence.id,)
    assert first[0].resolution_method == "verified_evidence_graph_component"
    assert first[1].resolution_method == "unconnected_canonical_asset"
    assert "matching provider and environment are not connection evidence" in (
        first[1].limitations
    )
    detail = get_ecosystem(
        first[0].ecosystem_id,
        ctx=SimpleNamespace(tenant=SimpleNamespace(id="tenant-ecosystem")),
        db=db,
    )
    assert detail.asset_ids == ["asset-a", "asset-b"]
    assert detail.evidence_refs == [evidence.id]
    assert detail.resolution_method == "verified_evidence_graph_component"
