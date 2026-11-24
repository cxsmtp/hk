from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.discovery_canonical import (
    DiscoveryCollector,
    DiscoveryObservation,
    DiscoveryScan,
    DiscoveryScanAssignment,
    DiscoveryScanTarget,
    DiscoveryTarget,
)
from app.db.models.endpoint_identity import EndpointDeviceIdentity
from app.db.models.endpoint_metadata_inventory import (
    EndpointMetadataInventoryAssignment,
    EndpointMetadataInventoryRun,
)
from app.db.models.ai_asset import DiscoveryAIAsset, DiscoveryEvidenceClaim
from app.db.models.evidence import EvidenceEdge, EvidenceNode
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base
from app.services.hmair.endpoint_metadata_inventory_service import (
    create_endpoint_metadata_inventory_run,
    get_endpoint_metadata_inventory_run,
    next_endpoint_metadata_inventory_assignment,
)
from app.services.hmair.deep_scan_contracts import DeepScanPreflightRequest
from app.services.hmair.deep_scan_readiness_service import preflight_deep_scan

try:
    from app.services.hmair.endpoint_snapshot_service import (
        EndpointMetadataSnapshotInput,
        project_endpoint_metadata_snapshot,
    )
except ImportError:  # TDD: the assertion below is the expected red state.
    EndpointMetadataSnapshotInput = None
    project_endpoint_metadata_snapshot = None

try:
    from app.services.hmair.endpoint_snapshot_service import (
        ingest_endpoint_metadata_snapshot,
    )
except ImportError:  # TDD: the assertion below is the expected red state.
    ingest_endpoint_metadata_snapshot = None


@pytest.fixture()
def snapshot_db() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    tables = [
        Tenant.__table__,
        User.__table__,
        UserTenantRole.__table__,
        EndpointDeviceIdentity.__table__,
        EndpointMetadataInventoryRun.__table__,
        EndpointMetadataInventoryAssignment.__table__,
        EvidenceNode.__table__,
        EvidenceEdge.__table__,
        DiscoveryAIAsset.__table__,
        DiscoveryEvidenceClaim.__table__,
        DiscoveryTarget.__table__,
        DiscoveryCollector.__table__,
        DiscoveryScan.__table__,
        DiscoveryScanTarget.__table__,
        DiscoveryScanAssignment.__table__,
        DiscoveryObservation.__table__,
    ]
    Base.metadata.create_all(engine, tables=tables)
    db = Session(engine)
    tenant = Tenant(name="Snapshot Lab", slug="snapshot-lab", is_active=True)
    user = User(
        email="snapshot-owner@example.test",
        hashed_password="not-used-by-unit-tests",
        full_name="Snapshot Owner",
        is_active=True,
    )
    db.add_all([tenant, user])
    db.flush()
    db.add(UserTenantRole(user_id=user.id, tenant_id=tenant.id, role="owner"))
    db.flush()
    db.info["tenant_id"] = tenant.id
    db.info["user_id"] = user.id
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(engine, tables=list(reversed(tables)))
        engine.dispose()


def _snapshot_payload() -> dict[str, object]:
    return {
        "snapshot_id": "lab-snapshot-001",
        "schema_version": "hawk.endpoint_metadata.v1",
        "collected_at": "2026-09-03T12:00:00Z",
        "collection_mode": "one_shot_read_only",
        "status": "completed",
        "network_used": False,
        "products": [
            {
                "id": "codex_cli",
                "name": "Codex CLI",
                "provider": "openai",
                "category": "cli",
                "presence": "present",
                "version": "1.2.3",
                "evidence_types": ["executable", "configuration"],
                "approval_status": "unknown",
                "account": {
                    "status": "unknown",
                    "identifiers_collected": False,
                },
            }
        ],
        "extensions": [
            {
                "id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "name": "Claude AI Assistant",
                "provider": "anthropic",
                "host": "chrome",
                "category": "browser",
                "presence": "present",
                "version": "2.3.4",
                "approval_status": "unknown",
            }
        ],
        "configurations": [
            {
                "product_id": "codex_cli",
                "kind": "mcp_agent_configuration",
                "source": "codex_config",
                "status": "present",
                "metadata": {
                    "model": "gpt-5-codex",
                    "model_provider": "openai",
                    "approval_policy": "on-request",
                    "mcp_server_names": ["filesystem"],
                },
            }
        ],
        "errors": [],
        "privacy": {
            "raw_file_contents_collected": False,
            "prompts_collected": False,
            "browser_history_collected": False,
            "cookies_collected": False,
            "secrets_or_tokens_collected": False,
            "account_identifiers_collected": False,
            "persistent_state_written": False,
        },
    }


def test_mcp_connection_metadata_remains_configuration_only() -> None:
    payload = _snapshot_payload()
    metadata = payload["configurations"][0]["metadata"]
    name = metadata["mcp_server_names"][0]
    metadata["mcp_servers"] = [{"name": name, "transport": "remote", "destination_host": "docs.example.com"}]
    snapshot = EndpointMetadataSnapshotInput.model_validate(payload)
    observations = project_endpoint_metadata_snapshot(snapshot=snapshot, endpoint_id="endpoint-1", scan_id="scan-1", collector_id="collector-1", collector_version="1.0.0", target_id="target-1")
    server = next(row for row in observations if row.candidate_asset_type == "mcp_server")
    assert server.attributes["destination_host"] == "docs.example.com"
    assert server.observed_state == "configured"
    assert server.configuration_summary["runtime_activity_observed"] is False


def test_projects_safe_endpoint_snapshot_into_direct_hmair_observations() -> None:
    assert EndpointMetadataSnapshotInput is not None
    assert project_endpoint_metadata_snapshot is not None

    snapshot = EndpointMetadataSnapshotInput.model_validate(_snapshot_payload())
    observations = project_endpoint_metadata_snapshot(
        snapshot=snapshot,
        scan_id="00000000-0000-4000-8000-000000000001",
        collector_id="endpoint-metadata:lab-endpoint-1",
        collector_version="1.0.0",
        target_id="endpoint-group:lab-endpoint-1",
        endpoint_id="lab-endpoint-1",
    )

    assert [item.observation_type for item in observations] == [
        "installed_application",
        "browser_extension",
        "agent_config",
        "mcp_server",
    ]
    assert [item.source_surface.value for item in observations] == [
        "endpoint",
        "browser",
        "endpoint",
        "mcp",
    ]
    assert all(item.evidence_mode.value == "direct" for item in observations)
    assert all(item.verification_state.value == "partially_verified" for item in observations)
    assert all(item.collection_scope["endpoint_denominator"] == 1 for item in observations)
    assert all(item.observed_at == datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc) for item in observations)


def test_projects_a_strict_four_part_semantic_extension_version() -> None:
    assert EndpointMetadataSnapshotInput is not None
    assert project_endpoint_metadata_snapshot is not None
    payload = _snapshot_payload()
    payload["extensions"][0]["version"] = "1.26.901.11451"
    snapshot = EndpointMetadataSnapshotInput.model_validate(payload)

    observations = project_endpoint_metadata_snapshot(
        snapshot=snapshot,
        scan_id="00000000-0000-4000-8000-000000000001",
        collector_id="endpoint-metadata:lab-endpoint-1",
        collector_version="1.0.0",
        target_id="endpoint-group:lab-endpoint-1",
        endpoint_id="lab-endpoint-1",
    )

    assert observations[1].attributes["version"] == "1.26.901.11451"


def test_rejects_raw_or_private_material_in_endpoint_snapshot() -> None:
    assert EndpointMetadataSnapshotInput is not None
    payload = _snapshot_payload()
    payload["configurations"] = [
        {
            "product_id": "codex_cli",
            "kind": "mcp_agent_configuration",
            "source": "codex_config",
            "status": "present",
            "metadata": {"prompt": "customer raw prompt must never upload"},
        }
    ]

    with pytest.raises(ValueError):
        EndpointMetadataSnapshotInput.model_validate(payload)


def test_snapshot_accepts_a_strict_four_part_semantic_extension_version() -> None:
    assert EndpointMetadataSnapshotInput is not None
    payload = _snapshot_payload()
    payload["extensions"][0]["version"] = "1.26.901.11451"

    snapshot = EndpointMetadataSnapshotInput.model_validate(payload)

    assert snapshot.extensions[0].version == "1.26.901.11451"


def test_snapshot_rejects_a_dotted_telephone_shaped_extension_version() -> None:
    assert EndpointMetadataSnapshotInput is not None
    payload = _snapshot_payload()
    payload["extensions"][0]["version"] = "971.50.123.4567"

    with pytest.raises(ValueError):
        EndpointMetadataSnapshotInput.model_validate(payload)


def test_snapshot_model_accepts_only_a_typed_inventory_assignment_reference() -> None:
    assert EndpointMetadataSnapshotInput is not None
    payload = _snapshot_payload()
    payload["inventory_assignment_id"] = "e08d8ca9-b31c-4fe6-b559-b9ca57bf2e06"

    snapshot = EndpointMetadataSnapshotInput.model_validate(payload)

    assert str(snapshot.inventory_assignment_id) == "e08d8ca9-b31c-4fe6-b559-b9ca57bf2e06"

    payload["inventory_assignment_id"] = "not-an-assignment-id"
    with pytest.raises(ValueError):
        EndpointMetadataSnapshotInput.model_validate(payload)


def test_projection_does_not_expose_the_raw_endpoint_identifier() -> None:
    assert EndpointMetadataSnapshotInput is not None
    assert project_endpoint_metadata_snapshot is not None
    snapshot = EndpointMetadataSnapshotInput.model_validate(_snapshot_payload())

    observations = project_endpoint_metadata_snapshot(
        snapshot=snapshot,
        scan_id="00000000-0000-4000-8000-000000000001",
        collector_id="endpoint-metadata:lab-endpoint-1",
        collector_version="1.0.0",
        target_id="endpoint-group:lab-endpoint-1",
        endpoint_id="finance-laptop-Ayush",
    )

    assert "finance-laptop-Ayush" not in json.dumps(
        [item.model_dump(mode="json") for item in observations], sort_keys=True
    )


def test_persists_one_endpoint_scoped_passive_scan_idempotently(
    snapshot_db: Session,
) -> None:
    assert EndpointMetadataSnapshotInput is not None
    assert ingest_endpoint_metadata_snapshot is not None
    snapshot = EndpointMetadataSnapshotInput.model_validate(_snapshot_payload())
    snapshot_db.add(
        EndpointDeviceIdentity(
            tenant_id=snapshot_db.info["tenant_id"],
            endpoint_id="finance-laptop-Ayush",
            assigned_user_id=snapshot_db.info["user_id"],
            public_key_pem="-----BEGIN PUBLIC KEY-----\nunit\n-----END PUBLIC KEY-----",
            key_thumbprint="endpoint-h2-unit-thumbprint",
            key_provider="secure_enclave",
            status="active",
            scopes=["endpoint:discovery:write"],
            enrolled_by_user_id=snapshot_db.info["user_id"],
            last_authenticated_at=snapshot.collected_at,
        )
    )
    snapshot_db.flush()

    first = ingest_endpoint_metadata_snapshot(
        snapshot_db,
        tenant_id=snapshot_db.info["tenant_id"],
        actor_user_id=snapshot_db.info["user_id"],
        endpoint_id="finance-laptop-Ayush",
        collector_version="1.0.0",
        snapshot=snapshot,
    )
    second = ingest_endpoint_metadata_snapshot(
        snapshot_db,
        tenant_id=snapshot_db.info["tenant_id"],
        actor_user_id=snapshot_db.info["user_id"],
        endpoint_id="finance-laptop-Ayush",
        collector_version="1.0.0",
        snapshot=snapshot,
    )

    assert first.scan_id == second.scan_id
    assert first.status == "complete"
    assert first.observations_count == 4
    assert first.endpoint_denominator == 1
    assert "saas:not_connected" in first.limitations
    scans = list(snapshot_db.scalars(select(DiscoveryScan)))
    observations = list(snapshot_db.scalars(select(DiscoveryObservation)))
    targets = list(snapshot_db.scalars(select(DiscoveryTarget)))
    collectors = list(snapshot_db.scalars(select(DiscoveryCollector)))
    assert len(scans) == 1
    assert len(observations) == 4
    assert len(targets) == 1
    assert len(collectors) == 1
    assert scans[0].scan_type == "collector_specific"
    assert scans[0].dry_run is False
    assert scans[0].scope_json["endpoint_denominator"] == 1
    assert scans[0].scope_json["coverage_claim"] == "single_enrolled_endpoint"
    assert targets[0].active_scan_allowed is True
    assert targets[0].permitted_methods_json == ["collect_inventory"]
    assert targets[0].coverage_baseline_json["authority_kind"] == "mdm"
    readiness = preflight_deep_scan(
        snapshot_db,
        tenant_id=snapshot_db.info["tenant_id"],
        request=DeepScanPreflightRequest.model_validate(
            {
                "target_ids": [targets[0].target_id],
                "collector_ids": [collectors[0].collector_id],
                "required_target_ids": [targets[0].target_id],
                "time_window_minutes": 30,
                "customer_authorization_reference": "endpoint-h2-unit",
                "requested_mode": "partial",
            }
        ),
        now=snapshot.collected_at,
    )
    assert readiness.sources[0].state == "ready"
    assert all(row.source_surface in {"endpoint", "browser", "mcp"} for row in observations)
    serialized = json.dumps(
        [row.normalized_signal_json for row in observations], sort_keys=True
    )
    assert "finance-laptop-Ayush" not in serialized


def test_persists_a_strict_semantic_extension_version_without_phone_redaction(
    snapshot_db: Session,
) -> None:
    assert EndpointMetadataSnapshotInput is not None
    assert ingest_endpoint_metadata_snapshot is not None
    payload = _snapshot_payload()
    payload["extensions"][0]["version"] = "1.26.901.11451"

    receipt = ingest_endpoint_metadata_snapshot(
        snapshot_db,
        tenant_id=snapshot_db.info["tenant_id"],
        actor_user_id=snapshot_db.info["user_id"],
        endpoint_id="finance-laptop-Ayush",
        collector_version="1.0.0",
        snapshot=EndpointMetadataSnapshotInput.model_validate(payload),
    )

    row = snapshot_db.scalar(
        select(DiscoveryObservation).where(
            DiscoveryObservation.scan_id == receipt.scan_id,
            DiscoveryObservation.observation_type == "browser_extension",
        )
    )
    assert row is not None
    assert row.attributes_json["version"] == "1.26.901.11451"


def test_fingerprinting_enabled_snapshot_creates_a_tenant_scoped_evidence_bundle(
    snapshot_db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An enrolled endpoint receipt gets evidence, never an implied org-wide asset."""

    assert EndpointMetadataSnapshotInput is not None
    assert ingest_endpoint_metadata_snapshot is not None
    monkeypatch.setattr(settings, "hmair_fingerprinting", True)

    receipt = ingest_endpoint_metadata_snapshot(
        snapshot_db,
        tenant_id=snapshot_db.info["tenant_id"],
        actor_user_id=snapshot_db.info["user_id"],
        endpoint_id="finance-laptop-Ayush",
        collector_version="1.0.0",
        snapshot=EndpointMetadataSnapshotInput.model_validate(_snapshot_payload()),
    )

    scan = snapshot_db.scalar(
        select(DiscoveryScan).where(DiscoveryScan.scan_id == receipt.scan_id)
    )
    assert scan is not None
    assert scan.evidence_bundle_id is not None
    nodes = list(snapshot_db.scalars(select(EvidenceNode)))
    claims = list(snapshot_db.scalars(select(DiscoveryEvidenceClaim)))
    assert any(node.id == scan.evidence_bundle_id for node in nodes)
    assert len(claims) == receipt.observations_count
    serialized = json.dumps([node.payload for node in nodes], sort_keys=True)
    assert "finance-laptop-Ayush" not in serialized
    assert "single_enrolled_endpoint" in serialized


def test_snapshot_atomically_completes_its_server_issued_inventory_assignment(
    snapshot_db: Session,
) -> None:
    assert EndpointMetadataSnapshotInput is not None
    assert ingest_endpoint_metadata_snapshot is not None
    tenant_id = snapshot_db.info["tenant_id"]
    identity = EndpointDeviceIdentity(
        tenant_id=tenant_id,
        endpoint_id="inventory-mac-1",
        public_key_pem="k" * 100,
        key_thumbprint="d" * 64,
        key_provider="macos_secure_enclave",
        status="active",
        scopes=["endpoint:discovery:write"],
    )
    snapshot_db.add(identity)
    snapshot_db.flush()
    issued_at = datetime.now(timezone.utc)
    run = create_endpoint_metadata_inventory_run(
        snapshot_db,
        tenant_id=tenant_id,
        requested_by_user_id=snapshot_db.info["user_id"],
        request_idempotency_key="snapshot-assignment-001",
        endpoint_ids=None,
        expires_in_minutes=30,
        now=issued_at,
    )
    directive = next_endpoint_metadata_inventory_assignment(
        snapshot_db,
        tenant_id=tenant_id,
        endpoint_identity_id=identity.id,
        now=issued_at,
    )
    assert directive is not None
    payload = _snapshot_payload()
    payload["inventory_assignment_id"] = directive.assignment_id
    snapshot = EndpointMetadataSnapshotInput.model_validate(payload)

    receipt = ingest_endpoint_metadata_snapshot(
        snapshot_db,
        tenant_id=tenant_id,
        actor_user_id=snapshot_db.info["user_id"],
        endpoint_id=identity.endpoint_id,
        endpoint_identity_id=identity.id,
        collector_version="1.0.0",
        snapshot=snapshot,
    )
    updated = get_endpoint_metadata_inventory_run(
        snapshot_db,
        tenant_id=tenant_id,
        run_id=run.id,
        now=issued_at.replace(microsecond=0) + timedelta(minutes=1),
    )

    assert receipt.status == "complete"
    assert updated.status == "complete"
    assert updated.completed_count == 1
