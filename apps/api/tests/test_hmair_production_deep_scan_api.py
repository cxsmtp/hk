from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker

from app.api.routers import discovery_scans
from app.core.config import settings
from app.core.security import create_access_token
from app.db.models.audit import AuditLog
from app.db.models.discovery_canonical import (
    DiscoveryCollector,
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
from app.db.models.evidence import EvidenceNode
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app


@pytest.fixture()
def deep_scan_api_env(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[dict[str, object]]:
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'hmair-deep-scan-api.sqlite3'}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    session_factory: sessionmaker[Session] = sessionmaker(
        bind=engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )
    tables = [
        Tenant.__table__,
        User.__table__,
        UserTenantRole.__table__,
        AuditLog.__table__,
        EvidenceNode.__table__,
        EndpointDeviceIdentity.__table__,
        DiscoveryTarget.__table__,
        DiscoveryCollector.__table__,
        DiscoveryScan.__table__,
        DiscoveryScanTarget.__table__,
        DiscoveryScanAssignment.__table__,
        EndpointMetadataInventoryRun.__table__,
        EndpointMetadataInventoryAssignment.__table__,
    ]
    Base.metadata.create_all(bind=engine, tables=tables)
    now = datetime.now(UTC)
    with session_factory() as db:
        tenant = Tenant(name="Deep Scan Primary", slug="deep-scan-primary")
        other_tenant = Tenant(name="Deep Scan Other", slug="deep-scan-other")
        owner = User(
            email="deep-scan-owner@example.test",
            hashed_password="not-used-by-unit-tests",
            full_name="Deep Scan Owner",
            is_active=True,
        )
        viewer = User(
            email="deep-scan-viewer@example.test",
            hashed_password="not-used-by-unit-tests",
            full_name="Deep Scan Viewer",
            is_active=True,
        )
        other_owner = User(
            email="deep-scan-other@example.test",
            hashed_password="not-used-by-unit-tests",
            full_name="Deep Scan Other Owner",
            is_active=True,
        )
        db.add_all([tenant, other_tenant, owner, viewer, other_owner])
        db.flush()
        db.add_all(
            [
                UserTenantRole(user_id=owner.id, tenant_id=tenant.id, role="owner"),
                UserTenantRole(user_id=viewer.id, tenant_id=tenant.id, role="viewer"),
                UserTenantRole(
                    user_id=other_owner.id,
                    tenant_id=other_tenant.id,
                    role="owner",
                ),
            ]
        )
        db.add(
            DiscoveryTarget(
                target_id="endpoint-estate",
                tenant_id=tenant.id,
                target_type="endpoint_group",
                identifier="managed-endpoint-estate",
                environment="production",
                owner_hint="security",
                credentials_reference="endpoint-enrollment-v1",
                permitted_methods_json=["collect_inventory"],
                exclusions_json=[],
                rate_limit=100,
                active_scan_allowed=True,
                sensitive_scope=False,
                coverage_baseline_json={
                    "expected_count": 1,
                    "authority_kind": "mdm",
                    "authority_reference": "mdm-estate-2026-09",
                    "verified_at": (now - timedelta(minutes=1)).isoformat(),
                    "expires_at": (now + timedelta(days=1)).isoformat(),
                },
            )
        )
        db.add(
            DiscoveryCollector(
                collector_id="endpoint-metadata",
                tenant_id=tenant.id,
                collector_type="endpoint_metadata_snapshot",
                version="1.0.0",
                supported_targets_json=["endpoint_group"],
                active_capabilities_json=[],
                passive_capabilities_json=["installed_application"],
                permissions_required_json=["endpoint:discovery:write"],
                sensitive_data_accessed_json=[],
                health="healthy",
                last_success_at=now - timedelta(minutes=1),
                last_failure_at=None,
                data_residency="tenant-selected",
                control_capability="monitor_only",
                schema_version="v1",
                limitations_json=["metadata_only"],
                declaration_hash="a" * 64,
            )
        )
        db.add(
            EndpointDeviceIdentity(
                tenant_id=tenant.id,
                endpoint_id="managed-mac-1",
                public_key_pem="x" * 100,
                key_thumbprint="b" * 64,
                key_provider="macos_secure_enclave",
                status="active",
                scopes=["endpoint:discovery:write"],
                last_authenticated_at=now - timedelta(minutes=1),
            )
        )
        db.commit()

    for flag in (
        "hmair_core",
        "hmair_active_scan",
        "hmair_endpoint",
        "hmair_browser",
        "hmair_mcp_runtime",
        "hmair_cloud",
        "hmair_saas",
        "hmair_identity",
        "hmair_repository",
        "hmair_network",
        "hmair_database",
        "hmair_connector_sources",
    ):
        monkeypatch.setitem(settings.__dict__, flag, flag in {
            "hmair_core",
            "hmair_active_scan",
            "hmair_endpoint",
        })

    def _headers(user_id: str, tenant_id: str, role: str) -> dict[str, str]:
        return {
            "Authorization": "Bearer "
            + create_access_token(user_id, tenant_id=tenant_id, role=role),
            "X-Tenant-ID": tenant_id,
        }

    with session_factory() as db:
        tenant = db.scalar(select(Tenant).where(Tenant.slug == "deep-scan-primary"))
        other_tenant = db.scalar(select(Tenant).where(Tenant.slug == "deep-scan-other"))
        owner = db.scalar(select(User).where(User.email == "deep-scan-owner@example.test"))
        viewer = db.scalar(select(User).where(User.email == "deep-scan-viewer@example.test"))
        other_owner = db.scalar(select(User).where(User.email == "deep-scan-other@example.test"))
        assert tenant is not None and other_tenant is not None
        assert owner is not None and viewer is not None and other_owner is not None
        identities = {
            "owner": _headers(owner.id, tenant.id, "owner"),
            "viewer": _headers(viewer.id, tenant.id, "viewer"),
            "other_owner": _headers(other_owner.id, other_tenant.id, "owner"),
        }

    def override_get_db() -> Iterator[Session]:
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    dispatches: list[tuple[str, str]] = []
    monkeypatch.setattr(
        discovery_scans.dispatch_scan,
        "delay",
        lambda tenant_id, scan_id: dispatches.append((tenant_id, scan_id)),
    )
    client = TestClient(app)
    try:
        yield {
            "client": client,
            "headers": identities,
            "dispatches": dispatches,
            "session_factory": session_factory,
        }
    finally:
        client.close()
        app.dependency_overrides.clear()
        with engine.begin() as connection:
            connection.execute(
                DiscoveryScan.__table__.update().values(rescan_of_scan_id=None)
            )
        Base.metadata.drop_all(bind=engine, tables=list(reversed(tables)))
        engine.dispose()


def _preflight_body() -> dict[str, object]:
    return {
        "target_ids": ["endpoint-estate"],
        "collector_ids": ["endpoint-metadata"],
        "required_target_ids": ["endpoint-estate"],
        "time_window_minutes": 30,
        "customer_authorization_reference": "change-2026-09",
        "requested_mode": "partial",
    }


def test_owner_can_preflight_launch_and_view_bounded_deep_scan_coverage(
    deep_scan_api_env: dict[str, object],
) -> None:
    client = deep_scan_api_env["client"]
    headers = deep_scan_api_env["headers"]
    assert isinstance(client, TestClient)
    assert isinstance(headers, dict)
    owner_headers = headers["owner"]
    assert isinstance(owner_headers, dict)

    preflight = client.post(
        "/discovery/scans/deep-scan/preflight",
        headers=owner_headers,
        json=_preflight_body(),
    )
    assert preflight.status_code == 200
    preflight_body = preflight.json()
    assert preflight_body["exhaustive_claim_permitted"] is False
    assert preflight_body["sources"] == [
        {
            "target_id": "endpoint-estate",
            "collector_id": "endpoint-metadata",
            "target_type": "endpoint_group",
            "required": True,
            "readiness": "ready",
            "observation_mode": "authoritative",
            "expected_count": 1,
            "last_success_at": preflight_body["sources"][0]["last_success_at"],
            "limitations": [],
        }
    ]
    assert "change-2026-09" not in preflight.text
    session_factory = deep_scan_api_env["session_factory"]
    assert callable(session_factory)
    with session_factory() as db:
        preflight_audit = db.scalar(
            select(AuditLog).where(
                AuditLog.action == "discovery.deep_scan.preflight"
            )
        )
        assert preflight_audit is not None
        assert preflight_audit.payload == {
            "mode": "partial",
            "target_count": 1,
            "collector_count": 1,
            "ready_source_count": 1,
            "required_gap_count": 0,
        }
        assert "change-2026-09" not in str(preflight_audit.payload)

    launch_body = {
        "name": "Production Endpoint Deep Scan",
        "preflight": _preflight_body(),
        "preflight_digest": preflight_body["preflight_digest"],
        "dry_run": False,
    }
    launched = client.post(
        "/discovery/scans/deep-scan",
        headers={**owner_headers, "Idempotency-Key": "deep-scan-launch-001"},
        json=launch_body,
    )
    assert launched.status_code == 202
    launch_response = launched.json()
    assert launch_response["scan"]["scan_type"] == "targeted"
    assert launch_response["scan"]["safety_profile"] == "metadata_only"
    assert launch_response["ready_assignment_count"] == 1
    scan_id = launch_response["scan"]["scan_id"]
    with session_factory() as db:
        persisted_scan = db.scalar(
            select(DiscoveryScan).where(DiscoveryScan.scan_id == scan_id)
        )
        assert persisted_scan is not None
        assert "change-2026-09" not in str(persisted_scan.scope_json)
        stored_profile = persisted_scan.scope_json["deep_scan"]
        assert isinstance(stored_profile, dict)
        assert "customer_authorization_reference" not in stored_profile
        assert len(stored_profile["customer_approval_binding_hash"]) == 64
        assert len(stored_profile["storage_digest"]) == 64
        launch_audit = db.scalar(
            select(AuditLog).where(AuditLog.action == "discovery.deep_scan.launch")
        )
        assert launch_audit is not None
        assert launch_audit.payload == {
            "mode": "partial",
            "ready_source_count": 1,
            "dry_run": False,
        }
        assert "change-2026-09" not in str(launch_audit.payload)
    dispatches = deep_scan_api_env["dispatches"]
    assert isinstance(dispatches, list)
    assert len(dispatches) == 1

    coverage = client.get(
        f"/discovery/scans/{scan_id}/coverage",
        headers=owner_headers,
    )
    assert coverage.status_code == 200
    coverage_body = coverage.json()
    assert coverage_body["exhaustive_claim_permitted"] is False
    assert coverage_body["sources"][0]["coverage_state"] == "unknown"
    assert "change-2026-09" not in coverage.text

    repeated = client.post(
        "/discovery/scans/deep-scan",
        headers={**owner_headers, "Idempotency-Key": "deep-scan-launch-001"},
        json=launch_body,
    )
    assert repeated.status_code == 202
    assert repeated.json()["scan"]["scan_id"] == scan_id
    assert len(dispatches) == 1


def test_full_enterprise_request_stops_at_preflight_without_scope_closure(
    deep_scan_api_env: dict[str, object],
) -> None:
    client = deep_scan_api_env["client"]
    headers = deep_scan_api_env["headers"]
    assert isinstance(client, TestClient)
    assert isinstance(headers, dict)
    owner_headers = headers["owner"]
    assert isinstance(owner_headers, dict)
    full_request = {**_preflight_body(), "requested_mode": "full_enterprise"}

    preflight = client.post(
        "/discovery/scans/deep-scan/preflight",
        headers=owner_headers,
        json=full_request,
    )

    assert preflight.status_code == 200
    assert preflight.json()["exhaustive_claim_permitted"] is False
    launch = client.post(
        "/discovery/scans/deep-scan",
        headers={**owner_headers, "Idempotency-Key": "full-enterprise-blocked-001"},
        json={
            "name": "Unverified Enterprise Deep Scan",
            "preflight": full_request,
            "preflight_digest": preflight.json()["preflight_digest"],
            "dry_run": False,
        },
    )
    assert launch.status_code == 409


def test_deep_scan_launch_rejects_stale_preflight_and_non_owner_access(
    deep_scan_api_env: dict[str, object],
) -> None:
    client = deep_scan_api_env["client"]
    headers = deep_scan_api_env["headers"]
    assert isinstance(client, TestClient)
    assert isinstance(headers, dict)
    owner_headers = headers["owner"]
    viewer_headers = headers["viewer"]
    assert isinstance(owner_headers, dict)
    assert isinstance(viewer_headers, dict)

    assert (
        client.post(
            "/discovery/scans/deep-scan/preflight",
            headers=viewer_headers,
            json=_preflight_body(),
        ).status_code
        == 403
    )
    rejected = client.post(
        "/discovery/scans/deep-scan",
        headers={**owner_headers, "Idempotency-Key": "deep-scan-launch-002"},
        json={
            "name": "Stale Deep Scan",
            "preflight": _preflight_body(),
            "preflight_digest": "0" * 64,
            "dry_run": False,
        },
    )
    assert rejected.status_code == 409
    assert "change-2026-09" not in rejected.text


def test_deep_scan_coverage_is_not_visible_across_tenants(
    deep_scan_api_env: dict[str, object],
) -> None:
    client = deep_scan_api_env["client"]
    headers = deep_scan_api_env["headers"]
    assert isinstance(client, TestClient)
    assert isinstance(headers, dict)
    owner_headers = headers["owner"]
    other_owner_headers = headers["other_owner"]
    assert isinstance(owner_headers, dict)
    assert isinstance(other_owner_headers, dict)

    preflight = client.post(
        "/discovery/scans/deep-scan/preflight",
        headers=owner_headers,
        json=_preflight_body(),
    )
    assert preflight.status_code == 200
    launched = client.post(
        "/discovery/scans/deep-scan",
        headers={**owner_headers, "Idempotency-Key": "deep-scan-cross-tenant-001"},
        json={
            "name": "Tenant-isolated Deep Scan",
            "preflight": _preflight_body(),
            "preflight_digest": preflight.json()["preflight_digest"],
            "dry_run": False,
        },
    )
    assert launched.status_code == 202

    response = client.get(
        f"/discovery/scans/{launched.json()['scan']['scan_id']}/coverage",
        headers=other_owner_headers,
    )
    assert response.status_code == 404
    assert "endpoint-estate" not in response.text


def test_only_owner_can_register_a_metadata_only_h2_surface_source(
    deep_scan_api_env: dict[str, object],
) -> None:
    client = deep_scan_api_env["client"]
    headers = deep_scan_api_env["headers"]
    session_factory = deep_scan_api_env["session_factory"]
    assert isinstance(client, TestClient)
    assert isinstance(headers, dict)
    assert isinstance(session_factory, sessionmaker)
    owner_headers = headers["owner"]
    viewer_headers = headers["viewer"]
    assert isinstance(owner_headers, dict)
    assert isinstance(viewer_headers, dict)
    payload = {
        "source_kind": "managed_browser",
        "target_identifier": "acme-chrome",
        "environment": "production",
        "expected_count": 1,
        "authority_reference": "change-2026-09",
        "baseline_expires_at": (datetime.now(UTC) + timedelta(days=7)).isoformat(),
    }

    assert (
        client.post(
            "/discovery/surface-sources", headers=viewer_headers, json=payload
        ).status_code
        == 403
    )
    response = client.post(
        "/discovery/surface-sources", headers=owner_headers, json=payload
    )
    assert response.status_code == 201
    rendered = response.json()
    assert rendered["target_type"] == "browser_tenant"
    assert rendered["collector_health"] == "unknown"
    assert rendered["ready"] is False
    assert "change-2026-09" not in response.text
    assert AuditLog.__table__.c.resource_id.type.length >= len(rendered["target_id"])

    with session_factory() as db:
        target = db.scalar(
            select(DiscoveryTarget).where(
                DiscoveryTarget.target_id == rendered["target_id"]
            )
        )
        collector = db.scalar(
            select(DiscoveryCollector).where(
                DiscoveryCollector.collector_id == rendered["collector_id"]
            )
        )
        audit = db.scalar(
            select(AuditLog).where(
                AuditLog.action == "discovery.surface_source.registered",
                AuditLog.resource_id == rendered["target_id"],
            )
        )
        assert target is not None and target.active_scan_allowed is True
        assert collector is not None and collector.health == "unknown"
        assert audit is not None
