from __future__ import annotations

from collections.abc import Iterator

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.security import create_access_token
from app.db.models.monitoring import MonitoringSignal
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app


@pytest.fixture()
def extension_control_env(tmp_path) -> Iterator[dict[str, object]]:
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'extension-removal-controls.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    session_factory: sessionmaker[Session] = sessionmaker(
        bind=engine, autocommit=False, autoflush=False, expire_on_commit=False
    )
    Base.metadata.create_all(bind=engine)

    with session_factory() as db:
        tenant = Tenant(name="Browser Control Tenant", slug="browser-control")
        owner = User(email="owner@example.test", hashed_password="x", full_name="Owner", is_active=True)
        viewer = User(email="viewer@example.test", hashed_password="x", full_name="Viewer", is_active=True)
        db.add_all([tenant, owner, viewer])
        db.flush()
        db.add_all(
            [
                UserTenantRole(user_id=owner.id, tenant_id=tenant.id, role="owner"),
                UserTenantRole(user_id=viewer.id, tenant_id=tenant.id, role="viewer"),
            ]
        )
        db.commit()
        tenant_id = tenant.id
        owner_id = owner.id
        viewer_id = viewer.id

    def _headers(user_id: str, role: str) -> dict[str, str]:
        return {
            "Authorization": "Bearer " + create_access_token(user_id, tenant_id=tenant_id, role=role),
            "X-Tenant-ID": tenant_id,
        }

    def override_get_db() -> Iterator[Session]:
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield {
            "client": client,
            "SessionLocal": session_factory,
            "headers": {
                "owner": _headers(owner_id, "owner"),
                "viewer": _headers(viewer_id, "viewer"),
            },
        }
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _disabled_status_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "browser": "chrome",
        "browser_profile": "work",
        "extension_id": "abcdefghijklmnopabcdefghijklmnop",
        "extension_name": "AI Control Plane - Discovery & Guard",
        "extension_version": "1.2.3",
        "endpoint_id": "macbook-01",
        "hostname": "macbook-01",
        "healthy": False,
        "status": "disabled",
        "status_trigger": "extension_disabled",
    }
    payload.update(overrides)
    return payload


def test_extension_disable_without_admin_authorization_is_tamper(extension_control_env) -> None:
    client: TestClient = extension_control_env["client"]  # type: ignore[assignment]
    headers = extension_control_env["headers"]["viewer"]  # type: ignore[index]

    response = client.post("/extension/status", headers=headers, json=_disabled_status_payload())

    assert response.status_code == 200
    with extension_control_env["SessionLocal"]() as db:  # type: ignore[index]
        signal = db.scalar(
            select(MonitoringSignal).where(
                MonitoringSignal.signal_type == "browser.extension_health_status",
                MonitoringSignal.payload["extension_removal_control"]["classification"].as_string()
                == "unauthorized_disable_or_removal",
            )
        )
        assert signal is not None
        assert signal.severity == "critical"
        assert signal.payload["governance_recommendation"] == "investigate_extension_tamper_or_unapproved_disablement"


def test_owner_authorization_marks_extension_disable_as_planned(extension_control_env) -> None:
    client: TestClient = extension_control_env["client"]  # type: ignore[assignment]
    headers = extension_control_env["headers"]  # type: ignore[assignment]

    authorization = client.post(
        "/extension/admin/removal-authorizations",
        headers=headers["owner"],
        json={
            "browser": "chrome",
            "browser_profile": "work",
            "extension_id": "abcdefghijklmnopabcdefghijklmnop",
            "endpoint_id": "macbook-01",
            "hostname": "macbook-01",
            "action": "disable",
            "reason": "Planned extension upgrade test",
            "expires_minutes": 15,
        },
    )

    assert authorization.status_code == 200
    authorization_id = authorization.json()["authorization_id"]

    response = client.post(
        "/extension/status",
        headers=headers["viewer"],
        json=_disabled_status_payload(removal_authorization_id=authorization_id),
    )

    assert response.status_code == 200
    with extension_control_env["SessionLocal"]() as db:  # type: ignore[index]
        signal = db.scalar(
            select(MonitoringSignal).where(
                MonitoringSignal.signal_type == "browser.extension_health_status",
                MonitoringSignal.payload["extension_removal_control"]["classification"].as_string()
                == "admin_authorized_disable_or_removal",
            )
        )
        assert signal is not None
        assert signal.severity == "med"
        assert signal.payload["governance_recommendation"] == "extension_disable_or_removal_authorized"


def test_viewer_cannot_create_extension_removal_authorization(extension_control_env) -> None:
    client: TestClient = extension_control_env["client"]  # type: ignore[assignment]
    headers = extension_control_env["headers"]["viewer"]  # type: ignore[index]

    response = client.post(
        "/extension/admin/removal-authorizations",
        headers=headers,
        json={
            "browser": "chrome",
            "extension_id": "abcdefghijklmnopabcdefghijklmnop",
            "action": "remove",
            "reason": "not allowed",
        },
    )

    assert response.status_code == 403


def test_extension_health_summary_shows_trusted_id_duplicates_and_tamper(extension_control_env) -> None:
    client: TestClient = extension_control_env["client"]  # type: ignore[assignment]
    headers = extension_control_env["headers"]  # type: ignore[assignment]

    healthy = client.post(
        "/extension/status",
        headers=headers["viewer"],
        json=_disabled_status_payload(
            extension_id="trusted-chrome-extension-id",
            extension_version="2.0.0",
            healthy=True,
            status="ok",
            status_trigger="heartbeat",
            telemetry_queue_depth=0,
            last_sync_at="2026-09-20T09:00:00Z",
        ),
    )
    assert healthy.status_code == 200

    duplicate = client.post(
        "/extension/status",
        headers=headers["viewer"],
        json=_disabled_status_payload(
            extension_id="duplicate-loaded-extension-id",
            extension_version="2.0.0",
            healthy=True,
            status="ok",
            status_trigger="heartbeat",
            telemetry_queue_depth=1,
            last_sync_at="2026-09-20T09:01:00Z",
        ),
    )
    assert duplicate.status_code == 200

    tamper = client.post(
        "/extension/status",
        headers=headers["viewer"],
        json=_disabled_status_payload(
            extension_id="trusted-chrome-extension-id",
            extension_version="2.0.0",
            healthy=False,
            status="disabled",
            status_trigger="extension_disabled",
            telemetry_queue_depth=3,
            last_sync_at="2026-09-20T09:02:00Z",
        ),
    )
    assert tamper.status_code == 200

    response = client.get("/extension/health", headers=headers["viewer"])

    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"]
    assert body["status"] == "tamper_suspected"
    assert body["trusted_extension_id"] == "trusted-chrome-extension-id"
    assert body["trusted_source"] == "tamper_event_extension_id"
    assert body["latest_heartbeat_at"]
    assert "duplicate-loaded-extension-id" in body["duplicate_extension_ids"]
    assert body["latest_status"]["extension_id"] == "trusted-chrome-extension-id"
    assert body["tamper_events"][0]["classification"] == "unauthorized_disable_or_removal"
    assert body["instances"]
    assert "hard_removal_prevention_requires_managed_browser_policy_or_mdm" in body["limitations"]


def test_extension_removal_governance_exposes_admin_mdm_and_audit_controls(extension_control_env) -> None:
    client: TestClient = extension_control_env["client"]  # type: ignore[assignment]
    headers = extension_control_env["headers"]  # type: ignore[assignment]

    heartbeat = client.post(
        "/extension/status",
        headers=headers["viewer"],
        json=_disabled_status_payload(
            extension_id="trusted-chrome-extension-id",
            extension_version="2.0.0",
            healthy=True,
            status="ok",
            status_trigger="heartbeat",
            telemetry_queue_depth=0,
            last_sync_at="2026-09-20T09:00:00Z",
        ),
    )
    assert heartbeat.status_code == 200

    response = client.get("/extension/governance/removal", headers=headers["owner"])

    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"]
    assert body["admin_removal_required"] is True
    assert body["hard_prevention_requires_mdm"] is True
    assert body["trusted_extension_id"] == "trusted-chrome-extension-id"
    assert "extension_cannot_prevent_its_own_uninstall" in body["limitations"]
    assert "extension.removal_authorization.create" in body["audit_events"]
    assert any(control["id"] == "admin_removal_authorization" for control in body["controls"])
    assert any(control["id"] == "mdm_hard_prevention" for control in body["controls"])

    chrome = next(policy for policy in body["mdm_policies"] if policy["browser"] == "chrome")
    assert chrome["required_policy"] == "ExtensionSettings / force_installed"
    assert chrome["trusted_extension_id"] == "trusted-chrome-extension-id"
    assert chrome["policy_payload"]["trusted-chrome-extension-id"]["installation_mode"] == "force_installed"

    safari = next(policy for policy in body["mdm_policies"] if policy["browser"] == "safari")
    assert safari["status"] == "mdm_required"
    assert "requires_customer_mdm_receipt_before_verified_coverage" in safari["limitations"]
