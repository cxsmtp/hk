from __future__ import annotations

import os
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.session import Base, get_db
from app.main import app


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "scan_engine.sqlite3"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    testing_session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = testing_session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield {"client": client}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Scan Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
        "user_id": body["user"]["id"],
    }


def _ingest_unknown_browser_event(client: TestClient, *, headers: dict[str, str], domain: str, endpoint_id: str) -> None:
    response = client.post(
        "/telemetry/browser",
        headers=headers,
        json={
            "event_type": "unknown_ai_detected",
            "domain": domain,
            "url": f"https://{domain}/chat",
            "page_title": "Unknown AI",
            "action_taken": "discover",
            "input_signal_types": ["domain_policy_mismatch"],
            "endpoint_id": endpoint_id,
            "browser": "chrome",
            "browser_version": "124.0.0",
            "extension_version": "1.0.0",
            "hostname": endpoint_id,
            "device_type": "laptop",
            "os_type": "mac",
            "os_version": "14",
            "ip_address": "10.0.0.10",
            "location": "HQ",
        },
    )
    assert response.status_code == 200, response.text


def _wait_for_scan_completion(client: TestClient, *, headers: dict[str, str], scan_id: str, timeout_seconds: float = 5.0) -> dict:
    deadline = time.time() + timeout_seconds
    last_payload: dict = {}
    while time.time() < deadline:
        response = client.get(f"/scans/{scan_id}", headers=headers)
        assert response.status_code == 200, response.text
        last_payload = response.json()
        if last_payload.get("status") in {"completed", "failed"}:
            return last_payload
        time.sleep(0.05)
    return last_payload


def test_scan_trigger_populates_latest_scan_card(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="scan-card-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _ingest_unknown_browser_event(
        client,
        headers=headers,
        domain="scan-shadow-one.example.ai",
        endpoint_id="scan-endpoint-001",
    )

    trigger = client.post(
        "/scans/trigger",
        headers=headers,
        json={"scan_type": "discovery", "scope": "global", "parameters": {}},
    )
    assert trigger.status_code == 202, trigger.text
    trigger_body = trigger.json()
    assert trigger_body["scan_id"]
    assert trigger_body["status"] == "running"

    completed = _wait_for_scan_completion(client, headers=headers, scan_id=trigger_body["scan_id"])
    assert completed["status"] == "completed"
    assert completed["data_source"] == "active_runtime_crawl"
    assert completed["summary"]["new_ai_apps_detected"] >= 1
    assert completed["summary"]["unknown_apps"] >= 1
    assert int(completed["snapshot_counts"]["apps"]) >= 1
    assert completed["links"]["new_ai_apps"]

    dashboard = client.get("/dashboard/command-center?time_window_hours=168", headers=headers)
    assert dashboard.status_code == 200, dashboard.text
    dashboard_body = dashboard.json()
    assert dashboard_body["ai_exposure_scan"]["scan_id"] == trigger_body["scan_id"]
    assert dashboard_body["ai_exposure_scan"]["status"] == "completed"
    assert dashboard_body["ai_exposure_scan"]["summary"]["unknown_apps"] >= 1
    assert dashboard_body["ai_exposure_scan"]["links"]["full_report"].startswith("/shadow-ai")


def test_scan_delta_tracks_new_apps_between_runs(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="scan-delta-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _ingest_unknown_browser_event(
        client,
        headers=headers,
        domain="scan-delta-old.example.ai",
        endpoint_id="scan-endpoint-101",
    )

    first = client.post(
        "/scans/trigger",
        headers=headers,
        json={"scan_type": "discovery", "scope": "global", "parameters": {}},
    )
    assert first.status_code == 202, first.text
    first_payload = _wait_for_scan_completion(client, headers=headers, scan_id=first.json()["scan_id"])
    assert first_payload["status"] == "completed"

    _ingest_unknown_browser_event(
        client,
        headers=headers,
        domain="scan-delta-new.example.ai",
        endpoint_id="scan-endpoint-102",
    )

    second = client.post(
        "/scans/trigger",
        headers=headers,
        json={"scan_type": "discovery", "scope": "global", "parameters": {}},
    )
    assert second.status_code == 202, second.text
    second_payload = _wait_for_scan_completion(client, headers=headers, scan_id=second.json()["scan_id"])
    assert second_payload["status"] == "completed"
    assert second_payload["summary"]["new_ai_apps_detected"] >= 1
    app_names = {str(item.get("name") or "").strip() for item in second_payload["delta"]["apps_added"]}
    assert "scan-delta-new.example.ai" in app_names

    latest = client.get("/scans/latest", headers=headers)
    assert latest.status_code == 200, latest.text
    latest_body = latest.json()
    assert latest_body["scan_id"] == second.json()["scan_id"]
    assert latest_body["data_source"] == "active_runtime_crawl"
    assert latest_body["summary"]["new_ai_apps_detected"] >= 1
