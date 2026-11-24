from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.core.config import settings
from app.db.session import Base, get_db
from app.main import app


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "auditor_snapshot_scope.sqlite3"
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
    original_flag = settings.auditor_tenant_snapshot_enabled
    settings.auditor_tenant_snapshot_enabled = False
    try:
        yield {"client": client}
    finally:
        settings.auditor_tenant_snapshot_enabled = original_flag
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": PASSWORD,
            "full_name": "Snapshot Scope Owner",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
    }


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "X-Tenant-ID": tenant_id,
    }


def _create_ai_system(client: TestClient, headers: dict[str, str], *, name: str, risk_tier: str) -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": name, "description": "", "risk_tier": risk_tier},
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _items(payload: dict) -> list[dict]:
    assert set(payload.keys()) == {"items", "total", "page", "page_size"}
    return payload["items"]


def test_snapshot_requires_ai_system_by_default(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="snapshot-default-required@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/auditor/snapshot",
        headers=headers,
        json={"trigger_type": "manual", "payload": {"k": "v"}},
    )
    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "AI_SYSTEM_ID_REQUIRED"
    assert detail["reason_code"] == "AI_SYSTEM_ID_MISSING_FOR_SNAPSHOT"

    audits_response = client.get("/trust-center/audit-logs?page=1&page_size=200", headers=headers)
    assert audits_response.status_code == 200, audits_response.text
    audits = _items(audits_response.json())
    assert any(
        row["action"] == "governance.context.blocked"
        and (row.get("payload") or {}).get("reason_code") == "AI_SYSTEM_ID_MISSING_FOR_SNAPSHOT"
        for row in audits
    )

    evidence_response = client.get("/trust-center/evidence/nodes?page=1&page_size=200", headers=headers)
    assert evidence_response.status_code == 200, evidence_response.text
    nodes = _items(evidence_response.json())
    assert any(
        row["node_type"] == "governance_context_block"
        and (row.get("payload") or {}).get("reason_code") == "AI_SYSTEM_ID_MISSING_FOR_SNAPSHOT"
        for row in nodes
    )


def test_tenant_scope_disabled_by_default(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="snapshot-tenant-disabled@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    now = datetime.now(timezone.utc)
    response = client.post(
        "/auditor/snapshot",
        headers=headers,
        json={
            "tenant_scope": True,
            "frameworks_in_scope": ["ISO/IEC 42001"],
            "time_range": {"start": (now - timedelta(days=1)).isoformat(), "end": now.isoformat()},
            "trigger_type": "manual",
            "payload": {},
        },
    )
    assert response.status_code == 403, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "TENANT_SNAPSHOT_DISABLED"
    assert detail["reason_code"] == "TENANT_SNAPSHOT_DISABLED"


def test_tenant_scope_enabled_requires_scope_and_time_range(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="snapshot-tenant-required-inputs@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    settings.auditor_tenant_snapshot_enabled = True
    try:
        missing_scope = client.post(
            "/auditor/snapshot",
            headers=headers,
            json={"tenant_scope": True, "trigger_type": "manual", "payload": {}},
        )
        assert missing_scope.status_code == 400, missing_scope.text
        assert missing_scope.json()["detail"]["code"] == "TENANT_SCOPE_TARGET_REQUIRED"

        missing_time = client.post(
            "/auditor/snapshot",
            headers=headers,
            json={
                "tenant_scope": True,
                "frameworks_in_scope": ["ISO/IEC 42001"],
                "trigger_type": "manual",
                "payload": {},
            },
        )
        assert missing_time.status_code == 400, missing_time.text
        assert missing_time.json()["detail"]["code"] == "TENANT_SCOPE_TIME_RANGE_REQUIRED"
    finally:
        settings.auditor_tenant_snapshot_enabled = False


def test_tenant_scope_enabled_stores_scope_metadata(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="snapshot-tenant-metadata@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    high_system_id = _create_ai_system(client, headers, name="High Risk System", risk_tier="HIGH")
    _create_ai_system(client, headers, name="Low Risk System", risk_tier="LOW")

    now = datetime.now(timezone.utc)
    request_body = {
        "tenant_scope": True,
        "frameworks_in_scope": ["ISO/IEC 42001", "ISO/IEC 42001"],
        "controls_in_scope": ["CTRL-001"],
        "time_range": {"start": (now - timedelta(days=7)).isoformat(), "end": now.isoformat()},
        "risk_tier": "HIGH",
        "trigger_type": "manual",
        "payload": {"source": "test"},
    }

    settings.auditor_tenant_snapshot_enabled = True
    try:
        first = client.post("/auditor/snapshot", headers=headers, json=request_body)
        assert first.status_code == 200, first.text
        first_payload = first.json()["payload"]
        assert first_payload["snapshot_scope"] == "tenant"
        assert isinstance(first_payload["scope_hash"], str) and len(first_payload["scope_hash"]) == 64
        assert first_payload["ai_systems_included"] == [high_system_id]
        assert first_payload["frameworks_in_scope"] == ["ISO/IEC 42001"]
        assert first_payload["controls_in_scope"] == ["CTRL-001"]
        assert set(first_payload["time_range"].keys()) == {"start", "end"}

        second = client.post("/auditor/snapshot", headers=headers, json=request_body)
        assert second.status_code == 200, second.text
        second_payload = second.json()["payload"]
        assert second_payload["scope_hash"] == first_payload["scope_hash"]
        assert second_payload["ai_systems_included"] == first_payload["ai_systems_included"]
    finally:
        settings.auditor_tenant_snapshot_enabled = False
