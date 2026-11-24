from __future__ import annotations

import os

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"

from app.db.session import Base, get_db
from app.main import app


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "api_contracts.sqlite3"
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
        yield client
    finally:
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
            "full_name": "Contract Owner",
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


def _assert_list_envelope(payload: dict) -> None:
    assert isinstance(payload, dict)
    assert set(payload.keys()) == {"items", "total", "page", "page_size"}
    assert isinstance(payload["items"], list)
    assert isinstance(payload["total"], int)
    assert isinstance(payload["page"], int)
    assert isinstance(payload["page_size"], int)


def test_all_list_endpoints_use_canonical_envelope(test_env: TestClient) -> None:
    client = test_env
    owner = _register_owner(client, email="api-contracts@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Contracts AI", "description": "contracts", "risk_tier": "MEDIUM"},
    )
    assert ai_system_response.status_code == 200, ai_system_response.text
    ai_system_id = ai_system_response.json()["id"]

    pack_response = client.post(
        "/policies/packs",
        headers=headers,
        json={"name": "Contracts Pack", "description": "contracts", "status": "draft"},
    )
    assert pack_response.status_code == 200, pack_response.text
    pack_id = pack_response.json()["pack"]["id"]

    list_paths = [
        "/auth/tenants",
        "/ai-systems",
        "/ai-iam/agents",
        "/policies/packs",
        f"/policies/packs/{pack_id}/versions",
        "/policies/guardian-matrix",
        "/guardian-contracts/v2",
        "/guardian-contracts/v2/bindings",
        "/guardian-contracts/v2/matrix",
        "/enforcement/events",
        "/enforcement/approvals",
        "/monitoring/connectors",
        "/monitoring/connectors/providers",
        "/monitoring/connectors/coverage",
        "/monitoring/drift-alerts",
        "/findings",
        "/simulations/templates",
        "/simulations/controls",
        f"/simulations/controls/traceability?ai_system_id={ai_system_id}",
        "/simulations/definitions",
        "/simulations/runs",
        "/kb/frameworks",
        "/kb/controls",
        "/trust-center/evidence/nodes",
        "/trust-center/evidence/edges",
        "/trust-center/maturity",
        "/trust-center/audit-logs",
        "/ops/jobs/status",
        "/auditor/conflicts",
    ]

    for path in list_paths:
        response = client.get(path, headers=headers)
        assert response.status_code == 200, f"{path} -> {response.status_code}: {response.text}"
        _assert_list_envelope(response.json())
