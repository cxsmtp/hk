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
    db_file = tmp_path / "contract_ai_systems.sqlite3"
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


def test_ai_systems_contract_create_update_list(test_env: TestClient) -> None:
    client = test_env
    owner = _register_owner(client, email="contract-ai-systems@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    create_response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Contract AI", "description": "contract", "risk_tier": "HIGH"},
    )
    assert create_response.status_code == 200, create_response.text
    created = create_response.json()
    assert created != {}
    assert created.get("id")

    update_response = client.patch(
        f"/ai-systems/{created['id']}",
        headers=headers,
        json={"status": "active"},
    )
    assert update_response.status_code == 200, update_response.text
    updated = update_response.json()
    assert updated != {}
    assert updated.get("id")

    list_response = client.get("/ai-systems", headers=headers)
    assert list_response.status_code == 200, list_response.text
    body = list_response.json()
    assert isinstance(body, dict)
    assert "items" in body
    assert "total" in body
    assert isinstance(body["items"], list)
    assert isinstance(body["total"], int)

    for item in body["items"]:
        assert item != {}
        assert item.get("id")
