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
    db_file = tmp_path / "contract_policies.sqlite3"
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


def test_policies_contract_create_update_list(test_env: TestClient) -> None:
    client = test_env
    owner = _register_owner(client, email="contract-policies@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    create_pack_response = client.post(
        "/policies/packs",
        headers=headers,
        json={"name": "Contract Pack", "description": "contract", "status": "draft"},
    )
    assert create_pack_response.status_code == 200, create_pack_response.text
    pack_payload = create_pack_response.json()
    assert pack_payload != {}
    assert pack_payload.get("pack")
    assert pack_payload["pack"].get("id")
    assert pack_payload.get("default_version")
    assert pack_payload["default_version"].get("id")

    pack_id = pack_payload["pack"]["id"]

    update_pack_response = client.patch(
        f"/policies/packs/{pack_id}",
        headers=headers,
        json={"status": "active"},
    )
    assert update_pack_response.status_code == 200, update_pack_response.text
    updated_pack = update_pack_response.json()
    assert updated_pack != {}
    assert updated_pack.get("id")

    list_packs_response = client.get("/policies/packs", headers=headers)
    assert list_packs_response.status_code == 200, list_packs_response.text
    packs_body = list_packs_response.json()
    assert isinstance(packs_body, dict)
    assert isinstance(packs_body.get("items"), list)
    assert isinstance(packs_body.get("total"), int)
    for item in packs_body["items"]:
        assert item != {}
        assert item.get("id")

    create_version_response = client.post(
        f"/policies/packs/{pack_id}/versions",
        headers=headers,
        json={
            "version": "1.0.1",
            "scope": {
                "applies_to_risk_tiers": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                "applies_to_ai_system_ids": None,
                "applies_to_actor_types": ["human", "agent", "system"],
            },
            "enforcement_defaults": {"default_decision": "allow", "escalation": "notify"},
            "guardian_contracts": [],
        },
    )
    assert create_version_response.status_code == 200, create_version_response.text
    version_payload = create_version_response.json()
    assert version_payload != {}
    assert version_payload.get("id")

    list_versions_response = client.get(f"/policies/packs/{pack_id}/versions", headers=headers)
    assert list_versions_response.status_code == 200, list_versions_response.text
    versions_body = list_versions_response.json()
    assert isinstance(versions_body, dict)
    assert isinstance(versions_body.get("items"), list)
    assert isinstance(versions_body.get("total"), int)
    for item in versions_body["items"]:
        assert item != {}
        assert item.get("id")


def test_ensure_pilot_policy_pack_is_idempotent(test_env: TestClient) -> None:
    client = test_env
    owner = _register_owner(client, email="contract-pilot-pack@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    first = client.post("/policies/pilot-pack/ensure", headers=headers, json={"activate": True})
    assert first.status_code == 200, first.text
    first_payload = first.json()
    assert first_payload["pack"]["name"] == "Pilot Safe Browser Extension Pack"
    assert first_payload["pack"]["status"] == "active"
    assert first_payload["applied"] in {"created", "updated"}
    assert first_payload["policy_version"]["id"]
    assert isinstance(first_payload["policy_version"].get("scope"), dict)
    assert isinstance(first_payload["policy_version"].get("guardian_contracts"), list)
    assert first_payload["policy_version"]["scope"].get("browser_automation_control")

    second = client.post("/policies/pilot-pack/ensure", headers=headers, json={"activate": True})
    assert second.status_code == 200, second.text
    second_payload = second.json()
    assert second_payload["pack"]["id"] == first_payload["pack"]["id"]
    assert second_payload["policy_version"]["id"] == first_payload["policy_version"]["id"]
    assert second_payload["applied"] == "updated"
