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
    db_file = tmp_path / "contract_ai_iam.sqlite3"
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


def test_ai_iam_contract_create_update_list(test_env: TestClient) -> None:
    client = test_env
    owner = _register_owner(client, email="contract-ai-iam@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    create_agent_response = client.post(
        "/ai-iam/agents",
        headers=headers,
        json={"name": "Contract Agent", "description": "contract", "max_chain_depth": 2},
    )
    assert create_agent_response.status_code == 200, create_agent_response.text
    created_agent = create_agent_response.json()
    assert created_agent != {}
    assert created_agent.get("id")

    agent_id = created_agent["id"]

    update_agent_response = client.patch(
        f"/ai-iam/agents/{agent_id}",
        headers=headers,
        json={"status": "active"},
    )
    assert update_agent_response.status_code == 200, update_agent_response.text
    updated_agent = update_agent_response.json()
    assert updated_agent != {}
    assert updated_agent.get("id")

    list_agents_response = client.get("/ai-iam/agents", headers=headers)
    assert list_agents_response.status_code == 200, list_agents_response.text
    list_payload = list_agents_response.json()
    assert isinstance(list_payload, dict)
    assert isinstance(list_payload.get("items"), list)
    assert isinstance(list_payload.get("total"), int)
    for item in list_payload["items"]:
        assert item != {}
        assert item.get("id")

    list_identities_response = client.get("/ai-iam/identities", headers=headers)
    assert list_identities_response.status_code == 200, list_identities_response.text
    identities_payload = list_identities_response.json()
    assert isinstance(identities_payload, dict)
    assert isinstance(identities_payload.get("items"), list)
    assert len(identities_payload["items"]) >= 1

    identity_payload = identities_payload["items"][0]
    assert identity_payload.get("identity_id") == agent_id
    assert identity_payload.get("type") == "agent"
    assert "crq" in identity_payload
    assert "risk_components" in identity_payload

    single_identity_response = client.get(f"/ai-iam/identities/{agent_id}", headers=headers)
    assert single_identity_response.status_code == 200, single_identity_response.text
    single_identity = single_identity_response.json()
    assert single_identity.get("identity_id") == agent_id
    assert isinstance(single_identity.get("permissions"), dict)
    assert isinstance(single_identity.get("token_scope"), list)

    ai_system_response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Contract AI System", "description": "contract", "risk_tier": "MEDIUM"},
    )
    assert ai_system_response.status_code == 200, ai_system_response.text
    ai_system_id = ai_system_response.json()["id"]

    mint_response = client.post(
        f"/ai-iam/agents/{agent_id}/tokens",
        headers=headers,
        json={"ai_system_id": ai_system_id, "scopes": ["tool.read"], "expires_minutes": 60, "chain_depth": 1},
    )
    assert mint_response.status_code == 200, mint_response.text
    minted = mint_response.json()
    assert minted != {}
    assert minted.get("token_id")

    revoke_response = client.post(
        f"/ai-iam/tokens/{minted['token_id']}/revoke",
        headers=headers,
        json={},
    )
    assert revoke_response.status_code == 200, revoke_response.text
    revoked = revoke_response.json()
    assert revoked != {}
    assert revoked.get("token_id")
