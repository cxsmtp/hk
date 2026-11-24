from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.main import app

@pytest.mark.integration
def test_register_and_me_roundtrip_on_postgres(integration_db_ready) -> None:  # noqa: ARG001
    client = TestClient(app)
    email = f"integration-{uuid4().hex[:12]}@example.com"
    password = "Password123!"

    register = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": password,
            "full_name": "Integration User",
        },
    )
    assert register.status_code == 200, register.text
    payload = register.json()
    assert payload["access_token"]
    assert payload["tenants"]

    tenant_id = payload["tenants"][0]["id"]
    headers = {
        "Authorization": f"Bearer {payload['access_token']}",
        "X-Tenant-ID": tenant_id,
    }
    me = client.get("/auth/me", headers=headers)
    assert me.status_code == 200, me.text
    assert me.json()["email"] == email
