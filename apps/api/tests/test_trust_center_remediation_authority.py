from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.ai_system import AISystem
from app.db.session import Base, get_db
from app.main import app


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "trust_center_remediation_authority.sqlite3"
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
        yield {"client": client, "SessionLocal": testing_session_local}
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
            "full_name": "Trust Center Owner",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
        "user_id": body["user"]["id"],
    }


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "X-Tenant-ID": tenant_id,
    }


def _create_ai_system(client: TestClient, headers: dict[str, str], *, risk_tier: str = "MEDIUM") -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Trust Center Remediation System", "description": "governance remediation test", "risk_tier": risk_tier},
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _set_owner_metadata(session_local: sessionmaker, *, ai_system_id: str, owner_user_id: str) -> None:
    with session_local() as db:
        row = db.scalar(select(AISystem).where(AISystem.id == ai_system_id))
        assert row is not None
        metadata = dict(row.metadata_json or {})
        metadata["owner_user_id"] = owner_user_id
        metadata["business_owner_user_id"] = owner_user_id
        metadata["technical_owner_user_id"] = owner_user_id
        metadata["ownership_state"] = "ASSIGNED"
        metadata["compliance_state"] = "COMPLIANT"
        row.metadata_json = metadata
        db.commit()


def _clear_owner_metadata(session_local: sessionmaker, *, ai_system_id: str) -> None:
    with session_local() as db:
        row = db.scalar(select(AISystem).where(AISystem.id == ai_system_id))
        assert row is not None
        metadata = dict(row.metadata_json or {})
        metadata.pop("owner_user_id", None)
        metadata.pop("business_owner_user_id", None)
        metadata.pop("technical_owner_user_id", None)
        metadata["ownership_state"] = "MISSING"
        metadata["compliance_state"] = "NON_COMPLIANT"
        row.metadata_json = metadata
        db.commit()


def test_live_transition_blocked_without_owner_or_policy_creates_governance_remediation(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="trust-center-live-block@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")

    response = client.patch(f"/ai-systems/{ai_system_id}", headers=headers, json={"status": "live"})
    assert response.status_code == 409, response.text
    body = response.json()["detail"]
    assert body["code"] == "lifecycle_transition_blocked"
    assert "ownership_assignment" in body["missing_requirements"]
    remediation_id = str(body["remediation_id"])
    assert remediation_id

    remediations = client.get(
        "/findings/remediations",
        headers=headers,
        params={"target_type": "ai_system", "target_id": ai_system_id},
    )
    assert remediations.status_code == 200, remediations.text
    rows = remediations.json()["items"]
    assert any(row["id"] == remediation_id for row in rows)
    assert any(row["id"] == remediation_id and row["remediation_type"] == "trust_center_escalation" for row in rows)

    state = client.get(f"/trust-center/ai-systems/{ai_system_id}/remediation-state", headers=headers)
    assert state.status_code == 200, state.text
    payload = state.json()
    assert payload["ownership_state"] == "MISSING"
    assert payload["open_remediations"] >= 1
    assert any(log["remediation_id"] == remediation_id for log in payload["remediation_logs"])


def test_existing_live_system_without_owner_is_downgraded_and_remediated(test_env, monkeypatch) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="trust-center-owner-downgrade@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="MEDIUM")

    _set_owner_metadata(session_local, ai_system_id=ai_system_id, owner_user_id=owner["user_id"])
    monkeypatch.setattr("app.api.routers.ai_systems.get_latest_policy_for_ai_system", lambda *args, **kwargs: object())

    go_live = client.patch(f"/ai-systems/{ai_system_id}", headers=headers, json={"status": "live"})
    assert go_live.status_code == 200, go_live.text
    assert go_live.json()["status"] == "live"

    _clear_owner_metadata(session_local, ai_system_id=ai_system_id)
    update = client.patch(f"/ai-systems/{ai_system_id}", headers=headers, json={"description": "trigger owner check"})
    assert update.status_code == 200, update.text
    assert update.json()["status"] == "restricted"

    state = client.get(f"/trust-center/ai-systems/{ai_system_id}/remediation-state", headers=headers)
    assert state.status_code == 200, state.text
    payload = state.json()
    assert payload["ownership_state"] == "MISSING"
    assert payload["ai_system_status"] == "restricted"
    assert any(log["action"] == "ai_system.lifecycle.transition_blocked" for log in payload["remediation_logs"])


def test_risk_escalation_on_live_system_downgrades_and_notifies_auditor(test_env, monkeypatch) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="trust-center-risk-escalation@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="MEDIUM")

    _set_owner_metadata(session_local, ai_system_id=ai_system_id, owner_user_id=owner["user_id"])
    monkeypatch.setattr("app.api.routers.ai_systems.get_latest_policy_for_ai_system", lambda *args, **kwargs: object())

    go_live = client.patch(f"/ai-systems/{ai_system_id}", headers=headers, json={"status": "live"})
    assert go_live.status_code == 200, go_live.text
    assert go_live.json()["status"] == "live"

    escalate = client.patch(f"/ai-systems/{ai_system_id}", headers=headers, json={"risk_tier": "HIGH"})
    assert escalate.status_code == 200, escalate.text
    assert escalate.json()["status"] == "restricted"

    state = client.get(f"/trust-center/ai-systems/{ai_system_id}/remediation-state", headers=headers)
    assert state.status_code == 200, state.text
    payload = state.json()
    assert payload["risk_tier"] == "HIGH"
    assert payload["open_remediations"] >= 1
    assert any(log["action"] == "ai_system.risk.escalated" for log in payload["remediation_logs"])
    assert any(log["action"] == "auditor.notify.risk_escalation" for log in payload["remediation_logs"])
    assert any(
        row["source_trigger_type"] == "runtime_pattern" and row["type"] == "trust_center_escalation"
        for row in payload["latest_remediations"]
    )
