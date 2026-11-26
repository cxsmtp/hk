from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.audit import AuditLog
from app.db.models.evidence import EvidenceNode
from app.db.session import Base, get_db
from app.main import app
from ai_system_approval_helpers import allow_self_approval, approve_pending_request


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "discovery_governance_flow.sqlite3"
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
        yield {"client": client, "session_factory": testing_session_local}
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
        json={"email": email, "password": PASSWORD, "full_name": "Discovery Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
        "user_id": body["user"]["id"],
    }


def test_discovered_application_moves_to_governed_and_enforced_without_manual_db(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["session_factory"]
    owner = _register_owner(client, email="discovery-flow-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    shadow_event = client.post(
        "/monitoring/shadow-events",
        headers=headers,
        json={
            "event_type": "dns_discovery",
            "payload": {
                "severity": "high",
                "ai_tool": "unknown_ops_assistant",
                "department": "operations",
                "risk_category": "shadow_ai",
            },
        },
    )
    assert shadow_event.status_code == 200, shadow_event.text
    assert shadow_event.headers.get("X-Correlation-Id")

    list_apps = client.get("/discovery/applications", headers=headers)
    assert list_apps.status_code == 200, list_apps.text
    apps_body = list_apps.json()
    assert sorted(apps_body.keys()) == ["items", "page", "page_size", "total"]
    assert apps_body["total"] == 1
    app_row = apps_body["items"][0]
    assert app_row["tool_name"] == "unknown_ops_assistant"
    assert app_row["status"] == "discovered"
    app_id = app_row["id"]

    assign_owner = client.post(
        f"/discovery/applications/{app_id}/assign-owner",
        headers=headers,
        json={"owner_department": "security"},
    )
    assert assign_owner.status_code == 200, assign_owner.text
    assert assign_owner.headers.get("X-Correlation-Id")
    assert assign_owner.json()["owner_department"] == "security"

    keep_monitoring = client.post(
        f"/discovery/applications/{app_id}/promote",
        headers=headers,
        json={"action": "keep_monitoring", "provisional_risk_tier": "HIGH"},
    )
    assert keep_monitoring.status_code == 200, keep_monitoring.text
    assert keep_monitoring.headers.get("X-Correlation-Id")
    assert keep_monitoring.json()["status"] == "monitoring"
    assert keep_monitoring.json()["provisional_risk_tier"] == "HIGH"

    # Promoting registers the AI system and asks for its approval; it is governed (allowed through the gateway) once
    # approved under the tenant's policy, here one approver who may be the promoter.
    allow_self_approval(client, headers)
    promote = client.post(
        f"/discovery/applications/{app_id}/promote",
        headers=headers,
        json={"action": "approve", "provisional_risk_tier": "HIGH"},
    )
    assert promote.status_code == 200, promote.text
    assert promote.headers.get("X-Correlation-Id")
    promoted_body = promote.json()
    assert promoted_body["status"] == "approved"
    assert promoted_body["ai_system_id"]
    ai_system_id = promoted_body["ai_system_id"]

    blocked_before_approval = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": owner["user_id"],
            "prompt": "normal prompt",
            "context_summary": "not approved yet",
            "attachments_meta": [],
        },
    )
    assert blocked_before_approval.status_code == 403, blocked_before_approval.text
    approve_pending_request(client, headers, ai_system_id)

    list_systems = client.get("/ai-systems", headers=headers)
    assert list_systems.status_code == 200, list_systems.text
    assert any(item["id"] == ai_system_id for item in list_systems.json()["items"])

    intercept = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": owner["user_id"],
            "prompt": "normal prompt",
            "context_summary": "discovery-to-governance enforcement check",
            "attachments_meta": [],
        },
    )
    assert intercept.status_code == 200, intercept.text
    assert intercept.headers.get("X-Correlation-Id")
    event_id = intercept.json()["event_id"]

    events = client.get("/enforcement/events", headers=headers)
    assert events.status_code == 200, events.text
    assert any(item["id"] == event_id for item in events.json()["items"])

    block = client.post(
        f"/discovery/applications/{app_id}/block",
        headers=headers,
        json={"reason": "Disallow further use"},
    )
    assert block.status_code == 200, block.text
    assert block.headers.get("X-Correlation-Id")
    assert block.json()["status"] == "blocked"

    with session_factory() as db:
        audit_rows = db.scalars(select(AuditLog).where(AuditLog.tenant_id == owner["tenant_id"])).all()
        audit_actions = {row.action for row in audit_rows}
        expected_audit_actions = {
            "discovery.application.assign_owner",
            "discovery.application.keep_monitoring",
            "discovery.application.promote",
            "discovery.application.block",
            "gateway.llm.intercept",
        }
        for action in expected_audit_actions:
            assert action in audit_actions
            assert any(row.action == action and bool(row.correlation_id) for row in audit_rows)

        evidence_rows = db.scalars(select(EvidenceNode).where(EvidenceNode.tenant_id == owner["tenant_id"])).all()
        evidence_signals = {row.signal_type for row in evidence_rows}
        expected_signals = {
            "discovery.application.owner_assigned",
            "discovery.application.monitoring",
            "discovery.application.promoted",
            "discovery.application.blocked",
        }
        for signal in expected_signals:
            assert signal in evidence_signals
            assert any(row.signal_type == signal and bool(row.correlation_id) for row in evidence_rows)
