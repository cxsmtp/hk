from __future__ import annotations

import os

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
    db_file = tmp_path / "findings_traceability.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Traceability Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {"access_token": body["access_token"], "tenant_id": body["tenants"][0]["id"]}


def _create_ai_system(client: TestClient, *, headers: dict[str, str], risk_tier: str = "HIGH") -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Traceability AI", "description": "", "risk_tier": risk_tier},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    approve = client.patch(
        f"/ai-systems/{ai_system_id}",
        headers=headers,
        json={"status": "approved"},
    )
    assert approve.status_code == 200, approve.text
    return ai_system_id


def test_findings_actions_and_traceability_chain(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="traceability-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers=headers)

    intercept = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "owner",
            "prompt": "ok",
            "context_summary": "asymmetry traceability coverage",
            "attachments_meta": [{"tool_calls": ["a", "b", "c", "d", "e"]}],
            "tool_output": "x" * 3000,
        },
    )
    assert intercept.status_code == 200, intercept.text

    list_response = client.get(
        "/findings",
        headers=headers,
        params={"finding_type_filter": "asymmetry_signal"},
    )
    assert list_response.status_code == 200, list_response.text
    items = list_response.json()["items"]
    assert len(items) == 1
    finding_id = items[0]["finding_id"]
    assert items[0]["recommended_actions"]
    assert items[0]["related_trace_ids"]
    assert any(action["action"] == "route_finding" for action in items[0]["action_panel"])

    detail = client.get(f"/findings/{finding_id}", headers=headers)
    assert detail.status_code == 200, detail.text
    detail_payload = detail.json()
    assert detail_payload["recommended_actions"]
    assert detail_payload["related_trace_ids"]
    assert detail_payload["chain_replay"]["finding_id"] == finding_id
    replay_stages = {item["stage"]: item for item in detail_payload["chain_replay"]["items"]}
    assert {"finding", "action", "policy", "evidence", "trace"}.issubset(replay_stages)
    assert detail_payload["chain_replay"]["completeness"]["has_finding"] is True
    assert detail_payload["chain_replay"]["completeness"]["has_evidence"] is True
    if detail_payload.get("ai_action_id"):
        assert replay_stages["action"]["href"].endswith(detail_payload["ai_action_id"])
    drilldowns = {item["type"]: item for item in detail_payload["drilldowns"]}
    assert drilldowns["finding_detail"]["href"] == f"/discovery/findings/{finding_id}"
    assert drilldowns["traceability"]["href"] == f"/discovery/findings/{finding_id}#traceability"
    assert drilldowns["evidence"]["href"] == f"/discovery/findings/{finding_id}#evidence"
    if detail_payload.get("ai_action_id"):
        assert drilldowns["action_trace"]["href"].endswith(detail_payload["ai_action_id"])
        assert drilldowns["action_graph"]["href"].endswith(detail_payload["ai_action_id"])
    action_names = {action["action"] for action in detail_payload["action_panel"]}
    assert {"route_finding", "run_validation", "create_ticket", "enforce_strict_policy"}.issubset(action_names)

    assign_owner = client.post(
        f"/findings/{finding_id}/assign-owner",
        headers=headers,
        json={"owner_department": "security"},
    )
    assert assign_owner.status_code == 200, assign_owner.text
    assert assign_owner.json()["department"] == "security"

    escalate = client.post(
        f"/findings/{finding_id}/escalate",
        headers=headers,
        json={"reason": "Escalate for traceability testing"},
    )
    assert escalate.status_code == 200, escalate.text
    assert escalate.json()["status"] in {"open", "reviewing"}

    ticket = client.post(
        f"/findings/{finding_id}/create-ticket",
        headers=headers,
        json={"system": "jira", "note": "Auto-generated from test"},
    )
    assert ticket.status_code == 200, ticket.text
    ticket_body = ticket.json()
    assert ticket_body["ticket_id"].startswith("TKT-")
    assert ticket_body["finding"]["status"] in {"reviewing", "open", "resolved", "accepted_risk"}

    filtered = client.get(
        "/findings",
        headers=headers,
        params={"department_filter": "security", "tool_filter": "llm_gateway"},
    )
    assert filtered.status_code == 200, filtered.text
    filtered_items = filtered.json()["items"]
    assert len(filtered_items) == 1
    assert filtered_items[0]["finding_id"] == finding_id

    traceability = client.get(f"/findings/{finding_id}/traceability", headers=headers)
    assert traceability.status_code == 200, traceability.text
    payload = traceability.json()
    assert payload["finding"]["finding_id"] == finding_id
    assert payload["finding"]["drilldowns"]
    assert payload["recommended_actions"]
    assert payload["action_panel"]
    assert payload["gateway_traces"]
    assert payload["gateway_traces"][0]["trace_id"]
    assert payload["gateway_traces"][0]["decision"]
    assert payload["chain_replay"]["finding_id"] == finding_id
    assert payload["chain_replay"]["items"]
    assert {item["stage"] for item in payload["chain_replay"]["items"]}.issuperset({"finding", "evidence", "trace"})
    assert payload["chain_replay"]["integrity_status"] in {"valid", "unchecked", "incomplete"}
    assert len(payload["proof_timeline"]) == 8
    assert [step["step"] for step in payload["proof_timeline"]] == [1, 2, 3, 4, 5, 6, 7, 8]
    assert payload["evidence_nodes"]
