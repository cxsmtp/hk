from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.session import Base, get_db
from app.main import app


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "runtime_enterprise_activity.sqlite3"
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
        yield {"client": client, "sessionmaker": testing_session_local}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Runtime Enterprise Owner"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    return {
        "access_token": payload["access_token"],
        "tenant_id": payload["tenants"][0]["id"],
        "user_id": payload["user"]["id"],
    }


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "X-Tenant-ID": tenant_id,
    }


def test_customer_activities_filter_passive_history_before_pagination(test_env) -> None:
    client = test_env["client"]
    owner = _register_owner(client, email="runtime-passive-pagination@example.com")
    now = datetime.now(timezone.utc)
    with test_env["sessionmaker"]() as db:
        db.add(RuntimeEvent(
            event_id="customer-prompt", tenant_id=owner["tenant_id"], source_surface="browser",
            event_type="prompt_blocked", app_id="chatgpt.com", correlation_id="prompt-one",
            metadata_json={"event_type": "prompt_blocked", "action_type": "prompt_submit", "decision": "block", "tool_name": "chatgpt.com"},
            created_at=now - timedelta(minutes=2),
        ))
        for index in range(120):
            db.add(RuntimeEvent(
                event_id=f"passive-{index}", tenant_id=owner["tenant_id"], source_surface="browser",
                event_type="extension_health_status", app_id="extension.local",
                metadata_json={"event_type": "extension_health_status", "action_type": "prompt_submit", "tool_name": "extension.local", "operational_telemetry": True},
                created_at=now + timedelta(seconds=index),
            ))
        db.commit()
    headers = _headers(owner["access_token"], owner["tenant_id"])
    activities = client.get("/runtime/activities", headers=headers, params={"page_size": 1})
    assert activities.status_code == 200, activities.text
    assert activities.json()["total"] == 1
    assert activities.json()["items"][0]["event_id"] == "customer-prompt"
    events = client.get("/runtime/events", headers=headers, params={"event_type": "extension_health_status", "page_size": 1})
    assert events.status_code == 200, events.text
    assert events.json()["total"] == 120
    assert events.json()["items"][0]["tool_name"] is None


def test_customer_activities_keep_explicit_warning_on_passive_browser_event(test_env) -> None:
    client = test_env["client"]
    owner = _register_owner(client, email="runtime-passive-warning@example.com")
    with test_env["sessionmaker"]() as db:
        for event_id, metadata in (
            ("passive-healthy", {"event_type": "extension_connected", "status": "healthy", "severity": "med", "decision": "block", "action_taken": "healthy"}),
            ("passive-warning", {"event_type": "extension_connected", "decision": "block", "action_taken": "warn:security", "status": "degraded"}),
        ):
            db.add(RuntimeEvent(event_id=event_id, tenant_id=owner["tenant_id"], source_surface="browser", event_type="extension_connected", metadata_json=metadata))
        db.commit()
    response = client.get("/runtime/activities", headers=_headers(owner["access_token"], owner["tenant_id"]))
    assert response.status_code == 200, response.text
    assert [item["event_id"] for item in response.json()["items"]] == ["passive-warning"]


def test_customer_activities_hide_historical_context_lifecycle_rows_but_keep_source_block(test_env) -> None:
    client = test_env["client"]
    owner = _register_owner(client, email="runtime-context-lifecycle-history@example.com")
    with test_env["sessionmaker"]() as db:
        db.add_all([
            RuntimeEvent(
                event_id="historical-context-lifecycle",
                tenant_id=owner["tenant_id"],
                source_surface="browser",
                event_type="context_invalidated",
                app_id="chatgpt.com",
                decision="block",
                metadata_json={
                    "event_type": "context_invalidated",
                    "action_taken": "input_node_replaced",
                    "reason": "input_node_replaced",
                },
            ),
            RuntimeEvent(
                event_id="source-block-context-lifecycle",
                tenant_id=owner["tenant_id"],
                source_surface="browser",
                event_type="context_invalidated",
                app_id="chatgpt.com",
                decision="block",
                metadata_json={
                    "event_type": "context_invalidated",
                    "action_taken": "block:context_policy",
                    "decision": "block",
                    "reason": "input_node_replaced",
                },
            ),
        ])
        db.commit()
    response = client.get("/runtime/activities", headers=_headers(owner["access_token"], owner["tenant_id"]))
    assert response.status_code == 200, response.text
    assert [item["event_id"] for item in response.json()["items"]] == ["source-block-context-lifecycle"]


def test_runtime_activities_return_enterprise_event_schema(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="runtime-enterprise-schema@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    now = datetime.now(timezone.utc)

    with session_factory() as db:
        db.add(
            RuntimeEvent(
                event_id="runtime-enterprise-1",
                tenant_id=owner["tenant_id"],
                source_surface="gateway",
                event_type="tool_call",
                app_id="Azure OpenAI",
                user_id="user-123",
                agent_id="agent-123",
                risk_score=0.87,
                evidence_node_ids=["ev-runtime-1"],
                correlation_id="corr-runtime-enterprise",
                context_id="ctx-runtime-enterprise",
                chain_id="chain-runtime-enterprise",
                metadata_json={
                    "user_email": "analyst@example.com",
                    "machine_id": "machine-123",
                    "device_name": "analyst-macbook",
                    "os_type": "macos",
                    "browser_type": "chrome",
                    "identity_type": "agent",
                    "ai_surface": "gateway",
                    "provider": "azure_openai",
                    "model_name": "gpt-4.1-mini",
                    "action_type": "tool_call",
                    "input_ref": "redacted-input-1",
                    "output_ref": "redacted-output-1",
                    "sensitivity_score": 0.72,
                    "policy_id": "policy-runtime-1",
                    "decision": "block",
                    "triggered_controls": ["CTRL-DLP", "CTRL-TOOL-SCOPE"],
                    "anomaly_score": 0.64,
                    "finding_id": "finding-runtime-1",
                    "related_event_ids": ["runtime-enterprise-0"],
                },
                created_at=now,
            )
        )
        db.commit()

    response = client.get("/runtime/activities", headers=headers)
    assert response.status_code == 200, response.text
    event = response.json()["items"][0]

    assert event["event_id"] == "runtime-enterprise-1"
    assert event["timestamp"]
    assert event["tenant_id"] == owner["tenant_id"]
    assert event["user_id"] == "user-123"
    assert event["user_email"] == "analyst@example.com"
    assert event["machine_id"] == "machine-123"
    assert event["device_name"] == "analyst-macbook"
    assert event["os_type"] == "macos"
    assert event["browser_type"] == "chrome"
    assert event["agent_id"] == "agent-123"
    assert event["identity_type"] == "agent"
    assert event["ai_surface"] == "gateway"
    assert event["application"] == "Azure OpenAI"
    assert event["provider"] == "azure_openai"
    assert event["model"] == "gpt-4.1-mini"
    assert event["action_type"] == "tool_call"
    assert event["input_ref"] == "redacted-input-1"
    assert event["output_ref"] == "redacted-output-1"
    assert event["sensitivity_score"] == 0.72
    assert event["policy_id"] == "policy-runtime-1"
    assert event["policy_decision"] == "block"
    assert event["control_triggered"] == ["CTRL-DLP", "CTRL-TOOL-SCOPE"]
    assert event["risk_score"] == 0.87
    assert event["anomaly_score"] == 0.64
    assert event["finding_id"] == "finding-runtime-1"
    assert event["related_event_ids"] == ["runtime-enterprise-0"]


def test_runtime_event_detail_user_activity_agent_activity_and_trace(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="runtime-enterprise-trace@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    now = datetime.now(timezone.utc)

    with session_factory() as db:
        db.add_all(
            [
                RuntimeEvent(
                    event_id="trace-step-1",
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    event_type="prompt",
                    app_id="ChatGPT",
                    user_id="user-trace",
                    agent_id=None,
                    risk_score=0.42,
                    correlation_id="corr-runtime-trace",
                    context_id="ctx-runtime-trace",
                    chain_id="chain-runtime-trace",
                    metadata_json={
                        "user_email": "trace@example.com",
                        "machine_id": "machine-trace",
                        "action_type": "prompt",
                        "decision": "warn",
                    },
                    created_at=now - timedelta(minutes=3),
                ),
                RuntimeEvent(
                    event_id="trace-step-2",
                    tenant_id=owner["tenant_id"],
                    source_surface="gateway",
                    event_type="tool_call",
                    app_id="Azure OpenAI",
                    user_id="user-trace",
                    agent_id="agent-trace",
                    risk_score=0.91,
                    correlation_id="corr-runtime-trace",
                    context_id="ctx-runtime-trace",
                    chain_id="chain-runtime-trace",
                    metadata_json={
                        "user_email": "trace@example.com",
                        "machine_id": "machine-trace",
                        "action_type": "tool_call",
                        "decision": "block",
                        "triggered_controls": ["CTRL-AGENT-SCOPE"],
                        "finding_id": "finding-trace",
                    },
                    created_at=now - timedelta(minutes=2),
                ),
            ]
        )
        db.commit()

    detail = client.get("/runtime/activities/trace-step-2", headers=headers)
    assert detail.status_code == 200, detail.text
    assert detail.json()["event_id"] == "trace-step-2"
    assert detail.json()["policy_decision"] == "block"

    user_activity = client.get("/runtime/users/user-trace/activity", headers=headers)
    assert user_activity.status_code == 200, user_activity.text
    assert [item["event_id"] for item in user_activity.json()["items"]] == ["trace-step-2", "trace-step-1"]

    agent_activity = client.get("/runtime/agents/agent-trace/activity", headers=headers)
    assert agent_activity.status_code == 200, agent_activity.text
    assert [item["event_id"] for item in agent_activity.json()["items"]] == ["trace-step-2"]

    trace = client.get("/runtime/trace/trace-step-2", headers=headers)
    assert trace.status_code == 200, trace.text
    payload = trace.json()
    assert payload["trace_key_type"] == "chain_id"
    assert payload["event_count"] == 2
    assert [step["event_id"] for step in payload["steps"]] == ["trace-step-1", "trace-step-2"]
    assert payload["steps"][0]["title"] == "Step 1: user entered prompt"
    assert payload["steps"][1]["title"] == "Step 2: gateway intercepted tool call"
    assert payload["steps"][1]["finding_id"] == "finding-trace"
