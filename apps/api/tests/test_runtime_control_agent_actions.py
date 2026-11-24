from __future__ import annotations

import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.activity_audit import AIAction
from app.db.models.evidence import DecisionReceipt, ExecutionIntegrityResult, ExecutionReceipt
from app.core.config import settings
from app.db.session import Base, get_db
from app.main import app


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "runtime_control_agent_actions.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Runtime Control Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
    }


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def _create_ai_system(client: TestClient, headers: dict[str, str], *, risk_tier: str = "MEDIUM") -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": f"Agent Runtime {risk_tier}", "description": "runtime control test", "risk_tier": risk_tier},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    approved = client.patch(
        f"/ai-systems/{ai_system_id}",
        headers=headers,
        json={"status": "approved"},
    )
    assert approved.status_code == 200, approved.text
    return ai_system_id


def _create_agent(client: TestClient, headers: dict[str, str], **overrides: object) -> str:
    payload = {
        "name": "Runtime Agent",
        "description": "agent action intercept",
        "max_chain_depth": 3,
        "capability_inheritance": False,
        "action_scope": ["tool.run", "tool.read", "tool.email_send"],
        "tool_registry": ["openai_api", "jira", "mail_sender"],
        "external_system_access": ["api.openai.com", "jira.internal.acme.ai", "mail.google.com"],
        "agent_type": "workflow_agent",
        "autonomy_level": "medium",
    }
    payload.update(overrides)
    response = client.post("/ai-iam/agents", headers=headers, json=payload)
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _mint_token(
    client: TestClient,
    headers: dict[str, str],
    *,
    agent_id: str,
    ai_system_id: str,
    scopes: list[str],
    chain_depth: int = 2,
) -> str:
    response = client.post(
        f"/ai-iam/agents/{agent_id}/tokens",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "scopes": scopes,
            "expires_minutes": 60,
            "chain_depth": chain_depth,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["capability_token"]


def test_agent_action_allow_for_registered_system(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="agent-action-allow@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers)
    agent_id = _create_agent(client, headers)
    token = _mint_token(
        client,
        headers,
        agent_id=agent_id,
        ai_system_id=ai_system_id,
        scopes=["tool.run", "tool.read", "tool.email_send"],
    )

    response = client.post(
        "/runtime-control/agent-action-intercept",
        headers=headers,
        json={
            "correlation_id": "corr-agent-allow",
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": token,
            "action_type": "api_call",
                "tool_name": "openai_api",
                "target_resource": "api.openai.com",
                "chain_depth": 1,
            "policy_version": "pv-agent-runtime",
            "platform_mode": "enforce",
            "input_context": {
                "provider": "openai",
                "model_name": "gpt-4.1-mini",
                "api_endpoint": "https://api.openai.com/v1/chat/completions",
                "payload": {"prompt": "summarize release notes"},
            },
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "allow"
    assert body["audit_log_id"]
    assert body["evidence_node_id"]
    assert body["runtime_event_id"]
    assert isinstance(body.get("identity_risk_score"), float)
    assert isinstance(body.get("identity_risk_level"), str)
    assert isinstance(body.get("identity_risk_reasoning"), list)
    assert isinstance(body.get("identity_crq"), dict)
    assert isinstance(body.get("identity_risk_components"), dict)


def test_selected_runtime_control_v2_is_authoritative_on_real_intercept_route(
    test_env, monkeypatch
) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="agent-action-v2-enforce@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers)
    agent_id = _create_agent(client, headers)
    token = _mint_token(
        client,
        headers,
        agent_id=agent_id,
        ai_system_id=ai_system_id,
        scopes=["tool.run", "tool.read"],
    )

    def intercept(correlation_id: str):
        return client.post(
            "/runtime-control/agent-action-intercept",
            headers=headers,
            json={
                "correlation_id": correlation_id,
                "ai_system_id": ai_system_id,
                "agent_id": agent_id,
                "capability_token": token,
                "action_type": "api_call",
                "tool_name": "openai_api",
                "target_resource": "api.openai.com",
                "chain_depth": 1,
                "policy_version": "pv-agent-runtime",
                "platform_mode": "enforce",
                "input_context": {
                    "provider": "openai",
                    "model_name": "gpt-4.1-mini",
                    "api_endpoint": "https://api.openai.com/v1/chat/completions",
                    "payload": {"prompt": "summarize release notes"},
                },
            },
        )

    baseline = intercept("corr-agent-v2-off")
    assert baseline.status_code == 200, baseline.text
    assert not str(baseline.json()["reason_code"]).startswith("authorization_kernel_v2:")
    with session_local() as db:
        assert db.scalar(
            select(DecisionReceipt).where(DecisionReceipt.tenant_id == owner["tenant_id"])
        ) is None

    # Exercise required-control selection, rather than the warning-only base kernel.
    monkeypatch.setattr(settings, "native_control_framework", True)
    monkeypatch.setattr(settings, "trusted_control_selector", True)
    monkeypatch.setattr(settings, "native_control_enforce", True)
    monkeypatch.setattr(settings, "native_control_openai", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", True)
    monkeypatch.setattr(
        settings,
        "authorization_kernel_v2_enforce_rollout",
        f'{{"{owner["tenant_id"]}":["runtime_control"]}}',
    )
    monkeypatch.setattr(settings, "decision_execution_receipts_enabled", True)
    monkeypatch.setattr(settings, "receipt_signing_active_key_id", "runtime-receipt-key")
    monkeypatch.setattr(
        settings,
        "receipt_signing_keys_json",
        '{"runtime-receipt-key":"runtime-receipt-signing-material-00000001"}',
    )
    selected = intercept("corr-agent-v2-selected")

    assert selected.status_code == 200, selected.text
    assert selected.json()["decision"] == "block", {
        "decision": selected.json().get("decision"),
        "reason_code": selected.json().get("reason_code"),
        "shadow": selected.json().get("authorization_kernel_v2_shadow"),
        "pre_action": selected.json().get("pre_action_governance_check"),
    }
    assert str(selected.json()["reason_code"]).startswith("authorization_kernel_v2:")
    with session_local() as db:
        runtime = db.get(RuntimeEvent, selected.json()["runtime_event_id"])
        activity = db.scalar(
            select(AIAction).where(AIAction.runtime_event_id == selected.json()["runtime_event_id"])
        )
        assert runtime is not None
        assert activity is not None
        assert runtime.metadata_json["authorization_kernel_v2_shadow"] == activity.metadata_json[
            "authorization_kernel_v2_shadow"
        ]
        assert runtime.metadata_json["authorization_kernel_v2_shadow_health"] == activity.metadata_json[
            "authorization_kernel_v2_shadow_health"
        ]
        assert runtime.metadata_json["authorization_kernel_v2_shadow"]["action_id"] == "corr-agent-v2-selected"
        decision_receipt = db.scalar(
            select(DecisionReceipt).where(
                DecisionReceipt.tenant_id == owner["tenant_id"],
                DecisionReceipt.action_id == "corr-agent-v2-selected",
            )
        )
        assert decision_receipt is not None
        assert db.scalar(
            select(ExecutionReceipt).where(
                ExecutionReceipt.decision_receipt_id == decision_receipt.receipt_id
            )
        ) is None
        integrity = db.scalar(
            select(ExecutionIntegrityResult).where(
                ExecutionIntegrityResult.decision_receipt_id == decision_receipt.receipt_id
            )
        )
        assert integrity is not None and integrity.result == "incomplete"


def test_agent_action_sensitive_requires_approval(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="agent-action-approval@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers)
    agent_id = _create_agent(client, headers)
    token = _mint_token(
        client,
        headers,
        agent_id=agent_id,
        ai_system_id=ai_system_id,
        scopes=["tool.run", "tool.email_send"],
    )

    response = client.post(
        "/runtime-control/agent-action-intercept",
        headers=headers,
        json={
            "correlation_id": "corr-agent-sensitive",
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": token,
            "action_type": "email_send",
                "tool_name": "mail_sender",
                "target_resource": "mail.google.com",
                "chain_depth": 1,
            "policy_version": "pv-agent-runtime",
            "platform_mode": "enforce",
            "input_context": {
                "payload": {
                    "subject": "Incident triage",
                    "body": "api_key: sk-live-123456789 secret token, contact admin@acme.ai",
                }
            },
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "require_approval"
    assert body["approval_required"] is True
    assert body["finding_id"] is not None


def test_unknown_ai_system_is_not_allowed_for_agent_actions(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="agent-action-unknown@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    sanctioned_ai_system_id = _create_ai_system(client, headers)
    agent_id = _create_agent(client, headers)
    token = _mint_token(
        client,
        headers,
        agent_id=agent_id,
        ai_system_id=sanctioned_ai_system_id,
        scopes=["tool.run"],
    )

    unknown_ai_system_id = str(uuid4())
    response = client.post(
        "/runtime-control/agent-action-intercept",
        headers=headers,
        json={
            "correlation_id": "corr-agent-unknown",
            "ai_system_id": unknown_ai_system_id,
            "agent_id": agent_id,
            "capability_token": token,
            "action_type": "api_call",
            "tool_name": "openai_api",
            "target_resource": "api.openai.com",
            "chain_depth": 1,
            "policy_version": "pv-agent-runtime",
            "platform_mode": "enforce",
            "input_context": {"payload": {"prompt": "hello"}},
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    assert body["reason_code"] == "unregistered_ai_system"
    assert body["finding_id"] is not None

    findings = client.get(
        "/findings",
        headers=headers,
        params={"finding_type_filter": "unregistered_ai_system"},
    )
    assert findings.status_code == 200, findings.text
    assert len(findings.json()["items"]) >= 1


def test_behavior_anomaly_escalates_to_require_approval(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="agent-action-anomaly@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers)
    agent_id = _create_agent(client, headers)
    token = _mint_token(
        client,
        headers,
        agent_id=agent_id,
        ai_system_id=ai_system_id,
        scopes=["tool.run", "tool.read", "tool.email_send"],
    )

    final_body: dict[str, object] | None = None
    for idx in range(6):
        response = client.post(
            "/runtime-control/agent-action-intercept",
            headers=headers,
            json={
                "correlation_id": f"corr-agent-anomaly-{idx}",
                "ai_system_id": ai_system_id,
                "agent_id": agent_id,
                "capability_token": token,
                "action_type": "api_call",
                "tool_name": "openai_api",
                "target_resource": "api.openai.com",
                "chain_depth": 1,
                "policy_version": "pv-agent-runtime",
                "platform_mode": "enforce",
                "input_context": {
                    "provider": "openai",
                    "model_name": "gpt-4.1-mini",
                    "api_endpoint": "https://api.openai.com/v1/chat/completions",
                    "payload": {"prompt": "repeat baseline action"},
                },
            },
        )
        assert response.status_code == 200, response.text
        final_body = response.json()

    assert final_body is not None
    assert final_body["decision"] == "require_approval"
    assert final_body["reason_code"] == "agent_behavior_anomaly_requires_approval"
    assert final_body["finding_id"] is not None
    assert final_body["runtime_event_id"] is not None


def test_privilege_mismatch_chain_depth_is_flagged_and_blocked(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="agent-action-chain-depth@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers)
    agent_id = _create_agent(client, headers, max_chain_depth=1)
    token = _mint_token(
        client,
        headers,
        agent_id=agent_id,
        ai_system_id=ai_system_id,
        scopes=["tool.run"],
        chain_depth=1,
    )

    response = client.post(
        "/runtime-control/agent-action-intercept",
        headers=headers,
        json={
            "correlation_id": "corr-agent-chain-depth-mismatch",
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": token,
            "action_type": "tool_execution",
            "tool_name": "jira",
            "target_resource": "jira.internal.acme.ai",
            "chain_depth": 3,
            "policy_version": "pv-agent-runtime",
            "platform_mode": "enforce",
            "input_context": {"payload": {"issue": "SEC-1234"}},
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    assert body["reason_code"] == "delegation_chain_depth_mismatch"
    assert body["runtime_event_id"] is not None
    assert body["finding_id"] is not None


def test_runtime_control_derives_root_depth_instead_of_trusting_claim(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="agent-action-derived-root-depth@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers)
    agent_id = _create_agent(client, headers, max_chain_depth=3, capability_inheritance=True)
    token = _mint_token(
        client,
        headers,
        agent_id=agent_id,
        ai_system_id=ai_system_id,
        scopes=["tool.run"],
        chain_depth=3,
    )

    response = client.post(
        "/runtime-control/agent-action-intercept",
        headers=headers,
        json={
            "correlation_id": "corr-agent-derived-root-depth",
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": token,
            "action_type": "tool_execution",
            "tool_name": "jira",
            "target_resource": "jira.internal.acme.ai",
            "chain_depth": 3,
            "policy_version": "pv-agent-runtime",
            "platform_mode": "enforce",
            "input_context": {"payload": {"issue": "SEC-1234"}},
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["runtime_event_id"]
    assert body["decision"] == "block"
    assert body["reason_code"] == "delegation_chain_depth_mismatch"

    session_local = test_env["SessionLocal"]
    with session_local() as db:
        event = db.get(RuntimeEvent, body["runtime_event_id"])
        assert event is not None
        metadata = dict(event.metadata_json or {})
        assert metadata["claimed_chain_depth"] == 3
        assert metadata["derived_chain_depth"] == 1
        assert metadata["chain_depth"] == 1
        assert metadata["chain_depth_authority_reason"] == "delegation_chain_depth_mismatch"


def test_runtime_control_invalid_token_never_reports_claim_as_derived_depth(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="agent-action-invalid-token-depth@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers)
    agent_id = _create_agent(client, headers)

    response = client.post(
        "/runtime-control/agent-action-intercept",
        headers=headers,
        json={
            "correlation_id": "corr-agent-invalid-token-depth",
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": "invalid-token",
            "action_type": "tool_execution",
            "tool_name": "jira",
            "target_resource": "jira.internal.acme.ai",
            "chain_depth": 9,
            "policy_version": "pv-agent-runtime",
            "platform_mode": "enforce",
            "input_context": {"payload": {"issue": "SEC-1234"}},
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    assert body["reason_code"] == "token_not_found"
    with test_env["SessionLocal"]() as db:
        event = db.get(RuntimeEvent, body["runtime_event_id"])
        assert event is not None
        metadata = dict(event.metadata_json or {})
        assert metadata["claimed_chain_depth"] == 9
        assert metadata["derived_chain_depth"] is None
        assert metadata["chain_depth"] is None
        assert metadata["chain_depth_authority_reason"] == "token_not_found"
