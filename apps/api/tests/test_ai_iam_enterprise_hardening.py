from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"

from app.db.models.activity_audit import DeploymentEndpoint, UserRegistry
from app.db.models.ai_iam import AgentActionBaseline, AgentDelegation, AgentIdentity, CapabilityToken
from app.db.models.audit import AuditLog
from app.db.models.finding import Finding
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.snapshot import AuditorSnapshot
from app.db.models.policy import BusinessPurposeSession
from app.db.models.user import UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.core.config import settings
from ai_system_approval_helpers import approve_ai_system


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "ai_iam_enterprise.sqlite3"
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
            "full_name": "Owner",
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


def _approve_scanned_tool(
    client: TestClient,
    headers: dict[str, str],
    *,
    tool_fingerprint_id: str,
) -> str:
    listed = client.get(
        "/gateway/mcp/tools/fingerprints?limit=100",
        headers=headers,
    )
    assert listed.status_code == 200, listed.text
    fingerprint = next(
        item
        for item in listed.json()["items"]
        if item["id"] == tool_fingerprint_id
    )
    approval = client.post(
        f"/gateway/mcp/tools/fingerprints/{tool_fingerprint_id}/decision",
        headers=headers,
        json={
            "decision": "approve",
            "expected_manifest_hash": fingerprint["manifest_hash"],
            "reason": "Approved exact test contract for the governed action.",
        },
    )
    assert approval.status_code == 200, approval.text
    return tool_fingerprint_id


def _create_ai_system(client: TestClient, headers: dict[str, str], *, risk_tier: str = "MEDIUM") -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": f"System-{risk_tier}", "description": "test", "risk_tier": risk_tier},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    approved = approve_ai_system(client, headers, ai_system_id)
    assert approved.status_code == 200, approved.text
    return ai_system_id


def _create_agent(client: TestClient, headers: dict[str, str], **extra: object) -> str:
    payload = {
        "name": "Enterprise Agent",
        "description": "ai iam hardening test",
        "max_chain_depth": 2,
        "capability_inheritance": False,
    }
    payload.update(extra)
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
    chain_depth: int,
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


def _agent_session_payload(
    *,
    agent_id: str,
    user_id: str,
    session_id: str,
    max_chain_depth: int = 3,
    connected_systems: list[str] | None = None,
) -> dict[str, object]:
    return {
        "session_id": session_id,
        "initiating_user_id": user_id,
        "session_context": {
            "session_id": session_id,
            "agent_id": agent_id,
            "initiating_user_id": user_id,
            "max_chain_depth": max_chain_depth,
            "connected_systems": list(connected_systems or []),
            "allowed_data_scope": ["internal"],
            "data_classification": "internal",
        },
    }


def _persist_purpose_session(
    test_env,
    *,
    owner: dict[str, str],
    agent_id: str,
    actions: list[str],
    tools: list[str],
    resources: list[str],
    max_chain_depth: int,
) -> None:
    with test_env["SessionLocal"]() as db:
        db.add(
            BusinessPurposeSession(
                tenant_id=owner["tenant_id"],
                user_id=owner["user_id"],
                declared_purpose="AI IAM enterprise control validation",
                purpose_category="security_testing",
                business_function="security",
                approved_scope={
                    "identity_id": agent_id,
                    "identity_type": "agent",
                    "purpose": {"name": "ai_iam_validation"},
                    "scope": {
                        "allowed_actions": actions,
                        "allowed_tools": tools,
                        "allowed_domains": resources,
                        "allowed_resources": resources,
                        "allowed_environments": ["prod", "unknown"],
                        "allowed_data_scopes": ["internal"],
                    },
                    "constraints": {"max_risk_level": "critical"},
                    "context": {"connected_systems": resources, "max_chain_depth": max_chain_depth},
                    "status": "active",
                    "mode": "block",
                },
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
                status="active",
            )
        )
        db.commit()


def test_chain_depth_limit(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="chain-depth@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers, risk_tier="MEDIUM")
    agent_id = _create_agent(client, headers, max_chain_depth=2)
    capability_token = _mint_token(
        client,
        headers,
        agent_id=agent_id,
        ai_system_id=ai_system_id,
        scopes=["tool.read", "tool.run"],
        chain_depth=2,
    )
    scan = client.post(
        "/gateway/mcp/tools/scan",
        headers=headers,
        json={
            "mcp_server_id": "control-plane",
            "tool_name": "control_reader",
            "tool_version": "1.0.0",
            "description": "Read control-plane state",
            "schema": {"type": "object", "properties": {}},
        },
    )
    assert scan.status_code == 200, scan.text
    tool_fingerprint_id = _approve_scanned_tool(
        client,
        headers,
        tool_fingerprint_id=scan.json()["tool_fingerprint_id"],
    )
    _persist_purpose_session(
        test_env,
        owner=owner,
        agent_id=agent_id,
        actions=["tool.read", "tool.run"],
        tools=["control_reader", "tool.read"],
        resources=["control-plane"],
        max_chain_depth=2,
    )

    allowed = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_id": agent_id,
            "capability_token": capability_token,
            "action": "tool.read",
            "resource": "control-plane",
            "chain_depth": 1,
            "tool_name": "control_reader",
            "api_endpoint": "mcp://control-plane/read",
            "tool_usage_meta": {
                "mcp_server_id": "control-plane",
                "tool_version": "1.0.0",
                "tool_fingerprint_id": tool_fingerprint_id,
            },
            **_agent_session_payload(
                agent_id=agent_id,
                user_id=owner["user_id"],
                session_id="sess-chain-depth-1",
                max_chain_depth=2,
                connected_systems=["control-plane"],
            ),
        },
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["decision"] == "allow", allowed.json()["reason"]

    blocked = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_id": agent_id,
            "capability_token": capability_token,
            "action": "tool.read",
            "resource": "control-plane",
            "chain_depth": 3,
            **_agent_session_payload(
                agent_id=agent_id,
                user_id=owner["user_id"],
                session_id="sess-chain-depth-1",
                max_chain_depth=2,
                connected_systems=["control-plane"],
            ),
        },
    )
    assert blocked.status_code == 200, blocked.text
    assert blocked.json()["decision"] == "block"
    assert blocked.json()["reason"] == "delegation_chain_depth_mismatch"


def test_mcp_requires_explicit_agent_session(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="session-required@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers, risk_tier="MEDIUM")
    agent_id = _create_agent(client, headers, max_chain_depth=2)
    capability_token = _mint_token(
        client,
        headers,
        agent_id=agent_id,
        ai_system_id=ai_system_id,
        scopes=["tool.read"],
        chain_depth=2,
    )

    response = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_id": agent_id,
            "capability_token": capability_token,
            "action": "tool.read",
            "resource": "control-plane",
            "chain_depth": 1,
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "block"
    assert response.json()["reason"] == "agent_session_required"


def test_mcp_expired_session_is_blocked(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="session-expired@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers, risk_tier="MEDIUM")
    agent_id = _create_agent(client, headers, max_chain_depth=3)
    capability_token = _mint_token(
        client,
        headers,
        agent_id=agent_id,
        ai_system_id=ai_system_id,
        scopes=["tool.read"],
        chain_depth=3,
    )
    _persist_purpose_session(
        test_env,
        owner=owner,
        agent_id=agent_id,
        actions=["tool.read"],
        tools=["tool.read"],
        resources=["control-plane"],
        max_chain_depth=3,
    )

    response = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_id": agent_id,
            "capability_token": capability_token,
            "action": "tool.read",
            "resource": "control-plane",
            "chain_depth": 1,
            **_agent_session_payload(
                agent_id=agent_id,
                    user_id=owner["user_id"],
                session_id="sess-expired-1",
                max_chain_depth=3,
                connected_systems=["control-plane"],
            ),
            "dynamic_permission": {
                "identity_id": agent_id,
                "allowed_tools": ["tool.read"],
                "allowed_actions": ["tool.read"],
                "allowed_data_scope": ["internal"],
                "context": {"connected_systems": ["control-plane"]},
                "expiry": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
            },
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "block"
    assert response.json()["reason"] == "agent_session_expired"


def test_mcp_session_anomalies_and_dynamic_over_scope_create_runtime_findings(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="session-runtime-findings@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers, risk_tier="MEDIUM")
    agent_id = _create_agent(client, headers, max_chain_depth=4)
    capability_token = _mint_token(
        client,
        headers,
        agent_id=agent_id,
        ai_system_id=ai_system_id,
        scopes=["tool.read", "tool.run"],
        chain_depth=4,
    )
    _persist_purpose_session(
        test_env,
        owner=owner,
        agent_id=agent_id,
        actions=["tool.read", "tool.run"],
        tools=["tool.read", "tool.run", "control_reader"],
        resources=["control-plane"],
        max_chain_depth=4,
    )

    no_session = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_id": agent_id,
            "capability_token": capability_token,
            "action": "tool.read",
            "resource": "control-plane",
            "chain_depth": 1,
            "request_id": "agent-session-no-session-1",
        },
    )
    assert no_session.status_code == 200, no_session.text
    assert no_session.json()["decision"] == "block"
    assert no_session.json()["reason"] == "agent_session_required"

    expired_session = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_id": agent_id,
            "capability_token": capability_token,
            "action": "tool.read",
            "resource": "control-plane",
            "chain_depth": 1,
            "request_id": "agent-session-expired-1",
            **_agent_session_payload(
                agent_id=agent_id,
                    user_id=owner["user_id"],
                session_id="agent-session-expired-1",
                max_chain_depth=4,
                connected_systems=["control-plane"],
            ),
            "dynamic_permission": {
                "identity_id": agent_id,
                    "allowed_tools": ["tool.read", "control_reader"],
                "allowed_actions": ["tool.read"],
                "allowed_data_scope": ["internal"],
                "context": {"connected_systems": ["control-plane"]},
                "expiry": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
            },
        },
    )
    assert expired_session.status_code == 200, expired_session.text
    assert expired_session.json()["decision"] == "block"
    assert expired_session.json()["reason"] == "agent_session_expired"

    mismatched_session = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_id": agent_id,
            "capability_token": capability_token,
            "action": "tool.read",
            "resource": "control-plane",
            "chain_depth": 1,
            "request_id": "agent-session-mismatch-1",
            **_agent_session_payload(
                agent_id="other-agent-id",
                    user_id=owner["user_id"],
                session_id="agent-session-mismatch-1",
                max_chain_depth=4,
                connected_systems=["control-plane"],
            ),
            "dynamic_permission": {
                "identity_id": agent_id,
                "allowed_tools": ["control_reader"],
                "allowed_actions": ["tool.read"],
                "allowed_data_scope": ["internal"],
                "context": {"connected_systems": ["control-plane"]},
                "expiry": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
            },
        },
    )
    assert mismatched_session.status_code == 200, mismatched_session.text
    assert mismatched_session.json()["decision"] == "block"
    assert mismatched_session.json()["reason"] == "agent_session_agent_mismatch"

    over_scope_agent_id = _create_agent(client, headers, name="Over Scope Agent", max_chain_depth=4)
    over_scope_token = _mint_token(
        client,
        headers,
        agent_id=over_scope_agent_id,
        ai_system_id=ai_system_id,
        scopes=["tool.read", "tool.run"],
        chain_depth=4,
    )
    _persist_purpose_session(
        test_env,
        owner=owner,
        agent_id=over_scope_agent_id,
        actions=["tool.run"],
        tools=["finance_executor"],
        resources=["finance.internal.acme.ai"],
        max_chain_depth=4,
    )

    over_scoped = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_id": over_scope_agent_id,
            "capability_token": over_scope_token,
            "action": "tool.run",
            "resource": "finance.internal.acme.ai",
            "chain_depth": 1,
            "request_id": "agent-over-scope-dynamic-1",
            "tool_name": "finance_executor",
            "tool_category": "mcp_tool",
            "api_endpoint": "mcp://finance/run",
            "data_source": "finance_system",
            **_agent_session_payload(
                agent_id=over_scope_agent_id,
                    user_id=owner["user_id"],
                session_id="agent-over-scope-dynamic-1",
                max_chain_depth=4,
                connected_systems=["crm.internal"],
            ),
            "dynamic_permission": {
                "identity_id": over_scope_agent_id,
                "allowed_tools": ["crm_reader"],
                "allowed_actions": ["tool.read"],
                "allowed_data_scope": ["internal"],
                "context": {"connected_systems": ["crm.internal"]},
                "expiry": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
            },
        },
    )
    assert over_scoped.status_code == 200, over_scoped.text
    assert over_scoped.json()["decision"] == "block"
    assert over_scoped.json()["reason"] in {
        "dynamic_action_scope_denied",
        "dynamic_tool_scope_denied",
        "dynamic_data_scope_denied",
        "agent_privilege_escalation_detected",
        "scope_reduced_denied",
        "caller_purpose_scope_outside_persisted_authority",
    }

    session_findings = client.get(
        "/runtime-intelligence/findings?page=1&page_size=100&finding_type=AGENT_SESSION_ANOMALY",
        headers=headers,
    )
    assert session_findings.status_code == 200, session_findings.text
    assert session_findings.json()["total"] >= 1
    assert "revoke stale sessions" in str(session_findings.json()["items"][0].get("recommended_action") or "").lower()

    over_scope_findings = client.get(
        "/runtime-intelligence/findings?page=1&page_size=100&finding_type=AGENT_OVER_SCOPE_RISK",
        headers=headers,
    )
    assert over_scope_findings.status_code == 200, over_scope_findings.text
    assert over_scope_findings.json()["total"] >= 1
    assert "dynamic permissions" in str(over_scope_findings.json()["items"][0].get("recommended_action") or "").lower()


def test_mcp_unknown_agent_auto_quarantined(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="auto-quarantine@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers, risk_tier="HIGH")
    actor_id = "f9f4f67a-6cdf-44cb-b670-740fe343c321"

    original = settings.ai_iam_auto_quarantine_new_agents
    settings.ai_iam_auto_quarantine_new_agents = True
    try:
        response = client.post(
            "/gateway/mcp/authorize",
            headers=headers,
            json={
                "ai_system_id": ai_system_id,
                "actor_id": actor_id,
                "capability_token": "unknown-token",
                "action": "tool.run",
                "resource": "internal-system",
                "chain_depth": 1,
            },
        )
    finally:
        settings.ai_iam_auto_quarantine_new_agents = original

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["decision"] == "block"
    assert payload["reason"] == "token_not_found"
    assert payload["agent_id"] == actor_id
    assert payload["auto_quarantine"]["created"] is True
    assert payload["auto_quarantine"]["reason"] == "created"

    with session_local() as db:
        row = db.get(AgentIdentity, actor_id)
        assert row is not None
        assert row.tenant_id == owner["tenant_id"]
        assert row.status == "quarantined"
        assert row.agent_type == "unregistered_agent"


def test_attestation_expiry(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="attestation-expiry@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers, risk_tier="MEDIUM")
    agent_id = _create_agent(client, headers)
    with session_local() as db:
        agent = db.get(AgentIdentity, agent_id)
        assert agent is not None
        agent.owner_attested_at = datetime.now(timezone.utc) - timedelta(minutes=2)
        agent.owner_attestation_expiry = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
    capability_token = _mint_token(
        client,
        headers,
        agent_id=agent_id,
        ai_system_id=ai_system_id,
        scopes=["tool.read"],
        chain_depth=1,
    )

    auth = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_id": agent_id,
            "capability_token": capability_token,
            "action": "tool.read",
            "resource": "kb",
            "chain_depth": 1,
            **_agent_session_payload(
                agent_id=agent_id,
                user_id=owner["user_id"],
                session_id="sess-attestation-1",
                max_chain_depth=2,
                connected_systems=["kb"],
            ),
        },
    )
    assert auth.status_code == 200, auth.text
    assert auth.json()["decision"] == "block"
    assert auth.json()["reason"] == "owner_attestation_expired"


def test_kill_switch_snapshot(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="kill-switch@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers, risk_tier="MEDIUM")
    agent_id = _create_agent(client, headers, max_chain_depth=3)

    _mint_token(
        client,
        headers,
        agent_id=agent_id,
        ai_system_id=ai_system_id,
        scopes=["tool.read"],
        chain_depth=1,
    )
    _mint_token(
        client,
        headers,
        agent_id=agent_id,
        ai_system_id=ai_system_id,
        scopes=["tool.run"],
        chain_depth=2,
    )

    kill = client.post(f"/ai-iam/agents/{agent_id}/kill-switch", headers=headers)
    assert kill.status_code == 200, kill.text
    body = kill.json()
    assert body["status"] == "isolated"
    assert body["revoked_tokens"] == 2
    assert body["snapshot_id"]
    assert len(body["evidence_node_ids"]) >= 2

    with session_local() as db:
        agent = db.get(AgentIdentity, agent_id)
        assert agent is not None
        assert agent.status == "isolated"

        tokens = db.scalars(
            select(CapabilityToken).where(
                CapabilityToken.tenant_id == owner["tenant_id"],
                CapabilityToken.agent_identity_id == agent_id,
            )
        ).all()
        assert len(tokens) == 2
        assert all(token.revoked_at is not None for token in tokens)

        snapshot = db.get(AuditorSnapshot, body["snapshot_id"])
    assert snapshot is not None
    assert snapshot.trigger_type == "kill_switch"
    graph = (snapshot.payload or {}).get("evidence_graph") or {}
    assert len(graph.get("nodes") or []) >= 2
    assert len(graph.get("edges") or []) >= 1


def test_user_registry_profile_includes_enterprise_ai_activity_context(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="user-profile-enterprise@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    now = datetime.now(timezone.utc)
    with session_local() as db:
        db.add(
            UserRegistry(
                tenant_id=owner["tenant_id"],
                user_id="user-enterprise-1",
                display_name="Asha Operator",
                email="asha@example.com",
                department="Security",
                role="Analyst",
                risk_score=0.71,
                deployment_surfaces=["browser", "gateway"],
                first_seen_at=now - timedelta(days=2),
                last_seen_at=now,
            )
        )
        db.add_all(
            [
                DeploymentEndpoint(
                    endpoint_id="machine-a",
                    tenant_id=owner["tenant_id"],
                    user_id="user-enterprise-1",
                    hostname="asha-macbook",
                    os_type="mac",
                    browser_type="chrome",
                    last_seen_at=now,
                    metadata_json={},
                ),
                DeploymentEndpoint(
                    endpoint_id="machine-b",
                    tenant_id=owner["tenant_id"],
                    user_id="user-enterprise-1",
                    hostname="asha-vscode-host",
                    os_type="linux",
                    browser_type="edge",
                    last_seen_at=now - timedelta(minutes=5),
                    metadata_json={},
                ),
                RuntimeEvent(
                    event_id="user-profile-runtime-1",
                    tenant_id=owner["tenant_id"],
                    source_surface="gateway",
                    event_type="tool_call",
                    app_id="Azure OpenAI",
                    user_id="user-enterprise-1",
                    agent_id="agent-owned-1",
                    risk_score=0.81,
                    metadata_json={
                        "ai_surface": "gateway",
                        "machine_id": "machine-a",
                        "browser_type": "chrome",
                        "action_type": "tool_call",
                        "decision": "block",
                        "oauth_relationships": [
                            {
                                "user_id": "user-enterprise-1",
                                "app_id": "oauth-ms-app-1",
                                "scopes": ["Files.Read.All", "Mail.ReadWrite"],
                                "anomaly_flag": True,
                            }
                        ],
                    },
                    created_at=now,
                ),
                RuntimeEvent(
                    event_id="user-profile-runtime-2",
                    tenant_id=owner["tenant_id"],
                    source_surface="endpoint",
                    event_type="api_call",
                    app_id="VSCode",
                    user_id="user-enterprise-1",
                    agent_id="agent-owned-2",
                    risk_score=0.32,
                    metadata_json={
                        "ai_surface": "local",
                        "machine_id": "machine-b",
                        "browser_type": "edge",
                        "action_type": "api_call",
                        "decision": "allow",
                    },
                    created_at=now - timedelta(minutes=2),
                ),
            ]
        )
        db.commit()

    response = client.get("/ai-iam/users/user-enterprise-1", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    user = payload["user"]
    assert user["user_id"] == "user-enterprise-1"
    assert user["machine_ids"] == ["machine-a", "machine-b"]
    assert user["browsers"] == ["chrome", "edge"]
    assert user["connected_apps"] == ["Azure OpenAI", "VSCode"]
    assert user["active_agent_ids"] == ["agent-owned-1", "agent-owned-2"]
    assert user["oauth_relationships"] == [
        {
            "user_id": "user-enterprise-1",
            "app_id": "oauth-ms-app-1",
            "scopes": ["Files.Read.All", "Mail.ReadWrite"],
            "anomaly_flag": True,
        }
    ]
    assert payload["ai_activity_count"] == 2


def test_agent_identity_profile_exposes_behavior_profile_and_linked_findings(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="agent-behavior-profile@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    now = datetime.now(timezone.utc)
    with session_local() as db:
        agent = AgentIdentity(
            tenant_id=owner["tenant_id"],
            name="Claims Agent",
            description="handles claim workflows",
            status="active",
            max_chain_depth=4,
            action_scope=["tool.run", "email_send"],
            tool_registry=["crm_lookup", "email_send"],
            external_system_access=["crm", "outlook"],
        )
        db.add(agent)
        db.flush()
        db.add(
            AgentActionBaseline(
                tenant_id=owner["tenant_id"],
                agent_identity_id=agent.id,
                action="tool_call",
                baseline_rate_per_hour=1.0,
                current_window_count=9,
                window_started_at=now - timedelta(hours=1),
                last_seen_at=now,
                metadata_json={"normal_apps": ["CRM"], "normal_tools": ["crm_lookup"]},
            )
        )
        db.add_all(
            [
                RuntimeEvent(
                    event_id="agent-profile-event-1",
                    tenant_id=owner["tenant_id"],
                    source_surface="agent",
                    event_type="tool_call",
                    app_id="CRM",
                    user_id="owner-user-1",
                    agent_id=agent.id,
                    risk_score=0.78,
                    chain_id="chain-agent-profile",
                    metadata_json={
                        "action_type": "tool_call",
                        "tool_name": "crm_lookup",
                        "target_resource": "crm://claims/42",
                        "decision": "allow",
                        "finding_id": "finding-agent-profile",
                    },
                    created_at=now - timedelta(minutes=4),
                ),
                RuntimeEvent(
                    event_id="agent-profile-event-2",
                    tenant_id=owner["tenant_id"],
                    source_surface="agent",
                    event_type="email_send",
                    app_id="Outlook",
                    user_id="owner-user-1",
                    agent_id=agent.id,
                    risk_score=0.91,
                    chain_id="chain-agent-profile",
                    metadata_json={
                        "action_type": "email_send",
                        "tool_name": "email_send",
                        "target_resource": "mailbox://external",
                        "decision": "block",
                        "finding_id": "finding-agent-profile",
                    },
                    created_at=now - timedelta(minutes=1),
                ),
            ]
        )
        db.add(
            Finding(
                finding_id="finding-agent-profile",
                tenant_id=owner["tenant_id"],
                source_surface="agent",
                ai_tool="Claims Agent",
                agent_id=agent.id,
                severity="high",
                finding_type="agent_behavior_anomaly",
                risk_category="agent_runtime",
                status="open",
                recommended_action="Disable agent or require approval before email_send.",
                related_event_ids=["agent-profile-event-1", "agent-profile-event-2"],
                related_control_ids=["CTRL-AGENT-SCOPE"],
                evidence_node_ids=[],
                dedupe_key="finding-agent-profile",
                first_seen_at=now - timedelta(minutes=4),
                last_seen_at=now,
            )
        )
        db.commit()
        agent_id = agent.id

    response = client.get(f"/ai-iam/identities/{agent_id}", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()

    assert payload["identity_id"] == agent_id
    assert payload["owner"] == "owner-user-1"
    assert payload["recent_actions"][0]["action_type"] == "email_send"
    assert payload["tools"] == ["crm_lookup", "email_send"]
    assert payload["linked_findings"] == ["finding-agent-profile"]
    assert payload["behavior_profile"]["identity_id"] == agent_id
    assert payload["behavior_profile"]["identity_type"] == "agent"
    assert payload["behavior_profile"]["baseline"]["normal_apps"] == ["CRM"]
    assert payload["behavior_profile"]["baseline"]["normal_tools"] == ["crm_lookup"]
    assert payload["behavior_profile"]["current_window"]["apps_seen"] == ["CRM", "Outlook"]
    assert payload["behavior_profile"]["current_window"]["tools_seen"] == ["crm_lookup", "email_send"]
    assert "new_app:Outlook" in payload["behavior_profile"]["deviations"]
    assert "new_tool:email_send" in payload["behavior_profile"]["deviations"]


def test_delegation_and_kill_switch_propagates_to_child_chain(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="delegation-chain@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers, risk_tier="MEDIUM")
    parent_agent_id = _create_agent(
        client,
        headers,
        name="Parent Agent",
        max_chain_depth=3,
        action_scope=["tool.run", "tool.read"],
        tool_registry=["jira_runner"],
        external_system_access=["jira.internal.acme.ai"],
    )
    child_agent_id = _create_agent(
        client,
        headers,
        name="Child Agent",
        max_chain_depth=3,
        capability_inheritance=True,
        action_scope=["tool.run"],
        tool_registry=["jira_runner"],
        external_system_access=["jira.internal.acme.ai"],
    )

    parent_token = _mint_token(
        client,
        headers,
        agent_id=parent_agent_id,
        ai_system_id=ai_system_id,
        scopes=["tool.run", "tool.read"],
        chain_depth=1,
    )

    delegate = client.post(
        "/ai-iam/delegate",
        headers=headers,
        json={
            "parent_agent_id": parent_agent_id,
            "child_agent_id": child_agent_id,
            "ai_system_id": ai_system_id,
            "parent_capability_token": parent_token,
            "action_scope": ["tool.run"],
            "expires_minutes": 60,
            "parent_chain_depth": 1,
        },
    )
    assert delegate.status_code == 200, delegate.text
    delegated_token = delegate.json()["capability_token"]
    assert delegate.json()["delegation_id"]
    scan = client.post(
        "/gateway/mcp/tools/scan",
        headers=headers,
        json={
            "mcp_server_id": "jira.internal.acme.ai",
            "tool_name": "jira_runner",
            "tool_version": "1.0.0",
            "description": "Run an approved Jira workflow",
            "schema": {"type": "object", "properties": {}},
        },
    )
    assert scan.status_code == 200, scan.text
    tool_fingerprint_id = _approve_scanned_tool(
        client,
        headers,
        tool_fingerprint_id=scan.json()["tool_fingerprint_id"],
    )
    _persist_purpose_session(
        test_env,
        owner=owner,
        agent_id=child_agent_id,
        actions=["tool.run"],
        tools=["jira_runner"],
        resources=["jira.internal.acme.ai"],
        max_chain_depth=3,
    )
    _persist_purpose_session(
        test_env,
        owner=owner,
        agent_id=parent_agent_id,
        actions=["tool.run"],
        tools=["jira_runner"],
        resources=["jira.internal.acme.ai"],
        max_chain_depth=3,
    )
    chain_id = "delegation-kill-switch-chain"
    parent_action = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_id": parent_agent_id,
            "capability_token": parent_token,
            "action": "tool.run",
            "resource": "jira.internal.acme.ai",
            "chain_depth": 1,
            "chain_id": chain_id,
            "tool_name": "jira_runner",
            "api_endpoint": "mcp://jira.internal.acme.ai/run",
            "tool_usage_meta": {
                "mcp_server_id": "jira.internal.acme.ai",
                "tool_version": "1.0.0",
                "tool_fingerprint_id": tool_fingerprint_id,
            },
            **_agent_session_payload(
                agent_id=parent_agent_id,
                user_id=owner["user_id"],
                session_id="sess-parent-agent-1",
                max_chain_depth=3,
                connected_systems=["jira.internal.acme.ai"],
            ),
        },
    )
    assert parent_action.status_code == 200, parent_action.text
    assert parent_action.json()["decision"] == "allow", parent_action.json()["reason"]
    parent_action_id = parent_action.json()["runtime_event_id"]

    delegated_action = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_id": child_agent_id,
            "capability_token": delegated_token,
            "action": "tool.run",
            "resource": "jira.internal.acme.ai",
            "chain_depth": 2,
            "chain_id": chain_id,
            "parent_action_id": parent_action_id,
            "parent_agent_id": parent_agent_id,
            "tool_name": "jira_runner",
            "api_endpoint": "mcp://jira.internal.acme.ai/run",
            "tool_usage_meta": {
                "mcp_server_id": "jira.internal.acme.ai",
                "tool_version": "1.0.0",
                "tool_fingerprint_id": tool_fingerprint_id,
            },
            **_agent_session_payload(
                agent_id=child_agent_id,
                user_id=owner["user_id"],
                session_id="sess-child-agent-1",
                max_chain_depth=3,
                connected_systems=["jira.internal.acme.ai"],
            ),
        },
    )
    assert delegated_action.status_code == 200, delegated_action.text
    assert delegated_action.json()["decision"] == "allow", delegated_action.json()["reason"]

    kill = client.post(f"/ai-iam/agents/{parent_agent_id}/kill-switch", headers=headers)
    assert kill.status_code == 200, kill.text
    assert kill.json()["status"] == "isolated"

    with session_local() as db:
        parent_agent = db.get(AgentIdentity, parent_agent_id)
        child_agent = db.get(AgentIdentity, child_agent_id)
        assert parent_agent is not None and parent_agent.status == "isolated"
        assert child_agent is not None and child_agent.status == "isolated"

        child_tokens = db.scalars(
            select(CapabilityToken).where(
                CapabilityToken.tenant_id == owner["tenant_id"],
                CapabilityToken.agent_identity_id == child_agent_id,
            )
        ).all()
        assert child_tokens
        assert all(token.revoked_at is not None for token in child_tokens)

        delegations = db.scalars(
            select(AgentDelegation).where(AgentDelegation.tenant_id == owner["tenant_id"])
        ).all()
        assert delegations
        assert all(row.status == "revoked" for row in delegations)


def test_agent_create_and_update_reject_client_attestation_timestamps(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="attestation-update@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    attested_at = datetime.now(timezone.utc).replace(microsecond=0)
    expiry = attested_at + timedelta(minutes=35)

    create = client.post(
        "/ai-iam/agents",
        headers=headers,
        json={
            "name": "Client-attested agent",
            "owner_attested_at": attested_at.isoformat(),
            "owner_attestation_expiry": expiry.isoformat(),
        },
    )
    assert create.status_code == 422, create.text
    assert any(
        error["type"] == "owner_attestation_server_issued"
        for error in create.json()["detail"]
    )

    agent_id = _create_agent(client, headers)

    response = client.patch(
        f"/ai-iam/agents/{agent_id}",
        headers=headers,
        json={
            "owner_attested_at": attested_at.isoformat(),
            "owner_attestation_expiry": expiry.isoformat(),
        },
    )

    assert response.status_code == 422, response.text
    assert any(
        error["type"] == "owner_attestation_server_issued"
        for error in response.json()["detail"]
    )
    with session_local() as db:
        agent = db.get(AgentIdentity, agent_id)
        assert agent is not None
        assert agent.owner_attested_at is None
        assert agent.owner_attestation_expiry is None


def test_owner_attestation_refresh_uses_server_time_and_audits_actor(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="attestation-refresh@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    agent_id = _create_agent(client, headers)
    before = datetime.now(timezone.utc)

    response = client.post(
        f"/ai-iam/agents/{agent_id}/owner-attestation/refresh",
        headers=headers,
        json={"expires_minutes": 35},
    )

    after = datetime.now(timezone.utc)
    assert response.status_code == 200, response.text
    body = response.json()
    attested_at = datetime.fromisoformat(body["owner_attested_at"].replace("Z", "+00:00"))
    expiry = datetime.fromisoformat(body["owner_attestation_expiry"].replace("Z", "+00:00"))
    if attested_at.tzinfo is None:
        attested_at = attested_at.replace(tzinfo=timezone.utc)
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    assert before <= attested_at <= after
    assert timedelta(minutes=34, seconds=59) <= expiry - attested_at <= timedelta(minutes=35, seconds=1)
    with session_local() as db:
        audit = db.scalar(
            select(AuditLog).where(
                AuditLog.tenant_id == owner["tenant_id"],
                AuditLog.action == "ai_iam.agent.owner_attestation.refresh",
                AuditLog.resource_id == agent_id,
            )
        )
        assert audit is not None
        assert audit.actor_user_id == owner["user_id"]
        assert audit.payload["expires_minutes"] == 35


def test_owner_attestation_refresh_rejects_operator_and_hides_other_tenant_agent(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="attestation-owner@example.com")
    owner_headers = _headers(owner["access_token"], owner["tenant_id"])
    agent_id = _create_agent(client, owner_headers)
    operator = _register_owner(client, email="attestation-operator@example.com")
    with session_local() as db:
        db.add(
            UserTenantRole(
                user_id=operator["user_id"],
                tenant_id=owner["tenant_id"],
                role="operator",
            )
        )
        db.commit()

    operator_refresh = client.post(
        f"/ai-iam/agents/{agent_id}/owner-attestation/refresh",
        headers=_headers(operator["access_token"], owner["tenant_id"]),
        json={"expires_minutes": 35},
    )

    assert operator_refresh.status_code == 403, operator_refresh.text

    other_owner = _register_owner(client, email="attestation-other-owner@example.com")
    other_headers = _headers(other_owner["access_token"], other_owner["tenant_id"])
    other_agent_id = _create_agent(client, other_headers)
    cross_tenant_refresh = client.post(
        f"/ai-iam/agents/{other_agent_id}/owner-attestation/refresh",
        headers=owner_headers,
        json={"expires_minutes": 35},
    )

    assert cross_tenant_refresh.status_code == 404, cross_tenant_refresh.text


@pytest.mark.parametrize("expires_minutes", [0, 61])
def test_owner_attestation_refresh_bounds_expiry(test_env, expires_minutes: int) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email=f"attestation-bound-{expires_minutes}@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    agent_id = _create_agent(client, headers)

    response = client.post(
        f"/ai-iam/agents/{agent_id}/owner-attestation/refresh",
        headers=headers,
        json={"expires_minutes": expires_minutes},
    )

    assert response.status_code == 422, response.text
