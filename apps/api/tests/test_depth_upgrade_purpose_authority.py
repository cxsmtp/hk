from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.core.security import token_hash
from app.db.models.ai_iam import AgentDelegation, AgentIdentity, CapabilityToken
from app.db.models.ai_system import AISystem
from app.db.models.policy import BusinessPurposeSession
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.session import Base, get_db
from app.main import app
from app.services.ai_iam_service import resolve_persisted_purpose_bound_permission
from app.services.ai_iam_service import evaluate_purpose_bound_permission
from app.services.ai_iam_service import narrow_authority_values


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "depth_upgrade_purpose_authority.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Purpose Authority Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
        "user_id": body["user"]["id"],
    }


def _headers(owner: dict[str, str]) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {owner['access_token']}",
        "X-Tenant-ID": owner["tenant_id"],
    }


def _setup_runtime_authority(
    test_env,
    *,
    agent_action_scope: list[str] | None = None,
    agent_tools: list[str] | None = None,
    agent_systems: list[str] | None = None,
    token_scopes: list[str] | None = None,
) -> tuple[dict[str, str], str, str, str]:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="purpose-authority-owner@example.com")
    headers = _headers(owner)
    system_response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Purpose Authority System", "description": "authority test", "risk_tier": "MEDIUM"},
    )
    assert system_response.status_code == 200, system_response.text
    ai_system_id = system_response.json()["id"]
    agent_response = client.post(
        "/ai-iam/agents",
        headers=headers,
        json={
            "name": "Purpose Authority Agent",
            "description": "authority test",
            "max_chain_depth": 3,
            "capability_inheritance": False,
            "action_scope": list(agent_action_scope or ["tool.run"]),
            "tool_registry": list(agent_tools or ["openai_api"]),
            "external_system_access": list(agent_systems or ["api.openai.com"]),
        },
    )
    assert agent_response.status_code == 200, agent_response.text
    agent_id = agent_response.json()["id"]
    raw_token = "purpose-authority-runtime-token"
    with test_env["SessionLocal"]() as db:
        ai_system = db.get(AISystem, ai_system_id)
        assert ai_system is not None
        ai_system.status = "active"
        ai_system.metadata_json = {
            **dict(ai_system.metadata_json or {}),
            "governance_state": "APPROVED",
            "lifecycle_state": "ACTIVE",
        }
        db.add(
            CapabilityToken(
                tenant_id=owner["tenant_id"],
                agent_identity_id=agent_id,
                ai_system_id=ai_system_id,
                token_hash=token_hash(raw_token),
                scopes=list(token_scopes or ["tool.run"]),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                chain_depth=3,
                issued_by_user_id=owner["user_id"],
            )
        )
        db.commit()
    return owner, ai_system_id, agent_id, raw_token


def _caller_permission(agent_id: str) -> dict:
    return {
        "permission_id": "caller-forged-purpose-authority",
        "identity_id": agent_id,
        "identity_type": "agent",
        "purpose": {"name": "caller_claim", "declared_intent": "run_api"},
        "scope": {
            "allowed_actions": ["api_call"],
            "allowed_tools": ["openai_api"],
            "allowed_domains": ["api.openai.com"],
            "allowed_resources": ["api.openai.com"],
            "allowed_environments": ["prod"],
        },
        "constraints": {
            "expiry": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
            "max_risk_level": "medium",
        },
        "status": "active",
        "mode": "block",
    }


def _persist_purpose_session(
    test_env,
    *,
    tenant_id: str,
    user_id: str,
    agent_id: str,
    allowed_actions: list[str] | None = None,
    allowed_tools: list[str] | None = None,
    status: str = "active",
    expires_at: datetime | None = None,
    allowed_data_scopes: list[str] | None = None,
    max_chain_depth: int | None = None,
    require_human_confirmation: bool = False,
    approval_required_for: list[str] | None = None,
) -> str:
    with test_env["SessionLocal"]() as db:
        row = BusinessPurposeSession(
            tenant_id=tenant_id,
            user_id=user_id,
            declared_purpose="Support triage",
            purpose_category="customer_support",
            business_function="support",
            approved_scope={
                "identity_id": agent_id,
                "identity_type": "agent",
                "purpose": {"name": "support_triage", "declared_intent": "support_triage"},
                "scope": {
                    "allowed_actions": list(allowed_actions or ["api_call"]),
                    "allowed_tools": list(allowed_tools or ["openai_api"]),
                    "allowed_domains": ["api.openai.com"],
                    "allowed_resources": ["api.openai.com"],
                    "allowed_environments": ["prod"],
                    "allowed_data_scopes": list(allowed_data_scopes or ["internal"]),
                },
                "constraints": {
                    "max_risk_level": "medium",
                    "require_human_confirmation": require_human_confirmation,
                    "approval_required_for": list(approval_required_for or []),
                },
                "context": ({"max_chain_depth": max_chain_depth} if max_chain_depth is not None else {}),
                "mode": "block",
            },
            status=status,
            expires_at=expires_at or (datetime.now(timezone.utc) + timedelta(minutes=30)),
        )
        db.add(row)
        db.commit()
        return row.id


def _persist_parent_delegation(
    test_env,
    *,
    tenant_id: str,
    child_agent_id: str,
    child_raw_token: str,
    ai_system_id: str,
) -> tuple[str, str, str, str, str]:
    with test_env["SessionLocal"]() as db:
        child_agent = db.get(AgentIdentity, child_agent_id)
        child_token = db.query(CapabilityToken).filter(
            CapabilityToken.tenant_id == tenant_id,
            CapabilityToken.token_hash == token_hash(child_raw_token),
        ).one()
        assert child_agent is not None
        child_agent.capability_inheritance = True
        parent = AgentIdentity(
            tenant_id=tenant_id,
            name="Purpose Authority Parent",
            max_chain_depth=3,
            capability_inheritance=True,
            action_scope=["tool.run"],
            tool_registry=["openai_api"],
            external_system_access=["api.openai.com"],
        )
        db.add(parent)
        db.flush()
        parent_token = CapabilityToken(
            tenant_id=tenant_id,
            agent_identity_id=parent.id,
            ai_system_id=ai_system_id,
            token_hash=token_hash("purpose-authority-parent-token"),
            scopes=["tool.run"],
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            chain_depth=1,
        )
        db.add(parent_token)
        db.flush()
        edge = AgentDelegation(
                tenant_id=tenant_id,
                parent_agent_identity_id=parent.id,
                child_agent_identity_id=child_agent_id,
                parent_token_id=parent_token.id,
                child_token_id=child_token.id,
                ai_system_id=ai_system_id,
                action_scope=["tool.run"],
                chain_depth=2,
                status="active",
            )
        db.add(edge)
        db.flush()
        chain_id = "purpose-depth-chain"
        parent_action_id = "purpose-depth-parent-action"
        db.add(
            RuntimeEvent(
                event_id=parent_action_id,
                tenant_id=tenant_id,
                source_surface="aiiam",
                event_type="agent_action_intercept",
                ai_system_id=ai_system_id,
                agent_id=parent.id,
                decision="allow",
                chain_id=chain_id,
                metadata_json={
                    "capability_token_id": parent_token.id,
                    "delegation_edge_id": None,
                },
            )
        )
        db.commit()
        return parent.id, chain_id, parent_action_id, edge.id, child_token.id


def test_runtime_rejects_forged_caller_permission_without_persisted_authority(test_env) -> None:
    client: TestClient = test_env["client"]
    owner, ai_system_id, agent_id, raw_token = _setup_runtime_authority(test_env)

    response = client.post(
        "/runtime-control/agent-action-intercept",
        headers=_headers(owner),
        json={
            "correlation_id": "forged-purpose-authority",
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": raw_token,
            "action_type": "api_call",
            "tool_name": "openai_api",
            "target_resource": "api.openai.com",
            "chain_depth": 1,
            "policy_version": "purpose-authority-v1",
            "platform_mode": "enforce",
            "input_context": {
                "purpose_bound_permission": _caller_permission(agent_id),
                "environment": "prod",
                "payload": {"prompt": "summarize public release notes"},
            },
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    assert body["reason_code"] == "persisted_purpose_permission_required"


def test_runtime_rejects_root_token_bound_to_another_ai_system(test_env) -> None:
    client: TestClient = test_env["client"]
    owner, _bound_system_id, agent_id, raw_token = _setup_runtime_authority(test_env)
    other = client.post(
        "/ai-systems",
        headers=_headers(owner),
        json={"name": "Other Runtime System", "description": "cross-system", "risk_tier": "LOW"},
    )
    assert other.status_code == 200, other.text
    other_system_id = other.json()["id"]
    with test_env["SessionLocal"]() as db:
        ai_system = db.get(AISystem, other_system_id)
        assert ai_system is not None
        ai_system.status = "active"
        ai_system.metadata_json = {"governance_state": "APPROVED", "lifecycle_state": "ACTIVE"}
        db.commit()

    response = client.post(
        "/runtime-control/agent-action-intercept",
        headers=_headers(owner),
        json={
            "ai_system_id": other_system_id,
            "agent_id": agent_id,
            "capability_token": raw_token,
            "action_type": "api_call",
            "tool_name": "openai_api",
            "target_resource": "api.openai.com",
            "chain_depth": 1,
            "platform_mode": "enforce",
            "input_context": {"data_classification": "internal", "environment": "prod"},
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "block"
    assert response.json()["reason_code"] == "delegation_chain_token_system_mismatch"


def test_runtime_rejects_malformed_caller_permission_with_valid_persisted_authority(test_env) -> None:
    client: TestClient = test_env["client"]
    owner, ai_system_id, agent_id, raw_token = _setup_runtime_authority(test_env)
    _persist_purpose_session(
        test_env,
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        agent_id=agent_id,
    )

    response = client.post(
        "/runtime-control/agent-action-intercept",
        headers=_headers(owner),
        json={
            "correlation_id": "malformed-runtime-purpose-authority",
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": raw_token,
            "action_type": "api_call",
            "tool_name": "openai_api",
            "target_resource": "api.openai.com",
            "chain_depth": 1,
            "policy_version": "purpose-authority-v1",
            "platform_mode": "enforce",
            "input_context": {
                "purpose_bound_permission": "caller-supplied-not-an-object",
                "environment": "prod",
                "payload": {"prompt": "summarize public release notes"},
            },
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    assert body["reason_code"] == "caller_purpose_permission_schema_invalid"


def test_runtime_enforces_persisted_data_scope(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_runtime_authority(test_env)
    _persist_purpose_session(
        test_env,
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        agent_id=agent_id,
        allowed_data_scopes=["public"],
    )
    response = test_env["client"].post(
        "/runtime-control/agent-action-intercept",
        headers=_headers(owner),
        json={
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": raw_token,
            "action_type": "api_call",
            "tool_name": "openai_api",
            "target_resource": "api.openai.com",
            "chain_depth": 1,
            "platform_mode": "enforce",
            "input_context": {"data_classification": "internal", "environment": "prod"},
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "block"
    assert response.json()["reason_code"] == "purpose_data_scope_denied"


def test_runtime_enforces_persisted_chain_depth(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_runtime_authority(test_env)
    parent_agent_id, chain_id, parent_action_id, edge_id, child_token_id = _persist_parent_delegation(
        test_env,
        tenant_id=owner["tenant_id"],
        child_agent_id=agent_id,
        child_raw_token=raw_token,
        ai_system_id=ai_system_id,
    )
    _persist_purpose_session(
        test_env,
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        agent_id=agent_id,
        max_chain_depth=1,
    )
    response = test_env["client"].post(
        "/runtime-control/agent-action-intercept",
        headers=_headers(owner),
        json={
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": raw_token,
            "action_type": "api_call",
            "tool_name": "openai_api",
            "target_resource": "api.openai.com",
            "chain_depth": 2,
            "chain_id": chain_id,
            "parent_action_id": parent_action_id,
            "platform_mode": "enforce",
            "input_context": {
                "data_classification": "internal",
                "environment": "prod",
                "parent_agent_id": parent_agent_id,
            },
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    assert body["reason_code"] == "purpose_chain_depth_exceeded"
    with test_env["SessionLocal"]() as db:
        event = db.get(RuntimeEvent, body["runtime_event_id"])
        assert event is not None
        assert event.metadata_json["capability_token_id"] == child_token_id
        assert event.metadata_json["delegation_edge_id"] == edge_id


def test_runtime_public_api_uses_emitted_parent_events_for_multi_hop_delegation(test_env) -> None:
    owner, ai_system_id, root_agent_id, root_token = _setup_runtime_authority(test_env)
    client: TestClient = test_env["client"]
    headers = _headers(owner)
    with test_env["SessionLocal"]() as db:
        root_agent = db.get(AgentIdentity, root_agent_id)
        assert root_agent is not None
        root_agent.capability_inheritance = True
        db.commit()
    _persist_purpose_session(
        test_env,
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        agent_id=root_agent_id,
        max_chain_depth=3,
    )
    chain_id = "runtime-emitted-authority-chain"

    root_response = client.post(
        "/runtime-control/agent-action-intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "agent_id": root_agent_id,
            "capability_token": root_token,
            "action_type": "api_call",
            "tool_name": "openai_api",
            "target_resource": "api.openai.com",
            "chain_depth": 1,
            "chain_id": chain_id,
            "platform_mode": "enforce",
            "input_context": {"data_classification": "internal", "environment": "prod"},
        },
    )
    assert root_response.status_code == 200, root_response.text
    assert root_response.json()["decision"] == "allow"
    root_action_id = root_response.json()["runtime_event_id"]

    mid_response = client.post(
        "/ai-iam/agents",
        headers=headers,
        json={
            "name": "Runtime Emitted Mid",
            "max_chain_depth": 3,
            "capability_inheritance": True,
            "action_scope": ["tool.run"],
            "tool_registry": ["openai_api"],
            "external_system_access": ["api.openai.com"],
        },
    )
    assert mid_response.status_code == 200, mid_response.text
    mid_agent_id = mid_response.json()["id"]
    mid_delegation = client.post(
        "/ai-iam/delegate",
        headers=headers,
        json={
            "parent_agent_id": root_agent_id,
            "child_agent_id": mid_agent_id,
            "ai_system_id": ai_system_id,
            "parent_capability_token": root_token,
            "action_scope": ["tool.run"],
            "parent_chain_depth": 1,
            "chain_depth": 2,
        },
    )
    assert mid_delegation.status_code == 200, mid_delegation.text
    _persist_purpose_session(test_env, tenant_id=owner["tenant_id"], user_id=owner["user_id"], agent_id=mid_agent_id, max_chain_depth=3)

    mid_action = client.post(
        "/runtime-control/agent-action-intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "agent_id": mid_agent_id,
            "capability_token": mid_delegation.json()["capability_token"],
            "action_type": "api_call",
            "tool_name": "openai_api",
            "target_resource": "api.openai.com",
            "chain_depth": 2,
            "chain_id": chain_id,
            "parent_action_id": root_action_id,
            "parent_agent_id": root_agent_id,
            "platform_mode": "enforce",
            "input_context": {"data_classification": "internal", "environment": "prod"},
        },
    )
    assert mid_action.status_code == 200, mid_action.text
    assert mid_action.json()["decision"] == "allow"
    mid_action_id = mid_action.json()["runtime_event_id"]
    with test_env["SessionLocal"]() as db:
        emitted_mid = db.get(RuntimeEvent, mid_action_id)
        assert emitted_mid is not None
        assert emitted_mid.metadata_json["capability_token_id"] == mid_delegation.json()["token_id"]
        assert emitted_mid.metadata_json["delegation_edge_id"] == mid_delegation.json()["delegation_id"]

    child_response = client.post(
        "/ai-iam/agents",
        headers=headers,
        json={
            "name": "Runtime Emitted Child",
            "max_chain_depth": 3,
            "capability_inheritance": True,
            "action_scope": ["tool.run"],
            "tool_registry": ["openai_api"],
            "external_system_access": ["api.openai.com"],
        },
    )
    assert child_response.status_code == 200, child_response.text
    child_agent_id = child_response.json()["id"]
    child_delegation = client.post(
        "/ai-iam/delegate",
        headers=headers,
        json={
            "parent_agent_id": mid_agent_id,
            "child_agent_id": child_agent_id,
            "ai_system_id": ai_system_id,
            "parent_capability_token": mid_delegation.json()["capability_token"],
            "action_scope": ["tool.run"],
            "parent_chain_depth": 2,
            "chain_depth": 3,
        },
    )
    assert child_delegation.status_code == 200, child_delegation.text
    _persist_purpose_session(test_env, tenant_id=owner["tenant_id"], user_id=owner["user_id"], agent_id=child_agent_id, max_chain_depth=3)

    child_action = client.post(
        "/runtime-control/agent-action-intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "agent_id": child_agent_id,
            "capability_token": child_delegation.json()["capability_token"],
            "action_type": "api_call",
            "tool_name": "openai_api",
            "target_resource": "api.openai.com",
            "chain_depth": 3,
            "chain_id": chain_id,
            "parent_action_id": mid_action_id,
            "parent_agent_id": mid_agent_id,
            "platform_mode": "enforce",
            "input_context": {"data_classification": "internal", "environment": "prod"},
        },
    )
    assert child_action.status_code == 200, child_action.text
    assert child_action.json()["decision"] == "allow"


def test_runtime_delegated_parent_surface_requires_ai_system_id(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_runtime_authority(test_env)
    parent_agent_id, chain_id, parent_action_id, _edge_id, _child_token_id = _persist_parent_delegation(
        test_env,
        tenant_id=owner["tenant_id"],
        child_agent_id=agent_id,
        child_raw_token=raw_token,
        ai_system_id=ai_system_id,
    )
    _persist_purpose_session(
        test_env,
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        agent_id=agent_id,
        max_chain_depth=3,
    )

    response = test_env["client"].post(
        "/runtime-control/agent-action-intercept",
        headers=_headers(owner),
        json={
            "agent_id": agent_id,
            "capability_token": raw_token,
            "action_type": "api_call",
            "tool_name": "openai_api",
            "target_resource": "api.openai.com",
            "chain_depth": 2,
            "chain_id": chain_id,
            "parent_action_id": parent_action_id,
            "parent_agent_id": parent_agent_id,
            "platform_mode": "enforce",
            "input_context": {"data_classification": "internal", "environment": "prod"},
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "block"
    assert response.json()["reason_code"] == "delegation_chain_ai_system_required"


def test_runtime_requires_persisted_confirmation_artifact(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_runtime_authority(test_env)
    _persist_purpose_session(
        test_env,
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        agent_id=agent_id,
        require_human_confirmation=True,
    )
    response = test_env["client"].post(
        "/runtime-control/agent-action-intercept",
        headers=_headers(owner),
        json={
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": raw_token,
            "action_type": "api_call",
            "tool_name": "openai_api",
            "target_resource": "api.openai.com",
            "chain_depth": 1,
            "platform_mode": "enforce",
            "input_context": {
                "data_classification": "internal",
                "environment": "prod",
                "human_confirmed": True,
            },
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "require_approval"
    assert response.json()["reason_code"] == "purpose_confirmation_required"


def test_runtime_enforces_persisted_approval_required_for(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_runtime_authority(test_env)
    _persist_purpose_session(
        test_env,
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        agent_id=agent_id,
        approval_required_for=["api_call"],
    )
    response = test_env["client"].post(
        "/runtime-control/agent-action-intercept",
        headers=_headers(owner),
        json={
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": raw_token,
            "action_type": "api_call",
            "tool_name": "openai_api",
            "target_resource": "api.openai.com",
            "chain_depth": 1,
            "platform_mode": "enforce",
            "input_context": {"data_classification": "internal", "environment": "prod"},
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "require_approval"
    assert response.json()["reason_code"] == "purpose_confirmation_required"


@pytest.mark.parametrize("target_resource", [None, "https://[invalid-host"])
def test_runtime_rejects_empty_or_malformed_purpose_target(test_env, target_resource: str | None) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_runtime_authority(test_env)
    _persist_purpose_session(
        test_env,
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        agent_id=agent_id,
    )
    response = test_env["client"].post(
        "/runtime-control/agent-action-intercept",
        headers=_headers(owner),
        json={
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": raw_token,
            "action_type": "api_call",
            "tool_name": "openai_api",
            "target_resource": target_resource,
            "chain_depth": 1,
            "platform_mode": "enforce",
            "input_context": {"data_classification": "internal", "environment": "prod"},
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "block"
    assert response.json()["pre_action_governance_check"]["purpose"]["violations"]


def test_mcp_rejects_forged_dynamic_permission_without_persisted_authority(test_env) -> None:
    client: TestClient = test_env["client"]
    owner, ai_system_id, agent_id, raw_token = _setup_runtime_authority(test_env)
    forged = _caller_permission(agent_id)
    forged["scope"]["allowed_actions"] = ["tool.run"]
    forged["allowed_actions"] = ["tool.run"]
    forged["allowed_tools"] = ["openai_api"]
    forged["allowed_data_scope"] = ["internal"]
    forged["constraints"]["max_risk_level"] = "critical"

    response = client.post(
        "/gateway/mcp/authorize",
        headers=_headers(owner),
        json={
            "request_id": "forged-mcp-purpose-authority",
            "ai_system_id": ai_system_id,
            "actor_id": agent_id,
            "capability_token": raw_token,
            "action": "tool.run",
            "resource": "api.openai.com",
            "chain_depth": 1,
            "api_endpoint": "mcp://runtime/run",
            "session_id": "caller-invented-session",
            "initiating_user_id": "caller-invented-user",
            "session_context": {
                "agent_id": agent_id,
                "allowed_data_scope": ["internal"],
                "data_classification": "internal",
                "max_chain_depth": 3,
            },
            "dynamic_permission": forged,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    purpose_check = body["pre_action_governance_check"]
    assert purpose_check["purpose"]["purpose_bound_permission_id"] is None
    assert purpose_check["policy"]["reason"] == "persisted_purpose_permission_required"


def test_caller_permission_can_only_narrow_persisted_approved_scope(test_env) -> None:
    owner, _ai_system_id, agent_id, _raw_token = _setup_runtime_authority(test_env)
    session_id = _persist_purpose_session(
        test_env,
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        agent_id=agent_id,
        allowed_actions=["api_call", "tool_execution"],
        allowed_tools=["openai_api", "jira"],
    )
    caller = _caller_permission(agent_id)
    caller["scope"]["allowed_actions"] = ["api_call", "email_send"]
    caller["scope"]["allowed_tools"] = ["openai_api", "mail_sender"]

    with test_env["SessionLocal"]() as db:
        result = resolve_persisted_purpose_bound_permission(
            db,
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            agent_id=agent_id,
            caller_permission=caller,
        )

    assert result["valid"] is True
    assert result["session_id"] == session_id
    assert result["permission"]["permission_id"] == session_id
    assert result["permission"]["identity_id"] == agent_id
    assert result["permission"]["scope"]["allowed_actions"] == ["api_call"]
    assert result["permission"]["scope"]["allowed_tools"] == ["openai_api"]


def test_empty_caller_intersection_fails_closed(test_env) -> None:
    owner, _ai_system_id, agent_id, _raw_token = _setup_runtime_authority(test_env)
    _persist_purpose_session(
        test_env,
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        agent_id=agent_id,
        allowed_actions=["db_query"],
    )
    caller = _caller_permission(agent_id)
    caller["scope"]["allowed_actions"] = ["api_call"]

    with test_env["SessionLocal"]() as db:
        result = resolve_persisted_purpose_bound_permission(
            db,
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            agent_id=agent_id,
            caller_permission=caller,
        )

    assert result["valid"] is False
    assert result["reason"] == "caller_purpose_scope_outside_persisted_authority"


@pytest.mark.parametrize(
    ("status", "expires_at", "expected_reason"),
    [
        ("inactive", datetime.now(timezone.utc) + timedelta(minutes=30), "persisted_purpose_permission_inactive"),
        ("active", datetime.now(timezone.utc) - timedelta(minutes=1), "persisted_purpose_permission_expired"),
    ],
)
def test_inactive_or_expired_persisted_session_fails_closed(
    test_env,
    status: str,
    expires_at: datetime,
    expected_reason: str,
) -> None:
    owner, _ai_system_id, agent_id, _raw_token = _setup_runtime_authority(test_env)
    _persist_purpose_session(
        test_env,
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        agent_id=agent_id,
        status=status,
        expires_at=expires_at,
    )

    with test_env["SessionLocal"]() as db:
        result = resolve_persisted_purpose_bound_permission(
            db,
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            agent_id=agent_id,
            caller_permission=_caller_permission(agent_id),
        )

    assert result["valid"] is False
    assert result["reason"] == expected_reason


@pytest.mark.parametrize("foreign_tenant", [False, True])
def test_foreign_tenant_or_wrong_user_persisted_session_does_not_grant_authority(
    test_env,
    foreign_tenant: bool,
) -> None:
    owner, _ai_system_id, agent_id, _raw_token = _setup_runtime_authority(test_env)
    other = _register_owner(
        test_env["client"],
        email=f"other-purpose-authority-{foreign_tenant}@example.com",
    )
    _persist_purpose_session(
        test_env,
        tenant_id=(other["tenant_id"] if foreign_tenant else owner["tenant_id"]),
        user_id=other["user_id"],
        agent_id=agent_id,
    )

    with test_env["SessionLocal"]() as db:
        result = resolve_persisted_purpose_bound_permission(
            db,
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            agent_id=agent_id,
            caller_permission=_caller_permission(agent_id),
        )

    assert result["valid"] is False
    assert result["reason"] == "persisted_purpose_permission_required"


def test_persisted_session_bound_to_other_agent_fails_closed(test_env) -> None:
    owner, _ai_system_id, agent_id, _raw_token = _setup_runtime_authority(test_env)
    _persist_purpose_session(
        test_env,
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        agent_id="different-server-agent",
    )

    with test_env["SessionLocal"]() as db:
        result = resolve_persisted_purpose_bound_permission(
            db,
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            agent_id=agent_id,
            caller_permission=_caller_permission(agent_id),
        )

    assert result["valid"] is False
    assert result["reason"] == "persisted_purpose_permission_agent_mismatch"


def test_empty_persisted_approved_scope_cannot_be_expanded_by_caller(test_env) -> None:
    owner, _ai_system_id, agent_id, _raw_token = _setup_runtime_authority(test_env)
    with test_env["SessionLocal"]() as db:
        db.add(
            BusinessPurposeSession(
                tenant_id=owner["tenant_id"],
                user_id=owner["user_id"],
                declared_purpose="Malformed empty scope",
                purpose_category="unknown",
                business_function="unknown",
                approved_scope={},
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
                status="active",
            )
        )
        db.commit()

    with test_env["SessionLocal"]() as db:
        result = resolve_persisted_purpose_bound_permission(
            db,
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            agent_id=agent_id,
            caller_permission=_caller_permission(agent_id),
        )

    assert result["valid"] is False
    assert result["reason"] == "persisted_purpose_scope_invalid"


@pytest.mark.parametrize(
    ("persisted_actions", "caller_actions", "expected_actions"),
    [
        (["*"], ["api_call"], ["api_call"]),
        (["api_call"], ["*"], ["api_call"]),
    ],
)
def test_wildcard_scope_intersection_never_expands_persisted_authority(
    test_env,
    persisted_actions: list[str],
    caller_actions: list[str],
    expected_actions: list[str],
) -> None:
    owner, _ai_system_id, agent_id, _raw_token = _setup_runtime_authority(test_env)
    _persist_purpose_session(
        test_env,
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        agent_id=agent_id,
        allowed_actions=persisted_actions,
    )
    caller = _caller_permission(agent_id)
    caller["scope"]["allowed_actions"] = caller_actions

    with test_env["SessionLocal"]() as db:
        result = resolve_persisted_purpose_bound_permission(
            db,
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            agent_id=agent_id,
            caller_permission=caller,
        )

    assert result["valid"] is True
    assert result["permission"]["scope"]["allowed_actions"] == expected_actions


def test_domain_scope_rejects_suffix_lookalike_and_canonicalizes_host() -> None:
    permission = _caller_permission("agent")
    blocked = evaluate_purpose_bound_permission(
        permission=permission,
        action_type="api_call",
        action_category="unknown",
        action_risk="medium",
        domain="api.openai.com.evil.test",
        target_resource="api.openai.com",
        environment="prod",
    )
    canonical = evaluate_purpose_bound_permission(
        permission=permission,
        action_type="api_call",
        action_category="unknown",
        action_risk="medium",
        domain="API.OPENAI.COM.",
        target_resource="api.openai.com",
        environment="prod",
    )

    assert blocked["decision"] == "block"
    assert canonical["decision"] == "allow"


def test_domain_scope_canonicalizes_unicode_idna_hosts() -> None:
    permission = _caller_permission("agent")
    permission["scope"]["allowed_domains"] = ["bücher.example"]
    result = evaluate_purpose_bound_permission(
        permission=permission,
        action_type="api_call",
        action_category="unknown",
        action_risk="medium",
        domain="XN--BCHER-KVA.EXAMPLE.",
        target_resource="api.openai.com",
        environment="prod",
    )

    assert result["decision"] == "allow"


def test_caller_domain_scope_cannot_widen_persisted_subdomain_authority() -> None:
    assert narrow_authority_values(
        ["api.example.com"],
        ["example.com"],
        kind="domain",
    ) == ["api.example.com"]


def test_resource_scope_uses_exact_or_explicit_prefix_glob_only() -> None:
    permission = _caller_permission("agent")
    permission["scope"]["allowed_resources"] = ["customer-record"]
    lookalike = evaluate_purpose_bound_permission(
        permission=permission,
        action_type="api_call",
        action_category="unknown",
        action_risk="medium",
        target_resource="not-customer-record-copy",
        domain="api.openai.com",
        environment="prod",
    )
    permission["scope"]["allowed_resources"] = ["customers/*"]
    explicit_prefix = evaluate_purpose_bound_permission(
        permission=permission,
        action_type="api_call",
        action_category="unknown",
        action_risk="medium",
        target_resource="customers/123",
        domain="api.openai.com",
        environment="prod",
    )

    assert lookalike["decision"] == "block"
    assert explicit_prefix["decision"] == "allow"


@pytest.mark.parametrize(
    ("domain", "target_resource"),
    [
        ("", "api.openai.com"),
        ("https://[invalid-host", "api.openai.com"),
        ("api.openai.com", ""),
        ("api.openai.com", "not a valid scoped resource"),
    ],
)
def test_purpose_scope_rejects_empty_or_malformed_domain_and_resource(
    domain: str,
    target_resource: str,
) -> None:
    result = evaluate_purpose_bound_permission(
        permission=_caller_permission("agent"),
        action_type="api_call",
        action_category="unknown",
        action_risk="medium",
        domain=domain,
        target_resource=target_resource,
        environment="prod",
    )
    assert result["decision"] == "block"


def test_caller_can_deactivate_but_not_activate_persisted_permission(test_env) -> None:
    owner, _ai_system_id, agent_id, _raw_token = _setup_runtime_authority(test_env)
    _persist_purpose_session(
        test_env,
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        agent_id=agent_id,
    )
    caller = _caller_permission(agent_id)
    caller["status"] = "inactive"

    with test_env["SessionLocal"]() as db:
        result = resolve_persisted_purpose_bound_permission(
            db,
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            agent_id=agent_id,
            caller_permission=caller,
        )

    assert result["valid"] is False
    assert result["reason"] == "caller_purpose_permission_inactive"


def test_persisted_agent_authority_requires_exact_explicit_binding(test_env) -> None:
    owner, _ai_system_id, agent_id, _raw_token = _setup_runtime_authority(test_env)
    with test_env["SessionLocal"]() as db:
        row = BusinessPurposeSession(
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            declared_purpose="Unbound agent authority",
            purpose_category="support",
            business_function="support",
            approved_scope={
                "scope": {"allowed_actions": ["api_call"]},
                "constraints": {},
                "context": {},
            },
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
            status="active",
        )
        db.add(row)
        db.commit()

        result = resolve_persisted_purpose_bound_permission(
            db,
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            agent_id=agent_id,
            caller_permission=None,
        )

    assert result["valid"] is False
    assert result["reason"] == "persisted_purpose_permission_agent_binding_required"
    assert result["permission"] is None


@pytest.mark.parametrize("authority_source", ["persisted", "caller"])
def test_agent_authority_rejects_explicit_non_agent_identity_type(test_env, authority_source: str) -> None:
    owner, _ai_system_id, agent_id, _raw_token = _setup_runtime_authority(test_env)
    persisted_scope = {
        "identity_id": agent_id,
        "identity_type": "user" if authority_source == "persisted" else "agent",
        "scope": {"allowed_actions": ["api_call"]},
        "constraints": {},
        "context": {},
    }
    with test_env["SessionLocal"]() as db:
        db.add(
            BusinessPurposeSession(
                tenant_id=owner["tenant_id"],
                user_id=owner["user_id"],
                declared_purpose="Identity type authority",
                purpose_category="support",
                business_function="support",
                approved_scope=persisted_scope,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
                status="active",
            )
        )
        db.commit()
        caller = None
        expected_reason = "persisted_purpose_permission_identity_type_invalid"
        if authority_source == "caller":
            caller = _caller_permission(agent_id)
            caller["identity_type"] = "user"
            expected_reason = "caller_purpose_permission_identity_type_invalid"
        result = resolve_persisted_purpose_bound_permission(
            db,
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            agent_id=agent_id,
            caller_permission=caller,
        )

    assert result["valid"] is False
    assert result["reason"] == expected_reason


@pytest.mark.parametrize(
    "approved_scope",
    [
        {"identity_id": "agent", "scope": "not-a-dict"},
        {"identity_id": "agent", "scope": {"allowed_actions": "tool.read"}},
        {"identity_id": "agent", "scope": {"allowed_actions": ["tool.read", 7]}},
        {"identity_id": "agent", "scope": {"allowed_actions": ["tool.read"]}, "constraints": []},
        {"identity_id": "agent", "scope": {"allowed_actions": ["tool.read"]}, "context": "bad"},
        {
            "identity_id": "agent",
            "agent_id": "different-agent",
            "scope": {"allowed_actions": ["tool.read"]},
        },
    ],
)
def test_malformed_persisted_authority_schema_fails_closed(test_env, approved_scope: dict) -> None:
    owner, _ai_system_id, agent_id, _raw_token = _setup_runtime_authority(test_env)
    approved_scope = {
        **approved_scope,
        "identity_id": agent_id if approved_scope.get("identity_id") == "agent" else approved_scope.get("identity_id"),
    }
    with test_env["SessionLocal"]() as db:
        db.add(
            BusinessPurposeSession(
                tenant_id=owner["tenant_id"],
                user_id=owner["user_id"],
                declared_purpose="Malformed authority",
                purpose_category="support",
                business_function="support",
                approved_scope=approved_scope,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
                status="active",
            )
        )
        db.commit()
        result = resolve_persisted_purpose_bound_permission(
            db,
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            agent_id=agent_id,
            caller_permission=None,
        )

    assert result["valid"] is False
    assert result["reason"] == "persisted_purpose_permission_schema_invalid"


@pytest.mark.parametrize(
    "mutation",
    [
        {"scope": "not-a-dict"},
        {"scope": {"blocked_actions": "tool.write"}},
        {"constraints": []},
        {"context": ["not", "a", "dict"]},
    ],
)
def test_malformed_caller_authority_schema_fails_closed(test_env, mutation: dict) -> None:
    owner, _ai_system_id, agent_id, _raw_token = _setup_runtime_authority(test_env)
    _persist_purpose_session(
        test_env,
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        agent_id=agent_id,
    )
    caller = _caller_permission(agent_id)
    caller.update(mutation)
    with test_env["SessionLocal"]() as db:
        result = resolve_persisted_purpose_bound_permission(
            db,
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            agent_id=agent_id,
            caller_permission=caller,
        )

    assert result["valid"] is False
    assert result["reason"] == "caller_purpose_permission_schema_invalid"


@pytest.mark.parametrize(
    "conflict",
    [
        {"tenant_id": "forged-tenant"},
        {"user_id": "forged-user"},
        {"initiating_user_id": "forged-user"},
        {"identity_id": "forged-agent"},
        {"agent_id": "forged-agent"},
        {"context": {"initiating_user_id": "forged-user"}},
        {"context": {"agent_id": "forged-agent"}},
        {"context": {"tenant_id": "forged-tenant"}},
    ],
)
def test_conflicting_caller_identity_assertions_fail_closed(test_env, conflict: dict) -> None:
    owner, _ai_system_id, agent_id, _raw_token = _setup_runtime_authority(test_env)
    _persist_purpose_session(
        test_env,
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        agent_id=agent_id,
    )
    caller = _caller_permission(agent_id)
    caller.update(conflict)
    with test_env["SessionLocal"]() as db:
        result = resolve_persisted_purpose_bound_permission(
            db,
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            agent_id=agent_id,
            caller_permission=caller,
        )

    assert result["valid"] is False
    assert result["reason"] == "caller_purpose_identity_conflict"


def _persist_mcp_authority(
    test_env,
    *,
    owner: dict[str, str],
    agent_id: str,
    action: str,
    tool: str | None = None,
    system: str = "crm.internal",
    require_human_confirmation: bool = False,
) -> None:
    scope = {
        "allowed_actions": [action],
        "allowed_domains": [system],
        "allowed_resources": [system],
        "allowed_environments": ["prod"],
    }
    if tool is not None:
        scope["allowed_tools"] = [tool]
    with test_env["SessionLocal"]() as db:
        db.add(
            BusinessPurposeSession(
                tenant_id=owner["tenant_id"],
                user_id=owner["user_id"],
                declared_purpose="Bound MCP execution",
                purpose_category="operations",
                business_function="operations",
                approved_scope={
                    "identity_id": agent_id,
                    "identity_type": "agent",
                    "purpose": {"name": "bound_mcp_execution"},
                    "scope": scope,
                    "constraints": {
                        "max_risk_level": "critical",
                        "require_human_confirmation": require_human_confirmation,
                    },
                    "context": {"connected_systems": [system], "max_chain_depth": 3},
                    "status": "active",
                    "mode": "block",
                },
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
                status="active",
            )
        )
        db.commit()


def _mcp_request(
    test_env,
    *,
    owner: dict[str, str],
    ai_system_id: str,
    agent_id: str,
    raw_token: str,
    action: str,
    resource: str,
    tool_name: str | None = None,
) -> dict:
    payload = {
        "request_id": f"mcp-server-intersection-{action}-{tool_name or 'none'}",
        "ai_system_id": ai_system_id,
        "actor_id": agent_id,
        "capability_token": raw_token,
        "action": action,
        "resource": resource,
        "chain_depth": 1,
        "session_id": "server-intersection-session",
        "initiating_user_id": owner["user_id"],
        "session_context": {"agent_id": agent_id, "initiating_user_id": owner["user_id"]},
    }
    if tool_name is not None:
        payload["tool_name"] = tool_name
    response = test_env["client"].post("/gateway/mcp/authorize", headers=_headers(owner), json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def test_mcp_purpose_cannot_expand_agent_action_scope(test_env) -> None:
    action = "custom.action"
    owner, ai_system_id, agent_id, raw_token = _setup_runtime_authority(
        test_env,
        agent_action_scope=["tool.read"],
        agent_systems=["crm.internal"],
        token_scopes=[action],
    )
    _persist_mcp_authority(test_env, owner=owner, agent_id=agent_id, action=action)

    body = _mcp_request(
        test_env,
        owner=owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        action=action,
        resource="crm.internal/customer",
    )

    assert body["decision"] == "block"


def test_mcp_server_action_scope_cannot_expand_persisted_purpose(test_env) -> None:
    requested_action = "custom.action"
    owner, ai_system_id, agent_id, raw_token = _setup_runtime_authority(
        test_env,
        agent_action_scope=[requested_action],
        agent_systems=["crm.internal"],
        token_scopes=[requested_action],
    )
    _persist_mcp_authority(
        test_env,
        owner=owner,
        agent_id=agent_id,
        action="different.action",
    )

    body = _mcp_request(
        test_env,
        owner=owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        action=requested_action,
        resource="crm.internal/customer",
    )

    assert body["decision"] == "block"


def test_mcp_purpose_cannot_expand_agent_tool_registry(test_env) -> None:
    action = "custom.action"
    owner, ai_system_id, agent_id, raw_token = _setup_runtime_authority(
        test_env,
        agent_action_scope=[action],
        agent_tools=["registered_tool"],
        agent_systems=["crm.internal"],
        token_scopes=[action],
    )
    _persist_mcp_authority(
        test_env,
        owner=owner,
        agent_id=agent_id,
        action=action,
        tool="forged_tool",
    )

    body = _mcp_request(
        test_env,
        owner=owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        action=action,
        resource="crm.internal/customer",
        tool_name="forged_tool",
    )

    assert body["decision"] == "block"


def test_mcp_purpose_cannot_expand_agent_connected_systems(test_env) -> None:
    action = "custom.action"
    owner, ai_system_id, agent_id, raw_token = _setup_runtime_authority(
        test_env,
        agent_action_scope=[action],
        agent_systems=["trusted.internal"],
        token_scopes=[action],
    )
    _persist_mcp_authority(
        test_env,
        owner=owner,
        agent_id=agent_id,
        action=action,
        system="evil.internal",
    )

    body = _mcp_request(
        test_env,
        owner=owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        action=action,
        resource="evil.internal/customer",
    )

    assert body["decision"] == "block"


def test_mcp_requires_persisted_confirmation_artifact(test_env) -> None:
    action = "custom.action"
    owner, ai_system_id, agent_id, raw_token = _setup_runtime_authority(
        test_env,
        agent_action_scope=[action],
        agent_systems=["crm.internal"],
        token_scopes=[action],
    )
    _persist_mcp_authority(
        test_env,
        owner=owner,
        agent_id=agent_id,
        action=action,
        require_human_confirmation=True,
    )
    body = _mcp_request(
        test_env,
        owner=owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        action=action,
        resource="crm.internal/customer",
    )
    assert body["decision"] in {"block", "hold_for_approval"}
    assert all(
        guardian.get("guardian_id") != "scoped_policy"
        for guardian in body.get("guardian_results", [])
    )


def test_mcp_persisted_confirmation_cannot_be_downgraded_by_scoped_allow(test_env, monkeypatch) -> None:
    action = "custom.action"
    owner, ai_system_id, agent_id, raw_token = _setup_runtime_authority(
        test_env,
        agent_action_scope=[action],
        agent_systems=["crm.internal"],
        token_scopes=[action],
    )
    _persist_mcp_authority(
        test_env,
        owner=owner,
        agent_id=agent_id,
        action=action,
        require_human_confirmation=True,
    )

    class ScopedAllow:
        matched = True
        decision = "allow"
        reason_code = "scoped_allow"
        explanation = "Scoped policy allows this action."
        policy_version_id = "test-policy"
        rule_id = "test-scoped-allow"
        matched_selectors = ["operation"]

        def to_dict(self) -> dict:
            return {"matched": True, "decision": "allow"}

    monkeypatch.setattr(
        "app.services.gateway_service.resolve_scoped_policy_decision",
        lambda *args, **kwargs: ScopedAllow(),
    )
    body = _mcp_request(
        test_env,
        owner=owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        action=action,
        resource="crm.internal/customer",
    )
    assert body["decision"] in {"block", "hold_for_approval"}
    assert all(
        guardian.get("guardian_id") != "scoped_policy"
        for guardian in body.get("guardian_results", [])
    )
