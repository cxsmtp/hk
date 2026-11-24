from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.core.config import settings
from app.core.security import token_hash
from app.db.models.activity_audit import AISession
from app.db.models.ai_iam import AgentDelegation, AgentIdentity, CapabilityToken
from app.db.models.ai_system import AISystem
from app.db.models.enforcement import EnforcementEvent
from app.db.models.policy import BusinessPurposeSession, ToolFingerprint
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.user import UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services.mcp_session_service import validate_persisted_mcp_session


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path, monkeypatch):
    db_file = tmp_path / "mcp-persisted-sessions.sqlite3"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    testing_session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(settings, "mcp_persisted_sessions_required", True, raising=False)

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


def _headers(owner: dict[str, str]) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {owner['access_token']}",
        "X-Tenant-ID": owner["tenant_id"],
    }


def _setup_authority(test_env) -> tuple[dict[str, str], str, str, str]:
    client: TestClient = test_env["client"]
    registered = client.post(
        "/auth/register",
        json={
            "email": "mcp-session-owner@example.com",
            "password": PASSWORD,
            "full_name": "MCP Session Owner",
        },
    )
    assert registered.status_code == 200, registered.text
    body = registered.json()
    owner = {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
        "user_id": body["user"]["id"],
    }
    headers = _headers(owner)
    system_response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "MCP Session System", "description": "session test", "risk_tier": "MEDIUM"},
    )
    assert system_response.status_code == 200, system_response.text
    ai_system_id = system_response.json()["id"]
    agent_response = client.post(
        "/ai-iam/agents",
        headers=headers,
        json={
            "name": "MCP Session Agent",
            "description": "session test",
            "max_chain_depth": 3,
            "capability_inheritance": False,
            "action_scope": ["tool.run"],
            "tool_registry": ["openai_api"],
            "external_system_access": ["api.openai.com"],
        },
    )
    assert agent_response.status_code == 200, agent_response.text
    agent_id = agent_response.json()["id"]
    raw_token = "mcp-persisted-session-token"
    with test_env["SessionLocal"]() as db:
        ai_system = db.get(AISystem, ai_system_id)
        assert ai_system is not None
        ai_system.status = "active"
        ai_system.metadata_json = {
            **dict(ai_system.metadata_json or {}),
            "governance_state": "APPROVED",
            "lifecycle_state": "ACTIVE",
        }
        agent = db.get(AgentIdentity, agent_id)
        assert agent is not None
        agent.owner_attested_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        agent.owner_attestation_expiry = datetime.now(timezone.utc) + timedelta(hours=2)
        db.add(
            CapabilityToken(
                tenant_id=owner["tenant_id"],
                agent_identity_id=agent_id,
                ai_system_id=ai_system_id,
                token_hash=token_hash(raw_token),
                scopes=["tool.run"],
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                chain_depth=3,
                issued_by_user_id=owner["user_id"],
            )
        )
        db.add(
            BusinessPurposeSession(
                tenant_id=owner["tenant_id"],
                user_id=owner["user_id"],
                declared_purpose="Support triage",
                purpose_category="customer_support",
                business_function="support",
                approved_scope={
                    "identity_id": agent_id,
                    "identity_type": "agent",
                    "purpose": {"name": "support_triage"},
                    "scope": {
                        "allowed_actions": ["tool.run"],
                        "allowed_tools": ["openai_api"],
                        "allowed_domains": ["api.openai.com"],
                        "allowed_resources": ["api.openai.com"],
                        "allowed_environments": ["prod"],
                        "allowed_data_scopes": ["internal"],
                    },
                    "constraints": {"max_risk_level": "medium"},
                    "context": {"max_chain_depth": 3},
                    "mode": "block",
                },
                status="active",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
            )
        )
        db.commit()
    return owner, ai_system_id, agent_id, raw_token


def test_open_issues_random_persisted_session_bound_to_authenticated_authority(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)

    first = test_env["client"].post(
        "/gateway/mcp/sessions/open",
        headers=_headers(owner),
        json={
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": raw_token,
            "expires_minutes": 15,
            "session_context": {
                "max_chain_depth": 2,
                "connected_systems": ["api.openai.com"],
                "allowed_data_scope": ["internal"],
            },
        },
    )
    assert first.status_code == 201, first.text
    second = test_env["client"].post(
        "/gateway/mcp/sessions/open",
        headers=_headers(owner),
        json={
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": raw_token,
            "expires_minutes": 15,
        },
    )
    assert second.status_code == 201, second.text
    first_body = first.json()
    second_body = second.json()
    assert first_body["session_id"].startswith("mcp_sess_")
    assert first_body["session_id"] != second_body["session_id"]
    assert first_body["status"] == "open"
    assert first_body["tenant_id"] == owner["tenant_id"]
    assert first_body["user_id"] == owner["user_id"]
    assert first_body["ai_system_id"] == ai_system_id
    assert first_body["agent_id"] == agent_id
    assert first_body["issued_at"]
    assert first_body["expires_at"]
    with test_env["SessionLocal"]() as db:
        persisted = db.get(AISession, first_body["session_id"])
        assert persisted is not None
        persisted_metadata = dict(persisted.metadata_json or {})
    assert raw_token not in str(persisted_metadata)
    assert "capability_token_id" in persisted_metadata


def test_owner_can_create_persisted_agent_purpose_session_for_mcp(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)

    purpose_response = test_env["client"].post(
        "/ai-iam/purpose-sessions",
        headers=_headers(owner),
        json={
            "declared_purpose": "Governed read-only GitHub pull request review",
            "purpose_category": "engineering_security_review",
            "business_function": "engineering",
            "expires_minutes": 30,
            "approved_scope": {
                "identity_id": agent_id,
                "identity_type": "agent",
                "purpose": {"name": "github_pull_request_review"},
                "scope": {
                    "allowed_actions": ["file_read"],
                    "allowed_tools": ["list_pull_requests"],
                    "allowed_domains": ["github.com"],
                    "allowed_resources": ["github.com/github/github-mcp-server"],
                    "allowed_environments": ["production"],
                    "allowed_data_scopes": ["public"],
                },
                "constraints": {"max_risk_level": "low"},
                "context": {"max_chain_depth": 1},
                "mode": "block",
            },
        },
    )

    assert purpose_response.status_code == 201, purpose_response.text
    body = purpose_response.json()
    assert body["tenant_id"] == owner["tenant_id"]
    assert body["user_id"] == owner["user_id"]
    assert body["status"] == "active"
    assert body["approved_scope"]["identity_id"] == agent_id
    assert body["approved_scope"]["scope"]["allowed_tools"] == ["list_pull_requests"]

    with test_env["SessionLocal"]() as db:
        row = db.get(BusinessPurposeSession, body["id"])
        assert row is not None
        assert row.tenant_id == owner["tenant_id"]
        assert row.user_id == owner["user_id"]
        assert row.approved_scope["identity_id"] == agent_id


def test_viewer_cannot_create_persisted_agent_purpose_session(test_env) -> None:
    owner, _, agent_id, _ = _setup_authority(test_env)
    client: TestClient = test_env["client"]
    registered = client.post(
        "/auth/register",
        json={
            "email": "mcp-session-viewer@example.com",
            "password": PASSWORD,
            "full_name": "MCP Session Viewer",
        },
    )
    assert registered.status_code == 200, registered.text
    viewer = {
        "access_token": registered.json()["access_token"],
        "tenant_id": owner["tenant_id"],
    }

    response = client.post(
        "/ai-iam/purpose-sessions",
        headers=_headers(viewer),
        json={
            "declared_purpose": "Unauthorized",
            "purpose_category": "engineering",
            "business_function": "engineering",
            "expires_minutes": 30,
            "approved_scope": {
                "identity_id": agent_id,
                "identity_type": "agent",
                "scope": {"allowed_actions": ["file_read"]},
            },
        },
    )

    assert response.status_code in {401, 403}


def _open_session(
    test_env,
    owner: dict[str, str],
    *,
    ai_system_id: str,
    agent_id: str,
    raw_token: str,
    session_context: dict | None = None,
) -> dict:
    response = test_env["client"].post(
        "/gateway/mcp/sessions/open",
        headers=_headers(owner),
        json={
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": raw_token,
            "expires_minutes": 15,
            "session_context": dict(session_context or {}),
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_open_rejects_caller_supplied_session_identifier(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    response = test_env["client"].post(
        "/gateway/mcp/sessions/open",
        headers=_headers(owner),
        json={
            "session_id": "caller-chosen-session",
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": raw_token,
        },
    )
    assert response.status_code == 422, response.text


def test_open_rejects_agent_with_expired_owner_attestation(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    with test_env["SessionLocal"]() as db:
        agent = db.get(AgentIdentity, agent_id)
        assert agent is not None
        agent.owner_attestation_expiry = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    response = test_env["client"].post(
        "/gateway/mcp/sessions/open",
        headers=_headers(owner),
        json={
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": raw_token,
        },
    )
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["reason_code"] == "mcp_session_owner_attestation_expired"


def test_open_succeeds_immediately_after_server_attestation_refresh(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    with test_env["SessionLocal"]() as db:
        agent = db.get(AgentIdentity, agent_id)
        assert agent is not None
        agent.owner_attested_at = None
        agent.owner_attestation_expiry = None
        db.commit()

    refreshed = test_env["client"].post(
        f"/ai-iam/agents/{agent_id}/owner-attestation/refresh",
        headers=_headers(owner),
        json={"expires_minutes": 35},
    )

    assert refreshed.status_code == 200, refreshed.text
    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
    )
    assert opened["status"] == "open"


def test_open_absolute_expiry_is_capped_by_owner_attestation(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    attestation_expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
    with test_env["SessionLocal"]() as db:
        agent = db.get(AgentIdentity, agent_id)
        assert agent is not None
        agent.owner_attestation_expiry = attestation_expiry
        db.commit()
    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
    )
    advertised_expiry = datetime.fromisoformat(opened["expires_at"].replace("Z", "+00:00"))
    assert abs((advertised_expiry - attestation_expiry).total_seconds()) < 0.001


@pytest.mark.parametrize(
    ("governance_state", "lifecycle_state", "row_status", "expected_reason"),
    [
        ("DRAFT", "ACTIVE", "active", "governance_state_not_approved"),
        ("REVIEW", "ACTIVE", "active", "governance_state_not_approved"),
        ("REJECTED", "ACTIVE", "active", "governance_state_not_approved"),
        ("APPROVED", "INACTIVE", "inactive", "lifecycle_state_not_active"),
        ("APPROVED", "ACTIVE", "inactive", "lifecycle_state_not_active"),
    ],
)
def test_open_requires_canonical_approved_active_governance(
    test_env,
    governance_state: str,
    lifecycle_state: str,
    row_status: str,
    expected_reason: str,
) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    with test_env["SessionLocal"]() as db:
        ai_system = db.get(AISystem, ai_system_id)
        assert ai_system is not None
        ai_system.status = row_status
        ai_system.metadata_json = {
            **dict(ai_system.metadata_json or {}),
            "governance_state": governance_state,
            "lifecycle_state": lifecycle_state,
        }
        db.commit()
    response = test_env["client"].post(
        "/gateway/mcp/sessions/open",
        headers=_headers(owner),
        json={
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": raw_token,
        },
    )
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["reason_code"] == expected_reason
    with test_env["SessionLocal"]() as db:
        assert db.query(AISession).filter(AISession.tenant_id == owner["tenant_id"]).count() == 0


@pytest.mark.parametrize(
    ("attested_at", "expiry", "expected_reason"),
    [
        (None, None, "mcp_session_owner_attestation_required"),
        ("future", "fresh", "mcp_session_owner_attestation_invalid"),
    ],
)
def test_open_requires_present_valid_owner_attestation(
    test_env,
    attested_at: str | None,
    expiry: str | None,
    expected_reason: str,
) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    now = datetime.now(timezone.utc)
    with test_env["SessionLocal"]() as db:
        agent = db.get(AgentIdentity, agent_id)
        assert agent is not None
        agent.owner_attested_at = None if attested_at is None else now + timedelta(minutes=5)
        agent.owner_attestation_expiry = None if expiry is None else now + timedelta(hours=1)
        db.commit()
    response = test_env["client"].post(
        "/gateway/mcp/sessions/open",
        headers=_headers(owner),
        json={
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": raw_token,
        },
    )
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["reason_code"] == expected_reason


def test_open_requires_valid_persisted_purpose_authority(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    with test_env["SessionLocal"]() as db:
        db.query(BusinessPurposeSession).filter(
            BusinessPurposeSession.tenant_id == owner["tenant_id"]
        ).delete(synchronize_session=False)
        db.commit()
    response = test_env["client"].post(
        "/gateway/mcp/sessions/open",
        headers=_headers(owner),
        json={
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": raw_token,
        },
    )
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["reason_code"] == "mcp_session_persisted_purpose_required"


@pytest.mark.parametrize(
    "caller_context",
    [
        {"max_chain_depth": 4},
        {"connected_systems": ["evil.example"]},
        {"allowed_data_scope": ["secret"]},
        {"allowed_actions": ["admin.delete"]},
        {"allowed_tools": ["shell"]},
    ],
)
def test_open_persists_server_bounds_and_use_cannot_add_omitted_authority(
    test_env,
    caller_context: dict,
) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_context={},
    )
    assert opened["context"] == {
        "max_chain_depth": 3,
        "connected_systems": ["api.openai.com"],
        "allowed_resources": ["api.openai.com"],
        "allowed_data_scope": ["internal"],
        "allowed_environments": ["prod"],
        "allowed_actions": ["tool.run"],
        "allowed_tools": ["openai_api"],
    }
    response = _authorize(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_id=opened["session_id"],
        session_context=caller_context,
    )
    assert response.status_code == 200, response.text
    assert response.json()["session"]["valid"] is False, (caller_context, response.text)
    assert response.json()["session"]["reason"] == "agent_session_context_widening"


@pytest.mark.parametrize(
    ("empty_bound", "caller_context"),
    [
        ("connected_systems", {"connected_systems": ["api.openai.com"]}),
        ("allowed_data_scope", {"allowed_data_scope": ["internal"]}),
        ("allowed_data_scope", {"data_classification": "internal"}),
        ("allowed_actions", {"allowed_actions": ["tool.run"]}),
        ("allowed_tools", {"allowed_tools": ["openai_api"]}),
    ],
)
def test_empty_server_bound_is_explicit_zero_authority_at_open_and_use(
    test_env,
    empty_bound: str,
    caller_context: dict,
) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    with test_env["SessionLocal"]() as db:
        agent = db.get(AgentIdentity, agent_id)
        token = db.scalar(
            select(CapabilityToken).where(
                CapabilityToken.tenant_id == owner["tenant_id"],
                CapabilityToken.token_hash == token_hash(raw_token),
            )
        )
        purpose = db.scalar(
            select(BusinessPurposeSession).where(
                BusinessPurposeSession.tenant_id == owner["tenant_id"],
                BusinessPurposeSession.user_id == owner["user_id"],
            )
        )
        assert agent is not None
        assert token is not None
        assert purpose is not None
        approved_scope = dict(purpose.approved_scope or {})
        scope = dict(approved_scope.get("scope") or {})
        if empty_bound == "connected_systems":
            agent.external_system_access = []
        elif empty_bound == "allowed_data_scope":
            scope.pop("allowed_data_scopes", None)
            scope.pop("allowed_data_scope", None)
        elif empty_bound == "allowed_actions":
            token.scopes = ["different.action"]
        else:
            agent.tool_registry = []
        approved_scope["scope"] = scope
        purpose.approved_scope = approved_scope
        db.commit()

    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_context={},
    )
    assert opened["context"][empty_bound] == []

    rejected_open = test_env["client"].post(
        "/gateway/mcp/sessions/open",
        headers=_headers(owner),
        json={
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": raw_token,
            "session_context": caller_context,
        },
    )
    assert rejected_open.status_code == 403, rejected_open.text
    assert rejected_open.json()["detail"]["reason_code"] == "mcp_session_context_outside_authority"

    response = _authorize(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_id=opened["session_id"],
        session_context=caller_context,
    )
    assert response.status_code == 200, response.text
    assert response.json()["session"]["valid"] is False
    assert response.json()["session"]["reason"] == "agent_session_context_widening"


def test_explicit_server_wildcard_allows_caller_to_narrow_to_concrete_values(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    with test_env["SessionLocal"]() as db:
        agent = db.get(AgentIdentity, agent_id)
        token = db.scalar(
            select(CapabilityToken).where(CapabilityToken.token_hash == token_hash(raw_token))
        )
        purpose = db.scalar(
            select(BusinessPurposeSession).where(
                BusinessPurposeSession.tenant_id == owner["tenant_id"],
                BusinessPurposeSession.user_id == owner["user_id"],
            )
        )
        assert agent is not None
        assert token is not None
        assert purpose is not None
        agent.external_system_access = ["*"]
        agent.action_scope = ["*"]
        agent.tool_registry = ["*"]
        token.scopes = ["*"]
        approved_scope = dict(purpose.approved_scope or {})
        scope = dict(approved_scope.get("scope") or {})
        scope.update(
            {
                "allowed_actions": ["*"],
                "allowed_tools": ["*"],
                "allowed_domains": ["*"],
                "allowed_resources": ["*"],
                "allowed_data_scopes": ["*"],
            }
        )
        approved_scope["scope"] = scope
        purpose.approved_scope = approved_scope
        db.commit()
    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
    )
    response = _authorize(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_id=opened["session_id"],
        session_context={
            "connected_systems": ["api.openai.com"],
            "allowed_data_scope": ["internal"],
            "allowed_actions": ["tool.run"],
            "allowed_tools": ["openai_api"],
            "data_classification": "internal",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["session"]["valid"] is True


@pytest.mark.parametrize(
    "bound_key",
    ["connected_systems", "allowed_data_scope", "allowed_actions", "allowed_tools"],
)
def test_open_explicit_empty_list_narrows_one_bound_to_deny_all(test_env, bound_key: str) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_context={bound_key: []},
    )
    assert opened["context"][bound_key] == []
    retained = {
        "connected_systems": ["api.openai.com"],
        "allowed_data_scope": ["internal"],
        "allowed_actions": ["tool.run"],
        "allowed_tools": ["openai_api"],
    }
    for key, expected in retained.items():
        if key != bound_key:
            assert opened["context"][key] == expected


@pytest.mark.parametrize(
    "bound_key",
    ["connected_systems", "allowed_data_scope", "allowed_actions", "allowed_tools"],
)
def test_open_rejects_non_list_bound_narrowing(test_env, bound_key: str) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    response = test_env["client"].post(
        "/gateway/mcp/sessions/open",
        headers=_headers(owner),
        json={
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": raw_token,
            "session_context": {bound_key: "not-a-list"},
        },
    )
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["reason_code"] == "mcp_session_context_invalid"


@pytest.mark.parametrize(
    ("session_context", "authorize_overrides", "expected_reason"),
    [
        ({"allowed_actions": []}, {}, "agent_session_action_scope_denied"),
        ({"allowed_actions": ["tool.read"]}, {}, "agent_session_action_scope_denied"),
        ({"allowed_tools": []}, {}, "agent_session_tool_scope_denied"),
        ({"allowed_tools": ["jira"]}, {}, "agent_session_tool_scope_denied"),
        ({"connected_systems": []}, {}, "agent_session_destination_scope_denied"),
        (
            {"connected_systems": ["api.openai.com"]},
            {"resource": "evil.example"},
            "agent_session_destination_scope_denied",
        ),
        ({"allowed_data_scope": []}, {}, "agent_session_data_scope_denied"),
        ({"allowed_data_scope": ["public"]}, {}, "agent_session_data_scope_denied"),
        ({"max_chain_depth": 1}, {"chain_depth": 2}, "agent_session_chain_depth_exceeded"),
    ],
)
def test_authorize_directly_enforces_persisted_session_floor_when_caller_omits_context(
    test_env,
    session_context: dict,
    authorize_overrides: dict,
    expected_reason: str,
) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    parent_agent_id = None
    chain_id = None
    parent_action_id = None
    if expected_reason == "agent_session_chain_depth_exceeded":
        parent_agent_id, chain_id, parent_action_id = _persist_parent_delegation(
            test_env,
            tenant_id=owner["tenant_id"],
            child_agent_id=agent_id,
            child_raw_token=raw_token,
            ai_system_id=ai_system_id,
        )
    with test_env["SessionLocal"]() as db:
        agent = db.get(AgentIdentity, agent_id)
        token = db.scalar(select(CapabilityToken).where(CapabilityToken.token_hash == token_hash(raw_token)))
        purpose = db.scalar(
            select(BusinessPurposeSession).where(
                BusinessPurposeSession.tenant_id == owner["tenant_id"],
                BusinessPurposeSession.user_id == owner["user_id"],
            )
        )
        assert agent is not None
        assert token is not None
        assert purpose is not None
        agent.action_scope = ["tool.run", "tool.read"]
        agent.tool_registry = ["openai_api", "jira"]
        agent.external_system_access = ["api.openai.com", "evil.example"]
        token.scopes = ["tool.run", "tool.read"]
        approved_scope = dict(purpose.approved_scope or {})
        scope = dict(approved_scope.get("scope") or {})
        scope.update(
            {
                "allowed_actions": ["tool.run", "tool.read"],
                "allowed_tools": ["openai_api", "jira"],
                "allowed_domains": ["api.openai.com", "evil.example"],
                "allowed_resources": ["api.openai.com", "evil.example"],
                "allowed_data_scopes": ["internal", "public"],
            }
        )
        approved_scope["scope"] = scope
        purpose.approved_scope = approved_scope
        db.commit()
    open_context = dict(session_context)
    if "allowed_data_scope" not in open_context:
        open_context["data_classification"] = "internal"
    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_context=open_context,
    )
    response = _authorize(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_id=opened["session_id"],
        session_context=None,
        chain_id=chain_id,
        parent_action_id=parent_action_id,
        parent_agent_id=parent_agent_id,
        **authorize_overrides,
    )
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "block"
    floor = response.json()["session"]["bounds_enforcement"]
    assert floor["valid"] is False
    assert floor["reason"] == expected_reason


def test_authorize_allows_explicit_public_production_context_within_persisted_session_floor(
    test_env,
) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    with test_env["SessionLocal"]() as db:
        agent = db.get(AgentIdentity, agent_id)
        token = db.scalar(select(CapabilityToken).where(CapabilityToken.token_hash == token_hash(raw_token)))
        purpose = db.scalar(
            select(BusinessPurposeSession).where(
                BusinessPurposeSession.tenant_id == owner["tenant_id"],
                BusinessPurposeSession.user_id == owner["user_id"],
            )
        )
        assert agent is not None
        assert token is not None
        assert purpose is not None
        agent.action_scope = ["file_read"]
        agent.tool_registry = ["list_pull_requests"]
        agent.external_system_access = ["github.com", "github.com/github/github-mcp-server"]
        token.scopes = ["file_read"]
        approved_scope = dict(purpose.approved_scope or {})
        scope = dict(approved_scope.get("scope") or {})
        scope.update(
            {
                "allowed_actions": ["file_read"],
                "allowed_tools": ["list_pull_requests"],
                "allowed_domains": ["github.com"],
                "allowed_resources": ["github.com/github/github-mcp-server"],
                "allowed_data_scopes": ["public"],
                "allowed_environments": ["production"],
            }
        )
        approved_scope["scope"] = scope
        purpose.approved_scope = approved_scope
        db.commit()

    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_context={
            "allowed_actions": ["file_read"],
            "allowed_tools": ["list_pull_requests"],
            "allowed_resources": ["github.com/github/github-mcp-server"],
            "allowed_data_scope": ["public"],
            "connected_systems": ["github.com"],
            "data_classification": "public",
            "environment": "production",
        },
    )
    response = _authorize(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_id=opened["session_id"],
        session_context={
            "data_classification": "public",
            "environment": "production",
        },
        action="file_read",
        resource="github.com/github/github-mcp-server",
        tool_name="list_pull_requests",
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["session"]["bounds_enforcement"]["valid"] is True
    assert body["session"]["context"]["data_classification"] == "public"
    assert body["pre_action_governance_check"]["surface"]["environment"] == "production"
    assert "environment:prod" not in body["pre_action_governance_check"]["purpose"].get("violations", [])


@pytest.mark.parametrize(
    ("purpose_change", "expected_reason"),
    [
        ("reduced", "agent_session_authority_changed"),
        ("inactive", "agent_session_purpose_mismatch"),
        ("expired", "agent_session_purpose_mismatch"),
    ],
)
def test_existing_session_invalidates_when_purpose_authority_changes(
    test_env,
    purpose_change: str,
    expected_reason: str,
) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
    )
    with test_env["SessionLocal"]() as db:
        purpose = db.scalar(
            select(BusinessPurposeSession).where(
                BusinessPurposeSession.tenant_id == owner["tenant_id"],
                BusinessPurposeSession.user_id == owner["user_id"],
            )
        )
        assert purpose is not None
        if purpose_change == "reduced":
            approved_scope = dict(purpose.approved_scope or {})
            scope = dict(approved_scope.get("scope") or {})
            scope["allowed_actions"] = ["different.action"]
            approved_scope["scope"] = scope
            purpose.approved_scope = approved_scope
        elif purpose_change == "inactive":
            purpose.status = "inactive"
        else:
            purpose.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    response = _authorize(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_id=opened["session_id"],
    )
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "block"
    assert response.json()["session"]["valid"] is False
    assert response.json()["session"]["reason"] == expected_reason


def test_authenticated_owner_can_read_close_and_revoke_sessions(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
    )

    status = test_env["client"].get(
        f"/gateway/mcp/sessions/{opened['session_id']}",
        headers=_headers(owner),
    )
    assert status.status_code == 200, status.text
    assert status.json()["status"] == "open"

    closed = test_env["client"].post(
        f"/gateway/mcp/sessions/{opened['session_id']}/close",
        headers=_headers(owner),
    )
    assert closed.status_code == 200, closed.text
    assert closed.json()["status"] == "closed"
    assert closed.json()["closed_at"]

    second = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
    )
    revoked = test_env["client"].post(
        f"/gateway/mcp/sessions/{second['session_id']}/revoke",
        headers=_headers(owner),
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"
    assert revoked.json()["revoked_at"]


def test_terminal_transition_retry_is_idempotent_and_conflict_fails_closed(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
    )
    path = f"/gateway/mcp/sessions/{opened['session_id']}"
    first_close = test_env["client"].post(f"{path}/close", headers=_headers(owner))
    assert first_close.status_code == 200, first_close.text
    retry_close = test_env["client"].post(f"{path}/close", headers=_headers(owner))
    assert retry_close.status_code == 200, retry_close.text
    assert retry_close.json()["closed_at"] == first_close.json()["closed_at"]

    conflicting_revoke = test_env["client"].post(f"{path}/revoke", headers=_headers(owner))
    assert conflicting_revoke.status_code == 409, conflicting_revoke.text
    assert conflicting_revoke.json()["detail"]["reason_code"] == "mcp_session_transition_conflict"


def _authorize(
    test_env,
    owner: dict[str, str],
    *,
    ai_system_id: str,
    agent_id: str,
    raw_token: str,
    session_id: str | None,
    initiating_user_id: str | None = None,
    session_context: dict | None = None,
    action: str = "tool.run",
    resource: str = "api.openai.com",
    tool_name: str = "openai_api",
    chain_depth: int = 1,
    chain_id: str | None = None,
    parent_action_id: str | None = None,
    parent_agent_id: str | None = None,
    tool_fingerprint_id: str | None = None,
    request_id: str | None = None,
):
    payload = {
        "ai_system_id": ai_system_id,
        "actor_id": agent_id,
        "capability_token": raw_token,
        "action": action,
        "resource": resource,
        "tool_name": tool_name,
        "chain_depth": chain_depth,
    }
    if session_id is not None:
        payload["session_id"] = session_id
    if chain_id is not None:
        payload["chain_id"] = chain_id
    if parent_action_id is not None:
        payload["parent_action_id"] = parent_action_id
    if parent_agent_id is not None:
        payload["parent_agent_id"] = parent_agent_id
    if initiating_user_id is not None:
        payload["initiating_user_id"] = initiating_user_id
    if session_context is not None:
        payload["session_context"] = session_context
    if tool_fingerprint_id is not None:
        payload["tool_usage_meta"] = {
            "mcp_server_id": resource,
            "tool_version": "unknown",
            "tool_fingerprint_id": tool_fingerprint_id,
            "parameters": {},
        }
    if request_id is not None:
        payload["request_id"] = request_id
    return test_env["client"].post(
        "/gateway/mcp/authorize",
        headers=_headers(owner),
        json=payload,
    )


def test_authorize_preserves_long_endpoint_request_correlation_with_bounded_event_id(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
    )
    source_request_id = "endpoint-" + ("a" * 32)

    response = _authorize(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_id=opened["session_id"],
        request_id=source_request_id,
    )

    assert response.status_code == 200, response.text
    with test_env["SessionLocal"]() as db:
        event = db.scalar(
            select(EnforcementEvent).where(
                EnforcementEvent.tenant_id == owner["tenant_id"]
            )
        )
    assert event is not None
    assert event.request_id != source_request_id
    assert len(event.request_id) == 36
    assert event.final_actions["mcp"]["source_request_id"] == source_request_id
    assert event.final_actions["mcp"]["enforcement_event_request_id"] == event.request_id


def test_mcp_rejects_root_token_bound_to_another_ai_system(test_env) -> None:
    owner, bound_system_id, agent_id, raw_token = _setup_authority(test_env)
    opened = _open_session(
        test_env,
        owner,
        ai_system_id=bound_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
    )
    other = test_env["client"].post(
        "/ai-systems",
        headers=_headers(owner),
        json={"name": "Other MCP System", "description": "cross-system", "risk_tier": "LOW"},
    )
    assert other.status_code == 200, other.text
    other_system_id = other.json()["id"]
    with test_env["SessionLocal"]() as db:
        ai_system = db.get(AISystem, other_system_id)
        assert ai_system is not None
        ai_system.status = "active"
        ai_system.metadata_json = {"governance_state": "APPROVED", "lifecycle_state": "ACTIVE"}
        db.commit()

    response = _authorize(
        test_env,
        owner,
        ai_system_id=other_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_id=opened["session_id"],
    )

    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "block"
    assert response.json()["reason"] == "delegation_chain_token_system_mismatch"


def _persist_parent_delegation(
    test_env,
    *,
    tenant_id: str,
    child_agent_id: str,
    child_raw_token: str,
    ai_system_id: str,
) -> tuple[str, str, str]:
    with test_env["SessionLocal"]() as db:
        child_agent = db.get(AgentIdentity, child_agent_id)
        child_token = db.scalar(
            select(CapabilityToken).where(
                CapabilityToken.tenant_id == tenant_id,
                CapabilityToken.token_hash == token_hash(child_raw_token),
            )
        )
        assert child_agent is not None
        assert child_token is not None
        child_agent.capability_inheritance = True
        parent = AgentIdentity(
            tenant_id=tenant_id,
            name="MCP Session Parent Agent",
            max_chain_depth=3,
            capability_inheritance=True,
            action_scope=["tool.run", "tool.read"],
            tool_registry=["openai_api", "jira"],
            external_system_access=["api.openai.com", "evil.example"],
        )
        db.add(parent)
        db.flush()
        parent_token = CapabilityToken(
            tenant_id=tenant_id,
            agent_identity_id=parent.id,
            ai_system_id=ai_system_id,
            token_hash=token_hash("mcp-persisted-session-parent-token"),
            scopes=["tool.run", "tool.read"],
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
                action_scope=["tool.run", "tool.read"],
                chain_depth=2,
                status="active",
            )
        db.add(edge)
        db.flush()
        chain_id = "mcp-session-depth-chain"
        parent_action_id = "mcp-session-depth-parent-action"
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
        return parent.id, chain_id, parent_action_id


def test_mcp_public_api_uses_emitted_parent_runtime_event_for_delegation(test_env) -> None:
    owner, ai_system_id, root_agent_id, root_token = _setup_authority(test_env)
    client: TestClient = test_env["client"]
    with test_env["SessionLocal"]() as db:
        root_agent = db.get(AgentIdentity, root_agent_id)
        assert root_agent is not None
        root_agent.capability_inheritance = True
        root_purpose = db.scalar(
            select(BusinessPurposeSession).where(
                BusinessPurposeSession.tenant_id == owner["tenant_id"],
                BusinessPurposeSession.user_id == owner["user_id"],
            )
        )
        assert root_purpose is not None
        approved_scope = dict(root_purpose.approved_scope or {})
        scope = dict(approved_scope.get("scope") or {})
        scope["allowed_data_scopes"] = ["internal", "unknown"]
        approved_scope["scope"] = scope
        root_purpose.approved_scope = approved_scope
        approved_tool_fingerprint = ToolFingerprint(
            tenant_id=owner["tenant_id"],
            mcp_server_id="api.openai.com",
            tool_name="openai_api",
            tool_version="unknown",
            manifest_hash="mcp-emitted-manifest",
            description_hash="mcp-emitted-description",
            schema_hash="mcp-emitted-schema",
            examples_hash="mcp-emitted-examples",
            approved_hash="mcp-emitted-manifest",
            trust_status="approved",
            approved_by=owner["user_id"],
            approved_at=datetime.now(timezone.utc),
        )
        db.add(approved_tool_fingerprint)
        db.commit()
        db.refresh(approved_tool_fingerprint)
        approved_tool_fingerprint_id = approved_tool_fingerprint.id
    root_session = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=root_agent_id,
        raw_token=root_token,
        session_context={
            "max_chain_depth": 3,
            "connected_systems": ["api.openai.com"],
            "allowed_data_scope": ["internal", "unknown"],
        },
    )
    chain_id = "mcp-emitted-authority-chain"
    root_authorize = _authorize(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=root_agent_id,
        raw_token=root_token,
        session_id=root_session["session_id"],
        chain_id=chain_id,
        tool_fingerprint_id=approved_tool_fingerprint_id,
    )
    assert root_authorize.status_code == 200, root_authorize.text
    assert root_authorize.json()["decision"] == "allow", root_authorize.text
    root_action_id = root_authorize.json()["runtime_event_id"]
    assert root_action_id
    with test_env["SessionLocal"]() as db:
        root_event = db.get(RuntimeEvent, root_action_id)
        assert root_event is not None
        assert "delegation_edge_id" in root_event.metadata_json
        assert root_event.metadata_json["delegation_edge_id"] is None

    child_created = client.post(
        "/ai-iam/agents",
        headers=_headers(owner),
        json={
            "name": "MCP Emitted Child",
            "max_chain_depth": 3,
            "capability_inheritance": True,
            "action_scope": ["tool.run"],
            "tool_registry": ["openai_api"],
            "external_system_access": ["api.openai.com"],
        },
    )
    assert child_created.status_code == 200, child_created.text
    child_agent_id = child_created.json()["id"]
    delegated = client.post(
        "/ai-iam/delegate",
        headers=_headers(owner),
        json={
            "parent_agent_id": root_agent_id,
            "child_agent_id": child_agent_id,
            "ai_system_id": ai_system_id,
            "parent_capability_token": root_token,
            "action_scope": ["tool.run"],
            "parent_chain_depth": 1,
            "chain_depth": 2,
        },
    )
    assert delegated.status_code == 200, delegated.text
    child_token = delegated.json()["capability_token"]
    with test_env["SessionLocal"]() as db:
        child_agent = db.get(AgentIdentity, child_agent_id)
        assert child_agent is not None
        child_agent.owner_attested_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        child_agent.owner_attestation_expiry = datetime.now(timezone.utc) + timedelta(hours=1)
        db.add(
            BusinessPurposeSession(
                tenant_id=owner["tenant_id"],
                user_id=owner["user_id"],
                declared_purpose="Support triage child",
                purpose_category="customer_support",
                business_function="support",
                approved_scope={
                    "identity_id": child_agent_id,
                    "identity_type": "agent",
                    "purpose": {"name": "support_triage"},
                    "scope": {
                        "allowed_actions": ["tool.run"],
                        "allowed_tools": ["openai_api"],
                        "allowed_domains": ["api.openai.com"],
                        "allowed_resources": ["api.openai.com"],
                        "allowed_environments": ["prod"],
                        "allowed_data_scopes": ["internal", "unknown"],
                    },
                    "constraints": {"max_risk_level": "medium"},
                    "context": {"max_chain_depth": 3},
                    "mode": "block",
                },
                status="active",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
            )
        )
        db.commit()
    child_session = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=child_agent_id,
        raw_token=child_token,
        session_context={
            "max_chain_depth": 2,
            "connected_systems": ["api.openai.com"],
            "allowed_data_scope": ["internal", "unknown"],
        },
    )
    child_authorize = _authorize(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=child_agent_id,
        raw_token=child_token,
        session_id=child_session["session_id"],
        chain_depth=2,
        chain_id=chain_id,
        parent_action_id=root_action_id,
        parent_agent_id=root_agent_id,
        tool_fingerprint_id=approved_tool_fingerprint_id,
    )
    assert child_authorize.status_code == 200, child_authorize.text
    assert child_authorize.json()["decision"] == "allow"
    child_action_id = child_authorize.json()["runtime_event_id"]
    assert child_action_id
    with test_env["SessionLocal"]() as db:
        child_event = db.get(RuntimeEvent, child_action_id)
        assert child_event is not None
        assert child_event.metadata_json["capability_token_id"] == delegated.json()["token_id"]
        assert child_event.metadata_json["delegation_edge_id"] == delegated.json()["delegation_id"]


def test_mcp_parent_surface_requires_ai_system_id(test_env) -> None:
    owner, _ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    response = test_env["client"].post(
        "/gateway/mcp/authorize",
        headers=_headers(owner),
        json={
            "actor_id": agent_id,
            "capability_token": raw_token,
            "action": "tool.run",
            "resource": "api.openai.com",
            "chain_depth": 2,
            "parent_action_id": "parent-action",
            "parent_agent_id": "parent-agent",
        },
    )
    assert response.status_code == 422, response.text


def test_enforcement_requires_lookup_and_accepts_only_server_issued_session(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    missing = _authorize(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_id=None,
    )
    assert missing.status_code == 200, missing.text
    assert missing.json()["session"]["valid"] is False
    assert missing.json()["session"]["reason"] == "agent_session_required"

    invented = _authorize(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_id="caller-invented-session",
    )
    assert invented.status_code == 200, invented.text
    assert invented.json()["decision"] == "block"
    invented_session = invented.json()["session"]
    assert invented_session["valid"] is False
    assert invented_session["reason"] == "agent_session_not_found"

    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_context={
            "max_chain_depth": 2,
            "connected_systems": ["api.openai.com"],
            "allowed_data_scope": ["internal"],
        },
    )
    allowed = _authorize(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_id=opened["session_id"],
        session_context={
            "max_chain_depth": 1,
            "connected_systems": ["api.openai.com"],
            "data_classification": "internal",
        },
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["session"]["valid"] is True


@pytest.mark.parametrize(
    ("use_other_token", "initiating_user_id", "caller_context", "expected_reason"),
    [
        (True, None, None, "agent_session_token_mismatch"),
        (False, "different-user", None, "agent_session_user_mismatch"),
        (False, None, {"session_id": "different-session"}, "agent_session_context_mismatch"),
        (False, None, {"max_chain_depth": 3}, "agent_session_context_widening"),
        (
            False,
            None,
            {"connected_systems": ["api.openai.com", "evil.example"]},
            "agent_session_context_widening",
        ),
        (
            False,
            None,
            {"expiry": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()},
            "agent_session_expired",
        ),
        (
            False,
            None,
            {"expiry": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()},
            "agent_session_context_widening",
        ),
    ],
)
def test_enforcement_rejects_token_expiry_and_context_spoofing(
    test_env,
    use_other_token: bool,
    initiating_user_id: str | None,
    caller_context: dict | None,
    expected_reason: str,
) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_context={
            "max_chain_depth": 2,
            "connected_systems": ["api.openai.com"],
            "allowed_data_scope": ["internal"],
        },
    )
    other_token = "same-agent-different-token"
    with test_env["SessionLocal"]() as db:
        db.add(
            CapabilityToken(
                tenant_id=owner["tenant_id"],
                agent_identity_id=agent_id,
                ai_system_id=ai_system_id,
                token_hash=token_hash(other_token),
                scopes=["tool.run"],
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                chain_depth=3,
                issued_by_user_id=owner["user_id"],
            )
        )
        db.commit()

    response = _authorize(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=(other_token if use_other_token else raw_token),
        session_id=opened["session_id"],
        initiating_user_id=initiating_user_id,
        session_context=caller_context,
    )
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "block", (expected_reason, response.text)
    validation = response.json()["session"]
    assert validation["valid"] is False
    assert validation["reason"] == expected_reason


@pytest.mark.parametrize(
    ("lifecycle", "expected_reason"),
    [
        ("expired", "agent_session_expired"),
        ("closed", "agent_session_inactive"),
        ("revoked", "agent_session_revoked"),
    ],
)
def test_enforcement_rejects_expired_closed_and_revoked_sessions(
    test_env,
    lifecycle: str,
    expected_reason: str,
) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
    )
    if lifecycle in {"closed", "revoked"}:
        transitioned = test_env["client"].post(
            f"/gateway/mcp/sessions/{opened['session_id']}/{'revoke' if lifecycle == 'revoked' else 'close'}",
            headers=_headers(owner),
        )
        assert transitioned.status_code == 200, transitioned.text
    else:
        with test_env["SessionLocal"]() as db:
            session = db.get(AISession, opened["session_id"])
            assert session is not None
            metadata = dict(session.metadata_json or {})
            metadata["absolute_expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
            session.metadata_json = metadata
            db.commit()

    response = _authorize(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_id=opened["session_id"],
    )
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "block"
    validation = response.json()["session"]
    assert validation["valid"] is False
    assert validation["reason"] == expected_reason


def test_enforcement_rejects_wrong_authenticated_user_and_wrong_agent(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
    )
    second_registration = test_env["client"].post(
        "/auth/register",
        json={
            "email": "second-mcp-operator@example.com",
            "password": PASSWORD,
            "full_name": "Second MCP Operator",
        },
    )
    assert second_registration.status_code == 200, second_registration.text
    second_body = second_registration.json()
    second = {
        "access_token": second_body["access_token"],
        "tenant_id": owner["tenant_id"],
        "user_id": second_body["user"]["id"],
    }
    with test_env["SessionLocal"]() as db:
        db.add(
            UserTenantRole(
                user_id=second["user_id"],
                tenant_id=owner["tenant_id"],
                role="operator",
            )
        )
        db.add(
            BusinessPurposeSession(
                tenant_id=owner["tenant_id"],
                user_id=second["user_id"],
                declared_purpose="Support triage",
                purpose_category="customer_support",
                business_function="support",
                approved_scope={
                    "identity_id": agent_id,
                    "scope": {
                        "allowed_actions": ["tool.run"],
                        "allowed_tools": ["openai_api"],
                        "allowed_domains": ["api.openai.com"],
                    },
                    "constraints": {},
                    "context": {"max_chain_depth": 3},
                    "mode": "block",
                },
                status="active",
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
            )
        )
        other_agent = AgentIdentity(
            tenant_id=owner["tenant_id"],
            name="Other MCP Agent",
            description="wrong agent test",
            status="active",
            max_chain_depth=3,
            action_scope=["tool.run"],
            tool_registry=["openai_api"],
            external_system_access=["api.openai.com"],
        )
        db.add(other_agent)
        db.flush()
        db.commit()
        other_agent_id = other_agent.id

    hidden = test_env["client"].get(
        f"/gateway/mcp/sessions/{opened['session_id']}",
        headers=_headers(second),
    )
    assert hidden.status_code == 404, hidden.text
    wrong_user = _authorize(
        test_env,
        second,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_id=opened["session_id"],
    )
    assert wrong_user.status_code == 200, wrong_user.text
    assert wrong_user.json()["session"]["reason"] == "agent_session_not_found"

    with test_env["SessionLocal"]() as db:
        session = db.get(AISession, opened["session_id"])
        assert session is not None
        metadata = dict(session.metadata_json or {})
        metadata["agent_id"] = other_agent_id
        session.metadata_json = metadata
        db.commit()
    wrong_agent = _authorize(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_id=opened["session_id"],
    )
    assert wrong_agent.status_code == 200, wrong_agent.text
    assert wrong_agent.json()["session"]["reason"] == "agent_session_agent_mismatch"


def test_foreign_tenant_session_identifier_is_not_authority(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
    )
    with test_env["SessionLocal"]() as db:
        session = db.get(AISession, opened["session_id"])
        assert session is not None
        metadata = dict(session.metadata_json or {})
        result = validate_persisted_mcp_session(
            db,
            tenant_id="foreign-tenant",
            authenticated_user_id=owner["user_id"],
            ai_system_id=ai_system_id,
            agent_id=agent_id,
            capability_token_id=metadata["capability_token_id"],
            session_id=opened["session_id"],
            initiating_user_id=owner["user_id"],
            caller_context={},
        )
    assert result["valid"] is False
    assert result["reason"] == "agent_session_not_found"


def test_enforcement_rejects_server_marked_inactive_session(test_env) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
    )
    with test_env["SessionLocal"]() as db:
        session = db.get(AISession, opened["session_id"])
        assert session is not None
        session.status = "inactive"
        db.commit()
    response = _authorize(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_id=opened["session_id"],
    )
    assert response.status_code == 200, response.text
    assert response.json()["session"]["valid"] is False
    assert response.json()["session"]["reason"] == "agent_session_inactive"


@pytest.mark.parametrize(
    ("authority_change", "expected_reason"),
    [
        ("token_revoked", "agent_session_token_revoked"),
        ("token_expired", "agent_session_token_expired"),
        ("agent_inactive", "agent_session_agent_inactive"),
        ("attestation_expired", "agent_session_owner_attestation_expired"),
        ("attestation_missing", "agent_session_owner_attestation_required"),
    ],
)
def test_authorization_revalidates_server_authority_after_session_open(
    test_env,
    authority_change: str,
    expected_reason: str,
) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    opened = _open_session(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
    )
    with test_env["SessionLocal"]() as db:
        session = db.get(AISession, opened["session_id"])
        assert session is not None
        metadata = dict(session.metadata_json or {})
        token = db.get(CapabilityToken, metadata["capability_token_id"])
        agent = db.get(AgentIdentity, agent_id)
        assert token is not None
        assert agent is not None
        if authority_change == "token_revoked":
            token.revoked_at = datetime.now(timezone.utc)
        elif authority_change == "token_expired":
            token.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        elif authority_change == "agent_inactive":
            agent.status = "inactive"
        elif authority_change == "attestation_expired":
            agent.owner_attestation_expiry = datetime.now(timezone.utc) - timedelta(seconds=1)
        else:
            agent.owner_attested_at = None
            agent.owner_attestation_expiry = None
        db.commit()
    response = _authorize(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_id=opened["session_id"],
    )
    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "block"
    assert response.json()["session"]["valid"] is False
    assert response.json()["session"]["reason"] == expected_reason


def test_flag_off_preserves_legacy_request_session_compatibility(test_env, monkeypatch) -> None:
    owner, ai_system_id, agent_id, raw_token = _setup_authority(test_env)
    monkeypatch.setattr(settings, "mcp_persisted_sessions_required", False)
    response = _authorize(
        test_env,
        owner,
        ai_system_id=ai_system_id,
        agent_id=agent_id,
        raw_token=raw_token,
        session_id="legacy-request-session",
    )
    assert response.status_code == 200, response.text
    assert response.json()["session"]["valid"] is True
    assert response.json()["session"]["session_id"] == "legacy-request-session"
