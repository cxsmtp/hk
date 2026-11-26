"""End to end through /gateway/mcp/authorize: hold, approve, bind, retry once."""

from __future__ import annotations

from datetime import UTC, datetime
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.evidence import EvidenceNode
from app.db.models.policy import ApprovalRequest, PolicyPack, PolicyVersion, ToolFingerprint
from app.db.models.policy_pack_platform import PolicyPackAssignment, PolicyPackDefinition, PolicyPackInstance
from app.db.session import Base, get_db
from app.main import app
from app.services.github_repository_access_service import persist_github_inventory_unit
from app.services.policy_pack_platform.service import _normalize_assignment_targets
from ai_system_approval_helpers import approve_ai_system

PASSWORD = "Password123!"


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'github_flow.sqlite3'}", connect_args={"check_same_thread": False})
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield client, session_local
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


USER: dict[str, str] = {}


def _owner(client: TestClient) -> tuple[dict[str, str], str]:
    response = client.post("/auth/register", json={"email": "github-flow@example.com", "password": PASSWORD, "full_name": "GitHub Flow Owner"})
    assert response.status_code == 200, response.text
    payload = response.json()
    tenant_id = payload["tenants"][0]["id"]
    USER["id"] = payload["user"]["id"]
    return {"Authorization": f"Bearer {payload['access_token']}", "X-Tenant-ID": tenant_id}, tenant_id


def _ai_system_and_token(client: TestClient, headers: dict[str, str]) -> tuple[str, str, str]:
    system = client.post("/ai-systems", headers=headers, json={"name": "GitHub agent", "description": "", "risk_tier": "LOW"})
    assert system.status_code == 200, system.text
    ai_system_id = system.json()["id"]
    assert approve_ai_system(client, headers, ai_system_id, status="active").status_code == 200
    agent = client.post("/ai-iam/agents", headers=headers, json={"name": "GitHub agent", "description": "", "max_chain_depth": 3, "capability_inheritance": True, "action_scope": ["REPOSITORY_PUSH"]})
    assert agent.status_code == 200, agent.text
    agent_id = agent.json()["id"]
    token = client.post(f"/ai-iam/agents/{agent_id}/tokens", headers=headers, json={"ai_system_id": ai_system_id, "scopes": ["REPOSITORY_PUSH"], "expires_minutes": 30, "chain_depth": 1})
    assert token.status_code == 200, token.text
    return ai_system_id, agent_id, token.json()["capability_token"]


def _approved_tool(session_local: sessionmaker, tenant_id: str, user_id: str) -> str:
    with session_local() as db:
        tool = ToolFingerprint(
            tenant_id=tenant_id, mcp_server_id="github-pull-requests--acme--app", tool_name="push_files", tool_version="unknown",
            manifest_hash="push-files-manifest", description_hash="d", schema_hash="s", examples_hash="e", approved_hash="push-files-manifest",
            trust_status="approved", approved_by=user_id, approved_at=datetime.now(UTC),
        )
        db.add(tool)
        db.commit()
        return tool.id


def _seed_repository(session_local: sessionmaker, tenant_id: str) -> None:
    with session_local() as db:
        repository = persist_github_inventory_unit(
            db,
            tenant_id=tenant_id,
            connection_id=None,
            record={
                "record_kind": "github_repository",
                "observed_at": datetime(2026, 9, 13, tzinfo=UTC),
                "identifiers": {"host": "github.com", "organization_id": "O_1", "organization_login": "acme", "repository_id": "R_1"},
                "metadata": {"full_name": "acme/app", "visibility": "PRIVATE", "lifecycle_state": "ACTIVE", "evidence_state": "CONFIRMED", "default_branch": "main"},
            },
        )
        pack = PolicyPack(id="pack-gh", tenant_id=tenant_id, name="GitHub", description="test", status="active")
        version = PolicyVersion(id="policy-gh", tenant_id=tenant_id, pack_id=pack.id, version="1", scope={}, enforcement_defaults={}, guardian_contracts=[], contract_json={})
        definition = PolicyPackDefinition(id="definition-gh", publisher_ref="test-gh", stable_pack_id="DEV-GITHUB-FLOW", version="1", name="GitHub", description="test", state="PUBLISHED")
        instance = PolicyPackInstance(id="instance-gh", tenant_id=tenant_id, definition_id=definition.id, source_pack_id="DEV-GITHUB-FLOW", source_pack_version="1", runtime_policy_pack_id=pack.id, effective_policy_version_id=version.id, owner_ref="owner", state="ENFORCED")
        assignment = PolicyPackAssignment(id="scope-gh", tenant_id=tenant_id, instance_id=instance.id, assignment_key="repository", targets=_normalize_assignment_targets({"application": ["github"], "deployment_surface": ["mcp_gateway"], "resource": [repository.id]}), active=True)
        db.add_all([pack, version, definition, instance, assignment])
        repository.governance_state = "APPROVED"
        repository.approved_scope_ref = assignment.id
        repository.policy_mapping_ref = version.id
        repository.policy_current = True
        db.commit()


def _authorize(client: TestClient, headers: dict[str, str], *, ai_system_id: str, agent_id: str, token: str, request_id: str, resource: str = "github.com/acme/app", approval_binding_id: str | None = None, tool_fingerprint_id: str | None = None) -> dict:
    change_context = {"repository_action": "REPOSITORY_PUSH", "branch": "feature/agent", "paths": ["src/app.py"], "files_changed": 1, "bytes_changed": 15}
    if approval_binding_id:
        change_context["approval_binding_id"] = approval_binding_id
    response = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_id": agent_id,
            "capability_token": token,
            "action": "REPOSITORY_PUSH",
            "resource": resource,
            "chain_depth": 1,
            "request_id": request_id,
            "session_id": "github-flow-session",
            "initiating_user_id": USER["id"],
            "session_context": {"session_id": "github-flow-session", "agent_id": agent_id, "initiating_user_id": USER["id"], "max_chain_depth": 3, "connected_systems": ["github.com/acme/app"]},
            "provider": "mcp",
            "tool_name": "push_files",
            "tool_usage_meta": {
                "mcp_server_id": "github-pull-requests--acme--app",
                "tool_version": "unknown",
                "tool_fingerprint_id": tool_fingerprint_id,
                "parameters": {"owner": "acme", "repo": "app", "branch": "feature/agent", "files": [{"path": "src/app.py", "content": "print('hi')\n"}]},
                "github_change_context": change_context,
            },
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_unknown_repository_push_is_denied_with_evidence(env) -> None:
    client, _session_local = env
    headers, _tenant_id = _owner(client)
    ai_system_id, agent_id, token = _ai_system_and_token(client, headers)
    body = _authorize(client, headers, ai_system_id=ai_system_id, agent_id=agent_id, token=token, request_id="gh-unknown-1", resource="github.com/acme/unknown")
    guard = body["trace"]["github_repository_guard"]
    assert guard["decision"] == "BLOCK"
    assert guard["reason"] == "repository_resolution_unavailable"
    assert body["decision"] == "block"
    assert guard["evidence_ref"] in body["evidence_nodes_created"]


def test_held_push_becomes_an_approval_whose_binding_authorizes_exactly_one_retry(env) -> None:
    client, session_local = env
    headers, tenant_id = _owner(client)
    ai_system_id, agent_id, token = _ai_system_and_token(client, headers)
    _seed_repository(session_local, tenant_id)
    tool_id = _approved_tool(session_local, tenant_id, USER["id"])

    held = _authorize(client, headers, ai_system_id=ai_system_id, agent_id=agent_id, token=token, request_id="gh-flow-1", tool_fingerprint_id=tool_id)
    guard = held["trace"]["github_repository_guard"]
    assert guard["decision"] == "HOLD_FOR_APPROVAL", guard
    assert held["decision"] == "hold_for_approval", held["reason"]
    approval_request_id = guard["approval_request_id"]
    with session_local() as db:
        request = db.scalar(select(ApprovalRequest).where(ApprovalRequest.id == approval_request_id))
        assert request is not None
        assert request.request_payload["github_repository_action"]["paths"] == ["src/app.py"]
        assert "print('hi')" not in str(request.request_payload)
        assert db.get(EvidenceNode, guard["evidence_ref"]) is not None

    # Binding before approval is refused.
    early = client.post("/control-coverage/source-control/github-repositories/mutation-approvals", headers=headers, json={"approval_request_id": approval_request_id})
    assert early.status_code == 409, early.text
    decided = client.post(f"/enforcement/approvals/{approval_request_id}/decision", headers=headers, json={"decision": "approve"})
    assert decided.status_code == 200, decided.text
    issued = client.post("/control-coverage/source-control/github-repositories/mutation-approvals", headers=headers, json={"approval_request_id": approval_request_id, "ttl_seconds": 600})
    assert issued.status_code == 200, issued.text
    binding = issued.json()
    assert set(binding) >= {"approval_binding_id", "expires_at", "state"}
    assert "action_mac" not in binding and "nonce" not in binding

    retried = _authorize(client, headers, ai_system_id=ai_system_id, agent_id=agent_id, token=token, request_id="gh-flow-2", approval_binding_id=binding["approval_binding_id"], tool_fingerprint_id=tool_id)
    assert retried["trace"]["github_repository_guard"]["reason"] == "approved_repository_mutation"
    replay = _authorize(client, headers, ai_system_id=ai_system_id, agent_id=agent_id, token=token, request_id="gh-flow-3", approval_binding_id=binding["approval_binding_id"], tool_fingerprint_id=tool_id)
    assert replay["trace"]["github_repository_guard"]["reason"] == "approval_binding_consumed"
    assert replay["decision"] == "block"


def test_agent_policy_route_saves_and_bumps_governance(env) -> None:
    client, session_local = env
    headers, tenant_id = _owner(client)
    _seed_repository(session_local, tenant_id)
    listing = client.get("/control-coverage/source-control/github-repositories/repositories", headers=headers)
    assert listing.status_code == 200, listing.text
    repository = listing.json()["items"][0]
    saved = client.put(
        f"/control-coverage/source-control/github-repositories/repositories/{repository['id']}/agent-policy",
        headers=headers,
        json={"policy": {"write_mode": "PULL_REQUEST_ONLY", "max_mutations_per_minute": 10}, "expected_governance_version": repository["governance_version"]},
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["agent_policy"]["write_mode"] == "PULL_REQUEST_ONLY"
    assert saved.json()["governance_version"] == repository["governance_version"] + 1
    invalid = client.put(
        f"/control-coverage/source-control/github-repositories/repositories/{repository['id']}/agent-policy",
        headers=headers,
        json={"policy": {"write_mode": "ANYTHING"}, "expected_governance_version": repository["governance_version"] + 1},
    )
    assert invalid.status_code == 422
