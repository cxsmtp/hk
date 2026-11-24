from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.activity_audit import AIAction, AISession, PromptPayload
from app.db.models.audit import AuditLog
from app.db.models.finding import Finding
from app.db.session import Base, get_db
from app.main import app


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'executive_mcp.sqlite3'}",
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
        yield {"client": client, "sessionmaker": testing_session_local, "tmp_path": tmp_path}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _register_owner(client: TestClient, *, email: str = "owner@example.com") -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Executive Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
        "user_id": body["user"]["id"],
    }


def _headers(owner: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {owner['access_token']}", "X-Tenant-ID": owner["tenant_id"]}


def _seed_activity(test_env, owner: dict[str, str]) -> None:
    now = datetime.now(timezone.utc)
    with test_env["sessionmaker"]() as db:
        session = AISession(
            session_id="exec-session-1",
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            source_surface="browser",
            ai_app="ChatGPT",
            ai_model="gpt-demo",
            start_time=now - timedelta(minutes=10),
        )
        db.add(session)
        db.add_all(
            [
                AIAction(
                    action_id="exec-action-allow",
                    tenant_id=owner["tenant_id"],
                    session_id=session.session_id,
                    user_id=owner["user_id"],
                    timestamp=now - timedelta(minutes=8),
                    action_type="prompt_submit",
                    ai_app="ChatGPT",
                    ai_model="gpt-demo",
                    enforcement_action="allowed",
                    metadata_json={"tokens": 42, "department": "Executive"},
                ),
                AIAction(
                    action_id="exec-action-block",
                    tenant_id=owner["tenant_id"],
                    session_id=session.session_id,
                    user_id=owner["user_id"],
                    timestamp=now - timedelta(minutes=7),
                    action_type="tool_call",
                    ai_app="Claude",
                    ai_model="claude-demo",
                    enforcement_action="blocked",
                    metadata_json={"tokens": 11, "department": "Executive"},
                ),
                PromptPayload(
                    action_id="exec-action-block",
                    raw_prompt="SECRET_PROMPT_SHOULD_NOT_LEAK",
                    redacted_prompt="redacted",
                    prompt_hash="hash-demo",
                    storage_mode="redacted",
                ),
                Finding(
                    tenant_id=owner["tenant_id"],
                    source_surface="runtime",
                    ai_tool="claude",
                    user_id=owner["user_id"],
                    user_email="exec@example.com",
                    application="Claude",
                    department="Executive",
                    severity="high",
                    finding_type="prompt_injection",
                    risk_category="prompt_injection",
                    decision="blocked",
                    status="open",
                    recommended_action="Review OWASP LLM prompt injection policy.",
                    evidence_node_ids=[],
                    related_event_ids=[],
                    related_control_ids=[],
                    remediation_action_ids=[],
                    dedupe_key="exec-finding-1",
                    occurrence_count=3,
                    first_seen_at=now - timedelta(minutes=9),
                    last_seen_at=now - timedelta(minutes=5),
                ),
            ]
        )
        db.commit()


def test_executive_mcp_summary_is_tenant_scoped_and_excludes_raw_prompts(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client)
    _seed_activity(test_env, owner)

    response = client.get("/executive-mcp/summary", headers=_headers(owner))
    assert response.status_code == 200, response.text
    payload = response.json()

    assert payload["tenant_id"] == owner["tenant_id"]
    assert payload["headline"]["total_ai_actions"] == 2
    assert payload["headline"]["blocked_or_restricted"] == 1
    assert payload["privacy"]["raw_prompt_content_included"] is False
    assert "SECRET_PROMPT_SHOULD_NOT_LEAK" not in response.text

    with test_env["sessionmaker"]() as db:
        audit = db.scalar(
            select(AuditLog).where(
                AuditLog.tenant_id == owner["tenant_id"],
                AuditLog.action == "executive_mcp.summary.view",
            )
        )
        assert audit is not None


def test_remote_executive_mcp_lists_tools_and_calls_summary(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client)
    _seed_activity(test_env, owner)

    metadata = client.get("/mcp/executive")
    assert metadata.status_code == 200, metadata.text
    assert metadata.json()["transport"] == "streamable-http"
    assert metadata.json()["privacy"]["raw_prompt_content_included"] is False

    tools = client.post(
        "/mcp/executive",
        headers=_headers(owner),
        json={"jsonrpc": "2.0", "id": "tools", "method": "tools/list"},
    )
    assert tools.status_code == 200, tools.text
    tool_names = {tool["name"] for tool in tools.json()["result"]["tools"]}
    assert "get_executive_summary" in tool_names
    assert "query_executive_metrics" in tool_names
    assert "create_executive_presentation" in tool_names

    summary = client.post(
        "/mcp/executive",
        headers=_headers(owner),
        json={
            "jsonrpc": "2.0",
            "id": "summary",
            "method": "tools/call",
            "params": {"name": "get_executive_summary", "arguments": {"window_days": 30}},
        },
    )
    assert summary.status_code == 200, summary.text
    content = summary.json()["result"]["content"][0]
    assert content["type"] == "text"
    assert "total_ai_actions" in content["text"]
    assert "SECRET_PROMPT_SHOULD_NOT_LEAK" not in summary.text


def test_remote_executive_mcp_exposes_hosted_connector_discovery_aliases(test_env) -> None:
    client: TestClient = test_env["client"]

    metadata = client.get("/.well-known/mcp")
    assert metadata.status_code == 200, metadata.text
    assert metadata.json()["endpoint"] == "/mcp/executive"
    assert metadata.json()["transport"] == "streamable-http"

    protected = client.get("/.well-known/oauth-protected-resource")
    assert protected.status_code == 200, protected.text
    assert protected.json()["resource"].endswith("/mcp/executive")
    assert protected.json()["authorization_servers"][0].endswith("/mcp/executive")

    server = client.get("/.well-known/oauth-authorization-server")
    assert server.status_code == 200, server.text
    assert server.json()["issuer"].endswith("/mcp/executive")
    assert server.json()["authorization_endpoint"].endswith("/mcp/executive/authorize")
    assert server.json()["token_endpoint"].endswith("/mcp/executive/token")

    path_scoped_server = client.get("/.well-known/oauth-authorization-server/mcp/executive")
    assert path_scoped_server.status_code == 200, path_scoped_server.text
    assert path_scoped_server.json()["issuer"].endswith("/mcp/executive")


def test_executive_mcp_queries_blocks_tokens_and_pseudonymized_violations(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client)
    _seed_activity(test_env, owner)

    blocked = client.post(
        "/executive-mcp/query",
        headers=_headers(owner),
        json={"metric": "blocked", "group_by": "app", "limit": 5},
    )
    assert blocked.status_code == 200, blocked.text
    assert blocked.json()["items"] == [{"key": "Claude", "value": 1}]

    tokens = client.post(
        "/executive-mcp/query",
        headers=_headers(owner),
        json={"metric": "tokens", "limit": 5},
    )
    assert tokens.status_code == 200, tokens.text
    assert tokens.json()["total_tokens"] == 53

    violations = client.post(
        "/executive-mcp/query",
        headers=_headers(owner),
        json={"metric": "top_violations", "include_named_users": False, "limit": 5},
    )
    assert violations.status_code == 200, violations.text
    assert violations.json()["items"][0]["key"].startswith("user:")
    assert "exec@example.com" not in violations.text


def test_executive_mcp_framework_query_and_presentation_export(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client)
    _seed_activity(test_env, owner)

    frameworks = client.post(
        "/executive-mcp/query",
        headers=_headers(owner),
        json={"metric": "violations_by_framework", "limit": 5},
    )
    assert frameworks.status_code == 200, frameworks.text
    assert any(item["key"] == "OWASP LLM / GenAI" for item in frameworks.json()["items"])

    presentation = client.post(
        "/executive-mcp/presentations",
        headers=_headers(owner),
        json={"title": "Board AI Governance Brief", "window_days": 30},
    )
    assert presentation.status_code == 200, presentation.text
    body = presentation.json()
    path = Path(body["path"])
    assert path.exists()
    assert body["raw_prompt_content_included"] is False
    with zipfile.ZipFile(path) as archive:
        assert "ppt/presentation.xml" in archive.namelist()
        assert "ppt/slides/slide1.xml" in archive.namelist()
    assert "SECRET_PROMPT_SHOULD_NOT_LEAK" not in presentation.text
