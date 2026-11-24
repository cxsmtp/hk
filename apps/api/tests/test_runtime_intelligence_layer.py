from __future__ import annotations


def test_browser_observation_is_not_a_tool_fingerprint() -> None:
    from app.db.models.runtime_intelligence import RuntimeEvent
    from app.services.runtime_intelligence.runtime_correlation_service import _tool_fingerprint

    browser = RuntimeEvent(
        event_id="browser-domain-only", tenant_id="tenant-a", source_surface="browser",
        event_type="prompt_submitted", app_id="chatgpt.com",
        metadata_json={"tool_name": "chatgpt.com", "api_endpoint": "https://chatgpt.com/", "model_name": "gpt"},
    )
    invoked = RuntimeEvent(
        event_id="mcp-real-call", tenant_id="tenant-a", source_surface="mcp",
        event_type="mcp_tool_call", app_id="repo-server",
        metadata_json={"mcp_tool_id": "list_pull_requests", "tool_name": "list_pull_requests"},
    )
    configured = RuntimeEvent(
        event_id="mcp-configured-only", tenant_id="tenant-a", source_surface="mcp",
        event_type="mcp_configuration", app_id="repo-server",
        metadata_json={"mcp_tool_id": "list_pull_requests", "tool_name": "list_pull_requests"},
    )
    assert _tool_fingerprint(browser) == ""
    assert _tool_fingerprint(configured) == ""
    assert _tool_fingerprint(invoked) == "list_pull_requests"


def test_draft_and_policy_companion_are_not_prompt_block_attempts() -> None:
    from app.db.models.runtime_intelligence import RuntimeEvent
    from app.services.runtime_intelligence.runtime_correlation_service import _is_prompt_block_like

    def event(event_type: str) -> RuntimeEvent:
        return RuntimeEvent(
            event_id=event_type, tenant_id="tenant-a", source_surface="browser",
            event_type=event_type, severity="high",
            metadata_json={"event_type": event_type, "decision": "block", "input_signal_types": ["prompt_injection"]},
        )

    assert _is_prompt_block_like(event("prompt_blocked"))
    assert not _is_prompt_block_like(event("prompt_drafted"))
    assert not _is_prompt_block_like(event("policy_blocked"))

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.runtime_intelligence import ContextNode, RuntimeBehaviorEdge, RuntimeEvent
from app.db.session import Base, get_db
from app.main import app
import app.services.runtime_intelligence.runtime_event_normalizer as runtime_normalizer
import app.services.runtime_intelligence.streaming as runtime_streaming


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "runtime_intelligence.sqlite3"
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


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "X-Tenant-ID": tenant_id,
    }


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Runtime Owner"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    return {
        "access_token": payload["access_token"],
        "tenant_id": payload["tenants"][0]["id"],
    }


def _create_ai_system(client: TestClient, *, headers: dict[str, str], risk_tier: str = "LOW") -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Runtime AI", "description": "", "risk_tier": risk_tier},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]

    activate = client.patch(
        f"/ai-systems/{ai_system_id}",
        headers=headers,
        json={"status": "active"},
    )
    assert activate.status_code == 200, activate.text
    return ai_system_id


def test_runtime_stream_tenant_auth_closes_session_before_context_return(test_env, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi import HTTPException

    from app.core import tenant as tenant_dependencies

    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-stream-tenant-auth@example.com")
    closed: list[bool] = []

    class TrackingSession:
        def __init__(self, delegate):
            self.delegate = delegate

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self.delegate.close()
            closed.append(True)

        def scalar(self, *args, **kwargs):
            return self.delegate.scalar(*args, **kwargs)

    def tracking_session_local():
        return TrackingSession(test_env["sessionmaker"]())

    monkeypatch.setattr(tenant_dependencies, "SessionLocal", tracking_session_local)

    context = tenant_dependencies.require_stream_tenant(
        x_tenant_id=owner["tenant_id"],
        token=owner["access_token"],
    )
    assert context.tenant.id == owner["tenant_id"]
    assert closed == [True]

    with pytest.raises(HTTPException) as invalid_token:
        tenant_dependencies.require_stream_tenant(x_tenant_id=owner["tenant_id"], token="invalid-token")
    assert invalid_token.value.status_code == 401

    with pytest.raises(HTTPException) as missing_tenant:
        tenant_dependencies.require_stream_tenant(x_tenant_id=None, token=owner["access_token"])
    assert missing_tenant.value.status_code == 400

    with pytest.raises(HTTPException) as missing_membership:
        tenant_dependencies.require_stream_tenant(x_tenant_id="tenant-not-in-memberships", token=owner["access_token"])
    assert missing_membership.value.status_code == 403
    assert len(closed) == 4


def test_runtime_stream_routes_use_short_lived_auth_only_for_five_sse_routes() -> None:
    from app.api.routers import runtime_intelligence as runtime_router
    from app.core import tenant as tenant_dependencies

    def dependency_calls(dependant) -> list[object]:
        calls = [dependant.call]
        for child in dependant.dependencies:
            calls.extend(dependency_calls(child))
        return calls

    routes = {route.path: route for route in runtime_router.router.routes if hasattr(route, "dependant")}

    stream_paths = [
        "/runtime-intelligence/stream/overview",
        "/runtime-intelligence/stream/activity",
        "/runtime-intelligence/stream/chains",
        "/runtime-intelligence/stream/patterns",
        "/runtime-intelligence/stream/recommendations",
    ]
    for path in stream_paths:
        calls = dependency_calls(routes[path].dependant)
        assert runtime_router._require_stream_viewer in calls
        assert tenant_dependencies.require_stream_tenant in calls
        assert tenant_dependencies.require_tenant not in calls

    for path in ["/runtime-intelligence/chains/{chain_id}", "/runtime-intelligence/events"]:
        calls = dependency_calls(routes[path].dependant)
        assert tenant_dependencies.require_tenant in calls
        assert tenant_dependencies.require_stream_tenant not in calls


def _create_blocking_policy(client: TestClient, *, headers: dict[str, str], trigger_token: str) -> None:
    pack = client.post(
        "/policies/packs",
        headers=headers,
        json={"name": "Runtime RI Pack", "description": "runtime", "status": "draft"},
    )
    assert pack.status_code == 200, pack.text
    pack_id = pack.json()["pack"]["id"]

    activate = client.patch(
        f"/policies/packs/{pack_id}",
        headers=headers,
        json={"status": "active"},
    )
    assert activate.status_code == 200, activate.text

    version = client.post(
        f"/policies/packs/{pack_id}/versions",
        headers=headers,
        json={
            "version": "1.0.0",
            "scope": {
                "applies_to_risk_tiers": ["LOW", "MEDIUM", "HIGH", "CRITICAL", "RESTRICTED"],
                "applies_to_ai_system_ids": None,
                "applies_to_actor_types": ["human", "agent", "system"],
            },
            "enforcement_defaults": {"default_decision": "allow", "escalation": "notify"},
            "guardian_contracts": [
                {
                    "guardian_id": "ri_prompt_block_guard",
                    "description": "block runtime token",
                    "enabled": True,
                    "trigger": {
                        "signal_types": ["prompt.text"],
                        "conditions": [
                            {
                                "field": "prompt.text",
                                "operator": "contains",
                                "value": trigger_token,
                                "case_sensitive": False,
                            }
                        ],
                    },
                    "evaluation": {"method": "rules", "confidence_threshold": 0.5},
                    "decision": {"on_pass": "allow", "on_fail": "block", "on_uncertain": "warn"},
                    "actions": {
                        "redact": {"fields": ["prompt"], "strategy": "mask"},
                        "mutate_output": {"enabled": False, "strategy": "safe_completion"},
                        "notify": {"channels": []},
                        "create_ticket": {"system": "jira", "severity": "high"},
                    },
                    "evidence": {
                        "evidence_signal_type": "guardian.ri_prompt_block_guard.detected",
                        "link_to_controls": ["CTRL-INPUT-001"],
                    },
                    "control_impact": {
                        "maturity_delta_on_fail": -0.1,
                        "increase_simulation_frequency": False,
                        "enforcement_strictness_increase": 1,
                    },
                    "approval_workflow": {
                        "required_roles": ["owner", "admin"],
                        "sla_minutes": 30,
                        "default_if_timeout": "block",
                    },
                }
            ],
        },
    )
    assert version.status_code == 200, version.text


def _create_agent_and_token(
    client: TestClient,
    *,
    headers: dict[str, str],
    ai_system_id: str,
    scope: str,
) -> tuple[str, str]:
    agent = client.post(
        "/ai-iam/agents",
        headers=headers,
        json={
            "name": "Runtime Tool Agent",
            "description": "",
            "max_chain_depth": 3,
            "capability_inheritance": False,
        },
    )
    assert agent.status_code == 200, agent.text
    agent_id = agent.json()["id"]

    token = client.post(
        f"/ai-iam/agents/{agent_id}/tokens",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "scopes": [scope],
            "expires_minutes": 30,
            "chain_depth": 1,
        },
    )
    assert token.status_code == 200, token.text
    return agent_id, token.json()["capability_token"]


def _mcp_session_payload(
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
        },
    }


def test_gateway_non_blocking_when_runtime_intelligence_fails(monkeypatch: pytest.MonkeyPatch, test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-nonblocking@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")

    def _raise(*args, **kwargs):
        raise RuntimeError("runtime intelligence down")

    monkeypatch.setattr(runtime_normalizer, "ingest_from_gateway_enforcement", _raise)

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "owner",
            "prompt": "hello world",
            "context_summary": "runtime test",
            "attachments_meta": [],
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["final_decision"] in {"allow", "warn", "block", "hold_for_approval", "redact"}


def test_runtime_events_normalize_from_browser_gateway_connector_and_aiiam(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-normalize@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")

    browser = client.post(
        "/telemetry/browser",
        headers=headers,
        json={
            "event_type": "unknown_ai_detected",
            "domain": "mystery-ai.example",
            "url": "https://mystery-ai.example/chat",
            "action_taken": "discover",
            "severity": "high",
        },
    )
    assert browser.status_code == 200, browser.text

    gateway = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "owner",
            "prompt": "normal prompt",
            "context_summary": "runtime",
            "attachments_meta": [],
        },
    )
    assert gateway.status_code == 200, gateway.text

    connector = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "connector.runtime.discovery",
            "severity": "med",
            "payload": {"ai_tool": "connector_tool"},
        },
    )
    assert connector.status_code == 200, connector.text

    connector_rich = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "connector.runtime.rich",
            "severity": "high",
            "payload": {
                "ai_tool": "rich_connector_tool",
                "tool_name": "rich_connector_tool",
                "tool_category": "data_pipeline",
                "provider_key": "openai",
                "model_provider": "openai",
                "model_name": "gpt-4.1",
                "api_endpoint": "https://api.openai.com/v1/responses",
                "data_source": "crm_export",
                "response_size": 2048,
                "chain_depth": 2,
                "parent_agent_id": "agent-parent-1",
                "user_id": "owner",
            },
        },
    )
    assert connector_rich.status_code == 200, connector_rich.text

    agent = client.post(
        "/ai-iam/agents",
        headers=headers,
        json={
            "name": "Runtime Agent",
            "description": "",
            "max_chain_depth": 3,
            "capability_inheritance": False,
        },
    )
    assert agent.status_code == 200, agent.text
    agent_id = agent.json()["id"]

    token = client.post(
        f"/ai-iam/agents/{agent_id}/tokens",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "scopes": ["tool.read"],
            "expires_minutes": 30,
            "chain_depth": 1,
        },
    )
    if token.status_code == 409:
        detail = token.json().get("detail") if isinstance(token.json(), dict) else {}
        if isinstance(detail, dict) and detail.get("code") == "jit_approval_required":
            reset_risk = client.patch(
                f"/ai-systems/{ai_system_id}",
                headers=headers,
                json={"risk_tier": "LOW"},
            )
            assert reset_risk.status_code == 200, reset_risk.text
            token = client.post(
                f"/ai-iam/agents/{agent_id}/tokens",
                headers=headers,
                json={
                    "ai_system_id": ai_system_id,
                    "scopes": ["tool.read"],
                    "expires_minutes": 30,
                    "chain_depth": 1,
                },
            )
    assert token.status_code == 200, token.text

    events = client.get("/runtime-intelligence/events?page=1&page_size=500", headers=headers)
    assert events.status_code == 200, events.text
    payload = events.json()
    surfaces = {item["source_surface"] for item in payload["items"]}
    assert {"browser", "gateway", "connector", "aiiam"}.issubset(surfaces)

    expected_surface_modes = {
        "browser": "enforceable",
        "gateway": "enforceable",
        "connector": "monitoring_only",
        "aiiam": "enforceable",
    }
    for item in payload["items"]:
        provider_catalog = dict(item.get("metadata", {}).get("provider_catalog") or {})
        assert "surface_policy_mode" in provider_catalog
        assert "enforcement_supported_for_source" in provider_catalog
        assert "monitoring_only_for_source" in provider_catalog
        source_surface = item["source_surface"]
        if source_surface in expected_surface_modes:
            assert provider_catalog.get("surface_policy_mode") == expected_surface_modes[source_surface]

    normalized_checked = 0
    for item in payload["items"]:
        assert item["event_id"]
        assert item["tenant_id"] == owner["tenant_id"]
        assert item["event_type"]
        assert isinstance(item["evidence_node_ids"], list)
        assert item["created_at"]
        normalized = dict(item.get("metadata", {}).get("normalized_enforcement_event") or {})
        if not normalized:
            continue
        normalized_checked += 1
        required_keys = {
            "event_id",
            "tenant_id",
            "source_surface",
            "action_type",
            "ai_system_id",
            "agent_id",
            "data_classification",
            "correlation_id",
        }
        assert required_keys.issubset(set(normalized.keys()))
        assert "provider_id" in normalized
        assert "provider_name" in normalized
        assert "created_at" in normalized
        assert normalized["event_id"] == item["event_id"]
        assert normalized["tenant_id"] == item["tenant_id"]
    assert normalized_checked >= 4

    rich_items = [item for item in payload["items"] if item["event_type"] == "connector.runtime.rich"]
    assert len(rich_items) >= 1
    rich = rich_items[0]
    assert rich["model_provider"] == "openai"
    assert rich["model_name"] == "gpt-4.1"
    assert rich["tool_name"] == "rich_connector_tool"
    assert rich["tool_category"] == "data_pipeline"
    assert rich["api_endpoint"] == "https://api.openai.com/v1/responses"
    assert rich["data_source"] == "crm_export"
    assert int(rich["response_size"]) == 2048
    assert int(rich["chain_depth"]) == 2
    assert rich["parent_agent_id"] == "agent-parent-1"


def test_behavior_graph_edges_are_created(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-graph@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "owner",
            "prompt": "graph event",
            "context_summary": "graph",
            "attachments_meta": [],
        },
    )
    assert response.status_code == 200, response.text

    graph = client.get(f"/runtime-intelligence/graph/{ai_system_id}", headers=headers)
    assert graph.status_code == 200, graph.text
    graph_payload = graph.json()
    assert graph_payload["total_edges"] >= 1
    relationships = {edge["relationship_type"] for edge in graph_payload["edges"]}
    assert "runtime.user_to_app" in relationships
    assert "runtime.app_to_ai_system" in relationships

    connector = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "connector.runtime.graph_enriched",
            "severity": "high",
            "payload": {
                "user_id": "owner",
                "tool_name": "tool-alpha",
                "tool_category": "retrieval",
                "model_provider": "anthropic",
                "model_name": "claude-3.5",
                "api_endpoint": "https://api.anthropic.com/v1/messages",
                "data_source": "kb_vector_store",
            },
        },
    )
    assert connector.status_code == 200, connector.text

    graph2 = client.get(f"/runtime-intelligence/graph/{ai_system_id}", headers=headers)
    assert graph2.status_code == 200, graph2.text
    relationships2 = {edge["relationship_type"] for edge in graph2.json()["edges"]}
    assert "runtime.user_to_app" in relationships2
    assert "runtime.app_to_ai_system" in relationships2
    assert "runtime.ai_system_to_model" in relationships2
    assert "runtime.model_to_tool" in relationships2
    assert "runtime.tool_to_api" in relationships2
    assert "runtime.api_to_data_source" in relationships2


def test_agent_graph_endpoint_returns_path_explainability(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-agent-graph@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")
    agent_id, token = _create_agent_and_token(
        client,
        headers=headers,
        ai_system_id=ai_system_id,
        scope="tool.read",
    )

    authorized = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_id": agent_id,
            "capability_token": token,
            "action": "tool.read",
            "resource": "kb/article/123",
            "chain_depth": 1,
            "request_id": "ri-agent-graph-001",
            "provider": "openai",
            "model": "gpt-4.1-mini",
            "model_version": "2026-03",
            "tool_name": "kb_reader",
            "tool_category": "mcp_tool",
            "api_endpoint": "mcp://kb/read",
            "data_source": "knowledge_base",
            **_mcp_session_payload(
                agent_id=agent_id,
                user_id="owner",
                session_id="ri-agent-graph-session-1",
                max_chain_depth=3,
                connected_systems=["kb", "mcp://kb/read"],
            ),
        },
    )
    assert authorized.status_code == 200, authorized.text

    graph = client.get(f"/runtime-intelligence/agent-graph/{agent_id}", headers=headers)
    assert graph.status_code == 200, graph.text
    payload = graph.json()
    assert payload["agent_id"] == agent_id
    assert payload["event_count"] >= 1
    assert isinstance(payload["decision_counts"], dict)
    assert ai_system_id in payload["linked_ai_system_ids"]
    assert payload["total_edges"] >= 1
    relationship_types = {edge["relationship_type"] for edge in payload["edges"]}
    assert "runtime.ai_system_to_tool" in relationship_types
    assert "runtime.tool_to_api" in relationship_types


def test_repeated_blocks_generate_runtime_findings_and_triggers(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-findings@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    for _ in range(3):
        response = client.post(
            "/telemetry/browser",
            headers=headers,
            json={
                "event_type": "prompt_blocked",
                "domain": "chat.openai.com",
                "url": "https://chat.openai.com",
                "action_taken": "block",
                "severity": "high",
                "input_signal_types": ["prompt_injection"],
                "prompt_preview_redacted": "ignored and redacted",
            },
        )
        assert response.status_code == 200, response.text

    findings = client.get(
        "/runtime-intelligence/findings?page=1&page_size=100&finding_type=repeated_prompt_injection_attempts",
        headers=headers,
    )
    assert findings.status_code == 200, findings.text
    assert findings.json()["total"] >= 1

    triggers = client.get(
        "/runtime-intelligence/triggers?page=1&page_size=100&reason_code=repeated_prompt_blocks",
        headers=headers,
    )
    assert triggers.status_code == 200, triggers.text
    assert triggers.json()["total"] >= 1
    assert any(item["target_pack"] == "prompt_attack_pack" for item in triggers.json()["items"])


def test_oauth_supply_chain_attack_correlation_generates_finding_trace_and_trigger(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-oauth-supply-chain@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="HIGH")

    correlation_id = "oauth-chain-demo-1"
    oauth_app = {
        "app_id": "oauth-app-attack-1",
        "name": "Untrusted OAuth AI App",
        "client_id": "oauth-client-attack-1",
        "publisher": "unknown",
        "scopes": ["Directory.Read.All", "Files.Read.All", "Mail.ReadWrite"],
        "users": ["owner"],
        "risk_score": 0.93,
        "last_used": datetime.now(timezone.utc).isoformat(),
    }

    baseline = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "connector.runtime.oauth.audit",
            "severity": "high",
            "payload": {
                "oauth_app": oauth_app,
                "oauth_new_app": True,
                "oauth_high_risk_scopes": True,
                "high_privilege_scopes": ["Directory.Read.All", "Files.Read.All"],
                "oauth_relationships": [
                    {
                        "user_id": "owner",
                        "app_id": "oauth-app-attack-1",
                        "scopes": ["Directory.Read.All", "Files.Read.All", "Mail.ReadWrite"],
                        "anomaly_flag": False,
                    }
                ],
                "correlation_id": correlation_id,
                "context_id": correlation_id,
                "chain_id": correlation_id,
                "user_id": "owner",
            },
        },
    )
    assert baseline.status_code == 200, baseline.text

    abnormal = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "connector.runtime.oauth.access",
            "severity": "high",
            "payload": {
                "oauth_app": oauth_app,
                "abnormal_access_pattern": True,
                "systems_accessed": ["SharePoint", "OneDrive", "Exchange"],
                "oauth_relationships": [
                    {
                        "user_id": "owner",
                        "app_id": "oauth-app-attack-1",
                        "scopes": ["Directory.Read.All", "Files.Read.All", "Mail.ReadWrite"],
                        "anomaly_flag": True,
                    }
                ],
                "correlation_id": correlation_id,
                "context_id": correlation_id,
                "chain_id": correlation_id,
                "user_id": "owner",
            },
        },
    )
    assert abnormal.status_code == 200, abnormal.text

    secrets = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "connector.runtime.oauth.secrets",
            "severity": "critical",
            "payload": {
                "oauth_app": oauth_app,
                "unprotected_secrets_accessed": True,
                "secrets": ["OPENAI_API_KEY", "CLIENT_SECRET"],
                "sensitivity_flags": ["sensitive", "unprotected"],
                "oauth_relationships": [
                    {
                        "user_id": "owner",
                        "app_id": "oauth-app-attack-1",
                        "scopes": ["Directory.Read.All", "Files.Read.All", "Mail.ReadWrite"],
                        "anomaly_flag": True,
                    }
                ],
                "correlation_id": correlation_id,
                "context_id": correlation_id,
                "chain_id": correlation_id,
                "user_id": "owner",
            },
        },
    )
    assert secrets.status_code == 200, secrets.text

    findings = client.get(
        "/runtime-intelligence/findings?page=1&page_size=100&finding_type=AI_SUPPLY_CHAIN_ATTACK",
        headers=headers,
    )
    assert findings.status_code == 200, findings.text
    assert findings.json()["total"] >= 1
    finding_item = findings.json()["items"][0]
    assert finding_item["risk_category"] == "supply_chain"
    assert "revoke oauth app" in str(finding_item.get("recommended_action") or "").lower()

    triggers = client.get(
        "/runtime-intelligence/triggers?page=1&page_size=100&reason_code=oauth_supply_chain_attack",
        headers=headers,
    )
    assert triggers.status_code == 200, triggers.text
    assert triggers.json()["total"] >= 1
    assert any(item["target_pack"] == "tool_abuse_pack" for item in triggers.json()["items"])

    recommendations = client.get("/runtime-intelligence/recommendations?page=1&page_size=100", headers=headers)
    assert recommendations.status_code == 200, recommendations.text
    reco_payloads = [
        dict(item.get("payload") or {})
        for item in recommendations.json()["items"]
        if str(item.get("reason_code") or "") == "oauth_supply_chain_attack"
    ]
    assert reco_payloads
    actions = {
        str(suggestion.get("action") or "")
        for payload in reco_payloads
        for suggestion in list(payload.get("remediation_suggestions") or [])
        if isinstance(suggestion, dict)
    }
    assert {"revoke_oauth_app", "revoke_tokens", "rotate_secrets", "disable_user"}.issubset(actions)

    events = client.get("/runtime-intelligence/events?page=1&page_size=200", headers=headers)
    assert events.status_code == 200, events.text
    oauth_events = [
        item
        for item in events.json()["items"]
        if str(dict(item.get("metadata") or {}).get("chain_id") or "") == correlation_id
    ]
    assert oauth_events
    anchor_event_id = oauth_events[0]["event_id"]

    trace = client.get(f"/runtime/trace/{anchor_event_id}", headers=headers)
    assert trace.status_code == 200, trace.text
    trace_payload = trace.json()
    assert trace_payload["trace_key_type"] in {"chain_id", "context_id", "correlation_id", "event_id"}
    assert len(trace_payload["steps"]) >= 1


def test_runtime_patterns_and_recommendations_capture_repeated_attack_behavior(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-patterns-repeated@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    for _ in range(3):
        response = client.post(
            "/telemetry/browser",
            headers=headers,
            json={
                "event_type": "prompt_blocked",
                "domain": "chat.openai.com",
                "url": "https://chat.openai.com",
                "action_taken": "block",
                "severity": "high",
                "input_signal_types": ["prompt_injection"],
                "prompt_preview_redacted": "ignored and redacted",
            },
        )
        assert response.status_code == 200, response.text

    patterns = client.get(
        "/runtime/patterns?page=1&page_size=100&type_filter=repeated_violations",
        headers=headers,
    )
    assert patterns.status_code == 200, patterns.text
    payload = patterns.json()
    assert payload["total"] >= 1
    assert any(int(item.get("frequency") or 0) >= 3 for item in payload["items"])
    assert any(str(item.get("severity") or "") in {"high", "critical"} for item in payload["items"])

    recommendations = client.get("/runtime/recommendations?page=1&page_size=100", headers=headers)
    assert recommendations.status_code == 200, recommendations.text
    recommendation_payload = recommendations.json()
    assert recommendation_payload["total"] >= 1
    items = recommendation_payload["items"]
    assert all("decision_impact_score" in dict(item.get("payload") or {}) for item in items)
    sorted_scores = [float(dict(item.get("payload") or {}).get("decision_impact_score") or 0.0) for item in items]
    assert sorted_scores == sorted(sorted_scores, reverse=True)


def test_runtime_recommendation_confidence_threshold_gates_remediation(test_env, monkeypatch: pytest.MonkeyPatch) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-confidence-gate@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    monkeypatch.setattr(runtime_normalizer.settings, "runtime_remediation_confidence_threshold", 0.95)
    for _ in range(3):
        response = client.post(
            "/telemetry/browser",
            headers=headers,
            json={
                "event_type": "prompt_blocked",
                "domain": "chat.openai.com",
                "url": "https://chat.openai.com",
                "action_taken": "block",
                "severity": "high",
                "input_signal_types": ["prompt_injection"],
                "prompt_preview_redacted": "ignored and redacted",
            },
        )
        assert response.status_code == 200, response.text

    recommendations_high_threshold = client.get("/runtime-intelligence/recommendations?page=1&page_size=100", headers=headers)
    assert recommendations_high_threshold.status_code == 200, recommendations_high_threshold.text
    assert recommendations_high_threshold.json()["total"] == 0

    remediations_high_threshold = client.get(
        "/findings/remediations?page=1&page_size=100&source_trigger_type=runtime_pattern",
        headers=headers,
    )
    assert remediations_high_threshold.status_code == 200, remediations_high_threshold.text
    baseline_runtime_pattern_remediations = int(remediations_high_threshold.json()["total"])

    monkeypatch.setattr(runtime_normalizer.settings, "runtime_remediation_confidence_threshold", 0.5)
    for _ in range(3):
        response = client.post(
            "/telemetry/browser",
            headers=headers,
            json={
                "event_type": "prompt_blocked",
                "domain": "chat.openai.com",
                "url": "https://chat.openai.com",
                "action_taken": "block",
                "severity": "high",
                "input_signal_types": ["prompt_injection"],
                "prompt_preview_redacted": "ignored and redacted",
            },
        )
        assert response.status_code == 200, response.text

    recommendations_low_threshold = client.get("/runtime-intelligence/recommendations?page=1&page_size=100", headers=headers)
    assert recommendations_low_threshold.status_code == 200, recommendations_low_threshold.text
    assert recommendations_low_threshold.json()["total"] >= 1

    remediations_low_threshold = client.get(
        "/findings/remediations?page=1&page_size=100&source_trigger_type=runtime_pattern",
        headers=headers,
    )
    assert remediations_low_threshold.status_code == 200, remediations_low_threshold.text
    assert int(remediations_low_threshold.json()["total"]) > baseline_runtime_pattern_remediations


def test_runtime_recommendation_payload_contains_cross_session_and_feedback_loop(
    test_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-feedback-loop@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    monkeypatch.setattr(runtime_normalizer.settings, "runtime_intelligence_repeat_threshold", 2)
    monkeypatch.setattr(runtime_normalizer.settings, "runtime_remediation_confidence_threshold", 0.4)

    for _ in range(3):
        response = client.post(
            "/telemetry/browser",
            headers=headers,
            json={
                "event_type": "prompt_blocked",
                "domain": "chat.openai.com",
                "url": "https://chat.openai.com",
                "action_taken": "block",
                "severity": "high",
                "input_signal_types": ["prompt_injection"],
                "prompt_preview_redacted": "ignored and redacted",
            },
        )
        assert response.status_code == 200, response.text

    remediations = client.get(
        "/findings/remediations?page=1&page_size=100&source_trigger_type=runtime_pattern",
        headers=headers,
    )
    assert remediations.status_code == 200, remediations.text
    remediation_items = remediations.json()["items"]
    assert len(remediation_items) >= 1
    prompt_scoped_item = next(
        (
            item
            for item in remediation_items
            if str(dict(dict(item.get("rollback_payload") or {}).get("context") or {}).get("reason_code") or "")
            == "repeated_prompt_blocks"
        ),
        None,
    )
    selected_item = prompt_scoped_item or remediation_items[0]
    applied_item = selected_item if str(selected_item.get("status") or "").lower() == "applied" else None
    if applied_item is not None:
        feedback_action = client.post(
            f"/findings/remediations/{applied_item['id']}/rollback",
            headers=headers,
            json={"justification": "mark as false positive for feedback-loop test"},
        )
        assert feedback_action.status_code == 200, feedback_action.text
    else:
        proposed_item = selected_item
        feedback_action = client.post(
            f"/findings/remediations/{proposed_item['id']}/reject",
            headers=headers,
            json={"justification": "mark as false positive for feedback-loop test"},
        )
        assert feedback_action.status_code == 200, feedback_action.text

    for _ in range(4):
        response = client.post(
            "/telemetry/browser",
            headers=headers,
            json={
                "event_type": "prompt_blocked",
                "domain": "chat.openai.com",
                "url": "https://chat.openai.com",
                "action_taken": "block",
                "severity": "high",
                "input_signal_types": ["prompt_injection"],
                "prompt_preview_redacted": "ignored and redacted",
            },
        )
        assert response.status_code == 200, response.text

    recommendations = client.get("/runtime-intelligence/recommendations?page=1&page_size=200", headers=headers)
    assert recommendations.status_code == 200, recommendations.text
    items = recommendations.json()["items"]
    assert len(items) >= 1
    all_scores = [float(dict(item.get("payload") or {}).get("decision_impact_score") or 0.0) for item in items]
    assert all_scores == sorted(all_scores, reverse=True)
    prompt_items = [item for item in items if str(item.get("reason_code") or "") == "repeated_prompt_blocks"]
    assert prompt_items
    payload = max(
        [item["payload"] for item in prompt_items],
        key=lambda item: int(dict(item.get("cross_session") or {}).get("pattern_frequency") or 0),
    )

    assert float(payload.get("confidence_score") or 0.0) >= float(payload.get("confidence_threshold") or 0.0)
    assert bool(payload.get("confidence_gate_passed")) is True
    assert float(payload.get("decision_impact_score") or 0.0) >= 0.0
    decision_impact = dict(payload.get("decision_impact") or {})
    assert decision_impact
    assert float(decision_impact.get("estimated_risk_reduction") or 0.0) >= 0.0
    assert float(decision_impact.get("base_risk") or 0.0) >= 0.0
    assert 0.0 <= float(decision_impact.get("confidence") or 0.0) <= 1.0

    cross_session = dict(payload.get("cross_session") or {})
    assert int(cross_session.get("pattern_frequency") or 0) >= 4
    assert bool(cross_session.get("is_long_term_pattern")) is True
    assert int(cross_session.get("escalation_level") or 0) >= 1

    remediation_suggestions = [item for item in (payload.get("remediation_suggestions") or []) if isinstance(item, dict)]
    assert remediation_suggestions
    categories = {str(item.get("category") or "") for item in remediation_suggestions}
    assert "policy_change" in categories

    feedback = dict(payload.get("feedback_loop") or {})
    assert int(feedback.get("sample_size") or 0) >= 1
    false_positive_rate = float(feedback.get("false_positive_rate") or 0.0)
    effectiveness_rate = float(feedback.get("effectiveness_rate") or 0.0)
    assert 0.0 <= false_positive_rate <= 1.0
    assert 0.0 <= effectiveness_rate <= 1.0


def test_runtime_patterns_detect_unusual_tool_sequences(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-patterns-sequence@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")

    sequence_payloads = [
        {"tool_name": "tool-alpha", "decision": "warn"},
        {"tool_name": "tool-beta", "decision": "warn"},
        {"tool_name": "tool-gamma", "decision": "warn"},
    ]
    for idx, payload in enumerate(sequence_payloads):
        response = client.post(
            "/monitoring/signals",
            headers=headers,
            json={
                "ai_system_id": ai_system_id,
                "signal_type": "connector.runtime.tool_sequence",
                "severity": "med",
                "payload": {
                    "user_id": "owner",
                    "ai_tool": payload["tool_name"],
                    "tool_name": payload["tool_name"],
                    "tool_invoked": True,
                    "tool_category": "assistant",
                    "decision": payload["decision"],
                    "api_endpoint": f"https://api.example.internal/{idx}",
                },
            },
        )
        assert response.status_code == 200, response.text

    patterns = client.get(
        "/runtime/patterns?page=1&page_size=100&type_filter=unusual_tool_sequences",
        headers=headers,
    )
    assert patterns.status_code == 200, patterns.text
    payload = patterns.json()
    assert payload["total"] >= 1
    assert any(int(item.get("frequency") or 0) >= 2 for item in payload["items"])

    triggers = client.get(
        "/runtime-intelligence/triggers?page=1&page_size=100&reason_code=unusual_tool_sequences",
        headers=headers,
    )
    assert triggers.status_code == 200, triggers.text
    assert triggers.json()["total"] >= 1
    assert any(item["target_pack"] == "tool_abuse_pack" for item in triggers.json()["items"])


def test_runtime_patterns_ignore_local_placeholder_browser_tool_noise(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-patterns-placeholder-noise@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    noise_payloads = [
        {
            "event_type": "extension_health_status",
            "source_surface": "browser_extension",
            "tool_name": "browser_extension",
            "domain": "extension.local",
            "operational_telemetry": True,
            "suppress_anomaly_detection": True,
        },
        {
            "event_type": "browser_interaction",
            "source_surface": "browser",
            "tool_name": "unknown_tool",
            "domain": "localhost",
            "api_endpoint": "http://localhost:3000/dashboard/command-center",
        },
        {
            "event_type": "browser_interaction",
            "source_surface": "browser",
            "tool_name": "localhost",
            "domain": "127.0.0.1",
            "api_endpoint": "http://127.0.0.1:8000/health",
        },
    ]
    for payload in noise_payloads:
        response = client.post(
            "/monitoring/signals",
            headers=headers,
            json={
                "ai_system_id": None,
                "signal_type": "connector.runtime.tool_sequence",
                "severity": "med",
                "payload": {
                    "user_id": "owner",
                    "decision": "allow",
                    **payload,
                },
            },
        )
        assert response.status_code == 200, response.text

    patterns = client.get(
        "/runtime/patterns?page=1&page_size=100&type_filter=unusual_tool_sequences",
        headers=headers,
    )
    assert patterns.status_code == 200, patterns.text
    assert patterns.json()["total"] == 0

    triggers = client.get(
        "/runtime-intelligence/triggers?page=1&page_size=100&reason_code=unusual_tool_sequences",
        headers=headers,
    )
    assert triggers.status_code == 200, triggers.text
    assert triggers.json()["total"] == 0


def test_governance_recommendations_do_not_auto_mutate_ai_system(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-recommendations@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")

    for _ in range(3):
        response = client.post(
            "/telemetry/browser",
            headers=headers,
            json={
                "event_type": "prompt_blocked",
                "domain": "chat.openai.com",
                "url": "https://chat.openai.com",
                "action_taken": "block",
                "severity": "high",
                "input_signal_types": ["prompt_injection"],
                "prompt_preview_redacted": "ignored and redacted",
                "ai_system_id": ai_system_id,
            },
        )
        assert response.status_code == 200, response.text

    recommendations = client.get("/runtime-intelligence/recommendations?page=1&page_size=100", headers=headers)
    assert recommendations.status_code == 200, recommendations.text
    assert recommendations.json()["total"] >= 1

    ai_system = client.get(f"/ai-systems/{ai_system_id}", headers=headers)
    assert ai_system.status_code == 200, ai_system.text
    assert ai_system.json()["risk_tier"] == "LOW"


def test_sensitive_multi_tool_and_agent_chain_correlation_generates_findings_and_recommendations(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-advanced-correlation@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")

    sensitive_payloads: list[dict[str, Any]] = [
        {
            "ai_tool": "tool-a",
            "tool_name": "tool-a",
            "tool_invoked": True,
            "tool_category": "chat",
            "user_id": "owner",
            "decision": "block",
            "input_signal_types": ["sensitive_data_pattern"],
            "data_source": "finance_sheet",
            "data_classification": "restricted",
        },
        {
            "ai_tool": "tool-b",
            "tool_name": "tool-b",
            "tool_invoked": True,
            "tool_category": "assistant",
            "user_id": "owner",
            "decision": "warn",
            "input_signal_types": ["sensitive_data_pattern"],
            "data_source": "finance_sheet",
            "data_classification": "restricted",
        },
        {
            "ai_tool": "tool-b",
            "tool_name": "tool-b",
            "tool_invoked": True,
            "tool_category": "assistant",
            "user_id": "owner",
            "decision": "hold_for_approval",
            "input_signal_types": ["sensitive_data_pattern"],
            "data_source": "finance_sheet",
            "data_classification": "restricted",
        },
    ]
    for payload in sensitive_payloads:
        response = client.post(
            "/monitoring/signals",
            headers=headers,
            json={
                "ai_system_id": ai_system_id,
                "signal_type": "connector.runtime.data_transfer",
                "severity": "high",
                "payload": payload,
            },
        )
        assert response.status_code == 200, response.text

    for _ in range(2):
        response = client.post(
            "/monitoring/signals",
            headers=headers,
            json={
                "ai_system_id": ai_system_id,
                "signal_type": "connector.runtime.agent_chain",
                "severity": "high",
                "payload": {
                    "user_id": "owner",
                    "agent_id": "agent-child-1",
                    "parent_agent_id": "agent-parent-1",
                    "chain_depth": 5,
                    "tool_name": "tool-c",
                    "decision": "warn",
                },
            },
        )
        assert response.status_code == 200, response.text

    findings = client.get("/runtime-intelligence/findings?page=1&page_size=200", headers=headers)
    assert findings.status_code == 200, findings.text
    finding_types = {item["finding_type"] for item in findings.json()["items"]}
    assert "repeated_sensitive_data_attempts" in finding_types
    assert "multi_tool_data_exposure" in finding_types
    assert "abnormal_agent_chains" in finding_types

    triggers = client.get("/runtime-intelligence/triggers?page=1&page_size=200", headers=headers)
    assert triggers.status_code == 200, triggers.text
    trigger_reasons = {item["reason_code"] for item in triggers.json()["items"]}
    assert "repeated_sensitive_data_uploads" in trigger_reasons
    assert "multi_tool_data_exposure" in trigger_reasons
    assert "abnormal_agent_chains" in trigger_reasons

    recommendations = client.get("/runtime-intelligence/recommendations?page=1&page_size=200", headers=headers)
    assert recommendations.status_code == 200, recommendations.text
    payloads = [item["payload"] for item in recommendations.json()["items"]]
    multi_tool_payload = next(
        (item for item in payloads if str(item.get("finding_type") or "") == "multi_tool_data_exposure"),
        None,
    )
    abnormal_chain_payload = next(
        (item for item in payloads if str(item.get("finding_type") or "") == "abnormal_agent_chains"),
        None,
    )
    assert multi_tool_payload is not None
    assert abnormal_chain_payload is not None

    multi_tool_categories = {
        str(suggestion.get("category") or "")
        for suggestion in list(multi_tool_payload.get("remediation_suggestions") or [])
        if isinstance(suggestion, dict)
    }
    assert "policy_change" in multi_tool_categories
    assert "system_restriction" in multi_tool_categories


def test_repeated_denied_tool_actions_generate_findings_triggers_and_recommendations(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-tool-denials@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")
    _agent_id, token = _create_agent_and_token(
        client,
        headers=headers,
        ai_system_id=ai_system_id,
        scope="tool.read",
    )

    for idx in range(3):
        denied = client.post(
            "/gateway/mcp/authorize",
            headers=headers,
            json={
                "ai_system_id": ai_system_id,
                "actor_id": "agent-ui",
                "capability_token": token,
                "action": "tool.write",
                "resource": f"crm/customer/{idx}",
                "chain_depth": 1,
                "request_id": f"ri-tool-deny-{idx}",
                "provider": "openai",
                "model": "gpt-4.1-mini",
                "model_version": "2026-03",
                "tool_name": "crm_writer",
                "tool_category": "mcp_tool",
                "api_endpoint": "mcp://crm/write",
                "data_source": "crm",
                **_mcp_session_payload(
                    agent_id=_agent_id,
                    user_id="owner",
                    session_id=f"ri-tool-deny-session-{idx}",
                    max_chain_depth=3,
                    connected_systems=["crm"],
                ),
            },
        )
        assert denied.status_code == 200, denied.text
        assert denied.json()["decision"] == "block"

    findings = client.get(
        "/runtime-intelligence/findings?page=1&page_size=100&finding_type=repeated_tool_denials",
        headers=headers,
    )
    assert findings.status_code == 200, findings.text
    assert findings.json()["total"] >= 1

    triggers = client.get(
        "/runtime-intelligence/triggers?page=1&page_size=100&reason_code=repeated_denied_tool_calls",
        headers=headers,
    )
    assert triggers.status_code == 200, triggers.text
    assert triggers.json()["total"] >= 1
    assert any(item["target_pack"] == "tool_abuse_pack" for item in triggers.json()["items"])

    recommendations = client.get("/runtime-intelligence/recommendations?page=1&page_size=100", headers=headers)
    assert recommendations.status_code == 200, recommendations.text
    payloads = [item["payload"] for item in recommendations.json()["items"]]
    tool_payload = next(
        (item for item in payloads if str(item.get("finding_type") or "") == "repeated_tool_denials"),
        None,
    )
    assert tool_payload is not None
    tool_categories = {
        str(suggestion.get("category") or "")
        for suggestion in list(tool_payload.get("remediation_suggestions") or [])
        if isinstance(suggestion, dict)
    }
    assert "permission_reduction" in tool_categories
    assert "policy_change" in tool_categories


def test_agent_session_and_over_scope_correlations_generate_runtime_findings(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-agent-session-over-scope@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")
    agent_id, token = _create_agent_and_token(
        client,
        headers=headers,
        ai_system_id=ai_system_id,
        scope="tool.run",
    )

    missing_session = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_id": agent_id,
            "capability_token": token,
            "action": "tool.run",
            "resource": "kb/internal/read",
            "chain_depth": 1,
            "request_id": "ri-session-anomaly-1",
            "tool_name": "kb_runner",
            "tool_category": "mcp_tool",
            "api_endpoint": "mcp://kb/run",
            "data_source": "knowledge_base",
        },
    )
    assert missing_session.status_code == 200, missing_session.text
    assert missing_session.json()["decision"] == "block"
    assert missing_session.json()["reason"] == "agent_session_required"

    over_scope = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_id": agent_id,
            "capability_token": token,
            "action": "tool.run",
            "resource": "finance.internal.acme.ai",
            "chain_depth": 2,
            "request_id": "ri-over-scope-1",
            "tool_name": "finance_executor",
            "tool_category": "mcp_tool",
            "api_endpoint": "mcp://finance/run",
            "data_source": "finance_system",
            **_mcp_session_payload(
                agent_id=agent_id,
                user_id="owner",
                session_id="ri-over-scope-session-1",
                max_chain_depth=1,
                connected_systems=["kb.internal"],
            ),
            "dynamic_permission": {
                "identity_id": agent_id,
                "allowed_tools": ["*"],
                "allowed_actions": ["*"],
                "allowed_data_scope": ["unknown", "internal"],
                "context": {
                    "max_chain_depth": 1,
                    "connected_systems": ["kb.internal"],
                },
                "expiry": (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(),
            },
        },
    )
    assert over_scope.status_code == 200, over_scope.text
    assert over_scope.json()["decision"] == "block"

    session_findings = client.get(
        "/runtime-intelligence/findings?page=1&page_size=100&finding_type=AGENT_SESSION_ANOMALY",
        headers=headers,
    )
    assert session_findings.status_code == 200, session_findings.text
    assert session_findings.json()["total"] >= 1

    over_scope_findings = client.get(
        "/runtime-intelligence/findings?page=1&page_size=100&finding_type=AGENT_OVER_SCOPE_RISK",
        headers=headers,
    )
    assert over_scope_findings.status_code == 200, over_scope_findings.text
    assert over_scope_findings.json()["total"] >= 1


def test_asymmetry_spikes_generate_findings_triggers_and_recommendations(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-asymmetry-spike@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="HIGH")

    for idx in range(2):
        response = client.post(
            "/gateway/llm/intercept",
            headers=headers,
            json={
                "ai_system_id": ai_system_id,
                "actor_type": "human",
                "actor_id": "owner",
                "request_id": f"ri-asymmetry-{idx}",
                "prompt": "ok",
                "context_summary": "asymmetry spike",
                "attachments_meta": [{"tool_calls": ["a", "b", "c", "d", "e"]}],
                "tool_output": "x" * 2600,
                "provider": "openai",
                "model": "gpt-4.1",
                "model_version": "2026-03",
                "tool_name": "assistant_tool",
                "tool_category": "assistant",
                "api_endpoint": "https://api.openai.com/v1/responses",
                "data_source": "internal_notes",
            },
        )
        assert response.status_code == 200, response.text

    findings = client.get(
        "/runtime-intelligence/findings?page=1&page_size=100&finding_type=asymmetry_risk_spike",
        headers=headers,
    )
    assert findings.status_code == 200, findings.text
    assert findings.json()["total"] >= 1

    triggers = client.get(
        "/runtime-intelligence/triggers?page=1&page_size=100&reason_code=asymmetry_spike",
        headers=headers,
    )
    assert triggers.status_code == 200, triggers.text
    assert triggers.json()["total"] >= 1
    assert any(item["target_pack"] == "data_leakage_pack" for item in triggers.json()["items"])

    recommendations = client.get("/runtime-intelligence/recommendations?page=1&page_size=100", headers=headers)
    assert recommendations.status_code == 200, recommendations.text
    payloads = [item["payload"] for item in recommendations.json()["items"]]
    assert any(str(item.get("finding_type") or "") == "asymmetry_risk_spike" for item in payloads)


def test_runtime_intelligence_disabled_does_not_block_gateway_enforcement(
    monkeypatch: pytest.MonkeyPatch,
    test_env,
) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-disabled-nonblocking@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")

    baseline = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "owner",
            "request_id": "ri-enabled-req-1",
            "prompt": "hello deterministic runtime check",
            "context_summary": "ri enabled baseline",
            "attachments_meta": [],
            "provider": "openai",
            "model": "gpt-4.1",
            "model_version": "2026-03",
        },
    )
    assert baseline.status_code == 200, baseline.text
    baseline_decision = baseline.json()["final_decision"]

    events_before_disable = client.get("/runtime-intelligence/events?page=1&page_size=100", headers=headers)
    assert events_before_disable.status_code == 200, events_before_disable.text
    count_before_disable = int(events_before_disable.json()["total"])

    monkeypatch.setattr(runtime_normalizer.settings, "runtime_intelligence_enabled", False)

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "owner",
            "request_id": "ri-disabled-req-2",
            "prompt": "hello deterministic runtime check",
            "context_summary": "ri disabled should not block enforcement path",
            "attachments_meta": [],
            "provider": "openai",
            "model": "gpt-4.1",
            "model_version": "2026-03",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["final_decision"] == baseline_decision

    events = client.get("/runtime-intelligence/events?page=1&page_size=10", headers=headers)
    assert events.status_code == 200, events.text
    assert int(events.json()["total"]) == count_before_disable


def test_multi_step_agent_chain_is_reconstructable_via_runtime_chain_api(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-chain-tree@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")
    agent_id, token = _create_agent_and_token(
        client,
        headers=headers,
        ai_system_id=ai_system_id,
        scope="tool.read",
    )

    chain_id = "ri-chain-demo-1"
    context_id = "ri-context-demo-1"
    first_request_id = "ri-chain-step-1"
    second_request_id = "ri-chain-step-2"

    first = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_id": agent_id,
            "capability_token": token,
            "action": "tool.read",
            "resource": "kb/article/1",
            "chain_depth": 1,
            "request_id": first_request_id,
            "context_id": context_id,
            "chain_id": chain_id,
            "tool_name": "kb_reader",
            "tool_category": "mcp_tool",
            "api_endpoint": "mcp://kb/read",
            "data_source": "knowledge_base",
            **_mcp_session_payload(
                agent_id=agent_id,
                user_id="owner",
                session_id="ri-chain-session-1",
                max_chain_depth=3,
                connected_systems=["kb"],
            ),
        },
    )
    assert first.status_code == 200, first.text

    second = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_id": agent_id,
            "capability_token": token,
            "action": "tool.read",
            "resource": "kb/article/2",
            "chain_depth": 2,
            "request_id": second_request_id,
            "context_id": context_id,
            "chain_id": chain_id,
            "parent_action_id": first_request_id,
            "tool_name": "kb_reader",
            "tool_category": "mcp_tool",
            "api_endpoint": "mcp://kb/read",
            "data_source": "knowledge_base",
            **_mcp_session_payload(
                agent_id=agent_id,
                user_id="owner",
                session_id="ri-chain-session-1",
                max_chain_depth=3,
                connected_systems=["kb"],
            ),
        },
    )
    assert second.status_code == 200, second.text

    chain_graph = client.get(f"/runtime/chain/{chain_id}", headers=headers)
    assert chain_graph.status_code == 200, chain_graph.text
    chain_payload = chain_graph.json()
    assert isinstance(chain_payload["nodes"], list)
    assert isinstance(chain_payload["edges"], list)
    assert float(chain_payload["risk_score"]) >= 0.0
    assert any(edge.get("relation_type") == "context.parent_action" for edge in chain_payload["edges"])

    events = client.get("/runtime-intelligence/events?page=1&page_size=200", headers=headers)
    assert events.status_code == 200, events.text
    chain_events = [item for item in events.json()["items"] if item.get("chain_id") == chain_id]
    assert len(chain_events) >= 2
    assert any(str(item.get("parent_action_id") or "") == first_request_id for item in chain_events)


def test_nested_tool_calls_build_context_graph_with_expected_relations(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-context-graph@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="MEDIUM")

    context_id = "ri-context-nested-1"
    chain_id = "ri-chain-nested-1"

    first_signal = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "connector.runtime.agent_tool_call",
            "severity": "high",
            "payload": {
                "source_surface": "connector",
                "event_type": "agent_tool_call",
                "user_id": "owner",
                "agent_id": "agent-nested-1",
                "tool_name": "sql_runner",
                "tool_category": "data_access",
                "target_resource": "warehouse.customer_table",
                "decision": "warn",
                "data_classification": "restricted",
                "context_id": context_id,
                "chain_id": chain_id,
                "entity_type": "agent",
                "entity_id": "agent-nested-1",
            },
        },
    )
    assert first_signal.status_code == 200, first_signal.text

    second_signal = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "connector.runtime.agent_tool_call",
            "severity": "high",
            "payload": {
                "source_surface": "connector",
                "event_type": "agent_tool_call",
                "user_id": "owner",
                "agent_id": "agent-nested-1",
                "tool_name": "api_uploader",
                "tool_category": "egress",
                "target_resource": "https://external-upload.example/api",
                "decision": "block",
                "data_classification": "restricted",
                "context_id": context_id,
                "chain_id": chain_id,
                "parent_action_id": "agent_tool_call_root",
                "entity_type": "agent",
                "entity_id": "agent-nested-1",
            },
        },
    )
    assert second_signal.status_code == 200, second_signal.text

    context_graph = client.get(f"/runtime/context/{context_id}", headers=headers)
    assert context_graph.status_code == 200, context_graph.text
    graph_payload = context_graph.json()
    assert isinstance(graph_payload["nodes"], list)
    assert isinstance(graph_payload["edges"], list)
    relation_types = {str(edge.get("relation_type")) for edge in graph_payload["edges"]}
    assert "context.user_to_agent" in relation_types
    assert "context.agent_to_tool" in relation_types
    assert "context.tool_to_resource" in relation_types
    assert float(graph_payload["risk_score"]) > 0.0


def test_context_graph_compacts_long_resource_entity_ids(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="ri-long-resource@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="MEDIUM")
    context_id = "ri-context-long-resource"
    long_resource = (
        "https://www.google.com/search?q=weather+query+with+very+long+browser+url"
        "&sca_esv=pilot-new-tab-page&source=hp&ei=very-long-value"
        "&ved=0ahUKEwi-long-long-long-long-long-long-long-long-long"
    )
    assert len(long_resource) > 128

    signal = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "connector.runtime.agent_tool_call",
            "severity": "med",
            "payload": {
                "source_surface": "browser",
                "event_type": "browser_interaction",
                "user_id": "owner",
                "agent_id": "agent-long-resource",
                "tool_name": "browser",
                "tool_category": "browser",
                "target_resource": long_resource,
                "decision": "allow",
                "context_id": context_id,
                "chain_id": context_id,
                "entity_type": "agent",
                "entity_id": "agent-long-resource",
            },
        },
    )
    assert signal.status_code == 200, signal.text

    with session_factory() as db:
        resource_node = (
            db.query(ContextNode)
            .filter(
                ContextNode.tenant_id == owner["tenant_id"],
                ContextNode.context_id == context_id,
                ContextNode.type == "resource",
            )
            .one()
        )
        assert len(resource_node.entity_id) <= 128
        assert resource_node.entity_id.startswith("resource:")
        assert resource_node.metadata_json["raw_entity_id"] == long_resource
        assert resource_node.metadata_json["entity_id_compacted"] is True


def test_behavior_graph_labels_are_safe_for_strict_pilot_schema(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="ri-long-behavior-label@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="MEDIUM")
    long_url = (
        "https://www.google.com/search?q=hawk+pilot+runtime+graph+label+overflow"
        "&sca_esv=pilot-new-tab-page&source=hp&ei=very-long-value"
        "&ved=0ahUKEwi-long-long-long-long-long-long-long-long-long"
        "&origin=chrome-new-tab-page&some_parameter=extra-long-browser-navigation-context"
    )
    assert len(long_url) > 128

    signal = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "connector.runtime.agent_tool_call",
            "severity": "med",
            "payload": {
                "source_surface": "browser",
                "event_type": "browser_interaction",
                "user_id": "owner",
                "agent_id": "agent-long-behavior-label",
                "tool_name": "browser",
                "tool_category": "browser",
                "api_endpoint": long_url,
                "data_source": long_url,
                "target_resource": long_url,
                "decision": "allow",
                "entity_type": "agent",
                "entity_id": "agent-long-behavior-label",
            },
        },
    )
    assert signal.status_code == 200, signal.text

    with session_factory() as db:
        edges = db.scalars(
            select(RuntimeBehaviorEdge).where(RuntimeBehaviorEdge.tenant_id == owner["tenant_id"])
        ).all()
        assert edges
        assert all(len(edge.source_node_id) <= 128 for edge in edges)
        assert all(len(edge.target_node_id) <= 128 for edge in edges)
        assert all(len(edge.source_node_label or "") <= 128 for edge in edges)
        assert all(len(edge.target_node_label or "") <= 128 for edge in edges)


def _parse_sse_message(raw: str) -> tuple[str, dict[str, Any]]:
    message = str(raw or "").strip()
    if not message or message.startswith(":"):
        return "", {}
    event_name = ""
    data_lines: list[str] = []
    for line in message.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(":"):
            continue
        if stripped.startswith("event:"):
            event_name = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("data:"):
            data_lines.append(stripped.split(":", 1)[1].strip())
    payload = {}
    if data_lines:
        payload = dict(json.loads("\n".join(data_lines)) or {})
    return event_name, payload


def _next_broker_event(stream, *, expected_event: str, max_messages: int = 200) -> dict[str, Any]:
    for _ in range(max_messages):
        event_name, payload = _parse_sse_message(next(stream))
        if event_name == expected_event:
            return payload
    raise AssertionError(f"did not observe broker stream event {expected_event}")


def test_runtime_intelligence_sse_connection_established(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-sse-connected@example.com")
    stream = runtime_streaming._BROKER.stream(
        tenant_id=owner["tenant_id"],
        channel="overview",
        heartbeat_seconds=0.05,
    )
    try:
        payload = _next_broker_event(stream, expected_event="runtime.stream.connected")
        assert payload["event_type"] == "runtime.stream.connected"
        assert payload["tenant_id"] == owner["tenant_id"]
        assert payload["payload"]["channel"] == "overview"
    finally:
        stream.close()


def test_runtime_intelligence_sse_activity_and_chain_updates_are_streamed(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-sse-activity@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    overview_stream = runtime_streaming._BROKER.stream(
        tenant_id=owner["tenant_id"],
        channel="overview",
        heartbeat_seconds=0.05,
    )
    chain_stream = runtime_streaming._BROKER.stream(
        tenant_id=owner["tenant_id"],
        channel="chains",
        heartbeat_seconds=0.05,
    )
    try:
        _ = _next_broker_event(overview_stream, expected_event="runtime.stream.connected")
        _ = _next_broker_event(chain_stream, expected_event="runtime.stream.connected")

        browser = client.post(
            "/telemetry/browser",
            headers=headers,
            json={
                "event_type": "unknown_ai_detected",
                "domain": "streaming-ai.example",
                "url": "https://streaming-ai.example/chat",
                "action_taken": "discover",
                "severity": "high",
                "chain_id": "ri-sse-chain-2",
                "context_id": "ri-sse-context-2",
            },
        )
        assert browser.status_code == 200, browser.text

        activity = _next_broker_event(overview_stream, expected_event="runtime.activity.created")
        assert activity["event_type"] == "runtime.activity.created"
        assert activity["tenant_id"] == owner["tenant_id"]
        assert str(activity["payload"].get("event_id") or "").strip()

        chain = _next_broker_event(chain_stream, expected_event="runtime.chain.updated")
        assert chain["event_type"] == "runtime.chain.updated"
        assert str(chain["payload"].get("chain_id") or "").strip()
        assert str(chain["payload"].get("event_id") or "").strip()
    finally:
        overview_stream.close()
        chain_stream.close()


def test_runtime_intelligence_sse_pattern_stream_emits_detected_pattern(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-sse-patterns@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    pattern_stream = runtime_streaming._BROKER.stream(
        tenant_id=owner["tenant_id"],
        channel="patterns",
        heartbeat_seconds=0.05,
    )
    try:
        _ = _next_broker_event(pattern_stream, expected_event="runtime.stream.connected")

        for _ in range(3):
            response = client.post(
                "/telemetry/browser",
                headers=headers,
                json={
                    "event_type": "prompt_blocked",
                    "domain": "chat.openai.com",
                    "url": "https://chat.openai.com",
                    "action_taken": "block",
                    "severity": "high",
                    "input_signal_types": ["prompt_injection"],
                    "prompt_preview_redacted": "ignored and redacted",
                },
            )
            assert response.status_code == 200, response.text

        pattern = _next_broker_event(pattern_stream, expected_event="runtime.pattern.detected")
        assert pattern["event_type"] == "runtime.pattern.detected"
        assert str(pattern["payload"].get("pattern_id") or "").strip()
        assert str(pattern["payload"].get("type") or "").strip()
    finally:
        pattern_stream.close()


def test_runtime_intelligence_sse_reconnect_recovers_and_receives_new_events(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-sse-reconnect@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    first_stream = runtime_streaming._BROKER.stream(
        tenant_id=owner["tenant_id"],
        channel="activity",
        heartbeat_seconds=0.05,
    )
    connected = _next_broker_event(first_stream, expected_event="runtime.stream.connected")
    assert connected["payload"]["channel"] == "activity"
    first_stream.close()

    second_stream = runtime_streaming._BROKER.stream(
        tenant_id=owner["tenant_id"],
        channel="activity",
        heartbeat_seconds=0.05,
    )
    try:
        _ = _next_broker_event(second_stream, expected_event="runtime.stream.connected")

        browser = client.post(
            "/telemetry/browser",
            headers=headers,
            json={
                "event_type": "unknown_ai_detected",
                "domain": "reconnect-ai.example",
                "url": "https://reconnect-ai.example/chat",
                "action_taken": "discover",
                "severity": "high",
            },
        )
        assert browser.status_code == 200, browser.text

        event_payload = _next_broker_event(second_stream, expected_event="runtime.activity.created")
        assert event_payload["event_type"] == "runtime.activity.created"
        assert str(event_payload["payload"].get("event_id") or "").strip()
    finally:
        second_stream.close()


def test_runtime_processing_stays_non_blocking_when_stream_publish_fails(
    monkeypatch: pytest.MonkeyPatch,
    test_env,
) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-stream-down-nonblocking@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")

    def _raise_publish(*args, **kwargs):
        raise RuntimeError("streaming unavailable")

    monkeypatch.setattr(runtime_normalizer, "publish_runtime_update", _raise_publish)

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "owner",
            "prompt": "non-blocking stream failure check",
            "context_summary": "runtime stream failure test",
            "attachments_meta": [],
        },
    )
    assert response.status_code == 200, response.text

    events = client.get("/runtime-intelligence/events?page=1&page_size=50", headers=headers)
    assert events.status_code == 200, events.text
    assert int(events.json()["total"]) >= 1


def test_aarm_runtime_event_contains_canonical_action_and_receipt(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-aarm-canonical-action@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "owner",
            "prompt": "Summarize Q4 operating metrics",
            "context_summary": "Produce concise executive summary for Q4 operating metrics",
            "attachments_meta": [],
        },
    )
    assert response.status_code == 200, response.text

    events = client.get("/runtime-intelligence/events?page=1&page_size=100&source_surface=gateway", headers=headers)
    assert events.status_code == 200, events.text
    items = events.json()["items"]
    assert len(items) >= 1
    latest = items[0]
    metadata = dict(latest.get("metadata") or {})

    action = dict(metadata.get("canonical_action") or {})
    assert action["action_id"] == latest["event_id"]
    assert action["source_surface"] == "api"
    assert action["operation"] in {"prompt", "prompt_submission", "llm_intercept"}

    receipt = dict(metadata.get("runtime_receipt") or {})
    assert receipt["enforcement_status"] == "enforced"
    assert dict(receipt.get("action") or {}).get("action_id") == latest["event_id"]
    assert dict(receipt.get("context") or {}).get("session_id")
    assert dict(receipt.get("decision") or {}).get("decision") in {"allow", "deny", "modify", "step_up", "defer"}

    semantic_drift = dict(metadata.get("semantic_drift") or {})
    assert semantic_drift.get("available") is True
    assert 0.0 <= float(semantic_drift.get("drift_score") or 0.0) <= 1.0


def test_aarm_non_enforceable_surface_generates_simulated_policy_outcome(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-aarm-simulated-outcome@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")

    response = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "dns.prompt_injection.detected",
            "severity": "high",
            "payload": {
                "source_surface": "dns",
                "event_type": "prompt_injection_detected",
                "decision": "block",
                "reason_code": "prompt_injection_signature_detected",
                "input_signal_types": ["prompt_injection"],
                "domain": "unknown-llm.example",
                "queried_domain": "unknown-llm.example",
                "original_intent": "summarize meeting notes",
                "operation": "prompt_submission",
                "context_id": "aarm-simulated-context",
                "chain_id": "aarm-simulated-chain",
            },
        },
    )
    assert response.status_code == 200, response.text

    events = client.get(
        "/runtime-intelligence/events?page=1&page_size=100&source_surface=dns&event_type=dns.prompt_injection.detected",
        headers=headers,
    )
    assert events.status_code == 200, events.text
    assert events.json()["total"] >= 1
    metadata = dict(events.json()["items"][0].get("metadata") or {})
    assert metadata.get("enforcement_status") == "simulated"
    policy_evaluation = dict(metadata.get("policy_evaluation") or {})
    assert policy_evaluation.get("simulated") is True
    assert policy_evaluation.get("decision") == "deny"
    receipt = dict(metadata.get("runtime_receipt") or {})
    assert receipt.get("enforcement_status") == "simulated"
    assert bool(dict(receipt.get("decision") or {}).get("simulated_outcome")) is True


def test_aarm_browser_sensitive_flow_stays_enforced_and_blocked(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-aarm-browser-block@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/telemetry/browser",
        headers=headers,
        json={
            "event_type": "prompt_blocked",
            "domain": "chat.openai.com",
            "url": "https://chat.openai.com",
            "action_taken": "block",
            "severity": "high",
            "data_classification": "sensitive",
            "contains_sensitive": True,
            "input_signal_types": ["sensitive_data_pattern"],
            "reason_codes": ["sensitive_data_to_public_ai_attempt"],
            "correlation_id": "aarm-browser-sensitive-1",
        },
    )
    assert response.status_code == 200, response.text

    events = client.get(
        "/runtime-intelligence/events?page=1&page_size=100&source_surface=browser&correlation_id=aarm-browser-sensitive-1",
        headers=headers,
    )
    assert events.status_code == 200, events.text
    assert events.json()["total"] >= 1
    metadata = dict(events.json()["items"][0].get("metadata") or {})
    assert metadata.get("enforcement_status") == "enforced"
    assert dict(metadata.get("policy_evaluation") or {}).get("decision") == "deny"
    assert dict(metadata.get("runtime_receipt") or {}).get("enforcement_status") == "enforced"


def test_runtime_event_fallback_policy_mapping_preserves_legacy_deny(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="ri-legacy-deny-fallback@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    correlation_id = "ri-legacy-deny-fallback-1"

    with session_factory() as db:
        db.add(
            RuntimeEvent(
                tenant_id=owner["tenant_id"],
                source_surface="connector",
                event_type="legacy.policy.decision",
                correlation_id=correlation_id,
                metadata_json={
                    "decision": "deny",
                    # Intentionally omit policy_evaluation to exercise router fallback mapping.
                },
            )
        )
        db.commit()

    events = client.get(
        f"/runtime-intelligence/events?page=1&page_size=20&correlation_id={correlation_id}",
        headers=headers,
    )
    assert events.status_code == 200, events.text
    assert int(events.json()["total"]) >= 1
    metadata = dict(events.json()["items"][0].get("metadata") or {})
    policy_evaluation = dict(metadata.get("policy_evaluation") or {})
    assert policy_evaluation.get("decision") == "deny"
    assert policy_evaluation.get("classification") == "forbidden"


def test_aarm_context_graph_includes_session_summary_and_semantic_drift(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ri-aarm-context-graph@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")

    context_id = "aarm-session-context-1"
    chain_id = "aarm-session-chain-1"

    first = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "connector.runtime.session.step1",
            "severity": "low",
            "payload": {
                "source_surface": "connector",
                "operation": "prompt_submission",
                "tool_name": "crm-assistant",
                "api_endpoint": "https://ai.crm.internal/query",
                "data_source": "crm_finance_data",
                "original_intent": "summarize quarterly finance data for executive review",
                "context_id": context_id,
                "chain_id": chain_id,
                "user_id": "owner",
            },
        },
    )
    assert first.status_code == 200, first.text

    second = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "connector.runtime.session.step2",
            "severity": "high",
            "payload": {
                "source_surface": "connector",
                "operation": "tool_execution",
                "tool_name": "db-admin-tool",
                "api_endpoint": "https://db.internal/delete",
                "target_resource": "finance_prod_table",
                "reason_code": "unexpected_destructive_operation",
                "context_id": context_id,
                "chain_id": chain_id,
                "parent_action_id": "manual-parent-action",
                "user_id": "owner",
            },
        },
    )
    assert second.status_code == 200, second.text

    context_graph = client.get(f"/runtime/context/{context_id}", headers=headers)
    assert context_graph.status_code == 200, context_graph.text
    payload = context_graph.json()
    summary = dict(payload.get("context") or {})
    assert summary.get("session_id") == context_id
    assert isinstance(summary.get("actions"), list)
    assert len(summary.get("actions") or []) >= 2
    assert "crm-assistant" in list(summary.get("tools_used") or [])
    semantic_drift = dict(summary.get("semantic_drift") or {})
    assert float(semantic_drift.get("max_drift") or 0.0) >= 0.0
    assert bool(semantic_drift.get("threshold_breach")) is True
    assert "unexpected_destructive_operation" in list(summary.get("risk_signals") or [])
