from __future__ import annotations

import os

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.session import Base, get_db
from app.main import app


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "deployment_coverage.sqlite3"
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


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Coverage Owner"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    return {
        "access_token": payload["access_token"],
        "tenant_id": payload["tenants"][0]["id"],
    }


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "X-Tenant-ID": tenant_id,
    }


def _create_ai_system(client: TestClient, *, headers: dict[str, str], risk_tier: str = "HIGH") -> str:
    created = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Coverage AI System", "description": "", "risk_tier": risk_tier},
    )
    assert created.status_code == 200, created.text
    ai_system_id = created.json()["id"]
    activated = client.patch(f"/ai-systems/{ai_system_id}", headers=headers, json={"status": "active"})
    assert activated.status_code == 200, activated.text
    return ai_system_id


def _create_policy_version(client: TestClient, *, headers: dict[str, str]) -> str:
    created = client.post(
        "/policies/packs",
        headers=headers,
        json={"name": "Coverage Pack", "description": "coverage", "status": "active"},
    )
    assert created.status_code == 200, created.text
    return created.json()["default_version"]["id"]


def test_deployment_coverage_endpoint_reports_surfaces_and_gaps(test_env) -> None:
    client: TestClient = test_env["client"]
    user = _register_owner(client, email="coverage-endpoint-owner@example.com")
    headers = _headers(user["access_token"], user["tenant_id"])

    ai_system_id = _create_ai_system(client, headers=headers)
    policy_version_id = _create_policy_version(client, headers=headers)
    low_risk_ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")

    browser = client.post(
        "/telemetry/browser",
        headers=headers,
        json={
            "browser": "chrome",
            "event_type": "unknown_ai_detected",
            "domain": "new-ai.example.ai",
            "url": "https://new-ai.example.ai/chat",
            "page_title": "New AI",
            "action_taken": "discover",
            "input_signal_types": ["domain_policy_mismatch"],
        },
    )
    assert browser.status_code == 200, browser.text

    gateway = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "coverage-user",
            "request_id": "coverage-gateway-001",
            "prompt": "Summarize policy posture",
            "context_summary": "coverage validation",
            "attachments_meta": [],
            "provider": "openai",
            "model": "gpt-4o-mini",
        },
    )
    assert gateway.status_code == 200, gateway.text

    connector = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "signal_type": "network.netskope.events",
            "severity": "high",
            "payload": {
                "provider_key": "netskope",
                "policy_version": policy_version_id,
                "record": {"domain": "api.openai.com"},
            },
        },
    )
    assert connector.status_code == 200, connector.text

    endpoint = client.post(
        "/shadow-ai/ingest/endpoint",
        headers=headers,
        json={
            "process_name": "ollama",
            "destination_domain": "localhost",
            "api_endpoint": "http://localhost:11434/api/chat",
            "host_id": "coverage-host-1",
            "bytes_sent": 1200,
            "bytes_received": 900,
        },
    )
    assert endpoint.status_code == 200, endpoint.text

    dns = client.post(
        "/shadow-ai/ingest/dns",
        headers=headers,
        json={
            "queried_domain": "api.openai.com",
            "query_count": 3,
            "source_system": "coverage-dns",
            "force_runtime": True,
        },
    )
    assert dns.status_code == 200, dns.text

    proxy = client.post(
        "/shadow-ai/ingest/proxy",
        headers=headers,
        json={
            "request_domain": "api.openai.com",
            "full_url": "https://api.openai.com/v1/responses",
            "method": "POST",
            "response_code": 200,
            "bytes_sent": 512,
            "bytes_received": 1024,
        },
    )
    assert proxy.status_code == 200, proxy.text

    created_agent = client.post(
        "/ai-iam/agents",
        headers=headers,
        json={
            "name": "Coverage Agent",
            "description": "coverage",
            "max_chain_depth": 3,
            "action_scope": ["api_call"],
            "tool_registry": ["mcp"],
        },
    )
    assert created_agent.status_code == 200, created_agent.text
    agent_id = created_agent.json()["id"]

    minted = client.post(
        f"/ai-iam/agents/{agent_id}/tokens",
        headers=headers,
        json={
            "ai_system_id": low_risk_ai_system_id,
            "scopes": ["tool.read"],
            "expires_minutes": 20,
            "chain_depth": 1,
        },
    )
    assert minted.status_code == 200, minted.text

    coverage = client.get("/coverage", headers=headers)
    assert coverage.status_code == 200, coverage.text
    payload = coverage.json()

    assert payload["tenant_id"] == user["tenant_id"]
    assert isinstance(payload["coverage_percent"], (float, int))
    assert isinstance(payload["surfaces"], list)
    assert isinstance(payload["policies_enforced"], dict)
    assert isinstance(payload.get("provider_catalog"), dict)
    assert isinstance(payload.get("observed_surface_counts"), dict)
    assert isinstance(payload.get("observed_provider_category_counts"), dict)
    assert isinstance(payload.get("observed_provider_counts"), dict)
    assert isinstance(payload.get("provider_surface_mode_counts"), dict)
    assert isinstance(payload.get("provider_blind_spots_by_category"), dict)
    assert isinstance(payload.get("coverage_by_surface_type"), dict)
    assert isinstance(payload.get("enforcement_capability"), dict)
    assert isinstance(payload["gaps"], list)

    surfaces = {row["surface"]: row for row in payload["surfaces"]}
    assert {"browser_extension", "gateway", "connectors_saas", "network_api_layer"}.issubset(set(surfaces))

    assert surfaces["browser_extension"]["observed_event_count"] > 0
    assert surfaces["gateway"]["observed_event_count"] > 0
    assert surfaces["connectors_saas"]["observed_event_count"] > 0
    assert surfaces["network_api_layer"]["observed_event_count"] > 0
    assert payload["policies_enforced"]["total_enforcement_events"] > 0
    assert payload["provider_catalog"]["supported_provider_counts"]["model_api"] >= 1
    assert "gateway" in payload["provider_catalog"]["supported_source_surfaces"]
    assert payload["observed_surface_counts"]["browser"] > 0
    assert payload["coverage_by_surface_type"]["api"] > 0
    assert payload["observed_surface_counts"]["endpoint"] > 0
    assert payload["observed_surface_counts"]["dns"] > 0
    assert payload["observed_surface_counts"]["proxy"] > 0
    assert payload["observed_surface_counts"]["aiiam"] > 0
    assert payload["coverage_by_surface_type"]["oss_local"] > 0
    assert payload["coverage_by_surface_type"]["agents"] > 0
    assert payload["observed_provider_counts"].get("openai_api", 0) > 0
    assert payload["provider_surface_mode_counts"].get("openai_api", {}).get("enforceable", 0) > 0
    assert payload["provider_surface_mode_counts"].get("openai_api", {}).get("monitoring_only", 0) > 0
    assert isinstance(payload["enforcement_capability"].get("enforcement_surface_gaps"), list)
    assert isinstance(payload["enforcement_capability"].get("monitoring_surface_gaps"), list)
