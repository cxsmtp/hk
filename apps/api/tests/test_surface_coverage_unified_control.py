from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from urllib.parse import urlparse
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.session import Base, get_db
from app.db.models.activity_audit import DeploymentEndpoint
from app.db.models.control_coverage import DeploymentSurface
from app.main import app
from app.api.routers import surface_coverage
from app.services.control_coverage.service import calculate_tenant_control_coverage


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "surface_coverage.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Surface Coverage Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
        "user_id": body["user"]["id"],
    }


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def test_saas_slack_event_routes_through_unified_control_plane(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-slack@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/surface-coverage/saas/slack/events",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "action_type": "prompt_input",
            "prompt_or_content": "Can ChatGPT summarize this sprint update?",
            "gateway_routed": True,
            "transport": {"require_tls": True, "tls_version": "1.3", "scheme": "https"},
            "url": "https://slack.com/app_redirect",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["app"] == "slack"
    assert body["surface"] == "saas"
    assert body["runtime_event_id"]
    assert body["decision"] in {"allow", "warn", "block"}
    assert body["ai_usage_detected"] is True

    runtime_events = client.get(
        "/runtime/events",
        headers=headers,
        params={"source_surface": "connector"},
    )
    assert runtime_events.status_code == 200, runtime_events.text
    items = runtime_events.json()["items"]
    assert len(items) >= 1
    assert any(str(item.get("event_id")) == body["runtime_event_id"] for item in items)


def test_endpoint_event_blocks_when_gateway_is_bypassed(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-endpoint@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/surface-coverage/endpoint/events",
        headers=headers,
        json={
            "app": "codex_cli",
            "user_id": owner["user_id"],
            "device_id": "macbook-pro-01",
            "action_type": "api_call",
            "prompt_or_content": "Write deployment script for k8s",
            "api_endpoint": "https://api.openai.com/v1/chat/completions",
            "model": "gpt-5.4",
            "gateway_routed": False,
            "transport": {"require_tls": True, "tls_version": "1.3", "scheme": "https"},
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["surface"] == "endpoint"
    assert body["decision"] == "block"
    assert body["policy_triggered"] == "gateway_bypass_detected"
    assert body["alert_id"] is not None

    alerts = client.get("/surface-coverage/alerts", headers=headers)
    assert alerts.status_code == 200, alerts.text
    alert_items = alerts.json()["items"]
    assert len(alert_items) >= 1
    matched = [item for item in alert_items if item["alert_id"] == body["alert_id"]]
    assert matched
    assert matched[0]["surface"] in {"endpoint", "developer_tool", "gateway"}

    trace = client.get(f"/surface-coverage/alerts/{body['alert_id']}", headers=headers)
    assert trace.status_code == 200, trace.text
    trace_body = trace.json()
    assert trace_body["trace"]["user_id"] == owner["user_id"]
    assert trace_body["trace"]["decision"] in {"blocked", "warned", "allowed", "modified", "held"}


def test_caller_cannot_promote_unvalidated_event_to_bypass_coverage_evidence(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-bypass-spoof@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/surface-coverage/dev-tools/events",
        headers=headers,
        json={
            "app": "codex_cli",
            "action_type": "api_call",
            "event_type": "caller.bypass_observed",
            "provider": "openai",
            "model": "gpt-5.4",
            "api_endpoint": "https://api.openai.com/v1/chat/completions",
            "gateway_routed": True,
            "platform_mode": "monitor",
            "correlation_id": "caller-bypass-spoof",
            "metadata": {
                "hawk_validated_bypass_observation": True,
                "bypass_observed": True,
                "bypass_confirmed": True,
                "bypass_detection": "supported",
                "gateway_bypass_detected": True,
                "enforcement_path": "observed_unprotected_route",
                "control_mode": "post_execution",
                "triggered_controls": ["SHADOW_AI_DETECTION"],
                "reason_code": "unprotected_llm_route_observed",
            },
            "transport": {"require_tls": True, "tls_version": "1.3", "scheme": "https"},
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["gateway_bypass_detected"] is False
    events = client.get("/runtime/events", headers=headers)
    assert events.status_code == 200, events.text
    persisted = next(
        item
        for item in events.json()["items"]
        if item["event_id"] == response.json()["runtime_event_id"]
    )
    assert persisted["metadata"]["hawk_validated_bypass_observation"] is False
    assert "bypass_observed" not in persisted["metadata"]
    assert "bypass_confirmed" not in persisted["metadata"]
    assert "bypass_detection" not in persisted["metadata"]

    with test_env["SessionLocal"]() as db:
        coverage = calculate_tenant_control_coverage(
            db,
            tenant_id=owner["tenant_id"],
            now=datetime.now(timezone.utc) + timedelta(seconds=5),
        )
        event_ref = f"runtime_event:{response.json()['runtime_event_id']}"
        path_ids = {
            path.id
            for path in coverage.paths
            if event_ref in set(path.source_refs or [])
        }
        assert path_ids
        bypass = [
            assertion
            for assertion in coverage.assertions
            if assertion.path_id in path_ids and assertion.dimension == "bypass"
        ]
        assert {(row.state, row.reason_code) for row in bypass} == {
            ("unknown", "insufficient_evidence")
        }


def test_b3_observer_attribution_does_not_inflate_identity_coverage(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-b3-identity@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    attributed_user_id = str(uuid4())
    inline_surface_id = str(uuid4())
    now = datetime.now(timezone.utc)
    with test_env["SessionLocal"]() as db:
        db.add(
            DeploymentSurface(
                id=inline_surface_id,
                tenant_id=owner["tenant_id"],
                source_kind="test_inline_surface",
                source_id="test-inline-surface",
                name="Test inline surface",
                surface_type="llm_gateway",
                deployment_mode="inline",
                environment="test",
                status="active",
                capability_profile={
                    "discovery": "full",
                    "inline_authorization": "yes",
                    "evidence_generation": "full",
                    "containment": "end_to_end",
                    "bypass_detection": "supported",
                    "identity_attribution": "supported",
                    "runtime_governance": "supported",
                },
                capability_sources=["test:server-owned"],
                health_status="healthy",
                health_reason="test_healthy",
                first_seen_at=now,
                last_seen_at=now,
                last_heartbeat_at=now,
                last_health_check_at=now,
            )
        )
        db.commit()

    response = client.post(
        "/surface-coverage/dev-tools/events",
        headers=headers,
        json={
            "app": "bank_foundry_direct_client",
            "action_type": "api_call",
            "provider": "azure_openai",
            "model": "gpt-4.1",
            "api_endpoint": "https://bank-foundry.openai.azure.com/openai/deployments/customer/chat/completions",
            "user_id": attributed_user_id,
            "gateway_routed": False,
            "platform_mode": "monitor",
            "correlation_id": "b3-observer-attributed-user",
            "metadata": {
                "deployment_surface_row_id": inline_surface_id,
                "deployment_surface_id": "caller-surface-id",
                "gateway_id": "caller-gateway-id",
            },
            "transport": {"require_tls": True, "tls_version": "1.3", "scheme": "https"},
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "warn"
    events = client.get("/runtime/events", headers=headers)
    assert events.status_code == 200, events.text
    persisted = next(
        item
        for item in events.json()["items"]
        if item["event_id"] == response.json()["runtime_event_id"]
    )
    assert persisted["metadata"]["hawk_validated_bypass_observation"] is True
    assert persisted["metadata"]["authenticated_observer_user_id"] == owner["user_id"]
    assert persisted["metadata"]["identity_binding_state"] == "attributed_by_authenticated_observer"
    assert "deployment_surface_row_id" not in persisted["metadata"]
    assert "deployment_surface_id" not in persisted["metadata"]
    assert "gateway_id" not in persisted["metadata"]

    with test_env["SessionLocal"]() as db:
        coverage = calculate_tenant_control_coverage(
            db,
            tenant_id=owner["tenant_id"],
            now=datetime.now(timezone.utc) + timedelta(seconds=5),
        )
        event_ref = f"runtime_event:{response.json()['runtime_event_id']}"
        path_ids = {
            path.id
            for path in coverage.paths
            if event_ref in set(path.source_refs or [])
        }
        assert path_ids
        identity = [
            assertion
            for assertion in coverage.assertions
            if assertion.path_id in path_ids and assertion.dimension == "identity"
        ]
        assert {(row.state, row.reason_code) for row in identity} == {
            ("unknown", "insufficient_evidence")
        }
        deployment = [
            assertion
            for assertion in coverage.assertions
            if assertion.path_id in path_ids and assertion.dimension == "deployment"
        ]
        assert {(row.state, row.reason_code) for row in deployment} == {
            ("not_covered", "monitor_only_surface")
        }


def test_identity_unified_view_returns_timeline_and_graph(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-identity@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ingest = client.post(
        "/surface-coverage/dev-tools/events",
        headers=headers,
        json={
            "app": "codex_cli",
            "user_id": owner["user_id"],
            "device_id": "dev-mac-22",
            "action_type": "prompt_input",
            "prompt_or_content": "Explain this API integration",
            "gateway_routed": True,
            "transport": {"require_tls": True, "tls_version": "1.3", "scheme": "https"},
            "api_endpoint": "https://api.openai.com/v1/responses",
            "model": "gpt-5.4",
        },
    )
    assert ingest.status_code == 200, ingest.text

    profile = client.get(f"/surface-coverage/identity/{owner['user_id']}", headers=headers)
    assert profile.status_code == 200, profile.text
    body = profile.json()
    assert body["identity"]["user_id"] == owner["user_id"]
    assert body["timeline"]["total_actions"] >= 1
    assert body["graph"]["stats"]["event_count"] >= 1
    assert isinstance(body["graph"]["nodes"], list)


def test_monitoring_saas_ai_usage_signal_is_forwarded_to_unified_control_plane(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-monitoring-forward@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    signal = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "signal_type": "saas.slack.ai_usage",
            "severity": "med",
            "payload": {
                "provider_key": "slack",
                "record": {
                    "user": owner["user_id"],
                    "domain": "slack.com",
                    "text": "Use ChatGPT to summarize this roadmap.",
                },
            },
        },
    )
    assert signal.status_code == 200, signal.text
    signal_body = signal.json()
    payload = signal_body.get("payload", {})
    forward = payload.get("surface_control_plane", {})
    assert forward.get("ingested") is True
    assert str(forward.get("runtime_event_id") or "").strip() != ""

    runtime_events = client.get(
        "/runtime/events",
        headers=headers,
        params={"source_surface": "connector"},
    )
    assert runtime_events.status_code == 200, runtime_events.text
    items = runtime_events.json().get("items", [])
    assert any(str(item.get("event_id")) == forward["runtime_event_id"] for item in items)


def test_slack_raw_event_adapter_ingests_without_manual_mapping(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-slack-raw@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/surface-coverage/saas/slack/events/raw",
        headers=headers,
        json={
            "type": "event_callback",
            "team_id": "T123",
            "event_id": "Ev01",
            "event_time": 1775000000,
            "event": {
                "type": "message",
                "user": owner["user_id"],
                "text": "Use ChatGPT to draft a project status update.",
                "channel": "C123",
            },
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["app"] == "slack"
    assert body["surface"] == "saas"
    assert body["runtime_event_id"]


def test_o365_raw_event_adapter_ingests_batch(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-o365-raw@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/surface-coverage/saas/o365/events/raw",
        headers=headers,
        json={
            "value": [
                {
                    "changeType": "created",
                    "resource": "users/john/messages",
                    "subscriptionId": "sub-1",
                    "resourceData": {
                        "id": "msg-1",
                        "userPrincipalName": owner["user_id"],
                        "subject": "Summarize this report with Copilot",
                    },
                },
                {
                    "changeType": "updated",
                    "resource": "teams/abc/chats",
                    "subscriptionId": "sub-2",
                    "resourceData": {
                        "id": "chat-1",
                        "userPrincipalName": owner["user_id"],
                        "chatMessage": "Run this through AI and share externally",
                    },
                },
            ]
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["processed"] == 2
    assert len(body["items"]) == 2
    assert {item["app"] for item in body["items"]}.issubset({"outlook", "teams", "microsoft_365"})


def test_endpoint_heartbeat_ingests_running_app_context(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-endpoint-heartbeat@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/surface-coverage/endpoint/heartbeat",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "device_id": "macbook-001",
            "hostname": "macbook-001.local",
            "os_type": "mac",
            "os_version": "14.7",
            "running_apps": ["Slack Desktop", "VS Code"],
            "gateway_routed": True,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["processed"] == 2
    assert body["device_id"] == "macbook-001"
    assert {item["app"] for item in body["items"]} == {"Slack Desktop", "VS Code"}


def test_endpoint_heartbeat_resolves_email_user_reference(test_env) -> None:
    client: TestClient = test_env["client"]
    email = "surface-endpoint-heartbeat-email@example.com"
    owner = _register_owner(client, email=email)
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/surface-coverage/endpoint/heartbeat",
        headers=headers,
        json={
            "user_id": email,
            "device_id": "macbook-email-001",
            "running_apps": ["endpoint_agent"],
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["processed"] == 1
    assert body["items"][0]["user_id"] == owner["user_id"]


def test_endpoint_heartbeat_bounds_long_os_version_and_preserves_raw_metadata(test_env) -> None:
    client: TestClient = test_env["client"]
    email = "surface-endpoint-heartbeat-long-os@example.com"
    owner = _register_owner(client, email=email)
    headers = _headers(owner["access_token"], owner["tenant_id"])
    long_os_version = (
        "Darwin Kernel Version 25.6.0: Fri Jul 31 19:11:03 PDT 2026; "
        "root:xnu-12377.161.14~5/RELEASE_ARM64_T8132"
    )

    response = client.post(
        "/surface-coverage/endpoint/heartbeat",
        headers=headers,
        json={
            "user_id": email,
            "device_id": "macbook-long-os-001",
            "hostname": "macbook-long-os.local",
            "os_type": "mac",
            "os_version": long_os_version,
            "running_apps": ["endpoint_agent"],
        },
    )

    assert response.status_code == 200, response.text
    with test_env["SessionLocal"]() as db:
        endpoint = db.get(DeploymentEndpoint, "macbook-long-os-001")
        assert endpoint is not None
        assert endpoint.os_version == long_os_version[:64]
        assert endpoint.metadata_json["raw_os_version"] == long_os_version


def test_endpoint_heartbeat_rejects_unknown_user_reference(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-endpoint-heartbeat-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/surface-coverage/endpoint/heartbeat",
        headers=headers,
        json={
            "user_id": "unknown-user@example.com",
            "device_id": "macbook-unknown-001",
            "running_apps": ["endpoint_agent"],
        },
    )

    assert response.status_code == 422, response.text
    assert response.json()["detail"]["code"] == "endpoint_heartbeat_user_not_in_tenant"


def test_microsoft_surface_specific_endpoints_ingest_into_unified_control_plane(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-microsoft-specific@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    outlook = client.post(
        "/surface-coverage/microsoft/outlook/events",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "subject": "Use Copilot to summarize this board deck",
            "body_preview": "Contains Q2 financial summary",
            "recipients": ["finance@example.com"],
        },
    )
    assert outlook.status_code == 200, outlook.text
    outlook_body = outlook.json()
    assert outlook_body["surface"] == "saas"
    assert outlook_body["app"] == "outlook"
    assert outlook_body["runtime_event_id"]

    teams = client.post(
        "/surface-coverage/microsoft/teams/events",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "message": "Share this with external AI for quick rewrite.",
            "team_id": "team-001",
            "channel_id": "channel-001",
        },
    )
    assert teams.status_code == 200, teams.text
    teams_body = teams.json()
    assert teams_body["surface"] == "saas"
    assert teams_body["app"] == "teams"
    assert teams_body["runtime_event_id"]

    storage = client.post(
        "/surface-coverage/microsoft/onedrive-sharepoint/events",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "source": "sharepoint",
            "action": "share",
            "file_name": "comp-plan.xlsx",
            "sharing_scope": "external",
        },
    )
    assert storage.status_code == 200, storage.text
    storage_body = storage.json()
    assert storage_body["surface"] == "saas"
    assert storage_body["app"] in {"sharepoint", "onedrive"}
    assert storage_body["runtime_event_id"]

    office = client.post(
        "/surface-coverage/microsoft/office-copilot/events",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "app_name": "powerpoint",
            "prompt_or_content": "Rewrite this product launch plan for external partners.",
            "document_title": "launch-q3.pptx",
        },
    )
    assert office.status_code == 200, office.text
    office_body = office.json()
    assert office_body["surface"] == "saas"
    assert office_body["app"] in {"word", "excel", "powerpoint"}
    assert office_body["runtime_event_id"]


def test_microsoft_azure_openai_surface_blocks_when_not_gateway_routed(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-microsoft-azure-openai@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/surface-coverage/microsoft/azure-openai/events",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "prompt_or_content": "Summarize this with sensitive employee salary details",
            "model": "gpt-4.1",
            "api_endpoint": "https://example-eastus.openai.azure.com/openai/deployments/demo/chat/completions",
            "gateway_routed": False,
            "transport": {"require_tls": True, "tls_version": "1.3", "scheme": "https"},
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["surface"] == "developer_tool"
    assert body["app"] == "azure_openai"
    assert body["decision"] == "block"
    assert body["policy_triggered"] == "gateway_bypass_detected"
    assert body["alert_id"] is not None

    alerts = client.get("/surface-coverage/alerts", headers=headers)
    assert alerts.status_code == 200, alerts.text
    matched = [item for item in alerts.json().get("items", []) if item.get("alert_id") == body["alert_id"]]
    assert matched
    assert matched[0].get("source") == "azure_openai"


def test_microsoft_foundry_and_copilot_are_first_class_honest_surfaces(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-microsoft-foundry-copilot@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    foundry = client.post(
        "/surface-coverage/microsoft/foundry/events",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "agent_id": "foundry-agent-1",
            "project_id": "foundry-project-poc",
            "project_name": "Customer Support Agent POC",
            "workspace_id": "foundry-workspace-01",
            "subscription_id": "sub-pilot-001",
            "resource_group": "rg-hawk-pilot",
            "agent_name": "Support Triage Agent",
            "model": "gpt-4.1",
            "model_deployment": "gpt-4.1-support",
            "model_deployment_id": "deployment-support-001",
            "action_type": "tool_call",
            "prompt_or_content": "Use approved customer support knowledge to draft an answer.",
            "tool": "retrieve_customer_case",
            "tool_names": ["retrieve_customer_case", "summarize_case"],
            "data_source": "foundry-knowledge-store",
            "data_source_ids": ["kb-support", "case-index"],
            "api_endpoint": "https://ai.azure.com/projects/poc/agents/foundry-agent-1/runs",
            "service_principal_id": "sp-foundry-agent-1",
            "managed_identity_id": "mi-foundry-agent-1",
            "entra_app_id": "app-foundry-agent-1",
            "authority": {
                "authority_type": "managed_identity",
                "authority_owner": "foundry-agent-1",
                "scope": "support.read",
            },
            "metadata": {"environment": "poc", "data_source_ids": ["kb-support"]},
            "gateway_routed": False,
        },
    )
    assert foundry.status_code == 200, foundry.text
    foundry_body = foundry.json()
    assert foundry_body["surface"] == "foundry"
    assert foundry_body["app"] == "microsoft_foundry"
    assert foundry_body["runtime_event_id"]
    assert foundry_body["decision"] in {"allow", "warn", "block"}

    copilot = client.post(
        "/surface-coverage/microsoft/copilot/events",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "app": "m365_copilot",
            "prompt_or_content": "Summarize this meeting transcript for the project team.",
            "copilot_type": "m365_copilot",
            "event_type": "copilot.prompt",
            "workload": "Teams",
            "source_app": "Teams",
            "sensitivity_label": "Confidential",
            "knowledge_asset_ids": ["sharepoint-board-pack"],
            "data_sources": ["SharePoint", "Teams Meeting Transcript"],
            "permission_scopes": ["Files.Read.All", "Sites.Read.All"],
            "oauth_app_id": "copilot-m365",
            "oauth_app_name": "Microsoft 365 Copilot",
            "remediation_actions": [
                "review_purview_dlp",
                "restrict_sharepoint_permissions",
                "review_copilot_policy",
            ],
            "external_action_status": "external_required",
            "gateway_routed": False,
        },
    )
    assert copilot.status_code == 200, copilot.text
    copilot_body = copilot.json()
    assert copilot_body["surface"] == "copilot"
    assert copilot_body["app"] == "m365_copilot"
    assert copilot_body["runtime_event_id"]

    studio = client.post(
        "/surface-coverage/microsoft/copilot-studio/events",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "agent_id": "copilot-studio-agent-1",
            "environment_id": "env-poc",
            "agent_name": "Sales Follow-up Agent",
            "connector_name": "Dynamics 365",
            "connector_names": ["Dynamics 365", "Outlook"],
            "oauth_scopes": ["Contacts.Read", "Mail.Send"],
            "action_type": "connector_action",
            "prompt_or_content": "Create a follow-up task for this customer.",
            "agent_owner": "sales-ops",
            "publisher": "Contoso",
            "oauth_app_id": "studio-app-1",
            "oauth_app_name": "Sales Follow-up Agent",
            "permission_scopes": ["Contacts.Read", "Mail.Send"],
            "data_sources": ["Dynamics 365 Contacts", "Outlook Mailbox"],
            "sensitivity_label": "Customer Confidential",
            "remediation_actions": ["disable_connector", "review_oauth_scopes", "require_dlp_policy"],
            "external_action_status": "external_required",
            "metadata": {"dlp_policy_status": "configured"},
            "gateway_routed": False,
        },
    )
    assert studio.status_code == 200, studio.text
    studio_body = studio.json()
    assert studio_body["surface"] == "copilot"
    assert studio_body["app"] == "copilot_studio"
    assert studio_body["runtime_event_id"]

    foundry_events = client.get(
        "/runtime/events",
        headers=headers,
        params={"source_surface": "foundry"},
    )
    assert foundry_events.status_code == 200, foundry_events.text
    foundry_items = foundry_events.json()["items"]
    foundry_row = next(item for item in foundry_items if item["event_id"] == foundry_body["runtime_event_id"])
    assert foundry_row["source_surface"] == "foundry"
    assert foundry_row["ai_surface"] == "foundry"
    assert foundry_row["provider"] == "Microsoft Foundry"
    assert foundry_row["application"] == "ai.azure.com"

    touchpoints = client.get("/ai-iam/agents/foundry-agent-1/touchpoints", headers=headers)
    assert touchpoints.status_code == 200, touchpoints.text
    touchpoint_edges = touchpoints.json()["edges"]
    edge_pairs = {(edge["edge_type"], edge["target_node_type"], edge["target_node_id"]) for edge in touchpoint_edges}
    assert ("belongs_to_project", "foundry_project", "foundry-project-poc") in edge_pairs
    assert ("uses_model", "model", "gpt-4.1") in edge_pairs
    assert ("invoked_tool", "mcp_tool", "retrieve_customer_case") in edge_pairs
    assert ("accessed_data", "data_source", "kb-support") in edge_pairs
    assert ("used_authority", "service_identity", "sp-foundry-agent-1") in edge_pairs
    assert all(edge["control_mode"] == "telemetry_only" for edge in touchpoint_edges)

    blast = client.get("/ai-iam/agents/foundry-agent-1/blast-radius", headers=headers)
    assert blast.status_code == 200, blast.text
    blast_body = blast.json()
    assert blast_body["reachable_tools_count"] >= 2
    assert blast_body["reachable_data_sources_count"] >= 2
    assert blast_body["reachable_saas_apps_count"] >= 1

    copilot_events = client.get(
        "/runtime/events",
        headers=headers,
        params={"source_surface": "copilot"},
    )
    assert copilot_events.status_code == 200, copilot_events.text
    copilot_items = copilot_events.json()["items"]
    event_by_id = {item["event_id"]: item for item in copilot_items}
    assert event_by_id[copilot_body["runtime_event_id"]]["source_surface"] == "copilot"
    assert event_by_id[copilot_body["runtime_event_id"]]["provider"] == "Microsoft Copilot"
    assert event_by_id[studio_body["runtime_event_id"]]["provider"] == "Microsoft Copilot Studio"
    assert event_by_id[studio_body["runtime_event_id"]]["application"] == "copilotstudio.microsoft.com"
    copilot_metadata = event_by_id[copilot_body["runtime_event_id"]]["metadata"]
    assert copilot_metadata["workload"] == "Teams"
    assert copilot_metadata["source_app"] == "Teams"
    assert copilot_metadata["sensitivity_label"] == "Confidential"
    assert copilot_metadata["knowledge_asset_ids"] == ["sharepoint-board-pack"]
    assert copilot_metadata["data_sources"] == ["SharePoint", "Teams Meeting Transcript"]
    assert copilot_metadata["permission_scopes"] == ["Files.Read.All", "Sites.Read.All"]
    assert copilot_metadata["oauth_app_name"] == "Microsoft 365 Copilot"
    assert copilot_metadata["remediation_actions"] == [
        "review_purview_dlp",
        "restrict_sharepoint_permissions",
        "review_copilot_policy",
    ]
    assert copilot_metadata["external_action_status"] == "external_required"
    assert copilot_metadata["control_mode_hint"] == "telemetry_only"
    studio_metadata = event_by_id[studio_body["runtime_event_id"]]["metadata"]
    assert studio_metadata["agent_name"] == "Sales Follow-up Agent"
    assert studio_metadata["connector_names"] == ["Dynamics 365", "Outlook"]
    assert studio_metadata["oauth_scopes"] == ["Contacts.Read", "Mail.Send"]
    assert studio_metadata["permission_scopes"] == ["Contacts.Read", "Mail.Send"]
    assert studio_metadata["data_sources"] == ["Dynamics 365 Contacts", "Outlook Mailbox"]
    assert studio_metadata["sensitivity_label"] == "Customer Confidential"
    assert studio_metadata["remediation_actions"] == ["disable_connector", "review_oauth_scopes", "require_dlp_policy"]
    assert studio_metadata["external_action_status"] == "external_required"

    dashboard = client.get(
        "/dashboard/command-center",
        headers=headers,
        params={"time_window_hours": 24, "force_refresh": True},
    )
    assert dashboard.status_code == 200, dashboard.text
    surfaces = dashboard.json()["surface_coverage_summary"]["surfaces"]
    assert surfaces["foundry"]["event_count"] >= 1
    assert surfaces["copilot"]["event_count"] >= 2


def test_microsoft_foundry_live_inventory_sync_creates_agent_touchpoints(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-foundry-live-sync@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/surface-coverage/microsoft/foundry/sync",
        headers=headers,
        json={
            "subscription_id": "sub-live-001",
            "resource_group": "rg-foundry-prod",
            "workspace_id": "workspace-live-01",
            "project_endpoint": "https://ai.azure.com/projects/customer-risk",
            "inventory": {
                "projects": [
                    {
                        "id": "project-customer-risk",
                        "name": "Customer Risk Copilot",
                        "workspace_id": "workspace-live-01",
                        "subscription_id": "sub-live-001",
                        "resource_group": "rg-foundry-prod",
                    }
                ],
                "agents": [
                    {
                        "id": "agent-risk-reviewer",
                        "name": "Risk Reviewer Agent",
                        "project_id": "project-customer-risk",
                        "model_deployment": "gpt-4.1-risk",
                        "model": "gpt-4.1",
                        "model_version": "2025-04-14",
                        "tools": [
                            {"name": "lookup_customer_profile", "type": "retrieval"},
                            {"name": "create_case_note", "type": "write"},
                        ],
                        "data_sources": [
                            {"id": "risk-vector-index", "name": "Risk Vector Index"},
                            {"id": "crm-customer-view", "name": "CRM Customer View"},
                        ],
                        "service_principal_id": "sp-risk-reviewer",
                        "managed_identity_id": "mi-risk-reviewer",
                        "entra_app_id": "app-risk-reviewer",
                    }
                ],
                "deployments": [
                    {
                        "id": "deployment-risk-001",
                        "name": "gpt-4.1-risk",
                        "model": "gpt-4.1",
                        "version": "2025-04-14",
                        "project_id": "project-customer-risk",
                    }
                ],
                "models": [
                    {
                        "id": "model-gpt-4.1",
                        "name": "gpt-4.1",
                        "version": "2025-04-14",
                        "provider": "azure_openai",
                    }
                ],
                "service_principals": [
                    {
                        "id": "sp-risk-reviewer",
                        "appId": "app-risk-reviewer",
                        "displayName": "Risk Reviewer Agent SP",
                    }
                ],
                "tools": [
                    {
                        "id": "tool-escalate-case",
                        "name": "escalate_customer_case",
                        "type": "write",
                        "agent_id": "agent-risk-reviewer",
                    }
                ],
                "data_sources": [
                    {
                        "id": "customer-risk-lake",
                        "name": "Customer Risk Lake",
                        "type": "adls",
                        "agent_id": "agent-risk-reviewer",
                    }
                ],
            },
            "gateway_routed_agent_ids": [],
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "ok"
    assert body["source"] == "azure_foundry_live_connector"
    assert body["control_mode"] == "telemetry_only"
    assert body["pulled"]["projects"] == 1
    assert body["pulled"]["agents"] == 1
    assert body["pulled"]["deployments"] == 1
    assert body["pulled"]["models"] == 1
    assert body["pulled"]["service_principals"] == 1
    assert body["pulled"]["tools"] == 3
    assert body["pulled"]["data_sources"] == 3
    assert body["ingested_events"] >= 7
    assert body["runtime_event_ids"]

    runtime_events = client.get(
        "/runtime/events",
        headers=headers,
        params={"source_surface": "foundry"},
    )
    assert runtime_events.status_code == 200, runtime_events.text
    items = runtime_events.json()["items"]
    synced = [
        item
        for item in items
        if item.get("metadata", {}).get("inventory_source") == "azure_foundry_live_connector"
    ]
    assert synced
    synced_object_types = {item.get("metadata", {}).get("inventory_object_type") for item in synced}
    assert {
        "project",
        "agent",
        "deployment",
        "model",
        "service_principal",
        "tool",
        "data_source",
    }.issubset(synced_object_types)
    agent_event = next(item for item in synced if item.get("metadata", {}).get("agent_name") == "Risk Reviewer Agent")
    assert agent_event["application"] == "ai.azure.com"
    assert agent_event["provider"] == "Microsoft Foundry"
    assert agent_event["metadata"]["foundry_project_id"] == "project-customer-risk"
    assert agent_event["metadata"]["tool_names"] == [
        "lookup_customer_profile",
        "create_case_note",
        "escalate_customer_case",
    ]
    assert agent_event["metadata"]["data_source_ids"] == [
        "risk-vector-index",
        "crm-customer-view",
        "customer-risk-lake",
    ]
    assert agent_event["metadata"]["service_principal_id"] == "sp-risk-reviewer"
    assert agent_event["metadata"]["control_mode_hint"] == "telemetry_only"
    deployment_event = next(item for item in synced if item.get("metadata", {}).get("inventory_object_type") == "deployment")
    assert deployment_event["metadata"]["model_deployment_id"] == "deployment-risk-001"
    assert deployment_event["metadata"]["foundry_project_id"] == "project-customer-risk"
    assert deployment_event["metadata"]["control_mode_hint"] == "telemetry_only"
    service_principal_event = next(
        item for item in synced if item.get("metadata", {}).get("inventory_object_type") == "service_principal"
    )
    assert service_principal_event["metadata"]["service_principal_id"] == "sp-risk-reviewer"
    assert service_principal_event["metadata"]["entra_app_id"] == "app-risk-reviewer"

    touchpoints = client.get("/ai-iam/agents/agent-risk-reviewer/touchpoints", headers=headers)
    assert touchpoints.status_code == 200, touchpoints.text
    edge_pairs = {(edge["edge_type"], edge["target_node_type"], edge["target_node_id"]) for edge in touchpoints.json()["edges"]}
    assert ("belongs_to_project", "foundry_project", "project-customer-risk") in edge_pairs
    assert ("uses_model", "model", "gpt-4.1") in edge_pairs
    assert ("invoked_tool", "mcp_tool", "lookup_customer_profile") in edge_pairs
    assert ("invoked_tool", "mcp_tool", "create_case_note") in edge_pairs
    assert ("invoked_tool", "mcp_tool", "escalate_customer_case") in edge_pairs
    assert ("accessed_data", "data_source", "risk-vector-index") in edge_pairs
    assert ("accessed_data", "data_source", "crm-customer-view") in edge_pairs
    assert ("accessed_data", "data_source", "customer-risk-lake") in edge_pairs
    assert ("used_authority", "service_identity", "sp-risk-reviewer") in edge_pairs
    assert all(edge["control_mode"] == "telemetry_only" for edge in touchpoints.json()["edges"])


def test_microsoft_foundry_sync_pulls_live_azure_endpoints(monkeypatch, test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-foundry-http-sync@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    requested_urls: list[str] = []
    requested_authorizations: list[str | None] = []

    inventory_by_path = {
        "/projects": [{"id": "project-live-http", "name": "Live HTTP Project"}],
        "/agents": [
            {
                "id": "agent-live-http",
                "name": "Live HTTP Agent",
                "project_id": "project-live-http",
                "model": "gpt-4.1",
                "service_principal_id": "sp-live-http",
                "tools": ["read_case"],
                "data_sources": ["customer-vector"],
            }
        ],
        "/deployments": [
            {
                "id": "deployment-live-http",
                "name": "gpt-4.1-prod",
                "project_id": "project-live-http",
                "model": "gpt-4.1",
            }
        ],
        "/models": [{"id": "model-live-http", "name": "gpt-4.1", "provider": "azure_openai"}],
        "/servicePrincipals": [
            {"id": "sp-live-http", "appId": "app-live-http", "displayName": "Live HTTP Agent SP"}
        ],
        "/tools": [{"id": "tool-live-write", "name": "write_case", "agent_id": "agent-live-http"}],
        "/dataSources": [{"id": "crm-live-http", "name": "CRM Live HTTP", "agent_id": "agent-live-http"}],
    }

    class FakeFoundryResponse:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self):
            return {"value": self._payload}

    class FakeFoundryClient:
        def __init__(self, *, timeout):
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url, headers):
            requested_urls.append(url)
            requested_authorizations.append(headers.get("Authorization"))
            parsed_path = urlparse(url).path
            matched = []
            for path, payload in sorted(inventory_by_path.items(), key=lambda item: len(item[0]), reverse=True):
                if parsed_path.endswith(path):
                    matched = payload
                    break
            return FakeFoundryResponse(matched)

    monkeypatch.setattr(surface_coverage.httpx, "Client", FakeFoundryClient)

    response = client.post(
        "/surface-coverage/microsoft/foundry/sync",
        headers=headers,
        json={
            "project_endpoint": "https://ai.azure.com/projects/live-http",
            "access_token": "test-foundry-token",
            "gateway_routed_agent_ids": ["agent-live-http"],
            "timeout_seconds": 3,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "ok"
    assert body["source"] == "azure_foundry_live_connector"
    assert body["control_mode"] == "inline_candidate"
    assert body["pulled"] == {
        "projects": 1,
        "agents": 1,
        "deployments": 1,
        "models": 1,
        "service_principals": 1,
        "tools": 2,
        "data_sources": 2,
    }
    assert len(requested_urls) == 7
    assert all(value == "Bearer test-foundry-token" for value in requested_authorizations)
    assert any("/projects?api-version=2025-05-01-preview" in url for url in requested_urls)
    assert any("/servicePrincipals?api-version=2025-05-01-preview" in url for url in requested_urls)

    runtime_events = client.get(
        "/runtime/events",
        headers=headers,
        params={"source_surface": "foundry"},
    )
    assert runtime_events.status_code == 200, runtime_events.text
    synced = [
        item
        for item in runtime_events.json()["items"]
        if item.get("metadata", {}).get("sync_id") == body["sync_id"]
    ]
    agent_event = next(item for item in synced if item.get("metadata", {}).get("agent_name") == "Live HTTP Agent")
    assert agent_event["metadata"]["control_mode_hint"] == "inline_candidate"
    assert agent_event["metadata"]["tool_names"] == ["read_case", "write_case"]
    assert agent_event["metadata"]["data_source_ids"] == ["customer-vector", "crm-live-http"]
    assert "test-foundry-token" not in str(agent_event["metadata"])


def test_microsoft_foundry_sync_follows_odata_pagination(monkeypatch, test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-foundry-pagination@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    requested_urls: list[str] = []

    class FakeFoundryPageResponse:
        def __init__(self, payload, *, next_link: str | None = None):
            self._payload = payload
            self._next_link = next_link
            self.status_code = 200
            self.headers = {}

        def raise_for_status(self) -> None:
            return None

        def json(self):
            body = {"value": self._payload}
            if self._next_link:
                body["@odata.nextLink"] = self._next_link
            return body

    class FakeFoundryPagedClient:
        def __init__(self, *, timeout):
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url, headers):
            requested_urls.append(url)
            parsed_path = urlparse(url).path
            if parsed_path.endswith("/projects") and "skiptoken=2" not in url:
                return FakeFoundryPageResponse(
                    [{"id": "project-page-1", "name": "Foundry Page 1"}],
                    next_link="https://ai.azure.com/projects/paged/projects?api-version=2025-05-01-preview&skiptoken=2",
                )
            if parsed_path.endswith("/projects") and "skiptoken=2" in url:
                return FakeFoundryPageResponse([{"id": "project-page-2", "name": "Foundry Page 2"}])
            return FakeFoundryPageResponse([])

    monkeypatch.setattr(surface_coverage.httpx, "Client", FakeFoundryPagedClient)

    response = client.post(
        "/surface-coverage/microsoft/foundry/sync",
        headers=headers,
        json={
            "project_endpoint": "https://ai.azure.com/projects/paged",
            "access_token": "test-foundry-token",
            "timeout_seconds": 3,
            "max_pages_per_endpoint": 3,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["pulled"]["projects"] == 2
    assert len(requested_urls) == 8
    diagnostics = body["connector_diagnostics"]
    assert diagnostics["mode"] == "live_pull"
    assert diagnostics["pages_fetched"] == 8
    assert diagnostics["endpoints"]["projects"]["pages_fetched"] == 2
    assert diagnostics["endpoints"]["projects"]["items_pulled"] == 2
    assert "test-foundry-token" not in str(diagnostics)


def test_microsoft_foundry_sync_rejects_cross_origin_pagination(monkeypatch, test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-foundry-pagination-ssrf@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    requested_urls: list[str] = []

    class FakeFoundryPageResponse:
        status_code = 200
        headers: dict[str, str] = {}

        def raise_for_status(self) -> None:
            return None

        def json(self):
            return {
                "value": [{"id": "project-page-1", "name": "Foundry Page 1"}],
                "@odata.nextLink": "https://attacker.example/collect",
            }

    class FakeFoundryPagedClient:
        def __init__(self, *, timeout):
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url, headers):
            requested_urls.append(url)
            return FakeFoundryPageResponse()

    monkeypatch.setattr(surface_coverage.httpx, "Client", FakeFoundryPagedClient)

    response = client.post(
        "/surface-coverage/microsoft/foundry/sync",
        headers=headers,
        json={
            "project_endpoint": "https://ai.azure.com/projects/paged",
            "access_token": "test-foundry-token",
            "timeout_seconds": 3,
            "max_pages_per_endpoint": 3,
        },
    )

    assert response.status_code == 422, response.text
    assert "approved Microsoft or Azure origin" in response.text
    assert requested_urls == [
        "https://ai.azure.com/projects/paged/projects?api-version=2025-05-01-preview"
    ]


def test_microsoft_foundry_sync_rejects_public_http_endpoint(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-foundry-http-reject@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/surface-coverage/microsoft/foundry/sync",
        headers=headers,
        json={
            "project_endpoint": "http://ai.azure.com/projects/unsafe",
            "access_token": "test-foundry-token",
        },
    )

    assert response.status_code == 422, response.text
    assert "must use HTTPS" in response.text


def test_microsoft_foundry_sync_rejects_non_microsoft_https_destination(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-foundry-origin-reject@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/surface-coverage/microsoft/foundry/sync",
        headers=headers,
        json={
            "project_endpoint": "https://attacker.example/collect",
            "access_token": "test-foundry-token",
        },
    )

    assert response.status_code == 422, response.text
    assert "approved Microsoft or Azure origin" in response.text


def test_microsoft_copilot_sync_rejects_non_microsoft_https_destination(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-copilot-origin-reject@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/surface-coverage/microsoft/copilot/sync",
        headers=headers,
        json={
            "tenant_graph_endpoint": "https://attacker.example/collect",
            "access_token": "test-copilot-token",
        },
    )

    assert response.status_code == 422, response.text
    assert "approved Microsoft or Azure origin" in response.text


def test_microsoft_copilot_live_inventory_sync_creates_activity_and_studio_touchpoints(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-copilot-live-sync@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/surface-coverage/microsoft/copilot/sync",
        headers=headers,
        json={
            "tenant_graph_endpoint": "https://graph.microsoft.com/beta",
            "copilot_studio_endpoint": "https://api.powerplatform.com/copilotstudio",
            "inventory": {
                "m365_activity": [
                    {
                        "id": "activity-teams-summary-001",
                        "userPrincipalName": "risk.user@example.com",
                        "workload": "Teams",
                        "source_app": "Teams",
                        "prompt": "Summarized a confidential board meeting with Copilot.",
                        "sensitivity_label": "Confidential",
                        "knowledge_asset_ids": ["sharepoint-board-pack"],
                        "data_sources": ["Teams Meeting Transcript", "SharePoint Board Site"],
                        "permission_scopes": ["Files.Read.All", "Sites.Read.All"],
                        "oauth_app_id": "copilot-m365-app",
                        "oauth_app_name": "Microsoft 365 Copilot",
                        "remediation_actions": ["review_purview_dlp", "restrict_sharepoint_permissions"],
                        "external_action_status": "external_required",
                    }
                ],
                "copilot_studio_agents": [
                    {
                        "id": "studio-agent-risk",
                        "displayName": "Risk Review Agent",
                        "environment_id": "env-prod-risk",
                        "owner": "Risk Automation Team",
                        "publisher": "Contoso",
                        "connectors": ["Dynamics 365", "Outlook"],
                        "data_sources": ["Dynamics 365 Accounts", "Outlook Mailbox"],
                        "oauth_scopes": ["Contacts.Read", "Mail.Send"],
                        "oauth_app_id": "copilot-studio-risk-app",
                        "oauth_app_name": "Risk Review Agent OAuth App",
                        "sensitivity_label": "Customer Confidential",
                        "remediation_actions": ["disable_connector", "review_oauth_scopes"],
                        "external_action_status": "external_required",
                    }
                ],
                "connectors": [
                    {
                        "id": "connector-d365",
                        "name": "Dynamics 365",
                        "agent_id": "studio-agent-risk",
                        "data_sources": ["Dynamics 365 Accounts"],
                        "oauth_scopes": ["Contacts.Read"],
                    },
                    {
                        "id": "connector-outlook",
                        "name": "Outlook",
                        "agent_id": "studio-agent-risk",
                        "data_sources": ["Outlook Mailbox"],
                        "oauth_scopes": ["Mail.Send"],
                    },
                ],
                "oauth_apps": [
                    {
                        "id": "copilot-studio-risk-app",
                        "displayName": "Risk Review Agent OAuth App",
                        "agent_id": "studio-agent-risk",
                        "permission_scopes": ["Contacts.Read", "Mail.Send"],
                        "remediation_actions": ["revoke_oauth_app", "review_admin_consent"],
                        "external_action_status": "external_required",
                    }
                ],
                "purview_signals": [
                    {
                        "id": "purview-sensitive-meeting-001",
                        "userPrincipalName": "risk.user@example.com",
                        "workload": "Teams",
                        "sensitivity_label": "Confidential",
                        "data_sources": ["Teams Meeting Transcript"],
                        "remediation_actions": ["review_purview_dlp"],
                    }
                ],
                "graph_permissions": [
                    {
                        "id": "graph-permission-risk-agent-001",
                        "agent_id": "studio-agent-risk",
                        "oauth_app_id": "copilot-studio-risk-app",
                        "oauth_app_name": "Risk Review Agent OAuth App",
                        "permission_scopes": ["Contacts.Read", "Mail.Send"],
                        "remediation_actions": ["review_admin_consent"],
                    }
                ],
                "remediation_hooks": [
                    {
                        "id": "remediation-hook-risk-agent",
                        "displayName": "Review Risk Agent OAuth grant",
                        "agent_id": "studio-agent-risk",
                        "action": "review_admin_consent",
                        "targetType": "oauth_app",
                        "targetResource": "copilot-studio-risk-app",
                        "externalActionStatus": "external_required",
                        "remediationActions": ["review_admin_consent"],
                    }
                ],
            },
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "ok"
    assert body["source"] == "microsoft_copilot_live_connector"
    assert body["control_mode"] == "telemetry_only"
    assert body["pulled"]["m365_activity"] == 1
    assert body["pulled"]["copilot_studio_agents"] == 1
    assert body["pulled"]["connectors"] == 2
    assert body["pulled"]["oauth_apps"] == 1
    assert body["pulled"]["purview_signals"] == 1
    assert body["pulled"]["graph_permissions"] == 1
    assert body["pulled"]["remediation_hooks"] == 1
    assert body["ingested_events"] >= 8
    assert body["runtime_event_ids"]

    runtime_events = client.get(
        "/runtime/events",
        headers=headers,
        params={"source_surface": "copilot"},
    )
    assert runtime_events.status_code == 200, runtime_events.text
    synced = [
        item
        for item in runtime_events.json()["items"]
        if item.get("metadata", {}).get("inventory_source") == "microsoft_copilot_live_connector"
    ]
    assert synced
    synced_object_types = {item.get("metadata", {}).get("inventory_object_type") for item in synced}
    assert {
        "m365_activity",
        "copilot_studio_agent",
        "connector",
        "oauth_app",
        "purview_signal",
        "graph_permission",
        "remediation_hook",
    }.issubset(synced_object_types)

    activity_event = next(item for item in synced if item.get("metadata", {}).get("inventory_object_type") == "m365_activity")
    assert activity_event["application"] == "copilot.microsoft.com"
    assert activity_event["metadata"]["workload"] == "Teams"
    assert activity_event["metadata"]["sensitivity_label"] == "Confidential"
    assert activity_event["metadata"]["permission_scopes"] == ["Files.Read.All", "Sites.Read.All"]
    assert activity_event["metadata"]["external_action_status"] == "external_required"
    assert activity_event["metadata"]["control_mode_hint"] == "telemetry_only"

    agent_event = next(item for item in synced if item.get("metadata", {}).get("agent_name") == "Risk Review Agent")
    assert agent_event["application"] == "copilotstudio.microsoft.com"
    assert agent_event["metadata"]["connector_names"] == ["Dynamics 365", "Outlook"]
    assert agent_event["metadata"]["data_sources"] == ["Dynamics 365 Accounts", "Outlook Mailbox"]
    assert agent_event["metadata"]["oauth_app_id"] == "copilot-studio-risk-app"

    permission_event = next(item for item in synced if item.get("metadata", {}).get("inventory_object_type") == "graph_permission")
    assert permission_event["metadata"]["oauth_app_id"] == "copilot-studio-risk-app"
    assert permission_event["metadata"]["permission_scopes"] == ["Contacts.Read", "Mail.Send"]

    remediation_event = next(
        item for item in synced if item.get("metadata", {}).get("inventory_object_type") == "remediation_hook"
    )
    assert remediation_event["metadata"]["remediation_action"] == "review_admin_consent"
    assert remediation_event["metadata"]["remediation_target_type"] == "oauth_app"
    assert remediation_event["metadata"]["remediation_target_resource"] == "copilot-studio-risk-app"
    assert remediation_event["metadata"]["control_mode_hint"] == "external_required"
    assert remediation_event["metadata"]["external_action_status"] == "external_required"

    touchpoints = client.get("/ai-iam/agents/studio-agent-risk/touchpoints", headers=headers)
    assert touchpoints.status_code == 200, touchpoints.text
    edge_pairs = {(edge["edge_type"], edge["target_node_type"], edge["target_node_id"]) for edge in touchpoints.json()["edges"]}
    assert ("invoked_tool", "mcp_tool", "Dynamics 365") in edge_pairs
    assert ("invoked_tool", "mcp_tool", "Outlook") in edge_pairs
    assert ("accessed_data", "data_source", "Dynamics 365 Accounts") in edge_pairs
    assert ("accessed_data", "data_source", "Outlook Mailbox") in edge_pairs
    assert all(edge["control_mode"] == "telemetry_only" for edge in touchpoints.json()["edges"])


def test_microsoft_copilot_sync_pulls_live_graph_and_studio_endpoints(monkeypatch, test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-copilot-http-sync@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    requested_urls: list[str] = []
    requested_authorizations: list[str | None] = []

    inventory_by_path = {
        "/copilot/activity": [
            {
                "id": "activity-live-copilot",
                "userPrincipalName": "risk.user@example.com",
                "workload": "Teams",
                "prompt": "Summarized a confidential customer renewal meeting.",
                "sensitivityLabel": "Confidential",
                "knowledgeAssetIds": ["sharepoint-renewals"],
                "dataSources": ["Teams Transcript"],
                "permissionScopes": ["Files.Read.All"],
            }
        ],
        "/agents": [
            {
                "id": "studio-agent-live",
                "displayName": "Live Copilot Studio Agent",
                "environmentId": "env-live",
                "owner": "Sales Automation",
                "connectors": ["Dynamics 365"],
                "dataSources": ["Dynamics Accounts"],
                "oauthScopes": ["Contacts.Read", "Mail.Send"],
                "oauthAppId": "app-live-copilot",
            }
        ],
        "/connectors": [
            {
                "id": "connector-live-d365",
                "name": "Dynamics 365",
                "agentId": "studio-agent-live",
                "dataSources": ["Dynamics Accounts"],
                "oauthScopes": ["Contacts.Read"],
            }
        ],
        "/applications": [
            {
                "id": "app-live-copilot",
                "displayName": "Live Copilot Studio OAuth App",
                "agentId": "studio-agent-live",
                "permissionScopes": ["Contacts.Read", "Mail.Send"],
                "remediationActions": ["revoke_oauth_app", "review_admin_consent"],
                "externalActionStatus": "external_required",
            }
        ],
        "/security/informationProtection/sensitivityLabels": [
            {
                "id": "purview-live-confidential",
                "userPrincipalName": "risk.user@example.com",
                "workload": "Teams",
                "sensitivityLabel": "Confidential",
                "dataSources": ["Teams Transcript"],
            }
        ],
        "/servicePrincipals": [
            {
                "id": "graph-live-permission",
                "agentId": "studio-agent-live",
                "oauthAppId": "app-live-copilot",
                "displayName": "Live Copilot Studio OAuth App",
                "permissionScopes": ["Contacts.Read", "Mail.Send"],
                "remediationActions": ["review_admin_consent"],
            }
        ],
        "/security/copilot/remediationHooks": [
            {
                "id": "hook-restrict-sharepoint-board",
                "displayName": "Restrict SharePoint board-pack access",
                "action": "restrict_sharepoint_permissions",
                "targetType": "sharepoint_site",
                "targetResource": "sharepoint-board-pack",
                "status": "external_required",
                "requiresApproval": True,
                "relatedActivityId": "activity-live-copilot",
                "userPrincipalName": "risk.user@example.com",
                "workload": "Teams",
                "sensitivityLabel": "Confidential",
                "dataSources": ["SharePoint Board Site"],
                "permissionScopes": ["Sites.FullControl.All"],
                "remediationActions": ["restrict_sharepoint_permissions"],
            },
            {
                "id": "hook-revoke-copilot-agent-oauth",
                "displayName": "Revoke Copilot Studio OAuth grant",
                "action": "revoke_oauth_app",
                "targetType": "oauth_app",
                "targetResource": "app-live-copilot",
                "status": "triggered",
                "agentId": "studio-agent-live",
                "oauthAppId": "app-live-copilot",
                "oauthAppName": "Live Copilot Studio OAuth App",
                "permissionScopes": ["Mail.Send"],
                "remediationActions": ["revoke_oauth_app"],
            },
        ],
    }

    class FakeCopilotResponse:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self):
            return {"value": self._payload}

    class FakeCopilotClient:
        def __init__(self, *, timeout):
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url, headers):
            requested_urls.append(url)
            requested_authorizations.append(headers.get("Authorization"))
            parsed_path = urlparse(url).path
            matched = []
            for path, payload in sorted(inventory_by_path.items(), key=lambda item: len(item[0]), reverse=True):
                if parsed_path.endswith(path):
                    matched = payload
                    break
            return FakeCopilotResponse(matched)

    monkeypatch.setattr(surface_coverage.httpx, "Client", FakeCopilotClient)

    response = client.post(
        "/surface-coverage/microsoft/copilot/sync",
        headers=headers,
        json={
            "tenant_graph_endpoint": "https://graph.microsoft.com/beta",
            "copilot_studio_endpoint": "https://api.powerplatform.com/copilotstudio",
            "access_token": "test-copilot-token",
            "gateway_routed_agent_ids": ["studio-agent-live"],
            "endpoints": {
                "oauth_apps": "https://graph.microsoft.com/beta/applications",
                "remediation_hooks": "https://graph.microsoft.com/beta/security/copilot/remediationHooks",
            },
            "timeout_seconds": 3,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "ok"
    assert body["source"] == "microsoft_copilot_live_connector"
    assert body["control_mode"] == "inline_candidate"
    assert body["pulled"] == {
        "m365_activity": 1,
        "copilot_studio_agents": 1,
        "connectors": 1,
        "oauth_apps": 1,
        "purview_signals": 1,
        "graph_permissions": 1,
        "remediation_hooks": 2,
    }
    assert len(requested_urls) == 7
    assert all(value == "Bearer test-copilot-token" for value in requested_authorizations)
    assert "https://graph.microsoft.com/beta/copilot/activity" in requested_urls
    assert "https://api.powerplatform.com/copilotstudio/agents" in requested_urls
    assert "https://api.powerplatform.com/copilotstudio/connectors" in requested_urls
    assert "https://graph.microsoft.com/beta/applications" in requested_urls
    assert "https://graph.microsoft.com/beta/security/copilot/remediationHooks" in requested_urls

    runtime_events = client.get(
        "/runtime/events",
        headers=headers,
        params={"source_surface": "copilot"},
    )
    assert runtime_events.status_code == 200, runtime_events.text
    synced = [
        item
        for item in runtime_events.json()["items"]
        if item.get("metadata", {}).get("sync_id") == body["sync_id"]
    ]
    assert synced
    agent_event = next(item for item in synced if item.get("metadata", {}).get("agent_name") == "Live Copilot Studio Agent")
    assert agent_event["metadata"]["control_mode_hint"] == "inline_candidate"
    assert agent_event["metadata"]["connector_names"] == ["Dynamics 365"]
    assert agent_event["metadata"]["data_sources"] == ["Dynamics Accounts"]
    assert agent_event["metadata"]["oauth_app_id"] == "app-live-copilot"
    assert "test-copilot-token" not in str(agent_event["metadata"])

    connector_event = next(item for item in synced if item.get("metadata", {}).get("inventory_object_type") == "connector")
    assert connector_event["metadata"]["control_mode_hint"] == "inline_candidate"
    assert "test-copilot-token" not in str(connector_event["metadata"])

    remediation_events = [
        item for item in synced if item.get("metadata", {}).get("inventory_object_type") == "remediation_hook"
    ]
    assert len(remediation_events) == 2
    sharepoint_hook = next(
        item for item in remediation_events if item["metadata"]["remediation_action"] == "restrict_sharepoint_permissions"
    )
    assert sharepoint_hook["metadata"]["remediation_target_type"] == "sharepoint_site"
    assert sharepoint_hook["metadata"]["remediation_target_resource"] == "sharepoint-board-pack"
    assert sharepoint_hook["metadata"]["control_mode_hint"] == "external_required"
    assert sharepoint_hook["metadata"]["requires_approval"] is True
    oauth_hook = next(item for item in remediation_events if item["metadata"]["remediation_action"] == "revoke_oauth_app")
    assert oauth_hook["metadata"]["control_mode_hint"] == "external_action_triggered"
    assert oauth_hook["metadata"]["oauth_app_id"] == "app-live-copilot"
    assert "test-copilot-token" not in str(oauth_hook["metadata"])


def test_microsoft_copilot_sync_retries_graph_rate_limits(monkeypatch, test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-copilot-rate-limit@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    request_count_by_path: dict[str, int] = {}

    class FakeCopilotRetryResponse:
        def __init__(self, payload, *, status_code: int = 200):
            self._payload = payload
            self.status_code = status_code
            self.headers = {"Retry-After": "0"} if status_code == 429 else {}

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise surface_coverage.httpx.HTTPStatusError(
                    "rate limited",
                    request=surface_coverage.httpx.Request("GET", "https://graph.microsoft.com/beta/copilot/activity"),
                    response=surface_coverage.httpx.Response(self.status_code),
                )

        def json(self):
            return {"value": self._payload}

    class FakeCopilotRetryClient:
        def __init__(self, *, timeout):
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url, headers):
            path = urlparse(url).path
            request_count_by_path[path] = request_count_by_path.get(path, 0) + 1
            if path.endswith("/copilot/activity") and request_count_by_path[path] == 1:
                return FakeCopilotRetryResponse([], status_code=429)
            if path.endswith("/copilot/activity"):
                return FakeCopilotRetryResponse(
                    [
                        {
                            "id": "activity-after-retry",
                            "userPrincipalName": "risk.user@example.com",
                            "workload": "Teams",
                            "prompt": "Summarized a confidential customer renewal meeting.",
                            "sensitivityLabel": "Confidential",
                        }
                    ]
                )
            return FakeCopilotRetryResponse([])

    monkeypatch.setattr(surface_coverage.httpx, "Client", FakeCopilotRetryClient)

    response = client.post(
        "/surface-coverage/microsoft/copilot/sync",
        headers=headers,
        json={
            "tenant_graph_endpoint": "https://graph.microsoft.com/beta",
            "copilot_studio_endpoint": "https://api.powerplatform.com/copilotstudio",
            "access_token": "test-copilot-token",
            "timeout_seconds": 3,
            "max_retries": 1,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["pulled"]["m365_activity"] == 1
    diagnostics = body["connector_diagnostics"]
    assert diagnostics["retry_count"] == 1
    assert diagnostics["rate_limited"] is True
    assert diagnostics["endpoints"]["m365_activity"]["retries"] == 1
    assert diagnostics["endpoints"]["m365_activity"]["rate_limited"] is True
    assert "test-copilot-token" not in str(diagnostics)


def test_microsoft_poc_surfaces_are_metadata_first_and_traceable(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-microsoft-poc-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    device_id = "microsoft-poc-device-01"

    permission_modes = client.get("/monitoring/connectors/microsoft/permission-modes", headers=headers)
    assert permission_modes.status_code == 200, permission_modes.text
    assert {item["mode"] for item in permission_modes.json()["items"]} == {
        "poc_safe",
        "standard",
        "full_enterprise",
    }

    outlook = client.post(
        "/surface-coverage/microsoft/outlook/events",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "device_id": device_id,
            "subject": "Customer escalation",
            "body_preview": "Ask Copilot to rewrite this customer API key sk-live-abcdef1234567890",
            "recipients": ["vendor@example.com"],
        },
    )
    assert outlook.status_code == 200, outlook.text
    outlook_body = outlook.json()

    teams = client.post(
        "/surface-coverage/microsoft/teams/events",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "device_id": device_id,
            "message": "Can Teams Copilot summarize this customer support thread?",
            "team_id": "team-poc",
            "channel_id": "channel-poc",
        },
    )
    assert teams.status_code == 200, teams.text
    teams_body = teams.json()

    drive = client.post(
        "/surface-coverage/microsoft/onedrive-sharepoint/events",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "device_id": device_id,
            "source": "sharepoint",
            "action": "share",
            "file_name": "customer-secret-plan.docx",
            "file_path": "/sites/sales/customer-secret-plan.docx",
            "content_preview": "This raw preview must not be stored by default",
            "sharing_scope": "external",
            "sensitivity_label": "confidential",
        },
    )
    assert drive.status_code == 200, drive.text
    drive_body = drive.json()

    entra = client.post(
        "/surface-coverage/microsoft/entra/events",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "device_id": device_id,
            "user_principal_name": "surface-microsoft-poc-owner@example.com",
            "activity": "risky_sign_in",
            "app_display_name": "Microsoft Copilot",
            "risk_level": "high",
            "risk_state": "at_risk",
            "ip_address": "203.0.113.10",
        },
    )
    assert entra.status_code == 200, entra.text
    entra_body = entra.json()

    azure_routed = client.post(
        "/surface-coverage/microsoft/azure-openai/events",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "device_id": device_id,
            "prompt_or_content": "Summarize this public product FAQ.",
            "model": "gpt-4.1",
            "api_endpoint": "https://example-eastus.openai.azure.com/openai/deployments/demo/chat/completions",
            "gateway_routed": True,
            "metadata": {"gateway_endpoint": "https://hawk-gateway.company.com/azure-openai"},
            "transport": {"require_tls": True, "tls_version": "1.3", "scheme": "https"},
        },
    )
    assert azure_routed.status_code == 200, azure_routed.text
    azure_routed_body = azure_routed.json()

    azure_bypass = client.post(
        "/surface-coverage/microsoft/azure-openai/events",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "device_id": device_id,
            "prompt_or_content": "Call Azure OpenAI directly with local code.",
            "model": "gpt-4.1",
            "api_endpoint": "https://example-eastus.openai.azure.com/openai/deployments/demo/chat/completions",
            "gateway_routed": False,
            "transport": {"require_tls": True, "tls_version": "1.3", "scheme": "https"},
        },
    )
    assert azure_bypass.status_code == 200, azure_bypass.text
    azure_bypass_body = azure_bypass.json()

    for row in [outlook_body, teams_body, drive_body, entra_body, azure_routed_body, azure_bypass_body]:
        assert row["user_id"] == owner["user_id"]
        assert row["device_id"] == device_id
        assert row["runtime_event_id"]
        assert row["audit_action_id"]
        assert row["trace_url"]
        assert row["enforcement_path"] == "hawk_ai_gateway"
        assert row["content_preview"]

    assert outlook_body["app"] == "outlook"
    assert outlook_body["alert_id"]
    assert teams_body["app"] == "teams"
    assert drive_body["app"] == "sharepoint"
    assert drive_body["content_preview"] != "This raw preview must not be stored by default"
    assert drive_body["policy_triggered"] in {"sensitive_data_detected", "policy_allow"}
    assert entra_body["app"] == "entra_id"
    assert entra_body["decision"] == "warn"
    assert entra_body["policy_triggered"] == "microsoft_entra_risky_signin"
    assert entra_body["alert_id"]
    assert azure_routed_body["surface"] == "developer_tool"
    assert azure_routed_body["gateway_routed"] is True
    assert azure_routed_body["gateway_bypass_detected"] is False
    assert azure_routed_body["decision"] in {"allow", "warn", "block"}
    assert azure_bypass_body["decision"] == "block"
    assert azure_bypass_body["policy_triggered"] == "gateway_bypass_detected"
    assert azure_bypass_body["gateway_bypass_detected"] is True
    assert azure_bypass_body["alert_id"]

    trace = client.get(f"/surface-coverage/alerts/{azure_bypass_body['alert_id']}", headers=headers)
    assert trace.status_code == 200, trace.text
    trace_body = trace.json()["trace"]
    assert trace_body["user_id"] == owner["user_id"]
    assert trace_body["device_id"] == device_id
    assert trace_body["app"] == "api.openai.azure.com"
    assert "GATEWAY_ENFORCEMENT" in trace_body["control_triggered"]
    assert trace_body["decision"] == "blocked"

    identity = client.get(f"/surface-coverage/identity/{owner['user_id']}", headers=headers)
    assert identity.status_code == 200, identity.text
    actions = identity.json()["timeline"]["actions"]
    apps = {item["ai_app"] for item in actions}
    surfaces = {item["source_surface"] for item in actions}
    assert {
        "outlook.office.com",
        "teams.microsoft.com",
        "sharepoint.com",
        "login.microsoftonline.com",
        "api.openai.azure.com",
    }.issubset(apps)
    assert {"saas", "developer_tool"}.issubset(surfaces)


def test_enterprise_poc_surfaces_share_one_control_contract_and_identity_trace(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="surface-enterprise-poc@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    device_id = "poc-macbook-30"

    heartbeat = client.post(
        "/surface-coverage/endpoint/heartbeat",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "device_id": device_id,
            "hostname": "poc-macbook-30.local",
            "os_type": "mac",
            "os_version": "15.5",
            "running_apps": [
                "Slack Desktop",
                "Outlook Desktop",
                "VS Code",
                "GitHub Desktop",
                "Codex CLI",
                "Terminal",
            ],
            "gateway_routed": True,
        },
    )
    assert heartbeat.status_code == 200, heartbeat.text
    heartbeat_body = heartbeat.json()
    assert heartbeat_body["processed"] == 6
    heartbeat_apps = {item["application_key"] for item in heartbeat_body["items"]}
    assert {"slack_desktop", "outlook_desktop", "vscode", "github_desktop", "codex_cli", "terminal"}.issubset(heartbeat_apps)

    slack = client.post(
        "/surface-coverage/saas/slack/events",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "device_id": device_id,
            "action_type": "prompt_input",
            "prompt_or_content": "Use ChatGPT to rewrite this customer token sk-live-1234567890abcdef for a vendor.",
            "gateway_routed": True,
            "transport": {"require_tls": True, "tls_version": "1.3", "scheme": "https"},
            "url": "https://slack.com/app_redirect",
        },
    )
    assert slack.status_code == 200, slack.text
    slack_body = slack.json()

    o365 = client.post(
        "/surface-coverage/saas/o365/events/raw",
        headers=headers,
        json={
            "value": [
                {
                    "changeType": "created",
                    "resource": "users/jane/messages",
                    "subscriptionId": "sub-poc-o365",
                    "resourceData": {
                        "id": "msg-poc-1",
                        "userPrincipalName": owner["user_id"],
                        "deviceId": device_id,
                        "subject": "Summarize this Copilot board deck for external partners",
                    },
                }
            ]
        },
    )
    assert o365.status_code == 200, o365.text
    o365_item = o365.json()["items"][0]

    browser = client.post(
        "/surface-coverage/events",
        headers=headers,
        json={
            "surface": "browser",
            "app": "chatgpt",
            "user_id": owner["user_id"],
            "device_id": device_id,
            "action_type": "prompt_input",
            "prompt_or_content": "Analyze this production API key sk-live-abcdef1234567890",
            "url": "https://chatgpt.com/",
            "gateway_routed": True,
            "transport": {"require_tls": True, "tls_version": "1.3", "scheme": "https"},
        },
    )
    assert browser.status_code == 200, browser.text
    browser_body = browser.json()

    codex_routed = client.post(
        "/surface-coverage/dev-tools/events",
        headers=headers,
        json={
            "app": "codex_cli",
            "user_id": owner["user_id"],
            "device_id": device_id,
            "action_type": "api_call",
            "prompt_or_content": "Generate a safe TypeScript helper.",
            "api_endpoint": "https://hawk-gateway.company.com/v1/responses",
            "model": "gpt-5.4",
            "gateway_routed": True,
            "transport": {"require_tls": True, "tls_version": "1.3", "scheme": "https"},
        },
    )
    assert codex_routed.status_code == 200, codex_routed.text
    codex_routed_body = codex_routed.json()

    codex_bypass = client.post(
        "/surface-coverage/dev-tools/events",
        headers=headers,
        json={
            "app": "codex_cli",
            "user_id": owner["user_id"],
            "device_id": device_id,
            "action_type": "api_call",
            "prompt_or_content": "Call OpenAI directly from a local script.",
            "api_endpoint": "https://api.openai.com/v1/responses",
            "model": "gpt-5.4",
            "gateway_routed": False,
            "transport": {"require_tls": True, "tls_version": "1.3", "scheme": "https"},
        },
    )
    assert codex_bypass.status_code == 200, codex_bypass.text
    codex_bypass_body = codex_bypass.json()

    contract_rows = [slack_body, o365_item, browser_body, codex_routed_body, codex_bypass_body]
    for row in contract_rows:
        assert row["user_id"] == owner["user_id"]
        assert row["app"]
        assert row["device_id"] == device_id
        assert "content_preview" in row
        assert row["sensitivity_score"] >= 0
        assert isinstance(row["ai_usage_detected"], bool)
        assert row["decision"] in {"allow", "warn", "block"}
        assert row["timestamp"]
        assert row["enforcement_path"] == "hawk_ai_gateway"
        assert row["trace_url"]

    assert slack_body["alert_id"]
    assert browser_body["decision"] == "block"
    assert browser_body["policy_triggered"] in {"sensitive_data_detected", "secret_or_credential_detected"}
    assert codex_routed_body["gateway_routed"] is True
    assert codex_routed_body["gateway_bypass_detected"] is False
    assert codex_bypass_body["decision"] == "block"
    assert codex_bypass_body["policy_triggered"] == "gateway_bypass_detected"
    assert codex_bypass_body["gateway_bypass_detected"] is True

    alerts = client.get("/surface-coverage/alerts", headers=headers)
    assert alerts.status_code == 200, alerts.text
    alert_items = alerts.json()["items"]
    assert any(item["alert_id"] == slack_body["alert_id"] for item in alert_items)
    assert any(item["alert_id"] == codex_bypass_body["alert_id"] for item in alert_items)

    trace = client.get(f"/surface-coverage/alerts/{codex_bypass_body['alert_id']}", headers=headers)
    assert trace.status_code == 200, trace.text
    trace_body = trace.json()["trace"]
    assert trace_body["user_id"] == owner["user_id"]
    assert trace_body["device_id"] == device_id
    assert trace_body["app"] == "api.openai.com"
    assert trace_body["control_triggered"]
    assert trace_body["decision"] == "blocked"
    assert trace_body["remediation_suggestion"]

    identity = client.get(f"/surface-coverage/identity/{owner['user_id']}", headers=headers)
    assert identity.status_code == 200, identity.text
    timeline_actions = identity.json()["timeline"]["actions"]
    timeline_surfaces = {item["source_surface"] for item in timeline_actions}
    timeline_apps = {item["ai_app"] for item in timeline_actions}
    assert {"saas", "browser", "developer_tool", "endpoint"}.issubset(timeline_surfaces)
    assert {"slack.com", "outlook.office.com", "chatgpt.com", "api.openai.com"}.issubset(timeline_apps)
