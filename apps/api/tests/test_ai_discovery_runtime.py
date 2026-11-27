from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.activity_audit import AIAction, AIActionAlert, AISession, DeploymentEndpoint
from app.db.models.audit import AuditLog
from app.db.models.discovery import DiscoveryApplication
from app.db.models.ai_iam import AgentActionBaseline, AgentIdentity, CapabilityToken
from app.db.models.evidence import EvidenceNode
from app.db.models.monitoring import MonitoringSignal
from app.db.models.runtime_intelligence import (
    RuntimeBehaviorEdge,
    RuntimeEvent,
    RuntimeGovernanceRecommendation,
    RuntimeSimulationTrigger,
)
from app.db.session import Base, get_db
from app.main import app
from app.core.config import settings
from app.services.activity_audit_service import record_activity_event
from app.services.ai_anomaly import detect_and_enforce_runtime_anomalies
from app.services.ai_discovery import process_runtime_event_for_ai_discovery
from app.services.ai_discovery.owasp_mapping_service import list_owasp_risk_mappings
from app.services.ai_graph import build_unified_ai_graph
from app.services.discovery_service import tool_key_for_name
from app.services.runtime_intelligence.runtime_event_normalizer import ingest_runtime_event
from app.services.runtime_intelligence.schemas import RuntimeEventIngestPayload
from ai_system_approval_helpers import approve_ai_system


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "ai_discovery_runtime.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "AI Discovery Owner"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    return {
        "access_token": payload["access_token"],
        "tenant_id": payload["tenants"][0]["id"],
        "user_id": payload["user"]["id"],
    }


def _create_ai_system(client: TestClient, *, headers: dict[str, str], name: str = "Discovery Runtime AI") -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": name, "description": "", "risk_tier": "MEDIUM"},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    approved = approve_ai_system(client, headers, ai_system_id)
    assert approved.status_code == 200, approved.text
    return ai_system_id


def _create_agent(client: TestClient, *, headers: dict[str, str], name: str = "agent-security-test") -> str:
    response = client.post(
        "/ai-iam/agents",
        headers=headers,
        json={
            "name": name,
            "description": "Agent used by AI discovery runtime tests",
            "max_chain_depth": 3,
            "action_scope": ["tool_execution", "policy.read"],
            "tool_registry": ["filesystem", "email"],
            "external_system_access": ["chatgpt.com", "mail.google.com"],
            "agent_type": "workflow_agent",
            "autonomy_level": "medium",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def test_activity_alert_type_is_compact_when_policy_reasons_are_long(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="compact-alert-owner@example.com")

    long_reason = ",".join(
        [
            "action_alignment:unknown",
            "action_type:prompt_submit",
            "browser_linked",
            "endpoint_linked",
            "input_sensitivity:none",
            "intent_aware_ai_action_control",
            "intent_category:unknown",
            "pii:phone",
            "sensitive_data_pattern",
            "session_linked",
            "user_linked",
        ]
    )

    with session_factory() as db:
        record = record_activity_event(
            db,
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            payload={
                "action_id": f"act_{uuid4().hex}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_surface": "browser",
                "action_type": "prompt_submit",
                "ai_app": "chatgpt.com",
                "enforcement_action": "blocked",
                "policy_triggered": long_reason,
                "risk_score": 0.95,
                "sensitivity_score": 0.6,
                "endpoint_id": "ep-compact-alert",
                "hostname": "pilot-laptop",
                "browser": "chrome",
                "correlation_id": f"corr-{uuid4().hex}",
            },
        )
        db.commit()
        assert record.alert_id

        alert = db.get(AIActionAlert, record.alert_id)
        assert alert is not None
        assert alert.alert_type == "action_alignment:unknown"
        assert len(alert.alert_type) <= 128
        assert alert.policy_reason == long_reason


def test_runtime_browser_urls_are_compacted_before_graph_and_activity_storage(test_env) -> None:
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(test_env["client"], email="ai-discovery-long-browser-url@example.com")

    long_google_url = (
        "https://www.google.com/search?q=weather+in+dubai"
        "&sca_esv=pilot-new-tab-page&origin=chrome"
        "&new-tab-page&ei=very-long-browser-url"
        "&source=lnms&ved=0ahUKEwjVeryLongPilotURL"
        "&biw=1920&bih=1080&dpr=2"
        "&hl=en-AE&gl=ae&safe=active&udm=2"
        "&more=params-that-make-this-url-longer-than-postgres-varchar-limits"
    )
    assert len(long_google_url) > 255

    with session_factory() as db:
        row = ingest_runtime_event(
            db,
            payload=RuntimeEventIngestPayload(
                tenant_id=owner["tenant_id"],
                source_surface="browser",
                event_type="browser_interaction",
                user_id=owner["user_id"],
                app_id=None,
                machine_id="pilot-mac-01",
                browser_type="chrome",
                application=long_google_url,
                decision="allow",
                severity="low",
                risk_score=0.1,
                metadata={
                    "endpoint_id": "ep-long-url-01",
                    "hostname": "pilot-mac-01",
                    "browser_type": "chrome",
                    "domain": "google.com",
                    "application": long_google_url,
                    "tool_name": long_google_url,
                    "api_endpoint": long_google_url,
                    "action_type": "prompt_input",
                    "decision": "allow",
                },
            ),
        )
        db.commit()

        assert row is not None
        assert row.application == "www.google.com"
        assert row.metadata_json["raw_application"] == long_google_url
        assert row.metadata_json["application_compacted"] is True
        edges = db.scalars(
            select(RuntimeBehaviorEdge).where(
                RuntimeBehaviorEdge.tenant_id == owner["tenant_id"],
                RuntimeBehaviorEdge.event_id == row.event_id,
            )
        ).all()
        assert edges
        for edge in edges:
            assert len(edge.source_node_id) <= 128
            assert len(edge.target_node_id) <= 128
            assert not edge.source_node_id.startswith("https://")
            assert not edge.target_node_id.startswith("https://")
        assert any(
            (edge.payload or {}).get("raw_target_node_id") == long_google_url
            or (edge.payload or {}).get("raw_source_node_id") == long_google_url
            for edge in edges
        )

        actions = db.scalars(
            select(AIAction).where(
                AIAction.tenant_id == owner["tenant_id"],
                AIAction.runtime_event_id == row.event_id,
            )
        ).all()
        assert actions
        assert all(not str(action.ai_app or "").startswith("https://") for action in actions)
        assert all(len(str(action.ai_app or "")) <= 255 for action in actions)


def test_owasp_mapping_catalog_uses_current_references_and_complete_metadata() -> None:
    mappings = list_owasp_risk_mappings()
    assert mappings

    by_framework = {}
    for mapping in mappings:
        by_framework.setdefault(mapping["framework_key"], []).append(mapping)
        assert mapping["risk_id"]
        assert mapping["reference"]
        assert mapping["title"]
        assert mapping["source_reference_url"].startswith("https://")
        assert mapping["risk_tags"]
        assert mapping["controls"], mapping["risk_id"]
        assert mapping["simulations"], mapping["risk_id"]
        assert mapping["enforcement_actions"], mapping["risk_id"]
        assert mapping["blast_radius_dimensions"], mapping["risk_id"]
        assert mapping["remediation_templates"], mapping["risk_id"]
        assert mapping["audit_metadata"]["evidence_node_type"]
        assert mapping["audit_metadata"]["audit_signal_type"]
        assert mapping["audit_metadata"]["trace_fields"]

    llm_refs = {item["reference"]: item["title"] for item in by_framework["OWASP_LLM_TOP_10"]}
    assert llm_refs == {
        "LLM01:2025": "Prompt Injection",
        "LLM02:2025": "Sensitive Information Disclosure",
        "LLM03:2025": "Supply Chain",
        "LLM04:2025": "Data and Model Poisoning",
        "LLM05:2025": "Improper Output Handling",
        "LLM06:2025": "Excessive Agency",
        "LLM07:2025": "System Prompt Leakage",
        "LLM08:2025": "Vector and Embedding Weaknesses",
        "LLM09:2025": "Misinformation",
        "LLM10:2025": "Unbounded Consumption",
    }

    agentic_refs = {item["reference"] for item in by_framework["OWASP_AGENTIC_TOP_10_2026"]}
    assert agentic_refs == {f"ASI{index:02d}:2026" for index in range(1, 11)}

    mcp_refs = {item["reference"] for item in by_framework["OWASP_MCP_TOP_10"]}
    assert mcp_refs == {f"MCP{index:02d}:2025" for index in range(1, 11)}


def test_ai_discovery_endpoints_return_live_overview_graph_and_identity(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="ai-discovery-runtime-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers=headers)
    gateway = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": owner["user_id"],
            "prompt": "Summarize endpoint hardening recommendations.",
            "context_summary": "AI discovery runtime test",
            "attachments_meta": [],
            "provider": "openai",
            "model": "gpt-4o-mini",
        },
    )
    assert gateway.status_code == 200, gateway.text

    with session_factory() as db:
        record_activity_event(
            db,
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            payload={
                "action_id": f"act_{uuid4().hex}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_surface": "browser",
                "action_type": "prompt_input",
                "ai_app": "chatgpt.com",
                "ai_model": "gpt-4o-mini",
                "enforcement_action": "allowed",
                "risk_score": 0.2,
                "sensitivity_score": 0.1,
                "endpoint_id": "ep-discovery-01",
                "hostname": "macbook-pro",
                "browser": "chrome",
                "os_type": "mac",
                "browser_version": "123",
                "extension_version": "1.0.0",
                "correlation_id": f"corr-{uuid4().hex}",
            },
        )
        db.commit()

    overview = client.get("/ai-discovery/overview", headers=headers)
    assert overview.status_code == 200, overview.text
    overview_payload = overview.json()
    assert overview_payload["apps_detected"] >= 1
    assert overview_payload["total_usage_events"] >= 1

    usage = client.get("/ai-discovery/usage-events", headers=headers)
    assert usage.status_code == 200, usage.text
    usage_payload = usage.json()
    assert usage_payload["total"] >= 1
    assert usage_payload["items"][0]["app_name"]
    assert usage_payload["items"][0]["source_surface"]

    graph = client.get("/ai-discovery/graph", headers=headers)
    assert graph.status_code == 200, graph.text
    graph_payload = graph.json()
    assert graph_payload["stats"]["event_count"] >= 1
    assert isinstance(graph_payload["nodes"], list)

    identities = client.get("/ai-discovery/identities", headers=headers)
    assert identities.status_code == 200, identities.text
    identity_payload = identities.json()
    assert any(item["user_id"] == owner["user_id"] for item in identity_payload["items"])

    profile = client.get(f"/ai-discovery/identities/{owner['user_id']}", headers=headers)
    assert profile.status_code == 200, profile.text
    profile_payload = profile.json()
    assert profile_payload["user_id"] == owner["user_id"]
    assert profile_payload["anomaly_count_7d"] >= 0

    recompute = client.post("/ai-discovery/recompute?lookback_hours=24&max_events=500", headers=headers)
    assert recompute.status_code == 200, recompute.text
    assert recompute.json()["recomputed_events"] >= 1


def test_discovery_upsert_skips_owner_binding_for_non_platform_user_id(test_env) -> None:
    session_factory = test_env["sessionmaker"]
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ai-discovery-owner-binding@example.com")

    with session_factory() as db:
        event = RuntimeEvent(
            event_id=f"evt-{uuid4().hex}",
            tenant_id=owner["tenant_id"],
            source_surface="browser",
            event_type="prompt_input",
            app_id="external-tool.example",
            user_id="external-user-123",  # not a users.id value in platform
            severity="low",
            risk_score=0.1,
            evidence_node_ids=[],
            correlation_id=f"corr-{uuid4().hex}",
            metadata_json={
                "domain": "external-tool.example",
                "action_type": "prompt_input",
                "browser": "chrome",
            },
        )
        db.add(event)
        db.flush()
        process_runtime_event_for_ai_discovery(db, event=event)
        db.commit()

        row = db.scalar(
            select(DiscoveryApplication).where(
                DiscoveryApplication.tenant_id == owner["tenant_id"],
                DiscoveryApplication.tool_key == tool_key_for_name("external-tool.example"),
            )
        )
        assert row is not None
        assert row.owner_user_id is None


def test_runtime_event_auto_quarantines_unknown_agent_identity(test_env) -> None:
    session_factory = test_env["sessionmaker"]
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ai-discovery-auto-quarantine@example.com")
    agent_id = "7dc0f118-42f0-4d14-bcf1-22f55cebc6ab"

    original = settings.ai_iam_auto_quarantine_new_agents
    settings.ai_iam_auto_quarantine_new_agents = True
    try:
        with session_factory() as db:
            event = RuntimeEvent(
                event_id=f"evt-{uuid4().hex}",
                tenant_id=owner["tenant_id"],
                source_surface="gateway",
                event_type="agent.tool_call",
                app_id="unknown-agent-runtime",
                user_id=owner["user_id"],
                agent_id=agent_id,
                severity="high",
                risk_score=0.81,
                evidence_node_ids=[],
                correlation_id=f"corr-{uuid4().hex}",
                metadata_json={
                    "action_type": "tool_call",
                    "decision": "block",
                    "tool_name": "filesystem",
                    "provider": "openai",
                },
            )
            db.add(event)
            db.flush()

            result = process_runtime_event_for_ai_discovery(db, event=event)
            db.commit()

            assert result["auto_quarantine"]["created"] is True
            row = db.get(AgentIdentity, agent_id)
            assert row is not None
            assert row.status == "quarantined"
            assert row.agent_type == "unregistered_agent"
    finally:
        settings.ai_iam_auto_quarantine_new_agents = original


def test_runtime_anomaly_detection_persists_signal_and_recommendation(test_env) -> None:
    session_factory = test_env["sessionmaker"]
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ai-discovery-anomaly@example.com")

    with session_factory() as db:
        event = RuntimeEvent(
            event_id=f"evt-{uuid4().hex}",
            tenant_id=owner["tenant_id"],
            source_surface="browser",
            event_type="prompt_input",
            app_id="chatgpt.com",
            user_id=owner["user_id"],
            severity="high",
            risk_score=0.94,
            evidence_node_ids=[],
            correlation_id=f"corr-{uuid4().hex}",
            metadata_json={
                "domain": "chatgpt.com",
                "action_type": "prompt_input",
                "decision": "allow",
                "contains_sensitive": True,
                "sensitive_entities": ["email"],
                "input_signal_types": ["sensitive_data_detected"],
                "crq": {"annualized_loss_expectancy": 150000.0},
            },
        )
        db.add(event)
        db.flush()

        anomalies = detect_and_enforce_runtime_anomalies(db, event=event)
        db.commit()

        assert anomalies
        assert any(item["anomaly_type"] == "data_extraction_anomaly" for item in anomalies)

        signal = db.scalar(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == owner["tenant_id"],
                MonitoringSignal.signal_type == "ai_anomaly.data_extraction_anomaly",
            )
        )
        assert signal is not None

        recommendation = db.scalar(
            select(RuntimeGovernanceRecommendation).where(
                RuntimeGovernanceRecommendation.tenant_id == owner["tenant_id"],
                RuntimeGovernanceRecommendation.event_id == event.event_id,
                RuntimeGovernanceRecommendation.reason_code == "data_extraction_anomaly",
            )
        )
        assert recommendation is not None

        trigger = db.scalar(
            select(RuntimeSimulationTrigger).where(
                RuntimeSimulationTrigger.tenant_id == owner["tenant_id"],
                RuntimeSimulationTrigger.event_id == event.event_id,
            )
        )
        assert trigger is not None


def test_owner_approved_public_read_only_mcp_anomaly_does_not_restrict_agent(test_env) -> None:
    session_factory = test_env["sessionmaker"]
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ai-discovery-mcp-anomaly@example.com")

    with session_factory() as db:
        agent_id = str(uuid4())
        db.add(
            AgentIdentity(
                id=agent_id,
                tenant_id=owner["tenant_id"],
                name="Codex governed GitHub read-only MCP",
                description="Owner-approved HMAIR H2 read-only MCP acceptance agent.",
                status="active",
                max_chain_depth=1,
                capability_inheritance=False,
                action_scope=["file_read"],
                tool_registry=["list_pull_requests"],
                external_system_access=["github.com"],
                agent_type="workflow_agent",
                autonomy_level="low",
            )
        )
        db.add(
            AgentActionBaseline(
                tenant_id=owner["tenant_id"],
                agent_identity_id=agent_id,
                action="mcp_tool_call",
                baseline_rate_per_hour=1.0,
                current_window_count=5,
                window_started_at=datetime.now(timezone.utc),
                last_seen_at=datetime.now(timezone.utc),
                metadata_json={},
            )
        )
        event = RuntimeEvent(
            event_id=f"evt-{uuid4().hex}",
            tenant_id=owner["tenant_id"],
            source_surface="gateway",
            event_type="mcp_tool_call",
            app_id="github.com",
            agent_id=agent_id,
            severity="low",
            risk_score=0.2,
            evidence_node_ids=[],
            correlation_id=f"corr-{uuid4().hex}",
            metadata_json={
                "source_surface": "gateway",
                "action_type": "mcp_tool_call",
                "decision": "allow",
                "tool_name": "list_pull_requests",
                "provider": "mcp",
                "data_classification": "public",
                "session_validation": {
                    "valid": True,
                    "bounds_enforcement": {"valid": True},
                },
                "dynamic_permission": {
                    "status": "active",
                    "mode": "block",
                    "allowed_actions": ["file_read"],
                },
            },
        )
        db.add(event)
        db.flush()

        anomalies = detect_and_enforce_runtime_anomalies(db, event=event)
        db.commit()

        assert any(item["anomaly_type"] == "agent_behavior_anomaly" for item in anomalies)
        assert any(
            item["enforcement_action"] == "session_bound_read_only_mcp_observed"
            for item in anomalies
        )
        agent = db.get(AgentIdentity, agent_id)
        assert agent is not None
        assert agent.status == "active"


def test_runtime_ingestion_contract_links_identity_graph_activity_anomaly_and_evidence(test_env) -> None:
    session_factory = test_env["sessionmaker"]
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ai-discovery-contract@example.com")

    original_runtime = settings.runtime_intelligence_enabled
    settings.runtime_intelligence_enabled = True
    try:
        with session_factory() as db:
            common_device = {
                "endpoint_id": "ep-contract-01",
                "hostname": "pilot-macbook-01",
                "device_type": "laptop",
                "os_type": "mac",
                "os_version": "14.5",
                "browser": "chrome",
                "browser_type": "chrome",
                "browser_version": "126",
                "extension_version": "1.4.0",
            }
            payloads = [
                RuntimeEventIngestPayload(
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    event_type="prompt_input",
                    app_id="chatgpt.com",
                    user_id=owner["user_id"],
                    severity="high",
                    risk_score=0.94,
                    provider="openai",
                    model_name="gpt-4o-mini",
                    metadata={
                        **common_device,
                        "action_type": "prompt_input",
                        "decision": "allow",
                        "prompt_preview_redacted": "Summarize customer [email]",
                        "contains_sensitive": True,
                        "sensitive_entities": ["email"],
                        "input_signal_types": ["sensitive_data_detected"],
                        "destination_is_external": True,
                        "data_classification": "restricted",
                        "data_source": "customer_records",
                    },
                ),
                RuntimeEventIngestPayload(
                    tenant_id=owner["tenant_id"],
                    source_surface="gateway",
                    event_type="llm_intercept",
                    app_id="api.openai.com",
                    user_id=owner["user_id"],
                    severity="low",
                    risk_score=0.2,
                    provider="openai",
                    model_name="gpt-4o-mini",
                    api_endpoint="/v1/chat/completions",
                    data_source="internal_docs",
                    metadata={
                        **common_device,
                        "action_type": "llm_api_call",
                        "decision": "allow",
                        "prompt_preview_redacted": "Draft release note",
                        "data_classification": "internal",
                    },
                ),
                RuntimeEventIngestPayload(
                    tenant_id=owner["tenant_id"],
                    source_surface="aiiam",
                    event_type="mcp_authorize",
                    app_id="claude.ai",
                    user_id=owner["user_id"],
                    agent_id="agent-contract-01",
                    severity="high",
                    risk_score=0.82,
                    provider="anthropic",
                    model_name="claude-sonnet",
                    tool_name="filesystem",
                    tool_category="mcp",
                    data_source="source_code_repo",
                    metadata={
                        **common_device,
                        "action_type": "tool_call",
                        "decision": "block",
                        "prompt_preview_redacted": "Read repository secrets",
                        "data_classification": "restricted",
                        "contains_sensitive": True,
                        "sensitive_entities": ["api_key"],
                    },
                ),
                RuntimeEventIngestPayload(
                    tenant_id=owner["tenant_id"],
                    source_surface="connector",
                    event_type="connector.message_observed",
                    app_id="slack",
                    user_id=owner["user_id"],
                    severity="med",
                    risk_score=0.45,
                    provider="slack",
                    metadata={
                        **common_device,
                        "action_type": "message_observed",
                        "decision": "warn",
                        "prompt_preview_redacted": "Discuss AI usage in channel",
                        "data_classification": "internal",
                        "domain": "slack.com",
                    },
                ),
            ]
            rows = [ingest_runtime_event(db, payload=payload) for payload in payloads]
            db.commit()

            assert all(row is not None for row in rows)
            runtime_ids = {row.event_id for row in rows if row is not None}

            actions = db.scalars(
                select(AIAction).where(
                    AIAction.tenant_id == owner["tenant_id"],
                    AIAction.runtime_event_id.in_(runtime_ids),
                )
            ).all()
            assert len(actions) == 4

            sessions = db.scalars(select(AISession).where(AISession.tenant_id == owner["tenant_id"])).all()
            assert sessions
            endpoint = db.get(DeploymentEndpoint, "ep-contract-01")
            assert endpoint is not None
            assert endpoint.user_id == owner["user_id"]
            assert endpoint.browser_type == "chrome"

            audit_rows = db.scalars(
                select(AuditLog).where(
                    AuditLog.tenant_id == owner["tenant_id"],
                    AuditLog.resource_type == "runtime_event",
                )
            ).all()
            assert len(audit_rows) >= 4
            evidence_rows = db.scalars(
                select(EvidenceNode).where(
                    EvidenceNode.tenant_id == owner["tenant_id"],
                    EvidenceNode.node_type == "runtime_event",
                )
            ).all()
            assert len(evidence_rows) >= 4

            discovery = db.scalar(
                select(DiscoveryApplication).where(
                    DiscoveryApplication.tenant_id == owner["tenant_id"],
                    DiscoveryApplication.tool_key == tool_key_for_name("chatgpt.com"),
                )
            )
            assert discovery is not None
            discovery_meta = dict(discovery.metadata_json or {})
            assert owner["user_id"] in set(discovery_meta.get("users") or [])
            assert "ep-contract-01" in set(discovery_meta.get("devices") or [])

            anomaly = db.scalar(
                select(MonitoringSignal).where(
                    MonitoringSignal.tenant_id == owner["tenant_id"],
                    MonitoringSignal.signal_type == "ai_anomaly.data_extraction_anomaly",
                )
            )
            assert anomaly is not None
            assert float((anomaly.payload or {}).get("risk_increase_usd") or 0.0) > 0.0

            graph = build_unified_ai_graph(db, tenant_id=owner["tenant_id"], lookback_hours=24)
            relationships = {
                (
                    edge["source_node_type"],
                    edge["source_node_id"],
                    edge["relationship_type"],
                    edge["target_node_type"],
                    edge["target_node_id"],
                )
                for edge in graph["edges"]
            }
            assert ("user", owner["user_id"], "uses", "device", "ep-contract-01") in relationships
            assert ("device", "ep-contract-01", "uses", "browser", "chrome") in relationships
            assert ("user", owner["user_id"], "uses", "ai_app", "chatgpt.com") in relationships
            assert any(edge[0] == "ai_app" and edge[2] == "uses" and edge[3] == "model" for edge in relationships)
            assert ("agent", "agent-contract-01", "invokes", "tool", "filesystem") in relationships
            assert any(edge[0] == "action" and edge[2] == "accesses" and edge[3] == "data_object" for edge in relationships)
    finally:
        settings.runtime_intelligence_enabled = original_runtime


def test_agent_security_endpoints_discover_graph_blast_behavior_enforce_and_simulate(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="ai-discovery-agent-security@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers=headers, name="Agent Security Runtime AI")
    agent_id = _create_agent(client, headers=headers, name="agent-security-runtime")

    with session_factory() as db:
        event = RuntimeEvent(
            event_id=f"evt-{uuid4().hex}",
            tenant_id=owner["tenant_id"],
            source_surface="gateway",
            event_type="agent.tool_call",
            ai_system_id=ai_system_id,
            app_id="chatgpt.com",
            user_id=owner["user_id"],
            agent_id=agent_id,
            severity="high",
            risk_score=0.82,
            evidence_node_ids=[],
            correlation_id=f"corr-{uuid4().hex}",
            metadata_json={
                "action_type": "tool_call",
                "tool_name": "filesystem",
                "data_classification": "restricted",
                "decision": "allow",
                "chain_depth": 3,
                "response_size": 1420,
                "triggered_controls": ["TOOL_CALL_VALIDATION", "AGENT_ACTION_AUTHORIZATION"],
            },
        )
        db.add(event)
        db.flush()

        db.add_all(
            [
                RuntimeBehaviorEdge(
                    tenant_id=owner["tenant_id"],
                    event_id=event.event_id,
                    ai_system_id=ai_system_id,
                    source_node_type="agent",
                    source_node_id=agent_id,
                    source_node_label="agent-security-runtime",
                    target_node_type="tool",
                    target_node_id="filesystem",
                    target_node_label="filesystem",
                    relationship_type="invokes",
                    payload={"risk_score": 0.82},
                ),
                RuntimeBehaviorEdge(
                    tenant_id=owner["tenant_id"],
                    event_id=event.event_id,
                    ai_system_id=ai_system_id,
                    source_node_type="tool",
                    source_node_id="filesystem",
                    source_node_label="filesystem",
                    target_node_type="data_object",
                    target_node_id="finance_db",
                    target_node_label="finance_db",
                    relationship_type="accesses",
                    payload={"risk_score": 0.78},
                ),
            ]
        )
        db.add(
            MonitoringSignal(
                tenant_id=owner["tenant_id"],
                ai_system_id=ai_system_id,
                signal_type="ai_anomaly.agent_behavior_anomaly",
                severity="high",
                payload={
                    "reason": "Unexpected high-risk tool access pattern.",
                    "confidence": 0.91,
                    "related_entities": [{"type": "agent", "id": agent_id}],
                    "control_ids": ["AGENT_ACTION_AUTHORIZATION", "TOOL_CALL_VALIDATION"],
                    "runtime_event_id": event.event_id,
                },
            )
        )
        db.commit()

    overview = client.get("/ai-discovery/agents/overview?lookback_hours=168", headers=headers)
    assert overview.status_code == 200, overview.text
    overview_payload = overview.json()
    assert overview_payload["discovered_agents"] >= 1
    assert any(item["agent_id"] == agent_id for item in overview_payload["agents"])

    attack_surface = client.get(
        f"/ai-discovery/agents/{agent_id}/attack-surface?lookback_hours=168&max_edges=500",
        headers=headers,
    )
    assert attack_surface.status_code == 200, attack_surface.text
    attack_payload = attack_surface.json()
    assert attack_payload["agent_id"] == agent_id
    assert attack_payload["stats"]["edge_count"] >= 1
    assert any(node["node_type"] == "agent" and node["node_id"] == agent_id for node in attack_payload["nodes"])
    assert any(item["reference"] == "LLM05:2025" for item in attack_payload["owasp_risk_overlays"])
    assert all(item["audit_metadata"]["evidence_node_type"] for item in attack_payload["owasp_risk_overlays"])

    blast_radius = client.get(f"/ai-discovery/agents/{agent_id}/blast-radius?lookback_hours=168", headers=headers)
    assert blast_radius.status_code == 200, blast_radius.text
    blast_payload = blast_radius.json()
    assert blast_payload["agent_id"] == agent_id
    assert blast_payload["risk_score"] >= 0
    assert "financial_impact" in blast_payload
    assert blast_payload["control_ids"]
    assert any(item["reference"].endswith(":2025") or item["reference"].endswith(":2026") for item in blast_payload["owasp_risk_overlays"])
    assert all(item["enforcement_actions"] for item in blast_payload["owasp_risk_overlays"])

    behavior = client.get(f"/ai-discovery/agents/{agent_id}/behavior?lookback_hours=168", headers=headers)
    assert behavior.status_code == 200, behavior.text
    behavior_payload = behavior.json()
    assert behavior_payload["agent_id"] == agent_id
    assert behavior_payload["usage_patterns"]["event_count"] >= 1

    anomalies = client.get(f"/ai-discovery/agents/{agent_id}/anomalies?lookback_hours=168&limit=20", headers=headers)
    assert anomalies.status_code == 200, anomalies.text
    anomalies_payload = anomalies.json()
    assert anomalies_payload["total"] >= 1
    assert any(item["anomaly_type"] == "agent_behavior_anomaly" for item in anomalies_payload["items"])
    assert any(item.get("owasp_mappings") for item in anomalies_payload["items"])
    assert all(
        mapping["audit_metadata"]["trace_fields"]
        for item in anomalies_payload["items"]
        for mapping in item.get("owasp_mappings", [])
    )

    owasp_coverage = client.get(
        f"/ai-discovery/agents/{agent_id}/owasp-coverage?lookback_hours=168",
        headers=headers,
    )
    assert owasp_coverage.status_code == 200, owasp_coverage.text
    owasp_payload = owasp_coverage.json()
    assert owasp_payload["agent_id"] == agent_id
    assert any(item["framework_key"] == "OWASP_LLM_TOP_10" for item in owasp_payload["framework_registry"])
    assert any(item["framework_key"] == "OWASP_AGENTIC_TOP_10_2026" for item in owasp_payload["framework_registry"])
    assert any(item["framework_key"] == "OWASP_MCP_TOP_10" for item in owasp_payload["framework_registry"])
    assert any(item["reference"] == "LLM01:2025" for item in owasp_payload["categories"])
    assert any(
        item["reference"] == "ASI01:2026" and item["controls"]
        for item in owasp_payload["categories"]
    )
    assert any(item["reference"] == "MCP10:2025" for item in owasp_payload["categories"])
    assert all(item["audit_metadata"]["audit_signal_type"] for item in owasp_payload["categories"])
    assert "runtime_active_categories" in owasp_payload["summary"]

    enforce = client.post(
        f"/ai-discovery/agents/{agent_id}/enforce",
        headers=headers,
        json={
            "action": "require_approval",
            "reason": "Manual containment test for agent security endpoint.",
            "required_approval": True,
            "control_ids": ["AGENT_ACTION_AUTHORIZATION"],
            "ai_system_id": ai_system_id,
        },
    )
    assert enforce.status_code == 200, enforce.text
    enforce_payload = enforce.json()
    assert enforce_payload["agent_id"] == agent_id
    assert enforce_payload["status"] == "enforced"
    assert enforce_payload["updated_state"]["status"] in {"restricted", "isolated", "blocked"}
    assert enforce_payload["owasp_mappings"]
    assert all(item["remediation_templates"] for item in enforce_payload["owasp_mappings"])

    simulate = client.post(
        f"/ai-discovery/agents/{agent_id}/simulate",
        headers=headers,
        json={
            "attack_type": "tool_abuse",
            "ai_system_id": ai_system_id,
            "mode": "deterministic",
            "max_definitions": 3,
            "target_control_ids": ["AGENT_ACTION_AUTHORIZATION", "TOOL_CALL_VALIDATION"],
        },
    )
    assert simulate.status_code == 200, simulate.text
    simulate_payload = simulate.json()
    assert simulate_payload["agent_id"] == agent_id
    assert simulate_payload["resolved_pack_id"] == "tool_abuse_pack"
    assert simulate_payload["execution_status"] in {"executed", "not_executable"}
    assert isinstance(simulate_payload.get("owasp_mappings"), list)
    assert all(item["blast_radius_dimensions"] for item in simulate_payload.get("owasp_mappings", []))


def test_agent_security_uses_token_scopes_and_live_runtime_edges_for_blast_radius(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="ai-discovery-agent-security-live@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers=headers, name="Agent Security Live Edge AI")
    agent_id = _create_agent(client, headers=headers, name="agent-security-live-edge")

    token_response = client.post(
        f"/ai-iam/agents/{agent_id}/tokens",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "scopes": ["payments.write", "secrets.read"],
            "expires_minutes": 30,
            "chain_depth": 1,
        },
    )
    assert token_response.status_code == 200, token_response.text

    with session_factory() as db:
        row = ingest_runtime_event(
            db,
            payload=RuntimeEventIngestPayload(
                tenant_id=owner["tenant_id"],
                source_surface="gateway",
                event_type="agent.tool_call",
                ai_system_id=ai_system_id,
                app_id="claude.ai",
                user_id=owner["user_id"],
                agent_id=agent_id,
                severity="high",
                risk_score=0.86,
                provider="anthropic",
                model_name="claude-sonnet",
                tool_name="payments-api",
                tool_category="mcp",
                data_source="customer_payment_records",
                metadata={
                    "action_type": "tool_call",
                    "decision": "allow",
                    "api_endpoint": "https://payments.internal/v1/refunds",
                    "target_resource": "refunds_endpoint",
                    "data_classification": "restricted",
                    "chain_depth": 4,
                    "response_size": 8192,
                    "triggered_controls": ["AGENT_ACTION_AUTHORIZATION", "TOOL_CALL_VALIDATION"],
                    "canonical_action": {
                        "operation": "refund_customer",
                        "data_entities": ["payment_card", "customer_id"],
                    },
                },
            ),
        )
        assert row is not None
        db.commit()

    overview = client.get("/ai-discovery/agents/overview?lookback_hours=168", headers=headers)
    assert overview.status_code == 200, overview.text
    agent_payload = next(item for item in overview.json()["agents"] if item["agent_id"] == agent_id)
    assert "payments.write" in agent_payload["capabilities"]
    assert "secrets.read" in agent_payload["capabilities"]

    attack_surface = client.get(
        f"/ai-discovery/agents/{agent_id}/attack-surface?lookback_hours=168&max_edges=500",
        headers=headers,
    )
    assert attack_surface.status_code == 200, attack_surface.text
    edge_tuples = {
        (
            item["source_node_type"],
            item["source_node_id"],
            item["relationship_type"],
            item["target_node_type"],
            item["target_node_id"],
        )
        for item in attack_surface.json()["edges"]
    }
    assert ("agent", agent_id, "uses", "model", "anthropic:claude-sonnet") in edge_tuples
    assert ("agent", agent_id, "invokes", "tool", "payments-api") in edge_tuples
    assert ("agent", agent_id, "connects_to", "api", "https://payments.internal/v1/refunds") in edge_tuples
    assert ("agent", agent_id, "accesses", "data_object", "customer_payment_records") in edge_tuples

    blast_radius = client.get(f"/ai-discovery/agents/{agent_id}/blast-radius?lookback_hours=168", headers=headers)
    assert blast_radius.status_code == 200, blast_radius.text
    blast_payload = blast_radius.json()
    assert blast_payload["reachable_assets"]["by_type"]["api"] >= 1
    assert blast_payload["reachable_assets"]["by_type"]["data_object"] >= 1
    assert blast_payload["financial_impact"]["loss_if_compromised_usd"] > 0

    enforce = client.post(
        f"/ai-discovery/agents/{agent_id}/enforce",
        headers=headers,
        json={
            "action": "block_agent",
            "reason": "Contain over-scoped live agent.",
            "control_ids": ["AGENT_ACTION_AUTHORIZATION", "TOOL_CALL_VALIDATION"],
            "ai_system_id": ai_system_id,
        },
    )
    assert enforce.status_code == 200, enforce.text
    enforce_payload = enforce.json()
    assert enforce_payload["status"] == "enforced"
    assert enforce_payload["updated_state"]["status"] == "blocked"
    assert enforce_payload["revoked_tokens"] >= 1

    with session_factory() as db:
        tokens = db.scalars(
            select(CapabilityToken).where(
                CapabilityToken.tenant_id == owner["tenant_id"],
                CapabilityToken.agent_identity_id == agent_id,
            )
        ).all()
        assert tokens
        assert all(token.revoked_at is not None for token in tokens)
