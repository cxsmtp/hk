from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.api.routers import dashboard as dashboard_router
from app.db.models.ai_iam import AgentIdentity
from app.db.models.activity_audit import AIAction, AIActionAlert, AISession
from app.db.models.finding import Finding
from app.db.models.job_run import ScheduledJobRun
from app.db.models.maturity import ControlMaturity
from app.db.models.monitoring import DriftAlert, MonitoringSignal
from app.db.models.policy import ApprovalRequest
from app.db.models.remediation import RemediationAction
from app.db.models.runtime_intelligence import RuntimeEvent, RuntimeGovernanceRecommendation
from app.db.models.shadow_ai import ShadowAIEntity, ShadowAISignal
from app.db.models.simulation import Control, SimulationDefinition, SimulationRun
from app.db.models.user import UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services.activity_audit_service import record_activity_event
from app.services.dashboard.aggregator import CommandCenterDataUnavailableError


PASSWORD = "Password123!"


def test_notifications_group_correlated_prompt_and_policy_even_with_distinct_findings() -> None:
    from app.services.dashboard.aggregator import _dedupe_notifications

    items = [
        {"notification_type": "activity_alert", "notification_id": "prompt", "finding_id": "finding-prompt", "correlation_id": "same-prompt", "severity": "critical", "created_at": datetime.now(timezone.utc).isoformat()},
        {"notification_type": "activity_alert", "notification_id": "policy", "finding_id": "finding-policy", "correlation_id": "same-prompt", "severity": "critical", "created_at": datetime.now(timezone.utc).isoformat()},
    ]
    grouped = _dedupe_notifications(items)
    assert len(grouped) == 1
    assert grouped[0]["repeat_count"] == 2


def test_notification_security_alert_survives_more_than_100_passive_alerts(test_env) -> None:
    client = test_env["client"]
    owner = _register_owner(client, email="notification-passive-starvation@example.com")
    now = datetime.now(timezone.utc)
    with test_env["sessionmaker"]() as db:
        db.add(AISession(session_id="passive-test-session", tenant_id=owner["tenant_id"], source_surface="browser"))
        db.flush()
        for index in range(121):
            signal = MonitoringSignal(
                tenant_id=owner["tenant_id"], ai_system_id=None,
                signal_type="browser.extension_health_status", severity="low",
                payload={"event_type": "extension_health_status", "source_surface": "browser", "healthy": True},
            )
            db.add(signal)
            db.flush()
            passive = AIAction(
                action_id=f"passive-action-{index}", tenant_id=owner["tenant_id"], session_id="passive-test-session",
                action_type="prompt_input", ai_app="extension.local", enforcement_action="warned",
                monitoring_signal_id=signal.id,
                metadata_json={"event_type": "extension_health_status", "healthy": True},
            )
            db.add(passive)
            db.flush()
            db.add(AIActionAlert(
                tenant_id=owner["tenant_id"], action_id=passive.action_id,
                alert_type="extension_health_status", severity="med", enforcement_action="warned",
                created_at=now + timedelta(seconds=index),
            ))
        action = AIAction(
            action_id="real-security-action", tenant_id=owner["tenant_id"], session_id="passive-test-session",
            action_type="prompt_input", ai_app="chatgpt.com", enforcement_action="blocked",
            correlation_id="real-security-prompt", metadata_json={"source_surface": "browser", "event_type": "prompt_blocked"},
        )
        db.add(action)
        db.flush()
        db.add(AIActionAlert(
            tenant_id=owner["tenant_id"], action_id=action.action_id,
            alert_type="prompt_blocked", severity="critical", enforcement_action="blocked", created_at=now,
        ))
        db.commit()
    response = client.get("/dashboard/notifications?limit=1", headers=_headers(owner["access_token"], owner["tenant_id"]))
    assert response.status_code == 200, response.text
    assert response.json()["items"][0]["action_id"] == "real-security-action"


def test_notifications_hide_historical_context_lifecycle_alerts_but_keep_source_block(test_env) -> None:
    client = test_env["client"]
    owner = _register_owner(client, email="notification-context-lifecycle-history@example.com")
    with test_env["sessionmaker"]() as db:
        db.add(AISession(session_id="context-lifecycle-session", tenant_id=owner["tenant_id"], source_surface="browser"))
        db.flush()
        passive_signal = MonitoringSignal(
            tenant_id=owner["tenant_id"], ai_system_id=None,
            signal_type="browser.context_invalidated", severity="low",
            payload={
                "event_type": "context_invalidated",
                "source_surface": "browser",
                "action_taken": "input_node_replaced",
                "reason": "input_node_replaced",
            },
        )
        db.add(passive_signal)
        db.flush()
        passive_action = AIAction(
            action_id="historical-context-lifecycle-action", tenant_id=owner["tenant_id"],
            session_id="context-lifecycle-session", action_type="prompt_input", ai_app="chatgpt.com",
            enforcement_action="blocked", monitoring_signal_id=passive_signal.id,
            metadata_json={
                "source_surface": "browser", "event_type": "context_invalidated",
                "action_taken": "input_node_replaced", "reason": "input_node_replaced",
            },
        )
        db.add(passive_action)
        db.flush()
        db.add(AIActionAlert(
            tenant_id=owner["tenant_id"], action_id=passive_action.action_id,
            alert_type="context_invalidated", severity="high", enforcement_action="blocked",
        ))
        source_action = AIAction(
            action_id="source-block-context-lifecycle-action", tenant_id=owner["tenant_id"],
            session_id="context-lifecycle-session", action_type="prompt_input", ai_app="chatgpt.com",
            enforcement_action="blocked",
            metadata_json={
                "source_surface": "browser", "event_type": "context_invalidated",
                "action_taken": "block:context_policy", "decision": "block",
                "reason": "input_node_replaced",
            },
        )
        db.add(source_action)
        db.flush()
        db.add(AIActionAlert(
            tenant_id=owner["tenant_id"], action_id=source_action.action_id,
            alert_type="context_invalidated", severity="high", enforcement_action="blocked",
        ))
        db.commit()
    response = client.get("/dashboard/notifications?limit=20", headers=_headers(owner["access_token"], owner["tenant_id"]))
    assert response.status_code == 200, response.text
    action_ids = {item.get("action_id") for item in response.json()["items"]}
    assert "historical-context-lifecycle-action" not in action_ids
    assert "source-block-context-lifecycle-action" in action_ids


def test_notification_hides_finding_linked_to_healthy_status_history(test_env) -> None:
    client = test_env["client"]
    owner = _register_owner(client, email="notification-historical-health@example.com")
    with test_env["sessionmaker"]() as db:
        db.add(RuntimeEvent(
            event_id="healthy-history-runtime", tenant_id=owner["tenant_id"], source_surface="browser",
            event_type="extension_health_status", app_id="extension.local",
            metadata_json={"event_type": "extension_health_status", "healthy": True},
        ))
        db.add(Finding(
            tenant_id=owner["tenant_id"], source_surface="browser", ai_tool="extension.local",
            severity="high", finding_type="browser_interaction_security", risk_category="intent_policy",
            decision="block", status="open", recommended_action="Review", dedupe_key="historical-healthy-finding",
            related_runtime_event_id="healthy-history-runtime",
        ))
        db.commit()
    response = client.get("/dashboard/notifications?limit=10", headers=_headers(owner["access_token"], owner["tenant_id"]))
    assert response.status_code == 200, response.text
    assert not any(item.get("notification_type") == "finding" for item in response.json()["items"])


def test_notification_filters_findings_proven_by_passive_browser_history(test_env) -> None:
    client = test_env["client"]
    owner = _register_owner(client, email="notification-passive-findings@example.com")
    now = datetime.now(timezone.utc)
    with test_env["sessionmaker"]() as db:
        db.add(RuntimeEvent(
            event_id="passive-app-open", tenant_id=owner["tenant_id"], source_surface="browser",
            event_type="ai_app_opened", app_id="chatgpt.com", metadata_json={"event_type": "ai_app_opened"},
        ))
        for index in range(3):
            db.add(RuntimeEvent(
                event_id=f"passive-tool-{index}", tenant_id=owner["tenant_id"], source_surface="browser",
                event_type="ai_app_opened", app_id=f"app-{index}.example",
                metadata_json={"event_type": "ai_app_opened", "tool_name": f"app-{index}.example"},
            ))
            db.add(RuntimeEvent(
                event_id=f"same-agent-{index}", tenant_id=owner["tenant_id"], source_surface="browser",
                event_type="agent_runtime_discovered", app_id="localhost", agent_id="same-agent",
                metadata_json={"event_type": "agent_runtime_discovered", "agent_name": "Local agent", "detected_tools": ["web.search"]},
            ))
        for index, event_type in enumerate(("prompt_blocked", "prompt_drafted", "prompt_drafted")):
            db.add(RuntimeEvent(
                event_id=f"same-prompt-{index}", tenant_id=owner["tenant_id"], source_surface="browser",
                event_type=event_type, app_id="chatgpt.com", correlation_id="same-prompt-correlation",
                severity="high", metadata_json={"event_type": event_type, "decision": "block"},
            ))
        db.add_all([
            Finding(tenant_id=owner["tenant_id"], source_surface="browser", ai_tool="chatgpt.com", severity="high", finding_type="browser_interaction_security", risk_category="intent_policy", decision="block", status="open", recommended_action="Review", dedupe_key="false-app-open", related_runtime_event_id="passive-app-open", last_seen_at=now),
            Finding(tenant_id=owner["tenant_id"], source_surface="browser", ai_tool="browser", severity="high", finding_type="unusual_tool_sequences", risk_category="anomaly", decision="warn", status="open", recommended_action="Review", dedupe_key="false-tool-sequence", related_event_ids=[f"passive-tool-{i}" for i in range(3)], last_seen_at=now),
            Finding(tenant_id=owner["tenant_id"], source_surface="browser", ai_tool="localhost", severity="high", finding_type="unknown_ai_adoption_spike", risk_category="shadow_ai", decision="warn", status="open", recommended_action="Review", dedupe_key="false-agent-spike", related_event_ids=[f"same-agent-{i}" for i in range(3)], last_seen_at=now),
            Finding(tenant_id=owner["tenant_id"], source_surface="browser", ai_tool="chatgpt.com", severity="high", finding_type="repeated_prompt_injection_attempts", risk_category="interaction_security", decision="block", status="open", recommended_action="Review", dedupe_key="false-prompt-spike", related_event_ids=[f"same-prompt-{i}" for i in range(3)], last_seen_at=now),
            Finding(tenant_id=owner["tenant_id"], source_surface="browser", ai_tool="unknown-ai.example", severity="high", finding_type="shadow_ai_discovered", risk_category="shadow_ai", decision="warn", status="open", recommended_action="Review", dedupe_key="real-unknown-ai", last_seen_at=now),
        ])
        db.commit()
    response = client.get("/dashboard/notifications?limit=20", headers=_headers(owner["access_token"], owner["tenant_id"]))
    assert response.status_code == 200, response.text
    findings = [item for item in response.json()["items"] if item.get("notification_type") == "finding"]
    assert len(findings) == 1
    assert "shadow ai discovered" in findings[0]["title"].lower()


def test_notification_keeps_repeated_blocks_when_finding_references_only_recent_subset(test_env) -> None:
    client = test_env["client"]
    owner = _register_owner(client, email="notification-real-repeat@example.com")
    now = datetime.now(timezone.utc)
    with test_env["sessionmaker"]() as db:
        for index in range(3):
            db.add(RuntimeEvent(
                event_id=f"distinct-block-{index}", tenant_id=owner["tenant_id"], source_surface="browser",
                event_type="prompt_blocked", app_id="chatgpt.com", correlation_id=f"distinct-{index}",
                severity="high", metadata_json={"event_type": "prompt_blocked", "decision": "block"},
                created_at=now - timedelta(seconds=3 - index),
            ))
        db.add(Finding(
            tenant_id=owner["tenant_id"], source_surface="browser", ai_tool="chatgpt.com",
            severity="high", finding_type="repeated_prompt_injection_attempts", risk_category="interaction_security",
            decision="block", status="open", recommended_action="Review", dedupe_key="real-repeated-blocks",
            related_event_ids=["distinct-block-1", "distinct-block-2"], last_seen_at=now,
        ))
        db.commit()
    response = client.get("/dashboard/notifications?limit=20", headers=_headers(owner["access_token"], owner["tenant_id"]))
    assert response.status_code == 200, response.text
    assert any(item.get("notification_type") == "finding" and "repeated prompt" in item.get("title", "").lower() for item in response.json()["items"])


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "dashboard_command_center.sqlite3"
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


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Dashboard Owner"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    return {
        "access_token": payload["access_token"],
        "tenant_id": payload["tenants"][0]["id"],
        "user_id": payload["user"]["id"],
    }


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "X-Tenant-ID": tenant_id,
    }


def _create_ai_system(client: TestClient, *, headers: dict[str, str], name: str) -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": name, "description": "", "risk_tier": "HIGH"},
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def test_command_center_returns_503_when_snapshot_unavailable(test_env, monkeypatch) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="command-center-unavailable@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    def _raise_unavailable(*_args, **_kwargs):
        raise CommandCenterDataUnavailableError("Command Center snapshot unavailable while refresh is in progress.")

    monkeypatch.setattr(dashboard_router, "get_command_center_dashboard_state", _raise_unavailable)

    response = client.get("/dashboard/command-center?time_window_hours=24", headers=headers)
    assert response.status_code == 503, response.text
    assert "snapshot unavailable" in response.json().get("detail", "").lower()


def test_dashboard_notifications_surface_control_mode_and_suppress_placeholder_noise(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="notification-control-mode@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    now = datetime.now(timezone.utc)

    with session_factory() as db:
        db.add(
            AISession(
                session_id="notif-session-1",
                tenant_id=owner["tenant_id"],
                user_id=owner["user_id"],
                source_surface="browser",
                ai_app="ChatGPT",
                start_time=now - timedelta(minutes=5),
                correlation_id="notif-corr-1",
            )
        )
        db.add(
            AIAction(
                action_id="notif-action-1",
                tenant_id=owner["tenant_id"],
                session_id="notif-session-1",
                user_id=owner["user_id"],
                timestamp=now - timedelta(minutes=4),
                action_type="prompt_submit",
                ai_app="ChatGPT",
                policy_triggered="BUSINESS_EMAIL_DATA_TO_AI",
                enforcement_action="blocked",
                risk_score=0.91,
                correlation_id="notif-corr-1",
                metadata_json={
                    "source_surface": "browser",
                    "control_mode": "inline_prevented",
                    "decision_badge": "Pre-Action Blocked",
                    "ai_action": {
                        "policy": {
                            "decision": "block",
                            "control_mode": "inline_prevented",
                            "decision_badge": "Pre-Action Blocked",
                        }
                    },
                },
            )
        )
        db.add(
            AIActionAlert(
                tenant_id=owner["tenant_id"],
                action_id="notif-action-1",
                session_id="notif-session-1",
                user_id=owner["user_id"],
                alert_type="business_email_data_to_ai",
                severity="critical",
                policy_reason="business_email_data_to_ai",
                enforcement_action="blocked",
                created_at=now - timedelta(minutes=3),
            )
        )
        db.add_all(
            [
                Finding(
                    finding_id="noise-unregistered-ai-system",
                    tenant_id=owner["tenant_id"],
                    source_surface="monitoring",
                    ai_tool="unknown_tool",
                    severity="high",
                    finding_type="unregistered_ai_system",
                    risk_category="governance",
                    decision="allow",
                    status="open",
                    recommended_action="Runtime trigger referenced unknown AI system. Route to governance before use.",
                    evidence_node_ids=[],
                    related_event_ids=[],
                    related_control_ids=[],
                    remediation_action_ids=[],
                    dedupe_key="noise-unregistered-ai-system",
                    first_seen_at=now - timedelta(minutes=2),
                    last_seen_at=now - timedelta(minutes=2),
                ),
                Finding(
                    finding_id="noise-tool-sequence",
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    ai_tool="unknown_tool",
                    severity="critical",
                    finding_type="unusual_tool_sequences",
                    risk_category="action_alignment:unknown,action_type:prompt_submit",
                    decision="allow",
                    status="open",
                    recommended_action="Unusual cross-tool execution sequence detected.",
                    evidence_node_ids=[],
                    related_event_ids=[],
                    related_control_ids=[],
                    remediation_action_ids=[],
                    dedupe_key="noise-tool-sequence",
                    first_seen_at=now - timedelta(minutes=1),
                    last_seen_at=now - timedelta(minutes=1),
                ),
            ]
        )
        db.commit()

    response = client.get("/dashboard/notifications?limit=20&lookback_hours=24", headers=headers)
    assert response.status_code == 200, response.text
    items = response.json()["items"]
    titles = [str(item.get("title") or "").lower() for item in items]
    assert any("business email" in title for title in titles)
    assert all("unregistered ai system" not in title for title in titles)
    assert all("unusual tool sequence" not in title for title in titles)

    activity_alert = next(item for item in items if item["notification_type"] == "activity_alert")
    assert activity_alert["control_mode"] == "inline_prevented"
    assert activity_alert["decision_badge"] == "Pre-Action Blocked"


def test_pilot_health_prefers_fresh_extension_heartbeat_over_stale_browser_runtime(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="pilot-health-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    now = datetime.now(timezone.utc)

    with session_factory() as db:
        db.add(
            RuntimeEvent(
                event_id="runtime-pilot-health-1",
                tenant_id=owner["tenant_id"],
                source_surface="browser",
                event_type="extension_connected",
                severity="low",
                created_at=now - timedelta(hours=20, minutes=51),
            )
        )
        db.add(
            MonitoringSignal(
                tenant_id=owner["tenant_id"],
                signal_type="browser.extension_health_status",
                severity="low",
                payload={
                    "healthy": True,
                    "last_sync_at": (now - timedelta(seconds=45)).isoformat(),
                    "policy_version": "pv-test",
                    "telemetry_queue_depth": 0,
                    "enterprise_managed": True,
                    "policy_locked": True,
                    "extension_version": "0.1.8",
                    "extension_build_hash": "abcdef1234567890",
                },
                created_at=now - timedelta(seconds=45),
            )
        )
        db.commit()

    response = client.get("/dashboard/pilot-health", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["policy_sync_health"]["status"] == "ok"
    assert payload["telemetry_health"]["status"] == "ok"
    assert payload["telemetry_health"]["lag_seconds"] is not None
    assert payload["telemetry_health"]["lag_seconds"] < 120
    assert "deployment_hardening" in payload
    hardening_checks = {item["id"]: item for item in payload["deployment_hardening"]["checks"]}
    assert hardening_checks["extension_managed"]["status"] == "ok"
    assert hardening_checks["extension_policy_locked"]["status"] == "ok"

    latest_browser_event_at = datetime.fromisoformat(payload["telemetry_health"]["latest_browser_event_at"])
    assert latest_browser_event_at >= (now - timedelta(minutes=2))


def test_command_center_dashboard_aggregates_cross_module_state(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="command-center-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers=headers, name="Command Center AI")
    now = datetime.now(timezone.utc)

    with session_factory() as db:
        runtime_event = RuntimeEvent(
            event_id="runtime-command-center-1",
            tenant_id=owner["tenant_id"],
            source_surface="gateway",
            event_type="prompt_intercepted",
            ai_system_id=ai_system_id,
            user_id="owner-user",
            agent_id="agent-one",
            severity="high",
            risk_score=0.91,
            evidence_node_ids=["ev-1"],
            correlation_id="corr-command-center-1",
            metadata_json={"decision": "block", "tool_name": "web_search"},
            created_at=now - timedelta(minutes=6),
        )
        db.add(runtime_event)
        db.add(
            RuntimeEvent(
                event_id="runtime-command-center-2",
                tenant_id=owner["tenant_id"],
                source_surface="browser",
                event_type="copy_paste_check",
                ai_system_id=ai_system_id,
                user_id="owner-user",
                severity="med",
                risk_score=0.54,
                evidence_node_ids=[],
                correlation_id="corr-command-center-2",
                metadata_json={"decision": "warn"},
                created_at=now - timedelta(minutes=3),
            )
        )
        db.add(
            RuntimeGovernanceRecommendation(
                recommendation_id="runtime-reco-command-center-1",
                tenant_id=owner["tenant_id"],
                event_id="runtime-command-center-1",
                ai_system_id=ai_system_id,
                recommendation_type="tighten_policy",
                reason_code="repeated_prompt_injection_attempts",
                priority="high",
                payload={
                    "decision_impact_score": 180000.0,
                    "estimated_risk_reduction": 120000.0,
                    "base_risk": 150000.0,
                    "confidence_score": 0.82,
                    "decision_impact": {
                        "action": "tighten_policy",
                        "decision_impact_score": 180000.0,
                        "estimated_risk_reduction": 120000.0,
                        "base_risk": 150000.0,
                        "confidence": 0.82,
                        "urgency_multiplier": 1.3,
                        "control_effectiveness": 0.8,
                        "impact_value": 200000.0,
                        "probability_score": 0.75,
                        "reasoning": ["high_repeat_frequency", "sensitive_data_context"],
                    },
                },
                status="proposed",
                created_at=now - timedelta(minutes=5),
            )
        )
        db.add(
            Finding(
                tenant_id=owner["tenant_id"],
                source_surface="gateway",
                ai_tool="chatgpt",
                ai_system_id=ai_system_id,
                severity="critical",
                finding_type="repeated_prompt_injection_attempts",
                risk_category="runtime_control",
                status="open",
                recommended_action="tighten_policy",
                evidence_node_ids=["ev-1"],
                related_event_ids=["chain_dashboard_1"],
                related_control_ids=["CTRL-1"],
                related_runtime_event_id="action-dashboard-1",
                dedupe_key="finding-command-center-1",
                occurrence_count=4,
                first_seen_at=now - timedelta(days=1),
                last_seen_at=now - timedelta(minutes=5),
            )
        )
        db.add(
            DriftAlert(
                tenant_id=owner["tenant_id"],
                ai_system_id=ai_system_id,
                title="Connector drift detected",
                status="open",
                details="token scope drift",
            )
        )
        db.add(
            ShadowAIEntity(
                tenant_id=owner["tenant_id"],
                canonical_name="unknown-assistant",
                discovery_status="discovered",
                confidence_score=0.82,
                provisional_risk_tier="HIGH",
                source_surfaces=["browser", "proxy"],
                linked_ai_system_id=None,
                first_seen=now - timedelta(days=2),
                last_seen=now - timedelta(minutes=9),
                metadata_json={},
            )
        )
        db.flush()
        entity = db.scalar(
            select(ShadowAIEntity).where(
                ShadowAIEntity.tenant_id == owner["tenant_id"],
                ShadowAIEntity.canonical_name == "unknown-assistant",
            )
        )
        assert entity is not None
        db.add(
            ShadowAISignal(
                tenant_id=owner["tenant_id"],
                shadow_ai_entity_id=entity.id,
                source_surface="proxy",
                source_event_id="proxy-event-1",
                domain="unknown-ai.example",
                provider="unknown",
                confidence_signal={"source_weight": 0.6},
                raw_fingerprint={"path": "/v1/chat"},
                created_at=now - timedelta(minutes=8),
            )
        )
        db.add(
            AgentIdentity(
                tenant_id=owner["tenant_id"],
                name="agent-one",
                description="runtime agent",
                status="active",
                max_chain_depth=3,
                action_scope=["api_call"],
                tool_registry=["web_search"],
                external_system_access=["crm"],
            )
        )
        db.add(
            Control(
                id="ctrl-dashboard-1",
                tenant_id=owner["tenant_id"],
                is_global=False,
                name="Prompt Safety",
                category="interaction_security",
                description="prompt controls",
            )
        )
        db.add(
            ControlMaturity(
                tenant_id=owner["tenant_id"],
                ai_system_id=ai_system_id,
                control_id="ctrl-dashboard-1",
                technical_enforcement_score=0.7,
                simulation_pass_rate=0.55,
                coverage_score=0.66,
                maturity_score=0.62,
                status="partial",
                confidence_score=0.72,
                confidence_inputs={"signals": 5},
            )
        )
        db.add(
            SimulationDefinition(
                id="sim-dashboard-def-1",
                tenant_id=owner["tenant_id"],
                name="Prompt Attack Sim",
                category="prompt_attack",
                target_module="interaction_security",
                version="1.0.0",
                dsl_json={"steps": []},
            )
        )
        db.add(
            SimulationRun(
                id="sim-dashboard-run-1",
                tenant_id=owner["tenant_id"],
                simulation_id="sim-dashboard-def-1",
                ai_system_id=ai_system_id,
                started_at=now - timedelta(hours=2),
                finished_at=now - timedelta(hours=2, minutes=-3),
                mode="deterministic",
                inputs_used={},
                results={"result": "fail", "pass_rate": 0.42},
                controls_impacted=["ctrl-dashboard-1"],
                notes="",
            )
        )
        db.add(
            RemediationAction(
                tenant_id=owner["tenant_id"],
                remediation_type="policy_tighten",
                target_type="ai_system",
                target_id=ai_system_id,
                source_trigger_type="guardian_violation",
                source_trigger_id="finding-command-center-1",
                recommendation_text="Tighten policy",
                action_mode="recommend_only",
                status="proposed",
                risk_level="high",
                requires_approval=True,
                rollback_supported=True,
                rollback_payload={"before": {"strictness": "medium"}, "after": {"strictness": "high"}},
                created_at=now - timedelta(minutes=20),
            )
        )
        db.add(
            MonitoringSignal(
                tenant_id=owner["tenant_id"],
                ai_system_id=ai_system_id,
                signal_type="cve.runtime.openai",
                severity="critical",
                payload={"cve_id": "CVE-2026-1001"},
                created_at=now - timedelta(minutes=25),
            )
        )
        db.add(
            ApprovalRequest(
                tenant_id=owner["tenant_id"],
                ai_system_id=ai_system_id,
                enforcement_event_id=None,
                request_payload={"type": "step_up"},
                required_roles=["owner"],
                sla_minutes=15,
                default_if_timeout="block",
                status="pending",
                created_at=now - timedelta(minutes=40),
            )
        )
        db.add(
            ScheduledJobRun(
                job_name="monitoring.hourly",
                tenant_id=owner["tenant_id"],
                started_at=now - timedelta(hours=1),
                finished_at=now - timedelta(hours=1, minutes=-2),
                status="success",
                error_message=None,
            )
        )
        db.commit()

    response = client.get("/dashboard/command-center?time_window_hours=168", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()

    assert payload["tenant_id"] == owner["tenant_id"]
    assert payload["view_scope"] == "full"
    assert set(payload.keys()) >= {
        "risk_over_time",
        "severity_distribution",
        "exposure_score",
        "active_incidents",
        "runtime_heatmap",
        "shadow_ai_summary",
        "identity_risk",
        "control_coverage",
        "violations",
        "simulations",
        "remediation_actions",
        "ai_exposure_scan",
        "sla_metrics",
        "recommendations",
    }
    severity_total = sum(payload["severity_distribution"]["counts"].values())
    assert payload["severity_distribution"]["total"] == severity_total
    assert payload["shadow_ai_summary"]["total_entities"] >= 1
    assert payload["violations"]["high_critical_open_count"] >= 1
    assert payload["simulations"]["fail_count"] >= 1
    assert payload["cve_exposure"]["open_count"] >= 1
    assert payload["active_incidents"]["total"] >= 1
    assert len(payload["recommendations"]) >= 1
    assert payload["crq_summary"]["scored_recommendation_count"] >= 1
    assert payload["crq_summary"]["risk_exposure_usd"] > 0
    assert payload["crq_summary"]["risk_reduced_usd"] > 0
    assert payload["crq_summary"]["at_risk_if_ignored_usd"] > 0
    assert payload["crq_summary"]["total_estimated_risk_reduction_usd"] > 0
    assert isinstance(payload["runtime_heatmap"]["rows"], list)
    assert payload["violations"]["drilldown"] == "/discovery/findings"
    violation = payload["violations"]["items"][0]
    violation_drilldowns = {item["type"]: item["href"] for item in violation["drilldowns"]}
    assert violation_drilldowns["action_graph"] == "/runtime-intelligence/action-graph/action-dashboard-1"
    assert violation_drilldowns["action_trace"] == "/runtime-intelligence/action-trace/action-dashboard-1"
    assert violation_drilldowns["chain_graph"] == "/runtime-intelligence/chains/chain_dashboard_1/graph"
    assert violation_drilldowns["evidence"].endswith("#evidence")
    assert violation["primary_drilldown_type"] == "chain_graph"
    assert violation["investigation_link"] == "/runtime-intelligence/chains/chain_dashboard_1/graph"
    assert "agentic_browser_activity" in payload
    assert payload["agentic_browser_activity"]["automation_events_today"] >= 0


def test_command_center_dashboard_exposes_unified_operations_sections(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="command-center-ops@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    now = datetime.now(timezone.utc)

    with session_factory() as db:
        agent = AgentIdentity(
            tenant_id=owner["tenant_id"],
            name="Ops Agent",
            description="agent behavior demo",
            status="active",
            max_chain_depth=3,
            action_scope=["tool.run", "email_send"],
            tool_registry=["crm_lookup", "email_send"],
            external_system_access=["crm", "outlook"],
        )
        db.add(agent)
        db.flush()
        agent_id = agent.id
        db.add_all(
            [
                RuntimeEvent(
                    event_id="ops-trace-1",
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    event_type="prompt",
                    app_id="ChatGPT",
                    user_id="user-ops",
                    agent_id=None,
                    risk_score=0.45,
                    correlation_id="corr-ops",
                    chain_id="chain-ops",
                    metadata_json={
                        "user_email": "ops@example.com",
                        "machine_id": "machine-ops",
                        "ai_surface": "browser",
                        "browser_type": "chrome",
                        "action_type": "prompt",
                        "decision": "warn",
                    },
                    created_at=now - timedelta(minutes=5),
                ),
                RuntimeEvent(
                    event_id="ops-trace-2",
                    tenant_id=owner["tenant_id"],
                    source_surface="gateway",
                    event_type="tool_call",
                    app_id="Azure OpenAI",
                    user_id="user-ops",
                    agent_id=agent_id,
                    risk_score=0.92,
                    correlation_id="corr-ops",
                    chain_id="chain-ops",
                    metadata_json={
                        "user_email": "ops@example.com",
                        "machine_id": "machine-ops",
                        "ai_surface": "gateway",
                        "action_type": "tool_call",
                        "tool_name": "email_send",
                        "decision": "block",
                        "triggered_controls": ["CTRL-AGENT-SCOPE"],
                        "finding_id": "finding-ops",
                    },
                    created_at=now - timedelta(minutes=2),
                ),
                RuntimeEvent(
                    event_id="ops-browser-prevented",
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    event_type="browser_automation_action",
                    app_id="jira.example.com",
                    user_id="user-ops",
                    agent_id=agent_id,
                    risk_score=0.89,
                    correlation_id="corr-browser-ops",
                    chain_id="chain-browser-ops",
                    metadata_json={
                        "user_email": "ops@example.com",
                        "machine_id": "machine-ops",
                        "ai_surface": "agentic_browser",
                        "browser_type": "chrome",
                        "action_type": "form_submit",
                        "action_risk": "high",
                        "decision": "block",
                        "control_mode": "inline_prevented",
                        "decision_badge": "Pre-Action Blocked",
                        "source_vendor": "custom",
                        "ai_action": {
                            "action_id": "ops-browser-prevented",
                            "surface": {"surface_type": "agentic_browser", "application": "Jira", "domain": "jira.example.com"},
                            "action": {"action_type": "form_submit", "action_risk": "high"},
                            "policy": {
                                "decision": "block",
                                "control_mode": "inline_prevented",
                                "decision_badge": "Pre-Action Blocked",
                            },
                            "evidence": {"evidence_status": "complete", "evidence_refs": ["ev-browser"]},
                            "decision_explanation": {
                                "explanation_id": "decision-explanation:ops-browser-prevented",
                                "decision_summary": {
                                    "final_decision": "block",
                                    "control_mode": "inline_prevented",
                                    "plain_english_reason": "form submit was blocked because of high-risk browser action.",
                                },
                                "decision_factors": [
                                    {"factor_type": "action", "label": "High-risk browser action", "effect": "block"}
                                ],
                            },
                        },
                    },
                    created_at=now - timedelta(minutes=3),
                ),
            ]
        )
        db.add(
            Finding(
                finding_id="finding-ops",
                tenant_id=owner["tenant_id"],
                source_surface="gateway",
                ai_tool="Azure OpenAI",
                user_id="user-ops",
                agent_id=agent_id,
                machine_id="machine-ops",
                severity="high",
                finding_type="agent_tool_blocked",
                risk_category="agent_runtime",
                status="open",
                recommended_action="Disable agent or require approval.",
                related_event_ids=["ops-trace-1", "ops-trace-2"],
                related_control_ids=["CTRL-AGENT-SCOPE"],
                evidence_node_ids=[],
                dedupe_key="finding-ops",
                first_seen_at=now - timedelta(minutes=2),
                last_seen_at=now - timedelta(minutes=1),
            )
        )
        db.commit()

    response = client.get("/dashboard/command-center?time_window_hours=24&force_refresh=true", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()

    assert payload["live_activity_feed"]["items"][0]["event_id"] == "ops-trace-2"
    browser_activity = next(
        item for item in payload["live_activity_feed"]["items"] if item["event_id"] == "ops-browser-prevented"
    )
    assert browser_activity["ai_action_id"] == "ops-browser-prevented"
    assert browser_activity["control_mode"] == "inline_prevented"
    assert browser_activity["decision_badge"] == "Prevented"
    assert browser_activity["decision_explanation"]["explanation_id"] == "decision-explanation:ops-browser-prevented"
    assert browser_activity["decision_explanation"]["decision_summary"]["final_decision"] == "block"
    assert browser_activity["application"] == "Jira"
    assert browser_activity["action_trace_url"] == "/runtime-intelligence/action-trace/ops-browser-prevented"
    assert browser_activity["action_graph_url"] == "/runtime-intelligence/action-graph/ops-browser-prevented"
    assert browser_activity["trace_url"] == "/runtime-intelligence/context-graph?event_id=ops-browser-prevented"
    assert payload["users_view"]["items"][0]["user_id"] == "user-ops"
    assert payload["users_view"]["items"][0]["machine_ids"] == ["machine-ops"]
    assert payload["agents_view"]["items"][0]["agent_id"] == agent_id
    assert payload["agents_view"]["items"][0]["recent_actions"][0]["action_type"] == "tool_call"
    finding_alert = payload["findings_alerts"]["items"][0]
    assert finding_alert["finding_id"] == "finding-ops"
    alert_drilldowns = {item["type"]: item["href"] for item in finding_alert["drilldowns"]}
    assert alert_drilldowns["finding_detail"] == "/discovery/findings/finding-ops"
    assert alert_drilldowns["traceability"].endswith("#traceability")
    assert alert_drilldowns["evidence"].endswith("#evidence")
    assert alert_drilldowns["agent_touchpoints"] == f"/ai-iam/agents/{agent_id}"
    assert finding_alert["primary_drilldown_type"] == "evidence"
    assert finding_alert["investigation_link"] == alert_drilldowns["evidence"]
    assert payload["surface_coverage_summary"]["surfaces"]["browser"]["event_count"] == 1
    assert payload["surface_coverage_summary"]["surfaces"]["agentic_browser"]["event_count"] == 1
    assert payload["surface_coverage_summary"]["surfaces"]["gateway"]["event_count"] == 1
    assert payload["agentic_browser_activity"]["automation_events_today"] >= 0
    assert payload["agentic_browser_activity"]["prevented_events"] >= 1
    assert payload["agentic_browser_activity"]["decision_badge_breakdown"]["Prevented"] >= 1
    assert payload["agentic_browser_activity"]["high_risk_actions_blocked"] >= 1
    assert payload["agentic_browser_activity"]["drilldown"] == "/runtime-intelligence/activity-map?surface=agentic_browser"
    assert payload["attack_trace_view"]["trace_key"] == "chain-ops"
    assert [step["event_id"] for step in payload["attack_trace_view"]["steps"]] == ["ops-trace-1", "ops-trace-2"]
    assert {action["action"] for action in payload["quick_actions"]} >= {
        "block_user",
        "revoke_token",
        "disable_agent",
        "block_tool",
        "isolate",
        "enforce_strict_policy",
        "require_approval",
        "route_finding",
    }


def test_command_center_dashboard_summarizes_ai_action_control_modes_and_evidence(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="command-center-action-control@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    now = datetime.now(timezone.utc)

    with session_factory() as db:
        db.add(
            AISession(
                session_id="action-control-session",
                tenant_id=owner["tenant_id"],
                user_id=owner["user_id"],
                source_surface="browser",
                ai_app="ChatGPT",
                start_time=now - timedelta(minutes=10),
                correlation_id="action-control-corr",
            )
        )
        db.add_all(
            [
                AIAction(
                    action_id="action-control-prevented",
                    tenant_id=owner["tenant_id"],
                    session_id="action-control-session",
                    user_id=owner["user_id"],
                    timestamp=now - timedelta(minutes=4),
                    action_type="file_upload",
                    ai_app="ChatGPT",
                    policy_triggered="CUSTOMER_CONTACT_DATA_TO_AI",
                    enforcement_action="blocked",
                    risk_score=0.94,
                    correlation_id="action-control-corr",
                    metadata_json={
                        "source_surface": "browser",
                        "evidence_status": "complete",
                        "ai_action": {
                            "policy": {"control_mode": "inline_prevented", "decision": "block"},
                            "evidence": {
                                "evidence_status": "complete",
                                "evidence_refs": ["evidence:action-control-prevented"],
                            },
                        },
                    },
                ),
                AIAction(
                    action_id="action-control-detected",
                    tenant_id=owner["tenant_id"],
                    session_id="action-control-session",
                    user_id=owner["user_id"],
                    timestamp=now - timedelta(minutes=3),
                    action_type="prompt_submit",
                    ai_app="Unknown AI",
                    policy_triggered="SHADOW_AI_DISCOVERED",
                    enforcement_action="detected",
                    risk_score=0.62,
                    correlation_id="action-control-corr-2",
                    metadata_json={
                        "source_surface": "browser",
                        "evidence_status": "incomplete",
                        "ai_action": {
                            "policy": {"control_mode": "detected_only", "decision": "detect_only"},
                            "evidence": {"evidence_status": "incomplete", "evidence_refs": []},
                        },
                    },
                ),
            ]
        )
        db.commit()

    response = client.get("/dashboard/command-center?time_window_hours=24&force_refresh=true", headers=headers)
    assert response.status_code == 200, response.text
    summary = response.json()["ai_action_control"]

    assert summary["total_actions"] == 2
    assert summary["control_mode_counts"]["inline_prevented"] == 1
    assert summary["control_mode_counts"]["detected_only"] == 1
    assert summary["evidence_status_counts"]["complete"] == 1
    assert summary["evidence_status_counts"]["incomplete"] == 1
    assert summary["high_risk_actions"] == 1
    assert summary["top_actions"][0]["action_id"] == "action-control-prevented"
    assert summary["top_actions"][0]["control_mode"] == "inline_prevented"
    assert summary["top_actions"][0]["evidence_status"] == "complete"
    assert summary["drilldown"] == "/runtime-intelligence/actions"


def test_command_center_dashboard_returns_buyer_ready_surface_matrix(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="command-center-surface-matrix@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    now = datetime.now(timezone.utc)

    with session_factory() as db:
        db.add_all(
            [
                RuntimeEvent(
                    event_id="surface-browser-block",
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    event_type="prompt_submit",
                    app_id="ChatGPT",
                    user_id=owner["user_id"],
                    risk_score=0.91,
                    correlation_id="surface-matrix",
                    metadata_json={
                        "ai_surface": "browser",
                        "action_type": "prompt_submit",
                        "decision": "block",
                        "control_mode": "inline_prevented",
                    },
                    created_at=now - timedelta(minutes=5),
                ),
                RuntimeEvent(
                    event_id="surface-mcp-block",
                    tenant_id=owner["tenant_id"],
                    source_surface="gateway",
                    event_type="mcp_tool_call",
                    app_id="Claude Code",
                    user_id=owner["user_id"],
                    agent_id="agent-mcp",
                    risk_score=0.96,
                    correlation_id="surface-matrix",
                    metadata_json={
                        "ai_surface": "mcp",
                        "action_type": "mcp_tool_call",
                        "tool_name": "write_file",
                        "mcp_server_id": "repo-tools",
                        "decision": "block",
                        "control_mode": "inline_prevented",
                    },
                    created_at=now - timedelta(minutes=4),
                ),
                RuntimeEvent(
                    event_id="surface-foundry-external",
                    tenant_id=owner["tenant_id"],
                    source_surface="foundry",
                    event_type="foundry_agent_action",
                    app_id="Azure AI Foundry",
                    user_id=owner["user_id"],
                    agent_id="foundry-agent-1",
                    risk_score=0.73,
                    correlation_id="surface-matrix",
                    metadata_json={
                        "ai_surface": "foundry",
                        "action_type": "foundry_agent_action",
                        "decision": "block",
                        "control_mode": "external_required",
                        "project_id": "foundry-project-1",
                    },
                    created_at=now - timedelta(minutes=3),
                ),
                RuntimeEvent(
                    event_id="surface-copilot-telemetry",
                    tenant_id=owner["tenant_id"],
                    source_surface="copilot",
                    event_type="copilot_event",
                    app_id="M365 Copilot",
                    user_id=owner["user_id"],
                    risk_score=0.32,
                    correlation_id="surface-matrix",
                    metadata_json={
                        "ai_surface": "copilot",
                        "action_type": "copilot_event",
                        "decision": "allow",
                        "control_mode": "telemetry_only",
                    },
                    created_at=now - timedelta(minutes=2),
                ),
            ]
        )
        db.commit()

    response = client.get("/dashboard/command-center?time_window_hours=24&force_refresh=true", headers=headers)
    assert response.status_code == 200, response.text
    summary = response.json()["surface_coverage_summary"]

    rows = {row["id"]: row for row in summary["surface_rows"]}
    assert {"browser", "mcp", "gateway_sdk", "foundry", "copilot", "desktop_proxy"}.issubset(rows)
    assert rows["browser"]["inline_prevented"] == 1
    assert rows["browser"]["current_mode"] == "inline_prevented"
    assert rows["browser"]["status"] == "active_inline"
    assert rows["mcp"]["inline_prevented"] == 1
    assert "tool" in rows["mcp"]["proof_label"].lower()
    assert rows["foundry"]["external_required"] == 1
    assert rows["foundry"]["current_mode"] == "external_required"
    assert rows["foundry"]["drilldown"] == "/surface-coverage#foundry"
    assert rows["copilot"]["telemetry_only"] == 1
    assert rows["copilot"]["status"] == "telemetry_only"
    assert summary["totals"]["event_count"] == 4
    assert summary["totals"]["inline_prevented"] == 2
    assert summary["totals"]["external_required"] == 1
    assert summary["totals"]["telemetry_only"] == 1


def test_command_center_dashboard_exposes_intent_aware_activity_summary(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="command-center-intent-aware@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    now = datetime.now(timezone.utc)

    intent_events = [
        RuntimeEvent(
            event_id="intent-allowed-research",
            tenant_id=owner["tenant_id"],
            source_surface="browser",
            event_type="prompt_submitted",
            app_id="chatgpt.com",
            user_id=owner["user_id"],
            decision="allow",
            risk_score=0.12,
            metadata_json={
                "ai_surface": "browser_extension",
                "application": "ChatGPT",
                "action_type": "prompt_submit",
                "intent_context": {"intent_category": "market_research"},
                "input_content_context": {"sensitivity_level": "low"},
                "output_context": {"output_sensitivity": "low"},
                "action_alignment_result": {"alignment": "aligned"},
                "destination_context": {"trust_level": "public_ai", "domain": "chatgpt.com"},
                "intent_aware_decision": {"decision": "allow", "decision_reason": "public_research_allowed"},
            },
            created_at=now - timedelta(minutes=5),
        ),
        RuntimeEvent(
            event_id="intent-blocked-input",
            tenant_id=owner["tenant_id"],
            source_surface="browser",
            event_type="prompt_submitted",
            app_id="chatgpt.com",
            user_id=owner["user_id"],
            decision="block",
            risk_score=0.91,
            metadata_json={
                "ai_surface": "browser_extension",
                "application": "ChatGPT",
                "action_type": "prompt_submit",
                "intent_context": {"intent_category": "sales_outreach"},
                "input_content_context": {"sensitivity_level": "high", "contains_business_emails": True},
                "action_alignment_result": {"alignment": "aligned"},
                "destination_context": {"trust_level": "public_ai", "domain": "chatgpt.com"},
                "intent_aware_decision": {
                    "decision": "block",
                    "decision_reason": "business_email_data_to_ai",
                    "finding_type": "BUSINESS_EMAIL_DATA_TO_AI",
                },
            },
            created_at=now - timedelta(minutes=4),
        ),
        RuntimeEvent(
            event_id="intent-shadow-output",
            tenant_id=owner["tenant_id"],
            source_surface="browser",
            event_type="data_transfer_check",
            app_id="wiki.acme.ai",
            user_id=owner["user_id"],
            decision="allow",
            risk_score=0.58,
            metadata_json={
                "ai_surface": "browser_extension",
                "application": "Internal Wiki",
                "action_type": "copy_output",
                "intent_context": {"intent_category": "company_lookup"},
                "output_context": {"output_sensitivity": "high", "contains_business_email": True},
                "action_alignment_result": {"alignment": "aligned"},
                "destination_context": {"trust_level": "approved_enterprise", "domain": "wiki.acme.ai"},
                "copy_export_control_applied": True,
                "intent_aware_decision": {
                    "decision": "allow",
                    "would_decision": "block",
                    "mode": "shadow",
                    "decision_reason": "ai_output_copy_contains_business_email",
                    "finding_type": "AI_OUTPUT_COPY_BLOCKED",
                },
            },
            created_at=now - timedelta(minutes=3),
        ),
        RuntimeEvent(
            event_id="intent-scope-violation",
            tenant_id=owner["tenant_id"],
            source_surface="agent",
            event_type="agent_action_intercept",
            app_id="mail.google.com",
            user_id=owner["user_id"],
            agent_id="agent-intent-1",
            decision="block",
            risk_score=0.87,
            metadata_json={
                "ai_surface": "agent",
                "application": "Gmail",
                "action_type": "send_email",
                "intent_context": {"intent_category": "public_research"},
                "action_alignment_result": {"alignment": "out_of_scope"},
                "destination_context": {"trust_level": "approved_public", "domain": "mail.google.com"},
                "intent_aware_decision": {
                    "decision": "block",
                    "decision_reason": "intent_action_scope_violation",
                    "finding_type": "INTENT_ACTION_SCOPE_VIOLATION",
                },
            },
            created_at=now - timedelta(minutes=2),
        ),
    ]

    with session_factory() as db:
        db.add_all(intent_events)
        db.commit()

    response = client.get("/dashboard/command-center?time_window_hours=24&force_refresh=true", headers=headers)
    assert response.status_code == 200, response.text
    summary = response.json()["intent_aware_activity"]

    assert summary["intent_aware_actions"] == 4
    assert summary["allowed_research"] == 1
    assert summary["blocked_sensitive_inputs"] == 1
    assert summary["blocked_output_copies"] == 1
    assert summary["intent_scope_violations"] == 1
    assert summary["sales_outreach_data_violations"] == 1
    assert summary["shadow_would_block"] == 1
    assert summary["top_sensitive_destinations"][0] == {"trust_level": "public_ai", "count": 1}
    assert summary["badge_breakdown"]["Prevented"] == 2
    assert summary["badge_breakdown"]["Allowed"] == 1
    assert summary["drilldown"] == "/runtime-intelligence/activity-map?filter=intent-aware"


def test_command_center_dashboard_applies_server_side_intent_filters(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="command-center-intent-filter@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    now = datetime.now(timezone.utc)

    with session_factory() as db:
        db.add_all(
            [
                RuntimeEvent(
                    event_id="intent-filter-sales-block",
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    event_type="prompt_submitted",
                    app_id="chatgpt.com",
                    user_id=owner["user_id"],
                    decision="block",
                    risk_score=0.93,
                    metadata_json={
                        "application": "ChatGPT",
                        "action_type": "prompt_submit",
                        "intent_context": {"intent_category": "sales_outreach"},
                        "input_content_context": {"sensitivity_level": "high", "contains_business_emails": True},
                        "output_context": {"output_sensitivity": "none"},
                        "action_alignment_result": {"alignment": "aligned"},
                        "destination_context": {"trust_level": "public_ai", "domain": "chatgpt.com"},
                        "intent_aware_decision": {
                            "decision": "block",
                            "decision_reason": "business_email_data_to_ai",
                            "finding_type": "BUSINESS_EMAIL_DATA_TO_AI",
                        },
                    },
                    created_at=now - timedelta(minutes=5),
                ),
                RuntimeEvent(
                    event_id="intent-filter-research-allow",
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    event_type="prompt_submitted",
                    app_id="perplexity.ai",
                    user_id=owner["user_id"],
                    decision="allow",
                    risk_score=0.1,
                    metadata_json={
                        "application": "Perplexity",
                        "action_type": "prompt_submit",
                        "intent_context": {"intent_category": "market_research"},
                        "input_content_context": {"sensitivity_level": "low"},
                        "output_context": {"output_sensitivity": "low"},
                        "action_alignment_result": {"alignment": "aligned"},
                        "destination_context": {"trust_level": "public_ai", "domain": "perplexity.ai"},
                        "intent_aware_decision": {"decision": "allow", "decision_reason": "public_research_allowed"},
                    },
                    created_at=now - timedelta(minutes=4),
                ),
                RuntimeEvent(
                    event_id="intent-filter-scope-block",
                    tenant_id=owner["tenant_id"],
                    source_surface="agent",
                    event_type="agent_action_intercept",
                    app_id="mail.google.com",
                    user_id=owner["user_id"],
                    agent_id="agent-intent-filter",
                    decision="block",
                    risk_score=0.88,
                    metadata_json={
                        "application": "Gmail",
                        "action_type": "send_email",
                        "intent_context": {"intent_category": "public_research"},
                        "input_content_context": {"sensitivity_level": "none"},
                        "action_alignment_result": {"alignment": "out_of_scope"},
                        "intent_aware_decision": {
                            "decision": "block",
                            "decision_reason": "intent_action_scope_violation",
                            "finding_type": "INTENT_ACTION_SCOPE_VIOLATION",
                        },
                    },
                    created_at=now - timedelta(minutes=3),
                ),
            ]
        )
        db.commit()

    response = client.get(
        "/dashboard/command-center"
        "?time_window_hours=24"
        "&intent_category=sales_outreach"
        "&input_sensitivity=high"
        "&output_sensitivity=none"
        "&action_alignment=aligned"
        "&force_refresh=true",
        headers=headers,
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["filters_applied"]["intent_category"] == "sales_outreach"
    assert payload["filters_applied"]["input_sensitivity"] == "high"
    assert payload["filters_applied"]["output_sensitivity"] == "none"
    assert payload["filters_applied"]["action_alignment"] == "aligned"
    assert payload["live_activity_feed"]["total"] == 1
    assert payload["live_activity_feed"]["items"][0]["event_id"] == "intent-filter-sales-block"
    assert payload["intent_aware_activity"]["intent_aware_actions"] == 1
    assert payload["intent_aware_activity"]["sales_outreach_data_violations"] == 1
    assert payload["intent_aware_activity"]["allowed_research"] == 0
    assert "market_research" in payload["available_filters"]["intent_categories"]
    assert "sales_outreach" in payload["available_filters"]["intent_categories"]
    assert "out_of_scope" in payload["available_filters"]["action_alignments"]


def test_command_center_dashboard_filters_and_refresh_behavior(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="command-center-filter-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_primary = _create_ai_system(client, headers=headers, name="Primary AI")
    ai_system_secondary = _create_ai_system(client, headers=headers, name="Secondary AI")
    now = datetime.now(timezone.utc)

    with session_factory() as db:
        db.add(
            Finding(
                tenant_id=owner["tenant_id"],
                source_surface="gateway",
                ai_tool="primary-tool",
                ai_system_id=ai_system_primary,
                severity="high",
                finding_type="repeated_tool_denials",
                risk_category="runtime_control",
                status="open",
                recommended_action="route_to_governance",
                evidence_node_ids=[],
                related_control_ids=[],
                dedupe_key="primary-high-1",
                occurrence_count=2,
                first_seen_at=now - timedelta(hours=2),
                last_seen_at=now - timedelta(hours=1),
            )
        )
        db.add(
            Finding(
                tenant_id=owner["tenant_id"],
                source_surface="gateway",
                ai_tool="secondary-tool",
                ai_system_id=ai_system_secondary,
                severity="critical",
                finding_type="repeated_prompt_injection_attempts",
                risk_category="runtime_control",
                status="open",
                recommended_action="block",
                evidence_node_ids=[],
                related_control_ids=[],
                dedupe_key="secondary-critical-1",
                occurrence_count=1,
                first_seen_at=now - timedelta(hours=3),
                last_seen_at=now - timedelta(hours=1, minutes=20),
            )
        )
        db.add(
            RuntimeEvent(
                event_id="runtime-filter-1",
                tenant_id=owner["tenant_id"],
                source_surface="gateway",
                event_type="prompt_intercepted",
                ai_system_id=ai_system_primary,
                severity="high",
                evidence_node_ids=[],
                risk_score=0.81,
                metadata_json={"decision": "block"},
                created_at=now - timedelta(hours=1, minutes=10),
            )
        )
        db.commit()

    primary_only = client.get(
        f"/dashboard/command-center?time_window_hours=72&ai_system_id={ai_system_primary}&severity=high",
        headers=headers,
    )
    assert primary_only.status_code == 200, primary_only.text
    primary_payload = primary_only.json()
    assert primary_payload["filters_applied"]["ai_system_id"] == ai_system_primary
    assert primary_payload["filters_applied"]["severity"] == "high"
    assert primary_payload["violations"]["count"] == 1

    with session_factory() as db:
        db.add(
            Finding(
                tenant_id=owner["tenant_id"],
                source_surface="browser",
                ai_tool="primary-tool",
                ai_system_id=ai_system_primary,
                severity="high",
                finding_type="repeated_sensitive_data_attempts",
                risk_category="data_transfer",
                status="open",
                recommended_action="tighten_policy",
                evidence_node_ids=[],
                related_control_ids=[],
                dedupe_key="primary-high-2",
                occurrence_count=3,
                first_seen_at=now - timedelta(minutes=20),
                last_seen_at=now - timedelta(minutes=10),
            )
        )
        db.commit()

    refreshed = client.get(
        f"/dashboard/command-center?time_window_hours=72&ai_system_id={ai_system_primary}&severity=high&force_refresh=true",
        headers=headers,
    )
    assert refreshed.status_code == 200, refreshed.text
    refreshed_payload = refreshed.json()
    assert refreshed_payload["violations"]["count"] == 2

    with session_factory() as db:
        role = db.scalar(
            select(UserTenantRole).where(
                UserTenantRole.user_id == owner["user_id"],
                UserTenantRole.tenant_id == owner["tenant_id"],
            )
        )
        assert role is not None
        role.role = "auditor"
        db.commit()

    scoped = client.get("/dashboard/command-center?time_window_hours=72&force_refresh=true", headers=headers)
    assert scoped.status_code == 200, scoped.text
    scoped_payload = scoped.json()
    assert scoped_payload["view_scope"] == "scoped"
    if scoped_payload["identity_risk"]["top_agents"]:
        assert "agent_name" not in scoped_payload["identity_risk"]["top_agents"][0]


def test_dashboard_notifications_surface_activity_alert_with_user_and_device(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="command-center-notify-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    with session_factory() as db:
        record_activity_event(
            db,
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            payload={
                "event_type": "prompt_blocked",
                "action_type": "prompt_input",
                "source_surface": "browser",
                "domain": "chatgpt.com",
                "ai_app": "chatgpt.com",
                "action_taken": "blocked",
                "enforcement_action": "blocked",
                "policy_triggered": "sensitive_data_pattern",
                "severity": "critical",
                "risk_score": 0.95,
                "correlation_id": "corr-dashboard-notify-1",
                "browser": "chrome",
                "browser_profile": "default",
                "endpoint_id": "ep-dashboard-test-1",
                "hostname": "analyst-mac",
                "os_type": "mac",
                "browser_version": "123.0.0.0",
                "extension_version": "1.2.3",
                "metadata": {
                    "source_surface": "browser",
                    "ai_action": {
                        "chain": {"chain_id": "chain_dashboard_notify_1"},
                        "policy": {"control_mode": "inline_prevented"},
                    },
                },
            },
        )
        db.commit()

    response = client.get("/dashboard/notifications?limit=10", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()

    assert payload["tenant_id"] == owner["tenant_id"]
    assert payload["total"] >= 1
    assert isinstance(payload["items"], list)

    activity_items = [item for item in payload["items"] if item.get("notification_type") == "activity_alert"]
    assert activity_items, payload["items"]
    first = activity_items[0]
    assert first["actor_user_id"] == owner["user_id"]
    assert first["source_surface"] == "browser"
    assert "chatgpt.com" in first["title"].lower()
    assert "blocked" in first["title"].lower()
    assert "sensitive prompt" in first["title"].lower()
    assert "alert: sensitive prompt" in str(first.get("summary") or "").lower()
    assert first["endpoint_id"] == "ep-dashboard-test-1"
    assert first["link"]
    drilldowns = {item["type"]: item for item in first.get("drilldowns") or []}
    assert drilldowns["action_graph"]["href"].startswith("/runtime-intelligence/action-graph/")
    assert drilldowns["action_trace"]["href"].startswith("/runtime-intelligence/action-trace/")
    assert drilldowns["chain_graph"]["href"] == "/runtime-intelligence/chains/chain_dashboard_notify_1/graph"
    assert first["primary_drilldown_type"] == "chain_graph"
    assert first["investigation_link"] == drilldowns["chain_graph"]["href"]
    if first.get("finding_id"):
        assert drilldowns["traceability"]["href"].endswith("#traceability")
        assert drilldowns["evidence"]["href"].endswith("#evidence")


def test_dashboard_notifications_dedupe_duplicate_activity_alerts(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="command-center-notify-dedupe-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    with session_factory() as db:
        record = record_activity_event(
            db,
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            payload={
                "event_type": "prompt_blocked",
                "action_type": "prompt_input",
                "source_surface": "browser",
                "domain": "chatgpt.com",
                "ai_app": "chatgpt.com",
                "action_taken": "blocked",
                "enforcement_action": "blocked",
                "policy_triggered": "prompt_injection",
                "severity": "critical",
                "risk_score": 0.99,
                "correlation_id": "corr-dashboard-notify-dedupe-1",
                "browser": "chrome",
                "browser_profile": "default",
                "endpoint_id": "ep-dashboard-dedupe-1",
                "hostname": "risk-analyst-mac",
                "os_type": "mac",
                "browser_version": "123.0.0.0",
                "extension_version": "1.2.3",
                "metadata": {"source_surface": "browser"},
            },
        )
        duplicate_alert = AIActionAlert(
            tenant_id=owner["tenant_id"],
            action_id=record.action_id,
            session_id=record.session_id,
            user_id=owner["user_id"],
            endpoint_id=record.endpoint_id,
            finding_id=None,
            alert_type="prompt_injection",
            severity="critical",
            policy_reason="prompt_injection",
            enforcement_action="blocked",
        )
        db.add(duplicate_alert)
        db.commit()

    response = client.get("/dashboard/notifications?limit=20", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()

    deduped = [
        item
        for item in payload["items"]
        if item.get("notification_type") == "activity_alert"
        and item.get("correlation_id") == "corr-dashboard-notify-dedupe-1"
    ]
    assert len(deduped) == 1, payload["items"]
    assert "prompt injection" in str(deduped[0].get("title") or "").lower()


def test_dashboard_notifications_suppress_pilot_noise_but_keep_real_shadow_ai(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="command-center-noise-filter@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    now = datetime.now(timezone.utc)
    with session_factory() as db:
        db.add_all(
            [
                Finding(
                    tenant_id=owner["tenant_id"],
                    source_surface="monitoring",
                    ai_tool="unknown_ai_system",
                    severity="high",
                    finding_type="unregistered_ai_system",
                    risk_category="unknown_ai",
                    decision="allow",
                    status="open",
                    recommended_action="Runtime trigger referenced unknown AI system.",
                    dedupe_key="noise-unknown-ai-system",
                    last_seen_at=now,
                ),
                Finding(
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    ai_tool="unknown_tool",
                    user_id=owner["user_id"],
                    severity="critical",
                    finding_type="unusual_tool_sequences",
                    risk_category="action_alignment:unknown",
                    decision="allow",
                    status="open",
                    recommended_action="Unusual cross-tool execution sequence detected.",
                    dedupe_key="noise-unknown-tool-sequence",
                    last_seen_at=now,
                ),
                Finding(
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    ai_tool="new-ai.example",
                    user_id=owner["user_id"],
                    severity="high",
                    finding_type="shadow_ai_discovered",
                    risk_category="shadow_ai",
                    decision="warn",
                    status="open",
                    recommended_action="Review shadow AI entity and assign governance owner.",
                    dedupe_key="real-shadow-ai-new-ai-example",
                    last_seen_at=now,
                ),
                MonitoringSignal(
                    tenant_id=owner["tenant_id"],
                    ai_system_id=None,
                    signal_type="browser.extension_health_status",
                    severity="med",
                    payload={
                        "event_type": "extension_health_status",
                        "source_surface": "browser_extension",
                        "user_id": owner["user_id"],
                        "domain": "extension.local",
                    },
                ),
                MonitoringSignal(
                    tenant_id=owner["tenant_id"],
                    ai_system_id=None,
                    signal_type="shadow_ai.browser_unknown_domain",
                    severity="high",
                    payload={
                        "event_type": "unknown_ai_detected",
                        "source_surface": "browser_extension",
                        "user_id": owner["user_id"],
                        "domain": "localhost",
                        "url": "http://localhost:3000/dashboard/command-center",
                        "page_title": "AI Control Plane",
                    },
                ),
                MonitoringSignal(
                    tenant_id=owner["tenant_id"],
                    ai_system_id=None,
                    signal_type="shadow_ai.browser_unknown_domain",
                    severity="high",
                    payload={
                        "event_type": "unknown_ai_detected",
                        "source_surface": "browser_extension",
                        "user_id": owner["user_id"],
                        "domain": "new-ai.example",
                        "action_taken": "monitor",
                        "input_signal_types": ["ai_like_prompt_box"],
                    },
                ),
            ]
        )
        db.commit()

    response = client.get("/dashboard/notifications?limit=20", headers=headers)
    assert response.status_code == 200, response.text
    items = response.json()["items"]
    rendered = "\n".join(f"{item.get('title')} {item.get('summary')}" for item in items).lower()
    assert "unregistered ai system" not in rendered
    assert "unknown_tool" not in rendered
    assert "extension_health_status" not in rendered
    assert "extension.local" not in rendered
    assert "localhost" not in rendered
    assert "new-ai.example" in rendered
    assert "shadow ai" in rendered or "unknown ai usage" in rendered


def test_dashboard_notifications_hide_internal_checks_and_group_repeated_discovery(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="command-center-internal-check-filter@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    now = datetime.now(timezone.utc)
    with session_factory() as db:
        db.add_all(
            [
                Finding(
                    tenant_id=owner["tenant_id"],
                    source_surface="monitoring",
                    ai_tool="scheduler",
                    severity="med",
                    finding_type="worker_heartbeat",
                    risk_category="internal_health",
                    decision="allow",
                    status="open",
                    recommended_action="Worker heartbeat check completed.",
                    dedupe_key="internal-worker-heartbeat",
                    last_seen_at=now,
                ),
                MonitoringSignal(
                    tenant_id=owner["tenant_id"],
                    ai_system_id=None,
                    signal_type="endpoint.heartbeat",
                    severity="low",
                    payload={
                        "event_type": "endpoint_heartbeat",
                        "source_surface": "endpoint",
                        "user_id": owner["user_id"],
                        "endpoint_id": "ep-heartbeat-noise",
                        "message": "Heartbeat check passed",
                    },
                ),
                MonitoringSignal(
                    tenant_id=owner["tenant_id"],
                    ai_system_id=None,
                    signal_type="browser.extension_heartbeat",
                    severity="low",
                    payload={
                        "event_type": "extension_heartbeat",
                        "source_surface": "browser_extension",
                        "user_id": owner["user_id"],
                        "domain": "extension.local",
                    },
                ),
                MonitoringSignal(
                    tenant_id=owner["tenant_id"],
                    ai_system_id=None,
                    signal_type="shadow_ai.browser_unknown_domain",
                    severity="high",
                    payload={
                        "event_type": "unknown_ai_detected",
                        "source_surface": "browser_extension",
                        "user_id": owner["user_id"],
                        "endpoint_id": "ep-browser-demo-1",
                        "domain": "chatgpt.com",
                        "action_taken": "monitor",
                        "input_signal_types": ["ai_like_prompt_box"],
                    },
                    created_at=now - timedelta(minutes=3),
                ),
                MonitoringSignal(
                    tenant_id=owner["tenant_id"],
                    ai_system_id=None,
                    signal_type="shadow_ai.browser_unknown_domain",
                    severity="high",
                    payload={
                        "event_type": "unknown_ai_detected",
                        "source_surface": "browser_extension",
                        "user_id": owner["user_id"],
                        "endpoint_id": "ep-browser-demo-1",
                        "domain": "chatgpt.com",
                        "action_taken": "monitor",
                        "input_signal_types": ["ai_like_prompt_box"],
                    },
                    created_at=now,
                ),
            ]
        )
        db.commit()

    response = client.get("/dashboard/notifications?limit=20", headers=headers)
    assert response.status_code == 200, response.text
    items = response.json()["items"]
    rendered = "\n".join(f"{item.get('title')} {item.get('summary')}" for item in items).lower()
    assert "heartbeat" not in rendered
    assert "internal health" not in rendered
    discovery_items = [
        item
        for item in items
        if item.get("notification_type") == "discovery_signal"
        and "chatgpt.com" in str(item.get("title") or "").lower()
    ]
    assert len(discovery_items) == 1, items
    assert discovery_items[0].get("repeat_count") == 2


def test_dashboard_notifications_surfaces_local_discovery_signal(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="command-center-notify-local-discovery@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    now = datetime.now(timezone.utc)
    with session_factory() as db:
        db.add(
            MonitoringSignal(
                tenant_id=owner["tenant_id"],
                ai_system_id=None,
                signal_type="shadow_ai.browser_unknown_domain",
                severity="high",
                payload={
                    "event_type": "unknown_ai_detected",
                    "domain": "localhost",
                    "action_taken": "hold_for_backend",
                    "source_surface": "browser_extension",
                    "user_id": owner["user_id"],
                    "input_signal_types": ["domain_policy_mismatch", "discovery_hint:local_agent_runtime"],
                    "correlation_id": "corr-local-discovery-1",
                    "timestamp": now.isoformat(),
                },
            )
        )
        db.commit()

    response = client.get("/dashboard/notifications?limit=20", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    discovery_items = [
        item
        for item in payload["items"]
        if item.get("notification_type") == "discovery_signal"
        and "localhost" in str(item.get("title") or "").lower()
    ]
    assert discovery_items, payload["items"]
    first = discovery_items[0]
    assert first["source_surface"] == "browser"
    assert first["actor_user_id"] == owner["user_id"]
    assert "unknown ai usage" in str(first["title"] or "").lower()
    assert "local_agent_runtime" in str(first["summary"] or "").lower()
    assert "hold_for_backend" in str(first["summary"] or "").lower()
    assert first["link"].startswith("/shadow-ai")


def test_dashboard_notifications_surface_agent_runtime_context_in_discovery_card(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="command-center-notify-agent-runtime@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    now = datetime.now(timezone.utc)
    with session_factory() as db:
        db.add(
            MonitoringSignal(
                tenant_id=owner["tenant_id"],
                ai_system_id=None,
                signal_type="shadow_ai.browser_agent_runtime_discovered",
                severity="high",
                payload={
                    "event_type": "agent_runtime_discovered",
                    "domain": "localhost",
                    "action_taken": "discover",
                    "source_surface": "browser_extension",
                    "user_id": owner["user_id"],
                    "agent_id": "agt-0123456789abcdef0123456789abcd",
                    "agent_name": "agent-os",
                    "model_name": "qwen2.5:14b",
                    "runtime_provider": "ollama",
                    "detected_tools": ["mcp.tools"],
                    "detected_actions": ["draft.email"],
                    "detected_privileges": ["email.gmail_draft_write"],
                    "input_signal_types": ["agent_runtime_detected", "discovery_hint:local_agent_runtime"],
                    "correlation_id": "corr-agent-runtime-card-1",
                    "timestamp": now.isoformat(),
                },
            )
        )
        db.commit()

    response = client.get("/dashboard/notifications?limit=20", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    discovery_items = [
        item
        for item in payload["items"]
        if item.get("notification_type") == "discovery_signal"
        and "local agent runtime" in str(item.get("title") or "").lower()
    ]
    assert discovery_items, payload["items"]
    first = discovery_items[0]
    summary = str(first.get("summary") or "").lower()
    assert "agent: agent-os" in summary
    assert "model: qwen2.5:14b" in summary
    assert "runtime: ollama" in summary
    assert "tools: mcp.tools" in summary
    assert "actions: draft.email" in summary
    assert "privileges: email.gmail_draft_write" in summary
    assert first["link"].startswith("/ai-iam?agent_id=")


def test_dashboard_notifications_suppress_hawk_control_plane_agent_runtime_signal(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="command-center-notify-control-plane-runtime@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    now = datetime.now(timezone.utc)
    with session_factory() as db:
        db.add(
            MonitoringSignal(
                tenant_id=owner["tenant_id"],
                ai_system_id=None,
                signal_type="shadow_ai.browser_agent_runtime_discovered",
                severity="high",
                payload={
                    "event_type": "agent_runtime_discovered",
                    "domain": "localhost",
                    "url": "http://localhost:3000/dashboard/command-center",
                    "page_title": "AI Control Plane",
                    "action_taken": "discover",
                    "source_surface": "browser_extension",
                    "user_id": owner["user_id"],
                    "agent_id": "agt-false-control-plane",
                    "agent_name": "ai",
                    "input_signal_types": ["agent_runtime_detected", "discovery_hint:local_agent_runtime"],
                    "correlation_id": "corr-control-plane-runtime-card-1",
                    "timestamp": now.isoformat(),
                },
            )
        )
        db.commit()

    response = client.get("/dashboard/notifications?limit=20", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert all(
        item.get("correlation_id") != "corr-control-plane-runtime-card-1"
        for item in payload["items"]
    )


def test_dashboard_notifications_finding_summary_includes_tool_hint(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="command-center-notify-finding-tool@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    now = datetime.now(timezone.utc)
    with session_factory() as db:
        db.add(
            Finding(
                tenant_id=owner["tenant_id"],
                source_surface="browser",
                ai_tool="localhost",
                ai_system_id=None,
                severity="high",
                finding_type="shadow_ai_discovery",
                risk_category="shadow_ai",
                status="open",
                recommended_action="Review shadow AI entity and assign governance owner.",
                evidence_node_ids=[],
                related_control_ids=[],
                dedupe_key="finding-notify-tool-hint",
                occurrence_count=1,
                first_seen_at=now - timedelta(minutes=2),
                last_seen_at=now - timedelta(minutes=1),
            )
        )
        db.commit()

    response = client.get("/dashboard/notifications?limit=20", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    finding_items = [
        item
        for item in payload["items"]
        if item.get("notification_type") == "finding"
        and "shadow ai discovery" in str(item.get("title") or "").lower()
    ]
    assert finding_items, payload["items"]
    assert "tool: localhost" in str(finding_items[0].get("summary") or "").lower()
    drilldowns = {item["type"]: item for item in finding_items[0].get("drilldowns") or []}
    assert drilldowns["finding_detail"]["href"].startswith("/discovery/findings/")
    assert drilldowns["traceability"]["href"].endswith("#traceability")
    assert drilldowns["evidence"]["href"].endswith("#evidence")


def test_dashboard_notifications_default_lookback_excludes_stale_findings(test_env) -> None:
    client: TestClient = test_env["client"]
    session_factory = test_env["sessionmaker"]
    owner = _register_owner(client, email="command-center-notify-lookback@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    now = datetime.now(timezone.utc)
    with session_factory() as db:
        db.add(
            Finding(
                tenant_id=owner["tenant_id"],
                source_surface="browser",
                ai_tool="localhost",
                ai_system_id=None,
                severity="high",
                finding_type="shadow_ai_discovery",
                risk_category="shadow_ai",
                status="open",
                recommended_action="Recent local finding",
                evidence_node_ids=[],
                related_control_ids=[],
                dedupe_key="finding-notify-recent",
                occurrence_count=1,
                first_seen_at=now - timedelta(minutes=20),
                last_seen_at=now - timedelta(minutes=10),
            )
        )
        db.add(
            Finding(
                tenant_id=owner["tenant_id"],
                source_surface="browser",
                ai_tool="localhost",
                ai_system_id=None,
                severity="high",
                finding_type="shadow_ai_discovery",
                risk_category="shadow_ai",
                status="open",
                recommended_action="Stale local finding",
                evidence_node_ids=[],
                related_control_ids=[],
                dedupe_key="finding-notify-stale",
                occurrence_count=1,
                first_seen_at=now - timedelta(days=10),
                last_seen_at=now - timedelta(days=9, minutes=5),
            )
        )
        db.commit()

    response = client.get("/dashboard/notifications?limit=50", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()

    summaries = [str(item.get("summary") or "") for item in payload["items"] if item.get("notification_type") == "finding"]
    assert any("Recent local finding" in text for text in summaries), payload["items"]
    assert all("Stale local finding" not in text for text in summaries), payload["items"]
