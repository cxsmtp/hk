from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.ai_system import AISystem
from app.db.models.enforcement import EnforcementEvent
from app.db.models.evidence import EvidenceNode
from app.db.models.finding import Finding
from app.db.models.activity_audit import AIAction
from app.db.models.policy import BusinessPurposeSession
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.runtime_intelligence import RuntimeBehaviorEdge
from app.db.models.audit import AuditLog
from app.db.session import Base, get_db
from app.main import app
from app.services.ai_iam_service import (
    build_ai_action_record,
    build_pre_action_governance_check,
    evaluate_purpose_bound_permission,
)


PASSWORD = "Password123!"


def _factor_types(explanation: dict) -> set[str]:
    return {
        str(item.get("factor_type") or "").strip()
        for item in list(explanation.get("decision_factors") or [])
        if isinstance(item, dict)
    }


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "ai_action_governance.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "AI Action Owner"},
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


def _create_ai_system(client: TestClient, headers: dict[str, str]) -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Governed MCP App", "description": "action governance", "risk_tier": "MEDIUM"},
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _create_agent(client: TestClient, headers: dict[str, str]) -> str:
    response = client.post(
        "/ai-iam/agents",
        headers=headers,
        json={
            "name": "Purpose Bound Agent",
            "description": "governance test",
            "max_chain_depth": 3,
            "capability_inheritance": False,
            "action_scope": ["tool.read", "tool.write", "tool.delete"],
            "tool_registry": ["jira"],
            "external_system_access": ["jira.internal.acme.ai"],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _mint_token(
    client: TestClient,
    headers: dict[str, str],
    *,
    agent_id: str,
    ai_system_id: str,
    scopes: list[str],
) -> str:
    response = client.post(
        f"/ai-iam/agents/{agent_id}/tokens",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "scopes": scopes,
            "expires_minutes": 60,
            "chain_depth": 3,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["capability_token"]


def _purpose_permission(*, mode: str = "block", shadow: bool = False) -> dict:
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    return {
        "permission_id": "pbp-read-jira-30m",
        "identity_id": "agent-purpose-test",
        "identity_type": "agent",
        "purpose": {
            "name": "support_triage",
            "description": "Read Jira tickets for support triage.",
            "allowed_intents": ["support_triage", "ticket_summary"],
            "prohibited_intents": ["modify_ticket", "delete_ticket"],
        },
        "scope": {
            "allowed_actions": ["tool.read", "read", "list", "search"],
            "blocked_actions": ["tool.write", "tool.delete", "write", "delete", "admin"],
            "allowed_tools": ["jira"],
            "blocked_tools": [],
            "allowed_domains": ["jira.internal.acme.ai"],
            "blocked_domains": [],
            "allowed_resources": ["jira.internal.acme.ai"],
            "blocked_resources": [],
            "allowed_data_scopes": ["internal"],
            "allowed_environments": ["prod"],
        },
        "constraints": {
            "expiry": expiry,
            "max_action_count": 5,
            "max_risk_level": "medium",
            "approval_required_for": ["high", "critical", "admin"],
            "require_human_confirmation": False,
        },
        "status": "active",
        "mode": "shadow" if shadow else mode,
    }


def test_purpose_bound_permission_allows_scoped_read_action() -> None:
    result = evaluate_purpose_bound_permission(
        permission=_purpose_permission(),
        action_type="tool.read",
        action_category="read",
        action_risk="low",
        tool_name="jira",
        target_resource="jira.internal.acme.ai",
        domain="jira.internal.acme.ai",
        environment="prod",
        current_action_count=1,
    )

    assert result["decision"] == "allow"
    assert result["reason"] == "purpose_bound_permission_allowed"
    assert result["purpose_bound_permission_id"] == "pbp-read-jira-30m"


def test_purpose_bound_permission_blocks_write_action() -> None:
    result = evaluate_purpose_bound_permission(
        permission=_purpose_permission(),
        action_type="tool.write",
        action_category="write",
        action_risk="medium",
        tool_name="jira",
        target_resource="jira.internal.acme.ai",
        domain="jira.internal.acme.ai",
        environment="prod",
        current_action_count=1,
    )

    assert result["decision"] == "block"
    assert result["reason"] == "action_outside_purpose_scope"
    assert "tool.write" in result["violations"]


def test_missing_purpose_blocks_high_risk_action() -> None:
    result = evaluate_purpose_bound_permission(
        permission=None,
        action_type="tool.delete",
        action_category="admin",
        action_risk="high",
        tool_name="jira",
        target_resource="jira.internal.acme.ai",
        domain="jira.internal.acme.ai",
        environment="prod",
        current_action_count=1,
    )

    assert result["decision"] == "block"
    assert result["reason"] == "purpose_bound_permission_required"


def test_pre_action_governance_check_labels_shadow_would_block() -> None:
    purpose_result = evaluate_purpose_bound_permission(
        permission=_purpose_permission(shadow=True),
        action_type="tool.write",
        action_category="write",
        action_risk="medium",
        tool_name="jira",
        target_resource="jira.internal.acme.ai",
        domain="jira.internal.acme.ai",
        environment="prod",
        current_action_count=1,
    )
    check = build_pre_action_governance_check(
        tenant_id="tenant-1",
        action_id="act-1",
        source_event_id=None,
        actor={
            "identity_type": "agent",
            "agent_id": "agent-purpose-test",
            "acting_on_behalf_of_user_id": "user-1",
        },
        authority={
            "authority_type": "delegated_agent",
            "authority_owner": "user-1",
            "standing_privilege": False,
        },
        purpose_permission=_purpose_permission(shadow=True),
        purpose_result=purpose_result,
        surface={"surface_type": "mcp", "application": "Jira", "domain": "jira.internal.acme.ai"},
        action={
            "action_type": "tool.write",
            "action_category": "write",
            "action_risk": "medium",
            "target_resource": "jira.internal.acme.ai",
            "tool_name": "jira",
        },
        workflow_risk_context={
            "workflow_id": "wf-1",
            "previous_action_count": 1,
            "cumulative_risk_score": 0.5,
            "scope_drift_score": 0.25,
            "privilege_escalation_score": 0.0,
            "recent_violations_count": 0,
        },
        policy_snapshot_id="pv-1",
        policy_ids=["AI_ACTION_BOUNDARY_CONTROL"],
        evidence_refs=["ev-1"],
        trace_id="trace-1",
    )

    assert check["policy"]["decision"] == "shadow_would_block"
    assert check["control_mode"] == "shadow_would_block"
    assert check["policy"]["mode"] == "shadow"


def test_mcp_purpose_check_evidence_and_runtime_metadata(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="mcp-purpose-evidence@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers)
    with session_local() as db:
        ai_system = db.get(AISystem, ai_system_id)
        assert ai_system is not None
        metadata = dict(ai_system.metadata_json or {})
        metadata.update({"governance_state": "APPROVED", "lifecycle_state": "ACTIVE"})
        ai_system.status = "active"
        ai_system.metadata_json = metadata
        db.commit()
    agent_id = _create_agent(client, headers)
    token = _mint_token(
        client,
        headers,
        agent_id=agent_id,
        ai_system_id=ai_system_id,
        scopes=["tool.read", "tool.write"],
    )
    persisted_permission = {
        **_purpose_permission(),
        "identity_id": agent_id,
        "allowed_actions": ["tool.read"],
        "allowed_tools": ["jira"],
        "allowed_data_scope": ["internal"],
        "context": {"max_chain_depth": 3},
    }
    with session_local() as db:
        purpose_session = BusinessPurposeSession(
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            declared_purpose="Read Jira tickets for support triage.",
            purpose_category="support_triage",
            business_function="support",
            approved_scope=persisted_permission,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
            status="active",
        )
        db.add(purpose_session)
        db.commit()
        persisted_permission_id = purpose_session.id

    response = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "request_id": "mcp-purpose-check-1",
            "ai_system_id": ai_system_id,
            "actor_id": agent_id,
            "capability_token": token,
            "action": "tool.write",
            "resource": "jira.internal.acme.ai/issue/SEC-1",
            "chain_depth": 1,
            "tool_name": "jira",
            "tool_category": "mcp_tool",
            "api_endpoint": "mcp://jira/write",
            "chain_id": "wf-purpose-mcp",
            "session_id": "sess-purpose-mcp",
            "initiating_user_id": owner["user_id"],
            "session_context": {
                "session_id": "sess-purpose-mcp",
                "agent_id": agent_id,
                "initiating_user_id": owner["user_id"],
                "max_chain_depth": 3,
                "connected_systems": ["jira.internal.acme.ai"],
                "allowed_data_scope": ["internal"],
            },
            "dynamic_permission": {
                **_purpose_permission(),
                "identity_id": agent_id,
                "allowed_actions": ["tool.read"],
                "allowed_tools": ["jira"],
                "allowed_data_scope": ["internal"],
                "context": {"max_chain_depth": 3},
            },
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    assert body["pre_action_governance_check"]["policy"]["decision"] == "block"
    assert body["pre_action_governance_check"]["purpose"]["purpose_bound_permission_id"] == persisted_permission_id, body["pre_action_governance_check"]["policy"]["reason"]
    assert body["pre_action_governance_check"]["control_mode"] == "inline_prevented"

    with session_local() as db:
        event = db.scalar(
            select(EnforcementEvent).where(
                EnforcementEvent.tenant_id == owner["tenant_id"],
                EnforcementEvent.request_id == "mcp-purpose-check-1",
            )
        )
        assert event is not None
        check = (event.final_actions or {}).get("pre_action_governance_check")
        assert check["policy"]["decision"] == "block"
        assert check["action"]["action_category"] == "write"

        evidence = db.scalar(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == owner["tenant_id"],
                EvidenceNode.signal_type == "gateway.mcp.authorize",
            )
        )
        assert evidence is not None
        assert (evidence.payload or {}).get("pre_action_governance_check", {}).get("check_id")

        runtime = db.scalar(
            select(RuntimeEvent).where(
                RuntimeEvent.tenant_id == owner["tenant_id"],
                RuntimeEvent.event_type == "mcp_authorize",
            )
        )
        assert runtime is not None
        assert runtime.metadata_json["pre_action_governance_check"]["policy"]["decision"] == "block"
        assert runtime.metadata_json["control_mode"] == "inline_prevented"

        finding = db.scalar(
            select(Finding).where(
                Finding.tenant_id == owner["tenant_id"],
                Finding.finding_type == "AI_ACTION_BOUNDARY_VIOLATION",
            )
        )
        assert finding is not None
        assert finding.decision == "block"


def test_browser_automation_pre_action_check_is_vendor_neutral(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="browser-action-governance@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/telemetry/browser",
        headers=headers,
        json={
            "correlation_id": "browser-generic-submit-1",
            "browser": "chrome",
            "browser_type": "chrome",
            "browser_profile": "pilot",
            "extension_version": "0.9.2",
            "event_type": "browser_automation_blocked",
            "domain": "workflow.example.internal",
            "url": "https://workflow.example.internal/approval",
            "page_title": "Workflow Approval",
            "policy_version": "pv-browser-generic-action",
            "platform_mode": "enforce",
            "action_taken": "block:blocked_high_risk_browser_action",
            "action_type": "submit_form",
            "action_risk": "high",
            "decision_badge": "Blocked Action",
            "reason": "blocked_high_risk_browser_action",
            "automation_suspected": True,
            "automation_confidence": 0.92,
            "automation_source": "browser_visible",
            "automation_indicators": ["scripted_input", "automated_click_cadence"],
            "application": "Workflow SaaS",
            "machine_id": "pilot-generic-machine-01",
            "user_id": owner["user_id"],
            "user_email": "browser-action-governance@example.com",
            "input_signal_types": ["automation_suspected"],
            "severity": "critical",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["runtime_event_id"]
    assert body["finding_id"]

    with session_local() as db:
        runtime = db.scalar(
            select(RuntimeEvent).where(
                RuntimeEvent.tenant_id == owner["tenant_id"],
                RuntimeEvent.event_id == body["runtime_event_id"],
            )
        )
        assert runtime is not None
        check = runtime.metadata_json["pre_action_governance_check"]
        assert check["surface"]["surface_type"] == "browser"
        assert check["surface"]["domain"] == "workflow.example.internal"
        assert check["action"]["action_type"] == "submit_form"
        assert check["policy"]["decision"] == "block"
        assert check["control_mode"] == "inline_prevented"
        assert runtime.metadata_json["decision_badge"] == "Blocked Action"

        finding = db.scalar(
            select(Finding).where(
                Finding.tenant_id == owner["tenant_id"],
                Finding.finding_id == body["finding_id"],
            )
        )
        assert finding is not None
        assert finding.decision == "block"
        assert finding.application == "Workflow SaaS"
        assert finding.evidence_status == "complete"


def test_browser_automation_event_persists_ai_action_backbone(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="browser-action-backbone@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/telemetry/browser",
        headers=headers,
        json={
            "correlation_id": "browser-ai-action-backbone-1",
            "browser": "chrome",
            "browser_type": "chrome",
            "browser_profile": "pilot",
            "extension_version": "0.9.2",
            "event_type": "browser_automation_blocked",
            "domain": "workflow.example.internal",
            "url": "https://workflow.example.internal/checkout",
            "page_title": "Workflow Checkout",
            "policy_version": "pv-browser-ai-action",
            "platform_mode": "enforce",
            "action_taken": "block:blocked_high_risk_browser_action",
            "action_type": "checkout",
            "action_risk": "high",
            "reason": "blocked_high_risk_browser_action",
            "automation_suspected": True,
            "automation_confidence": 0.94,
            "automation_source": "browser_visible",
            "automation_indicators": ["scripted_input", "automated_click_cadence"],
            "application": "Workflow SaaS",
            "machine_id": "pilot-ai-action-machine-01",
            "user_id": owner["user_id"],
            "user_email": "browser-action-backbone@example.com",
            "input_signal_types": ["automation_suspected"],
            "severity": "critical",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["runtime_event_id"]
    assert body["finding_id"]

    with session_local() as db:
        runtime = db.scalar(
            select(RuntimeEvent).where(
                RuntimeEvent.tenant_id == owner["tenant_id"],
                RuntimeEvent.event_id == body["runtime_event_id"],
            )
        )
        assert runtime is not None
        ai_action = (runtime.metadata_json or {}).get("ai_action")
        assert ai_action["action_id"] == runtime.event_id
        assert ai_action["tenant_id"] == owner["tenant_id"]
        assert ai_action["actor"]["identity_type"] == "agent"
        assert ai_action["actor"]["user_id"] == owner["user_id"]
        assert ai_action["actor"]["email"] == "browser-action-backbone@example.com"
        assert ai_action["actor"]["machine_id"] == "pilot-ai-action-machine-01"
        assert ai_action["authority"]["authority_type"] == "browser_session"
        assert ai_action["surface"]["surface_type"] == "agentic_browser"
        assert ai_action["surface"]["browser_type"] == "chrome"
        assert ai_action["surface"]["application"] == "Workflow SaaS"
        assert ai_action["action"]["action_type"] == "checkout"
        assert ai_action["action"]["action_risk"] == "high"
        assert ai_action["policy"]["decision"] == "block"
        assert ai_action["policy"]["control_mode"] == "inline_prevented"
        assert ai_action["policy"]["decision_badge"] == "Pre-Action Blocked"
        assert ai_action["context"]["automation"]["source"] == "browser_visible"
        assert ai_action["context"]["automation"]["confidence"] == 0.94
        assert ai_action["evidence"]["evidence_status"] == "complete"
        explanation = ai_action["decision_explanation"]
        assert explanation["decision_summary"]["final_decision"] == "block"
        assert explanation["decision_summary"]["control_mode"] == "inline_prevented"
        assert "checkout" in explanation["decision_summary"]["plain_english_reason"].lower()
        assert explanation["decision_summary"]["confidence"] == "high"
        assert explanation["evaluated_signals"]["surface"]["browser_type"] == "chrome"
        assert explanation["evaluated_signals"]["action"]["action_type"] == "checkout"
        assert explanation["evaluated_signals"]["automation"]["source"] == "browser_visible"
        assert {"action", "transaction", "approval", "automation", "policy"}.issubset(_factor_types(explanation))
        assert explanation["matched_policies"]
        assert explanation["evidence"]["trace_id"] == runtime.correlation_id
        assert (runtime.metadata_json or {}).get("decision_explanation") == explanation

        evidence = db.scalar(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == owner["tenant_id"],
                EvidenceNode.id == body["evidence_node_id"],
            )
        )
        assert evidence is not None
        assert runtime.event_id in ai_action["evidence"]["evidence_refs"] or body["evidence_node_id"] in ai_action["evidence"]["evidence_refs"]

        finding = db.scalar(
            select(Finding).where(
                Finding.tenant_id == owner["tenant_id"],
                Finding.finding_id == body["finding_id"],
            )
        )
        assert finding is not None
        assert finding.related_runtime_event_id == runtime.event_id
        assert finding.evidence_status == "complete"
        assert (runtime.metadata_json or {})["ai_action"]["finding_id"] == finding.finding_id


def test_browser_manual_browsing_ai_action_is_telemetry_only_not_prevented(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="manual-browser-backbone@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/telemetry/browser",
        headers=headers,
        json={
            "correlation_id": "browser-manual-ai-action-1",
            "browser": "chrome",
            "browser_type": "chrome",
            "browser_profile": "pilot",
            "extension_version": "0.9.2",
            "event_type": "ai_domain_visit",
            "domain": "chatgpt.com",
            "url": "https://chatgpt.com/",
            "page_title": "ChatGPT",
            "policy_version": "pv-browser-ai-action",
            "platform_mode": "enforce",
            "action_taken": "allow",
            "action_type": "page_view",
            "application": "ChatGPT",
            "machine_id": "pilot-manual-machine-01",
            "user_id": owner["user_id"],
            "user_email": "manual-browser-backbone@example.com",
            "severity": "low",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["runtime_event_id"]
    assert body["finding_id"] is None

    with session_local() as db:
        runtime = db.scalar(
            select(RuntimeEvent).where(
                RuntimeEvent.tenant_id == owner["tenant_id"],
                RuntimeEvent.event_id == body["runtime_event_id"],
            )
        )
        assert runtime is not None
        ai_action = (runtime.metadata_json or {}).get("ai_action")
        assert ai_action["action_id"] == runtime.event_id
        assert ai_action["actor"]["identity_type"] == "human"
        assert ai_action["surface"]["surface_type"] == "browser"
        assert ai_action["action"]["action_type"] == "page_view"
        assert ai_action["policy"]["decision"] == "allow"
        assert ai_action["policy"]["control_mode"] == "telemetry_only"
        assert ai_action["policy"]["decision_badge"] == "Detected-Only"
        explanation = ai_action["decision_explanation"]
        assert explanation["decision_summary"]["final_decision"] == "detected_only"
        assert "detected" in explanation["decision_summary"]["plain_english_reason"].lower()
        assert "prevention" not in explanation["decision_summary"]["plain_english_reason"].lower()
        assert "policy" in _factor_types(explanation)


def test_non_inline_surface_cannot_claim_inline_prevented() -> None:
    action = build_ai_action_record(
        tenant_id="tenant-control-honesty",
        action_id="saas-action-1",
        timestamp="2026-06-18T08:00:00Z",
        source_surface="saas",
        event_type="slack_message_detected",
        decision="block",
        app_id="slack",
        application="Slack",
        user_id="user-1",
        machine_id=None,
        browser_type=None,
        policy_version_id="policy-slack-shadow",
        evidence_node_ids=["ev-saas-1"],
        metadata={
            "control_mode": "inline_prevented",
            "policy_id": "SAAS_AI_USAGE_CONTROL",
            "reason": "sensitive_content_detected",
            "user_email": "pilot@example.com",
        },
    )

    assert action["policy"]["decision"] == "block"
    assert action["policy"]["control_mode"] == "external_required"
    assert action["policy"]["decision_badge"] == "Review Required"
    assert action["decision_explanation"]["decision_summary"]["control_mode"] == "external_required"


def test_decision_panel_tuning_action_records_audit_event(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="decision-tuning@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    event_response = client.post(
        "/telemetry/browser",
        headers=headers,
        json={
            "correlation_id": "decision-tuning-browser-1",
            "browser": "chrome",
            "browser_type": "chrome",
            "event_type": "browser_automation_blocked",
            "domain": "workflow.example.internal",
            "url": "https://workflow.example.internal/checkout",
            "policy_version": "pv-decision-tuning",
            "platform_mode": "enforce",
            "action_taken": "block:blocked_high_risk_browser_action",
            "action_type": "checkout",
            "action_risk": "high",
            "automation_suspected": True,
            "automation_confidence": 0.9,
            "automation_source": "browser_visible",
            "application": "Workflow SaaS",
            "machine_id": "decision-tuning-machine-01",
            "user_id": owner["user_id"],
            "user_email": "decision-tuning@example.com",
            "severity": "critical",
        },
    )
    assert event_response.status_code == 200, event_response.text
    event_body = event_response.json()

    with session_local() as db:
        runtime = db.scalar(select(RuntimeEvent).where(RuntimeEvent.event_id == event_body["runtime_event_id"]))
        assert runtime is not None
        explanation_id = runtime.metadata_json["decision_explanation"]["explanation_id"]

    response = client.post(
        f"/dashboard/decision-explanations/{explanation_id}/tuning-actions",
        headers=headers,
        json={
            "action": "suggest_policy_narrowing",
            "runtime_event_id": event_body["runtime_event_id"],
            "finding_id": event_body["finding_id"],
            "justification": "Pilot admin reviewed a high-risk checkout block.",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "recorded"
    assert body["requires_confirmation"] is True

    with session_local() as db:
        audit = db.scalar(
            select(AuditLog).where(
                AuditLog.tenant_id == owner["tenant_id"],
                AuditLog.action == "decision_explanation.tuning_action_requested",
            )
        )
        assert audit is not None
        assert audit.resource_id == explanation_id
        assert audit.payload["runtime_event_id"] == event_body["runtime_event_id"]
        assert audit.payload["finding_id"] == event_body["finding_id"]
        assert audit.payload["action"] == "suggest_policy_narrowing"


def test_data_transfer_event_persists_ai_action_backbone(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="transfer-action-backbone@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/runtime-control/data-transfer-check",
        headers=headers,
        json={
            "correlation_id": "data-transfer-ai-action-1",
            "policy_version": "pv-transfer-ai-action",
            "platform_mode": "enforce",
            "action_type": "paste_output_to_external_site",
            "browser": "chrome",
            "browser_type": "chrome",
            "extension_version": "0.9.2",
            "endpoint_id": "pilot-transfer-machine-01",
            "machine_id": "pilot-transfer-machine-01",
            "declared_intent": "summarize public market research",
            "copy_context": {
                "source_url": "https://internal.acme.ai/wiki",
                "source_domain": "internal.acme.ai",
                "source_app_name": "Internal Wiki",
                "source_surface_type": "internal_app",
                "source_classification_hint": "protected",
                "copied_text_hash": "transfer-backbone-hash",
                "copied_text_preview_redacted": "customer@example.com API key: sk-test-secret-value-123456",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "paste_context": {
                "destination_url": "https://chatgpt.com/",
                "destination_domain": "chatgpt.com",
                "destination_app_name": "ChatGPT",
                "destination_surface_type": "ai_tool",
                "destination_input_context": "chat_box",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    assert body["runtime_event_id"]
    assert body["finding_id"]

    with session_local() as db:
        runtime = db.scalar(select(RuntimeEvent).where(RuntimeEvent.event_id == body["runtime_event_id"]))
        assert runtime is not None
        ai_action = (runtime.metadata_json or {}).get("ai_action")
        assert ai_action["action_id"] == runtime.event_id
        assert ai_action["actor"]["identity_type"] == "human"
        assert ai_action["actor"]["user_id"] == owner["user_id"]
        assert ai_action["surface"]["surface_type"] == "browser"
        assert ai_action["surface"]["application"] == "ChatGPT"
        assert ai_action["action"]["action_type"] == "paste_output_to_external_site"
        assert ai_action["context"]["input"]["sensitivity_level"] == "critical"
        assert ai_action["context"]["destination"]["trust_level"] == "public_ai"
        assert ai_action["policy"]["decision"] == "block"
        assert ai_action["policy"]["control_mode"] == "inline_prevented"
        explanation = ai_action["decision_explanation"]
        assert explanation["decision_summary"]["final_decision"] == "block"
        assert explanation["evaluated_signals"]["destination"]["trust_level"] == "public_ai"
        assert {"content", "destination", "policy"}.issubset(_factor_types(explanation))
        assert explanation["hidden_or_redacted"]["raw_content_redacted"] is True
        assert explanation["hidden_or_redacted"]["secret_values_redacted"] is True
        assert "sk-test-secret-value" not in str(explanation)

        evidence = db.scalar(select(EvidenceNode).where(EvidenceNode.id == body["evidence_node_id"]))
        assert evidence is not None
        assert body["evidence_node_id"] in ai_action["evidence"]["evidence_refs"]

        finding = db.scalar(select(Finding).where(Finding.finding_id == body["finding_id"]))
        assert finding is not None
        assert finding.user_email == "transfer-action-backbone@example.com"
        assert finding.machine_id == "pilot-transfer-machine-01"
        assert finding.browser_type == "chrome"
        assert finding.application == "ChatGPT"
        assert finding.related_runtime_event_id == runtime.event_id
        assert finding.evidence_status == "complete"
        assert (runtime.metadata_json or {})["ai_action"]["finding_id"] == finding.finding_id


def test_agent_action_intercept_returns_pre_action_governance_check(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="agent-action-governance@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers)
    agent_id = _create_agent(client, headers)
    token = _mint_token(
        client,
        headers,
        agent_id=agent_id,
        ai_system_id=ai_system_id,
        scopes=["tool.read", "tool.delete"],
    )

    response = client.post(
        "/runtime-control/agent-action-intercept",
        headers=headers,
        json={
            "correlation_id": "agent-pre-action-1",
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": token,
            "action_type": "tool_execution",
            "tool_name": "jira",
            "target_resource": "jira.internal.acme.ai",
            "chain_depth": 1,
            "chain_id": "agent-pre-action-workflow",
            "policy_version": "pv-agent-action-governance",
            "platform_mode": "enforce",
            "input_context": {
                "purpose_bound_permission": {
                    **_purpose_permission(),
                    "identity_id": agent_id,
                    "scope": {
                        **_purpose_permission()["scope"],
                        "allowed_actions": ["tool.read"],
                        "blocked_actions": ["tool_execution", "tool.delete"],
                    },
                },
                "payload": {"request": "delete Jira issue SEC-1"},
                "api_endpoint": "mcp://jira/delete",
            },
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    assert body["pre_action_governance_check"]["policy"]["decision"] == "block"
    assert body["pre_action_governance_check"]["control_mode"] == "inline_prevented"

    with session_local() as db:
        runtime = db.scalar(
            select(RuntimeEvent).where(
                RuntimeEvent.tenant_id == owner["tenant_id"],
                RuntimeEvent.event_type == "agent_action_intercept",
            )
        )
        assert runtime is not None
        assert runtime.metadata_json["pre_action_governance_check"]["policy"]["decision"] == "block"


def test_runtime_activity_audit_row_preserves_canonical_ai_action_spine(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="activity-spine@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/telemetry/browser",
        headers=headers,
        json={
            "correlation_id": "activity-spine-browser-1",
            "browser": "chrome",
            "browser_type": "chrome",
            "browser_profile": "pilot",
            "extension_version": "0.9.5",
            "event_type": "browser_automation_blocked",
            "domain": "workflow.example.internal",
            "url": "https://workflow.example.internal/checkout",
            "page_title": "Workflow Checkout",
            "policy_version": "pv-activity-spine",
            "platform_mode": "enforce",
            "action_taken": "block:blocked_high_risk_browser_action",
            "action_type": "checkout",
            "action_risk": "high",
            "reason": "blocked_high_risk_browser_action",
            "automation_suspected": True,
            "automation_confidence": 0.94,
            "automation_source": "browser_visible",
            "automation_indicators": ["scripted_input", "automated_click_cadence"],
            "application": "Workflow SaaS",
            "machine_id": "pilot-activity-spine-machine-01",
            "user_id": owner["user_id"],
            "user_email": "activity-spine@example.com",
            "input_signal_types": ["automation_suspected"],
            "severity": "critical",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()

    with session_local() as db:
        runtime = db.scalar(select(RuntimeEvent).where(RuntimeEvent.event_id == body["runtime_event_id"]))
        assert runtime is not None
        runtime_ai_action = runtime.metadata_json["ai_action"]

        action = db.scalar(
            select(AIAction).where(
                AIAction.tenant_id == owner["tenant_id"],
                AIAction.runtime_event_id == runtime.event_id,
            )
        )
        assert action is not None
        metadata = action.metadata_json or {}
        assert metadata["ai_action"]["action_id"] == runtime.event_id
        assert metadata["ai_action"]["tenant_id"] == runtime_ai_action["tenant_id"]
        assert metadata["ai_action"]["actor"]["user_id"] == runtime_ai_action["actor"]["user_id"]
        assert metadata["ai_action"]["surface"]["surface_type"] == runtime_ai_action["surface"]["surface_type"]
        assert metadata["ai_action"]["policy"]["decision"] == runtime_ai_action["policy"]["decision"]
        assert metadata["control_mode"] == "external_required"
        assert metadata["policy_snapshot"]["policy_snapshot_id"]
        assert metadata["policy_snapshot"]["policy_category"] == "ai_action_control"
        assert (
            metadata["policy_snapshot"]["policy_snapshot_id"]
            == metadata["decision_explanation"]["matched_policies"][0]["policy_snapshot_id"]
        )
        assert metadata["decision_explanation"]["decision_summary"]["final_decision"] == "block"
        assert metadata["evidence_bundle"]["integrity_status"] == "unverified_legacy"
        assert metadata["evidence_bundle"]["verification_status"] == "unverified_legacy"
        assert metadata["evidence_bundle"]["canonical_authority"] is False
        assert metadata["evidence_bundle"]["display_only"] is True
        assert body["evidence_node_id"] in metadata["evidence_bundle"]["evidence_refs"]
        assert metadata["evidence_bundle"]["bundle_hash"]
        assert metadata["evidence_bundle"]["hash_algorithm"] == "sha256"
        assert metadata["evidence_bundle"]["redaction_policy"] == "privacy_sanitizer"
        assert metadata["evidence_bundle"]["evidence_ref_count"] == len(metadata["evidence_bundle"]["evidence_refs"])
        integrity_payload = {
            key: value
            for key, value in metadata["evidence_bundle"].items()
            if key
            not in {
                "payload_sha256",
                "bundle_hash",
                "integrity_status",
                "hash_algorithm",
                "redaction_policy",
                "evidence_ref_count",
                "related_action_count",
                "related_policy_snapshot_count",
                "related_finding_count",
                "related_trace_count",
                "created_at",
                "verification_status",
                "canonical_authority",
                "authority_source",
                "display_only",
            }
        }
        expected_bundle_hash = hashlib.sha256(
            json.dumps(integrity_payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()
        assert metadata["evidence_bundle"]["payload_sha256"] == expected_bundle_hash
        assert metadata["evidence_bundle"]["bundle_hash"] == expected_bundle_hash
        assert "sk-" not in str(metadata["decision_explanation"]).lower()

        behavior_edges = db.scalars(
            select(RuntimeBehaviorEdge).where(
                RuntimeBehaviorEdge.tenant_id == owner["tenant_id"],
                RuntimeBehaviorEdge.event_id == runtime.event_id,
            )
        ).all()
        relationships = {edge.relationship_type for edge in behavior_edges}
        assert "uses" in relationships
        assert "used_authority" in relationships
        assert "acted_as" in relationships
        assert "observed_on_surface" in relationships
        assert "triggered_policy" in relationships
        assert "has_evidence" in relationships
        assert "created_finding" in relationships
        assert any(edge.source_node_type == "human_user" and edge.target_node_type == "ai_action" for edge in behavior_edges)
        assert any(edge.source_node_type == "ai_action" and edge.target_node_type == "surface" for edge in behavior_edges)
        assert any(edge.target_node_type == "app" for edge in behavior_edges)
        assert any(edge.source_node_type == "ai_action" and edge.target_node_type == "authority" for edge in behavior_edges)
        assert any(edge.source_node_type == "ai_action" and edge.target_node_type == "policy" for edge in behavior_edges)
        assert any(edge.source_node_type == "ai_action" and edge.target_node_type == "evidence_bundle" for edge in behavior_edges)
        assert any(edge.source_node_type == "ai_action" and edge.target_node_type == "finding" for edge in behavior_edges)
