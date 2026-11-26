from __future__ import annotations

import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.discovery import DiscoveryApplication
from app.db.models.ai_iam import AgentDelegation, AgentIdentity
from app.db.models.monitoring import MonitoringSignal
from app.db.models.remediation import RemediationAction
from app.db.session import Base, get_db
from app.main import app
from app.services.remediation import (
    apply_remediation_action,
    approve_remediation_action,
    propose_remediation_action,
)
from ai_system_approval_helpers import approve_ai_system


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "remediation_workflow.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Remediation Owner"},
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


def _create_ai_system(client: TestClient, headers: dict[str, str], *, risk_tier: str = "HIGH") -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": f"Remediation AI {uuid4().hex[:8]}", "description": "remediation test", "risk_tier": risk_tier},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    activate = approve_ai_system(client, headers, ai_system_id, status="active")
    assert activate.status_code == 200, activate.text
    return ai_system_id


def _create_agent(client: TestClient, headers: dict[str, str], *, max_chain_depth: int = 1) -> str:
    payload = {
        "name": "Remediation Agent",
        "description": "remediation runtime intercept",
        "max_chain_depth": max_chain_depth,
        "capability_inheritance": False,
        "action_scope": ["tool.run", "tool.read"],
        "tool_registry": ["openai_api", "db_tool"],
        "external_system_access": ["api.openai.com", "db.internal.acme.ai"],
        "agent_type": "workflow_agent",
        "autonomy_level": "medium",
    }
    response = client.post("/ai-iam/agents", headers=headers, json=payload)
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _mint_token(
    client: TestClient,
    headers: dict[str, str],
    *,
    agent_id: str,
    ai_system_id: str,
    scopes: list[str],
    chain_depth: int = 1,
) -> str:
    response = client.post(
        f"/ai-iam/agents/{agent_id}/tokens",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "scopes": scopes,
            "expires_minutes": 60,
            "chain_depth": chain_depth,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["capability_token"]


def _approve_and_apply_remediation(
    client: TestClient,
    *,
    headers: dict[str, str],
    remediation_id: str,
    justification: str,
) -> dict:
    approve = client.post(
        f"/findings/remediations/{remediation_id}/approve",
        headers=headers,
        json={"justification": f"approve:{justification}"},
    )
    assert approve.status_code == 200, approve.text
    apply = client.post(
        f"/findings/remediations/{remediation_id}/apply",
        headers=headers,
        json={"justification": f"apply:{justification}"},
    )
    assert apply.status_code == 200, apply.text
    return apply.json()


def test_model_integrity_signal_creates_traceable_remediation_and_rollback(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="remediation-model-integrity@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers, risk_tier="HIGH")

    signal = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "model_integrity_failure",
            "severity": "critical",
            "payload": {
                "reason_code": "model_integrity_failure",
                "related_control_ids": ["CTRL-MODEL-001"],
                # Legacy remediation contexts may contain numeric telemetry.
                # Both apply and rollback must hash it without changing the
                # live context or the evidence payload.
                "risk_telemetry": {"estimated_loss": 1046250.0, "samples": [0.5, 2]},
                "ticket_system": "jira",
                "ticket_systems": ["jira", "servicenow"],
            },
        },
    )
    assert signal.status_code == 200, signal.text

    remediations = client.get(
        "/findings/remediations",
        headers=headers,
        params={
            "target_type": "ai_system",
            "target_id": ai_system_id,
            "source_trigger_type": "model_integrity_failure",
        },
    )
    assert remediations.status_code == 200, remediations.text
    items = remediations.json()["items"]
    assert len(items) >= 1
    row = items[0]
    assert row["remediation_type"] == "trust_center_escalation"
    assert row["status"] == "proposed"
    assert row["requires_approval"] is True
    applied = _approve_and_apply_remediation(
        client,
        headers=headers,
        remediation_id=row["id"],
        justification="model_integrity_escalation",
    )
    assert applied["status"] == "applied"
    assert applied["rollback_supported"] is True
    with test_env["SessionLocal"]() as db:
        persisted = db.get(RemediationAction, row["id"])
        source_signal = db.scalar(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == owner["tenant_id"],
                MonitoringSignal.signal_type == "model_integrity_failure",
            )
        )
        assert persisted is not None and source_signal is not None
        assert persisted.rollback_payload["context"]["risk_telemetry"]["estimated_loss"] == 1046250.0
        assert isinstance(persisted.rollback_payload["context"]["risk_telemetry"]["estimated_loss"], float)
        assert source_signal.payload["risk_telemetry"]["samples"] == [0.5, 2]

    trace = client.get(f"/auditor/remediation-trace/{row['id']}", headers=headers)
    assert trace.status_code == 200, trace.text
    trace_body = trace.json()
    assert trace_body["remediation"]["status"] == "applied"
    assert trace_body["trigger"]["source_trigger_type"] == "model_integrity_failure"
    assert [stage["stage"] for stage in trace_body["stages"]] == ["trigger", "decision", "execution", "outcome"]
    assert isinstance(trace_body["evidence_linkage"]["state_delta"], list)
    assert len(trace_body["tickets"]) >= 2
    assert {ticket["ticket_system"] for ticket in trace_body["tickets"]} >= {"jira", "servicenow"}
    assert "iso_27001" in trace_body["compliance_impact"]["frameworks_covered"]
    assert "nist_ai_rmf" in trace_body["compliance_impact"]["frameworks_covered"]
    assert "eu_ai_act" in trace_body["compliance_impact"]["frameworks_covered"]
    assert trace_body["compliance_impact"]["resolved_risk"] is True
    assert len(trace_body["audit_logs"]) >= 2
    assert len(trace_body["evidence_nodes"]) >= 1
    assert any(log["action"] == "remediation.applied" for log in trace_body["audit_logs"])
    assert any(log["action"] == "remediation.ticket.created" for log in trace_body["audit_logs"])

    rollback = client.post(
        f"/findings/remediations/{row['id']}/rollback",
        headers=headers,
        json={"justification": "false positive model integrity signal"},
    )
    assert rollback.status_code == 200, rollback.text
    rollback_body = rollback.json()
    assert rollback_body["status"] == "rolled_back"

    trace_after = client.get(f"/auditor/remediation-trace/{row['id']}", headers=headers)
    assert trace_after.status_code == 200, trace_after.text
    trace_after_body = trace_after.json()
    assert trace_after_body["remediation"]["status"] == "rolled_back"
    assert any(log["action"] == "remediation.rolled_back" for log in trace_after_body["audit_logs"])
    assert "rollback_completed_revalidation_required" in trace_after_body["compliance_impact"]["remaining_gaps"]


def test_repeated_blocked_agent_actions_trigger_permission_reduce_remediation(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="remediation-agent-repeat@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers, risk_tier="MEDIUM")
    agent_id = _create_agent(client, headers, max_chain_depth=1)
    token = _mint_token(
        client,
        headers,
        agent_id=agent_id,
        ai_system_id=ai_system_id,
        scopes=["*"],
        chain_depth=1,
    )

    reason_codes: list[str] = []
    for idx in range(3):
        response = client.post(
            "/runtime-control/agent-action-intercept",
            headers=headers,
            json={
                "correlation_id": f"corr-remediation-agent-depth-{idx}",
                "ai_system_id": ai_system_id,
                "agent_id": agent_id,
                "capability_token": token,
                "action_type": "tool_execution",
                "tool_name": "openai_api",
                "target_resource": "api.openai.com",
                "chain_depth": 2,
                "policy_version": "pv-remediation-agent",
                "platform_mode": "enforce",
                "input_context": {"payload": {"prompt": "run risky action"}},
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["decision"] in {"block", "require_approval"}
        reason_codes.append(str(response.json().get("reason_code") or ""))

    remediations = client.get(
        "/findings/remediations",
        headers=headers,
        params={"target_type": "agent", "target_id": agent_id},
    )
    assert remediations.status_code == 200, remediations.text
    items = remediations.json()["items"]
    candidate = next((item for item in items if item["remediation_type"] == "permission_reduce"), None)
    assert candidate is not None, reason_codes
    if candidate["status"] != "applied":
        applied = _approve_and_apply_remediation(
            client,
            headers=headers,
            remediation_id=candidate["id"],
            justification="agent_permission_reduce",
        )
        assert applied["status"] == "applied"

    session_local = test_env["SessionLocal"]
    with session_local() as db:
        notification = db.scalar(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == owner["tenant_id"],
                MonitoringSignal.signal_type == "aiiam.remediation.permission_reduce",
            )
        )
        assert notification is not None
        payload = dict(notification.payload or {})
        assert payload.get("agent_id") == agent_id
        assert payload.get("status") == "aiiam_notified"


def test_sensitive_file_upload_triggers_source_quarantine_watchlist_remediation(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="remediation-sensitive-upload@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    payload = {
        "correlation_id": "corr-sensitive-upload-remediation",
        "copy_context": {
            "source_url": "https://hr.acme.ai/docs",
            "source_domain": "hr.acme.ai",
            "source_app_name": "HR Portal",
            "source_surface_type": "document",
            "source_classification_hint": "unknown",
            "copied_text_hash": "upload-hash-123",
            "copied_text_preview_redacted": "employee record [redacted]",
            "timestamp": "2026-03-25T10:00:00Z",
        },
        "paste_context": {
            "destination_url": "https://chat.openai.com/",
            "destination_domain": "chat.openai.com",
            "destination_app_name": "ChatGPT",
            "destination_surface_type": "ai_tool",
            "destination_input_context": "chat_box",
            "timestamp": "2026-03-25T10:00:05Z",
        },
        "policy_version": "pv-remediation-upload",
        "platform_mode": "enforce",
        "file_meta": [
            {
                "name": "employee-card.png",
                "ocr_text": "Credit card 4242 4242 4242 4242 and secret token",
                "mime_type": "image/png",
            }
        ],
    }
    response = client.post("/runtime-control/data-transfer-check", headers=headers, json=payload)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    assert body["finding_id"] is not None

    remediations = client.get(
        "/findings/remediations",
        headers=headers,
        params={"finding_id": body["finding_id"]},
    )
    assert remediations.status_code == 200, remediations.text
    items = remediations.json()["items"]
    quarantine_items = [item for item in items if item["remediation_type"] == "source_quarantine"]
    assert quarantine_items
    for quarantine in quarantine_items:
        if quarantine["status"] != "applied":
            applied = _approve_and_apply_remediation(
                client,
                headers=headers,
                remediation_id=quarantine["id"],
                justification="source_quarantine_upload",
            )
            assert applied["status"] == "applied"

    session_local = test_env["SessionLocal"]
    with session_local() as db:
        source_app = db.scalar(
            select(DiscoveryApplication).where(
                DiscoveryApplication.tenant_id == owner["tenant_id"],
                DiscoveryApplication.tool_key == "hr_acme_ai",
            )
        )
        assert source_app is not None
        assert source_app.status == "blocked"
        metadata = dict(source_app.metadata_json or {})
        assert metadata.get("quarantined") is True
        assert metadata.get("watchlist") is True


def test_repeated_data_exfiltration_escalates_to_step_up_remediation(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="remediation-repeated-exfil@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    payload = {
        "correlation_id": "corr-repeated-exfil-base",
        "copy_context": {
            "source_url": "https://finance.acme.ai/doc",
            "source_domain": "finance.acme.ai",
            "source_app_name": "Finance",
            "source_surface_type": "internal_app",
            "source_classification_hint": "protected",
            "copied_text_hash": "repeat-exfil-hash",
            "copied_text_preview_redacted": "sensitive [redacted]",
            "timestamp": "2026-03-25T10:00:00Z",
        },
        "paste_context": {
            "destination_url": "https://chat.openai.com/",
            "destination_domain": "chat.openai.com",
            "destination_app_name": "ChatGPT",
            "destination_surface_type": "ai_tool",
            "destination_input_context": "chat_box",
            "timestamp": "2026-03-25T10:00:05Z",
        },
        "policy_version": "pv-remediation-exfil",
        "platform_mode": "enforce",
    }

    finding_id: str | None = None
    for idx in range(3):
        row = dict(payload)
        row["correlation_id"] = f"corr-repeated-exfil-{idx}"
        response = client.post("/runtime-control/data-transfer-check", headers=headers, json=row)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["decision"] == "block"
        finding_id = body.get("finding_id") or finding_id

    assert finding_id is not None
    remediations = client.get(
        "/findings/remediations",
        headers=headers,
        params={"finding_id": finding_id},
    )
    assert remediations.status_code == 200, remediations.text
    items = remediations.json()["items"]
    remediation_types = {item["remediation_type"] for item in items}
    assert "policy_tighten" in remediation_types
    assert "require_step_up" in remediation_types


def test_regulated_remediation_requires_approval_before_apply(test_env) -> None:
    owner = _register_owner(test_env["client"], email="remediation-regulated-approval@example.com")
    session_local = test_env["SessionLocal"]
    remediation_id: str | None = None

    with session_local() as db:
        row = propose_remediation_action(
            db,
            tenant_id=owner["tenant_id"],
            source_trigger_type="guardian_violation",
            source_trigger_id=f"finding-{uuid4().hex[:8]}",
            target_type="policy",
            target_id="policy-global",
            severity="high",
            context={
                "regulated": True,
                "finding_type": "sensitive_data_external_transfer_attempt",
                "reason_code": "regulated_sensitive_flow",
                "related_control_ids": ["CTRL-DATA-001"],
            },
        )
        db.commit()
        remediation_id = row.id
        assert row.requires_approval is True
        assert row.status == "proposed"

    assert remediation_id is not None

    with session_local() as db:
        with pytest.raises(ValueError):
            apply_remediation_action(
                db,
                tenant_id=owner["tenant_id"],
                remediation_id=str(remediation_id),
                actor_user_id=owner["user_id"],
                justification="should fail before approval",
            )
        db.rollback()

        approved = approve_remediation_action(
            db,
            tenant_id=owner["tenant_id"],
            remediation_id=str(remediation_id),
            approved_by=owner["user_id"],
            justification="approved under regulated policy exception flow",
        )
        applied = apply_remediation_action(
            db,
            tenant_id=owner["tenant_id"],
            remediation_id=str(remediation_id),
            actor_user_id=owner["user_id"],
            justification="apply after explicit approval",
        )
        db.commit()
        assert approved.approved_by == owner["user_id"]
        assert applied.status == "applied"


def test_unauthorized_tool_usage_auto_reduces_agent_permissions(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="remediation-unauthorized-tool@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers, risk_tier="MEDIUM")
    agent_id = _create_agent(client, headers, max_chain_depth=3)
    token = _mint_token(
        client,
        headers,
        agent_id=agent_id,
        ai_system_id=ai_system_id,
        scopes=["tool.run"],
        chain_depth=1,
    )

    blocked = client.post(
        "/runtime-control/agent-action-intercept",
        headers=headers,
        json={
            "correlation_id": "corr-remediation-unauthorized-tool",
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": token,
            "action_type": "api_call",
            "tool_name": "finance_exporter",
            "target_resource": "finance.internal.acme.ai",
            "chain_depth": 1,
            "policy_version": "pv-remediation-agent-tool",
            "platform_mode": "enforce",
            "input_context": {"payload": {"prompt": "run export"}},
        },
    )
    assert blocked.status_code == 200, blocked.text
    assert blocked.json()["decision"] == "block"
    assert blocked.json()["reason_code"] == "tool_not_allowed"

    remediations = client.get(
        "/findings/remediations",
        headers=headers,
        params={"target_type": "agent", "target_id": agent_id},
    )
    assert remediations.status_code == 200, remediations.text
    items = remediations.json()["items"]
    reduce_item = next((item for item in items if item["remediation_type"] == "permission_reduce"), None)
    assert reduce_item is not None
    if reduce_item["status"] != "applied":
        applied = _approve_and_apply_remediation(
            client,
            headers=headers,
            remediation_id=reduce_item["id"],
            justification="unauthorized_tool_permission_reduce",
        )
        assert applied["status"] == "applied"

    session_local = test_env["SessionLocal"]
    with session_local() as db:
        agent = db.get(AgentIdentity, agent_id)
        assert agent is not None
        assert int(agent.max_chain_depth) == 2
        assert "tool.read" in [str(item).strip().lower() for item in (agent.action_scope or [])]


def test_delegation_misuse_revokes_delegation_and_logs_escalation(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="remediation-delegation-misuse@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers, risk_tier="MEDIUM")
    parent_agent_id = _create_agent(client, headers, max_chain_depth=3)
    child_agent_id = _create_agent(client, headers, max_chain_depth=3)

    parent_token = _mint_token(
        client,
        headers,
        agent_id=parent_agent_id,
        ai_system_id=ai_system_id,
        scopes=["*"],
        chain_depth=1,
    )

    delegation = client.post(
        "/ai-iam/delegate",
        headers=headers,
        json={
            "parent_agent_id": parent_agent_id,
            "child_agent_id": child_agent_id,
            "ai_system_id": ai_system_id,
            "parent_capability_token": parent_token,
            "action_scope": ["tool.run"],
            "expires_minutes": 60,
            "parent_chain_depth": 1,
        },
    )
    assert delegation.status_code == 200, delegation.text
    assert delegation.json().get("delegation_id")

    misuse = client.post(
        "/runtime-control/agent-action-intercept",
        headers=headers,
        json={
            "correlation_id": "corr-remediation-delegation-misuse",
            "ai_system_id": ai_system_id,
            "agent_id": child_agent_id,
            "capability_token": parent_token,
            "action_type": "api_call",
            "tool_name": "openai_api",
            "target_resource": "api.openai.com",
            "chain_depth": 1,
            "parent_action_id": "delegation-parent-action",
            "policy_version": "pv-remediation-delegation",
            "platform_mode": "enforce",
            "input_context": {"parent_agent_id": parent_agent_id, "payload": {"prompt": "delegated task"}},
        },
    )
    assert misuse.status_code == 200, misuse.text
    body = misuse.json()
    assert body["decision"] == "block"
    assert body["reason_code"] == "delegation_chain_token_agent_mismatch"

    remediations = client.get(
        "/findings/remediations",
        headers=headers,
        params={"target_type": "agent", "target_id": child_agent_id},
    )
    assert remediations.status_code == 200, remediations.text
    reduce_item = next((item for item in remediations.json()["items"] if item["remediation_type"] == "permission_reduce"), None)
    assert reduce_item is not None
    if reduce_item["status"] != "applied":
        applied = _approve_and_apply_remediation(
            client,
            headers=headers,
            remediation_id=reduce_item["id"],
            justification="delegation_misuse_permission_reduce",
        )
        assert applied["status"] == "applied"

    session_local = test_env["SessionLocal"]
    with session_local() as db:
        delegations = db.scalars(
            select(AgentDelegation).where(AgentDelegation.tenant_id == owner["tenant_id"])
        ).all()
        assert delegations
        assert all(row.status == "revoked" for row in delegations)

        notification = db.scalar(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == owner["tenant_id"],
                MonitoringSignal.signal_type == "aiiam.remediation.permission_reduce",
            )
        )
        assert notification is not None
        payload = dict(notification.payload or {})
        assert payload.get("delegations_revoked", 0) >= 1
        assert payload.get("escalation_logged") is True


def test_high_risk_remediation_requires_approval_and_emits_lifecycle_signals(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="remediation-high-risk-approval@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers, risk_tier="HIGH")

    session_local = test_env["SessionLocal"]
    remediation_id: str | None = None
    with session_local() as db:
        row = propose_remediation_action(
            db,
            tenant_id=owner["tenant_id"],
            source_trigger_type="runtime_pattern",
            source_trigger_id=f"pattern-{uuid4().hex[:8]}",
            target_type="ai_system",
            target_id=ai_system_id,
            severity="high",
            context={
                "reason_code": "cross_session_risk_escalation",
                "related_control_ids": ["CTRL-RUNTIME-001"],
                "evidence_node_ids": [],
            },
        )
        db.commit()
        remediation_id = row.id
        assert row.requires_approval is True
        assert row.status == "proposed"

    assert remediation_id is not None
    _approve_and_apply_remediation(
        client,
        headers=headers,
        remediation_id=str(remediation_id),
        justification="high_risk_manual_approval",
    )

    with session_local() as db:
        signals = db.scalars(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == owner["tenant_id"],
                MonitoringSignal.signal_type.in_(
                    [
                        "remediation.lifecycle.proposed",
                        "remediation.lifecycle.approved",
                        "remediation.lifecycle.applied",
                    ]
                ),
            )
        ).all()
        assert len(signals) >= 3
        payloads = [dict(row.payload or {}) for row in signals if str((row.payload or {}).get("remediation_id") or "") == remediation_id]
        assert any(row.get("phase") == "proposed" for row in payloads)
        assert any(row.get("phase") == "approved" for row in payloads)
        assert any(row.get("phase") == "applied" for row in payloads)
        for payload in payloads:
            assert str(payload.get("source_module") or "").strip() != ""
            receiver_modules = list(payload.get("receiver_modules") or [])
            assert "automated_auditor" in receiver_modules
