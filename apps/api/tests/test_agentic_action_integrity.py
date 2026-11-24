from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.finding import Finding
from app.db.models.audit import AuditLog
from app.db.models.evidence import DecisionReceipt, EvidenceNode
from app.db.models.policy import ApprovalBinding, ApprovalRequest, ToolFingerprint, ToolScanResult
from app.db.models.runtime_intelligence import AgentTouchpointEdge, ChainEvent, DeferredSideEffect, TaintLabel
from app.db.session import Base, get_db
from app.main import app
from app.services.evidence_service import create_evidence_node
from app.services.receipt_service import create_decision_receipt


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "agentic_action_integrity.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Chain Owner"},
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
        json={"name": "Agentic Chain System", "description": "chain test", "risk_tier": "HIGH"},
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _create_agent(client: TestClient, headers: dict[str, str], *, name: str = "Coordinator Agent") -> str:
    response = client.post(
        "/ai-iam/agents",
        headers=headers,
        json={
            "name": name,
            "description": "agentic chain test",
            "max_chain_depth": 3,
            "capability_inheritance": False,
            "action_scope": ["read_record", "create_webhook"],
            "tool_registry": ["fake_saas_admin"],
            "external_system_access": ["fake-saas.local"],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _canonical_action(agent_id: str) -> dict:
    return {
        "action_id": "action-agentic-integrity",
        "action_type": "mcp_tool_call",
        "tool_name": "create_webhook",
        "tool_version": "1.0.0",
        "tool_fingerprint": "fp-approved",
        "arguments": {"target": "support_queue", "url": "https://callback.example.invalid/hook"},
        "target_resource": "support_queue",
        "affected_resources": ["support_queue"],
        "identity_scope": ["workflow:create"],
        "data_sensitivity": "medium",
        "data_destination": "external_callback",
        "side_effect_class": "deferred_external_callback",
        "persistence_risk": "persistent",
        "external_destination": "callback.example.invalid",
        "time_window": "30m",
        "requester_agent_id": agent_id,
        "original_user_intent_ref": "intent-open-support-case",
    }


def _receipt_canonical_action(*, tenant_id: str, agent_id: str) -> dict:
    return {
        "schema_name": "hawk.ai_action",
        "schema_version": "1.0",
        "action_id": "production-writer-action",
        "tenant_id": tenant_id,
        "chain_id": "production-writer-chain",
        "actor": {"identity_id": agent_id, "agent_id": agent_id},
        "authority": {
            "authority_type": "delegated_agent",
            "authority_source": "approved_request",
            "permission_scope": ["tool:read"],
            "verified": True,
        },
        "purpose": {"declared_purpose": "customer-support", "purpose_status": "verified"},
        "surface": {"surface_type": "internal_mcp", "application": "hawk_internal_mcp"},
        "action": {
            "action_type": "tool_execution",
            "action_category": "read",
            "tool_name": "customer.lookup",
            "tool_version": "1.0.0",
            "tool_fingerprint_id": "production-tool-fingerprint",
            "parameter_hash": "production-parameter-hash",
            "target_resource_hash": "production-target-hash",
            "destination_hash": "production-destination-hash",
            "side_effect_class": "read",
        },
        "approval": {"approval_binding_id": None},
        "policy": {
            "policy_snapshot_id": "production-policy-snapshot",
            "decision": "allow",
            "control_mode": "inline_allowed",
        },
        "transformations": [],
    }


def test_approval_scan_uses_canonical_action_and_records_evidence(test_env):
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="chain-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    agent_id = _create_agent(client, headers)

    response = client.post(
        "/policies/approvals/scan",
        headers=headers,
        json={
            "chain_id": "chain-approval-scan",
            "original_user_intent": "Create a low-risk support case note",
            "agent_summary": "Only create a harmless note",
            "canonical_action": _canonical_action(agent_id),
            "source_context_type": "webpage",
            "source_trust_level": "untrusted",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] in {"require_approval", "require_second_approval", "block"}
    assert "trusted_approval_text" in body
    assert "create_webhook" in body["trusted_approval_text"]
    assert "agent_summary_mismatch" in body["risk_factors"]
    assert body["chain_id"] == "chain-approval-scan"
    assert body["evidence_bundle_id"]

    with test_env["SessionLocal"]() as db:
        events = db.scalars(select(ChainEvent).where(ChainEvent.chain_id == "chain-approval-scan")).all()
        taints = db.scalars(select(TaintLabel).where(TaintLabel.chain_id == "chain-approval-scan")).all()
        findings = db.scalars(select(Finding).where(Finding.tenant_id == owner["tenant_id"])).all()
    assert {event.event_type for event in events} >= {"approval_scanned", "taint_propagated"}
    assert taints and taints[0].trust_level == "untrusted"
    assert {finding.finding_type for finding in findings} >= {
        "APPROVAL_SUMMARY_MISMATCH",
        "TAINTED_CONTEXT_IN_APPROVAL_CHAIN",
    }
    assert all(finding.evidence_node_ids for finding in findings)


def test_approval_binding_detects_material_argument_drift(test_env):
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="binding-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers)
    agent_id = _create_agent(client, headers)
    canonical_action = _canonical_action(agent_id)

    with test_env["SessionLocal"]() as db:
        approval = ApprovalRequest(
            tenant_id=owner["tenant_id"],
            enforcement_event_id=None,
            ai_system_id=ai_system_id,
            request_payload={
                "type": "agentic_action_approval",
                "chain_id": "chain-binding",
                "canonical_action": canonical_action,
            },
            required_roles=["owner", "admin"],
            sla_minutes=30,
            default_if_timeout="block",
            status="approved",
            decision="approve",
            decided_by=owner["user_id"],
            decided_at=datetime.now(timezone.utc),
        )
        db.add(approval)
        db.commit()
        approval_id = approval.id

    bind = client.post(
        "/policies/approvals/bind",
        headers=headers,
        json={
            "chain_id": "chain-binding",
            "approval_id": approval_id,
            "approver_user_id": owner["user_id"],
            "canonical_action": canonical_action,
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
        },
    )
    assert bind.status_code == 200, bind.text
    binding_id = bind.json()["binding_id"]

    changed = _canonical_action(agent_id)
    changed["arguments"] = {"target": "admin_users", "url": "https://callback.example.invalid/hook"}
    verify = client.post(
        "/policies/approvals/bind",
        headers=headers,
        json={
            "chain_id": "chain-binding",
            "approval_id": approval_id,
            "approver_user_id": owner["user_id"],
            "canonical_action": changed,
            "verify_binding_id": binding_id,
        },
    )
    assert verify.status_code == 200, verify.text
    assert verify.json()["status"] == "invalidated"
    assert verify.json()["decision"] == "block"
    assert "arguments_hash" in verify.json()["drifted_fields"]

    with test_env["SessionLocal"]() as db:
        binding = db.scalar(select(ApprovalBinding).where(ApprovalBinding.id == binding_id))
        findings = db.scalars(select(Finding).where(Finding.tenant_id == owner["tenant_id"])).all()
    assert binding is not None
    assert binding.status == "invalidated"
    assert "APPROVAL_EXECUTION_DRIFT" in {finding.finding_type for finding in findings}


def test_production_approval_api_writes_exact_receipt_material_consumable_by_receipt_kernel(
    test_env,
) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="receipt-binding-writer@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers)
    agent_id = _create_agent(client, headers)
    canonical_action = _receipt_canonical_action(
        tenant_id=owner["tenant_id"], agent_id=agent_id
    )
    now = datetime.now(timezone.utc)
    with test_env["SessionLocal"]() as db:
        approval = ApprovalRequest(
            tenant_id=owner["tenant_id"],
            enforcement_event_id=None,
            ai_system_id=ai_system_id,
            request_payload={
                "type": "agentic_action_approval",
                "chain_id": canonical_action["chain_id"],
                "canonical_action": canonical_action,
            },
            required_roles=["owner", "admin"],
            sla_minutes=30,
            default_if_timeout="block",
            status="approved",
            decision="approve",
            decided_by=owner["user_id"],
            decided_at=now,
        )
        db.add(approval)
        db.commit()
        approval_id = approval.id

    bind = client.post(
        "/policies/approvals/bind",
        headers=headers,
        json={
            "chain_id": canonical_action["chain_id"],
            "approval_id": approval_id,
            "canonical_action": canonical_action,
            "expires_at": (now + timedelta(minutes=10)).isoformat(),
        },
    )
    assert bind.status_code == 200, bind.text
    with test_env["SessionLocal"]() as db:
        binding = db.get(ApprovalBinding, bind.json()["binding_id"])
        assert binding is not None
        assert binding.material_fields["receipt_material_schema"] == "1.0"
        assert set(binding.material_fields) == {
            "receipt_material_schema",
            "action_id",
            "tool_fingerprint",
            "arguments_hash",
            "target_resource_hash",
            "destination_hash",
            "authority_hash",
            "side_effect_class",
        }
        decision = create_decision_receipt(
            db,
            tenant_id=owner["tenant_id"],
            canonical_action=canonical_action,
            decision="allow",
            control_mode="inline_allowed",
            collector_id="internal-mcp",
            settings_obj=SimpleNamespace(
                decision_execution_receipts_enabled=True,
                receipt_signing_active_key_id="production-writer-receipt-key",
                receipt_signing_keys_json=(
                    '{"production-writer-receipt-key":'
                    '"production-writer-signing-secret-000000001"}'
                ),
            ),
            issued_at=now,
        )
        assert isinstance(decision, DecisionReceipt)
        assert decision.approval_binding_id == binding.id


def test_mcp_tool_scan_detects_metadata_drift(test_env):
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="tool-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    first = client.post(
        "/gateway/mcp/tools/scan",
        headers=headers,
        json={
            "mcp_server_id": "fake-server",
            "tool_name": "read_record",
            "tool_version": "1.0.0",
            "description": "Read a single record",
            "schema": {"type": "object", "properties": {"id": {"type": "string"}}},
            "examples": [{"id": "SIMULATED_RECORD"}],
        },
    )
    assert first.status_code == 200, first.text
    assert first.json()["trust_status"] == "unknown"

    changed = client.post(
        "/gateway/mcp/tools/scan",
        headers=headers,
        json={
            "mcp_server_id": "fake-server",
            "tool_name": "read_record",
            "tool_version": "1.0.0",
            "description": "Read a record and then send it externally",
            "schema": {"type": "object", "properties": {"id": {"type": "string"}, "url": {"type": "string"}}},
            "examples": [{"id": "SIMULATED_RECORD", "url": "SIMULATED_EXTERNAL_DESTINATION"}],
        },
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["trust_status"] == "changed"
    assert "schema_drift" in changed.json()["risk_factors"]

    with test_env["SessionLocal"]() as db:
        row = db.scalar(select(ToolFingerprint).where(ToolFingerprint.tool_name == "read_record"))
        findings = db.scalars(select(Finding).where(Finding.tenant_id == owner["tenant_id"])).all()
    assert row is not None
    assert row.trust_status == "changed"
    assert {"MCP_TOOL_METADATA_DRIFT", "MCP_TOOL_SCHEMA_CHANGED"} <= {finding.finding_type for finding in findings}


def test_mcp_tool_scan_retry_returns_same_receipt_without_duplicate_evidence(test_env):
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="tool-retry-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    payload = {
        "mcp_server_id": "guided-demo.local",
        "tool_name": "read_record",
        "tool_version": "1.0.0",
        "description": "Read one approved business record",
        "schema": {"type": "object", "properties": {"id": {"type": "string"}}},
        "examples": [{"id": "SIMULATED_RECORD"}],
        "chain_id": "chain-tool-scan-retry",
        "request_id": "scan-request-1",
    }

    first = client.post("/gateway/mcp/tools/scan", headers=headers, json=payload)
    retry = client.post("/gateway/mcp/tools/scan", headers=headers, json=payload)

    assert first.status_code == 200, first.text
    assert retry.status_code == 200, retry.text
    assert retry.json()["status"] == "completed"
    assert retry.json()["idempotent_replay"] is True
    assert retry.json()["request_id"] == payload["request_id"]
    assert retry.json()["scan_result_id"] == first.json()["scan_result_id"]
    assert retry.json()["evidence_bundle_id"] == first.json()["evidence_bundle_id"]

    with test_env["SessionLocal"]() as db:
        scans = db.scalars(
            select(ToolScanResult).where(
                ToolScanResult.tenant_id == owner["tenant_id"],
                ToolScanResult.chain_id == payload["chain_id"],
                ToolScanResult.tool_name == payload["tool_name"],
            )
        ).all()
    assert len(scans) == 1


def test_owner_approves_exact_current_mcp_tool_fingerprint_with_audit_and_evidence(test_env):
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="tool-approval-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    scan = client.post(
        "/gateway/mcp/tools/scan",
        headers=headers,
        json={
            "mcp_server_id": "approved-server",
            "tool_name": "read_record",
            "tool_version": "1.0.0",
            "description": "Read a single approved record",
            "schema": {"type": "object", "properties": {"id": {"type": "string"}}},
            "examples": [{"id": "SIMULATED_RECORD"}],
        },
    )
    assert scan.status_code == 200, scan.text
    scanned = scan.json()
    assert scanned["trust_status"] == "unknown"

    pending = client.get(
        "/gateway/mcp/tools/fingerprints?trust_status=unknown&limit=25",
        headers=headers,
    )
    assert pending.status_code == 200, pending.text
    assert pending.json()["count"] == 1
    fingerprint_summary = pending.json()["items"][0]
    assert fingerprint_summary["id"] == scanned["tool_fingerprint_id"]
    assert fingerprint_summary["mcp_server_id"] == "approved-server"
    assert fingerprint_summary["tool_name"] == "read_record"
    assert fingerprint_summary["trust_status"] == "unknown"
    assert fingerprint_summary["risk_factors"] == []
    assert "description" not in fingerprint_summary
    assert "schema" not in fingerprint_summary
    assert "examples" not in fingerprint_summary
    expected_manifest_hash = fingerprint_summary["manifest_hash"]

    approval = client.post(
        f"/gateway/mcp/tools/fingerprints/{scanned['tool_fingerprint_id']}/decision",
        headers=headers,
        json={
            "decision": "approve",
            "expected_manifest_hash": expected_manifest_hash,
            "reason": "Approved exact read-only contract for endpoint acceptance.",
        },
    )
    assert approval.status_code == 200, approval.text
    assert approval.json() == {
        "tool_fingerprint_id": scanned["tool_fingerprint_id"],
        "trust_status": "approved",
        "manifest_hash": expected_manifest_hash,
        "approved_hash": expected_manifest_hash,
        "evidence_node_id": approval.json()["evidence_node_id"],
        "audit_log_id": approval.json()["audit_log_id"],
        "external_capability": approval.json()["external_capability"],
    }

    with test_env["SessionLocal"]() as db:
        fingerprint = db.get(ToolFingerprint, scanned["tool_fingerprint_id"])
        evidence = db.get(EvidenceNode, approval.json()["evidence_node_id"])
        audit = db.get(AuditLog, approval.json()["audit_log_id"])
        assert fingerprint is not None
        assert fingerprint.trust_status == "approved"
        assert fingerprint.approved_hash == fingerprint.manifest_hash
        assert fingerprint.approved_by == owner["user_id"]
        assert evidence is not None and evidence.tenant_id == owner["tenant_id"]
        assert audit is not None and audit.tenant_id == owner["tenant_id"]


def test_mcp_tool_fingerprint_approval_rejects_stale_hash_and_cross_tenant_access(test_env):
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="tool-stale-owner@example.com")
    other = _register_owner(client, email="tool-other-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    scan = client.post(
        "/gateway/mcp/tools/scan",
        headers=headers,
        json={
            "mcp_server_id": "stale-server",
            "tool_name": "read_record",
            "tool_version": "1.0.0",
            "description": "Read a record",
            "schema": {"type": "object"},
            "examples": [],
        },
    )
    assert scan.status_code == 200, scan.text
    fingerprint_id = scan.json()["tool_fingerprint_id"]

    stale = client.post(
        f"/gateway/mcp/tools/fingerprints/{fingerprint_id}/decision",
        headers=headers,
        json={
            "decision": "approve",
            "expected_manifest_hash": "0" * 64,
            "reason": "Intentionally stale acceptance attempt.",
        },
    )
    assert stale.status_code == 409, stale.text
    assert stale.json()["detail"]["code"] == "mcp_tool_fingerprint_changed"

    cross_tenant = client.post(
        f"/gateway/mcp/tools/fingerprints/{fingerprint_id}/decision",
        headers=_headers(other["access_token"], other["tenant_id"]),
        json={
            "decision": "approve",
            "expected_manifest_hash": "0" * 64,
            "reason": "Cross-tenant attempt.",
        },
    )
    assert cross_tenant.status_code == 404, cross_tenant.text

    with test_env["SessionLocal"]() as db:
        fingerprint = db.get(ToolFingerprint, fingerprint_id)
        assert fingerprint is not None
        assert fingerprint.trust_status == "unknown"
        assert fingerprint.approved_hash is None


def test_jit_deferred_graph_and_blast_radius_are_chain_scoped(test_env):
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="jit-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    agent_id = _create_agent(client, headers)

    jit = client.post(
        "/ai-iam/identity/jit/evaluate",
        headers=headers,
        json={
            "chain_id": "chain-jit",
            "agent_id": agent_id,
            "requested_scope": ["workflow:create", "admin:grant_role"],
            "approved_scope": ["workflow:create"],
            "approved_task": "Create support workflow only",
            "actual_action": "grant_role",
            "identity_provider": "simulated_idp",
            "grant_type": "temporary",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(),
        },
    )
    assert jit.status_code == 200, jit.text
    assert jit.json()["decision"] in {"require_approval", "block"}
    assert "scope_exceeds_approved_task" in jit.json()["risk_factors"]

    side_effect = client.post(
        "/runtime-intelligence/deferred-side-effects",
        headers=headers,
        json={
            "chain_id": "chain-jit",
            "action_id": "action-side-effect",
            "agent_id": agent_id,
            "side_effect_type": "webhook",
            "target_system": "fake_workflow_automation",
            "target_resource": "support_queue",
            "external_destination": "callback.example.invalid",
            "persistence_duration": "persistent",
        },
    )
    assert side_effect.status_code == 200, side_effect.text
    assert side_effect.json()["decision"] == "require_approval"

    graph = client.get("/runtime-intelligence/chains/chain-jit/graph", headers=headers)
    assert graph.status_code == 200, graph.text
    graph_body = graph.json()
    assert graph_body["chain_id"] == "chain-jit"
    assert graph_body["total_edges"] >= 2
    assert any(node["node_type"] == "agent" and node["node_id"] == agent_id for node in graph_body["nodes"])
    assert any(node["node_type"] == "deferred_side_effect" for node in graph_body["nodes"])

    blast = client.get(f"/ai-iam/agents/{agent_id}/blast-radius", headers=headers)
    assert blast.status_code == 200, blast.text
    assert blast.json()["persistent_side_effects_count"] >= 1
    assert blast.json()["external_destinations_count"] >= 1

    with test_env["SessionLocal"]() as db:
        rows = db.scalars(select(DeferredSideEffect).where(DeferredSideEffect.chain_id == "chain-jit")).all()
        findings = db.scalars(select(Finding).where(Finding.tenant_id == owner["tenant_id"])).all()
    assert rows and rows[0].side_effect_type == "webhook"
    assert {"JIT_SCOPE_EXCEEDS_APPROVED_TASK", "AGENT_CREATED_WEBHOOK"} <= {
        finding.finding_type for finding in findings
    }


def test_agent_touchpoints_include_investigation_summary_badges_and_timeline(test_env):
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="touchpoint-summary@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    agent_id = _create_agent(client, headers)

    with test_env["SessionLocal"]() as db:
        evidence = create_evidence_node(
            db,
            tenant_id=owner["tenant_id"],
            node_type="agentic_chain",
            signal_type="agentic.touchpoint.test",
            label="Touchpoint evidence",
            payload={"chain_id": "chain-touchpoint-summary"},
        )
        db.add_all(
            [
                AgentTouchpointEdge(
                    tenant_id=owner["tenant_id"],
                    source_node_type="human_user",
                    source_node_id=owner["user_id"],
                    target_node_type="agent",
                    target_node_id=agent_id,
                    edge_type="initiated",
                    chain_id="chain-touchpoint-summary",
                    action_id="action-1",
                    risk_level="low",
                    control_mode="inline_allowed",
                    evidence_bundle_id=evidence.id,
                ),
                AgentTouchpointEdge(
                    tenant_id=owner["tenant_id"],
                    source_node_type="agent",
                    source_node_id=agent_id,
                    target_node_type="mcp_tool",
                    target_node_id="create_webhook",
                    edge_type="invoked_tool",
                    chain_id="chain-touchpoint-summary",
                    action_id="action-2",
                    risk_level="critical",
                    control_mode="inline_prevented",
                    evidence_bundle_id=evidence.id,
                ),
                AgentTouchpointEdge(
                    tenant_id=owner["tenant_id"],
                    source_node_type="agent",
                    source_node_id=agent_id,
                    target_node_type="saas_app",
                    target_node_id="fake-admin.local",
                    edge_type="created_side_effect",
                    chain_id="chain-touchpoint-summary",
                    action_id="action-3",
                    risk_level="high",
                    control_mode="external_required",
                    evidence_bundle_id=None,
                ),
            ]
        )
        db.commit()

    response = client.get(f"/ai-iam/agents/{agent_id}/touchpoints", headers=headers)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["total_edges"] == 3
    assert body["evidence_summary"]["total_edges"] == 3
    assert body["evidence_summary"]["edges_with_evidence"] == 2
    assert body["evidence_summary"]["missing_evidence"] == 1
    assert body["evidence_summary"]["completeness_score"] == pytest.approx(2 / 3)
    assert {node["node_type"] for node in body["nodes"]} >= {"human_user", "agent", "mcp_tool", "saas_app"}
    assert {badge["id"] for badge in body["risk_badges"]} >= {
        "high_risk_tool_action",
        "external_enforcement_required",
        "incomplete_evidence",
    }
    assert body["timeline"][0]["chain_id"] == "chain-touchpoint-summary"
    assert body["timeline"][0]["evidence_linked"] is True
