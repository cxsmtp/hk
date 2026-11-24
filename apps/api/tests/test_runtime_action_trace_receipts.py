from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.services.receipt_service as receipt_service_module
from app.core.config import settings
from app.core.control_engine.authorization import (
    adapt_authorization_request,
    authorize_ai_action,
)
from app.db.models.evidence import DecisionReceipt, EvidenceNode
from app.db.models.policy import ApprovalBinding
from app.db.models.runtime_intelligence import RuntimeBehaviorEdge, RuntimeEvent
from app.db.session import Base, get_db
from app.main import app
from app.services.receipt_service import (
    approval_binding_contract,
    create_decision_receipt_from_authorization,
    create_decision_receipt,
    create_execution_receipt,
    record_execution_incomplete,
    record_execution_unknown,
)


@pytest.fixture()
def trace_env(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "self_registration_enabled", True)
    monkeypatch.setattr(settings, "decision_execution_receipts_enabled", True)
    monkeypatch.setattr(settings, "receipt_signing_active_key_id", "trace-receipt-key")
    monkeypatch.setattr(
        settings,
        "receipt_signing_keys_json",
        '{"trace-receipt-key":"trace-receipt-signing-material-0000000001"}',
    )

    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'runtime-action-trace.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield client, session_factory
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _register(client: TestClient, email: str) -> tuple[str, dict[str, str]]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": "Password123!", "full_name": "Trace Owner"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    tenant_id = payload["tenants"][0]["id"]
    return tenant_id, {
        "Authorization": f"Bearer {payload['access_token']}",
        "X-Tenant-ID": tenant_id,
    }


def _canonical_action(
    *,
    tenant_id: str,
    action_id: str,
    chain_id: str,
    approval_binding_id: str | None = None,
) -> dict:
    return {
        "schema_name": "hawk.ai_action",
        "schema_version": "1.0",
        "action_id": action_id,
        "tenant_id": tenant_id,
        "chain_id": chain_id,
        "actor": {
            "identity_id": "agent-1",
            "identity_type": "agent",
            "user_id": "user-1",
            "agent_id": "agent-1",
            "session_id": "session-1",
            "runtime_instance_id": "runtime-1",
            "machine_id": "runtime-machine-1",
            "acting_on_behalf_of": "user-1",
            "acting_on_behalf_of_user_id": "user-1",
            "delegation_chain": ["user-1", "agent-1"],
        },
        "authority": {
            "authority_type": "delegated",
            "authority_source": "approved_request",
            "authority_owner": "user-1",
            "standing_privilege": "none",
            "jit_grant_id": "jit-1",
            "permission_scope": ["customer:read"],
            "verified": True,
        },
        "purpose": {
            "tenant_sector": "financial_services",
            "business_function": "customer_support",
            "declared_purpose": "resolve customer case",
            "inferred_purpose": "resolve customer case",
            "purpose_confidence": 0.98,
            "business_relevance": "high",
            "purpose_status": "verified",
        },
        "surface": {
            "surface_type": "mcp",
            "collector_type": "mcp_gateway",
            "application": "support-copilot",
            "provider": "customer",
            "model": "customer-model",
            "environment": "production",
            "domain": "support.example.invalid",
            "endpoint": "https://support.example.invalid/mcp",
            "repo_id": "unknown",
            "workspace_id": "support",
            "mcp_server_id": "support-mcp",
            "asset_status": "managed",
        },
        "action": {
            "action_type": "tool_execution",
            "action_category": "read",
            "tool_name": "lookup_customer",
            "tool_version": "1.0.0",
            "tool_fingerprint_id": "tool-fingerprint",
            "parameter_hash": "parameter-hash",
            "target_resource_hash": "target-hash",
            "destination_hash": "destination-hash",
            "side_effect_class": "read",
        },
        "approval": {
            "approval_binding_id": approval_binding_id,
        },
        "policy": {
            "policy_snapshot_id": "policy-snapshot-1",
            "decision": "allow",
            "control_mode": "inline_allowed",
        },
        "transformations": [],
    }


def _runtime_event(
    *,
    tenant_id: str,
    action_id: str,
    chain_id: str,
    metadata: dict | None = None,
) -> RuntimeEvent:
    return RuntimeEvent(
        event_id=action_id,
        tenant_id=tenant_id,
        source_surface="mcp",
        event_type="mcp_tool_call",
        decision="allow",
        chain_id=chain_id,
        evidence_node_ids=[],
        metadata_json=dict(metadata or {}),
    )


def _create_approval_binding(
    db,
    *,
    tenant_id: str,
    canonical_action: dict,
    binding_id: str,
    issued_at: datetime,
) -> ApprovalBinding:
    contract = approval_binding_contract(canonical_action, tenant_id=tenant_id)
    binding = ApprovalBinding(
        id=binding_id,
        tenant_id=tenant_id,
        chain_id=canonical_action["chain_id"],
        action_id=canonical_action["action_id"],
        approval_id=f"approval-{binding_id}",
        canonical_action_hash=contract["canonical_action_hash"],
        receipt_material_hash=contract["receipt_material_hash"],
        signed_receipt="approval-signature-must-not-be-returned",
        material_fields=contract["material_fields"],
        approved_at=issued_at - timedelta(minutes=1),
        expires_at=issued_at + timedelta(minutes=10),
        status="active",
    )
    db.add(binding)
    db.flush()
    return binding


def _create_signed_proof(
    db,
    *,
    tenant_id: str,
    action_id: str,
    chain_id: str,
    with_approval: bool = False,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    with_execution: bool = True,
):
    issued = issued_at or datetime.now(timezone.utc)
    binding_id = str(uuid4()) if with_approval else None
    canonical = _canonical_action(
        tenant_id=tenant_id,
        action_id=action_id,
        chain_id=chain_id,
        approval_binding_id=binding_id,
    )
    binding = (
        _create_approval_binding(
            db,
            tenant_id=tenant_id,
            canonical_action=canonical,
            binding_id=binding_id,
            issued_at=issued,
        )
        if binding_id is not None
        else None
    )
    decision = create_decision_receipt(
        db,
        tenant_id=tenant_id,
        canonical_action=canonical,
        decision="allow",
        control_mode="inline_allowed",
        collector_id="runtime-trace-test",
        settings_obj=settings,
        issued_at=issued,
        expires_at=expires_at or issued + timedelta(minutes=5),
        clock=lambda: issued,
    )
    assert decision is not None
    execution = None
    integrity = None
    if with_execution:
        execution, integrity = create_execution_receipt(
            db,
            tenant_id=tenant_id,
            decision_receipt_id=decision.receipt_id,
            actual_canonical_action=canonical,
            execution_status="success",
            collector_id="runtime-trace-test",
            settings_obj=settings,
            executed_at=issued + timedelta(seconds=1),
            execution_attempt_id=f"attempt-{action_id}",
        )
    db.flush()
    evidence = db.get(EvidenceNode, decision.canonical_action_evidence_node_id)
    assert evidence is not None
    expected_canonical = deepcopy(dict(evidence.payload or {})["canonical_action"])
    return decision, execution, integrity, binding, expected_canonical


def test_action_trace_projects_only_receipt_verified_canonical_evidence(trace_env) -> None:
    client, session_factory = trace_env
    tenant_id, headers = _register(client, "verified-trace@example.com")
    action_id = "action-verified-trace"
    chain_id = "chain-verified-trace"
    legacy_signature = "legacy-signature-must-not-be-returned"
    nested_signature = "nested-signature-must-not-be-returned"
    hostile_edge_values = [
        "edge-arguments-must-not-leak",
        "edge-camel-prompt-must-not-leak",
        "edge-dotted-prompt-must-not-leak",
        "edge-nested-request-must-not-leak",
        "edge-content-must-not-leak",
        "edge-response-must-not-leak",
        "edge-secret-must-not-leak",
    ]

    with session_factory() as db:
        db.add(
            _runtime_event(
                tenant_id=tenant_id,
                action_id=action_id,
                chain_id=chain_id,
                metadata={
                    "canonical_ai_action_v1": {
                        "actor": {"identity_id": "forged-metadata-actor"}
                    },
                    "canonical_ai_action_hash": "forged-metadata-hash",
                    "ai_action": {
                        "action_id": action_id,
                        "signature": legacy_signature,
                        "signature_present": True,
                        "signature_verified": "attacker-string-must-be-removed",
                        "signing_key_id": "legacy-key",
                        "nested_status": {
                            "signature_present": {"attacker": True},
                        },
                        "policy_snapshot": {
                            "snapshot_id": "policy-snapshot-1",
                            "receipt_signature": nested_signature,
                        },
                        "decision_explanation": {
                            "reason": "server explanation",
                            "nested": {"integrity_signature": nested_signature},
                        },
                        "evidence_bundle": {
                            "bundle_id": "bundle-1",
                            "signed_receipt": nested_signature,
                        },
                    },
                },
            )
        )
        db.add(
            RuntimeBehaviorEdge(
                tenant_id=tenant_id,
                event_id=action_id,
                source_node_type="ai_action",
                source_node_id=action_id,
                target_node_type="tool",
                target_node_id="lookup_customer",
                relationship_type="invokes",
                payload={
                    "signature": nested_signature,
                    "signature_verified": True,
                    "signing_key_id": "edge-key",
                    "Arguments": hostile_edge_values[0],
                    "requestPrompt": hostile_edge_values[1],
                    "request.prompt": hostile_edge_values[2],
                    "nested": {
                        "request": {"prompt": hostile_edge_values[3]},
                    },
                    "content": {"raw": hostile_edge_values[4]},
                    "response": {"text": hostile_edge_values[5]},
                    "secret": hostile_edge_values[6],
                },
            )
        )
        decision, execution, integrity, _, expected_canonical = _create_signed_proof(
            db,
            tenant_id=tenant_id,
            action_id=action_id,
            chain_id=chain_id,
        )
        decision_id = decision.receipt_id
        execution_id = execution.receipt_id
        integrity_id = integrity.result_id
        decision_signature = decision.signature
        execution_signature = execution.signature
        integrity_signature = integrity.signature
        db.commit()

    response = client.get(
        f"/runtime-intelligence/action-trace/{action_id}",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["canonical_ai_action_status"] == "verified"
    assert payload["canonical_ai_action"] == expected_canonical
    assert payload["canonical_ai_action"]["actor"]["identity_id"] == "agent-1"
    assert "forged-metadata-actor" not in response.text
    assert payload["decision_receipt"]["receipt_id"] == decision_id
    assert payload["decision_receipt"]["signature_present"] is True
    assert payload["decision_receipt"]["signature_verified"] is True
    assert payload["execution_receipt"]["receipt_id"] == execution_id
    assert payload["execution_receipt"]["signature_present"] is True
    assert payload["execution_receipt"]["signature_verified"] is True
    assert payload["execution_integrity"]["result_id"] == integrity_id
    assert payload["execution_integrity"]["signature_present"] is True
    assert payload["execution_integrity"]["signature_verified"] is True
    assert payload["ai_action"]["signature_present"] is True
    assert "signature_verified" not in payload["ai_action"]
    assert payload["ai_action"]["signing_key_id"] == "legacy-key"
    assert "nested_status" not in payload["ai_action"]
    assert "signature" not in payload["ai_action"]
    assert "receipt_signature" not in payload["policy_snapshot"]
    assert "nested" not in payload["decision_explanation"]
    assert "signed_receipt" not in payload["evidence_bundle"]
    assert "signature" not in payload["graph"]["edges"][0]["payload"]
    assert payload["graph"]["edges"][0]["payload"]["signature_verified"] is True
    assert legacy_signature not in response.text
    assert nested_signature not in response.text
    for hostile_edge_value in hostile_edge_values:
        assert hostile_edge_value not in response.text
    assert "approval-signature-must-not-be-returned" not in response.text
    assert decision_signature not in response.text
    assert execution_signature not in response.text
    assert integrity_signature not in response.text


def test_action_trace_accepts_real_authorization_chain_canonical_projection(
    trace_env,
) -> None:
    client, session_factory = trace_env
    tenant_id, headers = _register(client, "production-chain-trace@example.com")
    action_id = "action-production-chain"
    chain_id = "chain-production-chain"
    request = adapt_authorization_request(
        {
            "tenant_id": tenant_id,
            "action_id": action_id,
            "chain_id": chain_id,
            "adapter": "mcp_gateway",
            "actor": {
                "identity_id": "user-001",
                "user_id": "user-001",
                "agent_id": "agent-001",
            },
            "authority": {
                "authority_type": "delegated",
                "authority_source": "capability-token",
                "permission_scope": ["tool:read"],
                "verified": True,
            },
            "purpose": {
                "declared_purpose": "customer-support",
                "purpose_status": "verified",
            },
            "surface": {
                "surface_type": "mcp_gateway",
                "collector_type": "mcp_gateway",
                "environment": "prod",
                "application": "bank-assistant",
                "asset_status": "approved",
                "mcp_server_id": "mcp-bank",
            },
            "action": {
                "action_type": "tool_execution",
                "risk_level": "low",
                "tool_name": "lookup_customer",
                "tool_version": "1.0.0",
                "tool_fingerprint_id": "tool-fingerprint",
                "parameter_hash": "parameter-hash",
                "target_resource_hash": "target-hash",
                "destination_hash": "destination-hash",
                "side_effect_class": "read",
                "persistent_side_effect": False,
            },
        },
        collector_id="runtime-trace-test",
        policy_snapshot_id="policy-snapshot-1",
        policy_profile={
            "base_decision": "allow",
            "matched_rules": [],
            "dependencies_healthy": True,
            "cache_ttl": 15,
            "degraded_behavior": "block",
        },
        path_evidence={
            "collector_inline_capable": True,
            "inline_pre_execution": True,
        },
    )
    authorization = authorize_ai_action(request)

    with session_factory() as db:
        db.add(
            _runtime_event(
                tenant_id=tenant_id,
                action_id=action_id,
                chain_id=chain_id,
            )
        )
        receipt, _ = create_decision_receipt_from_authorization(
            db,
            request=request,
            response=authorization,
            settings_obj=settings,
        )
        assert receipt is not None
        db.commit()

    response = client.get(
        f"/runtime-intelligence/action-trace/{action_id}",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["decision_receipt"]["signature_verified"] is True
    assert payload["canonical_ai_action_status"] == "verified"
    assert payload["canonical_ai_action"]["actor"]["identity_id"] == "user-001"
    assert payload["canonical_ai_action"]["surface"] == {
        "surface_type": "mcp_gateway",
        "application": "bank-assistant",
        "provider": None,
        "model": None,
        "mcp_server_id": "mcp-bank",
        "asset_status": "approved",
    }


def test_action_trace_projects_safe_optional_canonical_action_fields(trace_env) -> None:
    client, session_factory = trace_env
    tenant_id, headers = _register(client, "optional-canonical-action@example.com")
    action_id = "action-optional-canonical-fields"
    chain_id = "chain-optional-canonical-fields"
    canonical = _canonical_action(
        tenant_id=tenant_id,
        action_id=action_id,
        chain_id=chain_id,
    )
    canonical["action"].update(
        {
            "redacted_arguments": "[redacted]",
            "target_resource": None,
            "data_destination": "internal-analytics",
            "persistent_side_effect": False,
        }
    )

    with session_factory() as db:
        db.add(
            _runtime_event(
                tenant_id=tenant_id,
                action_id=action_id,
                chain_id=chain_id,
            )
        )
        decision = create_decision_receipt(
            db,
            tenant_id=tenant_id,
            canonical_action=canonical,
            decision="allow",
            control_mode="inline_allowed",
            collector_id="runtime-trace-test",
            settings_obj=settings,
        )
        assert decision is not None
        db.commit()

    response = client.get(
        f"/runtime-intelligence/action-trace/{action_id}",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["canonical_ai_action_status"] == "verified"
    assert payload["canonical_ai_action"]["action"] == {
        **_canonical_action(
            tenant_id=tenant_id,
            action_id=action_id,
            chain_id=chain_id,
        )["action"],
        "redacted_arguments": "[hashed_only]",
        "target_resource": None,
        "data_destination": "internal-analytics",
        "persistent_side_effect": False,
    }


@pytest.mark.parametrize(
    "redacted_arguments",
    [
        {"rawPrompt": "[redacted]"},
        {"customer_id": "sk-live-secret-value-must-not-leak"},
        {"customer_id": {"receiptSignature": "raw-signature-must-not-leak"}},
    ],
)
def test_action_trace_rejects_signed_non_redacted_argument_material(
    trace_env,
    monkeypatch,
    redacted_arguments,
) -> None:
    client, session_factory = trace_env
    suffix = uuid4().hex[:8]
    tenant_id, headers = _register(
        client,
        f"invalid-redacted-arguments-{suffix}@example.com",
    )
    action_id = f"action-invalid-redacted-{suffix}"
    chain_id = f"chain-invalid-redacted-{suffix}"
    canonical = _canonical_action(
        tenant_id=tenant_id,
        action_id=action_id,
        chain_id=chain_id,
    )
    canonical["action"]["redacted_arguments"] = redacted_arguments
    monkeypatch.setattr(
        receipt_service_module,
        "sanitize_privacy_payload",
        lambda value: deepcopy(value),
    )

    with session_factory() as db:
        db.add(
            _runtime_event(
                tenant_id=tenant_id,
                action_id=action_id,
                chain_id=chain_id,
            )
        )
        decision = create_decision_receipt(
            db,
            tenant_id=tenant_id,
            canonical_action=canonical,
            decision="allow",
            control_mode="inline_allowed",
            collector_id="runtime-trace-test",
            settings_obj=settings,
        )
        assert decision is not None
        db.commit()

    response = client.get(
        f"/runtime-intelligence/action-trace/{action_id}",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["decision_receipt"]["signature_verified"] is True
    assert payload["canonical_ai_action_status"] == "invalid"
    assert payload["canonical_ai_action"] == {}
    assert "sk-live-secret-value-must-not-leak" not in response.text
    assert "raw-signature-must-not-leak" not in response.text


def test_action_trace_does_not_promote_dual_write_metadata_without_receipt(trace_env) -> None:
    client, session_factory = trace_env
    tenant_id, headers = _register(client, "no-receipt-trace@example.com")
    action_id = "action-no-receipt-trace"
    chain_id = "chain-no-receipt-trace"

    with session_factory() as db:
        db.add(
            _runtime_event(
                tenant_id=tenant_id,
                action_id=action_id,
                chain_id=chain_id,
                metadata={
                    "canonical_ai_action_v1": {
                        "schema_name": "hawk.ai_action",
                        "schema_version": "1.0",
                        "tenant_id": tenant_id,
                        "action_id": action_id,
                        "chain_id": chain_id,
                        "actor": {"identity_id": "unverified-dual-write"},
                    },
                    "canonical_ai_action_hash": "unverified-dual-write-hash",
                    "ai_action": {
                        "action_id": action_id,
                        "signature": "legacy-signature-must-not-leak",
                    },
                },
            )
        )
        db.commit()

    response = client.get(
        f"/runtime-intelligence/action-trace/{action_id}",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["canonical_ai_action"] == {}
    assert payload["canonical_ai_action_status"] == "unavailable"
    assert "unverified-dual-write" not in response.text
    assert "legacy-signature-must-not-leak" not in response.text


def test_action_trace_legacy_compatibility_projection_drops_raw_material_and_secrets(
    trace_env,
) -> None:
    client, session_factory = trace_env
    tenant_id, headers = _register(client, "legacy-compatibility-safety@example.com")
    action_id = "action-legacy-compatibility-safety"
    chain_id = "chain-legacy-compatibility-safety"
    hostile_values = [
        "raw-arguments-must-not-leak",
        "raw-parameters-must-not-leak",
        "nested-request-prompt-must-not-leak",
        "camel-tool-arguments-must-not-leak",
        "dotted-prompt-must-not-leak",
        "content-prompt-must-not-leak",
        "secret-sk-live-1234567890-must-not-leak",
        "raw-signature-must-not-leak",
        "nested-policy-prompt-must-not-leak",
        "nested-explanation-prompt-must-not-leak",
        "nested-evidence-secret-must-not-leak",
    ]

    with session_factory() as db:
        db.add(
            _runtime_event(
                tenant_id=tenant_id,
                action_id=action_id,
                chain_id=chain_id,
                metadata={
                    "ai_action": {
                        "action_id": action_id,
                        "tenant_id": tenant_id,
                        "chain_id": chain_id,
                        "signature_present": True,
                        "signing_key_id": "legacy-key",
                        "arguments": hostile_values[0],
                        "raw_parameters": hostile_values[1],
                        "RawPrompt": hostile_values[4],
                        "request": {"Prompt": hostile_values[2]},
                        "toolArguments": hostile_values[3],
                        "content": {"prompt_text": hostile_values[5]},
                        "secret": hostile_values[6],
                        "signedReceipt": hostile_values[7],
                        "actor": {
                            "user_id": "user-safe",
                            "rawPrompt": hostile_values[2],
                        },
                        "surface": {
                            "surface_type": "mcp_gateway",
                            "provider": "customer",
                            "model": "safe-model",
                            "apiKey": hostile_values[6],
                        },
                        "action": {
                            "action_type": "tool_execution",
                            "tool_name": "lookup_customer",
                            "parameter_hash": "safe-parameter-hash",
                            "tool.arguments": hostile_values[3],
                            "request": {"prompt": hostile_values[2]},
                        },
                        "policy": {
                            "decision": "allow",
                            "control_mode": "inline_allowed",
                            "secret": hostile_values[6],
                        },
                        "policy_snapshot": {
                            "policy_snapshot_id": "policy-safe",
                            "request.prompt": hostile_values[8],
                        },
                        "decision_explanation": {
                            "reason_code": "policy_allow",
                            "requestPrompt": hostile_values[9],
                        },
                        "evidence_bundle": {
                            "evidence_bundle_id": "bundle-safe",
                            "tool_arguments": hostile_values[10],
                        },
                    },
                },
            )
        )
        db.commit()

    response = client.get(
        f"/runtime-intelligence/action-trace/{action_id}",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["ai_action"]["action_id"] == action_id
    assert payload["ai_action"]["actor"] == {"user_id": "user-safe"}
    assert payload["ai_action"]["surface"] == {
        "surface_type": "mcp_gateway",
        "provider": "customer",
        "model": "safe-model",
    }
    assert payload["ai_action"]["action"] == {
        "action_type": "tool_execution",
        "tool_name": "lookup_customer",
        "parameter_hash": "safe-parameter-hash",
    }
    assert payload["ai_action"]["policy"] == {
        "decision": "allow",
        "control_mode": "inline_allowed",
    }
    assert payload["policy_snapshot"] == {"policy_snapshot_id": "policy-safe"}
    assert payload["decision_explanation"] == {
        "reason_code": "policy_allow",
        "control_mode": "inline_allowed",
    }
    assert payload["evidence_bundle"] == {"evidence_bundle_id": "bundle-safe"}
    for hostile_value in hostile_values:
        assert hostile_value not in response.text


@pytest.mark.parametrize(
    "malformation",
    [
        "attacker_schema",
        "partial_projection",
        "unexpected_action_field",
        "extra_actor_field",
        "object_authority_type",
        "object_declared_purpose",
        "object_delegation_chain",
        "object_delegation_member",
        "object_surface_provider",
        "numeric_surface_model",
        "object_target_resource",
        "numeric_data_destination",
        "string_persistent_side_effect",
        "raw_signature",
    ],
)
def test_action_trace_rejects_genuinely_signed_noncanonical_display_schema(
    trace_env,
    malformation: str,
) -> None:
    client, session_factory = trace_env
    tenant_id, headers = _register(client, f"signed-schema-{malformation}@example.com")
    action_id = f"action-signed-schema-{malformation}"
    chain_id = f"chain-signed-schema-{malformation}"
    canonical = _canonical_action(
        tenant_id=tenant_id,
        action_id=action_id,
        chain_id=chain_id,
    )
    if malformation == "attacker_schema":
        canonical["schema_name"] = "attacker.ai_action"
    elif malformation == "partial_projection":
        canonical.pop("surface")
    elif malformation == "unexpected_action_field":
        canonical["action"]["unexpected_field"] = "signed-but-not-canonical"
    elif malformation == "extra_actor_field":
        canonical["actor"]["unexpected_actor_field"] = "signed-but-not-canonical"
    elif malformation == "object_authority_type":
        canonical["authority"]["authority_type"] = {"forged": "delegated"}
    elif malformation == "object_declared_purpose":
        canonical["purpose"]["declared_purpose"] = {"forged": "customer_support"}
    elif malformation == "object_delegation_chain":
        canonical["actor"]["delegation_chain"] = {"forged": ["agent-1"]}
    elif malformation == "object_delegation_member":
        canonical["actor"]["delegation_chain"] = [{"forged": "agent-1"}]
    elif malformation == "object_surface_provider":
        canonical["surface"]["provider"] = {"forged": "customer"}
    elif malformation == "numeric_surface_model":
        canonical["surface"]["model"] = 42
    elif malformation == "object_target_resource":
        canonical["action"]["target_resource"] = {"forged": "customer-record"}
    elif malformation == "numeric_data_destination":
        canonical["action"]["data_destination"] = 42
    elif malformation == "string_persistent_side_effect":
        canonical["action"]["persistent_side_effect"] = "false"
    elif malformation == "raw_signature":
        canonical["actor"]["receipt_signature"] = (
            "signed-evidence-signature-must-not-be-returned"
        )

    with session_factory() as db:
        db.add(
            _runtime_event(
                tenant_id=tenant_id,
                action_id=action_id,
                chain_id=chain_id,
            )
        )
        decision = create_decision_receipt(
            db,
            tenant_id=tenant_id,
            canonical_action=canonical,
            decision="allow",
            control_mode="inline_allowed",
            collector_id="runtime-trace-test",
            settings_obj=settings,
        )
        assert decision is not None
        db.commit()

    response = client.get(
        f"/runtime-intelligence/action-trace/{action_id}",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["decision_receipt"]["signature_verified"] is True
    assert payload["canonical_ai_action"] == {}
    assert payload["canonical_ai_action_status"] == "invalid"
    assert "signed-evidence-signature-must-not-be-returned" not in response.text


@pytest.mark.parametrize(
    "tamper",
    [
        "signature",
        "material",
        "approval",
        "approval_material",
        "approval_expiry",
        "expiry",
        "event_chain",
    ],
)
def test_action_trace_rejects_invalid_receipt_evidence_and_binding(
    trace_env,
    tamper: str,
) -> None:
    client, session_factory = trace_env
    tenant_id, headers = _register(client, f"invalid-receipt-{tamper}@example.com")
    action_id = f"action-invalid-{tamper}"
    chain_id = f"chain-invalid-{tamper}"
    now = datetime.now(timezone.utc)
    issued_at = now - timedelta(minutes=10) if tamper == "expiry" else now
    expires_at = now - timedelta(minutes=5) if tamper == "expiry" else now + timedelta(minutes=5)

    with session_factory() as db:
        event = _runtime_event(
            tenant_id=tenant_id,
            action_id=action_id,
            chain_id=chain_id,
            metadata={
                "canonical_ai_action_v1": {
                    "actor": {"identity_id": "forged-fallback-must-not-appear"}
                }
            },
        )
        db.add(event)
        decision, _, _, binding, _ = _create_signed_proof(
            db,
            tenant_id=tenant_id,
            action_id=action_id,
            chain_id=chain_id,
            with_approval=tamper in {"approval", "approval_material", "approval_expiry"},
            issued_at=issued_at,
            expires_at=expires_at,
            with_execution=False,
        )
        if tamper == "signature":
            decision.signature = "forged-decision-signature-must-not-leak"
        elif tamper == "material":
            evidence = db.get(EvidenceNode, decision.canonical_action_evidence_node_id)
            altered = deepcopy(dict(evidence.payload or {}))
            altered["canonical_action"]["action"]["parameter_hash"] = "forged-parameter-hash"
            evidence.payload = altered
        elif tamper == "approval":
            assert binding is not None
            binding.status = "invalidated"
            binding.invalidation_reason = "test-forged-approval"
        elif tamper == "approval_material":
            assert binding is not None
            binding.material_fields = {
                **dict(binding.material_fields or {}),
                "arguments_hash": "forged-approval-material",
            }
        elif tamper == "approval_expiry":
            assert binding is not None
            binding.expires_at = now - timedelta(seconds=1)
        elif tamper == "event_chain":
            event.chain_id = "different-event-chain"
        db.commit()

    response = client.get(
        f"/runtime-intelligence/action-trace/{action_id}",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["canonical_ai_action_status"] == "invalid"
    assert payload["canonical_ai_action"] == {}
    assert payload["decision_receipt"]["signature_present"] is True
    assert payload["decision_receipt"]["signature_verified"] is (tamper == "event_chain")
    assert "forged-fallback-must-not-appear" not in response.text
    assert "forged-decision-signature-must-not-leak" not in response.text
    assert "approval-signature-must-not-be-returned" not in response.text


@pytest.mark.parametrize(
    ("section", "field", "invalid_value"),
    [
        ("authority", "verified", "true"),
        ("action", "persistent_side_effect", "false"),
        ("purpose", "purpose_confidence", "0.98"),
        ("purpose", "purpose_confidence", float("nan")),
    ],
)
def test_action_trace_rejects_signed_canonical_sentinel_type_drift(
    trace_env,
    section: str,
    field: str,
    invalid_value,
) -> None:
    client, session_factory = trace_env
    suffix = f"{section}-{field}-{type(invalid_value).__name__}"
    tenant_id, headers = _register(client, f"sentinel-{suffix}@example.com")
    action_id = f"action-sentinel-{suffix}"
    chain_id = f"chain-sentinel-{suffix}"
    canonical = _canonical_action(
        tenant_id=tenant_id,
        action_id=action_id,
        chain_id=chain_id,
    )
    canonical[section][field] = invalid_value

    with session_factory() as db:
        db.add(
            _runtime_event(
                tenant_id=tenant_id,
                action_id=action_id,
                chain_id=chain_id,
            )
        )
        decision = create_decision_receipt(
            db,
            tenant_id=tenant_id,
            canonical_action=canonical,
            decision="allow",
            control_mode="inline_allowed",
            collector_id="runtime-trace-test",
            settings_obj=settings,
        )
        assert decision is not None
        db.commit()

    response = client.get(
        f"/runtime-intelligence/action-trace/{action_id}",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["decision_receipt"]["signature_verified"] is True
    assert payload["canonical_ai_action"] == {}
    assert payload["canonical_ai_action_status"] == "invalid"


def test_action_trace_reports_execution_and_integrity_verification_independently(
    trace_env,
) -> None:
    client, session_factory = trace_env
    tenant_id, headers = _register(client, "execution-tamper-trace@example.com")
    action_id = "action-execution-tamper"
    chain_id = "chain-execution-tamper"

    with session_factory() as db:
        db.add(
            _runtime_event(
                tenant_id=tenant_id,
                action_id=action_id,
                chain_id=chain_id,
            )
        )
        decision, execution, integrity, _, _ = _create_signed_proof(
            db,
            tenant_id=tenant_id,
            action_id=action_id,
            chain_id=chain_id,
        )
        decision_id = decision.receipt_id
        execution.signature = "forged-execution-signature-must-not-leak"
        integrity.signature = "forged-integrity-signature-must-not-leak"
        db.commit()

    response = client.get(
        f"/runtime-intelligence/action-trace/{action_id}",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["canonical_ai_action_status"] == "verified"
    assert payload["decision_receipt"]["receipt_id"] == decision_id
    assert payload["decision_receipt"]["signature_verified"] is True
    assert payload["execution_receipt"]["signature_present"] is True
    assert payload["execution_receipt"]["signature_verified"] is False
    assert payload["execution_integrity"]["signature_present"] is True
    assert payload["execution_integrity"]["signature_verified"] is False
    assert "forged-execution-signature-must-not-leak" not in response.text
    assert "forged-integrity-signature-must-not-leak" not in response.text


@pytest.mark.parametrize("later_result", ["execution_unknown", "incomplete"])
def test_action_trace_does_not_splice_integrity_from_another_execution_attempt(
    trace_env,
    later_result: str,
) -> None:
    client, session_factory = trace_env
    tenant_id, headers = _register(
        client,
        f"execution-attempt-binding-{later_result}@example.com",
    )
    action_id = f"action-attempt-binding-{later_result}"
    chain_id = f"chain-attempt-binding-{later_result}"
    issued_at = datetime.now(timezone.utc)

    with session_factory() as db:
        db.add(
            _runtime_event(
                tenant_id=tenant_id,
                action_id=action_id,
                chain_id=chain_id,
            )
        )
        decision, execution, matching_integrity, _, _ = _create_signed_proof(
            db,
            tenant_id=tenant_id,
            action_id=action_id,
            chain_id=chain_id,
            issued_at=issued_at,
        )
        assert execution is not None
        assert matching_integrity is not None
        recorder = (
            record_execution_unknown
            if later_result == "execution_unknown"
            else record_execution_incomplete
        )
        other_attempt_integrity = recorder(
            db,
            tenant_id=tenant_id,
            decision_receipt_id=decision.receipt_id,
            settings_obj=settings,
            evaluated_at=issued_at + timedelta(seconds=2),
            execution_attempt_id=f"other-attempt-{later_result}",
        )
        execution_id = execution.receipt_id
        matching_integrity_id = matching_integrity.result_id
        other_integrity_id = other_attempt_integrity.result_id
        db.commit()

    response = client.get(
        f"/runtime-intelligence/action-trace/{action_id}",
        headers=headers,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["execution_receipt"]["receipt_id"] == execution_id
    assert payload["execution_receipt"]["signature_verified"] is True
    assert payload["execution_integrity"]["result_id"] == matching_integrity_id
    assert payload["execution_integrity"]["result_id"] != other_integrity_id
    assert payload["execution_integrity"]["execution_receipt_id"] == execution_id
    assert payload["execution_integrity"]["signature_verified"] is True
