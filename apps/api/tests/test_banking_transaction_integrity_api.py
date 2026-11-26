from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import json
import os
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
import jwt
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.core.config import settings
from app.db.models.banking_transaction import BankingExecutionGrant
from app.db.models.evidence import DecisionReceipt, ExecutionIntegrityResult, ExecutionReceipt
from app.db.session import Base, get_db
from app.main import app


PASSWORD = "Password123!"
ISSUER = "https://bank.example/auth"
AUDIENCE = "hawk-bank-foundry"
KEY_ID = "bank-key-1"
PSEUDONYMIZATION_KEY = "bank-pseudonymization-key-material-00000001"
RECEIPT_KEY = "bank-receipt-signing-key-material-000000000001"


@pytest.fixture()
def bank_api_env(tmp_path, monkeypatch):
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'banking-transaction.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = session_local()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(settings, "banking_transaction_integrity_enabled", True)
    monkeypatch.setattr(
        settings,
        "banking_subject_trust_json",
        json.dumps(
            {
                ISSUER: {
                    "audience": AUDIENCE,
                    "keys": {KEY_ID: public_pem},
                }
            }
        ),
    )
    monkeypatch.setattr(
        settings,
        "banking_subject_pseudonymization_key",
        PSEUDONYMIZATION_KEY,
    )
    monkeypatch.setattr(
        settings,
        "banking_transaction_policy_profile_json",
        json.dumps(
            {
                "base_decision": "allow",
                "dependencies_healthy": True,
                "degraded_behavior": "block",
                "matched_rules": ["BANK_OWN_ACCOUNT_READ"],
                "policy_snapshot_id": "bank-policy-v1",
                "approved_ai_system_ids": ["foundry-bank-agent"],
                "approved_tools": {
                    "get_account_summary": {
                        "version": "1.0.0",
                        "schema_fingerprint": "a" * 64,
                        "target_binding": {
                            "account_argument": "account_id",
                            "resource": "bank.customer/current/summary",
                            "resource_type": "account",
                            "operation": "read_summary",
                            "customer_source": "signed_subject",
                        },
                    }
                },
                "approved_destinations": ["bank-core.internal"],
                "approved_workload_identities": ["foundry-managed-identity"],
                "approved_workload_identity_types": ["project_managed_identity"],
                "approved_workload_authentication_modes": ["managed_identity"],
                "approved_operation_types": ["read_summary"],
                "approved_models": {
                    "bank-chat": {
                        "provider": "azure_openai",
                        "deployment": "bank-gpt-4-1",
                        "model": "gpt-4.1",
                    }
                },
                "approved_model_destinations": ["bank-foundry.internal"],
                "allowed_model_request_classifications": ["confidential"],
                "blocked_model_response_classifications": ["restricted"],
                "allow_buffered_streaming": False,
                "response_assurance": {
                    "allowed_response_fields": [
                        "currency",
                        "total_amount",
                        "transaction_count",
                    ],
                    "mismatch_action": "safe_fallback",
                    "excess_field_action": "redact",
                    "max_regenerations": 1,
                },
                "allowed_purpose_ids": ["own-account-summary"],
            }
        ),
    )
    monkeypatch.setattr(settings, "decision_execution_receipts_enabled", True)
    monkeypatch.setattr(settings, "banking_evidence_attestation_keys_json", "{}")
    monkeypatch.setattr(settings, "receipt_signing_active_key_id", "bank-receipt-key")
    monkeypatch.setattr(
        settings,
        "receipt_signing_keys_json",
        json.dumps({"bank-receipt-key": RECEIPT_KEY}),
    )
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    register = client.post(
        "/auth/register",
        json={
            "email": f"bank-owner-{uuid4().hex[:8]}@example.com",
            "password": PASSWORD,
            "full_name": "Bank Owner",
        },
    )
    assert register.status_code == 200, register.text
    auth = register.json()
    headers = {
        "Authorization": f"Bearer {auth['access_token']}",
        "X-Tenant-ID": auth["tenants"][0]["id"],
    }

    def issue_assertion(*, nonce: str) -> str:
        now = datetime.now(timezone.utc)
        claims = {
            "tenant_id": auth["tenants"][0]["id"],
            "subject_type": "customer",
            "customer_subject_id": "customer-001",
            "authenticated_principal_id": "principal-001",
            "mobile_session_id": "mobile-session-001",
            "channel": "mobile_banking",
            "approved_account_ids": ["acct-001"],
            "approved_resource_scope": ["bank.customer/current/summary"],
            "approved_resource_scopes": [
                {
                    "resource_type": "account",
                    "resource_reference": "acct-001",
                    "relationship_to_subject": "owner",
                    "allowed_operations": ["read_summary"],
                    "expires_at": (now + timedelta(minutes=5)).isoformat(),
                    "source_of_authority": "bank_api_gateway",
                }
            ],
            "device_trust_reference": "device-trust-001",
            "purpose_id": "own-account-summary",
            "authority_scope": ["account.read_summary"],
            "auth_time": int((now - timedelta(minutes=1)).timestamp()),
            "provenance": "bank_api_gateway",
            "trust_level": "hardware_bound_session",
            "source_system": "bank-mobile-api",
            "policy_version": "bank-policy-v2",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "kid": KEY_ID,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "nonce": nonce,
        }
        return jwt.encode(claims, private_pem, algorithm="ES256", headers={"kid": KEY_ID})

    action_counter = 0

    def action(
        *,
        account_id: str,
        argument_account_id: str | None = None,
        requested_resource: str = "bank.customer/current/summary",
    ) -> dict:
        nonlocal action_counter
        action_counter += 1
        suffix = f"{action_counter:04d}"
        return {
            "subject_assertion": issue_assertion(nonce=f"banking-nonce-{suffix}"),
            "ai_transaction_id": f"txn-{suffix}",
            "action_id": f"action-{suffix}",
            "chain_id": f"chain-{suffix}",
            "ai_system_id": "foundry-bank-agent",
            "source_agent_id": "bank-summary-agent",
            "delegated_agent_ids": [],
            "action_type": "tool_execution",
            "operation_type": "read_summary",
            "tool_name": "get_account_summary",
            "tool_version": "1.0.0",
            "tool_schema_fingerprint": "a" * 64,
            "arguments": {
                "account_id": argument_account_id or account_id,
                "view": "summary",
            },
            "requested_customer_subject_id": "customer-001",
            "requested_account_id": account_id,
            "requested_resource": requested_resource,
            "destination": "bank-core.internal",
            "workload_identity": "foundry-managed-identity",
            "workload_identity_type": "project_managed_identity",
            "workload_authentication_mode": "managed_identity",
            "workload_identity_source": "microsoft_entra",
            "workload_identity_provenance": "verified_entra_claims",
            "side_effect_class": "read_only",
            "policy_snapshot_id": "bank-policy-v1",
        }

    def model_request(
        *,
        destination: str = "bank-foundry.internal",
        streaming: bool = False,
        request_classification: str = "confidential",
    ) -> dict:
        nonlocal action_counter
        action_counter += 1
        suffix = f"{action_counter:04d}"
        return {
            "subject_assertion": issue_assertion(nonce=f"model-nonce-{suffix}"),
            "ai_transaction_id": f"model-txn-{suffix}",
            "action_id": f"model-action-{suffix}",
            "run_id": f"model-run-{suffix}",
            "chain_id": f"model-chain-{suffix}",
            "ai_system_id": "foundry-bank-agent",
            "source_agent_id": "bank-summary-agent",
            "delegated_agent_ids": [],
            "provider": "azure_openai",
            "deployment": "bank-gpt-4-1",
            "model": "gpt-4.1",
            "request_classification": request_classification,
            "session_id": f"model-session-{suffix}",
            "streaming": streaming,
            "destination": destination,
            "request_hash": "b" * 64,
            "workload_identity": "foundry-managed-identity",
            "workload_identity_type": "project_managed_identity",
            "workload_authentication_mode": "managed_identity",
            "workload_identity_source": "microsoft_entra",
            "workload_identity_provenance": "verified_entra_claims",
            "policy_snapshot_id": "bank-policy-v1",
        }

    try:
        yield {
            "client": client,
            "headers": headers,
            "action": action,
            "model_request": model_request,
            "SessionLocal": session_local,
        }
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_model_request_allow_is_receipt_bound_and_contains_no_raw_prompt(
    bank_api_env,
) -> None:
    payload = bank_api_env["model_request"]()
    response = bank_api_env["client"].post(
        "/runtime-control/banking-models/authorize",
        headers=bank_api_env["headers"],
        json=payload,
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "allow"
    assert body["control_mode"] == "inline_allowed"
    assert body["decision_receipt_id"]
    assert body["model_binding_verified"] is True
    assert body["streaming_covered"] is False
    assert payload["subject_assertion"] not in response.text
    assert "show my balance" not in response.text.lower()

    transaction = bank_api_env["client"].get(
        f"/runtime-control/banking-transactions/{payload['ai_transaction_id']}",
        headers=bank_api_env["headers"],
    )
    assert transaction.status_code == 200, transaction.text
    projection = transaction.json()
    assert projection["coverage"]["model"]["status"] == "covered"
    assert projection["coverage"]["function"]["status"] == "unknown"
    assert "runtime_control:function" not in projection["selected_controls"]
    assert "model_request_control" in projection["selected_controls"]
    assert "model_request" in [event["stage"] for event in projection["timeline"]]


def test_banking_authorization_records_tenant_scoped_operational_metrics(
    bank_api_env,
) -> None:
    from app.core.observability import banking_runtime_metrics

    tenant_id = bank_api_env["headers"]["X-Tenant-ID"]
    banking_runtime_metrics.reset(tenant_id)
    response = bank_api_env["client"].post(
        "/runtime-control/banking-actions/authorize",
        headers=bank_api_env["headers"],
        json=bank_api_env["action"](account_id="acct-001"),
    )

    assert response.status_code == 200, response.text
    snapshot = banking_runtime_metrics.snapshot(tenant_id)
    assert snapshot["event_counts"]["actions"] == 1
    assert snapshot["event_counts"]["decisions"] == 1
    assert snapshot["event_counts"]["blocked"] == 0
    assert snapshot["latency"][
        "/runtime-control/banking-actions/authorize"
    ]["count"] == 1
    assert snapshot["transport_latency"]["function"]["count"] == 1

    metrics_response = bank_api_env["client"].get(
        "/ops/metrics",
        headers=bank_api_env["headers"],
    )
    assert metrics_response.status_code == 200, metrics_response.text
    runtime_metrics = metrics_response.json()["banking_runtime"]
    assert runtime_metrics["event_counts"]["actions"] == 1
    assert runtime_metrics["event_counts"]["decisions"] == 1
    assert runtime_metrics["latency"][
        "/runtime-control/banking-actions/authorize"
    ]["count"] == 1
    assert runtime_metrics["transport_latency"]["function"]["count"] == 1


@pytest.mark.parametrize(
    ("mutation", "expected_reason"),
    (
        ({"destination": "public-model.example"}, "bank_model_binding_mismatch"),
        ({"streaming": True}, "bank_streaming_not_covered"),
        ({"request_classification": "restricted"}, "bank_model_binding_mismatch"),
    ),
)
def test_model_request_unapproved_material_blocks_before_provider(
    bank_api_env,
    mutation: dict,
    expected_reason: str,
) -> None:
    payload = bank_api_env["model_request"]()
    payload.update(mutation)
    response = bank_api_env["client"].post(
        "/runtime-control/banking-models/authorize",
        headers=bank_api_env["headers"],
        json=payload,
    )

    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "block"
    assert response.json()["reason_code"] == expected_reason
    assert response.json()["control_mode"] == "inline_prevented"


def test_model_response_classification_is_correlated_and_fail_closed(
    bank_api_env,
) -> None:
    request_payload = bank_api_env["model_request"]()
    authorization = bank_api_env["client"].post(
        "/runtime-control/banking-models/authorize",
        headers=bank_api_env["headers"],
        json=request_payload,
    )
    assert authorization.status_code == 200, authorization.text
    receipt_id = authorization.json()["decision_receipt_id"]

    blocked = bank_api_env["client"].post(
        "/runtime-control/banking-models/response",
        headers=bank_api_env["headers"],
        json={
            "decision_receipt_id": receipt_id,
            "ai_transaction_id": request_payload["ai_transaction_id"],
            "action_id": request_payload["action_id"],
            "chain_id": request_payload["chain_id"],
            "response_hash": "c" * 64,
            "response_classification": "restricted",
            "streaming": False,
            "finish_reason": "stop",
        },
    )

    assert blocked.status_code == 200, blocked.text
    assert blocked.json() == {
        "decision": "block",
        "reason_code": "bank_model_response_classification_blocked",
        "control_mode": "inline_prevented",
        "safe_response": None,
        "evidence_complete": True,
        "decision_receipt_id": receipt_id,
    }


def test_cross_customer_api_returns_block_and_cannot_report_success(bank_api_env) -> None:
    blocked = bank_api_env["client"].post(
        "/runtime-control/banking-actions/authorize",
        headers=bank_api_env["headers"],
        json=bank_api_env["action"](account_id="acct-999"),
    )
    assert blocked.status_code == 200, blocked.text
    body = blocked.json()
    assert body["decision"] == "block"
    assert body["reason_code"] == "bank_customer_scope_mismatch"
    assert body["control_mode"] == "inline_prevented"

    execution = bank_api_env["client"].post(
        "/runtime-control/banking-actions/execution",
        headers=bank_api_env["headers"],
        json={
            "decision_receipt_id": body["decision_receipt_id"],
            "execution_grant_id": str(uuid4()),
            "execution_attempt_id": "attempt-blocked",
            "execution_status": "success",
        },
    )
    assert execution.status_code == 422
    assert "execution grant" in execution.json()["detail"]

    with bank_api_env["SessionLocal"]() as db:
        assert db.scalar(select(func.count(DecisionReceipt.receipt_id))) == 1
        assert db.scalar(select(func.count(ExecutionReceipt.receipt_id))) == 0


def test_declared_target_cannot_hide_cross_customer_executable_argument(
    bank_api_env,
) -> None:
    payload = bank_api_env["action"](
        account_id="acct-001",
        argument_account_id="acct-999",
    )

    response = bank_api_env["client"].post(
        "/runtime-control/banking-actions/authorize",
        headers=bank_api_env["headers"],
        json=payload,
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    assert body["reason_code"] == "bank_executable_target_mismatch"
    assert body["control_mode"] == "inline_prevented"


def test_allow_final_gate_and_execution_create_matched_receipts(bank_api_env) -> None:
    payload = bank_api_env["action"](account_id="acct-001")
    allowed = bank_api_env["client"].post(
        "/runtime-control/banking-actions/authorize",
        headers=bank_api_env["headers"],
        json=payload,
    )
    assert allowed.status_code == 200, allowed.text
    body = allowed.json()
    assert body["decision"] == "allow"
    assert body["control_mode"] == "inline_allowed"
    assert body["subject"]["customer_subject_hash"].startswith("hmac-sha256:")
    assert body["subject"]["authenticated_principal_hash"].startswith("hmac-sha256:")
    assert body["subject"]["identity_provenance"] == "bank_api_gateway"
    assert body["canonical_action"]["authority"]["workload_identity_quality"] == (
        "project_shared_identity"
    )
    assert body["canonical_action"]["authority"]["shared_authority"] is True
    assert "customer-001" not in allowed.text
    assert "principal-001" not in allowed.text

    gate = bank_api_env["client"].post(
        "/runtime-control/banking-actions/pre-execution",
        headers=bank_api_env["headers"],
        json={
            "decision_receipt_id": body["decision_receipt_id"],
            "execution_attempt_id": "attempt-allow",
            "final_action": payload,
        },
    )
    assert gate.status_code == 200, gate.text
    gate_body = gate.json()
    assert gate_body["executable"] is True
    assert gate_body["integrity_result_id"] is None
    assert gate_body["execution_grant_id"]
    assert gate_body["grant_expires_at"]

    execution = bank_api_env["client"].post(
        "/runtime-control/banking-actions/execution",
        headers=bank_api_env["headers"],
        json={
            "decision_receipt_id": body["decision_receipt_id"],
            "execution_grant_id": gate_body["execution_grant_id"],
            "execution_attempt_id": "attempt-allow",
            "execution_status": "success",
        },
    )
    assert execution.status_code == 200, execution.text
    assert execution.json()["integrity"] == "matched"

    with bank_api_env["SessionLocal"]() as db:
        assert db.scalar(select(func.count(DecisionReceipt.receipt_id))) == 1
        assert db.scalar(select(func.count(ExecutionReceipt.receipt_id))) == 1
        assert db.scalar(select(func.count(ExecutionIntegrityResult.result_id))) == 1
        assert db.scalar(select(func.count(BankingExecutionGrant.id))) == 1

    retry = bank_api_env["client"].post(
        "/runtime-control/banking-actions/execution",
        headers=bank_api_env["headers"],
        json={
            "decision_receipt_id": body["decision_receipt_id"],
            "execution_grant_id": gate_body["execution_grant_id"],
            "execution_attempt_id": "attempt-allow",
            "execution_status": "success",
        },
    )
    assert retry.status_code == 200, retry.text
    assert retry.json()["execution_receipt_id"] == execution.json()["execution_receipt_id"]

    conflicting_retry = bank_api_env["client"].post(
        "/runtime-control/banking-actions/execution",
        headers=bank_api_env["headers"],
        json={
            "decision_receipt_id": body["decision_receipt_id"],
            "execution_grant_id": gate_body["execution_grant_id"],
            "execution_attempt_id": "attempt-allow",
            "execution_status": "failure",
        },
    )
    assert conflicting_retry.status_code == 422


def test_final_gate_rejects_account_mutation_and_records_drift(bank_api_env) -> None:
    payload = bank_api_env["action"](account_id="acct-001")
    allowed = bank_api_env["client"].post(
        "/runtime-control/banking-actions/authorize",
        headers=bank_api_env["headers"],
        json=payload,
    )
    assert allowed.status_code == 200, allowed.text
    body = allowed.json()
    mutated = copy.deepcopy(payload)
    mutated["arguments"]["account_id"] = "acct-999"

    response = bank_api_env["client"].post(
        "/runtime-control/banking-actions/pre-execution",
        headers=bank_api_env["headers"],
        json={
            "decision_receipt_id": body["decision_receipt_id"],
            "execution_attempt_id": "attempt-mutated",
            "final_action": mutated,
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["executable"] is False
    assert response.json()["integrity_result_id"]
    assert response.json()["execution_grant_id"] is None


def test_execution_without_successful_final_gate_is_rejected(bank_api_env) -> None:
    allowed = bank_api_env["client"].post(
        "/runtime-control/banking-actions/authorize",
        headers=bank_api_env["headers"],
        json=bank_api_env["action"](account_id="acct-001"),
    )
    assert allowed.status_code == 200, allowed.text

    response = bank_api_env["client"].post(
        "/runtime-control/banking-actions/execution",
        headers=bank_api_env["headers"],
        json={
            "decision_receipt_id": allowed.json()["decision_receipt_id"],
            "execution_grant_id": str(uuid4()),
            "execution_attempt_id": "attempt-without-gate",
            "execution_status": "success",
        },
    )

    assert response.status_code == 422
    assert "execution grant" in response.json()["detail"]


def test_invalid_subject_assertion_is_never_reflected_in_validation_error(
    bank_api_env,
) -> None:
    payload = bank_api_env["action"](account_id="acct-001")
    raw_secret = "raw-secret-token"
    payload["subject_assertion"] = raw_secret

    response = bank_api_env["client"].post(
        "/runtime-control/banking-actions/authorize",
        headers=bank_api_env["headers"],
        json=payload,
    )

    assert response.status_code == 422
    assert raw_secret not in response.text
    assert all("input" not in detail for detail in response.json()["detail"])


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("tool_schema_fingerprint", "b" * 64),
        ("policy_snapshot_id", "attacker-policy"),
        ("ai_system_id", "unregistered-agent"),
        ("destination", "unknown-bank-route.internal"),
        ("workload_identity", "unregistered-managed-identity"),
    ),
)
def test_unregistered_runtime_material_is_receipt_bound_and_blocked(
    bank_api_env,
    field: str,
    value: str,
) -> None:
    payload = bank_api_env["action"](account_id="acct-001")
    payload[field] = value

    response = bank_api_env["client"].post(
        "/runtime-control/banking-actions/authorize",
        headers=bank_api_env["headers"],
        json=payload,
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    assert body["reason_code"] == "bank_runtime_binding_mismatch"
    assert body["control_mode"] == "inline_prevented"
    assert body["decision_receipt_id"]


def test_function_transport_is_bound_into_existing_receipt_and_final_gate(
    bank_api_env,
) -> None:
    payload = bank_api_env["action"](account_id="acct-001")
    payload["transport_binding"] = {
        "transport": "function",
        "route_id": "foundry:function:get_account_summary",
        "authentication_mode": "managed_identity",
        "direct_bypass": False,
        "function_manifest_id": "function:get_account_summary:1.0.0",
    }
    allowed = bank_api_env["client"].post(
        "/runtime-control/banking-actions/authorize",
        headers=bank_api_env["headers"],
        json=payload,
    )

    assert allowed.status_code == 200, allowed.text
    body = allowed.json()
    assert body["decision"] == "allow"
    assert body["canonical_action"]["surface"]["surface_type"] == "runtime_control"
    assert body["canonical_action"]["surface"]["transport"] == "function"
    assert len(body["canonical_action"]["action"]["tool_fingerprint_id"]) == 64
    assert "acct-001" not in allowed.text

    mutated = copy.deepcopy(payload)
    mutated["transport_binding"]["route_id"] = "bypass:function:get_account_summary"
    gate = bank_api_env["client"].post(
        "/runtime-control/banking-actions/pre-execution",
        headers=bank_api_env["headers"],
        json={
            "decision_receipt_id": body["decision_receipt_id"],
            "execution_attempt_id": "attempt-transport-drift",
            "final_action": mutated,
        },
    )

    assert gate.status_code == 200, gate.text
    assert gate.json()["executable"] is False


def test_direct_transport_bypass_is_evidence_backed_and_blocked(bank_api_env) -> None:
    payload = bank_api_env["action"](account_id="acct-001")
    payload["transport_binding"] = {
        "transport": "rest",
        "route_id": "direct:bank-core",
        "authentication_mode": "managed_identity",
        "direct_bypass": True,
        "http_method": "POST",
        "route_template": "/customers/{customer}/accounts/{account}/summary",
    }

    response = bank_api_env["client"].post(
        "/runtime-control/banking-actions/authorize",
        headers=bank_api_env["headers"],
        json=payload,
    )

    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "block"
    assert response.json()["reason_code"] == "bank_transport_binding_unverified"
    assert response.json()["control_mode"] == "inline_prevented"


def test_structured_response_endpoint_requires_matched_execution_and_server_policy(
    bank_api_env,
) -> None:
    from app.services.banking_response_assurance_service import (
        compute_banking_result_digest,
    )

    action = bank_api_env["action"](account_id="acct-001")
    allowed = bank_api_env["client"].post(
        "/runtime-control/banking-actions/authorize",
        headers=bank_api_env["headers"],
        json=action,
    )
    assert allowed.status_code == 200, allowed.text
    gate = bank_api_env["client"].post(
        "/runtime-control/banking-actions/pre-execution",
        headers=bank_api_env["headers"],
        json={
            "decision_receipt_id": allowed.json()["decision_receipt_id"],
            "execution_attempt_id": "response-assurance-attempt",
            "final_action": action,
        },
    )
    assert gate.status_code == 200, gate.text
    execution = bank_api_env["client"].post(
        "/runtime-control/banking-actions/execution",
        headers=bank_api_env["headers"],
        json={
            "decision_receipt_id": allowed.json()["decision_receipt_id"],
            "execution_grant_id": gate.json()["execution_grant_id"],
            "execution_attempt_id": "response-assurance-attempt",
            "execution_status": "success",
        },
    )
    assert execution.status_code == 200, execution.text

    claims = {
        "currency": "AED",
        "total_amount": "327.50",
        "transaction_count": 11,
    }
    trusted = {
        "ai_transaction_id": action["ai_transaction_id"],
        "action_id": action["action_id"],
        "customer_fingerprint": allowed.json()["subject"]["customer_subject_hash"],
        "account_fingerprint": allowed.json()["subject"]["approved_account_hashes"][0],
        "tool_fingerprint": allowed.json()["canonical_action"]["action"]["tool_fingerprint_id"],
        "result_schema": "bank.account_summary",
        "result_version": "1.0.0",
        "approved_fields": list(claims),
        "field_classifications": {field: "confidential" for field in claims},
        "claims": claims,
        "execution_status": "success",
    }
    trusted["result_digest"] = compute_banking_result_digest(trusted)
    response = bank_api_env["client"].post(
        "/runtime-control/banking-responses/assure",
        headers=bank_api_env["headers"],
        json={
            "decision_receipt_id": allowed.json()["decision_receipt_id"],
            "authorized_customer_fingerprint": trusted["customer_fingerprint"],
            "authorized_account_fingerprint": trusted["account_fingerprint"],
            "trusted_result": trusted,
            "candidate_claims": claims,
            "regeneration_attempt": 0,
            "evidence_source": {
                "claimed_grade": "provider_reported",
                "source_id": "foundry-function-result",
            },
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["decision"] == "allow"
    assert response.json()["evidence_grade"] == "provider_reported"
    assert response.json()["evidence_node_id"]
    assert "327.50" not in json.dumps(response.json()["evidence"])

    injected_policy = copy.deepcopy(response.request.content)
    assert b'"policy"' not in injected_policy

    transaction = bank_api_env["client"].get(
        f"/runtime-control/banking-transactions/{action['ai_transaction_id']}",
        headers=bank_api_env["headers"],
    )
    assert transaction.status_code == 200, transaction.text
    projection = transaction.json()
    assert projection["ai_transaction_id"] == action["ai_transaction_id"]
    assert projection["decision_receipt_ids"] == [allowed.json()["decision_receipt_id"]]
    assert projection["execution_receipt_ids"] == [execution.json()["execution_receipt_id"]]
    assert projection["integrity_status"] == "matched"
    assert [event["stage"] for event in projection["timeline"]] == [
        "authenticated",
        "action_proposed",
        "hawk_decision",
        "execution",
        "verification",
        "response_assurance",
        "customer_response",
    ]
    assert projection["coverage"]["subject"]["status"] == "covered"
    assert projection["coverage"]["execution_verification"]["status"] == "covered"
    assert projection["coverage"]["mcp"]["status"] == "not_applicable"
    assert projection["coverage"]["direct_api"]["status"] == "not_applicable"
    assert projection["tool_reference"] == "get_account_summary"
    assert projection["policy_version"] == "bank-policy-v1"
    assert projection["control_point_reference"] == "unknown"
    assert projection["side_effect_class"] == "read_only"
    assert "customer-001" not in transaction.text
    assert "acct-001" not in transaction.text
    assert "327.50" not in transaction.text

    ciso = bank_api_env["client"].get(
        "/runtime-control/banking-transactions/summary/ciso",
        headers=bank_api_env["headers"],
    )
    assert ciso.status_code == 200, ciso.text
    summary = ciso.json()
    assert summary["observed_transaction_count"] == 1
    assert summary["customer_facing_agents"] == ["bank-summary-agent"]
    assert summary["tool_references"] == ["get_account_summary"]
    assert summary["subject_boundary_status"] == "evidence_backed"
    assert summary["inline_blockable_count"] == 1
    assert summary["execution_verified_count"] == 1
    assert summary["consequential_transaction_count"] == 0
    assert summary["consequential_execution_verified_percent"] is None
    assert summary["recent_transactions"][0]["ai_transaction_id"] == action[
        "ai_transaction_id"
    ]
    assert "customer-001" not in ciso.text
    assert "acct-001" not in ciso.text
