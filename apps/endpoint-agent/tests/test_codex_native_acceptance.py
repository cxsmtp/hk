import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from hawk_endpoint_agent.native_control.codex_acceptance import (
    CodexAcceptanceReport,
    _canonical,
    _prompt_was_blocked_by_codex,
    _verify_callback,
)


def _report(**changes: object) -> CodexAcceptanceReport:
    values: dict[str, object] = {
        "binary": "/usr/local/bin/codex",
        "binary_sha256": "a" * 64,
        "expected_binary_sha256": "a" * 64,
        "version": "0.154.0",
        "expected_version": "0.154.0",
        "version_command_succeeded": True,
        "adapter_version": "1.0.0",
        "platform": "macos-arm64",
        "evidence_timestamp": "2026-10-05T19:00:00+00:00",
        "tested_events": ("session_start", "before_model"),
        "hardware_key_provider": "macos_secure_enclave",
        "key_thumbprint": "b" * 64,
        "hardware_backed_key": True,
        "hook_installation_observed": True,
        "allow_callback_observed": True,
        "allow_signature_verified": True,
        "prompt_hook_observed": True,
        "block_signature_verified": True,
        "prompt_blocked_before_model": True,
        "raw_prompt_exported": False,
        "isolated_hook_trust_bypass": True,
        "model_transport_isolated": True,
        "model_request_observed": False,
        "measured_callback_p95_ms": 8.5,
        "total_acceptance_runtime_ms": 12.5,
        "return_code": 1,
        "diagnostic": "passed",
    }
    values.update(changes)
    return CodexAcceptanceReport(**values)  # type: ignore[arg-type]


def test_codex_acceptance_requires_an_explicit_current_version() -> None:
    assert _report().passed is True
    assert _report(version="0.137.0").passed is False
    assert _report(expected_version="0.155.0").passed is False
    assert _report(binary_sha256="c" * 64).passed is False
    assert _report(hardware_backed_key=False).passed is False
    assert _report(allow_signature_verified=False).passed is False
    assert _report(model_request_observed=True).passed is False
    assert _report(model_transport_isolated=False).passed is False


def test_codex_acceptance_recognizes_the_real_user_prompt_block_signal() -> None:
    assert _prompt_was_blocked_by_codex("hook: UserPromptSubmit Blocked") is True
    assert _prompt_was_blocked_by_codex("hook: UserPromptSubmit Completed") is False


def test_codex_acceptance_artifact_never_claims_tenant_or_live_backend_acceptance() -> None:
    artifact = _report().as_evidence_artifact()

    assert artifact["classification"] == "real_binary_isolated_hardware_signed_callback_acceptance"
    assert artifact["scope"]["provider_adapter_contract_verified"] is True
    assert artifact["scope"]["tenant_deployment_accepted"] is False
    assert artifact["scope"]["live_backend_signature_verified"] is False
    assert artifact["scope"]["synthetic_fixture"] is False
    assert artifact["result"]["tested_events"] == ["session_start", "before_model"]
    assert artifact["result"]["model_transport_isolated"] is True
    assert artifact["result"]["model_request_observed"] is False


def test_codex_acceptance_cryptographically_verifies_exact_callback_binding() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    payload = json.dumps({"prompt_hash": "p" * 64}, sort_keys=True).encode("utf-8")
    current = datetime.now(timezone.utc)
    envelope: dict[str, object] = {
        "event_id": "event-1",
        "integration_instance_id": "codex-native-acceptance",
        "tenant_binding": "codex-acceptance-tenant",
        "provider": "openai",
        "product": "codex",
        "provider_event_id": "provider-event-1",
        "provider_event_type": "before_model",
        "provider_version": "0.154.0",
        "adapter_version": "1.0.0",
        "issued_at": current.isoformat(),
        "expires_at": (current + timedelta(seconds=30)).isoformat(),
        "nonce": "nonce-1",
        "session_id": "session-1",
        "chain_id": "session-1",
        "correlation_id": "correlation-1",
        "payload_hash": hashlib.sha256(payload).hexdigest(),
        "canonical_action_hash": None,
        "credential_id": "codex-acceptance-credential",
        "credential_epoch": 1,
        "signature_algorithm": "ES256",
    }
    signature = private_key.sign(_canonical(envelope), ec.ECDSA(hashes.SHA256()))
    envelope["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    body = {
        "envelope_base64": base64.b64encode(_canonical(envelope)).decode("ascii"),
        "payload_base64": base64.b64encode(payload).decode("ascii"),
    }

    event, verified, latency_ms = _verify_callback(
        body,
        public_key_pem=public_key,
        expected_version="0.154.0",
    )
    assert event == "before_model"
    assert verified is True
    assert latency_ms >= 0

    envelope["provider_version"] = "0.155.0"
    tampered = {
        "envelope_base64": base64.b64encode(_canonical(envelope)).decode("ascii"),
        "payload_base64": body["payload_base64"],
    }
    assert _verify_callback(
        tampered,
        public_key_pem=public_key,
        expected_version="0.154.0",
    )[1] is False
