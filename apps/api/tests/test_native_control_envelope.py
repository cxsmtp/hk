from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from app.services.native_control.envelope import (
    InMemoryReplayStore,
    TrustedControlEnvelope,
    WorkloadCredential,
    canonical_envelope_body,
    parse_envelope_json,
    validate_trusted_envelope,
)


NOW = datetime(2026, 8, 11, 8, 0, tzinfo=timezone.utc)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _signed_envelope(**overrides: object) -> tuple[TrustedControlEnvelope, WorkloadCredential]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    credential = WorkloadCredential(
        credential_id="credential-1",
        credential_epoch=4,
        tenant_id="tenant-1",
        integration_instance_id="integration-1",
        provider="openai",
        product="codex",
        environment="production",
        allowed_event_types=("before_tool",),
        public_key_pem=public_pem,
        expires_at=NOW + timedelta(hours=1),
        revoked=False,
    )
    values: dict[str, object] = {
        "event_id": "event-12345678",
        "integration_instance_id": "integration-1",
        "tenant_binding": "tenant-1",
        "provider": "openai",
        "product": "codex",
        "provider_event_id": "provider-event-1",
        "provider_event_type": "before_tool",
        "provider_version": "1.5.0",
        "adapter_version": "1.0.0",
        "issued_at": NOW,
        "expires_at": NOW + timedelta(seconds=30),
        "nonce": "nonce-1234567890",
        "session_id": "session-1",
        "chain_id": "chain-1",
        "correlation_id": "correlation-1",
        "payload_hash": "a" * 64,
        "canonical_action_hash": "b" * 64,
        "credential_id": "credential-1",
        "credential_epoch": 4,
        "signature_algorithm": "ES256",
        "signature": "",
    }
    values.update(overrides)
    unsigned = TrustedControlEnvelope(**values)
    signature = private_key.sign(canonical_envelope_body(unsigned), ec.ECDSA(hashes.SHA256()))
    return TrustedControlEnvelope(**{**values, "signature": _b64url(signature)}), credential


def test_accepts_valid_integration_scoped_signed_envelope_once() -> None:
    envelope, credential = _signed_envelope()
    store = InMemoryReplayStore()

    result = validate_trusted_envelope(
        envelope,
        credential=credential,
        payload=b"test-payload",
        now=NOW,
        replay_store=store,
        payload_hash_override="a" * 64,
    )

    assert result.credential_id == "credential-1"
    assert result.tenant_id == "tenant-1"
    assert result.integration_instance_id == "integration-1"
    assert result.event_id == "event-12345678"

    with pytest.raises(ValueError, match="replay_detected"):
        validate_trusted_envelope(
            envelope,
            credential=credential,
            payload=b"test-payload",
            now=NOW,
            replay_store=store,
            payload_hash_override="a" * 64,
        )


@pytest.mark.parametrize(
    ("envelope_change", "credential_change", "code"),
    [
        ({"tenant_binding": "tenant-2"}, {}, "tenant_binding_mismatch"),
        ({"integration_instance_id": "integration-2"}, {}, "integration_binding_mismatch"),
        ({"credential_epoch": 3}, {}, "credential_epoch_mismatch"),
        ({"provider_event_type": "after_tool"}, {}, "event_type_not_allowed"),
        ({"issued_at": NOW + timedelta(minutes=3)}, {}, "issued_in_future"),
        ({"expires_at": NOW}, {}, "event_expired"),
        ({"expires_at": NOW - timedelta(seconds=1)}, {}, "event_expired"),
        ({}, {"expires_at": NOW}, "credential_expired"),
        ({}, {"revoked": True}, "credential_revoked"),
    ],
)
def test_rejects_untrusted_bindings_and_time_state(envelope_change, credential_change, code: str) -> None:
    envelope, credential = _signed_envelope(**envelope_change)
    if credential_change:
        credential = WorkloadCredential(
            **{
                name: credential_change.get(name, getattr(credential, name))
                for name in credential.__dataclass_fields__
            }
        )

    with pytest.raises(ValueError, match=code):
        validate_trusted_envelope(
            envelope,
            credential=credential,
            payload=b"test-payload",
            now=NOW,
            replay_store=InMemoryReplayStore(),
            payload_hash_override="a" * 64,
        )


def test_rejects_payload_or_signature_mutation() -> None:
    envelope, credential = _signed_envelope()

    with pytest.raises(ValueError, match="payload_hash_mismatch"):
        validate_trusted_envelope(
            envelope,
            credential=credential,
            payload=b"mutated",
            now=NOW,
            replay_store=InMemoryReplayStore(),
        )

    mutated = TrustedControlEnvelope(
        **{
            name: ("invalid" if name == "signature" else getattr(envelope, name))
            for name in envelope.__dataclass_fields__
        }
    )
    with pytest.raises(ValueError, match="signature_invalid"):
        validate_trusted_envelope(
            mutated,
            credential=credential,
            payload=b"test-payload",
            now=NOW,
            replay_store=InMemoryReplayStore(),
            payload_hash_override="a" * 64,
        )


def test_parser_rejects_duplicate_unknown_deep_and_oversized_json() -> None:
    with pytest.raises(ValueError, match="duplicate_json_key"):
        parse_envelope_json(b'{"event_id":"one","event_id":"two"}')

    envelope, _credential = _signed_envelope()
    payload = envelope.as_dict()
    payload["caller_risk"] = "safe"
    with pytest.raises(ValueError, match="unknown_envelope_field"):
        parse_envelope_json(json.dumps(payload).encode("utf-8"))

    with pytest.raises(ValueError, match="envelope_too_large"):
        parse_envelope_json(b"{" + (b" " * 70_000) + b"}")
