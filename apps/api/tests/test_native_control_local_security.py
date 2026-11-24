from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.services.native_control.local_helper import validate_local_helper_message
from app.services.native_control.policy_cache import (
    PolicyVerificationKey,
    SignedPolicySnapshot,
    canonical_policy_body,
    evaluate_local_policy,
    validate_policy_snapshot,
)
from app.services.native_control.software_update import (
    SoftwareUpdateArtifact,
    SoftwareUpdateVerificationKey,
    canonical_update_body,
    validate_software_update,
)


NOW = datetime(2026, 8, 11, 9, 0, tzinfo=timezone.utc)


def _key_pair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private, public


def _sign(private: ec.EllipticCurvePrivateKey, body: bytes) -> str:
    signature = private.sign(body, ec.ECDSA(hashes.SHA256()))
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")


def test_signed_policy_cache_is_declarative_scoped_and_deterministic() -> None:
    private, public = _key_pair()
    unsigned = SignedPolicySnapshot(
        tenant_id="tenant-1",
        integration_instance_id="integration-1",
        scope={
            "default_decision": "block",
            "rules": [
                {"action_class": "low_risk_read", "decision": "allow"},
                {"action_class": "external_data_transfer", "decision": "block"},
            ],
        },
        policy_version="policy-8",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        supported_action_classes=("external_data_transfer", "low_risk_read"),
        key_id="policy-key-1",
        signature_algorithm="ES256",
        signature="",
    )
    snapshot = SignedPolicySnapshot(**{**unsigned.as_dict(), "signature": _sign(private, canonical_policy_body(unsigned))})
    verified = validate_policy_snapshot(
        snapshot,
        key=PolicyVerificationKey(
            key_id="policy-key-1",
            key_role="policy_signing",
            public_key_pem=public,
            tenant_id="tenant-1",
        ),
        tenant_id="tenant-1",
        integration_instance_id="integration-1",
        now=NOW,
    )

    assert evaluate_local_policy(verified, action_class="low_risk_read") == "allow"
    assert evaluate_local_policy(verified, action_class="external_data_transfer") == "block"
    assert evaluate_local_policy(verified, action_class="unsupported") == "REMOTE_EVALUATION_REQUIRED"


@pytest.mark.parametrize(
    "payload",
    (
        {"operation": "execute_command", "payload": {"command": "rm -rf /"}},
        {"operation": "configuration.apply", "payload": {"shell": "curl attacker"}},
        {"operation": "policy.install", "payload": {"plugin": "https://attacker/module"}},
        {"operation": "software.update", "payload": {"artifact": "binary"}},
        {"operation": "configuration.apply", "payload": {"program": "/bin/sh", "arguments": ["-c", "id"]}},
        {"operation": "metadata.sync", "payload": {"process": "curl", "argv": ["attacker"]}},
    ),
)
def test_local_helper_rejects_remote_execution_and_update_material(payload: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        validate_local_helper_message(payload)


def test_local_helper_accepts_only_a_bounded_operation_specific_message() -> None:
    message = validate_local_helper_message(
        {
            "operation": "decision.cache",
            "payload": {
                "action_hash": "a" * 64,
                "decision": "block",
                "expires_at": "2026-08-11T10:00:00+00:00",
                "policy_version": "policy-7",
            },
        }
    )

    assert message.operation == "decision.cache"


def test_software_updates_require_a_cryptographically_separate_key_role() -> None:
    private, public = _key_pair()
    unsigned = SoftwareUpdateArtifact(
        product="hawk-native-helper",
        version="1.2.0",
        artifact_sha256="a" * 64,
        sbom_sha256="b" * 64,
        provenance_sha256="c" * 64,
        rollout_channel="canary",
        rollback_version="1.1.0",
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
        key_id="update-key-1",
        signature_algorithm="ES256",
        signature="",
    )
    artifact = SoftwareUpdateArtifact(
        **{**unsigned.as_dict(), "signature": _sign(private, canonical_update_body(unsigned))}
    )
    with pytest.raises(ValueError, match="update_key_role_invalid"):
        validate_software_update(
            artifact,
            key=SoftwareUpdateVerificationKey(
                key_id="update-key-1",
                key_role="policy_signing",
                public_key_pem=public,
            ),
            now=NOW,
        )

    assert validate_software_update(
        artifact,
        key=SoftwareUpdateVerificationKey(
            key_id="update-key-1",
            key_role="software_update_signing",
            public_key_pem=public,
        ),
        now=NOW,
    ).version == "1.2.0"
