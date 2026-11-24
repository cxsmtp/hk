from __future__ import annotations

import base64
import copy
from datetime import UTC, datetime
import json
import stat
import pytest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hawk_endpoint_agent.auth.device_key import (
    DeviceKeyStatus,
    DevicePublicIdentity,
    public_key_thumbprint,
)
from hawk_endpoint_agent.endpoint_floor.local_policy import canonical_policy_bytes
from hawk_endpoint_agent.endpoint_floor.runtime import (
    default_floor_posture,
    load_signed_runtime_floor_posture,
    publish_signed_runtime_floor_posture,
)
from hawk_endpoint_agent.config import load_config


NOW = datetime(2026, 8, 12, 10, 0, tzinfo=UTC)
PRIVATE = Ed25519PrivateKey.from_private_bytes(b"\x32" * 32)
PUBLIC = PRIVATE.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)


def _control(status: str = "inline") -> dict:
    return {
        "status": status,
        "verification": "verified",
        "health": "healthy",
        "evidence_refs": ["native:receipt:component"],
    }


def _receipt_payload() -> dict:
    return {
        "schema": "hawk.endpoint-floor-runtime-receipt",
        "version": 1,
        "tenant_id": "tenant-1",
        "device_id": "device-1",
        "issued_at": "2026-08-12T09:59:00Z",
        "expires_at": "2026-08-12T10:01:00Z",
        "controls": {
            "file_control": _control(),
            "process_control": _control(),
            "network_control": _control(),
            "semantic_proxy": _control("unavailable"),
        },
        "local_policy": {
            "status": "active",
            "freshness": "fresh",
            "policy_version": "policy-7",
            "signature_verified": True,
            "evidence_refs": ["native:policy:" + "a" * 64],
        },
        "native_authority": {
            "mode": "monitor",
            "policy_digest": "a" * 64,
            "policy_epoch": 7,
            "team_id": "ABCDEFGHIJ",
            "bundle_ids": [
                "ai.hawk.endpoint.host", "ai.hawk.endpoint.endpoint-security",
                "ai.hawk.endpoint.content-filter", "ai.hawk.endpoint.managed-routing",
            ],
            "issued_at_unix_seconds": int(NOW.timestamp()) - 60,
            "expires_at_unix_seconds": int(NOW.timestamp()) + 60,
            "artifact_sha256": "b" * 64,
            "target_acceptance_artifact_sha256": "",
            "target_acceptance_verified": False,
            "network_child_attribution_verified": True,
        },
        "reason_codes": [],
        "blind_spots": ["semantic_http_control_unavailable"],
    }


def _envelope(payload: dict | None = None) -> dict:
    body = copy.deepcopy(payload or _receipt_payload())
    return {
        "key_id": "native-runtime-key-1",
        "algorithm": "Ed25519",
        "payload": body,
        "signature": base64.b64encode(PRIVATE.sign(canonical_policy_bytes(body))).decode("ascii"),
    }


def test_source_presence_without_runtime_receipts_is_not_endpoint_protection() -> None:
    posture = default_floor_posture("darwin")

    assert posture["schema_version"] == "1.0"
    assert posture["minimum_floor_satisfied"] is False
    assert posture["health"] == "unknown"
    assert posture["controls"]["file_control"] == {
        "status": "unknown",
        "verification": "unverified",
        "health": "unknown",
        "evidence_refs": [],
    }
    assert posture["controls"]["process_control"]["status"] == "unknown"
    assert posture["controls"]["network_control"]["status"] == "unknown"
    assert posture["controls"]["semantic_proxy"]["status"] == "unavailable"
    assert "native_runtime_acceptance_missing" in posture["blind_spots"]


def test_unsupported_os_is_explicitly_unavailable() -> None:
    posture = default_floor_posture("linux")

    assert posture["minimum_floor_satisfied"] is False
    assert all(
        control["status"] == "unavailable"
        for control in posture["controls"].values()
    )
    assert posture["reason_codes"] == ["ENDPOINT_FLOOR_OS_UNSUPPORTED"]


def test_signed_current_native_receipt_can_prove_the_minimum_floor(tmp_path) -> None:
    receipt_path = tmp_path / "floor-receipt.json"
    receipt_path.write_text(json.dumps(_envelope()), encoding="utf-8")

    posture = load_signed_runtime_floor_posture(
        os_type="darwin",
        receipt_path=receipt_path,
        trusted_public_keys={"native-runtime-key-1": PUBLIC},
        expected_tenant_id="tenant-1",
        expected_device_id="device-1",
        now=NOW,
    )

    assert posture["minimum_floor_satisfied"] is False
    assert posture["health"] == "degraded"
    assert posture["display_state"] == "Needs attention"
    assert posture["controls"]["file_control"]["status"] == "inline"
    assert posture["local_policy"]["signature_verified"] is True
    assert posture["semantic_control_available"] is False


def test_hardware_device_identity_publishes_es256_runtime_receipt_without_secrets(
    tmp_path,
) -> None:
    class HardwareProvider:
        def __init__(self) -> None:
            self.key = ec.generate_private_key(ec.SECP256R1())
            self.public_pem = self.key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii")

        def ensure_key(self, endpoint_id: str) -> DevicePublicIdentity:
            assert endpoint_id == "device-1"
            return DevicePublicIdentity(
                provider="test_hardware",
                public_key_pem=self.public_pem,
                key_thumbprint=public_key_thumbprint(self.public_pem),
                hardware_backed=True,
            )

        def sign(self, payload: bytes) -> bytes:
            return self.key.sign(payload, ec.ECDSA(hashes.SHA256()))

        def status(self) -> DeviceKeyStatus:
            return DeviceKeyStatus(
                provider="test_hardware",
                available=True,
                hardware_backed=True,
                signed_helper=True,
            )

        def destroy(self) -> None:
            raise AssertionError("publisher must not destroy identity")

    provider = HardwareProvider()
    receipt_path = tmp_path / "runtime" / "floor-receipt.json"
    result = publish_signed_runtime_floor_posture(
        payload=_receipt_payload(),
        receipt_path=receipt_path,
        provider=provider,
        endpoint_id="device-1",
        require_hardware_backed=True,
    )

    envelope = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert result["algorithm"] == "ES256"
    assert envelope["algorithm"] == "ES256"
    assert envelope["key_id"] == public_key_thumbprint(provider.public_pem)
    assert set(envelope) == {"key_id", "algorithm", "payload", "signature"}
    assert receipt_path.stat().st_mode & 0o777 == stat.S_IRUSR | stat.S_IWUSR
    assert not any(
        token in receipt_path.read_text(encoding="utf-8").lower()
        for token in ("private_key", "access_token", "password", "secret")
    )

    posture = load_signed_runtime_floor_posture(
        os_type="darwin",
        receipt_path=receipt_path,
        trusted_public_keys={envelope["key_id"]: provider.public_pem.encode("ascii")},
        expected_tenant_id="tenant-1",
        expected_device_id="device-1",
        now=NOW,
    )
    assert posture["minimum_floor_satisfied"] is True
    assert posture["display_state"] == "Monitoring"


@pytest.mark.parametrize("acceptance,accepted_hash,expected", [
    (False, "", "Needs attention"),
    (True, "c" * 64, "Needs attention"),
    (True, "b" * 64, "Protected"),
])
def test_enforce_receipt_requires_matching_artifact_target_acceptance(
    tmp_path, acceptance: bool, accepted_hash: str, expected: str,
) -> None:
    payload = _receipt_payload()
    payload["native_authority"]["mode"] = "enforce"
    payload["native_authority"]["target_acceptance_verified"] = acceptance
    payload["native_authority"]["target_acceptance_artifact_sha256"] = accepted_hash
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    envelope = {
        "key_id": "device-key", "algorithm": "ES256", "payload": payload,
        "signature": base64.b64encode(
            key.sign(canonical_policy_bytes(payload), ec.ECDSA(hashes.SHA256()))
        ).decode("ascii"),
    }
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(envelope), encoding="utf-8")
    posture = load_signed_runtime_floor_posture(
        os_type="darwin", receipt_path=receipt_path,
        trusted_public_keys={"device-key": public},
        expected_tenant_id="tenant-1", expected_device_id="device-1", now=NOW,
    )
    assert posture["display_state"] == expected


def test_tampered_wrong_scope_or_oversized_receipt_stays_unknown(tmp_path) -> None:
    cases: list[tuple[str, bytes]] = []
    tampered = _envelope()
    tampered["payload"]["controls"]["file_control"]["status"] = "inline_bound"
    cases.append(("tampered", json.dumps(tampered).encode("utf-8")))
    wrong_device_payload = _receipt_payload()
    wrong_device_payload["device_id"] = "device-2"
    cases.append(("wrong-device", json.dumps(_envelope(wrong_device_payload)).encode("utf-8")))
    cases.append(("oversized", b"{" + b" " * (256 * 1024) + b"}"))

    for name, body in cases:
        receipt_path = tmp_path / f"{name}.json"
        receipt_path.write_bytes(body)
        posture = load_signed_runtime_floor_posture(
            os_type="darwin",
            receipt_path=receipt_path,
            trusted_public_keys={"native-runtime-key-1": PUBLIC},
            expected_tenant_id="tenant-1",
            expected_device_id="device-1",
            now=NOW,
        )
        assert posture["minimum_floor_satisfied"] is False
        assert posture["controls"]["file_control"]["status"] == "unknown"
        assert any(code.startswith("runtime_receipt_rejected:") for code in posture["reason_codes"])


def test_config_rejects_malformed_native_receipt_trust_map(tmp_path) -> None:
    config_path = tmp_path / "agent.json"
    config_path.write_text(
        json.dumps(
            {
                "api_base_url": "http://127.0.0.1:8000",
                "security_profile": "development",
                "key_provider": "development_ephemeral",
                "endpoint_floor_receipt_public_keys": ["not-a-key-map"],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="receipt public keys"):
        load_config(config_path)
