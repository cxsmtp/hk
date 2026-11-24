from __future__ import annotations

from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from hawk_endpoint_agent.auth.device_key import (
    DeviceKeyStatus,
    DevicePublicIdentity,
    public_key_thumbprint,
)
from hawk_endpoint_agent.auth.identity_health import (
    DeviceIdentityHealthError,
    verify_device_identity,
)


class HardwareProvider:
    provider_name = "macos_secure_enclave"

    def __init__(self, *, available: bool = True, hardware_backed: bool = True) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        self._available = available
        self._hardware_backed = hardware_backed
        self.calls: list[str] = []

    def ensure_key(self, endpoint_id: str) -> DevicePublicIdentity:
        self.calls.append(f"ensure:{endpoint_id}")
        public_pem = self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        return DevicePublicIdentity(
            provider=self.provider_name,
            public_key_pem=public_pem,
            key_thumbprint=public_key_thumbprint(public_pem),
            hardware_backed=self._hardware_backed,
        )

    def status(self) -> DeviceKeyStatus:
        self.calls.append("status")
        return DeviceKeyStatus(
            provider=self.provider_name,
            available=self._available,
            hardware_backed=self._hardware_backed,
            signed_helper=True,
        )

    def sign(self, payload: bytes) -> bytes:
        self.calls.append("sign")
        return self._key.sign(payload, ec.ECDSA(hashes.SHA256()))


def _config(provider: HardwareProvider, *, pin: str | None = None) -> SimpleNamespace:
    identity = provider.ensure_key("endpoint-health-test")
    provider.calls.clear()
    return SimpleNamespace(
        endpoint_id="endpoint-health-test",
        key_provider=provider.provider_name,
        security_profile="bank",
        identity_helper_path="/private/helper",
        device_key_tag="com.hawk.endpoint-agent.device-key.v2",
        ipc_trusted_device_thumbprint=pin or identity.key_thumbprint,
    )


def test_verify_device_identity_proves_hardware_signature_and_pin() -> None:
    provider = HardwareProvider()

    result = verify_device_identity(_config(provider), provider=provider)

    assert result.as_dict() == {
        "ok": True,
        "provider": "macos_secure_enclave",
        "hardware_backed": True,
        "key_available": True,
        "key_thumbprint_matches": True,
        "signature_verified": True,
    }
    assert provider.calls == ["ensure:endpoint-health-test", "status", "sign"]


def test_verify_device_identity_rejects_enrollment_pin_mismatch() -> None:
    provider = HardwareProvider()

    with pytest.raises(DeviceIdentityHealthError, match="enrolled key pin mismatch"):
        verify_device_identity(_config(provider, pin="0" * 64), provider=provider)


@pytest.mark.parametrize(
    ("available", "hardware_backed", "message"),
    [
        (False, True, "device key is unavailable"),
        (True, False, "device key is not hardware backed"),
    ],
)
def test_verify_device_identity_fails_closed_on_untrusted_status(
    available: bool,
    hardware_backed: bool,
    message: str,
) -> None:
    provider = HardwareProvider(
        available=available,
        hardware_backed=hardware_backed,
    )

    with pytest.raises(DeviceIdentityHealthError, match=message):
        verify_device_identity(_config(provider), provider=provider)

