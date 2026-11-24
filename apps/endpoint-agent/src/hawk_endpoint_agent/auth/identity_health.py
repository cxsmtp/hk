"""Fail-closed verification for an enrolled hardware device identity."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .device_key import (
    DeviceKeyError,
    DeviceKeyProvider,
    build_device_key_provider,
)


class DeviceIdentityHealthError(RuntimeError):
    """The configured identity cannot prove its enrolled hardware key."""


@dataclass(frozen=True)
class DeviceIdentityHealthResult:
    provider: str
    hardware_backed: bool = True
    key_available: bool = True
    key_thumbprint_matches: bool = True
    signature_verified: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": True,
            "provider": self.provider,
            "hardware_backed": self.hardware_backed,
            "key_available": self.key_available,
            "key_thumbprint_matches": self.key_thumbprint_matches,
            "signature_verified": self.signature_verified,
        }


def verify_device_identity(
    config: Any,
    *,
    provider: DeviceKeyProvider | None = None,
) -> DeviceIdentityHealthResult:
    """Reopen and prove the enrolled key without exposing signed material."""
    selected = provider or build_device_key_provider(
        provider_name=config.key_provider,
        security_profile=config.security_profile,
        helper_path=config.identity_helper_path,
        helper_sha256=getattr(config, "identity_helper_sha256", ""),
        key_tag=config.device_key_tag,
    )
    try:
        identity = selected.ensure_key(config.endpoint_id)
        status = selected.status()
    except DeviceKeyError as exc:
        raise DeviceIdentityHealthError("device key is unavailable") from exc

    if not status.available:
        raise DeviceIdentityHealthError("device key is unavailable")
    if not status.hardware_backed or not identity.hardware_backed:
        raise DeviceIdentityHealthError("device key is not hardware backed")

    expected_thumbprint = str(
        getattr(config, "ipc_trusted_device_thumbprint", "") or ""
    ).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_thumbprint):
        raise DeviceIdentityHealthError("enrolled key pin is missing")
    if identity.key_thumbprint != expected_thumbprint:
        raise DeviceIdentityHealthError("enrolled key pin mismatch")

    challenge = secrets.token_bytes(32)
    try:
        signature = selected.sign(challenge)
        public_key = serialization.load_pem_public_key(
            identity.public_key_pem.encode("ascii")
        )
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise DeviceIdentityHealthError("device public key is not P-256")
        public_key.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
    except DeviceIdentityHealthError:
        raise
    except (DeviceKeyError, InvalidSignature, TypeError, ValueError) as exc:
        raise DeviceIdentityHealthError("device signature verification failed") from exc

    return DeviceIdentityHealthResult(provider=identity.provider)
