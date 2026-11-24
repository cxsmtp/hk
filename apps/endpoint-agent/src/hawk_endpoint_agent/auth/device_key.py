"""Platform device-key providers for secretless endpoint authentication."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


_SAFE_TAG = re.compile(r"^[A-Za-z0-9._-]{1,200}$")


class UnsupportedKeyProviderError(RuntimeError):
    """Raised when a security profile cannot safely use the requested provider."""


DEVICE_KEY_ERROR_CODES = frozenset({
    "device_key_helper_missing", "device_key_helper_unsigned", "device_key_operation_failed",
})
CANONICAL_MACOS_IDENTITY_HELPER = Path.home() / "Library/Application Support/Hawk/EndpointAgent/runtime/bin/hawk-device-identity"


class DeviceKeyError(RuntimeError):
    """Platform failure with a fixed diagnostic code; message is never diagnostic output."""

    def __init__(self, message: str, *, code: str = "device_key_operation_failed") -> None:
        super().__init__(message)
        self.code = code if code in DEVICE_KEY_ERROR_CODES else "device_key_operation_failed"


@dataclass(frozen=True)
class DevicePublicIdentity:
    provider: str
    public_key_pem: str
    key_thumbprint: str
    hardware_backed: bool


@dataclass(frozen=True)
class DeviceKeyStatus:
    provider: str
    available: bool
    hardware_backed: bool
    signed_helper: bool
    detail: str = ""


class DeviceKeyProvider(Protocol):
    def ensure_key(self, endpoint_id: str) -> DevicePublicIdentity: ...

    def sign(self, payload: bytes) -> bytes: ...

    def status(self) -> DeviceKeyStatus: ...

    def destroy(self) -> None: ...


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def public_key_thumbprint(public_key_pem: str) -> str:
    key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise DeviceKeyError("device identity is not P-256")
    numbers = key.public_numbers()
    canonical = json.dumps(
        {
            "crv": "P-256",
            "kty": "EC",
            "x": _b64url(numbers.x.to_bytes(32, "big")),
            "y": _b64url(numbers.y.to_bytes(32, "big")),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class EphemeralDeviceKeyProvider:
    """Process-only development key. It is never accepted by a bank profile."""

    provider_name = "development_ephemeral"

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())

    def ensure_key(self, endpoint_id: str) -> DevicePublicIdentity:
        del endpoint_id
        public_pem = self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        return DevicePublicIdentity(
            provider=self.provider_name,
            public_key_pem=public_pem,
            key_thumbprint=public_key_thumbprint(public_pem),
            hardware_backed=False,
        )

    def sign(self, payload: bytes) -> bytes:
        return self._key.sign(payload, ec.ECDSA(hashes.SHA256()))

    def status(self) -> DeviceKeyStatus:
        return DeviceKeyStatus(
            provider=self.provider_name,
            available=True,
            hardware_backed=False,
            signed_helper=False,
            detail="process-only development identity",
        )

    def destroy(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())


class MacSecureEnclaveProvider:
    provider_name = "macos_secure_enclave"

    def __init__(
        self,
        *,
        helper_path: str,
        key_tag: str,
        require_signed: bool = True,
    ) -> None:
        if not _SAFE_TAG.fullmatch(key_tag):
            raise ValueError("invalid Secure Enclave key tag")
        self._helper = Path(helper_path).expanduser().resolve()
        self._key_tag = key_tag
        self._require_signed = require_signed

    def _signature_status(self) -> tuple[bool, str]:
        if not self._helper.is_file():
            return False, "helper not installed"
        try:
            verified = subprocess.run(
                ["/usr/bin/codesign", "--verify", "--strict", str(self._helper)],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if verified.returncode != 0:
                return False, "helper signature is invalid"
            result = subprocess.run(
                ["/usr/bin/codesign", "-dv", "--verbose=4", str(self._helper)],
                capture_output=True, text=True, timeout=5, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False, "helper signature could not be verified"
        output = f"{result.stdout}\n{result.stderr}"
        signed = (
            result.returncode == 0
            and "Signature=adhoc" not in output
            and "TeamIdentifier=not set" not in output
            and re.search(r"^TeamIdentifier=[A-Z0-9]{10}$", output, re.MULTILINE) is not None
        )
        return signed, "developer-signed helper" if signed else "helper is unsigned or ad-hoc signed"

    def _run(self, verb: str, payload: bytes = b"") -> dict:
        if verb not in {"ensure", "status", "sign", "destroy"}:
            raise ValueError("unsupported identity-helper operation")
        if not self._helper.is_file():
            raise DeviceKeyError("Secure Enclave helper is not installed", code="device_key_helper_missing")
        signed, signature_detail = self._signature_status()
        if self._require_signed and not signed:
            raise DeviceKeyError("Secure Enclave helper is not developer-signed", code="device_key_helper_unsigned")
        try:
            result = subprocess.run(
                [str(self._helper), verb, self._key_tag],
                input=payload,
                capture_output=True,
                timeout=45.0,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise DeviceKeyError("Secure Enclave helper could not run") from exc
        if result.returncode != 0:
            raise DeviceKeyError("Secure Enclave operation failed")
        try:
            decoded = json.loads(result.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DeviceKeyError("Secure Enclave helper returned invalid output") from exc
        if not isinstance(decoded, dict) or decoded.get("ok") is not True:
            raise DeviceKeyError("Secure Enclave operation was not successful")
        return decoded

    def ensure_key(self, endpoint_id: str) -> DevicePublicIdentity:
        del endpoint_id
        result = self._run("ensure")
        public_pem = str(result.get("public_key_pem") or "")
        return DevicePublicIdentity(
            provider=self.provider_name,
            public_key_pem=public_pem,
            key_thumbprint=public_key_thumbprint(public_pem),
            hardware_backed=bool(result.get("hardware_backed")),
        )

    def sign(self, payload: bytes) -> bytes:
        result = self._run("sign", payload)
        encoded = str(result.get("signature") or "")
        try:
            return base64.urlsafe_b64decode(encoded + ("=" * (-len(encoded) % 4)))
        except ValueError as exc:
            raise DeviceKeyError("Secure Enclave helper returned invalid signature") from exc

    def status(self) -> DeviceKeyStatus:
        signed, detail = self._signature_status()
        if not self._helper.is_file():
            return DeviceKeyStatus(
                provider=self.provider_name,
                available=False,
                hardware_backed=False,
                signed_helper=False,
                detail=detail,
            )
        if self._require_signed and not signed:
            return DeviceKeyStatus(
                provider=self.provider_name,
                available=False,
                hardware_backed=False,
                signed_helper=False,
                detail=detail,
            )
        try:
            result = self._run("status")
        except DeviceKeyError as exc:
            return DeviceKeyStatus(
                provider=self.provider_name,
                available=False,
                hardware_backed=False,
                signed_helper=signed,
                detail=str(exc),
            )
        return DeviceKeyStatus(
            provider=self.provider_name,
            available=bool(result.get("exists")),
            hardware_backed=bool(result.get("hardware_backed", True)),
            signed_helper=signed,
            detail=detail,
        )

    def destroy(self) -> None:
        self._run("destroy")



def validate_macos_identity_helper(helper_path: str) -> Path:
    """Validate a bank helper without invoking a key operation."""
    helper = Path(helper_path).expanduser().absolute()
    if helper.is_symlink() or not helper.is_file():
        raise DeviceKeyError("Secure Enclave helper is not installed", code="device_key_helper_missing")
    if helper.stat().st_mode & 0o022 or not os.access(helper, os.X_OK):
        raise DeviceKeyError("Secure Enclave helper permissions are invalid", code="device_key_helper_unsigned")
    provider = MacSecureEnclaveProvider(helper_path=str(helper), key_tag="com.hawk.signature-preflight")
    signed, _detail = provider._signature_status()
    if not signed:
        raise DeviceKeyError("Secure Enclave helper is not developer-signed", code="device_key_helper_unsigned")
    return helper.resolve()

def build_device_key_provider(
    *,
    provider_name: str,
    security_profile: str,
    helper_path: str = "~/Library/Application Support/Hawk/EndpointAgent/bin/hawk-device-identity",
    helper_sha256: str = "",
    key_tag: str = "com.hawk.endpoint-agent.device-key",
    kms_hsm_helper_path: str = "unix:///var/run/hawk/kms-signer.sock",
    kms_hsm_key_reference: str = "",
) -> DeviceKeyProvider:
    profile = str(security_profile or "bank").strip().lower()
    provider = str(provider_name or "").strip().lower()
    if provider == "development_ephemeral":
        if profile != "development":
            raise UnsupportedKeyProviderError(
                "bank profile requires a hardware-backed device key"
            )
        return EphemeralDeviceKeyProvider()
    if provider == "macos_secure_enclave":
        return MacSecureEnclaveProvider(
            helper_path=helper_path,
            key_tag=key_tag,
            require_signed=profile != "development",
        )
    if provider == "windows_tpm_cng":
        from .windows_tpm import WindowsTpmCngProvider

        return WindowsTpmCngProvider(
            key_name=key_tag,
            helper_path=helper_path,
            expected_helper_sha256=helper_sha256,
            require_signed_helper=profile != "development",
        )
    if provider == "linux_tpm2":
        from .linux_tpm2 import LinuxTpm2Provider

        return LinuxTpm2Provider(key_name=key_tag)
    if provider == "kms_hsm_helper":
        from .kms_hsm import KmsHsmHelperProvider

        return KmsHsmHelperProvider(
            helper_path=kms_hsm_helper_path,
            key_reference=kms_hsm_key_reference,
        )
    raise UnsupportedKeyProviderError(
        f"key provider {provider or 'unset'} is not implemented on this endpoint"
    )
