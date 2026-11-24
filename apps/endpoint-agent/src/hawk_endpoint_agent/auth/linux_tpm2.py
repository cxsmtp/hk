"""Linux TPM2-tools device identity with no software-key fallback."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric import utils

from .device_key import (
    DeviceKeyError,
    DeviceKeyStatus,
    DevicePublicIdentity,
    public_key_thumbprint,
)


_SAFE_KEY_NAME = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
_DEFAULT_TOOLS = {
    "getcap": "/usr/bin/tpm2_getcap",
    "createprimary": "/usr/bin/tpm2_createprimary",
    "readpublic": "/usr/bin/tpm2_readpublic",
    "sign": "/usr/bin/tpm2_sign",
    "flushcontext": "/usr/bin/tpm2_flushcontext",
}
_DEFAULT_TPM_DEVICE = "/dev/tpmrm0"


def _is_tpm_character_device(path: Path) -> bool:
    try:
        return path.is_absolute() and stat.S_ISCHR(path.stat().st_mode)
    except OSError:
        return False


class LinuxTpm2Provider:
    """P-256 signing key represented by an opaque TPM2 context."""

    provider_name = "linux_tpm2"

    def __init__(
        self,
        *,
        key_name: str = "hawk-endpoint-agent-device-key",
        state_dir: str = "~/.local/state/hawk/device-keys",
        platform_name: str | None = None,
        tool_paths: Mapping[str, str] | None = None,
        device_path: str = _DEFAULT_TPM_DEVICE,
    ) -> None:
        if not _SAFE_KEY_NAME.fullmatch(key_name):
            raise ValueError("invalid Linux TPM key name")
        configured = dict(_DEFAULT_TOOLS)
        if tool_paths:
            unknown = set(tool_paths) - set(_DEFAULT_TOOLS)
            if unknown:
                raise ValueError("unsupported TPM2 tool override")
            configured.update({key: str(value) for key, value in tool_paths.items()})
        self._platform_name = platform_name or sys.platform
        self._tools = {key: Path(value) for key, value in configured.items()}
        self._device_path = Path(device_path)
        self._tcti = f"device:{self._device_path}"
        self._state_dir = Path(state_dir).expanduser()
        self._context_path = self._state_dir / f"{key_name}.ctx"

    def _supported(self) -> tuple[bool, str]:
        if not self._platform_name.startswith("linux"):
            return False, "Linux TPM2 is unavailable on this platform"
        if not _is_tpm_character_device(self._device_path):
            return False, "fixed Linux TPM character device is unavailable"
        missing = [name for name, path in self._tools.items() if not path.is_file()]
        if missing:
            return False, "required fixed TPM2 tools are unavailable"
        return True, "fixed TPM2 tools are installed"

    def _run(self, tool: str, argv: list[str], payload: bytes = b"") -> bytes:
        if tool not in _DEFAULT_TOOLS:
            raise ValueError("unsupported TPM2 operation")
        supported, detail = self._supported()
        if not supported:
            raise DeviceKeyError(detail)
        try:
            result = subprocess.run(
                [str(self._tools[tool]), "-T", self._tcti, *argv],
                input=payload,
                capture_output=True,
                timeout=45.0,
                check=False,
                env={
                    key: value
                    for key, value in os.environ.items()
                    if key != "TPM2TOOLS_TCTI"
                },
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise DeviceKeyError("TPM2 command could not run") from exc
        if result.returncode != 0:
            raise DeviceKeyError("TPM2 operation failed")
        return bytes(result.stdout)

    def _probe(self) -> tuple[bool, str]:
        supported, detail = self._supported()
        if not supported:
            return False, detail
        try:
            output = self._run("getcap", ["properties-fixed"]).decode(
                "utf-8", errors="replace"
            )
        except DeviceKeyError as exc:
            return False, str(exc)
        verified = (
            "TPM2_PT_MANUFACTURER" in output
            and "TPM2_PT_FIRMWARE_VERSION_1" in output
        )
        return (
            (True, "TPM2 tool and fixed-property device response observed")
            if verified
            else (False, "TPM2 fixed-property evidence is unavailable")
        )

    def _require_hardware(self) -> None:
        verified, detail = self._probe()
        if not verified:
            raise DeviceKeyError(detail)

    def _transient_handles(self) -> set[str]:
        output = self._run("getcap", ["handles-transient"]).decode(
            "ascii", errors="replace"
        )
        return {
            match.group(1).lower()
            for match in re.finditer(
                r"(?im)^\s*-\s*(0x8[0-9a-f]{7})\s*$",
                output,
            )
        }

    def ensure_key(self, endpoint_id: str) -> DevicePublicIdentity:
        del endpoint_id
        self._require_hardware()
        self._state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(self._state_dir, 0o700)
        except OSError as exc:
            raise DeviceKeyError("TPM2 state directory could not be secured") from exc
        if not self._context_path.is_file():
            try:
                self._run(
                    "createprimary",
                    [
                        "-Q",
                        "-C",
                        "o",
                        "-G",
                        "ecc256",
                        "-g",
                        "sha256",
                        "-a",
                        "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign",
                        "-c",
                        str(self._context_path),
                    ],
                )
            except DeviceKeyError:
                self._context_path.unlink(missing_ok=True)
                raise
        public_pem_bytes = self._run(
            "readpublic",
            ["-Q", "-c", str(self._context_path), "-f", "pem", "-o", "-"],
        )
        try:
            public_pem = public_pem_bytes.decode("ascii")
            thumbprint = public_key_thumbprint(public_pem)
        except (UnicodeDecodeError, ValueError, DeviceKeyError) as exc:
            raise DeviceKeyError("TPM2 returned an invalid P-256 public key") from exc
        return DevicePublicIdentity(
            provider=self.provider_name,
            public_key_pem=public_pem,
            key_thumbprint=thumbprint,
            hardware_backed=True,
        )

    def sign(self, payload: bytes) -> bytes:
        self._require_hardware()
        if not self._context_path.is_file():
            raise DeviceKeyError("TPM2 device key does not exist")
        signature = self._run(
            "sign",
            [
                "-Q",
                "-c",
                str(self._context_path),
                "-g",
                "sha256",
                "-f",
                "plain",
                "-o",
                "-",
                "-",
            ],
            bytes(payload),
        )
        if len(signature) == 64:
            return utils.encode_dss_signature(
                int.from_bytes(signature[:32], "big"),
                int.from_bytes(signature[32:], "big"),
            )
        try:
            utils.decode_dss_signature(signature)
        except ValueError as exc:
            raise DeviceKeyError("TPM2 returned an invalid signature") from exc
        return signature

    def status(self) -> DeviceKeyStatus:
        verified, detail = self._probe()
        if verified:
            detail += "; device key " + (
                "present" if self._context_path.is_file() else "not created"
            )
        return DeviceKeyStatus(
            provider=self.provider_name,
            available=verified,
            hardware_backed=verified,
            signed_helper=False,
            detail=detail,
        )

    def destroy(self) -> None:
        self._require_hardware()
        if not self._context_path.is_file():
            raise DeviceKeyError("TPM2 device key does not exist")
        raise DeviceKeyError(
            "Linux TPM key destruction requires a signed single-process TPM helper"
        )
