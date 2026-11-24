"""Windows TPM-backed CNG device identity.

Managed deployments use the signed, fixed-operation native helper. A PowerShell
implementation remains only as a compatibility path when no helper is configured.
Both pin CNG to the Microsoft Platform Crypto Provider and machine-scoped,
non-exportable P-256 keys.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import re
import subprocess
import sys
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .device_key import (
    DeviceKeyError,
    DeviceKeyStatus,
    DevicePublicIdentity,
    public_key_thumbprint,
)


_SAFE_KEY_NAME = re.compile(r"^[A-Za-z0-9._-]{1,160}$")
_PROVIDER_NAME = "Microsoft Platform Crypto Provider"
_DEFAULT_POWERSHELL = (
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
)
_OPERATIONS = frozenset({"status", "ensure", "sign", "destroy"})


def _authenticode_valid(path: Path) -> bool:
    if sys.platform != "win32" or not path.is_file():
        return False
    from ctypes import wintypes

    class _Guid(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class _WintrustFileInfo(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.c_void_p),
        ]

    class _WintrustData(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.POINTER(_WintrustFileInfo)),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPCWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
        ]

    action = _Guid(
        0x00AAC56B,
        0xCD44,
        0x11D0,
        (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
    )
    file_info = _WintrustFileInfo(
        ctypes.sizeof(_WintrustFileInfo), str(path), None, None
    )
    trust_data = _WintrustData(
        ctypes.sizeof(_WintrustData),
        None,
        None,
        2,  # WTD_UI_NONE
        0,  # WTD_REVOKE_NONE; install-time validation owns revocation evidence
        1,  # WTD_CHOICE_FILE
        ctypes.pointer(file_info),
        0,
        None,
        None,
        0x00001000,  # WTD_CACHE_ONLY_URL_RETRIEVAL
        0,
    )
    wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    wintrust.WinVerifyTrust.argtypes = (
        wintypes.HWND,
        ctypes.POINTER(_Guid),
        ctypes.c_void_p,
    )
    wintrust.WinVerifyTrust.restype = ctypes.c_long
    return wintrust.WinVerifyTrust(
        None, ctypes.byref(action), ctypes.byref(trust_data)
    ) == 0

# This script is a constant. Operation and key name are passed as separate,
# validated argv values and signing bytes arrive only through stdin.
_CNG_SCRIPT = r"""
param([string]$Operation, [string]$KeyName)
$ErrorActionPreference = 'Stop'
$providerName = 'Microsoft Platform Crypto Provider'
$provider = [System.Security.Cryptography.CngProvider]::new($providerName)
$tpm = Get-Tpm
$ready = [bool]($tpm.TpmPresent -and $tpm.TpmReady)
if (-not $ready) {
  @{ok=$true; available=$false; hardware_backed=$false; tpm_present=[bool]$tpm.TpmPresent; tpm_ready=[bool]$tpm.TpmReady; provider=$providerName} | ConvertTo-Json -Compress
  exit 0
}
$machineKey = [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey
$exists = [System.Security.Cryptography.CngKey]::Exists($KeyName, $provider, $machineKey)
if ($Operation -eq 'status') {
  @{ok=$true; available=$true; hardware_backed=$true; tpm_present=$true; tpm_ready=$true; provider=$providerName; exists=$exists} | ConvertTo-Json -Compress
  exit 0
}
if ($Operation -eq 'ensure') {
  if (-not $exists) {
    $parameters = [System.Security.Cryptography.CngKeyCreationParameters]::new()
    $parameters.Provider = $provider
    $parameters.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::Signing
    $parameters.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
    $parameters.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey
    $key = [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::ECDsaP256, $KeyName, $parameters)
  } else {
    $key = [System.Security.Cryptography.CngKey]::Open($KeyName, $provider, $machineKey)
  }
  try { $public = [Convert]::ToBase64String($key.Export([System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)) } finally { $key.Dispose() }
  @{ok=$true; available=$true; hardware_backed=$true; tpm_present=$true; tpm_ready=$true; provider=$providerName; public_key_blob=$public} | ConvertTo-Json -Compress
  exit 0
}
if (-not $exists) { throw 'TPM device key does not exist' }
$key = [System.Security.Cryptography.CngKey]::Open($KeyName, $provider, $machineKey)
try {
  if ($Operation -eq 'sign') {
    $stream = [Console]::OpenStandardInput()
    $buffer = [System.IO.MemoryStream]::new()
    $stream.CopyTo($buffer)
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($buffer.ToArray())
    $signer = [System.Security.Cryptography.ECDsaCng]::new($key)
    try { $signature = [Convert]::ToBase64String($signer.SignHash($hash)) } finally { $signer.Dispose() }
    @{ok=$true; available=$true; hardware_backed=$true; tpm_present=$true; tpm_ready=$true; provider=$providerName; signature=$signature} | ConvertTo-Json -Compress
    exit 0
  }
  if ($Operation -eq 'destroy') {
    $key.Delete()
    @{ok=$true; available=$true; hardware_backed=$true; tpm_present=$true; tpm_ready=$true; provider=$providerName} | ConvertTo-Json -Compress
    exit 0
  }
} finally { $key.Dispose() }
throw 'Unsupported operation'
""".strip()
_CNG_COMMAND = f"& {{ {_CNG_SCRIPT} }}"


class WindowsTpmCngProvider:
    """Non-exportable P-256 identity in the Windows platform CNG provider."""

    provider_name = "windows_tpm_cng"

    def __init__(
        self,
        *,
        key_name: str = "HawkEndpointAgentDeviceKey",
        platform_name: str | None = None,
        powershell_path: str = _DEFAULT_POWERSHELL,
        helper_path: str = "",
        expected_helper_sha256: str = "",
        require_signed_helper: bool = True,
        signature_verifier: Callable[[Path], bool] = _authenticode_valid,
    ) -> None:
        if not _SAFE_KEY_NAME.fullmatch(key_name):
            raise ValueError("invalid Windows TPM key name")
        self._key_name = key_name
        self._platform_name = platform_name or sys.platform
        self._powershell = Path(powershell_path)
        self._helper = Path(helper_path).expanduser() if helper_path else None
        self._expected_helper_sha256 = str(expected_helper_sha256 or "").lower()
        self._require_signed_helper = bool(require_signed_helper)
        self._signature_verifier = signature_verifier

    def _helper_digest_valid(self) -> bool:
        if self._helper is None or not self._helper.is_file():
            return False
        if not re.fullmatch(r"[0-9a-f]{64}", self._expected_helper_sha256):
            return not self._require_signed_helper
        try:
            observed = hashlib.sha256(self._helper.read_bytes()).hexdigest()
        except OSError:
            return False
        return observed == self._expected_helper_sha256

    @contextmanager
    def _locked_native_helper(self):
        """Prevent write/delete replacement while the signed helper executes."""
        if self._helper is None or sys.platform != "win32":
            with nullcontext():
                yield
            return
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = (
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        )
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.CreateFileW(
            str(self._helper),
            0x80000000,  # GENERIC_READ
            0x00000001,  # FILE_SHARE_READ only; deny replacement/deletion
            None,
            3,  # OPEN_EXISTING
            0x00000080,  # FILE_ATTRIBUTE_NORMAL
            None,
        )
        if handle in (None, wintypes.HANDLE(-1).value):
            raise DeviceKeyError("native Windows identity helper could not be locked")
        try:
            yield
        finally:
            kernel32.CloseHandle(handle)

    def _supported(self) -> tuple[bool, str]:
        if self._platform_name != "win32":
            return False, "Windows TPM CNG is unavailable on this platform"
        if self._helper is not None:
            if not self._helper.is_file():
                return False, "signed native Windows identity helper is unavailable"
            if not self._helper_digest_valid():
                return False, "native Windows identity helper digest is invalid"
            if self._require_signed_helper and not self._signature_verifier(self._helper):
                return False, "native Windows identity helper signature is invalid"
            return True, "signature-verified native Windows TPM/CNG helper is installed"
        if not self._powershell.is_file():
            return False, "fixed Windows PowerShell executable is unavailable"
        return True, "Windows TPM CNG tooling is installed"

    def _run(self, operation: str, payload: bytes = b"") -> dict:
        if operation not in _OPERATIONS:
            raise ValueError("unsupported Windows TPM operation")
        supported, detail = self._supported()
        if not supported:
            raise DeviceKeyError(detail)
        try:
            argv = (
                [str(self._helper), operation, self._key_name]
                if self._helper is not None
                else [
                    str(self._powershell), "-NoLogo", "-NoProfile",
                    "-NonInteractive", "-Command", _CNG_COMMAND,
                    operation, self._key_name,
                ]
            )
            lock = self._locked_native_helper() if self._helper is not None else nullcontext()
            with lock:
                if self._helper is not None and (
                    not self._helper_digest_valid()
                    or (self._require_signed_helper and not self._signature_verifier(self._helper))
                ):
                    raise DeviceKeyError("native Windows identity helper trust changed")
                result = subprocess.run(
                    argv,
                    input=payload,
                    capture_output=True,
                    timeout=45.0,
                    check=False,
                )
                if self._helper is not None and not self._helper_digest_valid():
                    raise DeviceKeyError("native Windows identity helper changed during use")
        except (OSError, subprocess.SubprocessError) as exc:
            raise DeviceKeyError("Windows TPM CNG command could not run") from exc
        if result.returncode != 0:
            raise DeviceKeyError("Windows TPM CNG operation failed")
        try:
            decoded = json.loads(result.stdout.decode("utf-8-sig"))
        except (AttributeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DeviceKeyError("Windows TPM CNG returned invalid output") from exc
        if not isinstance(decoded, dict) or decoded.get("ok") is not True:
            raise DeviceKeyError("Windows TPM CNG operation was not successful")
        return decoded

    @staticmethod
    def _has_hardware_evidence(result: dict) -> bool:
        return (
            result.get("available") is True
            and result.get("hardware_backed") is True
            and result.get("tpm_present") is True
            and result.get("tpm_ready") is True
            and result.get("provider") == _PROVIDER_NAME
        )

    def _require_hardware_result(self, result: dict) -> None:
        if not self._has_hardware_evidence(result):
            raise DeviceKeyError("Windows TPM hardware evidence is unavailable")

    @staticmethod
    def _public_pem(encoded_blob: object) -> str:
        try:
            blob = base64.b64decode(str(encoded_blob), validate=True)
        except (ValueError, TypeError) as exc:
            raise DeviceKeyError("Windows TPM returned an invalid public key") from exc
        if len(blob) != 72 or blob[:4] != b"ECS1" or int.from_bytes(blob[4:8], "little") != 32:
            raise DeviceKeyError("Windows TPM did not return a P-256 public key")
        public_key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(blob[8:40], "big"),
            int.from_bytes(blob[40:72], "big"),
            ec.SECP256R1(),
        ).public_key()
        return public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def ensure_key(self, endpoint_id: str) -> DevicePublicIdentity:
        del endpoint_id
        result = self._run("ensure")
        self._require_hardware_result(result)
        public_pem = self._public_pem(result.get("public_key_blob"))
        return DevicePublicIdentity(
            provider=self.provider_name,
            public_key_pem=public_pem,
            key_thumbprint=public_key_thumbprint(public_pem),
            hardware_backed=True,
        )

    def sign(self, payload: bytes) -> bytes:
        result = self._run("sign", bytes(payload))
        self._require_hardware_result(result)
        try:
            signature = base64.b64decode(str(result.get("signature")), validate=True)
        except (ValueError, TypeError) as exc:
            raise DeviceKeyError("Windows TPM returned an invalid signature") from exc
        if len(signature) == 64:
            return utils.encode_dss_signature(
                int.from_bytes(signature[:32], "big"),
                int.from_bytes(signature[32:], "big"),
            )
        try:
            utils.decode_dss_signature(signature)
        except ValueError as exc:
            raise DeviceKeyError("Windows TPM returned an invalid signature") from exc
        return signature

    def status(self) -> DeviceKeyStatus:
        supported, detail = self._supported()
        if not supported:
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
                signed_helper=False,
                detail=str(exc),
            )
        verified = self._has_hardware_evidence(result)
        key_exists = result.get("exists") is True
        return DeviceKeyStatus(
            provider=self.provider_name,
            available=verified,
            hardware_backed=verified,
            signed_helper=bool(
                self._helper is not None
                and self._signature_verifier(self._helper)
            ),
            detail=(
                "TPM-ready Microsoft Platform Crypto Provider; device key "
                + ("present" if key_exists else "not created")
                if verified
                else "Windows TPM hardware evidence is unavailable"
            ),
        )

    def destroy(self) -> None:
        result = self._run("destroy")
        self._require_hardware_result(result)
