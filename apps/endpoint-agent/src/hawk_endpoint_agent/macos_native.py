"""Bounded managed macOS Endpoint Security/Network Extension glue.

This module deliberately treats native state as evidence.  It does not launch
shells, accept executable paths from policy, or infer child-process coverage
from process names or mutable environment variables.
"""

from __future__ import annotations

import hashlib
import base64
import binascii
import json
import os
import platform
import plistlib
import re
import stat
import struct
import subprocess
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


MAX_POLICY_BYTES = 2 * 1024 * 1024
HOST_BUNDLE_ID = "ai.hawk.endpoint.host"
EXTENSION_BUNDLE_IDS = (
    "ai.hawk.endpoint.endpoint-security",
    "ai.hawk.endpoint.content-filter",
    "ai.hawk.endpoint.managed-routing",
)
_COMPONENT_DOMAIN = b"hawk.macos-component-set.v1\0"
_MONITOR_SCENARIOS = frozenset({
    "file", "process", "child", "grandchild", "domain", "direct_ip", "quic", "localhost",
})
_ENFORCE_SCENARIOS = frozenset({
    "file_allow", "file_deny", "process_allow", "process_deny_nonexecution",
    "child_deny_nonexecution", "grandchild_deny_nonexecution",
    "domain_deny_nontransfer", "direct_ip_deny_nontransfer",
    "quic_deny_nontransfer", "localhost_deny_nontransfer",
})
_ACCEPTANCE_FIELDS = {
    "schema", "version", "tenant_id", "device_id", "policy_digest", "policy_epoch",
    "component_set_digest", "team_id", "bundle_ids", "os_build",
    "tested_at_unix_seconds", "issued_at_unix_seconds", "expires_at_unix_seconds",
    "monitor_observations", "enforce_results",
}


def macos_component_set_digest(records: Sequence[Mapping[str, Any]]) -> str:
    """Bind exact installed component executable bytes, IDs, and versions."""
    identifiers = {HOST_BUNDLE_ID, *EXTENSION_BUNDLE_IDS}
    if (len(records) != 4 or {row.get("bundle_id") for row in records} != identifiers):
        raise ValueError("component set is incomplete or duplicated")
    canonical: list[dict[str, str]] = []
    for row in records:
        if set(row) != {"bundle_id", "version", "bundle_version", "sha256"}:
            raise ValueError("component evidence schema is invalid")
        if (not isinstance(row["version"], str) or not row["version"] or
                not isinstance(row["bundle_version"], str) or not row["bundle_version"] or
                not isinstance(row["sha256"], str) or
                re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is None):
            raise ValueError("component evidence is invalid")
        canonical.append(dict(row))
    encoded = json.dumps(sorted(canonical, key=lambda row: row["bundle_id"]),
                         sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(_COMPONENT_DOMAIN + encoded).hexdigest()


def verify_macos_target_acceptance(
    envelope: Mapping[str, Any], *, trusted_public_keys: Mapping[str, bytes],
    tenant_id: str, device_id: str, policy_digest: str, policy_epoch: int,
    component_set_digest: str, team_id: str, os_build: str,
    now_unix_seconds: int | None = None,
) -> dict[str, Any]:
    """Verify short-lived external test evidence against this installed Mac."""
    if not isinstance(envelope, dict) or set(envelope) != {
        "key_id", "algorithm", "payload", "signature",
    } or envelope.get("algorithm") != "Ed25519":
        raise ValueError("target acceptance envelope is invalid")
    payload = envelope.get("payload")
    key_id = envelope.get("key_id")
    if not isinstance(key_id, str):
        raise ValueError("target acceptance key ID is invalid")
    key = trusted_public_keys.get(key_id)
    if (not isinstance(payload, dict) or set(payload) != _ACCEPTANCE_FIELDS or
            not isinstance(key, bytes) or len(key) != 32):
        raise ValueError("target acceptance schema or signer is invalid")
    try:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("target acceptance payload is invalid") from exc
    if len(canonical) > 16 * 1024:
        raise ValueError("target acceptance is oversized")
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
        if len(signature) != 64:
            raise ValueError("target acceptance signature length is invalid")
        Ed25519PublicKey.from_public_bytes(key).verify(signature, canonical)
    except (ValueError, TypeError, binascii.Error, InvalidSignature) as exc:
        raise ValueError("target acceptance signature is invalid") from exc
    if (payload["schema"] != "hawk.macos-endpoint-control-acceptance" or
            payload["version"] != 1 or payload["tenant_id"] != tenant_id or
            payload["device_id"] != device_id or payload["policy_digest"] != policy_digest or
            payload["policy_epoch"] != policy_epoch or
            payload["component_set_digest"] != component_set_digest or
            payload["team_id"] != team_id or
            payload["bundle_ids"] != [HOST_BUNDLE_ID, *EXTENSION_BUNDLE_IDS] or
            payload["os_build"] != os_build or
            not isinstance(os_build, str) or not 0 < len(os_build) <= 64):
        raise ValueError("target acceptance binding is invalid")
    now = int(time.time()) if now_unix_seconds is None else now_unix_seconds
    tested = payload["tested_at_unix_seconds"]
    issued = payload["issued_at_unix_seconds"]
    expires = payload["expires_at_unix_seconds"]
    if (any(type(value) is not int or value <= 0 for value in (tested, issued, expires, now)) or
            not issued <= tested <= now < expires or expires - issued > 600 or
            now - tested > 600):
        raise ValueError("target acceptance is stale or has invalid UTC bounds")
    observations = payload["monitor_observations"]
    denials = payload["enforce_results"]
    if (not isinstance(observations, dict) or set(observations) != _MONITOR_SCENARIOS or
            any(type(value) is not bool for value in observations.values()) or
            not isinstance(denials, dict) or set(denials) != _ENFORCE_SCENARIOS or
            any(type(value) is not bool for value in denials.values())):
        raise ValueError("target acceptance scenarios are invalid")
    monitor = all(observations.values())
    child = all(observations[name] for name in (
        "child", "grandchild", "domain", "direct_ip", "quic", "localhost"))
    return {
        "monitor_verified": monitor,
        "enforce_verified": monitor and all(denials.values()),
        "network_child_attribution_verified": child,
        "expires_at_unix_seconds": expires,
        "component_set_digest": component_set_digest,
    }


def verified_managed_envelope_metadata(raw: bytes, config: Mapping[str, Any]) -> dict[str, Any]:
    """Verify the staged native signature before a managed host command runs."""
    if not isinstance(raw, bytes) or config.get("HawkPolicyEnvelope") != raw or len(raw) < 368:
        raise ValueError("managed signed envelope is invalid")
    schema, payload_size, signature_size, reserved = struct.unpack_from("<IIII", raw)
    if (schema != 2 or reserved != 0 or payload_size < 352 or
            not 8 <= signature_size <= 80 or 16 + payload_size + signature_size != len(raw)):
        raise ValueError("managed envelope framing is invalid")
    payload = raw[16:16 + payload_size]
    signature = raw[16 + payload_size:]
    key_bytes = config.get("HawkPolicySigningPublicKeyX963")
    if not isinstance(key_bytes, bytes) or len(key_bytes) != 65 or key_bytes[0] != 4:
        raise ValueError("managed signing key is invalid")
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key_bytes)
        key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
    except (ValueError, InvalidSignature) as exc:
        raise ValueError("managed envelope signature is invalid") from exc
    fields = struct.unpack_from("<IIQQQQIIIIII32s32s40I64s", payload)
    wire, floor, sequence, epoch, issued, expires, rules, permits, identities, resources, destinations, mode = fields[:12]
    expected_size = 352 + rules * 128 + permits * 192 + identities * 32 + (resources + destinations) * 36
    if (wire != 2 or floor != 2 or not sequence or not epoch or
            issued >= expires or rules > 4096 or permits > 4096 or
            identities > 256 or resources > 1024 or destinations > 1024 or
            expected_size != len(payload) or mode not in (1, 2) or
            any(fields[14:54])):
        raise ValueError("managed signed payload is invalid")
    version_bytes = fields[-1].split(b"\0", 1)[0]
    try:
        version = version_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("managed policy version is invalid") from exc
    signed_mode = "enforce" if mode == 2 else "monitor"
    if (config.get("HawkPolicyMode") != signed_mode or
            config.get("HawkPolicyEpoch") != epoch or
            config.get("HawkPolicyVersion") != version or
            config.get("HawkPolicyIssuedAtUnixSeconds") != issued or
            config.get("HawkPolicyExpiresAtUnixSeconds") != expires):
        raise ValueError("managed config differs from signed policy")
    return {"mode": signed_mode, "epoch": epoch, "version": version,
            "issued_at_unix_seconds": issued, "expires_at_unix_seconds": expires}


def _sha256(parts: Sequence[bytes]) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


def macos_path_reference(path: str) -> str:
    """Return the native exact path-context digest; never reads the path."""

    rendered = str(path or "")
    if not rendered.startswith("/") or "\x00" in rendered:
        raise ValueError("macOS resource path must be an absolute UTF-8 path")
    normalized = os.path.normpath(rendered).encode("utf-8")
    # HawkHashPathContext hashes domain including its NUL, the non-truncated
    # marker, then the ES token's uint64 byte length and exact UTF-8 bytes.
    return _sha256(
        (
            b"hawk.macos.path-context.v1\0",
            struct.pack("<?Q", False, len(normalized)),
            normalized,
        )
    ).hex()


def macos_destination_reference(
    host: str,
    port: int,
    protocol: int | str,
    family: int | str,
) -> str:
    """Return the native normalized host/IP + port/protocol/family digest."""

    rendered = str(host or "").strip()
    if rendered.startswith("[") and rendered.endswith("]"):
        rendered = rendered[1:-1]
    if rendered.endswith("."):
        rendered = rendered[:-1]
    if not rendered or len(rendered.encode("utf-8")) > 255:
        raise ValueError("destination host is invalid")
    rendered = rendered.casefold()
    if any(character not in "abcdefghijklmnopqrstuvwxyz0123456789.-:%" for character in rendered):
        raise ValueError("destination host is invalid")
    try:
        port_value = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError("destination port is invalid") from exc
    if not 1 <= port_value <= 65535:
        raise ValueError("destination port is invalid")
    if isinstance(protocol, str):
        protocol = {"tcp": 6, "udp": 17}.get(protocol.casefold()) if not protocol.isdigit() else int(protocol)
    if isinstance(family, str):
        family = {"ipv4": 2, "ipv6": 30}.get(family.casefold()) if not family.isdigit() else int(family)
    if protocol is None or family is None:
        raise ValueError("destination protocol or family is invalid")
    protocol_value = int(protocol)
    family_value = int(family)
    encoded = rendered.encode("utf-8")
    return _sha256(
        (
            b"hawk.macos.network-destination.v1\0",
            struct.pack("<Q", len(encoded)),
            encoded,
            struct.pack("<Hii", port_value, protocol_value, family_value),
        )
    ).hex()


def macos_code_identity_reference(
    team_id: str,
    signing_id: str,
    cdhash: bytes | str,
    platform_binary: bool,
) -> str:
    """Hash the stable signed identity tuple used by native providers."""

    team = str(team_id or "").encode("utf-8")
    signing = str(signing_id or "").encode("utf-8")
    digest = bytes.fromhex(cdhash) if isinstance(cdhash, str) else bytes(cdhash)
    if not team or not signing or len(team) > 16384 or len(signing) > 16384 or len(digest) != 20:
        raise ValueError("macOS code identity tuple is invalid")
    return _sha256(
        (
            b"hawk.macos.code-identity.v1\0",
            struct.pack("<Q", len(team)),
            team,
            struct.pack("<Q", len(signing)),
            signing,
            digest,
            struct.pack("<?", bool(platform_binary)),
        )
    ).hex()


def _safe_json_output(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or len(value) > 64:
        raise ValueError("native host response is not bounded JSON")
    rendered = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if len(rendered.encode("utf-8")) > 64 * 1024:
        raise ValueError("native host response is oversized")
    return dict(value)


@dataclass(slots=True)
class MacOSNativeStatus:
    schema: str = "hawk.macos-native-status"
    mode: str = "disarmed"
    policy_current: bool = False
    policy_signed: bool = False
    policy_digest: str | None = None
    policy_epoch: int | None = None
    policy_version: str | None = None
    issued_at_unix_seconds: int | None = None
    expires_at_unix_seconds: int | None = None
    team_id: str | None = None
    file_control: str = "unknown"
    process_control: str = "unknown"
    network_control: str = "unknown"
    target_acceptance: bool = False
    network_child_attribution_verified: bool = False
    accepted_artifact_sha256: str | None = None
    acceptance_expires_at_unix_seconds: int | None = None
    healthy: bool = False
    reason_codes: list[str] = field(default_factory=lambda: ["native_status_unavailable"])

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "MacOSNativeStatus":
        required = {
            "schema", "mode", "policy_current", "policy_signed", "healthy",
            "policy_digest", "policy_epoch", "policy_version", "team_id",
            "issued_at_unix_seconds", "expires_at_unix_seconds",
            "host_bundle_id", "endpoint_security_bundle_id",
            "content_filter_bundle_id", "routing_bundle_id",
            "file_control", "process_control", "network_control", "reason_codes",
        }
        if not required.issubset(value) or value.get("schema") != "hawk.macos-native-status":
            raise ValueError("native status schema mismatch")
        mode = str(value.get("mode") or "")
        if mode not in {"disarmed", "monitor", "enforce"}:
            raise ValueError("native mode is invalid")
        if not all(type(value[field]) is bool for field in ("policy_current", "policy_signed", "healthy")):
            raise ValueError("native boolean state is invalid")
        digest = value["policy_digest"]
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("native policy digest is invalid")
        if any(value.get(field) != expected for field, expected in (
            ("host_bundle_id", HOST_BUNDLE_ID),
            ("endpoint_security_bundle_id", EXTENSION_BUNDLE_IDS[0]),
            ("content_filter_bundle_id", EXTENSION_BUNDLE_IDS[1]),
            ("routing_bundle_id", EXTENSION_BUNDLE_IDS[2]),
        )):
            raise ValueError("native bundle identity mismatch")
        team = value["team_id"]
        if not isinstance(team, str) or re.fullmatch(r"[A-Z0-9]{10}", team) is None:
            raise ValueError("native Team ID is invalid")
        epoch = value["policy_epoch"]
        issued = value["issued_at_unix_seconds"]
        expires = value["expires_at_unix_seconds"]
        if any(type(item) is not int or item <= 0 for item in (epoch, issued, expires)) or issued >= expires:
            raise ValueError("native policy timing or epoch is invalid")
        if value["file_control"] not in {"verified", "unknown"} or value["process_control"] not in {"verified", "unknown"} or value["network_control"] not in {"verified", "active_unverified", "unknown"}:
            raise ValueError("native control state is invalid")
        reasons = value["reason_codes"]
        if not isinstance(reasons, list) or len(reasons) > 32 or any(
            not isinstance(reason, str) or len(reason) > 128 for reason in reasons
        ):
            raise ValueError("native reason codes are invalid")
        status = cls(
            mode=mode,
            policy_current=value.get("policy_current") is True,
            policy_signed=value.get("policy_signed") is True,
            policy_digest=digest,
            policy_epoch=epoch,
            policy_version=str(value["policy_version"]) if value.get("policy_version") else None,
            issued_at_unix_seconds=issued,
            expires_at_unix_seconds=expires,
            team_id=team,
            file_control=str(value.get("file_control") or "unknown"),
            process_control=str(value.get("process_control") or "unknown"),
            network_control=str(value.get("network_control") or "unknown"),
            target_acceptance=False,
            network_child_attribution_verified=value.get("network_child_attribution_verified") is True,
            healthy=value.get("healthy") is True,
            reason_codes=list(reasons),
        )
        return status


class MacOSNativeFloorManager:
    """Reconcile a signed local policy through the fixed host command."""

    def __init__(
        self, *, policy_path: str, config_path: str, host_app_path: str,
        acceptance_path: str | None = None,
        acceptance_public_keys: Mapping[str, bytes] | None = None,
        tenant_id: str | None = None, device_id: str | None = None,
        policy_public_keys: Mapping[str, bytes] | None = None, routing_provider: Any = None,
    ) -> None:
        self.policy_path = Path(policy_path).expanduser()
        self.config_path = Path(config_path).expanduser()
        self.host_app_path = Path(host_app_path).expanduser()
        self.acceptance_path = Path(acceptance_path).expanduser() if acceptance_path else None
        self.acceptance_public_keys = dict(acceptance_public_keys or {})
        self.tenant_id = tenant_id
        self.device_id = device_id
        self.policy_public_keys = dict(policy_public_keys or {})
        self.routing_provider = routing_provider
        self._applied_config_digest: str | None = None
        self._routing_expires = 0
        self._last_status = MacOSNativeStatus()

    @property
    def status(self) -> MacOSNativeStatus:
        return self._last_status

    def _read_policy(self) -> tuple[bytes, str]:
        raw = self._read_protected_file(self.policy_path, MAX_POLICY_BYTES)
        if not raw or len(raw) > MAX_POLICY_BYTES:
            raise ValueError("managed policy is missing or oversized")
        return raw, hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _read_protected_file(path: Path, maximum: int) -> bytes:
        if not path.is_absolute() or path.is_symlink():
            raise ValueError("managed path must be absolute and not a symlink")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or
                    metadata.st_mode & 0o022 or not 0 < metadata.st_size <= maximum):
                raise ValueError("managed file ownership or mode is invalid")
            raw = os.read(descriptor, maximum + 1)
            if len(raw) != metadata.st_size:
                raise ValueError("managed file changed while reading")
            return raw
        finally:
            os.close(descriptor)

    def _read_config(self) -> dict[str, Any]:
        raw = self._read_protected_file(self.config_path, 2_200_000)
        try:
            value = plistlib.loads(raw)
        except (ValueError, TypeError) as exc:
            raise ValueError("managed config plist is invalid") from exc
        if not isinstance(value, dict) or len(value) > 32:
            raise ValueError("managed config is invalid")
        return value

    def _verify_host_signature(self, team: str) -> str:
        if self.host_app_path.is_symlink() or not self.host_app_path.is_absolute():
            raise ValueError("managed host app path is invalid")
        components = {HOST_BUNDLE_ID: self.host_app_path}
        extension_root = self.host_app_path / "Contents" / "Library" / "SystemExtensions"
        for extension in extension_root.glob("*.systemextension"):
            if extension.is_symlink():
                raise ValueError("embedded extension may not be a symlink")
            info_path = extension / "Contents" / "Info.plist"
            try:
                info = plistlib.loads(info_path.read_bytes())
            except (OSError, ValueError, TypeError) as exc:
                raise ValueError("embedded extension Info.plist is invalid") from exc
            identifier = info.get("CFBundleIdentifier")
            if identifier not in EXTENSION_BUNDLE_IDS or identifier in components:
                raise ValueError("embedded extension identity is invalid")
            components[identifier] = extension
        if set(components) != {HOST_BUNDLE_ID, *EXTENSION_BUNDLE_IDS}:
            raise ValueError("embedded extension set is incomplete")
        records: list[dict[str, str]] = []
        host_version: str | None = None
        for identifier, path in components.items():
            verified = subprocess.run(
                ["/usr/bin/codesign", "--verify", "--strict", str(path)],
                capture_output=True, check=False, timeout=8,
            )
            if verified.returncode != 0:
                raise ValueError("native component signature verification failed")
            detail = subprocess.run(
                ["/usr/bin/codesign", "-dv", "--verbose=4", str(path)],
                capture_output=True, check=False, timeout=8,
            )
            rendered = (detail.stdout + detail.stderr).decode("utf-8", errors="replace")
            if (detail.returncode != 0 or f"Identifier={identifier}" not in rendered or
                    f"TeamIdentifier={team}" not in rendered or
                    re.search(r"flags=.*\(runtime\)", rendered) is None):
                raise ValueError("native component Team ID or hardened runtime is invalid")
            info = plistlib.loads((path / "Contents/Info.plist").read_bytes())
            executable_name = info.get("CFBundleExecutable")
            version = info.get("CFBundleShortVersionString")
            bundle_version = info.get("CFBundleVersion")
            if (not isinstance(executable_name, str) or not executable_name or
                    not isinstance(version, str) or not version or
                    not isinstance(bundle_version, str) or not bundle_version):
                raise ValueError("native component metadata is invalid")
            if identifier == HOST_BUNDLE_ID:
                host_version = version
            elif version != host_version:
                raise ValueError("native component version mismatch")
            executable = path / "Contents/MacOS" / executable_name
            if not executable.is_file() or executable.is_symlink():
                raise ValueError("native component executable is invalid")
            records.append({
                "bundle_id": identifier, "version": version,
                "bundle_version": bundle_version,
                "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            })
        return macos_component_set_digest(records)

    @staticmethod
    def _os_build() -> str:
        if platform.system() != "Darwin":
            raise ValueError("target acceptance requires macOS")
        result = subprocess.run(["/usr/bin/sw_vers", "-buildVersion"],
                                capture_output=True, check=False, timeout=5)
        value = result.stdout.decode("ascii", errors="strict").strip()
        if result.returncode or not value or len(value) > 64:
            raise ValueError("macOS build version is unavailable")
        return value

    def _apply_acceptance(self, status: MacOSNativeStatus, component_digest: str | None) -> None:
        if (self.acceptance_path is None or not self.acceptance_public_keys or
                not self.tenant_id or not self.device_id or not component_digest or
                not status.policy_digest or not status.policy_epoch or not status.team_id):
            status.reason_codes = list(dict.fromkeys([
                *status.reason_codes, "target_acceptance_unavailable",
            ]))[:32]
            return
        try:
            raw = self._read_protected_file(self.acceptance_path, 16 * 1024)
            envelope = json.loads(raw.decode("utf-8"))
            accepted = verify_macos_target_acceptance(
                envelope, trusted_public_keys=self.acceptance_public_keys,
                tenant_id=self.tenant_id, device_id=self.device_id,
                policy_digest=status.policy_digest, policy_epoch=status.policy_epoch,
                component_set_digest=component_digest, team_id=status.team_id,
                os_build=self._os_build(),
            )
            if not accepted["monitor_verified"]:
                raise ValueError("target monitor scenarios incomplete")
        except (OSError, ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError,
                subprocess.TimeoutExpired) as exc:
            status.reason_codes = list(dict.fromkeys([
                *status.reason_codes, f"target_acceptance_unverified:{type(exc).__name__}",
            ]))[:32]
            return
        status.accepted_artifact_sha256 = component_digest
        status.acceptance_expires_at_unix_seconds = accepted["expires_at_unix_seconds"]
        status.network_child_attribution_verified = accepted["network_child_attribution_verified"]
        if (status.network_control == "active_unverified" and
                status.network_child_attribution_verified):
            status.network_control = "verified"
        status.target_acceptance = status.mode == "enforce" and accepted["enforce_verified"]
        status.reason_codes = [code for code in status.reason_codes if code not in {
            "network_child_attribution_unverified", "target_acceptance_unverified",
        }]

    def _invoke(self, command: str, request: bytes | None = None) -> dict[str, Any]:
        if command not in {"status", "apply-managed-monitor-policy", "apply-managed-enforce-policy"}:
            raise ValueError("unsupported managed command")
        if not self.host_app_path.is_absolute() or "\x00" in str(self.host_app_path):
            raise ValueError("host application path is invalid")
        # The signed host is a fixed app bundle. No shell, module, or script
        # material is accepted from policy or environment.
        executable = self.host_app_path / "Contents" / "MacOS" / "HawkEndpointHost"
        completed = subprocess.run(
            [str(executable), command],
            capture_output=True,
            check=False,
            timeout=8,
            input=request,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"native_host_{command}_failed")
        try:
            return _safe_json_output(json.loads(completed.stdout.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("native host returned malformed JSON") from exc

    def _managed_status(self, command: str, *, snapshot: tuple | None = None,
                        request: bytes | None = None) -> MacOSNativeStatus:
        if snapshot is None:
            raw, digest = self._read_policy()
            config = self._read_config()
        else:
            raw, digest, config = snapshot
        if config.get("HawkPolicyEnvelope") != raw:
            raise ValueError("managed config and policy digest mismatch")
        if any(config.get(field) != expected for field, expected in (
            ("HawkHostBundleIdentifier", HOST_BUNDLE_ID),
            ("HawkEndpointSecurityBundleIdentifier", EXTENSION_BUNDLE_IDS[0]),
            ("HawkContentFilterBundleIdentifier", EXTENSION_BUNDLE_IDS[1]),
            ("HawkRoutingBundleIdentifier", EXTENSION_BUNDLE_IDS[2]),
        )):
            raise ValueError("managed config bundle identity mismatch")
        team = config.get("HawkTeamIdentifier")
        if not isinstance(team, str) or re.fullmatch(r"[A-Z0-9]{10}", team) is None:
            raise ValueError("managed Team ID is invalid")
        component_digest = self._verify_host_signature(team)
        value = self._invoke(command, request) if request is not None else self._invoke(command)
        if value.get("policy_digest") != digest:
            raise ValueError("native policy digest mismatch")
        status = MacOSNativeStatus.from_mapping(value)
        if status.network_control == "verified":
            status.network_control = "active_unverified"
        if (status.team_id != team or status.policy_epoch != config.get("HawkPolicyEpoch") or
                status.mode != config.get("HawkPolicyMode") or
                status.policy_version != config.get("HawkPolicyVersion") or
                status.issued_at_unix_seconds != config.get("HawkPolicyIssuedAtUnixSeconds") or
                status.expires_at_unix_seconds != config.get("HawkPolicyExpiresAtUnixSeconds")):
            raise ValueError("native policy metadata mismatch")
        self._apply_acceptance(status, component_digest)
        self._last_status = status
        return status

    def read_status(self) -> MacOSNativeStatus:
        return self._managed_status("status")

    def _routing_trust_root(self) -> bytes:
        root = self.host_app_path / "Contents/Library/SystemExtensions"
        matches = []
        for extension in root.glob("*.systemextension"):
            info = plistlib.loads((extension / "Contents/Info.plist").read_bytes())
            if info.get("CFBundleIdentifier") == EXTENSION_BUNDLE_IDS[2]:
                matches.append(base64.b64decode(info["HawkRoutingTrustRootPublicKeyX963Base64"], validate=True))
        if len(matches) != 1 or len(matches[0]) != 65:
            raise ValueError("routing trust root is unavailable")
        return matches[0]

    def _issue_routing(self, config: dict, scope: dict, now: int) -> tuple[dict, int]:
        from .macos_routing import (MacRoutingReceiptIssuer, issue_authorized_routing_configuration,
                                   verify_routing_provider_configuration)
        root = self._routing_trust_root()
        if root != config.get("HawkRoutingTrustRootPublicKeyX963") or self.routing_provider is None:
            raise ValueError("routing signing authority unavailable")
        issuer = MacRoutingReceiptIssuer(provider=self.routing_provider,
            identity=self.routing_provider.ensure_key(self.device_id),
            broker_key_authorization=config["HawkRoutingBrokerKeyAuthorization"],
            broker_key_authorization_signature_der=config["HawkRoutingBrokerKeyAuthorizationSignatureDER"],
            trust_root_public_key_x963=root, clock=lambda: now, require_hardware_backed=True)
        provider = issue_authorized_routing_configuration(issuer, scope, now_unix_seconds=now)
        if base64.b64decode(provider["HawkRoutingReceiptPublicKeyX963"], validate=True) != config["HawkRoutingReceiptPublicKeyX963"]:
            raise ValueError("routing broker identity mismatch")
        expiry = verify_routing_provider_configuration(provider, scope=scope,
            trust_root_public_key_x963=root, now_unix_seconds=now)
        return provider, expiry

    def reconcile(self, *, mode: str) -> MacOSNativeStatus:
        if mode not in {"monitor", "enforce"}:
            raise ValueError("unsupported macOS native mode")
        try:
            from .macos_policy_compiler import verify_managed_routing_authority
            raw, digest = self._read_policy()
            config = self._read_config()
            signed = verified_managed_envelope_metadata(raw, config)
            if signed["mode"] != mode:
                raise ValueError("central control-plane mode differs from signed managed policy")
            now = int(time.time())
            scope = verify_managed_routing_authority(config, trusted_public_keys=self.policy_public_keys,
                tenant_id=self.tenant_id, device_id=self.device_id, now=datetime.fromtimestamp(now, UTC))
            self._verify_host_signature(config["HawkTeamIdentifier"])
            configuration_data = plistlib.dumps(config, fmt=plistlib.FMT_BINARY, sort_keys=True)
            fingerprint = hashlib.sha256(configuration_data).hexdigest()
            request = None
            command = "status"
            expiry = self._routing_expires
            if fingerprint != self._applied_config_digest or expiry - now <= 30:
                routing, expiry = self._issue_routing(config, scope, now)
                request = plistlib.dumps({"schema": "hawk.macos-managed-apply-request", "version": 1,
                    "expected_policy_sha256": digest, "managed_configuration_data": configuration_data,
                    "routing_provider_configuration": routing}, fmt=plistlib.FMT_BINARY, sort_keys=True)
                if len(request) > 2_500_000:
                    raise ValueError("managed apply request oversized")
                command = f"apply-managed-{mode}-policy"
            status = self._managed_status(command, snapshot=(raw, digest, config), request=request)
            if status.mode != mode:
                raise ValueError("native mode mismatch")
            if request is not None and status.policy_current:
                self._applied_config_digest = fingerprint
                self._routing_expires = expiry
            return status
        except Exception as exc:  # noqa: BLE001 - bounded health state
            retained = self._last_status
            retained.reason_codes = list(dict.fromkeys([*retained.reason_codes, type(exc).__name__]))[:32]
            retained.healthy = False
            retained.policy_current = False
            self._applied_config_digest = None
            return retained

    def posture(self) -> dict[str, Any]:
        status = self._last_status
        now = int(time.time())
        current = bool(status.policy_current and status.policy_signed and
            status.issued_at_unix_seconds is not None and
            status.expires_at_unix_seconds is not None and
            status.issued_at_unix_seconds <= now + 60 and
            now < status.expires_at_unix_seconds)
        acceptance_current = bool(status.acceptance_expires_at_unix_seconds is not None and
                                  now < status.acceptance_expires_at_unix_seconds)
        controls_verified = all(value == "verified" for value in (
            status.file_control, status.process_control, status.network_control
        ))
        if self._routing_expires and now >= self._routing_expires:
            controls_verified = False
        if current and acceptance_current and status.healthy and controls_verified and status.mode == "monitor":
            display_state = "Monitoring"
        elif current and acceptance_current and status.healthy and controls_verified and status.mode == "enforce" and status.target_acceptance:
            display_state = "Protected"
        else:
            display_state = "Needs attention"
        return {
            "display_state": display_state,
            "mode": status.mode,
            "policy_current": current,
            "policy_signed": status.policy_signed,
            "policy_digest": status.policy_digest,
            "policy_epoch": status.policy_epoch,
            "policy_version": status.policy_version,
            "controls": {
                "file_control": status.file_control,
                "process_control": status.process_control,
                "network_control": status.network_control,
            },
            "target_acceptance": status.target_acceptance,
            "network_child_attribution_verified": status.network_child_attribution_verified,
            "healthy": status.healthy,
            "reason_codes": list(status.reason_codes),
        }

    def runtime_receipt_payload(self, *, tenant_id: str, device_id: str) -> dict[str, Any]:
        status = self._last_status
        posture = self.posture()
        if (not tenant_id or not device_id or not posture["policy_current"] or
                status.policy_digest is None or status.policy_epoch is None or
                status.team_id is None or status.expires_at_unix_seconds is None or
                status.issued_at_unix_seconds is None):
            raise ValueError("current signed native authority is unavailable")
        now = datetime.now(UTC)
        expiry = min(now + timedelta(seconds=60),
                     datetime.fromtimestamp(status.expires_at_unix_seconds, UTC))
        if self._routing_expires:
            expiry = min(expiry, datetime.fromtimestamp(self._routing_expires, UTC))
        acceptance_current = bool(status.acceptance_expires_at_unix_seconds is not None and
                                  int(now.timestamp()) < status.acceptance_expires_at_unix_seconds)
        if acceptance_current:
            expiry = min(expiry, datetime.fromtimestamp(
                status.acceptance_expires_at_unix_seconds, UTC))
        if expiry <= now:
            raise ValueError("signed native authority has expired")
        controls: dict[str, dict[str, Any]] = {}
        for name in ("file_control", "process_control", "network_control"):
            verified = status.healthy and getattr(status, name) == "verified"
            if name == "network_control":
                verified = verified and acceptance_current and status.network_child_attribution_verified
            controls[name] = {
                "status": "inline" if verified else "unknown",
                "verification": "verified" if verified else "unverified",
                "health": "healthy" if verified else "unknown",
                "evidence_refs": [f"native:policy:{status.policy_digest}"] if verified else [],
            }
        controls["semantic_proxy"] = {
            "status": "unavailable", "verification": "unverified",
            "health": "unknown", "evidence_refs": [],
        }
        return {
            "schema": "hawk.endpoint-floor-runtime-receipt", "version": 1,
            "tenant_id": tenant_id, "device_id": device_id,
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": expiry.isoformat().replace("+00:00", "Z"),
            "controls": controls,
            "local_policy": {
                "status": "active", "freshness": "fresh",
                "policy_version": status.policy_version,
                "signature_verified": status.policy_signed,
                "evidence_refs": [f"native:policy:{status.policy_digest}"],
            },
            "native_authority": {
                "mode": status.mode, "policy_digest": status.policy_digest,
                "policy_epoch": status.policy_epoch, "team_id": status.team_id,
                "bundle_ids": [HOST_BUNDLE_ID, *EXTENSION_BUNDLE_IDS],
                "issued_at_unix_seconds": status.issued_at_unix_seconds,
                "expires_at_unix_seconds": status.expires_at_unix_seconds,
                "artifact_sha256": status.accepted_artifact_sha256 if acceptance_current else "",
                "target_acceptance_artifact_sha256": status.accepted_artifact_sha256 if
                    acceptance_current and status.target_acceptance else "",
                "target_acceptance_verified": acceptance_current and status.target_acceptance,
                "network_child_attribution_verified": acceptance_current and
                    status.network_child_attribution_verified,
            },
            "reason_codes": list(status.reason_codes),
            "blind_spots": ([] if acceptance_current else
                            ["target_acceptance_unverified", "network_child_attribution_unverified"]),
        }
