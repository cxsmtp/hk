"""Verify and compile binary-scoped Hawk policies for the Windows driver."""

from __future__ import annotations

import hashlib
import ctypes
import ipaddress
import json
import os
import re
import struct
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from ..endpoint_floor.contracts import EndpointPrimitive
from ..endpoint_floor.local_policy import EndpointPolicyFastPath, canonical_policy_bytes
from .kernel_channel import HAWK_WINDOWS_MAX_POLICY_BYTES, WindowsKernelChannel


_MAGIC = 0x4B574148
_VERSION = 4
_HEADER = struct.Struct("<IIIIQQQ32s32s32sBB6x64s40I")
_RULE = struct.Struct("<QIII?32s3xI64s4x")
_PERMIT_MAGIC = 0x54504B48
_PERMIT_VERSION = 2
_PERMIT_HEADER = struct.Struct("<IIIIQQQQ32s32s32s16sBB6x")
_PERMIT = struct.Struct("<B3xIQQI4x32s32s32s32s32s")
_CANONICAL_ACTION = struct.Struct("<32sI4xQQ32s32s32s32s32s")
_PROCESS_LAUNCH = struct.Struct("<40s32sII32s")
_FILE_IDENTITY = struct.Struct("<40sQIIQ")
_IDENTITY = re.compile(r"^windows_path_sha256:([0-9a-f]{64})$")
_PRIMITIVES = {primitive.value: index for index, primitive in enumerate(EndpointPrimitive)}
_RESOURCE_CLASSIFICATIONS = {
    "public": 0x00000001,
    "internal": 0x00000002,
    "confidential": 0x00000004,
    "restricted": 0x00000008,
    "credential": 0x00000010,
    "source_code": 0x00000020,
    "unknown": 0x80000000,
}
_DESTINATION_CLASSIFICATIONS = {
    "approved": 0x00000001,
    "internal": 0x00000002,
    "external": 0x00000004,
    "unknown": 0x80000000,
}
_ACTIONS = {
    "allow": 0,
    "block": 1,
    "require_preauthorized_permit": 2,
}
_WINDOWS_KERNEL_MATCH_FIELDS = {
    "primitives",
    "resource_classifications",
    "destination_classifications",
    "binary_identities",
}
_WINDOWS_KERNEL_PRIMITIVES = {
    "file_open",
    "file_read",
    "file_write",
    "file_create",
    "file_truncate",
    "file_rename",
    "file_delete",
    "file_execute",
    "file_metadata_change",
    "process_execute",
    "process_child_create",
    "network_connect",
}
_WINDOWS_KERNEL_PERMIT_PRIMITIVES = {
    # Only ALE TCP/UDP destination binding currently reaches a stable,
    # pre-consequence Windows authorization point. File opens execute in a
    # minifilter pre-create callback where the target file is not yet open, and
    # process launch material still lacks a target image-generation binding.
    # Reject those permits before they can consume replay capacity.
    "network_connect",
}


def windows_path_identity(path: str) -> str:
    rendered = str(path or "")
    if not rendered or "\x00" in rendered or len(rendered) > 32767:
        raise ValueError("Windows governed binary path is invalid")
    if any(ord(character) > 0x7F for character in rendered):
        raise ValueError(
            "Windows governed binary identity requires an ASCII canonical path"
        )
    encoded = bytearray(rendered.encode("utf-16-le", errors="surrogatepass"))
    # This exactly mirrors the driver's DISPATCH_LEVEL-safe fold: only ASCII
    # lowercase UTF-16 code units are uppercased. Non-ASCII path code units are
    # matched exactly, avoiding pageable Windows NLS calls in WFP callbacks.
    for offset in range(0, len(encoded), 2):
        if encoded[offset + 1] == 0 and 0x61 <= encoded[offset] <= 0x7A:
            encoded[offset] -= 0x20
    digest = hashlib.sha256(encoded).hexdigest()
    return f"windows_path_sha256:{digest}"


class WindowsPathResolver(Protocol):
    def resolve(self, path: str) -> str: ...


class _Win32PathResolver:
    """Resolve a Win32 path to the exact NT namespace used by process callbacks."""

    def resolve(self, path: str) -> str:
        if sys.platform != "win32":
            raise RuntimeError("Windows binary identity resolution is unavailable")
        rendered = str(path or "")
        if not rendered or "\x00" in rendered:
            raise ValueError("Windows governed binary path is invalid")
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = (
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        )
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.GetFinalPathNameByHandleW.argtypes = (
            wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
        )
        kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        handle = kernel32.CreateFileW(
            rendered,
            0,  # metadata-only handle
            0x00000007,  # FILE_SHARE_READ | WRITE | DELETE
            None,
            3,  # OPEN_EXISTING
            0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
            None,
        )
        if handle in (None, wintypes.HANDLE(-1).value):
            raise OSError(ctypes.get_last_error(), "Windows binary path unavailable")
        try:
            required = kernel32.GetFinalPathNameByHandleW(
                handle, None, 0, 0x00000002  # VOLUME_NAME_NT
            )
            if required <= 1 or required > 32767:
                raise OSError(
                    ctypes.get_last_error(), "Windows binary path resolution failed"
                )
            buffer = ctypes.create_unicode_buffer(required + 1)
            observed = kernel32.GetFinalPathNameByHandleW(
                handle, buffer, len(buffer), 0x00000002
            )
            if observed == 0 or observed >= len(buffer):
                raise OSError(
                    ctypes.get_last_error(), "Windows binary path resolution failed"
                )
            canonical = buffer.value
            if not canonical.startswith("\\Device\\"):
                raise RuntimeError("Windows binary path was not an NT device path")
            return canonical
        finally:
            kernel32.CloseHandle(handle)


def windows_binary_identity(
    path: str,
    *,
    resolver: WindowsPathResolver | None = None,
) -> str:
    return windows_path_identity((resolver or _Win32PathResolver()).resolve(path))


def windows_kernel_process_launch_hash(
    *,
    target_image_path: str,
    command_line: str,
) -> str:
    """Mirror the driver's secret-free process launch binding.

    The command line is hashed exactly as UTF-16LE and is never persisted in
    the kernel permit. Different interpreter arguments therefore cannot reuse
    one approved launch action. Empty or NUL-bearing command material is
    rejected because it cannot support an exact permit claim.
    """

    rendered_command = str(command_line or "")
    if not rendered_command or "\x00" in rendered_command:
        raise ValueError("Windows process launch command line is invalid")
    encoded_command = rendered_command.encode("utf-16-le", errors="surrogatepass")
    if len(encoded_command) > 65534:
        raise ValueError("Windows process launch command line is invalid")
    target_identity = windows_path_identity(target_image_path)
    target_digest = bytes.fromhex(target_identity.rsplit(":", 1)[1])
    material = _PROCESS_LAUNCH.pack(
        b"hawk.windows.process-launch.v1".ljust(40, b"\0"),
        target_digest,
        len(encoded_command),
        0,
        hashlib.sha256(encoded_command).digest(),
    )
    return hashlib.sha256(material).hexdigest()


def windows_kernel_network_destination(
    *,
    remote_address: str,
    remote_port: int,
    protocol: int,
    remote_interface_index: int,
) -> tuple[str, int]:
    """Build the driver's secret-free WFP destination binding.

    WFP exposes ALE address and port values in host order.  The shared native
    canonicalizer converts them into network-order hash material while keeping
    requestedRights numeric and host-order.  Real WDK/target acceptance remains
    mandatory before the capability is promoted.
    """

    if (
        isinstance(remote_port, bool)
        or not isinstance(remote_port, int)
        or not 1 <= remote_port <= 0xFFFF
        or isinstance(protocol, bool)
        or not isinstance(protocol, int)
        or protocol not in {6, 17}
        or isinstance(remote_interface_index, bool)
        or not isinstance(remote_interface_index, int)
        or not 1 <= remote_interface_index <= 0xFFFFFFFF
    ):
        raise ValueError("Windows network destination is invalid")
    try:
        address = ipaddress.ip_address(str(remote_address))
    except ValueError as exc:
        raise ValueError("Windows network destination is invalid") from exc
    if getattr(address, "scope_id", None):
        raise ValueError("Windows network destination is invalid")

    port_bytes = struct.pack(">H", remote_port)
    material = b"".join(
        (
            b"hawk.windows.network-destination.v3".ljust(40, b"\0"),
            bytes((address.version, protocol)),
            port_bytes,
            struct.pack(">I", remote_interface_index),
            address.packed.ljust(16, b"\0"),
        )
    )
    requested_rights = (
        (address.version << 56)
        | (protocol << 48)
        | remote_port
    )
    return hashlib.sha256(material).hexdigest(), requested_rights


def windows_kernel_file_identity(
    *,
    volume_creation_time: int,
    volume_serial_number: int,
    file_id: int,
) -> str:
    """Mirror the driver's strong volume/file identifier projection.

    This intentionally has no path or kernel-pointer input.  Windows file IDs
    are scoped to a filesystem volume, so the identity binds the queried volume
    creation time and serial number to the queried file reference number.
    """

    values = (volume_creation_time, volume_serial_number, file_id)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        raise ValueError("Windows file identity is invalid")
    if (
        not 1 <= volume_creation_time <= 0x7FFFFFFFFFFFFFFF
        or not 1 <= volume_serial_number <= 0xFFFFFFFF
        or not 1 <= file_id <= 0xFFFFFFFFFFFFFFFF
    ):
        raise ValueError("Windows file identity is invalid")
    material = _FILE_IDENTITY.pack(
        b"hawk.windows.file-identity.v2".ljust(40, b"\0"),
        volume_creation_time,
        volume_serial_number,
        0,
        file_id,
    )
    return hashlib.sha256(material).hexdigest()


def _mask(values: object, mapping: Mapping[str, int], *, label: str) -> int:
    if values is None:
        return 0
    if not isinstance(values, list) or len(values) > 64:
        raise ValueError(f"Windows policy {label} is invalid")
    result = 0
    for value in values:
        try:
            result |= mapping[str(value)]
        except KeyError as exc:
            raise ValueError(f"Windows policy {label} is unsupported") from exc
    return result


def _reference(value: str) -> bytes:
    encoded = str(value).encode("ascii", errors="strict")
    if not encoded or len(encoded) >= 64:
        raise ValueError("Windows policy reference is invalid")
    return encoded + b"\x00" * (64 - len(encoded))


def _business_purpose(value: str | None) -> int:
    if value is None:
        return 0
    result = int.from_bytes(hashlib.sha256(str(value).encode("utf-8")).digest()[:4], "little")
    return result or 1


@dataclass(frozen=True, slots=True)
class CompiledWindowsPolicy:
    blob: bytes
    generation: int
    policy_version: str
    rule_count: int
    valid_for_nanoseconds: int
    policy_sequence: int
    policy_fingerprint: str
    key_id: str


def _exact_hash(value: str, *, field: str, allow_zero: bool = False) -> bytes:
    rendered = str(value or "")
    if not re.fullmatch(r"[0-9a-f]{64}", rendered):
        raise ValueError(f"Windows kernel permit {field} is invalid")
    decoded = bytes.fromhex(rendered)
    if not allow_zero and decoded == bytes(32):
        raise ValueError(f"Windows kernel permit {field} cannot be empty")
    return decoded


@dataclass(frozen=True, slots=True)
class WindowsKernelPermit:
    """Secret-free native projection of one broker-verified permit step."""

    primitive: EndpointPrimitive
    requested_rights: int
    process_instance_hash: str
    stable_resource_identity_hash: str
    destination_reference_hash: str
    canonical_action_hash: str
    permit_digest: str
    expires_at: datetime
    maximum_uses: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.primitive, EndpointPrimitive):
            raise ValueError("Windows kernel permit primitive is invalid")
        if self.primitive.value not in _WINDOWS_KERNEL_PERMIT_PRIMITIVES:
            raise ValueError("Windows kernel permit primitive is unsupported")
        if type(self.requested_rights) is not int or not 1 <= self.requested_rights <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("Windows kernel permit requested rights are invalid")
        if type(self.maximum_uses) is not int or not 1 <= self.maximum_uses <= 64:
            raise ValueError("Windows kernel permit maximum uses are invalid")
        _exact_hash(self.process_instance_hash, field="process instance")
        stable = _exact_hash(
            self.stable_resource_identity_hash,
            field="stable resource",
            allow_zero=True,
        )
        destination = _exact_hash(
            self.destination_reference_hash,
            field="destination",
            allow_zero=True,
        )
        _exact_hash(self.canonical_action_hash, field="canonical action")
        _exact_hash(self.permit_digest, field="digest")
        if self.primitive.value.startswith("file_") and stable == bytes(32):
            raise ValueError("Windows file permit requires stable resource binding")
        if self.primitive in {
            EndpointPrimitive.NETWORK_CONNECT,
            EndpointPrimitive.NETWORK_QUIC,
            EndpointPrimitive.NETWORK_LOCALHOST,
        } and destination == bytes(32):
            raise ValueError("Windows network permit requires destination binding")
        if self.expires_at.tzinfo is None:
            raise ValueError("Windows kernel permit expiry must be timezone-aware")


@dataclass(frozen=True, slots=True)
class CompiledWindowsPermitBatch:
    blob: bytes
    permit_count: int
    policy_generation: int
    policy_sequence: int
    permit_batch_sequence: int
    arm_session_epoch: int
    driver_session_id: str
    policy_fingerprint: str


def windows_kernel_canonical_action_hash(
    *,
    primitive: EndpointPrimitive,
    requested_rights: int,
    policy_epoch: int,
    tenant_id: str,
    device_id: str,
    process_instance_hash: str,
    stable_resource_identity_hash: str,
    destination_reference_hash: str,
) -> str:
    if not isinstance(primitive, EndpointPrimitive) or primitive.value not in _WINDOWS_KERNEL_PRIMITIVES:
        raise ValueError("Windows canonical action primitive is unsupported")
    if type(requested_rights) is not int or not 1 <= requested_rights <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Windows canonical action rights are invalid")
    if type(policy_epoch) is not int or policy_epoch <= 0:
        raise ValueError("Windows canonical action policy epoch is invalid")
    tenant = str(tenant_id or "")
    device = str(device_id or "")
    if not tenant or not device:
        raise ValueError("Windows canonical action scope is invalid")
    material = _CANONICAL_ACTION.pack(
        b"hawk.windows.floor-action.v1".ljust(32, b"\0"),
        _PRIMITIVES[primitive.value],
        requested_rights,
        policy_epoch,
        hashlib.sha256(tenant.encode("utf-8")).digest(),
        hashlib.sha256(device.encode("utf-8")).digest(),
        _exact_hash(process_instance_hash, field="process instance"),
        _exact_hash(
            stable_resource_identity_hash,
            field="stable resource",
            allow_zero=True,
        ),
        _exact_hash(
            destination_reference_hash,
            field="destination",
            allow_zero=True,
        ),
    )
    return hashlib.sha256(material).hexdigest()


def compile_windows_permit_batch(
    permits: tuple[WindowsKernelPermit, ...],
    *,
    tenant_id: str,
    device_id: str,
    policy_generation: int,
    policy_sequence: int,
    permit_batch_sequence: int,
    arm_session_epoch: int,
    driver_session_id: str,
    policy_fingerprint: str,
    now: datetime,
) -> CompiledWindowsPermitBatch:
    """Build the bounded service-to-driver permit snapshot.

    The Hawk service calls this only after its in-memory broker has verified
    permit integrity. No MAC key, nonce, token, raw identity, or application
    bearer authority crosses this boundary.
    """

    if not 0 <= len(permits) <= 4096:
        raise ValueError("Windows kernel permit count is invalid")
    if type(policy_generation) is not int or policy_generation <= 0:
        raise ValueError("Windows kernel permit policy generation is invalid")
    if type(policy_sequence) is not int or policy_sequence <= 0:
        raise ValueError("Windows kernel permit policy sequence is invalid")
    if type(permit_batch_sequence) is not int or permit_batch_sequence <= 0:
        raise ValueError("Windows kernel permit batch sequence is invalid")
    if type(arm_session_epoch) is not int or arm_session_epoch <= 0:
        raise ValueError("Windows kernel permit arm session epoch is invalid")
    try:
        driver_session = bytes.fromhex(str(driver_session_id))
    except ValueError as exc:
        raise ValueError("Windows kernel permit driver session is invalid") from exc
    if len(driver_session) != 16 or driver_session == bytes(16):
        raise ValueError("Windows kernel permit driver session is invalid")
    fingerprint = _exact_hash(policy_fingerprint, field="policy fingerprint")
    observed = now.astimezone(UTC) if now.tzinfo else None
    if observed is None:
        raise ValueError("Windows kernel permit compilation time must be timezone-aware")
    tenant = str(tenant_id or "")
    device = str(device_id or "")
    if not tenant or not device or len(tenant) > 1024 or len(device) > 1024:
        raise ValueError("Windows kernel permit scope is invalid")

    encoded: list[bytes] = []
    observed_digests: set[str] = set()
    for permit in sorted(permits, key=lambda value: value.permit_digest):
        if permit.permit_digest in observed_digests:
            raise ValueError("Windows kernel permit batch contains a duplicate digest")
        observed_digests.add(permit.permit_digest)
        expiry = permit.expires_at.astimezone(UTC)
        remaining = int((expiry - observed).total_seconds() * 1_000_000_000)
        if not 0 < remaining <= 5 * 60 * 1_000_000_000:
            raise ValueError("Windows kernel permit lifetime is invalid")
        expected_action = windows_kernel_canonical_action_hash(
            primitive=permit.primitive,
            requested_rights=permit.requested_rights,
            policy_epoch=policy_sequence,
            tenant_id=tenant,
            device_id=device,
            process_instance_hash=permit.process_instance_hash,
            stable_resource_identity_hash=permit.stable_resource_identity_hash,
            destination_reference_hash=permit.destination_reference_hash,
        )
        if permit.canonical_action_hash != expected_action:
            raise ValueError("Windows kernel permit canonical action does not match")
        encoded.append(
            _PERMIT.pack(
                1,
                _PRIMITIVES[permit.primitive.value],
                permit.requested_rights,
                remaining,
                permit.maximum_uses,
                _exact_hash(permit.process_instance_hash, field="process instance"),
                _exact_hash(
                    permit.stable_resource_identity_hash,
                    field="stable resource",
                    allow_zero=True,
                ),
                _exact_hash(
                    permit.destination_reference_hash,
                    field="destination",
                    allow_zero=True,
                ),
                _exact_hash(permit.canonical_action_hash, field="canonical action"),
                _exact_hash(permit.permit_digest, field="digest"),
            )
        )
    total_size = _PERMIT_HEADER.size + len(encoded) * _PERMIT.size
    if total_size > HAWK_WINDOWS_MAX_POLICY_BYTES:
        raise ValueError("Windows kernel permit batch exceeds the driver byte limit")
    header = _PERMIT_HEADER.pack(
        _PERMIT_MAGIC,
        _PERMIT_VERSION,
        total_size,
        len(encoded),
        policy_generation,
        policy_sequence,
        permit_batch_sequence,
        arm_session_epoch,
        fingerprint,
        hashlib.sha256(tenant.encode("utf-8")).digest(),
        hashlib.sha256(device.encode("utf-8")).digest(),
        driver_session,
        1,  # authenticated Hawk service/broker projection
        1,  # protected configuration was integrity checked
    )
    return CompiledWindowsPermitBatch(
        blob=header + b"".join(encoded),
        permit_count=len(encoded),
        policy_generation=policy_generation,
        policy_sequence=policy_sequence,
        permit_batch_sequence=permit_batch_sequence,
        arm_session_epoch=arm_session_epoch,
        driver_session_id=driver_session_id,
        policy_fingerprint=policy_fingerprint,
    )


def compile_windows_policy(
    envelope: Mapping[str, Any],
    *,
    trusted_public_keys: Mapping[str, bytes],
    expected_tenant_id: str,
    expected_device_id: str,
    now: datetime,
    now_monotonic_ns: int,
    generation: int,
) -> CompiledWindowsPolicy:
    observed_now = now.astimezone(UTC) if now.tzinfo else now.replace(tzinfo=UTC)
    del now_monotonic_ns  # kernel converts the bounded duration on its own clock
    try:
        immutable_envelope = json.loads(
            json.dumps(
                envelope,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("signed endpoint policy rejected: invalid_envelope") from exc
    if not isinstance(immutable_envelope, dict):
        raise ValueError("signed endpoint policy rejected: invalid_envelope")
    verification = EndpointPolicyFastPath.try_load_signed(
        immutable_envelope,
        trusted_public_keys=trusted_public_keys,
        expected_tenant_id=expected_tenant_id,
        expected_device_id=expected_device_id,
        now=observed_now,
    )
    if not verification.accepted:
        raise ValueError(
            "signed endpoint policy rejected: " + ",".join(verification.failures)
        )
    policy = immutable_envelope.get("policy")
    if not isinstance(policy, dict):
        raise ValueError("signed endpoint policy rejected: invalid_policy")
    if type(policy.get("policy_sequence")) is not int or policy["policy_sequence"] <= 0:
        raise ValueError("Windows policy requires a positive signed policy_sequence")
    policy_sequence = int(policy["policy_sequence"])
    policy_fingerprint = hashlib.sha256(canonical_policy_bytes(policy)).hexdigest()
    key_id = str(immutable_envelope.get("key_id") or "")
    exact_generation = int(generation)
    if exact_generation <= 0:
        raise ValueError("Windows policy generation must be positive")
    issued_at = datetime.fromisoformat(
        str(policy["issued_at"]).replace("Z", "+00:00")
    ).astimezone(UTC)
    expires_at = datetime.fromisoformat(
        str(policy["expires_at"]).replace("Z", "+00:00")
    ).astimezone(UTC)
    remaining_ns = int((expires_at - observed_now).total_seconds() * 1_000_000_000)
    signed_lifetime_ns = int((expires_at - issued_at).total_seconds() * 1_000_000_000)
    if (
        signed_lifetime_ns <= 0
        or signed_lifetime_ns > 24 * 60 * 60 * 1_000_000_000
        or remaining_ns <= 0
        or remaining_ns > 24 * 60 * 60 * 1_000_000_000
    ):
        raise ValueError("Windows policy lifetime is invalid")

    encoded_rules: list[bytes] = []
    ordered_rules = sorted(
        policy["rules"],
        key=lambda rule: (int(rule["priority"]), str(rule["rule_id"])),
    )
    for rule in ordered_rules:
        match = rule["match"]
        unsupported_fields = set(match) - _WINDOWS_KERNEL_MATCH_FIELDS
        if unsupported_fields:
            raise ValueError("Windows kernel rule has an unsupported match field")
        identities = match.get("binary_identities")
        if not isinstance(identities, list) or not identities:
            raise ValueError("Windows kernel rules must be binary-scoped")
        primitives = match.get("primitives")
        if not isinstance(primitives, list) or not primitives:
            raise ValueError("Windows kernel rules require explicit primitives")
        primitive_mask = 0
        for value in primitives:
            if str(value) not in _WINDOWS_KERNEL_PRIMITIVES:
                raise ValueError("Windows kernel rule primitive is unsupported")
            primitive_mask |= 1 << _PRIMITIVES[str(value)]
        for field in (
            "resource_classifications",
            "destination_classifications",
        ):
            values = match.get(field)
            if values is not None and (
                not isinstance(values, list)
                or not values
                or {str(value) for value in values} != {"unknown"}
            ):
                raise ValueError(
                    "Windows kernel rule classification is not locally observable"
                )
        resource_mask = _mask(
            match.get("resource_classifications"),
            _RESOURCE_CLASSIFICATIONS,
            label="resource classification",
        )
        destination_mask = _mask(
            match.get("destination_classifications"),
            _DESTINATION_CLASSIFICATIONS,
            label="destination classification",
        )
        try:
            action = _ACTIONS[str(rule["action"])]
        except KeyError as exc:
            raise ValueError("Windows kernel rule action is unsupported") from exc
        for identity in identities:
            identity_match = _IDENTITY.fullmatch(str(identity))
            if identity_match is None:
                raise ValueError("Windows policy binary identity is invalid")
            binary_hash = bytes.fromhex(identity_match.group(1))
            encoded_rules.append(
                _RULE.pack(
                    primitive_mask,
                    resource_mask,
                    destination_mask,
                    0,
                    True,
                    binary_hash,
                    action,
                    _reference(str(rule["rule_id"])),
                )
            )
    if len(encoded_rules) > 4096:
        raise ValueError("Windows policy expands beyond the driver rule limit")
    policy_version = str(policy["policy_version"])
    policy_reference = _reference(policy_version)
    total_size = _HEADER.size + len(encoded_rules) * _RULE.size
    if total_size > HAWK_WINDOWS_MAX_POLICY_BYTES:
        raise ValueError("Windows policy expands beyond the driver byte limit")
    header = _HEADER.pack(
        _MAGIC,
        _VERSION,
        total_size,
        len(encoded_rules),
        exact_generation,
        policy_sequence,
        remaining_ns,
        bytes.fromhex(policy_fingerprint),
        hashlib.sha256(expected_tenant_id.encode("utf-8")).digest(),
        hashlib.sha256(expected_device_id.encode("utf-8")).digest(),
        1,
        1,
        policy_reference,
        *([0] * len(EndpointPrimitive)),
    )
    return CompiledWindowsPolicy(
        blob=header + b"".join(encoded_rules),
        generation=exact_generation,
        policy_version=policy_version,
        rule_count=len(encoded_rules),
        valid_for_nanoseconds=remaining_ns,
        policy_sequence=policy_sequence,
        policy_fingerprint=policy_fingerprint,
        key_id=key_id,
    )


class WindowsPolicyReplayStore:
    """Protected content high-water mark for signed Windows floor policies."""

    _SCHEMA = "hawk.windows-floor-policy-high-water"

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        tenant_id: str,
        device_id: str,
    ) -> None:
        self._path = Path(path).expanduser() if path else None
        self._tenant_id = str(tenant_id)
        self._device_id = str(device_id)
        self._memory: dict[str, Any] | None = None
        self._memory_lock = threading.RLock()

    @contextmanager
    def transaction(self):
        """Serialize high-water assessment and commit across service instances."""
        if self._path is None:
            with self._memory_lock:
                yield
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self._path.with_suffix(self._path.suffix + ".lock")
        if lock_path.is_symlink():
            raise ValueError("Windows policy replay lock cannot be a symlink")
        with lock_path.open("a+b") as handle:
            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _load(self) -> dict[str, Any] | None:
        if self._path is None:
            return dict(self._memory) if self._memory else None
        if self._path.is_symlink():
            raise ValueError("Windows policy replay state cannot be a symlink")
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except json.JSONDecodeError as exc:
            raise ValueError("Windows policy replay state is invalid") from exc
        expected = {
            "schema", "version", "policy_sequence", "policy_fingerprint",
            "policy_version", "rule_count", "status", "accepted_at",
            "tenant_id", "device_id", "key_id",
        }
        if (
            not isinstance(payload, dict)
            or set(payload) != expected
            or payload.get("schema") != self._SCHEMA
            or payload.get("version") != 2
            or payload.get("tenant_id") != self._tenant_id
            or payload.get("device_id") != self._device_id
            or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", str(payload.get("key_id") or ""))
            or type(payload.get("policy_sequence")) is not int
            or payload["policy_sequence"] <= 0
            or not re.fullmatch(r"[0-9a-f]{64}", str(payload.get("policy_fingerprint") or ""))
            or payload.get("status") not in {"pending", "committed"}
            or type(payload.get("rule_count")) is not int
            or not 0 <= payload["rule_count"] <= 4096
        ):
            raise ValueError("Windows policy replay state is invalid")
        try:
            accepted_at = datetime.fromisoformat(
                str(payload["accepted_at"]).replace("Z", "+00:00")
            )
            if accepted_at.tzinfo is None:
                raise ValueError("timezone required")
        except ValueError as exc:
            raise ValueError("Windows policy replay state is invalid") from exc
        return payload

    def assess(
        self,
        *,
        policy_sequence: int,
        policy_fingerprint: str,
        key_id: str,
        observed_at: datetime,
    ) -> tuple[str, dict[str, Any] | None]:
        prior = self._load()
        if prior is None:
            return "new", None
        prior_time = datetime.fromisoformat(
            str(prior["accepted_at"]).replace("Z", "+00:00")
        ).astimezone(UTC)
        if observed_at.astimezone(UTC).timestamp() + 5 < prior_time.timestamp():
            raise ValueError("Windows policy clock rollback detected")
        prior_sequence = int(prior["policy_sequence"])
        if policy_sequence < prior_sequence:
            raise ValueError("Windows policy content rollback rejected")
        if policy_sequence == prior_sequence:
            if policy_fingerprint != prior["policy_fingerprint"]:
                raise ValueError("Windows policy sequence collision rejected")
            if key_id != prior["key_id"]:
                raise ValueError("Windows policy signing-key collision rejected")
            return str(prior["status"]), prior
        return "new", prior

    def _save(self, payload: dict[str, Any]) -> None:
        if self._path is None:
            self._memory = dict(payload)
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._path.with_suffix(self._path.suffix + ".tmp")
        if self._path.is_symlink() or temporary.is_symlink():
            raise ValueError("Windows policy replay state cannot be a symlink")
        try:
            temporary.write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            os.chmod(temporary, 0o600)
            os.replace(temporary, self._path)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def record(
        self,
        compiled: CompiledWindowsPolicy,
        *,
        observed_at: datetime,
        status: str,
    ) -> None:
        if status not in {"pending", "committed"}:
            raise ValueError("Windows policy replay status is invalid")
        self._save({
            "schema": self._SCHEMA,
            "version": 2,
            "tenant_id": self._tenant_id,
            "device_id": self._device_id,
            "key_id": compiled.key_id,
            "policy_sequence": compiled.policy_sequence,
            "policy_fingerprint": compiled.policy_fingerprint,
            "policy_version": compiled.policy_version,
            "rule_count": compiled.rule_count,
            "status": status,
            "accepted_at": observed_at.astimezone(UTC).isoformat(),
        })


@dataclass(frozen=True, slots=True)
class WindowsFloorReconcileResult:
    armed: bool
    policy_current: bool
    identity_coverage_ready: bool
    wfp_ready: bool
    policy_version: str
    generation: int
    rule_count: int
    allow_count: int
    block_count: int
    policy_reject_count: int


class WindowsFloorPolicyManager:
    def __init__(
        self,
        *,
        channel: WindowsKernelChannel,
        trusted_public_keys: Mapping[str, bytes],
        tenant_id: str,
        device_id: str,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
        replay_state_path: str | Path | None = None,
        process_ids_provider: Callable[
            [],
            list[int | tuple[int, int]] | tuple[int | tuple[int, int], ...],
        ] | None = None,
    ) -> None:
        self._channel = channel
        self._trusted_keys = dict(trusted_public_keys)
        self._tenant_id = str(tenant_id)
        self._device_id = str(device_id)
        self._monotonic_ns = monotonic_ns
        self._generation = 0
        self._replay = WindowsPolicyReplayStore(
            replay_state_path,
            tenant_id=self._tenant_id,
            device_id=self._device_id,
        )
        self._process_ids_provider = process_ids_provider or self._running_process_ids

    @staticmethod
    def _running_process_ids() -> list[tuple[int, int]]:
        import psutil

        # A signed service snapshot is the denominator used by the driver to
        # assert identity coverage. Never convert an access race or skipped
        # process into a complete snapshot. The intersection is a bounded
        # point-in-time set; processes created concurrently are covered by the
        # registered kernel process callback.
        for _attempt in range(3):
            try:
                before = {int(value) for value in psutil.pids() if int(value) > 0}
            except (TypeError, ValueError, psutil.Error) as exc:
                raise RuntimeError(
                    "Windows could not establish a complete live-process snapshot"
                ) from exc
            observed: list[tuple[float, int, int]] = []
            try:
                iterator = psutil.process_iter(
                    attrs=["pid", "ppid", "create_time"]
                )
                for process in iterator:
                    try:
                        process_id = int(process.info["pid"])
                        parent_process_id = int(process.info.get("ppid") or 0)
                        created_at = float(
                            process.info.get("create_time") or 0.0
                        )
                    except (TypeError, ValueError, psutil.Error):
                        continue
                    if process_id > 0:
                        observed.append(
                            (created_at, process_id, max(0, parent_process_id))
                        )
                after = {int(value) for value in psutil.pids() if int(value) > 0}
            except (TypeError, ValueError, psutil.Error):
                continue
            stable_ids = before & after
            observed_by_id = {
                process_id: (created_at, parent_process_id)
                for created_at, process_id, parent_process_id in observed
                if process_id in stable_ids
            }
            if stable_ids <= set(observed_by_id):
                return [
                    (process_id, parent_process_id)
                    for process_id, (created_at, parent_process_id) in sorted(
                        observed_by_id.items(),
                        key=lambda item: (item[1][0], item[0]),
                    )
                ]
        raise RuntimeError(
            "Windows could not establish a complete live-process snapshot"
        )

    def _seed_process_identities(self) -> None:
        process_ids = self._process_ids_provider()
        self._channel.seed_processes(process_ids)

    def disarm(self) -> None:
        """Fail safe without replacing the last verified policy snapshot."""
        self._channel.disarm()

    def status(self):
        return self._channel.status()

    def install_permits(
        self,
        permits: tuple[WindowsKernelPermit, ...],
        *,
        now: datetime | None = None,
    ) -> CompiledWindowsPermitBatch:
        """Replace the driver's exact active permit set.

        ``permits`` is the complete desired active set, not an incremental
        append. Omitting a previously published permit revokes it. A batch can
        never arm the floor or introduce a policy; its authority is bounded to
        the exact already-loaded policy identity and is rejected when health
        or identity coverage is incomplete.
        """

        status = self._channel.status()
        if not (
            status.armed
            and status.policy_loaded
            and status.policy_current
            and status.identity_coverage_ready
            and status.wfp_ready
            and status.generation > 0
            and status.policy_sequence > 0
            and status.arm_session_epoch > 0
            and status.policy_fingerprint != "00" * 32
        ):
            raise RuntimeError("Windows endpoint floor is not eligible for permits")
        observed = now or datetime.now(UTC)
        batch = compile_windows_permit_batch(
            permits,
            tenant_id=self._tenant_id,
            device_id=self._device_id,
            policy_generation=status.generation,
            policy_sequence=status.policy_sequence,
            permit_batch_sequence=status.permit_batch_sequence + 1,
            arm_session_epoch=status.arm_session_epoch,
            driver_session_id=status.driver_session_id,
            policy_fingerprint=status.policy_fingerprint,
            now=observed,
        )
        self._channel.replace_permits(batch.blob)
        return batch

    def reconcile(
        self,
        envelope: Mapping[str, Any],
        *,
        mode: str,
        now: datetime | None = None,
    ) -> WindowsFloorReconcileResult:
        normalized_mode = str(mode).strip().lower()
        if normalized_mode not in {"monitor", "enforce"}:
            raise ValueError("Windows endpoint mode is invalid")
        initial_status = self._channel.status()
        if normalized_mode == "monitor" and initial_status.armed:
            self._channel.disarm()
            initial_status = self._channel.status()
            if initial_status.armed:
                raise RuntimeError("Windows endpoint-floor disarm verification failed")
        observed_at = now or datetime.now(UTC)
        observed_at = (
            observed_at.astimezone(UTC)
            if observed_at.tzinfo
            else observed_at.replace(tzinfo=UTC)
        )
        generation = max(self._generation, int(initial_status.generation)) + 1
        compiled = compile_windows_policy(
            envelope,
            trusted_public_keys=self._trusted_keys,
            expected_tenant_id=self._tenant_id,
            expected_device_id=self._device_id,
            now=observed_at,
            now_monotonic_ns=self._monotonic_ns(),
            generation=generation,
        )
        with self._replay.transaction():
            replay_status, replay_state = self._replay.assess(
                policy_sequence=compiled.policy_sequence,
                policy_fingerprint=compiled.policy_fingerprint,
                key_id=compiled.key_id,
                observed_at=observed_at,
            )
            expected_armed = normalized_mode == "enforce"
            exact_loaded_policy = (
                initial_status.policy_loaded
                and initial_status.policy_current
                and initial_status.policy_sequence == compiled.policy_sequence
                and initial_status.policy_fingerprint == compiled.policy_fingerprint
            )
            if replay_status == "committed" and exact_loaded_policy:
                if expected_armed and (
                    not initial_status.armed
                    or not initial_status.identity_coverage_ready
                ):
                    self._seed_process_identities()
                    self._channel.arm(initial_status.generation)
                existing = self._channel.status()
                if (
                    existing.armed != expected_armed
                    or not existing.policy_current
                    or existing.policy_sequence != compiled.policy_sequence
                    or existing.policy_fingerprint != compiled.policy_fingerprint
                    or (expected_armed and not existing.identity_coverage_ready)
                ):
                    raise RuntimeError("Windows endpoint-floor mode verification failed")
                return WindowsFloorReconcileResult(
                    armed=bool(existing.armed),
                    policy_current=True,
                    identity_coverage_ready=bool(existing.identity_coverage_ready),
                    wfp_ready=bool(existing.wfp_ready),
                    policy_version=str(replay_state["policy_version"]),
                    generation=int(existing.generation),
                    rule_count=int(replay_state["rule_count"]),
                    allow_count=int(existing.allow_count),
                    block_count=int(existing.block_count),
                    policy_reject_count=int(existing.policy_reject_count),
                )
            if replay_status == "new":
                self._replay.record(compiled, observed_at=observed_at, status="pending")
            self._channel.replace_policy(compiled.blob)
            if normalized_mode == "enforce":
                self._seed_process_identities()
                self._channel.arm(compiled.generation)
                armed = True
            else:
                self._channel.disarm()
                armed = False
            observed = self._channel.status()
            if (
                not observed.policy_loaded
                or not observed.policy_current
                or observed.generation != compiled.generation
                or observed.policy_sequence != compiled.policy_sequence
                or observed.policy_fingerprint != compiled.policy_fingerprint
                or observed.armed != armed
                or (armed and not observed.identity_coverage_ready)
            ):
                raise RuntimeError("Windows endpoint-floor state verification failed")
            self._generation = generation
            self._replay.record(compiled, observed_at=observed_at, status="committed")
        return WindowsFloorReconcileResult(
            armed=armed,
            policy_current=bool(observed.policy_current),
            identity_coverage_ready=bool(observed.identity_coverage_ready),
            wfp_ready=bool(observed.wfp_ready),
            policy_version=compiled.policy_version,
            generation=compiled.generation,
            rule_count=compiled.rule_count,
            allow_count=int(observed.allow_count),
            block_count=int(observed.block_count),
            policy_reject_count=int(observed.policy_reject_count),
        )
