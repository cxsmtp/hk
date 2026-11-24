"""Service-SID mutation and administrator status channel for the Windows floor."""

from __future__ import annotations

import ctypes
import struct
import sys
from dataclasses import dataclass
from typing import Protocol


HAWK_WINDOWS_DEVICE_TYPE = 0x8337
METHOD_BUFFERED = 0
FILE_READ_DATA = 0x0001
FILE_WRITE_DATA = 0x0002
HAWK_WINDOWS_MAX_POLICY_BYTES = 1024 * 1024
HAWK_WINDOWS_POLICY_VERSION = 4
HAWK_WINDOWS_PROCESS_SEED_VERSION = 1
HAWK_WINDOWS_MIN_POLICY_BYTES = 368
HAWK_WINDOWS_MIN_PERMIT_BYTES = 168


def _ctl_code(device_type: int, function: int, method: int, access: int) -> int:
    return (device_type << 16) | (access << 14) | (function << 2) | method


IOCTL_HAWK_POLICY_REPLACE = _ctl_code(
    HAWK_WINDOWS_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA
)
IOCTL_HAWK_POLICY_ARM = _ctl_code(
    HAWK_WINDOWS_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA
)
IOCTL_HAWK_POLICY_STATUS = _ctl_code(
    HAWK_WINDOWS_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_DATA
)
IOCTL_HAWK_PROCESS_SEED = _ctl_code(
    HAWK_WINDOWS_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_WRITE_DATA
)
IOCTL_HAWK_PERMITS_REPLACE = _ctl_code(
    HAWK_WINDOWS_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_WRITE_DATA
)
IOCTL_HAWK_PROCESS_IDENTITY_QUERY = _ctl_code(
    HAWK_WINDOWS_DEVICE_TYPE,
    0x806,
    METHOD_BUFFERED,
    FILE_READ_DATA | FILE_WRITE_DATA,
)


class DeviceBackend(Protocol):
    def invoke(self, code: int, payload: bytes, output_size: int = 0) -> bytes: ...


class _Win32DeviceBackend:
    def __init__(self, device_path: str = r"\\.\HawkEndpointFloor") -> None:
        if sys.platform != "win32":
            raise RuntimeError("Windows endpoint-floor device is unavailable")
        self._device_path = str(device_path)

    def invoke(self, code: int, payload: bytes, output_size: int = 0) -> bytes:
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.DeviceIoControl.argtypes = (
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        )
        kernel32.DeviceIoControl.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        if code == IOCTL_HAWK_POLICY_STATUS:
            desired_access = 0x80000000  # GENERIC_READ
        elif code == IOCTL_HAWK_PROCESS_IDENTITY_QUERY:
            desired_access = 0xC0000000  # GENERIC_READ | GENERIC_WRITE
        else:
            desired_access = 0x40000000  # GENERIC_WRITE
        handle = kernel32.CreateFileW(
            self._device_path,
            desired_access,
            0x00000003,  # FILE_SHARE_READ | FILE_SHARE_WRITE
            None,
            3,  # OPEN_EXISTING
            0x80,  # FILE_ATTRIBUTE_NORMAL
            None,
        )
        invalid = wintypes.HANDLE(-1).value
        if handle in (None, invalid):
            raise OSError(ctypes.get_last_error(), "Hawk endpoint-floor device unavailable")
        try:
            input_buffer = ctypes.create_string_buffer(payload) if payload else None
            output_buffer = ctypes.create_string_buffer(output_size) if output_size else None
            returned = wintypes.DWORD(0)
            ok = kernel32.DeviceIoControl(
                handle,
                code,
                input_buffer,
                len(payload),
                output_buffer,
                output_size,
                ctypes.byref(returned),
                None,
            )
            if not ok:
                raise OSError(ctypes.get_last_error(), "Hawk endpoint-floor operation failed")
            return bytes(output_buffer.raw[: returned.value]) if output_buffer else b""
        finally:
            kernel32.CloseHandle(handle)


@dataclass(frozen=True, slots=True)
class WindowsKernelPolicyStatus:
    armed: bool
    policy_loaded: bool
    policy_current: bool
    identity_coverage_ready: bool
    wfp_ready: bool
    generation: int
    policy_sequence: int
    permit_batch_sequence: int
    arm_session_epoch: int
    driver_session_id: str
    policy_fingerprint: str
    allow_count: int
    block_count: int
    policy_reject_count: int


@dataclass(frozen=True, slots=True)
class WindowsKernelProcessIdentity:
    process_id: int
    binary_identity_hash: str
    policy_binary_identity_hash: str
    process_instance_hash: str
    family_root_instance_hash: str
    governed_lineage: bool


class WindowsKernelChannel:
    def __init__(
        self,
        *,
        backend: DeviceBackend | None = None,
        device_path: str = r"\\.\HawkEndpointFloor",
    ) -> None:
        self._backend = backend or _Win32DeviceBackend(device_path)

    def replace_policy(self, blob: bytes) -> None:
        bounded = bytes(blob)
        if not HAWK_WINDOWS_MIN_POLICY_BYTES <= len(bounded) <= HAWK_WINDOWS_MAX_POLICY_BYTES:
            raise ValueError("Windows endpoint-floor policy size is invalid")
        self._backend.invoke(IOCTL_HAWK_POLICY_REPLACE, bounded)

    def replace_permits(self, blob: bytes) -> None:
        """Replace the broker-owned kernel permit view atomically.

        The buffer contains no bearer credential or secret key. The driver
        accepts it only from the Hawk service SID and binds it to the already
        loaded policy generation, sequence, fingerprint, tenant, and device.
        """

        bounded = bytes(blob)
        if not HAWK_WINDOWS_MIN_PERMIT_BYTES <= len(bounded) <= HAWK_WINDOWS_MAX_POLICY_BYTES:
            raise ValueError("Windows endpoint-floor permit batch size is invalid")
        self._backend.invoke(IOCTL_HAWK_PERMITS_REPLACE, bounded)

    def arm(self, generation: int) -> None:
        exact = int(generation)
        if exact <= 0:
            raise ValueError("Windows endpoint-floor generation must be positive")
        self._backend.invoke(
            IOCTL_HAWK_POLICY_ARM,
            struct.pack("<IB3xQ", HAWK_WINDOWS_POLICY_VERSION, 1, exact),
        )

    def disarm(self) -> None:
        self._backend.invoke(
            IOCTL_HAWK_POLICY_ARM,
            struct.pack("<IB3xQ", HAWK_WINDOWS_POLICY_VERSION, 0, 0),
        )

    def status(self) -> WindowsKernelPolicyStatus:
        raw = self._backend.invoke(IOCTL_HAWK_POLICY_STATUS, b"", 116)
        if len(raw) != 116:
            raise RuntimeError("Windows endpoint-floor status response is invalid")
        (
            version, armed, loaded, current, identity_ready, wfp_ready,
            generation, policy_sequence, permit_batch_sequence, arm_session_epoch,
            allows, blocks, rejects, fingerprint, driver_session_id,
        ) = struct.unpack(
            "<IBBBBB3xQQQQQQQ32s16s", raw
        )
        if version != HAWK_WINDOWS_POLICY_VERSION or any(
            value not in {0, 1}
            for value in (armed, loaded, current, identity_ready, wfp_ready)
        ) or (armed == 1 and arm_session_epoch == 0) or driver_session_id == bytes(16):
            raise RuntimeError("Windows endpoint-floor status schema is invalid")
        return WindowsKernelPolicyStatus(
            armed=bool(armed),
            policy_loaded=bool(loaded),
            policy_current=bool(current),
            identity_coverage_ready=bool(identity_ready),
            wfp_ready=bool(wfp_ready),
            generation=generation,
            policy_sequence=policy_sequence,
            permit_batch_sequence=permit_batch_sequence,
            arm_session_epoch=arm_session_epoch,
            driver_session_id=driver_session_id.hex(),
            policy_fingerprint=fingerprint.hex(),
            allow_count=allows,
            block_count=blocks,
            policy_reject_count=rejects,
        )

    def seed_processes(
        self,
        processes: list[int | tuple[int, int]] | tuple[int | tuple[int, int], ...],
    ) -> None:
        bounded: list[tuple[int, int]] = []
        observed: set[int] = set()
        for value in processes:
            if isinstance(value, tuple):
                if len(value) != 2:
                    raise ValueError("Windows process identity seed is invalid")
                process_id, parent_process_id = (int(value[0]), int(value[1]))
            else:
                process_id, parent_process_id = int(value), 0
            if process_id <= 0 or parent_process_id < 0 or process_id == parent_process_id:
                raise ValueError("Windows process identity seed is invalid")
            if process_id in observed:
                continue
            observed.add(process_id)
            bounded.append((process_id, parent_process_id))
        if not bounded or len(bounded) > 16384:
            raise ValueError("Windows process identity seed is invalid")
        payload = struct.pack(
            "<II", HAWK_WINDOWS_PROCESS_SEED_VERSION, len(bounded)
        ) + b"".join(
            struct.pack("<QQ", process_id, parent_process_id)
            for process_id, parent_process_id in bounded
        )
        self._backend.invoke(IOCTL_HAWK_PROCESS_SEED, payload)

    def query_process_identity(self, process_id: int) -> WindowsKernelProcessIdentity:
        exact = int(process_id)
        if exact <= 0 or exact > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("Windows process identity query is invalid")
        raw = self._backend.invoke(
            IOCTL_HAWK_PROCESS_IDENTITY_QUERY,
            struct.pack("<IIQ", HAWK_WINDOWS_POLICY_VERSION, 0, exact),
            152,
        )
        if len(raw) != 152:
            raise RuntimeError("Windows process identity response is invalid")
        (
            version,
            reserved,
            observed_process_id,
            binary_hash,
            policy_binary_hash,
            instance_hash,
            family_root_hash,
            governed_lineage,
        ) = struct.unpack("<IIQ32s32s32s32sB7x", raw)
        if (
            version != HAWK_WINDOWS_POLICY_VERSION
            or reserved != 0
            or observed_process_id != exact
            or binary_hash == bytes(32)
            or policy_binary_hash == bytes(32)
            or instance_hash == bytes(32)
            or family_root_hash == bytes(32)
            or governed_lineage not in {0, 1}
        ):
            raise RuntimeError("Windows process identity response is invalid")
        return WindowsKernelProcessIdentity(
            process_id=exact,
            binary_identity_hash=binary_hash.hex(),
            policy_binary_identity_hash=policy_binary_hash.hex(),
            process_instance_hash=instance_hash.hex(),
            family_root_instance_hash=family_root_hash.hex(),
            governed_lineage=bool(governed_lineage),
        )
