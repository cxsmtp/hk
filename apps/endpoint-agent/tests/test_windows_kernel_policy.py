from __future__ import annotations

import base64
import copy
import hashlib
import json
import struct
import sys
import types
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hawk_endpoint_agent.endpoint_floor.local_policy import canonical_policy_bytes
from hawk_endpoint_agent.config import load_config
from hawk_endpoint_agent.windows.kernel_channel import (
    IOCTL_HAWK_POLICY_ARM,
    IOCTL_HAWK_PROCESS_SEED,
    IOCTL_HAWK_POLICY_REPLACE,
    IOCTL_HAWK_POLICY_STATUS,
    WindowsKernelChannel,
)
import hawk_endpoint_agent.windows.kernel_channel as kernel_channel_module
from hawk_endpoint_agent.windows.policy_compiler import (
    WindowsFloorPolicyManager,
    compile_windows_policy,
    windows_binary_identity,
    windows_path_identity,
)


PRIVATE = Ed25519PrivateKey.from_private_bytes(b"\x44" * 32)
PUBLIC = PRIVATE.public_key().public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
)
NOW = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
MONOTONIC = 9_000_000_000
MANUS_PATH = r"C:\Program Files\Manus\Manus.exe"


def _policy(*, bind_binary: bool = True) -> dict[str, object]:
    match: dict[str, object] = {
        "primitives": ["file_read", "process_child_create", "network_connect"],
        "resource_classifications": ["unknown"],
        "destination_classifications": ["unknown"],
    }
    if bind_binary:
        match["binary_identities"] = [windows_path_identity(MANUS_PATH)]
    return {
        "schema": "hawk.endpoint-fast-path-policy",
        "version": 1,
        "tenant_id": "tenant-1",
        "device_id": "device-1",
        "policy_version": "windows-policy-1",
        "policy_sequence": 1,
        "issued_at": "2026-08-12T11:55:00Z",
        "expires_at": "2026-08-12T12:05:00Z",
        "rules": [
            {
                "rule_id": "manus-local-consequence-block",
                "priority": 10,
                "match": match,
                "action": "block",
            }
        ],
        "degradation": {
            "low_risk_read": "allow_with_evidence",
            "sensitive_file_read": "fail_closed",
            "file_write": "local_policy_only",
            "process_exec": "local_policy_only",
            "known_approved_destination": "allow_with_evidence",
            "unknown_external_destination": "require_exception",
            "sensitive_external_transfer": "fail_closed",
            "mcp_local_connection": "require_exception",
        },
    }


def _signed(*, bind_binary: bool = True) -> dict[str, object]:
    policy = _policy(bind_binary=bind_binary)
    return _signed_policy(policy)


def _signed_policy(policy: dict[str, object]) -> dict[str, object]:
    return {
        "key_id": "endpoint-floor-prod-1",
        "algorithm": "Ed25519",
        "policy": policy,
        "signature": base64.b64encode(
            PRIVATE.sign(canonical_policy_bytes(policy))
        ).decode("ascii"),
    }


def test_windows_path_identity_matches_case_insensitive_utf16_kernel_hash() -> None:
    expected = hashlib.sha256(MANUS_PATH.upper().encode("utf-16-le")).hexdigest()

    assert windows_path_identity(MANUS_PATH) == f"windows_path_sha256:{expected}"
    assert windows_path_identity(MANUS_PATH.lower()) == f"windows_path_sha256:{expected}"


def test_windows_path_identity_uses_irql_safe_ascii_fold_and_rejects_non_ascii() -> None:
    assert windows_path_identity(r"C:\Apps\HAWK.exe") == windows_path_identity(
        r"c:\apps\hawk.EXE"
    )
    with pytest.raises(ValueError, match="ASCII canonical path"):
        windows_path_identity(r"C:\Apps\Éclair.exe")


def test_windows_binary_identity_uses_exact_nt_path_seen_by_process_callback() -> None:
    class _Resolver:
        def resolve(self, path: str) -> str:
            assert path == MANUS_PATH
            return r"\Device\HarddiskVolume8\Program Files\Manus\Manus.exe"

    identity = windows_binary_identity(MANUS_PATH, resolver=_Resolver())

    assert identity == windows_path_identity(
        r"\Device\HarddiskVolume8\Program Files\Manus\Manus.exe"
    )


def test_signed_binary_scoped_policy_compiles_to_bounded_driver_envelope() -> None:
    compiled = compile_windows_policy(
        _signed(),
        trusted_public_keys={"endpoint-floor-prod-1": PUBLIC},
        expected_tenant_id="tenant-1",
        expected_device_id="device-1",
        now=NOW,
        now_monotonic_ns=MONOTONIC,
        generation=7,
    )

    magic, version, total_size, rule_count = struct.unpack_from("<IIII", compiled.blob)
    assert magic == 0x4B574148
    assert version == 4
    assert total_size == len(compiled.blob)
    assert rule_count == 1
    assert compiled.generation == 7
    assert compiled.valid_for_nanoseconds == 300_000_000_000
    assert struct.unpack_from("<Q", compiled.blob, 32)[0] == 300_000_000_000
    assert compiled.policy_version == "windows-policy-1"
    assert len(compiled.blob) <= 1024 * 1024
    assert compiled.blob[136:138] == b"\x01\x01"
    assert struct.unpack_from("<40I", compiled.blob, 208) == (0,) * 40


def test_compiler_rejects_tamper_and_non_allow_rule_without_binary_scope() -> None:
    tampered = _signed()
    tampered["policy"]["policy_version"] = "attacker"

    for envelope, error in (
        (tampered, "signed endpoint policy rejected"),
        (_signed(bind_binary=False), "binary-scoped"),
    ):
        with pytest.raises(ValueError, match=error):
            compile_windows_policy(
                envelope,
                trusted_public_keys={"endpoint-floor-prod-1": PUBLIC},
                expected_tenant_id="tenant-1",
                expected_device_id="device-1",
                now=NOW,
                now_monotonic_ns=MONOTONIC,
                generation=1,
            )


def test_windows_compiler_requires_signed_monotonic_policy_sequence() -> None:
    policy = _policy()
    del policy["policy_sequence"]

    with pytest.raises(ValueError, match="policy_sequence"):
        compile_windows_policy(
            _signed_policy(policy),
            trusted_public_keys={"endpoint-floor-prod-1": PUBLIC},
            expected_tenant_id="tenant-1",
            expected_device_id="device-1",
            now=NOW,
            now_monotonic_ns=MONOTONIC,
            generation=1,
        )


@pytest.mark.parametrize(
    "action", ["local_escalation_required", "remote_enrichment_allowed"]
)
def test_windows_compiler_rejects_actions_the_kernel_cannot_complete(
    action: str,
) -> None:
    policy = _policy()
    policy["rules"][0]["action"] = action

    with pytest.raises(ValueError, match="action is unsupported"):
        compile_windows_policy(
            _signed_policy(policy),
            trusted_public_keys={"endpoint-floor-prod-1": PUBLIC},
            expected_tenant_id="tenant-1",
            expected_device_id="device-1",
            now=NOW,
            now_monotonic_ns=MONOTONIC,
            generation=1,
        )


def test_windows_compiler_preserves_preauthorized_permit_gate() -> None:
    policy = _policy()
    policy["rules"][0]["action"] = "require_preauthorized_permit"

    compiled = compile_windows_policy(
        _signed_policy(policy),
        trusted_public_keys={"endpoint-floor-prod-1": PUBLIC},
        expected_tenant_id="tenant-1",
        expected_device_id="device-1",
        now=NOW,
        now_monotonic_ns=MONOTONIC,
        generation=1,
    )

    assert struct.unpack_from("<I", compiled.blob, 368 + 56)[0] == 2


@pytest.mark.parametrize(
    ("extra_match", "message"),
    [
        ({"users": ["user-1"]}, "unsupported match field"),
        ({"application_assets": ["app-1"]}, "unsupported match field"),
        ({"ai_assets": ["ai-1"]}, "unsupported match field"),
        ({"business_purposes": ["support"]}, "unsupported match field"),
        ({"resource_classifications": ["confidential"]}, "classification"),
        ({"destination_classifications": ["external"]}, "classification"),
        ({"primitives": ["network_send"]}, "primitive is unsupported"),
    ],
)
def test_compiler_rejects_policy_conditions_the_kernel_cannot_observe(
    extra_match: dict[str, object], message: str
) -> None:
    policy = _policy()
    policy["rules"][0]["match"].update(extra_match)

    with pytest.raises(ValueError, match=message):
        compile_windows_policy(
            _signed_policy(policy),
            trusted_public_keys={"endpoint-floor-prod-1": PUBLIC},
            expected_tenant_id="tenant-1",
            expected_device_id="device-1",
            now=NOW,
            now_monotonic_ns=MONOTONIC,
            generation=1,
        )


def test_compiler_orders_rules_by_signed_priority_not_input_order() -> None:
    policy = _policy()
    match = dict(policy["rules"][0]["match"])
    policy["rules"] = [
        {
            "rule_id": "late-allow",
            "priority": 100,
            "match": match,
            "action": "allow",
        },
        {
            "rule_id": "early-block",
            "priority": 1,
            "match": match,
            "action": "block",
        },
    ]

    compiled = compile_windows_policy(
        _signed_policy(policy),
        trusted_public_keys={"endpoint-floor-prod-1": PUBLIC},
        expected_tenant_id="tenant-1",
        expected_device_id="device-1",
        now=NOW,
        now_monotonic_ns=MONOTONIC,
        generation=1,
    )

    # The action field is 56 bytes into the first 128-byte rule; block == 1.
    assert struct.unpack_from("<I", compiled.blob, 368 + 56)[0] == 1


class FakeDeviceBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[int, bytes, int]] = []
        self.generation = 0
        self.armed = False
        self.loaded = False
        self.identity_ready = False
        self.wfp_ready = True
        self.policy_sequence = 0
        self.permit_batch_sequence = 0
        self.arm_session_epoch = 0
        self.policy_fingerprint = bytes(32)
        self.driver_session_id = bytes.fromhex("ab" * 16)

    def invoke(self, code: int, payload: bytes, output_size: int = 0) -> bytes:
        self.calls.append((code, bytes(payload), output_size))
        if code == IOCTL_HAWK_POLICY_REPLACE:
            self.generation = struct.unpack_from("<Q", payload, 16)[0]
            self.policy_sequence = struct.unpack_from("<Q", payload, 24)[0]
            self.policy_fingerprint = payload[40:72]
            self.loaded = True
        if code == IOCTL_HAWK_PROCESS_SEED:
            version, count = struct.unpack_from("<II", payload)
            assert version == 1
            assert count > 0
            self.identity_ready = True
        if code == IOCTL_HAWK_POLICY_ARM:
            _version, armed, generation = struct.unpack("<IB3xQ", payload)
            self.armed = bool(armed)
            self.arm_session_epoch += 1
            if self.armed:
                assert self.identity_ready
                assert generation == self.generation
        if code == IOCTL_HAWK_POLICY_STATUS:
            return struct.pack(
                "<IBBBBB3xQQQQQQQ32s16s",
                4,
                int(self.armed),
                int(self.loaded),
                int(self.loaded),
                int(self.identity_ready),
                int(self.wfp_ready),
                self.generation,
                self.policy_sequence,
                self.permit_batch_sequence,
                self.arm_session_epoch,
                11,
                3,
                0,
                self.policy_fingerprint,
                self.driver_session_id,
            )
        return b""


def test_kernel_channel_replaces_before_arm_and_parses_bounded_status() -> None:
    backend = FakeDeviceBackend()
    channel = WindowsKernelChannel(backend=backend)
    compiled = compile_windows_policy(
        _signed(),
        trusted_public_keys={"endpoint-floor-prod-1": PUBLIC},
        expected_tenant_id="tenant-1",
        expected_device_id="device-1",
        now=NOW,
        now_monotonic_ns=MONOTONIC,
        generation=7,
    )

    channel.replace_policy(compiled.blob)
    channel.seed_processes([8, 4, 8])
    channel.arm(compiled.generation)
    status = channel.status()

    assert [call[0] for call in backend.calls] == [
        IOCTL_HAWK_POLICY_REPLACE,
        IOCTL_HAWK_PROCESS_SEED,
        IOCTL_HAWK_POLICY_ARM,
        IOCTL_HAWK_POLICY_STATUS,
    ]
    assert status.armed is True
    assert status.policy_current is True
    assert status.generation == 7
    assert status.block_count == 3
    assert status.driver_session_id == "ab" * 16


def test_compiler_rejects_memory_map_until_native_section_control_exists() -> None:
    policy = _policy()
    policy["rules"][0]["match"]["primitives"] = ["file_memory_map"]

    with pytest.raises(ValueError, match="primitive is unsupported"):
        compile_windows_policy(
            _signed_policy(policy),
            trusted_public_keys={"endpoint-floor-prod-1": PUBLIC},
            expected_tenant_id="tenant-1",
            expected_device_id="device-1",
            now=NOW,
            now_monotonic_ns=MONOTONIC,
            generation=7,
        )


def test_win32_channel_declares_64_bit_safe_ctypes_signatures() -> None:
    source = Path(kernel_channel_module.__file__).read_text(encoding="utf-8")

    assert "CreateFileW.argtypes" in source
    assert "DeviceIoControl.argtypes" in source
    assert "CloseHandle.argtypes" in source


def test_policy_manager_disarms_monitor_and_arms_only_verified_enforce_policy() -> None:
    backend = FakeDeviceBackend()
    manager = WindowsFloorPolicyManager(
        channel=WindowsKernelChannel(backend=backend),
        trusted_public_keys={"endpoint-floor-prod-1": PUBLIC},
        tenant_id="tenant-1",
        device_id="device-1",
        monotonic_ns=lambda: MONOTONIC,
        process_ids_provider=lambda: [4, 100],
    )

    monitor = manager.reconcile(_signed(), mode="monitor", now=NOW)
    enforce = manager.reconcile(_signed(), mode="enforce", now=NOW)

    assert monitor.armed is False
    assert monitor.policy_current is True
    assert enforce.armed is True
    assert enforce.policy_version == "windows-policy-1"
    codes = [call[0] for call in backend.calls]
    assert codes == [
        IOCTL_HAWK_POLICY_STATUS,
        IOCTL_HAWK_POLICY_REPLACE,
        IOCTL_HAWK_POLICY_ARM,
        IOCTL_HAWK_POLICY_STATUS,
        IOCTL_HAWK_POLICY_STATUS,
        IOCTL_HAWK_PROCESS_SEED,
        IOCTL_HAWK_POLICY_ARM,
        IOCTL_HAWK_POLICY_STATUS,
    ]
    arm_payloads = [call[1] for call in backend.calls if call[0] == IOCTL_HAWK_POLICY_ARM]
    assert struct.unpack("<IB3xQ", arm_payloads[0]) == (4, 0, 0)
    assert struct.unpack("<IB3xQ", arm_payloads[1])[1] == 1


def test_process_seed_snapshot_never_claims_completeness_after_skipped_live_pid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PsutilError(Exception):
        pass

    class Process:
        def __init__(self, pid: int, ppid: int) -> None:
            self.info = {"pid": pid, "ppid": ppid, "create_time": float(pid)}

    fake = types.SimpleNamespace(
        Error=PsutilError,
        pids=lambda: [4, 100],
        process_iter=lambda attrs: [Process(4, 0)],
    )
    monkeypatch.setitem(sys.modules, "psutil", fake)

    with pytest.raises(RuntimeError, match="complete live-process snapshot"):
        WindowsFloorPolicyManager._running_process_ids()


def test_process_seed_snapshot_preserves_missing_parent_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PsutilError(Exception):
        pass

    class Process:
        info = {"pid": 100, "ppid": 4, "create_time": 100.0}

    fake = types.SimpleNamespace(
        Error=PsutilError,
        pids=lambda: [100],
        process_iter=lambda attrs: [Process()],
    )
    monkeypatch.setitem(sys.modules, "psutil", fake)

    assert WindowsFloorPolicyManager._running_process_ids() == [(100, 4)]


def test_policy_manager_advances_generation_after_service_restart() -> None:
    backend = FakeDeviceBackend()
    backend.generation = 41
    backend.loaded = True
    manager = WindowsFloorPolicyManager(
        channel=WindowsKernelChannel(backend=backend),
        trusted_public_keys={"endpoint-floor-prod-1": PUBLIC},
        tenant_id="tenant-1",
        device_id="device-1",
        monotonic_ns=lambda: MONOTONIC,
        process_ids_provider=lambda: [4, 100],
    )

    result = manager.reconcile(_signed(), mode="enforce", now=NOW)

    assert result.generation == 42
    assert backend.generation == 42


def test_policy_replay_high_water_survives_manager_restart(tmp_path: Path) -> None:
    state_path = tmp_path / "windows-floor-replay-state.json"
    backend = FakeDeviceBackend()
    first = WindowsFloorPolicyManager(
        channel=WindowsKernelChannel(backend=backend),
        trusted_public_keys={"endpoint-floor-prod-1": PUBLIC},
        tenant_id="tenant-1",
        device_id="device-1",
        monotonic_ns=lambda: MONOTONIC,
        replay_state_path=state_path,
        process_ids_provider=lambda: [4, 100],
    )
    policy = _policy()
    policy["policy_sequence"] = 2
    first.reconcile(_signed_policy(policy), mode="enforce", now=NOW)
    replace_count = sum(
        call[0] == IOCTL_HAWK_POLICY_REPLACE for call in backend.calls
    )

    restarted = WindowsFloorPolicyManager(
        channel=WindowsKernelChannel(backend=backend),
        trusted_public_keys={"endpoint-floor-prod-1": PUBLIC},
        tenant_id="tenant-1",
        device_id="device-1",
        monotonic_ns=lambda: MONOTONIC,
        replay_state_path=state_path,
        process_ids_provider=lambda: [4, 100],
    )
    same = restarted.reconcile(_signed_policy(policy), mode="enforce", now=NOW)
    older = _policy()
    older["policy_sequence"] = 1
    older["policy_version"] = "windows-policy-older"

    assert same.armed is True
    assert sum(call[0] == IOCTL_HAWK_POLICY_REPLACE for call in backend.calls) == replace_count
    with pytest.raises(ValueError, match="rollback"):
        restarted.reconcile(_signed_policy(older), mode="enforce", now=NOW)


def test_committed_policy_is_safely_republished_after_driver_state_loss(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "windows-floor-replay-state.json"
    initial_backend = FakeDeviceBackend()
    manager = WindowsFloorPolicyManager(
        channel=WindowsKernelChannel(backend=initial_backend),
        trusted_public_keys={"endpoint-floor-prod-1": PUBLIC},
        tenant_id="tenant-1",
        device_id="device-1",
        replay_state_path=state_path,
        process_ids_provider=lambda: [4, 100],
    )
    manager.reconcile(_signed(), mode="enforce", now=NOW)

    restarted_backend = FakeDeviceBackend()
    restarted = WindowsFloorPolicyManager(
        channel=WindowsKernelChannel(backend=restarted_backend),
        trusted_public_keys={"endpoint-floor-prod-1": PUBLIC},
        tenant_id="tenant-1",
        device_id="device-1",
        replay_state_path=state_path,
        process_ids_provider=lambda: [4, 100],
    )

    recovered = restarted.reconcile(_signed(), mode="enforce", now=NOW)

    assert recovered.armed is True
    assert restarted_backend.identity_ready is True
    assert any(
        code == IOCTL_HAWK_POLICY_REPLACE for code, _payload, _size in restarted_backend.calls
    )


def test_config_accepts_only_bounded_public_windows_floor_keys(tmp_path) -> None:
    path = tmp_path / "agent.json"
    path.write_text(
        json.dumps(
            {
                "api_base_url": "https://hawk.example",
                "tenant_id": "tenant-1",
                "endpoint_id": "device-1",
                "os_type": "windows",
                "security_profile": "bank",
                "key_provider": "windows_tpm_cng",
                "identity_helper_sha256": "a" * 64,
                "windows_native_enforcement_enabled": True,
                "windows_floor_policy_path": str(tmp_path / "policy.json"),
                "endpoint_floor_policy_public_keys": {
                    "endpoint-floor-prod-1": base64.b64encode(PUBLIC).decode("ascii")
                },
            }
        ),
        encoding="utf-8",
    )

    config = load_config(path)

    assert config.windows_native_enforcement_enabled is True
    assert config.key_provider == "windows_tpm_cng"
    assert config.endpoint_floor_policy_public_keys == {
        "endpoint-floor-prod-1": base64.b64encode(PUBLIC).decode("ascii")
    }


def test_bank_windows_native_config_rejects_missing_policy_trust(tmp_path) -> None:
    path = tmp_path / "agent.json"
    path.write_text(
        json.dumps(
            {
                "api_base_url": "https://hawk.example",
                "tenant_id": "tenant-1",
                "endpoint_id": "device-1",
                "os_type": "windows",
                "security_profile": "bank",
                "key_provider": "windows_tpm_cng",
                "identity_helper_sha256": "a" * 64,
                "windows_native_enforcement_enabled": True,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="policy verification key"):
        load_config(path)


def test_windows_config_defaults_keep_runtime_state_out_of_the_user_profile(
    tmp_path,
) -> None:
    path = tmp_path / "agent.json"
    path.write_text(
        json.dumps(
            {
                "api_base_url": "https://hawk.example",
                "tenant_id": "tenant-1",
                "endpoint_id": "device-1",
                "os_type": "windows",
                "security_profile": "development",
                "key_provider": "development_ephemeral",
            }
        ),
        encoding="utf-8",
    )

    config = load_config(path)

    for value in (
        config.policy_cache_path,
        config.baseline_path,
        config.evidence_queue_path,
        config.mode_state_path,
        config.endpoint_floor_receipt_path,
        config.ipc_socket_path,
        config.windows_state_path,
    ):
        assert value.startswith(r"C:\ProgramData\Hawk\EndpointAgent")
        assert "Library" not in value
        assert "~" not in value
    assert config.identity_helper_path == (
        r"C:\Program Files\Hawk\EndpointAgent\hawk-device-identity.exe"
    )
