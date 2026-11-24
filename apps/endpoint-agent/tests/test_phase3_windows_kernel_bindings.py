from __future__ import annotations

import struct
import subprocess
import ipaddress
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from hawk_endpoint_agent.endpoint_floor.contracts import EndpointPrimitive
from hawk_endpoint_agent.windows.kernel_channel import (
    IOCTL_HAWK_PERMITS_REPLACE,
    IOCTL_HAWK_PROCESS_IDENTITY_QUERY,
    WindowsKernelChannel,
)
from hawk_endpoint_agent.windows.policy_compiler import (
    WindowsFloorPolicyManager,
    WindowsKernelPermit,
    compile_windows_permit_batch,
    windows_kernel_canonical_action_hash,
    windows_kernel_file_identity,
    windows_kernel_network_destination,
    windows_kernel_process_launch_hash,
)


ROOT = Path(__file__).resolve().parents[1]
WINDOWS = ROOT / "native" / "windows"
CLANG = Path(
    "/Applications/Xcode.app/Contents/Developer/Toolchains/"
    "XcodeDefault.xctoolchain/usr/bin/clang"
)


def _assert_balanced_c_delimiters(source: str, *, path: Path) -> None:
    """Catch malformed native source even when a target WDK is unavailable."""

    state = "code"
    stack: list[tuple[str, int]] = []
    expected = {")": "(", "]": "[", "}": "{"}
    index = 0
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if character == "/" and following == "*":
                state = "block_comment"
                index += 2
                continue
            if character == "/" and following == "/":
                state = "line_comment"
                index += 2
                continue
            if character == '"':
                state = "string"
            elif character == "'":
                state = "character"
            elif character in "([{":
                stack.append((character, index))
            elif character in ")]}":
                assert stack and stack[-1][0] == expected[character], (
                    f"unbalanced {character!r} in {path} at byte {index}"
                )
                stack.pop()
        elif state == "block_comment":
            if character == "*" and following == "/":
                state = "code"
                index += 2
                continue
        elif state == "line_comment":
            if character == "\n":
                state = "code"
        else:
            quote = '"' if state == "string" else "'"
            if character == "\\":
                index += 2
                continue
            if character == quote:
                state = "code"
        index += 1

    assert state in {"code", "line_comment"}, f"unterminated {state} in {path}"
    assert not stack, f"unclosed native delimiters in {path}: {stack[-3:]}"


def test_windows_native_sources_have_balanced_lexical_delimiters() -> None:
    for pattern in ("*.c", "*.h", "*.cpp"):
        for path in WINDOWS.rglob(pattern):
            if path.name.startswith("._"):
                continue
            _assert_balanced_c_delimiters(
                path.read_text(encoding="utf-8"),
                path=path,
            )


def test_process_identity_cache_binds_pid_start_key_and_binary_identity() -> None:
    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    header = (WINDOWS / "include" / "HawkKernelPolicy.h").read_text(
        encoding="utf-8"
    )
    process = (WINDOWS / "process-control" / "HawkProcessControl.c").read_text(
        encoding="utf-8"
    )

    assert "processStartKey" in policy
    assert "processInstanceHash" in policy
    assert "familyRootInstanceHash" in policy
    assert "policyBinaryHash" in policy
    assert "governedLineage" in policy
    assert "lineageAuthoritative" in policy
    assert "PsGetProcessStartKey" in policy
    assert "PEPROCESS Process" in header
    assert "Process," in process
    assert "RtlCopyMemory(request.processInstanceHash, request.binaryIdentityHash" not in policy
    assert "HawkReadExistingLineage" in policy
    assert "HawkPolicyHashIsGoverned" in policy


def test_process_create_uses_one_policy_snapshot_and_publishes_lineage_atomically() -> None:
    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    process = (WINDOWS / "process-control" / "HawkProcessControl.c").read_text(
        encoding="utf-8"
    )
    evaluate = policy[
        policy.index("HawkKernelDecision HawkFloorEvaluateProcess(") :
    ]
    transaction = policy[
        policy.index("static HawkKernelDecision HawkEvaluateProcessWithPolicy(") :
        policy.index("HawkKernelDecision HawkFloorEvaluateProcess(")
    ]

    assert "HawkAcquireControlTransitionLock();" in evaluate
    assert evaluate.count("HawkAcquirePolicy()") == 1
    assert transaction.count("HawkEvaluateRequestWithPolicy(") == 2
    assert "HawkRememberProcessIdentity(" in evaluate
    assert "HawkRememberProcessIdentity(" not in process
    assert "HawkEnforcementArmed()" not in process
    assert "HawkReleaseControlTransitionLock();" in evaluate

    publish = policy[
        policy.index("NTSTATUS HawkFloorPublishSnapshot(") :
        policy.index("typedef enum HawkPermitInstallResult")
    ]
    assert "HawkAcquireControlTransitionLock();" in publish
    assert "HawkReleaseControlTransitionLock();" in publish
    assert "entry->processStartKey == processStartKey" in policy
    assert "entry->policyBinaryHash" in policy


def test_restart_seed_keeps_lost_parent_lineage_ambiguous_and_fail_closed() -> None:
    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    restore = policy[
        policy.index("static BOOLEAN HawkRestoreSeededProcessLineage(") :
        policy.index("static NTSTATUS HawkSeedProcessIdentitiesUnarmed(")
    ]
    ambiguous = policy[
        policy.index("static BOOLEAN HawkRememberAmbiguousOrphanProcess(") :
        policy.index("static BOOLEAN HawkRestoreSeededProcessLineage(")
    ]

    assert "PsGetProcessInheritedFromUniqueProcessId(process)" in restore
    assert "HawkRememberAmbiguousOrphanProcess(" in restore
    assert "seed.governedLineage = TRUE" in ambiguous
    assert "seed.lineageAuthoritative = FALSE" in ambiguous
    assert "parent identity is unavailable" in ambiguous
    assert "parentLineageAmbiguous" in restore
    assert "preserveExistingAuthority" in policy
    assert "seed.allowConservativeAuthorityDowngrade = TRUE" in ambiguous
    assert "!lineageSeed->allowConservativeAuthorityDowngrade" in policy
    assert "if (parentLineageAmbiguous)" in restore
    descendant_downgrade = restore[
        restore.index("if (parentLineageAmbiguous)") :
        restore.index("if (HawkCrossGovernedFamilyConflict(")
    ]
    assert "seed.governedLineage = TRUE" in descendant_downgrade
    assert "seed.lineageAuthoritative = FALSE" in descendant_downgrade
    assert "seed.allowConservativeAuthorityDowngrade = TRUE" in descendant_downgrade
    assert "seed.policyBinaryHash" in descendant_downgrade
    assert "seed.actualBinaryHash" in descendant_downgrade
    assert "seed.familyRootInstanceHash" in descendant_downgrade
    assert "seed.processInstanceHash" in descendant_downgrade


def test_process_launch_binding_changes_with_arguments_and_rejects_ambiguity() -> None:
    target = r"\Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    benign = windows_kernel_process_launch_hash(
        target_image_path=target,
        command_line='powershell.exe -NoProfile -Command "Write-Output ok"',
    )
    changed = windows_kernel_process_launch_hash(
        target_image_path=target,
        command_line='powershell.exe -NoProfile -Command "Invoke-WebRequest evil.invalid"',
    )

    assert benign != changed
    assert len(benign) == 64
    with pytest.raises(ValueError, match="command line"):
        windows_kernel_process_launch_hash(
            target_image_path=target,
            command_line="",
        )

    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    assert "HawkBuildProcessLaunchIdentity" in policy
    assert "createInfo->CommandLine" in policy
    assert "hawk.windows.process-launch.v1" in policy
    assert "permitBindingComplete" in policy
    launch_start = policy.rindex("static BOOLEAN HawkBuildProcessLaunchIdentity(")
    launch_helper = policy[
        launch_start : policy.index(
            "static BOOLEAN HawkCrossGovernedFamilyConflict(", launch_start
        )
    ]
    assert "same-path executable replacement" in launch_helper
    assert launch_helper.rstrip().endswith("return FALSE;\n}")


@pytest.mark.parametrize(
    ("address", "port", "protocol", "expected_hash", "expected_rights"),
    (
        (
            "203.0.113.7",
            443,
            6,
            "5e6e7f7e5a69275ac5de3d4e3d6a39211790772e0f422042637e94918343351b",
            0x04060000000001BB,
        ),
        (
            "2001:db8::7",
            8443,
            17,
            "d89266f53ef41397c9964512179d106edd104de66f344e6338e10f79690d1a8e",
            0x06110000000020FB,
        ),
    ),
)
def test_wfp_destination_builder_matches_driver_material(
    address: str,
    port: int,
    protocol: int,
    expected_hash: str,
    expected_rights: int,
) -> None:
    reference_hash, requested_rights = windows_kernel_network_destination(
        remote_address=address,
        remote_port=port,
        protocol=protocol,
        remote_interface_index=12,
    )

    assert reference_hash == expected_hash
    assert requested_rights == expected_rights

    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    identity_header = (
        WINDOWS / "include" / "HawkWindowsNetworkIdentity.h"
    ).read_text(encoding="utf-8")
    assert "hawk.windows.network-destination.v3" in identity_header
    assert "FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT" in policy
    assert "FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT" in policy
    assert "HawkWindowsBuildNetworkDestinationMaterial" in policy


@pytest.mark.parametrize(
    ("address", "port", "protocol"),
    (
        ("not-an-ip", 443, 6),
        ("203.0.113.7", 0, 6),
        ("203.0.113.7", 443, 0),
    ),
)
def test_wfp_destination_builder_rejects_ambiguous_material(
    address: str,
    port: int,
    protocol: int,
) -> None:
    with pytest.raises(ValueError, match="network destination"):
        windows_kernel_network_destination(
            remote_address=address,
            remote_port=port,
            protocol=protocol,
            remote_interface_index=12,
        )

    with pytest.raises(ValueError, match="network destination"):
        windows_kernel_network_destination(
            remote_address="fe80::1",
            remote_port=443,
            protocol=6,
            remote_interface_index=0,
        )


def test_wfp_shared_canonicalizer_matches_python_bytes(tmp_path: Path) -> None:
    if not CLANG.is_file():
        raise AssertionError("reviewed Xcode clang is missing")
    source = tmp_path / "hawk_windows_network_identity.c"
    binary = tmp_path / "hawk_windows_network_identity"
    source.write_text(
        r'''
#include "HawkWindowsNetworkIdentity.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

static void emit(
    uint8_t family,
    uint8_t protocol,
    uint16_t port,
    uint32_t scopeId,
    const uint8_t *address,
    size_t addressLength
) {
    HawkWindowsNetworkDestinationMaterial material;
    uint64_t rights = 0;
    assert(HawkWindowsBuildNetworkDestinationMaterial(
        family, protocol, port, scopeId, address, addressLength, &material, &rights
    ));
    assert(sizeof(material) == 64U);
    assert(fwrite(&material, 1, sizeof(material), stdout) == sizeof(material));
    assert(fwrite(&rights, 1, sizeof(rights), stdout) == sizeof(rights));
}

int main(void) {
    const uint8_t ipv4[4] = {203, 0, 113, 7};
    const uint8_t ipv6[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 7
    };
    emit(4, 6, 443, 12, ipv4, sizeof(ipv4));
    emit(6, 17, 8443, 12, ipv6, sizeof(ipv6));
    return 0;
}
''',
        encoding="utf-8",
    )
    compiled = subprocess.run(
        [
            str(CLANG),
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-isysroot",
            "/Applications/Xcode.app/Contents/Developer/Platforms/"
            "MacOSX.platform/Developer/SDKs/MacOSX.sdk",
            "-I",
            str(WINDOWS / "include"),
            str(source),
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(binary)], capture_output=True, check=False)
    assert executed.returncode == 0, executed.stderr.decode(errors="replace")

    domain = b"hawk.windows.network-destination.v3".ljust(40, b"\0")
    expected = b"".join(
        (
            domain + bytes((4, 6)) + struct.pack(">H", 443) + struct.pack(">I", 12)
            + ipaddress.ip_address("203.0.113.7").packed.ljust(16, b"\0")
            + struct.pack("<Q", 0x04060000000001BB),
            domain + bytes((6, 17)) + struct.pack(">H", 8443) + struct.pack(">I", 12)
            + ipaddress.ip_address("2001:db8::7").packed
            + struct.pack("<Q", 0x06110000000020FB),
        )
    )
    assert executed.stdout == expected


def test_wfp_interface_binding_and_protocol_scope_are_explicit() -> None:
    scoped, rights = windows_kernel_network_destination(
        remote_address="fe80::1",
        remote_port=443,
        protocol=6,
        remote_interface_index=3,
    )
    assert scoped == "161b1eb686970eac30530c62ba2fb85c610ddbf97f9501748c999db01b8971df"
    assert rights == 0x06060000000001BB

    kernel = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(encoding="utf-8")
    wfp = (WINDOWS / "wfp" / "HawkWfpCallout.c").read_text(encoding="utf-8")
    assert "FWPS_FIELD_ALE_AUTH_CONNECT_V4_INTERFACE_INDEX" in kernel
    assert "FWPS_FIELD_ALE_AUTH_CONNECT_V6_INTERFACE_INDEX" in kernel
    assert "FWPM_CONDITION_IP_PROTOCOL" in wfp
    assert "const UCHAR protocols[2] = {6U, 17U}" in wfp
    network_evaluator = kernel.index("HawkKernelDecision HawkFloorEvaluateNetwork(")
    governed_check = kernel.index("HawkBinaryGoverned(", network_evaluator)
    destination_bind = kernel.index("HawkBindNetworkDestination(", governed_check)
    assert governed_check < destination_bind


def test_wfp_reauthorization_reuses_only_the_exact_current_flow_decision() -> None:
    kernel = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(encoding="utf-8")
    header = (WINDOWS / "include" / "HawkKernelPolicy.h").read_text(
        encoding="utf-8"
    )
    wfp = (WINDOWS / "wfp" / "HawkWfpCallout.c").read_text(encoding="utf-8")

    assert "FWP_CONDITION_FLAG_IS_REAUTHORIZE" in wfp
    assert "FwpsFlowAssociateContext0" in wfp
    assert "flowDeleteFn = HawkFlowDelete" in wfp
    assert "HAWK_NETWORK_AUTHORIZATION_STATE_VERSION 2U" in header
    assert "HawkNetworkPriorAuthorizationCurrent" in kernel
    assert "authorization->policyGeneration == policy->generation" in kernel
    assert "authorization->policySequence == policy->policySequence" in kernel
    assert "authorization->armSessionEpoch ==" in kernel
    assert "priorAuthorization->processInstanceHash" in kernel
    assert "priorAuthorization->destinationReferenceHash" in kernel
    assert "policy->snapshot.expiresAtMonotonicNs > HawkMonotonicNanoseconds()" in kernel
    assert "HawkNetworkBindingUnavailable" in kernel
    assert "HawkPolicyChangeReauthorization" in kernel
    assert "FWP_CONDITION_REAUTHORIZE_REASON_POLICY_CHANGE" in kernel
    assert "protocolValue->type != FWP_UINT8" in kernel
    assert "addressValue->type != FWP_BYTE_ARRAY16_TYPE" in kernel


def test_wfp_policy_and_arm_transitions_force_existing_flow_reauthorization() -> None:
    kernel = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    header = (WINDOWS / "include" / "HawkKernelPolicy.h").read_text(
        encoding="utf-8"
    )
    wfp = (WINDOWS / "wfp" / "HawkWfpCallout.c").read_text(
        encoding="utf-8"
    )

    assert "HAWK_CONNECT_FILTER_KEYS[2][2][2]" in wfp
    assert "filter.filterKey" in wfp
    assert "HAWK_CONNECT_FILTER_KEYS[bank][layerIndex][protocolIndex]" in wfp
    assert "static NTSTATUS HawkInstallFilterBank" in wfp
    assert "static NTSTATUS HawkDeleteFilterBank" in wfp
    assert "NTSTATUS HawkWfpReauthorizeFlows(VOID)" in wfp
    reauthorize = wfp[
        wfp.index("NTSTATUS HawkWfpReauthorizeFlows(VOID)") :
        wfp.index("BOOLEAN HawkWfpReady(VOID)")
    ]
    assert "FwpmTransactionBegin0" in reauthorize
    assert "HawkInstallFilterBank(inactiveBank)" in reauthorize
    assert "HawkDeleteFilterBank(activeBank)" in reauthorize
    assert "FwpmTransactionCommit0" in reauthorize
    assert "FwpmTransactionAbort0" in reauthorize
    assert "InterlockedExchange(&gHawkWfpReady, 0)" in reauthorize
    assert "!HawkWfpReady()" not in reauthorize
    assert "InterlockedExchange(&gHawkWfpReady, 1)" in reauthorize
    assert "HawkWfpReauthorizeFlows" in header

    publish = kernel[
        kernel.index("NTSTATUS HawkFloorPublishSnapshot(") :
        kernel.index("typedef enum HawkPermitInstallResult")
    ]
    arm = kernel[
        kernel.index("NTSTATUS HawkSetPolicyArmed(") :
        kernel.index("VOID HawkGetPolicyStatus(")
    ]
    assert "HawkWfpReauthorizeFlows()" in publish
    assert "HawkWfpReauthorizeFlows()" in arm
    assert "networkTransitionRequired && !HawkWfpReady()" in publish
    assert "networkRequired && !HawkWfpReady()" in arm
    assert arm.count("HawkWfpReauthorizeFlows()") >= 2
    assert arm.index("HawkWfpReauthorizeFlows()") < arm.index(
        "const UINT64 nextArmEpoch = HawkAdvanceArmSessionEpoch()"
    )
    assert arm.rindex("HawkWfpReauthorizeFlows()") > arm.index(
        "HawkCommitArmSession(nextArmEpoch)"
    )
    assert publish.rindex("HawkWfpReauthorizeFlows()") > publish.index(
        "gHawkPolicy = replacement"
    )
    assert "postPublishReauthorizationStatus" in publish
    assert "(VOID)HawkAdvanceArmSessionEpoch();" in publish
    assert arm.rindex("(VOID)HawkAdvanceArmSessionEpoch();") > arm.index(
        "HawkCommitArmSession(nextArmEpoch)"
    )
    assert "HawkInvalidateArmAuthorityPreserveEnforcement" in publish
    assert "InterlockedExchange(&gHawkIdentityCoverageReady, 0)" in publish


def test_policy_expiry_queues_passive_wfp_reauthorization() -> None:
    kernel = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )

    assert "static KTIMER gHawkPolicyExpiryTimer" in kernel
    assert "static KDPC gHawkPolicyExpiryDpc" in kernel
    assert "typedef struct HawkPolicyExpiryWorkContext" in kernel
    assert "static EX_RUNDOWN_REF gHawkPolicyExpiryRundown" in kernel
    assert "static volatile LONG gHawkPolicyExpiryWorkPending" in kernel
    assert "static VOID HawkPolicyExpiryDpc" in kernel
    assert "static VOID HawkPolicyExpiryWorker" in kernel
    worker = kernel[
        kernel.index("static VOID HawkPolicyExpiryWorker") :
        kernel.index("static VOID HawkPolicyExpiryDpc")
    ]
    assert "HawkWfpReauthorizeFlows()" in worker
    assert "HawkAcquireControlTransitionLock()" in worker
    assert "HawkSchedulePolicyExpiry(HAWK_POLICY_EXPIRY_RETRY_NS)" in worker
    assert "HawkQueuePolicyExpiryWork()" in worker
    assert "ExFreePoolWithTag(workContext" in worker
    assert "InterlockedExchange(&gHawkWfpReady" not in worker
    assert "KeSetTimer(" in kernel
    assert "KeCancelTimer(&gHawkPolicyExpiryTimer)" in kernel
    assert "KeRemoveQueueDpc(&gHawkPolicyExpiryDpc)" in kernel
    assert "KeFlushQueuedDpcs()" in kernel
    assert "ExWaitForRundownProtectionRelease(&gHawkPolicyExpiryRundown)" in kernel


def test_windows_file_identity_matches_stable_volume_and_file_material() -> None:
    assert windows_kernel_file_identity(
        volume_creation_time=133801632000000000,
        volume_serial_number=0xA1B2C3D4,
        file_id=0x1122334455667788,
    ) == "c4bcc250f836359ba0afc45ea07148208b431fd0a9de34d0eefa1570b71b54bd"

    for values in (
        {"volume_creation_time": 0, "volume_serial_number": 1, "file_id": 1},
        {"volume_creation_time": 1, "volume_serial_number": 0, "file_id": 1},
        {"volume_creation_time": 1, "volume_serial_number": 1, "file_id": 0},
    ):
        with pytest.raises(ValueError, match="file identity"):
            windows_kernel_file_identity(**values)

    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    file_helper = policy[
        policy.index("static BOOLEAN HawkBindFileIdentity(") :
        policy.index("static BOOLEAN HawkBindSetInformationDestination(")
    ]
    assert "hawk.windows.file-identity.v2" in file_helper
    assert "FltQueryVolumeInformation" in file_helper
    assert "FileFsVolumeInformation" in file_helper
    assert "FileInternalInformation" in file_helper
    assert "FltGetFileSystemType" in file_helper
    assert "FLT_FSTYPE_NTFS" in file_helper
    assert "FLT_FSTYPE_REFS" in file_helper
    assert "stableIdentityVerified" in file_helper
    assert "volumeObject" not in file_helper
    assert "fileObject" not in file_helper
    assert "fsContext" not in file_helper
    assert "sectionObjectPointers" not in file_helper


@pytest.mark.parametrize(
    "primitive",
    (
        EndpointPrimitive.FILE_OPEN,
        EndpointPrimitive.FILE_READ,
        EndpointPrimitive.FILE_WRITE,
        EndpointPrimitive.FILE_CREATE,
        EndpointPrimitive.FILE_RENAME,
        EndpointPrimitive.PROCESS_EXECUTE,
    ),
)
def test_windows_rejects_permits_without_an_exact_preconsequence_binding(
    primitive: EndpointPrimitive,
) -> None:
    with pytest.raises(ValueError, match="primitive is unsupported"):
        WindowsKernelPermit(
            primitive=primitive,
            requested_rights=1,
            process_instance_hash="11" * 32,
            stable_resource_identity_hash="22" * 32,
            destination_reference_hash="33" * 32,
            canonical_action_hash="44" * 32,
            permit_digest="55" * 32,
            expires_at=datetime(2026, 8, 15, 12, 1, tzinfo=UTC),
        )

    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    assert "HawkPrimitivePermitBindingImplemented" in policy
    assert "return primitive == HAWK_FLOOR_NETWORK_CONNECT" in policy
    assert "const BOOLEAN permitBindingComplete = FALSE" in policy


def test_windows_network_binding_uses_remote_address_port_protocol_and_family() -> None:
    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )

    assert "FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS" in policy
    assert "FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS" in policy
    assert "FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT" in policy
    assert "FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL" in policy
    assert "destinationReferenceHash" in policy
    assert "UNREFERENCED_PARAMETER(fixedValues)" not in policy


def test_windows_permit_batch_is_bounded_policy_bound_and_contains_no_secret() -> None:
    now = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
    destination_hash, requested_rights = windows_kernel_network_destination(
        remote_address="203.0.113.7",
        remote_port=443,
        protocol=6,
        remote_interface_index=12,
    )
    canonical = windows_kernel_canonical_action_hash(
        primitive=EndpointPrimitive.NETWORK_CONNECT,
        requested_rights=requested_rights,
        policy_epoch=12,
        tenant_id="tenant-1",
        device_id="device-1",
        process_instance_hash="11" * 32,
        stable_resource_identity_hash="00" * 32,
        destination_reference_hash=destination_hash,
    )
    permit = WindowsKernelPermit(
        primitive=EndpointPrimitive.NETWORK_CONNECT,
        requested_rights=requested_rights,
        process_instance_hash="11" * 32,
        stable_resource_identity_hash="00" * 32,
        destination_reference_hash=destination_hash,
        canonical_action_hash=canonical,
        permit_digest="44" * 32,
        expires_at=now + timedelta(seconds=30),
        maximum_uses=1,
    )

    compiled = compile_windows_permit_batch(
        (permit,),
        tenant_id="tenant-1",
        device_id="device-1",
        policy_generation=8,
        policy_sequence=12,
        permit_batch_sequence=3,
        arm_session_epoch=9,
        driver_session_id="ab" * 16,
        policy_fingerprint="55" * 32,
        now=now,
    )

    magic, version, total_size, count = struct.unpack_from("<IIII", compiled.blob)
    assert magic == 0x54504B48
    assert version == 2
    assert total_size == len(compiled.blob)
    assert count == 1
    assert compiled.policy_generation == 8
    assert compiled.policy_sequence == 12
    assert compiled.permit_batch_sequence == 3
    assert compiled.arm_session_epoch == 9
    assert compiled.driver_session_id == "ab" * 16
    assert len(compiled.blob) <= 1024 * 1024
    assert b"tenant-1" not in compiled.blob
    assert b"device-1" not in compiled.blob
    assert b"secret" not in compiled.blob.lower()


@pytest.mark.parametrize(
    "mutation",
    (
        {"maximum_uses": 0},
        {"maximum_uses": 65},
        {"requested_rights": 0},
        {"process_instance_hash": "00" * 32},
        {"expires_at": datetime(2026, 8, 15, 12, 6, tzinfo=UTC)},
    ),
)
def test_windows_permit_batch_rejects_unbound_or_overbroad_material(
    mutation: dict[str, object],
) -> None:
    now = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
    destination_hash, requested_rights = windows_kernel_network_destination(
        remote_address="203.0.113.7",
        remote_port=443,
        protocol=6,
        remote_interface_index=12,
    )
    values: dict[str, object] = {
        "primitive": EndpointPrimitive.NETWORK_CONNECT,
        "requested_rights": requested_rights,
        "process_instance_hash": "11" * 32,
        "stable_resource_identity_hash": "00" * 32,
        "destination_reference_hash": destination_hash,
        "canonical_action_hash": "33" * 32,
        "permit_digest": "44" * 32,
        "expires_at": now + timedelta(seconds=30),
        "maximum_uses": 1,
    }
    values.update(mutation)

    with pytest.raises(ValueError):
        permit = WindowsKernelPermit(**values)  # type: ignore[arg-type]
        compile_windows_permit_batch(
            (permit,),
            tenant_id="tenant-1",
            device_id="device-1",
            policy_generation=8,
            policy_sequence=12,
            permit_batch_sequence=3,
            arm_session_epoch=9,
            driver_session_id="ab" * 16,
            policy_fingerprint="55" * 32,
            now=now,
        )


def test_windows_permit_batch_rejects_duplicate_digest_and_invalid_batch_sequence() -> None:
    now = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
    destination_hash, requested_rights = windows_kernel_network_destination(
        remote_address="203.0.113.7",
        remote_port=443,
        protocol=6,
        remote_interface_index=12,
    )
    canonical = windows_kernel_canonical_action_hash(
        primitive=EndpointPrimitive.NETWORK_CONNECT,
        requested_rights=requested_rights,
        policy_epoch=12,
        tenant_id="tenant-1",
        device_id="device-1",
        process_instance_hash="11" * 32,
        stable_resource_identity_hash="00" * 32,
        destination_reference_hash=destination_hash,
    )
    permit = WindowsKernelPermit(
        primitive=EndpointPrimitive.NETWORK_CONNECT,
        requested_rights=requested_rights,
        process_instance_hash="11" * 32,
        stable_resource_identity_hash="00" * 32,
        destination_reference_hash=destination_hash,
        canonical_action_hash=canonical,
        permit_digest="44" * 32,
        expires_at=now + timedelta(seconds=30),
    )

    for batch_sequence in (0, -1):
        with pytest.raises(ValueError, match="batch sequence"):
            compile_windows_permit_batch(
                (permit,),
                tenant_id="tenant-1",
                device_id="device-1",
                policy_generation=8,
                policy_sequence=12,
                permit_batch_sequence=batch_sequence,
                arm_session_epoch=9,
                driver_session_id="ab" * 16,
                policy_fingerprint="55" * 32,
                now=now,
            )

    with pytest.raises(ValueError, match="duplicate digest"):
        compile_windows_permit_batch(
            (permit, permit),
            tenant_id="tenant-1",
            device_id="device-1",
            policy_generation=8,
            policy_sequence=12,
            permit_batch_sequence=3,
            arm_session_epoch=9,
            driver_session_id="ab" * 16,
            policy_fingerprint="55" * 32,
            now=now,
        )

    with pytest.raises(ValueError, match="arm session epoch"):
        compile_windows_permit_batch(
            (permit,),
            tenant_id="tenant-1",
            device_id="device-1",
            policy_generation=8,
            policy_sequence=12,
            permit_batch_sequence=3,
            arm_session_epoch=0,
            driver_session_id="ab" * 16,
            policy_fingerprint="55" * 32,
            now=now,
        )

    with pytest.raises(ValueError, match="driver session"):
        compile_windows_permit_batch(
            (permit,),
            tenant_id="tenant-1",
            device_id="device-1",
            policy_generation=8,
            policy_sequence=12,
            permit_batch_sequence=3,
            arm_session_epoch=9,
            driver_session_id="00" * 16,
            policy_fingerprint="55" * 32,
            now=now,
        )


def test_kernel_channel_exposes_separate_bounded_permit_handoff() -> None:
    class Backend:
        def __init__(self) -> None:
            self.calls: list[tuple[int, bytes, int]] = []

        def invoke(self, code: int, payload: bytes, output_size: int = 0) -> bytes:
            self.calls.append((code, bytes(payload), output_size))
            return b""

    backend = Backend()
    channel = WindowsKernelChannel(backend=backend)
    payload = struct.pack("<IIII", 0x54504B48, 2, 168, 0) + bytes(152)

    channel.replace_permits(payload)

    assert backend.calls == [(IOCTL_HAWK_PERMITS_REPLACE, payload, 0)]


def test_service_can_query_kernel_bound_process_instance_without_path_authority() -> None:
    class Backend:
        def __init__(self) -> None:
            self.calls: list[tuple[int, bytes, int]] = []

        def invoke(self, code: int, payload: bytes, output_size: int = 0) -> bytes:
            self.calls.append((code, bytes(payload), output_size))
            return struct.pack(
                "<IIQ32s32s32s32sB7x",
                4,
                0,
                4242,
                bytes.fromhex("11" * 32),
                bytes.fromhex("22" * 32),
                bytes.fromhex("33" * 32),
                bytes.fromhex("44" * 32),
                1,
            )

    backend = Backend()
    identity = WindowsKernelChannel(backend=backend).query_process_identity(4242)

    assert identity.process_id == 4242
    assert identity.binary_identity_hash == "11" * 32
    assert identity.policy_binary_identity_hash == "22" * 32
    assert identity.process_instance_hash == "33" * 32
    assert identity.family_root_instance_hash == "44" * 32
    assert identity.governed_lineage is True
    assert backend.calls == [
        (
            IOCTL_HAWK_PROCESS_IDENTITY_QUERY,
            struct.pack("<IIQ", 4, 0, 4242),
            152,
        )
    ]


def test_process_seed_binds_parent_lineage_in_parent_first_order() -> None:
    class Backend:
        def __init__(self) -> None:
            self.calls: list[tuple[int, bytes, int]] = []

        def invoke(self, code: int, payload: bytes, output_size: int = 0) -> bytes:
            self.calls.append((code, bytes(payload), output_size))
            return b""

    backend = Backend()
    WindowsKernelChannel(backend=backend).seed_processes(
        ((4, 0), (100, 4), (101, 100), (101, 100))
    )

    payload = backend.calls[0][1]
    version, count = struct.unpack_from("<II", payload)
    assert version == 1
    assert count == 3
    assert struct.unpack_from("<QQQQQQ", payload, 8) == (4, 0, 100, 4, 101, 100)

    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    assert "parentProcessId" in policy
    assert "PsGetProcessInheritedFromUniqueProcessId" in policy
    assert "HawkRestoreSeededProcessLineage" in policy
    assert "lineageSourceAuthoritative" in policy
    assert "directlyGoverned ||" in policy
    assert "existingLineageAuthoritative" in policy
    assert "!lineageSeed->lineageAuthoritative" in policy
    assert "actorLineageAuthoritative || targetDirectlyGoverned" in policy
    assert "targetIdentity->lineageAuthoritative = TRUE" not in policy


def test_complete_authenticated_seed_enables_identity_coverage_without_promoting_ppid_lineage() -> None:
    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    seed = policy[
        policy.index("static NTSTATUS HawkSeedProcessIdentitiesUnarmed(") :
        policy.index("VOID HawkForgetProcessIdentity(")
    ]

    assert "InterlockedExchange(&gHawkIdentityCoverageReady, 0);" in seed
    assert "InterlockedExchange(&gHawkIdentityCoverageReady, 1);" in seed
    assert "reconstruction is observational" in seed
    assert "authenticated service snapshot" in seed
    assert "HawkPolicyIsArmed()" in seed
    assert "STATUS_INVALID_DEVICE_STATE" in seed

    assert "HawkLineageRequiresFailClosed" in policy
    assert policy.count("HawkLineageRequiresFailClosed(") >= 4
    assert "governedLineage ||" in policy
    assert "!HawkIdentityCoverageReady()" in policy


def test_unarmed_process_callback_records_authoritative_creator_lineage() -> None:
    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    callback = policy[
        policy.index("HawkKernelDecision HawkFloorEvaluateProcess(") :
        policy.index("#endif") if "#endif" in policy[policy.index("HawkKernelDecision HawkFloorEvaluateProcess(") :] else len(policy)
    ]

    assert "createInfo->CreatingThreadId.UniqueProcess" in callback
    assert "HawkRestoreSeededProcessLineage(" in callback
    assert "targetImageFileName,\n            TRUE\n        )" in callback


def test_kernel_permit_path_is_atomic_epoch_bound_and_replay_resistant() -> None:
    header = (WINDOWS / "include" / "HawkKernelPolicyIoctl.h").read_text(
        encoding="utf-8"
    )
    control = (WINDOWS / "common" / "HawkKernelControl.c").read_text(
        encoding="utf-8"
    )
    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )

    assert "IOCTL_HAWK_PERMITS_REPLACE" in header
    assert "HawkWindowsPermitEnvelope" in header
    assert "HawkFloorPublishPermits" in control
    assert "HawkApplyMatchingPermit" in policy
    assert "HawkFloorEvaluate" in policy
    assert "permitConsumed" in policy
    assert "policySequence" in policy
    assert "permitBatchSequence" in policy
    assert "armSessionEpoch" in header
    assert "driverSessionId" in header
    assert "gHawkDriverSessionId" in policy
    assert "gHawkArmSessionEpoch" in policy
    assert "gHawkControlTransitionLock" in policy
    assert "ExAcquirePushLockExclusive" in policy
    assert "ExAcquireFastMutex(&gHawkPermitPublishMutex)" not in policy
    assert "HawkPermitReplaySeen" in policy
    assert "HawkRememberPermitReplayDigest" in policy
    assert "gHawkPermitReplayBitmap" in policy
    assert "HawkBuildPermitIndex" in policy
    assert "HawkFindIndexedPermit" in policy
    assert "consumedUses = 0" not in policy
    assert "HawkAdvanceArmSessionEpoch" in policy
    assert "HawkCaptureArmSessionEpoch" in policy
    assert "HawkArmSessionCurrent" in policy
    assert "permitCapacity" not in policy
    assert "exact active-set replacement" in policy
    assert "policyFingerprint" in policy
    assert "InterlockedCompareExchange" in policy
    assert "ExQueueWorkItem" in policy
    assert "gHawkDeferredReleaseEvent" in policy
    assert "IoGetTopLevelIrp() == NULL" in policy
    assert "!KeAreAllApcsDisabled()" in policy


def test_rearm_detaches_active_permits_without_resetting_replay_history() -> None:
    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    disarm = policy[
        policy.index("NTSTATUS HawkSetPolicyArmed(") :
        policy.index("VOID HawkGetPolicyStatus(")
    ]

    assert "HawkAdvanceArmSessionEpoch();" in disarm
    advance = policy[
        policy.index("static UINT64 HawkAdvanceArmSessionEpoch") :
        policy.index("static UINT64 HawkInvalidateArmAuthorityPreserveEnforcement")
    ]
    assert "gHawkPermits = NULL" in advance
    assert "HawkReleasePermits(permits)" in advance
    assert "gHawkPermitReplayBitmap" not in advance
    assert "HawkClearPermits();" not in disarm


def test_network_allow_is_linearized_against_arm_session_transition() -> None:
    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    evaluator = policy[
        policy.index("HawkKernelDecision HawkFloorEvaluateNetwork(") :
        policy.index("static BOOLEAN HawkBuildProcessLaunchIdentity")
    ]
    arm_transition = policy[
        policy.index("NTSTATUS HawkSetPolicyArmed(") :
        policy.index("VOID HawkGetPolicyStatus(")
    ]

    assert "HawkCaptureArmSessionEpoch(&evaluationArmEpoch)" in evaluator
    assert evaluator.count("HawkArmSessionCurrent(evaluationArmEpoch)") >= 2
    assert "authorization->armSessionEpoch = evaluationArmEpoch" in evaluator
    assert "&gHawkArmSessionEpoch" not in evaluator
    assert "HawkCommitArmSession(nextArmEpoch)" in arm_transition
    assert "InterlockedExchange(&gHawkPolicyArmed, 1)" not in arm_transition
    assert "InterlockedExchange(&gHawkPolicyArmed, 0)" not in arm_transition


def test_windows_permit_wire_matches_packed_c_abi(tmp_path: Path) -> None:
    clang = Path(
        "/Applications/Xcode.app/Contents/Developer/Toolchains/"
        "XcodeDefault.xctoolchain/usr/bin/clang"
    )
    source = tmp_path / "permit_abi.c"
    source.write_text(
        r'''
#include "HawkKernelPolicyIoctl.h"
#include <stddef.h>
int main(void) {
    _Static_assert(sizeof(HawkWindowsPermitEntry) == 192, "permit entry ABI");
    _Static_assert(offsetof(HawkWindowsPermitEnvelope, permits) == 168, "permit header ABI");
    _Static_assert(sizeof(HawkWindowsPolicyStatus) == 116, "policy status ABI");
    _Static_assert(offsetof(HawkWindowsPermitEntry, processInstanceHash) == 32, "process binding ABI");
    _Static_assert(offsetof(HawkWindowsPermitEntry, permitDigest) == 160, "digest ABI");
    _Static_assert(sizeof(HawkWindowsProcessIdentityResponse) == 152, "process identity ABI");
    _Static_assert(offsetof(HawkWindowsProcessIdentityResponse, familyRootInstanceHash) == 112, "family root ABI");
    return 0;
}
''',
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            str(clang),
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsyntax-only",
            "-I",
            str(WINDOWS / "include"),
            "-I",
            str(ROOT / "native" / "shared"),
            str(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_policy_manager_installs_permits_only_into_current_armed_floor() -> None:
    class Backend:
        def __init__(self) -> None:
            self.calls: list[tuple[int, bytes, int]] = []

        def invoke(self, code: int, payload: bytes, output_size: int = 0) -> bytes:
            self.calls.append((code, bytes(payload), output_size))
            if output_size:
                return struct.pack(
                    "<IBBBBB3xQQQQQQQ32s16s",
                    4,
                    1,
                    1,
                    1,
                    1,
                    1,
                    8,
                    12,
                    7,
                    9,
                    0,
                    0,
                    0,
                    bytes.fromhex("55" * 32),
                    bytes.fromhex("ab" * 16),
                )
            return b""

    now = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
    destination_hash, requested_rights = windows_kernel_network_destination(
        remote_address="203.0.113.7",
        remote_port=443,
        protocol=6,
        remote_interface_index=12,
    )
    canonical = windows_kernel_canonical_action_hash(
        primitive=EndpointPrimitive.NETWORK_CONNECT,
        requested_rights=requested_rights,
        policy_epoch=12,
        tenant_id="tenant-1",
        device_id="device-1",
        process_instance_hash="11" * 32,
        stable_resource_identity_hash="00" * 32,
        destination_reference_hash=destination_hash,
    )
    permit = WindowsKernelPermit(
        primitive=EndpointPrimitive.NETWORK_CONNECT,
        requested_rights=requested_rights,
        process_instance_hash="11" * 32,
        stable_resource_identity_hash="00" * 32,
        destination_reference_hash=destination_hash,
        canonical_action_hash=canonical,
        permit_digest="44" * 32,
        expires_at=now + timedelta(seconds=30),
        maximum_uses=1,
    )
    backend = Backend()
    manager = WindowsFloorPolicyManager(
        channel=WindowsKernelChannel(backend=backend),
        trusted_public_keys={},
        tenant_id="tenant-1",
        device_id="device-1",
        process_ids_provider=lambda: [4],
    )

    batch = manager.install_permits((permit,), now=now)

    assert batch.permit_count == 1
    assert batch.permit_batch_sequence == 8
    assert batch.arm_session_epoch == 9
    assert batch.driver_session_id == "ab" * 16
    assert backend.calls[-1][0] == IOCTL_HAWK_PERMITS_REPLACE


def test_permit_publication_is_atomic_with_policy_replacement() -> None:
    policy_source = (
        WINDOWS / "common" / "HawkKernelPolicy.c"
    ).read_text(encoding="utf-8")

    assert "HawkInstallPermitsIfPolicyCurrent" in policy_source
    assert "HawkAcquireControlTransitionLock();" in policy_source
    assert "KeAcquireSpinLock(&gHawkPermitLock" in policy_source
    assert "gHawkPolicy == policy" in policy_source
    assert "gHawkPermits = replacement" in policy_source


def test_installed_permit_cannot_override_an_explicit_block_rule() -> None:
    policy_source = (
        WINDOWS / "common" / "HawkKernelPolicy.c"
    ).read_text(encoding="utf-8")

    preliminary = policy_source.index("preliminaryDecision = HawkFloorEvaluate")
    permit_lookup = policy_source.index("HawkApplyMatchingPermit", preliminary)
    assert preliminary < permit_lookup
    assert (
        "preliminaryDecision.action == "
        "HAWK_FLOOR_ACTION_REQUIRE_PREAUTHORIZED_PERMIT"
    ) in policy_source
