from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WINDOWS = ROOT / "native" / "windows"


def test_minifilter_separates_open_rights_truncate_and_metadata() -> None:
    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    filter_source = (WINDOWS / "minifilter" / "HawkMinifilter.c").read_text(
        encoding="utf-8"
    )

    contract = json.loads(
        (WINDOWS / "minifilter" / "build-contract.json").read_text(
            encoding="utf-8"
        )
    )

    assert "IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION" not in filter_source
    assert contract["file_memory_map_control"] == "unavailable"
    assert "HAWK_FLOOR_FILE_TRUNCATE" in policy
    assert "HAWK_FLOOR_FILE_METADATA_CHANGE" in policy
    assert "FILE_EXECUTE" in policy
    assert "HAWK_FLOOR_FILE_EXECUTE" in policy
    assert "HAWK_FLOOR_FILE_OPEN" in policy
    assert "HAWK_FLOOR_FILE_READ" in policy
    assert "HAWK_FLOOR_FILE_WRITE" in policy
    assert "HAWK_FLOOR_FILE_CREATE" in policy
    assert "HAWK_FLOOR_FILE_RENAME" in policy
    assert "HAWK_FLOOR_FILE_DELETE" in policy
    assert "HawkSetInformationReplacesDestination" in policy
    truncation_cases = policy[
        policy.index("case FileEndOfFileInformation:") :
        policy.index("case FileValidDataLengthInformation:")
    ]
    assert "case FileAllocationInformation:" in truncation_cases
    assert "return HAWK_FLOOR_FILE_TRUNCATE;" in truncation_cases


def test_rename_and_hard_link_bind_destination_material() -> None:
    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )

    assert "HawkBindSetInformationDestination" in policy
    assert "FileRenameInformation" in policy
    assert "FileLinkInformation" in policy
    assert "FILE_RENAME_REPLACE_IF_EXISTS" in policy
    assert "FILE_LINK_REPLACE_IF_EXISTS" in policy
    assert "InfoBuffer" in policy
    assert "destinationReferenceHash" in policy
    destination_helper = policy[
        policy.index("static BOOLEAN HawkBindSetInformationDestination(") :
        policy.index("static UINT64 HawkFileRequestedRights(")
    ]
    replacement_helper = policy[
        policy.index("static BOOLEAN HawkSetInformationReplacesDestination(") :
        policy.index("static HawkKernelDecision HawkEvaluateFilePrimitive(")
    ]
    assert "ProbeForRead" not in destination_helper
    assert "ProbeForRead" not in replacement_helper


def test_process_callback_applies_actor_child_and_target_execution_gates() -> None:
    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    process = (WINDOWS / "process-control" / "HawkProcessControl.c").read_text(
        encoding="utf-8"
    )
    header = (WINDOWS / "include" / "HawkKernelPolicy.h").read_text(
        encoding="utf-8"
    )

    assert "HAWK_FLOOR_PROCESS_CHILD_CREATE" in policy
    assert "HAWK_FLOOR_PROCESS_EXECUTE" in policy
    assert "HawkBuildProcessIdentity" in policy
    assert "HawkBuildProcessLaunchIdentity" in policy
    assert "policyBinaryHash" in policy
    assert "familyRootInstanceHash" in policy
    assert "governedLineage" in policy
    assert "targetIdentity" in process
    assert "PEPROCESS TargetProcess" in header
    assert "HawkProcessLineageSeed" in header
    assert "HawkFloorEvaluateProcess(" in process
    assert "Process," in process
    assert "CreationStatus = STATUS_ACCESS_DENIED" in process


def test_cross_governed_family_launch_fails_closed_until_multi_label_policy_exists() -> None:
    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )

    assert "targetDirectlyGoverned" in policy
    assert "HawkCrossGovernedFamilyConflict" in policy
    assert "actorGovernedLineage && targetDirectlyGoverned" in policy
    process_gate = policy[
        policy.index("static HawkKernelDecision HawkEvaluateProcessWithPolicy(") :
        policy.index("HawkKernelDecision HawkFloorEvaluateProcess(")
    ]
    conflict_call = process_gate.index("if (HawkCrossGovernedFamilyConflict(")
    assert "return HawkKernelBlock;" in process_gate[conflict_call:conflict_call + 1200]


def test_disarmed_process_observation_uses_self_seed_without_blocking() -> None:
    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    process = (WINDOWS / "process-control" / "HawkProcessControl.c").read_text(
        encoding="utf-8"
    )
    process_gate = policy[policy.index("HawkKernelDecision HawkFloorEvaluateProcess(") :]

    assert "if (!HawkPolicyIsArmed())" in process_gate
    assert "HawkRestoreSeededProcessLineage(" in process_gate
    assert "createInfo->CreatingThreadId.UniqueProcess" in process_gate
    assert "targetImageFileName" in process_gate
    assert "const BOOLEAN denyForIdentityFailure = !remembered" in process_gate
    assert "HawkEnforcementArmed()" not in process


def test_unattributable_user_mode_operations_fail_closed_only_when_armed() -> None:
    policy = (WINDOWS / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    filter_source = (WINDOWS / "minifilter" / "HawkMinifilter.c").read_text(
        encoding="utf-8"
    )

    assert "if (!HawkPolicyIsArmed()) return HawkKernelAllow;" in policy
    assert "!HawkLookupProcessIdentity" in policy
    assert "return HawkKernelBlock;" in policy
    assert "Data->RequestorMode == KernelMode" in filter_source


def test_build_contracts_remain_unverified_until_real_windows_receipts() -> None:
    for path in (
        WINDOWS / "minifilter" / "build-contract.json",
        WINDOWS / "process-control" / "build-contract.json",
        WINDOWS / "wfp" / "build-contract.json",
    ):
        payload = path.read_text(encoding="utf-8")
        assert '"verification_status": "unverified"' in payload
        assert '"activation_default": "off"' in payload


def test_build_contracts_expose_exact_permit_and_protocol_boundaries() -> None:
    minifilter = json.loads(
        (WINDOWS / "minifilter" / "build-contract.json").read_text(
            encoding="utf-8"
        )
    )
    process = json.loads(
        (WINDOWS / "process-control" / "build-contract.json").read_text(
            encoding="utf-8"
        )
    )
    wfp = json.loads(
        (WINDOWS / "wfp" / "build-contract.json").read_text(encoding="utf-8")
    )

    assert minifilter["exact_endpoint_permit_binding"] == "unavailable"
    assert minifilter["pre_create_durable_file_id"] == "unavailable"
    assert process["exact_endpoint_permit_binding"] == "unavailable"
    assert process["restart_lineage_behavior"] == (
        "conservative_fail_closed_until_authoritative_seed"
    )
    assert wfp["protocols"] == ["TCP", "UDP"]
    assert wfp["icmp_and_other_protocols"] == "unavailable"
    assert wfp["destination_binding_version"] == 3
    assert wfp["flow_reauthorization_state_version"] == 2
    assert wfp["policy_change_reauthorization_trigger"] == (
        "atomic_ale_filter_bank_swap"
    )
    assert wfp["expiry_reauthorization_trigger"] == (
        "kernel_timer_passive_work_item"
    )
    assert wfp["reauthorization_retry"] == (
        "bounded_kernel_timer_until_ale_bank_swap_succeeds"
    )
    assert wfp["exact_endpoint_permit_binding"] == (
        "source_implemented_unverified"
    )
