from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"


def _text(relative: str) -> str:
    return (NATIVE / relative).read_text(encoding="utf-8")


def _contract(relative: str) -> dict:
    return json.loads(_text(relative))


def test_shared_fast_path_is_bounded_declarative_and_fails_closed() -> None:
    header = _text("shared/HawkFloorDecisionEngine.h")
    source = _text("shared/HawkFloorDecisionEngine.c")

    assert "HAWK_FLOOR_MAX_RULES" in header
    assert "HAWK_FLOOR_ACTION_BLOCK" in header
    assert "signatureVerified" in header
    assert "HawkFloorEvaluate" in source
    assert "snapshot->signatureVerified" in source
    assert "HAWK_FLOOR_ACTION_BLOCK" in source
    assert not any(token in source for token in ("curl", "URLSession", "WinHttp", "system(", "popen("))


def test_macos_endpoint_security_uses_supported_auth_events_and_local_policy_only() -> None:
    source = _text("macos/endpoint-security/HawkEndpointSecurityClient.c")
    contract = _contract("macos/endpoint-security/build-contract.json")

    assert "es_new_client" in source
    assert "es_subscribe" in source
    assert "ES_EVENT_TYPE_AUTH_OPEN" in source
    assert "ES_EVENT_TYPE_AUTH_EXEC" in source
    assert "ES_EVENT_TYPE_AUTH_CREATE" in source
    assert "es_respond_flags_result" in source
    assert "es_respond_auth_result" in source
    assert "HawkEvaluateCurrentFloorRequest" in source
    assert not any(token in source for token in ("URLSession", "curl", "http://", "https://"))
    assert contract["source_ready_is_runtime_ready"] is False
    assert contract["verification_status"] == "unverified"
    assert contract["activation_default"] == "off"
    assert "endpoint_security_entitlement" in contract["runtime_evidence_required"]


def test_macos_network_floor_owns_explicit_drop_semantics() -> None:
    source = _text("macos/content-filter/HawkNetworkFilterDataProvider.swift")
    contract = _contract("macos/content-filter/build-contract.json")

    assert "NEFilterDataProvider" in source
    assert "handleNewFlow" in source
    assert ".drop()" in source
    assert "HawkLocalNetworkDecisionEngine" in source
    assert "NETransparentProxyProvider" not in source
    assert contract["network_floor_owns_blocking"] is True
    assert contract["semantic_proxy_is_authoritative_for_deny"] is False
    assert contract["direct_quic_bypass_allowed"] is False
    assert contract["verification_status"] == "unverified"


def test_windows_minifilter_blocks_in_preoperation_without_cloud_call() -> None:
    source = _text("windows/minifilter/HawkMinifilter.c")
    contract = _contract("windows/minifilter/build-contract.json")

    assert "FltRegisterFilter" in source
    assert "FltStartFiltering" in source
    assert "IRP_MJ_CREATE" in source
    assert "IRP_MJ_READ" in source
    assert "IRP_MJ_WRITE" in source
    assert "FLT_PREOP_COMPLETE" in source
    assert "STATUS_ACCESS_DENIED" in source
    assert "HawkFloorEvaluateFile" in source
    assert not any(token in source for token in ("WinHttp", "FltSendMessage", "ZwCreateFile", "system("))
    assert contract["verification_status"] == "unverified"
    assert contract["cloud_call_in_preoperation"] is False


def test_windows_wfp_and_process_callbacks_have_real_deny_paths() -> None:
    wfp = _text("windows/wfp/HawkWfpCallout.c")
    process = _text("windows/process-control/HawkProcessControl.c")
    wfp_contract = _contract("windows/wfp/build-contract.json")
    process_contract = _contract("windows/process-control/build-contract.json")

    assert "FwpsCalloutRegister" in wfp
    assert "FWPM_LAYER_ALE_AUTH_CONNECT_V4" in wfp
    assert "FWP_ACTION_BLOCK" in wfp
    assert "HawkFloorEvaluateNetwork" in wfp
    assert "PsSetCreateProcessNotifyRoutineEx" in process
    assert "CreationStatus = STATUS_ACCESS_DENIED" in process
    assert "HawkFloorEvaluateProcess" in process
    assert wfp_contract["verification_status"] == "unverified"
    assert process_contract["verification_status"] == "unverified"


def test_windows_unified_driver_registers_and_unwinds_all_control_boundaries() -> None:
    minifilter = _text("windows/minifilter/HawkMinifilter.c")
    wfp = _text("windows/wfp/HawkWfpCallout.c")
    process = _text("windows/process-control/HawkProcessControl.c")

    assert "HawkInitializeKernelPolicy" in minifilter
    assert "HawkInitializeKernelControl" in minifilter
    assert "HawkRegisterProcessControl" in minifilter
    assert "HawkRegisterWfpCallouts" in minifilter
    assert "HawkUnregisterWfpCallouts" in minifilter
    assert "HawkUnregisterProcessControl" in minifilter
    assert "HawkShutdownKernelControl" in minifilter
    assert "HawkShutdownKernelPolicy" in minifilter
    assert "FwpmFilterAdd" in wfp
    assert "FWPM_CONDITION_IP_PROTOCOL" in wfp
    assert "const UCHAR protocols[2] = {6U, 17U}" in wfp
    assert "FWPM_CONDITION_ALE_APP_ID" not in wfp
    assert "CreateInfo == NULL" in process
    assert "HawkForgetProcessIdentity" in process


def test_all_native_floor_contracts_require_target_os_runtime_acceptance() -> None:
    contracts = [
        _contract("macos/endpoint-security/build-contract.json"),
        _contract("macos/content-filter/build-contract.json"),
        _contract("windows/minifilter/build-contract.json"),
        _contract("windows/wfp/build-contract.json"),
        _contract("windows/process-control/build-contract.json"),
    ]

    assert all(contract["source_ready_is_runtime_ready"] is False for contract in contracts)
    assert all(contract["verification_status"] == "unverified" for contract in contracts)
    assert all("signed_artifact" in contract["runtime_evidence_required"] for contract in contracts)
    assert all("target_os_acceptance" in contract["runtime_evidence_required"] for contract in contracts)
