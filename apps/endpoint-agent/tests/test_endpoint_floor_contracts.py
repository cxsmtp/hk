from __future__ import annotations

from hawk_endpoint_agent.endpoint_floor.contracts import (
    CapabilityState,
    EndpointPrimitive,
    EndpointProcessIdentity,
    VerificationState,
)


def test_endpoint_primitive_taxonomy_is_closed_and_complete() -> None:
    assert {item.value for item in EndpointPrimitive} == {
        "file_open",
        "file_read",
        "file_write",
        "file_create",
        "file_truncate",
        "file_rename",
        "file_move",
        "file_delete",
        "file_execute",
        "file_memory_map",
        "file_metadata_change",
        "file_unknown",
        "process_execute",
        "process_child_create",
        "process_script_launch",
        "process_interpreter_launch",
        "process_terminate",
        "process_unknown",
        "network_connect",
        "network_accept",
        "network_listen",
        "network_redirect",
        "network_send",
        "network_receive",
        "network_dns",
        "network_quic",
        "network_localhost",
        "network_unix_socket",
        "network_named_pipe",
        "network_unknown",
        "download",
        "upload",
        "external_transfer",
        "internal_transfer",
        "unknown_transfer",
        "local_mcp_connection",
        "local_agent_connection",
        "local_model_connection",
        "local_service_connection",
        "unknown_local_service",
    }


def test_legacy_primitive_names_deserialize_to_canonical_values() -> None:
    assert EndpointPrimitive("process_exec") is EndpointPrimitive.PROCESS_EXECUTE
    assert EndpointPrimitive("mcp_local_connection") is EndpointPrimitive.LOCAL_MCP_CONNECTION
    assert EndpointPrimitive("local_service_access") is EndpointPrimitive.LOCAL_SERVICE_CONNECTION
    assert EndpointPrimitive("unknown_endpoint_action") is EndpointPrimitive.UNKNOWN_LOCAL_SERVICE
    assert EndpointPrimitive.PROCESS_EXEC is EndpointPrimitive.PROCESS_EXECUTE


def test_capability_and_verification_are_independent_closed_states() -> None:
    assert {item.value for item in CapabilityState} == {
        "inline_bound",
        "inline",
        "external",
        "observe",
        "unavailable",
        "unknown",
    }
    assert {item.value for item in VerificationState} == {
        "verified",
        "experimental",
        "unverified",
        "broken",
        "removed",
    }


def test_process_identity_uses_binary_and_start_identity_not_process_name() -> None:
    first = EndpointProcessIdentity(
        process_id=412,
        parent_process_id=11,
        process_start_time_ns=1_000,
        binary_path="/Applications/Example.app/Contents/MacOS/Example",
        binary_signature="TEAMID:com.example.app",
        binary_hash_reference="sha256:abc",
        bundle_or_package_identity="com.example.app",
        user_id="user-1",
        device_id="device-1",
        session_id="session-1",
        process_name="Example",
    )
    reused = EndpointProcessIdentity(
        process_id=412,
        parent_process_id=11,
        process_start_time_ns=2_000,
        binary_path="/tmp/Example",
        binary_signature=None,
        binary_hash_reference="sha256:def",
        bundle_or_package_identity=None,
        user_id="user-1",
        device_id="device-1",
        session_id="session-1",
        process_name="Example",
    )

    assert first.canonical_identity != reused.canonical_identity
    assert first.canonical_identity == first.canonical_identity
    assert first.process_instance_id
    assert reused.process_instance_id
    assert first.process_instance_id != reused.process_instance_id


def test_process_identity_evidence_is_bounded_and_drops_raw_command_text() -> None:
    identity = EndpointProcessIdentity(
        process_id=7,
        parent_process_id=1,
        process_start_time_ns=99,
        binary_path="/usr/bin/python3",
        binary_signature=None,
        binary_hash_reference="sha256:abc",
        bundle_or_package_identity="python.org",
        user_id="user-1",
        device_id="device-1",
        session_id="session-1",
        process_name="python3",
        command_fingerprint="sha256:command",
        workspace_reference="workspace:hashed",
        process_tree_reference="tree:hashed",
    )

    evidence = identity.as_evidence()

    assert evidence["process_id"] == 7
    assert evidence["command_fingerprint"] == "sha256:command"
    assert "command" not in evidence
    assert all(len(str(value)) <= 512 for value in evidence.values() if value is not None)
