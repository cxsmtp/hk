from __future__ import annotations

from hawk_endpoint_agent.endpoint_floor.contracts import EndpointProcessIdentity
from hawk_endpoint_agent.endpoint_floor.correlation import (
    FileActivity,
    NetworkActivity,
    RelationshipConfidence,
    correlate_file_and_network,
)


def _process() -> EndpointProcessIdentity:
    return EndpointProcessIdentity(
        process_id=8,
        parent_process_id=1,
        process_start_time_ns=500,
        binary_path="/Applications/ChatGPT.app/Contents/MacOS/ChatGPT",
        binary_signature="OPENAI:com.openai.chat",
        binary_hash_reference="sha256:chatgpt",
        bundle_or_package_identity="com.openai.chat",
        user_id="user-1",
        device_id="device-1",
        session_id="session-1",
        process_name="ChatGPT",
    )


def test_same_process_file_read_then_egress_is_correlated_not_confirmed() -> None:
    file_event = FileActivity("file-evidence", _process(), "file:financial", 1_000)
    network_event = NetworkActivity("net-evidence", _process(), "dest:external", 1_100)

    result = correlate_file_and_network(file_event, network_event, window_ns=500)

    assert result.confidence is RelationshipConfidence.CORRELATED
    assert result.reason == "same_process_session_within_window"


def test_direct_semantic_upload_binding_is_confirmed() -> None:
    file_event = FileActivity("file-evidence", _process(), "file:financial", 1_000)
    network_event = NetworkActivity(
        "net-evidence",
        _process(),
        "dest:external",
        4_000,
        semantic_transfer_id="upload-1",
        semantic_resource_reference="file:financial",
    )

    result = correlate_file_and_network(file_event, network_event, window_ns=1)

    assert result.confidence is RelationshipConfidence.CONFIRMED
    assert result.reason == "semantic_transfer_resource_binding"


def test_pid_reuse_or_different_session_is_not_correlated() -> None:
    first = _process()
    reused = EndpointProcessIdentity(
        process_id=first.process_id,
        parent_process_id=first.parent_process_id,
        process_start_time_ns=999,
        binary_path=first.binary_path,
        binary_signature=first.binary_signature,
        binary_hash_reference=first.binary_hash_reference,
        bundle_or_package_identity=first.bundle_or_package_identity,
        user_id=first.user_id,
        device_id=first.device_id,
        session_id="session-2",
        process_name=first.process_name,
    )
    result = correlate_file_and_network(
        FileActivity("file", first, "file:a", 1_000),
        NetworkActivity("net", reused, "dest:a", 1_001),
        window_ns=500,
    )

    assert result.confidence is RelationshipConfidence.UNKNOWN

