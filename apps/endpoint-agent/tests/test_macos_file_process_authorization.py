from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MACOS = ROOT / "native" / "macos"


def test_endpoint_security_subscribes_supported_file_process_authorization_events() -> None:
    source = (MACOS / "endpoint-security" / "HawkEndpointSecurityClient.c").read_text(
        encoding="utf-8"
    )
    required = (
        "ES_EVENT_TYPE_AUTH_EXEC",
        "ES_EVENT_TYPE_AUTH_OPEN",
        "ES_EVENT_TYPE_AUTH_CREATE",
        "ES_EVENT_TYPE_AUTH_RENAME",
        "ES_EVENT_TYPE_AUTH_UNLINK",
        "ES_EVENT_TYPE_AUTH_TRUNCATE",
        "ES_EVENT_TYPE_AUTH_MMAP",
        "ES_EVENT_TYPE_AUTH_LINK",
        "ES_EVENT_TYPE_AUTH_SETEXTATTR",
        "ES_EVENT_TYPE_AUTH_SETFLAGS",
        "ES_EVENT_TYPE_AUTH_SETMODE",
        "ES_EVENT_TYPE_AUTH_SETOWNER",
        "ES_EVENT_TYPE_AUTH_CLONE",
        "ES_EVENT_TYPE_AUTH_COPYFILE",
    )
    assert all(token in source for token in required)
    assert "HAWK_FLOOR_FILE_MEMORY_MAP" in source
    assert "HAWK_FLOOR_FILE_METADATA_CHANGE" in source
    assert "HAWK_FLOOR_FILE_TRUNCATE" in source


def test_dynamic_authorization_is_noncacheable_and_policy_epoch_clears_es_cache() -> None:
    client = (MACOS / "endpoint-security" / "HawkEndpointSecurityClient.c").read_text(
        encoding="utf-8"
    )
    bridge_header = (MACOS / "shared" / "HawkMacPolicyBridge.h").read_text(
        encoding="utf-8"
    )
    bridge_source = (MACOS / "shared" / "HawkMacPolicyBridge.c").read_text(
        encoding="utf-8"
    )

    assert "es_respond_flags_result(client, message, flags, false)" in client
    assert "ES_AUTH_RESULT_DENY" in client
    assert "es_clear_cache" in client
    assert "HawkMacSetPolicyEpochObserver" in client
    assert "HawkMacPolicyEpochObserver" in bridge_header
    assert "sPolicyEpochObserver" in bridge_source


def test_request_bridge_binds_event_specific_rights_and_destination_material() -> None:
    source = (MACOS / "endpoint-security" / "HawkMacEndpointRequest.c").read_text(
        encoding="utf-8"
    )

    assert "message->event.open.fflag" in source
    assert "message->event.mmap.protection" in source
    assert "message->event.setmode.mode" in source
    assert "message->event.setowner.uid" in source
    assert "message->event.copyfile.flags" in source
    assert "destinationReferenceHash" in source
    assert "requestedRights" in source
