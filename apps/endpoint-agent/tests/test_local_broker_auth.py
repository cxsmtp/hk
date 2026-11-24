from __future__ import annotations

import copy

import pytest

from hawk_endpoint_agent.auth.device_key import EphemeralDeviceKeyProvider
from hawk_endpoint_agent.local_broker_auth import (
    LocalBrokerAuthenticator,
    LocalBrokerAuthenticationError,
    verify_local_broker_response,
)


def _authenticator() -> LocalBrokerAuthenticator:
    provider = EphemeralDeviceKeyProvider()
    identity = provider.ensure_key("endpoint-1")
    return LocalBrokerAuthenticator(
        endpoint_id="endpoint-1",
        provider=provider,
        identity=identity,
        clock=lambda: 1_800_000_000.0,
    )


def test_signed_local_response_is_bound_to_device_key_and_payload() -> None:
    authenticator = _authenticator()
    signed = authenticator.sign_response(
        {"ok": True, "request_id": "request-1", "action": "allow"}
    )

    verified = verify_local_broker_response(
        signed,
        expected_thumbprint=signed["broker_auth"]["key_thumbprint"],
        now=1_800_000_001.0,
    )

    assert verified["request_id"] == "request-1"
    assert verified["broker_auth"]["endpoint_id"] == "endpoint-1"
    assert verified["broker_auth"]["signed_payload"]


def test_tampered_outer_response_uses_the_authenticated_payload() -> None:
    signed = _authenticator().sign_response(
        {"ok": True, "request_id": "request-1", "action": "block"}
    )
    signed["action"] = "allow"

    verified = verify_local_broker_response(
        signed,
        expected_thumbprint=signed["broker_auth"]["key_thumbprint"],
        now=1_800_000_001.0,
    )

    assert verified["action"] == "block"


def test_wrong_pin_and_stale_signature_fail_closed() -> None:
    signed = _authenticator().sign_response(
        {"ok": True, "request_id": "request-1", "action": "allow"}
    )

    with pytest.raises(LocalBrokerAuthenticationError):
        verify_local_broker_response(
            copy.deepcopy(signed),
            expected_thumbprint="0" * 64,
            now=1_800_000_001.0,
        )
    with pytest.raises(LocalBrokerAuthenticationError):
        verify_local_broker_response(
            copy.deepcopy(signed),
            expected_thumbprint=signed["broker_auth"]["key_thumbprint"],
            now=1_800_000_301.0,
        )
