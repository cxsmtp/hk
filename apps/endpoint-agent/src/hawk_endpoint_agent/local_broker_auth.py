"""Cryptographic authentication for local endpoint-broker responses.

The Unix-socket pathname is access control, not peer authentication.  Each
decision is therefore signed by the enrolled device key and verified against a
managed public-key thumbprint before a client treats it as endpoint-authorized.
Only public identity material is placed on the wire; no reusable secret is
stored in the client configuration.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .auth.device_key import (
    DeviceKeyProvider,
    DevicePublicIdentity,
    public_key_thumbprint,
)

_VERSION = "hawk-local-broker-v1"
_ALGORITHM = "ES256"
_MAX_AGE_SECONDS = 120
_MAX_FUTURE_SKEW_SECONDS = 30


class LocalBrokerAuthenticationError(RuntimeError):
    """Raised when a local response cannot prove the enrolled endpoint key."""


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
    except (ValueError, TypeError) as exc:
        raise LocalBrokerAuthenticationError("invalid broker signature") from exc


def _canonical(value: dict[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LocalBrokerAuthenticationError("invalid broker response") from exc


def _signature_statement(
    *, endpoint_id: str, issued_at: int, key_thumbprint: str, signed_payload: str
) -> bytes:
    return (
        f"{_VERSION}\n{_ALGORITHM}\n{endpoint_id}\n{issued_at}\n"
        f"{key_thumbprint}\n{signed_payload}"
    ).encode("utf-8")


@dataclass
class LocalBrokerAuthenticator:
    endpoint_id: str
    provider: DeviceKeyProvider
    identity: DevicePublicIdentity
    clock: Callable[[], float] = time.time

    def sign_response(self, response: dict[str, Any]) -> dict[str, Any]:
        unsigned = dict(response)
        unsigned.pop("broker_auth", None)
        issued_at = int(self.clock())
        signed_payload = _b64url(_canonical(unsigned))
        signature = self.provider.sign(
            _signature_statement(
                endpoint_id=self.endpoint_id,
                issued_at=issued_at,
                key_thumbprint=self.identity.key_thumbprint,
                signed_payload=signed_payload,
            )
        )
        return {
            **unsigned,
            "broker_auth": {
                "version": _VERSION,
                "algorithm": _ALGORITHM,
                "endpoint_id": self.endpoint_id,
                "issued_at": issued_at,
                "key_thumbprint": self.identity.key_thumbprint,
                "public_key_pem": self.identity.public_key_pem,
                "signed_payload": signed_payload,
                "signature": _b64url(signature),
            },
        }


def verify_local_broker_response(
    response: dict[str, Any],
    *,
    expected_thumbprint: str,
    now: float | None = None,
) -> dict[str, Any]:
    """Verify a broker response against an out-of-band managed public pin."""
    if not isinstance(response, dict):
        raise LocalBrokerAuthenticationError("invalid broker response")
    auth = response.get("broker_auth")
    if not isinstance(auth, dict):
        raise LocalBrokerAuthenticationError("unsigned broker response")
    thumbprint = str(auth.get("key_thumbprint") or "")
    if not expected_thumbprint or thumbprint != expected_thumbprint:
        raise LocalBrokerAuthenticationError("broker key pin mismatch")
    if auth.get("version") != _VERSION or auth.get("algorithm") != _ALGORITHM:
        raise LocalBrokerAuthenticationError("unsupported broker authentication")
    try:
        issued_at = int(auth.get("issued_at"))
    except (TypeError, ValueError) as exc:
        raise LocalBrokerAuthenticationError("invalid broker timestamp") from exc
    current = float(time.time() if now is None else now)
    if issued_at > current + _MAX_FUTURE_SKEW_SECONDS or current - issued_at > _MAX_AGE_SECONDS:
        raise LocalBrokerAuthenticationError("stale broker response")

    public_key_pem = str(auth.get("public_key_pem") or "")
    try:
        if public_key_thumbprint(public_key_pem) != thumbprint:
            raise LocalBrokerAuthenticationError("broker public key mismatch")
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise LocalBrokerAuthenticationError("unsupported broker public key")
        endpoint_id = str(auth.get("endpoint_id") or "")
        signed_payload = str(auth.get("signed_payload") or "")
        payload_bytes = _b64url_decode(signed_payload)
        public_key.verify(
            _b64url_decode(str(auth.get("signature") or "")),
            _signature_statement(
                endpoint_id=endpoint_id,
                issued_at=issued_at,
                key_thumbprint=thumbprint,
                signed_payload=signed_payload,
            ),
            ec.ECDSA(hashes.SHA256()),
        )
        authenticated = json.loads(payload_bytes.decode("utf-8"))
        if not isinstance(authenticated, dict):
            raise LocalBrokerAuthenticationError("invalid authenticated broker payload")
    except LocalBrokerAuthenticationError:
        raise
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise LocalBrokerAuthenticationError("invalid broker signature") from exc
    return {**authenticated, "broker_auth": dict(auth)}
