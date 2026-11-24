"""Minimal RFC 9449-style proof builder for Hawk endpoint requests."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from .device_key import DeviceKeyError, DeviceKeyProvider


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _json_part(value: dict[str, Any]) -> str:
    return _b64url(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def public_key_jwk(public_key_pem: str) -> dict[str, str]:
    key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise DeviceKeyError("DPoP identity must be a P-256 public key")
    numbers = key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }


def build_dpop_proof(
    *,
    provider: DeviceKeyProvider,
    public_key_pem: str,
    method: str,
    url: str,
    access_token: bytes | bytearray,
    issued_at: int | None = None,
    proof_id: str | None = None,
) -> str:
    """Return a compact ES256 proof bound to one method, URL, and token."""
    token_bytes = bytes(access_token)
    header = {
        "alg": "ES256",
        "jwk": public_key_jwk(public_key_pem),
        "typ": "dpop+jwt",
    }
    claims = {
        "ath": _b64url(hashlib.sha256(token_bytes).digest()),
        "htm": method.upper(),
        "htu": url,
        "iat": int(time.time()) if issued_at is None else int(issued_at),
        "jti": proof_id or str(uuid.uuid4()),
    }
    encoded_header = _json_part(header)
    encoded_claims = _json_part(claims)
    signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
    der_signature = provider.sign(signing_input)
    try:
        r, s = decode_dss_signature(der_signature)
    except ValueError as exc:
        raise DeviceKeyError("device provider returned an invalid ECDSA signature") from exc
    if r.bit_length() > 256 or s.bit_length() > 256:
        raise DeviceKeyError("device provider returned an invalid P-256 signature")
    raw_signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{encoded_header}.{encoded_claims}.{_b64url(raw_signature)}"

