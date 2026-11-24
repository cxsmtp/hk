from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import create_endpoint_access_token, decode_endpoint_access_token
from app.db.models.endpoint_identity import (
    EndpointAuthChallenge,
    EndpointDeviceIdentity,
    EndpointEnrollmentAuthorization,
)


DEFAULT_ENDPOINT_SCOPES: tuple[str, ...] = (
    "endpoint:policy:read",
    "endpoint:decision:execute",
    "endpoint:heartbeat:write",
    "endpoint:evidence:write",
    "endpoint:telemetry:write",
    "endpoint:discovery:write",
)
ALLOWED_ENDPOINT_SCOPES = frozenset(DEFAULT_ENDPOINT_SCOPES)
HARDWARE_KEY_PROVIDERS = frozenset(
    {"macos_secure_enclave", "windows_tpm_cng", "linux_tpm2", "kms_hsm_helper"}
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _sha256_hex(value: str | bytes) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Endpoint identity verification failed",
        ) from exc


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_p256_public_key(public_key_pem: str) -> ec.EllipticCurvePublicKey:
    if len(public_key_pem) > 2048:
        raise HTTPException(status_code=422, detail="Endpoint public key is too large")
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise HTTPException(status_code=422, detail="Invalid endpoint public key") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise HTTPException(status_code=422, detail="Endpoint key must be P-256")
    return key


def public_key_jwk(public_key_pem: str) -> dict[str, str]:
    key = _load_p256_public_key(public_key_pem)
    numbers = key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }


def public_key_thumbprint(public_key_pem: str) -> str:
    """Return the RFC 7638 SHA-256 JWK thumbprint as hex for indexed storage."""
    return _sha256_hex(_canonical(public_key_jwk(public_key_pem)))


def _validate_scopes(scopes: list[str] | tuple[str, ...]) -> list[str]:
    normalized = list(
        dict.fromkeys(str(scope).strip() for scope in scopes if str(scope).strip())
    )
    if not normalized or not set(normalized).issubset(ALLOWED_ENDPOINT_SCOPES):
        raise HTTPException(status_code=422, detail="Invalid endpoint scopes")
    return normalized


def build_enrollment_statement(
    *,
    authorization_id: str,
    tenant_id: str,
    endpoint_id: str,
    key_provider: str,
    public_key_thumbprint: str,
    nonce: str,
    timestamp: int,
) -> bytes:
    return _canonical(
        {
            "authorization_id": authorization_id,
            "endpoint_id": endpoint_id,
            "key_provider": key_provider,
            "nonce": nonce,
            "public_key_thumbprint": public_key_thumbprint,
            "tenant_id": tenant_id,
            "timestamp": int(timestamp),
            "version": "hawk-enroll-v1",
        }
    )


def build_auth_statement(
    *, challenge_id: str, tenant_id: str, endpoint_id: str, nonce: str
) -> bytes:
    return _canonical(
        {
            "challenge_id": challenge_id,
            "endpoint_id": endpoint_id,
            "nonce": nonce,
            "tenant_id": tenant_id,
            "version": "hawk-auth-v1",
        }
    )


def create_enrollment_authorization(
    db: Session,
    *,
    tenant_id: str,
    endpoint_id: str | None,
    assigned_user_id: str | None,
    issued_by_user_id: str,
    scopes: list[str] | tuple[str, ...] = DEFAULT_ENDPOINT_SCOPES,
) -> dict[str, Any]:
    code = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    record = EndpointEnrollmentAuthorization(
        tenant_id=tenant_id,
        endpoint_id=(endpoint_id or "").strip() or None,
        assigned_user_id=assigned_user_id,
        code_hash=_sha256_hex(code),
        nonce_hash=_sha256_hex(nonce),
        scopes=_validate_scopes(scopes),
        expires_at=utcnow() + timedelta(minutes=5),
        issued_by_user_id=issued_by_user_id,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return {
        "authorization_id": record.id,
        "enrollment_code": code,
        "enrollment_nonce": nonce,
        "expires_at": record.expires_at,
        "scopes": list(record.scopes),
    }


def create_reenrollment_authorization(
    db: Session,
    *,
    tenant_id: str,
    endpoint_id: str,
    issued_by_user_id: str,
    scopes: list[str] | tuple[str, ...] = DEFAULT_ENDPOINT_SCOPES,
) -> dict[str, Any]:
    """Issue a one-time re-enrollment bundle and clear the old active key.

    Re-enrollment is intentionally admin driven: the server revokes the existing
    active endpoint identity first, then creates a short-lived authorization for
    the same tenant endpoint. The endpoint can only become active again by
    proving control of its new hardware-backed key through the normal enrollment
    signature path.
    """

    endpoint_id = endpoint_id.strip()
    if not endpoint_id:
        raise HTTPException(status_code=422, detail="Endpoint id is required")

    identity = db.scalar(
        select(EndpointDeviceIdentity)
        .where(
            EndpointDeviceIdentity.tenant_id == tenant_id,
            EndpointDeviceIdentity.endpoint_id == endpoint_id,
        )
        .with_for_update()
    )
    if identity is None:
        raise HTTPException(status_code=404, detail="Endpoint identity not found")

    assigned_user_id = identity.assigned_user_id
    if identity.status == "active":
        identity.status = "revoked"
        identity.revoked_at = utcnow()
        identity.revoked_by_user_id = issued_by_user_id
        identity.revocation_reason = "reenrollment_requested"

    issued = create_enrollment_authorization(
        db,
        tenant_id=tenant_id,
        endpoint_id=endpoint_id,
        assigned_user_id=assigned_user_id,
        issued_by_user_id=issued_by_user_id,
        scopes=scopes,
    )
    issued["revoked_identity_id"] = identity.id
    issued["endpoint_id"] = endpoint_id
    issued["assigned_user_id"] = assigned_user_id
    return issued


def complete_enrollment(
    db: Session,
    *,
    authorization_id: str,
    enrollment_code: str,
    enrollment_nonce: str,
    tenant_id: str,
    endpoint_id: str,
    key_provider: str,
    public_key_pem: str,
    timestamp: int,
    signature_b64: str,
) -> EndpointDeviceIdentity:
    failure = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Endpoint enrollment authorization is invalid or expired",
    )
    record = db.scalar(
        select(EndpointEnrollmentAuthorization)
        .where(EndpointEnrollmentAuthorization.id == authorization_id)
        .with_for_update()
    )
    if (
        record is None
        or record.consumed_at is not None
        or _as_utc(record.expires_at) <= utcnow()
        or not secrets.compare_digest(record.code_hash, _sha256_hex(enrollment_code))
        or not secrets.compare_digest(record.nonce_hash, _sha256_hex(enrollment_nonce))
        or record.tenant_id != tenant_id
        or (record.endpoint_id and record.endpoint_id != endpoint_id)
    ):
        raise failure
    if abs(int(utcnow().timestamp()) - int(timestamp)) > 120:
        raise failure
    if key_provider not in HARDWARE_KEY_PROVIDERS:
        raise HTTPException(status_code=422, detail="Unsupported endpoint key provider")

    thumbprint = public_key_thumbprint(public_key_pem)
    statement = build_enrollment_statement(
        authorization_id=record.id,
        tenant_id=tenant_id,
        endpoint_id=endpoint_id,
        key_provider=key_provider,
        public_key_thumbprint=thumbprint,
        nonce=enrollment_nonce,
        timestamp=timestamp,
    )
    try:
        _load_p256_public_key(public_key_pem).verify(
            _b64url_decode(signature_b64), statement, ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature as exc:
        raise failure from exc

    existing = db.scalar(
        select(EndpointDeviceIdentity)
        .where(
            EndpointDeviceIdentity.tenant_id == tenant_id,
            EndpointDeviceIdentity.endpoint_id == endpoint_id,
        )
        .with_for_update()
    )
    if existing is not None and existing.status == "active":
        raise HTTPException(status_code=409, detail="Endpoint already has an active identity")

    if existing is None:
        identity = EndpointDeviceIdentity(
            tenant_id=tenant_id,
            endpoint_id=endpoint_id,
            assigned_user_id=record.assigned_user_id,
            public_key_pem=public_key_pem,
            key_thumbprint=thumbprint,
            key_provider=key_provider,
            status="active",
            scopes=list(record.scopes),
            enrolled_by_user_id=record.issued_by_user_id,
        )
        db.add(identity)
    else:
        identity = existing
        identity.assigned_user_id = record.assigned_user_id
        identity.public_key_pem = public_key_pem
        identity.key_thumbprint = thumbprint
        identity.key_provider = key_provider
        identity.status = "active"
        identity.scopes = list(record.scopes)
        identity.enrolled_by_user_id = record.issued_by_user_id
        identity.last_authenticated_at = None
        identity.revoked_at = None
        identity.revoked_by_user_id = None
        identity.revocation_reason = None

    record.consumed_at = utcnow()
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Endpoint identity conflicts with an existing device") from exc
    db.refresh(identity)
    return identity


def create_auth_challenge(
    db: Session, *, tenant_id: str, endpoint_id: str
) -> dict[str, Any]:
    identity = db.scalar(
        select(EndpointDeviceIdentity).where(
            EndpointDeviceIdentity.tenant_id == tenant_id,
            EndpointDeviceIdentity.endpoint_id == endpoint_id,
            EndpointDeviceIdentity.status == "active",
        )
    )
    if identity is None:
        raise HTTPException(status_code=401, detail="Endpoint identity unavailable")
    nonce = secrets.token_urlsafe(32)
    challenge = EndpointAuthChallenge(
        device_identity_id=identity.id,
        nonce_hash=_sha256_hex(nonce),
        expires_at=utcnow() + timedelta(seconds=60),
    )
    db.add(challenge)
    db.commit()
    db.refresh(challenge)
    return {
        "challenge_id": challenge.id,
        "nonce": nonce,
        "expires_at": challenge.expires_at,
    }


def exchange_challenge_for_token(
    db: Session,
    *,
    challenge_id: str,
    tenant_id: str,
    endpoint_id: str,
    nonce: str,
    signature_b64: str,
) -> dict[str, Any]:
    failure = HTTPException(status_code=401, detail="Endpoint authentication failed")
    challenge = db.scalar(
        select(EndpointAuthChallenge)
        .where(EndpointAuthChallenge.id == challenge_id)
        .with_for_update()
    )
    if (
        challenge is None
        or challenge.consumed_at is not None
        or _as_utc(challenge.expires_at) <= utcnow()
        or not secrets.compare_digest(challenge.nonce_hash, _sha256_hex(nonce))
    ):
        raise failure
    identity = db.scalar(
        select(EndpointDeviceIdentity).where(
            EndpointDeviceIdentity.id == challenge.device_identity_id,
            EndpointDeviceIdentity.tenant_id == tenant_id,
            EndpointDeviceIdentity.endpoint_id == endpoint_id,
            EndpointDeviceIdentity.status == "active",
        )
    )
    if identity is None:
        raise failure
    statement = build_auth_statement(
        challenge_id=challenge.id,
        tenant_id=tenant_id,
        endpoint_id=endpoint_id,
        nonce=nonce,
    )
    try:
        _load_p256_public_key(identity.public_key_pem).verify(
            _b64url_decode(signature_b64), statement, ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature as exc:
        raise failure from exc

    challenge.consumed_at = utcnow()
    identity.last_authenticated_at = utcnow()
    db.commit()
    token = create_endpoint_access_token(
        identity.id,
        tenant_id=identity.tenant_id,
        endpoint_id=identity.endpoint_id,
        scopes=list(identity.scopes),
        key_thumbprint=identity.key_thumbprint,
    )
    payload = decode_endpoint_access_token(token)
    return {
        "access_token": token,
        "token_type": "DPoP",
        "expires_in": max(0, int(payload["exp"] - utcnow().timestamp())),
        "scope": list(identity.scopes),
    }
