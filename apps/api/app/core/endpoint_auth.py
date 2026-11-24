from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import decode_endpoint_access_token
from app.db.models.endpoint_identity import EndpointDeviceIdentity, EndpointProofReplay
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import get_db


@dataclass(frozen=True)
class EndpointPrincipal:
    identity: EndpointDeviceIdentity
    tenant: Tenant
    user: User
    scopes: frozenset[str]


def _unauthorized(detail: str = "Endpoint authentication failed") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "DPoP"},
    )


def _b64url_decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
    except (ValueError, TypeError) as exc:
        raise _unauthorized() from exc


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json_part(value: str) -> dict[str, Any]:
    try:
        decoded = json.loads(_b64url_decode(value))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _unauthorized() from exc
    if not isinstance(decoded, dict):
        raise _unauthorized()
    return decoded


def _jwk_key_and_thumbprint(jwk: dict[str, Any]) -> tuple[ec.EllipticCurvePublicKey, str]:
    if (
        jwk.get("kty") != "EC"
        or jwk.get("crv") != "P-256"
        or not isinstance(jwk.get("x"), str)
        or not isinstance(jwk.get("y"), str)
    ):
        raise _unauthorized()
    x_raw = _b64url_decode(jwk["x"])
    y_raw = _b64url_decode(jwk["y"])
    if len(x_raw) != 32 or len(y_raw) != 32:
        raise _unauthorized()
    try:
        key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x_raw, "big"),
            int.from_bytes(y_raw, "big"),
            ec.SECP256R1(),
        ).public_key()
    except ValueError as exc:
        raise _unauthorized() from exc
    canonical = json.dumps(
        {"crv": "P-256", "kty": "EC", "x": jwk["x"], "y": jwk["y"]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return key, hashlib.sha256(canonical).hexdigest()


def _parse_and_verify_proof(
    proof: str,
    *,
    access_token: str,
    method: str,
    url: str,
    expected_thumbprint: str,
) -> str:
    parts = proof.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise _unauthorized()
    header = _json_part(parts[0])
    claims = _json_part(parts[1])
    if header.get("alg") != "ES256" or header.get("typ") != "dpop+jwt":
        raise _unauthorized()
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise _unauthorized()
    key, thumbprint = _jwk_key_and_thumbprint(jwk)
    if not secrets.compare_digest(thumbprint, expected_thumbprint):
        raise _unauthorized()

    signature = _b64url_decode(parts[2])
    if len(signature) != 64:
        raise _unauthorized()
    der_signature = encode_dss_signature(
        int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    )
    try:
        key.verify(
            der_signature,
            f"{parts[0]}.{parts[1]}".encode("ascii"),
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as exc:
        raise _unauthorized() from exc

    expected_ath = _b64url(hashlib.sha256(access_token.encode("ascii")).digest())
    issued_at = claims.get("iat")
    jti = claims.get("jti")
    if (
        claims.get("htm") != method.upper()
        or claims.get("htu") != url
        or not isinstance(issued_at, int)
        or abs(int(datetime.now(timezone.utc).timestamp()) - issued_at) > 60
        or not isinstance(jti, str)
        or not 8 <= len(jti) <= 128
        or not secrets.compare_digest(str(claims.get("ath") or ""), expected_ath)
    ):
        raise _unauthorized()
    return jti


def validate_endpoint_request(
    db: Session,
    *,
    access_token: str,
    proof: str,
    method: str,
    url: str,
    tenant_id: str,
    required_scope: str,
) -> EndpointPrincipal:
    try:
        claims = decode_endpoint_access_token(access_token)
    except ValueError as exc:
        raise _unauthorized("Endpoint access token is invalid or expired") from exc
    token_tenant = str(claims.get("tenant_id") or "")
    identity_id = str(claims.get("sub") or "")
    endpoint_id = str(claims.get("endpoint_id") or "")
    cnf = claims.get("cnf")
    token_scopes = frozenset(str(scope) for scope in claims.get("scope") or [])
    if (
        not tenant_id
        or token_tenant != tenant_id
        or not identity_id
        or not endpoint_id
        or not isinstance(cnf, dict)
        or not isinstance(cnf.get("jkt"), str)
    ):
        raise _unauthorized()
    if required_scope not in token_scopes:
        raise HTTPException(status_code=403, detail="Endpoint scope denied")

    identity = db.scalar(
        select(EndpointDeviceIdentity).where(
            EndpointDeviceIdentity.id == identity_id,
            EndpointDeviceIdentity.tenant_id == tenant_id,
            EndpointDeviceIdentity.endpoint_id == endpoint_id,
            EndpointDeviceIdentity.status == "active",
        )
    )
    if (
        identity is None
        or not secrets.compare_digest(identity.key_thumbprint, cnf["jkt"])
        or required_scope not in set(identity.scopes or [])
    ):
        raise _unauthorized()
    tenant = db.scalar(
        select(Tenant).where(Tenant.id == tenant_id, Tenant.is_active.is_(True))
    )
    user_id = identity.assigned_user_id or identity.enrolled_by_user_id
    user = db.scalar(select(User).where(User.id == user_id, User.is_active.is_(True)))
    membership = db.scalar(
        select(UserTenantRole).where(
            UserTenantRole.user_id == user_id,
            UserTenantRole.tenant_id == tenant_id,
        )
    )
    if tenant is None or user is None or membership is None:
        raise _unauthorized()

    jti = _parse_and_verify_proof(
        proof,
        access_token=access_token,
        method=method,
        url=url,
        expected_thumbprint=identity.key_thumbprint,
    )
    now = datetime.now(timezone.utc)
    db.execute(delete(EndpointProofReplay).where(EndpointProofReplay.expires_at < now))
    db.add(
        EndpointProofReplay(
            device_identity_id=identity.id,
            proof_hash=hashlib.sha256(f"{identity.id}:{jti}".encode()).hexdigest(),
            expires_at=now + timedelta(minutes=2),
        )
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise _unauthorized("Endpoint proof replay rejected") from exc
    return EndpointPrincipal(
        identity=identity,
        tenant=tenant,
        user=user,
        scopes=token_scopes,
    )


def require_endpoint_scope(required_scope: str) -> Callable[..., EndpointPrincipal]:
    def checker(
        request: Request,
        authorization: str | None = Header(default=None, alias="Authorization"),
        dpop: str | None = Header(default=None, alias="DPoP"),
        tenant_id: str | None = Header(default=None, alias="X-Tenant-ID"),
        db: Session = Depends(get_db),
    ) -> EndpointPrincipal:
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "dpop" or not token or not dpop or not tenant_id:
            raise _unauthorized("Endpoint DPoP credentials are required")
        return validate_endpoint_request(
            db,
            access_token=token,
            proof=dpop,
            method=request.method,
            url=str(request.url),
            tenant_id=tenant_id,
            required_scope=required_scope,
        )

    return checker
