from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import bcrypt
import jwt
from jwt import PyJWTError as JWTError

from app.core.config import settings


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def create_token(subject: str, token_type: str, expires_delta: timedelta, extra: dict[str, Any] | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "jti": str(uuid4()),
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def create_access_token(user_id: str, tenant_id: str | None = None, role: str | None = None) -> str:
    return create_token(
        subject=user_id,
        token_type="access",
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
        extra={"tenant_id": tenant_id, "role": role},
    )


def create_refresh_token(user_id: str, tenant_id: str | None = None) -> str:
    return create_token(
        subject=user_id,
        token_type="refresh",
        expires_delta=timedelta(minutes=settings.refresh_token_expire_minutes),
        extra={"tenant_id": tenant_id},
    )


def create_endpoint_access_token(
    identity_id: str,
    *,
    tenant_id: str,
    endpoint_id: str,
    scopes: list[str],
    key_thumbprint: str,
) -> str:
    """Issue a short-lived proof-of-possession token for an endpoint identity."""
    return create_token(
        subject=identity_id,
        token_type="endpoint_access",
        expires_delta=timedelta(minutes=5),
        extra={
            "tenant_id": tenant_id,
            "endpoint_id": endpoint_id,
            "scope": list(scopes),
            "iss": "hawk-api",
            "aud": "hawk-endpoint-api",
            "nbf": int(datetime.now(timezone.utc).timestamp()),
            "cnf": {"jkt": key_thumbprint},
        },
    )


def decode_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm], options={"verify_iat": False})
    except JWTError as exc:
        raise ValueError("Invalid token") from exc


def decode_endpoint_access_token(token: str) -> dict[str, Any]:
    """Strictly validate an endpoint-only token and its dedicated audience."""
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm],
            audience="hawk-endpoint-api",
            issuer="hawk-api",
            options={"verify_iat": False},
        )
    except JWTError as exc:
        raise ValueError("Invalid endpoint token") from exc
    if payload.get("type") != "endpoint_access":
        raise ValueError("Invalid endpoint token type")
    return payload


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
