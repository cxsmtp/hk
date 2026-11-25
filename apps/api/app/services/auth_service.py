from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    token_hash,
    verify_password,
)
from app.db.models.user import RefreshToken, User, UserTenantRole


_DUMMY_BCRYPT_HASH = "$2b$12$C6UzMDM.H6dfI/f/IKcEe.5D6Q.Z5N6J8XcJteLoI0lp4rWuIwoL2"


def _as_utc(value: datetime | None) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    return datetime.min.replace(tzinfo=timezone.utc)


def authenticate_user(db: Session, email: str, password: str) -> User:
    user = db.scalar(select(User).where(User.email == email, User.is_active.is_(True)))
    hashed_password = user.hashed_password if user else _DUMMY_BCRYPT_HASH
    password_valid = verify_password(password, hashed_password)
    if not user or not password_valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return user


def get_user_tenants(db: Session, user_id: str) -> list[UserTenantRole]:
    return db.scalars(select(UserTenantRole).where(UserTenantRole.user_id == user_id)).all()


def issue_tokens(db: Session, *, user: User, tenant_id: str, role: str) -> dict:
    access_token = create_access_token(user.id, tenant_id=tenant_id, role=role)
    refresh_token = create_refresh_token(user.id, tenant_id=tenant_id)

    refresh_payload = decode_token(refresh_token)
    access_payload = decode_token(access_token)
    record = RefreshToken(
        user_id=user.id,
        tenant_id=tenant_id,
        token_hash=token_hash(refresh_token),
        expires_at=datetime.fromtimestamp(refresh_payload["exp"], tz=timezone.utc),
        created_at=datetime.now(timezone.utc),
    )
    db.add(record)
    db.flush()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": int(access_payload["exp"] - datetime.now(timezone.utc).timestamp()),
    }


def refresh_tokens(db: Session, refresh_token: str) -> dict:
    try:
        payload = decode_token(refresh_token)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from exc

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    user_id = payload.get("sub")
    tenant_id = payload.get("tenant_id")
    if not user_id or not tenant_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    record = db.scalar(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash(refresh_token),
            RefreshToken.user_id == user_id,
            RefreshToken.tenant_id == tenant_id,
            RefreshToken.revoked_at.is_(None),
        )
    )
    if not record:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked or unknown")

    now = datetime.now(timezone.utc)
    if _as_utc(record.expires_at) < now:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")
    # Idle sign-ins end (CxMissionZero's SESSION_IDLE_MINUTES, docs/sign-in.md): every refresh issues a new refresh
    # token, so the age of this one is the time since this sign-in was last used.
    if _as_utc(record.created_at) + timedelta(minutes=max(1, int(settings.session_idle_minutes))) < now:
        record.revoked_at = now
        db.flush()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Signed out after a time without activity")

    membership = db.scalar(
        select(UserTenantRole).where(UserTenantRole.user_id == user_id, UserTenantRole.tenant_id == tenant_id)
    )
    if not membership:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant membership not found")

    user = db.scalar(select(User).where(User.id == user_id, User.is_active.is_(True)))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User inactive")

    record.revoked_at = datetime.now(timezone.utc)
    db.flush()

    return issue_tokens(db, user=user, tenant_id=tenant_id, role=membership.role)
