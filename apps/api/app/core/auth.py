from __future__ import annotations

from datetime import timezone

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import access_gate
from app.core.log_config import update_log_context
from app.core.security import decode_token
from app.db.models.user import User
from app.db.session import get_db


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(
    request: Request = None,  # type: ignore[assignment]  # FastAPI fills it; direct callers pass it
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    try:
        payload = decode_token(token)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing subject")

    user = db.scalar(select(User).where(User.id == user_id, User.is_active.is_(True)))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    # Signed out everywhere (a password reset, docs/sign-in.md): tokens issued before that moment no longer work.
    signed_out = user.signed_out_at
    if signed_out is not None:
        if signed_out.tzinfo is None:
            signed_out = signed_out.replace(tzinfo=timezone.utc)
        if int(payload.get("iat") or 0) < int(signed_out.timestamp()):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Signed out")
    # Who is asking, on every log line of this request from now on (app/core/log_config.py).
    update_log_context(user_id=user.id)
    # A temporary password to change, or terms of use to accept, first (app/core/access_gate.py).
    access_gate.enforce(request, db, user)
    return user
