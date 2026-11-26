"""Signing in with a password, ported from CxMissionZero's src/iam.js (signIn, checkTwoStep, recordSignIn) and
src/routes/session.js (the limit per address, the sign-in policy). /settings/guide/people-and-access.

- Five wrong passwords in a row lock the account for 15 minutes. While it is locked, only someone who typed the right
  password learns it (423); to anyone else it looks like any wrong password (401), so nothing gives it away.
- Wrong two-step codes count as wrong passwords do.
- At most 30 sign-in attempts per 10 minutes from one network address (request.client.host: uvicorn takes it from
  X-Forwarded-For only behind the front proxy, which sets that header itself).
- The administrator's rules for the whole installation (sign_in_policy, one row): who may reset a forgotten password
  by email, whether two-step sign-in is required, and who may sign in through the identity provider.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import verify_password
from app.db.models.access import SignInPolicy
from app.db.models.user import RefreshToken, User, UserTenantRole
from app.services import mfa_service, sign_in_store
from app.services.sign_in_store import StoreUnavailable


logger = logging.getLogger(__name__)

MAX_FAILED = 5
LOCK_SECONDS = 15 * 60
SIGN_IN_LIMIT = 30
SIGN_IN_WINDOW_SECONDS = 10 * 60
ADMIN_ROLES = ("owner", "admin")
#: Roles people added at their first single sign-on may be given: never an owner or admin.
SSO_ROLES = ("viewer", "operator", "auditor")
RESET_POLICIES = ("everyone", "not-admins", "off")
POLICY_ID = 1

_DUMMY_BCRYPT_HASH = "$2b$12$C6UzMDM.H6dfI/f/IKcEe.5D6Q.Z5N6J8XcJteLoI0lp4rWuIwoL2"

WRONG = "Wrong email or password."
DISABLED = "This account is disabled. Ask an administrator."
TOO_MANY = "Too many sign-in attempts from this address. Wait a few minutes."


class SignInRefused(Exception):
    """A sign-in step refused: the HTTP status, the sentence for the person, and what the audit log needs."""

    def __init__(self, status_code: int, message: str, *, user: User | None = None, locked: bool = False, **extra: Any) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.user = user
        self.locked = locked
        self.extra = extra


def utcnow() -> datetime:
    return datetime.fromtimestamp(sign_in_store.now(), tz=timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def locked(user: User, now: datetime | None = None) -> bool:
    until = _as_utc(user.locked_until)
    return bool(until and until > (now or utcnow()))


def locked_message(user: User) -> str:
    until = _as_utc(user.locked_until) or utcnow()
    return f"Too many failed attempts: try again after {until.strftime('%H:%M:%S')} UTC, or ask an administrator."


def client_ip(request: Request | None) -> str:
    if request is None or request.client is None:
        return "unknown"
    return str(request.client.host or "unknown")


# ---------------------------------------------------------------------------------------------------------------------
# The limit per network address
# ---------------------------------------------------------------------------------------------------------------------


def too_many_sign_ins(request: Request | None) -> bool:
    """Count one attempt from this address; True when it is over 30 in 10 minutes.

    Should Redis be unreachable, the attempt is let through (the lock after 5 wrong passwords, kept in the database,
    still holds): a Redis outage must not lock everyone out of their own server."""

    try:
        recent = sign_in_store.store().hit(f"signin-ip:{client_ip(request)}", SIGN_IN_WINDOW_SECONDS, sign_in_store.now())
    except StoreUnavailable:
        logger.warning("Sign-in limit per address unavailable (Redis unreachable): the attempt is let through", extra={"reason_code": "store_unavailable"})
        return False
    return recent > SIGN_IN_LIMIT


# ---------------------------------------------------------------------------------------------------------------------
# The administrator's rules
# ---------------------------------------------------------------------------------------------------------------------


def policy(db: Session) -> SignInPolicy:
    row = db.get(SignInPolicy, POLICY_ID)
    if row is None:
        row = SignInPolicy(id=POLICY_ID)
        db.add(row)
        db.flush()
    return row


def sso_domains(row: SignInPolicy) -> list[str]:
    try:
        value = json.loads(row.sso_domains or "[]")
    except (TypeError, ValueError):
        return []
    return [str(item) for item in value if isinstance(item, str)] if isinstance(value, list) else []


_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def clean_domains(value: Any) -> list[str]:
    """A list of email domains from a text or a list: lower case, without "@". Anything that is not a domain raises
    ValueError with the sentence to show (CxMissionZero's cleanDomains)."""

    entries = value if isinstance(value, list) else re.split(r"[\s,;]+", str(value or ""))
    out: list[str] = []
    for entry in entries:
        domain = str(entry or "").strip().lower().lstrip("@")
        if not domain:
            continue
        if len(domain) > 253 or not _DOMAIN.match(domain):
            raise ValueError(f'"{domain[:60]}" is not an email domain. Write domains such as company.com, separated by commas.')
        if domain not in out:
            out.append(domain)
    return out[:50]


def is_admin(db: Session, user: User) -> bool:
    """An owner or admin of any tenant: Hawk's "Admin" for the sign-in rules (CxMissionZero: may manage people)."""

    return db.scalar(select(UserTenantRole.id).where(UserTenantRole.user_id == user.id, UserTenantRole.role.in_(ADMIN_ROLES)).limit(1)) is not None


def two_step_required(db: Session) -> bool:
    return bool(policy(db).two_step_required)


def two_step_on(user: User) -> bool:
    return bool(user.mfa_secret)


def needs_two_step(db: Session, user: User) -> bool:
    """A second step stands between this person's correct password and their tokens: they have it on, or an
    administrator requires it."""

    return two_step_on(user) or two_step_required(db)


def password_not_enough(db: Session, user: User) -> bool:
    """Single sign-on is on and "only Admins may still sign in with a password": a correct password is not enough for
    anyone else."""

    from app.core.config import settings

    return bool(settings.company_sso_enabled and policy(db).sso_password_admins_only and not is_admin(db, user))


# ---------------------------------------------------------------------------------------------------------------------
# Passwords and codes
# ---------------------------------------------------------------------------------------------------------------------


def find_by_email(db: Session, email: str) -> User | None:
    text = str(email or "").strip()
    if not text or len(text) > 320:
        return None
    return db.scalar(select(User).where(func.lower(User.email) == text.lower()))


def _lock_user(db: Session, user: User) -> None:
    """Hold the person's row until the caller commits (PostgreSQL ``SELECT … FOR UPDATE``), reading it afresh: two
    sign-in attempts at the same moment are then checked one after the other, so neither the wrong-attempt count (and
    so the lock), nor a two-step code's step, nor a recovery code can be used twice by racing requests."""

    db.flush()
    db.refresh(user, with_for_update=True)


def _count_wrong(user: User, now: datetime) -> None:
    user.failed_logins = int(user.failed_logins or 0) + 1
    if user.failed_logins >= MAX_FAILED:
        user.locked_until = now + timedelta(seconds=LOCK_SECONDS)
        user.failed_logins = 0
        logger.warning(
            "Account locked after %d failed sign-in attempts",
            MAX_FAILED,
            extra={"user_id": user.id, "locked_seconds": LOCK_SECONDS, "reason_code": "account_locked"},
        )


def check_password(db: Session, email: str, password: str, *, more: bool | None = None) -> User:
    """Check an email and password. Returns the user, or raises SignInRefused: 401 (the same sentence whether the
    account exists or not), 423 when locked (only to someone who typed the right password), 403 when disabled.

    The caller commits: the wrong attempts counted here must be kept even when the answer is a refusal.
    ``more``: a second step follows, so the sign-in is not recorded yet (and wrong attempts keep counting)."""

    now = utcnow()
    user = find_by_email(db, email)
    if user is not None:
        _lock_user(db, user)
    ok = verify_password(str(password or ""), user.hashed_password if user else _DUMMY_BCRYPT_HASH)
    if user is None:
        raise SignInRefused(401, WRONG)
    if locked(user, now):
        if not ok:
            raise SignInRefused(401, WRONG, user=user, locked=True)
        raise SignInRefused(423, locked_message(user), user=user, locked=True)
    if not ok:
        _count_wrong(user, now)
        db.flush()
        raise SignInRefused(401, WRONG, user=user, locked=locked(user, now))
    if not user.is_active:
        raise SignInRefused(403, DISABLED, user=user)
    if not (needs_two_step(db, user) if more is None else more):
        record_sign_in(user)
    return user


def record_sign_in(user: User) -> None:
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = utcnow()


def check_two_step(db: Session, user: User, typed: Any, *, recovery: bool = True) -> dict[str, Any]:
    """Check a code from the authenticator app, or (unless ``recovery`` is False) a recovery code, which is then gone.
    Returns {kind: 'code' | 'recovery', left}. A wrong one raises SignInRefused 401 and counts as a wrong password
    does: five in a row lock the account for 15 minutes (423 while it is locked). The caller commits."""

    _lock_user(db, user)
    secret = mfa_service.open_secret(user.mfa_secret)
    if not secret:
        raise SignInRefused(400, "Two-step sign-in is not on.", user=user)
    now = utcnow()
    if locked(user, now):
        raise SignInRefused(423, locked_message(user), user=user, locked=True)
    codes = mfa_service.recovery_list(user.mfa_recovery)
    if mfa_service.typed_code(typed):
        step = mfa_service.match_totp(secret, typed, now=now.timestamp(), after=int(user.mfa_last_step or 0))
        if step:
            user.mfa_last_step = step
            db.flush()
            return {"kind": "code", "left": len(codes)}
    elif recovery and mfa_service.typed_recovery_code(typed):
        wanted = mfa_service.recovery_hash(user.id, str(typed))
        index = next((i for i, kept in enumerate(codes) if len(kept) == len(wanted) and _same(kept, wanted)), -1)
        if index >= 0:
            codes.pop(index)
            user.mfa_recovery = json.dumps(codes)
            db.flush()
            return {"kind": "recovery", "left": len(codes)}
    _count_wrong(user, now)
    db.flush()
    raise SignInRefused(401, "That code is not right.", user=user, locked=locked(user, now))


def _same(a: str, b: str) -> bool:
    import hmac

    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def enable_two_step(user: User, secret: str, *, step: int) -> list[str]:
    """Turn two-step sign-in on with a secret the person's app has just proved it holds: ten new recovery codes,
    shown this once."""

    codes = mfa_service.new_recovery_codes()
    user.mfa_secret = mfa_service.seal_secret(secret)
    user.mfa_enabled_at = utcnow()
    user.mfa_last_step = int(step)
    user.mfa_recovery = json.dumps([mfa_service.recovery_hash(user.id, code) for code in codes])
    return codes


def reset_two_step(user: User) -> bool:
    """Take two-step sign-in off (the person's own choice, an administrator's reset, RESET_TWO_STEP, reset_admin).
    Nothing of the secret stays. Returns whether it was on."""

    had = bool(user.mfa_secret)
    user.mfa_secret = None
    user.mfa_enabled_at = None
    user.mfa_last_step = 0
    user.mfa_recovery = None
    try:
        mfa_service.revoke_tickets(user.id)
        mfa_service.clear_setup(user.id)
    except StoreUnavailable:
        pass
    return had


def sign_out_everywhere(db: Session, user: User) -> int:
    """Every refresh token of this person stops working, and access tokens issued before now are refused
    (app/core/auth.py). Returns how many refresh tokens were revoked."""

    # The real clock: it is compared with the issue time of tokens (app/core/security.py), which uses it too.
    now = datetime.now(timezone.utc)
    count = 0
    for record in db.scalars(select(RefreshToken).where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))):
        record.revoked_at = now
        count += 1
    user.signed_out_at = now
    return count


def two_step_view(db: Session, user: User) -> dict[str, Any]:
    """Two-step sign-in for this person: on or not, since when, recovery codes left, and whether it is required."""

    on = two_step_on(user)
    return {
        "available": bool(user.hashed_password) and not user.hashed_password.startswith("!"),
        "on": on,
        "since": _as_utc(user.mfa_enabled_at).isoformat() if on and user.mfa_enabled_at else "",
        "recoveryLeft": len(mfa_service.recovery_list(user.mfa_recovery)) if on else 0,
        "required": two_step_required(db),
    }
