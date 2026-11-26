"""Two-step sign-in, forgotten passwords and the administrator's sign-in rules, ported from CxMissionZero's
src/routes/session.js (/settings/guide/people-and-access).

Before signing in:
- GET  /auth/sign-in-options           what the sign-in page offers ("Forgot your password?")
- POST /auth/two-step                  the ticket from the password step and a code: only then are there tokens
- POST /auth/password-reset            "Forgot your password?": always the same answer
- POST /auth/password-reset/check      does a link still work? (whose account, partly hidden)
- POST /auth/password-reset/confirm    the new password: the link is used up and the account signed out everywhere

Signed in, for oneself:
- POST /auth/me/two-step/setup | enable | disable | recovery-codes

An owner or admin (for the whole installation; Settings → Sign-in):
- GET/PUT /auth/sign-in-settings, POST /auth/sign-in-settings/test-email
- GET /auth/sign-in-settings/people, DELETE …/people/{id}/two-step, DELETE …/people/{id}/sso-link
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from time import perf_counter, sleep
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Body, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.routers.auth import audit_access, refused, signed_in_response
from app.core import session_cookies
from app.core.auth import get_current_user
from app.core.config import settings
from app.core.log_config import mask_email
from app.core.rbac import require_permission
from app.core.security import get_password_hash, verify_password
from app.core.tenant import TenantContext
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import get_db
from app.services import account_security, mailer, mfa_service, password_reset_service, sign_in_store
from app.services.account_security import SignInRefused
from app.services.audit_service import write_audit_log
from app.services import password_policy
from app.services.sign_in_store import StoreUnavailable


router = APIRouter(prefix="/auth", tags=["sign-in"])

TICKET_OVER = "That sign-in is over: it lasts five minutes and takes a few tries. Sign in again."
WRONG_CODE = "That code is not right. Use the newest code in your authenticator app, and check that the phone's clock is right."
UNAVAILABLE = "Sign-in is unavailable for a moment. Try again shortly."
_RESET_MIN_RESPONSE_SECONDS = 0.25


logger = logging.getLogger(__name__)


def _no_store(content: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(status_code=status_code, content=content, headers={"Cache-Control": "no-store"})


def _utc(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ---------------------------------------------------------------------------------------------------------------------
# What the sign-in page offers
# ---------------------------------------------------------------------------------------------------------------------


def password_reset_ready(db: Session) -> dict[str, Any]:
    """Whether "Forgot your password?" can work, and if not why: an administrator allows it, the email server is set
    up and tested, and the server's https address is set."""

    row = account_security.policy(db)
    missing = []
    if row.password_reset == "off":
        missing.append("Turned off.")
    if not mailer.configured() or row.smtp_verified != mailer.fingerprint():
        missing.append("The email server is not set up and tested (Settings → Email (SMTP)).")
    if not password_reset_service.link_base():
        missing.append("No https address for this server is set (PUBLIC_URL / WEB_ORIGIN).")
    return {"ready": not missing, "policy": row.password_reset, "missing": missing}


@router.get("/sign-in-options")
def sign_in_options(db: Session = Depends(get_db)):
    ready = password_reset_ready(db)["ready"]
    admins_only = bool(settings.company_sso_enabled and account_security.policy(db).sso_password_admins_only)
    db.commit()
    banner = account_security.policy(db).banner_text or ""
    db.commit()
    return _no_store({"passwordReset": ready, "ssoPasswordAdminsOnly": admins_only, "banner": banner})


# ---------------------------------------------------------------------------------------------------------------------
# The second step
# ---------------------------------------------------------------------------------------------------------------------


@router.post("/two-step")
def two_step(request: Request, body: Annotated[dict[str, Any] | None, Body()] = None, db: Session = Depends(get_db)):
    """The ticket from the password step, and a code (or a recovery code). Only then are there tokens."""

    body = body or {}
    if account_security.too_many_sign_ins(request):
        return refused(429, account_security.TOO_MANY)
    ticket_value = str(body.get("ticket") or "")
    typed = str(body.get("code") or "")[:40]
    try:
        entry = mfa_service.ticket(ticket_value)
    except StoreUnavailable:
        return refused(503, UNAVAILABLE)
    user = db.get(User, entry["user_id"]) if entry else None

    def refuse(status_code: int, message: str, why: str, **extra: Any) -> JSONResponse:
        audit_access(db, user, action="auth.sign_in.refused", reason=f"Sign-in refused{f' for {user.email}' if user else ''}: {why}", request=request)
        db.commit()
        return refused(status_code, message, **extra)

    if not entry or user is None:
        return refuse(401, TICKET_OVER, "the two-step sign-in was over, or was never started.", restart=True)
    if not user.is_active:
        mfa_service.consume_ticket(ticket_value)
        return refuse(403, account_security.DISABLED, "the account is disabled.", restart=True)
    how = "signed in with a password and a two-step code"
    recovery_codes: list[str] | None = None
    if entry["secret"]:
        # An administrator requires two-step sign-in and this person had none: the first right code turns it on.
        if account_security.two_step_on(user):
            mfa_service.consume_ticket(ticket_value)
            return refuse(409, "Two-step sign-in was turned on for this account in the meantime. Sign in again.", "two-step sign-in was set up elsewhere in the meantime.", restart=True)
        step = mfa_service.match_totp(entry["secret"], typed)
        if not step:
            left = mfa_service.ticket_wrong(ticket_value)
            return refuse(401, WRONG_CODE if left else TICKET_OVER, "wrong code while setting up two-step sign-in.", restart=not left)
        recovery_codes = account_security.enable_two_step(user, entry["secret"], step=step)
        audit_access(db, user, action="auth.two_step.enabled", reason=f"{user.email} turned on two-step sign-in (required at sign-in).", request=request)
        how = "signed in with a password and set up two-step sign-in"
    else:
        if not account_security.two_step_on(user):
            mfa_service.consume_ticket(ticket_value)
            return refuse(409, "Two-step sign-in was reset for this account in the meantime. Sign in again.", "two-step sign-in was reset in the meantime.", restart=True)
        try:
            result = account_security.check_two_step(db, user, typed)
        except SignInRefused as refusal:
            db.commit()  # the wrong code counts towards the lock
            if refusal.status_code == 423:
                mfa_service.consume_ticket(ticket_value)
                return refuse(423, refusal.message, "the account is locked after too many wrong attempts.", restart=True)
            left = mfa_service.ticket_wrong(ticket_value)
            over = not left or refusal.locked
            if over:
                mfa_service.consume_ticket(ticket_value)
            return refuse(401, TICKET_OVER if over else WRONG_CODE, f"wrong two-step code.{' Account locked.' if refusal.locked else ''}", restart=over)
        if result["kind"] == "recovery":
            audit_access(db, user, action="auth.two_step.recovery_used", reason=f"{user.email} used a recovery code to sign in: it is gone, {result['left']} left.", request=request)
            how = f"signed in with a password and a recovery code ({result['left']} left)"
    if not mfa_service.consume_ticket(ticket_value):
        # Used by another request at the same moment: one ticket gives one sign-in.
        return refuse(401, TICKET_OVER, "the two-step ticket was used at the same moment.", restart=True)
    account_security.record_sign_in(user)
    response = signed_in_response(db, user)
    audit_access(db, user, action="auth.sign_in", reason=f"{user.email} {how}.", request=request)
    db.commit()
    content = json.loads(response.model_dump_json())
    if recovery_codes:
        content["recovery_codes"] = recovery_codes
    # The console's session: the tokens as cookies (app/core/session_cookies.py).
    return session_cookies.answer(request, content, 200)


# ---------------------------------------------------------------------------------------------------------------------
# Two-step sign-in for oneself
# ---------------------------------------------------------------------------------------------------------------------


def _me(db: Session, user: User) -> dict[str, Any]:
    return {"two_step": account_security.two_step_view(db, user)}


@router.post("/me/two-step/setup")
def two_step_setup(current_user: Annotated[User, Depends(get_current_user)], db: Session = Depends(get_db)):
    """Someone signed in turns two-step sign-in on: first a secret to put in their authenticator app (kept for ten
    minutes until a code proves the app holds it)."""

    if current_user.hashed_password.startswith("!"):
        return refused(400, "Two-step sign-in is for people who sign in with a password. Set a password first.")
    if account_security.two_step_on(current_user):
        return refused(400, "Two-step sign-in is already on.")
    try:
        secret = mfa_service.start_setup(current_user.id)
    except StoreUnavailable:
        return refused(503, UNAVAILABLE)
    return _no_store(mfa_service.setup_view(current_user.email, secret))


@router.post("/me/two-step/enable")
def two_step_enable(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    body: Annotated[dict[str, Any] | None, Body()] = None,
    db: Session = Depends(get_db),
):
    """…then the code the app shows: only now is it on. The recovery codes are shown this once."""

    if account_security.two_step_on(current_user):
        return refused(400, "Two-step sign-in is already on.")
    try:
        secret = mfa_service.pending_setup(current_user.id)
    except StoreUnavailable:
        return refused(503, UNAVAILABLE)
    if not secret:
        return refused(400, "That key is more than ten minutes old. Start again.", restart=True)
    step = mfa_service.match_totp(secret, (body or {}).get("code"))
    if not step:
        return refused(400, WRONG_CODE)
    codes = account_security.enable_two_step(current_user, secret, step=step)
    mfa_service.clear_setup(current_user.id)
    audit_access(db, current_user, action="auth.two_step.enabled", reason=f"{current_user.email} turned on two-step sign-in.", request=request)
    db.commit()
    return _no_store({"recovery_codes": codes, **_me(db, current_user)})


def _own_code(db: Session, request: Request, user: User, typed: Any, what: str) -> JSONResponse | None:
    """A current code from the app (a recovery code is not enough). Wrong ones count towards the lock."""

    try:
        account_security.check_two_step(db, user, typed, recovery=False)
        return None
    except SignInRefused as refusal:
        if refusal.status_code not in (401, 423):
            return refused(refusal.status_code, refusal.message)
        audit_access(db, user, action="auth.two_step.refused", reason=f"{user.email} could not {what}: {'too many wrong codes' if refusal.status_code == 423 else 'wrong code'}.", request=request)
        db.commit()
        return refused(423 if refusal.status_code == 423 else 400, refusal.message if refusal.status_code == 423 else WRONG_CODE)


@router.post("/me/two-step/disable")
def two_step_disable(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    body: Annotated[dict[str, Any] | None, Body()] = None,
    db: Session = Depends(get_db),
):
    """Turn one's own two-step sign-in off: only with a current code, and not while an administrator requires it."""

    if not account_security.two_step_on(current_user):
        return refused(400, "Two-step sign-in is not on.")
    if account_security.two_step_required(db):
        return refused(403, "An administrator requires two-step sign-in for everyone who signs in with a password, so it cannot be turned off.")
    problem = _own_code(db, request, current_user, (body or {}).get("code"), "turn off two-step sign-in")
    if problem is not None:
        return problem
    account_security.reset_two_step(current_user)
    audit_access(db, current_user, action="auth.two_step.disabled", reason=f"{current_user.email} turned off two-step sign-in.", request=request)
    db.commit()
    return _no_store(_me(db, current_user))


@router.post("/me/two-step/recovery-codes")
def two_step_recovery_codes(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    body: Annotated[dict[str, Any] | None, Body()] = None,
    db: Session = Depends(get_db),
):
    """Ten new recovery codes in place of the old ones: with a current code."""

    if not account_security.two_step_on(current_user):
        return refused(400, "Two-step sign-in is not on.")
    problem = _own_code(db, request, current_user, (body or {}).get("code"), "make new recovery codes")
    if problem is not None:
        return problem
    codes = mfa_service.new_recovery_codes()
    current_user.mfa_recovery = json.dumps([mfa_service.recovery_hash(current_user.id, code) for code in codes])
    audit_access(db, current_user, action="auth.two_step.recovery_codes", reason=f"{current_user.email} made new recovery codes; the old ones no longer work.", request=request)
    db.commit()
    return _no_store({"recovery_codes": codes, **_me(db, current_user)})


# ---------------------------------------------------------------------------------------------------------------------
# Forgotten password
# ---------------------------------------------------------------------------------------------------------------------


def _send_in_background(message, to: str, user_id: str) -> None:  # type: ignore[no-untyped-def]
    try:
        mailer.send(message, to)
    except mailer.MailError as error:
        # The link cannot be used by anyone: it is ended.
        try:
            password_reset_service.revoke_user(user_id)
        except StoreUnavailable:
            pass
        logger.warning("[password reset] The link for %s could not be sent: %s", mask_email(to), error, extra={"user_id": user_id})


@router.post("/password-reset")
def password_reset(request: Request, background: BackgroundTasks, body: Annotated[dict[str, Any] | None, Body()] = None, db: Session = Depends(get_db)):
    """"Forgot your password?": always the same answer, whether or not the address has an account. The email itself
    goes out after the answer is given."""

    started = perf_counter()
    try:
        ip = account_security.client_ip(request)
        try:
            if password_reset_service.ip_blocked(ip):
                return refused(429, password_reset_service.TOO_MANY)
            password_reset_service.note_ip(ip)
        except StoreUnavailable:
            return refused(503, UNAVAILABLE)
        email = str((body or {}).get("email") or "").strip()[:254]
        if not email:
            return refused(400, "Enter the email address you sign in with.")
        try:
            _queue_reset_link(db, request, background, email)
        except StoreUnavailable:
            pass
        db.commit()
        return _no_store({"message": password_reset_service.RESET_ASKED}, 202)
    finally:
        remaining = _RESET_MIN_RESPONSE_SECONDS - (perf_counter() - started)
        if remaining > 0:
            sleep(remaining)


def _queue_reset_link(db: Session, request: Request, background: BackgroundTasks, email: str) -> None:
    user = account_security.find_by_email(db, email)
    row = account_security.policy(db)
    base = password_reset_service.link_base()
    if user is None:
        why = "no account has that address"
    elif not user.is_active:
        why = "the account is disabled"
    elif not user.hashed_password or user.hashed_password.startswith("!"):
        why = "the account signs in with single sign-on only"
    elif not password_reset_service.reset_allowed(row.password_reset, is_admin=account_security.is_admin(db, user)):
        why = "resetting by email is not allowed for this account"
    elif not base or not mailer.configured() or row.smtp_verified != mailer.fingerprint():
        why = "email or the server address is not set up"
    elif not password_reset_service.may_send(user.id):
        why = "too many links for this account in the last hour"
    else:
        why = ""
    if why:
        # What was typed is kept only when it is an account here: it may be a password typed in the wrong box.
        audit_access(db, user, action="auth.password_reset.refused", reason=f"Password reset asked{f' for {user.email}' if user else ' for an address with no account here'}: no link sent ({why}).", request=request)
        return
    assert user is not None
    token, exp = password_reset_service.issue(user.id, user.hashed_password)
    # The secret travels after #: browsers never send that part to a server, nor in a Referer.
    link = f"{base}/login/reset#reset={token}"
    message = mailer.system_email(
        subject="Reset your Hawk AI password",
        lines=[
            f"Someone, hopefully you, asked to reset the password of {user.email} on Hawk AI.",
            "To choose a new password, open the link below. It works once, for 30 minutes, and only on this server.",
        ],
        facts=[("Asked from", account_security.client_ip(request)), ("Asked at", _utc(sign_in_store.now())), ("Link works until", _utc(exp))],
        buttons=[("Choose a new password", link)],
        footer="Did not ask for this? Ignore this email: your password stays as it is, and the link stops working by itself. If it keeps happening, tell an administrator.",
    )
    audit_access(db, user, action="auth.password_reset.sent", reason=f"Password reset link sent to {user.email} (works until {_utc(exp)}).", request=request)
    background.add_task(_send_in_background, message, user.email, user.id)


def _reset_user(db: Session, token: Any) -> User | None:
    user = password_reset_service.check(token, lambda user_id: db.get(User, user_id))
    if user is None:
        return None
    if not password_reset_service.reset_allowed(account_security.policy(db).password_reset, is_admin=account_security.is_admin(db, user)):
        return None
    return user


@router.post("/password-reset/check")
def password_reset_check(request: Request, body: Annotated[dict[str, Any] | None, Body()] = None, db: Session = Depends(get_db)):
    """Does a link still work? Says whose account it is for (partly hidden), so the person knows."""

    ip = account_security.client_ip(request)
    try:
        if password_reset_service.ip_blocked(ip):
            return refused(429, password_reset_service.TOO_MANY)
        user = _reset_user(db, (body or {}).get("token"))
        if user is None:
            password_reset_service.note_ip(ip)
            return refused(400, password_reset_service.RESET_DEAD)
    except StoreUnavailable:
        return refused(503, UNAVAILABLE)
    return _no_store({"email": password_reset_service.mask_email(user.email), "minutes": password_reset_service.RESET_TTL_SECONDS // 60})


@router.post("/password-reset/confirm")
def password_reset_confirm(
    request: Request,
    background: BackgroundTasks,
    body: Annotated[dict[str, Any] | None, Body()] = None,
    db: Session = Depends(get_db),
):
    """Choose the new password: the link is used up, and every sign-in of the account ends."""

    body = body or {}
    ip = account_security.client_ip(request)
    token = str(body.get("token") or "")
    password = str(body.get("password") or "")
    try:
        if password_reset_service.ip_blocked(ip):
            return refused(429, password_reset_service.TOO_MANY)
        user = _reset_user(db, token)
        if user is None:
            password_reset_service.note_ip(ip)
            return refused(400, password_reset_service.RESET_DEAD)
        problem = password_policy.problem(db, password, user=user)
        if problem:
            return refused(400, problem)
        if verify_password(password, user.hashed_password):
            return refused(400, "Choose a password different from the current one.")
        # Taken at once: one link sets one password, even when two requests use it at the same moment.
        if not password_reset_service.consume(token):
            password_reset_service.note_ip(ip)
            return refused(400, password_reset_service.RESET_DEAD)
    except StoreUnavailable:
        return refused(503, UNAVAILABLE)
    password_policy.remember(user, get_password_hash(password))
    user.must_change_password = False
    # Saving it clears a lock after wrong passwords, and signs the account out everywhere.
    user.failed_logins = 0
    user.locked_until = None
    account_security.sign_out_everywhere(db, user)
    try:
        mfa_service.revoke_tickets(user.id)
    except StoreUnavailable:
        pass
    audit_access(db, user, action="auth.password_reset.done", reason=f"{user.email} reset their password with an emailed link.", request=request)
    db.commit()
    if mailer.configured():
        confirmation = mailer.system_email(
            subject="Your Hawk AI password was changed",
            lines=[f"The password of {user.email} on Hawk AI was just changed with a reset link sent to this address, and every place it was signed in was signed out."],
            facts=[("Changed from", ip), ("Changed at", _utc(sign_in_store.now()))],
            footer="Was this not you? Tell an administrator at once: they can disable the account and set a new password.",
        )
        background.add_task(_send_in_background, confirmation, user.email, user.id)
    return _no_store({"email": user.email})


# ---------------------------------------------------------------------------------------------------------------------
# The administrator's sign-in rules (Settings → Sign-in)
# ---------------------------------------------------------------------------------------------------------------------


AdminContext = Annotated[TenantContext, Depends(require_permission("security.sso"))]


def _audit_admin(db: Session, ctx: TenantContext, *, action: str, reason: str, payload: dict[str, Any] | None = None) -> None:
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human",
        action=action,
        resource_type="sign_in_policy",
        resource_id="sign-in",
        payload={"reason": reason, **(payload or {})},
    )


def _providers_view() -> list[dict[str, str]]:
    from app.services import oidc_auth_service

    try:
        rows = oidc_auth_service.providers()
    except oidc_auth_service.OIDCError:
        return []
    return [
        {"key": p.key, "kind": p.kind, "label": p.display_name, "workspace": p.workspace_slug, "issuer": p.issuer, "clientId": p.client_id}
        for p in rows
    ]


def settings_view(db: Session) -> dict[str, Any]:
    row = account_security.policy(db)
    smtp = mailer.current()
    return {
        "passwordReset": row.password_reset,
        "passwordResetReady": password_reset_ready(db),
        "twoStepRequired": bool(row.two_step_required),
        "sso": {
            "enabled": bool(settings.company_sso_enabled),
            "provision": row.sso_provision,
            "role": row.sso_role,
            "domains": account_security.sso_domains(row),
            "requireVerifiedEmail": bool(row.sso_require_verified_email),
            "passwordAdminsOnly": bool(row.sso_password_admins_only),
            "callbackUrl": settings.oidc_callback_url,
            "roles": list(account_security.SSO_ROLES),
            # The identity providers themselves are configuration (OIDC_PROVIDERS_JSON): shown, never the secrets.
            "providers": _providers_view(),
        },
        "email": {
            "configured": mailer.configured(smtp),
            "host": smtp.host,
            "port": smtp.port,
            "from": smtp.from_address,
            "tested": bool(row.smtp_verified) and row.smtp_verified == mailer.fingerprint(smtp),
        },
        "serverAddress": password_reset_service.link_base(),
        # The idle sign-out in force; sessionIdleSet: the value set here (None: SESSION_IDLE_MINUTES).
        "sessionIdleMinutes": account_security.idle_minutes(db),
        "sessionIdleSet": row.session_idle_minutes,
        "sessionIdleDefault": int(settings.session_idle_minutes),
        "passwordRule": {**password_policy.rule(db).view(), "text": password_policy.describe(password_policy.rule(db))},
        "banner": row.banner_text or "",
        "baseline": dict(password_policy.BASELINE),
    }


@router.get("/sign-in-settings")
def get_sign_in_settings(ctx: AdminContext, db: Session = Depends(get_db)):
    view = settings_view(db)
    db.commit()
    return _no_store(view)


@router.put("/sign-in-settings")
def put_sign_in_settings(ctx: AdminContext, body: Annotated[dict[str, Any] | None, Body()] = None, db: Session = Depends(get_db)):
    body = body or {}
    row = account_security.policy(db)
    changes: list[str] = []
    if "passwordReset" in body:
        wanted = str(body.get("passwordReset") or "")
        if wanted not in password_reset_service.RESET_POLICIES:
            return refused(400, "Choose who may reset a forgotten password by email: everyone with a password, everyone except Admins, or nobody.")
        if wanted != row.password_reset:
            names = password_reset_service.POLICY_NAMES
            changes.append(f"Password reset by email: {names[row.password_reset]} → {names[wanted]}.")
            row.password_reset = wanted
    if "twoStepRequired" in body:
        wanted_on = body.get("twoStepRequired") is True
        if wanted_on != bool(row.two_step_required):
            changes.append(f"Two-step sign-in for everyone who signs in with a password: {'required' if row.two_step_required else 'not required'} → {'required' if wanted_on else 'not required'}.")
            row.two_step_required = wanted_on
    rule_body = body.get("passwordRule")
    if isinstance(rule_body, dict):
        values, problem = password_policy.clean(rule_body)
        if problem:
            return refused(400, problem)
        before = password_policy.rule(db)
        columns = {"minLength": "password_min_length", "classes": "password_classes", "history": "password_history", "maxAgeDays": "password_max_age_days"}
        for key, value in values.items():
            setattr(row, columns[key], value)
        db.flush()
        after = password_policy.rule(db)
        if after != before:
            changes.append(f"Password rule: {password_policy.describe(before)} → {password_policy.describe(after)}.")
    if "sessionIdleMinutes" in body:
        wanted_idle = body.get("sessionIdleMinutes")
        if wanted_idle in (None, "", 0, "0"):
            new_idle = None
        else:
            try:
                new_idle = int(str(wanted_idle).strip())
            except ValueError:
                new_idle = -1
            if isinstance(wanted_idle, bool) or not account_security.MIN_IDLE_MINUTES <= new_idle <= account_security.MAX_IDLE_MINUTES:
                return refused(400, f"Sign out after {account_security.MIN_IDLE_MINUTES} to {account_security.MAX_IDLE_MINUTES} minutes without activity, or leave it empty for SESSION_IDLE_MINUTES.")
        if new_idle != row.session_idle_minutes:
            def said(value: int | None) -> str:
                return f"{value} minutes" if value else f"SESSION_IDLE_MINUTES ({int(settings.session_idle_minutes)} minutes)"

            changes.append(f"Idle sign-out: {said(row.session_idle_minutes)} → {said(new_idle)}.")
            row.session_idle_minutes = new_idle
    if "banner" in body:
        banner = str(body.get("banner") or "").replace("\r\n", "\n").strip()
        if len(banner) > account_security.MAX_BANNER:
            return refused(400, f"The sign-in notice is at most {account_security.MAX_BANNER} characters.")
        if banner != (row.banner_text or ""):
            changes.append("Sign-in notice: " + ("set." if banner and not row.banner_text else "changed." if banner else "removed."))
            row.banner_text = banner
    sso = body.get("sso")
    if isinstance(sso, dict):
        provision = row.sso_provision
        role = row.sso_role
        domains = account_security.sso_domains(row)
        if "domains" in sso:
            try:
                domains = account_security.clean_domains(sso.get("domains"))
            except ValueError as error:
                return refused(400, str(error))
        if "provision" in sso:
            if sso.get("provision") not in ("existing", "create"):
                return refused(400, "Choose who may sign in this way: people already here, or everyone the identity provider signs in.")
            provision = str(sso["provision"])
        if "role" in sso:
            role = str(sso.get("role") or "")
        if provision == "create":
            # Without a domain, everyone the identity provider signs in (a guest, another organisation's account) would be added.
            if not domains:
                return refused(400, "List at least one email domain allowed before adding people at their first single sign-on. Otherwise everyone the identity provider signs in would be added.")
            if role in account_security.ADMIN_ROLES:
                return refused(400, "People added by single sign-on cannot be given the owner or admin role. Choose another role, and make someone an admin yourself.")
            if role not in account_security.SSO_ROLES:
                return refused(400, "Choose the role people added by single sign-on get.")
        elif role not in account_security.SSO_ROLES:
            role = row.sso_role
        admins_only = bool(row.sso_password_admins_only)
        if "passwordAdminsOnly" in sso:
            admins_only = sso.get("passwordAdminsOnly") is True
            if admins_only and not settings.company_sso_enabled:
                return refused(400, "Turn single sign-on on before keeping passwords for Admins only.")
        verified = bool(row.sso_require_verified_email)
        if "requireVerifiedEmail" in sso:
            verified = sso.get("requireVerifiedEmail") is not False
        before = {"provision": row.sso_provision, "role": row.sso_role, "domains": account_security.sso_domains(row), "requireVerifiedEmail": bool(row.sso_require_verified_email), "passwordAdminsOnly": bool(row.sso_password_admins_only)}
        after = {"provision": provision, "role": role, "domains": domains, "requireVerifiedEmail": verified, "passwordAdminsOnly": admins_only}
        names = {"provision": "who may sign in", "role": "role for new people", "domains": "email domains", "requireVerifiedEmail": "verified email check", "passwordAdminsOnly": "passwords for Admins only"}
        changed = [names[key] for key in names if before[key] != after[key]]
        if changed:
            changes.append(f"Changed single sign-on: {', '.join(changed)}.")
            row.sso_provision = provision
            row.sso_role = role
            row.sso_domains = json.dumps(domains)
            row.sso_require_verified_email = verified
            row.sso_password_admins_only = admins_only
    for reason in changes:
        _audit_admin(db, ctx, action="auth.sign_in_policy.changed", reason=reason)
    db.commit()
    return _no_store(settings_view(db))


@router.post("/sign-in-settings/test-email")
def test_email(ctx: AdminContext, background: BackgroundTasks, db: Session = Depends(get_db)):
    """Send a test email to oneself with the email server in force (Settings → Email (SMTP), else SMTP_*): once it arrives, password reset links may be sent with
    exactly these settings (CxMissionZero's isVerified)."""

    smtp = mailer.current()
    if not mailer.configured(smtp):
        return refused(400, "Set up the email server first (Settings → Email (SMTP)): a mail server and a From address.")
    to = ctx.user.email if ctx.user else ""
    message = mailer.system_email(subject="Hawk AI — test message", lines=["This is a test message from Hawk AI. Email is working: password reset links can be sent."])
    try:
        mailer.send(message, to, smtp=smtp)
    except mailer.MailError as error:
        _audit_admin(db, ctx, action="auth.email.test_failed", reason=f"Test email to {to} failed: {error}")
        db.commit()
        return refused(400, str(error))
    mailer.mark_verified(db, smtp)
    _audit_admin(db, ctx, action="auth.email.tested", reason=f"Test email sent to {to}; password reset links may use this email server.")
    db.commit()
    # Copies of the licence agreement waiting for the email server go out now (app/services/terms_copy_service.py).
    from app.services import terms_copy_service

    background.add_task(terms_copy_service.deliver_with, db.get_bind())
    return _no_store({"message": f"A test message was sent to {to}.", **settings_view(db)})


def _target(db: Session, ctx: TenantContext, user_id: str) -> tuple[User, UserTenantRole] | JSONResponse:
    membership = db.scalar(select(UserTenantRole).where(UserTenantRole.user_id == user_id, UserTenantRole.tenant_id == ctx.tenant.id))
    user = db.get(User, user_id) if membership else None
    if user is None or membership is None:
        return refused(404, "No such person in this workspace.")
    # Only for people whose role is not above one's own (CxMissionZero's canGrant).
    from app.services import iam_service

    if not iam_service.can_grant(ctx.permissions, ctx.role_key, iam_service.role(db, ctx.tenant.id, membership.role)):
        return refused(403, "You cannot change this person's sign-in: their role is above yours.")
    return user, membership


@router.get("/sign-in-settings/people")
def people(ctx: AdminContext, db: Session = Depends(get_db)):
    rows = db.execute(
        select(User, UserTenantRole.role)
        .join(UserTenantRole, UserTenantRole.user_id == User.id)
        .where(UserTenantRole.tenant_id == ctx.tenant.id)
        .order_by(User.email)
    ).all()
    now = account_security.utcnow()
    return _no_store(
        {
            "people": [
                {
                    "id": user.id,
                    "email": user.email,
                    "name": user.full_name,
                    "role": role,
                    "active": bool(user.is_active),
                    "twoStep": account_security.two_step_on(user),
                    "ssoLinked": bool(user.sso_subject),
                    "locked": account_security.locked(user, now),
                    "lastSignIn": user.last_login_at.isoformat() if user.last_login_at else "",
                    "you": ctx.user is not None and user.id == ctx.user.id,
                }
                for user, role in rows
            ]
        }
    )


@router.delete("/sign-in-settings/people/{user_id}/two-step")
def reset_person_two_step(user_id: str, ctx: AdminContext, db: Session = Depends(get_db)):
    """An administrator takes someone's two-step sign-in off (a lost phone): they set it up again themselves, at once
    when it is required."""

    if ctx.user is not None and user_id == ctx.user.id:
        return refused(400, "Turn your own two-step sign-in off under Settings → Two-step sign-in.")
    found = _target(db, ctx, user_id)
    if isinstance(found, JSONResponse):
        return found
    user, _ = found
    if account_security.reset_two_step(user):
        _audit_admin(db, ctx, action="auth.two_step.reset", reason=f"Reset two-step sign-in for {user.email}.")
    db.commit()
    return people(ctx, db)


@router.delete("/sign-in-settings/people/{user_id}/sso-link")
def reset_person_sso_link(user_id: str, ctx: AdminContext, db: Session = Depends(get_db)):
    """Reset someone's link to their account at the identity provider (it was made anew there): their next single
    sign-on links them again, by their email address."""

    found = _target(db, ctx, user_id)
    if isinstance(found, JSONResponse):
        return found
    user, _ = found
    if user.sso_subject:
        user.sso_issuer = None
        user.sso_subject = None
        _audit_admin(db, ctx, action="auth.sso.unlinked", reason=f"Reset the single sign-on link of {user.email}.")
    db.commit()
    return people(ctx, db)


# ---------------------------------------------------------------------------------------------------------------------
# RESET_TWO_STEP=<email>, at start-up
# ---------------------------------------------------------------------------------------------------------------------


def reset_two_step_from_environment(db: Session, value: str | None, log=print) -> str:  # type: ignore[no-untyped-def]
    """RESET_TWO_STEP=<email>: the way back in for someone whose authenticator app and recovery codes are both gone
    when no administrator is left to reset it for them. At start-up their two-step sign-in is taken off; they sign in
    with their password and set it up again. Recorded in the audit log. It works once for a person: left in the
    environment it does nothing more, until the API has started without it. The caller commits. Returns what
    happened: "", "used-before", "unknown", "reset" or "not-on"."""

    email = str(value or "").strip().lower()
    row = account_security.policy(db)
    if not email:
        row.two_step_reset_for = ""
        return ""
    if row.two_step_reset_for == email:
        log("! [access] RESET_TWO_STEP was used for this person at an earlier start, so nothing was reset now. Take it out of the environment.")
        return "used-before"
    user = account_security.find_by_email(db, email)
    if user is None:
        log("! [access] RESET_TWO_STEP names nobody who has access here: nothing was reset. Take it out of the environment.")
        return "unknown"
    row.two_step_reset_for = email
    if account_security.reset_two_step(user):
        membership = db.scalar(select(UserTenantRole).where(UserTenantRole.user_id == user.id).limit(1))
        write_audit_log(
            db,
            tenant_id=membership.tenant_id if membership else None,
            actor_user_id=None,
            actor_type="system",
            action="auth.two_step.reset",
            resource_type="user",
            resource_id=user.id,
            payload={"reason": f"Two-step sign-in reset for {user.email} from the server's environment (RESET_TWO_STEP)."},
        )
        log(f"[access] Two-step sign-in was reset for {user.email} (RESET_TWO_STEP). Take RESET_TWO_STEP out of the environment now.")
        return "reset"
    log(f"[access] RESET_TWO_STEP: {user.email} has no two-step sign-in to reset. Take RESET_TWO_STEP out of the environment.")
    return "not-on"


__all__ = ["router", "reset_two_step_from_environment", "password_reset_ready", "Tenant"]
