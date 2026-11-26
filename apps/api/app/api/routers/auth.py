from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from time import perf_counter, sleep
from typing import Annotated, Any

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import AfterValidator, BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core import session_cookies
from app.core.auth import get_current_user, oauth2_scheme
from app.core.config import settings
from app.core.security import decode_token, get_password_hash, token_hash, verify_password
from app.db.models.tenant import Tenant
from app.db.models.user import RefreshToken, User, UserTenantRole
from app.db.session import get_db
from app.services import activation_service, first_run_service, terms_service
from app.services.audit_service import write_audit_log
from app.services.auth_service import get_user_tenants, issue_tokens, refresh_tokens
from app.services import account_security, mfa_service, oidc_auth_service, refusal_audit, sign_in_store
from app.services.account_security import SignInRefused
from app.services.passwords import password_problem
from app.version import APP_VERSION


router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger(__name__)
_AUTH_MIN_RESPONSE_SECONDS = 0.25
_REGISTRATION_FAILURE_DETAIL = "Unable to process registration request"


def _normalize_auth_timing(started_at: float) -> None:
    elapsed = perf_counter() - started_at
    remaining = _AUTH_MIN_RESPONSE_SECONDS - elapsed
    if remaining > 0:
        sleep(remaining)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str


_SIGN_IN_EMAIL = re.compile(r"^[^\s@<>\"]+@[^\s@<>\"]+\.[^\s@<>\"]+$")


def _sign_in_email(value: str) -> str:
    """An email to sign in with. Not EmailStr: that refuses special-use names such as the first administrator's
    admin@hawk.local (app/services/first_run_service.py). The domain is lower-cased, as EmailStr did."""

    email = first_run_service.normalize_email(value)
    if len(email) > 320 or not _SIGN_IN_EMAIL.match(email):
        raise ValueError("value is not a valid email address")
    return email


SignInEmail = Annotated[str, AfterValidator(_sign_in_email)]


class LoginRequest(BaseModel):
    email: SignInEmail
    password: str


class ChangePasswordRequest(BaseModel):
    current: str = ""
    next: str = ""


class RefreshRequest(BaseModel):
    # Left out by the console, whose refresh token is in its cookie (app/core/session_cookies.py).
    refresh_token: str = ""


class SelectTenantRequest(BaseModel):
    tenant_id: str


class TenantMembershipResponse(BaseModel):
    id: str
    name: str
    role: str


class AuthUserResponse(BaseModel):
    id: str
    email: str
    full_name: str


class AuthTokensResponse(BaseModel):
    # Empty for the console, which gets them as HttpOnly cookies instead (app/core/session_cookies.py).
    access_token: str = ""
    refresh_token: str = ""
    token_type: str
    expires_in: int


class RegisterResponse(AuthTokensResponse):
    user: AuthUserResponse
    tenants: list[TenantMembershipResponse]


class LoginResponse(AuthTokensResponse):
    user: AuthUserResponse
    tenants: list[TenantMembershipResponse]
    selected_tenant_id: str
    # A temporary password (the first administrator, or after reset_admin): the console asks for a new one first.
    must_change_password: bool = False


class TwoStepChallenge(BaseModel):
    """The password was right and a second step follows (/settings/guide/people-and-access): no tokens yet, only a ticket for the code.
    ``setup``: an administrator requires two-step sign-in and this person has none yet; the page shows the key and its
    QR code, and the first right code turns it on."""

    two_step: bool = True
    ticket: str
    minutes: int
    setup: dict[str, str] | None = None


class MeResponse(BaseModel):
    id: str
    email: str
    full_name: str
    tenants: list[TenantMembershipResponse]
    # The product licence's end, for the admins' banner in its last 30 days (/settings/guide/licence): only for
    # someone who is an owner or admin of a tenant, as they may enter activation codes.
    licence: dict[str, Any] | None = None
    # Choose a new password first (app/core/access_gate.py).
    must_change_password: bool = False
    # Where this person stands with the terms of use (TERMS.md): {version, organisationAccepted, accepted,
    # canAcceptForOrganisation}.
    terms: dict[str, Any] | None = None
    # This build's version, shown bottom-left in the console (VERSION).
    version: str = APP_VERSION
    # Two-step sign-in for this person (/settings/guide/people-and-access): {available, on, since, recoveryLeft, required}.
    two_step: dict[str, Any] | None = None


class SelectTenantResponse(AuthTokensResponse):
    selected_tenant_id: str


class OIDCCompleteRequest(BaseModel):
    ticket: str


def _oidc_failure(exc: oidc_auth_service.OIDCError) -> HTTPException:
    return oidc_auth_service.as_http_error(exc)


@router.get("/oidc/providers")
def oidc_providers(workspace: str = Query(..., min_length=1, max_length=100)):
    try:
        return {"providers": oidc_auth_service.public_provider_rows(workspace_slug=workspace)}
    except oidc_auth_service.OIDCError as exc:
        raise _oidc_failure(exc) from exc


@router.get("/oidc/{provider_key}/start")
def oidc_start(provider_key: str, response: Response, workspace: str = Query(..., min_length=1, max_length=100)):
    try:
        authorization_url, browser = oidc_auth_service.start(provider_key=provider_key, workspace_slug=workspace)
    except oidc_auth_service.OIDCError as exc:
        raise _oidc_failure(exc) from exc
    response.set_cookie(oidc_auth_service.STATE_COOKIE, browser, max_age=settings.oidc_state_ttl_seconds, secure=True, httponly=True, samesite="lax", path="/")
    return {"authorization_url": authorization_url}


def _sso_refused(db: Session, exc: oidc_auth_service.OIDCError, provider_key: str = "") -> Response:
    """Back to the sign-in page with a short code, which picks the sentence the page shows (CxMissionZero's
    /#sso=<code>). What went wrong is in the audit log: never a token, the client secret or the provider's own text."""

    db.rollback()
    try:
        oidc_auth_service.audit_refusal(db, provider_key=provider_key, error=exc)
        db.commit()
    except Exception:  # noqa: BLE001 - the refusal is still answered
        db.rollback()
    logger.warning("[single sign-on] Not signed in (%s): %s.", exc.code, exc, extra={"sso_provider": provider_key or None, "reason_code": exc.code})
    if not settings.oidc_frontend_url:
        raise _oidc_failure(exc)
    base = settings.oidc_frontend_url.split("#", 1)[0]
    login = base.rsplit("/oidc/callback", 1)[0] if base.endswith("/oidc/callback") else base
    redirect = RedirectResponse(url=f"{login}#sso={re.sub(r'[^a-z]', '', exc.code)[:20] or 'token'}", status_code=status.HTTP_303_SEE_OTHER)
    redirect.headers["Cache-Control"] = "no-store"
    redirect.headers["Referrer-Policy"] = "no-referrer"
    redirect.delete_cookie(oidc_auth_service.STATE_COOKIE, path="/")
    return redirect


@router.get("/oidc/callback")
def oidc_callback(
    request: Request,
    code: str = Query(default="", max_length=4096),
    state: str = Query(default="", max_length=200),
    error: str | None = Query(default=None, max_length=200),
    browser: str | None = Cookie(default=None, alias=oidc_auth_service.STATE_COOKIE),
    db: Session = Depends(get_db),
):
    # The same limit as every sign-in: 30 attempts in ten minutes from one address.
    if account_security.too_many_sign_ins(request):
        return _sso_refused(db, oidc_auth_service.OIDCError("too many sign-in attempts from this address", "busy"))
    try:
        if not browser:
            raise oidc_auth_service.OIDCError("the answer belongs to no sign-in started from this browser (state)", "expired")
        if error is not None:
            said = error if re.fullmatch(r"[a-z0-9_.-]{1,60}", error, re.IGNORECASE) else "an error"
            raise oidc_auth_service.OIDCError(f"the identity provider answered {said}", "cancelled")
        if not code:
            raise oidc_auth_service.OIDCError("the identity provider sent no code", "provider")
        ticket = oidc_auth_service.callback(code=code, state=state, browser=browser, db=db)
        db.commit()
    except oidc_auth_service.OIDCError as exc:
        return _sso_refused(db, exc)
    redirect = RedirectResponse(url=f"{settings.oidc_frontend_url}#ticket={ticket}", status_code=status.HTTP_303_SEE_OTHER)
    redirect.headers["Cache-Control"] = "no-store"
    redirect.headers["Referrer-Policy"] = "no-referrer"
    redirect.delete_cookie(oidc_auth_service.STATE_COOKIE, path="/")
    redirect.set_cookie(oidc_auth_service.TICKET_COOKIE, browser, max_age=settings.oidc_ticket_ttl_seconds, secure=True, httponly=True, samesite="lax", path="/")
    return redirect


@router.post("/oidc/complete", response_model=LoginResponse)
def oidc_complete(payload: OIDCCompleteRequest, request: Request, response: Response, db: Session = Depends(get_db), browser: str | None = Cookie(default=None, alias=oidc_auth_service.TICKET_COOKIE)):
    # Single sign-on only ever ends in the console (the ticket is bound to this browser): always the cookie session,
    # so the tokens are never in a body a script on the page could read.
    request.state.cookie_session = True
    try:
        if not browser:
            raise oidc_auth_service.OIDCError("OIDC ticket invalid")
        tokens = oidc_auth_service.complete(ticket=payload.ticket, browser=browser, db=db)
        db.commit()
        response.headers["Cache-Control"] = "no-store"
        response.delete_cookie(oidc_auth_service.TICKET_COOKIE, path="/")
        return LoginResponse(**session_cookies.deliver(request, response, tokens))
    except oidc_auth_service.OIDCError as exc:
        db.rollback()
        raise _oidc_failure(exc) from exc


@router.post("/register", response_model=RegisterResponse | TwoStepChallenge)
def register(payload: RegisterRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    started_at = perf_counter()
    try:
        # The same password rule as everywhere (12+ characters, not repetitive).
        problem = password_problem(payload.password)
        if problem:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=problem)
        if not settings.self_registration_enabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=_REGISTRATION_FAILURE_DETAIL,
            )

        existing = db.scalar(select(User).where(User.email == payload.email))
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=_REGISTRATION_FAILURE_DETAIL,
            )

        user = User(
            email=payload.email,
            hashed_password=get_password_hash(payload.password),
            full_name=payload.full_name,
            is_active=True,
        )
        db.add(user)
        db.flush()

        # Several tenants need a tenants activation code (/settings/guide/licence).
        activation_service.assert_may_add_tenant(db)
        tenant = Tenant(name=f"{payload.full_name} Org", slug=f"{payload.email.split('@')[0]}-org", is_active=True)
        db.add(tenant)
        db.flush()

        activation_service.assert_may_add_member(db, tenant.id)
        membership = UserTenantRole(user_id=user.id, tenant_id=tenant.id, role="owner")
        db.add(membership)

        write_audit_log(
            db,
            tenant_id=tenant.id,
            actor_user_id=user.id,
            actor_type="human",
            action="auth.register",
            resource_type="user",
            resource_id=user.id,
            payload={"email": user.email, "tenant_id": tenant.id},
        )
        if account_security.needs_two_step(db, user):
            # Two-step sign-in is required for everyone: no tokens yet. As at the password sign-in, the person sets it
            # up first (the key comes with the ticket) and POST /auth/two-step gives the tokens. Without a ticket the
            # account is not created, so registering can simply be tried again.
            try:
                challenge = two_step_challenge(user)
            except sign_in_store.StoreUnavailable:
                db.rollback()
                return refused(503, SIGN_IN_UNAVAILABLE)
            db.commit()
            return JSONResponse(content=challenge.model_dump(), headers={"Cache-Control": "no-store"})
        db.commit()

        tokens = issue_tokens(db, user=user, tenant_id=tenant.id, role="owner")
        db.commit()

        return RegisterResponse(
            **session_cookies.deliver(request, response, tokens),
            user=AuthUserResponse(id=user.id, email=user.email, full_name=user.full_name),
            tenants=[TenantMembershipResponse(id=tenant.id, name=tenant.name, role="owner")],
        )
    finally:
        _normalize_auth_timing(started_at)


def _tenant_rows(db: Session, user: User) -> tuple[list[UserTenantRole], list[TenantMembershipResponse]]:
    memberships = get_user_tenants(db, user.id)
    tenants = []
    for m in memberships:
        tenant = db.get(Tenant, m.tenant_id)
        if tenant:
            tenants.append(TenantMembershipResponse(id=tenant.id, name=tenant.name, role=m.role))
    return memberships, tenants


def signed_in_response(db: Session, user: User) -> LoginResponse:
    """The tokens a password sign-in gives (after the second step when there is one). The caller commits."""

    memberships, tenants = _tenant_rows(db, user)
    if not memberships:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=account_security.WRONG)
    default_membership = memberships[0]
    tokens = issue_tokens(db, user=user, tenant_id=default_membership.tenant_id, role=default_membership.role)
    return LoginResponse(
        **tokens,
        user=AuthUserResponse(id=user.id, email=user.email, full_name=user.full_name),
        tenants=tenants,
        selected_tenant_id=default_membership.tenant_id,
        must_change_password=bool(user.must_change_password),
    )


def deliver_sign_in(request: Request, response: Response, result: LoginResponse) -> LoginResponse:
    """A sign-in's answer: for the console, the tokens as cookies on ``response`` instead of in the body."""

    return LoginResponse(**session_cookies.deliver(request, response, result.model_dump()))


def audit_access(db: Session, user: User | None, *, action: str, reason: str, request: Request | None) -> None:
    """A sign-in event in the audit log (CxMissionZero's auditAccess): never a password, code, ticket or token."""

    ip = account_security.client_ip(request)
    # The log line: who (their id, never the email or what was typed), from where, and what came of it.
    fields = {"auth_event": action, "client_ip": ip, **({"user_id": user.id} if user is not None else {})}
    if "refused" in action:
        logger.warning("Sign-in refused", extra=fields)
    else:
        logger.info("Sign-in event: %s", action, extra=fields)
    # Refusals are listed only so many a minute (app/services/refusal_audit.py: 30 per address, 120 in all).
    if "refused" in action and not refusal_audit.may_list(db, "sign_in", ip):
        return
    membership = get_user_tenants(db, user.id)[:1] if user is not None else []
    write_audit_log(
        db,
        tenant_id=membership[0].tenant_id if membership else None,
        actor_user_id=user.id if user is not None else None,
        actor_type="human" if user is not None else "system",
        action=action,
        resource_type="user",
        resource_id=user.id if user is not None else "sign-in",
        payload={"reason": reason, "ip": ip},
    )


SIGN_IN_UNAVAILABLE = "Sign-in is unavailable for a moment. Try again shortly."


def two_step_challenge(user: User) -> TwoStepChallenge:
    """The second step instead of tokens (/settings/guide/people-and-access): a ticket for the code, and when an administrator requires
    two-step sign-in and this person has none yet, the key to set it up (the first right code at POST /auth/two-step
    turns it on and only then gives tokens). Raises sign_in_store.StoreUnavailable."""

    secret = "" if account_security.two_step_on(user) else mfa_service.new_secret()
    ticket = mfa_service.issue_ticket(user.id, secret=secret)
    return TwoStepChallenge(
        ticket=ticket,
        minutes=mfa_service.TICKET_TTL_SECONDS // 60,
        setup=mfa_service.setup_view(user.email, secret) if secret else None,
    )


def refused(status_code: int, message: str, **extra: Any) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"detail": message, **extra}, headers={"Cache-Control": "no-store"})


@router.post("/login", response_model=LoginResponse | TwoStepChallenge)
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    """Sign in with an email and password (CxMissionZero's POST /api/session/password): limited per address, five
    wrong passwords lock the account for 15 minutes, and with two-step sign-in only a ticket for the code comes back."""

    started_at = perf_counter()
    try:
        if account_security.too_many_sign_ins(request):
            logger.warning("Sign-in refused: too many attempts from this address", extra={"client_ip": account_security.client_ip(request), "reason_code": "rate_limited"})
            return refused(429, account_security.TOO_MANY)
        try:
            user = account_security.check_password(db, payload.email, payload.password, more=True)
        except SignInRefused as refusal:
            db.commit()  # the wrong attempt counts
            audit_access(db, refusal.user, action="auth.sign_in.refused", reason=f"Sign-in refused for {refusal.user.email if refusal.user else 'an address with no account here'}: {refusal.message}{' Account locked.' if refusal.locked else ''}", request=request)
            db.commit()
            return refused(refusal.status_code, refusal.message)
        # Single sign-on is on and passwords are kept for Admins: said only to someone who typed the right password.
        if account_security.password_not_enough(db, user):
            audit_access(db, user, action="auth.sign_in.refused", reason=f"Sign-in refused for {user.email}: only Admins may sign in with a password; everyone else uses single sign-on.", request=request)
            db.commit()
            return refused(403, "Signing in with a password is turned off for this account. Use single sign-on.", sso=True)
        if account_security.needs_two_step(db, user):
            try:
                challenge = two_step_challenge(user)
            except sign_in_store.StoreUnavailable:
                db.commit()
                return refused(503, SIGN_IN_UNAVAILABLE)
            db.commit()
            return JSONResponse(content=challenge.model_dump(), headers={"Cache-Control": "no-store"})
        # Only now is it a sign-in: wrong attempts before it are forgotten.
        account_security.record_sign_in(user)
        result = signed_in_response(db, user)
        audit_access(db, user, action="auth.sign_in", reason=f"{user.email} signed in with a password.", request=request)
        db.commit()
        return deliver_sign_in(request, response, result)
    finally:
        _normalize_auth_timing(started_at)


def _refresh_token_of(request: Request, payload: RefreshRequest | None) -> str:
    """The refresh token in the body (every client but the console), else the console's cookie, which only a request
    with the CSRF header may use."""

    if payload is not None and payload.refresh_token:
        return payload.refresh_token
    cookie = session_cookies.refresh_cookie(request)
    if cookie:
        session_cookies.require_csrf(request)
        request.state.cookie_session = True
    return cookie


@router.post("/refresh", response_model=AuthTokensResponse)
def refresh(request: Request, response: Response, payload: RefreshRequest | None = None, db: Session = Depends(get_db)):
    token = _refresh_token_of(request, payload)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    try:
        tokens = refresh_tokens(db, token)
        db.commit()
        return AuthTokensResponse(**session_cookies.deliver(request, response, tokens, keep_csrf=True))
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from exc


@router.post("/refresh/sign-out")
def sign_out(request: Request, response: Response, payload: RefreshRequest | None = None, db: Session = Depends(get_db)):
    """Sign out: this sign-in's refresh token stops working and the console's cookies go. Under /auth/refresh because
    the refresh cookie is sent nowhere else. The access token lives out its few minutes, as after any sign-out."""

    token = _refresh_token_of(request, payload)
    record = None
    if token:
        record = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash(token), RefreshToken.revoked_at.is_(None)))
    if record is not None:
        record.revoked_at = datetime.now(timezone.utc)
        user = db.get(User, record.user_id)
        if user is not None:
            audit_access(db, user, action="auth.sign_out", reason=f"{user.email} signed out.", request=request)
        db.commit()
    session_cookies.clear(request, response)
    response.headers["Cache-Control"] = "no-store"
    return {"ok": True}


@router.get("/me", response_model=MeResponse)
def me(current_user: Annotated[User, Depends(get_current_user)], db: Session = Depends(get_db)):
    memberships = get_user_tenants(db, current_user.id)
    tenants = []
    for m in memberships:
        tenant = db.get(Tenant, m.tenant_id)
        if tenant:
            tenants.append({"id": tenant.id, "name": tenant.name, "role": m.role})

    licence = None
    if any(m.role in {"owner", "admin"} for m in memberships):
        licence = activation_service.licence_for_admins(db)
        db.commit()

    two_step = account_security.two_step_view(db, current_user)
    db.commit()
    return MeResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        tenants=[TenantMembershipResponse(**tenant_row) for tenant_row in tenants],
        licence=licence,
        must_change_password=bool(current_user.must_change_password),
        terms=terms_service.describe(db, current_user),
        two_step=two_step,
    )


@router.post("/me/password", response_model=LoginResponse)
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    response: Response,
    current_user: Annotated[User, Depends(get_current_user)],
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    """Change one's own password (required after a generated or reset one), ported from CxMissionZero's
    /api/me/password. Anyone else signed in as this person is signed out (their refresh tokens stop working); this
    browser gets new tokens and stays signed in."""

    if not verify_password(payload.current, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Your current password is wrong.")
    if payload.next == payload.current:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Choose a password different from the current one.")
    problem = password_problem(payload.next)
    if problem:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=problem)
    current_user.hashed_password = get_password_hash(payload.next)
    current_user.must_change_password = False
    # Anyone else signed in as this person is signed out; a reset link sent earlier stops working (its stamp no longer
    # matches the password), and so do two-step tickets.
    account_security.sign_out_everywhere(db, current_user)
    try:
        mfa_service.revoke_tickets(current_user.id)
    except sign_in_store.StoreUnavailable:
        pass
    # The generated first password is no longer any use: its file goes (CxMissionZero removes it here too).
    first_run_service.remove_first_admin_file()

    memberships = get_user_tenants(db, current_user.id)
    if not memberships:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant membership not found")
    wanted = str(decode_token(token).get("tenant_id") or "")
    membership = next((m for m in memberships if m.tenant_id == wanted), memberships[0])
    write_audit_log(
        db,
        tenant_id=membership.tenant_id,
        actor_user_id=current_user.id,
        actor_type="human",
        action="auth.password.changed",
        resource_type="user",
        resource_id=current_user.id,
        payload={"reason": f"{current_user.email} changed their password."},
    )
    tokens = issue_tokens(db, user=current_user, tenant_id=membership.tenant_id, role=membership.role)
    db.commit()
    tenants = []
    for m in memberships:
        tenant = db.get(Tenant, m.tenant_id)
        if tenant:
            tenants.append(TenantMembershipResponse(id=tenant.id, name=tenant.name, role=m.role))
    return LoginResponse(
        **session_cookies.deliver(request, response, tokens),
        user=AuthUserResponse(id=current_user.id, email=current_user.email, full_name=current_user.full_name),
        tenants=tenants,
        selected_tenant_id=membership.tenant_id,
        must_change_password=False,
    )


@router.get("/tenants", response_model=ListEnvelope[TenantMembershipResponse])
def my_tenants(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
    page: int = 1,
    page_size: int = 50,
):
    memberships = get_user_tenants(db, current_user.id)
    out = []
    for m in memberships:
        tenant = db.get(Tenant, m.tenant_id)
        if tenant:
            out.append({"id": tenant.id, "name": tenant.name, "role": m.role})
    dto_rows = [TenantMembershipResponse(**row) for row in out]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[TenantMembershipResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.post("/select-tenant", response_model=SelectTenantResponse)
def select_tenant(
    payload: SelectTenantRequest,
    request: Request,
    response: Response,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    membership = db.scalar(
        select(UserTenantRole).where(UserTenantRole.user_id == current_user.id, UserTenantRole.tenant_id == payload.tenant_id)
    )
    if not membership:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No membership in selected tenant")

    tokens = issue_tokens(db, user=current_user, tenant_id=payload.tenant_id, role=membership.role)

    write_audit_log(
        db,
        tenant_id=payload.tenant_id,
        actor_user_id=current_user.id,
        actor_type="human",
        action="auth.select_tenant",
        resource_type="tenant",
        resource_id=payload.tenant_id,
        payload={"selected_at": datetime.now(timezone.utc).isoformat()},
    )

    db.commit()
    return SelectTenantResponse(**session_cookies.deliver(request, response, tokens), selected_tenant_id=payload.tenant_id)
