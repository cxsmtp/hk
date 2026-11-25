from __future__ import annotations

import re
from datetime import datetime, timezone
from time import perf_counter, sleep
from typing import Annotated, Any

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Response, status
from fastapi.responses import RedirectResponse
from pydantic import AfterValidator, BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.auth import get_current_user, oauth2_scheme
from app.core.config import settings
from app.core.security import decode_token, get_password_hash, verify_password
from app.db.models.tenant import Tenant
from app.db.models.user import RefreshToken, User, UserTenantRole
from app.db.session import get_db
from app.services import activation_service, first_run_service, terms_service
from app.services.audit_service import write_audit_log
from app.services.auth_service import authenticate_user, get_user_tenants, issue_tokens, refresh_tokens
from app.services import oidc_auth_service
from app.services.passwords import password_problem
from app.version import APP_VERSION


router = APIRouter(prefix="/auth", tags=["auth"])
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
    refresh_token: str


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
    access_token: str
    refresh_token: str
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


class MeResponse(BaseModel):
    id: str
    email: str
    full_name: str
    tenants: list[TenantMembershipResponse]
    # The product licence's end, for the admins' banner in its last 30 days (docs/activation-codes.md): only for
    # someone who is an owner or admin of a tenant, as they may enter activation codes.
    licence: dict[str, Any] | None = None
    # Choose a new password first (app/core/access_gate.py).
    must_change_password: bool = False
    # Where this person stands with the terms of use (TERMS.md): {version, organisationAccepted, accepted,
    # canAcceptForOrganisation}.
    terms: dict[str, Any] | None = None
    # This build's version, shown bottom-left in the console (VERSION).
    version: str = APP_VERSION


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


@router.get("/oidc/callback")
def oidc_callback(code: str, state: str, browser: str | None = Cookie(default=None, alias=oidc_auth_service.STATE_COOKIE)):
    try:
        if not browser:
            raise oidc_auth_service.OIDCError("OIDC state invalid")
        ticket = oidc_auth_service.callback(code=code, state=state, browser=browser)
    except oidc_auth_service.OIDCError as exc:
        raise _oidc_failure(exc) from exc
    redirect = RedirectResponse(url=f"{settings.oidc_frontend_url}#ticket={ticket}", status_code=status.HTTP_303_SEE_OTHER)
    redirect.headers["Cache-Control"] = "no-store"
    redirect.headers["Referrer-Policy"] = "no-referrer"
    redirect.delete_cookie(oidc_auth_service.STATE_COOKIE, path="/")
    redirect.set_cookie(oidc_auth_service.TICKET_COOKIE, browser, max_age=settings.oidc_ticket_ttl_seconds, secure=True, httponly=True, samesite="lax", path="/")
    return redirect


@router.post("/oidc/complete", response_model=LoginResponse)
def oidc_complete(payload: OIDCCompleteRequest, response: Response, db: Session = Depends(get_db), browser: str | None = Cookie(default=None, alias=oidc_auth_service.TICKET_COOKIE)):
    try:
        if not browser:
            raise oidc_auth_service.OIDCError("OIDC ticket invalid")
        tokens = oidc_auth_service.complete(ticket=payload.ticket, browser=browser, db=db)
        db.commit()
        response.headers["Cache-Control"] = "no-store"
        response.delete_cookie(oidc_auth_service.TICKET_COOKIE, path="/")
        return LoginResponse(**tokens)
    except oidc_auth_service.OIDCError as exc:
        db.rollback()
        raise _oidc_failure(exc) from exc


@router.post("/register", response_model=RegisterResponse)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    started_at = perf_counter()
    try:
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

        # Several tenants need a tenants activation code (docs/activation-codes.md).
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
        db.commit()

        tokens = issue_tokens(db, user=user, tenant_id=tenant.id, role="owner")
        db.commit()

        return RegisterResponse(
            **tokens,
            user=AuthUserResponse(id=user.id, email=user.email, full_name=user.full_name),
            tenants=[TenantMembershipResponse(id=tenant.id, name=tenant.name, role="owner")],
        )
    finally:
        _normalize_auth_timing(started_at)


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    started_at = perf_counter()
    try:
        user = authenticate_user(db, payload.email, payload.password)
        memberships = get_user_tenants(db, user.id)
        if not memberships:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

        default_membership = memberships[0]
        tokens = issue_tokens(db, user=user, tenant_id=default_membership.tenant_id, role=default_membership.role)
        db.commit()

        tenants = []
        for m in memberships:
            tenant = db.get(Tenant, m.tenant_id)
            if tenant:
                tenants.append({"id": tenant.id, "name": tenant.name, "role": m.role})

        return LoginResponse(
            **tokens,
            user=AuthUserResponse(id=user.id, email=user.email, full_name=user.full_name),
            tenants=[TenantMembershipResponse(**tenant_row) for tenant_row in tenants],
            selected_tenant_id=default_membership.tenant_id,
            must_change_password=bool(user.must_change_password),
        )
    finally:
        _normalize_auth_timing(started_at)


@router.post("/refresh", response_model=AuthTokensResponse)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)):
    try:
        tokens = refresh_tokens(db, payload.refresh_token)
        db.commit()
        return AuthTokensResponse(**tokens)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from exc


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

    return MeResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        tenants=[TenantMembershipResponse(**tenant_row) for tenant_row in tenants],
        licence=licence,
        must_change_password=bool(current_user.must_change_password),
        terms=terms_service.describe(db, current_user),
    )


@router.post("/me/password", response_model=LoginResponse)
def change_password(
    payload: ChangePasswordRequest,
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
    now = datetime.now(timezone.utc)
    for record in db.scalars(select(RefreshToken).where(RefreshToken.user_id == current_user.id, RefreshToken.revoked_at.is_(None))):
        record.revoked_at = now
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
        **tokens,
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
    return SelectTenantResponse(**tokens, selected_tenant_id=payload.tenant_id)
