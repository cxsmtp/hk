"""First-run setup and the terms of use, ported from CxMissionZero's /api/setup (src/routes/session.js) and
/api/terms (src/routes/account.js).

- GET /setup, POST /setup: with FIRST_ADMIN=setup-code, whoever has the setup code from the API's log creates the
  first administrator (app/services/first_run_service.py). Open: nobody can sign in yet.
- GET /terms: the terms of use (TERMS.md), readable by anyone (also before signing in), with where this person
  stands when a token is given.
- POST /terms/accept: an owner or admin for the organisation (first), then each person for themselves.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from fastapi import APIRouter, Body, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.routers.auth import SIGN_IN_UNAVAILABLE, two_step_challenge
from app.core import session_cookies
from app.core.auth import get_current_user
from app.core.security import decode_token
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import get_db
from app.services import account_security, first_run_service, refusal_audit, sign_in_store, terms_service
from app.services.audit_service import write_audit_log
from app.services.auth_service import issue_tokens


router = APIRouter(tags=["access"])

#: Setup attempts from one address in 10 minutes (CxMissionZero limits sign-in to 30 per 10 minutes per address).
SETUP_TRIES = 30
SETUP_WINDOW_SECONDS = 600


class _Tries:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_ip: dict[str, list[float]] = {}

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            recent = [t for t in self._by_ip.get(ip, []) if now - t < SETUP_WINDOW_SECONDS]
            if len(recent) >= SETUP_TRIES:
                self._by_ip[ip] = recent
                return False
            self._by_ip[ip] = [*recent, now]
            if len(self._by_ip) > 1000:
                self._by_ip.clear()
            return True

    def clear(self) -> None:
        with self._lock:
            self._by_ip.clear()


setup_tries = _Tries()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _error(status_code: int, message: str, **extra: Any) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": message, **extra}, headers={"Cache-Control": "no-store"})


def _tenants_of(db: Session, user: User) -> list[dict[str, str]]:
    rows = db.execute(
        select(Tenant.id, Tenant.name, UserTenantRole.role)
        .join(UserTenantRole, UserTenantRole.tenant_id == Tenant.id)
        .where(UserTenantRole.user_id == user.id)
        .order_by(UserTenantRole.created_at)
    ).all()
    return [{"id": tenant_id, "name": name, "role": role} for tenant_id, name, role in rows]


@router.get("/setup")
def setup_status(db: Session = Depends(get_db)):
    """Whether the sign-in page offers to create the first administrator with the setup code."""

    return JSONResponse(content={"setup": first_run_service.setup_pending(db)}, headers={"Cache-Control": "no-store"})


@router.post("/setup")
def setup(request: Request, body: dict[str, Any] | None = Body(default=None), db: Session = Depends(get_db)):
    """First start: whoever holds the setup code from the server log creates the first administrator."""

    body = body or {}
    if first_run_service.has_users(db):
        return _error(409, "Hawk AI already has an administrator.")
    if not setup_tries.allow(_client_ip(request)):
        return _error(429, "Too many tries. Wait a few minutes, then try again.")
    try:
        admin = first_run_service.use_setup_code(
            db,
            code=str(body.get("code") or ""),
            email=str(body.get("email") or ""),
            full_name=str(body.get("name") or body.get("full_name") or ""),
            password=str(body.get("password") or ""),
        )
    except first_run_service.SetupRefused as refused:
        db.rollback()
        # Listed only so many a minute (app/services/refusal_audit.py: 10 per address, 40 in all).
        if refused.status_code == 403 and refusal_audit.may_list(db, "unauthenticated", _client_ip(request)):
            write_audit_log(
                db,
                tenant_id=None,
                actor_user_id=None,
                actor_type="system",
                action="access.setup.refused",
                resource_type="setup",
                resource_id="first-administrator",
                payload={"reason": "First-administrator setup refused: wrong setup code.", "ip": _client_ip(request)},
            )
            db.commit()
        return _error(refused.status_code, refused.message)
    if account_security.needs_two_step(db, admin):
        # Two-step sign-in is required for everyone (a sign-in policy kept from before, say): no tokens yet. As at the
        # password sign-in, the administrator sets it up first and POST /auth/two-step gives the tokens. Without a
        # ticket nothing is kept: the setup code stays usable.
        try:
            challenge = two_step_challenge(admin)
        except sign_in_store.StoreUnavailable:
            db.rollback()
            return _error(503, SIGN_IN_UNAVAILABLE)
        db.commit()
        return JSONResponse(status_code=201, headers={"Cache-Control": "no-store"}, content=challenge.model_dump())
    db.commit()
    tenants = _tenants_of(db, admin)
    tokens = issue_tokens(db, user=admin, tenant_id=tenants[0]["id"], role=tenants[0]["role"])
    db.commit()
    # The console's session: the tokens as cookies (app/core/session_cookies.py).
    return session_cookies.answer(
        request,
        {
            **tokens,
            "user": {"id": admin.id, "email": admin.email, "full_name": admin.full_name},
            "tenants": tenants,
            "selected_tenant_id": tenants[0]["id"],
            "must_change_password": False,
        },
        201,
    )


def _optional_user(request: Request, db: Session) -> User | None:
    header = request.headers.get("authorization") or ""
    # A bearer token, else the console's session cookie (app/core/session_cookies.py; a read, so no CSRF check).
    token = header[7:].strip() if header.lower().startswith("bearer ") else session_cookies.access_cookie(request)
    if not token:
        return None
    try:
        payload = decode_token(token)
    except ValueError:
        return None
    if payload.get("type") != "access" or not payload.get("sub"):
        return None
    return db.scalar(select(User).where(User.id == payload["sub"], User.is_active.is_(True)))


@router.get("/terms")
def read_terms(request: Request, db: Session = Depends(get_db)):
    terms = terms_service.current()
    org = terms_service.organisation(db)
    user = _optional_user(request, db)
    content: dict[str, Any] = {
        "version": terms.version,
        "text": terms.text,
        "notice": terms_service.ON_PREMISE_NOTICE,
        "organisation": {"at": org.accepted_at.isoformat(), "by": org.email, "via": org.via} if org else None,
        "organisationName": terms_service.organisation_name(db),
    }
    if user is not None:
        mine = terms_service.user_acceptance(db, user.id)
        at = mine.accepted_at if mine else (org.accepted_at if org is not None and org.everyone else None)
        content["you"] = {
            "accepted": org is not None and terms_service.accepted_by(db, user.id, org),
            "at": at.isoformat() if at else None,
            "canAcceptForOrganisation": terms_service.may_accept_for_organisation(db, user),
        }
    return JSONResponse(content=content, headers={"Cache-Control": "no-store"})


@router.post("/terms/accept")
def accept_terms(
    request: Request,
    body: dict[str, Any] | None = Body(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    body = body or {}
    terms = terms_service.current()
    if str(body.get("version") or "") != terms.version:
        return _error(409, "The terms changed while you were reading them: read the current version, then accept.")
    ip = _client_ip(request)
    tenants = _tenants_of(db, current_user)
    tenant_id = tenants[0]["id"] if tenants else None
    if terms_service.organisation(db) is None:
        if not terms_service.may_accept_for_organisation(db, current_user) or not body.get("forOrganisation"):
            return _error(403, "An administrator must accept the terms of use for the organisation first.")
        name = terms_service.clean_name(body.get("organisationName"))
        if not name and not terms_service.organisation_name(db):
            return _error(400, "Write your organisation’s name: it names your tenant and goes on the reports Hawk AI makes.")
        terms_service.accept_for_organisation(db, by=current_user.email, ip=ip, name=name, user_id=current_user.id)
        if name:
            # The first administrator's tenant is named after the organisation once its name is known.
            for tenant in db.scalars(
                select(Tenant)
                .join(UserTenantRole, UserTenantRole.tenant_id == Tenant.id)
                .where(UserTenantRole.user_id == current_user.id, Tenant.name == first_run_service.DEFAULT_TENANT_NAME)
            ):
                tenant.name = name
        write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=current_user.id,
            actor_type="human",
            action="terms.accepted",
            resource_type="terms",
            resource_id=terms.hash,
            payload={
                "reason": f"Terms of use v{terms.version} accepted for the organisation by {current_user.email}"
                + (f" (organisation name: {name})." if name else "."),
                "terms": {"version": terms.version, "hash": terms.hash, "scope": "organisation"},
                "ip": ip,
            },
        )
    if not terms_service.accepted_by(db, current_user.id):
        terms_service.accept_for_user(db, user_id=current_user.id, email=current_user.email, ip=ip)
        write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=current_user.id,
            actor_type="human",
            action="terms.accepted",
            resource_type="terms",
            resource_id=terms.hash,
            payload={
                "reason": f"Terms of use v{terms.version} accepted by {current_user.email}.",
                "terms": {"version": terms.version, "hash": terms.hash, "scope": "user"},
                "ip": ip,
            },
        )
    db.commit()
    return JSONResponse(content={"terms": terms_service.describe(db, current_user)}, headers={"Cache-Control": "no-store"})
