"""First-run setup and the terms of use, ported from CxMissionZero's /api/setup (src/routes/session.js) and
/api/terms (src/routes/account.js).

- GET /setup, POST /setup: with FIRST_ADMIN=setup-code, whoever has the setup code from the API's log creates the
  first administrator (app/services/first_run_service.py). Open: nobody can sign in yet.
- GET /terms: the terms of use (TERMS.md), readable by anyone (also before signing in), with where this person
  stands when a token is given.
- POST /terms/accept: each owner or admin accepts the licence agreement for the organisation (company name, full
  name, email, "authorised"), the first one before anyone else; everyone else then accepts the terms of use for users.
- GET /terms/acceptances, GET /terms/acceptances/{id}/copy, POST /terms/acceptances/{id}/resend: the acceptances,
  the accepted copy and its email (app/services/terms_copy_service.py). Acceptances cannot be changed or deleted.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Body, Depends, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.routers.auth import SIGN_IN_UNAVAILABLE, two_step_challenge
from app.core import session_cookies
from app.core.auth import get_current_user
from app.core.security import decode_token
from app.db.models.access import TermsAcceptance
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import get_db
from app.services import account_security, first_run_service, mailer, refusal_audit, sign_in_store, terms_copy_service, terms_service
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


def _terms_view(db: Session, user: User | None) -> dict[str, Any]:
    terms = terms_service.current()
    org = terms_service.organisation(db)
    content: dict[str, Any] = {
        "version": terms.version,
        "hash": terms.hash,
        "text": terms.text,
        # The terms of use for users (Schedule 2): what someone who is not an owner or admin accepts.
        "userText": terms_service.user_terms(terms.text),
        "licensor": terms_service.values()["LICENSOR_LEGAL_NAME"],
        "notice": terms_service.ON_PREMISE_NOTICE,
        "organisation": {"at": org.accepted_at.isoformat(), "by": org.email, "via": org.via} if org else None,
        "organisationName": terms_service.organisation_name(db),
    }
    if user is not None:
        mine = terms_service.user_acceptance(db, user.id)
        at = mine.accepted_at if mine else (org.accepted_at if org is not None and org.everyone else None)
        admin = terms_service.may_accept_for_organisation(db, user)
        content["you"] = {
            "accepted": org is not None and terms_service.accepted_by(db, user, org),
            "at": at.isoformat() if at else None,
            "canAcceptForOrganisation": admin,
            "scope": "organisation" if admin else "user",
            "email": user.email,
            "fullName": user.full_name or "",
        }
    return content


@router.get("/terms")
def read_terms(request: Request, db: Session = Depends(get_db)):
    return JSONResponse(content=_terms_view(db, _optional_user(request, db)), headers={"Cache-Control": "no-store"})


def _deliver_copies_later(background: BackgroundTasks, db: Session) -> None:
    """Send the queued copies of the agreement after the answer, in a session of their own."""

    background.add_task(terms_copy_service.deliver_with, db.get_bind())


@router.post("/terms/accept")
def accept_terms(
    request: Request,
    background: BackgroundTasks,
    body: dict[str, Any] | None = Body(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """An owner or admin accepts the whole agreement for the organisation (company name, their full name and email,
    "I am authorised", "I have read"); anyone else accepts the terms of use for users once that is done."""

    body = body or {}
    terms = terms_service.current()
    if str(body.get("version") or "") != terms.version or str(body.get("hash") or terms.hash) != terms.hash:
        return _error(409, "The terms changed while you were reading them: read the current version, then accept.")
    if body.get("read") is not True:
        return _error(400, "Read the terms to the end and confirm that you have read them.")
    ip = _client_ip(request)
    user_agent = str(request.headers.get("user-agent") or "")
    tenants = _tenants_of(db, current_user)
    tenant_id = tenants[0]["id"] if tenants else None
    admin = terms_service.may_accept_for_organisation(db, current_user)
    org = terms_service.organisation(db)
    if org is None and (not admin or not body.get("forOrganisation")):
        return _error(403, "An administrator must accept the terms of use for the organisation first.")
    if terms_service.accepted_by(db, current_user, org):
        return JSONResponse(content={"terms": terms_service.describe(db, current_user)}, headers={"Cache-Control": "no-store"})
    if admin:
        problems: dict[str, str] = {}
        company = terms_service.clean_name(body.get("companyName") or body.get("organisationName"))
        full_name = terms_service.clean_name(body.get("fullName"), 200)
        email = terms_service.clean_email(body.get("email") or current_user.email)
        if not company:
            problems["companyName"] = "Write your company’s legal name."
        if len(full_name) < 2:
            problems["fullName"] = "Write your full name."
        if not email:
            problems["email"] = "Write an email address the copy of the agreement can be sent to."
        if body.get("authorised") is not True:
            problems["authorised"] = "Confirm that you accept on behalf of the company and are authorised to."
        if problems:
            return _error(400, next(iter(problems.values())), fields=problems)
        first = org is None
        row = terms_service.accept_for_organisation(
            db,
            by=email,
            ip=ip,
            name=company,
            user_id=current_user.id,
            full_name=full_name,
            tenant_id=tenant_id,
            user_agent=user_agent,
            authorised=True,
        )
        if first:
            # The first administrator's tenant is named after the organisation once its name is known.
            for tenant in db.scalars(
                select(Tenant)
                .join(UserTenantRole, UserTenantRole.tenant_id == Tenant.id)
                .where(UserTenantRole.user_id == current_user.id, Tenant.name == first_run_service.DEFAULT_TENANT_NAME)
            ):
                tenant.name = company
        reason = f"Licence agreement v{terms.version} accepted for {company} by {full_name} ({email}), who confirmed they are authorised to accept for the company."
        scope = "organisation"
    else:
        full_name = terms_service.clean_name(body.get("fullName") or current_user.full_name, 200)
        row = terms_service.accept_for_user(
            db, user_id=current_user.id, email=current_user.email, ip=ip, full_name=full_name, tenant_id=tenant_id, user_agent=user_agent
        )
        reason = f"Terms of use v{terms.version} accepted by {current_user.email}."
        scope = "user"
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=current_user.id,
        actor_type="human",
        action="terms.accepted",
        resource_type="terms_acceptance",
        resource_id=row.id,
        payload={
            "reason": reason,
            "terms": {"version": terms.version, "hash": terms.hash, "scope": scope},
            "acceptance": terms_service.acceptance_view(row),
            "ip": ip,
        },
    )
    db.commit()
    if scope == "organisation":
        _deliver_copies_later(background, db)
    return JSONResponse(content={"terms": terms_service.describe(db, current_user)}, headers={"Cache-Control": "no-store"})


# ---- Accepted copies (Settings → About): read, download, send again. Never changed or deleted. -----------------


def _acceptance_for(db: Session, user: User, acceptance_id: str) -> TermsAcceptance | JSONResponse:
    row = db.get(TermsAcceptance, acceptance_id)
    if row is None:
        return _error(404, "No such acceptance.")
    if row.user_id != user.id and not terms_service.may_accept_for_organisation(db, user):
        return _error(403, "Only owners and admins can see other people’s acceptances.")
    return row


def _with_copy(db: Session, row: TermsAcceptance) -> dict[str, Any]:
    return {**terms_service.acceptance_view(row), "copy": terms_copy_service.status(db, row)}


@router.get("/terms/acceptances")
def list_acceptances(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """The licence agreement's acceptances for the organisation (owners and admins), newest first, each with where its
    emailed copy is; anyone else gets their own."""

    query = select(TermsAcceptance).order_by(TermsAcceptance.accepted_at.desc()).limit(200)
    if terms_service.may_accept_for_organisation(db, current_user):
        query = query.where(TermsAcceptance.scope == "organisation")
    else:
        query = query.where(TermsAcceptance.user_id == current_user.id)
    rows = db.scalars(query).all()
    current = terms_service.current()
    return JSONResponse(
        content={
            "current": {"version": current.version, "hash": current.hash},
            "emailReady": mailer.verified(db),
            "acceptances": [_with_copy(db, row) for row in rows],
        },
        headers={"Cache-Control": "no-store"},
    )


@router.get("/terms/acceptances/{acceptance_id}/copy")
def download_copy(acceptance_id: str, format: str = "html", current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """The accepted copy: ``txt`` is exactly the text accepted (its SHA-256 is the recorded hash); ``html`` adds the
    acceptance details."""

    row = _acceptance_for(db, current_user, acceptance_id)
    if isinstance(row, JSONResponse):
        return row
    text = terms_service.accepted_text(db, row)
    if text is None:
        return _error(404, "The text of this version was not kept (accepted before this version of Hawk AI).")
    files = {name.rsplit(".", 1)[-1]: (name, content, kind) for name, content, kind in terms_copy_service.copy_files(row, text)}
    if format not in files:
        return _error(400, "Choose txt or html.")
    name, content, kind = files[format]
    return Response(
        content=content,
        media_type=f"{kind}; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


@router.post("/terms/acceptances/{acceptance_id}/resend")
def resend_copy(
    acceptance_id: str,
    background: BackgroundTasks,
    body: dict[str, Any] | None = Body(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Queue the copy again (to the acceptor, or another address an owner or admin gives); it goes out at once when
    the email server is ready, else as soon as it is."""

    if not terms_service.may_accept_for_organisation(db, current_user):
        return _error(403, "Only owners and admins can send the agreement again.")
    row = _acceptance_for(db, current_user, acceptance_id)
    if isinstance(row, JSONResponse):
        return row
    if row.scope != "organisation":
        return _error(400, "Only the licence agreement accepted for the organisation is emailed.")
    given = (body or {}).get("to")
    to = terms_service.clean_email(given) if given else row.email
    if not to:
        return _error(400, "That is not an email address.")
    terms_copy_service.queue(db, row, to=to, requested_by=current_user.email)
    write_audit_log(
        db,
        tenant_id=row.tenant_id,
        actor_user_id=current_user.id,
        actor_type="human",
        action="terms.copy.resend",
        resource_type="terms_acceptance",
        resource_id=row.id,
        payload={"reason": f"Copy of licence agreement v{row.version} queued again for {to}.", "terms": {"version": row.version, "hash": row.text_hash}},
    )
    db.commit()
    _deliver_copies_later(background, db)
    return JSONResponse(content=_with_copy(db, row), headers={"Cache-Control": "no-store"})
