"""Get help (app/services/support_desk.py): support cases and enhancement requests. The routes under /support
(/api/support from the browser), ported from CxMissionZero's src/routes/support.js: a person's own requests, the
support team's queue (the tenant's owners and admins), a new request, a message, a change of status, the email that
tells the other side, and Settings → Get help (the portal, or email for an offline installation).
"""

from __future__ import annotations

from email.message import EmailMessage
from typing import Any

from fastapi import APIRouter, Body, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.rbac import holds, require_permission
from app.core.tenant import TenantContext, require_tenant
from app.db.models.platform_records import SupportTicket
from app.db.session import get_db
from app.services import account_security, iam_service, mailer, password_reset_service, support_desk
from app.services.audit_service import write_audit_log
from app.version import APP_VERSION

router = APIRouter(tags=["support"])


def _error(status_code: int, message: str, **extra: Any) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": message, "detail": message, **extra})


def _team(ctx: TenantContext) -> bool:
    return holds(ctx, "support.manage")


def _me(ctx: TenantContext) -> dict[str, str]:
    user = ctx.user
    return {"id": user.id if user else "", "name": (user.full_name if user else "") or "", "email": (user.email if user else "") or ""}


def _sees(ctx: TenantContext, ticket: SupportTicket) -> bool:
    """The one who raised it, or the support team of its tenant."""

    return ticket.requester_id == (ctx.user.id if ctx.user else None) or (_team(ctx) and ticket.tenant_id == ctx.tenant.id)


def _view(ctx: TenantContext, t: SupportTicket, *, full: bool = False) -> dict[str, Any]:
    me = ctx.user.id if ctx.user else ""
    view = {
        "id": t.id,
        "kind": t.kind,
        "subject": t.subject,
        "status": t.status,
        "priority": t.priority,
        "requester": {"name": t.requester_name, "email": t.requester_email},
        "mine": t.requester_id == me,
        "createdAt": support_desk.iso(t.created_at),
        "updatedAt": support_desk.iso(t.updated_at),
        "messages": len(t.messages or []),
    }
    if not full:
        return view
    return {
        **view,
        "page": t.page,
        "version": t.version,
        "conversation": [
            {"at": m.get("at"), "name": (m.get("by") or {}).get("name") or (m.get("by") or {}).get("email") or "", "team": bool(m.get("team")), "mine": (m.get("by") or {}).get("id") == me, "text": m.get("text", "")}
            for m in (t.messages or [])
        ],
        "history": [{"at": h.get("at"), "name": (h.get("by") or {}).get("name") or (h.get("by") or {}).get("email") or "", "status": h.get("status")} for h in (t.history or [])],
    }


def support_team(db: Session, tenant_id: str | None) -> list[str]:
    """The addresses of the team that answers requests raised in a tenant: everyone active whose role holds
    support.manage (Settings → Roles & permissions), not the owners and admins by name."""

    if not tenant_id:
        return []
    return iam_service.emails_holding(db, tenant_id, "support.manage")


def mail_ready(db: Session) -> str:
    """'' when email can go out; otherwise why not (the email server must be set up and tested, docs/sign-in.md)."""

    if not mailer.configured():
        return "The email server is not set up (Settings → Email (SMTP))."
    if account_security.policy(db).smtp_verified != mailer.fingerprint():
        return "The email server is not tested: test it under Settings → Email (SMTP)."
    return ""


def mail_support(db: Session, ctx: TenantContext, t: SupportTicket, event: str, *, from_team: bool = False, message: str | None = None) -> dict[str, Any]:
    """Email about a request (MZ's mailSupport). The person who raised it hears of every answer and status change; the
    team, of every new request and every answer from that person. Never fails the request: the answer says what could
    not be sent."""

    self_email = str(ctx.user.email if ctx.user else "").lower()
    jobs: list[tuple[str, list[str]]] = []
    if (event != "message" or from_team) and t.requester_email and (event == "created" or t.requester_email.lower() != self_email):
        jobs.append(("requester", [t.requester_email]))
    if not from_team and event != "status":
        team = [e for e in support_team(db, t.tenant_id) if e != self_email]
        if team:
            jobs.append(("team", team))
    result: dict[str, Any] = {"sent": 0, "error": ""}
    if not jobs:
        return result
    why = mail_ready(db)
    if why:
        result["error"] = why
        return result
    url = password_reset_service.link_base()
    for to, addresses in jobs:
        content = support_desk.support_email(t, event=event, to=to, app_name="Hawk AI", url=url, message=message)
        for address in addresses:
            message_obj = EmailMessage()
            message_obj["Subject"] = content["subject"]
            message_obj.set_content(content["text"])
            message_obj.add_alternative(content["html"], subtype="html")
            if to == "team" and t.requester_email:
                message_obj["Reply-To"] = t.requester_email
            try:
                mailer.send(message_obj, address)
                result["sent"] += 1
            except mailer.MailError as error:
                result["error"] = str(error)
    return result


def _audit(db: Session, ctx: TenantContext, action: str, t: SupportTicket, reason: str, **details: Any) -> None:
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human",
        action=action,
        resource_type="support",
        resource_id=t.id,
        payload={"outcome": "info", "reason": reason, **details},
    )


# ---- Settings → Get help (before /support/{ticket_id}, which would take "settings" for a number) --------------------


@router.get("/support/settings")
def get_support_settings(ctx: TenantContext = Depends(require_permission("support.manage")), db: Session = Depends(get_db)):
    return support_desk.channel(db, ctx.tenant.id)


@router.put("/support/settings")
def put_support_settings(body: dict[str, Any] | None = Body(default=None), ctx: TenantContext = Depends(require_permission("support.manage")), db: Session = Depends(get_db)):
    body = body or {}
    before = support_desk.channel(db, ctx.tenant.id)
    try:
        after = support_desk.save_channel(db, ctx.tenant.id, mode=body.get("mode"), email=body.get("email"), by=ctx.user.email if ctx.user else "")
    except support_desk.SupportError as error:
        db.rollback()
        return _error(error.status_code, error.message)
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human",
        action="settings.support",
        resource_type="settings",
        resource_id="support",
        payload={"outcome": "changed", "reason": f"Get help: {after['mode']} · {after['email'] or 'no address'}.", "mode": after["mode"], "email": after["email"], "before": before},
    )
    db.commit()
    return after


# ---- Requests ----------------------------------------------------------------------------------------------------


@router.get("/support")
def list_requests(ctx: TenantContext = Depends(require_tenant), db: Session = Depends(get_db)):
    me = ctx.user.id if ctx.user else ""
    query = select(SupportTicket).order_by(SupportTicket.updated_at.desc())
    if _team(ctx):
        query = query.where((SupportTicket.tenant_id == ctx.tenant.id) | (SupportTicket.requester_id == me))
    else:
        query = query.where(SupportTicket.requester_id == me)
    rows = db.scalars(query.limit(1000)).all()
    channel = support_desk.channel(db, ctx.tenant.id)
    return {"team": _team(ctx), "statuses": support_desk.STATUSES, "channel": channel, "limits": {**support_desk.LIMITS, "perHour": support_desk.PER_HOUR}, "requests": [_view(ctx, t) for t in rows if _sees(ctx, t)]}


@router.get("/support/mailto/{kind}")
def email_request_link(kind: str, ctx: TenantContext = Depends(require_tenant), db: Session = Depends(get_db)):
    """Email mode: the mailto: link that opens the person's own email app, with the template filled in."""

    channel = support_desk.channel(db, ctx.tenant.id)
    if channel["mode"] != "email":
        return _error(409, "Get help uses the support portal here.")
    if kind not in support_desk.KINDS:
        return _error(400, "Choose a support case or an enhancement.")
    return {
        "href": support_desk.mailto(
            kind,
            to=channel["email"],
            user=f"{ctx.user.full_name or ''} <{ctx.user.email}>".strip() if ctx.user else "",
            version=APP_VERSION,
            tenant=ctx.tenant.name,
            server=password_reset_service.link_base() or "",
        )
    }


@router.get("/support/{ticket_id}")
def get_request(ticket_id: str, ctx: TenantContext = Depends(require_tenant), db: Session = Depends(get_db)):
    t = support_desk.get(db, ticket_id)
    if t is None or not _sees(ctx, t):
        return _error(404, support_desk.NOT_YOURS)
    return {"team": _team(ctx), "request": _view(ctx, t, full=True)}


@router.post("/support")
def raise_request(body: dict[str, Any] | None = Body(default=None), ctx: TenantContext = Depends(require_tenant), db: Session = Depends(get_db)):
    import datetime as dt

    body = body or {}
    kind = body.get("kind")
    if kind not in support_desk.KINDS:
        return _error(400, "Choose a support case or an enhancement.")
    channel = support_desk.channel(db, ctx.tenant.id)
    if channel["mode"] == "email":
        return _error(409, f"Requests go by email here: write to {channel['email']}.", email=channel["email"])
    me = _me(ctx)
    if support_desk.raised_since(db, me["id"], dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)) >= support_desk.PER_HOUR:
        return _error(429, support_desk.TOO_MANY)
    try:
        t = support_desk.create(db, kind=kind, tenant_id=ctx.tenant.id, subject=body.get("subject"), text=body.get("text"), priority=body.get("priority"), requester=me, page=body.get("page"), version=APP_VERSION)
    except support_desk.SupportError as error:
        db.rollback()
        return _error(error.status_code, error.message)
    _audit(db, ctx, "support.case" if t.kind == "case" else "support.enhancement", t, f"{t.id} {t.subject}", priority=t.priority)
    db.commit()
    emailed = mail_support(db, ctx, t, "created")
    return JSONResponse(status_code=201, content={"request": _view(ctx, t, full=True), "emailed": emailed})


@router.post("/support/{ticket_id}/messages")
def write_on_request(ticket_id: str, body: dict[str, Any] | None = Body(default=None), ctx: TenantContext = Depends(require_tenant), db: Session = Depends(get_db)):
    t = support_desk.get(db, ticket_id)
    if t is None or not _sees(ctx, t):
        return _error(404, support_desk.NOT_YOURS)
    me = _me(ctx)
    # Someone who both raised it and is on the team answers as the person who raised it.
    from_team = t.requester_id != me["id"]
    try:
        support_desk.reply(db, t, by=me, team=from_team, text=(body or {}).get("text"))
    except support_desk.SupportError as error:
        db.rollback()
        return _error(error.status_code, error.message)
    db.commit()
    emailed = mail_support(db, ctx, t, "message", from_team=from_team, message=(t.messages or [{}])[-1].get("text", ""))
    return {"request": _view(ctx, t, full=True), "emailed": emailed}


@router.post("/support/{ticket_id}/status")
def move_request_on(ticket_id: str, body: dict[str, Any] | None = Body(default=None), ctx: TenantContext = Depends(require_tenant), db: Session = Depends(get_db)):
    if not _team(ctx):
        return _error(403, "Only the support team (the organisation's owners and admins) changes a request's status.")
    t = support_desk.get(db, ticket_id)
    if t is None or not _sees(ctx, t):
        return _error(404, support_desk.NOT_YOURS)
    try:
        changed = support_desk.set_status(db, t, str((body or {}).get("status") or ""), by=_me(ctx))
    except support_desk.SupportError as error:
        db.rollback()
        return _error(error.status_code, error.message)
    if changed:
        _audit(db, ctx, "support.status", t, f"{t.id} is now: {support_desk.STATUSES[t.status]}.", status=t.status)
    db.commit()
    emailed = mail_support(db, ctx, t, "status", from_team=True) if changed else {"sent": 0, "error": ""}
    return {"request": _view(ctx, t, full=True), "emailed": emailed}
