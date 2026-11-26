"""Get help: support cases and enhancement requests (CxMissionZero's src/support.js and /settings/guide/self-check-and-help), each with a
number (SUP-0001, ENH-0001), a status, and a conversation between the person who raised it and the support team.

Hawk's support team for a request is the owners and admins of the tenant it was raised in (MZ's ``support.manage``,
which its Admin role holds). Numbers are the whole installation's, as MZ's one support.json is; each request remembers
its tenant. Kept in the database (support_tickets), so in every backup.

Limits (MZ): a title of 200 characters, a message of 10,000, 500 messages a request, 20 requests an hour a person.
Statuses: New → In progress → Waiting for reply → Completed, or Declined. When the person who raised it answers, a
request waiting for them goes back to In progress, and a completed or declined one is reopened as New.
"""

from __future__ import annotations

import datetime as dt
import html
import re
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

KINDS = {
    "case": {"prefix": "SUP", "label": "Support case"},
    "enhancement": {"prefix": "ENH", "label": "Enhancement"},
}
STATUSES = {
    "new": "New",
    "in-progress": "In progress",
    "waiting": "Waiting for reply",
    "completed": "Completed",
    "declined": "Declined",
}
PRIORITIES = ["low", "normal", "high", "urgent"]
LIMITS = {"subject": 200, "text": 10_000, "messages": 500}
PER_HOUR = 20
TOO_MANY = "You raised 20 requests in the last hour. Add to one of them instead, or try again later."
NOT_YOURS = "No such request, or it is not yours to see."
#: Who answers: the tenant's owners and admins (MZ's support.manage).
TEAM_ROLES = ("owner", "admin")
EMAIL_RE = re.compile(r"^[^\s@<>()\",;]+@[^\s@<>()\",;]+\.[a-z]{2,}$", re.IGNORECASE)


class SupportError(Exception):
    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def clean(value: Any, limit: int) -> str:
    return str(value if value is not None else "").replace("\r\n", "\n").replace("\r", "\n").strip()[:limit]


def person(p: dict[str, Any] | None) -> dict[str, str]:
    p = p or {}
    return {"id": str(p.get("id") or ""), "name": str(p.get("name") or ""), "email": str(p.get("email") or "")}


def _now(now: dt.datetime | None = None) -> dt.datetime:
    return (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)


def iso(moment: Any) -> str:
    if isinstance(moment, dt.datetime):
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=dt.timezone.utc)
        return moment.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return str(moment or "")


def get(db: Session, ticket_id: str, *, lock: bool = False) -> Any:
    """A request by its number. ``lock``: held until the caller commits (``SELECT … FOR UPDATE``), for a change to its
    conversation or status, so two at the same moment are made one after the other and neither is lost."""

    from app.db.models.platform_records import SupportTicket

    return db.get(SupportTicket, str(ticket_id or "").upper(), with_for_update=True if lock else None)


def raised_since(db: Session, requester_id: str, since: dt.datetime) -> int:
    from app.db.models.platform_records import SupportTicket

    return int(db.scalar(select(func.count()).select_from(SupportTicket).where(SupportTicket.requester_id == requester_id, SupportTicket.created_at >= since)) or 0)


def _next_number(db: Session, kind: str) -> int:
    """The next number of this kind, under the counter row's lock (an UPDATE), so two requests never share one."""

    from sqlalchemy import text

    db.execute(text("INSERT INTO support_counters (kind, value) VALUES (:kind, 0) ON CONFLICT (kind) DO NOTHING"), {"kind": kind})
    return int(db.execute(text("UPDATE support_counters SET value = value + 1 WHERE kind = :kind RETURNING value"), {"kind": kind}).scalar_one())


def create(
    db: Session,
    *,
    kind: str,
    tenant_id: str | None,
    subject: Any,
    text: Any,
    priority: Any = "normal",
    requester: dict[str, Any],
    page: Any = "",
    version: str = "",
    now: dt.datetime | None = None,
) -> Any:
    from app.db.models.platform_records import SupportTicket

    if kind not in KINDS:
        raise SupportError(400, "Choose a support case or an enhancement.")
    title = clean(subject, LIMITS["subject"])
    body = clean(text, LIMITS["text"])
    if not title:
        raise SupportError(400, "Give it a short title.")
    if not body:
        raise SupportError(400, "Describe what you need.")
    at = _now(now)
    n = _next_number(db, kind)
    who = person(requester)
    ticket = SupportTicket(
        id=f"{KINDS[kind]['prefix']}-{n:04d}",
        kind=kind,
        tenant_id=tenant_id,
        subject=title,
        priority=(priority if priority in PRIORITIES else "normal") if kind == "case" else "",
        status="new",
        requester_id=who["id"],
        requester_name=who["name"],
        requester_email=who["email"],
        page=clean(page, 200),
        version=clean(version, 64),
        messages=[{"at": iso(at), "by": who, "team": False, "text": body}],
        history=[{"at": iso(at), "by": who, "status": "new"}],
        created_at=at,
        updated_at=at,
    )
    db.add(ticket)
    db.flush()
    return ticket


def reply(db: Session, ticket: Any, *, by: dict[str, Any], team: bool, text: Any, now: dt.datetime | None = None) -> Any:
    """A message in the conversation. When the person who raised it answers, a request that was waiting for them, or
    closed, goes back to the team."""

    body = clean(text, LIMITS["text"])
    if not body:
        raise SupportError(400, "Write a message first.")
    messages = list(ticket.messages or [])
    if len(messages) >= LIMITS["messages"]:
        raise SupportError(409, "This conversation is full. Raise a new request that refers to this one.")
    at = iso(_now(now))
    who = person(by)
    messages.append({"at": at, "by": who, "team": bool(team), "text": body})
    ticket.messages = messages
    if not team:
        following = "in-progress" if ticket.status == "waiting" else "new" if ticket.status in ("completed", "declined") else None
        if following:
            ticket.status = following
            ticket.history = [*list(ticket.history or []), {"at": at, "by": who, "status": following}]
    ticket.updated_at = _now(now)
    db.flush()
    return ticket


def set_status(db: Session, ticket: Any, status: str, *, by: dict[str, Any], now: dt.datetime | None = None) -> bool:
    """The team moves a request on. Returns whether it changed."""

    if status not in STATUSES:
        raise SupportError(400, f"Status must be one of: {', '.join(STATUSES)}.")
    if ticket.status == status:
        return False
    at = _now(now)
    ticket.status = status
    ticket.history = [*list(ticket.history or []), {"at": iso(at), "by": person(by), "status": status}]
    ticket.updated_at = at
    db.flush()
    return True


# ---------------------------------------------------------------------------------------------------------------------
# Where requests go: the portal (the default), or email (offline installations)
# ---------------------------------------------------------------------------------------------------------------------


def channel(db: Session, tenant_id: str | None) -> dict[str, str]:
    """{mode: portal|email (in force), email, chosen (what was chosen)}: the page's choice wins over SUPPORT_MODE / SUPPORT_EMAIL; email mode needs a valid
    address, else Get help stays on the portal (/settings/guide/self-check-and-help)."""

    import os

    from app.db.models.platform_records import SupportSettings

    row = db.get(SupportSettings, tenant_id) if tenant_id else None
    env_mode = "email" if str(os.environ.get("SUPPORT_MODE") or "").strip().lower() == "email" else "portal"
    env_email = str(os.environ.get("SUPPORT_EMAIL") or "").strip().lower()
    chosen = row.mode if row is not None else env_mode
    email = (row.email if row is not None and row.email else env_email) or ""
    mode = "portal" if chosen == "email" and not EMAIL_RE.match(email) else chosen
    return {"mode": mode, "email": email, "chosen": chosen}


def save_channel(db: Session, tenant_id: str, *, mode: Any, email: Any, by: str, now: dt.datetime | None = None) -> dict[str, str]:
    from app.db.models.platform_records import SupportSettings

    before = channel(db, tenant_id)
    new_mode = before["chosen"] if mode is None else ("email" if mode == "email" else "portal")
    new_email = before["email"] if email is None else str(email).strip().lower()
    # An address that is not one yet is refused; email mode without one is kept, and Get help stays on the portal
    # until a valid address is entered (/settings/guide/self-check-and-help).
    if new_email and not EMAIL_RE.match(new_email):
        raise SupportError(400, "Give the email address requests go to.")
    row = db.get(SupportSettings, tenant_id)
    if row is None:
        row = SupportSettings(tenant_id=tenant_id)
        db.add(row)
    row.mode, row.email, row.updated_at, row.updated_by = new_mode, new_email, _now(now), by
    db.flush()
    return channel(db, tenant_id)


# ---------------------------------------------------------------------------------------------------------------------
# The email about a request (MZ's supportEmail)
# ---------------------------------------------------------------------------------------------------------------------


def _safe_url(url: str) -> str:
    return url if re.match(r"^https?://", url or "", re.IGNORECASE) else ""


def support_email(ticket: Any, *, event: str, to: str, app_name: str = "Hawk AI", url: str = "", message: str | None = None) -> dict[str, str]:
    kind = KINDS[ticket.kind]["label"]
    status = STATUSES[ticket.status]
    link = _safe_url(f"{url.rstrip('/')}/help?open={ticket.id}" if url else "")
    for_team = to == "team"
    who = ticket.requester_name or ticket.requester_email
    lines = {
        "created": [f"{who} raised {kind.lower()} {ticket.id}."]
        if for_team
        else [f"Thank you: your {kind.lower()} is {ticket.id}. Keep this number to follow it.", "The support team has been told and will answer here."],
        "message": [f"{who} wrote on {ticket.id}."] if for_team else [f"The support team answered on {ticket.id}."],
        "status": [f"{ticket.id} is now: {status}."],
    }[event]
    subject = f"[{ticket.id}] {f'{status}: ' if event == 'status' else 'New message: ' if event == 'message' else ''}{ticket.subject}"
    quoted = message if message is not None else ((ticket.messages or [{}])[0].get("text", "") if event == "created" else "")
    facts = [
        ("Number", ticket.id),
        ("Type", kind),
        ("Status", status),
        *([("Priority", ticket.priority[:1].upper() + ticket.priority[1:])] if ticket.priority else []),
        ("Raised by", f"{ticket.requester_name + ' ' if ticket.requester_name else ''}<{ticket.requester_email}>"),
    ]
    text = "\n".join(
        [
            *lines,
            "",
            *(f"{k}: {v}" for k, v in facts),
            f"Title: {ticket.subject}",
            *(["", quoted] if quoted else []),
            *(["", f"Follow it, and answer, at {link}"] if link else []),
        ]
    )
    esc = html.escape
    body = (
        "<!doctype html><html><body style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#0f172a;font-size:14px;line-height:1.5\">\n"
        '<div style="max-width:640px;margin:0 auto;padding:16px">\n'
        f'<p style="margin:0 0 4px;color:#64748b;font-size:12px">{esc(app_name)} · {esc(kind)}</p>\n'
        f'<h1 style="font-size:18px;margin:0 0 12px">{esc(ticket.id)} · {esc(ticket.subject)}</h1>\n'
        + "".join(f'<p style="margin:0 0 8px">{esc(line)}</p>' for line in lines)
        + '\n<table role="presentation" style="border-collapse:collapse;margin:8px 0 12px;font-size:13px">'
        + "".join(f'<tr><td style="padding:2px 12px 2px 0;color:#64748b">{esc(k)}</td><td style="padding:2px 0">{esc(v)}</td></tr>' for k, v in facts)
        + "</table>\n"
        + (f'<blockquote style="margin:0 0 12px;padding:8px 12px;border-left:3px solid #c7d2fe;background:#f8fafc;white-space:pre-wrap">{esc(quoted)}</blockquote>\n' if quoted else "")
        + (f'<p style="margin:0"><a href="{esc(link)}">Follow it, and answer, in {esc(app_name)}</a></p>\n' if link else "")
        + "</div></body></html>"
    )
    return {"subject": subject, "text": text, "html": body}


def mailto(kind: str, *, to: str, user: str, version: str, tenant: str, server: str) -> str:
    """The email-mode link (/settings/guide/self-check-and-help): a subject and a short template, ending in who is asking, the version,
    the tenant and the server address."""

    from urllib.parse import quote

    if kind == "case":
        subject = "Support case: "
        lines = ["What happened:", "", "What I expected:", "", "Steps to see it:", "", "Priority (Low, Normal, High, Urgent):", ""]
    else:
        subject = "Enhancement: "
        lines = ["What I would like:", "", "Who it helps:", ""]
    lines += ["--", f"User: {user}", f"Hawk AI version: {version}", f"Tenant: {tenant}", f"Server: {server}"]
    return f"mailto:{quote(to, safe='@')}?subject={quote(subject)}&body={quote(chr(10).join(lines))}"
