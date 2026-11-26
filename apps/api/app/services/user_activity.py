"""What people do in Hawk AI's console, one row each (CxMissionZero's src/activity-log.js): who (email, name, role),
when, from where (IP), what (the action, the item), which fields a change touched (their names only, never their
values: no passwords, keys or text are kept), and how it ended (status, time taken).

MZ keeps it per tenant in activity.jsonl, rotated at 20 MB to activity.1.jsonl, and shows nothing older than a year.
Hawk keeps it in the ``user_activity`` table, per tenant, with the same limits adapted to a table: rows older than
``KEEP_DAYS`` are not shown and are removed, and a tenant keeps at most ``MAX_ROWS`` (about MZ's two 20 MB files at
~200 bytes a row), the oldest going first. Not hash-chained (MZ's is not either); the audit log is the chained record.

Recorded by the API's request middleware (app/main.py) for every signed-in request that changes something, and for
the reads worth recording (downloads and exports), once it is answered.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from typing import Any, Iterable

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

KEEP_DAYS = 365
MAX_ROWS = 200_000
#: Removing what is past the limits runs once every this many rows written (per process).
PRUNE_EVERY = 500
MAX_TEXT = 200
KINDS = ("action", "page", "sign-in", "event")

_CONTROL = re.compile(r"[\u0000-\u001f\u007f]+")


def clean(value: Any, limit: int = MAX_TEXT) -> str:
    return _CONTROL.sub(" ", str(value if value is not None else "")).strip()[:limit]


#: The actions people take, by "METHOD route". Anything else is described from its route (MZ's ACTIONS, for Hawk's routes).
ACTIONS: dict[str, str] = {
    # Signing in and one's own account
    "POST /auth/me/password": "Changed their password",
    "POST /auth/me/two-step/setup": "Started setting up two-step sign-in",
    "POST /auth/me/two-step/enable": "Turned on two-step sign-in",
    "POST /auth/me/two-step/disable": "Turned off two-step sign-in",
    "POST /auth/me/two-step/recovery-codes": "Made new recovery codes",
    "POST /auth/select-tenant": "Switched tenant",
    "POST /terms/accept": "Accepted the terms of use",
    # Sign-in rules
    "PUT /auth/sign-in-settings": "Changed the sign-in settings",
    "POST /auth/sign-in-settings/test-email": "Sent a test email",
    "DELETE /auth/sign-in-settings/people/{user_id}/two-step": "Reset a person's two-step sign-in",
    "DELETE /auth/sign-in-settings/people/{user_id}/sso-link": "Reset a person's single sign-on link",
    # HTTPS
    "POST /https/certificate": "Uploaded an HTTPS certificate",
    "POST /https/certificate/previous": "Went back to the previous HTTPS certificate",
    "DELETE /https/certificate": "Removed the HTTPS certificate",
    "POST /https/self-signed": "Made a self-signed certificate",
    "POST /https/request": "Made a certificate request",
    "POST /https/mode": "Changed HTTP and HTTPS",
    "POST /https/hardening": "Changed HTTPS hardening",
    "POST /https/acme": "Set up Let's Encrypt",
    "POST /https/acme/renew": "Renewed the Let's Encrypt certificate",
    "DELETE /https/acme": "Removed Let's Encrypt",
    "GET /https/request.csr": "Downloaded the certificate request",
    # Network and trusted certificates
    "PUT /network": "Changed the proxy",
    "DELETE /network": "Removed the proxy",
    "POST /network/check": "Checked the connection",
    "POST /trust/upload": "Uploaded a trusted certificate",
    "POST /trust/presented": "Trusted a presented certificate",
    "POST /trust/diagnose": "Looked at a server's certificate",
    "DELETE /trust/{fingerprint}": "Removed a trusted certificate",
    # Activation
    "POST /activation": "Entered an activation code",
    # Logs, backups, support
    "GET /audit/log/export.csv": "Exported the audit log",
    "GET /audit/log/export.jsonl": "Exported the audit log",
    "GET /audit/log/verify": "Checked the audit log",
    "GET /activity/log/export.csv": "Exported the user activity log",
    "GET /connector-activity/export.csv": "Exported the connector API activity",
    "GET /backups/{name}": "Downloaded a backup",
    "POST /backups": "Made a backup",
    "POST /backups/restore": "Restored a backup",
    "DELETE /backups/restore": "Cancelled a restore",
    "POST /backups/key/show": "Looked at the backup key",
    "POST /backups/key/confirm": "Confirmed saving the backup key",
    "POST /backups/encryption": "Turned on backup encryption",
    "PUT /backups/readiness/{check_id}": "Changed a readiness check",
    "POST /support": "Opened a support case",
    "POST /support/{ticket_id}/messages": "Wrote on a support case",
    "POST /support/{ticket_id}/status": "Changed a support case's status",
    "PUT /support/settings": "Changed where Get help sends requests",
    # Connectors
    "POST /monitoring/connectors": "Added a connector",
    "POST /monitoring/connectors/{connector_id}/pull": "Pulled a connector now",
}

VERBS = {"POST": "Did", "PUT": "Changed", "PATCH": "Changed", "DELETE": "Removed", "GET": "Opened"}


def describe(method: str, route: str) -> str:
    """"PUT /backups/readiness/{check_id}" → its name; otherwise "Changed backups › readiness"."""

    named = ACTIONS.get(f"{method} {route}")
    if named:
        return named
    words = [p.replace("-", " ").replace("_", " ") for p in str(route).split("/") if p and not p.startswith("{")]
    return f"{VERBS.get(method, method)} {' › '.join(words) or route}"


def field_names(body: Any) -> list[str]:
    """The names of the fields a request sent (two levels deep), never their values."""

    if not isinstance(body, dict):
        return []
    out: list[str] = []
    for key, value in body.items():
        if isinstance(value, dict):
            out.extend(f"{key}.{inner}" for inner in value.keys())
        else:
            out.append(str(key))
        if len(out) >= 30:
            break
    return [clean(f, 60) for f in out[:30]]


def target_of(params: dict[str, Any] | None) -> str:
    """Which item a request was about: its route's ids ("{id}" → "id 7f3a…")."""

    return clean(", ".join(f"{k} {str(v)[:60]}" for k, v in (params or {}).items()))


def records_get(route: str) -> bool:
    """GET requests worth recording: downloads, exports, the audit check. Everything else read is not."""

    return f"GET {route}" in ACTIONS or bool(re.search(r"/(download|export)\b|\.(csv|jsonl|csr)$", route))


def should_record(method: str, route: str) -> bool:
    method = method.upper()
    if method in {"HEAD", "OPTIONS"}:
        return False
    return method != "GET" or records_get(route)


def body_fields(raw: bytes, content_type: str) -> list[str]:
    if not raw or "json" not in (content_type or "").lower():
        return []
    try:
        return field_names(json.loads(raw.decode("utf-8")))
    except (ValueError, UnicodeDecodeError):
        return []


_written = 0


def record(db: Session, entry: dict[str, Any], *, now: dt.datetime | None = None) -> Any:
    """One thing someone did. Fields are cut to size; nothing but these fields is kept."""

    from app.db.models.platform_records import UserActivity

    global _written
    row = UserActivity(
        tenant_id=entry.get("tenant_id"),
        at=now or dt.datetime.now(dt.timezone.utc),
        user_id=entry.get("user_id"),
        user=clean(entry.get("user"), 254),
        name=clean(entry.get("name"), 120),
        role=clean(entry.get("role"), 60),
        ip=clean(entry.get("ip"), 64),
        kind=entry.get("kind") if entry.get("kind") in KINDS else "action",
        action=clean(entry.get("action")),
        target=clean(entry.get("target")),
        fields=[clean(f, 60) for f in (entry.get("fields") or [])][:30] if isinstance(entry.get("fields"), list) else [],
        method=clean(entry.get("method"), 8),
        route=clean(entry.get("route"), 120),
        status=entry.get("status") if isinstance(entry.get("status"), int) else None,
        ms=int(round(entry["ms"])) if isinstance(entry.get("ms"), (int, float)) else None,
    )
    db.add(row)
    db.flush()
    _written += 1
    if _written % PRUNE_EVERY == 0:
        prune(db, entry.get("tenant_id"))
    return row


def prune(db: Session, tenant_id: str | None, *, now: dt.datetime | None = None) -> int:
    """Remove what is past a year, and the oldest beyond MAX_ROWS for this tenant."""

    from app.db.models.platform_records import UserActivity

    now = now or dt.datetime.now(dt.timezone.utc)
    removed = db.execute(delete(UserActivity).where(UserActivity.at < now - dt.timedelta(days=KEEP_DAYS)).execution_options(synchronize_session=False)).rowcount or 0
    count = int(db.scalar(select(func.count()).select_from(UserActivity).where(UserActivity.tenant_id == tenant_id)) or 0)
    if count > MAX_ROWS:
        cutoff = db.scalar(
            select(UserActivity.at).where(UserActivity.tenant_id == tenant_id).order_by(UserActivity.at.desc()).offset(MAX_ROWS).limit(1)
        )
        if cutoff is not None:
            removed += db.execute(delete(UserActivity).where(UserActivity.tenant_id == tenant_id, UserActivity.at <= cutoff).execution_options(synchronize_session=False)).rowcount or 0
    return int(removed)


def _iso(moment: Any) -> str:
    if isinstance(moment, dt.datetime):
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=dt.timezone.utc)
        return moment.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    return str(moment or "")


def view(row: Any) -> dict[str, Any]:
    return {
        "at": _iso(row.at),
        "user": row.user,
        "name": row.name,
        "role": row.role,
        "ip": row.ip,
        "kind": row.kind,
        "action": row.action,
        "target": row.target,
        "fields": list(row.fields or []),
        "method": row.method,
        "route": row.route,
        "status": row.status,
        "ms": row.ms,
    }


MAX_OFFSET = 1_000_000  # a page far past any kept row, and well inside a 64-bit OFFSET


def listing(
    db: Session,
    tenant_id: str,
    *,
    limit: int = 50,
    offset: int = 0,
    user: str = "",
    q: str = "",
    kind: str = "",
    since: str = "",
    until: str = "",
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """The newest first, ``limit`` at a time from ``offset``, narrowed to one person, a text, a kind and a time window;
    ``people``: everyone seen. Nothing older than KEEP_DAYS."""

    from app.db.models.platform_records import UserActivity

    now = now or dt.datetime.now(dt.timezone.utc)
    conditions = [UserActivity.tenant_id == tenant_id, UserActivity.at >= now - dt.timedelta(days=KEEP_DAYS)]
    people = db.execute(select(UserActivity.user, func.max(UserActivity.name)).where(*conditions).where(UserActivity.user != "").group_by(UserActivity.user)).all()
    if user:
        conditions.append(UserActivity.user == user)
    if kind:
        conditions.append(UserActivity.kind == kind)
    start, end = _parse(since), _parse(until, end=True)
    if start is not None:
        conditions.append(UserActivity.at >= start)
    if end is not None:
        conditions.append(UserActivity.at <= end)
    needle = clean(q).lower()
    if needle:
        like = f"%{needle}%"
        conditions.append(
            or_(
                *(
                    func.lower(column).like(like)
                    for column in (UserActivity.user, UserActivity.name, UserActivity.role, UserActivity.ip, UserActivity.action, UserActivity.target)
                )
            )
        )
    total = int(db.scalar(select(func.count()).select_from(UserActivity).where(*conditions)) or 0)
    size = min(500, max(1, int(limit or 50)))
    rows = db.scalars(select(UserActivity).where(*conditions).order_by(UserActivity.at.desc(), UserActivity.id.desc()).offset(min(MAX_OFFSET, max(0, int(offset or 0)))).limit(size)).all()
    return {
        "total": total,
        "entries": [view(r) for r in rows],
        "people": sorted(({"email": e, "name": n or ""} for e, n in people), key=lambda p: p["email"]),
        "keepDays": KEEP_DAYS,
    }


def _parse(value: str, *, end: bool = False) -> dt.datetime | None:
    """A date or ISO time from the query string; None for one that is not (the bound is then ignored, as the audit log
    does) rather than a server error."""

    text_value = str(value).strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text_value):
        text_value += "T23:59:59.999999+00:00" if end else "T00:00:00+00:00"
    try:
        moment = dt.datetime.fromisoformat(text_value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=dt.timezone.utc)


CSV_COLUMNS = ["at", "user", "name", "role", "ip", "kind", "action", "target", "fields", "status", "ms"]


def csv_rows(db: Session, tenant_id: str, *, now: dt.datetime | None = None) -> Iterable[list[Any]]:
    """Every row still kept, oldest first (MZ's csv())."""

    from app.db.models.platform_records import UserActivity

    now = now or dt.datetime.now(dt.timezone.utc)
    for row in db.scalars(
        select(UserActivity).where(UserActivity.tenant_id == tenant_id, UserActivity.at >= now - dt.timedelta(days=KEEP_DAYS)).order_by(UserActivity.at, UserActivity.id)
    ):
        item = view(row)
        yield [" ".join(item["fields"]) if c == "fields" else item[c] for c in CSV_COLUMNS]


def session_factory() -> Any:
    """A database session of the activity log's own (tests point this at their database)."""

    from app.db.session import SessionLocal

    return SessionLocal()
