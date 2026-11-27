"""Requests from data subjects (Settings → Compliance → Data requests, /settings/guide/compliance; migration 0106).

A person asks the organisation running Hawk AI to see the personal data it holds about them, to correct or erase it,
raises a grievance, or nominates someone to act for them: India's DPDP Act 2023 (s.11 access, s.12 correction and
erasure, s.13 grievances, s.14 nomination; Rules 2025 R.14) and the UAE PDPL (Federal Decree-Law 45/2021, Art. 13-15).

What it does:

- records each request with its kind, who it is about, when it was received and when it is due (30 days by default
  under both laws as this pack reads them; each tenant sets its own, 1 to 90 days), who handles it and how it ended,
  with an append-only trail of every step (data_subject_request_events);
- counts the open requests that are overdue or due within DUE_SOON_DAYS, for the Compliance page, the control
  registry (``privacy.data_subject_requests``) and the DPDP / UAE PDPL packs;
- for an access request, exports what Hawk AI holds about the person in this tenant: their account, membership,
  directory entry, the audit entries they made, their console activity, their AI sessions and activity (the masked
  prompt only, never the raw one), alerts, findings, endpoints and support cases;
- for an erasure, pseudonymises the person's personal fields in this tenant's records (account, directory, activity,
  findings, endpoints, support cases; raw prompts are cleared) with a stable pseudonym, so records still add up. The
  audit log is never changed or deleted: its entries point at the account, which now carries the pseudonym. It
  refuses to erase the tenant's last active owner, one's own account, or an account another workspace shares.

Every action is written to the audit log by the router (``privacy.request.*``), naming the request, never the person.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy import update as sql_update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import xact_lock

KINDS = ("access", "correction", "erasure", "grievance", "nomination")
STATUSES = ("received", "verifying", "in_progress", "completed", "refused")
OPEN_STATUSES = ("received", "verifying", "in_progress")
FINAL_STATUSES = ("completed", "refused")
LAWS = ("dpdp", "pdpl", "other")
DEFAULT_DUE_DAYS = 30
MIN_DUE_DAYS = 1
MAX_DUE_DAYS = 90
DUE_SOON_DAYS = 7
MAX_ROWS = 5000
MAX_NOTE = 4000
ERASED_NAME = "Erased person"
ERASED_DOMAIN = "erased.invalid"
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")

KIND_LABELS = {
    "access": "See their data",
    "correction": "Correct their data",
    "erasure": "Erase their data",
    "grievance": "Grievance",
    "nomination": "Nominate someone",
}


class DsrError(ValueError):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _utc(value: Any) -> dt.datetime | None:
    if not isinstance(value, dt.datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def _iso(value: Any) -> str | None:
    moment = _utc(value)
    return moment.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z") if moment else None


def _text(value: Any, limit: int) -> str:
    return " ".join(str(value if value is not None else "").split())[:limit]


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def email_hash(email: str) -> str:
    return hashlib.sha256(str(email or "").strip().lower().encode("utf-8")).hexdigest() if email else ""


def pseudonym(key: str) -> str:
    """The stable pseudonym of a person: the same account (or address) always gets the same one."""

    return "erased-" + hashlib.sha256(f"hawk-dsr:{key}".encode("utf-8")).hexdigest()[:12]


# ---- Settings (per tenant) -----------------------------------------------------------------------------------------


def settings_row(db: Session, tenant_id: str) -> Any:
    from app.db.models.data_subject import DataSubjectRequestSettings

    row = db.get(DataSubjectRequestSettings, tenant_id)
    if row is None:
        try:
            with db.begin_nested():
                row = DataSubjectRequestSettings(tenant_id=tenant_id, due_days=DEFAULT_DUE_DAYS, grievance_contact="")
                db.add(row)
                db.flush()
        except IntegrityError:
            row = db.get(DataSubjectRequestSettings, tenant_id, populate_existing=True)
            if row is None:
                raise
    return row


def _read_settings(db: Session, tenant_id: str | None) -> Any:
    """The tenant's settings when they exist, without creating them (for checks that must not write)."""

    if not tenant_id:
        return None
    from app.db.models.data_subject import DataSubjectRequestSettings

    try:
        return db.get(DataSubjectRequestSettings, tenant_id)
    except Exception:  # noqa: BLE001 - a database before migration 0106: the defaults
        return None


def due_days(db: Session, tenant_id: str | None) -> int:
    row = _read_settings(db, tenant_id)
    value = int(row.due_days) if row is not None and row.due_days else DEFAULT_DUE_DAYS
    return max(MIN_DUE_DAYS, min(MAX_DUE_DAYS, value))


def grievance_contact(db: Session, tenant_id: str | None) -> str:
    row = _read_settings(db, tenant_id)
    return str(row.grievance_contact or "").strip() if row is not None else ""


def settings_view(db: Session, tenant_id: str) -> dict[str, Any]:
    row = _read_settings(db, tenant_id)
    return {
        "dueDays": due_days(db, tenant_id),
        "defaultDueDays": DEFAULT_DUE_DAYS,
        "minDueDays": MIN_DUE_DAYS,
        "maxDueDays": MAX_DUE_DAYS,
        "dueSoonDays": DUE_SOON_DAYS,
        "grievanceContact": grievance_contact(db, tenant_id),
        "updatedBy": str(row.updated_by_email or "") if row is not None else "",
        "updatedAt": _iso(row.updated_at) if row is not None else None,
    }


def save_settings(db: Session, tenant_id: str, body: Any, *, email: str) -> list[str]:
    """Change the due days and the grievance contact. Returns what changed, in words (one sentence each)."""

    if not isinstance(body, dict):
        raise DsrError("Send dueDays and grievanceContact.")
    values: dict[str, Any] = {}
    if "dueDays" in body:
        raw = body.get("dueDays")
        try:
            days = int(str(raw).strip()) if not isinstance(raw, bool) else -1
        except ValueError:
            days = -1
        if not MIN_DUE_DAYS <= days <= MAX_DUE_DAYS:
            raise DsrError(f"A request is due within {MIN_DUE_DAYS} to {MAX_DUE_DAYS} days (30 is the default under the DPDP Act and the UAE PDPL as Hawk AI reads them).")
        values["due_days"] = days
    if "grievanceContact" in body:
        contact = _text(body.get("grievanceContact"), 400)
        if len(contact) > 320:
            raise DsrError("The grievance contact is at most 320 characters (a name, email and phone).")
        values["grievance_contact"] = contact
    row = settings_row(db, tenant_id)
    names = {"due_days": "Days to answer a data request", "grievance_contact": "Grievance contact"}
    changes = []
    for column, value in values.items():
        before = getattr(row, column)
        if before != value:
            changes.append(f"{names[column]}: {before or '—'} → {value or '—'}.")
            setattr(row, column, value)
    if changes:
        row.updated_by_email = email or ""
    db.flush()
    return changes


# ---- Views ----------------------------------------------------------------------------------------------------------


def is_overdue(row: Any, now: dt.datetime) -> bool:
    due = _utc(row.due_at)
    return row.status in OPEN_STATUSES and due is not None and due < now


def is_due_soon(row: Any, now: dt.datetime) -> bool:
    due = _utc(row.due_at)
    return row.status in OPEN_STATUSES and due is not None and now <= due <= now + dt.timedelta(days=DUE_SOON_DAYS)


def view(row: Any, now: dt.datetime | None = None) -> dict[str, Any]:
    now = now or _now()
    due = _utc(row.due_at)
    days_left = None
    if row.status in OPEN_STATUSES and due is not None:
        days_left = int((due - now).total_seconds() // 86400)
    return {
        "id": row.id,
        "kind": row.kind,
        "kindLabel": KIND_LABELS.get(row.kind, row.kind),
        "law": row.law,
        "subjectEmail": row.subject_email,
        "subjectIdentifier": row.subject_identifier,
        "subjectMatched": bool(row.subject_user_id),
        "channel": row.channel,
        "receivedAt": _iso(row.received_at),
        "dueAt": _iso(row.due_at),
        "status": row.status,
        "overdue": is_overdue(row, now),
        "dueSoon": is_due_soon(row, now),
        "daysLeft": days_left,
        "refusalReason": row.refusal_reason or "",
        "handledBy": row.handled_by_email or "",
        "notes": row.notes or "",
        "completedAt": _iso(row.completed_at),
        "createdBy": row.created_by_email or "",
        "createdAt": _iso(row.created_at),
    }


def event_view(row: Any) -> dict[str, Any]:
    return {
        "id": row.id,
        "at": _iso(row.at),
        "by": row.actor_email or "",
        "kind": row.kind,
        "from": row.from_status or "",
        "to": row.to_status or "",
        "note": row.note or "",
        "details": row.details if isinstance(row.details, dict) else {},
    }


def summary(db: Session, tenant_id: str | None, now: dt.datetime | None = None) -> dict[str, Any]:
    """The tenant's requests in counts: open, overdue, due soon, completed, refused; the next due date. Never raises
    (a database before 0106 counts nothing)."""

    now = now or _now()
    out: dict[str, Any] = {"total": 0, "open": 0, "overdue": 0, "dueSoon": 0, "completed": 0, "refused": 0, "nextDueAt": None, "dueSoonDays": DUE_SOON_DAYS}
    if not tenant_id:
        return out
    from app.db.models.data_subject import DataSubjectRequest

    try:
        rows = db.execute(select(DataSubjectRequest.status, DataSubjectRequest.due_at).where(DataSubjectRequest.tenant_id == tenant_id)).all()
    except Exception:  # noqa: BLE001
        return out
    next_due: dt.datetime | None = None
    soon_until = now + dt.timedelta(days=DUE_SOON_DAYS)
    for status, due_at in rows:
        out["total"] += 1
        due = _utc(due_at)
        if status in OPEN_STATUSES:
            out["open"] += 1
            if due is not None and due < now:
                out["overdue"] += 1
            elif due is not None and due <= soon_until:
                out["dueSoon"] += 1
            if due is not None and due >= now and (next_due is None or due < next_due):
                next_due = due
        elif status in out:
            out[status] += 1
    out["nextDueAt"] = _iso(next_due)
    return out


# ---- Reading and writing requests -----------------------------------------------------------------------------------


def get(db: Session, tenant_id: str, request_id: str) -> Any:
    from app.db.models.data_subject import DataSubjectRequest

    row = db.scalar(select(DataSubjectRequest).where(DataSubjectRequest.id == str(request_id or "")[:36], DataSubjectRequest.tenant_id == tenant_id))
    if row is None:
        raise DsrError("No such request.", 404)
    return row


def events(db: Session, row: Any) -> list[Any]:
    from app.db.models.data_subject import DataSubjectRequestEvent

    return list(
        db.scalars(
            select(DataSubjectRequestEvent)
            .where(DataSubjectRequestEvent.request_id == row.id, DataSubjectRequestEvent.tenant_id == row.tenant_id)
            .order_by(DataSubjectRequestEvent.at, DataSubjectRequestEvent.id)
        ).all()
    )


def add_event(db: Session, row: Any, *, kind: str, actor: Any, note: str = "", from_status: str = "", to_status: str = "", details: dict[str, Any] | None = None, at: dt.datetime | None = None) -> Any:
    from app.db.models.data_subject import DataSubjectRequestEvent

    entry = DataSubjectRequestEvent(
        request_id=row.id,
        tenant_id=row.tenant_id,
        at=at or _now(),
        actor_user_id=getattr(actor, "id", None),
        actor_email=str(getattr(actor, "email", "") or ""),
        kind=kind,
        from_status=from_status,
        to_status=to_status,
        note=note[:MAX_NOTE],
        details=details or {},
    )
    db.add(entry)
    db.flush()
    return entry


def list_requests(db: Session, tenant_id: str, *, status: str = "", overdue: bool = False, kind: str = "", now: dt.datetime | None = None) -> list[Any]:
    from app.db.models.data_subject import DataSubjectRequest

    now = now or _now()
    query = select(DataSubjectRequest).where(DataSubjectRequest.tenant_id == tenant_id)
    if status == "open":
        query = query.where(DataSubjectRequest.status.in_(OPEN_STATUSES))
    elif status:
        if status not in STATUSES:
            raise DsrError(f"Status is one of open, {', '.join(STATUSES)}.")
        query = query.where(DataSubjectRequest.status == status)
    if kind:
        if kind not in KINDS:
            raise DsrError(f"Kind is one of {', '.join(KINDS)}.")
        query = query.where(DataSubjectRequest.kind == kind)
    if overdue:
        query = query.where(DataSubjectRequest.status.in_(OPEN_STATUSES), DataSubjectRequest.due_at < now)
    rows = list(db.scalars(query.order_by(DataSubjectRequest.due_at, DataSubjectRequest.created_at).limit(MAX_ROWS)).all())
    # Open requests first (soonest due first), then the finished ones, newest first.
    open_rows = [r for r in rows if r.status in OPEN_STATUSES]
    done = sorted((r for r in rows if r.status not in OPEN_STATUSES), key=lambda r: _utc(r.completed_at) or _utc(r.updated_at) or now, reverse=True)
    return open_rows + done


def member(db: Session, tenant_id: str, email: str) -> Any:
    """The member of this tenant with this email (never someone of another tenant), or None."""

    from app.db.models.user import User, UserTenantRole

    address = str(email or "").strip().lower()
    if not address:
        return None
    return db.scalar(
        select(User).join(UserTenantRole, UserTenantRole.user_id == User.id).where(func.lower(User.email) == address, UserTenantRole.tenant_id == tenant_id)
    )


def _moment(value: Any) -> dt.datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        if len(raw) == 10:
            raw += "T00:00:00+00:00"
        moment = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        raise DsrError("Give the date received as a date (2026-11-26) or a time (2026-11-26T08:00:00Z).") from None
    return moment if moment.tzinfo else moment.replace(tzinfo=dt.timezone.utc)


def create(db: Session, tenant_id: str, body: Any, *, actor: Any, now: dt.datetime | None = None) -> Any:
    from app.db.models.data_subject import DataSubjectRequest

    if not isinstance(body, dict):
        raise DsrError("Send kind, subjectEmail and receivedAt.")
    now = now or _now()
    kind = str(body.get("kind") or "")
    if kind not in KINDS:
        raise DsrError(f"Kind is one of {', '.join(KINDS)}.")
    law = str(body.get("law") or "other")
    if law not in LAWS:
        raise DsrError("Law is dpdp, pdpl or other.")
    email = _text(body.get("subjectEmail"), 400).lower()
    identifier = _text(body.get("subjectIdentifier"), 400)
    if email and not _EMAIL.match(email):
        raise DsrError("The person's email does not look like an email address.")
    if not email and not identifier:
        raise DsrError("Say who the request is about: their email, or another identifier you know them by.")
    if len(identifier) > 200:
        raise DsrError("The identifier is at most 200 characters.")
    received = _moment(body.get("receivedAt")) or now
    if received > now + dt.timedelta(days=1):
        raise DsrError("The request cannot be received in the future.")
    if received < now - dt.timedelta(days=366):
        raise DsrError("Record requests received within the last year.")
    note = str(body.get("notes") or "").strip()[:MAX_NOTE]
    channel = _text(body.get("channel"), 32)
    found = member(db, tenant_id, email) if email else None
    row = DataSubjectRequest(
        tenant_id=tenant_id,
        kind=kind,
        law=law,
        subject_email=email,
        subject_identifier=identifier,
        subject_hash=email_hash(email),
        subject_user_id=found.id if found is not None else None,
        channel=channel,
        received_at=received,
        due_at=received + dt.timedelta(days=due_days(db, tenant_id)),
        status="received",
        notes=note,
        created_by=getattr(actor, "id", None),
        created_by_email=str(getattr(actor, "email", "") or ""),
        handled_by=getattr(actor, "id", None),
        handled_by_email=str(getattr(actor, "email", "") or ""),
    )
    db.add(row)
    db.flush()
    add_event(db, row, kind="created", actor=actor, to_status="received", note=note, details={"kind": kind, "law": law, "dueAt": _iso(row.due_at), "matchedAccount": found is not None}, at=now)
    return row


def update(db: Session, tenant_id: str, request_id: str, body: Any, *, actor: Any) -> tuple[Any, list[str]]:
    """Move a request on, add a note, or give it to someone. Returns (row, what changed in words)."""

    if not isinstance(body, dict):
        raise DsrError("Send status, note or handledBy.")
    row = get(db, tenant_id, request_id)
    changes: list[str] = []
    note = str(body.get("note") or "").strip()[:MAX_NOTE]
    status = body.get("status")
    if status is not None and status != row.status:
        if status not in STATUSES or status == "received":
            raise DsrError("Status is verifying, in_progress, completed or refused.")
        if row.status in FINAL_STATUSES:
            raise DsrError(f"The request is already {row.status.replace('_', ' ')}: record a new one if the person asks again.", 409)
        reason = str(body.get("refusalReason") or "").strip()[:MAX_NOTE]
        if status == "refused" and not reason:
            raise DsrError("Say why the request is refused (the person is told, and may complain to the regulator).")
        if status == "completed" and row.kind != "access" and not note:
            raise DsrError("Say what was done (a note) before completing the request.")
        before = row.status
        row.status = status
        if status == "refused":
            row.refusal_reason = reason
        if status in FINAL_STATUSES:
            row.completed_at = _now()
        add_event(db, row, kind="status", actor=actor, from_status=before, to_status=status, note=reason if status == "refused" else note)
        changes.append(f"{before} → {status}")
        note = ""
    handler = body.get("handledBy")
    if handler is not None:
        address = str(handler or "").strip().lower()
        person = actor if address == "me" else member(db, tenant_id, address)
        if person is None:
            raise DsrError("The person handling it must be a member of this workspace.")
        if row.handled_by != person.id:
            row.handled_by = person.id
            row.handled_by_email = str(person.email or "")
            add_event(db, row, kind="assigned", actor=actor, note=f"Handled by {person.email}.")
            changes.append("handler changed")
    if note:
        row.notes = (row.notes + "\n" if row.notes else "") + note
        row.notes = row.notes[-MAX_NOTE * 4:]
        add_event(db, row, kind="note", actor=actor, note=note)
        changes.append("note added")
    if not changes:
        raise DsrError("Nothing to change.")
    db.flush()
    return row, changes


# ---- Access: what Hawk AI holds about the person ----------------------------------------------------------------------


def _subject(db: Session, row: Any) -> Any:
    """The tenant member the request is about, checked again now (they may have left the tenant since)."""

    from app.db.models.user import User, UserTenantRole

    if row.subject_user_id:
        found = db.scalar(
            select(User).join(UserTenantRole, UserTenantRole.user_id == User.id).where(User.id == row.subject_user_id, UserTenantRole.tenant_id == row.tenant_id)
        )
        if found is not None:
            return found
    return member(db, row.tenant_id, row.subject_email) if row.subject_email else None


def _limited(rows: list[Any]) -> tuple[list[Any], bool]:
    return rows[:MAX_ROWS], len(rows) > MAX_ROWS


def access_export(db: Session, row: Any, *, generated_by: str, now: dt.datetime | None = None) -> dict[str, Any]:
    """What Hawk AI holds about the person in this tenant, from stored fields only: never password hashes, two-step
    secrets, tokens or raw prompts (the masked prompt only); reasons and prompts pass through the redactor again."""

    from app.db.models.activity_audit import AIAction, AIActionAlert, AISession, DeploymentEndpoint, PromptPayload, UserRegistry
    from app.db.models.audit import AuditLog
    from app.db.models.finding import Finding
    from app.db.models.platform_records import SupportTicket, UserActivity
    from app.db.models.tenant import Tenant
    from app.db.models.user import UserTenantRole
    from app.services.privacy_sanitizer import redact_sensitive_text

    if row.kind != "access":
        raise DsrError("An export answers an access request.", 409)
    if row.status == "refused":
        raise DsrError("The request was refused.", 409)
    now = now or _now()
    tenant_id = row.tenant_id
    user = _subject(db, row)
    email = row.subject_email
    truncated: dict[str, bool] = {}
    holds: dict[str, Any] = {}

    if user is not None:
        membership = db.scalar(select(UserTenantRole).where(UserTenantRole.user_id == user.id, UserTenantRole.tenant_id == tenant_id))
        holds["account"] = {
            "id": user.id,
            "email": user.email,
            "fullName": user.full_name,
            "active": bool(user.is_active),
            "createdAt": _iso(getattr(user, "created_at", None)),
            "lastSignInAt": _iso(user.last_login_at),
            "passwordChangedAt": _iso(user.password_changed_at),
            "twoStepSignIn": bool(user.mfa_enabled_at),
            "singleSignOnLinked": bool(user.sso_subject),
        }
        holds["membership"] = {
            "role": membership.role,
            "title": membership.title,
            "teamId": membership.team_id,
            "joinedAt": _iso(membership.joined_at or getattr(membership, "created_at", None)),
        } if membership is not None else None
        directory = db.scalars(select(UserRegistry).where(UserRegistry.tenant_id == tenant_id, UserRegistry.user_id == user.id)).all()
        holds["directory"] = [
            {"displayName": d.display_name, "email": d.email, "department": d.department, "role": d.role, "status": d.status, "riskScore": d.risk_score, "violations": d.violation_count, "firstSeenAt": _iso(d.first_seen_at), "lastSeenAt": _iso(d.last_seen_at)}
            for d in directory
        ]
        audit_rows, truncated["auditEntries"] = _limited(list(db.scalars(
            select(AuditLog).where(AuditLog.tenant_id == tenant_id, AuditLog.actor_user_id == user.id).order_by(AuditLog.created_at, AuditLog.seq).limit(MAX_ROWS + 1)
        ).all()))
        holds["auditEntries"] = [
            {
                "at": _iso(a.created_at),
                "seq": a.seq,
                "action": a.action,
                "target": f"{a.resource_type} {a.resource_id}".strip(),
                "outcome": str((a.payload or {}).get("outcome") or "") if isinstance(a.payload, dict) else "",
                "reason": redact_sensitive_text((a.payload or {}).get("reason") or "", max_len=500) if isinstance(a.payload, dict) else "",
            }
            for a in audit_rows
        ]
        sessions, truncated["aiSessions"] = _limited(list(db.scalars(
            select(AISession).where(AISession.tenant_id == tenant_id, AISession.user_id == user.id).order_by(AISession.start_time).limit(MAX_ROWS + 1)
        ).all()))
        holds["aiSessions"] = [
            {"id": s.session_id, "surface": s.source_surface, "aiApp": s.ai_app, "aiModel": s.ai_model, "startedAt": _iso(s.start_time), "endedAt": _iso(s.end_time), "actions": s.total_actions, "status": s.status}
            for s in sessions
        ]
        actions, truncated["aiActivity"] = _limited(list(db.execute(
            select(AIAction, PromptPayload.redacted_prompt)
            .outerjoin(PromptPayload, PromptPayload.action_id == AIAction.action_id)
            .where(AIAction.tenant_id == tenant_id, AIAction.user_id == user.id)
            .order_by(AIAction.timestamp)
            .limit(MAX_ROWS + 1)
        ).all()))
        holds["aiActivity"] = [
            {
                "id": a.action_id,
                "at": _iso(a.timestamp),
                "type": a.action_type,
                "aiApp": a.ai_app,
                "aiModel": a.ai_model,
                "dataClassification": a.data_classification,
                "policy": a.policy_triggered,
                "decision": a.enforcement_action,
                "riskScore": a.risk_score,
                "maskedPrompt": redact_sensitive_text(prompt or "", max_len=2000),
            }
            for a, prompt in actions
        ]
        alerts, truncated["alerts"] = _limited(list(db.scalars(
            select(AIActionAlert).where(AIActionAlert.tenant_id == tenant_id, AIActionAlert.user_id == user.id).order_by(AIActionAlert.created_at).limit(MAX_ROWS + 1)
        ).all()))
        holds["alerts"] = [{"at": _iso(a.created_at), "type": a.alert_type, "severity": a.severity, "decision": a.enforcement_action} for a in alerts]
        endpoints = db.scalars(select(DeploymentEndpoint).where(DeploymentEndpoint.tenant_id == tenant_id, DeploymentEndpoint.user_id == user.id)).all()
        holds["endpoints"] = [
            {"id": e.endpoint_id, "hostname": e.hostname, "deviceType": e.device_type, "os": e.os_type, "browser": e.browser_type, "ipAddress": e.ip_address, "location": e.location, "lastSeenAt": _iso(e.last_seen_at)}
            for e in endpoints
        ]
        tickets = db.scalars(select(SupportTicket).where(SupportTicket.tenant_id == tenant_id, SupportTicket.requester_id == user.id).order_by(SupportTicket.created_at)).all()
        holds["supportCases"] = [{"id": t.id, "kind": t.kind, "subject": t.subject, "status": t.status, "createdAt": _iso(t.created_at)} for t in tickets]
    else:
        holds["account"] = None

    who = [UserActivity.user_id == user.id] if user is not None else []
    if email:
        who.append(func.lower(UserActivity.user) == email)
    if who:
        activity, truncated["consoleActivity"] = _limited(list(db.scalars(
            select(UserActivity).where(UserActivity.tenant_id == tenant_id, or_(*who)).order_by(UserActivity.at).limit(MAX_ROWS + 1)
        ).all()))
    else:
        activity = []
    holds["consoleActivity"] = [{"at": _iso(a.at), "action": a.action, "target": a.target, "method": a.method, "route": a.route, "status": a.status, "ip": a.ip} for a in activity]

    match = [Finding.user_id == user.id] if user is not None else []
    if email:
        match.append(func.lower(Finding.user_email) == email)
    findings = db.scalars(select(Finding).where(Finding.tenant_id == tenant_id, or_(*match)).order_by(Finding.first_seen_at).limit(MAX_ROWS)).all() if match else []
    holds["findings"] = [
        {"id": f.finding_id, "type": f.finding_type, "severity": f.severity, "aiTool": f.ai_tool, "application": f.application, "department": f.department, "dataClassification": f.data_classification, "decision": f.decision, "status": f.status, "firstSeenAt": _iso(f.first_seen_at), "lastSeenAt": _iso(f.last_seen_at)}
        for f in findings
    ]

    tenant = db.get(Tenant, tenant_id)
    counts = {key: (len(value) if isinstance(value, list) else (0 if value is None else 1)) for key, value in holds.items()}
    return {
        "kind": "hawk-ai-data-subject-access-export",
        "version": 1,
        "generatedAt": _iso(now),
        "generatedBy": generated_by,
        "workspace": {"id": tenant_id, "name": tenant.name if tenant is not None else ""},
        "request": {"id": row.id, "kind": row.kind, "law": row.law, "receivedAt": _iso(row.received_at), "dueAt": _iso(row.due_at)},
        "subject": {"email": email, "identifier": row.subject_identifier, "accountFound": user is not None},
        "counts": counts,
        "truncated": {k: v for k, v in truncated.items() if v},
        "holds": holds,
        "notIncluded": [
            "Password hashes, two-step secrets, recovery codes and sign-in tokens: kept only to sign the person in.",
            "Raw prompts: only the masked prompt Hawk AI stores is shown; personal data in it was redacted.",
            "Other workspaces on this server: only this workspace's records are searched.",
            "Records of other people that mention this person by name in free text are not searched.",
        ],
    }


# ---- Erasure: pseudonymise the person's personal fields ---------------------------------------------------------------


def _active_owners(db: Session, tenant_id: str) -> int:
    from app.db.models.user import User, UserTenantRole

    return int(db.scalar(
        select(func.count()).select_from(UserTenantRole).join(User, User.id == UserTenantRole.user_id).where(UserTenantRole.tenant_id == tenant_id, UserTenantRole.role == "owner", User.is_active.is_(True))
    ) or 0)


def erase(db: Session, row: Any, *, actor: Any, now: dt.datetime | None = None) -> dict[str, Any]:
    """Pseudonymise the person's personal fields in this tenant's records and complete the request. Returns what was
    changed, as counts. The audit log is not changed: its entries keep pointing at the (now pseudonymised) account."""

    from app.db.models.activity_audit import AIAction, DeploymentEndpoint, PromptPayload, UserRegistry
    from app.db.models.audit import AuditLog
    from app.db.models.data_subject import DataSubjectRequest
    from app.db.models.finding import Finding
    from app.db.models.platform_records import SupportTicket, UserActivity
    from app.db.models.user import RefreshToken, UserTenantRole

    if row.kind != "erasure":
        raise DsrError("Erasure answers an erasure request.", 409)
    if row.status in FINAL_STATUSES:
        raise DsrError(f"The request is already {row.status}.", 409)
    now = now or _now()
    tenant_id = row.tenant_id
    user = _subject(db, row)
    original = row.subject_email
    if user is not None:
        if getattr(actor, "id", None) == user.id:
            raise DsrError("You cannot erase your own account: ask another administrator.", 409)
        # The lock People takes before it counts the Owners (iam_service.keep_an_owner): two erasures, or an erasure
        # and a role change, at the same moment are counted one after the other, so the last Owner always stays.
        xact_lock.hold(db, "tenant-people", tenant_id)
        membership = db.scalar(select(UserTenantRole).where(UserTenantRole.user_id == user.id, UserTenantRole.tenant_id == tenant_id))
        if membership is not None and membership.role == "owner" and user.is_active and _active_owners(db, tenant_id) <= 1:
            raise DsrError("This person is the workspace's last active Owner: make someone else an Owner first.", 409)
        elsewhere = db.scalar(select(func.count()).select_from(UserTenantRole).where(UserTenantRole.user_id == user.id, UserTenantRole.tenant_id != tenant_id)) or 0
        if elsewhere:
            raise DsrError("This account also belongs to another workspace on this server: the server's administrators erase it there first.", 409)
    if user is None and not original:
        raise DsrError("Nothing to erase: the request names no email and no account here matches.", 409)

    alias = pseudonym(user.id if user is not None else email_hash(original))
    alias_email = f"{alias}@{ERASED_DOMAIN}"
    changed: dict[str, int] = {}

    previous_email = user.email if user is not None else ""
    if user is not None:
        user.email = alias_email
        user.full_name = ERASED_NAME
        user.is_active = False
        user.hashed_password = "!erased"
        user.mfa_secret = None
        user.mfa_enabled_at = None
        user.mfa_recovery = None
        user.sso_issuer = None
        user.sso_subject = None
        user.password_history = None
        user.signed_out_at = now
        changed["account"] = 1
        changed["signInTokensRevoked"] = db.execute(
            sql_update(RefreshToken).where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None)).values(revoked_at=now)
        ).rowcount or 0
        changed["membership"] = db.execute(sql_update(UserTenantRole).where(UserTenantRole.user_id == user.id, UserTenantRole.tenant_id == tenant_id).values(title="")).rowcount or 0
        changed["directory"] = db.execute(
            sql_update(UserRegistry).where(UserRegistry.tenant_id == tenant_id, UserRegistry.user_id == user.id).values(display_name=ERASED_NAME, email=alias_email, department=None)
        ).rowcount or 0
        changed["endpoints"] = db.execute(
            sql_update(DeploymentEndpoint).where(DeploymentEndpoint.tenant_id == tenant_id, DeploymentEndpoint.user_id == user.id).values(hostname=None, ip_address=None, location=None)
        ).rowcount or 0
        action_ids = select(AIAction.action_id).where(AIAction.tenant_id == tenant_id, AIAction.user_id == user.id).scalar_subquery()
        changed["rawPromptsCleared"] = db.execute(
            sql_update(PromptPayload).where(PromptPayload.action_id.in_(action_ids), PromptPayload.raw_prompt.is_not(None)).values(raw_prompt=None)
        ).rowcount or 0
        changed["supportCases"] = db.execute(
            sql_update(SupportTicket).where(SupportTicket.tenant_id == tenant_id, SupportTicket.requester_id == user.id).values(requester_name=ERASED_NAME, requester_email=alias_email)
        ).rowcount or 0
    addresses = sorted({a for a in (original, str(previous_email or "").lower()) if a})
    activity_who = [UserActivity.user_id == user.id] if user is not None else []
    finding_who = [Finding.user_id == user.id] if user is not None else []
    if addresses:
        activity_who.append(func.lower(UserActivity.user).in_(addresses))
        finding_who.append(func.lower(Finding.user_email).in_(addresses))
    changed["consoleActivity"] = db.execute(
        sql_update(UserActivity).where(UserActivity.tenant_id == tenant_id, or_(*activity_who)).values(user=alias_email, name=ERASED_NAME, ip="").execution_options(synchronize_session=False)
    ).rowcount or 0
    changed["findings"] = db.execute(
        sql_update(Finding).where(Finding.tenant_id == tenant_id, or_(*finding_who)).values(user_email=alias_email).execution_options(synchronize_session=False)
    ).rowcount or 0
    # This tenant's other requests about the same address carry the pseudonym too; subject_hash still identifies them.
    if original:
        changed["otherRequests"] = db.execute(
            sql_update(DataSubjectRequest)
            .where(DataSubjectRequest.tenant_id == tenant_id, DataSubjectRequest.subject_hash == email_hash(original), DataSubjectRequest.id != row.id)
            .values(subject_email=alias_email)
            .execution_options(synchronize_session=False)
        ).rowcount or 0
    kept = int(db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.tenant_id == tenant_id, AuditLog.actor_user_id == user.id)) or 0) if user is not None else 0
    before = row.status
    row.subject_email = alias_email
    row.status = "completed"
    row.completed_at = now
    result = {"pseudonym": alias, "changed": {k: int(v) for k, v in changed.items()}, "auditEntriesKept": kept}
    add_event(
        db,
        row,
        kind="erased",
        actor=actor,
        from_status=before,
        to_status="completed",
        note=f"Personal fields replaced by the pseudonym {alias}; {kept} audit entries kept unchanged (the audit log is never changed or deleted).",
        details=result,
        at=now,
    )
    db.flush()
    return result


# ---- Evidence ------------------------------------------------------------------------------------------------------


def evidence_records(db: Session, tenant_id: str, *, since: dt.datetime, until: dt.datetime, now: dt.datetime | None = None) -> dict[str, Any]:
    """For a pack's evidence bundle: the tenant's requests open now or received, finished or due in the window, without
    who they are about (the request id stands for the person), and the settings."""

    from app.db.models.data_subject import DataSubjectRequest

    now = now or _now()
    try:
        rows = db.scalars(
            select(DataSubjectRequest)
            .where(
                DataSubjectRequest.tenant_id == tenant_id,
                or_(
                    DataSubjectRequest.status.in_(OPEN_STATUSES),
                    DataSubjectRequest.received_at.between(since, until),
                    DataSubjectRequest.completed_at.between(since, until),
                ),
            )
            .order_by(DataSubjectRequest.received_at)
            .limit(MAX_ROWS)
        ).all()
    except Exception:  # noqa: BLE001 - a database before 0106
        rows = []
    items = []
    for r in rows:
        trail = events(db, r)
        items.append({
            "id": r.id,
            "kind": r.kind,
            "law": r.law,
            "status": r.status,
            "receivedAt": _iso(r.received_at),
            "dueAt": _iso(r.due_at),
            "completedAt": _iso(r.completed_at),
            "overdue": is_overdue(r, now),
            "answeredInTime": (_utc(r.completed_at) <= _utc(r.due_at)) if r.completed_at and r.due_at else None,
            "refusalReason": r.refusal_reason or "",
            "handledBy": r.handled_by_email or "",
            "events": [{"at": _iso(e.at), "kind": e.kind, "from": e.from_status, "to": e.to_status, "by": e.actor_email} for e in trail],
        })
    return {"settings": {"dueDays": due_days(db, tenant_id), "grievanceContact": grievance_contact(db, tenant_id)}, "summary": summary(db, tenant_id, now), "requests": items}


__all__ = [
    "DEFAULT_DUE_DAYS",
    "DUE_SOON_DAYS",
    "DsrError",
    "FINAL_STATUSES",
    "KINDS",
    "LAWS",
    "OPEN_STATUSES",
    "STATUSES",
    "access_export",
    "add_event",
    "create",
    "erase",
    "event_view",
    "events",
    "evidence_records",
    "get",
    "list_requests",
    "pseudonym",
    "save_settings",
    "settings_view",
    "summary",
    "update",
    "view",
]
