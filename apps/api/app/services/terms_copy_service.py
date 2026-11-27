"""The emailed copy of an accepted licence agreement (TERMS.md, app/services/terms_service.py).

When an administrator accepts the agreement (or ACCEPT_TERMS does), a copy is queued for them in terms_copy_emails:
the full text of the exact version accepted, in the email and attached (the .txt is byte for byte the text whose
SHA-256 is recorded, the .html adds the acceptance details), with who accepted, for which company, when and from
where.

Hawk AI runs on the customer's own server, so the email server is often set up after the first sign-in. Nothing is
lost meanwhile: copies wait until the email server in force has been tested (mailer.verified, the same rule as every
other email Hawk AI sends), and go out

- at once, after an acceptance, when the email server is already tested;
- as soon as a test of the email server passes (Settings → Email (SMTP): Test, Send test, or Save and test);
- every five minutes from the scheduler (app/jobs/terms_jobs.py), which also retries failed sends with backoff
  (1, 5, 15 minutes, 1, 3, 6, 12 then 24 hours) and gives up after MAX_ATTEMPTS tries.

Settings → About shows where the copy is, and lets an owner or admin send it again or download it.
"""

from __future__ import annotations

import html
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.db.models.access import TermsAcceptance, TermsCopyEmail
from app.services import mailer

log = logging.getLogger("hawk.terms")

#: Seconds before each retry: the n-th failure waits BACKOFF_SECONDS[n-1] (the last one repeats).
BACKOFF_SECONDS = (60, 300, 900, 3600, 3 * 3600, 6 * 3600, 12 * 3600, 24 * 3600)
MAX_ATTEMPTS = 10


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def queue(db: Session, acceptance: TermsAcceptance, *, to: str | None = None, requested_by: str = "") -> TermsCopyEmail:
    """Queue a copy of this acceptance for ``to`` (default: the address given when accepting)."""

    row = TermsCopyEmail(
        acceptance_id=acceptance.id,
        to_email=(to or acceptance.email).strip().lower(),
        status="queued",
        attempts=0,
        next_attempt_at=None,
        requested_by=requested_by[:320],
        created_at=_now(),
    )
    db.add(row)
    db.flush()
    return row


def latest(db: Session, acceptance_id: str) -> TermsCopyEmail | None:
    return db.scalar(
        select(TermsCopyEmail)
        .where(TermsCopyEmail.acceptance_id == acceptance_id)
        .order_by(TermsCopyEmail.created_at.desc(), TermsCopyEmail.id.desc())
        .limit(1)
    )


def status(db: Session, acceptance: TermsAcceptance) -> dict[str, Any]:
    """Where the emailed copy is: sent (and when), waiting for the email server, retrying, failed, or none."""

    row = latest(db, acceptance.id)
    if row is None:
        return {"state": "none", "to": acceptance.email, "sentAt": None, "attempts": 0, "lastError": "", "nextAttemptAt": None}
    if row.status == "sent":
        state = "sent"
    elif row.status == "failed":
        state = "failed"
    elif not mailer.verified(db):
        state = "waiting"
    else:
        state = "retrying" if row.attempts else "queued"
    return {
        "state": state,
        "to": row.to_email,
        "sentAt": _aware(row.sent_at).isoformat() if row.sent_at else None,
        "attempts": row.attempts,
        "lastError": row.last_error,
        "nextAttemptAt": _aware(row.next_attempt_at).isoformat() if row.next_attempt_at else None,
    }


# ---- The message ----------------------------------------------------------------------------------------------------


def terms_html(markdown: str) -> str:
    """TERMS.md as simple HTML (headings, paragraphs, lists, bold), everything else escaped (as the console's
    termsHtml in apps/web/src/lib/access.ts)."""

    def inline(text: str) -> str:
        out = html.escape(text)
        out = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", out)
        return re.sub(r"`([^`]+)`", r"<code>\1</code>", out)

    parts: list[str] = []
    paragraph: list[str] = []
    in_list = False

    def flush() -> None:
        nonlocal paragraph
        if paragraph:
            parts.append(f'<p style="margin:0 0 8px">{inline(" ".join(paragraph))}</p>')
        paragraph = []

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            parts.append("</ul>")
            in_list = False

    for line in markdown.split("\n"):
        item = re.match(r"^\s*- (.*)$", line)
        if item:
            flush()
            if not in_list:
                parts.append('<ul style="margin:0 0 8px;padding-left:20px">')
                in_list = True
            parts.append(f"<li>{inline(item.group(1))}</li>")
            continue
        if not line.strip():
            flush()
            close_list()
            continue
        heading = re.match(r"^(#{1,3}) (.*)$", line)
        if heading:
            flush()
            close_list()
            level = len(heading.group(1)) + 1
            parts.append(f'<h{level} style="margin:16px 0 6px">{inline(heading.group(2))}</h{level}>')
            continue
        paragraph.append(line.strip())
    flush()
    close_list()
    return "".join(parts)


def _facts(acceptance: TermsAcceptance) -> list[tuple[str, str]]:
    accepted_at = _aware(acceptance.accepted_at)
    return [
        ("Company", acceptance.organisation_name or "—"),
        ("Accepted by", acceptance.full_name or acceptance.email),
        ("Email", acceptance.email),
        ("Authorised to accept for the company", "Yes" if acceptance.authorised else "Not confirmed"),
        ("Accepted at", accepted_at.strftime("%Y-%m-%d %H:%M:%S UTC") if accepted_at else "—"),
        ("From address", acceptance.ip or "—"),
        ("Browser", acceptance.user_agent or "—"),
        ("Recorded through", acceptance.via),
        ("Agreement version", acceptance.version),
        ("SHA-256 of the accepted text", acceptance.text_hash),
        ("Acceptance record", acceptance.id),
    ]


def copy_files(acceptance: TermsAcceptance, text: str) -> list[tuple[str, bytes, str]]:
    """The attachments: the exact accepted text (its SHA-256 is the recorded one) and an HTML copy with the details."""

    stem = f"hawk-ai-licence-agreement-v{acceptance.version}"
    esc = html.escape
    details = "".join(f"<tr><td style=\"padding:2px 12px 2px 0;color:#64748b\">{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in _facts(acceptance))
    page = (
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Hawk AI licence agreement</title></head>"
        "<body style=\"font-family:Arial,Helvetica,sans-serif;color:#0f172a;font-size:14px;line-height:1.5;max-width:820px;margin:24px auto;padding:0 16px\">"
        f"<h1 style=\"font-size:20px\">Acceptance record</h1><table style=\"border-collapse:collapse;font-size:13px\">{details}</table>"
        f"<hr style=\"margin:20px 0\">{terms_html(text)}</body></html>"
    )
    return [
        (f"{stem}.txt", text.encode("utf-8"), "text/plain"),
        (f"{stem}-accepted.html", page.encode("utf-8"), "text/html"),
    ]


def build_message(acceptance: TermsAcceptance, text: str):
    """The email: a short note with the acceptance details, then the full agreement, with the two attachments."""

    app_name = mailer.brand_name()
    subject = f"{app_name}: your copy of the licence agreement (version {acceptance.version})"
    lines = [
        f"This is your copy of the {app_name} licence agreement and terms of use, version {acceptance.version}, as accepted "
        f"for {acceptance.organisation_name or 'your organisation'}.",
        "Keep it for your records. The full text follows and is attached: the .txt file is exactly the text accepted "
        "(its SHA-256 is below), and the .html file adds these acceptance details.",
    ]
    message = mailer.system_email(subject=subject, lines=lines, facts=_facts(acceptance), app_name=app_name)
    # The full text after the note, in both parts.
    plain = message.get_body(("plain",))
    rich = message.get_body(("html",))
    if plain is not None:
        plain.set_content(plain.get_content() + "\n\n" + "-" * 72 + "\n\n" + text)
    if rich is not None:
        body = rich.get_content()
        rich.set_content(body.replace("</div></body></html>", f'<hr style="margin:16px 0">{terms_html(text)}</div></body></html>'), subtype="html")
    for filename, content, _kind in copy_files(acceptance, text):
        # As bytes (base64), so the .txt arrives exactly as accepted and its SHA-256 can be checked.
        message.add_attachment(content, maintype="application", subtype="octet-stream", filename=filename)
    return message


# ---- Sending --------------------------------------------------------------------------------------------------------


def _backoff(attempts: int) -> timedelta:
    return timedelta(seconds=BACKOFF_SECONDS[min(max(attempts, 1), len(BACKOFF_SECONDS)) - 1])


def deliver_due(db: Session, *, now: datetime | None = None) -> dict[str, int]:
    """Send every queued copy that is due, if the email server is tested. The caller commits."""

    from app.services import terms_service

    now = now or _now()
    rows = db.scalars(select(TermsCopyEmail).where(TermsCopyEmail.status == "queued").order_by(TermsCopyEmail.created_at)).all()
    counts = {"sent": 0, "failed": 0, "waiting": 0, "retrying": 0}
    if not rows:
        return counts
    smtp = mailer.current()
    if not mailer.verified(db, smtp):
        counts["waiting"] = len(rows)
        return counts
    for row in rows:
        due = _aware(row.next_attempt_at)
        if due is not None and due > now:
            counts["retrying"] += 1
            continue
        acceptance = db.get(TermsAcceptance, row.acceptance_id)
        text = terms_service.accepted_text(db, acceptance) if acceptance is not None else None
        if acceptance is None or text is None:
            row.status = "failed"
            row.last_error = "The accepted text is no longer available."
            counts["failed"] += 1
            continue
        # Claim the copy first: the scheduler and the request that queued it (or two workers) can run this at once,
        # and only the one whose conditional update lands sends it. The row stays locked until that one commits; the
        # other then finds it no longer queued as it was, and leaves it.
        claimed = db.execute(
            update(TermsCopyEmail)
            .where(TermsCopyEmail.id == row.id, TermsCopyEmail.status == "queued", TermsCopyEmail.attempts == row.attempts)
            .values(attempts=row.attempts)
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount != 1:
            db.expire(row)
            continue
        try:
            mailer.send(build_message(acceptance, text), row.to_email, smtp=smtp)
        except Exception as error:  # noqa: BLE001 - kept, retried later, never with the password in it
            row.attempts += 1
            row.last_error = mailer.redact_secrets(str(error), smtp)[:500]
            if row.attempts >= MAX_ATTEMPTS:
                row.status = "failed"
                row.next_attempt_at = None
                counts["failed"] += 1
            else:
                row.next_attempt_at = now + _backoff(row.attempts)
                counts["retrying"] += 1
            log.warning("[terms] The copy of the licence agreement for %s was not sent (try %s): %s", row.to_email, row.attempts, row.last_error)
            continue
        row.attempts += 1
        row.status = "sent"
        row.sent_at = now
        row.next_attempt_at = None
        row.last_error = ""
        counts["sent"] += 1
        log.info("[terms] The copy of the licence agreement v%s was emailed to %s.", acceptance.version, row.to_email)
    db.flush()
    return counts


def deliver_with(bind: Engine | Any) -> dict[str, int]:
    """Send what is due in a session of its own (after a response, or from the scheduler). Never raises."""

    try:
        with Session(bind=bind) as db:
            counts = deliver_due(db)
            db.commit()
            return counts
    except Exception:  # noqa: BLE001 - the scheduler tries again
        log.exception("[terms] Sending the queued copies of the licence agreement failed.")
        return {"sent": 0, "failed": 0, "waiting": 0, "retrying": 0}
