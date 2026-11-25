"""Sending an email, ported (minimally) from CxMissionZero's src/mailer.js and the system emails of src/hands-off.js.
Hawk had no way to send email before; password reset links (docs/sign-in.md) need one.

The email server comes from the environment, under CxMissionZero's names: SMTP_HOST, SMTP_PORT (587), SMTP_SECURE
(implicit TLS, for port 465), SMTP_USER, SMTP_PASS, SMTP_FROM (defaults to SMTP_USER) and SMTP_FROM_NAME.

- With SMTP_SECURE off, a login is never sent in clear: STARTTLS must be offered and taken (nodemailer's requireTLS).
- The mail server's certificate is always checked.
- Nothing is sent until an administrator has sent a test email with exactly these settings (Settings → Sign-in): the
  fingerprint of the settings is kept (CxMissionZero's isVerified), so changing any of them asks for a new test.
- The password is never part of an error message, a log line or the audit log.
"""

from __future__ import annotations

import hashlib
import html
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

from app.core.config import settings


TIMEOUT_SECONDS = 20


class MailError(Exception):
    """Mail could not be sent; the message names no secret."""


@dataclass(frozen=True)
class Smtp:
    host: str
    port: int
    secure: bool
    user: str
    password: str
    from_address: str
    from_name: str


def current() -> Smtp:
    user = str(settings.smtp_user or "").strip()
    return Smtp(
        host=str(settings.smtp_host or "").strip(),
        port=int(settings.smtp_port or 587),
        secure=bool(settings.smtp_secure),
        user=user,
        password=str(settings.smtp_pass or ""),
        from_address=str(settings.smtp_from or "").strip() or (user if "@" in user else ""),
        from_name=str(settings.smtp_from_name or "").strip(),
    )


def configured(smtp: Smtp | None = None) -> bool:
    smtp = smtp or current()
    return bool(smtp.host and smtp.from_address)


def fingerprint(smtp: Smtp | None = None) -> str:
    """What a successful test is bound to: every setting, the password included (only as part of this hash)."""

    smtp = smtp or current()
    raw = "\n".join([smtp.host, str(smtp.port), str(smtp.secure), smtp.user, smtp.password, smtp.from_address])
    return hashlib.sha256(f"hawk-smtp\n{raw}".encode("utf-8")).hexdigest()


def from_header(smtp: Smtp) -> str:
    """``"Name" <address>``: no line breaks, quotes or angle brackets, so nothing can end the header."""

    clean = lambda value: "".join(ch for ch in str(value) if ch not in '\r\n"<>').strip()  # noqa: E731
    address = clean(smtp.from_address)
    return formataddr((clean(smtp.from_name), address)) if smtp.from_name else address


def _redact(text: str, smtp: Smtp) -> str:
    out = str(text)
    if smtp.password and len(smtp.password) >= 3:
        out = out.replace(smtp.password, "[hidden]")
    return out


def system_email(*, subject: str, lines: list[str], facts: list[tuple[str, str]] = (), buttons: list[tuple[str, str]] = (), footer: str = "", app_name: str = "Hawk AI") -> EmailMessage:
    """CxMissionZero's systemEmail: plain text and the same simple HTML."""

    text = "\n".join(
        [
            *lines,
            *([""] + [f"{k}: {v}" for k, v in facts] if facts else []),
            *([""] + [f"{label}: {url}" for label, url in buttons] if buttons else []),
            *(["", footer] if footer else []),
        ]
    )
    esc = html.escape
    body = (
        "<!doctype html><html><body style=\"font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;"
        'color:#0f172a;font-size:14px;line-height:1.5"><div style="max-width:640px;margin:0 auto;padding:16px">'
        f'<p style="margin:0 0 4px;color:#64748b;font-size:12px">{esc(app_name)}</p>'
        f'<h1 style="font-size:18px;margin:0 0 12px">{esc(subject)}</h1>'
        + "".join(f'<p style="margin:0 0 8px">{esc(line)}</p>' for line in lines)
        + (
            '<table role="presentation" style="border-collapse:collapse;margin:8px 0 12px;font-size:13px">'
            + "".join(f'<tr><td style="padding:2px 12px 2px 0;color:#64748b">{esc(k)}</td><td style="padding:2px 0">{esc(v)}</td></tr>' for k, v in facts)
            + "</table>"
            if facts
            else ""
        )
        + (
            '<p style="margin:12px 0">'
            + "".join(
                f'<a href="{esc(url)}" style="display:inline-block;margin:0 8px 8px 0;padding:8px 14px;border-radius:6px;background:#14171c;color:#fff;text-decoration:none;font-weight:600">{esc(label)}</a>'
                for label, url in buttons
                if url.startswith(("https://", "http://"))
            )
            + "</p>"
            if buttons
            else ""
        )
        + (f'<p style="margin:8px 0;color:#475467;font-size:13px;white-space:pre-wrap">{esc(footer)}</p>' if footer else "")
        + "</div></body></html>"
    )
    message = EmailMessage()
    message["Subject"] = subject
    message.set_content(text)
    message.add_alternative(body, subtype="html")
    return message


def send(message: EmailMessage, to: str, *, smtp: Smtp | None = None) -> None:
    """Send one message to one address. Raises MailError."""

    smtp = smtp or current()
    if not smtp.host:
        raise MailError("No email server is set (SMTP_HOST).")
    if not smtp.from_address:
        raise MailError("No From address is set (SMTP_FROM).")
    message["From"] = from_header(smtp)
    message["To"] = to
    message["Message-ID"] = make_msgid(domain=smtp.from_address.rpartition("@")[2] or None)
    context = ssl.create_default_context()
    try:
        if smtp.secure:
            client: smtplib.SMTP = smtplib.SMTP_SSL(smtp.host, smtp.port, timeout=TIMEOUT_SECONDS, context=context)
        else:
            client = smtplib.SMTP(smtp.host, smtp.port, timeout=TIMEOUT_SECONDS)
        with client:
            client.ehlo()
            if not smtp.secure:
                if client.has_extn("starttls"):
                    client.starttls(context=context)
                    client.ehlo()
                elif smtp.user:
                    # A login is never sent in clear.
                    raise MailError("The mail server does not offer STARTTLS, so the login is not sent. Use SMTP_SECURE=true with port 465, or a server that offers STARTTLS.")
            if smtp.user:
                client.login(smtp.user, smtp.password)
            client.send_message(message)
    except MailError:
        raise
    except smtplib.SMTPAuthenticationError as exc:
        raise MailError("The server rejected that username and password.") from exc
    except (OSError, smtplib.SMTPException) as exc:
        raise MailError(_redact(f"Sending failed: {exc}", smtp)) from exc
