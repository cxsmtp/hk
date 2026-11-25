"""Sending email: the minimal SMTP sender backups need (the copy to the backup mailbox, and the "Hawk AI stopped" email
to the administrators). Ported from CxMissionZero's src/mailer.js, with its environment names:

  SMTP_HOST, SMTP_PORT (587), SMTP_SECURE (implicit TLS, for 465), SMTP_USER, SMTP_PASS (or SMTP_PASSWORD, or
  SMTP_PASS_FILE), SMTP_FROM (or SMTP_FROM_ADDRESS; else SMTP_USER), SMTP_FROM_NAME, SMTP_REQUIRE_AUTH (on when a user
  is given), SMTP_REJECT_UNAUTHORIZED (false turns the certificate check off, said in the log).

As in CxMissionZero a login is never sent in clear: without TLS from the start, STARTTLS must be offered and taken.
Certificates are checked unless SMTP_REJECT_UNAUTHORIZED=false. The password is taken out of every error message,
whatever the server echoed back.

Self-contained on purpose: if Hawk AI gains a mail service of its own (for sign-in emails), this module is the one to
merge into it; nothing else here depends on more than send_mail() and smtp_from_env().
"""

from __future__ import annotations

import base64
import logging
import os
import re
import smtplib
import ssl
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

log = logging.getLogger("hawk.mail")

CONNECT_TIMEOUT = 15
SOCKET_TIMEOUT = 20
_warned: set[str] = set()


class MailError(Exception):
    pass


def _truthy(value: str | None, default: bool) -> bool:
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _clean(value: str) -> str:
    return re.sub(r"[\r\n]+", "", str(value or "")).strip().strip("\"'").strip()


@dataclass(frozen=True)
class SmtpSettings:
    host: str
    port: int = 587
    secure: bool = False
    user: str = ""
    password: str = ""
    from_address: str = ""
    from_name: str = ""
    require_auth: bool = False
    reject_unauthorized: bool = True

    @property
    def sender(self) -> str:
        address = re.sub(r"[\r\n\"<>]", "", self.from_address or self.user).strip()
        if not address:
            return ""
        name = re.sub(r"[\r\n\"<>]", "", self.from_name).strip()
        return formataddr((name, address)) if name else address


def smtp_from_env(env: Mapping[str, str] | None = None) -> SmtpSettings | None:
    """The mail server the deployment names, or None when SMTP_HOST is not set."""

    env = os.environ if env is None else env
    host = _clean(env.get("SMTP_HOST", ""))
    if not host:
        return None
    password = str(env.get("SMTP_PASS") or env.get("SMTP_PASSWORD") or "")
    if not password and env.get("SMTP_PASS_FILE"):
        try:
            with open(str(env["SMTP_PASS_FILE"]), encoding="utf-8") as handle:
                password = handle.read().strip()
        except OSError:
            password = ""
    user = _clean(env.get("SMTP_USER", ""))
    try:
        port = int(_clean(env.get("SMTP_PORT", "")) or 0)
    except ValueError:
        port = 0
    secure = _truthy(env.get("SMTP_SECURE"), False)
    return SmtpSettings(
        host=host,
        port=port or (465 if secure else 587),
        secure=secure,
        user=user,
        password=password,
        from_address=_clean(env.get("SMTP_FROM") or env.get("SMTP_FROM_ADDRESS") or "") or (user if "@" in user else ""),
        from_name=_clean(env.get("SMTP_FROM_NAME", "")),
        require_auth=_truthy(env.get("SMTP_REQUIRE_AUTH"), bool(user)),
        reject_unauthorized=_truthy(env.get("SMTP_REJECT_UNAUTHORIZED"), True),
    )


def _secret_forms(smtp: SmtpSettings) -> list[str]:
    """The forms the password takes on the wire: as given, and base64 as AUTH LOGIN and AUTH PLAIN carry it."""

    forms: set[str] = set()
    if smtp.password:
        forms.add(smtp.password)
        forms.add(base64.b64encode(smtp.password.encode()).decode())
        forms.add(base64.b64encode(f"\0{smtp.user}\0{smtp.password}".encode()).decode())
    return sorted((f for f in forms if len(f) >= 3), key=len, reverse=True)


def redact_secrets(text: str, smtp: SmtpSettings) -> str:
    for form in _secret_forms(smtp):
        text = text.replace(form, "[hidden]")
    return text


def _tls_context(smtp: SmtpSettings, kind: str) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not smtp.reject_unauthorized:
        key = f"{kind}|{smtp.host}:{smtp.port}"
        if key not in _warned:
            _warned.add(key)
            log.warning("! [mail] Certificate checks are off for the %s %s:%s (SMTP_REJECT_UNAUTHORIZED=false). Its identity is not verified.", kind, smtp.host, smtp.port)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _friendly(error: BaseException, smtp: SmtpSettings) -> str:
    if isinstance(error, smtplib.SMTPAuthenticationError):
        return "The server rejected that username and password."
    if isinstance(error, ConnectionRefusedError):
        return f"Nothing is listening on port {smtp.port} of the mail server."
    if isinstance(error, (TimeoutError, OSError)) and "timed out" in str(error).lower():
        return "Could not reach the server — check the host, port and any firewall."
    if isinstance(error, ssl.SSLCertVerificationError):
        return "The server presented a certificate that could not be verified."
    return str(error) or error.__class__.__name__


def _connect(smtp: SmtpSettings) -> smtplib.SMTP:
    if smtp.secure:
        client: smtplib.SMTP = smtplib.SMTP_SSL(smtp.host, smtp.port, timeout=CONNECT_TIMEOUT, context=_tls_context(smtp, "mail server"))
    else:
        client = smtplib.SMTP(smtp.host, smtp.port, timeout=CONNECT_TIMEOUT)
        client.ehlo()
        if client.has_extn("starttls"):
            client.starttls(context=_tls_context(smtp, "mail server"))
            client.ehlo()
        elif smtp.require_auth and smtp.user:
            client.close()
            raise MailError("The mail server offers no STARTTLS, and a password is never sent without encryption. Use port 465 with SMTP_SECURE=true, or turn STARTTLS on at the mail server.")
    if client.sock is not None:
        client.sock.settimeout(SOCKET_TIMEOUT)
    if smtp.require_auth and smtp.user:
        client.login(smtp.user, smtp.password)
    return client


def send_mail(
    to: Iterable[str],
    *,
    subject: str,
    text: str,
    attachments: Iterable[tuple[str, bytes, str]] = (),
    smtp: SmtpSettings | None = None,
) -> dict[str, list[str]]:
    """Send one message. Returns {accepted, rejected}; raises MailError (never with the password in it)."""

    smtp = smtp or smtp_from_env()
    if smtp is None:
        raise MailError("No mail server is set (SMTP_HOST).")
    recipients = [r for r in (str(x).strip() for x in to) if r]
    if not recipients:
        raise MailError("No recipients.")
    if not smtp.sender:
        raise MailError("No From address is set (SMTP_FROM, or SMTP_USER as an address).")
    message = EmailMessage()
    message["From"] = smtp.sender
    message["To"] = ", ".join(recipients)
    message["Subject"] = re.sub(r"[\r\n]+", " ", subject)
    message["Message-ID"] = make_msgid(domain=(smtp.sender.rsplit("@", 1)[-1].strip(">") or None))
    message.set_content(text)
    for filename, content, content_type in attachments:
        maintype, _, subtype = (content_type or "application/octet-stream").partition("/")
        message.add_attachment(content, maintype=maintype, subtype=subtype or "octet-stream", filename=filename)
    try:
        client = _connect(smtp)
        try:
            refused = client.send_message(message, from_addr=smtp.from_address or smtp.user, to_addrs=recipients)
        finally:
            try:
                client.quit()
            except Exception:  # noqa: BLE001
                client.close()
    except MailError:
        raise
    except Exception as error:  # noqa: BLE001 - one message, without the password
        raise MailError(redact_secrets(f"Sending failed: {_friendly(error, smtp)}", smtp)) from None
    rejected = sorted(refused)
    return {"accepted": [r for r in recipients if r not in refused], "rejected": rejected}


__all__ = ["MailError", "SmtpSettings", "redact_secrets", "send_mail", "smtp_from_env"]
