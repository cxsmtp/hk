"""Hawk AI's one way of sending email: password reset links, welcome and sign-in emails, support cases, hands-off and
the self-check (app/api/routers/sign_in.py, iam.py, support.py, app/services/self_check.py), and the backups (the copy
to the backup mailbox and the "Hawk AI stopped" email, app/services/backup_service.py). Ported from CxMissionZero's
src/mailer.js and FTR Command Center's server/mailer.js; it replaces the two senders Hawk AI had before (this module's
first version, for sign-in, and app/services/backup_mailer.py, for backups).

Where the email server comes from:

- Settings → Email (SMTP), saved on the server in ``email.json`` in the data folder (HAWK_DATA_DIR, in every backup),
  the password encrypted (Fernet, with the connector secrets key) and never sent back to a browser (FTR's
  settings.value.smtp, sealed with secrets.seal);
- otherwise the environment, under CxMissionZero's names: SMTP_HOST, SMTP_PORT (587), SMTP_SECURE (implicit TLS, for
  465), SMTP_USER, SMTP_PASS (or SMTP_PASSWORD, or SMTP_PASS_FILE), SMTP_FROM (or SMTP_FROM_ADDRESS; else SMTP_USER),
  SMTP_FROM_NAME, SMTP_REQUIRE_AUTH (on when a user is given), SMTP_REJECT_UNAUTHORIZED (false turns the certificate
  check off, said in the log).

As in CxMissionZero and FTR:

- A login is never sent in clear: without TLS from the start, STARTTLS must be offered and taken.
- The mail server's certificate is checked (the public roots and the certificates trusted under Settings → Network &
  proxy) unless the certificate check is turned off.
- Nothing is sent for sign-in, people, support or hands-off until the settings in force were tested (a connection test,
  or a test email): the fingerprint of the settings is kept (MZ's isVerified, FTR's smtpVerified), so changing any of
  them asks for a new test. Backups keep their own rule: they are emailed whenever a mail server is set.
- The password is never part of an error message, a log line or the audit log, in any of the forms it takes on the wire.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import html
import logging
import os
import re
import smtplib
import ssl
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, replace
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.services.pci_controls import scrub_pan

log = logging.getLogger("hawk.mail")

TIMEOUT_SECONDS = 20
CONNECT_TIMEOUT = 15
SOCKET_TIMEOUT = 20
FILE_NAME = "email.json"
EMAIL = re.compile(r"^(?=.{3,254}$)[^\s@<>\"]+@[^\s@<>\"]+\.[^\s@<>\"]+$")
#: The ports mail servers listen on (1025: a local test server), as FTR's SMTP_PORTS.
SMTP_PORTS = (25, 465, 587, 2525, 1025)
STARTTLS_PORTS = (25, 587, 2525)
_warned: set[str] = set()


class MailError(Exception):
    """Mail could not be sent; the message names no secret."""

    def __init__(self, message: str = "", status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class Smtp:
    host: str
    port: int = 587
    secure: bool = False
    user: str = ""
    password: str = ""
    from_address: str = ""
    from_name: str = ""
    require_auth: bool = True
    reject_unauthorized: bool = True

    @property
    def sender(self) -> str:
        """``"Name" <address>`` (the From address, else the user name): no line breaks, quotes or angle brackets."""

        address = re.sub(r"[\r\n\"<>]", "", self.from_address or self.user).strip()
        if not address:
            return ""
        name = re.sub(r"[\r\n\"<>]", "", self.from_name).strip()
        return formataddr((name, address)) if name else address

    @property
    def signs_in(self) -> bool:
        return bool(self.require_auth and self.user)


#: The backups' name for the same settings (app/services/backup_service.py).
SmtpSettings = Smtp


# ---- The environment ----------------------------------------------------------------------------------------------


def _truthy(value: Any, default: bool) -> bool:
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _clean(value: Any) -> str:
    return re.sub(r"[\r\n]+", "", str(value or "")).strip().strip("\"'").strip()


def smtp_from_env(env: Mapping[str, str] | None = None) -> Smtp | None:
    """The mail server the deployment names (SMTP_*), or None when SMTP_HOST is not set. Without ``env``, the API's
    own settings (app/core/config.py) and the process environment."""

    if env is None:
        env = {
            **os.environ,
            "SMTP_HOST": str(settings.smtp_host or ""),
            "SMTP_PORT": str(settings.smtp_port or ""),
            "SMTP_SECURE": "true" if settings.smtp_secure else "false",
            "SMTP_USER": str(settings.smtp_user or ""),
            "SMTP_PASS": str(settings.smtp_pass or ""),
            "SMTP_FROM": str(settings.smtp_from or ""),
            "SMTP_FROM_NAME": str(settings.smtp_from_name or ""),
        }
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
    return Smtp(
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


# ---- Settings → Email (SMTP): kept on the server ------------------------------------------------------------------


def data_dir() -> Path:
    return Path(str(settings.hawk_data_dir or ".runtime/data"))


def _seal(text: str) -> str:
    if not text:
        return ""
    from app.services.connector_secret_service import _fernet

    return _fernet().encrypt(text.encode("utf-8")).decode("utf-8")


def _open(sealed: str) -> str:
    if not sealed:
        return ""
    from cryptography.fernet import InvalidToken

    from app.services.connector_secret_service import _fernet

    try:
        return _fernet().decrypt(str(sealed).encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        # A key that changed: the password is asked for again, never guessed.
        return ""


def read_saved(directory: Path | None = None) -> dict[str, Any]:
    """What Settings → Email (SMTP) saved: {smtp, good, verifiedAt}; {} when nothing was. A file that cannot be read
    is said in the log and not used (the environment's settings apply)."""

    from app.services.state_file import read_state

    try:
        saved = read_state((directory or data_dir()) / FILE_NAME, fallback={}, holds="the email server's settings")
    except Exception as error:  # noqa: BLE001 - never stops email that the environment can still send
        log.warning("! [mail] The saved email settings cannot be read, so the SMTP_* settings apply. %s", str(error).splitlines()[0])
        return {}
    return saved if isinstance(saved, dict) else {}


def _write_saved(value: dict[str, Any], directory: Path | None = None) -> None:
    from app.services.state_file import write_state

    folder = directory or data_dir()
    folder.mkdir(parents=True, exist_ok=True)
    # No .bak: it would keep a password changed or taken out on purpose on the disk.
    write_state(folder / FILE_NAME, value, keep_last=False)


def _to_saved(smtp: Smtp) -> dict[str, Any]:
    return {
        "host": smtp.host,
        "port": smtp.port,
        "secure": smtp.secure,
        "requireAuth": smtp.require_auth,
        "rejectUnauthorized": smtp.reject_unauthorized,
        "user": smtp.user,
        "password": _seal(smtp.password),
        "fromName": smtp.from_name,
        "fromAddress": smtp.from_address,
    }


def _from_saved(raw: Any) -> Smtp | None:
    if not isinstance(raw, dict) or not str(raw.get("host") or "").strip():
        return None
    try:
        port = int(raw.get("port") or 587)
    except (TypeError, ValueError):
        port = 587
    return Smtp(
        host=str(raw.get("host") or "").strip(),
        port=port,
        secure=raw.get("secure") is True,
        user=str(raw.get("user") or ""),
        password=_open(str(raw.get("password") or "")),
        from_address=str(raw.get("fromAddress") or ""),
        from_name=str(raw.get("fromName") or ""),
        require_auth=raw.get("requireAuth") is not False,
        reject_unauthorized=raw.get("rejectUnauthorized") is not False,
    )


def saved_smtp(directory: Path | None = None) -> Smtp | None:
    return _from_saved(read_saved(directory).get("smtp"))


def source(directory: Path | None = None) -> str:
    """Where the settings in force come from: "settings" (saved here), "environment" (SMTP_*) or ""."""

    if saved_smtp(directory) is not None:
        return "settings"
    return "environment" if smtp_from_env() is not None else ""


def smtp_settings(env: Mapping[str, str] | None = None, directory: Path | None = None) -> Smtp | None:
    """The settings in force: the ones saved under Settings → Email (SMTP), else the environment's; None for none."""

    return saved_smtp(directory) or smtp_from_env(env)


def current() -> Smtp:
    """The settings in force (an empty host when there are none)."""

    return smtp_settings() or Smtp(host="", port=int(settings.smtp_port or 587), from_name=str(settings.smtp_from_name or ""))


def configured(smtp: Smtp | None = None) -> bool:
    smtp = smtp or current()
    return bool(smtp.host and (smtp.from_address or "@" in smtp.user))


def fingerprint(smtp: Smtp | None = None) -> str:
    """What a successful test is bound to: every setting, the password included (only as part of this hash)."""

    smtp = smtp or current()
    raw = "\n".join([smtp.host, str(smtp.port), str(smtp.secure), smtp.user, smtp.password, smtp.from_address])
    if not smtp.reject_unauthorized or not smtp.require_auth:
        raw += f"\n{smtp.require_auth}\n{smtp.reject_unauthorized}"
    return hashlib.sha256(f"hawk-smtp\n{raw}".encode("utf-8")).hexdigest()


def plain(value: Any, limit: int = 254) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", "", str(value or "")).strip()[:limit]


def merge_smtp(current_smtp: Smtp | None, incoming: Mapping[str, Any]) -> Smtp:
    """The settings as changed by what an administrator sent (FTR's mergeSmtp): a password left empty keeps the one
    kept (null clears it; a new host clears it too). Raises MailError with the sentence to show."""

    smtp = current_smtp or Smtp(host="", from_name=str(settings.smtp_from_name or "Hawk AI"))
    changes: dict[str, Any] = {}
    if "host" in incoming:
        changes["host"] = plain(incoming.get("host")).lower()
    if "port" in incoming:
        try:
            port = min(65535, max(1, int(incoming.get("port"))))
        except (TypeError, ValueError):
            port = smtp.port
        # Mail ports only: the connection test must not become a way to knock on other services inside the network.
        if port not in SMTP_PORTS and port != smtp.port:
            raise MailError(f"Port {port} is not a mail port: use 587 (STARTTLS), 465 (implicit TLS), 25 or 2525.")
        changes["port"] = port
    if "secure" in incoming:
        changes["secure"] = incoming.get("secure") is True
    if "requireAuth" in incoming:
        changes["require_auth"] = incoming.get("requireAuth") is True
    if "rejectUnauthorized" in incoming:
        changes["reject_unauthorized"] = incoming.get("rejectUnauthorized") is not False
    if "user" in incoming:
        changes["user"] = plain(incoming.get("user"))
    if "fromName" in incoming:
        changes["from_name"] = re.sub(r"[\"<>]", "", plain(incoming.get("fromName"), 120))
    if "fromAddress" in incoming:
        changes["from_address"] = plain(incoming.get("fromAddress"))
    out = replace(smtp, **changes)
    host_changed = bool(smtp.host) and out.host != smtp.host
    password = incoming.get("password")
    if isinstance(password, str) and password != "":
        out = replace(out, password=password[:512])
    elif password is None and "password" in incoming or host_changed:
        out = replace(out, password="")
    if out.host and not re.fullmatch(r"[a-z0-9.-]+", out.host):
        raise MailError("The mail server is a host name, like smtp.office365.com.")
    if out.secure and out.port in (587, 25):
        raise MailError(f"Port {out.port} uses STARTTLS: untick Implicit TLS (it is for port 465).")
    if out.from_address and not EMAIL.match(out.from_address):
        raise MailError('The "from" address is not an email address.')
    return out


def public_smtp(smtp: Smtp) -> dict[str, Any]:
    """What a browser may see: never the password."""

    return {
        "host": smtp.host,
        "port": smtp.port,
        "secure": smtp.secure,
        "requireAuth": smtp.require_auth,
        "rejectUnauthorized": smtp.reject_unauthorized,
        "user": smtp.user,
        "fromName": smtp.from_name,
        "fromAddress": smtp.from_address,
        "passwordSet": bool(smtp.password),
    }


def save_smtp(smtp: Smtp, directory: Path | None = None) -> None:
    """Saved as the settings in force; the last good ones and when they were tested are kept."""

    saved = read_saved(directory)
    _write_saved({**saved, "smtp": _to_saved(smtp)}, directory)


def mark_good(smtp: Smtp, directory: Path | None = None) -> str:
    """These settings worked (a connection test or a test email): they are the last good ones. Returns when."""

    at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    saved = read_saved(directory)
    value = {**saved, "verifiedAt": at}
    if saved_smtp(directory) is not None:
        value["good"] = _to_saved(smtp)
    _write_saved(value, directory)
    return at


def last_good(directory: Path | None = None) -> Smtp | None:
    return _from_saved(read_saved(directory).get("good"))


def put_back_good(directory: Path | None = None) -> Smtp | None:
    """The last settings that worked, back in force; None when there are none (or they are the ones in force)."""

    saved = read_saved(directory)
    good = saved.get("good")
    if not isinstance(good, dict) or good == saved.get("smtp"):
        return None
    _write_saved({**saved, "smtp": good}, directory)
    return _from_saved(good)


def forget_saved(directory: Path | None = None) -> None:
    """Back to the environment's settings (SMTP_*): the saved ones and the password are removed from the disk."""

    file = (directory or data_dir()) / FILE_NAME
    for name in (file, Path(f"{file}.bak")):
        try:
            name.unlink()
        except FileNotFoundError:
            pass


def verified(db: Any, smtp: Smtp | None = None) -> bool:
    """May email be sent with the settings in force: set up, and tested with exactly these settings?"""

    from app.services import account_security

    smtp = smtp or current()
    return configured(smtp) and account_security.policy(db).smtp_verified == fingerprint(smtp)


def mark_verified(db: Any, smtp: Smtp | None = None) -> str:
    """A test passed for these settings: email may be sent with them (the caller commits)."""

    from app.services import account_security

    smtp = smtp or current()
    account_security.policy(db).smtp_verified = fingerprint(smtp)
    return mark_good(smtp)


# ---- What is sent -------------------------------------------------------------------------------------------------


def from_header(smtp: Smtp) -> str:
    """``"Name" <address>``: no line breaks, quotes or angle brackets, so nothing can end the header."""

    clean = lambda value: "".join(ch for ch in str(value) if ch not in '\r\n"<>').strip()  # noqa: E731
    address = clean(smtp.from_address or (smtp.user if "@" in smtp.user else ""))
    return formataddr((clean(smtp.from_name), address)) if smtp.from_name else address


def _secret_forms(smtp: Smtp) -> list[str]:
    """The forms the password takes on the wire: as given, and base64 as AUTH LOGIN and AUTH PLAIN carry it."""

    forms: set[str] = set()
    if smtp.password:
        forms.add(smtp.password)
        forms.add(base64.b64encode(smtp.password.encode()).decode())
        forms.add(base64.b64encode(f"\0{smtp.user}\0{smtp.password}".encode()).decode())
    return sorted((f for f in forms if len(f) >= 3), key=len, reverse=True)


def redact_secrets(text: str, smtp: Smtp) -> str:
    for form in _secret_forms(smtp):
        text = str(text).replace(form, "[hidden]")
    return str(text)


_redact = redact_secrets


def brand_name() -> str:
    """The name emails carry: the product name set under Settings → Branding."""

    try:
        from app.services import branding

        return branding.app_name()
    except Exception:  # noqa: BLE001 - an email never fails for its heading
        return "Hawk AI"


def system_email(*, subject: str, lines: list[str], facts: list[tuple[str, str]] = (), buttons: list[tuple[str, str]] = (), footer: str = "", app_name: str | None = None) -> EmailMessage:
    """CxMissionZero's systemEmail: plain text and the same simple HTML, headed with the product name."""

    app_name = app_name if app_name is not None else brand_name()
    # Never a full card number in an email (PCI DSS 3.4): an error's text or a reference can quote one.
    subject = scrub_pan(subject, boundary="email")
    lines = [scrub_pan(line, boundary="email") for line in lines]
    facts = [(k, scrub_pan(v, boundary="email")) for k, v in facts]
    footer = scrub_pan(footer, boundary="email")
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


# ---- Talking to the mail server -----------------------------------------------------------------------------------


def _tls_context(smtp: Smtp) -> ssl.SSLContext:
    if smtp.reject_unauthorized:
        # The public roots and the certificates an administrator trusts (Settings → Network & proxy).
        from app.services.trust_store import outbound_ssl_context

        return outbound_ssl_context()
    key = f"{smtp.host}:{smtp.port}"
    if key not in _warned:
        _warned.add(key)
        log.warning("! [mail] Certificate checks are off for the mail server %s:%s. Its identity is not verified.", smtp.host, smtp.port)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _friendly(error: BaseException, smtp: Smtp) -> str:
    if isinstance(error, smtplib.SMTPAuthenticationError):
        return "The server rejected that username and password."
    if isinstance(error, ConnectionRefusedError):
        return f"Nothing is listening on port {smtp.port} of the mail server."
    if isinstance(error, (TimeoutError, OSError)) and "timed out" in str(error).lower():
        return "Could not reach the server — check the host, port and any firewall."
    if isinstance(error, ssl.SSLCertVerificationError):
        return "The server presented a certificate that could not be verified."
    return str(error) or error.__class__.__name__


def _connect(smtp: Smtp) -> smtplib.SMTP:
    if smtp.secure:
        client: smtplib.SMTP = smtplib.SMTP_SSL(smtp.host, smtp.port, timeout=CONNECT_TIMEOUT, context=_tls_context(smtp))
        client.ehlo()
    else:
        client = smtplib.SMTP(smtp.host, smtp.port, timeout=CONNECT_TIMEOUT)
        client.ehlo()
        if client.has_extn("starttls"):
            client.starttls(context=_tls_context(smtp))
            client.ehlo()
        elif smtp.signs_in:
            client.close()
            # A login is never sent in clear.
            raise MailError("The mail server does not offer STARTTLS, so the login is not sent. Use implicit TLS with port 465, or a server that offers STARTTLS.")
    if client.sock is not None:
        client.sock.settimeout(SOCKET_TIMEOUT)
    if smtp.signs_in:
        client.login(smtp.user, smtp.password)
    return client


def _close(client: smtplib.SMTP) -> None:
    try:
        client.quit()
    except Exception:  # noqa: BLE001
        client.close()


def test_connection(smtp: Smtp | None = None) -> None:
    """Connect and sign in, but send nothing (CxMissionZero's testConnection, FTR's verify). Raises MailError, with
    what went wrong underneath as its cause (so the self-check can tell an outage from a refusal)."""

    smtp = smtp or current()
    if not smtp.host:
        raise MailError("No email server is set up (Settings → Email (SMTP), or SMTP_HOST).")
    try:
        client = _connect(smtp)
        try:
            client.noop()
        finally:
            _close(client)
    except MailError:
        raise
    except smtplib.SMTPAuthenticationError as exc:
        raise MailError("The server rejected that username and password.") from exc
    except (OSError, smtplib.SMTPException) as exc:
        raise MailError(redact_secrets(f"The mail server could not be reached: {_friendly(exc, smtp)}", smtp)) from exc


def send(message: EmailMessage, to: str, *, smtp: Smtp | None = None) -> None:
    """Send one message to one address. Raises MailError."""

    smtp = smtp or current()
    if not smtp.host:
        raise MailError("No email server is set up (Settings → Email (SMTP), or SMTP_HOST).")
    sender = from_header(smtp)
    if not sender:
        raise MailError("No From address is set (Settings → Email (SMTP), or SMTP_FROM).")
    address = smtp.from_address or smtp.user
    message["From"] = sender
    message["To"] = to
    message["Message-ID"] = make_msgid(domain=address.rpartition("@")[2] or None)
    try:
        client = _connect(smtp)
        try:
            client.send_message(message, from_addr=address, to_addrs=[to])
        finally:
            _close(client)
    except MailError:
        raise
    except smtplib.SMTPAuthenticationError as exc:
        raise MailError("The server rejected that username and password.") from exc
    except (OSError, smtplib.SMTPException) as exc:
        raise MailError(redact_secrets(f"Sending failed: {_friendly(exc, smtp)}", smtp)) from exc


def send_mail(
    to: Iterable[str],
    *,
    subject: str,
    text: str,
    attachments: Iterable[tuple[str, bytes, str]] = (),
    smtp: Smtp | None = None,
) -> dict[str, list[str]]:
    """One message to several addresses, with attachments (the backups'). Returns {accepted, rejected}; raises
    MailError (never with the password in it)."""

    smtp = smtp or smtp_settings()
    if smtp is None:
        raise MailError("No mail server is set (Settings → Email (SMTP), or SMTP_HOST).")
    recipients = [r for r in (str(x).strip() for x in to) if r]
    if not recipients:
        raise MailError("No recipients.")
    if not smtp.sender:
        raise MailError("No From address is set (SMTP_FROM, or SMTP_USER as an address).")
    message = EmailMessage()
    message["From"] = smtp.sender
    message["To"] = ", ".join(recipients)
    message["Subject"] = re.sub(r"[\r\n]+", " ", scrub_pan(subject, boundary="email"))
    message["Message-ID"] = make_msgid(domain=(smtp.sender.rsplit("@", 1)[-1].strip(">") or None))
    message.set_content(scrub_pan(text, boundary="email"))
    for filename, content, content_type in attachments:
        maintype, _, subtype = (content_type or "application/octet-stream").partition("/")
        message.add_attachment(content, maintype=maintype, subtype=subtype or "octet-stream", filename=filename)
    try:
        client = _connect(smtp)
        try:
            refused = client.send_message(message, from_addr=smtp.from_address or smtp.user, to_addrs=recipients)
        finally:
            _close(client)
    except MailError:
        raise
    except Exception as error:  # noqa: BLE001 - one message, without the password
        raise MailError(redact_secrets(f"Sending failed: {_friendly(error, smtp)}", smtp)) from None
    rejected = sorted(refused)
    return {"accepted": [r for r in recipients if r not in refused], "rejected": rejected}


def as_dict(smtp: Smtp) -> dict[str, Any]:
    """For tests and the troubleshooting report: everything but the password."""

    out = asdict(smtp)
    out["password"] = "[hidden]" if smtp.password else ""
    return out


__all__ = [
    "MailError",
    "Smtp",
    "SmtpSettings",
    "configured",
    "current",
    "fingerprint",
    "merge_smtp",
    "redact_secrets",
    "send",
    "send_mail",
    "smtp_from_env",
    "smtp_settings",
    "system_email",
    "test_connection",
    "verified",
]
