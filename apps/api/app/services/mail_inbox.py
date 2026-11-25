"""The backup mailbox, read over IMAP: how a new, empty Hawk AI finds its newest backup by itself. Ported from
CxMissionZero's src/mail-inbox.js (findBackupInMailbox, with imaplib in place of imapflow).

It reads only: the mailbox is opened read-only (EXAMINE) and messages are fetched with BODY.PEEK, so nothing is marked
read, moved or deleted. Only the newest 20 messages whose subject starts with "Hawk AI backup" are looked at, and only
their .hkbackup attachments up to 25 MB. Certificates are always checked. The password is only ever sent over TLS:
from the start (port 993), or else STARTTLS must be offered and taken, so a server (or anyone in between) that leaves
STARTTLS out gets no sign-in at all.
"""

from __future__ import annotations

import datetime as dt
import email
import email.policy
import email.utils
import imaplib
import re
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

#: What a backup email's subject starts with: how a new server finds the backups in the mailbox.
BACKUP_SUBJECT = "Hawk AI backup"
#: The newest this many backup emails are looked at.
NEWEST = 20
#: The largest backup attachment read from the mailbox. Backups are emailed only up to 15 MB and mail servers rarely
#: carry more than 25 MB; anyone can send mail to the mailbox, so nothing bigger is held in memory.
MAX_BACKUP_BYTES = 25 * 1024 * 1024
SOCKET_TIMEOUT = 60

#: Said when the mailbox server offers no STARTTLS.
NO_STARTTLS = (
    "The mailbox server offers no encrypted connection, and Hawk AI never sends a password without one. How to fix it: "
    "use port 993 (encrypted from the start), or ask the mail server's administrator to turn on STARTTLS for this port."
)


class MailboxError(Exception):
    pass


@dataclass(frozen=True)
class MailboxAccount:
    host: str
    port: int = 993
    user: str = ""
    password: str = ""

    @property
    def secure(self) -> bool:
        return self.port == 993


def _connect(account: MailboxAccount) -> Any:
    context = ssl.create_default_context()
    if account.secure:
        return imaplib.IMAP4_SSL(account.host, account.port, ssl_context=context, timeout=SOCKET_TIMEOUT)
    client = imaplib.IMAP4(account.host, account.port, timeout=SOCKET_TIMEOUT)
    if "STARTTLS" not in getattr(client, "capabilities", ()):
        try:
            client.shutdown()
        except Exception:  # noqa: BLE001
            pass
        raise MailboxError(NO_STARTTLS)
    client.starttls(ssl_context=context)
    return client


def _safe(error: BaseException, account: MailboxAccount) -> MailboxError:
    if isinstance(error, MailboxError):
        return error
    text = str(error) or error.__class__.__name__
    if account.password:
        text = text.replace(account.password, "[hidden]")
    return MailboxError(text[:300])


def _ok(response: tuple[str, list[Any]], what: str) -> list[Any]:
    typ, data = response
    if typ != "OK":
        raise MailboxError(f"The mailbox server refused to {what}.")
    return data


def _header_date(raw: bytes) -> float:
    message = email.message_from_bytes(raw, policy=email.policy.compat32)
    try:
        parsed = email.utils.parsedate_to_datetime(str(message.get("Date") or ""))
        return parsed.timestamp() if parsed else 0.0
    except (TypeError, ValueError):
        return 0.0


def _header_subject(raw: bytes) -> str:
    message = email.message_from_bytes(raw, policy=email.policy.default)
    return str(message.get("Subject") or "")


def _fetched(data: list[Any]) -> tuple[bytes, str]:
    """(literal, the response line) from a FETCH answer."""

    for part in data:
        if isinstance(part, tuple) and len(part) >= 2:
            return bytes(part[1]), part[0].decode("utf-8", "replace") if isinstance(part[0], bytes) else str(part[0])
    return b"", ""


def _backup_parts(raw: bytes) -> list[tuple[str, bytes]]:
    message = email.message_from_bytes(raw, policy=email.policy.default)
    out = []
    for part in message.walk():
        name = part.get_filename() or ""
        if re.search(r"\.hkbackup$", name, re.IGNORECASE):
            payload = part.get_payload(decode=True) or b""
            out.append((name, payload))
    return out


def find_backup_in_mailbox(
    account: MailboxAccount,
    accept: Callable[[bytes], bool],
    *,
    connect: Callable[[MailboxAccount], Any] = _connect,
) -> dict[str, Any] | None:
    """The newest backup in the mailbox that ``accept(buffer)`` takes (it checks the passphrase), or None:
    {buffer, name, date}. Changes nothing in the mailbox."""

    client = None
    try:
        client = connect(account)
        _ok(client.login(account.user, account.password), "sign in")
        _ok(client.select("INBOX", readonly=True), "open the inbox")
        found = _ok(client.uid("SEARCH", None, "SUBJECT", f'"{BACKUP_SUBJECT}"'), "search the inbox")
        uids = [u for u in (found[0] or b"").split() if u] if found else []
        uids = uids[-NEWEST:]
        messages = []
        for uid in uids:
            head, line = _fetched(_ok(client.uid("FETCH", uid, "(RFC822.SIZE BODY.PEEK[HEADER.FIELDS (DATE SUBJECT)])"), "read the inbox"))
            if not _header_subject(head).startswith(BACKUP_SUBJECT):
                continue
            size_match = re.search(r"RFC822\.SIZE (\d+)", line)
            messages.append({"uid": uid, "date": _header_date(head), "size": int(size_match.group(1)) if size_match else 0})
        messages.sort(key=lambda m: m["date"], reverse=True)
        for m in messages:
            # Base64 grows an attachment by a third: too large before it is fetched.
            if m["size"] > MAX_BACKUP_BYTES * 1.4:
                continue
            raw, _ = _fetched(_ok(client.uid("FETCH", m["uid"], "(BODY.PEEK[])"), "read a message"))
            for name, buffer in _backup_parts(raw):
                if len(buffer) <= MAX_BACKUP_BYTES and accept(buffer):
                    iso = ""
                    if m["date"]:
                        iso = dt.datetime.fromtimestamp(m["date"], dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                    return {"buffer": buffer, "name": name, "date": iso}
        return None
    except Exception as error:  # noqa: BLE001 - never with the password in it
        raise _safe(error, account) from None
    finally:
        if client is not None:
            try:
                client.logout()
            except Exception:  # noqa: BLE001
                pass


__all__ = ["BACKUP_SUBJECT", "MAX_BACKUP_BYTES", "MailboxAccount", "MailboxError", "NO_STARTTLS", "find_backup_in_mailbox"]
