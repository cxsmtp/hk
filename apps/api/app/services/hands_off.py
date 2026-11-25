"""Hands-off: Hawk AI set up once (Settings → Hands-off), then left alone, ported from CxMissionZero's src/hands-off.js.
It emails a short status once a week and takes requests from those emails: a one-click link, or a reply with one word
(PAUSE, RESUME, RUN, STATUS, STOP, SOLVED). Nobody has to sign in.

MZ's settings live in each tenant's settings.json; Hawk AI's are the installation's, in ``hands-off.json`` in the data
folder (in every backup). MZ's developer reminders are Checkmarx domain and are not here.
"""

from __future__ import annotations

import datetime as dt
import re
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.services import mailer
from app.services.state_file import read_state, write_state

FILE_NAME = "hands-off.json"
EMAIL = re.compile(r"^(?=.{3,254}$)[^\s@<>\"]+@[^\s@<>\"]+\.[^\s@<>\"]+$")

DEFAULT_HANDS_OFF: dict[str, Any] = {
    "on": False,
    # Who gets the weekly status, and may steer Hawk AI from it.
    "statusTo": [],
    # 0 = Sunday … 6 = Saturday, and the hour (server time) it is sent.
    "statusDay": 1,
    "statusHour": 8,
    # The weekly status stops until then (ISO), from a link or a PAUSE reply.
    "pausedUntil": "",
    # Read replies from the mailbox Hawk AI sends from (IMAP).
    "replies": False,
    "imapHost": "",
    "imapPort": 993,
    "lastStatusAt": "",
}


class HandsOffError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def addresses(value: Any) -> list[str]:
    items = value if isinstance(value, list) else re.split(r"[\s,;]+", str(value or ""))
    out: list[str] = []
    for item in items:
        address = str(item).strip().lower()
        if EMAIL.match(address) and address not in out:
            out.append(address)
    return out


def merge_hands_off(current: dict[str, Any] | None, incoming: dict[str, Any] | None = None) -> dict[str, Any]:
    """Hands-off settings, checked (MZ's mergeHandsOff)."""

    out = {**DEFAULT_HANDS_OFF, **(current or {})}
    out["statusTo"] = list(out.get("statusTo") or [])
    if not incoming:
        return out
    if "on" in incoming:
        out["on"] = incoming["on"] is True
    if "statusTo" in incoming:
        out["statusTo"] = addresses(incoming["statusTo"])[:50]
    if "statusDay" in incoming:
        day = incoming["statusDay"]
        if not isinstance(day, int) or isinstance(day, bool) or not 0 <= day <= 6:
            raise HandsOffError("Hands-off: choose a day of the week.")
        out["statusDay"] = day
    if "statusHour" in incoming:
        hour = incoming["statusHour"]
        if not isinstance(hour, int) or isinstance(hour, bool) or not 0 <= hour <= 23:
            raise HandsOffError("Hands-off: the hour must be from 0 to 23.")
        out["statusHour"] = hour
    if "pausedUntil" in incoming:
        at = str(incoming["pausedUntil"] or "")
        parsed = _parse(at) if at else None
        out["pausedUntil"] = _iso(parsed) if parsed else ""
    if "replies" in incoming:
        out["replies"] = incoming["replies"] is True
    if "imapHost" in incoming:
        host = str(incoming["imapHost"] or "").strip()
        if host and not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
            raise HandsOffError("Hands-off: the mailbox server must be a host name, such as imap.company.com.")
        out["imapHost"] = host
    if "imapPort" in incoming:
        port = incoming["imapPort"]
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise HandsOffError("Hands-off: the mailbox port must be from 1 to 65535.")
        out["imapPort"] = port
    if "lastStatusAt" in incoming:
        out["lastStatusAt"] = str(incoming["lastStatusAt"] or "")
    return out


def _iso(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse(value: Any) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def _file(data_dir: Path | str | None = None) -> Path:
    return Path(data_dir or settings.hawk_data_dir) / FILE_NAME


def load(data_dir: Path | str | None = None) -> dict[str, Any]:
    raw = read_state(_file(data_dir), fallback={}, holds="the hands-off settings (Settings → Hands-off)")
    return merge_hands_off(raw if isinstance(raw, dict) else {})


def save(patch: dict[str, Any], data_dir: Path | str | None = None) -> dict[str, Any]:
    merged = merge_hands_off(load(data_dir), patch)
    write_state(_file(data_dir), merged)
    return merged


def is_paused(hands_off: dict[str, Any], now: dt.datetime | None = None) -> bool:
    until = _parse(hands_off.get("pausedUntil")) if hands_off.get("pausedUntil") else None
    return bool(until and until > (now or dt.datetime.now(dt.timezone.utc)))


def status_due(hands_off: dict[str, Any], now: dt.datetime, zone: dt.tzinfo) -> bool:
    """Is this week's status due: its day and hour (in the server's time zone) have come, and it has not gone out
    since?"""

    if not hands_off.get("on") or not hands_off.get("statusTo") or is_paused(hands_off, now):
        return False
    local = now.astimezone(zone)
    slot = local.replace(hour=hands_off["statusHour"], minute=0, second=0, microsecond=0)
    # Python's weekday(): Monday 0 … Sunday 6; MZ's day: Sunday 0 … Saturday 6.
    js_day = (slot.weekday() + 1) % 7
    slot -= dt.timedelta(days=(js_day - hands_off["statusDay"] + 7) % 7)
    if slot > local:
        slot -= dt.timedelta(days=7)
    last = _parse(hands_off.get("lastStatusAt")) if hands_off.get("lastStatusAt") else None
    return last is None or last < slot


#: The words a reply may start with, and what each does.
COMMANDS = {
    "pause": 'Pause the weekly status (7 days, or "PAUSE 14")',
    "resume": "Resume after a pause",
    "run": "Run the monitoring checks that are due now",
    "status": "Send me the status now",
    "stop": "Stop sending me the status",
    "solved": "Close the case this email is about",
}
ALIASES = {"close": "solved", "closed": "solved", "resolved": "solved", "fixed": "solved", "unsubscribe": "stop", "start": "resume", "continue": "resume", "report": "status", "now": "run"}
_QUOTE_START = re.compile(r"^(On .+ wrote:|-----Original Message-----|From: )", re.IGNORECASE)
_WORD = re.compile(r"^([A-Za-z]+)\b[\s:,-]*(\d{1,3})?")


def parse_command(text: Any) -> dict[str, Any] | None:
    """The command a reply asks for: its first word, above the quoted message. {command, days?} or None when the reply
    says nothing Hawk AI understands."""

    for raw in str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.strip()
        if not line:
            continue
        # The quoted original starts: nothing below it is the person's own words.
        if line.startswith(">") or _QUOTE_START.match(line):
            return None
        match = _WORD.match(line)
        if not match:
            return None
        word = match.group(1).lower()
        command = word if word in COMMANDS else ALIASES.get(word)
        if not command:
            return None
        if command == "pause":
            return {"command": command, "days": min(90, max(1, int(match.group(2) or 0) or 7))}
        return {"command": command}
    return None


def system_email(
    *,
    subject: str,
    lines: list[str],
    facts: list[tuple[str, str]] = (),
    buttons: list[tuple[str, str]] = (),
    reference: str = "",
    reply_help: bool = True,
    footer: str = "",
    app_name: str = "Hawk AI",
) -> EmailMessage:
    """MZ's systemEmail: a few lines, facts, buttons that act after one more click, how to reply instead, and the
    reference that lets a reply act."""

    shown = [c for c in COMMANDS if c != "solved" or any(re.search("solved", label, re.IGNORECASE) for label, _ in buttons)]
    help_line = f"Or reply to this email with one word: {', '.join(c.upper() for c in shown)}." if reply_help else ""
    tail = "\n\n".join(t for t in (help_line, footer, f"{app_name} reference: {reference}" if reference else "") if t)
    message = mailer.system_email(subject=subject, lines=list(lines), facts=list(facts), buttons=list(buttons), footer=tail, app_name=app_name)
    del message["Subject"]
    message["Subject"] = f"{subject} [{reference}]" if reference else subject
    return message


__all__ = [
    "ALIASES",
    "COMMANDS",
    "DEFAULT_HANDS_OFF",
    "HandsOffError",
    "addresses",
    "is_paused",
    "load",
    "merge_hands_off",
    "parse_command",
    "save",
    "status_due",
    "system_email",
]
