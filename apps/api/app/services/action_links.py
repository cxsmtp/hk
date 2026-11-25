"""One-click links in Hawk AI's own emails (hands-off, self-healing), ported from CxMissionZero's
src/action-links.js: pause, resume, run now, send the status, stop the status, mark a case solved.

A link carries what to do, for whom and until when, signed with the server's key, so nobody can make one up or change
one. Opening it shows a page with one button ("Yes, do it", apps/web/src/app/hands-off/confirm): mail scanners that
open every link never act. A short reference in each email's subject ([HKR-…], MZ's [MZR-…]) lets a reply be matched
to the person it was sent to (app/services/hands_off.py reads the command).

Hawk AI's hands-off settings are the installation's, not a tenant's, so a token names no tenant (MZ's ``t``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any

from app.core.config import settings

ACTIONS = ("pause", "resume", "run", "status", "stop", "solved")
DAY_SECONDS = 86_400
#: How long a link stays good.
LINK_DAYS = 30
_REFERENCE = re.compile(r"HKR-[A-Za-z0-9]{12}")


def _key() -> bytes:
    return hashlib.sha256(f"hawk-hands-off\n{settings.secret_key}".encode("utf-8")).digest()


def mac_text(text: str) -> str:
    """The server's keyed hash of ``text`` (MZ's reportGrants.macText), URL-safe."""

    digest = hmac.new(_key(), text.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _b64(value: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")


def _unb64(text: str) -> Any:
    return json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)).decode("utf-8"))


def sign_action(a: str, e: str, *, r: str = "", now: float | None = None) -> str:
    """A signed token: payload {a: action, e: email, r?: reference (a case number), x: expiry in ms}."""

    if a not in ACTIONS:
        raise ValueError(f"Unknown action {a}.")
    moment = time.time() if now is None else now
    body = _b64({"a": a, "e": str(e).lower(), **({"r": r} if r else {}), "x": int((moment + LINK_DAYS * DAY_SECONDS) * 1000)})
    return body + "." + mac_text("action\n" + body)


def read_action(token: Any, *, now: float | None = None) -> dict[str, Any] | None:
    """The payload of a genuine, unexpired token; None otherwise."""

    parts = str(token or "").strip().split(".")
    if len(parts) != 2:
        return None
    body, sig = parts
    if not body or not sig or len(body) > 2000:
        return None
    if not hmac.compare_digest(mac_text("action\n" + body).encode("ascii"), sig.encode("ascii", "replace")):
        return None
    try:
        payload = _unb64(body)
    except (ValueError, UnicodeDecodeError):
        return None
    moment = time.time() if now is None else now
    if not isinstance(payload, dict) or payload.get("a") not in ACTIONS or not isinstance(payload.get("e"), str):
        return None
    expiry = payload.get("x")
    if not isinstance(expiry, (int, float)) or expiry <= moment * 1000:
        return None
    return payload


def reply_reference(email: str) -> str:
    """The short reference in the subject and at the end of every hands-off email: derived from the address it was sent
    to, so a reply from that address can be checked without anything stored, and short enough that no mail client
    breaks it."""

    return "HKR-" + re.sub(r"[^A-Za-z0-9]", "", mac_text(f"reply\n{str(email).lower()}"))[:12]


def find_references(text: Any) -> list[str]:
    """The references (HKR-…) in a subject or text."""

    return list(dict.fromkeys(_REFERENCE.findall(str(text or ""))))


__all__ = ["ACTIONS", "LINK_DAYS", "find_references", "mac_text", "read_action", "reply_reference", "sign_action"]
