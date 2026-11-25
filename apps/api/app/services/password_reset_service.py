"""Forgotten passwords: a one-time link sent to the account's own email address, ported from CxMissionZero's
src/password-reset.js (docs/sign-in.md).

- The link carries 32 random bytes after ``#``. Only their SHA-256 is kept, in the sign-in store (Redis, with its time
  to live), so neither a copy of the database nor the audit log gives anyone a working link.
- One link per person at a time: asking again replaces the earlier one. It works once, for 30 minutes, and only while
  the account's password is the one it was made for, so a password changed any other way ends it too.
- Asking never says whether an address has an account: the answer is always the same.
- Asking is limited per person (3 an hour, a minute apart) and per network address (10 requests, and 10 links that
  do not work, a quarter of an hour).
"""

from __future__ import annotations

import hashlib
import re
import secrets
from typing import Any
from urllib.parse import urlsplit

from app.core.config import settings
from app.services import sign_in_store


RESET_TTL_SECONDS = 30 * 60
#: Per person: at most this many links an hour, and never two within a minute.
PER_ACCOUNT_PER_HOUR = 3
PER_ACCOUNT_GAP_SECONDS = 60
#: Per network address: this many requests for a link, and links that did not work, a quarter of an hour.
PER_IP_PER_WINDOW = 10
IP_WINDOW_SECONDS = 15 * 60
HOUR_SECONDS = 60 * 60

#: Who may reset a forgotten password by email (Settings → Sign-in).
RESET_POLICIES = ("everyone", "not-admins", "off")
POLICY_NAMES = {"everyone": "everyone with a password", "not-admins": "everyone except Admins", "off": "nobody"}

#: A link's token: 43 URL-safe characters (256 bits). Anything else is not one of ours.
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")

RESET_ASKED = (
    "If that address has an account that may reset its password here, a link to choose a new one is on its way. "
    "It works once, for 30 minutes. Nothing arrived? Check spam, or ask an administrator."
)
RESET_DEAD = (
    "This link no longer works: it was used, a newer one was sent, it is more than 30 minutes old, or the password has "
    "changed since. Ask for a new one."
)
TOO_MANY = "Too many requests from this address. Wait a quarter of an hour."

_LOOPBACK = re.compile(r"^(localhost|127(\.\d{1,3}){3}|\[?::1\]?)$", re.IGNORECASE)


def _hex(text: str) -> str:
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()


def password_stamp(password_hash: str | None) -> str:
    """What a link is bound to: the password the account had when it was made."""

    return _hex(f"hawk-reset\n{password_hash or ''}")


def mask_email(email: str) -> str:
    """"d•••@acme.io": enough for the owner to recognise, not enough to collect addresses."""

    local, _, domain = str(email or "").partition("@")
    if not domain:
        return ""
    return f"{local[:1]}{'•' * max(2, min(6, len(local) - 1))}@{domain}"


def reset_allowed(policy: str, *, is_admin: bool) -> bool:
    """Whether ``policy`` lets this person reset by email. ``is_admin``: an owner or admin of a tenant."""

    if policy == "off":
        return False
    if policy == "not-admins":
        return not is_admin
    return True


def link_base() -> str:
    """The address reset links point at: only the one set for this server (WEB_ORIGIN, which deploy/compose.yaml sets
    from PUBLIC_URL), never the address a request came in on, which anyone can forge to steer the link (and its
    secret) to their own site. https, unless it is this computer. '' when there is none."""

    url = str(settings.web_origin or "").strip()
    try:
        parsed = urlsplit(url)
    except ValueError:
        return ""
    host = parsed.hostname or ""
    if parsed.scheme == "https" and host:
        return url.rstrip("/")
    if parsed.scheme == "http" and _LOOPBACK.match(host):
        return url.rstrip("/")
    return ""


# ---------------------------------------------------------------------------------------------------------------------
# The limits
# ---------------------------------------------------------------------------------------------------------------------


def ip_blocked(ip: str) -> bool:
    """Has this network address asked (or tried dead links) too often lately? Counts nothing."""

    return sign_in_store.store().count(f"reset-ip:{ip or 'unknown'}", IP_WINDOW_SECONDS, sign_in_store.now()) >= PER_IP_PER_WINDOW


def note_ip(ip: str) -> None:
    """Count a request for a link, or a link that did not work, against this network address."""

    sign_in_store.store().hit(f"reset-ip:{ip or 'unknown'}", IP_WINDOW_SECONDS, sign_in_store.now())


def may_send(user_id: str) -> bool:
    """May a link go to this person now (3 an hour, a minute apart)?"""

    now = sign_in_store.now()
    times = sign_in_store.store().times(f"reset-sent:{user_id}", HOUR_SECONDS, now)
    if len(times) >= PER_ACCOUNT_PER_HOUR:
        return False
    return not times or now - times[-1] >= PER_ACCOUNT_GAP_SECONDS


# ---------------------------------------------------------------------------------------------------------------------
# The links
# ---------------------------------------------------------------------------------------------------------------------


def issue(user_id: str, password_hash: str) -> tuple[str, float]:
    """A new link for this person. Any earlier link of theirs stops working. Returns the token (it goes only into the
    email) and when it expires."""

    store = sign_in_store.store()
    now = sign_in_store.now()
    revoke_user(user_id)
    token = secrets.token_urlsafe(32)
    exp = now + RESET_TTL_SECONDS
    key = _hex(token)
    store.put(f"reset:{key}", {"user_id": user_id, "stamp": password_stamp(password_hash), "exp": exp}, RESET_TTL_SECONDS + 5)
    store.put(f"reset-user:{user_id}", {"key": key}, RESET_TTL_SECONDS + 5)
    store.hit(f"reset-sent:{user_id}", HOUR_SECONDS, now)
    return token, exp


def check(token: Any, user_of) -> Any:  # type: ignore[no-untyped-def]
    """The link's person, if it still works: the token is one of ours, not used, not expired, and the account still
    has the password it was made for. ``user_of(id)`` reads the account. Returns the user, or None (never why: an
    expired link and a made-up one look alike)."""

    text = str(token or "")
    if not TOKEN_PATTERN.match(text):
        return None
    store = sign_in_store.store()
    key = _hex(text)
    link = store.get(f"reset:{key}")
    if not link:
        return None
    if float(link.get("exp", 0)) <= sign_in_store.now():
        store.delete(f"reset:{key}")
        return None
    user = user_of(str(link.get("user_id") or ""))
    if user is None or not user.is_active or not user.hashed_password or password_stamp(user.hashed_password) != link.get("stamp"):
        store.delete(f"reset:{key}")
        return None
    return user


def consume(token: str) -> bool:
    """Use the link: it never works again (taken atomically, so one link cannot set two passwords), and neither does
    any other link of that person's. Returns whether it was still there."""

    link = sign_in_store.store().take(f"reset:{_hex(str(token))}")
    if link:
        revoke_user(str(link.get("user_id") or ""))
    return link is not None


def revoke_user(user_id: str) -> None:
    """End every link of one person (their password changed, they were removed or disabled)."""

    store = sign_in_store.store()
    pointer = store.take(f"reset-user:{user_id}")
    if pointer and pointer.get("key"):
        store.delete(f"reset:{pointer['key']}")
