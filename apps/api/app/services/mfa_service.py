"""Two-step sign-in for people who sign in with a password, ported from CxMissionZero's src/mfa.js: a six-digit code
from an authenticator app (TOTP, RFC 6238: HMAC-SHA1, 30-second steps), and ten one-time recovery codes for the day
the phone is gone. Python's own hmac/hashlib only.

- The secret is kept with the person (users.mfa_secret), encrypted: the server must be able to work out the code, so
  it cannot be a hash. Recovery codes are kept as hashes only.
- A code is accepted for its own 30 seconds, the 30 before and the 30 after (clocks differ), and only once: the step
  it belonged to is remembered, and nothing at or before it works again.
- Between the password and the code there is no session, only a ticket: random, kept as its SHA-256 in the sign-in
  store (app/services/sign_in_store.py), for one person, five minutes, and five wrong codes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
from typing import Any
from urllib.parse import quote

from app.services import sign_in_store
from app.services.connector_secret_service import decrypt_connector_secrets, encrypt_connector_secrets


TOTP_STEP_SECONDS = 30
TOTP_DIGITS = 6
#: What the authenticator app shows as the account's issuer.
TOTP_ISSUER = "Hawk AI"
RECOVERY_CODES = 10
TICKET_TTL_SECONDS = 5 * 60
#: Wrong codes one ticket takes before the password has to be typed again.
TICKET_MAX_WRONG = 5
#: How long a secret shown to someone signed in waits for its first code.
SETUP_TTL_SECONDS = 10 * 60

_BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{43}$")


def base32_encode(data: bytes) -> str:
    """Bytes as base32 (RFC 4648, no padding): how authenticator apps take a key."""

    return base64.b32encode(data).decode("ascii").rstrip("=")


def base32_decode(text: str) -> bytes:
    """Base32 as bytes: spaces, hyphens, padding and lower case are fine; anything else raises ValueError."""

    clean = re.sub(r"[\s=-]", "", str(text or "").upper())
    if any(char not in _BASE32 for char in clean):
        raise ValueError("Not a base32 key.")
    bits = 0
    value = 0
    out = bytearray()
    for char in clean:
        value = ((value << 5) | _BASE32.index(char)) & 0xFFF
        bits += 5
        if bits >= 8:
            out.append((value >> (bits - 8)) & 0xFF)
            bits -= 8
    return bytes(out)


def new_secret() -> str:
    """A new secret: 160 random bits, as RFC 4226 recommends, in base32."""

    return base32_encode(secrets.token_bytes(20))


def totp_step(now: float | None = None) -> int:
    """The 30-second step a moment falls in."""

    return int((sign_in_store.now() if now is None else now) // TOTP_STEP_SECONDS)


def code_at(secret: str, step: int) -> str:
    """The code of one step (HOTP, RFC 4226, with the step as the counter)."""

    mac = hmac.new(base32_decode(secret), struct.pack(">Q", int(step)), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    number = ((mac[offset] & 0x7F) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3]
    return str(number % 10**TOTP_DIGITS).zfill(TOTP_DIGITS)


def totp(secret: str, now: float | None = None) -> str:
    """The code an authenticator app shows now."""

    return code_at(secret, totp_step(now))


def typed_code(value: Any) -> str:
    """What was typed, as a six-digit code ('' when it is not one). Spaces are fine: apps show "123 456"."""

    text = re.sub(r"\s+", "", str(value or ""))
    return text if re.fullmatch(r"\d{6}", text) else ""


def match_totp(secret: str, code: Any, *, now: float | None = None, after: int = 0) -> int:
    """The step a typed code belongs to: this one, the one before or the one after. 0 when it matches none, or when
    its step is at or before ``after`` (the step of the last code used: a code works once)."""

    typed = typed_code(code)
    if not typed or not secret:
        return 0
    current = totp_step(now)
    found = 0
    # Every step is worked out and compared in constant time, whichever matches.
    for step in (current - 1, current, current + 1):
        same = hmac.compare_digest(code_at(secret, step), typed)
        if same and step > after and not found:
            found = step
    return found


def otpauth_uri(account: str, secret: str, issuer: str = TOTP_ISSUER) -> str:
    """The address an authenticator app takes (as a QR code, or typed): otpauth://totp/Issuer:account?secret=…"""

    label = f"{quote(issuer, safe='')}:{quote(str(account or ''), safe='')}"
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECONDS}"
    )


def grouped_key(secret: str) -> str:
    """A key as people type it: groups of four."""

    text = str(secret or "")
    return " ".join(text[i : i + 4] for i in range(0, len(text), 4))


#: Recovery codes: ten letters and digits that cannot be mistaken for each other, in two groups of five (50 bits).
RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def new_recovery_codes(count: int = RECOVERY_CODES) -> list[str]:
    codes = []
    for _ in range(count):
        text = "".join(RECOVERY_ALPHABET[b % len(RECOVERY_ALPHABET)] for b in secrets.token_bytes(10))
        codes.append(f"{text[:5]}-{text[5:]}")
    return codes


def typed_recovery_code(value: Any) -> str:
    """What was typed, as a recovery code without its hyphen ('' when it is not one)."""

    text = re.sub(r"[\s-]", "", str(value or "").upper())
    return text if re.fullmatch(r"[A-Z2-9]{10}", text) else ""


def recovery_hash(user_id: str, code: str) -> str:
    """What is kept of a recovery code: its SHA-256, bound to the person it is for."""

    return hashlib.sha256(f"hawk-recovery|{user_id}|{typed_recovery_code(code)}".encode("utf-8")).hexdigest()


def setup_view(email: str, secret: str) -> dict[str, str]:
    """What the page shows to set an authenticator app up: the key (also in groups of four) and the address its QR
    code carries."""

    return {"secret": secret, "key": grouped_key(secret), "otpauth": otpauth_uri(email, secret)}


# ---------------------------------------------------------------------------------------------------------------------
# The secret, as kept with the person
# ---------------------------------------------------------------------------------------------------------------------


def seal_secret(secret: str) -> str:
    return str(encrypt_connector_secrets({"totp": secret}))


def open_secret(sealed: str | None) -> str:
    if not sealed:
        return ""
    try:
        return str(decrypt_connector_secrets(sealed).get("totp") or "")
    except (ValueError, TypeError):
        return ""


def recovery_list(raw: str | None) -> list[str]:
    try:
        value = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    return [str(item) for item in value if isinstance(item, str)] if isinstance(value, list) else []


# ---------------------------------------------------------------------------------------------------------------------
# Tickets between a correct password and the code
# ---------------------------------------------------------------------------------------------------------------------


def _digest(ticket: str) -> str:
    return hashlib.sha256(f"hawk-two-step|{ticket}".encode("utf-8")).hexdigest()


def issue_ticket(user_id: str, *, secret: str = "") -> str:
    """A ticket for one person: 256 random bits, kept as a hash. ``secret`` is set when that person is setting
    two-step sign-in up at sign-in (an administrator requires it) and has no secret saved yet. A person has a few at
    most (two browsers, a second try): the oldest of theirs goes first."""

    store = sign_in_store.store()
    now = sign_in_store.now()
    ticket = secrets.token_urlsafe(32)
    key = _digest(ticket)
    mine = store.get(f"ticket-user:{user_id}") or {"tickets": []}
    own = [item for item in mine.get("tickets", []) if isinstance(item, list) and len(item) == 2 and item[1] > now]
    for old_key, _ in own[: max(0, len(own) - 2)]:
        store.delete(f"ticket:{old_key}")
        store.delete(f"ticket-wrong:{old_key}")
    own = own[max(0, len(own) - 2) :]
    exp = now + TICKET_TTL_SECONDS
    store.put(f"ticket:{key}", {"user_id": user_id, "exp": exp, "secret": seal_secret(secret) if secret else ""}, TICKET_TTL_SECONDS + 5)
    own.append([key, exp])
    store.put(f"ticket-user:{user_id}", {"tickets": own}, TICKET_TTL_SECONDS + 5)
    return ticket


def ticket(ticket_value: str) -> dict[str, Any] | None:
    """The ticket's {user_id, secret, exp}, or None when it is not one, was used, or is over."""

    if not isinstance(ticket_value, str) or not _TOKEN.match(ticket_value):
        return None
    store = sign_in_store.store()
    key = _digest(ticket_value)
    entry = store.get(f"ticket:{key}")
    if not entry:
        return None
    if float(entry.get("exp", 0)) <= sign_in_store.now():
        store.delete(f"ticket:{key}")
        return None
    return {"user_id": str(entry.get("user_id") or ""), "secret": open_secret(entry.get("secret")), "exp": float(entry["exp"])}


def ticket_wrong(ticket_value: str) -> int:
    """A wrong code on this ticket: how many more it takes (0: the ticket is over)."""

    store = sign_in_store.store()
    key = _digest(str(ticket_value))
    if not store.get(f"ticket:{key}"):
        return 0
    wrong = store.incr(f"ticket-wrong:{key}", TICKET_TTL_SECONDS + 5)
    if wrong >= TICKET_MAX_WRONG:
        consume_ticket(ticket_value)
    return max(0, TICKET_MAX_WRONG - wrong)


def consume_ticket(ticket_value: str) -> bool:
    """Used: it never works again."""

    store = sign_in_store.store()
    key = _digest(str(ticket_value))
    taken = store.take(f"ticket:{key}")
    store.delete(f"ticket-wrong:{key}")
    return taken is not None


def revoke_tickets(user_id: str) -> None:
    """End every ticket of a person (their password changed, they were disabled, their two-step sign-in was reset)."""

    store = sign_in_store.store()
    mine = store.take(f"ticket-user:{user_id}") or {"tickets": []}
    for item in mine.get("tickets", []):
        if isinstance(item, list) and item:
            store.delete(f"ticket:{item[0]}")
            store.delete(f"ticket-wrong:{item[0]}")


# ---------------------------------------------------------------------------------------------------------------------
# Secrets shown to people who are signed in and turning two-step sign-in on
# ---------------------------------------------------------------------------------------------------------------------


def start_setup(user_id: str) -> str:
    secret = new_secret()
    sign_in_store.store().put(
        f"mfa-setup:{user_id}", {"secret": seal_secret(secret), "exp": sign_in_store.now() + SETUP_TTL_SECONDS}, SETUP_TTL_SECONDS + 5
    )
    return secret


def pending_setup(user_id: str) -> str:
    entry = sign_in_store.store().get(f"mfa-setup:{user_id}")
    if not entry or float(entry.get("exp", 0)) <= sign_in_store.now():
        return ""
    return open_secret(entry.get("secret"))


def clear_setup(user_id: str) -> None:
    sign_in_store.store().delete(f"mfa-setup:{user_id}")
