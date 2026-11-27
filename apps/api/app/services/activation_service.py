"""The product licence (/settings/guide/licence): a 3-day trial per installation, then a ``.hawkai`` licence file.

Every installation gets a random installation ID the first time it starts (kept in the activation_state row with
when its trial started). Hawk AI works for 72 hours from then without a licence. After that every request is
refused with the message that it has been deactivated, until an owner or admin of the installation imports a
``.hawkai`` licence file made for this installation ID by the owner of Hawk AI. Data is never deleted. An
installation upgraded from a version without the trial gets its 72 hours from the upgrade.

A ``.hawkai`` file is a small JSON file, ``{"format": "hawkai-licence", "v": 2, "licence": "HK2.<payload>.<sig>"}``
(other fields in it are for people to read and are ignored). The licence is base64url: the payload is JSON
``{ v: 2, id, org, installationId, scopes: ["product", "tenants"?], maxTenants?, maxUsers?, issued, expires }``,
signed with the owner's Ed25519 private key; the public half is ISSUER_KEYS below. The signed head includes the
prefix, so an older ``HK1`` code or a CxMissionZero ``MZ1`` code can never be passed off as a licence. A licence is
checked here, offline: nothing is sent anywhere. A licence for another installation ID is refused.

Several tenants: without a licence with the ``tenants`` scope Hawk AI serves one tenant, with no cap on its users.
The ``tenants`` scope names how many tenants the installation may have (``maxTenants``) and, optionally, how many
active users each tenant may have (``maxUsers``). Tenants and users already there are never removed or disabled.

What is kept of an imported licence is the signed licence itself, and it is checked again each time it is read: a
date changed by hand in the database counts for nothing. The installation ID and the trial's start are sealed with
a key derived from the server's SECRET_KEY: changed by hand, the installation gets a new ID and no trial. The time
the licence goes by never goes back (``seenAt``), and the trial also ends once 72 hours have been seen to pass
(``trialUsedMs``), so setting the server's clock back or forward does not lengthen it.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import hmac
import json
import logging
import math
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key
from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.activation import ActivationState
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db import xact_lock
from app.db.session import SessionLocal


logger = logging.getLogger(__name__)

#: The owner's public key(s), base64 SPKI DER. Empty: no licence is valid.
ISSUER_KEYS: list[str] = [
    "MCowBQYDK2VwAyEAlWEwF9lhzKv0IZ1GaDJSmlJqaZd7Gc1JqvYju52uKo4=",
]

PREFIX = "HK2"
LICENCE_VERSION = 2
#: The licence file: its extension, its "format" and the largest one taken.
FILE_EXTENSION = ".hawkai"
FILE_FORMAT = "hawkai-licence"
MAX_FILE_BYTES = 16 * 1024
#: The licence request an administrator downloads and sends to the owner.
REQUEST_EXTENSION = ".hawkai-request"
REQUEST_FORMAT = "hawkai-licence-request"

DAY_MS = 24 * 60 * 60 * 1000
HOUR_MS = 60 * 60 * 1000
MINUTE_MS = 60 * 1000
#: Without a licence, each installation works for this long from its first start.
TRIAL_HOURS = 72
TRIAL_MS = TRIAL_HOURS * HOUR_MS
#: A clock found this much behind the last one seen has been set back (less is two processes a moment apart).
CLOCK_BACK_MS = 5 * MINUTE_MS
#: Admins are told this long before a licence expires (and throughout the trial).
WARN_DAYS = 30

#: What every request is answered with once it has stopped.
DEACTIVATED_MESSAGE = "The product has been deactivated. Please reach out to Bhawani Singh."

#: How many history entries are kept.
HISTORY_LIMIT = 50
#: The one row of activation_state.
STATE_ROW_ID = 1

#: What a licence may unlock. "product" keeps Hawk AI working until the licence's date (every licence has it);
#: "tenants" allows several tenants (and, optionally, caps the active users in each).
SCOPES = frozenset({"product", "tenants"})

#: Without a licence with the tenants scope in force: one tenant, and no cap on its users.
DEFAULT_MAX_TENANTS = 1

#: The test key is trusted only under pytest, and never in production (see trusted_keys()).
TEST_KEY_ENV = "HAWK_ACTIVATION_TEST_KEY"

NOT_A_LICENCE = "This file is not a Hawk AI licence."
NOT_VALID = "This licence is not valid: it was not signed by the owner of Hawk AI, or it was changed."


# ---- Small helpers, so the dates and numbers behave as in the console ------------------------------------------


def now_ms() -> int:
    return int(time.time() * 1000)


def parse_ms(value: Any) -> float | None:
    """An ISO date as milliseconds since 1970 (UTC), or None when it is not one (JavaScript's Date.parse)."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp() * 1000


def iso(ms: float) -> str:
    """Milliseconds since 1970 as an ISO date in UTC, with milliseconds (JavaScript's toISOString)."""
    whole = int(math.floor(ms))
    moment = datetime.fromtimestamp(whole // 1000, tz=timezone.utc)
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{whole % 1000:03d}Z"


def _is_int(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and value.is_integer()


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _fail(reason: str, **extra: Any) -> dict[str, Any]:
    return {"valid": False, "reason": reason, **extra}


def _production() -> bool:
    env = str(settings.env or "").strip().lower()
    return env in {"prod", "production"} or settings.deployment_topology == "single_node_compose"


def _release() -> bool:
    from app.services.integrity.service import is_release

    return is_release()


def trusted_keys() -> list[str]:
    """The issuer keys this process trusts: ISSUER_KEYS, and a test key only while pytest runs a test outside
    production (never in production, where it would let anyone sign their own licences)."""
    keys = list(ISSUER_KEYS)
    test_key = os.environ.get(TEST_KEY_ENV)
    # A release image carries the list of its files (integrity.json, app/services/integrity/manifest.py); a development
    # copy does not. A release never trusts the test key, whatever its settings.
    if test_key and os.environ.get("PYTEST_CURRENT_TEST") and not _production() and not _release():
        keys.append(test_key)
    return keys


def _signed_by(key: str, signed: bytes, signature: bytes) -> bool:
    try:
        public_key = load_der_public_key(base64.b64decode(key))
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        public_key.verify(signature, signed)
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False


def plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


# ---- The installation ID ----------------------------------------------------------------------------------------

_ID_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def new_installation_id() -> str:
    """A random installation ID people can read out and copy: HK-XXXX-XXXX-XXXX-XXXX (80 bits)."""
    chars = "".join(secrets.choice(_ID_ALPHABET) for _ in range(16))
    return "HK-" + "-".join(chars[i : i + 4] for i in range(0, 16, 4))


def normalize_installation_id(value: Any) -> str:
    return _text(value).strip().upper()


def _identity_seal(installation_id: str, trial_start: str) -> str:
    """The seal of the installation ID and the trial's start: a key derived from SECRET_KEY, so a hand-made change in
    the database does not verify."""
    secret = str(getattr(settings, "secret_key", "") or "")
    key = hashlib.sha256(b"hawk-ai-installation-identity\x00" + secret.encode("utf-8")).digest()
    message = f"{installation_id}\x00{trial_start}".encode("utf-8")
    return base64.urlsafe_b64encode(hmac.new(key, message, hashlib.sha256).digest()).rstrip(b"=").decode()


# ---- Licences ---------------------------------------------------------------------------------------------------


def read_licence(code: Any) -> dict[str, Any] | None:
    """Read a licence string without trusting it: {payload, signed, signature}, or None."""
    parts = _text(code).strip().split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        return None
    try:
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", errors="replace"))
        return {
            "payload": payload,
            "signed": f"{parts[0]}.{parts[1]}".encode("utf-8"),
            "signature": _b64url_decode(parts[2]),
        }
    except (ValueError, binascii.Error):
        return None


def check_licence(
    code: Any,
    *,
    now: float | None = None,
    keys: list[str] | None = None,
    installation_id: str | None = None,
) -> dict[str, Any]:
    """Check a licence string: signed by a trusted key, well formed, for this installation (when given), in date.

    Returns {valid, reason?, expired?, wrongInstallation?, id, org, installationId, scopes, maxTenants, maxUsers,
    issued, expires, daysLeft, warn, code}.
    """
    now = now_ms() if now is None else now
    keys = trusted_keys() if keys is None else list(keys)
    read = read_licence(code)
    if not read:
        return _fail(NOT_A_LICENCE)
    if not keys:
        return _fail("This installation has no key to check licences with.")
    if not any(_signed_by(key, read["signed"], read["signature"]) for key in keys):
        return _fail(NOT_VALID)
    p = read["payload"]
    if not isinstance(p, dict):
        return _fail(NOT_VALID)
    scopes = p.get("scopes")
    expires = parse_ms(p.get("expires"))
    version = p.get("v")
    licensed_id = normalize_installation_id(p.get("installationId"))
    well_formed = (
        _is_int(version)
        and version == LICENCE_VERSION
        and bool(_text(p.get("id")).strip())
        and bool(_text(p.get("org")).strip())
        and bool(licensed_id)
        and isinstance(scopes, list)
        and all(isinstance(s, str) and s in SCOPES for s in scopes)
        and "product" in scopes
        and expires is not None
    )
    max_users = p.get("maxUsers")
    for_tenants = well_formed and "tenants" in scopes
    if for_tenants and not (
        _is_int(p.get("maxTenants")) and p["maxTenants"] >= 1 and (max_users is None or (_is_int(max_users) and max_users >= 1))
    ):
        well_formed = False
    if not well_formed:
        return _fail(NOT_VALID)
    days_left = math.ceil((expires - now) / DAY_MS)
    info: dict[str, Any] = {
        "id": _text(p["id"]),
        "org": _text(p["org"]),
        "installationId": licensed_id,
        "scopes": sorted(set(scopes)),
        "maxTenants": int(p["maxTenants"]) if for_tenants else 0,
        "maxUsers": int(max_users) if for_tenants and max_users is not None else None,
        "issued": _text(p.get("issued")),
        "expires": iso(expires),
        "daysLeft": days_left,
        # The signed licence itself: what the store keeps, and checks again whenever it is read.
        "code": _text(code).strip(),
    }
    if installation_id is not None and licensed_id != normalize_installation_id(installation_id):
        return {
            **info,
            "valid": False,
            "wrongInstallation": True,
            "reason": (
                f"This licence is for installation {licensed_id}, not this one ({normalize_installation_id(installation_id)}). "
                "Send this installation's licence request to the owner of Hawk AI for a licence made for it."
            ),
        }
    if expires <= now:
        return {**info, "valid": False, "expired": True, "reason": f"This licence expired on {info['expires'][:10]}."}
    return {**info, "valid": True, "warn": days_left <= WARN_DAYS}


def licence_from_file(data: bytes | None, filename: str | None) -> tuple[str, str]:
    """The licence string in an uploaded ``.hawkai`` file: (licence, '') or ('', why the file is refused)."""
    name = _text(filename).strip()
    if data is None or not name:
        return "", "Choose a .hawkai licence file."
    if len(data) > MAX_FILE_BYTES:
        return "", f"This file is too large to be a Hawk AI licence (at most {MAX_FILE_BYTES // 1024} KB)."
    if not name.lower().endswith(FILE_EXTENSION):
        return "", "Choose a .hawkai licence file: this file does not end in .hawkai."
    try:
        body = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError):
        return "", NOT_A_LICENCE
    if not isinstance(body, dict) or body.get("format") != FILE_FORMAT or body.get("v") != LICENCE_VERSION:
        return "", NOT_A_LICENCE
    licence = body.get("licence")
    if not isinstance(licence, str) or not licence.strip():
        return "", NOT_A_LICENCE
    return licence.strip(), ""


# ---- The store --------------------------------------------------------------------------------------------------


class ActivationStore:
    """This installation's identity, trial, licence and the history of licences imported or refused. ``save`` keeps
    the state (the activation_state row); ``keys`` are the keys a kept licence is checked with (the trusted ones
    unless given); ``trial_floor`` is the earliest the trial may have started when none is recorded (the oldest
    account, when the row is missing on a database that has accounts)."""

    def __init__(
        self,
        state: dict[str, Any] | None = None,
        *,
        keys: list[str] | None = None,
        save: Callable[[dict[str, Any]], None] | None = None,
        trial_floor: float | None = None,
    ) -> None:
        raw = copy.deepcopy(state) if isinstance(state, dict) else {}
        history = raw.get("history")
        used = raw.get("trialUsedMs")
        self._state: dict[str, Any] = {
            "installationId": _text(raw.get("installationId")),
            "trialStart": _text(raw.get("trialStart")),
            "identitySeal": _text(raw.get("identitySeal")),
            "licence": raw.get("licence") if isinstance(raw.get("licence"), dict) else None,
            "seenAt": _text(raw.get("seenAt")),
            "lastAt": _text(raw.get("lastAt")),
            "trialUsedMs": int(used) if _is_int(used) and used >= 0 else 0,
            "history": history if isinstance(history, list) else [],
        }
        # An installation that had a sealed identity which no longer verifies has been changed by hand.
        self._had_identity = bool(self._state["installationId"] or self._state["identitySeal"])
        self._keys = keys
        self._save_state = save
        self._trial_floor = trial_floor
        self._sealed_licence: dict[str, Any] | None = None
        self._seal_licence()

    @property
    def state(self) -> dict[str, Any]:
        return copy.deepcopy(self._state)

    def _save(self) -> None:
        if self._save_state is not None:
            self._save_state(copy.deepcopy(self._state))

    def _try_save(self) -> None:
        try:
            self._save()
        except Exception:  # noqa: BLE001 - kept in memory; it is saved next time.
            logger.debug("activation_state_not_saved", exc_info=True)

    # -- Identity and clock --

    def _identity_ok(self) -> bool:
        s = self._state
        return bool(
            s["installationId"]
            and parse_ms(s["trialStart"]) is not None
            and hmac.compare_digest(s["identitySeal"], _identity_seal(s["installationId"], s["trialStart"]))
        )

    def ensure_identity(self, now: float | None = None) -> bool:
        """Give the installation its ID and trial when it has none yet. Returns whether anything changed (saved)."""
        if self._identity_ok():
            return False
        now = now_ms() if now is None else now
        s = self._state
        seen = parse_ms(s["seenAt"]) or 0
        if self._had_identity:
            # The ID, the trial's start or their seal were changed outside Hawk AI: a new ID, and no trial.
            start = 0.0
            note = "The installation's identity did not verify (changed outside Hawk AI): a new installation ID, without a trial."
            logger.warning("Licence: %s", note)
            s["history"] = [{"outcome": "identity", "reason": note, "at": iso(now), "by": "Hawk AI server"}, *s["history"]][:HISTORY_LIMIT]
            s["licence"] = None
        else:
            start = max(now, seen)
            if self._trial_floor is not None:
                start = min(start, self._trial_floor)
        s["installationId"] = new_installation_id()
        s["trialStart"] = iso(start)
        s["identitySeal"] = _identity_seal(s["installationId"], s["trialStart"])
        self._had_identity = True
        self._seal_licence()
        self._try_save()
        return True

    @property
    def installation_id(self) -> str:
        self.ensure_identity()
        return self._state["installationId"]

    def now(self, now: float | None = None) -> float:
        """The time the licence goes by: never earlier than the latest it has seen (kept, at most hourly), so setting
        the server's clock back does not undo an end date. Also counts the time seen to pass for the trial."""
        now = now_ms() if now is None else now
        self.ensure_identity(now)
        s = self._state
        seen = parse_ms(s["seenAt"]) or 0
        last = parse_ms(s["lastAt"])
        changed = False
        if last is None:
            s["lastAt"] = iso(now)
            changed = True
        elif now < last - CLOCK_BACK_MS:
            # The clock was set back: count from here, never from the later time again.
            s["lastAt"] = iso(now)
            changed = True
        elif now > last + HOUR_MS:
            s["trialUsedMs"] = int(s["trialUsedMs"] + (now - last))
            s["lastAt"] = iso(now)
            changed = True
        if now > seen + HOUR_MS:
            s["seenAt"] = iso(now)
            changed = True
        if changed:
            self._try_save()
        return max(now, seen)

    def _trial_used(self, now: float) -> float:
        last = parse_ms(self._state["lastAt"])
        pending = now - last if last is not None and now > last else 0
        return self._state["trialUsedMs"] + pending

    def trial(self, now: float | None = None) -> dict[str, Any]:
        """The trial: {start, end, active, msLeft}. It ends 72 hours after it started by the licence's clock, or once
        72 hours have been seen to pass, whichever comes first."""
        raw = now_ms() if now is None else now
        t = self.now(raw)
        start = parse_ms(self._state["trialStart"]) or 0
        unused = max(0.0, TRIAL_MS - self._trial_used(raw))
        end = min(start + TRIAL_MS, t + unused)
        left = max(0.0, end - t)
        return {"start": iso(start), "end": iso(end), "active": left > 0, "msLeft": left}

    # -- The licence --

    def _check_kept(self, code: Any) -> dict[str, Any]:
        # now: 0, so an expired licence still reads (its date then says it is over).
        return check_licence(code, now=0, keys=self._keys, installation_id=self._state["installationId"] or None)

    def _seal_licence(self) -> None:
        """The kept licence as its signed string says it: the scopes, the date and the limits are read from the
        licence, not from what is kept beside it. One that does not verify (edited, from another key, or for another
        installation) counts for nothing."""
        entry = self._state["licence"]
        if not isinstance(entry, dict) or not entry.get("code") or not self._identity_ok():
            self._sealed_licence = None
            return
        checked = self._check_kept(entry["code"])
        self._sealed_licence = {**checked, "at": entry.get("at"), "by": entry.get("by")} if checked["valid"] else None

    def check(self, code: Any, now: float | None = None) -> dict[str, Any]:
        """Check a licence for this installation, in date by the licence's own clock, and not older than the one in
        force (an older licence imported again would cut the date short or take tenants away)."""
        t = self.now(now)
        result = check_licence(code, now=t, keys=self._keys, installation_id=self._state["installationId"])
        if not result["valid"]:
            return result
        current = self._sealed_licence
        if current:
            issued = parse_ms(result.get("issued"))
            issued_before = parse_ms(current.get("issued"))
            if issued is not None and issued_before is not None and issued < issued_before:
                return {
                    **result,
                    "valid": False,
                    "reason": f"This licence was issued before the one in force (issued {current['issued'][:10]}): ask for a new one.",
                }
        return result

    def _history_entry(self, result: dict[str, Any], by: Any, outcome: str, reason: str = "") -> dict[str, Any]:
        entry: dict[str, Any] = {"outcome": outcome, "at": iso(now_ms()), "by": _text(by)}
        for key in ("id", "org", "installationId", "scopes", "expires"):
            if result.get(key):
                entry[key] = result[key]
        if reason:
            entry["reason"] = reason
        return entry

    def record(self, result: dict[str, Any], by: Any = "") -> dict[str, Any]:
        """Record an imported licence (the result of check) and who imported it."""
        entry = self._history_entry(result, by, "imported")
        self._state["licence"] = {
            "code": result["code"],
            "id": result["id"],
            "org": result["org"],
            "expires": result["expires"],
            "at": entry["at"],
            "by": entry["by"],
        }
        self._state["history"] = [entry, *self._state["history"]][:HISTORY_LIMIT]
        self._seal_licence()
        self._save()
        return entry

    def record_refusal(self, result: dict[str, Any], reason: str, by: Any = "") -> dict[str, Any]:
        entry = self._history_entry(result or {}, by, "refused", reason)
        self._state["history"] = [entry, *self._state["history"]][:HISTORY_LIMIT]
        self._save()
        return entry

    def licence(self, now: float | None = None) -> dict[str, Any] | None:
        """The licence in force (in date or not): {id, org, installationId, scopes, maxTenants, maxUsers, issued,
        expires, at, by, daysLeft, valid, warn}."""
        lic = self._sealed_licence
        if not lic:
            return None
        t = self.now(now)
        days_left = math.ceil(((parse_ms(lic["expires"]) or 0) - t) / DAY_MS)
        return {
            "id": lic["id"],
            "org": lic["org"],
            "installationId": lic["installationId"],
            "scopes": lic["scopes"],
            "maxTenants": lic["maxTenants"] or None,
            "maxUsers": lic["maxUsers"],
            "issued": lic["issued"],
            "expires": lic["expires"],
            "at": lic.get("at"),
            "by": lic.get("by"),
            "daysLeft": days_left,
            "valid": days_left > 0 and (parse_ms(lic["expires"]) or 0) > t,
            "warn": 0 < days_left <= WARN_DAYS,
        }

    def tenants(self, now: float | None = None) -> dict[str, Any] | None:
        """The tenants scope in force: {org, maxTenants, maxUsers, expires, at, by, daysLeft, valid, warn}."""
        lic = self.licence(now)
        if not lic or "tenants" not in lic["scopes"]:
            return None
        return {key: lic[key] for key in ("org", "maxTenants", "maxUsers", "expires", "at", "by", "daysLeft", "valid", "warn")}

    def history(self) -> list[dict[str, Any]]:
        return [dict(h) if isinstance(h, dict) else h for h in self._state["history"]]

    def product(self, now: float | None = None) -> dict[str, Any]:
        """Whether Hawk AI may work: during the trial, or while a licence for this installation is in date.
        {active, until, daysLeft, hoursLeft, warn, trial, trialEnds, installationId, activation, message}."""
        raw = now_ms() if now is None else now
        trial = self.trial(raw)
        t = self.now(raw)
        lic = self.licence(raw)
        licensed_until = (parse_ms(lic["expires"]) or 0) if lic and lic["valid"] else 0
        in_trial = bool(trial["active"]) and licensed_until <= t
        until = licensed_until if licensed_until > t else (parse_ms(trial["end"]) or 0)
        active = in_trial or licensed_until > t
        ms_left = max(0.0, until - t) if active else 0.0
        days_left = math.ceil(ms_left / DAY_MS)
        return {
            "active": active,
            "until": iso(until),
            "daysLeft": days_left,
            "hoursLeft": math.ceil(ms_left / HOUR_MS),
            # Admins see the banner throughout the trial, and in a licence's last 30 days.
            "warn": active and (in_trial or days_left <= WARN_DAYS),
            "trial": in_trial,
            "trialEnds": trial["end"],
            "installationId": self._state["installationId"],
            "activation": (
                {"org": lic["org"], "expires": lic["expires"], "at": lic.get("at"), "id": lic["id"], "scopes": lic["scopes"]}
                if lic
                else None
            ),
            "message": "" if active else DEACTIVATED_MESSAGE,
        }


# ---- Kept in the database ---------------------------------------------------------------------------------------

#: Where the licence gate and the background tasks read the state from (a session factory). Tests point it at
#: their own database.
licence_session_factory: Callable[[], Session] = SessionLocal


def _as_ms(value: Any) -> float | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.timestamp() * 1000


def _oldest_account_ms(db: Session) -> float | None:
    try:
        return _as_ms(db.scalar(select(func.min(User.created_at))))
    except Exception:  # noqa: BLE001
        return None


def load_store(db: Session, *, for_update: bool = False, commit: bool = False) -> ActivationStore:
    """The store as kept in the activation_state row of ``db``. What it saves is flushed to ``db`` (committed too
    with ``commit``); ``for_update`` locks the row until the transaction ends, for a licence being recorded.

    The row is made by migration 0106 on every database, so it is missing only on a new database (no accounts yet)
    or when it was deleted by hand: then the trial counts from the oldest account."""
    statement = select(ActivationState).where(ActivationState.id == STATE_ROW_ID)
    if for_update:
        statement = statement.with_for_update()
    row = db.scalar(statement)
    if row is None or not isinstance(row.state, dict) or not row.state.get("installationId"):
        # Two processes giving the installation its ID at the same moment: one after the other.
        if xact_lock.hold(db, "licence-identity"):
            row = db.scalar(select(ActivationState).where(ActivationState.id == STATE_ROW_ID).execution_options(populate_existing=True))

    def save(state: dict[str, Any]) -> None:
        try:
            current = db.get(ActivationState, STATE_ROW_ID)
            if current is None:
                db.add(ActivationState(id=STATE_ROW_ID, state=state))
            else:
                current.state = state
            db.flush()
            if commit:
                db.commit()
        except Exception:
            db.rollback()
            raise

    floor = _oldest_account_ms(db) if row is None else None
    return ActivationStore(row.state if row is not None else None, save=save, trial_floor=floor)


#: The last product licence this process read: used when the state cannot be read (never a fresh trial).
_last_product: dict[str, Any] | None = None


def read_product(now: float | None = None) -> dict[str, Any]:
    """The product licence as every process sees it. If the state cannot be read, the last one this process read
    still applies, up to its date; without one, Hawk AI is not active (a missing table never starts a new trial)."""
    global _last_product
    try:
        with licence_session_factory() as db:
            product = load_store(db, commit=True).product(now)
            _last_product = product
            return product
    except Exception:  # noqa: BLE001
        logger.debug("activation_state_unreadable", exc_info=True)
        t = now_ms() if now is None else now
        last = _last_product
        if last and last["active"] and (parse_ms(last["until"]) or 0) > t:
            return last
        return {**ActivationStore(None).product(t), "active": False, "warn": False, "trial": False, "message": DEACTIVATED_MESSAGE}


def licence_active(now: float | None = None) -> bool:
    return bool(read_product(now)["active"])


def licence_for_admins(db: Session) -> dict[str, Any]:
    """The product licence's end, for the admins' banner during the trial and in a licence's last 30 days."""
    product = load_store(db).product()
    return {key: product[key] for key in ("until", "daysLeft", "hoursLeft", "warn", "trial", "activation", "installationId")}


def start_installation(session_factory: Callable[[], Session] | None = None, log: Callable[[str], None] | None = None) -> None:
    """At start-up: the installation gets its ID and its trial starts, if it has none yet; the log says where it is."""
    factory = session_factory or licence_session_factory
    with factory() as db:
        store = load_store(db, commit=True)
        product = store.product()
        db.commit()
    if log is None:
        return
    if product["trial"]:
        log(f"[licence] Installation {product['installationId']}: trial until {product['until']} ({plural(product['hoursLeft'], 'hour')} left). Import a .hawkai licence under Settings → Licence.")
    elif product["active"]:
        log(f"[licence] Installation {product['installationId']}: licensed until {product['until']}.")
    else:
        log(f"[licence] Installation {product['installationId']}: no licence in force. Hawk AI is deactivated until a .hawkai licence for this installation is imported.")


# ---- Several tenants, and the active users in each ----------------------------------------------------------------

LIMIT_HINT = "Import a licence that allows more under Settings → Licence."


def tenant_limits(db: Session, now: float | None = None) -> tuple[int, int | None]:
    """(maxTenants, maxUsers) in force: a licence with the tenants scope in date, or one tenant and no cap on users."""
    tenants = load_store(db).tenants(now)
    if tenants and tenants["valid"]:
        return int(tenants["maxTenants"]), tenants["maxUsers"]
    return DEFAULT_MAX_TENANTS, None


def assert_may_add_tenant(db: Session) -> None:
    """Refuse (403) a tenant created or activated beyond what the licence allows. Nothing already there is removed
    or disabled. Two at the same moment are counted one after the other."""
    xact_lock.hold(db, "tenants")
    tenants = load_store(db).tenants()
    in_force = bool(tenants and tenants["valid"])
    max_tenants = int(tenants["maxTenants"]) if in_force else DEFAULT_MAX_TENANTS
    active = int(db.scalar(select(func.count()).select_from(Tenant).where(Tenant.is_active.is_(True))) or 0)
    if active < max_tenants:
        return
    if in_force:
        detail = f"The licence allows up to {plural(max_tenants, 'tenant')}, and all are in use. {LIMIT_HINT}"
    else:
        detail = "Without a licence for several tenants Hawk AI serves 1 tenant, and it is in use. Import a licence for several tenants under Settings → Licence."
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def assert_may_add_member(db: Session, tenant_id: str) -> None:
    """Refuse (403) a user added to, or activated in, a tenant that already has the active users the licence
    allows. Nothing already there is removed or disabled."""
    _, max_users = tenant_limits(db)
    if max_users is None:
        return
    # Two people added at the same moment are counted one after the other.
    xact_lock.hold(db, "tenant-people", tenant_id)
    active = int(
        db.scalar(
            select(func.count())
            .select_from(UserTenantRole)
            .join(User, User.id == UserTenantRole.user_id)
            .where(UserTenantRole.tenant_id == tenant_id, User.is_active.is_(True))
        )
        or 0
    )
    if active >= max_users:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"The licence allows up to {plural(max_users, 'active user')} in each tenant, and all are in use in this one. {LIMIT_HINT}",
        )
