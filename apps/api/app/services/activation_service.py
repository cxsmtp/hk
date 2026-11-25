"""Activation codes and the product licence (docs/activation-codes.md).

Ported from CxMissionZero's src/activation.js, with the same behaviour, messages and protections.

The product licence: Hawk AI works until the end of 31 January 2027 (UTC). After that every request is refused
with the message that it has been deactivated, until a product activation code from the maintainer is entered;
the code says until when it works. Data is never deleted.

Several tenants: without a tenants activation code Hawk AI serves one tenant, with no cap on its users. A tenants
code names the organisation, how many tenants it may have (``maxTenants``) and, optionally, how many active users
each tenant may have (``maxUsers``). Tenants and users already there are never removed or disabled.

A code is ``HK1.<payload>.<signature>`` (base64url): the payload is JSON
``{ v: 1, id, org, scope, action?, maxTenants?, maxUsers?, issued, expires }``, signed with the maintainer's
Ed25519 key; the public half is ISSUER_KEYS below. The signed head includes the prefix, so a CxMissionZero code
(``MZ1``) never works here. Codes are made with tools/licensing/activation.py. A code is checked here, offline:
nothing is sent anywhere.

What is kept of an accepted code is the signed code itself, and it is checked again each time it is read: a date
changed by hand in the database counts for nothing.
"""

from __future__ import annotations

import base64
import binascii
import copy
import json
import logging
import math
import os
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
from app.db.session import SessionLocal


logger = logging.getLogger(__name__)

#: The maintainer's public key(s), base64 SPKI DER. Empty: no code is valid yet.
ISSUER_KEYS: list[str] = [
    "MCowBQYDK2VwAyEAlWEwF9lhzKv0IZ1GaDJSmlJqaZd7Gc1JqvYju52uKo4=",
]

PREFIX = "HK1"
DAY_MS = 24 * 60 * 60 * 1000
HOUR_MS = 60 * 60 * 1000
#: Admins are told this long before a code expires.
WARN_DAYS = 30

#: Without a product activation code, Hawk AI works until this moment: the end of 31 January 2027, UTC.
PRODUCT_DEADLINE = "2027-02-01T00:00:00.000Z"
#: What every request is answered with once it has stopped.
DEACTIVATED_MESSAGE = "The product has been deactivated. Please reach out to Bhawani Singh."

#: How many history entries are kept.
HISTORY_LIMIT = 50
#: The one row of activation_state.
STATE_ROW_ID = 1

#: What a code may unlock. "product" keeps Hawk AI working until the code's date; "tenants" allows several tenants
#: (and, optionally, caps the active users in each). A held-back feature would be a "feature:<name>" scope, named in
#: FEATURES; there are none yet.
SCOPES = frozenset({"tenants", "product"})
FEATURES: frozenset[str] = frozenset()
#: For a feature scope, whether the code turns it on or off.
ACTIONS = frozenset({"activate", "deactivate"})

#: Without a tenants code in force: one tenant, and no cap on its users.
DEFAULT_MAX_TENANTS = 1

#: The test key is trusted only under pytest, and never in production (see trusted_keys()).
TEST_KEY_ENV = "HAWK_ACTIVATION_TEST_KEY"


# ---- Small helpers, so the dates and numbers behave as they do in CxMissionZero -------------------------------


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


def _fail(reason: str) -> dict[str, Any]:
    return {"valid": False, "reason": reason}


def _production() -> bool:
    env = str(settings.env or "").strip().lower()
    return env in {"prod", "production"} or settings.deployment_topology == "single_node_compose"


def _release() -> bool:
    from app.services.integrity.service import is_release

    return is_release()


def trusted_keys() -> list[str]:
    """The issuer keys this process trusts: ISSUER_KEYS, and a test key only while pytest runs a test outside
    production (never in production, where it would let anyone sign their own codes)."""
    keys = list(ISSUER_KEYS)
    test_key = os.environ.get(TEST_KEY_ENV)
    # A release image carries the list of its files (integrity.json, app/services/integrity/manifest.py); a development
    # copy does not. A release never trusts the test key, whatever its settings (CxMissionZero's RELEASE).
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


# ---- Codes ------------------------------------------------------------------------------------------------------


def read_code(code: Any) -> dict[str, Any] | None:
    """Read a code without trusting it: {payload, signed, signature}, or None."""
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


def _scope_known(scope: str) -> bool:
    return scope in SCOPES or (scope.startswith("feature:") and scope[len("feature:"):] in FEATURES)


def check_code(code: Any, *, now: float | None = None, keys: list[str] | None = None) -> dict[str, Any]:
    """Check a code: signed by a trusted key, well formed, not expired.

    Returns {valid, reason?, expired?, id, org, scope, action, maxTenants, maxUsers, issued, expires, daysLeft,
    warn, code}. ``scope`` defaults to "tenants" (as in CxMissionZero). A product code only activates.
    """
    now = now_ms() if now is None else now
    keys = trusted_keys() if keys is None else list(keys)
    read = read_code(code)
    if not read:
        return _fail("This is not an activation code.")
    if not keys:
        return _fail("This installation has no activation key to check codes with.")
    if not any(_signed_by(key, read["signed"], read["signature"]) for key in keys):
        return _fail("This activation code is not valid.")
    p = read["payload"]
    if not isinstance(p, dict):
        return _fail("This activation code is not valid.")
    scope = _text(p.get("scope"), "tenants")
    expires = parse_ms(p.get("expires"))
    version = p.get("v")
    base = (
        _is_int(version)
        and version == 1
        and bool(p.get("id"))
        and bool(p.get("org"))
        and _scope_known(scope)
        and expires is not None
    )
    max_users = p.get("maxUsers")
    for_tenants = (
        scope == "tenants"
        and _is_int(p.get("maxTenants"))
        and p["maxTenants"] >= 1
        and (max_users is None or (_is_int(max_users) and max_users >= 1))
    )
    action = _text(p.get("action"))
    # A product code only activates: until its date, Hawk AI works.
    for_flag = (scope.startswith("feature:") and action in ACTIONS) or (scope == "product" and action == "activate")
    if not base or not (for_tenants or for_flag):
        return _fail("This activation code is not valid.")
    days_left = math.ceil((expires - now) / DAY_MS)
    info: dict[str, Any] = {
        "id": _text(p["id"]),
        "org": _text(p["org"]),
        "scope": scope,
        "action": action if for_flag else "",
        "maxTenants": int(p["maxTenants"]) if for_tenants else 0,
        "maxUsers": int(max_users) if for_tenants and max_users is not None else None,
        "issued": _text(p.get("issued")),
        "expires": iso(expires),
        "daysLeft": days_left,
        # The signed code itself: what the store keeps, and checks again whenever it is read.
        "code": _text(code).strip(),
    }
    if expires <= now:
        return {**info, "valid": False, "expired": True, "reason": f"This activation code expired on {info['expires'][:10]}."}
    return {**info, "valid": True, "warn": days_left <= WARN_DAYS}


# ---- The store --------------------------------------------------------------------------------------------------


class ActivationStore:
    """The activation codes accepted on this installation: what they unlock, for whom, until when, and the history
    of what was entered. ``save`` keeps the state (the activation_state row); ``keys`` are the keys kept codes are
    checked with (the trusted ones unless given)."""

    def __init__(
        self,
        state: dict[str, Any] | None = None,
        *,
        keys: list[str] | None = None,
        save: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        raw = copy.deepcopy(state) if isinstance(state, dict) else {}
        history = raw.get("history")
        self._state: dict[str, Any] = {
            "tenants": raw.get("tenants"),
            "product": raw.get("product"),
            "seenAt": _text(raw.get("seenAt")),
            "history": history if isinstance(history, list) else [],
        }
        self._keys = keys
        self._save_state = save
        self._sealed: dict[str, Any] = {"tenants": None, "product": None}
        self._seal()

    @property
    def state(self) -> dict[str, Any]:
        return copy.deepcopy(self._state)

    def _check_kept(self, code: Any) -> dict[str, Any]:
        # now: 0, so an expired code still reads (its date then says it is over).
        return check_code(code, now=0, keys=self._keys)

    def _seal(self) -> None:
        """Each kept entry as its signed code says it: the scope, the action, the date and the limits are read from
        the code, not from what is kept beside it. An entry whose code does not verify (edited, or from another
        key), or that has no code, counts for nothing."""

        def sealed(entry: Any, scope: str) -> dict[str, Any] | None:
            if not isinstance(entry, dict) or not entry.get("code"):
                return None
            checked = self._check_kept(entry["code"])
            if not checked["valid"] or checked["scope"] != scope:
                return None
            out = {**entry, "org": checked["org"], "action": checked["action"] or "activate", "expires": checked["expires"]}
            if scope == "tenants":
                out["maxTenants"] = checked["maxTenants"]
                out["maxUsers"] = checked["maxUsers"]
            return out

        self._sealed = {
            "tenants": sealed(self._state["tenants"], "tenants"),
            "product": sealed(self._state["product"], "product"),
        }

    def _save(self) -> None:
        if self._save_state is not None:
            self._save_state(copy.deepcopy(self._state))

    def refusal(self, result: dict[str, Any], *, must_extend: bool = False) -> str:
        """Why a code that checks out must still not replace the one in force for its scope ('' when it may): codes
        are not tied to one installation, so an older one, still in date, could be entered again to undo a later
        one (to cut the product's date short).
        - Issued before the code in force: never.
        - ``must_extend`` (the deactivation page, open to everyone): only a code that ends later than the one in force.
        """
        scope = _text((result or {}).get("scope"))
        entry = self._state["tenants"] if scope == "tenants" else self._state["product"] if scope == "product" else None
        if not isinstance(entry, dict) or not entry.get("code"):
            return ""
        current = self._check_kept(entry["code"])
        if not current["valid"] or current["scope"] != scope:
            return ""
        issued = parse_ms(result.get("issued"))
        issued_before = parse_ms(current["issued"])
        if issued is not None and issued_before is not None and issued < issued_before:
            return f"This activation code was issued before the one in force (issued {current['issued'][:10]}): ask for a new one."
        if must_extend and current["action"] != "deactivate":
            ends = parse_ms(result.get("expires"))
            ends_now = parse_ms(current["expires"])
            if ends is None or ends_now is None or ends <= ends_now:
                return f"An activation code that runs until {current['expires'][:10]} is already in force: this one does not run longer."
        return ""

    def record(self, result: dict[str, Any], by: Any = "") -> dict[str, Any]:
        """Record an accepted code (the result of check_code) and who entered it."""
        entry = {
            "id": result["id"],
            "org": result["org"],
            "scope": result["scope"],
            "action": result.get("action") or "activate",
            "expires": result["expires"],
            "at": iso(now_ms()),
            "by": _text(by),
        }
        # Kept with the signed code, so what it says can be checked again and never taken from what is kept alone.
        kept = {**entry, **({"code": result["code"]} if result.get("code") else {})}
        if result["scope"] == "tenants":
            self._state["tenants"] = {**kept, "maxTenants": result["maxTenants"], "maxUsers": result.get("maxUsers")}
        if result["scope"] == "product":
            self._state["product"] = kept
        self._state["history"] = [entry, *self._state["history"]][:HISTORY_LIMIT]
        self._save()
        self._seal()
        return entry

    def tenants(self, now: float | None = None) -> dict[str, Any] | None:
        """The tenants activation in force: {org, maxTenants, maxUsers, expires, at, by, daysLeft, valid, warn}."""
        now = now_ms() if now is None else now
        t = self._sealed["tenants"]
        if not t:
            return None
        days_left = math.ceil(((parse_ms(t["expires"]) or 0) - now) / DAY_MS)
        return {
            "org": t["org"],
            "maxTenants": t["maxTenants"],
            "maxUsers": t["maxUsers"],
            "expires": t["expires"],
            "at": t.get("at"),
            "by": t.get("by"),
            "daysLeft": days_left,
            "valid": days_left > 0,
            "warn": 0 < days_left <= WARN_DAYS,
        }

    def history(self) -> list[dict[str, Any]]:
        return [dict(h) if isinstance(h, dict) else h for h in self._state["history"]]

    def now(self, now: float | None = None) -> float:
        """The time the licence goes by: never earlier than the latest it has seen (kept, at most hourly), so setting
        the server's clock back does not undo the end date."""
        now = now_ms() if now is None else now
        seen = parse_ms(self._state["seenAt"]) or 0
        if now > seen + HOUR_MS:
            self._state["seenAt"] = iso(now)
            try:
                self._save()
            except Exception:  # noqa: BLE001 - the clock still holds in memory; it is kept next time.
                logger.debug("activation_seen_at_not_saved", exc_info=True)
        return max(now, seen)

    def product(self, now: float | None = None) -> dict[str, Any]:
        """Whether Hawk AI may work: until the end of 31 January 2027 (UTC), or a product code's date if later.
        {active, until, daysLeft, warn, activation: {org, expires, at} | None, message}."""
        t = self.now(now)
        code = self._sealed["product"]
        coded = (parse_ms(code["expires"]) or 0) if code and code.get("action") == "activate" else 0
        until = max(parse_ms(PRODUCT_DEADLINE) or 0, coded)
        active = t < until
        days_left = math.ceil((until - t) / DAY_MS)
        return {
            "active": active,
            "until": iso(until),
            "daysLeft": days_left,
            "warn": active and days_left <= WARN_DAYS,
            "activation": {"org": code["org"], "expires": code["expires"], "at": code.get("at")} if code else None,
            "message": "" if active else DEACTIVATED_MESSAGE,
        }


# ---- Kept in the database ---------------------------------------------------------------------------------------

#: Where the licence gate and the background tasks read the state from (a session factory). Tests point it at
#: their own database.
licence_session_factory: Callable[[], Session] = SessionLocal


def load_store(db: Session, *, for_update: bool = False, commit: bool = False) -> ActivationStore:
    """The store as kept in the activation_state row of ``db``. What it saves is flushed to ``db`` (committed too
    with ``commit``); ``for_update`` locks the row until the transaction ends, for a code being recorded."""
    statement = select(ActivationState).where(ActivationState.id == STATE_ROW_ID)
    if for_update:
        statement = statement.with_for_update()
    row = db.scalar(statement)

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

    return ActivationStore(row.state if row is not None else None, save=save)


def read_product(now: float | None = None) -> dict[str, Any]:
    """The product licence as every process sees it. If the state cannot be read, the built-in date still applies
    (a code can then only be missing, never added)."""
    try:
        with licence_session_factory() as db:
            return load_store(db, commit=True).product(now)
    except Exception:  # noqa: BLE001
        logger.debug("activation_state_unreadable", exc_info=True)
        return ActivationStore(None).product(now)


def licence_active(now: float | None = None) -> bool:
    return bool(read_product(now)["active"])


def licence_for_admins(db: Session) -> dict[str, Any]:
    """The product licence's end, for the admins' banner in the last 30 days: {until, daysLeft, warn, activation}."""
    product = load_store(db).product()
    return {key: product[key] for key in ("until", "daysLeft", "warn", "activation")}


# ---- Several tenants, and the active users in each ----------------------------------------------------------------

LIMIT_HINT = "Apply a new tenants activation code under Settings → Activation codes."


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def tenant_limits(db: Session, now: float | None = None) -> tuple[int, int | None]:
    """(maxTenants, maxUsers) in force: a tenants code in date, or one tenant and no cap on users."""
    tenants = load_store(db).tenants(now)
    if tenants and tenants["valid"]:
        return int(tenants["maxTenants"]), tenants["maxUsers"]
    return DEFAULT_MAX_TENANTS, None


def assert_may_add_tenant(db: Session) -> None:
    """Refuse (403) a tenant created or activated beyond what the tenants code allows. Nothing already there is
    removed or disabled."""
    tenants = load_store(db).tenants()
    in_force = bool(tenants and tenants["valid"])
    max_tenants = int(tenants["maxTenants"]) if in_force else DEFAULT_MAX_TENANTS
    active = int(db.scalar(select(func.count()).select_from(Tenant).where(Tenant.is_active.is_(True))) or 0)
    if active < max_tenants:
        return
    if in_force:
        detail = f"The activation code allows up to {_plural(max_tenants, 'tenant')}, and all are in use. {LIMIT_HINT}"
    else:
        detail = "Without a tenants activation code Hawk AI serves 1 tenant, and it is in use. Apply a tenants activation code under Settings → Activation codes."
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def assert_may_add_member(db: Session, tenant_id: str) -> None:
    """Refuse (403) a user added to, or activated in, a tenant that already has the active users the tenants code
    allows. Nothing already there is removed or disabled."""
    _, max_users = tenant_limits(db)
    if max_users is None:
        return
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
            detail=f"The activation code allows up to {_plural(max_users, 'active user')} in each tenant, and all are in use in this one. {LIMIT_HINT}",
        )
