"""The password rule an administrator sets for the whole installation (Settings → Sign-in → Password rule;
/settings/guide/compliance), on top of the fixed one in app/services/passwords.py.

What Dubai's Information Security Regulation (DESC ISR, access control), the UAE IA Standard (T5) and most
customers' own policies ask of passwords, each set in sign_in_policy (migration 0104):

- the shortest length (8 to 64, 12 by default; never under 8);
- how many kinds of character it must mix (0 = any, else 2, 3 or 4 of lower case, upper case, digits and symbols);
- how many earlier passwords may not come back (0 = only the current one; at most 24); their bcrypt hashes are kept
  on the person's row, never the passwords;
- how many days a password lasts (0 = no limit; at most 365): at the next sign-in after that, the person must choose
  a new one before anything else (the same "must change password" step as a generated password).

Single sign-on accounts have no password here and are not touched. The rule is checked wherever a person chooses a
password: first run, the change on one's own account, a reset link, joining, and an administrator adding someone
with a chosen password. Generated temporary passwords (20 characters of letters and digits in groups) meet any rule.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.services.passwords import MIN_PASSWORD_LENGTH, password_problem

MIN_LENGTH_FLOOR = 8
MIN_LENGTH_CEILING = 64
MAX_HISTORY = 24
MAX_AGE_CEILING = 365

#: What the recommended baseline sets (Settings → Compliance → "Apply the recommended baseline"): the values most
#: often asked of a Dubai government entity's systems under the ISR and of UAE IA Standard T5.2 / T5.4 controls.
#: The entity's own information security policy decides in the end; every value can be changed afterwards.
BASELINE = {"minLength": 12, "classes": 3, "history": 5, "maxAgeDays": 90, "sessionIdleMinutes": 15}

CLASS_NAMES = ("lower-case letters", "upper-case letters", "digits", "symbols")


@dataclass(frozen=True)
class Rule:
    min_length: int = MIN_PASSWORD_LENGTH
    classes: int = 0
    history: int = 0
    max_age_days: int = 0

    def view(self) -> dict[str, int]:
        return {"minLength": self.min_length, "classes": self.classes, "history": self.history, "maxAgeDays": self.max_age_days}


def rule(db: Session | None) -> Rule:
    """The rule in force; the fixed defaults when there is no database to ask."""

    if db is None:
        return Rule()
    from app.db.models.access import SignInPolicy
    from app.services import account_security

    row = db.get(SignInPolicy, account_security.POLICY_ID)
    if row is None:
        return Rule()
    return Rule(
        min_length=_clamp(row.password_min_length, MIN_PASSWORD_LENGTH, MIN_LENGTH_FLOOR, MIN_LENGTH_CEILING),
        classes=_clamp(row.password_classes, 0, 0, 4),
        history=_clamp(row.password_history, 0, 0, MAX_HISTORY),
        max_age_days=_clamp(row.password_max_age_days, 0, 0, MAX_AGE_CEILING),
    )


def _clamp(value: Any, default: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def classes_in(password: str) -> int:
    kinds = (
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    )
    return sum(1 for kind in kinds if kind)


def _history(user: Any) -> list[str]:
    try:
        value = json.loads(getattr(user, "password_history", None) or "[]")
    except (TypeError, ValueError):
        return []
    return [str(item) for item in value if isinstance(item, str) and item.startswith("$2")] if isinstance(value, list) else []


def problem(db: Session | None, password: str, *, user: Any = None) -> str:
    """What is wrong with a password someone chose under the rule in force, or "" if nothing."""

    text = str(password or "")
    current = rule(db)
    if len(text) < current.min_length:
        return f"Use at least {current.min_length} characters."
    base = password_problem(text)
    if base and not base.startswith("Use at least"):
        return base
    if current.classes and classes_in(text) < current.classes:
        return f"Mix at least {current.classes} of these: {', '.join(CLASS_NAMES)}."
    if current.history and user is not None:
        from app.core.security import verify_password

        earlier = [str(user.hashed_password or "")] + _history(user)[: current.history - 1]
        if any(h.startswith("$2") and verify_password(text, h) for h in earlier):
            return f"Choose a password you have not used recently (not one of your last {current.history})."
    return ""


def remember(user: Any, new_hash: str, *, now: datetime | None = None) -> None:
    """Set a new password hash on the person: the one it replaces joins their history (at most MAX_HISTORY kept), and
    the password's age starts again."""

    old = str(getattr(user, "hashed_password", "") or "")
    kept = _history(user)
    if old.startswith("$2") and old != new_hash:
        kept = [old, *[h for h in kept if h != old]]
    user.password_history = json.dumps(kept[:MAX_HISTORY])
    user.hashed_password = new_hash
    user.password_changed_at = now or datetime.now(timezone.utc)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def expired(db: Session | None, user: Any, *, now: datetime | None = None) -> bool:
    """Has this person's password lasted longer than the rule allows? Never for an account without a password
    (single sign-on only: its hash starts with "!")."""

    days = rule(db).max_age_days
    hashed = str(getattr(user, "hashed_password", "") or "")
    if not days or not hashed.startswith("$2"):
        return False
    since = _utc(getattr(user, "password_changed_at", None)) or _utc(getattr(user, "created_at", None))
    if since is None:
        return False
    return since + timedelta(days=days) < (now or datetime.now(timezone.utc))


def clean(body: dict[str, Any]) -> tuple[dict[str, int], str]:
    """The rule from Settings → Sign-in: (values, "") or ({}, the sentence to show)."""

    out: dict[str, int] = {}
    limits = {
        "minLength": (MIN_LENGTH_FLOOR, MIN_LENGTH_CEILING, f"The shortest password is between {MIN_LENGTH_FLOOR} and {MIN_LENGTH_CEILING} characters."),
        "classes": (0, 4, "Choose how many kinds of character a password mixes: 0 (any), 2, 3 or 4."),
        "history": (0, MAX_HISTORY, f"Earlier passwords that may not come back: 0 to {MAX_HISTORY}."),
        "maxAgeDays": (0, MAX_AGE_CEILING, f"A password lasts 0 (no limit) to {MAX_AGE_CEILING} days."),
    }
    for key, (low, high, sentence) in limits.items():
        if key not in body:
            continue
        value = body.get(key)
        if isinstance(value, bool) or not re.fullmatch(r"\d{1,4}", str(value if value is not None else "").strip()):
            return {}, sentence
        number = int(str(value).strip())
        if number < low or number > high or (key == "classes" and number == 1):
            return {}, sentence
        out[key] = number
    return out, ""


def describe(current: Rule) -> str:
    """The rule in words, for the sign-in settings and the audit log."""

    parts = [f"at least {current.min_length} characters"]
    if current.classes:
        parts.append(f"{current.classes} of 4 kinds of character")
    if current.history:
        parts.append(f"not one of the last {current.history}")
    parts.append(f"changed every {current.max_age_days} days" if current.max_age_days else "no expiry")
    return "; ".join(parts)
