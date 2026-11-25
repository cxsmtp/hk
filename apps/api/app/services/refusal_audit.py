"""How many refusals from people who are not signed in are written to the audit log, one by one (CxMissionZero
MZ-01.01.10, src/routes/credit-rules.js ``refusalListed``).

Nobody has signed in on these routes, so without a limit anyone who can reach the server could fill the disk with
audit entries. Past the limit for one address, or for everyone, in a minute, the rest are counted, and one entry says
how many were left out when the next minute starts. One count per kind of refusal, so a flood of one kind never hides
another:

- ``unauthenticated``: refused requests from someone not signed in (the first administrator's setup code, …): 10 a
  minute per address, 40 in all;
- ``licence``: refused product activation codes: 10 per address, 40 in all;
- ``sign_in``: refused sign-ins (passwords, two-step codes, password reset requests, single sign-on): 30 per address,
  120 in all.

The counts are per process (each API worker keeps its own), as CxMissionZero's are per server.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

REFUSED_AUDIT_PER_MINUTE = 10


@dataclass(frozen=True)
class Limits:
    per_key: int
    total: int
    what: str


KINDS: dict[str, Limits] = {
    "unauthenticated": Limits(REFUSED_AUDIT_PER_MINUTE, REFUSED_AUDIT_PER_MINUTE * 4, "refused requests from people not signed in"),
    "licence": Limits(REFUSED_AUDIT_PER_MINUTE, REFUSED_AUDIT_PER_MINUTE * 4, "refused product activation codes"),
    "sign_in": Limits(30, 120, "refused sign-ins"),
}


@dataclass
class _State:
    since: float = -1e18
    total: int = 0
    by_key: dict[str, int] = field(default_factory=dict)
    left_out: int = 0


class RefusalsListed:
    """May one more refusal of ``kind`` from ``key`` (an address) be listed in the audit log this minute?"""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.limits = KINDS[kind]
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        self._state = _State()

    # Kept for the licence routes' tests (app/api/routers/licence.py named these before).
    @property
    def left_out(self) -> int:
        return self._state.left_out

    def listed(self, key: str, now_ms: float | None = None) -> tuple[bool, int]:
        """(listed, how many were left out in the minute before, to record now as one entry)."""

        now_ms = time.time() * 1000 if now_ms is None else now_ms
        with self._lock:
            state = self._state
            left_before = 0
            if now_ms - state.since >= 60_000:
                left_before = state.left_out
                self._state = state = _State(since=now_ms)
            seen = state.by_key.get(key, 0)
            if seen >= self.limits.per_key or state.total >= self.limits.total:
                state.left_out += 1
                return False, left_before
            # (The map cannot grow past the total allowed in a minute.)
            state.by_key[key] = seen + 1
            state.total += 1
            return True, left_before

    def left_out_line(self, count: int) -> str:
        return f"{count} more {self.limits.what} in the minute before were not listed one by one (too many at once)."


_listers: dict[str, RefusalsListed] = {}
_listers_lock = threading.Lock()


def lister(kind: str) -> RefusalsListed:
    with _listers_lock:
        if kind not in _listers:
            _listers[kind] = RefusalsListed(kind)
        return _listers[kind]


def reset_all() -> None:
    with _listers_lock:
        for item in _listers.values():
            item.reset()


def may_list(db, kind: str, address: str | None, *, now_ms: float | None = None) -> bool:  # noqa: ANN001 - a Session
    """Whether this refusal is listed in the audit log; when the minute before left some out, one entry says how many
    first (CxMissionZero's refusalListed)."""

    from app.services.audit_service import write_audit_log

    limiter = lister(kind)
    listed, left_before = limiter.listed(f"address {address or 'unknown'}", now_ms)
    if left_before:
        write_audit_log(
            db,
            tenant_id=None,
            actor_user_id=None,
            actor_type="system",
            action=f"audit.refusals_not_listed.{kind}",
            resource_type="audit",
            resource_id=kind,
            payload={"outcome": "refused", "reason": limiter.left_out_line(left_before), "count": left_before},
        )
    return listed
