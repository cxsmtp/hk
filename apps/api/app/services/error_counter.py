"""How many errors Hawk AI met lately, counted across the API and the worker (MZ's diagnostics.recentErrors, which one
process could keep in memory). Every error nobody caught (the API's error handler, a Celery task that failed) adds one
to a per-minute counter in Redis that lives 16 minutes; the self-check (app/services/self_check.py) adds up the last 15.

Counting never gets in the way: without Redis nothing is counted, and nothing fails.
"""

from __future__ import annotations

import os
import time
from typing import Any

KEY_PREFIX = "hawk:errors:"
KEEP_SECONDS = 16 * 60


def _client() -> Any | None:
    # Not in the unit tests' profile (no Redis there): the tests hand in their own counter store.
    if (os.getenv("TEST_PROFILE") or "").strip().lower() == "unit":
        return None
    try:
        from redis import Redis

        from app.core.config import settings

        return Redis.from_url(settings.redis_url, socket_connect_timeout=0.5, socket_timeout=0.5, decode_responses=True)
    except Exception:  # noqa: BLE001
        return None


def note(client: Any | None = None, *, now: float | None = None) -> None:
    """One more error, now."""

    client = client if client is not None else _client()
    if client is None:
        return
    minute = int((time.time() if now is None else now) // 60)
    key = f"{KEY_PREFIX}{minute}"
    try:
        client.incr(key)
        client.expire(key, KEEP_SECONDS)
    except Exception:  # noqa: BLE001 - counting never breaks a request
        return


def recent(client: Any | None = None, *, minutes: int = 15, now: float | None = None) -> int:
    """The errors of the last ``minutes`` minutes (this minute included)."""

    client = client if client is not None else _client()
    if client is None:
        return 0
    minute = int((time.time() if now is None else now) // 60)
    keys = [f"{KEY_PREFIX}{m}" for m in range(minute - minutes + 1, minute + 1)]
    try:
        values = client.mget(keys)
    except Exception:  # noqa: BLE001
        return 0
    total = 0
    for value in values or []:
        try:
            total += int(value or 0)
        except (TypeError, ValueError):
            continue
    return total


__all__ = ["note", "recent"]
