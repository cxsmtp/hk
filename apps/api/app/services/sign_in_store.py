"""Short-lived sign-in state shared by every API process (docs/sign-in.md).

CxMissionZero keeps its two-step tickets, pending two-step setups, password reset links and sign-in limits in the
memory of its one process (src/mfa.js, src/password-reset.js, src/routes/session.js). Hawk runs several API
processes, so they are kept in Redis (REDIS_URL), each with its time to live, as the existing OIDC state is
(app/services/oidc_auth_service.py). SIGN_IN_STORE=memory keeps them in this process instead: for unit tests and a
single local process only. A restart of a Redis without persistence ends every ticket and link, as a restart of
CxMissionZero does.

Only hashes of the secrets are used as keys (a ticket's or a link's SHA-256): the store never holds a working ticket
or link. A two-step secret waiting for its first code is encrypted (app/services/connector_secret_service.py).
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Protocol

from app.core.config import settings


class StoreUnavailable(RuntimeError):
    """Redis could not be reached: sign-in steps that need it are refused (never let through)."""


class SignInStore(Protocol):
    def put(self, key: str, value: dict[str, Any], ttl_seconds: float) -> None: ...

    def get(self, key: str) -> dict[str, Any] | None: ...

    def take(self, key: str) -> dict[str, Any] | None: ...

    def delete(self, key: str) -> None: ...

    def incr(self, key: str, ttl_seconds: float) -> int: ...

    def hit(self, key: str, window_seconds: float, now: float) -> int: ...

    def count(self, key: str, window_seconds: float, now: float) -> int: ...

    def times(self, key: str, window_seconds: float, now: float) -> list[float]: ...

    def clear(self) -> None: ...


class MemoryStore:
    """One process: a dict with expiry times. Sliding windows are lists of times."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: dict[str, tuple[float, Any]] = {}
        self._windows: dict[str, list[float]] = {}

    def _live(self, key: str) -> Any | None:
        entry = self._values.get(key)
        if entry is None:
            return None
        if entry[0] <= time.monotonic():
            self._values.pop(key, None)
            return None
        return entry[1]

    def put(self, key: str, value: dict[str, Any], ttl_seconds: float) -> None:
        with self._lock:
            self._values[key] = (time.monotonic() + max(0.001, ttl_seconds), json.dumps(value))
            if len(self._values) > 50_000:
                now = time.monotonic()
                for name in [k for k, (exp, _) in self._values.items() if exp <= now]:
                    self._values.pop(name, None)

    def get(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            raw = self._live(key)
        return json.loads(raw) if isinstance(raw, str) else None

    def take(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            raw = self._live(key)
            self._values.pop(key, None)
        return json.loads(raw) if isinstance(raw, str) else None

    def delete(self, key: str) -> None:
        with self._lock:
            self._values.pop(key, None)
            self._windows.pop(key, None)

    def incr(self, key: str, ttl_seconds: float) -> int:
        with self._lock:
            current = self._live(key)
            value = int(current or 0) + 1
            expires = self._values[key][0] if current is not None else time.monotonic() + max(0.001, ttl_seconds)
            self._values[key] = (expires, value)
            return value

    def hit(self, key: str, window_seconds: float, now: float) -> int:
        with self._lock:
            recent = [t for t in self._windows.get(key, []) if now - t < window_seconds]
            recent.append(now)
            # Re-inserted, so the map stays in order of last use; addresses long quiet are forgotten first, never all.
            self._windows.pop(key, None)
            self._windows[key] = recent
            if len(self._windows) > 10_000:
                for name in [k for k, times in self._windows.items() if not any(now - t < window_seconds for t in times)]:
                    self._windows.pop(name, None)
            return len(recent)

    def count(self, key: str, window_seconds: float, now: float) -> int:
        return len(self.times(key, window_seconds, now))

    def times(self, key: str, window_seconds: float, now: float) -> list[float]:
        with self._lock:
            return [t for t in self._windows.get(key, []) if now - t < window_seconds]

    def clear(self) -> None:
        with self._lock:
            self._values.clear()
            self._windows.clear()


class RedisStore:
    """Every API process: Redis keys with a time to live; windows are sorted sets of times."""

    PREFIX = "hawk:signin:"

    def __init__(self, url: str) -> None:
        self._url = url
        self._client: Any = None

    def _redis(self) -> Any:
        if self._client is None:
            from redis import Redis

            self._client = Redis.from_url(self._url, socket_connect_timeout=0.5, socket_timeout=0.5, decode_responses=True)
        return self._client

    def _call(self, fn):  # type: ignore[no-untyped-def]
        try:
            return fn(self._redis())
        except Exception as exc:  # noqa: BLE001 - any Redis failure: the step is refused
            raise StoreUnavailable("The sign-in store (Redis) cannot be reached.") from exc

    def put(self, key: str, value: dict[str, Any], ttl_seconds: float) -> None:
        self._call(lambda r: r.set(self.PREFIX + key, json.dumps(value), px=max(1, int(ttl_seconds * 1000))))

    def get(self, key: str) -> dict[str, Any] | None:
        raw = self._call(lambda r: r.get(self.PREFIX + key))
        return json.loads(raw) if raw else None

    def take(self, key: str) -> dict[str, Any] | None:
        raw = self._call(lambda r: r.getdel(self.PREFIX + key))
        return json.loads(raw) if raw else None

    def delete(self, key: str) -> None:
        self._call(lambda r: r.delete(self.PREFIX + key))

    def incr(self, key: str, ttl_seconds: float) -> int:
        def run(r: Any) -> int:
            pipe = r.pipeline()
            pipe.incr(self.PREFIX + key)
            pipe.pexpire(self.PREFIX + key, max(1, int(ttl_seconds * 1000)), nx=True)
            return int(pipe.execute()[0])

        return self._call(run)

    def hit(self, key: str, window_seconds: float, now: float) -> int:
        def run(r: Any) -> int:
            name = self.PREFIX + key
            pipe = r.pipeline()
            pipe.zremrangebyscore(name, "-inf", now - window_seconds)
            pipe.zadd(name, {f"{now:.6f}:{time.monotonic_ns()}": now})
            pipe.zcard(name)
            pipe.expire(name, int(window_seconds) + 1)
            return int(pipe.execute()[2])

        return self._call(run)

    def count(self, key: str, window_seconds: float, now: float) -> int:
        return len(self.times(key, window_seconds, now))

    def times(self, key: str, window_seconds: float, now: float) -> list[float]:
        rows = self._call(lambda r: r.zrangebyscore(self.PREFIX + key, now - window_seconds + 1e-6, "+inf", withscores=True))
        return sorted(float(score) for _, score in rows)

    def clear(self) -> None:  # tests only
        def run(r: Any) -> None:
            for name in r.scan_iter(self.PREFIX + "*"):
                r.delete(name)

        self._call(run)


def now() -> float:
    """The sign-in clock, in seconds since the epoch. Every sign-in rule reads it here, so tests can move it."""

    return time.time()


_store: SignInStore | None = None
_store_lock = threading.Lock()


def store() -> SignInStore:
    global _store
    with _store_lock:
        if _store is None:
            kind = str(settings.sign_in_store or "redis").strip().lower()
            _store = MemoryStore() if kind == "memory" else RedisStore(settings.redis_url)
        return _store


def use(replacement: SignInStore | None) -> None:
    """Tests: put another store in place (None: back to the configured one at the next call)."""

    global _store
    with _store_lock:
        _store = replacement
