from __future__ import annotations

import time
from collections import deque
from threading import Lock


class TenantRateLimiter:
    def __init__(self) -> None:
        self._lock = Lock()
        self._events: dict[tuple[str, str], deque[float]] = {}

    def check_and_consume(
        self,
        *,
        route_key: str,
        tenant_id: str,
        qps_limit: int,
        window_seconds: float = 1.0,
    ) -> tuple[bool, float]:
        if qps_limit <= 0:
            return True, 0.0

        now = time.monotonic()
        key = (route_key, tenant_id)
        with self._lock:
            bucket = self._events.get(key)
            if bucket is None:
                bucket = deque()
                self._events[key] = bucket

            cutoff = now - max(0.001, window_seconds)
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= qps_limit:
                retry_after = max(0.0, window_seconds - (now - bucket[0]))
                return False, round(retry_after, 4)

            bucket.append(now)
            return True, 0.0

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


tenant_rate_limiter = TenantRateLimiter()
