from __future__ import annotations

import json
import logging
from collections.abc import Callable
from collections import deque
from contextvars import ContextVar, Token
from threading import Lock
from typing import Any

from app.services.privacy_sanitizer import sanitize_privacy_payload


_correlation_id_ctx: ContextVar[str | None] = ContextVar("correlation_id", default=None)

gateway_latency_paths = (
    "/gateway/llm/intercept",
    "/gateway/mcp/authorize",
)
regulated_banking_latency_paths = (
    "/runtime-control/banking-actions/authorize",
    "/runtime-control/banking-actions/pre-execution",
    "/runtime-control/banking-actions/execution",
    "/runtime-control/banking-models/authorize",
    "/runtime-control/banking-models/response",
    "/runtime-control/banking-responses/assure",
)
regulated_banking_transports = (
    "function",
    "mcp",
    "toolbox",
    "rest",
    "openapi",
    "apim",
)
banking_runtime_event_names = frozenset(
    {
        "actions",
        "decisions",
        "blocked",
        "approvals",
        "policy_errors",
        "subject_violations",
        "target_violations",
        "action_drift",
        "response_mismatches",
        "receipt_failures",
        "selector_failures",
        "coverage_degradation",
        "enforcements",
    }
)


def set_correlation_id(correlation_id: str | None) -> Token[str | None]:
    return _correlation_id_ctx.set(correlation_id)


def reset_correlation_id(token: Token[str | None]) -> None:
    _correlation_id_ctx.reset(token)


def get_correlation_id() -> str | None:
    return _correlation_id_ctx.get()


class RequestLatencyTracker:
    def __init__(self, *, max_samples_per_path: int = 4096) -> None:
        self._max_samples_per_path = max_samples_per_path
        self._lock = Lock()
        self._samples: dict[str, deque[float]] = {}

    def observe(self, path: str, latency_ms: float) -> None:
        with self._lock:
            bucket = self._samples.get(path)
            if bucket is None:
                bucket = deque(maxlen=self._max_samples_per_path)
                self._samples[path] = bucket
            bucket.append(float(latency_ms))

    def _percentile(self, values: list[float], percentile: float) -> float | None:
        if not values:
            return None
        sorted_values = sorted(values)
        if len(sorted_values) == 1:
            return round(sorted_values[0], 4)
        rank = max(0.0, min(1.0, percentile)) * (len(sorted_values) - 1)
        lo = int(rank)
        hi = min(lo + 1, len(sorted_values) - 1)
        if lo == hi:
            return round(sorted_values[lo], 4)
        weight = rank - lo
        value = sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * weight
        return round(value, 4)

    def summary_for_path(self, path: str) -> dict[str, Any]:
        with self._lock:
            values = list(self._samples.get(path, []))
        return {
            "count": len(values),
            "p50_ms": self._percentile(values, 0.50),
            "p95_ms": self._percentile(values, 0.95),
            "p99_ms": self._percentile(values, 0.99),
        }

    def gateway_summary(self) -> dict[str, Any]:
        return {path: self.summary_for_path(path) for path in gateway_latency_paths}

    def reset(self) -> None:
        with self._lock:
            self._samples.clear()


class OutcomeLatencyTracker:
    """Bounded in-process latency telemetry including failure and timeout outcomes."""

    def __init__(self, *, max_samples_per_path: int = 4096) -> None:
        self._max_samples_per_path = max_samples_per_path
        self._lock = Lock()
        self._samples: dict[str, deque[tuple[float, int]]] = {}

    def observe(self, path: str, latency_ms: float, *, status_code: int) -> None:
        with self._lock:
            bucket = self._samples.get(path)
            if bucket is None:
                bucket = deque(maxlen=self._max_samples_per_path)
                self._samples[path] = bucket
            bucket.append((float(latency_ms), int(status_code)))

    @staticmethod
    def _percentile(values: list[float], percentile: float) -> float | None:
        if not values:
            return None
        ordered = sorted(values)
        if len(ordered) == 1:
            return round(ordered[0], 4)
        rank = max(0.0, min(1.0, percentile)) * (len(ordered) - 1)
        lower = int(rank)
        upper = min(lower + 1, len(ordered) - 1)
        weight = rank - lower
        return round(ordered[lower] + (ordered[upper] - ordered[lower]) * weight, 4)

    def summary_for_path(self, path: str) -> dict[str, Any]:
        with self._lock:
            samples = list(self._samples.get(path, []))
        values = [latency for latency, _status in samples]
        failures = sum(status >= 400 for _latency, status in samples)
        return {
            "count": len(samples),
            "p50_ms": self._percentile(values, 0.50),
            "p95_ms": self._percentile(values, 0.95),
            "p99_ms": self._percentile(values, 0.99),
            "max_ms": round(max(values), 4) if values else None,
            "error_rate": round(failures / len(samples), 6) if samples else 0.0,
            "timeout_count": sum(
                status in {408, 504} for _latency, status in samples
            ),
        }

    def summary_for_paths(self, paths: tuple[str, ...]) -> dict[str, dict[str, Any]]:
        return {path: self.summary_for_path(path) for path in paths}

    def reset(self) -> None:
        with self._lock:
            self._samples.clear()


class BankingRuntimeMetrics:
    """Tenant-scoped bounded rates and latency for regulated runtime operations."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] | None = None,
        max_events_per_metric: int = 16_384,
        max_latency_samples_per_path: int = 4096,
    ) -> None:
        import time

        self._clock = clock or time.monotonic
        self._max_events_per_metric = max_events_per_metric
        self._max_latency_samples_per_path = max_latency_samples_per_path
        self._lock = Lock()
        self._events: dict[str, dict[str, deque[float]]] = {}
        self._latencies: dict[str, OutcomeLatencyTracker] = {}
        self._transport_latencies: dict[str, OutcomeLatencyTracker] = {}

    @staticmethod
    def _tenant_key(tenant_id: str) -> str:
        token = str(tenant_id or "").strip()
        if not token or len(token) > 64:
            raise ValueError("banking metrics tenant is invalid")
        return token

    def increment(
        self,
        tenant_id: str,
        event_name: str,
        *,
        occurred_at: float | None = None,
    ) -> None:
        tenant = self._tenant_key(tenant_id)
        if event_name not in banking_runtime_event_names:
            raise ValueError("banking runtime metric is invalid")
        when = float(self._clock() if occurred_at is None else occurred_at)
        with self._lock:
            tenant_events = self._events.setdefault(tenant, {})
            bucket = tenant_events.get(event_name)
            if bucket is None:
                bucket = deque(maxlen=self._max_events_per_metric)
                tenant_events[event_name] = bucket
            bucket.append(when)

    def observe_latency(
        self,
        tenant_id: str,
        path: str,
        latency_ms: float,
        *,
        status_code: int,
    ) -> None:
        tenant = self._tenant_key(tenant_id)
        if path not in regulated_banking_latency_paths:
            raise ValueError("banking runtime latency path is invalid")
        with self._lock:
            tracker = self._latencies.get(tenant)
            if tracker is None:
                tracker = OutcomeLatencyTracker(
                    max_samples_per_path=self._max_latency_samples_per_path
                )
                self._latencies[tenant] = tracker
        tracker.observe(path, latency_ms, status_code=status_code)

    def observe_transport_latency(
        self,
        tenant_id: str,
        transport: str,
        latency_ms: float,
        *,
        status_code: int,
    ) -> None:
        tenant = self._tenant_key(tenant_id)
        if transport not in regulated_banking_transports:
            raise ValueError("banking runtime transport is invalid")
        with self._lock:
            tracker = self._transport_latencies.get(tenant)
            if tracker is None:
                tracker = OutcomeLatencyTracker(
                    max_samples_per_path=self._max_latency_samples_per_path
                )
                self._transport_latencies[tenant] = tracker
        tracker.observe(transport, latency_ms, status_code=status_code)

    def snapshot(
        self,
        tenant_id: str,
        *,
        window_seconds: int = 60,
    ) -> dict[str, Any]:
        tenant = self._tenant_key(tenant_id)
        if window_seconds < 1 or window_seconds > 3600:
            raise ValueError("banking metrics window is invalid")
        now = float(self._clock())
        cutoff = now - window_seconds
        with self._lock:
            tenant_events = self._events.setdefault(tenant, {})
            counts: dict[str, int] = {}
            for event_name in sorted(banking_runtime_event_names):
                bucket = tenant_events.get(event_name)
                if bucket is None:
                    bucket = deque(maxlen=self._max_events_per_metric)
                    tenant_events[event_name] = bucket
                while bucket and bucket[0] < cutoff:
                    bucket.popleft()
                counts[event_name] = len(bucket)
            tracker = self._latencies.get(tenant)
            transport_tracker = self._transport_latencies.get(tenant)
        if tracker is None:
            tracker = OutcomeLatencyTracker(
                max_samples_per_path=self._max_latency_samples_per_path
            )
        if transport_tracker is None:
            transport_tracker = OutcomeLatencyTracker(
                max_samples_per_path=self._max_latency_samples_per_path
            )
        decision_count = counts["decisions"]
        return {
            "window_seconds": window_seconds,
            "actions_per_second": round(counts["actions"] / window_seconds, 6),
            "decisions_per_second": round(
                counts["decisions"] / window_seconds, 6
            ),
            "blocked_per_second": round(counts["blocked"] / window_seconds, 6),
            "approval_rate": round(
                counts["approvals"] / decision_count, 6
            )
            if decision_count
            else 0.0,
            "event_counts": counts,
            "latency": tracker.summary_for_paths(regulated_banking_latency_paths),
            "transport_latency": transport_tracker.summary_for_paths(
                regulated_banking_transports
            ),
        }

    def reset(self, tenant_id: str | None = None) -> None:
        with self._lock:
            if tenant_id is None:
                self._events.clear()
                self._latencies.clear()
                self._transport_latencies.clear()
                return
            tenant = self._tenant_key(tenant_id)
            self._events.pop(tenant, None)
            self._latencies.pop(tenant, None)
            self._transport_latencies.pop(tenant, None)


latency_tracker = RequestLatencyTracker()
banking_runtime_metrics = BankingRuntimeMetrics()
request_logger = logging.getLogger("app.request")


def log_structured(event: str, **fields: Any) -> None:
    correlation_id = fields.get("correlation_id") or get_correlation_id()
    payload = sanitize_privacy_payload({"event": event, **fields})
    if correlation_id:
        payload["correlation_id"] = correlation_id
    level = fields.get("level")
    emitters = {
        "debug": request_logger.debug,
        "info": request_logger.info,
        "warning": request_logger.warning,
        "error": request_logger.error,
        "critical": request_logger.critical,
    }
    emitter = emitters.get(level, request_logger.info) if isinstance(level, str) else request_logger.info
    emitter(json.dumps(payload, default=str))
