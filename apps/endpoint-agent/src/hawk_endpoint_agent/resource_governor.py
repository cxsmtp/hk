"""Balanced endpoint resource budget and ordered degradation."""

from __future__ import annotations

import platform
import resource
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ResourceBudget:
    idle_rss_mb: float = 100.0
    active_rss_mb: float = 200.0
    idle_cpu_percent: float = 1.0
    active_cpu_percent: float = 5.0


@dataclass(frozen=True)
class ResourceSample:
    rss_mb: float
    cpu_percent: float
    active: bool


@dataclass(frozen=True)
class ResourceState:
    health: str
    sample: ResourceSample
    budget: ResourceBudget
    disabled_capabilities: list[str]
    reasons: list[str]
    cooldown_remaining_seconds: float = 0.0

    def as_dict(self) -> dict[str, object]:
        return {
            "health": self.health,
            "sample": asdict(self.sample),
            "budget": asdict(self.budget),
            "disabled_capabilities": list(self.disabled_capabilities),
            "reasons": list(self.reasons),
            "cooldown_remaining_seconds": self.cooldown_remaining_seconds,
        }


class ResourceGovernor:
    def __init__(
        self,
        budget: ResourceBudget | None = None,
        *,
        passive_discovery_cooldown_seconds: float = 60.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.budget = budget or ResourceBudget()
        self._monotonic = monotonic
        self._cooldown_seconds = max(0.0, float(passive_discovery_cooldown_seconds))
        self._passive_discovery_disabled_until = 0.0
        self._last_wall = self._monotonic()
        self._last_cpu = time.process_time()

    def sample(self, *, active: bool) -> ResourceSample:
        now_wall = self._monotonic()
        now_cpu = time.process_time()
        wall_delta = max(0.001, now_wall - self._last_wall)
        cpu_delta = max(0.0, now_cpu - self._last_cpu)
        self._last_wall = now_wall
        self._last_cpu = now_cpu
        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        rss_mb = usage / (1024 * 1024) if platform.system() == "Darwin" else usage / 1024
        return ResourceSample(
            rss_mb=round(rss_mb, 3),
            cpu_percent=round((cpu_delta / wall_delta) * 100, 3),
            active=bool(active),
        )

    def evaluate(self, sample: ResourceSample) -> ResourceState:
        now = self._monotonic()
        rss_limit = self.budget.active_rss_mb if sample.active else self.budget.idle_rss_mb
        cpu_limit = self.budget.active_cpu_percent if sample.active else self.budget.idle_cpu_percent
        reasons: list[str] = []
        if sample.rss_mb > rss_limit:
            reasons.append("rss_budget_exceeded")
        if sample.cpu_percent > cpu_limit:
            reasons.append("cpu_budget_exceeded")

        if reasons:
            self._passive_discovery_disabled_until = max(
                self._passive_discovery_disabled_until,
                now + self._cooldown_seconds,
            )
            ratio = max(
                sample.rss_mb / max(rss_limit, 0.001),
                sample.cpu_percent / max(cpu_limit, 0.001),
            )
            disabled = ["passive_discovery"]
            if ratio > 1.1:
                disabled.append("baseline_aggregation")
            if ratio > 1.25:
                disabled.append("evidence_upload")
            if ratio > 1.5:
                disabled.append("optional_tls_inspection")
            return ResourceState(
                "resource_limited",
                sample,
                self.budget,
                disabled,
                reasons,
                round(max(0.0, self._passive_discovery_disabled_until - now), 3),
            )

        remaining = max(0.0, self._passive_discovery_disabled_until - now)
        if remaining > 0:
            return ResourceState(
                "resource_limited",
                sample,
                self.budget,
                ["passive_discovery"],
                ["passive_discovery_cooldown"],
                round(remaining, 3),
            )
        self._passive_discovery_disabled_until = 0.0
        return ResourceState("healthy", sample, self.budget, [], [], 0.0)
