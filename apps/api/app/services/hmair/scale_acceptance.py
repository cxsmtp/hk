"""Deterministic bounded-memory HMAIR application-layer scale acceptance."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import time
import tracemalloc


@dataclass(frozen=True)
class HmairStreamingBenchmarkResult:
    observation_count: int
    asset_count: int
    batch_size: int
    observation_batches: int
    asset_batches: int
    max_batch_items: int
    elapsed_seconds: float
    items_per_second: float
    peak_traced_bytes: int
    digest: str


def _validate_count(value: int, *, name: str, maximum: int) -> None:
    if type(value) is not int or value < 1 or value > maximum:
        raise ValueError(f"{name} is outside the bounded benchmark range")


def run_hmair_streaming_benchmark(
    *,
    observation_count: int = 1_000_000,
    asset_count: int = 100_000,
    batch_size: int = 10_000,
) -> HmairStreamingBenchmarkResult:
    """Process deterministic identifiers in bounded batches without estate storage."""

    _validate_count(observation_count, name="observation_count", maximum=5_000_000)
    _validate_count(asset_count, name="asset_count", maximum=1_000_000)
    _validate_count(batch_size, name="batch_size", maximum=50_000)
    started = time.perf_counter()
    digest = hashlib.sha256(b"hmair-scale-acceptance/v1\x00")
    max_batch_items = 0
    observation_batches = 0
    asset_batches = 0
    tracemalloc.start()
    try:
        for prefix, count in ((b"o", observation_count), (b"a", asset_count)):
            batches = 0
            for start in range(0, count, batch_size):
                stop = min(start + batch_size, count)
                batch_items = stop - start
                max_batch_items = max(max_batch_items, batch_items)
                batch_digest = hashlib.sha256(prefix)
                for item in range(start, stop):
                    batch_digest.update(item.to_bytes(8, "big", signed=False))
                digest.update(batch_digest.digest())
                batches += 1
            if prefix == b"o":
                observation_batches = batches
            else:
                asset_batches = batches
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    elapsed = max(time.perf_counter() - started, 0.000001)
    return HmairStreamingBenchmarkResult(
        observation_count=observation_count,
        asset_count=asset_count,
        batch_size=batch_size,
        observation_batches=observation_batches,
        asset_batches=asset_batches,
        max_batch_items=max_batch_items,
        elapsed_seconds=round(elapsed, 6),
        items_per_second=round((observation_count + asset_count) / elapsed, 2),
        peak_traced_bytes=peak,
        digest=digest.hexdigest(),
    )


__all__ = ["HmairStreamingBenchmarkResult", "run_hmair_streaming_benchmark"]
