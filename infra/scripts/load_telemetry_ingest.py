from __future__ import annotations

import argparse
import asyncio
import statistics
import time
from collections import Counter
from datetime import datetime, timezone
from uuid import uuid4

import httpx


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, int(round((percentile / 100.0) * (len(ordered) - 1)))))
    return ordered[rank]


async def _bootstrap_auth(client: httpx.AsyncClient, password: str, email: str | None) -> tuple[str, str]:
    chosen_email = email or f"load.telemetry.{uuid4().hex[:10]}@example.com"
    response = await client.post(
        "/auth/register",
        json={"email": chosen_email, "password": password, "full_name": "Load Telemetry"},
    )
    response.raise_for_status()
    payload = response.json()
    token = payload["access_token"]
    tenant_id = payload["tenants"][0]["id"]
    return token, tenant_id


async def main() -> None:
    parser = argparse.ArgumentParser(description="Load test telemetry ingest endpoint.")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--password", default="Password123!")
    parser.add_argument("--email", default=None)
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--timeout-seconds", type=float, default=15.0)
    args = parser.parse_args()

    timeout = httpx.Timeout(args.timeout_seconds)
    async with httpx.AsyncClient(base_url=args.base_url, timeout=timeout) as client:
        token, tenant_id = await _bootstrap_auth(client, password=args.password, email=args.email)
        headers = {"Authorization": f"Bearer {token}", "X-Tenant-ID": tenant_id}

        status_counts: Counter[int] = Counter()
        latencies_ms: list[float] = []
        lock = asyncio.Lock()
        semaphore = asyncio.Semaphore(max(1, args.concurrency))

        async def _send(index: int) -> None:
            payload = {
                "correlation_id": f"load-telemetry-{index}",
                "browser": "chrome",
                "event_type": "ai_domain_visit",
                "domain": "chat.openai.com",
                "url": "https://chat.openai.com",
                "page_title": "ChatGPT",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "policy_version": "load-test",
                "platform_mode": "discover",
                "action_taken": "monitor",
                "prompt_preview_redacted": "load test event",
                "input_signal_types": ["telemetry.load_test"],
                "file_meta": [],
            }
            async with semaphore:
                started = time.perf_counter()
                response = await client.post("/telemetry/browser", headers=headers, json=payload)
                elapsed_ms = (time.perf_counter() - started) * 1000
                async with lock:
                    status_counts[response.status_code] += 1
                    latencies_ms.append(elapsed_ms)

        run_started = time.perf_counter()
        await asyncio.gather(*(_send(i) for i in range(args.requests)))
        total_seconds = max(0.001, time.perf_counter() - run_started)

    successful = sum(count for code, count in status_counts.items() if 200 <= code < 300)
    summary = {
        "scenario": "telemetry_ingest",
        "base_url": args.base_url,
        "requests": args.requests,
        "concurrency": args.concurrency,
        "duration_seconds": round(total_seconds, 3),
        "throughput_rps": round(args.requests / total_seconds, 2),
        "success_rate": round((successful / max(1, args.requests)) * 100.0, 2),
        "status_counts": dict(status_counts),
        "latency_ms": {
            "avg": round(statistics.fmean(latencies_ms), 2) if latencies_ms else 0.0,
            "p50": round(_percentile(latencies_ms, 50), 2),
            "p95": round(_percentile(latencies_ms, 95), 2),
            "p99": round(_percentile(latencies_ms, 99), 2),
        },
    }
    print(summary)


if __name__ == "__main__":
    asyncio.run(main())
