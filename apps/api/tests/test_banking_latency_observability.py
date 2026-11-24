from __future__ import annotations


def test_outcome_latency_tracker_reports_percentiles_errors_and_timeouts() -> None:
    from app.core.observability import OutcomeLatencyTracker

    tracker = OutcomeLatencyTracker(max_samples_per_path=10)
    path = "/runtime-control/banking-actions/authorize"
    tracker.observe(path, 10.0, status_code=200)
    tracker.observe(path, 20.0, status_code=422)
    tracker.observe(path, 30.0, status_code=504)

    assert tracker.summary_for_path(path) == {
        "count": 3,
        "p50_ms": 20.0,
        "p95_ms": 29.0,
        "p99_ms": 29.8,
        "max_ms": 30.0,
        "error_rate": 0.666667,
        "timeout_count": 1,
    }


def test_banking_latency_summary_has_all_regulated_runtime_paths() -> None:
    from app.core.observability import (
        OutcomeLatencyTracker,
        regulated_banking_latency_paths,
    )

    tracker = OutcomeLatencyTracker()
    summary = tracker.summary_for_paths(regulated_banking_latency_paths)

    assert set(summary) == set(regulated_banking_latency_paths)
    assert all(item["count"] == 0 for item in summary.values())


def test_banking_runtime_metrics_are_tenant_scoped_and_report_required_rates() -> None:
    from app.core.observability import BankingRuntimeMetrics

    now = [100.0]
    metrics = BankingRuntimeMetrics(clock=lambda: now[0])
    metrics.increment("tenant-a", "actions")
    metrics.increment("tenant-a", "decisions")
    metrics.increment("tenant-a", "blocked")
    metrics.increment("tenant-a", "approvals")
    metrics.increment("tenant-a", "subject_violations")
    metrics.observe_latency(
        "tenant-a",
        "/runtime-control/banking-actions/authorize",
        12.5,
        status_code=200,
    )
    metrics.observe_transport_latency(
        "tenant-a",
        "mcp",
        12.5,
        status_code=200,
    )

    tenant_a = metrics.snapshot("tenant-a", window_seconds=60)
    tenant_b = metrics.snapshot("tenant-b", window_seconds=60)

    assert tenant_a["actions_per_second"] == round(1 / 60, 6)
    assert tenant_a["decisions_per_second"] == round(1 / 60, 6)
    assert tenant_a["blocked_per_second"] == round(1 / 60, 6)
    assert tenant_a["approval_rate"] == 1.0
    assert tenant_a["event_counts"]["subject_violations"] == 1
    assert tenant_a["latency"]["/runtime-control/banking-actions/authorize"]["count"] == 1
    assert tenant_a["transport_latency"]["mcp"]["count"] == 1
    assert tenant_a["transport_latency"]["function"]["count"] == 0
    assert tenant_b["event_counts"]["actions"] == 0
    assert tenant_b["latency"]["/runtime-control/banking-actions/authorize"]["count"] == 0
    assert tenant_b["transport_latency"]["mcp"]["count"] == 0


def test_banking_runtime_metrics_expire_old_rate_events_without_losing_bounded_latency() -> None:
    from app.core.observability import BankingRuntimeMetrics

    now = [100.0]
    metrics = BankingRuntimeMetrics(clock=lambda: now[0])
    metrics.increment("tenant-a", "actions")
    metrics.observe_latency(
        "tenant-a",
        "/runtime-control/banking-actions/authorize",
        10.0,
        status_code=504,
    )
    now[0] = 161.0

    snapshot = metrics.snapshot("tenant-a", window_seconds=60)

    assert snapshot["actions_per_second"] == 0.0
    assert snapshot["event_counts"]["actions"] == 0
    assert snapshot["latency"]["/runtime-control/banking-actions/authorize"][
        "timeout_count"
    ] == 1
