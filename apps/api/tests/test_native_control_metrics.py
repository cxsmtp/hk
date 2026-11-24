from app.services.native_control.metrics import NativeControlMetrics


def test_native_metrics_reject_unbounded_labels_and_expose_required_counters() -> None:
    metrics = NativeControlMetrics()
    metrics.increment(
        "control_selector_runs_total",
        provider="openai",
        method="gateway_inline",
        outcome="selected",
    )
    metrics.increment(
        "control_requirement_unsatisfied_total",
        provider="attacker-supplied-high-cardinality-value",
        method="unknown-method",
        outcome="unexpected-outcome",
    )

    snapshot = metrics.snapshot()

    assert snapshot["control_selector_runs_total"][0] == {
        "provider": "openai",
        "method": "gateway_inline",
        "outcome": "selected",
        "value": 1,
    }
    assert snapshot["control_requirement_unsatisfied_total"][0] == {
        "provider": "other",
        "method": "other",
        "outcome": "other",
        "value": 1,
    }


def test_adapter_foundation_metrics_are_registered_with_low_cardinality_labels() -> None:
    metrics = NativeControlMetrics()
    required = {
        "adapter_events_total",
        "adapter_errors_total",
        "adapter_auth_failures_total",
        "adapter_replay_rejections_total",
        "adapter_normalization_failures_total",
        "adapter_validation_runs_total",
        "adapter_validation_failures_total",
        "adapter_health_state",
        "adapter_install_failures_total",
        "adapter_uninstall_failures_total",
        "adapter_decision_translation_failures_total",
        "adapter_event_latency_ms",
    }

    for name in required:
        metrics.increment(name, provider="unknown", method="unknown", outcome="other")

    snapshot = metrics.snapshot()
    assert required <= set(snapshot)
