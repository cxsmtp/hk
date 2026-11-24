from __future__ import annotations

from collections import Counter
from threading import Lock


METRIC_NAMES = {
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
    "native_control_events_total",
    "native_control_decisions_total",
    "native_control_blocks_total",
    "native_control_monitor_would_block_total",
    "native_control_approvals_total",
    "native_control_timeouts_total",
    "native_control_auth_failures_total",
    "native_control_replay_rejections_total",
    "native_control_integrity_failures_total",
    "control_selector_runs_total",
    "control_selector_failures_total",
    "control_requirement_unsatisfied_total",
    "control_failovers_total",
    "control_downgrades_total",
    "execution_drift_total",
    "provider_adapter_events_total",
    "provider_adapter_allow_total",
    "provider_adapter_block_total",
    "provider_adapter_would_block_total",
    "provider_adapter_errors_total",
    "provider_adapter_timeouts_total",
    "provider_adapter_auth_failures_total",
    "provider_adapter_replay_rejections_total",
    "provider_adapter_deduplicated_total",
    "provider_adapter_validation_total",
    "provider_adapter_validation_failures_total",
    "provider_contract_drift_total",
    "control_plan_resolution_total",
    "control_plan_unsatisfied_total",
    "control_plan_failover_total",
    "control_plan_downgrade_total",
    "endpoint_permit_mismatch_total",
    "provider_bypass_total",
}

PROVIDERS = {
    "anthropic",
    "cursor",
    "openai",
    "google",
    "microsoft",
    "azure",
    "aws",
    "meta",
    "moonshot_kimi",
    "alibaba_qwen",
    "deepseek",
    "unknown",
}
METHODS = {
    "native_hook",
    "sdk_middleware",
    "agent_middleware",
    "tool_loop_intercept",
    "api_intercept",
    "gateway_inline",
    "endpoint_runtime",
    "browser_inline",
    "saas_control_api",
    "network_external",
    "observe_only",
    "unknown",
}
OUTCOMES = {
    "selected",
    "rejected",
    "allowed",
    "blocked",
    "warned",
    "approval",
    "failed",
    "timeout",
    "replay",
    "downgraded",
    "other",
}


class NativeControlMetrics:
    """Process-local low-cardinality counters matching Hawk's current observability pattern."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._counts: Counter[tuple[str, str, str, str]] = Counter()

    def increment(
        self,
        name: str,
        *,
        provider: str = "unknown",
        method: str = "unknown",
        outcome: str = "other",
        value: int = 1,
    ) -> None:
        if name not in METRIC_NAMES:
            raise ValueError("native_control_metric_invalid")
        provider_label = provider if provider in PROVIDERS else "other"
        method_label = method if method in METHODS else "other"
        outcome_label = outcome if outcome in OUTCOMES else "other"
        with self._lock:
            self._counts[(name, provider_label, method_label, outcome_label)] += max(0, int(value))

    def snapshot(self) -> dict[str, list[dict[str, object]]]:
        result: dict[str, list[dict[str, object]]] = {name: [] for name in sorted(METRIC_NAMES)}
        with self._lock:
            rows = sorted(self._counts.items())
        for (name, provider, method, outcome), value in rows:
            result[name].append(
                {
                    "provider": provider,
                    "method": method,
                    "outcome": outcome,
                    "value": value,
                }
            )
        return result

    def reset(self) -> None:
        with self._lock:
            self._counts.clear()


native_control_metrics = NativeControlMetrics()
