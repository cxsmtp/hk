from __future__ import annotations

from app.services.native_control.findings import (
    FINDING_PROFILES,
    canonical_finding_type,
    phase4_finding_types_for_reason_codes,
)
from app.services.native_control.metrics import METRIC_NAMES, NativeControlMetrics


PHASE4_FINDINGS = {
    "PROVIDER_CONTROL_DISABLED",
    "PROVIDER_CONTROL_TAMPERED",
    "PROVIDER_VERSION_UNSUPPORTED",
    "PROVIDER_CONTROL_UNHEALTHY",
    "PROVIDER_CONTROL_DOWNGRADED",
    "DIRECT_PROVIDER_BYPASS",
    "REMOTE_EXECUTION_COVERAGE_GAP",
    "TOOL_CLASS_COVERAGE_GAP",
    "MODEL_ROUTE_DRIFT",
    "HOSTED_TOOL_OPAQUE",
    "CONTROL_REQUIREMENT_UNSATISFIED",
    "PROVIDER_CONTRACT_CHANGED",
    "PROVIDER_VALIDATION_FAILED",
    "PROTOCOL_COMPATIBILITY_OVERCLAIM",
    "CONFIGURATION_SCOPE_WEAK",
    "ACCOUNT_CONTEXT_UNKNOWN",
}

PHASE4_METRICS = {
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
    "execution_drift_total",
}


def test_phase4_finding_catalog_contains_the_exact_high_value_profiles() -> None:
    assert PHASE4_FINDINGS.issubset(FINDING_PROFILES)


def test_legacy_finding_names_canonicalize_without_a_parallel_incident_type() -> None:
    assert canonical_finding_type("NATIVE_CONTROL_CALLBACK_UNHEALTHY") == (
        "PROVIDER_CONTROL_UNHEALTHY"
    )
    assert canonical_finding_type("CONTROL_POINT_DOWNGRADED") == (
        "PROVIDER_CONTROL_DOWNGRADED"
    )
    assert canonical_finding_type("CONTROL_REQUIREMENT_UNSATISFIED") == (
        "CONTROL_REQUIREMENT_UNSATISFIED"
    )


def test_phase4_metric_catalog_contains_the_exact_operational_names() -> None:
    assert PHASE4_METRICS.issubset(METRIC_NAMES)


def test_control_plan_rejections_map_to_high_value_phase4_findings() -> None:
    assert phase4_finding_types_for_reason_codes(
        [
            "deployment_acceptance_contract_hash_mismatch",
            "deployment_acceptance_model_mismatch",
            "remote_execution_floor_unavailable",
            "hosted_tool_execution_opaque",
            "protocol_compatibility_only",
            "enterprise_account_context_required",
        ]
    ) == (
        "PROVIDER_CONTRACT_CHANGED",
        "MODEL_ROUTE_DRIFT",
        "REMOTE_EXECUTION_COVERAGE_GAP",
        "HOSTED_TOOL_OPAQUE",
        "PROTOCOL_COMPATIBILITY_OVERCLAIM",
        "ACCOUNT_CONTEXT_UNKNOWN",
    )
    assert phase4_finding_types_for_reason_codes(["policy_evaluated"]) == ()


def test_legacy_and_canonical_metrics_never_double_count_one_another() -> None:
    metrics = NativeControlMetrics()

    metrics.increment(
        "adapter_events_total",
        provider="anthropic",
        method="native_hook",
        outcome="allowed",
    )

    snapshot = metrics.snapshot()
    assert snapshot["adapter_events_total"] == [
        {
            "provider": "anthropic",
            "method": "native_hook",
            "outcome": "allowed",
            "value": 1,
        }
    ]
    assert snapshot["provider_adapter_events_total"] == []

    metrics.increment(
        "provider_adapter_events_total",
        provider="anthropic",
        method="native_hook",
        outcome="allowed",
    )
    snapshot = metrics.snapshot()
    assert snapshot["provider_adapter_events_total"] == [
        {
            "provider": "anthropic",
            "method": "native_hook",
            "outcome": "allowed",
            "value": 1,
        }
    ]


def test_legacy_native_metrics_remain_isolated_during_canonical_migration() -> None:
    metrics = NativeControlMetrics()

    metrics.increment(
        "native_control_blocks_total",
        provider="google",
        method="native_hook",
        outcome="blocked",
    )
    metrics.increment(
        "native_control_replay_rejections_total",
        provider="google",
        method="native_hook",
        outcome="replay",
    )

    snapshot = metrics.snapshot()
    assert snapshot["native_control_blocks_total"][0]["value"] == 1
    assert snapshot["native_control_replay_rejections_total"][0]["value"] == 1
    assert snapshot["provider_adapter_block_total"] == []
    assert snapshot["provider_adapter_replay_rejections_total"] == []


def test_phase4_metric_labels_remain_bounded() -> None:
    metrics = NativeControlMetrics()

    metrics.increment(
        "provider_adapter_events_total",
        provider="tenant-controlled-provider-value",
        method="arbitrary-provider-method",
        outcome="unbounded-event-result",
    )

    assert metrics.snapshot()["provider_adapter_events_total"] == [
        {
            "provider": "other",
            "method": "other",
            "outcome": "other",
            "value": 1,
        }
    ]
