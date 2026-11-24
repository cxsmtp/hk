from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.services.native_control.contracts import (
    HealthState,
    IntegrationMode,
    IntegrationState,
    VerificationStatus,
)
from app.services.native_control.service import (
    IntegrationFacts,
    NativeValidationResult,
    derive_native_coverage,
    transition_integration,
)


NOW = datetime(2026, 8, 11, 8, 0, tzinfo=timezone.utc)


def _facts(**overrides: object) -> IntegrationFacts:
    values: dict[str, object] = {
        "state": IntegrationState.MONITORING,
        "mode": IntegrationMode.MONITOR,
        "profile_verification": VerificationStatus.VERIFIED,
        "profile_active": True,
        "health": HealthState.HEALTHY,
        "validation": NativeValidationResult.PASSED,
        "validated_at": NOW,
        "validation_valid_until": NOW + timedelta(hours=1),
        "policy_fresh_until": NOW + timedelta(hours=1),
        "configuration_integrity_valid": True,
        "provider_version_supported": True,
        "adapter_version_supported": True,
        "route_binding_current": True,
        "enforcement_feature_active": True,
        "active_workload_identity": True,
        "real_acceptance_current": True,
        "callback_authenticated": True,
        "evidence_flowing": True,
        "measured_latency_ms": 20,
    }
    values.update(overrides)
    return IntegrationFacts(**values)


def test_state_machine_allows_only_backend_validated_progression() -> None:
    discovered = _facts(
        state=IntegrationState.DISCOVERED,
        mode=IntegrationMode.DISCOVER,
        validation=NativeValidationResult.UNKNOWN,
        health=HealthState.UNVERIFIED,
    )
    configuring = transition_integration(discovered, IntegrationState.CONFIGURING, now=NOW)
    validating = transition_integration(configuring, IntegrationState.VALIDATING, now=NOW)
    monitoring = transition_integration(
        _facts(state=IntegrationState.VALIDATING, mode=IntegrationMode.DISCOVER),
        IntegrationState.MONITORING,
        now=NOW,
    )
    enforcing = transition_integration(monitoring, IntegrationState.ENFORCING, now=NOW)

    assert configuring.state is IntegrationState.CONFIGURING
    assert validating.state is IntegrationState.VALIDATING
    assert monitoring.mode is IntegrationMode.MONITOR
    assert enforcing.mode is IntegrationMode.ENFORCE


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"profile_verification": VerificationStatus.UNVERIFIED}, "profile_not_verified"),
        ({"health": HealthState.DEGRADED}, "health_not_healthy"),
        ({"validation": NativeValidationResult.FAILED}, "validation_not_passed"),
        ({"real_acceptance_current": False}, "real_acceptance_required"),
        ({"policy_fresh_until": NOW - timedelta(seconds=1)}, "policy_stale"),
        ({"configuration_integrity_valid": False}, "configuration_integrity_invalid"),
        ({"provider_version_supported": False}, "provider_version_unsupported"),
        ({"active_workload_identity": False}, "workload_identity_inactive"),
        ({"callback_authenticated": False}, "callback_unhealthy"),
        ({"evidence_flowing": False}, "evidence_flow_unavailable"),
        ({"measured_latency_ms": None}, "latency_unmeasured"),
    ],
)
def test_enforce_refuses_unverified_or_unhealthy_integration(change, code: str) -> None:
    with pytest.raises(ValueError, match=code):
        transition_integration(_facts(**change), IntegrationState.ENFORCING, now=NOW)


def test_degraded_recovery_requires_fresh_successful_revalidation() -> None:
    degraded = _facts(
        state=IntegrationState.DEGRADED,
        health=HealthState.DEGRADED,
        validation=NativeValidationResult.FAILED,
    )

    with pytest.raises(ValueError, match="revalidation_required"):
        transition_integration(degraded, IntegrationState.MONITORING, now=NOW)


def test_degraded_control_point_can_return_to_configuring_for_admin_repair() -> None:
    degraded = _facts(
        state=IntegrationState.DEGRADED,
        health=HealthState.DEGRADED,
        validation=NativeValidationResult.FAILED,
    )

    configuring = transition_integration(
        degraded,
        IntegrationState.CONFIGURING,
        now=NOW,
    )

    assert configuring.state is IntegrationState.CONFIGURING
    assert configuring.mode is IntegrationMode.MONITOR


def test_coverage_uses_verified_healthy_active_capabilities_not_installation() -> None:
    capabilities = {
        "discovery": {"level": "observe", "verification_status": "verified"},
        "identity": {"level": "inline_bound", "verification_status": "verified"},
        "tool_control": {"level": "inline", "verification_status": "verified"},
        "parameter_binding": {"level": "inline_bound", "verification_status": "verified"},
        "post_execution_verification": {"level": "unknown", "verification_status": "unverified"},
        "containment": {"level": "external", "verification_status": "verified"},
        "bypass_detection": {"level": "observe", "verification_status": "verified"},
    }

    active = derive_native_coverage(
        _facts(state=IntegrationState.ENFORCING, mode=IntegrationMode.ENFORCE),
        capabilities,
        now=NOW,
    )
    installed_only = derive_native_coverage(
        _facts(
            state=IntegrationState.CONFIGURING,
            mode=IntegrationMode.DISCOVER,
            health=HealthState.UNVERIFIED,
            validation=NativeValidationResult.UNKNOWN,
        ),
        capabilities,
        now=NOW,
    )

    assert active == {
        "discovery": "covered",
        "identity": "covered",
        "authorization": "covered",
        "binding": "covered",
        "evidence": "unknown",
        "execution_verification": "unknown",
        "containment": "covered",
        "bypass": "covered",
    }
    assert set(installed_only.values()) == {"unknown"}


@pytest.mark.parametrize(
    "changes",
    (
        {"validation_valid_until": NOW - timedelta(seconds=1)},
        {"policy_fresh_until": NOW - timedelta(seconds=1)},
        {"configuration_integrity_valid": False},
        {"provider_version_supported": False},
        {"adapter_version_supported": False},
        {"route_binding_current": False},
        {"active_workload_identity": False},
        {"profile_active": False},
        {"profile_verification": VerificationStatus.BROKEN},
    ),
)
def test_coverage_falls_to_unknown_when_current_trust_gate_fails(changes: dict[str, object]) -> None:
    capabilities = {
        "identity": {"level": "inline_bound", "verification_status": "verified"},
        "tool_control": {"level": "inline", "verification_status": "verified"},
    }
    facts = _facts(state=IntegrationState.ENFORCING, mode=IntegrationMode.ENFORCE, **changes)

    assert set(derive_native_coverage(facts, capabilities, now=NOW).values()) == {"unknown"}


def test_disabled_enforcement_keeps_monitor_truth_but_never_reports_authorization() -> None:
    capabilities = {
        "identity": {"level": "inline_bound", "verification_status": "verified"},
        "tool_control": {"level": "inline", "verification_status": "verified"},
    }
    coverage = derive_native_coverage(
        _facts(
            state=IntegrationState.ENFORCING,
            mode=IntegrationMode.ENFORCE,
            enforcement_feature_active=False,
        ),
        capabilities,
        now=NOW,
    )

    assert coverage["identity"] == "covered"
    assert coverage["authorization"] == "unknown"
    assert coverage["binding"] == "unknown"
