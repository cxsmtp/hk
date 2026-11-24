from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum

from app.services.native_control.contracts import (
    CapabilityLevel,
    HealthState,
    IntegrationMode,
    IntegrationState,
    VerificationStatus,
)


class NativeValidationResult(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class IntegrationFacts:
    state: IntegrationState
    mode: IntegrationMode
    profile_verification: VerificationStatus
    profile_active: bool
    health: HealthState
    validation: NativeValidationResult
    validated_at: datetime | None
    validation_valid_until: datetime | None
    policy_fresh_until: datetime | None
    configuration_integrity_valid: bool
    provider_version_supported: bool
    adapter_version_supported: bool
    route_binding_current: bool
    enforcement_feature_active: bool
    active_workload_identity: bool
    # Catalog/profile review and safe synthetic probes are not deployed
    # acceptance.  Native enforcement requires the latest immutable real
    # acceptance bound to this integration's active contract.
    real_acceptance_current: bool = False
    callback_authenticated: bool = False
    evidence_flowing: bool = False
    measured_latency_ms: int | None = None


_TRANSITIONS = {
    IntegrationState.DISCOVERED: {IntegrationState.CONFIGURING, IntegrationState.DISABLED, IntegrationState.UNSUPPORTED},
    IntegrationState.CONFIGURING: {IntegrationState.VALIDATING, IntegrationState.DISABLED, IntegrationState.UNSUPPORTED},
    IntegrationState.VALIDATING: {
        IntegrationState.MONITORING,
        IntegrationState.DEGRADED,
        IntegrationState.UNHEALTHY,
        IntegrationState.DISABLED,
    },
    IntegrationState.MONITORING: {
        IntegrationState.ENFORCING,
        IntegrationState.VALIDATING,
        IntegrationState.DEGRADED,
        IntegrationState.UNHEALTHY,
        IntegrationState.DISABLED,
    },
    IntegrationState.ENFORCING: {
        IntegrationState.MONITORING,
        IntegrationState.VALIDATING,
        IntegrationState.DEGRADED,
        IntegrationState.UNHEALTHY,
        IntegrationState.DISABLED,
    },
    IntegrationState.DEGRADED: {
        IntegrationState.CONFIGURING,
        IntegrationState.VALIDATING,
        IntegrationState.MONITORING,
        IntegrationState.ENFORCING,
        IntegrationState.UNHEALTHY,
        IntegrationState.DISABLED,
    },
    IntegrationState.UNHEALTHY: {IntegrationState.VALIDATING, IntegrationState.DISABLED},
    IntegrationState.DISABLED: {IntegrationState.CONFIGURING},
    IntegrationState.UNSUPPORTED: {IntegrationState.DISABLED},
}


def _as_utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _enforce_readiness(facts: IntegrationFacts, now: datetime) -> None:
    if not facts.profile_active:
        raise ValueError("profile_inactive")
    if facts.profile_verification is not VerificationStatus.VERIFIED:
        raise ValueError("profile_not_verified")
    if facts.health is not HealthState.HEALTHY:
        raise ValueError("health_not_healthy")
    if facts.validation is not NativeValidationResult.PASSED:
        raise ValueError("validation_not_passed")
    if not facts.real_acceptance_current:
        raise ValueError("real_acceptance_required")
    if _as_utc(facts.validation_valid_until) < _as_utc(now):
        raise ValueError("validation_stale")
    if _as_utc(facts.policy_fresh_until) < _as_utc(now):
        raise ValueError("policy_stale")
    if not facts.configuration_integrity_valid:
        raise ValueError("configuration_integrity_invalid")
    if not facts.provider_version_supported:
        raise ValueError("provider_version_unsupported")
    if not facts.adapter_version_supported:
        raise ValueError("adapter_version_unsupported")
    if not facts.route_binding_current:
        raise ValueError("route_binding_unavailable")
    if not facts.enforcement_feature_active:
        raise ValueError("enforcement_feature_disabled")
    if not facts.active_workload_identity:
        raise ValueError("workload_identity_inactive")
    if not facts.callback_authenticated:
        raise ValueError("callback_unhealthy")
    if not facts.evidence_flowing:
        raise ValueError("evidence_flow_unavailable")
    if facts.measured_latency_ms is None:
        raise ValueError("latency_unmeasured")


def transition_integration(
    facts: IntegrationFacts,
    target: IntegrationState,
    *,
    now: datetime,
) -> IntegrationFacts:
    if target is facts.state:
        return facts
    if target not in _TRANSITIONS.get(facts.state, set()):
        raise ValueError(f"invalid_state_transition:{facts.state.value}:{target.value}")
    if facts.state is IntegrationState.DEGRADED and target in {
        IntegrationState.MONITORING,
        IntegrationState.ENFORCING,
    }:
        if facts.validation is not NativeValidationResult.PASSED or _as_utc(facts.validation_valid_until) < _as_utc(now):
            raise ValueError("revalidation_required")
    if target is IntegrationState.MONITORING:
        if facts.validation is NativeValidationResult.UNKNOWN:
            raise ValueError("validation_required")
        return replace(facts, state=target, mode=IntegrationMode.MONITOR)
    if target is IntegrationState.ENFORCING:
        _enforce_readiness(facts, now)
        return replace(facts, state=target, mode=IntegrationMode.ENFORCE)
    if target in {IntegrationState.DEGRADED, IntegrationState.UNHEALTHY}:
        return replace(facts, state=target, health=HealthState.DEGRADED, mode=IntegrationMode.MONITOR)
    if target is IntegrationState.DISABLED:
        return replace(facts, state=target, mode=IntegrationMode.DISCOVER)
    if target is IntegrationState.VALIDATING:
        return replace(facts, state=target, mode=IntegrationMode.MONITOR)
    return replace(facts, state=target)


def _dimension_state(
    capabilities: dict[str, dict[str, str]],
    *dimensions: str,
    minimum: CapabilityLevel = CapabilityLevel.OBSERVE,
) -> str:
    rank = {
        CapabilityLevel.UNKNOWN.value: 0,
        CapabilityLevel.UNAVAILABLE.value: 0,
        CapabilityLevel.OBSERVE.value: 1,
        CapabilityLevel.EXTERNAL.value: 2,
        CapabilityLevel.INLINE.value: 3,
        CapabilityLevel.INLINE_BOUND.value: 4,
    }
    values = [capabilities.get(name) for name in dimensions]
    values = [value for value in values if isinstance(value, dict)]
    if not values:
        return "unknown"
    verified = [value for value in values if value.get("verification_status") == VerificationStatus.VERIFIED.value]
    if not verified:
        return "unknown"
    if any(rank.get(str(value.get("level")), 0) >= rank[minimum.value] for value in verified):
        return "covered"
    if all(value.get("level") == CapabilityLevel.UNAVAILABLE.value for value in verified):
        return "not_covered"
    return "unknown"


def derive_native_coverage(
    facts: IntegrationFacts,
    capabilities: dict[str, dict[str, str]],
    *,
    now: datetime,
) -> dict[str, str]:
    dimensions = (
        "discovery",
        "identity",
        "authorization",
        "binding",
        "evidence",
        "execution_verification",
        "containment",
        "bypass",
    )
    active = (
        facts.state in {IntegrationState.MONITORING, IntegrationState.ENFORCING}
        and facts.health is HealthState.HEALTHY
        and facts.profile_active
        and facts.profile_verification is VerificationStatus.VERIFIED
        and facts.validation is NativeValidationResult.PASSED
        and facts.real_acceptance_current
        and _as_utc(facts.validation_valid_until) >= _as_utc(now)
        and _as_utc(facts.policy_fresh_until) >= _as_utc(now)
        and facts.configuration_integrity_valid
        and facts.provider_version_supported
        and facts.adapter_version_supported
        and facts.route_binding_current
        and facts.active_workload_identity
    )
    if not active:
        return {dimension: "unknown" for dimension in dimensions}
    authorization_active = bool(
        facts.state is IntegrationState.ENFORCING
        and facts.mode is IntegrationMode.ENFORCE
        and facts.route_binding_current
        and facts.enforcement_feature_active
    )
    return {
        "discovery": _dimension_state(capabilities, "discovery"),
        "identity": _dimension_state(capabilities, "identity"),
        "authorization": _dimension_state(
            capabilities,
            "prompt_control",
            "tool_control",
            "mcp_control",
            "command_control",
            minimum=CapabilityLevel.INLINE,
        ) if authorization_active else "unknown",
        "binding": _dimension_state(
            capabilities,
            "parameter_binding",
            "target_binding",
            "destination_binding",
            minimum=CapabilityLevel.INLINE_BOUND,
        ) if authorization_active else "unknown",
        "evidence": _dimension_state(capabilities, "post_execution_visibility"),
        "execution_verification": _dimension_state(
            capabilities,
            "post_execution_verification",
            minimum=CapabilityLevel.INLINE_BOUND,
        ),
        "containment": _dimension_state(capabilities, "containment", minimum=CapabilityLevel.EXTERNAL),
        "bypass": _dimension_state(capabilities, "bypass_detection"),
    }
