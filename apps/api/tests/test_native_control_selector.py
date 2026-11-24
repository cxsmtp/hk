from __future__ import annotations

from dataclasses import replace

import pytest

from app.services.native_control.contracts import (
    AssuranceLevel,
    CapabilityClaim,
    CapabilityDimension,
    CapabilityLevel,
    ControlCapabilityProfile,
    ControlMethod,
    ControlPointCandidate,
    ControlPointHealth,
    ControlRequirementProfile,
    DegradationMode,
    HealthState,
    SecurityProperties,
    SelectionContext,
    VerificationStatus,
)
from app.services.native_control.selector import TrustedControlPointSelector


def _claim(
    level: CapabilityLevel,
    *,
    verification: VerificationStatus = VerificationStatus.VERIFIED,
) -> CapabilityClaim:
    return CapabilityClaim(level=level, verification_status=verification)


def _profile(
    profile_id: str,
    *,
    method: ControlMethod,
    capabilities: dict[CapabilityDimension, CapabilityClaim],
    version: str = "1.0.0",
    min_version: str = "1.0.0",
    max_version: str = "2.0.0",
    latency_ms: int = 20,
) -> ControlCapabilityProfile:
    return ControlCapabilityProfile(
        profile_id=profile_id,
        profile_version="native-control-profile/1.0",
        provider="openai",
        product="codex",
        integration_method=method,
        adapter_version="1.0.0",
        tested_min_version=min_version,
        tested_max_version=max_version,
        current_verified_version=version,
        verification_status=VerificationStatus.VERIFIED,
        verification_source="integration_test:test_native_control_selector",
        capabilities=capabilities,
        security_properties=SecurityProperties(
            pre_execution_capable=True,
            post_execution_capable=True,
            blocking_strength=90,
            action_fidelity=90,
            identity_quality=90,
            parameter_fidelity=90,
            target_fidelity=90,
            destination_fidelity=90,
            result_fidelity=90,
            bypass_resistance=90,
            tamper_resistance=90,
            expected_latency_ms=latency_ms,
            availability_profile="local_and_remote",
            required_permissions=("integration.invoke",),
            privacy_impact="metadata_only",
        ),
        health_requirements=("authenticated_callback", "fresh_policy"),
        degradation_modes=(DegradationMode.FAIL_CLOSED,),
        known_blind_spots=(),
        documentation_references=("repo:test_native_control_selector",),
    )


def _candidate(
    point_id: str,
    profile: ControlCapabilityProfile,
    *,
    health: HealthState = HealthState.HEALTHY,
    provider_version: str = "1.5.0",
    tenant_binding_valid: bool = True,
    policy_fresh: bool = True,
    configuration_integrity_valid: bool = True,
) -> ControlPointCandidate:
    return ControlPointCandidate(
        control_point_id=point_id,
        integration_instance_id=f"integration-{point_id}",
        tenant_id="tenant-1",
        profile=profile,
        health=ControlPointHealth(
            state=health,
            callback_authenticated=True,
            validation_current=True,
            evidence_flowing=True,
            configuration_integrity_valid=configuration_integrity_valid,
            policy_fresh=policy_fresh,
            observed_latency_ms=profile.security_properties.expected_latency_ms,
        ),
        provider_version=provider_version,
        adapter_version="1.0.0",
        policy_version="policy-7",
        policy_binding_mode=(
            "authoritative_per_action"
            if profile.integration_method is ControlMethod.GATEWAY_INLINE
            else "pinned_snapshot"
        ),
        tenant_binding_valid=tenant_binding_valid,
        exposed_lifecycle_events=("before_tool", "after_tool"),
        visible_action_fields=("identity", "parameters", "target", "destination", "result"),
        blocking_semantics=True,
        current_degradation_mode=DegradationMode.FAIL_CLOSED,
    )


def _bound_capabilities() -> dict[CapabilityDimension, CapabilityClaim]:
    return {
        CapabilityDimension.IDENTITY: _claim(CapabilityLevel.INLINE_BOUND),
        CapabilityDimension.TOOL_CONTROL: _claim(CapabilityLevel.INLINE_BOUND),
        CapabilityDimension.PARAMETER_BINDING: _claim(CapabilityLevel.INLINE_BOUND),
        CapabilityDimension.TARGET_BINDING: _claim(CapabilityLevel.INLINE_BOUND),
        CapabilityDimension.DESTINATION_BINDING: _claim(CapabilityLevel.INLINE_BOUND),
        CapabilityDimension.POST_EXECUTION_VERIFICATION: _claim(CapabilityLevel.INLINE_BOUND),
        CapabilityDimension.CONTAINMENT: _claim(CapabilityLevel.EXTERNAL),
    }


def _requirement(**overrides: object) -> ControlRequirementProfile:
    values: dict[str, object] = {
        "action_class": "persistent_side_effect",
        "requires_pre_execution": True,
        "pre_execution_capability": CapabilityDimension.TOOL_CONTROL,
        "requires_identity": True,
        "requires_parameter_binding": True,
        "requires_target_binding": True,
        "requires_destination_binding": True,
        "requires_post_execution": True,
        "requires_persistence_detection": False,
        "minimum_assurance": AssuranceLevel.A5_VERIFIED,
        "maximum_latency_ms": 100,
        "acceptable_degradation_modes": (DegradationMode.FAIL_CLOSED,),
    }
    values.update(overrides)
    return ControlRequirementProfile(**values)


def _context(**overrides: object) -> SelectionContext:
    values: dict[str, object] = {
        "tenant_id": "tenant-1",
        "action_id": "action-1",
        "policy_version": "policy-7",
        "matrix_version": "matrix-3",
        "provider": "openai",
        "product": "codex",
        "provider_version": "1.5.0",
        "adapter_version": "1.0.0",
        "route_binding_source": "authenticated_native_adapter",
        "allowed_control_methods": ("native_hook",),
        "required_lifecycle_event": "before_tool",
        "current_bypass_state": "none_detected",
        "policy_fresh": True,
    }
    values.update(overrides)
    return SelectionContext(**values)


def test_selects_strongest_verified_eligible_control_point_deterministically() -> None:
    selector = TrustedControlPointSelector()
    native = _candidate(
        "native",
        _profile("profile-native", method=ControlMethod.NATIVE_HOOK, capabilities=_bound_capabilities()),
    )
    gateway_profile = _profile(
        "profile-gateway",
        method=ControlMethod.GATEWAY_INLINE,
        capabilities={
            **_bound_capabilities(),
            CapabilityDimension.POST_EXECUTION_VERIFICATION: _claim(CapabilityLevel.OBSERVE),
        },
    )
    gateway = _candidate("gateway", gateway_profile)

    forward = selector.select(_context(), _requirement(), [gateway, native])
    reverse = selector.select(_context(), _requirement(), [native, gateway])

    assert forward.primary_control_point == "native"
    assert forward.as_dict() == reverse.as_dict()
    assert forward.selector_version == "trusted-control-selector/1.0"
    assert forward.matrix_version == "matrix-3"
    assert forward.policy_version == "policy-7"
    assert forward.assurance_level is AssuranceLevel.A5_VERIFIED
    assert forward.unsatisfied_capabilities == ()
    assert [(row.control_point_id, row.reason_codes) for row in forward.rejected_candidates] == [
        ("gateway", ("insufficient_post_execution_verification", "minimum_assurance_unsatisfied")),
    ]


@pytest.mark.parametrize(
    ("candidate_mutator", "reason"),
    [
        (lambda row: replace(row, provider_version="3.0.0"), "provider_version_unsupported"),
        (lambda row: replace(row, tenant_binding_valid=False), "tenant_binding_invalid"),
        (
            lambda row: replace(row, health=replace(row.health, state=HealthState.TAMPERED)),
            "health_tampered",
        ),
        (
            lambda row: replace(row, health=replace(row.health, policy_fresh=False)),
            "policy_stale",
        ),
        (
            lambda row: replace(row, health=replace(row.health, configuration_integrity_valid=False)),
            "configuration_integrity_invalid",
        ),
        (
            lambda row: replace(row, health=replace(row.health, observed_latency_ms=101)),
            "latency_requirement_unsatisfied",
        ),
    ],
)
def test_rejects_ineligible_candidate_with_explainable_reason(candidate_mutator, reason: str) -> None:
    candidate = _candidate(
        "native",
        _profile("profile-native", method=ControlMethod.NATIVE_HOOK, capabilities=_bound_capabilities()),
    )

    result = TrustedControlPointSelector().select(
        _context(),
        _requirement(),
        [candidate_mutator(candidate)],
    )

    assert result.primary_control_point is None
    assert result.selection_reason == "CONTROL_REQUIREMENT_UNSATISFIED"
    assert reason in result.rejected_candidates[0].reason_codes


def test_unverified_capability_never_participates_in_enforce_selection() -> None:
    claims = _bound_capabilities()
    claims[CapabilityDimension.PARAMETER_BINDING] = _claim(
        CapabilityLevel.INLINE_BOUND,
        verification=VerificationStatus.UNVERIFIED,
    )
    candidate = _candidate(
        "native",
        _profile("profile-native", method=ControlMethod.NATIVE_HOOK, capabilities=claims),
    )

    result = TrustedControlPointSelector().select(_context(), _requirement(), [candidate])

    assert result.primary_control_point is None
    assert result.unsatisfied_capabilities == (CapabilityDimension.PARAMETER_BINDING,)
    assert result.rejected_candidates[0].reason_codes == (
        "capability_parameter_binding_unverified",
        "minimum_assurance_unsatisfied",
    )


def test_failover_refuses_weaker_control_even_when_it_can_block() -> None:
    gateway_claims = _bound_capabilities()
    gateway_claims[CapabilityDimension.PARAMETER_BINDING] = _claim(CapabilityLevel.INLINE)
    gateway = _candidate(
        "gateway",
        _profile("profile-gateway", method=ControlMethod.GATEWAY_INLINE, capabilities=gateway_claims),
    )

    result = TrustedControlPointSelector().select(_context(), _requirement(), [gateway])

    assert result.primary_control_point is None
    assert result.selection_reason == "CONTROL_REQUIREMENT_UNSATISFIED"
    assert "insufficient_parameter_binding" in result.rejected_candidates[0].reason_codes


def test_equal_candidates_use_stable_control_point_id_tie_break() -> None:
    profile = _profile("profile", method=ControlMethod.SDK_MIDDLEWARE, capabilities=_bound_capabilities())
    result = TrustedControlPointSelector().select(
        _context(),
        _requirement(),
        [_candidate("z-point", profile), _candidate("a-point", profile)],
    )

    assert result.primary_control_point == "a-point"


def test_action_capability_cannot_be_satisfied_by_a_different_inline_dimension() -> None:
    candidate = _candidate(
        "tool-only",
        _profile(
            "profile-tool-only",
            method=ControlMethod.SDK_MIDDLEWARE,
            capabilities={
                CapabilityDimension.IDENTITY: _claim(CapabilityLevel.INLINE_BOUND),
                CapabilityDimension.TOOL_CONTROL: _claim(CapabilityLevel.INLINE_BOUND),
            },
        ),
    )

    result = TrustedControlPointSelector().select(
        _context(required_lifecycle_event="before_model"),
        _requirement(
            action_class="model_interaction",
            pre_execution_capability=CapabilityDimension.PROMPT_CONTROL,
            requires_parameter_binding=False,
            requires_target_binding=False,
            requires_destination_binding=False,
            requires_post_execution=False,
            minimum_assurance=AssuranceLevel.A3_INLINE,
        ),
        [replace(candidate, exposed_lifecycle_events=("before_model",), visible_action_fields=("identity",))],
    )

    assert result.primary_control_point is None
    assert result.unsatisfied_capabilities == (CapabilityDimension.PROMPT_CONTROL,)


def test_actual_route_version_must_match_the_registered_control_point_version() -> None:
    candidate = _candidate(
        "native",
        _profile("profile-native", method=ControlMethod.NATIVE_HOOK, capabilities=_bound_capabilities()),
    )

    result = TrustedControlPointSelector().select(
        _context(provider_version="1.6.0"),
        _requirement(),
        [candidate],
    )

    assert result.primary_control_point is None
    assert "provider_version_route_mismatch" in result.rejected_candidates[0].reason_codes


def test_adapter_version_drift_rejects_the_control_point() -> None:
    candidate = _candidate(
        "native",
        _profile("profile-native", method=ControlMethod.NATIVE_HOOK, capabilities=_bound_capabilities()),
    )

    result = TrustedControlPointSelector().select(
        _context(),
        _requirement(),
        [replace(candidate, adapter_version="2.0.0")],
    )

    assert result.primary_control_point is None
    assert "adapter_version_route_mismatch" in result.rejected_candidates[0].reason_codes
    assert "adapter_version_unsupported" in result.rejected_candidates[0].reason_codes


def test_policy_snapshot_mismatch_rejects_the_control_point() -> None:
    candidate = _candidate(
        "native",
        _profile("profile-native", method=ControlMethod.NATIVE_HOOK, capabilities=_bound_capabilities()),
    )

    result = TrustedControlPointSelector().select(
        _context(policy_version="policy-8"),
        _requirement(),
        [candidate],
    )

    assert result.primary_control_point is None
    assert "policy_version_mismatch" in result.rejected_candidates[0].reason_codes


def test_central_gateway_binds_the_authoritative_policy_per_action() -> None:
    candidate = _candidate(
        "gateway",
        _profile("profile-gateway", method=ControlMethod.GATEWAY_INLINE, capabilities=_bound_capabilities()),
    )

    result = TrustedControlPointSelector().select(
        _context(policy_version="policy-8"),
        _requirement(),
        [candidate],
    )

    assert result.primary_control_point == "gateway"


def test_detected_bypass_or_missing_evidence_flow_rejects_inline_selection() -> None:
    candidate = _candidate(
        "native",
        _profile("profile-native", method=ControlMethod.NATIVE_HOOK, capabilities=_bound_capabilities()),
    )
    bypassed = TrustedControlPointSelector().select(
        _context(current_bypass_state="detected"),
        _requirement(),
        [candidate],
    )
    no_evidence = TrustedControlPointSelector().select(
        _context(),
        _requirement(),
        [replace(candidate, health=replace(candidate.health, evidence_flowing=False))],
    )

    assert "active_bypass_detected" in bypassed.rejected_candidates[0].reason_codes
    assert "evidence_flow_unavailable" in no_evidence.rejected_candidates[0].reason_codes


def test_selection_id_is_stable_across_retry_timestamps() -> None:
    candidate = _candidate(
        "native",
        _profile("profile-native", method=ControlMethod.NATIVE_HOOK, capabilities=_bound_capabilities()),
    )
    first = TrustedControlPointSelector().select(
        _context(evaluated_at="2026-08-11T08:00:00+00:00"),
        _requirement(),
        [candidate],
    )
    retry = TrustedControlPointSelector().select(
        _context(evaluated_at="2026-08-11T08:00:01+00:00"),
        _requirement(),
        [candidate],
    )

    assert retry.selection_id == first.selection_id


def test_observation_and_containment_points_do_not_need_primary_authorization_capabilities() -> None:
    primary = _candidate(
        "primary",
        _profile("profile-primary", method=ControlMethod.NATIVE_HOOK, capabilities=_bound_capabilities()),
    )
    observer_profile = _profile(
        "profile-observer",
        method=ControlMethod.OBSERVE_ONLY,
        capabilities={
            CapabilityDimension.IDENTITY: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.POST_EXECUTION_VISIBILITY: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.CONTAINMENT: _claim(CapabilityLevel.EXTERNAL),
        },
    )
    observer = replace(
        _candidate("observer", observer_profile),
        blocking_semantics=False,
        visible_action_fields=("identity",),
    )

    result = TrustedControlPointSelector().select(_context(), _requirement(), [primary, observer])

    assert result.primary_control_point == "primary"
    assert result.secondary_observation_points == ("observer",)
    assert result.containment_points == ("observer",)
