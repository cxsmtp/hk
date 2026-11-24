from __future__ import annotations

from dataclasses import replace

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
    EndpointControlPlan,
    HealthState,
    MandatoryEnforcementFloorRequirement,
    SecurityProperties,
    SelectionContext,
    VerificationStatus,
)
from app.services.native_control.endpoint_floor_profiles import endpoint_floor_profiles
from app.services.native_control.selector import TrustedControlPointSelector


def _claim(level: CapabilityLevel) -> CapabilityClaim:
    return CapabilityClaim(level=level, verification_status=VerificationStatus.VERIFIED)


def _profile(
    profile_id: str,
    *,
    provider: str,
    product: str,
    method: ControlMethod,
    capability: CapabilityDimension,
) -> ControlCapabilityProfile:
    return ControlCapabilityProfile(
        profile_id=profile_id,
        profile_version="endpoint-floor-test/1",
        provider=provider,
        product=product,
        integration_method=method,
        adapter_version="1.0.0",
        tested_min_version="1.0.0",
        tested_max_version="2.0.0",
        current_verified_version="1.5.0",
        verification_status=VerificationStatus.VERIFIED,
        verification_source="test:runtime-acceptance",
        capabilities={
            CapabilityDimension.DISCOVERY: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.IDENTITY: _claim(CapabilityLevel.INLINE_BOUND),
            CapabilityDimension.PROCESS_IDENTITY: _claim(CapabilityLevel.INLINE_BOUND),
            capability: _claim(CapabilityLevel.INLINE_BOUND),
            CapabilityDimension.POST_EXECUTION_VISIBILITY: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.CONTAINMENT: _claim(CapabilityLevel.EXTERNAL),
        },
        security_properties=SecurityProperties(
            pre_execution_capable=True,
            post_execution_capable=True,
            blocking_strength=95,
            action_fidelity=90,
            identity_quality=95,
            parameter_fidelity=80,
            target_fidelity=90,
            destination_fidelity=90,
            result_fidelity=80,
            bypass_resistance=95,
            tamper_resistance=95,
            expected_latency_ms=5,
            availability_profile="local_only",
            required_permissions=("managed_endpoint",),
            privacy_impact="metadata_only",
        ),
        health_requirements=("runtime_acceptance", "fresh_policy"),
        degradation_modes=(DegradationMode.FAIL_CLOSED, DegradationMode.LOCAL_POLICY_ONLY),
        known_blind_spots=(),
        documentation_references=("test:runtime-acceptance",),
    )


def _candidate(point_id: str, profile: ControlCapabilityProfile) -> ControlPointCandidate:
    return ControlPointCandidate(
        control_point_id=point_id,
        integration_instance_id=f"instance:{point_id}",
        tenant_id="tenant-1",
        profile=profile,
        health=ControlPointHealth(
            state=HealthState.HEALTHY,
            callback_authenticated=True,
            validation_current=True,
            evidence_flowing=True,
            configuration_integrity_valid=True,
            policy_fresh=True,
            observed_latency_ms=5,
        ),
        provider_version="1.5.0",
        adapter_version="1.0.0",
        policy_version="policy-7",
        policy_binding_mode="pinned_snapshot",
        tenant_binding_valid=True,
        exposed_lifecycle_events=("before_action", "after_action"),
        visible_action_fields=("identity", "parameters", "target", "destination", "result"),
        blocking_semantics=True,
        current_degradation_mode=DegradationMode.FAIL_CLOSED,
    )


def _context() -> SelectionContext:
    return SelectionContext(
        tenant_id="tenant-1",
        action_id="action-1",
        policy_version="policy-7",
        matrix_version="matrix-7",
        provider="openai",
        product="codex",
        provider_version="1.5.0",
        adapter_version="1.0.0",
        route_binding_source="verified_route",
        allowed_control_methods=("native_hook",),
        required_lifecycle_event="before_action",
        current_bypass_state="none_detected",
        policy_fresh=True,
        evaluated_at="2026-08-12T10:00:00Z",
        plan_expires_at="2026-08-12T10:05:00Z",
    )


def _semantic_requirement() -> ControlRequirementProfile:
    return ControlRequirementProfile(
        action_class="tool_call",
        requires_pre_execution=True,
        pre_execution_capability=CapabilityDimension.TOOL_CONTROL,
        requires_identity=True,
        requires_parameter_binding=False,
        requires_target_binding=False,
        requires_destination_binding=False,
        requires_post_execution=False,
        requires_persistence_detection=False,
        minimum_assurance=AssuranceLevel.A3_INLINE,
        maximum_latency_ms=100,
        acceptable_degradation_modes=(DegradationMode.FAIL_CLOSED,),
    )


def _floors() -> tuple[MandatoryEnforcementFloorRequirement, ...]:
    return (
        MandatoryEnforcementFloorRequirement(
            floor_id="file",
            capability=CapabilityDimension.FILE_READ_CONTROL,
            maximum_latency_ms=20,
        ),
        MandatoryEnforcementFloorRequirement(
            floor_id="process",
            capability=CapabilityDimension.PROCESS_EXEC_CONTROL,
            maximum_latency_ms=20,
        ),
        MandatoryEnforcementFloorRequirement(
            floor_id="network",
            capability=CapabilityDimension.NETWORK_CONTROL,
            maximum_latency_ms=20,
        ),
    )


def _candidates() -> list[ControlPointCandidate]:
    semantic = _candidate(
        "semantic:codex",
        _profile(
            "semantic",
            provider="openai",
            product="codex",
            method=ControlMethod.NATIVE_HOOK,
            capability=CapabilityDimension.TOOL_CONTROL,
        ),
    )
    floors = [
        _candidate(
            "floor:file",
            _profile(
                "floor-file",
                provider="hawk_endpoint",
                product="macos_file",
                method=ControlMethod.ENDPOINT_RUNTIME,
                capability=CapabilityDimension.FILE_READ_CONTROL,
            ),
        ),
        _candidate(
            "floor:process",
            _profile(
                "floor-process",
                provider="hawk_endpoint",
                product="macos_process",
                method=ControlMethod.ENDPOINT_RUNTIME,
                capability=CapabilityDimension.PROCESS_EXEC_CONTROL,
            ),
        ),
        _candidate(
            "floor:network",
            _profile(
                "floor-network",
                provider="hawk_endpoint",
                product="macos_network",
                method=ControlMethod.ENDPOINT_RUNTIME,
                capability=CapabilityDimension.NETWORK_CONTROL,
            ),
        ),
    ]
    return [semantic, *floors]


def test_resolve_control_plan_composes_mandatory_floors_and_semantic_primary() -> None:
    selector = TrustedControlPointSelector()

    forward = selector.resolve_control_plan(_context(), _semantic_requirement(), _floors(), _candidates())
    reverse = selector.resolve_control_plan(_context(), _semantic_requirement(), _floors(), list(reversed(_candidates())))

    assert forward.as_dict() == reverse.as_dict()
    assert forward.mandatory_enforcement_floors == (
        ("file", "floor:file"),
        ("network", "floor:network"),
        ("process", "floor:process"),
    )
    assert forward.semantic_primary_control == "semantic:codex"
    assert set(forward.verification_points) >= {"floor:file", "floor:process", "floor:network"}
    assert forward.unsatisfied_mandatory_floors == ()
    assert forward.control_requirement_unsatisfied is False
    assert isinstance(forward, EndpointControlPlan)
    assert set(forward.required_capabilities) == {
        CapabilityDimension.IDENTITY,
        CapabilityDimension.TOOL_CONTROL,
        CapabilityDimension.FILE_READ_CONTROL,
        CapabilityDimension.PROCESS_EXEC_CONTROL,
        CapabilityDimension.NETWORK_CONTROL,
    }
    assert set(forward.satisfied_capabilities) == set(forward.required_capabilities)
    assert forward.unsatisfied_capabilities == ()
    assert forward.minimum_assurance is AssuranceLevel.A3_INLINE
    assert forward.degradation_policy == {
        "file": "fail_closed",
        "network": "fail_closed",
        "process": "fail_closed",
        "semantic": "fail_closed",
    }
    assert forward.expiry == "2026-08-12T10:05:00Z"
    assert forward.blind_spots == ()


def test_dead_mandatory_network_floor_cannot_be_replaced_by_semantic_control() -> None:
    candidates = _candidates()
    candidates[-1] = replace(
        candidates[-1],
        health=replace(candidates[-1].health, state=HealthState.UNHEALTHY),
    )

    result = TrustedControlPointSelector().resolve_control_plan(
        _context(), _semantic_requirement(), _floors(), candidates
    )

    assert result.semantic_primary_control == "semantic:codex"
    assert result.unsatisfied_mandatory_floors == ("network",)
    assert result.control_requirement_unsatisfied is True
    assert "CONTROL_REQUIREMENT_UNSATISFIED:network" in result.reason_codes
    assert CapabilityDimension.NETWORK_CONTROL in result.unsatisfied_capabilities
    assert "mandatory_floor_unsatisfied:network" in result.blind_spots


def test_unknown_ai_application_can_have_endpoint_floors_without_semantic_primary() -> None:
    floors_only = [row for row in _candidates() if row.control_point_id.startswith("floor:")]

    result = TrustedControlPointSelector().resolve_control_plan(
        _context(), None, _floors(), floors_only
    )

    assert result.semantic_primary_control is None
    assert result.unsatisfied_mandatory_floors == ()
    assert result.control_requirement_unsatisfied is False


def test_repository_endpoint_profiles_never_promote_source_presence() -> None:
    profiles = endpoint_floor_profiles()

    assert len(profiles) == 8
    assert {profile.profile_id for profile in profiles} == {
        "macos_endpoint_file",
        "macos_endpoint_process",
        "macos_endpoint_network",
        "macos_semantic_proxy",
        "windows_endpoint_file",
        "windows_endpoint_process",
        "windows_endpoint_network",
        "windows_semantic_proxy",
    }
    assert all(profile.verification_status is VerificationStatus.UNVERIFIED for profile in profiles)
    assert not any(
        claim.verification_status is VerificationStatus.VERIFIED
        for profile in profiles
        for claim in profile.capabilities.values()
    )


def test_windows_profiles_do_not_overstate_unbound_file_or_process_permits() -> None:
    profiles = {profile.profile_id: profile for profile in endpoint_floor_profiles()}
    file_profile = profiles["windows_endpoint_file"]
    process_profile = profiles["windows_endpoint_process"]
    network_profile = profiles["windows_endpoint_network"]

    for dimension in (
        CapabilityDimension.FILE_OPEN_CONTROL,
        CapabilityDimension.FILE_READ_CONTROL,
        CapabilityDimension.FILE_WRITE_CONTROL,
        CapabilityDimension.FILE_CREATE_CONTROL,
        CapabilityDimension.FILE_RENAME_CONTROL,
        CapabilityDimension.FILE_DELETE_CONTROL,
    ):
        assert file_profile.capabilities[dimension].level is CapabilityLevel.INLINE
    assert (
        process_profile.capabilities[CapabilityDimension.PROCESS_EXEC_CONTROL].level
        is CapabilityLevel.INLINE
    )
    assert (
        process_profile.capabilities[CapabilityDimension.CHILD_PROCESS_CONTROL].level
        is CapabilityLevel.INLINE
    )
    assert "exact_precreate_resource_permit_binding" in file_profile.known_blind_spots
    assert "memory_mapped_and_paging_io" in file_profile.known_blind_spots
    assert "exact_target_image_generation_permit_binding" in process_profile.known_blind_spots
    assert (
        network_profile.capabilities[
            CapabilityDimension.NETWORK_DESTINATION_BINDING
        ].level
        is CapabilityLevel.INLINE_BOUND
    )
    assert (
        network_profile.capabilities[
            CapabilityDimension.NETWORK_DESTINATION_BINDING
        ].verification_status
        is VerificationStatus.UNVERIFIED
    )


def test_phase3_capability_dimensions_and_health_states_are_explicit() -> None:
    required_dimensions = {
        "process_discovery",
        "process_identity",
        "process_exec_control",
        "child_process_control",
        "file_open_control",
        "file_read_control",
        "file_write_control",
        "file_create_control",
        "file_rename_control",
        "file_delete_control",
        "file_mmap_control",
        "network_connect_control",
        "network_destination_binding",
        "url_control",
        "http_semantics",
        "content_inspection",
        "quic_control",
        "local_ipc_control",
        "upload_control",
        "download_control",
        "taint_propagation",
        "post_execution_visibility",
        "containment",
        "bypass_detection",
        "config_integrity",
        "self_protection",
    }
    assert required_dimensions <= {item.value for item in CapabilityDimension}
    assert {
        "healthy",
        "degraded",
        "unhealthy",
        "tampered",
        "version_mismatch",
        "policy_stale",
        "not_installed",
        "unknown",
    } <= {item.value for item in HealthState}
