from __future__ import annotations

from app.services.native_control.contracts import (
    CapabilityClaim,
    CapabilityDimension,
    CapabilityLevel,
    ControlCapabilityProfile,
    ControlMethod,
    DegradationMode,
    SecurityProperties,
    VerificationStatus,
)


def _claim(level: CapabilityLevel) -> CapabilityClaim:
    # Repository source is implementation evidence, not runtime acceptance.
    return CapabilityClaim(level=level, verification_status=VerificationStatus.UNVERIFIED)


def _capabilities(
    overrides: dict[CapabilityDimension, CapabilityLevel],
) -> dict[CapabilityDimension, CapabilityClaim]:
    values = {
        dimension: _claim(CapabilityLevel.UNKNOWN)
        for dimension in CapabilityDimension
    }
    for dimension, level in overrides.items():
        values[dimension] = _claim(level)
    return values


def _profile(
    profile_id: str,
    *,
    capabilities: dict[CapabilityDimension, CapabilityLevel],
    blind_spots: tuple[str, ...],
    permissions: tuple[str, ...],
) -> ControlCapabilityProfile:
    return ControlCapabilityProfile(
        profile_id=profile_id,
        profile_version="endpoint-enforcement-floor/1.0",
        provider="hawk_endpoint",
        product=profile_id,
        integration_method=ControlMethod.ENDPOINT_RUNTIME,
        adapter_version="1.0.0",
        tested_min_version=None,
        tested_max_version=None,
        current_verified_version=None,
        verification_status=VerificationStatus.UNVERIFIED,
        verification_source=f"repo:apps/endpoint-agent/native/{profile_id}",
        capabilities=_capabilities(capabilities),
        security_properties=SecurityProperties(
            pre_execution_capable=True,
            post_execution_capable=True,
            blocking_strength=90,
            action_fidelity=70,
            identity_quality=85,
            parameter_fidelity=40,
            target_fidelity=75,
            destination_fidelity=75,
            result_fidelity=65,
            bypass_resistance=90,
            tamper_resistance=85,
            expected_latency_ms=25,
            availability_profile="local_signed_policy_only",
            required_permissions=permissions,
            privacy_impact="bounded_endpoint_metadata",
        ),
        health_requirements=(
            "signed_runtime_artifact",
            "managed_activation",
            "fresh_signed_local_policy",
            "configuration_integrity",
            "runtime_acceptance_receipt",
            "evidence_flow",
        ),
        degradation_modes=(
            DegradationMode.FAIL_CLOSED,
            DegradationMode.LOCAL_POLICY_ONLY,
            DegradationMode.REQUIRE_EXCEPTION,
        ),
        known_blind_spots=blind_spots,
        documentation_references=(
            "repo:docs/superpowers/plans/2026-08-12-universal-endpoint-enforcement-floor.md",
        ),
    )


def endpoint_floor_profiles() -> tuple[ControlCapabilityProfile, ...]:
    common = {
        CapabilityDimension.DISCOVERY: CapabilityLevel.OBSERVE,
        CapabilityDimension.IDENTITY: CapabilityLevel.OBSERVE,
        CapabilityDimension.PROCESS_DISCOVERY: CapabilityLevel.OBSERVE,
        CapabilityDimension.PROCESS_IDENTITY: CapabilityLevel.INLINE_BOUND,
        CapabilityDimension.POST_EXECUTION_VISIBILITY: CapabilityLevel.OBSERVE,
        CapabilityDimension.BYPASS_DETECTION: CapabilityLevel.OBSERVE,
        CapabilityDimension.TAMPER_RESISTANCE: CapabilityLevel.OBSERVE,
        CapabilityDimension.CONFIG_INTEGRITY: CapabilityLevel.OBSERVE,
        CapabilityDimension.SELF_PROTECTION: CapabilityLevel.OBSERVE,
        CapabilityDimension.CONTAINMENT: CapabilityLevel.EXTERNAL,
    }
    return (
        _profile(
            "macos_endpoint_file",
            capabilities={
                **common,
                CapabilityDimension.FILE_OPEN_CONTROL: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.FILE_READ_CONTROL: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.FILE_WRITE_CONTROL: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.FILE_CREATE_CONTROL: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.FILE_RENAME_CONTROL: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.FILE_DELETE_CONTROL: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.FILE_MMAP_CONTROL: CapabilityLevel.UNKNOWN,
            },
            blind_spots=("cloud_side_file_actions", "file_semantics_not_exposed_by_os"),
            permissions=("endpoint-security-client", "full-disk-access", "system-extension"),
        ),
        _profile(
            "macos_endpoint_process",
            capabilities={
                **common,
                CapabilityDimension.PROCESS_EXEC_CONTROL: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.CHILD_PROCESS_CONTROL: CapabilityLevel.INLINE_BOUND,
            },
            blind_spots=("cloud_side_execution",),
            permissions=("endpoint-security-client", "system-extension"),
        ),
        _profile(
            "macos_endpoint_network",
            capabilities={
                **common,
                CapabilityDimension.NETWORK_CONTROL: CapabilityLevel.INLINE,
                CapabilityDimension.NETWORK_CONNECT_CONTROL: CapabilityLevel.INLINE,
                CapabilityDimension.DESTINATION_BINDING: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.NETWORK_DESTINATION_BINDING: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.QUIC_CONTROL: CapabilityLevel.INLINE,
                CapabilityDimension.LOCAL_IPC_CONTROL: CapabilityLevel.UNKNOWN,
                CapabilityDimension.UPLOAD_CONTROL: CapabilityLevel.INLINE,
                CapabilityDimension.DOWNLOAD_CONTROL: CapabilityLevel.INLINE,
                CapabilityDimension.TAINT_PROPAGATION: CapabilityLevel.OBSERVE,
            },
            blind_spots=("encrypted_content_without_approved_inspection", "cloud_side_actions"),
            permissions=("network-extension-content-filter", "system-extension", "mdm-approval"),
        ),
        _profile(
            "macos_semantic_proxy",
            capabilities={
                **common,
                CapabilityDimension.NETWORK_CONTROL: CapabilityLevel.EXTERNAL,
                CapabilityDimension.NETWORK_CONNECT_CONTROL: CapabilityLevel.EXTERNAL,
                CapabilityDimension.NETWORK_DESTINATION_BINDING: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.URL_CONTROL: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.HTTP_SEMANTICS: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.CONTENT_INSPECTION: CapabilityLevel.UNKNOWN,
                CapabilityDimension.UPLOAD_CONTROL: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.DOWNLOAD_CONTROL: CapabilityLevel.INLINE_BOUND,
            },
            blind_spots=("certificate_pinning", "unapproved_tls_inspection", "non_http_protocols"),
            permissions=("managed-routing",),
        ),
        _profile(
            "windows_endpoint_file",
            capabilities={
                **common,
                CapabilityDimension.FILE_OPEN_CONTROL: CapabilityLevel.INLINE,
                CapabilityDimension.FILE_READ_CONTROL: CapabilityLevel.INLINE,
                CapabilityDimension.FILE_WRITE_CONTROL: CapabilityLevel.INLINE,
                CapabilityDimension.FILE_CREATE_CONTROL: CapabilityLevel.INLINE,
                CapabilityDimension.FILE_RENAME_CONTROL: CapabilityLevel.INLINE,
                CapabilityDimension.FILE_DELETE_CONTROL: CapabilityLevel.INLINE,
                CapabilityDimension.FILE_MMAP_CONTROL: CapabilityLevel.UNKNOWN,
            },
            blind_spots=(
                "exact_precreate_resource_permit_binding",
                "memory_mapped_and_paging_io",
                "cloud_side_file_actions",
            ),
            permissions=("signed-minifilter-driver", "administrator", "mdm-approval"),
        ),
        _profile(
            "windows_endpoint_process",
            capabilities={
                **common,
                CapabilityDimension.PROCESS_EXEC_CONTROL: CapabilityLevel.INLINE,
                CapabilityDimension.CHILD_PROCESS_CONTROL: CapabilityLevel.INLINE,
            },
            blind_spots=(
                "exact_target_image_generation_permit_binding",
                "cloud_side_execution",
            ),
            permissions=("signed-kernel-driver", "administrator"),
        ),
        _profile(
            "windows_endpoint_network",
            capabilities={
                **common,
                CapabilityDimension.NETWORK_CONTROL: CapabilityLevel.INLINE,
                CapabilityDimension.NETWORK_CONNECT_CONTROL: CapabilityLevel.INLINE,
                CapabilityDimension.DESTINATION_BINDING: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.NETWORK_DESTINATION_BINDING: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.QUIC_CONTROL: CapabilityLevel.INLINE,
                CapabilityDimension.LOCAL_IPC_CONTROL: CapabilityLevel.UNKNOWN,
                CapabilityDimension.UPLOAD_CONTROL: CapabilityLevel.INLINE,
                CapabilityDimension.DOWNLOAD_CONTROL: CapabilityLevel.INLINE,
                CapabilityDimension.TAINT_PROPAGATION: CapabilityLevel.OBSERVE,
            },
            blind_spots=("encrypted_content_without_approved_inspection", "cloud_side_actions"),
            permissions=("signed-wfp-callout-driver", "administrator"),
        ),
        _profile(
            "windows_semantic_proxy",
            capabilities={
                **common,
                CapabilityDimension.NETWORK_CONTROL: CapabilityLevel.EXTERNAL,
                CapabilityDimension.NETWORK_CONNECT_CONTROL: CapabilityLevel.EXTERNAL,
                CapabilityDimension.NETWORK_DESTINATION_BINDING: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.URL_CONTROL: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.HTTP_SEMANTICS: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.CONTENT_INSPECTION: CapabilityLevel.UNKNOWN,
                CapabilityDimension.UPLOAD_CONTROL: CapabilityLevel.INLINE_BOUND,
                CapabilityDimension.DOWNLOAD_CONTROL: CapabilityLevel.INLINE_BOUND,
            },
            blind_spots=("certificate_pinning", "unapproved_tls_inspection", "non_http_protocols"),
            permissions=("managed-routing",),
        ),
    )
