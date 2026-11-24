from __future__ import annotations

from dataclasses import dataclass, replace

from app.services.native_control.adapter_contract import (
    NativeControlAdapter,
    SynchronousBlockingAdapter,
    validate_adapter_contract,
)
from app.services.native_control.contracts import (
    CapabilityClaim,
    CapabilityDimension,
    CapabilityLevel,
    ControlCapabilityProfile,
    ControlPointCandidate,
    ControlPointHealth,
    DegradationMode,
    VerificationStatus,
)
from app.services.native_control.openai_action_matrix import (
    OPENAI_ACTION_SCOPED_DIMENSIONS,
    OpenAIActionClass,
)


_UNKNOWN_ACTION_CLAIM = CapabilityClaim(
    level=CapabilityLevel.UNKNOWN,
    verification_status=VerificationStatus.UNVERIFIED,
)


@dataclass(frozen=True, slots=True)
class AdapterIntegrationContext:
    control_point_id: str
    integration_instance_id: str
    tenant_id: str
    provider_version: str
    policy_version: str
    policy_binding_mode: str
    tenant_binding_valid: bool
    current_degradation_mode: DegradationMode


class ControlPointFactory:
    """Projects verified adapter facts; selection stays in TrustedControlPointSelector."""

    def create(
        self,
        adapter: NativeControlAdapter,
        *,
        integration: AdapterIntegrationContext,
        health: ControlPointHealth,
        action_class: OpenAIActionClass | str | None = None,
    ) -> ControlPointCandidate:
        validate_adapter_contract(adapter)
        manifest = adapter.manifest
        costs = manifest.selection_characteristics
        security = replace(
            manifest.security_properties,
            operational_complexity=costs.operational_complexity,
            required_privilege=costs.required_privilege,
            privacy_impact_score=costs.privacy_impact,
            deployment_friction=costs.deployment_friction,
        )
        capabilities = dict(manifest.capabilities)
        action_blind_spots: tuple[str, ...] = ()
        response_coverage = "unknown"
        if manifest.provider == "openai" and hasattr(adapter, "action_profile"):
            selected_action = action_class or OpenAIActionClass.UNKNOWN_TOOL
            action_profile = adapter.action_profile(selected_action)  # type: ignore[attr-defined]
            for dimension in OPENAI_ACTION_SCOPED_DIMENSIONS:
                capabilities[dimension] = action_profile.capabilities.get(
                    dimension,
                    _UNKNOWN_ACTION_CLAIM,
                )
            action_blind_spots = action_profile.blind_spots
            response_coverage = action_profile.response_coverage.value
        profile = ControlCapabilityProfile(
            profile_id=f"adapter:{adapter.descriptor.adapter_id}",
            profile_version=manifest.schema_version,
            provider=manifest.provider,
            product=manifest.product,
            integration_method=adapter.descriptor.enforcement_methods_supported[0],
            adapter_version=manifest.adapter_version,
            tested_min_version=manifest.provider_version_min,
            tested_max_version=manifest.provider_version_max,
            current_verified_version=(
                manifest.exact_verified_versions[-1]
                if manifest.exact_verified_versions
                else None
            ),
            verification_status=manifest.verification_status,
            verification_source=manifest.source_reference,
            capabilities=capabilities,
            security_properties=security,
            health_requirements=(
                "authentication",
                "validation_current",
                "evidence_flow",
                "configuration_integrity",
                "policy_freshness",
                "provider_version",
            ),
            degradation_modes=manifest.supported_degradation_modes,
            known_blind_spots=(
                *(item.id for item in manifest.known_blind_spots),
                *action_blind_spots,
            ),
            documentation_references=(manifest.source_reference,),
        )
        normalized = set(manifest.event_semantics.normalized_fields)
        visible_fields: list[str] = []
        identity_claim = capabilities.get(CapabilityDimension.IDENTITY)
        if (
            "identity" in normalized
            and identity_claim is not None
            and identity_claim.level not in {CapabilityLevel.UNKNOWN, CapabilityLevel.UNAVAILABLE}
        ):
            visible_fields.append("identity")
        parameter_claim = capabilities.get(CapabilityDimension.PARAMETER_BINDING)
        if (
            {"canonical_parameters", "parameter_hash"} <= normalized
            and parameter_claim is not None
            and parameter_claim.level not in {CapabilityLevel.UNKNOWN, CapabilityLevel.UNAVAILABLE}
        ):
            visible_fields.append("parameters")
        target_claim = capabilities.get(CapabilityDimension.TARGET_BINDING)
        if (
            {"canonical_target", "target_hash"} <= normalized
            and target_claim is not None
            and target_claim.level not in {CapabilityLevel.UNKNOWN, CapabilityLevel.UNAVAILABLE}
        ):
            visible_fields.append("target")
        destination_claim = capabilities.get(CapabilityDimension.DESTINATION_BINDING)
        if (
            "destination_hash" in normalized
            and destination_claim is not None
            and destination_claim.level not in {CapabilityLevel.UNKNOWN, CapabilityLevel.UNAVAILABLE}
        ):
            visible_fields.append("destination")
        result_claim = capabilities.get(CapabilityDimension.POST_EXECUTION_VISIBILITY)
        if (
            manifest.event_semantics.post_execution_events
            and result_claim is not None
            and result_claim.level not in {CapabilityLevel.UNKNOWN, CapabilityLevel.UNAVAILABLE}
        ):
            visible_fields.append("result")
        return ControlPointCandidate(
            control_point_id=integration.control_point_id,
            integration_instance_id=integration.integration_instance_id,
            tenant_id=integration.tenant_id,
            profile=profile,
            health=health,
            provider_version=integration.provider_version,
            adapter_version=adapter.descriptor.adapter_version,
            policy_version=integration.policy_version,
            policy_binding_mode=integration.policy_binding_mode,
            tenant_binding_valid=integration.tenant_binding_valid,
            exposed_lifecycle_events=tuple(
                dict.fromkeys(
                    [
                        *manifest.event_semantics.pre_execution_events,
                        *manifest.event_semantics.post_execution_events,
                    ]
                )
            ),
            visible_action_fields=tuple(visible_fields),
            blocking_semantics=isinstance(adapter, SynchronousBlockingAdapter),
            current_degradation_mode=integration.current_degradation_mode,
            response_coverage=response_coverage,
        )
