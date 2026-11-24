"""Conservative Anthropic Enterprise control boundaries.

These profiles are intentionally *not* executable provider adapters.  They
describe two separately deployable, provider-hosted control boundaries so a
tenant cannot inherit them from Claude Code, a personal Claude account, or a
generic Anthropic-compatible route.  A real enterprise tenant acceptance is
required before either profile can be eligible for enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.native_control.adapter_contract import (
    CapabilityManifest,
    DeploymentFamily,
    DeploymentAcceptanceResult,
    EvidenceQuality,
    EventSemantics,
    SelectionCharacteristics,
    StructuredBlindSpot,
)
from app.services.native_control.contracts import (
    ActionClass,
    CapabilityClaim,
    CapabilityDimension,
    CapabilityLevel,
    ControlMethod,
    DegradationMode,
    ProviderRuntimeContext,
    RuntimeLocation,
    SecurityProperties,
    VerificationStatus,
)


_ENTERPRISE_ACCOUNT_MODES = frozenset(
    {
        "enterprise",
        "enterprise_managed",
        "approved_enterprise",
    }
)
_APPROVED_TENANT_MODES = frozenset(
    {
        "approved_organization",
        "enterprise_managed",
        "tenant_verified",
    }
)


def _unavailable_claims() -> dict[CapabilityDimension, CapabilityClaim]:
    return {
        dimension: CapabilityClaim(
            level=CapabilityLevel.UNAVAILABLE,
            verification_status=VerificationStatus.UNVERIFIED,
        )
        for dimension in CapabilityDimension
    }


def _external_claims(
    *dimensions: CapabilityDimension,
) -> dict[CapabilityDimension, CapabilityClaim]:
    claims = _unavailable_claims()
    for dimension in dimensions:
        claims[dimension] = CapabilityClaim(
            level=CapabilityLevel.EXTERNAL,
            verification_status=VerificationStatus.UNVERIFIED,
        )
    return claims


@dataclass(frozen=True, slots=True)
class AnthropicEnterpriseControlProfile:
    """A provider contract plus the account/tenant gate it must never bypass."""

    contract: CapabilityManifest
    method: ControlMethod

    @property
    def provider(self) -> str:
        return self.contract.provider

    @property
    def product(self) -> str:
        return self.contract.product

    @property
    def required_account_modes(self) -> frozenset[str]:
        """Derived display projection; the contract is the only source of scope."""

        return frozenset(self.contract.required_account_modes)

    @property
    def required_tenant_modes(self) -> frozenset[str]:
        """Derived display projection; the contract is the only source of scope."""

        return frozenset(self.contract.required_tenant_modes)

    def enforcement_ineligibility_reasons(
        self,
        runtime_context: ProviderRuntimeContext | None,
    ) -> tuple[str, ...]:
        """Return reasons rather than inferring a broad enterprise allowance.

        The underlying provider-control contract enforces version, runtime,
        action class, lifecycle, and real-deployment acceptance.  This profile
        adds the enterprise-only account and organization boundary before a
        selection path may consider that contract.
        """

        if runtime_context is None:
            return tuple(
                dict.fromkeys(
                    self.contract.enforcement_ineligibility_reasons(
                        None,
                        self.contract.provider_version_state("unknown"),
                    )
                )
            )

        reasons = list(
            self.contract.enforcement_ineligibility_reasons(
                runtime_context,
                self.contract.provider_version_state(runtime_context.provider_version),
            )
        )
        if runtime_context.account_mode not in self.required_account_modes:
            reasons.append("enterprise_account_context_required")
        if runtime_context.tenant_mode not in self.required_tenant_modes:
            reasons.append("enterprise_tenant_context_required")
        return tuple(dict.fromkeys(reasons))

    def provider_profile(self):
        """Return the existing ProviderCapabilityManifest projection lazily.

        The canonical contract above remains the source of capability truth.
        The product matrix projection is deliberately derived here so it cannot
        strengthen this profile independently.
        """

        from app.services.native_control.manifests import ProviderCapabilityManifest

        return ProviderCapabilityManifest(
            manifest_id=f"anthropic:{self.product}:{self.method.value}",
            manifest_version="provider-capability-manifest/1.0",
            provider=self.contract.provider,
            product=self.contract.product,
            method=self.method,
            supported_versions=(),
            capability_matrix=dict(self.contract.capabilities),
            security_properties=self.contract.security_properties,
            verification_status=self.contract.verification_status,
            verified_at=self.contract.verified_at,
            adapter_version=self.contract.adapter_version,
            verification_evidence=(
                "No Hawk real-enterprise-tenant allow/block/non-execution acceptance exists.",
                "repo:docs/superpowers/specs/2026-08-20-phase4-multi-provider-control-fabric-design.md",
            ),
            official_documentation_reference=self.contract.source_reference,
            required_permissions=self.contract.required_permissions,
            deployment_requirements=(
                "Configure the control in the customer-owned Anthropic Enterprise tenant.",
                "Capture tenant-bound signed callback/route evidence and a real allow, block, and protected non-execution acceptance before Enforce.",
                "Do not apply this profile to personal or unapproved organization accounts.",
            ),
            known_blind_spots=tuple(
                blind_spot.impact for blind_spot in self.contract.known_blind_spots
            ),
            failure_modes=self.contract.failure_modes,
            privacy_implications=(self.contract.privacy_profile,),
            fallback_methods=(
                ControlMethod.GATEWAY_INLINE,
                ControlMethod.ENDPOINT_RUNTIME,
                ControlMethod.OBSERVE_ONLY,
            ),
        )


def _inference_hook_contract() -> CapabilityManifest:
    return CapabilityManifest(
        schema_version="native-control-adapter-manifest/1.0",
        descriptor_id="anthropic.enterprise_inference_hook.provider_boundary",
        provider="anthropic",
        product="enterprise_inference_hook",
        # This is Hawk's explicitly reviewed Enterprise feature-contract
        # identifier, not a claim that Anthropic publishes a provider binary
        # version for this managed service.
        provider_version_min="2026.08.20",
        provider_version_max="2026.08.20",
        exact_verified_versions=(),
        adapter_version="1.0.0",
        verification_status=VerificationStatus.UNVERIFIED,
        verified_at=None,
        source_reference=(
            "provider-enterprise-inference-hook contract requires customer-tenant acceptance"
        ),
        capabilities=_external_claims(
            CapabilityDimension.MODEL_REQUEST_CONTROL,
            CapabilityDimension.MODEL_ROUTE_BINDING,
        ),
        security_properties=SecurityProperties(
            pre_execution_capable=True,
            post_execution_capable=False,
            blocking_strength=0,
            action_fidelity=0,
            identity_quality=0,
            parameter_fidelity=0,
            target_fidelity=0,
            destination_fidelity=0,
            result_fidelity=0,
            bypass_resistance=0,
            tamper_resistance=0,
            expected_latency_ms=0,
            availability_profile="provider_hosted_enterprise_boundary_unverified",
            required_permissions=("anthropic.enterprise.inference_hook.configure",),
            privacy_impact="provider-managed model request metadata; deployment evidence required",
        ),
        required_permissions=("anthropic.enterprise.inference_hook.configure",),
        event_semantics=EventSemantics(
            pre_execution_events=("before_model_request",),
            normalized_fields=("managed_route", "enterprise_account_context"),
            synchronous_decision_mechanism="provider enterprise inference hook; unverified",
            ordering_guaranteed=False,
            runs_before_untrusted_mutators=False,
            runs_after_untrusted_mutators=False,
        ),
        known_blind_spots=(
            StructuredBlindSpot(
                id="anthropic-enterprise-inference-hook-not-accepted",
                control_dimension=CapabilityDimension.MODEL_REQUEST_CONTROL,
                scope="Anthropic Enterprise tenant and managed model-request route",
                condition="No tenant-specific signed callback and real allow/block/non-execution evidence",
                impact="The potential provider-side model-request boundary is unavailable for Hawk Enforce.",
                detection_method="deployment acceptance state and tenant-bound evidence verification",
                mitigation="Complete reviewed tenant acceptance for the exact enterprise configuration and route.",
                evidence=(
                    "docs/superpowers/specs/2026-08-20-phase4-multi-provider-control-fabric-design.md",
                ),
            ),
            StructuredBlindSpot(
                id="anthropic-enterprise-inference-hook-no-tool-semantics",
                control_dimension=CapabilityDimension.TOOL_CONTROL,
                scope="Provider-hosted model request",
                condition="A model request may propose or lead to a tool action",
                impact="Inference-hook control does not authorize tools, parameters, targets, MCP, or endpoint consequences.",
                detection_method="Action-class and capability-contract separation",
                mitigation="Use a verified native/runtime/MCP control point plus endpoint permits for consequential tool actions.",
                evidence=("phase4-action-class-separation",),
            ),
        ),
        failure_modes=(
            "enterprise route not enrolled",
            "provider tenant restriction or hook disabled",
            "direct or personal-account route bypass",
            "real tenant acceptance missing or stale",
        ),
        supported_installation_modes=("customer_enterprise_tenant_configuration",),
        supported_degradation_modes=(
            DegradationMode.REQUIRE_EXCEPTION,
            DegradationMode.MONITOR_ONLY,
        ),
        execution_evidence_quality=EvidenceQuality.NONE,
        selection_characteristics=SelectionCharacteristics(
            latency_cost=0,
            operational_complexity=80,
            required_privilege=80,
            privacy_impact=60,
            deployment_friction=80,
        ),
        supported_action_classes=(ActionClass.MODEL_REQUEST,),
        supported_runtime_locations=(RuntimeLocation.PROVIDER_HOSTED,),
        supported_deployment_families=(DeploymentFamily.SAAS_API,),
        supported_runtimes=("anthropic_enterprise_inference_hook",),
        supported_control_methods=(ControlMethod.PROVIDER_ENTERPRISE_HOOK,),
        supported_lifecycle_events=("before_model_request",),
        required_account_modes=tuple(sorted(_ENTERPRISE_ACCOUNT_MODES)),
        required_tenant_modes=tuple(sorted(_APPROVED_TENANT_MODES)),
        supports_action_mutation=False,
        supports_approval_pause=False,
        retry_semantics="unverified",
        failure_semantics="unverified; never select for enforce",
        privacy_profile="No customer prompts or model content are claimed by Hawk absent customer-approved tenant acceptance.",
        reviewed_by="hawk-provider-contract-review",
        reviewed_at="2026-08-20T00:00:00+00:00",
        reviewed_evidence_refs=(
            "docs/superpowers/specs/2026-08-20-phase4-multi-provider-control-fabric-design.md",
            "docs/native-controls/anthropic.md",
        ),
        deployment_acceptance=DeploymentAcceptanceResult.not_tested(),
    )


def _tenant_restrictions_contract() -> CapabilityManifest:
    return CapabilityManifest(
        schema_version="native-control-adapter-manifest/1.0",
        descriptor_id="anthropic.tenant_restrictions.provider_boundary",
        provider="anthropic",
        product="tenant_restrictions",
        # This is Hawk's explicitly reviewed Enterprise feature-contract
        # identifier, not a claim that Anthropic publishes a provider binary
        # version for this managed service.
        provider_version_min="2026.08.20",
        provider_version_max="2026.08.20",
        exact_verified_versions=(),
        adapter_version="1.0.0",
        verification_status=VerificationStatus.UNVERIFIED,
        verified_at=None,
        source_reference=(
            "provider-tenant-restrictions contract requires customer-tenant acceptance"
        ),
        capabilities=_external_claims(
            CapabilityDimension.IDENTITY,
            CapabilityDimension.MODEL_ROUTE_BINDING,
        ),
        security_properties=SecurityProperties(
            pre_execution_capable=True,
            post_execution_capable=False,
            blocking_strength=0,
            action_fidelity=0,
            identity_quality=0,
            parameter_fidelity=0,
            target_fidelity=0,
            destination_fidelity=0,
            result_fidelity=0,
            bypass_resistance=0,
            tamper_resistance=0,
            expected_latency_ms=0,
            availability_profile="provider_hosted_tenant_route_filter_unverified",
            required_permissions=("anthropic.enterprise.tenant_restrictions.configure",),
            privacy_impact="provider-managed account and route metadata; deployment evidence required",
        ),
        required_permissions=("anthropic.enterprise.tenant_restrictions.configure",),
        event_semantics=EventSemantics(
            pre_execution_events=("before_managed_route",),
            normalized_fields=("managed_route", "enterprise_account_context"),
            synchronous_decision_mechanism="provider tenant restrictions; unverified",
            ordering_guaranteed=False,
            runs_before_untrusted_mutators=False,
            runs_after_untrusted_mutators=False,
        ),
        known_blind_spots=(
            StructuredBlindSpot(
                id="anthropic-tenant-restrictions-not-accepted",
                control_dimension=CapabilityDimension.MODEL_ROUTE_BINDING,
                scope="Anthropic Enterprise managed routes and account filtering",
                condition="No tenant-specific route/account acceptance evidence",
                impact="Managed-route and account filtering cannot become Hawk Enforce coverage.",
                detection_method="tenant-bound route evidence and deployment acceptance state",
                mitigation="Complete reviewed managed-route acceptance in the customer enterprise tenant.",
                evidence=(
                    "docs/superpowers/specs/2026-08-20-phase4-multi-provider-control-fabric-design.md",
                ),
            ),
            StructuredBlindSpot(
                id="anthropic-tenant-restrictions-no-action-authorization",
                control_dimension=CapabilityDimension.TOOL_CONTROL,
                scope="Provider account and managed-route filter",
                condition="A request is allowed onto a managed provider route",
                impact="Tenant restrictions do not supply Hawk tool, parameter, target, MCP, or endpoint authorization.",
                detection_method="Action-class and capability-contract separation",
                mitigation="Compose a verified semantic action control and endpoint permit where the action is consequential.",
                evidence=("phase4-action-class-separation",),
            ),
        ),
        failure_modes=(
            "tenant restriction not enrolled",
            "personal or unapproved organization account",
            "direct route bypass",
            "real tenant acceptance missing or stale",
        ),
        supported_installation_modes=("customer_enterprise_tenant_configuration",),
        supported_degradation_modes=(
            DegradationMode.REQUIRE_EXCEPTION,
            DegradationMode.MONITOR_ONLY,
        ),
        execution_evidence_quality=EvidenceQuality.NONE,
        selection_characteristics=SelectionCharacteristics(
            latency_cost=0,
            operational_complexity=75,
            required_privilege=80,
            privacy_impact=45,
            deployment_friction=75,
        ),
        # Tenant Restrictions are an account/managed-route eligibility check
        # for a model request.  They never grant generic API action authority.
        supported_action_classes=(ActionClass.MODEL_REQUEST,),
        supported_runtime_locations=(RuntimeLocation.PROVIDER_HOSTED,),
        supported_deployment_families=(DeploymentFamily.SAAS_API,),
        supported_runtimes=("anthropic_enterprise_tenant_restrictions",),
        supported_control_methods=(ControlMethod.PROVIDER_TENANT_RESTRICTION,),
        supported_lifecycle_events=("before_managed_route",),
        required_account_modes=tuple(sorted(_ENTERPRISE_ACCOUNT_MODES)),
        required_tenant_modes=tuple(sorted(_APPROVED_TENANT_MODES)),
        supports_action_mutation=False,
        supports_approval_pause=False,
        retry_semantics="unverified",
        failure_semantics="unverified; never select for enforce",
        privacy_profile="No customer prompts or account content are claimed by Hawk absent customer-approved tenant acceptance.",
        reviewed_by="hawk-provider-contract-review",
        reviewed_at="2026-08-20T00:00:00+00:00",
        reviewed_evidence_refs=(
            "docs/superpowers/specs/2026-08-20-phase4-multi-provider-control-fabric-design.md",
            "docs/native-controls/anthropic.md",
        ),
        deployment_acceptance=DeploymentAcceptanceResult.not_tested(),
    )


ANTHROPIC_ENTERPRISE_INFERENCE_HOOK = _inference_hook_contract()
ANTHROPIC_TENANT_RESTRICTIONS = _tenant_restrictions_contract()


_PROFILES = (
    AnthropicEnterpriseControlProfile(
        contract=ANTHROPIC_ENTERPRISE_INFERENCE_HOOK,
        method=ControlMethod.PROVIDER_ENTERPRISE_HOOK,
    ),
    AnthropicEnterpriseControlProfile(
        contract=ANTHROPIC_TENANT_RESTRICTIONS,
        method=ControlMethod.PROVIDER_TENANT_RESTRICTION,
    ),
)


def anthropic_enterprise_control_profiles() -> tuple[AnthropicEnterpriseControlProfile, ...]:
    return _PROFILES


def anthropic_enterprise_provider_profiles():
    return tuple(profile.provider_profile() for profile in _PROFILES)
