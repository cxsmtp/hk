"""Direct and cloud-provider control contracts without provider-wide inheritance.

These reviewed contracts describe five different *possible* model-route
boundaries.  They are deliberately not executable adapters, route records, or
policy engines.  Hawk must receive immutable, tenant-bound deployment
acceptance for the exact provider/product/runtime/model/route/deployment before
any one can be selected for Enforce.

A Hawk gateway route remains a separately proven control point.  Its model
request/response capability never promotes a direct-provider API, customer
cloud deployment, provider-hosted runtime, tool proposal, tool execution,
hosted tool, MCP operation, or remote consequence.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.native_control.adapter_contract import (
    CapabilityManifest,
    DeploymentAcceptanceResult,
    DeploymentFamily,
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


_REVIEWED_AT = "2026-08-21T00:00:00+00:00"
_CONTRACT_EVIDENCE = (
    "repo:docs/superpowers/specs/2026-08-20-phase4-multi-provider-control-fabric-design.md",
    "repo:docs/native-controls/direct-cloud-provider-contracts.md",
)
_NOT_TESTED = DeploymentAcceptanceResult.not_tested()


def _unavailable_claims() -> dict[CapabilityDimension, CapabilityClaim]:
    return {
        dimension: CapabilityClaim(
            level=CapabilityLevel.UNAVAILABLE,
            verification_status=VerificationStatus.UNVERIFIED,
        )
        for dimension in CapabilityDimension
    }


def _claims() -> dict[CapabilityDimension, CapabilityClaim]:
    """Potential route claims that cannot select an enforcement path yet."""

    claims = _unavailable_claims()
    for dimension, level in (
        (CapabilityDimension.RUNTIME_IDENTITY, CapabilityLevel.OBSERVE),
        (CapabilityDimension.MODEL_ROUTE_BINDING, CapabilityLevel.OBSERVE),
        (CapabilityDimension.IDENTITY, CapabilityLevel.OBSERVE),
        (CapabilityDimension.MODEL_REQUEST_CONTROL, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.MODEL_RESPONSE_CONTROL, CapabilityLevel.OBSERVE),
        (CapabilityDimension.DIRECT_API_CONTROL, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.POST_EXECUTION_VISIBILITY, CapabilityLevel.OBSERVE),
        (CapabilityDimension.BYPASS_DETECTION, CapabilityLevel.OBSERVE),
    ):
        claims[dimension] = CapabilityClaim(
            level=level,
            verification_status=VerificationStatus.UNVERIFIED,
            evidence_refs=_CONTRACT_EVIDENCE,
        )
    return claims


def _blind_spot(
    *,
    identifier: str,
    dimension: CapabilityDimension,
    scope: str,
    condition: str,
    impact: str,
    mitigation: str,
) -> StructuredBlindSpot:
    return StructuredBlindSpot(
        id=identifier,
        control_dimension=dimension,
        scope=scope,
        condition=condition,
        impact=impact,
        detection_method=(
            "immutable tenant-bound deployment acceptance with exact provider, product, "
            "runtime, model, route, deployment, allow, block, and protected non-execution evidence"
        ),
        mitigation=mitigation,
        evidence=_CONTRACT_EVIDENCE,
    )


def _contract(
    *,
    descriptor_id: str,
    provider: str,
    product: str,
    runtime: str,
    runtime_location: RuntimeLocation,
    method: ControlMethod,
    lifecycle_event: str,
    account_mode: str,
    tenant_mode: str,
    source_reference: str,
) -> CapabilityManifest:
    """Build a reviewed boundary hypothesis with no accepted provider version.

    The opaque version sentinel prevents a real provider/runtime version from
    accidentally receiving compatibility or Enforce eligibility.  Tool
    proposal is model output; exact tool execution remains an independent
    Hawk-native, runtime, MCP, endpoint, or target-service boundary.
    """

    return CapabilityManifest(
        schema_version="native-control-adapter-manifest/1.0",
        descriptor_id=descriptor_id,
        provider=provider,
        product=product,
        provider_version_min="not-accepted",
        provider_version_max="not-accepted",
        exact_verified_versions=(),
        adapter_version="1.0.0",
        verification_status=VerificationStatus.UNVERIFIED,
        verified_at=None,
        source_reference=source_reference,
        capabilities=_claims(),
        security_properties=SecurityProperties(
            pre_execution_capable=True,
            post_execution_capable=True,
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
            availability_profile="direct_cloud_provider_boundary_unverified_not_tested",
            required_permissions=("customer.provider.route.interceptor.configure",),
            privacy_impact=(
                "No raw prompt, response, credential, account identifier, model content, "
                "or remote tool payload is claimed by Hawk before real acceptance."
            ),
        ),
        required_permissions=("customer.provider.route.interceptor.configure",),
        event_semantics=EventSemantics(
            pre_execution_events=(lifecycle_event,),
            post_execution_events=("after_model_response",),
            normalized_fields=(
                "provider_product",
                "runtime_location",
                "account_context",
                "tenant_context",
                "model_provider",
                "model",
                "route_identity",
                "deployment_identity",
            ),
            synchronous_decision_mechanism=(
                "customer-bound provider route interceptor required; unverified"
            ),
            ordering_guaranteed=False,
            runs_before_untrusted_mutators=False,
            runs_after_untrusted_mutators=False,
        ),
        known_blind_spots=(
            _blind_spot(
                identifier=f"{provider}-{product}-route-not-accepted",
                dimension=CapabilityDimension.MODEL_REQUEST_CONTROL,
                scope=f"{provider} {product} exact model request route",
                condition=(
                    "No exact customer/provider route, version, account, tenant, model, "
                    "deployment, allow, block, protected non-execution, latency, or failure-mode acceptance exists"
                ),
                impact=(
                    "Hawk cannot select this direct/cloud provider profile for Enforce or "
                    "claim a verified model-request boundary."
                ),
                mitigation=(
                    "Bind the final route and accept the exact provider/product/runtime, "
                    "account/tenant, model, deployment, route, allow, block, non-execution, "
                    "timeout, and bypass behaviour."
                ),
            ),
            _blind_spot(
                identifier=f"{provider}-{product}-tool-proposal-not-execution",
                dimension=CapabilityDimension.TOOL_CONTROL,
                scope=f"{provider} {product} provider/model tool proposals",
                condition=(
                    "A model response proposes a function, hosted tool, MCP operation, shell, "
                    "browser task, or other remote consequence"
                ),
                impact=(
                    "Model-route control does not authorize exact tool invocation, parameters, "
                    "targets, destinations, hosted execution, MCP, or post-execution outcome."
                ),
                mitigation=(
                    "Use an independently accepted Hawk tool-loop, MCP, native adapter, "
                    "endpoint permit, runtime middleware, or target-service revalidation boundary."
                ),
            ),
            _blind_spot(
                identifier=f"{provider}-{product}-gateway-and-direct-route-separation",
                dimension=CapabilityDimension.BYPASS_DETECTION,
                scope=f"{provider} {product} direct, alternate, and Hawk-gateway routes",
                condition=(
                    "A workload switches between the generic Hawk gateway, direct provider "
                    "endpoint, alternate deployment, protocol-compatible endpoint, or remote agent"
                ),
                impact=(
                    "A verified generic gateway route cannot promote this direct/cloud profile "
                    "or prove remote execution, account context, route completeness, or bypass resistance."
                ),
                mitigation=(
                    "Keep gateway and provider profiles separate; bind and accept each exact "
                    "route/deployment independently and surface missing evidence as Unknown."
                ),
            ),
        ),
        failure_modes=(
            "customer provider route interceptor omitted",
            "generic Hawk gateway route does not match provider route",
            "direct or alternate provider endpoint bypass",
            "account, tenant, model, route, or deployment identity unavailable or drifted",
            "tool or hosted execution occurs outside the model-route boundary",
            "provider/runtime version unsupported or unknown",
            "real tenant/cloud deployment acceptance missing or stale",
        ),
        supported_installation_modes=("customer_provider_route_configuration",),
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
        supported_action_classes=(
            ActionClass.MODEL_REQUEST,
            ActionClass.MODEL_RESPONSE,
        ),
        supported_runtime_locations=(runtime_location,),
        supported_deployment_families=(DeploymentFamily.SAAS_API,),
        supported_runtimes=(runtime,),
        supported_control_methods=(method,),
        supported_lifecycle_events=(lifecycle_event,),
        required_account_modes=(account_mode,),
        required_tenant_modes=(tenant_mode,),
        supports_action_mutation=False,
        supports_approval_pause=False,
        retry_semantics="unverified",
        failure_semantics="unverified; never select for enforce",
        privacy_profile=(
            "Hawk stores no raw direct/cloud provider request, response, credential, account, "
            "tool payload, or remote execution content by default."
        ),
        reviewed_by="hawk-provider-contract-review",
        reviewed_at=_REVIEWED_AT,
        reviewed_evidence_refs=_CONTRACT_EVIDENCE,
        deployment_acceptance=_NOT_TESTED,
    )


ANTHROPIC_DIRECT_API = _contract(
    descriptor_id="anthropic.direct_api.customer_route",
    provider="anthropic",
    product="direct_api",
    runtime="anthropic_direct_api",
    runtime_location=RuntimeLocation.PROVIDER_HOSTED,
    method=ControlMethod.API_INTERCEPT,
    lifecycle_event="before_anthropic_direct_model_request",
    account_mode="anthropic_customer_credential_bound",
    tenant_mode="anthropic_tenant_context_bound",
    source_reference=(
        "Anthropic direct API is separate from Claude Code, Enterprise inference hook, "
        "Tenant Restrictions, and the generic Hawk gateway route"
    ),
)

GEMINI_API = _contract(
    descriptor_id="google.gemini_api.customer_route",
    provider="google",
    product="gemini_api",
    runtime="google_gemini_api",
    runtime_location=RuntimeLocation.PROVIDER_HOSTED,
    method=ControlMethod.API_INTERCEPT,
    lifecycle_event="before_google_gemini_api_model_request",
    account_mode="google_gemini_api_credential_bound",
    tenant_mode="google_gemini_api_tenant_context_bound",
    source_reference=(
        "Google Gemini API is separate from Gemini CLI native hooks, Vertex AI, Google tenant "
        "administration, hosted tools, and the generic Hawk gateway route"
    ),
)

VERTEX_AI = _contract(
    descriptor_id="google.vertex_ai.customer_cloud_route",
    provider="google",
    product="vertex_ai",
    runtime="google_vertex_ai",
    runtime_location=RuntimeLocation.CUSTOMER_CLOUD,
    method=ControlMethod.API_INTERCEPT,
    lifecycle_event="before_google_vertex_ai_model_request",
    account_mode="google_cloud_project_credential_bound",
    tenant_mode="google_cloud_project_tenant_bound",
    source_reference=(
        "Google Vertex AI customer-cloud deployment is separate from Gemini API, Gemini CLI, "
        "provider-hosted tools, and the generic Hawk gateway route"
    ),
)

AZURE_OPENAI_DIRECT_API = _contract(
    descriptor_id="azure.azure_openai_direct_api.customer_cloud_route",
    provider="azure",
    product="azure_openai_direct_api",
    runtime="azure_openai_direct_api",
    runtime_location=RuntimeLocation.CUSTOMER_CLOUD,
    method=ControlMethod.API_INTERCEPT,
    lifecycle_event="before_azure_openai_direct_model_request",
    account_mode="azure_subscription_credential_bound",
    tenant_mode="azure_tenant_context_bound",
    source_reference=(
        "Azure OpenAI direct API deployment is separate from Microsoft Agent Framework, "
        "Microsoft Foundry hosted runtime, APIM, and the generic Hawk gateway route"
    ),
)

MICROSOFT_FOUNDRY_HOSTED_MODEL_RUNTIME = _contract(
    descriptor_id="microsoft.foundry_hosted_model_runtime.provider_boundary",
    provider="microsoft",
    product="foundry_hosted_model_runtime",
    runtime="microsoft_foundry_hosted_model_runtime",
    runtime_location=RuntimeLocation.REMOTE_AGENT,
    method=ControlMethod.SAAS_CONTROL_API,
    lifecycle_event="before_microsoft_foundry_hosted_model_request",
    account_mode="microsoft_foundry_project_credential_bound",
    tenant_mode="microsoft_foundry_tenant_context_bound",
    source_reference=(
        "Microsoft Foundry hosted model/runtime is separate from Azure OpenAI direct API, "
        "local Agent Framework Function middleware, hosted tools/MCP, and the generic Hawk gateway route"
    ),
)


@dataclass(frozen=True, slots=True)
class DirectCloudProviderControlProfile:
    """Non-authorizing matrix projection around one canonical contract.

    This class adds only deterministic scope guards.  The underlying
    :class:`CapabilityManifest` and its immutable
    :class:`DeploymentAcceptanceResult` remain the one source of contract and
    deployment proof; no independent route/deployment record is created here.
    """

    contract: CapabilityManifest
    method: ControlMethod

    def enforcement_ineligibility_reasons(
        self,
        runtime_context: ProviderRuntimeContext,
    ) -> tuple[str, ...]:
        version_state = self.contract.provider_version_state(
            runtime_context.provider_version
        )
        reasons = list(
            self.contract.enforcement_ineligibility_reasons(
                runtime_context,
                version_state,
            )
        )
        model_provider = runtime_context.model_provider.strip().lower()
        model = runtime_context.model.strip().lower()
        if model_provider in {"", "unknown", "unknown_provider"}:
            reasons.append("model_provider_unresolved")
        if model in {"", "unknown"}:
            reasons.append("model_identity_unresolved")

        acceptance = self.contract.deployment_acceptance
        accepted_scope = (
            acceptance.model_provider,
            acceptance.model,
            acceptance.route_identity,
            acceptance.deployment_identity,
        )
        if (
            not acceptance.is_real_acceptance
            or any(value.strip().lower() in {"", "unknown"} for value in accepted_scope)
        ):
            reasons.append("exact_model_route_acceptance_missing")
        return tuple(dict.fromkeys(reasons))

    def provider_profile(self):
        """Project the contract into the existing matrix without strengthening it."""

        from app.services.native_control.manifests import ProviderCapabilityManifest

        return ProviderCapabilityManifest(
            manifest_id=(
                f"{self.contract.provider}:{self.contract.product}:{self.method.value}"
            ),
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
                "No real tenant/cloud provider deployment allow, block, or protected non-execution acceptance exists.",
                *_CONTRACT_EVIDENCE,
            ),
            official_documentation_reference=self.contract.source_reference,
            required_permissions=self.contract.required_permissions,
            deployment_requirements=(
                "Bind the exact provider product, account/tenant context, runtime location, model, route, and deployment identity.",
                "Complete immutable tenant/cloud deployment acceptance with exact allow, block, protected non-execution, latency, failure-mode, direct-route, alternate-route, and remote-execution evidence before Enforce.",
                "Accept tool-loop, hosted-tool, MCP, endpoint, and target-service boundaries separately; a model proposal is not exact tool execution authority.",
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


DIRECT_CLOUD_PROVIDER_PROFILES = (
    DirectCloudProviderControlProfile(ANTHROPIC_DIRECT_API, ControlMethod.API_INTERCEPT),
    DirectCloudProviderControlProfile(GEMINI_API, ControlMethod.API_INTERCEPT),
    DirectCloudProviderControlProfile(VERTEX_AI, ControlMethod.API_INTERCEPT),
    DirectCloudProviderControlProfile(
        AZURE_OPENAI_DIRECT_API,
        ControlMethod.API_INTERCEPT,
    ),
    DirectCloudProviderControlProfile(
        MICROSOFT_FOUNDRY_HOSTED_MODEL_RUNTIME,
        ControlMethod.SAAS_CONTROL_API,
    ),
)


def direct_cloud_provider_control_profiles() -> tuple[DirectCloudProviderControlProfile, ...]:
    """Return reviewed contract profiles; no route probing or policy occurs."""

    return DIRECT_CLOUD_PROVIDER_PROFILES


def direct_cloud_provider_matrix_profiles():
    """Return conservative existing-matrix projections derived from contracts."""

    return tuple(profile.provider_profile() for profile in DIRECT_CLOUD_PROVIDER_PROFILES)
