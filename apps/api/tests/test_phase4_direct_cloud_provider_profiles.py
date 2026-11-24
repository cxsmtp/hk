from __future__ import annotations

from app.services.native_control.contracts import (
    ActionClass,
    CapabilityDimension,
    CapabilityLevel,
    ControlMethod,
    DeploymentAcceptanceState,
    ProviderRuntimeContext,
    RuntimeLocation,
    VerificationStatus,
)
from app.services.native_control.direct_cloud_provider_profiles import (
    ANTHROPIC_DIRECT_API,
    AZURE_OPENAI_DIRECT_API,
    DIRECT_CLOUD_PROVIDER_PROFILES,
    GEMINI_API,
    MICROSOFT_FOUNDRY_HOSTED_MODEL_RUNTIME,
    VERTEX_AI,
    direct_cloud_provider_control_profiles,
    direct_cloud_provider_matrix_profiles,
)
from app.services.native_control.manifests import build_default_registry


def _context_for(profile, **overrides) -> ProviderRuntimeContext:
    contract = profile.contract
    values = {
        "provider": contract.provider,
        "product": contract.product,
        "runtime": contract.supported_runtimes[0],
        "action_class": ActionClass.MODEL_REQUEST,
        "runtime_location": contract.supported_runtime_locations[0],
        "provider_version": "unaccepted-provider-version",
        "adapter_version": contract.adapter_version,
        "control_method": profile.method,
        "environment": "production",
        "application": "customer-approved-application",
        "application_version": "1.0.0",
        "runtime_version": "unaccepted-provider-version",
        "model_provider": contract.provider,
        "model": "customer-selected-model",
        "route_identity": "customer-route:direct-cloud-review",
        "deployment_identity": "customer-deployment:direct-cloud-review",
        "deployment_reference": "customer-deployment-ref:direct-cloud-review",
        "lifecycle_stage": contract.supported_lifecycle_events[0],
        "account_mode": contract.required_account_modes[0],
        "tenant_mode": contract.required_tenant_modes[0],
        "route_evidence_ref": "repo:tests/direct-cloud-provider-route.json",
        "route_evidence_fresh": True,
    }
    values.update(overrides)
    return ProviderRuntimeContext(**values)


def test_direct_cloud_profiles_are_separate_reviewed_not_tested_contracts() -> None:
    profiles = direct_cloud_provider_control_profiles()

    assert profiles == DIRECT_CLOUD_PROVIDER_PROFILES
    assert tuple(profile.contract for profile in profiles) == (
        ANTHROPIC_DIRECT_API,
        GEMINI_API,
        VERTEX_AI,
        AZURE_OPENAI_DIRECT_API,
        MICROSOFT_FOUNDRY_HOSTED_MODEL_RUNTIME,
    )
    assert {(profile.contract.provider, profile.contract.product) for profile in profiles} == {
        ("anthropic", "direct_api"),
        ("google", "gemini_api"),
        ("google", "vertex_ai"),
        ("azure", "azure_openai_direct_api"),
        ("microsoft", "foundry_hosted_model_runtime"),
    }

    for profile in profiles:
        contract = profile.contract
        assert contract.is_reviewed_contract is True
        assert contract.verification_status is VerificationStatus.UNVERIFIED
        assert contract.deployment_acceptance.state is DeploymentAcceptanceState.NOT_TESTED
        assert contract.deployment_acceptance.is_real_acceptance is False
        assert contract.exact_verified_versions == ()
        assert profile.enforcement_ineligibility_reasons(_context_for(profile))
        assert "contract_not_verified" in profile.enforcement_ineligibility_reasons(
            _context_for(profile)
        )
        assert "deployment_acceptance_not_real" in profile.enforcement_ineligibility_reasons(
            _context_for(profile)
        )


def test_direct_cloud_profiles_never_convert_model_routes_into_tool_or_hosted_execution_authority() -> None:
    profiles = direct_cloud_provider_control_profiles()
    unsupported = (
        CapabilityDimension.TOOL_CONTROL,
        CapabilityDimension.FUNCTION_TOOL_CONTROL,
        CapabilityDimension.MCP_CONTROL,
        CapabilityDimension.LOCAL_MCP_CONTROL,
        CapabilityDimension.HOSTED_MCP_CONTROL,
        CapabilityDimension.PARAMETER_BINDING,
        CapabilityDimension.TARGET_BINDING,
        CapabilityDimension.DESTINATION_BINDING,
        CapabilityDimension.PERSISTENT_SIDE_EFFECT_CONTROL,
        CapabilityDimension.POST_EXECUTION_VERIFICATION,
    )

    for profile in profiles:
        contract = profile.contract
        assert contract.supported_action_classes == (
            ActionClass.MODEL_REQUEST,
            ActionClass.MODEL_RESPONSE,
        )
        assert contract.capabilities[CapabilityDimension.MODEL_REQUEST_CONTROL].level is CapabilityLevel.INLINE_BOUND
        assert contract.capabilities[CapabilityDimension.MODEL_REQUEST_CONTROL].verification_status is VerificationStatus.UNVERIFIED
        assert contract.capabilities[CapabilityDimension.MODEL_RESPONSE_CONTROL].level is CapabilityLevel.OBSERVE
        for dimension in unsupported:
            claim = contract.capabilities[dimension]
            assert claim.level is CapabilityLevel.UNAVAILABLE
            assert claim.verification_status is VerificationStatus.UNVERIFIED


def test_gemini_api_and_vertex_ai_are_independent_control_and_execution_boundaries() -> None:
    assert GEMINI_API.provider == VERTEX_AI.provider == "google"
    assert GEMINI_API.product == "gemini_api"
    assert VERTEX_AI.product == "vertex_ai"
    assert GEMINI_API.supported_runtimes == ("google_gemini_api",)
    assert VERTEX_AI.supported_runtimes == ("google_vertex_ai",)
    assert GEMINI_API.supported_runtime_locations == (RuntimeLocation.PROVIDER_HOSTED,)
    assert VERTEX_AI.supported_runtime_locations == (RuntimeLocation.CUSTOMER_CLOUD,)
    assert GEMINI_API.supported_control_methods == (ControlMethod.API_INTERCEPT,)
    assert VERTEX_AI.supported_control_methods == (ControlMethod.API_INTERCEPT,)

    vertex_as_direct = _context_for(
        direct_cloud_provider_control_profiles()[2],
        product="gemini_api",
        runtime="google_gemini_api",
        runtime_location=RuntimeLocation.PROVIDER_HOSTED,
    )
    reasons = VERTEX_AI.enforcement_ineligibility_reasons(
        vertex_as_direct,
        VERTEX_AI.provider_version_state(vertex_as_direct.provider_version),
    )
    assert "runtime_context_provider_product_mismatch" in reasons
    assert "runtime_not_reviewed" in reasons
    assert "runtime_location_not_reviewed" in reasons


def test_azure_openai_direct_api_and_foundry_hosted_runtime_are_independent() -> None:
    assert AZURE_OPENAI_DIRECT_API.provider == "azure"
    assert AZURE_OPENAI_DIRECT_API.product == "azure_openai_direct_api"
    assert AZURE_OPENAI_DIRECT_API.supported_runtimes == ("azure_openai_direct_api",)
    assert AZURE_OPENAI_DIRECT_API.supported_runtime_locations == (RuntimeLocation.CUSTOMER_CLOUD,)

    assert MICROSOFT_FOUNDRY_HOSTED_MODEL_RUNTIME.provider == "microsoft"
    assert MICROSOFT_FOUNDRY_HOSTED_MODEL_RUNTIME.product == "foundry_hosted_model_runtime"
    assert MICROSOFT_FOUNDRY_HOSTED_MODEL_RUNTIME.supported_runtimes == (
        "microsoft_foundry_hosted_model_runtime",
    )
    assert MICROSOFT_FOUNDRY_HOSTED_MODEL_RUNTIME.supported_runtime_locations == (
        RuntimeLocation.REMOTE_AGENT,
    )
    assert MICROSOFT_FOUNDRY_HOSTED_MODEL_RUNTIME.supported_control_methods == (
        ControlMethod.SAAS_CONTROL_API,
    )


def test_openai_direct_api_is_reused_and_generic_gateway_does_not_strengthen_new_profiles() -> None:
    profiles = direct_cloud_provider_control_profiles()
    assert all(profile.contract.provider != "openai" for profile in profiles)

    registry = build_default_registry()
    assert len(
        [
            item
            for item in registry.for_provider("openai")
            if item.product == "direct_api" and item.method is ControlMethod.GATEWAY_INLINE
        ]
    ) == 1
    generic_google_gateway = registry.get(
        "google", "direct_api", ControlMethod.GATEWAY_INLINE
    )
    gemini_api = next(
        item
        for item in direct_cloud_provider_matrix_profiles()
        if item.provider == "google" and item.product == "gemini_api"
    )
    assert generic_google_gateway.verification_status is VerificationStatus.VERIFIED
    assert gemini_api.verification_status is VerificationStatus.UNVERIFIED
    assert generic_google_gateway.capability_matrix[
        CapabilityDimension.MODEL_REQUEST_CONTROL
    ].verification_status is VerificationStatus.VERIFIED
    assert gemini_api.capability_matrix[
        CapabilityDimension.MODEL_REQUEST_CONTROL
    ].verification_status is VerificationStatus.UNVERIFIED


def test_account_tenant_route_and_deployment_context_are_required_and_never_inferred() -> None:
    profile = direct_cloud_provider_control_profiles()[0]
    context = _context_for(
        profile,
        account_mode="unknown",
        tenant_mode="unknown",
        route_identity="unknown",
        deployment_identity="unknown",
        route_evidence_ref="unknown",
        route_evidence_fresh=False,
    )

    reasons = profile.enforcement_ineligibility_reasons(context)
    assert "runtime_context_unresolved" in reasons
    assert "account_mode_not_reviewed" in reasons
    assert "tenant_mode_not_reviewed" in reasons
    assert "exact_model_route_acceptance_missing" in reasons
