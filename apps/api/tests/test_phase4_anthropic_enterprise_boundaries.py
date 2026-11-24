from __future__ import annotations

from app.services.native_control.anthropic_enterprise import (
    ANTHROPIC_ENTERPRISE_INFERENCE_HOOK,
    ANTHROPIC_TENANT_RESTRICTIONS,
    anthropic_enterprise_control_profiles,
    anthropic_enterprise_provider_profiles,
)
from app.services.native_control.contracts import (
    ActionClass,
    CapabilityDimension,
    CapabilityLevel,
    ControlMethod,
    ProviderRuntimeContext,
    RuntimeLocation,
    VerificationStatus,
)
from app.services.native_control.manifests import build_default_registry


def _enterprise_context(
    *,
    product: str,
    runtime: str,
    action_class: ActionClass,
    account_mode: str = "enterprise_managed",
    tenant_mode: str = "approved_organization",
) -> ProviderRuntimeContext:
    return ProviderRuntimeContext(
        provider="anthropic",
        product=product,
        runtime=runtime,
        action_class=action_class,
        runtime_location=RuntimeLocation.PROVIDER_HOSTED,
        provider_version="2026.08.20",
        adapter_version="1.0.0",
        control_method=(
            ControlMethod.PROVIDER_ENTERPRISE_HOOK
            if product == "enterprise_inference_hook"
            else ControlMethod.PROVIDER_TENANT_RESTRICTION
        ),
        environment="production",
        application="enterprise-claude",
        application_version="2026.08.20",
        runtime_version="2026.08.20",
        route_identity="anthropic-enterprise-managed-route",
        deployment_identity="anthropic-enterprise-deployment",
        deployment_reference="anthropic-enterprise-deployment",
        lifecycle_stage="before_model_request"
        if product == "enterprise_inference_hook"
        else "before_managed_route",
        account_mode=account_mode,
        tenant_mode=tenant_mode,
        route_evidence_ref="tenant-verified-route-observation",
        route_evidence_fresh=True,
    )


def test_enterprise_controls_are_distinct_not_tested_contracts_and_profiles() -> None:
    assert ANTHROPIC_ENTERPRISE_INFERENCE_HOOK.product == "enterprise_inference_hook"
    assert ANTHROPIC_ENTERPRISE_INFERENCE_HOOK.supported_action_classes == (ActionClass.MODEL_REQUEST,)
    assert ANTHROPIC_ENTERPRISE_INFERENCE_HOOK.supported_runtimes == (
        "anthropic_enterprise_inference_hook",
    )
    assert ANTHROPIC_ENTERPRISE_INFERENCE_HOOK.supported_control_methods == (
        ControlMethod.PROVIDER_ENTERPRISE_HOOK,
    )
    assert ANTHROPIC_ENTERPRISE_INFERENCE_HOOK.is_reviewed_contract is True
    assert ANTHROPIC_ENTERPRISE_INFERENCE_HOOK.provider_version_min == "2026.08.20"
    assert ANTHROPIC_ENTERPRISE_INFERENCE_HOOK.provider_version_max == "2026.08.20"
    assert ANTHROPIC_ENTERPRISE_INFERENCE_HOOK.security_properties.pre_execution_capable is True
    assert ANTHROPIC_ENTERPRISE_INFERENCE_HOOK.verification_status is VerificationStatus.UNVERIFIED
    assert ANTHROPIC_ENTERPRISE_INFERENCE_HOOK.deployment_acceptance.state.value == "not_tested"

    assert ANTHROPIC_TENANT_RESTRICTIONS.product == "tenant_restrictions"
    assert ANTHROPIC_TENANT_RESTRICTIONS.supported_action_classes == (ActionClass.MODEL_REQUEST,)
    assert ANTHROPIC_TENANT_RESTRICTIONS.supported_runtimes == (
        "anthropic_enterprise_tenant_restrictions",
    )
    assert ANTHROPIC_TENANT_RESTRICTIONS.supported_control_methods == (
        ControlMethod.PROVIDER_TENANT_RESTRICTION,
    )
    assert ANTHROPIC_TENANT_RESTRICTIONS.is_reviewed_contract is True
    assert ANTHROPIC_TENANT_RESTRICTIONS.provider_version_min == "2026.08.20"
    assert ANTHROPIC_TENANT_RESTRICTIONS.provider_version_max == "2026.08.20"
    assert ANTHROPIC_TENANT_RESTRICTIONS.security_properties.pre_execution_capable is True
    assert ANTHROPIC_TENANT_RESTRICTIONS.verification_status is VerificationStatus.UNVERIFIED
    assert ANTHROPIC_TENANT_RESTRICTIONS.deployment_acceptance.state.value == "not_tested"

    profiles = anthropic_enterprise_provider_profiles()
    assert {(profile.product, profile.method) for profile in profiles} == {
        ("enterprise_inference_hook", ControlMethod.PROVIDER_ENTERPRISE_HOOK),
        ("tenant_restrictions", ControlMethod.PROVIDER_TENANT_RESTRICTION),
    }

    registry = build_default_registry()
    assert registry.get(
        "anthropic",
        "enterprise_inference_hook",
        ControlMethod.PROVIDER_ENTERPRISE_HOOK,
    ).verification_status is VerificationStatus.UNVERIFIED
    assert registry.get(
        "anthropic",
        "tenant_restrictions",
        ControlMethod.PROVIDER_TENANT_RESTRICTION,
    ).verification_status is VerificationStatus.UNVERIFIED


def test_inference_hook_claims_only_unverified_server_side_model_request_control() -> None:
    contract = ANTHROPIC_ENTERPRISE_INFERENCE_HOOK

    request = contract.capabilities[CapabilityDimension.MODEL_REQUEST_CONTROL]
    assert request.level is CapabilityLevel.EXTERNAL
    assert request.verification_status is VerificationStatus.UNVERIFIED

    for dimension in (
        CapabilityDimension.TOOL_CONTROL,
        CapabilityDimension.PARAMETER_BINDING,
        CapabilityDimension.TARGET_BINDING,
        CapabilityDimension.FILE_READ_CONTROL,
        CapabilityDimension.FILE_WRITE_CONTROL,
        CapabilityDimension.PROCESS_EXEC_CONTROL,
        CapabilityDimension.NETWORK_CONNECT_CONTROL,
    ):
        claim = contract.capabilities[dimension]
        assert claim.level is CapabilityLevel.UNAVAILABLE
        assert claim.verification_status is VerificationStatus.UNVERIFIED

    tool_context = _enterprise_context(
        product="enterprise_inference_hook",
        runtime="anthropic_enterprise_inference_hook",
        action_class=ActionClass.FUNCTION_TOOL,
    )
    profile = anthropic_enterprise_control_profiles()[0]
    assert "action_class_not_reviewed" in profile.enforcement_ineligibility_reasons(tool_context)


def test_tenant_restrictions_are_route_account_filtering_not_tool_or_endpoint_control() -> None:
    contract = ANTHROPIC_TENANT_RESTRICTIONS
    route = contract.capabilities[CapabilityDimension.MODEL_ROUTE_BINDING]
    assert route.level is CapabilityLevel.EXTERNAL
    assert route.verification_status is VerificationStatus.UNVERIFIED

    for dimension in (
        CapabilityDimension.TOOL_CONTROL,
        CapabilityDimension.PARAMETER_BINDING,
        CapabilityDimension.TARGET_BINDING,
        CapabilityDimension.FILE_OPEN_CONTROL,
        CapabilityDimension.FILE_READ_CONTROL,
        CapabilityDimension.FILE_WRITE_CONTROL,
        CapabilityDimension.PROCESS_EXEC_CONTROL,
        CapabilityDimension.NETWORK_CONNECT_CONTROL,
    ):
        claim = contract.capabilities[dimension]
        assert claim.level is CapabilityLevel.UNAVAILABLE
        assert claim.verification_status is VerificationStatus.UNVERIFIED

    generic_api_context = _enterprise_context(
        product="tenant_restrictions",
        runtime="anthropic_enterprise_tenant_restrictions",
        action_class=ActionClass.API_ACTION,
    )
    restrictions_profile = anthropic_enterprise_control_profiles()[1]
    assert "action_class_not_reviewed" in restrictions_profile.enforcement_ineligibility_reasons(
        generic_api_context
    )


def test_personal_or_unapproved_organizations_never_inherit_enterprise_coverage() -> None:
    inference_profile, restrictions_profile = anthropic_enterprise_control_profiles()
    personal = _enterprise_context(
        product="enterprise_inference_hook",
        runtime="anthropic_enterprise_inference_hook",
        action_class=ActionClass.MODEL_REQUEST,
        account_mode="personal",
    )
    unapproved = _enterprise_context(
        product="tenant_restrictions",
        runtime="anthropic_enterprise_tenant_restrictions",
        action_class=ActionClass.MODEL_REQUEST,
        tenant_mode="unapproved_organization",
    )

    assert "account_mode_not_reviewed" in ANTHROPIC_ENTERPRISE_INFERENCE_HOOK.enforcement_ineligibility_reasons(
        personal,
        ANTHROPIC_ENTERPRISE_INFERENCE_HOOK.provider_version_state(personal.provider_version),
    )
    assert "tenant_mode_not_reviewed" in ANTHROPIC_TENANT_RESTRICTIONS.enforcement_ineligibility_reasons(
        unapproved,
        ANTHROPIC_TENANT_RESTRICTIONS.provider_version_state(unapproved.provider_version),
    )
    assert "enterprise_account_context_required" in inference_profile.enforcement_ineligibility_reasons(personal)
    assert "enterprise_tenant_context_required" in restrictions_profile.enforcement_ineligibility_reasons(unapproved)


def test_no_anthropic_enterprise_profile_is_enforce_eligible_without_tenant_acceptance() -> None:
    inference_profile, restrictions_profile = anthropic_enterprise_control_profiles()
    inference_context = _enterprise_context(
        product="enterprise_inference_hook",
        runtime="anthropic_enterprise_inference_hook",
        action_class=ActionClass.MODEL_REQUEST,
    )
    route_context = _enterprise_context(
        product="tenant_restrictions",
        runtime="anthropic_enterprise_tenant_restrictions",
        action_class=ActionClass.MODEL_REQUEST,
    )

    assert "deployment_acceptance_not_real" in inference_profile.enforcement_ineligibility_reasons(inference_context)
    assert "deployment_acceptance_not_real" in restrictions_profile.enforcement_ineligibility_reasons(route_context)
