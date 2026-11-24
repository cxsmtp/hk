from __future__ import annotations

from dataclasses import replace

import pytest

from app.services.native_control.adapter_contract import (
    AdapterContractError,
    _validate_version_range,
)
from app.services.native_control.aws_bedrock import (
    AWSGuardrailAction,
    BEDROCK_ACTION_RUNTIME,
    BEDROCK_AGENTCORE,
    BEDROCK_AGENTCORE_MCP_GATEWAY,
    BEDROCK_AGENTS_CLASSIC_EXISTING,
    BEDROCK_GUARDRAIL,
    BEDROCK_KNOWLEDGE_BASE,
    BEDROCK_MCP,
    BEDROCK_MODEL_API,
    CUSTOM_BEDROCK_AGENT,
    aws_bedrock_control_profiles,
    compose_bedrock_guardrail_decision,
)
from app.services.native_control.contracts import (
    ActionClass,
    CapabilityDimension,
    CapabilityLevel,
    ControlMethod,
    DeploymentAcceptanceState,
    ProviderRuntimeContext,
    ProviderVersionState,
    RuntimeLocation,
    VerificationStatus,
)
from app.services.native_control.manifests import build_default_registry


def _context_for(profile) -> ProviderRuntimeContext:
    contract = profile.contract
    return ProviderRuntimeContext(
        provider="aws",
        product=contract.product,
        runtime=contract.supported_runtimes[0],
        action_class=contract.supported_action_classes[0],
        runtime_location=contract.supported_runtime_locations[0],
        provider_version="unknown",
        adapter_version=contract.adapter_version,
        control_method=profile.method,
        environment="test",
        lifecycle_stage=contract.supported_lifecycle_events[0],
        route_identity="aws-route:reviewed-test",
        deployment_identity="aws-deployment:reviewed-test",
        deployment_reference="aws-deployment-ref:reviewed-test",
        route_evidence_ref="repo:tests/aws-bedrock-reviewed-route.json",
        route_evidence_fresh=True,
    )


def test_bedrock_profiles_are_distinct_reviewed_contracts_with_no_deployment_acceptance() -> None:
    profiles = aws_bedrock_control_profiles()

    assert tuple(profile.contract for profile in profiles) == (
        BEDROCK_MODEL_API,
        BEDROCK_GUARDRAIL,
        BEDROCK_AGENTCORE,
        BEDROCK_ACTION_RUNTIME,
        BEDROCK_MCP,
        BEDROCK_AGENTCORE_MCP_GATEWAY,
        BEDROCK_KNOWLEDGE_BASE,
        BEDROCK_AGENTS_CLASSIC_EXISTING,
        CUSTOM_BEDROCK_AGENT,
    )
    assert len({profile.contract.descriptor_id for profile in profiles}) == 9
    assert len({profile.contract.product for profile in profiles}) == 9

    for profile in profiles:
        contract = profile.contract
        assert contract.provider == "aws"
        assert contract.is_reviewed_contract is True
        assert contract.verification_status is VerificationStatus.UNVERIFIED
        assert contract.deployment_acceptance.state is DeploymentAcceptanceState.NOT_TESTED
        assert contract.deployment_acceptance.is_real_acceptance is False
        reasons = contract.enforcement_ineligibility_reasons(
            _context_for(profile), contract.provider_version_state("unknown")
        )
        assert "provider_version_unknown" in reasons
        assert "contract_not_verified" in reasons
        assert "deployment_acceptance_not_real" in reasons


def test_review_revision_is_never_treated_as_an_accepted_aws_service_version() -> None:
    for profile in aws_bedrock_control_profiles():
        contract = profile.contract

        assert contract.reviewed_at == "2026-08-20T00:00:00+00:00"
        assert contract.provider_version_state("unknown") is ProviderVersionState.UNKNOWN
        assert contract.provider_version_state("2026.08.20") is ProviderVersionState.UNSUPPORTED
        assert contract.provider_version_state("not-accepted") is ProviderVersionState.UNSUPPORTED
        assert contract.provider_version_min == ""
        assert contract.provider_version_max == ""
        _validate_version_range(contract)


def test_unaccepted_version_range_cannot_be_used_by_a_verified_or_half_configured_contract() -> None:
    contract = BEDROCK_MODEL_API

    with pytest.raises(AdapterContractError, match="invalid_provider_version_range"):
        _validate_version_range(
            replace(contract, verification_status=VerificationStatus.VERIFIED)
        )
    with pytest.raises(AdapterContractError, match="invalid_provider_version_range"):
        _validate_version_range(replace(contract, provider_version_min="1.0.0"))


def test_guardrails_remain_content_only_and_never_gain_exact_action_identity_or_execution_control() -> None:
    claims = BEDROCK_GUARDRAIL.capabilities

    for dimension in (
        CapabilityDimension.PROMPT_CONTROL,
        CapabilityDimension.RESPONSE_CONTROL,
    ):
        assert claims[dimension].level is CapabilityLevel.EXTERNAL
        assert claims[dimension].verification_status is VerificationStatus.UNVERIFIED

    for dimension in (
        CapabilityDimension.FUNCTION_TOOL_CONTROL,
        CapabilityDimension.PARAMETER_BINDING,
        CapabilityDimension.TARGET_BINDING,
        CapabilityDimension.SUBJECT_BINDING,
        CapabilityDimension.APPROVAL_CONTROL,
        CapabilityDimension.EXECUTION_CORRELATION,
        CapabilityDimension.POST_EXECUTION_VERIFICATION,
    ):
        assert claims[dimension].level is CapabilityLevel.UNAVAILABLE
        assert claims[dimension].verification_status is VerificationStatus.UNVERIFIED


def test_bedrock_guardrail_deny_is_monotonic_and_hawk_cannot_weaken_it() -> None:
    assert compose_bedrock_guardrail_decision(
        provider_action=AWSGuardrailAction.GUARDRAIL_INTERVENED,
        hawk_decision="allow",
    ) == "block"
    assert compose_bedrock_guardrail_decision(
        provider_action="GUARDRAIL_INTERVENED",
        hawk_decision="require_approval",
    ) == "block"
    assert compose_bedrock_guardrail_decision(
        provider_action=AWSGuardrailAction.NONE,
        hawk_decision="block",
    ) == "block"
    assert compose_bedrock_guardrail_decision(
        provider_action="NONE",
        hawk_decision="allow",
    ) == "allow"


@pytest.mark.parametrize("malformed", [0, "", "false", [], {}, None, False, True])
def test_bedrock_guardrail_rejects_malformed_provider_outcomes(malformed: object) -> None:
    with pytest.raises(ValueError, match="^provider_guardrail_action_invalid$"):
        compose_bedrock_guardrail_decision(
            provider_action=malformed,
            hawk_decision="allow",
        )


def test_provider_hosted_agentcore_does_not_infer_hawk_tool_or_customer_identity_authorization() -> None:
    claims = BEDROCK_AGENTCORE.capabilities

    assert claims[CapabilityDimension.RUNTIME_IDENTITY].level is CapabilityLevel.OBSERVE
    assert claims[CapabilityDimension.MODEL_ROUTE_BINDING].level is CapabilityLevel.OBSERVE
    for dimension in (
        CapabilityDimension.FUNCTION_TOOL_CONTROL,
        CapabilityDimension.MCP_CONTROL,
        CapabilityDimension.PARAMETER_BINDING,
        CapabilityDimension.TARGET_BINDING,
        CapabilityDimension.SUBJECT_BINDING,
        CapabilityDimension.AUTHORITY_BINDING,
        CapabilityDimension.APPROVAL_CONTROL,
    ):
        assert claims[dimension].level is CapabilityLevel.UNAVAILABLE
        assert claims[dimension].verification_status is VerificationStatus.UNVERIFIED


def test_customer_controlled_action_and_mcp_boundaries_are_not_provider_hosted_authorization() -> None:
    action_runtime = BEDROCK_ACTION_RUNTIME
    mcp = BEDROCK_MCP

    assert action_runtime.supported_action_classes == (ActionClass.FUNCTION_TOOL,)
    assert action_runtime.supported_runtime_locations == (RuntimeLocation.CUSTOMER_CLOUD,)
    assert action_runtime.supported_control_methods == (ControlMethod.FUNCTION_MIDDLEWARE,)
    assert action_runtime.capabilities[CapabilityDimension.FUNCTION_TOOL_CONTROL].level is CapabilityLevel.INLINE_BOUND
    assert action_runtime.capabilities[CapabilityDimension.FUNCTION_TOOL_CONTROL].verification_status is VerificationStatus.UNVERIFIED
    assert action_runtime.capabilities[CapabilityDimension.POST_EXECUTION_VERIFICATION].level is CapabilityLevel.UNAVAILABLE
    assert action_runtime.capabilities[CapabilityDimension.SUBJECT_BINDING].level is CapabilityLevel.UNAVAILABLE
    assert action_runtime.capabilities[CapabilityDimension.AUTHORITY_BINDING].level is CapabilityLevel.UNAVAILABLE

    assert mcp.supported_action_classes == (ActionClass.MCP,)
    assert mcp.supported_control_methods == (ControlMethod.TOOL_LOOP_INTERCEPT,)
    assert mcp.source_reference == (
        "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agents-tools-runtime.html"
    )
    assert mcp.required_permissions == ("customer.mcp.invoke",)
    assert mcp.capabilities[CapabilityDimension.MCP_CONTROL].level is CapabilityLevel.INLINE_BOUND
    assert mcp.capabilities[CapabilityDimension.MCP_CONTROL].verification_status is VerificationStatus.UNVERIFIED
    assert mcp.capabilities[CapabilityDimension.LOCAL_MCP_CONTROL].level is CapabilityLevel.UNAVAILABLE
    assert mcp.capabilities[CapabilityDimension.HOSTED_MCP_CONTROL].level is CapabilityLevel.UNAVAILABLE
    assert mcp.capabilities[CapabilityDimension.FUNCTION_TOOL_CONTROL].level is CapabilityLevel.UNAVAILABLE


def test_agentcore_gateway_mcp_is_a_separate_provider_hosted_unverified_boundary() -> None:
    hosted = BEDROCK_AGENTCORE_MCP_GATEWAY

    assert hosted.supported_action_classes == (ActionClass.MCP,)
    assert hosted.supported_runtime_locations == (RuntimeLocation.PROVIDER_HOSTED,)
    assert hosted.supported_control_methods == (ControlMethod.SAAS_CONTROL_API,)
    assert hosted.capabilities[CapabilityDimension.HOSTED_MCP_CONTROL].level is CapabilityLevel.EXTERNAL
    assert hosted.capabilities[CapabilityDimension.HOSTED_MCP_CONTROL].verification_status is VerificationStatus.UNVERIFIED
    for dimension in (
        CapabilityDimension.LOCAL_MCP_CONTROL,
        CapabilityDimension.MCP_CONTROL,
        CapabilityDimension.PARAMETER_BINDING,
        CapabilityDimension.TARGET_BINDING,
        CapabilityDimension.SUBJECT_BINDING,
        CapabilityDimension.APPROVAL_CONTROL,
        CapabilityDimension.EXECUTION_CORRELATION,
    ):
        assert hosted.capabilities[dimension].level is CapabilityLevel.UNAVAILABLE
        assert hosted.capabilities[dimension].verification_status is VerificationStatus.UNVERIFIED


def test_knowledge_base_is_retrieval_context_observation_not_content_inspection() -> None:
    knowledge_base = BEDROCK_KNOWLEDGE_BASE

    assert knowledge_base.source_reference == (
        "https://docs.aws.amazon.com/bedrock/latest/userguide/kb-how-retrieval.html"
    )
    assert knowledge_base.capabilities[CapabilityDimension.CONTENT_INSPECTION].level is CapabilityLevel.UNAVAILABLE
    assert knowledge_base.capabilities[CapabilityDimension.DISCOVERY].level is CapabilityLevel.OBSERVE
    assert knowledge_base.capabilities[CapabilityDimension.MODEL_ROUTE_BINDING].level is CapabilityLevel.UNAVAILABLE
    assert knowledge_base.capabilities[CapabilityDimension.POST_EXECUTION_VISIBILITY].level is CapabilityLevel.OBSERVE


def test_each_bedrock_profile_persists_its_exact_pre_and_post_lifecycle() -> None:
    expected = {
        BEDROCK_MODEL_API.descriptor_id: (
            ("before_model_request",),
            ("after_model_response",),
        ),
        BEDROCK_GUARDRAIL.descriptor_id: (
            ("before_guardrail_input_evaluation",),
            ("after_guardrail_output_evaluation",),
        ),
        BEDROCK_AGENTCORE.descriptor_id: (
            (),
            ("agentcore_runtime_response_observed",),
        ),
        BEDROCK_ACTION_RUNTIME.descriptor_id: (
            ("before_customer_action_executor",),
            ("after_customer_action_executor",),
        ),
        BEDROCK_MCP.descriptor_id: (
            ("before_customer_mcp_tool_call",),
            ("after_customer_mcp_tool_result",),
        ),
        BEDROCK_AGENTCORE_MCP_GATEWAY.descriptor_id: (
            ("before_agentcore_gateway_mcp_call",),
            ("agentcore_gateway_mcp_result_observed",),
        ),
        BEDROCK_KNOWLEDGE_BASE.descriptor_id: (
            (),
            ("after_knowledge_base_retrieval",),
        ),
        BEDROCK_AGENTS_CLASSIC_EXISTING.descriptor_id: (
            (),
            ("classic_agent_response_observed",),
        ),
        CUSTOM_BEDROCK_AGENT.descriptor_id: (
            ("before_customer_agent_action",),
            ("after_customer_agent_action",),
        ),
    }

    for profile in aws_bedrock_control_profiles():
        contract = profile.contract
        pre_events, post_events = expected[contract.descriptor_id]
        assert contract.event_semantics.pre_execution_events == pre_events
        assert contract.event_semantics.post_execution_events == post_events
        assert contract.supported_lifecycle_events == (*pre_events, *post_events)


def test_bedrock_classic_is_compatibility_only_and_does_not_inherit_agentcore_or_action_runtime_claims() -> None:
    classic = BEDROCK_AGENTS_CLASSIC_EXISTING

    assert classic.product == "bedrock_agents_classic"
    assert classic.supported_action_classes == (ActionClass.MODEL_REQUEST,)
    for dimension in (
        CapabilityDimension.FUNCTION_TOOL_CONTROL,
        CapabilityDimension.MCP_CONTROL,
        CapabilityDimension.PARAMETER_BINDING,
        CapabilityDimension.TARGET_BINDING,
        CapabilityDimension.RUNTIME_IDENTITY,
    ):
        assert classic.capabilities[dimension].level is CapabilityLevel.UNAVAILABLE
        assert classic.capabilities[dimension].verification_status is VerificationStatus.UNVERIFIED
    details = tuple(
        f"{item.condition} {item.impact}".lower()
        for item in classic.known_blind_spots
    )
    assert any("maintenance" in item for item in details)
    assert any("does not inherit" in item for item in details)


def test_bedrock_matrix_projects_every_profile_without_enforcement_strengthening() -> None:
    registry = build_default_registry()

    expected = {
        "bedrock_model_api": ControlMethod.API_INTERCEPT,
        "bedrock_guardrails": ControlMethod.SAAS_CONTROL_API,
        "bedrock_agentcore": ControlMethod.SAAS_CONTROL_API,
        "bedrock_action_runtime": ControlMethod.FUNCTION_MIDDLEWARE,
        "bedrock_mcp": ControlMethod.TOOL_LOOP_INTERCEPT,
        "bedrock_agentcore_mcp_gateway": ControlMethod.SAAS_CONTROL_API,
        "bedrock_knowledge_base": ControlMethod.SAAS_CONTROL_API,
        "bedrock_agents_classic": ControlMethod.AGENT_MIDDLEWARE,
        "custom_bedrock_agent": ControlMethod.AGENT_MIDDLEWARE,
    }
    for product, method in expected.items():
        manifest = registry.get("aws", product, method)
        assert manifest.verification_status is VerificationStatus.UNVERIFIED
        assert manifest.supported_versions == ()
        assert "real aws" in " ".join(manifest.deployment_requirements).lower()
        assert "direct" in " ".join(
            (*manifest.known_blind_spots, *manifest.failure_modes)
        ).lower()

    # Bedrock does not expose a reviewed Hawk native-hook contract.  Classic
    # is represented only by its separate compatibility profile above; it may
    # not inherit a generic, invented ``bedrock_agents`` native hook.
    assert not any(
        manifest.provider == "aws"
        and manifest.product == "bedrock_agents"
        and manifest.method is ControlMethod.NATIVE_HOOK
        for manifest in registry.manifests
    )
