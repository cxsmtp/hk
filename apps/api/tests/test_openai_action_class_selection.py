from __future__ import annotations

from app.services.native_control.contracts import (
    CapabilityDimension,
    CapabilityLevel,
    ControlPointHealth,
    DegradationMode,
    HealthState,
    VerificationStatus,
)
from app.services.native_control.control_point_factory import (
    AdapterIntegrationContext,
    ControlPointFactory,
)
from app.services.native_control.openai_adapters import (
    OpenAIAgentsSDKControlAdapter,
    OpenAIDirectAPIControlAdapter,
)


def _health(*, verified: bool) -> ControlPointHealth:
    return ControlPointHealth(
        state=HealthState.HEALTHY if verified else HealthState.UNVERIFIED,
        callback_authenticated=verified,
        validation_current=verified,
        evidence_flowing=verified,
        configuration_integrity_valid=verified,
        policy_fresh=verified,
        observed_latency_ms=10,
    )


def _integration() -> AdapterIntegrationContext:
    return AdapterIntegrationContext(
        control_point_id="openai-control-1",
        integration_instance_id="openai-control-1",
        tenant_id="tenant-1",
        provider_version="1.0.0",
        policy_version="policy-1",
        policy_binding_mode="authoritative_per_action",
        tenant_binding_valid=True,
        current_degradation_mode=DegradationMode.FAIL_CLOSED,
    )


def test_agents_function_tool_claim_does_not_propagate_to_hosted_tool() -> None:
    factory = ControlPointFactory()
    adapter = OpenAIAgentsSDKControlAdapter()

    function = factory.create(
        adapter,
        integration=_integration(),
        health=_health(verified=False),
        action_class="function_tool",
    )
    hosted = factory.create(
        adapter,
        integration=_integration(),
        health=_health(verified=False),
        action_class="hosted_web_search",
    )

    function_claim = function.profile.capabilities[CapabilityDimension.FUNCTION_TOOL_CONTROL]
    hosted_claim = hosted.profile.capabilities[CapabilityDimension.FUNCTION_TOOL_CONTROL]
    assert function_claim.level is CapabilityLevel.INLINE_BOUND
    assert function_claim.verification_status is VerificationStatus.VERIFIED
    assert hosted_claim.level is CapabilityLevel.UNAVAILABLE
    assert hosted.profile.capabilities[CapabilityDimension.TOOL_CONTROL].level in {
        CapabilityLevel.UNKNOWN,
        CapabilityLevel.UNAVAILABLE,
    }
    assert hosted.response_coverage == "unknown"


def test_gateway_model_request_does_not_become_tool_loop_authorization() -> None:
    candidate = ControlPointFactory().create(
        OpenAIDirectAPIControlAdapter(),
        integration=_integration(),
        health=_health(verified=True),
        action_class="function_tool",
    )

    assert candidate.profile.capabilities[CapabilityDimension.MODEL_REQUEST_CONTROL].level is CapabilityLevel.UNKNOWN
    assert candidate.profile.capabilities[CapabilityDimension.FUNCTION_TOOL_CONTROL].level is CapabilityLevel.UNAVAILABLE
    assert candidate.profile.capabilities[CapabilityDimension.TOOL_CONTROL].level in {
        CapabilityLevel.UNKNOWN,
        CapabilityLevel.UNAVAILABLE,
    }
    assert candidate.response_coverage == "partial"


def test_missing_openai_action_class_fails_conservatively() -> None:
    candidate = ControlPointFactory().create(
        OpenAIAgentsSDKControlAdapter(),
        integration=_integration(),
        health=_health(verified=False),
    )

    assert candidate.profile.capabilities[CapabilityDimension.FUNCTION_TOOL_CONTROL].level is CapabilityLevel.UNAVAILABLE
    assert candidate.profile.capabilities[CapabilityDimension.TOOL_CONTROL].level in {
        CapabilityLevel.UNKNOWN,
        CapabilityLevel.UNAVAILABLE,
    }
    assert candidate.response_coverage == "unknown"
