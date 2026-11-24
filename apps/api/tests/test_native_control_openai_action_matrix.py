from __future__ import annotations

from app.services.native_control.contracts import (
    CapabilityDimension,
    CapabilityLevel,
    ControlMethod,
    VerificationStatus,
)
from app.services.native_control.openai_action_matrix import (
    OpenAIActionClass,
    OpenAIResponseCoverage,
    build_openai_action_control_matrix,
)


REQUIRED_ACTION_CLASSES = {
    "model_request",
    "model_response",
    "function_tool",
    "hosted_web_search",
    "hosted_file_search",
    "hosted_code_interpreter",
    "hosted_image_generation",
    "hosted_mcp",
    "local_mcp",
    "tool_search",
    "local_shell",
    "hosted_shell",
    "computer_tool",
    "apply_patch",
    "agent_as_tool",
    "handoff",
    "codex_tool",
    "unknown_tool",
}


def test_openai_matrix_has_independent_profiles_for_every_required_tool_class() -> None:
    matrix = build_openai_action_control_matrix()

    assert {value.value for value in OpenAIActionClass} == REQUIRED_ACTION_CLASSES
    assert set(matrix.action_classes(product="agents_sdk")) == REQUIRED_ACTION_CLASSES


def test_function_tool_control_is_exact_and_does_not_propagate_to_other_classes() -> None:
    matrix = build_openai_action_control_matrix()
    function = matrix.resolve(
        product="agents_sdk",
        action_class=OpenAIActionClass.FUNCTION_TOOL,
        method=ControlMethod.SDK_MIDDLEWARE,
    )

    assert function.claim(CapabilityDimension.FUNCTION_TOOL_CONTROL).level is CapabilityLevel.INLINE_BOUND
    assert function.claim(CapabilityDimension.FUNCTION_TOOL_PARAMETER_BINDING).level is CapabilityLevel.INLINE_BOUND
    assert function.claim(CapabilityDimension.PARAMETER_BINDING).level is CapabilityLevel.INLINE_BOUND
    assert function.claim(CapabilityDimension.TARGET_BINDING).level is CapabilityLevel.INLINE_BOUND
    assert function.claim(CapabilityDimension.FUNCTION_TOOL_CONTROL).verification_status is VerificationStatus.VERIFIED

    excluded = REQUIRED_ACTION_CLASSES - {OpenAIActionClass.FUNCTION_TOOL.value}
    for action_class in excluded:
        profile = matrix.resolve(
            product="agents_sdk",
            action_class=action_class,
            method=ControlMethod.SDK_MIDDLEWARE,
        )
        claim = profile.claim(CapabilityDimension.FUNCTION_TOOL_CONTROL)
        assert claim.level in {CapabilityLevel.UNAVAILABLE, CapabilityLevel.UNKNOWN}
        assert claim.verification_status is not VerificationStatus.VERIFIED


def test_hosted_and_local_mcp_shell_patch_and_delegation_are_separate_capabilities() -> None:
    matrix = build_openai_action_control_matrix()

    hosted_mcp = matrix.resolve("agents_sdk", "hosted_mcp", ControlMethod.SDK_MIDDLEWARE)
    local_mcp = matrix.resolve("agents_sdk", "local_mcp", ControlMethod.SDK_MIDDLEWARE)
    local_shell = matrix.resolve("agents_sdk", "local_shell", ControlMethod.SDK_MIDDLEWARE)
    hosted_shell = matrix.resolve("agents_sdk", "hosted_shell", ControlMethod.SDK_MIDDLEWARE)
    patch = matrix.resolve("agents_sdk", "apply_patch", ControlMethod.SDK_MIDDLEWARE)
    handoff = matrix.resolve("agents_sdk", "handoff", ControlMethod.SDK_MIDDLEWARE)
    nested = matrix.resolve("agents_sdk", "agent_as_tool", ControlMethod.SDK_MIDDLEWARE)

    assert hosted_mcp.claim(CapabilityDimension.HOSTED_MCP_CONTROL).level is CapabilityLevel.EXTERNAL
    assert local_mcp.claim(CapabilityDimension.LOCAL_MCP_CONTROL).level is CapabilityLevel.EXTERNAL
    assert local_shell.claim(CapabilityDimension.LOCAL_SHELL_CONTROL).level is CapabilityLevel.EXTERNAL
    assert hosted_shell.claim(CapabilityDimension.HOSTED_SHELL_CONTROL).level is CapabilityLevel.UNKNOWN
    assert patch.claim(CapabilityDimension.PATCH_CONTROL).level is CapabilityLevel.EXTERNAL
    assert handoff.claim(CapabilityDimension.DELEGATION_CONTROL).level is CapabilityLevel.UNKNOWN
    assert nested.claim(CapabilityDimension.AGENT_AS_TOOL_CONTROL).level is CapabilityLevel.EXTERNAL


def test_direct_api_streaming_coverage_is_route_and_phase_specific() -> None:
    matrix = build_openai_action_control_matrix()

    routed = matrix.resolve("direct_api", "function_tool", ControlMethod.TOOL_LOOP_INTERCEPT)
    gateway = matrix.resolve("direct_api", "unknown_tool", ControlMethod.GATEWAY_INLINE)
    bypass = matrix.resolve("direct_api", "unknown_tool", ControlMethod.API_INTERCEPT)

    assert routed.response_coverage is OpenAIResponseCoverage.COMPLETE
    assert gateway.response_coverage is OpenAIResponseCoverage.PARTIAL
    assert bypass.response_coverage is OpenAIResponseCoverage.REQUEST_ONLY
    assert "route" in " ".join(gateway.blind_spots).lower()


def test_direct_model_and_tool_boundaries_do_not_inherit_each_other() -> None:
    matrix = build_openai_action_control_matrix()
    request = matrix.resolve("direct_api", "model_request", ControlMethod.GATEWAY_INLINE)
    response = matrix.resolve("direct_api", "model_response", ControlMethod.GATEWAY_INLINE)
    tool = matrix.resolve("direct_api", "function_tool", ControlMethod.GATEWAY_INLINE)

    assert request.claim(CapabilityDimension.PROMPT_CONTROL).verification_status is VerificationStatus.VERIFIED
    assert request.claim(CapabilityDimension.TOOL_CONTROL).verification_status is not VerificationStatus.VERIFIED
    assert response.claim(CapabilityDimension.RESPONSE_CONTROL).verification_status is VerificationStatus.VERIFIED
    assert response.claim(CapabilityDimension.PROMPT_CONTROL).verification_status is not VerificationStatus.VERIFIED
    assert tool.claim(CapabilityDimension.MODEL_REQUEST_CONTROL).verification_status is not VerificationStatus.VERIFIED
    assert tool.claim(CapabilityDimension.TOOL_CONTROL).verification_status is not VerificationStatus.VERIFIED
