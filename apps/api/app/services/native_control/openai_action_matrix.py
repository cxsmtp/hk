from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from app.services.native_control.contracts import (
    CapabilityClaim,
    CapabilityDimension,
    CapabilityLevel,
    ControlMethod,
    VerificationStatus,
)


class OpenAIActionClass(str, Enum):
    MODEL_REQUEST = "model_request"
    MODEL_RESPONSE = "model_response"
    FUNCTION_TOOL = "function_tool"
    HOSTED_WEB_SEARCH = "hosted_web_search"
    HOSTED_FILE_SEARCH = "hosted_file_search"
    HOSTED_CODE_INTERPRETER = "hosted_code_interpreter"
    HOSTED_IMAGE_GENERATION = "hosted_image_generation"
    HOSTED_MCP = "hosted_mcp"
    LOCAL_MCP = "local_mcp"
    TOOL_SEARCH = "tool_search"
    LOCAL_SHELL = "local_shell"
    HOSTED_SHELL = "hosted_shell"
    COMPUTER_TOOL = "computer_tool"
    APPLY_PATCH = "apply_patch"
    AGENT_AS_TOOL = "agent_as_tool"
    HANDOFF = "handoff"
    CODEX_TOOL = "codex_tool"
    UNKNOWN_TOOL = "unknown_tool"


class OpenAIResponseCoverage(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    REQUEST_ONLY = "request_only"
    POST_EXECUTION = "post_execution"
    UNKNOWN = "unknown"


_AGENTS_GUARDRAIL_DOC = "https://openai.github.io/openai-agents-python/guardrails/"
_AGENTS_TOOL_DOC = "https://openai.github.io/openai-agents-python/tools/"
_AGENTS_MCP_DOC = "https://openai.github.io/openai-agents-python/mcp/"
_CODEX_HOOK_DOC = "https://developers.openai.com/codex/config-advanced#hooks"
_DIRECT_API_EVIDENCE = "repo:apps/api/tests/test_llm_response_control_chain_contract.py"


# These dimensions describe an execution boundary. They must be replaced by
# the selected action-class profile rather than inherited from a product-wide
# manifest. Discovery/identity/configuration facts remain product-scoped.
OPENAI_ACTION_SCOPED_DIMENSIONS = frozenset(
    {
        CapabilityDimension.PROMPT_CONTROL,
        CapabilityDimension.RESPONSE_CONTROL,
        CapabilityDimension.TOOL_CONTROL,
        CapabilityDimension.MCP_CONTROL,
        CapabilityDimension.COMMAND_CONTROL,
        CapabilityDimension.FILE_READ_CONTROL,
        CapabilityDimension.FILE_WRITE_CONTROL,
        CapabilityDimension.NETWORK_CONTROL,
        CapabilityDimension.APPROVAL_CONTROL,
        CapabilityDimension.PARAMETER_BINDING,
        CapabilityDimension.TARGET_BINDING,
        CapabilityDimension.DESTINATION_BINDING,
        CapabilityDimension.DELEGATION_CONTROL,
        CapabilityDimension.POST_EXECUTION_VISIBILITY,
        CapabilityDimension.EXECUTION_CORRELATION,
        CapabilityDimension.POST_EXECUTION_VERIFICATION,
        CapabilityDimension.PERSISTENT_SIDE_EFFECT_CONTROL,
        CapabilityDimension.MODEL_REQUEST_CONTROL,
        CapabilityDimension.MODEL_RESPONSE_CONTROL,
        CapabilityDimension.FUNCTION_TOOL_CONTROL,
        CapabilityDimension.FUNCTION_TOOL_PARAMETER_BINDING,
        CapabilityDimension.FUNCTION_TOOL_TARGET_BINDING,
        CapabilityDimension.LOCAL_MCP_CONTROL,
        CapabilityDimension.HOSTED_MCP_CONTROL,
        CapabilityDimension.LOCAL_SHELL_CONTROL,
        CapabilityDimension.HOSTED_SHELL_CONTROL,
        CapabilityDimension.PATCH_CONTROL,
        CapabilityDimension.COMPUTER_CONTROL,
        CapabilityDimension.AGENT_AS_TOOL_CONTROL,
        CapabilityDimension.HITL_APPROVAL,
        CapabilityDimension.CODEX_COMMAND_CONTROL,
        CapabilityDimension.CODEX_FILE_CONTROL,
        CapabilityDimension.CODEX_MCP_CONTROL,
        CapabilityDimension.DIRECT_API_CONTROL,
    }
)


def _claim(
    level: CapabilityLevel,
    status: VerificationStatus,
    *evidence: str,
) -> CapabilityClaim:
    return CapabilityClaim(level=level, verification_status=status, evidence_refs=tuple(evidence))


_UNKNOWN = _claim(CapabilityLevel.UNKNOWN, VerificationStatus.UNVERIFIED)
_UNAVAILABLE = _claim(CapabilityLevel.UNAVAILABLE, VerificationStatus.UNVERIFIED)


@dataclass(frozen=True, slots=True)
class OpenAIActionControlProfile:
    product: str
    action_class: OpenAIActionClass
    method: ControlMethod
    capabilities: dict[CapabilityDimension, CapabilityClaim]
    response_coverage: OpenAIResponseCoverage
    evidence_refs: tuple[str, ...]
    blind_spots: tuple[str, ...]

    def claim(self, dimension: CapabilityDimension) -> CapabilityClaim:
        return self.capabilities.get(dimension, _UNKNOWN)


class OpenAIActionControlMatrix:
    """Action-class evidence for OpenAI products.

    The matrix is deliberately separate from provider-level manifests. A
    function-tool claim is never inherited by hosted tools, MCP, shell,
    patches, delegation, Codex, or an unknown tool class.
    """

    def __init__(self, profiles: Iterable[OpenAIActionControlProfile]) -> None:
        values = tuple(profiles)
        keys = {(row.product, row.action_class.value, row.method.value) for row in values}
        if len(keys) != len(values):
            raise ValueError("duplicate_openai_action_control_profile")
        self._profiles = values

    def action_classes(self, *, product: str) -> tuple[str, ...]:
        normalized = str(product or "").strip().lower()
        return tuple(sorted({row.action_class.value for row in self._profiles if row.product == normalized}))

    def resolve(
        self,
        product: str,
        action_class: OpenAIActionClass | str,
        method: ControlMethod,
    ) -> OpenAIActionControlProfile:
        product_value = str(product or "").strip().lower()
        try:
            action_value = (
                action_class
                if isinstance(action_class, OpenAIActionClass)
                else OpenAIActionClass(str(action_class or "").strip().lower())
            )
        except ValueError:
            action_value = OpenAIActionClass.UNKNOWN_TOOL
        for row in self._profiles:
            if row.product == product_value and row.action_class is action_value and row.method is method:
                return row
        for row in self._profiles:
            if (
                row.product == product_value
                and row.action_class is OpenAIActionClass.UNKNOWN_TOOL
                and row.method is method
            ):
                return row
        raise KeyError((product_value, action_value.value, method.value))


def _agents_profile(action_class: OpenAIActionClass) -> OpenAIActionControlProfile:
    experimental = VerificationStatus.EXPERIMENTAL
    verified = VerificationStatus.VERIFIED
    values: dict[CapabilityDimension, CapabilityClaim] = {
        CapabilityDimension.FUNCTION_TOOL_CONTROL: _UNAVAILABLE,
        CapabilityDimension.FUNCTION_TOOL_PARAMETER_BINDING: _UNAVAILABLE,
        CapabilityDimension.FUNCTION_TOOL_TARGET_BINDING: _UNAVAILABLE,
    }
    response = OpenAIResponseCoverage.UNKNOWN
    blind_spots = ["No capability from another Agents SDK tool class is inherited."]
    refs = (_AGENTS_GUARDRAIL_DOC, _AGENTS_TOOL_DOC)
    if action_class is OpenAIActionClass.FUNCTION_TOOL:
        values.update(
            {
                CapabilityDimension.FUNCTION_TOOL_CONTROL: _claim(
                    CapabilityLevel.INLINE_BOUND,
                    verified,
                    _AGENTS_GUARDRAIL_DOC,
                    "repo:apps/api/scripts/accept_openai_agents_sdk.py",
                ),
                CapabilityDimension.FUNCTION_TOOL_PARAMETER_BINDING: _claim(
                    CapabilityLevel.INLINE_BOUND,
                    verified,
                    _AGENTS_GUARDRAIL_DOC,
                    "repo:apps/api/scripts/accept_openai_agents_sdk.py",
                ),
                CapabilityDimension.FUNCTION_TOOL_TARGET_BINDING: _claim(
                    CapabilityLevel.INLINE_BOUND,
                    verified,
                    _AGENTS_GUARDRAIL_DOC,
                    "repo:apps/api/tests/test_openai_agents_bridge.py",
                ),
                CapabilityDimension.PARAMETER_BINDING: _claim(
                    CapabilityLevel.INLINE_BOUND,
                    verified,
                    _AGENTS_GUARDRAIL_DOC,
                    "repo:apps/api/tests/test_openai_agents_bridge.py",
                ),
                CapabilityDimension.TARGET_BINDING: _claim(
                    CapabilityLevel.INLINE_BOUND,
                    verified,
                    _AGENTS_GUARDRAIL_DOC,
                    "repo:apps/api/tests/test_openai_agents_bridge.py",
                ),
                CapabilityDimension.TOOL_CONTROL: _claim(
                    CapabilityLevel.INLINE_BOUND,
                    verified,
                    _AGENTS_GUARDRAIL_DOC,
                    "repo:apps/api/scripts/accept_openai_agents_sdk.py",
                ),
                CapabilityDimension.HITL_APPROVAL: _claim(
                    CapabilityLevel.EXTERNAL, experimental, _AGENTS_GUARDRAIL_DOC
                ),
                CapabilityDimension.POST_EXECUTION_VISIBILITY: _claim(
                    CapabilityLevel.OBSERVE,
                    verified,
                    _AGENTS_GUARDRAIL_DOC,
                    "repo:apps/api/scripts/accept_openai_agents_sdk.py",
                ),
                CapabilityDimension.EXECUTION_CORRELATION: _claim(
                    CapabilityLevel.OBSERVE,
                    verified,
                    _AGENTS_GUARDRAIL_DOC,
                    "repo:apps/api/scripts/accept_openai_agents_sdk.py",
                ),
            }
        )
        response = OpenAIResponseCoverage.COMPLETE
        blind_spots = [
            "Verified only for openai-agents 0.20.0 function tools with both Hawk guardrails explicitly attached; HITL remains experimental."
        ]
    elif action_class is OpenAIActionClass.MODEL_REQUEST:
        values[CapabilityDimension.MODEL_REQUEST_CONTROL] = _claim(
            CapabilityLevel.OBSERVE, experimental, _AGENTS_TOOL_DOC
        )
        response = OpenAIResponseCoverage.REQUEST_ONLY
        blind_spots = [
            "RunHooks/AgentHooks observe model lifecycle events; they do not authorize the model request."
        ]
    elif action_class is OpenAIActionClass.MODEL_RESPONSE:
        values[CapabilityDimension.MODEL_RESPONSE_CONTROL] = _claim(
            CapabilityLevel.OBSERVE, experimental, _AGENTS_TOOL_DOC
        )
        response = OpenAIResponseCoverage.POST_EXECUTION
        blind_spots = [
            "Lifecycle response callbacks are evidence-only and do not prove streaming response prevention."
        ]
    elif action_class is OpenAIActionClass.HOSTED_MCP:
        values[CapabilityDimension.HOSTED_MCP_CONTROL] = _claim(
            CapabilityLevel.EXTERNAL, experimental, _AGENTS_MCP_DOC
        )
        values[CapabilityDimension.HITL_APPROVAL] = _claim(
            CapabilityLevel.EXTERNAL, experimental, _AGENTS_MCP_DOC
        )
        values[CapabilityDimension.DESTINATION_BINDING] = _claim(
            CapabilityLevel.OBSERVE, experimental, _AGENTS_MCP_DOC
        )
        response = OpenAIResponseCoverage.POST_EXECUTION
        blind_spots = ["Hosted execution is provider-reported and is not independently verified by the SDK callback."]
    elif action_class is OpenAIActionClass.LOCAL_MCP:
        values[CapabilityDimension.LOCAL_MCP_CONTROL] = _claim(
            CapabilityLevel.EXTERNAL, experimental, _AGENTS_MCP_DOC
        )
        values[CapabilityDimension.MCP_CONTROL] = _claim(
            CapabilityLevel.EXTERNAL, experimental, _AGENTS_MCP_DOC
        )
        values[CapabilityDimension.HITL_APPROVAL] = _claim(
            CapabilityLevel.EXTERNAL, experimental, _AGENTS_MCP_DOC
        )
        response = OpenAIResponseCoverage.COMPLETE
        blind_spots = ["Tool filtering reduces capability but does not authorize each consequential call."]
    elif action_class is OpenAIActionClass.LOCAL_SHELL:
        values[CapabilityDimension.LOCAL_SHELL_CONTROL] = _claim(
            CapabilityLevel.EXTERNAL, experimental, _AGENTS_TOOL_DOC
        )
        values[CapabilityDimension.COMMAND_CONTROL] = _claim(
            CapabilityLevel.EXTERNAL, experimental, _AGENTS_TOOL_DOC
        )
        response = OpenAIResponseCoverage.COMPLETE
        blind_spots = ["Control depends on the customer-owned local executor and approval callback."]
    elif action_class is OpenAIActionClass.HOSTED_SHELL:
        values[CapabilityDimension.HOSTED_SHELL_CONTROL] = _claim(
            CapabilityLevel.UNKNOWN, experimental, _AGENTS_TOOL_DOC
        )
        response = OpenAIResponseCoverage.POST_EXECUTION
        blind_spots = ["Hosted shell does not inherit local shell approval or runtime observation."]
    elif action_class is OpenAIActionClass.APPLY_PATCH:
        values[CapabilityDimension.PATCH_CONTROL] = _claim(
            CapabilityLevel.EXTERNAL, experimental, _AGENTS_TOOL_DOC
        )
        values[CapabilityDimension.HITL_APPROVAL] = _claim(
            CapabilityLevel.EXTERNAL, experimental, _AGENTS_TOOL_DOC
        )
        response = OpenAIResponseCoverage.COMPLETE
        blind_spots = ["Patch approval must bind the canonical patch hash and workspace."]
    elif action_class is OpenAIActionClass.COMPUTER_TOOL:
        values[CapabilityDimension.COMPUTER_CONTROL] = _claim(
            CapabilityLevel.EXTERNAL, experimental, _AGENTS_TOOL_DOC
        )
        blind_spots = ["Coverage depends on the exact local or hosted ComputerTool implementation."]
    elif action_class is OpenAIActionClass.AGENT_AS_TOOL:
        values[CapabilityDimension.AGENT_AS_TOOL_CONTROL] = _claim(
            CapabilityLevel.EXTERNAL, experimental, _AGENTS_TOOL_DOC
        )
        values[CapabilityDimension.DELEGATION_CONTROL] = _claim(
            CapabilityLevel.OBSERVE, experimental, _AGENTS_TOOL_DOC
        )
        blind_spots = ["Outer approval does not authorize consequential actions inside the child agent."]
    elif action_class is OpenAIActionClass.HANDOFF:
        values[CapabilityDimension.DELEGATION_CONTROL] = _claim(
            CapabilityLevel.UNKNOWN, experimental, _AGENTS_TOOL_DOC
        )
        blind_spots = ["Handoffs use the delegation pipeline and do not inherit function-tool guardrails."]
    elif action_class is OpenAIActionClass.TOOL_SEARCH:
        values[CapabilityDimension.TOOL_CONTROL] = _claim(
            CapabilityLevel.EXTERNAL, experimental, _AGENTS_TOOL_DOC
        )
        blind_spots = ["Tool filtering is capability reduction, not exact action authorization."]
    else:
        blind_spots = ["No verified pre-execution control exists for this Agents SDK tool class."]
    return OpenAIActionControlProfile(
        product="agents_sdk",
        action_class=action_class,
        method=ControlMethod.SDK_MIDDLEWARE,
        capabilities=values,
        response_coverage=response,
        evidence_refs=refs,
        blind_spots=tuple(blind_spots),
    )


def _direct_profile(
    action_class: OpenAIActionClass,
    method: ControlMethod,
) -> OpenAIActionControlProfile:
    verified = VerificationStatus.VERIFIED
    experimental = VerificationStatus.EXPERIMENTAL
    values: dict[CapabilityDimension, CapabilityClaim] = {
        CapabilityDimension.FUNCTION_TOOL_CONTROL: _UNAVAILABLE,
        CapabilityDimension.FUNCTION_TOOL_PARAMETER_BINDING: _UNAVAILABLE,
        CapabilityDimension.FUNCTION_TOOL_TARGET_BINDING: _UNAVAILABLE,
        CapabilityDimension.DIRECT_API_CONTROL: _claim(
            CapabilityLevel.INLINE,
            verified if method is ControlMethod.GATEWAY_INLINE else experimental,
            _DIRECT_API_EVIDENCE,
        ),
        CapabilityDimension.BYPASS_DETECTION: _claim(
            CapabilityLevel.OBSERVE, experimental, _DIRECT_API_EVIDENCE
        ),
    }
    if action_class is OpenAIActionClass.MODEL_REQUEST:
        values[CapabilityDimension.MODEL_REQUEST_CONTROL] = _claim(
            CapabilityLevel.INLINE,
            verified if method is ControlMethod.GATEWAY_INLINE else experimental,
            _DIRECT_API_EVIDENCE,
        )
        values[CapabilityDimension.PROMPT_CONTROL] = _claim(
            CapabilityLevel.INLINE,
            verified if method is ControlMethod.GATEWAY_INLINE else experimental,
            _DIRECT_API_EVIDENCE,
        )
    if action_class is OpenAIActionClass.MODEL_RESPONSE and method is ControlMethod.GATEWAY_INLINE:
        values[CapabilityDimension.RESPONSE_CONTROL] = _claim(
            CapabilityLevel.INLINE, verified, _DIRECT_API_EVIDENCE
        )
        values[CapabilityDimension.MODEL_RESPONSE_CONTROL] = _claim(
            CapabilityLevel.INLINE, verified, _DIRECT_API_EVIDENCE
        )
    coverage = (
        OpenAIResponseCoverage.COMPLETE
        if method is ControlMethod.TOOL_LOOP_INTERCEPT
        else OpenAIResponseCoverage.PARTIAL
        if method is ControlMethod.GATEWAY_INLINE
        else OpenAIResponseCoverage.REQUEST_ONLY
    )
    if action_class is OpenAIActionClass.FUNCTION_TOOL and method is ControlMethod.TOOL_LOOP_INTERCEPT:
        values[CapabilityDimension.FUNCTION_TOOL_CONTROL] = _claim(
            CapabilityLevel.INLINE_BOUND, experimental, _DIRECT_API_EVIDENCE
        )
        values[CapabilityDimension.FUNCTION_TOOL_PARAMETER_BINDING] = _claim(
            CapabilityLevel.INLINE_BOUND, experimental, _DIRECT_API_EVIDENCE
        )
        values[CapabilityDimension.TOOL_CONTROL] = _claim(
            CapabilityLevel.INLINE_BOUND, experimental, _DIRECT_API_EVIDENCE
        )
        values[CapabilityDimension.PARAMETER_BINDING] = _claim(
            CapabilityLevel.INLINE_BOUND, experimental, _DIRECT_API_EVIDENCE
        )
    return OpenAIActionControlProfile(
        product="direct_api",
        action_class=action_class,
        method=method,
        capabilities=values,
        response_coverage=coverage,
        evidence_refs=(_DIRECT_API_EVIDENCE,),
        blind_spots=(
            "Only traffic bound to the selected Hawk route is controlled; direct bypass remains outside authorization.",
        ),
    )


def _codex_profile(action_class: OpenAIActionClass) -> OpenAIActionControlProfile:
    experimental = VerificationStatus.EXPERIMENTAL
    values: dict[CapabilityDimension, CapabilityClaim] = {
        CapabilityDimension.FUNCTION_TOOL_CONTROL: _UNAVAILABLE,
        CapabilityDimension.FUNCTION_TOOL_PARAMETER_BINDING: _UNAVAILABLE,
        CapabilityDimension.FUNCTION_TOOL_TARGET_BINDING: _UNAVAILABLE,
    }
    if action_class is OpenAIActionClass.MODEL_REQUEST:
        values[CapabilityDimension.PROMPT_CONTROL] = _claim(
            CapabilityLevel.INLINE, experimental, _CODEX_HOOK_DOC
        )
        values[CapabilityDimension.MODEL_REQUEST_CONTROL] = _claim(
            CapabilityLevel.INLINE, experimental, _CODEX_HOOK_DOC
        )
    elif action_class is OpenAIActionClass.LOCAL_SHELL:
        values[CapabilityDimension.CODEX_COMMAND_CONTROL] = _claim(
            CapabilityLevel.INLINE, experimental, _CODEX_HOOK_DOC
        )
        values[CapabilityDimension.COMMAND_CONTROL] = _claim(
            CapabilityLevel.INLINE, experimental, _CODEX_HOOK_DOC
        )
        values[CapabilityDimension.PARAMETER_BINDING] = _claim(
            CapabilityLevel.OBSERVE, experimental, _CODEX_HOOK_DOC
        )
        values[CapabilityDimension.TARGET_BINDING] = _claim(
            CapabilityLevel.OBSERVE, experimental, _CODEX_HOOK_DOC
        )
    elif action_class is OpenAIActionClass.APPLY_PATCH:
        values[CapabilityDimension.CODEX_FILE_CONTROL] = _claim(
            CapabilityLevel.INLINE, experimental, _CODEX_HOOK_DOC
        )
        values[CapabilityDimension.FILE_WRITE_CONTROL] = _claim(
            CapabilityLevel.INLINE, experimental, _CODEX_HOOK_DOC
        )
        values[CapabilityDimension.PARAMETER_BINDING] = _claim(
            CapabilityLevel.OBSERVE, experimental, _CODEX_HOOK_DOC
        )
        values[CapabilityDimension.TARGET_BINDING] = _claim(
            CapabilityLevel.OBSERVE, experimental, _CODEX_HOOK_DOC
        )
    elif action_class is OpenAIActionClass.LOCAL_MCP:
        values[CapabilityDimension.CODEX_MCP_CONTROL] = _claim(
            CapabilityLevel.INLINE, experimental, _CODEX_HOOK_DOC
        )
        values[CapabilityDimension.MCP_CONTROL] = _claim(
            CapabilityLevel.INLINE, experimental, _CODEX_HOOK_DOC
        )
        values[CapabilityDimension.PARAMETER_BINDING] = _claim(
            CapabilityLevel.OBSERVE, experimental, _CODEX_HOOK_DOC
        )
        values[CapabilityDimension.TARGET_BINDING] = _claim(
            CapabilityLevel.OBSERVE, experimental, _CODEX_HOOK_DOC
        )
        values[CapabilityDimension.DESTINATION_BINDING] = _claim(
            CapabilityLevel.OBSERVE, experimental, _CODEX_HOOK_DOC
        )
    elif action_class is OpenAIActionClass.CODEX_TOOL:
        values[CapabilityDimension.TOOL_CONTROL] = _claim(
            CapabilityLevel.INLINE, experimental, _CODEX_HOOK_DOC
        )
    return OpenAIActionControlProfile(
        product="codex",
        action_class=action_class,
        method=ControlMethod.NATIVE_HOOK,
        capabilities=values,
        response_coverage=OpenAIResponseCoverage.POST_EXECUTION,
        evidence_refs=(_CODEX_HOOK_DOC,),
        blind_spots=(
            "Codex hosted tools and cloud execution do not inherit local PreToolUse coverage.",
        ),
    )


def build_openai_action_control_matrix() -> OpenAIActionControlMatrix:
    profiles: list[OpenAIActionControlProfile] = []
    for action_class in OpenAIActionClass:
        profiles.append(_agents_profile(action_class))
        profiles.append(_codex_profile(action_class))
        for method in (
            ControlMethod.GATEWAY_INLINE,
            ControlMethod.API_INTERCEPT,
            ControlMethod.TOOL_LOOP_INTERCEPT,
        ):
            profiles.append(_direct_profile(action_class, method))
    return OpenAIActionControlMatrix(profiles)
