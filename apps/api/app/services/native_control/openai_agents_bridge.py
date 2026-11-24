from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from importlib import metadata
import inspect
import json
from typing import Any, Awaitable, Callable, Mapping

from app.core.control_engine.authorization import AuthorizationRequest, AuthorizationResponse
from app.services.native_control.adapter_contract import (
    AdapterError,
    AdapterErrorCode,
    AdapterPipelineContext,
    stable_hash,
)
from app.services.native_control.openai_adapters import OpenAIAgentsSDKControlAdapter


AuthorizationCallback = Callable[
    [AuthorizationRequest], AuthorizationResponse | Awaitable[AuthorizationResponse]
]
ExecutionSink = Callable[[dict[str, object]], None]
OPENAI_AGENTS_ACCEPTED_VERSIONS = ("0.20.0",)


class OpenAIToolBlocked(RuntimeError):
    """The Hawk pre-execution decision prevented the function tool call."""


class OpenAIReauthorizationRequired(RuntimeError):
    """The exact action no longer matches the action approved by Hawk."""


@dataclass(frozen=True, slots=True)
class FunctionToolInvocation:
    tool_call_id: str
    tool_name: str
    tool_schema: Mapping[str, Any]
    arguments: Mapping[str, Any]
    agent_id: str
    run_id: str
    business_purpose: str
    target: str
    destination: str
    persistent_side_effect: bool

    def __post_init__(self) -> None:
        for name in (
            "tool_call_id",
            "tool_name",
            "agent_id",
            "run_id",
            "business_purpose",
            "target",
            "destination",
        ):
            value = str(getattr(self, name) or "").strip()
            if not value or len(value.encode("utf-8")) > 512:
                raise ValueError(f"openai_function_tool_{name}_invalid")
        if not isinstance(self.tool_schema, Mapping) or not isinstance(self.arguments, Mapping):
            raise ValueError("openai_function_tool_mapping_invalid")

    def exact_action_material(self) -> dict[str, object]:
        return {
            "tool_call_id": self.tool_call_id,
            "tool_name": self.tool_name,
            "tool_schema": dict(self.tool_schema),
            "arguments": dict(self.arguments),
            "agent_id": self.agent_id,
            "run_id": self.run_id,
            "business_purpose": self.business_purpose,
            "target": self.target,
            "destination": self.destination,
            "persistent_side_effect": self.persistent_side_effect,
        }

    @property
    def exact_action_hash(self) -> str:
        return stable_hash(self.exact_action_material())


@dataclass(frozen=True, slots=True)
class BoundToolDecision:
    action_id: str
    exact_action_hash: str
    parameter_hash: str
    sdk_behavior: str
    response: AuthorizationResponse


@dataclass(frozen=True, slots=True)
class OpenAIApprovalBinding:
    action_id: str
    exact_action_hash: str
    decision_receipt_id: str
    approver_ids: tuple[str, ...]
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class AgentsSDKGuardrailBinding:
    invocation: FunctionToolInvocation
    pipeline_context: AdapterPipelineContext


AgentsSDKBindingResolver = Callable[
    [Any],
    AgentsSDKGuardrailBinding | Awaitable[AgentsSDKGuardrailBinding],
]
LifecycleSink = Callable[[dict[str, object]], None]


class OpenAIAgentsControlBridge:
    """Binds Agents SDK function-tool control to Hawk's existing kernel.

    This bridge owns no provider-specific policy. It normalizes one exact SDK
    invocation, delegates the decision to Hawk, and preserves the same action
    identity across HITL interruption and resume.
    """

    def __init__(
        self,
        *,
        authorize: AuthorizationCallback,
        execution_sink: ExecutionSink | None = None,
        adapter: OpenAIAgentsSDKControlAdapter | None = None,
    ) -> None:
        if not callable(authorize):
            raise ValueError("openai_agents_authorize_callback_required")
        self._authorize = authorize
        self._execution_sink = execution_sink
        self.adapter = adapter or OpenAIAgentsSDKControlAdapter()

    def action_id_for(
        self,
        invocation: FunctionToolInvocation,
        *,
        context: AdapterPipelineContext,
    ) -> str:
        digest = stable_hash(
            {
                "tenant_id": context.tenant_id,
                "integration_instance_id": context.integration_instance_id,
                "session_id": context.session_id,
                "run_id": invocation.run_id,
                "tool_call_id": invocation.tool_call_id,
            }
        )
        return f"openai-tool:{digest}"

    def _event_context(
        self,
        invocation: FunctionToolInvocation,
        context: AdapterPipelineContext,
    ) -> AdapterPipelineContext:
        return replace(
            context,
            provider_event_id=self.action_id_for(invocation, context=context),
            correlation_id=f"openai-tool:{stable_hash((context.correlation_id, invocation.tool_call_id))}",
        )

    def _payload(self, invocation: FunctionToolInvocation, *, event_type: str) -> dict[str, object]:
        return {
            "event_type": event_type,
            "tool_class": "function_tool",
            "tool_name": invocation.tool_name,
            "tool_call_id": invocation.tool_call_id,
            "tool_schema": dict(invocation.tool_schema),
            "arguments": dict(invocation.arguments),
            "agent_id": invocation.agent_id,
            "run_id": invocation.run_id,
            "business_purpose": invocation.business_purpose,
            "target": invocation.target,
            "destination": invocation.destination,
            "persistent_side_effect": invocation.persistent_side_effect,
            "execution_location": "application_runtime",
        }

    async def _evaluate(self, request: AuthorizationRequest) -> AuthorizationResponse:
        result = self._authorize(request)
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, AuthorizationResponse):
            raise AdapterError(
                AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED,
                safe_diagnostic="authorization_callback_returned_invalid_response",
            )
        return result

    async def evaluate_input(
        self,
        invocation: FunctionToolInvocation,
        *,
        context: AdapterPipelineContext,
        approval_capable: bool,
    ) -> BoundToolDecision:
        event = self.adapter.normalize_event(
            self._payload(invocation, event_type="function_tool_input"),
            self._event_context(invocation, context),
        )
        request = event.to_authorization_request()
        response = await self._evaluate(request)
        if response.decision in {"review", "require_approval", "require_second_approval"}:
            if not approval_capable:
                raise AdapterError(
                    AdapterErrorCode.ENFORCEMENT_SEMANTIC_UNAVAILABLE,
                    safe_diagnostic="sdk_runtime_cannot_pause_for_required_approval",
                )
            formatted = self.adapter.format_approval_pause(response)
        else:
            formatted = self.adapter.format_decision_response(response)
        return BoundToolDecision(
            action_id=request.action_id,
            exact_action_hash=invocation.exact_action_hash,
            parameter_hash=str(request.parameters.get("parameter_hash") or "unknown"),
            sdk_behavior=str(formatted.get("behavior") or "unknown"),
            response=response,
        )

    async def execute(
        self,
        invocation: FunctionToolInvocation,
        *,
        context: AdapterPipelineContext,
        function: Callable[[], Any],
    ) -> Any:
        decision = await self.evaluate_input(
            invocation,
            context=context,
            approval_capable=False,
        )
        if decision.sdk_behavior == "raise_exception":
            raise OpenAIToolBlocked(decision.response.reason)
        if decision.sdk_behavior != "allow":
            raise AdapterError(
                AdapterErrorCode.ENFORCEMENT_SEMANTIC_UNAVAILABLE,
                safe_diagnostic=f"unsupported_sdk_behavior:{decision.sdk_behavior}",
            )
        result = function()
        if inspect.isawaitable(result):
            result = await result
        if self._execution_sink is not None:
            self._execution_sink(
                {
                    "action_id": decision.action_id,
                    "exact_action_hash": decision.exact_action_hash,
                    "parameter_hash": decision.parameter_hash,
                    "execution_status": "succeeded",
                    "result_hash": stable_hash(result),
                    "evidence_quality": "provider_reported",
                }
            )
        return result

    def record_output(
        self,
        invocation: FunctionToolInvocation,
        *,
        context: AdapterPipelineContext,
        result: Any,
        execution_status: str = "succeeded",
    ) -> dict[str, object]:
        evidence = {
            "action_id": self.action_id_for(invocation, context=context),
            "exact_action_hash": invocation.exact_action_hash,
            "parameter_hash": stable_hash(invocation.arguments),
            "execution_status": str(execution_status or "unknown")[:64],
            "result_hash": stable_hash(result),
            "evidence_quality": "provider_reported",
        }
        if self._execution_sink is not None:
            self._execution_sink(evidence)
        return evidence

    def bind_approval(
        self,
        invocation: FunctionToolInvocation,
        *,
        context: AdapterPipelineContext,
        decision_receipt_id: str,
        approver_ids: tuple[str, ...],
        expires_at: datetime,
    ) -> OpenAIApprovalBinding:
        receipt = str(decision_receipt_id or "").strip()
        approvers = tuple(dict.fromkeys(str(value or "").strip() for value in approver_ids))
        if not receipt or not approvers or expires_at.tzinfo is None:
            raise ValueError("openai_approval_binding_invalid")
        return OpenAIApprovalBinding(
            action_id=self.action_id_for(invocation, context=context),
            exact_action_hash=invocation.exact_action_hash,
            decision_receipt_id=receipt,
            approver_ids=approvers,
            expires_at=expires_at.astimezone(timezone.utc),
        )

    def revalidate_approval(
        self,
        binding: OpenAIApprovalBinding,
        invocation: FunctionToolInvocation,
        *,
        context: AdapterPipelineContext,
        now: datetime | None = None,
    ) -> OpenAIApprovalBinding:
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if binding.expires_at <= current:
            raise OpenAIReauthorizationRequired("approval_expired")
        if binding.action_id != self.action_id_for(invocation, context=context):
            raise OpenAIReauthorizationRequired("tool_call_identity_changed")
        if binding.exact_action_hash != invocation.exact_action_hash:
            raise OpenAIReauthorizationRequired("approved_action_changed")
        return binding


def build_agents_sdk_function_tool_guardrails(
    *,
    bridge: OpenAIAgentsControlBridge,
    resolve_binding: AgentsSDKBindingResolver,
) -> tuple[Any, Any]:
    """Build real OpenAI Agents SDK 0.20.0 function-tool guardrails.

    Imports are deliberately optional so the Hawk API does not silently add a
    provider runtime dependency. An application must pin an accepted SDK and
    explicitly attach both returned guardrails to each governed function tool.
    """

    if not callable(resolve_binding):
        raise ValueError("openai_agents_binding_resolver_required")
    try:
        installed_version = metadata.version("openai-agents")
        from agents import (
            ToolGuardrailFunctionOutput,
            ToolInputGuardrail,
            ToolOutputGuardrail,
        )
    except (metadata.PackageNotFoundError, ImportError) as exc:
        raise AdapterError(
            AdapterErrorCode.CAPABILITY_UNAVAILABLE,
            safe_diagnostic="openai_agents_sdk_not_installed",
        ) from exc
    if installed_version not in OPENAI_AGENTS_ACCEPTED_VERSIONS:
        raise AdapterError(
            AdapterErrorCode.UNSUPPORTED_PROVIDER_VERSION,
            safe_diagnostic=f"openai_agents_sdk_version:{installed_version}",
        )

    async def binding_for(data: Any) -> AgentsSDKGuardrailBinding:
        value = resolve_binding(data)
        if inspect.isawaitable(value):
            value = await value
        if not isinstance(value, AgentsSDKGuardrailBinding):
            raise AdapterError(
                AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED,
                safe_diagnostic="openai_agents_binding_invalid",
            )
        sdk_context = getattr(data, "context", None)
        sdk_tool_name = str(getattr(sdk_context, "tool_name", "") or "")
        sdk_tool_call_id = str(getattr(sdk_context, "tool_call_id", "") or "")
        raw_arguments = getattr(sdk_context, "tool_arguments", None)
        try:
            sdk_arguments = json.loads(raw_arguments) if isinstance(raw_arguments, str) else raw_arguments
        except json.JSONDecodeError as exc:
            raise AdapterError(
                AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED,
                safe_diagnostic="openai_agents_sdk_arguments_invalid_json",
            ) from exc
        if not isinstance(sdk_arguments, Mapping):
            raise AdapterError(
                AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED,
                safe_diagnostic="openai_agents_sdk_arguments_not_object",
            )
        if (
            sdk_tool_name != value.invocation.tool_name
            or sdk_tool_call_id != value.invocation.tool_call_id
            or stable_hash(sdk_arguments) != stable_hash(value.invocation.arguments)
        ):
            raise AdapterError(
                AdapterErrorCode.CONFIG_TAMPERED,
                safe_diagnostic="openai_agents_sdk_invocation_binding_mismatch",
            )
        return value

    async def input_guardrail(data: Any) -> Any:
        binding = await binding_for(data)
        decision = await bridge.evaluate_input(
            binding.invocation,
            context=binding.pipeline_context,
            approval_capable=False,
        )
        info = {
            "hawk_action_id": decision.action_id,
            "hawk_decision": decision.response.decision,
            "policy_snapshot_id": decision.response.policy_snapshot_id,
            "exact_action_hash": decision.exact_action_hash,
        }
        if decision.sdk_behavior == "allow":
            return ToolGuardrailFunctionOutput.allow(output_info=info)
        if decision.sdk_behavior == "raise_exception":
            return ToolGuardrailFunctionOutput.raise_exception(output_info=info)
        raise AdapterError(
            AdapterErrorCode.ENFORCEMENT_SEMANTIC_UNAVAILABLE,
            safe_diagnostic=f"openai_agents_sdk_behavior:{decision.sdk_behavior}",
        )

    async def output_guardrail(data: Any) -> Any:
        binding = await binding_for(data)
        evidence = bridge.record_output(
            binding.invocation,
            context=binding.pipeline_context,
            result=getattr(data, "output", None),
        )
        return ToolGuardrailFunctionOutput.allow(output_info=evidence)

    return (
        ToolInputGuardrail(guardrail_function=input_guardrail, name="hawk_function_tool_input"),
        ToolOutputGuardrail(guardrail_function=output_guardrail, name="hawk_function_tool_output"),
    )


def build_agents_sdk_lifecycle_observer(*, event_sink: LifecycleSink) -> Any:
    """Return real SDK RunHooks that emit evidence but never authorize.

    Keeping this object separate from the function-tool bridge prevents a
    lifecycle callback from being mistaken for a pre-execution control point.
    """

    if not callable(event_sink):
        raise ValueError("openai_agents_lifecycle_sink_required")
    try:
        installed_version = metadata.version("openai-agents")
        from agents import RunHooks
    except (metadata.PackageNotFoundError, ImportError) as exc:
        raise AdapterError(
            AdapterErrorCode.CAPABILITY_UNAVAILABLE,
            safe_diagnostic="openai_agents_sdk_not_installed",
        ) from exc
    if installed_version not in OPENAI_AGENTS_ACCEPTED_VERSIONS:
        raise AdapterError(
            AdapterErrorCode.UNSUPPORTED_PROVIDER_VERSION,
            safe_diagnostic=f"openai_agents_sdk_version:{installed_version}",
        )
    base = getattr(RunHooks, "__origin__", RunHooks)

    def emit(event_type: str, **fields: object) -> None:
        event_sink(
            {
                "event_type": event_type,
                "evidence_role": "lifecycle_observation",
                "authorization_capable": False,
                **fields,
            }
        )

    class HawkLifecycleObserver(base):  # type: ignore[misc, valid-type]
        async def on_llm_start(self, _context, agent, system_prompt, input_items) -> None:
            emit(
                "llm_start",
                agent_hash=stable_hash(getattr(agent, "name", "unknown")),
                system_prompt_hash=stable_hash(system_prompt or ""),
                input_item_count=len(input_items),
            )

        async def on_llm_end(self, _context, agent, response) -> None:
            emit(
                "llm_end",
                agent_hash=stable_hash(getattr(agent, "name", "unknown")),
                response_hash=stable_hash(response),
            )

        async def on_agent_start(self, _context, agent) -> None:
            emit("agent_start", agent_hash=stable_hash(getattr(agent, "name", "unknown")))

        async def on_agent_end(self, _context, agent, output) -> None:
            emit(
                "agent_end",
                agent_hash=stable_hash(getattr(agent, "name", "unknown")),
                output_hash=stable_hash(output),
            )

        async def on_handoff(self, _context, from_agent, to_agent) -> None:
            emit(
                "handoff",
                from_agent_hash=stable_hash(getattr(from_agent, "name", "unknown")),
                to_agent_hash=stable_hash(getattr(to_agent, "name", "unknown")),
            )

        async def on_tool_start(self, context, _agent, tool) -> None:
            emit(
                "tool_start",
                tool_hash=stable_hash(getattr(tool, "name", type(tool).__name__)),
                tool_call_hash=stable_hash(getattr(context, "tool_call_id", "unknown")),
            )

        async def on_tool_end(self, context, _agent, tool, result) -> None:
            emit(
                "tool_end",
                tool_hash=stable_hash(getattr(tool, "name", type(tool).__name__)),
                tool_call_hash=stable_hash(getattr(context, "tool_call_id", "unknown")),
                result_hash=stable_hash(result),
            )

    return HawkLifecycleObserver()
