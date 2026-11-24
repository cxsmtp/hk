from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
from time import perf_counter

from agents import Agent, FunctionTool
from agents import ToolInputGuardrailData
from agents.exceptions import ToolInputGuardrailTripwireTriggered
from agents.run_internal.tool_execution import (
    _execute_tool_input_guardrails,
    _execute_tool_output_guardrails,
)
from agents.tool_context import ToolContext

from app.core.control_engine.authorization import AuthorizationResponse
from app.services.native_control.adapter_contract import AdapterPipelineContext
from app.services.native_control.adapter_contract import AdapterError, AdapterErrorCode
from app.services.native_control.openai_agents_bridge import (
    AgentsSDKGuardrailBinding,
    FunctionToolInvocation,
    OpenAIAgentsControlBridge,
    build_agents_sdk_function_tool_guardrails,
    build_agents_sdk_lifecycle_observer,
)


@dataclass
class AcceptanceState:
    decision: str = "allow"
    executions: int = 0


def _response(decision: str) -> AuthorizationResponse:
    return AuthorizationResponse(
        decision=decision,
        control_mode="inline_allowed" if decision == "allow" else "inline_prevented",
        reason=f"hawk_{decision}",
        policy_snapshot_id="acceptance-policy",
        policy_profile_hash="p" * 64,
        response_hash="r" * 64,
    )


async def main() -> None:
    state = AcceptanceState()
    evidence: list[dict[str, object]] = []
    context = AdapterPipelineContext.reference(
        tenant_id="acceptance-tenant",
        integration_instance_id="openai-agents-0-20-0",
        provider_event_id="sdk-acceptance",
    )
    invocation = FunctionToolInvocation(
        tool_call_id="call-acceptance-1",
        tool_name="synthetic_write",
        tool_schema={"type": "object", "properties": {"value": {"type": "string"}}},
        arguments={"value": "synthetic"},
        agent_id="acceptance-agent",
        run_id="acceptance-run",
        business_purpose="safe local conformance",
        target="synthetic-target",
        destination="local",
        persistent_side_effect=True,
    )

    async def authorize(_request):
        return _response(state.decision)

    bridge = OpenAIAgentsControlBridge(authorize=authorize, execution_sink=evidence.append)

    def resolve(_data):
        return AgentsSDKGuardrailBinding(invocation=invocation, pipeline_context=context)

    input_guardrail, output_guardrail = build_agents_sdk_function_tool_guardrails(
        bridge=bridge,
        resolve_binding=resolve,
    )
    lifecycle: list[dict[str, object]] = []
    observer = build_agents_sdk_lifecycle_observer(event_sink=lifecycle.append)

    async def invoke(_context, _arguments):
        state.executions += 1
        return {"status": "executed"}

    tool = FunctionTool(
        name="synthetic_write",
        description="safe acceptance tool",
        params_json_schema=dict(invocation.tool_schema),
        on_invoke_tool=invoke,
        tool_input_guardrails=[input_guardrail],
        tool_output_guardrails=[output_guardrail],
    )
    agent = Agent(name="Hawk acceptance agent")
    tool_context = ToolContext(
        context={},
        tool_name=tool.name,
        tool_call_id=invocation.tool_call_id,
        tool_arguments=json.dumps(invocation.arguments),
        agent=agent,
    )
    await observer.on_tool_start(tool_context, agent, tool)

    started = perf_counter()
    input_results = []
    rejected = await _execute_tool_input_guardrails(
        func_tool=tool,
        tool_context=tool_context,
        agent=agent,
        tool_input_guardrail_results=input_results,
    )
    assert rejected is None
    result = await tool.on_invoke_tool(tool_context, json.dumps(invocation.arguments))
    state.executions += 0
    output_results = []
    guarded = await _execute_tool_output_guardrails(
        func_tool=tool,
        tool_context=tool_context,
        agent=agent,
        real_result=result,
        tool_output_guardrail_results=output_results,
    )
    assert guarded.output == result
    assert state.executions == 1
    assert len(evidence) == 1
    assert evidence[0]["evidence_quality"] == "provider_reported"
    assert lifecycle[0]["authorization_capable"] is False
    assert "synthetic_write" not in str(lifecycle[0])

    tampered_context = ToolContext(
        context={},
        tool_name=tool.name,
        tool_call_id=invocation.tool_call_id,
        tool_arguments=json.dumps({"value": "changed-after-binding"}),
        agent=agent,
    )
    try:
        await input_guardrail.run(ToolInputGuardrailData(context=tampered_context, agent=agent))
    except AdapterError as exc:
        assert exc.code is AdapterErrorCode.CONFIG_TAMPERED
    else:
        raise AssertionError("SDK argument binding mismatch was accepted")

    state.decision = "block"
    try:
        await _execute_tool_input_guardrails(
            func_tool=tool,
            tool_context=tool_context,
            agent=agent,
            tool_input_guardrail_results=[],
        )
    except ToolInputGuardrailTripwireTriggered:
        pass
    else:
        raise AssertionError("SDK block guardrail did not trip")
    assert state.executions == 1, "blocked action executed"
    elapsed_ms = (perf_counter() - started) * 1_000
    print(
        json.dumps(
            {
                "adapter": "OpenAIAgentsSDKControlAdapter",
                "sdk_version": "0.20.0",
                "allow_executed_once": True,
                "block_non_execution": True,
                "output_evidence": "provider_reported_hash_only",
                "lifecycle_authorization_capable": False,
                "sdk_context_binding_enforced": True,
                "local_acceptance_latency_ms": round(elapsed_ms, 3),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
