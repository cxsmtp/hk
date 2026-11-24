from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.core.control_engine.authorization import AuthorizationRequest, AuthorizationResponse
from app.services.native_control.adapter_contract import AdapterError, AdapterErrorCode, AdapterPipelineContext
from app.services.native_control.openai_agents_bridge import (
    FunctionToolInvocation,
    OpenAIAgentsControlBridge,
    OpenAIReauthorizationRequired,
    OpenAIToolBlocked,
)


def _response(decision: str) -> AuthorizationResponse:
    return AuthorizationResponse(
        decision=decision,
        control_mode={
            "allow": "inline_allowed",
            "warn": "warned",
            "block": "inline_prevented",
            "require_approval": "review_required",
            "require_second_approval": "review_required",
        }[decision],
        reason=f"hawk_{decision}",
        policy_snapshot_id="policy-1",
        policy_profile_hash="p" * 64,
        response_hash="r" * 64,
    )


def _context() -> AdapterPipelineContext:
    return AdapterPipelineContext.reference(
        tenant_id="tenant-1",
        integration_instance_id="openai-agents-1",
        provider_event_id="provider-event-is-not-authoritative",
    )


def _invocation(**changes: object) -> FunctionToolInvocation:
    values: dict[str, object] = {
        "tool_call_id": "tool-call-7",
        "tool_name": "create_refund",
        "tool_schema": {"type": "object", "properties": {"amount": {"type": "number"}}},
        "arguments": {"amount": 25, "currency": "USD"},
        "agent_id": "refund-agent",
        "run_id": "run-7",
        "business_purpose": "customer correction",
        "target": "payment-7",
        "destination": "payments.internal",
        "persistent_side_effect": True,
    }
    values.update(changes)
    return FunctionToolInvocation(**values)


def test_safe_allow_executes_exactly_once_and_emits_correlated_post_event() -> None:
    requests: list[AuthorizationRequest] = []
    executions: list[dict[str, object]] = []

    async def authorize(request: AuthorizationRequest) -> AuthorizationResponse:
        requests.append(request)
        return _response("allow")

    bridge = OpenAIAgentsControlBridge(authorize=authorize, execution_sink=executions.append)
    calls = 0

    async def function() -> dict[str, object]:
        nonlocal calls
        calls += 1
        return {"status": "created", "provider_execution_id": "refund-7"}

    result = asyncio.run(bridge.execute(_invocation(), context=_context(), function=function))

    assert result["status"] == "created"
    assert calls == 1
    assert len(requests) == 1
    assert requests[0].action["action_class"] == "function_tool"
    assert requests[0].parameters["parameter_hash"] != "unknown"
    assert len(executions) == 1
    assert executions[0]["action_id"] == requests[0].action_id
    assert executions[0]["evidence_quality"] == "provider_reported"
    assert "refund-7" not in repr(executions[0])


def test_block_never_executes_function_tool() -> None:
    async def authorize(_request: AuthorizationRequest) -> AuthorizationResponse:
        return _response("block")

    bridge = OpenAIAgentsControlBridge(authorize=authorize)
    calls = 0

    async def function() -> None:
        nonlocal calls
        calls += 1

    with pytest.raises(OpenAIToolBlocked, match="hawk_block"):
        asyncio.run(bridge.execute(_invocation(), context=_context(), function=function))

    assert calls == 0


def test_approval_is_not_approximated_when_runtime_cannot_pause() -> None:
    async def authorize(_request: AuthorizationRequest) -> AuthorizationResponse:
        return _response("require_approval")

    bridge = OpenAIAgentsControlBridge(authorize=authorize)

    with pytest.raises(AdapterError) as failure:
        asyncio.run(
            bridge.evaluate_input(_invocation(), context=_context(), approval_capable=False)
        )
    assert failure.value.code is AdapterErrorCode.ENFORCEMENT_SEMANTIC_UNAVAILABLE

    paused = asyncio.run(
        bridge.evaluate_input(_invocation(), context=_context(), approval_capable=True)
    )
    assert paused.sdk_behavior == "pause"
    assert paused.action_id == bridge.action_id_for(_invocation(), context=_context())


def test_changed_arguments_target_or_destination_invalidate_approval_binding() -> None:
    bridge = OpenAIAgentsControlBridge(authorize=lambda _request: _response("allow"))
    original = _invocation()
    binding = bridge.bind_approval(
        original,
        context=_context(),
        decision_receipt_id="decision-7",
        approver_ids=("approver-1",),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )

    assert bridge.revalidate_approval(binding, original, context=_context()).decision_receipt_id == "decision-7"
    for changed in (
        _invocation(arguments={"amount": 26, "currency": "USD"}),
        _invocation(target="payment-8"),
        _invocation(destination="other-payments.internal"),
    ):
        with pytest.raises(OpenAIReauthorizationRequired):
            bridge.revalidate_approval(binding, changed, context=_context())


def test_pending_and_resumed_tool_call_share_one_hawk_action_identity() -> None:
    bridge = OpenAIAgentsControlBridge(authorize=lambda _request: _response("allow"))

    pending = bridge.action_id_for(_invocation(), context=_context())
    resumed = bridge.action_id_for(_invocation(), context=_context())
    other = bridge.action_id_for(_invocation(tool_call_id="tool-call-8"), context=_context())

    assert pending == resumed
    assert pending != other
