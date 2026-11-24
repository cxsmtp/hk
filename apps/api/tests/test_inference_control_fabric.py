from __future__ import annotations

from dataclasses import replace

import pytest

from app.core.control_engine.authorization import AuthorizationResponse
from app.services.native_control.adapter_contract import AdapterPipelineContext
from app.services.native_control.inference_control import (
    GenericOpenAICompatibleInferenceAdapter,
    InferenceCapabilityStatus,
    InferenceControlContext,
    InferenceControlFabric,
    InferenceLifecycleEvent,
    VllmInferenceControlAdapter,
    build_default_inference_control_registry,
)


def _response(decision: str) -> AuthorizationResponse:
    return AuthorizationResponse(
        decision=decision,
        control_mode="inline_prevented" if decision == "block" else "inline_allowed",
        reason=f"test:{decision}",
        policy_snapshot_id="policy-1",
        policy_profile_hash="a" * 64,
        response_hash="b" * 64,
    )


def _context(
    event: InferenceLifecycleEvent,
    *,
    tenant_id: str = "tenant-a",
    event_id: str = "event-1",
    provider: str = "openai_compatible",
    product: str = "generic",
    runtime: str = "openai_compatible",
) -> InferenceControlContext:
    pipeline = AdapterPipelineContext.reference(
        tenant_id=tenant_id,
        integration_instance_id=f"integration:{tenant_id}",
        provider_event_id=event_id,
        policy_profile={"base_decision": "allow", "dependencies_healthy": True},
    )
    return InferenceControlContext(
        pipeline=pipeline,
        lifecycle_event=event,
        provider=provider,
        product=product,
        runtime=runtime,
        model="test-model",
        actor={"identity_id": "user-1", "identity_type": "human"},
        executing_principal={"identity_id": "service-1", "identity_type": "service"},
        represented_subject={"identity_id": "customer-1", "identity_type": "customer"},
        business_purpose={"purpose_id": "support", "verified": True},
        authority={"authority_type": "delegated", "authority_source": "bank-session"},
        agent={"agent_id": "agent-1"},
        run_id="run-1",
        tool={"name": "lookup", "version": "1"},
        tool_fingerprint="tool-fingerprint-1",
        parameters={"account_ref": "acct-safe-ref"},
        resource="account-summary",
        target="customer-1",
        destination="internal-bank-api",
        parent_context={"parent_action_id": "parent-1"},
        delegation_context={"originating_actor_id": "user-1", "delegation_id": "delegation-1"},
        policy_epoch=7,
        evidence_refs=("evidence:identity-1",),
    )


def _fabric(decision: str, *, captured: list | None = None) -> InferenceControlFabric:
    def policy(request):
        if captured is not None:
            captured.append(request)
        return _response(decision)

    return InferenceControlFabric(
        registry=build_default_inference_control_registry(),
        evidence_sink=lambda _event: None,
        policy_evaluator=policy,
    )


def test_pre_inference_block_prevents_provider_invocation() -> None:
    invoked: list[str] = []
    result = _fabric("block").intercept(
        context=_context(InferenceLifecycleEvent.PRE_INFERENCE),
        raw_payload={"request_id": "request-1", "model": "test-model", "input": "not-retained"},
        invoke=lambda: invoked.append("provider"),
    )

    assert invoked == []
    assert result.prevented is True
    assert result.provider_invoked is False
    assert result.decision == "block"


def test_pre_tool_execution_block_prevents_tool_invocation() -> None:
    invoked: list[str] = []
    result = _fabric("block").intercept(
        context=_context(InferenceLifecycleEvent.PRE_TOOL_EXECUTION, event_id="tool-1"),
        raw_payload={"tool_call_id": "call-1", "tool_name": "lookup", "arguments": {"safe": True}},
        invoke=lambda: invoked.append("tool"),
    )

    assert invoked == []
    assert result.prevented is True
    assert result.tool_invoked is False


def test_post_tool_detection_is_never_reported_as_prevention() -> None:
    policy_calls: list[object] = []
    result = _fabric("block", captured=policy_calls).intercept(
        context=_context(InferenceLifecycleEvent.POST_TOOL_EXECUTION, event_id="tool-post-1"),
        raw_payload={"tool_call_id": "call-1", "status": "success"},
    )

    assert policy_calls == []
    assert result.prevented is False
    assert result.tool_invoked is True
    assert result.outcome == "observed_after_execution"


def test_unsupported_lifecycle_event_remains_unsupported() -> None:
    registry = build_default_inference_control_registry()
    record = registry.resolve(provider="aws", product="bedrock_model_api", runtime="bedrock")

    capability = record.manifest.for_event(InferenceLifecycleEvent.PRE_MEMORY_WRITE)

    assert capability.verification_status is InferenceCapabilityStatus.UNSUPPORTED
    assert capability.pre_execution_blocking is InferenceCapabilityStatus.UNSUPPORTED


def test_cross_tenant_receipt_correlation_is_rejected() -> None:
    with pytest.raises(ValueError, match="cross_tenant_receipt_correlation"):
        replace(
            _context(InferenceLifecycleEvent.POST_INFERENCE),
            decision_receipt_id="decision-1",
            decision_receipt_tenant_id="tenant-b",
        )

    with pytest.raises(ValueError, match="receipt_tenant_binding_required"):
        replace(
            _context(InferenceLifecycleEvent.POST_INFERENCE),
            decision_receipt_id="decision-without-tenant",
        )


def test_handoff_preserves_originating_actor_and_delegation_context() -> None:
    requests: list[object] = []
    result = _fabric("allow", captured=requests).intercept(
        context=_context(InferenceLifecycleEvent.PRE_HANDOFF, event_id="handoff-1"),
        raw_payload={"handoff_target": "agent-2"},
        invoke=lambda: None,
    )

    assert result.decision == "allow"
    assert requests[0].actor["identity_id"] == "user-1"
    assert requests[0].actor["executing_principal"]["identity_id"] == "service-1"
    assert requests[0].actor["represented_subject"]["identity_id"] == "customer-1"
    assert requests[0].runtime["delegation_context"]["originating_actor_id"] == "user-1"


def test_stream_chunk_already_emitted_is_not_retroactively_blocked() -> None:
    result = _fabric("block").intercept(
        context=_context(InferenceLifecycleEvent.STREAM_CHUNK, event_id="chunk-1"),
        raw_payload={"chunk_index": 1, "output": "not-retained"},
    )

    assert result.emitted_already is True
    assert result.prevented is False
    assert result.outcome == "observed_after_execution"


def test_generic_openai_compatible_adapter_normalizes_valid_request() -> None:
    adapter = GenericOpenAICompatibleInferenceAdapter()
    event = adapter.normalize_event(
        {"event_type": "pre_inference", "model": "qwen-2", "input": "not-retained"},
        _context(InferenceLifecycleEvent.PRE_INFERENCE).pipeline,
    )

    assert event.provider == "openai_compatible"
    assert event.product == "generic"
    assert event.lifecycle_stage == "before_model"
    assert event.action["prompt_hash"] != "unknown"
    assert "not-retained" not in repr(event)


def test_vllm_specialization_reuses_generic_contract_without_core_branching() -> None:
    adapter = VllmInferenceControlAdapter()
    context = _context(
        InferenceLifecycleEvent.PRE_INFERENCE,
        provider="self_hosted_runtime",
        product="vllm",
        runtime="vllm",
    )
    event = adapter.normalize_event(
        {"event_type": "pre_inference", "model": "meta-llama/Llama-3"},
        context.pipeline,
    )

    assert isinstance(adapter, GenericOpenAICompatibleInferenceAdapter)
    assert event.provider == "self_hosted_runtime"
    assert event.product == "vllm"
    assert adapter.inference_manifest.runtime == "vllm"


def test_existing_provider_statuses_are_projected_without_global_promotion() -> None:
    registry = build_default_inference_control_registry()

    claude = registry.resolve(provider="anthropic", product="claude_code", runtime="claude_code")
    gemini = registry.resolve(provider="google", product="gemini_cli", runtime="gemini_cli")
    microsoft = registry.resolve(provider="microsoft", product="agent_framework", runtime="agent_framework")

    assert claude.manifest.for_event(InferenceLifecycleEvent.PRE_TOOL_EXECUTION).verification_status is InferenceCapabilityStatus.VERIFIED
    assert gemini.manifest.for_event(InferenceLifecycleEvent.PRE_INFERENCE).verification_status is InferenceCapabilityStatus.PARTIAL
    assert microsoft.manifest.for_event(InferenceLifecycleEvent.PRE_TOOL_EXECUTION).verification_status is InferenceCapabilityStatus.PARTIAL
    assert microsoft.manifest.for_event(InferenceLifecycleEvent.STREAM_CHUNK).verification_status is InferenceCapabilityStatus.UNSUPPORTED


def test_existing_openai_direct_adapter_executes_through_common_fabric() -> None:
    invoked: list[str] = []
    context = _context(
        InferenceLifecycleEvent.PRE_INFERENCE,
        event_id="openai-request-1",
        provider="openai",
        product="direct_api",
        runtime="openai_responses",
    )

    result = _fabric("block").intercept(
        context=context,
        raw_payload={"model": "gpt-test", "input": "not-retained"},
        invoke=lambda: invoked.append("provider"),
    )

    assert invoked == []
    assert result.decision == "block"
    assert result.prevented is True


def test_provider_reported_success_is_weaker_than_independent_verification() -> None:
    result = _fabric("allow").intercept(
        context=_context(InferenceLifecycleEvent.POST_INFERENCE, event_id="post-1"),
        raw_payload={"status": "success"},
    )

    assert result.evidence_quality == "provider_reported"
    assert result.independently_verified is False


def test_missing_provider_does_not_break_registered_adapters() -> None:
    registry = build_default_inference_control_registry()

    with pytest.raises(LookupError, match="inference_adapter_not_registered"):
        registry.resolve(provider="missing", product="missing", runtime="missing")

    openai = registry.resolve(provider="openai", product="direct_api", runtime="openai_responses")
    assert openai.manifest.for_event(InferenceLifecycleEvent.PRE_INFERENCE).visibility is InferenceCapabilityStatus.VERIFIED
