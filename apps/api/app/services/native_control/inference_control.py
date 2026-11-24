"""Provider-neutral inference lifecycle control over Hawk's existing spine.

This module intentionally owns no policy language, action schema, permit, or
receipt persistence.  It projects existing provider manifests into one
inference lifecycle vocabulary and delegates pre-execution decisions to the
existing authorization kernel.  Post-execution events are evidence only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

from app.core.control_engine.authorization import (
    AuthorizationRequest,
    AuthorizationResponse,
    authorize_ai_action,
)
from app.services.native_control.adapter_contract import (
    AdapterContractError,
    AdapterDescriptor,
    AdapterError,
    AdapterErrorCode,
    AdapterMaturity,
    AdapterPipelineContext,
    CapabilityManifest,
    DeploymentFamily,
    EvidenceQuality,
    EventSemantics,
    NativeControlAdapter,
    NativeControlEvent,
    ProviderTransport,
    SelectionCharacteristics,
    StructuredBlindSpot,
    stable_hash,
)
from app.services.native_control.adapter_pipeline import HawkCallbackSecurityBoundary
from app.services.native_control.contracts import (
    CapabilityClaim,
    CapabilityDimension,
    CapabilityLevel,
    ControlMethod,
    DegradationMode,
    RuntimeLocation,
    SecurityProperties,
    VerificationStatus,
)


class InferenceLifecycleEvent(str, Enum):
    PRE_INFERENCE = "pre_inference"
    POST_INFERENCE = "post_inference"
    STREAM_CHUNK = "stream_chunk"
    PRE_RETRIEVAL = "pre_retrieval"
    POST_RETRIEVAL = "post_retrieval"
    PRE_TOOL_SELECTION = "pre_tool_selection"
    PRE_TOOL_EXECUTION = "pre_tool_execution"
    POST_TOOL_EXECUTION = "post_tool_execution"
    PRE_HANDOFF = "pre_handoff"
    POST_HANDOFF = "post_handoff"
    PRE_MEMORY_WRITE = "pre_memory_write"
    POST_MEMORY_WRITE = "post_memory_write"
    RUN_END = "run_end"
    FAILURE = "failure"


class InferenceCapabilityStatus(str, Enum):
    VERIFIED = "VERIFIED"
    PARTIAL = "PARTIAL"
    UNVERIFIED = "UNVERIFIED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


_PRE_EVENTS = frozenset(
    {
        InferenceLifecycleEvent.PRE_INFERENCE,
        InferenceLifecycleEvent.PRE_RETRIEVAL,
        InferenceLifecycleEvent.PRE_TOOL_SELECTION,
        InferenceLifecycleEvent.PRE_TOOL_EXECUTION,
        InferenceLifecycleEvent.PRE_HANDOFF,
        InferenceLifecycleEvent.PRE_MEMORY_WRITE,
    }
)
_POST_EVENTS = frozenset(set(InferenceLifecycleEvent) - set(_PRE_EVENTS))
_HALTING_DECISIONS = frozenset(
    {"block", "review", "require_approval", "require_second_approval", "redact"}
)


@dataclass(frozen=True, slots=True)
class InferenceEventCapability:
    visibility: InferenceCapabilityStatus = InferenceCapabilityStatus.UNSUPPORTED
    pre_execution_blocking: InferenceCapabilityStatus = InferenceCapabilityStatus.UNSUPPORTED
    input_mutation_redaction: InferenceCapabilityStatus = InferenceCapabilityStatus.UNSUPPORTED
    parameter_binding: InferenceCapabilityStatus = InferenceCapabilityStatus.UNSUPPORTED
    target_binding: InferenceCapabilityStatus = InferenceCapabilityStatus.UNSUPPORTED
    destination_binding: InferenceCapabilityStatus = InferenceCapabilityStatus.UNSUPPORTED
    subject_binding: InferenceCapabilityStatus = InferenceCapabilityStatus.UNKNOWN
    authority_visibility: InferenceCapabilityStatus = InferenceCapabilityStatus.UNKNOWN
    post_execution_observation: InferenceCapabilityStatus = InferenceCapabilityStatus.UNSUPPORTED
    independent_verification: InferenceCapabilityStatus = InferenceCapabilityStatus.UNVERIFIED
    event_ordering: str = "unsupported"
    timeout_failure_behavior: str = "unsupported"
    provider_runtime_version: str = "unknown"
    verification_status: InferenceCapabilityStatus = InferenceCapabilityStatus.UNSUPPORTED
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class InferenceCapabilityManifest:
    adapter_id: str
    provider: str
    product: str
    runtime: str
    provider_version: str
    adapter_version: str
    overall_status: InferenceCapabilityStatus
    events: Mapping[InferenceLifecycleEvent, InferenceEventCapability]
    failure_modes: tuple[str, ...]
    evidence_quality: str
    limitations: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()

    def for_event(self, event: InferenceLifecycleEvent) -> InferenceEventCapability:
        return self.events.get(event, InferenceEventCapability())


@dataclass(frozen=True, slots=True)
class InferenceControlContext:
    pipeline: AdapterPipelineContext
    lifecycle_event: InferenceLifecycleEvent
    provider: str
    product: str
    runtime: str
    model: str = "unknown"
    actor: Mapping[str, Any] = field(default_factory=dict)
    executing_principal: Mapping[str, Any] = field(default_factory=dict)
    represented_subject: Mapping[str, Any] = field(default_factory=dict)
    business_purpose: Mapping[str, Any] = field(default_factory=dict)
    authority: Mapping[str, Any] = field(default_factory=dict)
    agent: Mapping[str, Any] = field(default_factory=dict)
    run_id: str = "unknown"
    tool: Mapping[str, Any] = field(default_factory=dict)
    tool_fingerprint: str = "unknown"
    parameters: Mapping[str, Any] = field(default_factory=dict)
    resource: str = "unknown"
    target: str = "unknown"
    destination: str = "unknown"
    parent_context: Mapping[str, Any] = field(default_factory=dict)
    delegation_context: Mapping[str, Any] = field(default_factory=dict)
    policy_epoch: int | None = None
    evidence_refs: tuple[str, ...] = ()
    decision_receipt_id: str | None = None
    decision_receipt_tenant_id: str | None = None
    execution_receipt_id: str | None = None
    execution_receipt_tenant_id: str | None = None

    def __post_init__(self) -> None:
        for name in ("provider", "product", "runtime"):
            if not str(getattr(self, name) or "").strip():
                raise ValueError(f"inference_{name}_required")
        for receipt_tenant in (
            self.decision_receipt_tenant_id,
            self.execution_receipt_tenant_id,
        ):
            if receipt_tenant is not None and receipt_tenant != self.pipeline.tenant_id:
                raise ValueError("cross_tenant_receipt_correlation")
        if self.decision_receipt_id and self.decision_receipt_tenant_id is None:
            raise ValueError("receipt_tenant_binding_required")
        if self.execution_receipt_id and self.execution_receipt_tenant_id is None:
            raise ValueError("receipt_tenant_binding_required")
        if self.policy_epoch is not None and self.policy_epoch < 0:
            raise ValueError("policy_epoch_invalid")


@dataclass(frozen=True, slots=True)
class InferenceControlResult:
    lifecycle_event: InferenceLifecycleEvent
    action_id: str
    outcome: str
    decision: str | None
    prevented: bool
    provider_invoked: bool
    tool_invoked: bool
    emitted_already: bool
    evidence_quality: str
    independently_verified: bool
    evidence_ref: str
    decision_receipt_id: str | None = None
    execution_permit_id: str | None = None
    execution_receipt_id: str | None = None


@runtime_checkable
class InferenceControlAdapter(Protocol):
    descriptor: AdapterDescriptor
    manifest: CapabilityManifest
    inference_manifest: InferenceCapabilityManifest

    def normalize_event(
        self, raw_payload: Mapping[str, Any], context: AdapterPipelineContext
    ) -> NativeControlEvent: ...

    def format_decision_response(self, response: AuthorizationResponse) -> dict[str, Any]: ...

    def limitations(self) -> tuple[StructuredBlindSpot, ...]: ...


def _native_status(status: VerificationStatus) -> InferenceCapabilityStatus:
    return {
        VerificationStatus.VERIFIED: InferenceCapabilityStatus.VERIFIED,
        VerificationStatus.EXPERIMENTAL: InferenceCapabilityStatus.PARTIAL,
        VerificationStatus.UNVERIFIED: InferenceCapabilityStatus.UNVERIFIED,
        VerificationStatus.BROKEN: InferenceCapabilityStatus.UNSUPPORTED,
        VerificationStatus.REMOVED: InferenceCapabilityStatus.UNSUPPORTED,
    }[status]


def _claim_status(
    manifest: CapabilityManifest,
    dimension: CapabilityDimension,
) -> InferenceCapabilityStatus:
    claim = manifest.capabilities.get(dimension)
    if claim is None or claim.level in {CapabilityLevel.UNAVAILABLE, CapabilityLevel.UNKNOWN}:
        return InferenceCapabilityStatus.UNSUPPORTED
    return _native_status(claim.verification_status)


_LIFECYCLE_ALIASES: dict[str, InferenceLifecycleEvent] = {
    "PreToolUse": InferenceLifecycleEvent.PRE_TOOL_EXECUTION,
    "BeforeTool": InferenceLifecycleEvent.PRE_TOOL_EXECUTION,
    "function_tool_input": InferenceLifecycleEvent.PRE_TOOL_EXECUTION,
    "tool_approval": InferenceLifecycleEvent.PRE_TOOL_EXECUTION,
    "tool_proposal": InferenceLifecycleEvent.PRE_TOOL_SELECTION,
    "BeforeToolSelection": InferenceLifecycleEvent.PRE_TOOL_SELECTION,
    "PostToolUse": InferenceLifecycleEvent.POST_TOOL_EXECUTION,
    "PostToolUseFailure": InferenceLifecycleEvent.FAILURE,
    "AfterTool": InferenceLifecycleEvent.POST_TOOL_EXECUTION,
    "function_tool_output": InferenceLifecycleEvent.POST_TOOL_EXECUTION,
    "tool_result": InferenceLifecycleEvent.POST_TOOL_EXECUTION,
    "UserPromptSubmit": InferenceLifecycleEvent.PRE_INFERENCE,
    "BeforeAgent": InferenceLifecycleEvent.PRE_INFERENCE,
    "BeforeModel": InferenceLifecycleEvent.PRE_INFERENCE,
    "responses_request": InferenceLifecycleEvent.PRE_INFERENCE,
    "AfterModel": InferenceLifecycleEvent.POST_INFERENCE,
    "llm_end": InferenceLifecycleEvent.POST_INFERENCE,
    "responses_chunk": InferenceLifecycleEvent.STREAM_CHUNK,
    "AfterAgent": InferenceLifecycleEvent.RUN_END,
    "agent_end": InferenceLifecycleEvent.RUN_END,
    "SessionEnd": InferenceLifecycleEvent.RUN_END,
    "run_end": InferenceLifecycleEvent.RUN_END,
}


def project_native_inference_manifest(
    adapter: NativeControlAdapter,
    *,
    runtime: str,
) -> InferenceCapabilityManifest:
    source = adapter.manifest
    overall = _native_status(source.verification_status)
    rows: dict[InferenceLifecycleEvent, InferenceEventCapability] = {}
    for raw_event in source.event_semantics.pre_execution_events:
        event = _LIFECYCLE_ALIASES.get(raw_event)
        if event is None:
            continue
        rows[event] = InferenceEventCapability(
            visibility=overall,
            pre_execution_blocking=overall if source.security_properties.pre_execution_capable else InferenceCapabilityStatus.UNSUPPORTED,
            input_mutation_redaction=overall if source.supports_action_mutation else InferenceCapabilityStatus.UNSUPPORTED,
            parameter_binding=_claim_status(source, CapabilityDimension.PARAMETER_BINDING),
            target_binding=_claim_status(source, CapabilityDimension.TARGET_BINDING),
            destination_binding=_claim_status(source, CapabilityDimension.DESTINATION_BINDING),
            subject_binding=_claim_status(source, CapabilityDimension.SUBJECT_BINDING),
            authority_visibility=_claim_status(source, CapabilityDimension.AUTHORITY_BINDING),
            event_ordering="provider_contract" if source.event_semantics.ordering_guaranteed else "not_guaranteed",
            timeout_failure_behavior=source.failure_semantics,
            provider_runtime_version=source.provider_version_max,
            verification_status=overall,
            evidence_refs=tuple(source.reviewed_evidence_refs) or (source.source_reference,),
        )
    for raw_event in source.event_semantics.post_execution_events:
        event = _LIFECYCLE_ALIASES.get(raw_event)
        if event is None:
            continue
        rows[event] = InferenceEventCapability(
            visibility=overall,
            post_execution_observation=overall if source.security_properties.post_execution_capable else InferenceCapabilityStatus.UNSUPPORTED,
            independent_verification=(
                InferenceCapabilityStatus.VERIFIED
                if source.execution_evidence_quality is EvidenceQuality.HAWK_EXTERNALLY_VERIFIED
                else InferenceCapabilityStatus.UNVERIFIED
            ),
            event_ordering="after_provider_callback",
            timeout_failure_behavior=source.failure_semantics,
            provider_runtime_version=source.provider_version_max,
            verification_status=overall,
            evidence_refs=tuple(source.reviewed_evidence_refs) or (source.source_reference,),
        )
    return InferenceCapabilityManifest(
        adapter_id=adapter.descriptor.adapter_id,
        provider=source.provider,
        product=source.product,
        runtime=runtime,
        provider_version=source.provider_version_max,
        adapter_version=source.adapter_version,
        overall_status=overall,
        events=rows,
        failure_modes=tuple(source.failure_modes),
        evidence_quality=source.execution_evidence_quality.value,
        limitations=tuple(row.impact for row in source.known_blind_spots),
        evidence_refs=tuple(source.reviewed_evidence_refs) or (source.source_reference,),
    )


def _generic_native_manifest(*, provider: str, product: str, adapter_id: str) -> CapabilityManifest:
    unknown = {
        dimension: CapabilityClaim(
            level=CapabilityLevel.UNAVAILABLE,
            verification_status=VerificationStatus.UNVERIFIED,
        )
        for dimension in CapabilityDimension
    }
    for dimension, level in (
        (CapabilityDimension.RUNTIME_IDENTITY, CapabilityLevel.OBSERVE),
        (CapabilityDimension.MODEL_ROUTE_BINDING, CapabilityLevel.OBSERVE),
        (CapabilityDimension.MODEL_REQUEST_CONTROL, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.MODEL_RESPONSE_CONTROL, CapabilityLevel.OBSERVE),
        (CapabilityDimension.FUNCTION_TOOL_CONTROL, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.PARAMETER_BINDING, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.TARGET_BINDING, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.DESTINATION_BINDING, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.POST_EXECUTION_VISIBILITY, CapabilityLevel.OBSERVE),
    ):
        unknown[dimension] = CapabilityClaim(level=level, verification_status=VerificationStatus.UNVERIFIED)
    return CapabilityManifest(
        schema_version="native-control-adapter-manifest/1.0",
        descriptor_id=adapter_id,
        provider=provider,
        product=product,
        provider_version_min="not-accepted",
        provider_version_max="not-accepted",
        exact_verified_versions=(),
        adapter_version="1.0.0",
        verification_status=VerificationStatus.UNVERIFIED,
        verified_at=None,
        source_reference="repo:apps/api/tests/test_inference_control_fabric.py",
        capabilities=unknown,
        security_properties=SecurityProperties(
            pre_execution_capable=True,
            post_execution_capable=True,
            blocking_strength=0,
            action_fidelity=0,
            identity_quality=0,
            parameter_fidelity=0,
            target_fidelity=0,
            destination_fidelity=0,
            result_fidelity=0,
            bypass_resistance=0,
            tamper_resistance=0,
            expected_latency_ms=0,
            availability_profile="caller_owned_openai_compatible_interceptor_unverified",
            required_permissions=("customer.runtime.interceptor.configure",),
            privacy_impact="bounded hashes and normalized metadata; raw prompt and response are not retained",
        ),
        required_permissions=("customer.runtime.interceptor.configure",),
        event_semantics=EventSemantics(
            pre_execution_events=("pre_inference", "pre_tool_execution", "pre_handoff"),
            post_execution_events=("post_inference", "stream_chunk", "post_tool_execution", "run_end", "failure"),
            normalized_fields=("tenant", "runtime", "model", "tool", "target", "destination"),
            synchronous_decision_mechanism="caller-owned final pre-execution interceptor; deployment unverified",
            ordering_guaranteed=False,
            runs_after_untrusted_mutators=False,
        ),
        known_blind_spots=(),
        failure_modes=("adapter_unavailable", "hook_unsupported", "hook_timeout", "malformed_event", "missing_tenant_identity"),
        supported_installation_modes=("runtime_middleware",),
        supported_degradation_modes=(DegradationMode.FAIL_CLOSED,),
        execution_evidence_quality=EvidenceQuality.PROVIDER_REPORTED,
        selection_characteristics=SelectionCharacteristics(20, 35, 30, 25, 35),
        supported_runtime_locations=(RuntimeLocation.CUSTOMER_RUNTIME, RuntimeLocation.CUSTOMER_CLOUD),
        supported_deployment_families=(DeploymentFamily.RUNTIME,),
        supported_runtimes=(product,),
        supported_control_methods=(ControlMethod.API_INTERCEPT,),
        supported_lifecycle_events=("pre_inference", "pre_tool_execution", "pre_handoff", "post_inference", "stream_chunk", "post_tool_execution", "run_end", "failure"),
        failure_semantics="fail_closed_for_mandatory_pre_event; evidence_only_after_execution",
        privacy_profile="hashes_and_bounded_metadata_only",
    )


def _generic_inference_manifest(*, provider: str, product: str, runtime: str, adapter_id: str) -> InferenceCapabilityManifest:
    partial_pre = InferenceEventCapability(
        visibility=InferenceCapabilityStatus.PARTIAL,
        pre_execution_blocking=InferenceCapabilityStatus.PARTIAL,
        parameter_binding=InferenceCapabilityStatus.PARTIAL,
        target_binding=InferenceCapabilityStatus.PARTIAL,
        destination_binding=InferenceCapabilityStatus.PARTIAL,
        subject_binding=InferenceCapabilityStatus.UNKNOWN,
        authority_visibility=InferenceCapabilityStatus.PARTIAL,
        event_ordering="caller_must_place_at_final_pre_execution_boundary",
        timeout_failure_behavior="fail_closed_when_mandatory",
        provider_runtime_version="unverified",
        verification_status=InferenceCapabilityStatus.PARTIAL,
        evidence_refs=("repo:apps/api/tests/test_inference_control_fabric.py",),
    )
    partial_post = InferenceEventCapability(
        visibility=InferenceCapabilityStatus.PARTIAL,
        post_execution_observation=InferenceCapabilityStatus.PARTIAL,
        independent_verification=InferenceCapabilityStatus.UNVERIFIED,
        event_ordering="caller_reported_after_event",
        timeout_failure_behavior="evidence_gap_only; never prevention",
        provider_runtime_version="unverified",
        verification_status=InferenceCapabilityStatus.PARTIAL,
        evidence_refs=("repo:apps/api/tests/test_inference_control_fabric.py",),
    )
    events = {
        event: partial_pre
        for event in (
            InferenceLifecycleEvent.PRE_INFERENCE,
            InferenceLifecycleEvent.PRE_RETRIEVAL,
            InferenceLifecycleEvent.PRE_TOOL_SELECTION,
            InferenceLifecycleEvent.PRE_TOOL_EXECUTION,
            InferenceLifecycleEvent.PRE_HANDOFF,
            InferenceLifecycleEvent.PRE_MEMORY_WRITE,
        )
    }
    events.update({event: partial_post for event in _POST_EVENTS})
    return InferenceCapabilityManifest(
        adapter_id=adapter_id,
        provider=provider,
        product=product,
        runtime=runtime,
        provider_version="unverified",
        adapter_version="1.0.0",
        overall_status=InferenceCapabilityStatus.UNVERIFIED,
        events=events,
        failure_modes=("adapter_unavailable", "hook_unsupported", "hook_timeout", "malformed_event", "missing_tenant_identity"),
        evidence_quality=EvidenceQuality.PROVIDER_REPORTED.value,
        limitations=("OpenAI wire compatibility does not establish provider-native lifecycle, hosted-tool, or independent execution guarantees.",),
        evidence_refs=("repo:apps/api/tests/test_inference_control_fabric.py",),
    )


class GenericOpenAICompatibleInferenceAdapter:
    provider_family = "openai_compatible"
    product_family = "generic"
    runtime_family = "openai_compatible"
    adapter_id = "inference.openai-compatible.generic"

    def __init__(self) -> None:
        self.descriptor = AdapterDescriptor(
            adapter_id=self.adapter_id,
            provider_family=self.provider_family,
            product_family=self.product_family,
            adapter_version="1.0.0",
            deployment_families_supported=(DeploymentFamily.RUNTIME,),
            enforcement_methods_supported=(ControlMethod.API_INTERCEPT,),
            event_schema_version="inference-control/openai-compatible-v1",
            minimum_hawk_version="1.0.0",
            maturity=AdapterMaturity.EXPERIMENTAL,
            description="Caller-owned OpenAI-compatible inference lifecycle interception.",
        )
        self.manifest = _generic_native_manifest(
            provider=self.provider_family,
            product=self.product_family,
            adapter_id=self.adapter_id,
        )
        self.inference_manifest = _generic_inference_manifest(
            provider=self.provider_family,
            product=self.product_family,
            runtime=self.runtime_family,
            adapter_id=self.adapter_id,
        )

    def normalize_event(
        self,
        raw_payload: Mapping[str, Any],
        context: AdapterPipelineContext,
    ) -> NativeControlEvent:
        if not isinstance(raw_payload, Mapping):
            raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED)
        raw_event = str(raw_payload.get("event_type") or "").strip().lower()
        try:
            lifecycle_event = InferenceLifecycleEvent(raw_event)
        except ValueError as exc:
            raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED, safe_diagnostic="inference_lifecycle_event_unknown") from exc
        lifecycle_stage = {
            InferenceLifecycleEvent.PRE_INFERENCE: "before_model",
            InferenceLifecycleEvent.POST_INFERENCE: "after_model",
            InferenceLifecycleEvent.STREAM_CHUNK: "after_model_stream_chunk",
            InferenceLifecycleEvent.PRE_RETRIEVAL: "before_retrieval",
            InferenceLifecycleEvent.POST_RETRIEVAL: "after_retrieval",
            InferenceLifecycleEvent.PRE_TOOL_SELECTION: "before_tool_selection",
            InferenceLifecycleEvent.PRE_TOOL_EXECUTION: "before_tool",
            InferenceLifecycleEvent.POST_TOOL_EXECUTION: "after_tool",
            InferenceLifecycleEvent.PRE_HANDOFF: "before_handoff",
            InferenceLifecycleEvent.POST_HANDOFF: "after_handoff",
            InferenceLifecycleEvent.PRE_MEMORY_WRITE: "before_memory_write",
            InferenceLifecycleEvent.POST_MEMORY_WRITE: "after_memory_write",
            InferenceLifecycleEvent.RUN_END: "run_end",
            InferenceLifecycleEvent.FAILURE: "failure",
        }[lifecycle_event]
        parameters = raw_payload.get("arguments", raw_payload.get("parameters", {}))
        prompt_material = raw_payload.get("input", raw_payload.get("messages", raw_payload.get("prompt")))
        response_material = raw_payload.get("output", raw_payload.get("chunk", raw_payload.get("response")))
        target = str(raw_payload.get("target") or raw_payload.get("resource") or "unknown")[:512]
        destination = str(raw_payload.get("destination") or raw_payload.get("base_url") or "unknown")[:512]
        tool_name = str(raw_payload.get("tool_name") or "unknown")[:256]
        action_class = (
            "function_tool"
            if lifecycle_event in {InferenceLifecycleEvent.PRE_TOOL_SELECTION, InferenceLifecycleEvent.PRE_TOOL_EXECUTION, InferenceLifecycleEvent.POST_TOOL_EXECUTION}
            else "delegation"
            if lifecycle_event in {InferenceLifecycleEvent.PRE_HANDOFF, InferenceLifecycleEvent.POST_HANDOFF}
            else "model_response"
            if lifecycle_event in _POST_EVENTS
            else "model_request"
        )
        return NativeControlEvent(
            tenant_id=context.tenant_id,
            integration_instance_id=context.integration_instance_id,
            provider=self.provider_family,
            product=self.product_family,
            raw_provider_event_type=raw_event,
            provider_event_id=context.provider_event_id,
            provider_version=context.provider_version,
            adapter_version="1.0.0",
            lifecycle_stage=lifecycle_stage,
            actor=dict(context.resolved_actor),
            session={"session_id": context.session_id, "run_id_hash": stable_hash(raw_payload.get("run_id") or context.session_id)},
            runtime={"environment": context.environment, "correlation_id": context.correlation_id, "runtime": self.runtime_family, "integration_method": ControlMethod.API_INTERCEPT.value},
            tool={"name": tool_name, "version": str(raw_payload.get("tool_version") or "unknown")[:128], "fingerprint_id": str(raw_payload.get("tool_fingerprint") or "unknown")[:256]},
            model={"name": str(raw_payload.get("model") or "unknown")[:256]},
            mcp={},
            action={
                "action_type": lifecycle_event.value,
                "action_class": action_class,
                "parameter_hash": stable_hash(parameters),
                "prompt_hash": stable_hash(prompt_material) if prompt_material is not None else "unknown",
                "response_hash": stable_hash(response_material) if response_material is not None else "unknown",
                "evidence_quality": EvidenceQuality.PROVIDER_REPORTED.value if lifecycle_event in _POST_EVENTS else EvidenceQuality.HAWK_OBSERVED.value,
            },
            target={"resource": target, "resource_hash": stable_hash(target)},
            destination={"destination": destination, "destination_hash": stable_hash(destination)},
            side_effect_class="unknown",
            persistence={"persistent_side_effect": False},
            provider_correlation={"chain_id": context.chain_id, "correlation_id": context.correlation_id},
            timing={"received_at": context.received_at},
            integrity={"transport_authenticated": context.transport_authenticated, "signature_valid": context.signature_valid},
            policy_snapshot_id=context.policy_snapshot_id,
            policy_profile=dict(context.policy_profile),
        )

    def format_decision_response(self, response: AuthorizationResponse) -> dict[str, Any]:
        if response.decision in _HALTING_DECISIONS:
            return {"continue": False, "decision": response.decision, "reason": response.reason}
        return {"continue": True, "decision": response.decision, "reason": response.reason}

    def limitations(self) -> tuple[StructuredBlindSpot, ...]:
        return ()


class VllmInferenceControlAdapter(GenericOpenAICompatibleInferenceAdapter):
    provider_family = "self_hosted_runtime"
    product_family = "vllm"
    runtime_family = "vllm"
    adapter_id = "inference.openai-compatible.vllm"


@dataclass(frozen=True, slots=True)
class RegisteredInferenceAdapter:
    manifest: InferenceCapabilityManifest
    adapter: NativeControlAdapter | None
    event_names: Mapping[InferenceLifecycleEvent, str] = field(default_factory=dict)


class InferenceControlRegistry:
    def __init__(self) -> None:
        self._records: dict[tuple[str, str, str], RegisteredInferenceAdapter] = {}

    def register(
        self,
        *,
        manifest: InferenceCapabilityManifest,
        adapter: NativeControlAdapter | None,
        event_names: Mapping[InferenceLifecycleEvent, str] | None = None,
    ) -> None:
        key = (manifest.provider, manifest.product, manifest.runtime)
        if key in self._records:
            raise ValueError("duplicate_inference_adapter_registration")
        self._records[key] = RegisteredInferenceAdapter(
            manifest=manifest,
            adapter=adapter,
            event_names=dict(event_names or {}),
        )

    def resolve(self, *, provider: str, product: str, runtime: str) -> RegisteredInferenceAdapter:
        key = (str(provider).strip().lower(), str(product).strip().lower(), str(runtime).strip().lower())
        try:
            return self._records[key]
        except KeyError as exc:
            raise LookupError("inference_adapter_not_registered") from exc

    def records(self) -> tuple[RegisteredInferenceAdapter, ...]:
        return tuple(self._records[key] for key in sorted(self._records))


def _manifest_only(
    *,
    adapter_id: str,
    provider: str,
    product: str,
    runtime: str,
    overall: InferenceCapabilityStatus,
    events: Mapping[InferenceLifecycleEvent, InferenceEventCapability] | None = None,
    limitation: str,
) -> InferenceCapabilityManifest:
    return InferenceCapabilityManifest(
        adapter_id=adapter_id,
        provider=provider,
        product=product,
        runtime=runtime,
        provider_version="unverified",
        adapter_version="unverified",
        overall_status=overall,
        events=dict(events or {}),
        failure_modes=("adapter_unavailable",),
        evidence_quality=EvidenceQuality.NONE.value,
        limitations=(limitation,),
    )


def build_default_inference_control_registry() -> InferenceControlRegistry:
    from app.services.native_control.claude_adapter import ClaudeAdapter
    from app.services.native_control.gemini_cli_adapter import GeminiCliAdapter
    from app.services.native_control.manifests import build_default_registry
    from app.services.native_control.openai_adapters import (
        OpenAIAgentsSDKControlAdapter,
        OpenAIDirectAPIControlAdapter,
    )

    registry = InferenceControlRegistry()
    for adapter, runtime, event_names in (
        (
            ClaudeAdapter(),
            "claude_code",
            {
                InferenceLifecycleEvent.PRE_INFERENCE: "UserPromptSubmit",
                InferenceLifecycleEvent.PRE_TOOL_EXECUTION: "PreToolUse",
                InferenceLifecycleEvent.POST_TOOL_EXECUTION: "PostToolUse",
                InferenceLifecycleEvent.FAILURE: "PostToolUseFailure",
                InferenceLifecycleEvent.RUN_END: "SessionEnd",
            },
        ),
        (
            GeminiCliAdapter(),
            "gemini_cli",
            {
                InferenceLifecycleEvent.PRE_INFERENCE: "BeforeModel",
                InferenceLifecycleEvent.PRE_TOOL_SELECTION: "BeforeToolSelection",
                InferenceLifecycleEvent.PRE_TOOL_EXECUTION: "BeforeTool",
                InferenceLifecycleEvent.POST_INFERENCE: "AfterModel",
                InferenceLifecycleEvent.POST_TOOL_EXECUTION: "AfterTool",
                InferenceLifecycleEvent.RUN_END: "AfterAgent",
            },
        ),
        (
            OpenAIAgentsSDKControlAdapter(),
            "openai_agents_sdk",
            {
                InferenceLifecycleEvent.PRE_TOOL_EXECUTION: "function_tool_input",
                InferenceLifecycleEvent.POST_TOOL_EXECUTION: "function_tool_output",
                InferenceLifecycleEvent.POST_INFERENCE: "llm_end",
                InferenceLifecycleEvent.RUN_END: "agent_end",
            },
        ),
        (
            OpenAIDirectAPIControlAdapter(),
            "openai_responses",
            {
                InferenceLifecycleEvent.PRE_INFERENCE: "responses_request",
                InferenceLifecycleEvent.PRE_TOOL_SELECTION: "tool_proposal",
                InferenceLifecycleEvent.STREAM_CHUNK: "responses_chunk",
                InferenceLifecycleEvent.POST_TOOL_EXECUTION: "tool_result",
            },
        ),
    ):
        registry.register(
            manifest=project_native_inference_manifest(adapter, runtime=runtime),
            adapter=adapter,
            event_names=event_names,
        )
    for adapter in (GenericOpenAICompatibleInferenceAdapter(), VllmInferenceControlAdapter()):
        registry.register(
            manifest=adapter.inference_manifest,
            adapter=adapter,
            event_names={event: event.value for event in adapter.inference_manifest.events},
        )

    microsoft = build_default_registry().get(
        "microsoft", "agent_framework", ControlMethod.AGENT_MIDDLEWARE
    )
    microsoft_status = _native_status(microsoft.verification_status)
    microsoft_event = InferenceEventCapability(
        visibility=microsoft_status,
        pre_execution_blocking=microsoft_status,
        parameter_binding=microsoft_status,
        target_binding=microsoft_status,
        post_execution_observation=microsoft_status,
        independent_verification=InferenceCapabilityStatus.UNVERIFIED,
        event_ordering="final_function_middleware_when_correctly_ordered",
        timeout_failure_behavior="fail_closed_at_function_boundary",
        provider_runtime_version=",".join(microsoft.supported_versions) or "unverified",
        verification_status=microsoft_status,
        evidence_refs=tuple(microsoft.verification_evidence),
    )
    registry.register(
        manifest=_manifest_only(
            adapter_id=microsoft.manifest_id,
            provider="microsoft",
            product="agent_framework",
            runtime="agent_framework",
            overall=microsoft_status,
            events={
                InferenceLifecycleEvent.PRE_TOOL_EXECUTION: microsoft_event,
                InferenceLifecycleEvent.POST_TOOL_EXECUTION: microsoft_event,
            },
            limitation="The .NET function middleware is registered as an existing boundary; broader Foundry lifecycle interception is not implied.",
        ),
        adapter=None,
    )
    registry.register(
        manifest=_manifest_only(
            adapter_id="aws.bedrock.model-api",
            provider="aws",
            product="bedrock_model_api",
            runtime="bedrock",
            overall=InferenceCapabilityStatus.UNVERIFIED,
            limitation="Bedrock profiles exist, but no executable inference adapter is accepted in this bounded run.",
        ),
        adapter=None,
    )
    registry.register(
        manifest=_manifest_only(
            adapter_id="huggingface.inference-endpoints.descriptor",
            provider="huggingface",
            product="inference_endpoints",
            runtime="huggingface_inference_endpoints",
            overall=InferenceCapabilityStatus.UNKNOWN,
            limitation="Provider catalog identity exists without an executable lifecycle adapter.",
        ),
        adapter=None,
    )
    registry.register(
        manifest=_manifest_only(
            adapter_id="nvidia.nim-nemo.descriptor",
            provider="nvidia",
            product="nim_nemo",
            runtime="nvidia_nim_nemo",
            overall=InferenceCapabilityStatus.UNKNOWN,
            limitation="No repository integration boundary was found for NVIDIA NIM/NeMo.",
        ),
        adapter=None,
    )
    return registry


DecisionReceiptWriter = Callable[[AuthorizationRequest, AuthorizationResponse, NativeControlEvent], str]
ExecutionPermitIssuer = Callable[[AuthorizationRequest, AuthorizationResponse, NativeControlEvent], str]
ExecutionReceiptWriter = Callable[[AuthorizationRequest, NativeControlEvent], str]


class InferenceControlFabric:
    """One lifecycle facade over existing adapters, policy, evidence, and receipts."""

    def __init__(
        self,
        *,
        registry: InferenceControlRegistry,
        evidence_sink: Callable[[dict[str, object]], None],
        policy_evaluator: Callable[[AuthorizationRequest], AuthorizationResponse] = authorize_ai_action,
        decision_receipt_writer: DecisionReceiptWriter | None = None,
        execution_permit_issuer: ExecutionPermitIssuer | None = None,
        execution_receipt_writer: ExecutionReceiptWriter | None = None,
        security_boundary: HawkCallbackSecurityBoundary | None = None,
    ) -> None:
        self.registry = registry
        self._evidence_sink = evidence_sink
        self._policy = policy_evaluator
        self._write_decision_receipt = decision_receipt_writer
        self._issue_execution_permit = execution_permit_issuer
        self._write_execution_receipt = execution_receipt_writer
        self._security = security_boundary or HawkCallbackSecurityBoundary()

    @staticmethod
    def _trusted_payload(
        context: InferenceControlContext,
        raw_payload: Mapping[str, Any],
        provider_event_name: str,
    ) -> dict[str, Any]:
        payload = dict(raw_payload)
        payload.pop("hook_event_name", None)
        payload.update(
            {
                "event_type": provider_event_name,
                "model": context.model,
                "run_id": context.run_id,
                "tool_name": str(context.tool.get("name") or "unknown"),
                "tool_version": str(context.tool.get("version") or "unknown"),
                "tool_fingerprint": context.tool_fingerprint,
                "arguments": dict(context.parameters),
                "resource": context.resource,
                "target": context.target,
                "destination": context.destination,
            }
        )
        return payload

    @staticmethod
    def _authorization_request(
        context: InferenceControlContext,
        event: NativeControlEvent,
    ) -> AuthorizationRequest:
        material = event.to_authorization_request().model_dump()
        material["actor"] = {
            **dict(material["actor"]),
            **dict(context.actor),
            "executing_principal": dict(context.executing_principal),
            "represented_subject": dict(context.represented_subject),
        }
        material["authority"] = dict(context.authority)
        material["purpose"] = dict(context.business_purpose)
        material["runtime"] = {
            **dict(material["runtime"]),
            "provider": context.provider,
            "product": context.product,
            "runtime": context.runtime,
            "model": context.model,
            "agent": dict(context.agent),
            "run_id": context.run_id,
            "parent_context": dict(context.parent_context),
            "delegation_context": dict(context.delegation_context),
            "policy_epoch": context.policy_epoch,
            "evidence_refs": list(context.evidence_refs),
        }
        material["tool"] = {
            **dict(material["tool"]),
            **dict(context.tool),
            "fingerprint_id": context.tool_fingerprint,
        }
        material["target"] = {
            **dict(material["target"]),
            "resource": context.resource,
            "target": context.target,
            "destination": context.destination,
        }
        return AuthorizationRequest.model_validate(material)

    def _emit_evidence(
        self,
        *,
        context: InferenceControlContext,
        event: NativeControlEvent,
        outcome: str,
        decision: str | None,
        quality: str,
    ) -> str:
        evidence_ref = f"inference-control:{stable_hash((context.pipeline.tenant_id, context.pipeline.integration_instance_id, context.pipeline.provider_event_id, context.lifecycle_event.value))}"
        self._evidence_sink(
            {
                "evidence_ref": evidence_ref,
                "tenant_id": context.pipeline.tenant_id,
                "integration_instance_id": context.pipeline.integration_instance_id,
                "provider_event_id_hash": stable_hash(context.pipeline.provider_event_id),
                "lifecycle_event": context.lifecycle_event.value,
                "normalized_event_hash": stable_hash(event),
                "outcome": outcome,
                "decision": decision,
                "evidence_quality": quality,
                "prevented": decision == "block" and context.lifecycle_event in _PRE_EVENTS,
                "raw_payload_retained": False,
                "decision_receipt_id": context.decision_receipt_id,
                "execution_receipt_id": context.execution_receipt_id,
            }
        )
        return evidence_ref

    def intercept(
        self,
        *,
        context: InferenceControlContext,
        raw_payload: Mapping[str, Any],
        invoke: Callable[[], Any] | None = None,
    ) -> InferenceControlResult:
        record = self.registry.resolve(
            provider=context.provider,
            product=context.product,
            runtime=context.runtime,
        )
        capability = record.manifest.for_event(context.lifecycle_event)
        if capability.visibility is InferenceCapabilityStatus.UNSUPPORTED:
            return InferenceControlResult(
                lifecycle_event=context.lifecycle_event,
                action_id=context.pipeline.provider_event_id,
                outcome="unsupported_lifecycle_event",
                decision=None,
                prevented=False,
                provider_invoked=False,
                tool_invoked=False,
                emitted_already=context.lifecycle_event is InferenceLifecycleEvent.STREAM_CHUNK,
                evidence_quality=EvidenceQuality.NONE.value,
                independently_verified=False,
                evidence_ref="",
            )
        if record.adapter is None:
            return InferenceControlResult(
                lifecycle_event=context.lifecycle_event,
                action_id=context.pipeline.provider_event_id,
                outcome="adapter_unavailable",
                decision=None,
                prevented=False,
                provider_invoked=False,
                tool_invoked=False,
                emitted_already=context.lifecycle_event in _POST_EVENTS,
                evidence_quality=EvidenceQuality.NONE.value,
                independently_verified=False,
                evidence_ref="",
            )
        provider_event_name = record.event_names.get(context.lifecycle_event)
        if provider_event_name is None:
            return InferenceControlResult(
                lifecycle_event=context.lifecycle_event,
                action_id=context.pipeline.provider_event_id,
                outcome="hook_unsupported",
                decision=None,
                prevented=False,
                provider_invoked=False,
                tool_invoked=False,
                emitted_already=context.lifecycle_event in _POST_EVENTS,
                evidence_quality=EvidenceQuality.NONE.value,
                independently_verified=False,
                evidence_ref="",
            )
        payload = self._trusted_payload(context, raw_payload, provider_event_name)
        if not self._security.validate(context=context.pipeline, raw_payload=payload):
            raise AdapterContractError("inference_event_replay")
        event = record.adapter.normalize_event(payload, context.pipeline)
        if event.tenant_id != context.pipeline.tenant_id:
            raise AdapterContractError("adapter_tenant_override_rejected")
        if event.integration_instance_id != context.pipeline.integration_instance_id:
            raise AdapterContractError("adapter_integration_override_rejected")
        if (event.provider, event.product) != (context.provider, context.product):
            raise AdapterContractError("adapter_provider_product_override_rejected")
        request = self._authorization_request(context, event)

        if context.lifecycle_event in _POST_EVENTS:
            execution_receipt_id = context.execution_receipt_id
            if self._write_execution_receipt is not None:
                execution_receipt_id = self._write_execution_receipt(request, event)
            quality = record.manifest.evidence_quality
            evidence_ref = self._emit_evidence(
                context=context,
                event=event,
                outcome="observed_after_execution",
                decision=None,
                quality=quality,
            )
            return InferenceControlResult(
                lifecycle_event=context.lifecycle_event,
                action_id=request.action_id,
                outcome="observed_after_execution",
                decision=None,
                prevented=False,
                provider_invoked=True,
                tool_invoked=context.lifecycle_event in {InferenceLifecycleEvent.POST_TOOL_EXECUTION, InferenceLifecycleEvent.FAILURE},
                emitted_already=context.lifecycle_event is InferenceLifecycleEvent.STREAM_CHUNK,
                evidence_quality=quality,
                independently_verified=capability.independent_verification is InferenceCapabilityStatus.VERIFIED,
                evidence_ref=evidence_ref,
                decision_receipt_id=context.decision_receipt_id,
                execution_receipt_id=execution_receipt_id,
            )

        if capability.pre_execution_blocking in {
            InferenceCapabilityStatus.UNSUPPORTED,
            InferenceCapabilityStatus.UNKNOWN,
        }:
            evidence_ref = self._emit_evidence(
                context=context,
                event=event,
                outcome="control_requirement_unsatisfied",
                decision="block",
                quality=EvidenceQuality.HAWK_OBSERVED.value,
            )
            return InferenceControlResult(
                lifecycle_event=context.lifecycle_event,
                action_id=request.action_id,
                outcome="control_requirement_unsatisfied",
                decision="block",
                prevented=True,
                provider_invoked=False,
                tool_invoked=False,
                emitted_already=False,
                evidence_quality=EvidenceQuality.HAWK_OBSERVED.value,
                independently_verified=False,
                evidence_ref=evidence_ref,
            )
        response = self._policy(request)
        decision_receipt_id = context.decision_receipt_id
        if self._write_decision_receipt is not None:
            decision_receipt_id = self._write_decision_receipt(request, response, event)
        halted = response.decision in _HALTING_DECISIONS
        execution_permit_id = None
        if not halted and self._issue_execution_permit is not None:
            execution_permit_id = self._issue_execution_permit(request, response, event)
        provider_invoked = False
        tool_invoked = False
        if not halted and invoke is not None:
            invoke()
            provider_invoked = context.lifecycle_event is InferenceLifecycleEvent.PRE_INFERENCE
            tool_invoked = context.lifecycle_event is InferenceLifecycleEvent.PRE_TOOL_EXECUTION
        outcome = "blocked_before_execution" if response.decision == "block" else "approval_or_transformation_required" if halted else "allowed_before_execution"
        evidence_ref = self._emit_evidence(
            context=context,
            event=event,
            outcome=outcome,
            decision=response.decision,
            quality=EvidenceQuality.HAWK_OBSERVED.value,
        )
        return InferenceControlResult(
            lifecycle_event=context.lifecycle_event,
            action_id=request.action_id,
            outcome=outcome,
            decision=response.decision,
            prevented=response.decision == "block",
            provider_invoked=provider_invoked,
            tool_invoked=tool_invoked,
            emitted_already=False,
            evidence_quality=EvidenceQuality.HAWK_OBSERVED.value,
            independently_verified=False,
            evidence_ref=evidence_ref,
            decision_receipt_id=decision_receipt_id,
            execution_permit_id=execution_permit_id,
        )


__all__ = [
    "GenericOpenAICompatibleInferenceAdapter",
    "InferenceCapabilityManifest",
    "InferenceCapabilityStatus",
    "InferenceControlAdapter",
    "InferenceControlContext",
    "InferenceControlFabric",
    "InferenceControlRegistry",
    "InferenceControlResult",
    "InferenceEventCapability",
    "InferenceLifecycleEvent",
    "VllmInferenceControlAdapter",
    "build_default_inference_control_registry",
    "project_native_inference_manifest",
]
