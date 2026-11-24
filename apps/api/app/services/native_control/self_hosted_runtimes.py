"""Conservative contracts for customer-controlled, self-hosted model runtimes.

These profiles deliberately describe *serving/runtime* boundaries, not model
weights, protocol formats, provider-native hooks, or tool execution.  For
example, an Ollama or vLLM endpoint can serve several model families; an
OpenAI-compatible request shape does not make it an OpenAI security adapter.

Every profile is reviewed as a boundary hypothesis only.  It remains
``UNVERIFIED`` and ``NOT_TESTED`` until an exact customer deployment proves
its route, runtime/version, allow, block, protected non-execution, and bypass
behaviour.  These definitions do not install middleware, call a runtime, or
select an enforcement point.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.native_control.adapter_contract import (
    CapabilityManifest,
    DeploymentAcceptanceResult,
    DeploymentFamily,
    EvidenceQuality,
    EventSemantics,
    SelectionCharacteristics,
    StructuredBlindSpot,
)
from app.services.native_control.contracts import (
    ActionClass,
    CapabilityClaim,
    CapabilityDimension,
    CapabilityLevel,
    ControlMethod,
    DegradationMode,
    ProviderRuntimeContext,
    RuntimeLocation,
    SecurityProperties,
    VerificationStatus,
)


_REVIEWED_AT = "2026-08-20T00:00:00+00:00"
_CONTRACT_EVIDENCE = (
    "repo:docs/superpowers/specs/2026-08-20-phase4-multi-provider-control-fabric-design.md",
    "repo:docs/native-controls/self-hosted-runtimes.md",
)
_NOT_TESTED = DeploymentAcceptanceResult.not_tested()


def _unavailable_claims() -> dict[CapabilityDimension, CapabilityClaim]:
    return {
        dimension: CapabilityClaim(
            level=CapabilityLevel.UNAVAILABLE,
            verification_status=VerificationStatus.UNVERIFIED,
        )
        for dimension in CapabilityDimension
    }


def _claims(
    *items: tuple[CapabilityDimension, CapabilityLevel],
) -> dict[CapabilityDimension, CapabilityClaim]:
    """Describe a potential customer boundary without promoting it.

    A non-``UNAVAILABLE`` level is intentionally still ``UNVERIFIED``.  It
    states only what an installed, customer-owned interceptor might expose;
    enforcement eligibility remains blocked by the canonical contract and
    immutable deployment-acceptance checks.
    """

    claims = _unavailable_claims()
    for dimension, level in items:
        claims[dimension] = CapabilityClaim(
            level=level,
            verification_status=VerificationStatus.UNVERIFIED,
            evidence_refs=_CONTRACT_EVIDENCE,
        )
    return claims


def _blind_spot(
    *,
    identifier: str,
    dimension: CapabilityDimension,
    scope: str,
    condition: str,
    impact: str,
    mitigation: str,
) -> StructuredBlindSpot:
    return StructuredBlindSpot(
        id=identifier,
        control_dimension=dimension,
        scope=scope,
        condition=condition,
        impact=impact,
        detection_method=(
            "exact customer deployment acceptance, runtime identity/version "
            "evidence, and route/bypass validation"
        ),
        mitigation=mitigation,
        evidence=_CONTRACT_EVIDENCE,
    )


def _contract(
    *,
    descriptor_id: str,
    provider: str,
    product: str,
    runtimes: tuple[str, ...],
    action_classes: tuple[ActionClass, ...] = (
        ActionClass.MODEL_REQUEST,
        ActionClass.MODEL_RESPONSE,
    ),
    runtime_locations: tuple[RuntimeLocation, ...] = (
        RuntimeLocation.LOCAL_ENDPOINT,
        RuntimeLocation.CUSTOMER_RUNTIME,
        RuntimeLocation.CUSTOMER_CLOUD,
    ),
    method: ControlMethod = ControlMethod.API_INTERCEPT,
    deployment_family: DeploymentFamily = DeploymentFamily.RUNTIME,
    lifecycle_event: str = "before_customer_runtime_model_request",
    capability_items: tuple[
        tuple[CapabilityDimension, CapabilityLevel], ...
    ] = (
        (CapabilityDimension.RUNTIME_IDENTITY, CapabilityLevel.OBSERVE),
        (CapabilityDimension.MODEL_ROUTE_BINDING, CapabilityLevel.OBSERVE),
        (CapabilityDimension.MODEL_REQUEST_CONTROL, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.MODEL_RESPONSE_CONTROL, CapabilityLevel.OBSERVE),
        (CapabilityDimension.DIRECT_API_CONTROL, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.POST_EXECUTION_VISIBILITY, CapabilityLevel.OBSERVE),
        (CapabilityDimension.BYPASS_DETECTION, CapabilityLevel.OBSERVE),
    ),
    source_reference: str,
    required_permissions: tuple[str, ...],
) -> CapabilityManifest:
    """Create one reviewed-but-unaccepted runtime control contract.

    No runtime version has been accepted.  The opaque sentinel prevents a
    real model/server version from being accidentally treated as compatible;
    ``exact_verified_versions`` stays empty.
    """

    return CapabilityManifest(
        schema_version="native-control-adapter-manifest/1.0",
        descriptor_id=descriptor_id,
        provider=provider,
        product=product,
        provider_version_min="not-accepted",
        provider_version_max="not-accepted",
        exact_verified_versions=(),
        adapter_version="1.0.0",
        verification_status=VerificationStatus.UNVERIFIED,
        verified_at=None,
        source_reference=source_reference,
        capabilities=_claims(*capability_items),
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
            availability_profile="self_hosted_runtime_boundary_unverified_not_tested",
            required_permissions=required_permissions,
            privacy_impact=(
                "No raw prompt, response, credential, model content, provider account, "
                "or customer-runtime payload is claimed by Hawk before real acceptance."
            ),
        ),
        required_permissions=required_permissions,
        event_semantics=EventSemantics(
            pre_execution_events=(lifecycle_event,),
            post_execution_events=("after_customer_runtime_model_response",),
            normalized_fields=(
                "runtime_identity",
                "runtime_version",
                "model_provider",
                "model_route",
                "route_identity",
            ),
            synchronous_decision_mechanism="customer-owned runtime/API interceptor required; unverified",
            ordering_guaranteed=False,
            runs_before_untrusted_mutators=False,
            runs_after_untrusted_mutators=False,
        ),
        known_blind_spots=(
            _blind_spot(
                identifier=f"{product}-runtime-route-not-accepted",
                dimension=CapabilityDimension.MODEL_REQUEST_CONTROL,
                scope=f"customer-controlled {product} serving route",
                condition=(
                    "No exact runtime/version/route allow, block, protected non-execution, "
                    "latency, or failure-mode acceptance has been recorded"
                ),
                impact=(
                    "Hawk cannot select this runtime profile for Enforce or claim an "
                    "inline model-request boundary."
                ),
                mitigation=(
                    "Bind the final customer runtime/API interceptor and accept the exact "
                    "runtime, version, deployment, route, model action, allow, block, "
                    "protected non-execution, and timeout behaviour."
                ),
            ),
            _blind_spot(
                identifier=f"{product}-protocol-compatibility-is-not-hook",
                dimension=CapabilityDimension.TOOL_CONTROL,
                scope=f"{product} model and protocol compatibility",
                condition=(
                    "A serving endpoint accepts an OpenAI-compatible or Anthropic-compatible "
                    "request format, or a model emits a tool-call representation"
                ),
                impact=(
                    "Protocol compatibility and model output do not establish a Hawk native "
                    "hook, tool/MCP authorization, parameter/target/destination binding, "
                    "provider account identity, or hosted execution control."
                ),
                mitigation=(
                    "Install and accept a separate customer tool-loop, MCP, middleware, "
                    "endpoint, gateway, or target-service control point."
                ),
            ),
            _blind_spot(
                identifier=f"{product}-direct-and-alternate-route-bypass",
                dimension=CapabilityDimension.BYPASS_DETECTION,
                scope=f"{product} serving topology",
                condition=(
                    "The client uses a direct endpoint, alternate endpoint, sidecar bypass, "
                    "new runtime, remote executor, or mutable route after Hawk observation"
                ),
                impact=(
                    "The unaccepted profile cannot claim route completeness, bypass "
                    "resistance, remote execution control, or protected coverage."
                ),
                mitigation=(
                    "Require fresh route evidence, detect route/runtime/model drift, and "
                    "accept every approved direct and alternate path independently."
                ),
            ),
            _blind_spot(
                identifier=f"{product}-model-runtime-identity-separate",
                dimension=CapabilityDimension.MODEL_ROUTE_BINDING,
                scope=f"{product} model family and serving runtime",
                condition=(
                    "Model identity is inferred from a runtime name, endpoint URL, or protocol "
                    "alone"
                ),
                impact=(
                    "Hawk cannot safely identify the model provider/model, policy route, or "
                    "control surface from runtime identity alone."
                ),
                mitigation=(
                    "Record model provider/model and serving runtime as distinct authenticated "
                    "runtime facts; treat missing or conflicting facts as Unknown."
                ),
            ),
        ),
        failure_modes=(
            "customer runtime interceptor omitted",
            "direct runtime endpoint bypass",
            "alternate endpoint or sidecar bypass",
            "runtime, model-route, or tool-loop drift",
            "remote execution outside the accepted customer runtime",
            "runtime version unsupported or unknown",
            "real customer acceptance missing or stale",
        ),
        supported_installation_modes=("customer_runtime_configuration",),
        supported_degradation_modes=(
            DegradationMode.REQUIRE_EXCEPTION,
            DegradationMode.MONITOR_ONLY,
        ),
        execution_evidence_quality=EvidenceQuality.NONE,
        selection_characteristics=SelectionCharacteristics(
            latency_cost=0,
            operational_complexity=80,
            required_privilege=80,
            privacy_impact=60,
            deployment_friction=80,
        ),
        supported_action_classes=action_classes,
        supported_runtime_locations=runtime_locations,
        supported_deployment_families=(deployment_family,),
        supported_runtimes=runtimes,
        supported_control_methods=(method,),
        supported_lifecycle_events=(lifecycle_event,),
        supports_action_mutation=False,
        supports_approval_pause=False,
        retry_semantics="unverified",
        failure_semantics="unverified; never select for enforce",
        privacy_profile=(
            "Hawk stores no raw self-hosted runtime request, response, credential, model "
            "content, or customer payload from this profile by default."
        ),
        reviewed_by="hawk-provider-contract-review",
        reviewed_at=_REVIEWED_AT,
        reviewed_evidence_refs=_CONTRACT_EVIDENCE,
        deployment_acceptance=_NOT_TESTED,
    )


LLAMA_RUNTIME = _contract(
    descriptor_id="meta.llama.customer_runtime",
    provider="meta",
    product="llama_self_hosted",
    runtimes=("customer_llama_runtime",),
    source_reference=(
        "Meta Llama model identity and customer runtime identity are separate; Llama "
        "weights are not a provider-native control"
    ),
    required_permissions=("customer.runtime.interceptor.configure",),
)

LLAMA_STACK_RUNTIME = _contract(
    descriptor_id="self_hosted_runtime.llama_stack",
    provider="self_hosted_runtime",
    product="llama_stack",
    runtimes=("llama_stack",),
    source_reference=(
        "Llama Stack is a serving/runtime identity that may host different model and "
        "infrastructure identities; exact customer acceptance is required"
    ),
    required_permissions=("customer.runtime.interceptor.configure",),
)

OLLAMA_RUNTIME = _contract(
    descriptor_id="self_hosted_runtime.ollama",
    provider="self_hosted_runtime",
    product="ollama",
    runtimes=("ollama",),
    source_reference=(
        "Ollama is a customer serving-runtime identity, not a model-provider or native "
        "security-hook identity"
    ),
    required_permissions=("customer.runtime.interceptor.configure",),
)

VLLM_RUNTIME = _contract(
    descriptor_id="self_hosted_runtime.vllm",
    provider="self_hosted_runtime",
    product="vllm",
    runtimes=("vllm",),
    source_reference=(
        "vLLM is a customer serving-runtime identity, not a model-provider or native "
        "security-hook identity"
    ),
    required_permissions=("customer.runtime.interceptor.configure",),
)

TGI_RUNTIME = _contract(
    descriptor_id="self_hosted_runtime.text_generation_inference",
    provider="self_hosted_runtime",
    product="text_generation_inference",
    runtimes=("text_generation_inference",),
    source_reference=(
        "Text Generation Inference is a customer serving-runtime identity, not a "
        "model-provider or native security-hook identity"
    ),
    required_permissions=("customer.runtime.interceptor.configure",),
)

QWEN_RUNTIME = _contract(
    descriptor_id="alibaba_qwen.customer_runtime",
    provider="alibaba_qwen",
    product="qwen_self_hosted",
    runtimes=("customer_qwen_runtime",),
    source_reference=(
        "Qwen model identity and customer self-hosted runtime are separate; serving "
        "runtime and tool loop require independent acceptance"
    ),
    required_permissions=("customer.runtime.interceptor.configure",),
)

QWEN_PROVIDER_API = _contract(
    descriptor_id="alibaba_qwen.provider_api",
    provider="alibaba_qwen",
    product="qwen_provider_api",
    runtimes=("qwen_provider_api",),
    runtime_locations=(RuntimeLocation.PROVIDER_HOSTED,),
    deployment_family=DeploymentFamily.SAAS_API,
    source_reference=(
        "Qwen provider API is separate from Qwen-Agent and customer self-hosted runtime"
    ),
    required_permissions=("provider.api.route.intercept",),
)

QWEN_AGENT = _contract(
    descriptor_id="alibaba_qwen.agent_product",
    provider="alibaba_qwen",
    product="qwen_agent",
    runtimes=("qwen_agent",),
    method=ControlMethod.TOOL_LOOP_INTERCEPT,
    lifecycle_event="before_customer_qwen_tool_dispatch",
    action_classes=(ActionClass.FUNCTION_TOOL,),
    capability_items=(
        (CapabilityDimension.RUNTIME_IDENTITY, CapabilityLevel.OBSERVE),
        (CapabilityDimension.FUNCTION_TOOL_CONTROL, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.POST_EXECUTION_VISIBILITY, CapabilityLevel.OBSERVE),
        (CapabilityDimension.BYPASS_DETECTION, CapabilityLevel.OBSERVE),
    ),
    source_reference=(
        "Qwen tool calls are model output until the customer Qwen-Agent tool loop dispatches "
        "them; that tool loop requires separate exact acceptance"
    ),
    required_permissions=("customer.tool_loop.interceptor.configure",),
)

DEEPSEEK_RUNTIME = _contract(
    descriptor_id="deepseek.customer_runtime",
    provider="deepseek",
    product="deepseek_self_hosted",
    runtimes=("customer_deepseek_runtime",),
    source_reference=(
        "DeepSeek model identity and customer self-hosted runtime are separate; protocol "
        "compatibility inherits no OpenAI or Anthropic security semantics"
    ),
    required_permissions=("customer.runtime.interceptor.configure",),
)

DEEPSEEK_PROVIDER_API = _contract(
    descriptor_id="deepseek.provider_api",
    provider="deepseek",
    product="deepseek_provider_api",
    runtimes=("deepseek_provider_api",),
    runtime_locations=(RuntimeLocation.PROVIDER_HOSTED,),
    deployment_family=DeploymentFamily.SAAS_API,
    source_reference=(
        "DeepSeek provider API, compatibility routes, and customer self-hosted runtime are "
        "separate boundaries"
    ),
    required_permissions=("provider.api.route.intercept",),
)

DEEPSEEK_CUSTOMER_TOOL_LOOP = _contract(
    descriptor_id="deepseek.customer_tool_loop",
    provider="deepseek",
    product="deepseek_customer_tool_loop",
    runtimes=(
        "deepseek_customer_tool_loop",
        "deepseek_agent_framework",
    ),
    method=ControlMethod.TOOL_LOOP_INTERCEPT,
    lifecycle_event="before_customer_deepseek_tool_dispatch",
    action_classes=(ActionClass.FUNCTION_TOOL,),
    capability_items=(
        (CapabilityDimension.RUNTIME_IDENTITY, CapabilityLevel.OBSERVE),
        (CapabilityDimension.FUNCTION_TOOL_CONTROL, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.POST_EXECUTION_VISIBILITY, CapabilityLevel.OBSERVE),
        (CapabilityDimension.BYPASS_DETECTION, CapabilityLevel.OBSERVE),
    ),
    source_reference=(
        "A customer-owned DeepSeek tool loop or agent framework is distinct from "
        "the DeepSeek provider API and self-hosted model runtime; tool-call output "
        "has no security authority before the customer dispatcher is accepted"
    ),
    required_permissions=("customer.tool_loop.interceptor.configure",),
)

KIMI_RUNTIME = _contract(
    descriptor_id="moonshot_kimi.customer_runtime",
    provider="moonshot_kimi",
    product="kimi_customer_runtime",
    runtimes=("customer_kimi_runtime",),
    source_reference=(
        "Kimi model identity and customer runtime are separate; no native hook is claimed "
        "without documentation and real acceptance"
    ),
    required_permissions=("customer.runtime.interceptor.configure",),
)

KIMI_PROVIDER_API = _contract(
    descriptor_id="moonshot_kimi.provider_api",
    provider="moonshot_kimi",
    product="kimi_provider_api",
    runtimes=("kimi_provider_api",),
    runtime_locations=(RuntimeLocation.PROVIDER_HOSTED,),
    deployment_family=DeploymentFamily.SAAS_API,
    source_reference=(
        "Kimi provider API is separate from its coding product and customer runtime"
    ),
    required_permissions=("provider.api.route.intercept",),
)

KIMI_CODING_AGENT = _contract(
    descriptor_id="moonshot_kimi.coding_agent",
    provider="moonshot_kimi",
    product="kimi_coding_agent",
    runtimes=("kimi_coding_agent",),
    runtime_locations=(RuntimeLocation.LOCAL_ENDPOINT, RuntimeLocation.REMOTE_AGENT),
    method=ControlMethod.TOOL_LOOP_INTERCEPT,
    lifecycle_event="before_customer_kimi_tool_dispatch",
    action_classes=(ActionClass.FUNCTION_TOOL,),
    capability_items=(
        (CapabilityDimension.RUNTIME_IDENTITY, CapabilityLevel.OBSERVE),
        (CapabilityDimension.FUNCTION_TOOL_CONTROL, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.POST_EXECUTION_VISIBILITY, CapabilityLevel.OBSERVE),
        (CapabilityDimension.BYPASS_DETECTION, CapabilityLevel.OBSERVE),
    ),
    source_reference=(
        "Kimi coding-agent product and its local/remote execution paths require independent "
        "exact acceptance; no provider-native hook is claimed"
    ),
    required_permissions=("customer.tool_loop.interceptor.configure",),
)

OPENAI_COMPATIBLE_UNKNOWN = _contract(
    descriptor_id="unknown_provider.openai_compatible_runtime",
    provider="unknown_provider",
    product="openai_compatible_unknown",
    runtimes=("openai_compatible_unknown",),
    source_reference=(
        "Unknown OpenAI-compatible protocol route; compatibility alone is not a provider "
        "security contract"
    ),
    required_permissions=("customer.runtime.interceptor.configure",),
)

ANTHROPIC_COMPATIBLE_UNKNOWN = _contract(
    descriptor_id="unknown_provider.anthropic_compatible_runtime",
    provider="unknown_provider",
    product="anthropic_compatible_unknown",
    runtimes=("anthropic_compatible_unknown",),
    source_reference=(
        "Unknown Anthropic-compatible protocol route; compatibility alone is not a provider "
        "security contract"
    ),
    required_permissions=("customer.runtime.interceptor.configure",),
)

CUSTOM_MODEL_RUNTIME = _contract(
    descriptor_id="unknown_provider.custom_model_runtime",
    provider="unknown_provider",
    product="custom_model_runtime",
    runtimes=("custom_model_runtime",),
    source_reference=(
        "Customer custom-model runtime; no protocol, model, provider, account, or tool "
        "semantics may be inferred before real acceptance"
    ),
    required_permissions=("customer.runtime.interceptor.configure",),
)


@dataclass(frozen=True, slots=True)
class SelfHostedRuntimeControlProfile:
    """Derived product-matrix projection of one canonical runtime contract."""

    contract: CapabilityManifest
    method: ControlMethod = ControlMethod.API_INTERCEPT
    expected_model_provider: str | None = None

    def enforcement_ineligibility_reasons(
        self,
        runtime_context: ProviderRuntimeContext,
    ) -> tuple[str, ...]:
        """Reject unresolved or drifted model/route facts through canonical acceptance.

        The manifest remains the only contract and its
        :class:`DeploymentAcceptanceResult` remains the only deployment proof.
        This wrapper adds the model-family expectation that cannot be inferred
        from a serving runtime such as Ollama or vLLM. It does not authorize an
        action or introduce a parallel route-binding record.
        """

        version_state = self.contract.provider_version_state(
            runtime_context.provider_version
        )
        reasons = list(
            self.contract.enforcement_ineligibility_reasons(
                runtime_context,
                version_state,
            )
        )

        model_provider = runtime_context.model_provider.strip().lower()
        model = runtime_context.model.strip().lower()
        if model_provider in {
            "",
            "unknown",
            "unknown_provider",
            "self_hosted_runtime",
        }:
            reasons.append("model_provider_unresolved")
        elif (
            self.expected_model_provider is not None
            and model_provider != self.expected_model_provider
        ):
            reasons.append("model_provider_runtime_contract_mismatch")
        if model in {"", "unknown"}:
            reasons.append("model_identity_unresolved")

        acceptance = self.contract.deployment_acceptance
        accepted_scope = (
            acceptance.model_provider,
            acceptance.model,
            acceptance.route_identity,
            acceptance.deployment_identity,
        )
        if (
            not acceptance.is_real_acceptance
            or any(value.strip().lower() in {"", "unknown"} for value in accepted_scope)
        ):
            reasons.append("exact_model_route_acceptance_missing")

        return tuple(dict.fromkeys(reasons))

    def provider_profile(self):
        """Project the contract to the legacy matrix without strengthening it."""

        from app.services.native_control.manifests import ProviderCapabilityManifest

        return ProviderCapabilityManifest(
            manifest_id=f"{self.contract.provider}:{self.contract.product}:{self.method.value}",
            manifest_version="provider-capability-manifest/1.0",
            provider=self.contract.provider,
            product=self.contract.product,
            method=self.method,
            supported_versions=(),
            capability_matrix=dict(self.contract.capabilities),
            security_properties=self.contract.security_properties,
            verification_status=self.contract.verification_status,
            verified_at=self.contract.verified_at,
            adapter_version=self.contract.adapter_version,
            verification_evidence=(
                "No real customer runtime/version/route allow, block, or protected non-execution acceptance exists.",
                *_CONTRACT_EVIDENCE,
            ),
            official_documentation_reference=self.contract.source_reference,
            required_permissions=self.contract.required_permissions,
            deployment_requirements=(
                "Identify the model provider/model and serving runtime separately from authenticated customer runtime facts.",
                "Bind Hawk at the final real customer-owned model route and complete exact runtime/version/route allow, block, protected non-execution, latency, and failure-mode acceptance before Enforce.",
                "Test direct endpoint, alternate endpoint, sidecar, remote-execution, and unsupported-version bypass paths independently.",
            ),
            known_blind_spots=tuple(
                blind_spot.impact for blind_spot in self.contract.known_blind_spots
            ),
            failure_modes=self.contract.failure_modes,
            privacy_implications=(self.contract.privacy_profile,),
            fallback_methods=(
                ControlMethod.GATEWAY_INLINE,
                ControlMethod.ENDPOINT_RUNTIME,
                ControlMethod.OBSERVE_ONLY,
            ),
        )


SELF_HOSTED_RUNTIME_PROFILES = (
    SelfHostedRuntimeControlProfile(LLAMA_RUNTIME, expected_model_provider="meta"),
    SelfHostedRuntimeControlProfile(LLAMA_STACK_RUNTIME),
    SelfHostedRuntimeControlProfile(OLLAMA_RUNTIME),
    SelfHostedRuntimeControlProfile(VLLM_RUNTIME),
    SelfHostedRuntimeControlProfile(TGI_RUNTIME),
    SelfHostedRuntimeControlProfile(QWEN_RUNTIME, expected_model_provider="alibaba_qwen"),
    SelfHostedRuntimeControlProfile(QWEN_PROVIDER_API, expected_model_provider="alibaba_qwen"),
    SelfHostedRuntimeControlProfile(
        QWEN_AGENT,
        method=ControlMethod.TOOL_LOOP_INTERCEPT,
        expected_model_provider="alibaba_qwen",
    ),
    SelfHostedRuntimeControlProfile(DEEPSEEK_RUNTIME, expected_model_provider="deepseek"),
    SelfHostedRuntimeControlProfile(
        DEEPSEEK_PROVIDER_API,
        expected_model_provider="deepseek",
    ),
    SelfHostedRuntimeControlProfile(
        DEEPSEEK_CUSTOMER_TOOL_LOOP,
        method=ControlMethod.TOOL_LOOP_INTERCEPT,
        expected_model_provider="deepseek",
    ),
    SelfHostedRuntimeControlProfile(KIMI_RUNTIME, expected_model_provider="moonshot_kimi"),
    SelfHostedRuntimeControlProfile(
        KIMI_PROVIDER_API,
        expected_model_provider="moonshot_kimi",
    ),
    SelfHostedRuntimeControlProfile(
        KIMI_CODING_AGENT,
        method=ControlMethod.TOOL_LOOP_INTERCEPT,
        expected_model_provider="moonshot_kimi",
    ),
    SelfHostedRuntimeControlProfile(
        OPENAI_COMPATIBLE_UNKNOWN,
        expected_model_provider=None,
    ),
    SelfHostedRuntimeControlProfile(
        ANTHROPIC_COMPATIBLE_UNKNOWN,
        expected_model_provider=None,
    ),
    SelfHostedRuntimeControlProfile(
        CUSTOM_MODEL_RUNTIME,
        expected_model_provider=None,
    ),
)


def self_hosted_runtime_control_profiles() -> tuple[SelfHostedRuntimeControlProfile, ...]:
    """Return reviewed profile definitions; no discovery or network probing occurs."""

    return SELF_HOSTED_RUNTIME_PROFILES


def self_hosted_runtime_provider_profiles():
    """Return non-strengthening legacy matrix projections."""

    return tuple(profile.provider_profile() for profile in SELF_HOSTED_RUNTIME_PROFILES)
