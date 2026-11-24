from __future__ import annotations

from dataclasses import replace

from app.services.native_control.adapter_contract import DeploymentAcceptanceResult
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
from app.services.native_control.providers import canonical_provider
from app.services.native_control.self_hosted_runtimes import (
    ANTHROPIC_COMPATIBLE_UNKNOWN,
    CUSTOM_MODEL_RUNTIME,
    DEEPSEEK_CUSTOMER_TOOL_LOOP,
    DEEPSEEK_PROVIDER_API,
    DEEPSEEK_RUNTIME,
    KIMI_CODING_AGENT,
    KIMI_PROVIDER_API,
    KIMI_RUNTIME,
    LLAMA_STACK_RUNTIME,
    LLAMA_RUNTIME,
    OLLAMA_RUNTIME,
    OPENAI_COMPATIBLE_UNKNOWN,
    QWEN_AGENT,
    QWEN_PROVIDER_API,
    QWEN_RUNTIME,
    SELF_HOSTED_RUNTIME_PROFILES,
    TGI_RUNTIME,
    VLLM_RUNTIME,
    self_hosted_runtime_control_profiles,
)


def _context_for(profile, *, runtime: str | None = None, **overrides) -> ProviderRuntimeContext:
    contract = profile.contract
    values = {
        "provider": contract.provider,
        "product": contract.product,
        "runtime": runtime or contract.supported_runtimes[0],
        "action_class": contract.supported_action_classes[0],
        "runtime_location": contract.supported_runtime_locations[0],
        # No deployed runtime version is accepted by the static contract.
        "provider_version": "unaccepted-runtime-version",
        "adapter_version": contract.adapter_version,
        "control_method": profile.method,
        "environment": "test",
        "application": "customer-runtime",
        "runtime_version": "unaccepted-runtime-version",
        "model_provider": contract.provider,
        "model": "customer-selected-model",
        "route_identity": "customer-route:reviewed-test",
        "deployment_identity": "customer-deployment:reviewed-test",
        "deployment_reference": "customer-deployment-ref:reviewed-test",
        "lifecycle_stage": contract.supported_lifecycle_events[0],
        "route_evidence_ref": "repo:tests/self-hosted-reviewed-route.json",
        "route_evidence_fresh": True,
    }
    values.update(overrides)
    return ProviderRuntimeContext(**values)


def test_self_hosted_profiles_are_reviewed_contracts_but_have_no_runtime_acceptance() -> None:
    profiles = self_hosted_runtime_control_profiles()

    assert profiles == SELF_HOSTED_RUNTIME_PROFILES
    assert tuple(profile.contract for profile in profiles) == (
        LLAMA_RUNTIME,
        LLAMA_STACK_RUNTIME,
        OLLAMA_RUNTIME,
        VLLM_RUNTIME,
        TGI_RUNTIME,
        QWEN_RUNTIME,
        QWEN_PROVIDER_API,
        QWEN_AGENT,
        DEEPSEEK_RUNTIME,
        DEEPSEEK_PROVIDER_API,
        DEEPSEEK_CUSTOMER_TOOL_LOOP,
        KIMI_RUNTIME,
        KIMI_PROVIDER_API,
        KIMI_CODING_AGENT,
        OPENAI_COMPATIBLE_UNKNOWN,
        ANTHROPIC_COMPATIBLE_UNKNOWN,
        CUSTOM_MODEL_RUNTIME,
    )

    for profile in profiles:
        contract = profile.contract
        assert contract.is_reviewed_contract is True
        assert contract.verification_status is VerificationStatus.UNVERIFIED
        assert contract.deployment_acceptance.state is DeploymentAcceptanceState.NOT_TESTED
        assert contract.deployment_acceptance.is_real_acceptance is False
        reasons = contract.enforcement_ineligibility_reasons(
            _context_for(profile),
            ProviderVersionState.VERIFIED_COMPATIBLE_RANGE,
        )
        assert "contract_not_verified" in reasons
        assert "deployment_acceptance_not_real" in reasons


def test_model_family_and_serving_runtime_contracts_are_independent() -> None:
    assert LLAMA_RUNTIME.provider == "meta"
    assert LLAMA_RUNTIME.product == "llama_self_hosted"
    assert LLAMA_RUNTIME.supported_runtimes == ("customer_llama_runtime",)

    independent = {
        (profile.contract.provider, profile.contract.product, profile.contract.supported_runtimes)
        for profile in SELF_HOSTED_RUNTIME_PROFILES
        if profile.contract in (
            LLAMA_STACK_RUNTIME,
            OLLAMA_RUNTIME,
            VLLM_RUNTIME,
            TGI_RUNTIME,
        )
    }
    assert independent == {
        ("self_hosted_runtime", "llama_stack", ("llama_stack",)),
        ("self_hosted_runtime", "ollama", ("ollama",)),
        ("self_hosted_runtime", "vllm", ("vllm",)),
        (
            "self_hosted_runtime",
            "text_generation_inference",
            ("text_generation_inference",),
        ),
    }

    assert LLAMA_RUNTIME.supported_runtime_locations == (
        RuntimeLocation.LOCAL_ENDPOINT,
        RuntimeLocation.CUSTOMER_RUNTIME,
        RuntimeLocation.CUSTOMER_CLOUD,
    )
    assert LLAMA_RUNTIME.supported_control_methods == (ControlMethod.API_INTERCEPT,)

    # The serving stack cannot make model weight identity a native hook.
    for dimension in (
        CapabilityDimension.TOOL_CONTROL,
        CapabilityDimension.MCP_CONTROL,
        CapabilityDimension.PARAMETER_BINDING,
        CapabilityDimension.TARGET_BINDING,
        CapabilityDimension.DESTINATION_BINDING,
        CapabilityDimension.PROVIDER_PERMISSION_CONTEXT,
        CapabilityDimension.HOSTED_MCP_CONTROL,
    ):
        claim = LLAMA_RUNTIME.capabilities[dimension]
        assert claim.level is CapabilityLevel.UNAVAILABLE
        assert claim.verification_status is VerificationStatus.UNVERIFIED

    ollama_profile = next(
        profile
        for profile in SELF_HOSTED_RUNTIME_PROFILES
        if profile.contract is OLLAMA_RUNTIME
    )
    assert "model_provider_unresolved" in ollama_profile.enforcement_ineligibility_reasons(
        _context_for(ollama_profile, model_provider="self_hosted_runtime")
    )
    assert "model_provider_unresolved" not in ollama_profile.enforcement_ineligibility_reasons(
        _context_for(ollama_profile, model_provider="meta")
    )


def test_provider_api_agent_product_and_customer_runtime_contracts_are_separate() -> None:
    assert QWEN_RUNTIME.product == "qwen_self_hosted"
    assert QWEN_RUNTIME.supported_runtimes == ("customer_qwen_runtime",)
    assert QWEN_PROVIDER_API.product == "qwen_provider_api"
    assert QWEN_PROVIDER_API.supported_runtime_locations == (RuntimeLocation.PROVIDER_HOSTED,)
    assert QWEN_AGENT.product == "qwen_agent"
    assert QWEN_AGENT.supported_control_methods == (ControlMethod.TOOL_LOOP_INTERCEPT,)

    assert DEEPSEEK_RUNTIME.product == "deepseek_self_hosted"
    assert DEEPSEEK_RUNTIME.supported_runtimes == ("customer_deepseek_runtime",)
    assert DEEPSEEK_PROVIDER_API.product == "deepseek_provider_api"
    assert DEEPSEEK_PROVIDER_API.supported_runtime_locations == (RuntimeLocation.PROVIDER_HOSTED,)
    assert DEEPSEEK_CUSTOMER_TOOL_LOOP.product == "deepseek_customer_tool_loop"
    assert DEEPSEEK_CUSTOMER_TOOL_LOOP.supported_runtimes == (
        "deepseek_customer_tool_loop",
        "deepseek_agent_framework",
    )
    assert DEEPSEEK_CUSTOMER_TOOL_LOOP.supported_control_methods == (
        ControlMethod.TOOL_LOOP_INTERCEPT,
    )

    assert KIMI_RUNTIME.product == "kimi_customer_runtime"
    assert KIMI_RUNTIME.supported_runtimes == ("customer_kimi_runtime",)
    assert KIMI_PROVIDER_API.product == "kimi_provider_api"
    assert KIMI_CODING_AGENT.product == "kimi_coding_agent"
    assert KIMI_CODING_AGENT.supported_control_methods == (ControlMethod.TOOL_LOOP_INTERCEPT,)

    for provider_api in (QWEN_PROVIDER_API, DEEPSEEK_PROVIDER_API, KIMI_PROVIDER_API):
        assert provider_api.supported_runtimes[0].endswith("_provider_api")
        assert "self_hosted" not in provider_api.supported_runtimes[0]

    for dimension in CapabilityDimension:
        claim = DEEPSEEK_CUSTOMER_TOOL_LOOP.capabilities[dimension]
        assert claim.verification_status is VerificationStatus.UNVERIFIED
        if dimension is CapabilityDimension.FUNCTION_TOOL_CONTROL:
            assert claim.level is CapabilityLevel.INLINE_BOUND
        elif dimension in {
            CapabilityDimension.RUNTIME_IDENTITY,
            CapabilityDimension.POST_EXECUTION_VISIBILITY,
            CapabilityDimension.BYPASS_DETECTION,
        }:
            assert claim.level is CapabilityLevel.OBSERVE
        else:
            assert claim.level is CapabilityLevel.UNAVAILABLE

    assert DEEPSEEK_CUSTOMER_TOOL_LOOP.deployment_acceptance.state is (
        DeploymentAcceptanceState.NOT_TESTED
    )


def test_compatible_protocols_do_not_inherit_openai_or_anthropic_semantics() -> None:
    for contract in (QWEN_RUNTIME, DEEPSEEK_RUNTIME, KIMI_RUNTIME, OPENAI_COMPATIBLE_UNKNOWN):
        assert contract.verification_status is VerificationStatus.UNVERIFIED
        assert contract.deployment_acceptance.state is DeploymentAcceptanceState.NOT_TESTED
        assert contract.capabilities[CapabilityDimension.MODEL_REQUEST_CONTROL].verification_status is VerificationStatus.UNVERIFIED
        for dimension in (
            CapabilityDimension.TOOL_CONTROL,
            CapabilityDimension.MCP_CONTROL,
            CapabilityDimension.PARAMETER_BINDING,
            CapabilityDimension.TARGET_BINDING,
            CapabilityDimension.DESTINATION_BINDING,
        ):
            assert contract.capabilities[dimension].level is CapabilityLevel.UNAVAILABLE
            assert contract.capabilities[dimension].verification_status is VerificationStatus.UNVERIFIED
        assert "native hook" in " ".join(
            blind_spot.impact for blind_spot in contract.known_blind_spots
        ).lower()

    assert OPENAI_COMPATIBLE_UNKNOWN.provider == "unknown_provider"
    assert OPENAI_COMPATIBLE_UNKNOWN.product == "openai_compatible_unknown"
    assert OPENAI_COMPATIBLE_UNKNOWN.provider != "openai"
    assert canonical_provider("openai-compatible-unknown") == "unknown_provider"
    assert canonical_provider("anthropic compatible unknown") == "unknown_provider"
    assert canonical_provider("custom model runtime") == "unknown_provider"
    assert canonical_provider("openai-compatible") == "unknown_provider"
    assert canonical_provider("anthropic compatible") == "unknown_provider"

    unknown_profile = next(
        profile
        for profile in SELF_HOSTED_RUNTIME_PROFILES
        if profile.contract is OPENAI_COMPATIBLE_UNKNOWN
    )
    assert "model_provider_unresolved" in unknown_profile.enforcement_ineligibility_reasons(
        _context_for(unknown_profile, model_provider="unknown_provider")
    )
    assert unknown_profile.expected_model_provider is None
    authenticated_unknown = unknown_profile.enforcement_ineligibility_reasons(
        _context_for(
            unknown_profile,
            model_provider="customer-attested-model-provider",
        )
    )
    assert "model_provider_unresolved" not in authenticated_unknown
    assert "model_provider_runtime_contract_mismatch" not in authenticated_unknown

    anthropic_compatible_profile = next(
        profile
        for profile in SELF_HOSTED_RUNTIME_PROFILES
        if profile.contract is ANTHROPIC_COMPATIBLE_UNKNOWN
    )
    assert anthropic_compatible_profile.expected_model_provider is None
    assert "model_provider_unresolved" in (
        anthropic_compatible_profile.enforcement_ineligibility_reasons(
            _context_for(
                anthropic_compatible_profile,
                model_provider="unknown_provider",
            )
        )
    )

    # A compatible wire protocol remains an unknown-provider profile even if
    # an exact future acceptance names an OpenAI or Anthropic model provider.
    # It never inherits either provider's native/security capability rows.
    for profile, named_model_provider in (
        (unknown_profile, "openai"),
        (anthropic_compatible_profile, "anthropic"),
    ):
        reasons = profile.enforcement_ineligibility_reasons(
            _context_for(profile, model_provider=named_model_provider)
        )
        assert "contract_not_verified" in reasons
        assert "deployment_acceptance_not_real" in reasons
        assert profile.contract.provider == "unknown_provider"
        assert profile.contract.capabilities[
            CapabilityDimension.PROVIDER_PERMISSION_CONTEXT
        ].level is CapabilityLevel.UNAVAILABLE


def test_runtime_and_route_drift_never_promote_a_self_hosted_contract() -> None:
    profile = next(item for item in SELF_HOSTED_RUNTIME_PROFILES if item.contract is QWEN_RUNTIME)
    contract = profile.contract

    alternate_runtime = _context_for(profile, runtime="alternate_unreviewed_runtime")
    alternate_action = _context_for(profile, action_class=ActionClass.FUNCTION_TOOL)
    remote_execution = _context_for(profile, runtime_location=RuntimeLocation.REMOTE_AGENT)
    unsupported_runtime_version = _context_for(profile, provider_version="2026.08.21")
    changed_model_provider = _context_for(profile, model_provider="meta")
    direct_route = _context_for(profile, route_identity="direct-runtime-endpoint")
    alternate_route = _context_for(profile, route_identity="alternate-runtime-endpoint")

    assert "runtime_not_reviewed" in contract.enforcement_ineligibility_reasons(
        alternate_runtime,
        ProviderVersionState.VERIFIED_COMPATIBLE_RANGE,
    )
    assert "action_class_not_reviewed" in contract.enforcement_ineligibility_reasons(
        alternate_action,
        ProviderVersionState.VERIFIED_COMPATIBLE_RANGE,
    )
    assert "runtime_location_not_reviewed" in contract.enforcement_ineligibility_reasons(
        remote_execution,
        ProviderVersionState.VERIFIED_COMPATIBLE_RANGE,
    )
    assert contract.provider_version_state(unsupported_runtime_version.provider_version) is ProviderVersionState.UNSUPPORTED

    assert "model_provider_runtime_contract_mismatch" in profile.enforcement_ineligibility_reasons(
        changed_model_provider
    )
    assert "exact_model_route_acceptance_missing" in profile.enforcement_ineligibility_reasons(
        direct_route
    )
    assert "exact_model_route_acceptance_missing" in profile.enforcement_ineligibility_reasons(
        alternate_route
    )

    blind_spots = " ".join(blind_spot.impact for blind_spot in contract.known_blind_spots).lower()
    failures = " ".join(contract.failure_modes).lower()
    assert "direct" in blind_spots or "direct" in failures
    assert "alternate" in blind_spots or "alternate" in failures


def test_real_runtime_acceptance_is_exactly_bound_to_model_route_and_deployment() -> None:
    base = replace(
        QWEN_RUNTIME,
        provider_version_min="1.0.0",
        provider_version_max="1.0.0",
        exact_verified_versions=("1.0.0",),
        verification_status=VerificationStatus.VERIFIED,
    )
    acceptance = DeploymentAcceptanceResult(
        state=DeploymentAcceptanceState.REAL_CLOUD_RUNTIME_ACCEPTED,
        environment="production",
        provider=base.provider,
        product=base.product,
        runtime=base.supported_runtimes[0],
        action_classes=base.supported_action_classes,
        control_method=ControlMethod.API_INTERCEPT,
        provider_version="1.0.0",
        adapter_version=base.adapter_version,
        contract_fingerprint=base.contract_fingerprint,
        acceptance_run_ref="acceptance:self-hosted-runtime:test",
        evidence_refs=("repo:tests/self-hosted-exact-acceptance.json",),
        lifecycle_events=base.supported_lifecycle_events,
        allow_verified=True,
        block_verified=True,
        protected_callback_not_executed=True,
        deployment_reference="deployment-ref:one",
        model_provider="alibaba_qwen",
        model="qwen2.5:test",
        route_identity="route:one",
        deployment_identity="deployment:one",
    )
    accepted = replace(base, deployment_acceptance=acceptance)
    profile = type(SELF_HOSTED_RUNTIME_PROFILES[0])(
        accepted,
        expected_model_provider="alibaba_qwen",
    )
    context = _context_for(
        profile,
        provider_version="1.0.0",
        runtime_version="1.0.0",
        runtime_location=RuntimeLocation.CUSTOMER_RUNTIME,
        environment="production",
        model_provider="alibaba_qwen",
        model="qwen2.5:test",
        route_identity="route:one",
        deployment_identity="deployment:one",
        deployment_reference="deployment-ref:one",
    )

    assert profile.enforcement_ineligibility_reasons(context) == ()
    assert "deployment_acceptance_model_provider_mismatch" in (
        profile.enforcement_ineligibility_reasons(
            replace(context, model_provider="deepseek")
        )
    )
    assert "deployment_acceptance_model_mismatch" in (
        profile.enforcement_ineligibility_reasons(
            replace(context, model="qwen3:test")
        )
    )
    assert "deployment_acceptance_route_identity_mismatch" in (
        profile.enforcement_ineligibility_reasons(
            replace(context, route_identity="route:direct-bypass")
        )
    )
    assert "deployment_acceptance_deployment_identity_mismatch" in (
        profile.enforcement_ineligibility_reasons(
            replace(context, deployment_identity="deployment:replacement")
        )
    )


def test_custom_runtime_accepts_only_exact_authenticated_opaque_model_scope() -> None:
    static_profile = next(
        profile
        for profile in SELF_HOSTED_RUNTIME_PROFILES
        if profile.contract is CUSTOM_MODEL_RUNTIME
    )
    assert static_profile.expected_model_provider is None
    assert "model_provider_unresolved" in static_profile.enforcement_ineligibility_reasons(
        _context_for(static_profile, model_provider="unknown_provider")
    )
    opaque_reasons = static_profile.enforcement_ineligibility_reasons(
        _context_for(
            static_profile,
            model_provider="customer-attested-provider:opaque-7",
        )
    )
    assert "model_provider_unresolved" not in opaque_reasons
    assert "model_provider_runtime_contract_mismatch" not in opaque_reasons

    base = replace(
        CUSTOM_MODEL_RUNTIME,
        provider_version_min="customer-runtime-1",
        provider_version_max="customer-runtime-1",
        exact_verified_versions=("customer-runtime-1",),
        verification_status=VerificationStatus.VERIFIED,
    )
    acceptance = DeploymentAcceptanceResult(
        state=DeploymentAcceptanceState.REAL_CLOUD_RUNTIME_ACCEPTED,
        environment="production",
        provider=base.provider,
        product=base.product,
        runtime=base.supported_runtimes[0],
        action_classes=base.supported_action_classes,
        control_method=ControlMethod.API_INTERCEPT,
        provider_version="customer-runtime-1",
        adapter_version=base.adapter_version,
        contract_fingerprint=base.contract_fingerprint,
        acceptance_run_ref="acceptance:custom-runtime:test",
        evidence_refs=("repo:tests/custom-runtime-exact-acceptance.json",),
        lifecycle_events=base.supported_lifecycle_events,
        allow_verified=True,
        block_verified=True,
        protected_callback_not_executed=True,
        deployment_reference="deployment-ref:custom-one",
        model_provider="customer-attested-provider:opaque-7",
        model="customer-model:opaque-11",
        route_identity="route:custom-one",
        deployment_identity="deployment:custom-one",
    )
    accepted_profile = type(static_profile)(
        replace(base, deployment_acceptance=acceptance),
        expected_model_provider=None,
    )
    context = _context_for(
        accepted_profile,
        provider_version="customer-runtime-1",
        runtime_version="customer-runtime-1",
        runtime_location=RuntimeLocation.CUSTOMER_RUNTIME,
        environment="production",
        model_provider="customer-attested-provider:opaque-7",
        model="customer-model:opaque-11",
        route_identity="route:custom-one",
        deployment_identity="deployment:custom-one",
        deployment_reference="deployment-ref:custom-one",
    )

    assert accepted_profile.enforcement_ineligibility_reasons(context) == ()
    for field_name, replacement_value, expected_reason in (
        (
            "model_provider",
            "customer-attested-provider:opaque-8",
            "deployment_acceptance_model_provider_mismatch",
        ),
        (
            "model",
            "customer-model:opaque-12",
            "deployment_acceptance_model_mismatch",
        ),
        (
            "route_identity",
            "route:custom-bypass",
            "deployment_acceptance_route_identity_mismatch",
        ),
        (
            "deployment_identity",
            "deployment:custom-replacement",
            "deployment_acceptance_deployment_identity_mismatch",
        ),
    ):
        assert expected_reason in accepted_profile.enforcement_ineligibility_reasons(
            replace(context, **{field_name: replacement_value})
        )

    for dimension in (
        CapabilityDimension.PROVIDER_PERMISSION_CONTEXT,
        CapabilityDimension.TOOL_CONTROL,
        CapabilityDimension.MCP_CONTROL,
        CapabilityDimension.PARAMETER_BINDING,
        CapabilityDimension.TARGET_BINDING,
        CapabilityDimension.DESTINATION_BINDING,
    ):
        assert accepted_profile.contract.capabilities[dimension].level is (
            CapabilityLevel.UNAVAILABLE
        )


def test_matrix_projects_self_hosted_profiles_without_overriding_verified_generic_gateway() -> None:
    registry = build_default_registry()

    for profile in SELF_HOSTED_RUNTIME_PROFILES:
        contract = profile.contract
        projection = registry.get(contract.provider, contract.product, profile.method)
        assert projection.verification_status is VerificationStatus.UNVERIFIED
        assert projection.supported_versions == ()
        assert "real customer" in " ".join(projection.deployment_requirements).lower()

    # Existing evidence applies only to a Hawk-routed generic model route, not
    # to the newly named self-hosted runtime profiles.
    gateway = registry.get("alibaba_qwen", "direct_api", ControlMethod.GATEWAY_INLINE)
    assert gateway.verification_status is VerificationStatus.VERIFIED
    assert gateway.capability_matrix[CapabilityDimension.MODEL_REQUEST_CONTROL].verification_status is VerificationStatus.VERIFIED
    assert QWEN_RUNTIME.capabilities[CapabilityDimension.MODEL_REQUEST_CONTROL].verification_status is VerificationStatus.UNVERIFIED

    for label, product in (
        ("llama-stack", "llama_stack"),
        ("ollama", "ollama"),
        ("vllm", "vllm"),
        ("tgi", "text_generation_inference"),
    ):
        assert canonical_provider(label) == "self_hosted_runtime"
        runtime = registry.get(
            "self_hosted_runtime",
            product,
            ControlMethod.API_INTERCEPT,
        )
        assert runtime.verification_status is VerificationStatus.UNVERIFIED

    for label, product in (
        ("openai-compatible", "openai_compatible_unknown"),
        ("anthropic-compatible", "anthropic_compatible_unknown"),
    ):
        assert canonical_provider(label) == "unknown_provider"
        compatible = registry.get(
            "unknown_provider",
            product,
            ControlMethod.API_INTERCEPT,
        )
        assert compatible.verification_status is VerificationStatus.UNVERIFIED
