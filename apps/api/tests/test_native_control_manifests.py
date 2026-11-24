from __future__ import annotations

from app.services.native_control.contracts import (
    CapabilityDimension,
    CapabilityLevel,
    ControlMethod,
    VerificationStatus,
)
from app.services.native_control.manifests import (
    MATRIX_ONLY_PROVIDER_FAMILIES,
    REQUIRED_PROVIDER_FAMILIES,
    build_default_registry,
)


def test_registry_contains_every_required_provider_family() -> None:
    registry = build_default_registry()

    assert set(registry.providers()) == {
        *REQUIRED_PROVIDER_FAMILIES,
        *MATRIX_ONLY_PROVIDER_FAMILIES,
    }


def test_every_manifest_has_security_decision_fields_and_no_marketing_boolean() -> None:
    registry = build_default_registry()

    for manifest in registry.manifests:
        payload = manifest.as_dict()
        assert set(payload) == {
            "manifest_id",
            "manifest_version",
            "provider",
            "product",
            "method",
            "supported_versions",
            "capability_matrix",
            "security_properties",
            "verification_status",
            "verified_at",
            "adapter_version",
            "verification_evidence",
            "official_documentation_reference",
            "required_permissions",
            "deployment_requirements",
            "known_blind_spots",
            "failure_modes",
            "privacy_implications",
            "fallback_methods",
        }
        assert "supported" not in payload
        assert payload["capability_matrix"]
        assert set(payload["security_properties"]) == {
            "pre_execution_capable",
            "post_execution_capable",
            "blocking_strength",
            "action_fidelity",
            "identity_quality",
            "parameter_fidelity",
            "target_fidelity",
            "destination_fidelity",
            "result_fidelity",
            "bypass_resistance",
            "tamper_resistance",
            "expected_latency_ms",
            "availability_profile",
            "required_permissions",
            "privacy_impact",
        }
        assert payload["verification_evidence"]
        assert payload["known_blind_spots"]
        assert payload["failure_modes"]
        assert payload["fallback_methods"]


def test_unverified_native_hooks_are_unavailable_not_protected() -> None:
    registry = build_default_registry()

    native_manifests = [row for row in registry.manifests if row.method is ControlMethod.NATIVE_HOOK]
    assert native_manifests
    for manifest in native_manifests:
        if manifest.verification_status in {
            VerificationStatus.UNVERIFIED,
            VerificationStatus.BROKEN,
            VerificationStatus.REMOVED,
        }:
            assert all(
                claim.level in {CapabilityLevel.UNAVAILABLE, CapabilityLevel.UNKNOWN}
                for claim in manifest.capability_matrix.values()
            )
            assert all(
                claim.verification_status is not VerificationStatus.VERIFIED
                for claim in manifest.capability_matrix.values()
            )


def test_claude_hook_manifest_promotes_only_exact_real_binary_capabilities() -> None:
    registry = build_default_registry()
    claude = registry.get("anthropic", "claude_code", ControlMethod.NATIVE_HOOK)
    assert claude.verification_status is VerificationStatus.VERIFIED
    assert claude.supported_versions == ("2.1.183",)
    assert claude.adapter_version == "1.2.0"
    assert claude.capability_matrix[CapabilityDimension.TOOL_CONTROL].verification_status is VerificationStatus.VERIFIED
    assert claude.capability_matrix[CapabilityDimension.PARAMETER_BINDING].level is CapabilityLevel.INLINE_BOUND
    assert claude.capability_matrix[CapabilityDimension.TARGET_BINDING].level is CapabilityLevel.OBSERVE
    assert claude.capability_matrix[CapabilityDimension.POST_EXECUTION_VERIFICATION].level is CapabilityLevel.UNAVAILABLE
    assert claude.capability_matrix[CapabilityDimension.APPROVAL_CONTROL].verification_status is VerificationStatus.EXPERIMENTAL
    assert claude.capability_matrix[CapabilityDimension.PROMPT_CONTROL].verification_status is VerificationStatus.VERIFIED
    assert claude.capability_matrix[CapabilityDimension.MCP_CONTROL].verification_status is VerificationStatus.VERIFIED
    assert claude.capability_matrix[CapabilityDimension.DELEGATION_CONTROL].verification_status is VerificationStatus.VERIFIED
    assert claude.capability_matrix[CapabilityDimension.PROVIDER_PERMISSION_CONTEXT].verification_status is VerificationStatus.VERIFIED
    assert claude.capability_matrix[CapabilityDimension.HAWK_APPROVAL_BINDING].verification_status is VerificationStatus.VERIFIED
    assert claude.capability_matrix[CapabilityDimension.APPROVAL_CORRELATION].verification_status is VerificationStatus.VERIFIED
    assert claude.capability_matrix[CapabilityDimension.TOOL_FAILURE_VISIBILITY].verification_status is VerificationStatus.VERIFIED
    assert claude.capability_matrix[CapabilityDimension.CONFIG_CHANGE_VISIBILITY].verification_status is VerificationStatus.EXPERIMENTAL
    assert any("untested version" in row.lower() for row in claude.known_blind_spots)

    gemini = registry.get("google", "gemini_cli", ControlMethod.NATIVE_HOOK)
    assert gemini.verification_status is VerificationStatus.EXPERIMENTAL
    assert gemini.supported_versions == ("0.54.4", "0.55.1")
    assert gemini.security_properties.pre_execution_capable is True
    assert gemini.capability_matrix[CapabilityDimension.TOOL_CONTROL].level is CapabilityLevel.INLINE_BOUND
    assert gemini.capability_matrix[CapabilityDimension.TOOL_CONTROL].verification_status is VerificationStatus.VERIFIED
    assert gemini.capability_matrix[CapabilityDimension.MCP_CONTROL].verification_status is VerificationStatus.VERIFIED
    assert gemini.capability_matrix[CapabilityDimension.FILE_READ_CONTROL].level is CapabilityLevel.OBSERVE
    assert gemini.capability_matrix[CapabilityDimension.FILE_READ_CONTROL].verification_status is VerificationStatus.VERIFIED
    assert gemini.capability_matrix[CapabilityDimension.FILE_WRITE_CONTROL].verification_status is VerificationStatus.VERIFIED
    assert gemini.capability_matrix[CapabilityDimension.PARAMETER_BINDING].verification_status is VerificationStatus.EXPERIMENTAL
    assert gemini.capability_matrix[CapabilityDimension.RESPONSE_CONTROL].verification_status is VerificationStatus.EXPERIMENTAL


def test_generic_gateway_claims_only_the_verified_model_request_response_route() -> None:
    registry = build_default_registry()
    unsupported = (
        CapabilityDimension.TOOL_CONTROL,
        CapabilityDimension.MCP_CONTROL,
        CapabilityDimension.PARAMETER_BINDING,
        CapabilityDimension.TARGET_BINDING,
        CapabilityDimension.DESTINATION_BINDING,
    )

    for provider in (
        "anthropic",
        "google",
        "cursor",
        "microsoft",
        "azure",
        "aws",
        "meta",
        "moonshot_kimi",
        "alibaba_qwen",
        "deepseek",
    ):
        manifest = registry.get(provider, "direct_api", ControlMethod.GATEWAY_INLINE)
        for dimension in (
            CapabilityDimension.MODEL_REQUEST_CONTROL,
            CapabilityDimension.MODEL_RESPONSE_CONTROL,
        ):
            claim = manifest.capability_matrix[dimension]
            assert claim.level is CapabilityLevel.INLINE
            assert claim.verification_status is VerificationStatus.VERIFIED
        for dimension in unsupported:
            claim = manifest.capability_matrix[dimension]
            assert claim.level is CapabilityLevel.UNAVAILABLE
            assert claim.verification_status is VerificationStatus.UNVERIFIED


def test_long_tail_runtime_claims_only_explicit_client_binding_observation() -> None:
    registry = build_default_registry()
    unsupported = (
        CapabilityDimension.TOOL_CONTROL,
        CapabilityDimension.MCP_CONTROL,
        CapabilityDimension.COMMAND_CONTROL,
        CapabilityDimension.FILE_READ_CONTROL,
        CapabilityDimension.FILE_WRITE_CONTROL,
        CapabilityDimension.NETWORK_CONTROL,
        CapabilityDimension.PARAMETER_BINDING,
        CapabilityDimension.TARGET_BINDING,
        CapabilityDimension.DESTINATION_BINDING,
        CapabilityDimension.CONFIG_INTEGRITY,
    )

    for provider in ("meta", "alibaba_qwen", "deepseek", "moonshot_kimi"):
        manifest = registry.get(provider, "self_hosted", ControlMethod.ENDPOINT_RUNTIME)
        for dimension in (
            CapabilityDimension.DISCOVERY,
            CapabilityDimension.IDENTITY,
            CapabilityDimension.POST_EXECUTION_VISIBILITY,
        ):
            claim = manifest.capability_matrix[dimension]
            assert claim.level is CapabilityLevel.OBSERVE
            assert claim.verification_status is VerificationStatus.VERIFIED
        for dimension in unsupported:
            claim = manifest.capability_matrix[dimension]
            assert claim.level is CapabilityLevel.UNAVAILABLE
            assert claim.verification_status is VerificationStatus.UNVERIFIED
        assert manifest.security_properties.pre_execution_capable is False
        assert manifest.security_properties.post_execution_capable is True


def test_bedrock_guardrails_do_not_claim_exact_action_binding() -> None:
    registry = build_default_registry()
    guardrails = registry.get("aws", "bedrock_guardrails", ControlMethod.SAAS_CONTROL_API)

    assert guardrails.capability_matrix[CapabilityDimension.PROMPT_CONTROL].level is CapabilityLevel.EXTERNAL
    assert guardrails.capability_matrix[CapabilityDimension.RESPONSE_CONTROL].level is CapabilityLevel.EXTERNAL
    assert guardrails.capability_matrix[CapabilityDimension.PARAMETER_BINDING].level is CapabilityLevel.UNAVAILABLE
    assert guardrails.capability_matrix[CapabilityDimension.TARGET_BINDING].level is CapabilityLevel.UNAVAILABLE


def test_microsoft_agent_framework_promotes_only_the_local_function_gate() -> None:
    registry = build_default_registry()
    middleware = registry.get(
        "microsoft",
        "agent_framework",
        ControlMethod.AGENT_MIDDLEWARE,
    )

    assert middleware.verification_status is VerificationStatus.EXPERIMENTAL
    assert middleware.supported_versions == ("1.15.0",)
    assert middleware.adapter_version == "1.0.0"
    for dimension in (
        CapabilityDimension.FUNCTION_TOOL_CONTROL,
        CapabilityDimension.FUNCTION_TOOL_PARAMETER_BINDING,
        CapabilityDimension.FUNCTION_TOOL_TARGET_BINDING,
    ):
        claim = middleware.capability_matrix[dimension]
        assert claim.level is CapabilityLevel.INLINE_BOUND
        assert claim.verification_status is VerificationStatus.VERIFIED
        assert "repo:docs/validation/bank-foundry-first-proof-path.md" in claim.evidence_refs

    for dimension in (
        CapabilityDimension.MODEL_REQUEST_CONTROL,
        CapabilityDimension.MODEL_RESPONSE_CONTROL,
        CapabilityDimension.MCP_CONTROL,
        CapabilityDimension.LOCAL_MCP_CONTROL,
        CapabilityDimension.DIRECT_API_CONTROL,
        CapabilityDimension.POST_EXECUTION_VERIFICATION,
    ):
        claim = middleware.capability_matrix[dimension]
        assert claim.verification_status is VerificationStatus.EXPERIMENTAL
        assert claim.evidence_refs

    assert (
        middleware.capability_matrix[CapabilityDimension.MODEL_REQUEST_CONTROL].level
        is CapabilityLevel.INLINE_BOUND
    )
    assert (
        middleware.capability_matrix[CapabilityDimension.MODEL_RESPONSE_CONTROL].level
        is CapabilityLevel.INLINE_BOUND
    )
    assert (
        middleware.capability_matrix[CapabilityDimension.MCP_CONTROL].level
        is CapabilityLevel.INLINE_BOUND
    )
    assert (
        middleware.capability_matrix[CapabilityDimension.DIRECT_API_CONTROL].level
        is CapabilityLevel.INLINE_BOUND
    )
    assert (
        middleware.capability_matrix[
            CapabilityDimension.POST_EXECUTION_VERIFICATION
        ].level
        is CapabilityLevel.OBSERVE
    )

    hosted = middleware.capability_matrix[CapabilityDimension.HOSTED_MCP_CONTROL]
    assert hosted.level is CapabilityLevel.UNAVAILABLE
    assert hosted.verification_status is VerificationStatus.UNVERIFIED

    blind_spots = " ".join(middleware.known_blind_spots).lower()
    assert "local function" in blind_spots
    assert "foundry model" in blind_spots
    assert "mcp" in blind_spots
    assert "apim" in blind_spots
    assert "hosted" in blind_spots


def test_self_hosted_model_families_use_runtime_as_control_point() -> None:
    registry = build_default_registry()

    for provider in ("meta", "alibaba_qwen", "deepseek", "moonshot_kimi"):
        manifest = registry.get(provider, "self_hosted", ControlMethod.ENDPOINT_RUNTIME)
        assert manifest.method is ControlMethod.ENDPOINT_RUNTIME
        assert manifest.capability_matrix[CapabilityDimension.TOOL_CONTROL].level is CapabilityLevel.UNAVAILABLE
        assert manifest.capability_matrix[CapabilityDimension.DISCOVERY].level is CapabilityLevel.OBSERVE
        assert manifest.capability_matrix[CapabilityDimension.POST_EXECUTION_VISIBILITY].level is CapabilityLevel.OBSERVE
        assert "native provider hook" not in " ".join(manifest.verification_evidence).lower()


def test_matrix_version_is_stable_and_changes_with_manifest_content() -> None:
    first = build_default_registry()
    second = build_default_registry()

    assert first.matrix_version == second.matrix_version
    assert first.matrix_version.startswith("control-capability-matrix/1.0+")
