from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

from app.services.native_control.contracts import (
    CapabilityClaim,
    CapabilityDimension,
    CapabilityLevel,
    ControlMethod,
    SecurityProperties,
    VerificationStatus,
)
from app.services.native_control.claude_acceptance_registry import (
    load_claude_acceptance_registry,
)


REQUIRED_PROVIDER_FAMILIES = (
    "anthropic",
    "openai",
    "google",
    "cursor",
    "microsoft",
    "azure",
    "aws",
    "meta",
    "moonshot_kimi",
    "alibaba_qwen",
    "deepseek",
)

# These identities are matrix-only compatibility classifications.  They are
# not provider families with a generic native hook or gateway claim: an
# unknown protocol-compatible server must never inherit OpenAI/Anthropic
# capabilities just because it uses a familiar wire format.
MATRIX_ONLY_PROVIDER_FAMILIES = (
    "unknown_provider",
    "self_hosted_runtime",
)


@dataclass(frozen=True, slots=True)
class ProviderCapabilityManifest:
    manifest_id: str
    manifest_version: str
    provider: str
    product: str
    method: ControlMethod
    supported_versions: tuple[str, ...]
    capability_matrix: dict[CapabilityDimension, CapabilityClaim]
    security_properties: SecurityProperties
    verification_status: VerificationStatus
    verified_at: str | None
    adapter_version: str
    verification_evidence: tuple[str, ...]
    official_documentation_reference: str
    required_permissions: tuple[str, ...]
    deployment_requirements: tuple[str, ...]
    known_blind_spots: tuple[str, ...]
    failure_modes: tuple[str, ...]
    privacy_implications: tuple[str, ...]
    fallback_methods: tuple[ControlMethod, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "manifest_id": self.manifest_id,
            "manifest_version": self.manifest_version,
            "provider": self.provider,
            "product": self.product,
            "method": self.method.value,
            "supported_versions": list(self.supported_versions),
            "capability_matrix": {
                dimension.value: {
                    "level": claim.level.value,
                    "verification_status": claim.verification_status.value,
                    "evidence_refs": list(claim.evidence_refs),
                }
                for dimension, claim in sorted(self.capability_matrix.items(), key=lambda row: row[0].value)
            },
            "security_properties": {
                "pre_execution_capable": self.security_properties.pre_execution_capable,
                "post_execution_capable": self.security_properties.post_execution_capable,
                "blocking_strength": self.security_properties.blocking_strength,
                "action_fidelity": self.security_properties.action_fidelity,
                "identity_quality": self.security_properties.identity_quality,
                "parameter_fidelity": self.security_properties.parameter_fidelity,
                "target_fidelity": self.security_properties.target_fidelity,
                "destination_fidelity": self.security_properties.destination_fidelity,
                "result_fidelity": self.security_properties.result_fidelity,
                "bypass_resistance": self.security_properties.bypass_resistance,
                "tamper_resistance": self.security_properties.tamper_resistance,
                "expected_latency_ms": self.security_properties.expected_latency_ms,
                "availability_profile": self.security_properties.availability_profile,
                "required_permissions": list(self.security_properties.required_permissions),
                "privacy_impact": self.security_properties.privacy_impact,
            },
            "verification_status": self.verification_status.value,
            "verified_at": self.verified_at,
            "adapter_version": self.adapter_version,
            "verification_evidence": list(self.verification_evidence),
            "official_documentation_reference": self.official_documentation_reference,
            "required_permissions": list(self.required_permissions),
            "deployment_requirements": list(self.deployment_requirements),
            "known_blind_spots": list(self.known_blind_spots),
            "failure_modes": list(self.failure_modes),
            "privacy_implications": list(self.privacy_implications),
            "fallback_methods": [method.value for method in self.fallback_methods],
        }


class ProviderManifestRegistry:
    def __init__(self, manifests: tuple[ProviderCapabilityManifest, ...]):
        keys = [(row.provider, row.product, row.method.value) for row in manifests]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate provider capability manifest")
        self.manifests = tuple(sorted(manifests, key=lambda row: (row.provider, row.product, row.method.value)))
        encoded = json.dumps(
            [row.as_dict() for row in self.manifests],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.matrix_version = f"control-capability-matrix/1.0+{sha256(encoded).hexdigest()[:12]}"

    def providers(self) -> tuple[str, ...]:
        return tuple(sorted({row.provider for row in self.manifests}))

    def for_provider(self, provider: str) -> tuple[ProviderCapabilityManifest, ...]:
        normalized = str(provider or "").strip().lower()
        return tuple(row for row in self.manifests if row.provider == normalized)

    def get(self, provider: str, product: str, method: ControlMethod) -> ProviderCapabilityManifest:
        normalized_provider = str(provider or "").strip().lower()
        normalized_product = str(product or "").strip().lower()
        for row in self.manifests:
            if row.provider == normalized_provider and row.product == normalized_product and row.method is method:
                return row
        raise KeyError((normalized_provider, normalized_product, method.value))


def _all_unknown() -> dict[CapabilityDimension, CapabilityClaim]:
    return {
        dimension: CapabilityClaim(
            level=CapabilityLevel.UNKNOWN,
            verification_status=VerificationStatus.UNVERIFIED,
        )
        for dimension in CapabilityDimension
    }


def _claims(
    overrides: dict[CapabilityDimension, tuple[CapabilityLevel, VerificationStatus]],
) -> dict[CapabilityDimension, CapabilityClaim]:
    values = _all_unknown()
    for dimension, (level, status) in overrides.items():
        values[dimension] = CapabilityClaim(
            level=level,
            verification_status=status,
            evidence_refs=("repo:apps/api/tests/test_authorization_surface_parity.py",)
            if status is VerificationStatus.VERIFIED
            else (),
        )
    return values


def _native_unverified(provider: str, product: str) -> ProviderCapabilityManifest:
    unavailable = {
        dimension: (CapabilityLevel.UNAVAILABLE, VerificationStatus.UNVERIFIED)
        for dimension in CapabilityDimension
    }
    return ProviderCapabilityManifest(
        manifest_id=f"{provider}:{product}:native_hook",
        manifest_version="provider-capability-manifest/1.0",
        provider=provider,
        product=product,
        method=ControlMethod.NATIVE_HOOK,
        supported_versions=(),
        capability_matrix=_claims(unavailable),
        security_properties=SecurityProperties(
            pre_execution_capable=False,
            post_execution_capable=False,
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
            availability_profile="unverified",
            required_permissions=(),
            privacy_impact="unknown",
        ),
        verification_status=VerificationStatus.UNVERIFIED,
        verified_at=None,
        adapter_version="1.0.0",
        verification_evidence=("No repository conformance evidence for a provider-native security hook.",),
        official_documentation_reference="verification_required_before_enablement",
        required_permissions=(),
        deployment_requirements=("Provider-native lifecycle interface must be documented and conformance-tested.",),
        known_blind_spots=("Native lifecycle enforcement is not verified and contributes no protected coverage.",),
        failure_modes=("Provider or product version may not expose a pre-action blocking callback.",),
        privacy_implications=("Unknown until a concrete native integration is validated.",),
        fallback_methods=(
            ControlMethod.SDK_MIDDLEWARE,
            ControlMethod.GATEWAY_INLINE,
            ControlMethod.ENDPOINT_RUNTIME,
        ),
    )


def _cli_native_hook(provider: str, product: str) -> ProviderCapabilityManifest:
    if provider == "google":
        from app.services.native_control.gemini_cli_adapter import GeminiCliAdapter

        source = GeminiCliAdapter.manifest
        return ProviderCapabilityManifest(
            manifest_id=f"{provider}:{product}:native_hook",
            manifest_version="provider-capability-manifest/1.3",
            provider=provider,
            product=product,
            method=ControlMethod.NATIVE_HOOK,
            supported_versions=source.exact_verified_versions,
            capability_matrix=dict(source.capabilities),
            security_properties=source.security_properties,
            verification_status=source.verification_status,
            verified_at=source.verified_at,
            adapter_version=source.adapter_version,
            verification_evidence=(
                "repo:apps/endpoint-agent/tests/test_gemini_binary_acceptance.py",
                "repo:apps/api/tests/test_native_control_gemini_adapter.py",
                "repo:docs/evidence/gemini-cli-acceptance-registry.json",
            ),
            official_documentation_reference="https://geminicli.com/docs/hooks/reference/",
            required_permissions=source.required_permissions,
            deployment_requirements=(
                "Pin an exact reviewed Gemini CLI version.",
                "Install the Hawk-owned hook through a managed system override and wrapper.",
                "Reject competing security-sensitive hooks before Enforce.",
            ),
            known_blind_spots=tuple(row.impact for row in source.known_blind_spots),
            failure_modes=source.failure_modes,
            privacy_implications=(source.security_properties.privacy_impact,),
            fallback_methods=(
                ControlMethod.ENDPOINT_RUNTIME,
                ControlMethod.GATEWAY_INLINE,
                ControlMethod.OBSERVE_ONLY,
            ),
        )
    # The documented hook contracts and Hawk helper behavior are implemented,
    # but the provider binaries have not passed the mandatory adapter
    # conformance/acceptance gate. Keep them ineligible for production selection.
    verified = VerificationStatus.EXPERIMENTAL
    manifest_version = "provider-capability-manifest/1.1"
    adapter_version = "1.0.0"
    verified_at = "2026-08-11T00:00:00+00:00"
    if provider == "anthropic":
        adapter_version = "1.2.0"
        registry = load_claude_acceptance_registry()
        accepted_versions = registry.accepted_versions(adapter_version=adapter_version)
        if not accepted_versions:
            return _native_unverified(provider, product)
        contract_version = accepted_versions[-1]
        accepted = registry.entry(contract_version, adapter_version=adapter_version)
        if accepted is None:
            return _native_unverified(provider, product)
        documentation = "https://code.claude.com/docs/en/hooks"
        lifecycle = (
            "PreToolUse/PermissionRequest/PostToolUse/PostToolUseFailure/"
            "UserPromptSubmit/SubagentStart/SubagentStop/SessionStart/SessionEnd/"
            "ConfigChange command hooks"
        )
        verified = VerificationStatus.VERIFIED
        manifest_version = "provider-capability-manifest/1.3"
        verified_at = accepted.evidence_timestamp
    else:
        raise ValueError("verified CLI hook provider is unsupported")
    return ProviderCapabilityManifest(
        manifest_id=f"{provider}:{product}:native_hook",
        manifest_version=manifest_version,
        provider=provider,
        product=product,
        method=ControlMethod.NATIVE_HOOK,
        supported_versions=(contract_version,),
        capability_matrix=_claims(
            {
                CapabilityDimension.DISCOVERY: (CapabilityLevel.OBSERVE, verified),
                CapabilityDimension.IDENTITY: (CapabilityLevel.OBSERVE, verified),
                CapabilityDimension.PROMPT_CONTROL: (
                    CapabilityLevel.INLINE_BOUND if provider == "anthropic" else CapabilityLevel.INLINE,
                    verified,
                ),
                CapabilityDimension.TOOL_CONTROL: (
                    CapabilityLevel.INLINE_BOUND if provider == "anthropic" else CapabilityLevel.INLINE,
                    verified,
                ),
                CapabilityDimension.MCP_CONTROL: (
                    CapabilityLevel.INLINE_BOUND if provider == "anthropic" else CapabilityLevel.INLINE,
                    verified,
                ),
                CapabilityDimension.COMMAND_CONTROL: (
                    CapabilityLevel.INLINE_BOUND if provider == "anthropic" else CapabilityLevel.INLINE,
                    verified,
                ),
                CapabilityDimension.FILE_READ_CONTROL: (
                    CapabilityLevel.INLINE_BOUND if provider == "anthropic" else CapabilityLevel.INLINE,
                    verified,
                ),
                CapabilityDimension.FILE_WRITE_CONTROL: (
                    CapabilityLevel.INLINE_BOUND if provider == "anthropic" else CapabilityLevel.INLINE,
                    verified,
                ),
                CapabilityDimension.APPROVAL_CONTROL: (
                    CapabilityLevel.EXTERNAL,
                    VerificationStatus.EXPERIMENTAL if provider == "anthropic" else verified,
                ),
                CapabilityDimension.PROVIDER_PERMISSION_CONTEXT: (
                    CapabilityLevel.OBSERVE,
                    verified if provider == "anthropic" else VerificationStatus.EXPERIMENTAL,
                ),
                CapabilityDimension.HAWK_APPROVAL_BINDING: (
                    CapabilityLevel.EXTERNAL,
                    verified if provider == "anthropic" else VerificationStatus.EXPERIMENTAL,
                ),
                CapabilityDimension.APPROVAL_CORRELATION: (
                    CapabilityLevel.OBSERVE,
                    verified if provider == "anthropic" else VerificationStatus.EXPERIMENTAL,
                ),
                CapabilityDimension.PARAMETER_BINDING: (CapabilityLevel.INLINE_BOUND, verified),
                CapabilityDimension.TARGET_BINDING: (
                    CapabilityLevel.OBSERVE if provider == "anthropic" else CapabilityLevel.INLINE_BOUND,
                    verified,
                ),
                CapabilityDimension.POST_EXECUTION_VISIBILITY: (CapabilityLevel.OBSERVE, verified),
                CapabilityDimension.TOOL_FAILURE_VISIBILITY: (
                    CapabilityLevel.OBSERVE,
                    verified if provider == "anthropic" else VerificationStatus.EXPERIMENTAL,
                ),
                CapabilityDimension.EXECUTION_CORRELATION: (
                    CapabilityLevel.OBSERVE,
                    verified if provider == "anthropic" else VerificationStatus.EXPERIMENTAL,
                ),
                CapabilityDimension.POST_EXECUTION_VERIFICATION: (
                    CapabilityLevel.UNAVAILABLE,
                    verified,
                ),
                CapabilityDimension.CONFIG_CHANGE_VISIBILITY: (
                    CapabilityLevel.OBSERVE,
                    VerificationStatus.EXPERIMENTAL,
                ),
                CapabilityDimension.BACKGROUND_EXECUTION_VISIBILITY: (
                    CapabilityLevel.OBSERVE,
                    VerificationStatus.EXPERIMENTAL,
                ),
                CapabilityDimension.PERSISTENT_SIDE_EFFECT_VISIBILITY: (
                    CapabilityLevel.OBSERVE,
                    VerificationStatus.EXPERIMENTAL,
                ),
                CapabilityDimension.PERSISTENT_SIDE_EFFECT_CONTROL: (
                    CapabilityLevel.INLINE,
                    VerificationStatus.EXPERIMENTAL if provider == "anthropic" else verified,
                ),
                CapabilityDimension.DELEGATION_CONTROL: (
                    CapabilityLevel.INLINE_BOUND if provider == "anthropic" else CapabilityLevel.UNKNOWN,
                    verified if provider == "anthropic" else VerificationStatus.EXPERIMENTAL,
                ),
                CapabilityDimension.BYPASS_DETECTION: (CapabilityLevel.OBSERVE, verified),
                CapabilityDimension.CONFIG_INTEGRITY: (CapabilityLevel.INLINE_BOUND, verified),
            }
        ),
        security_properties=SecurityProperties(
            pre_execution_capable=True,
            post_execution_capable=True,
            blocking_strength=90,
            action_fidelity=90,
            identity_quality=60,
            parameter_fidelity=95,
            target_fidelity=90,
            destination_fidelity=70,
            result_fidelity=65,
            bypass_resistance=60,
            tamper_resistance=80,
            expected_latency_ms=5_000 if provider == "anthropic" else 100,
            availability_profile="provider_cli_hook",
            required_permissions=("provider.settings.write", "hawk.callback.send"),
            privacy_impact="hashed_action_metadata",
        ),
        verification_status=verified,
        verified_at=verified_at,
        adapter_version=adapter_version,
        verification_evidence=(
            "repo:apps/endpoint-agent/tests/test_native_hook_installer.py",
            "repo:apps/endpoint-agent/tests/test_native_hook_callback.py",
            *(
                (
                    "repo:apps/endpoint-agent/tests/test_claude_binary_acceptance.py",
                    "repo:apps/api/tests/test_native_control_claude_adapter.py",
                    "repo:docs/evidence/claude-code-acceptance-registry.json",
                )
                if provider == "anthropic"
                else ()
            ),
            f"provider contract: {lifecycle}",
        ),
        official_documentation_reference=documentation,
        required_permissions=("provider.settings.write", "hawk.callback.send"),
        deployment_requirements=(
            "Install the Hawk-owned hook fragment atomically.",
            "Register the hardware-backed public workload key and pass signed callback validation.",
        ),
        known_blind_spots=(
            "Direct provider API calls outside the governed CLI do not traverse this hook.",
            "Any untested version, including an auto-update beyond 2.1.183, becomes VERSION_MISMATCH until its own real-binary acceptance is promoted.",
            "Parallel PreToolUse handlers can mutate input; verified v1 disables Hawk input mutation and treats parameter/target binding as observed, not exact pre-execution binding.",
            "PermissionRequest enriches approval context but does not fire for every tool invocation and is not the primary authorization point.",
            "PostToolUse and PostToolUseFailure are provider-reported evidence, not independent execution verification.",
            "Raw content is not exported; Hawk receives bounded hashes and classifications.",
            "Provider application chrome cannot be modified by this lifecycle hook.",
        ),
        failure_modes=("Hook removed", "callback unavailable", "provider contract version mismatch"),
        privacy_implications=("Only normalized action metadata, hashes, and classifications leave the client.",),
        fallback_methods=(ControlMethod.ENDPOINT_RUNTIME, ControlMethod.GATEWAY_INLINE, ControlMethod.OBSERVE_ONLY),
    )


def _gateway(provider: str, product: str = "direct_api") -> ProviderCapabilityManifest:
    verified = VerificationStatus.VERIFIED
    return ProviderCapabilityManifest(
        manifest_id=f"{provider}:{product}:gateway_inline",
        manifest_version="provider-capability-manifest/1.0",
        provider=provider,
        product=product,
        method=ControlMethod.GATEWAY_INLINE,
        supported_versions=("hawk-openai-compatible-v1",),
        capability_matrix=_claims(
            {
                CapabilityDimension.DISCOVERY: (CapabilityLevel.OBSERVE, verified),
                CapabilityDimension.IDENTITY: (CapabilityLevel.OBSERVE, verified),
                CapabilityDimension.PROMPT_CONTROL: (CapabilityLevel.INLINE, verified),
                CapabilityDimension.RESPONSE_CONTROL: (CapabilityLevel.INLINE, verified),
                CapabilityDimension.MODEL_REQUEST_CONTROL: (CapabilityLevel.INLINE, verified),
                CapabilityDimension.MODEL_RESPONSE_CONTROL: (CapabilityLevel.INLINE, verified),
                CapabilityDimension.DIRECT_API_CONTROL: (CapabilityLevel.INLINE, verified),
                CapabilityDimension.POST_EXECUTION_VISIBILITY: (CapabilityLevel.OBSERVE, verified),
                CapabilityDimension.BYPASS_DETECTION: (CapabilityLevel.OBSERVE, verified),
                CapabilityDimension.TOOL_CONTROL: (CapabilityLevel.UNAVAILABLE, VerificationStatus.UNVERIFIED),
                CapabilityDimension.MCP_CONTROL: (CapabilityLevel.UNAVAILABLE, VerificationStatus.UNVERIFIED),
                CapabilityDimension.PARAMETER_BINDING: (CapabilityLevel.UNAVAILABLE, VerificationStatus.UNVERIFIED),
                CapabilityDimension.TARGET_BINDING: (CapabilityLevel.UNAVAILABLE, VerificationStatus.UNVERIFIED),
                CapabilityDimension.DESTINATION_BINDING: (CapabilityLevel.UNAVAILABLE, VerificationStatus.UNVERIFIED),
            }
        ),
        security_properties=SecurityProperties(
            pre_execution_capable=True,
            post_execution_capable=True,
            blocking_strength=80,
            action_fidelity=65,
            identity_quality=65,
            parameter_fidelity=0,
            target_fidelity=0,
            destination_fidelity=0,
            result_fidelity=65,
            bypass_resistance=70,
            tamper_resistance=85,
            expected_latency_ms=75,
            availability_profile="remote_inline",
            required_permissions=("gateway.intercept", "policy.evaluate"),
            privacy_impact="prompt_response_and_action_metadata",
        ),
        verification_status=verified,
        verified_at="2026-08-11T00:00:00+00:00",
        adapter_version="1.0.0",
        verification_evidence=(
            "repo:apps/api/tests/test_authorization_surface_parity.py",
            "repo:apps/api/tests/test_llm_gateway.py",
        ),
        official_documentation_reference="repository_conformance_evidence; provider-native hook not claimed",
        required_permissions=("gateway.intercept", "policy.evaluate"),
        deployment_requirements=("Application traffic must be routed through the Hawk LLM/API gateway.",),
        known_blind_spots=(
            "Direct provider API traffic that bypasses Hawk is outside inline control.",
            "The generic gateway route does not establish exact provider tool, MCP, parameter, target, destination, or provider-native lifecycle authorization.",
        ),
        failure_modes=("Gateway bypass", "stale policy", "provider protocol incompatibility"),
        privacy_implications=("Prompt, response and actionable metadata traverse the configured Hawk gateway boundary.",),
        fallback_methods=(ControlMethod.ENDPOINT_RUNTIME, ControlMethod.OBSERVE_ONLY),
    )


def _microsoft_agent_framework_function_middleware() -> ProviderCapabilityManifest:
    """Project only the locally accepted Agent Framework Function boundary."""

    verified = VerificationStatus.VERIFIED
    unverified = VerificationStatus.UNVERIFIED
    evidence = (
        "repo:integrations/microsoft-agent-framework-dotnet/tests/"
        "Hawk.AI.MicrosoftAgentFramework.Tests/HawkFunctionExecutionGateTests.cs",
        "repo:integrations/microsoft-agent-framework-dotnet/tests/"
        "Hawk.AI.MicrosoftAgentFramework.Tests/HawkAgentFrameworkMiddlewareTests.cs",
        "repo:apps/api/tests/test_banking_transaction_integrity_api.py",
        "repo:docs/validation/bank-foundry-first-proof-path.md",
    )
    capabilities = _all_unknown()
    for dimension in (
        CapabilityDimension.FUNCTION_TOOL_CONTROL,
        CapabilityDimension.FUNCTION_TOOL_PARAMETER_BINDING,
        CapabilityDimension.FUNCTION_TOOL_TARGET_BINDING,
    ):
        capabilities[dimension] = CapabilityClaim(
            level=CapabilityLevel.INLINE_BOUND,
            verification_status=verified,
            evidence_refs=evidence,
        )
    model_evidence = (
        "repo:integrations/microsoft-agent-framework-dotnet/tests/"
        "Hawk.AI.MicrosoftAgentFramework.Tests/HawkChatClientTests.cs",
        "repo:integrations/microsoft-agent-framework-dotnet/tests/"
        "Hawk.AI.MicrosoftAgentFramework.Tests/HawkResponseAssuranceTests.cs",
        "repo:apps/api/tests/test_banking_transaction_integrity_api.py",
        "repo:apps/api/tests/test_banking_response_assurance.py",
    )
    transport_evidence = (
        "repo:integrations/microsoft-agent-framework-dotnet/tests/"
        "Hawk.AI.MicrosoftAgentFramework.Tests/HawkTransportAdaptersTests.cs",
        "repo:apps/api/tests/test_banking_transport_control.py",
        "repo:apps/api/tests/test_banking_transaction_integrity_api.py",
    )
    post_execution_evidence = (
        "repo:apps/api/tests/test_banking_transaction_integrity_api.py",
        "repo:apps/api/tests/test_banking_transaction_projection.py",
    )
    for dimension in (
        CapabilityDimension.MODEL_REQUEST_CONTROL,
        CapabilityDimension.MODEL_RESPONSE_CONTROL,
    ):
        capabilities[dimension] = CapabilityClaim(
            level=CapabilityLevel.INLINE_BOUND,
            verification_status=VerificationStatus.EXPERIMENTAL,
            evidence_refs=model_evidence,
        )
    for dimension in (
        CapabilityDimension.MCP_CONTROL,
        CapabilityDimension.LOCAL_MCP_CONTROL,
        CapabilityDimension.DIRECT_API_CONTROL,
    ):
        capabilities[dimension] = CapabilityClaim(
            level=CapabilityLevel.INLINE_BOUND,
            verification_status=VerificationStatus.EXPERIMENTAL,
            evidence_refs=transport_evidence,
        )
    capabilities[CapabilityDimension.POST_EXECUTION_VERIFICATION] = CapabilityClaim(
        level=CapabilityLevel.OBSERVE,
        verification_status=VerificationStatus.EXPERIMENTAL,
        evidence_refs=post_execution_evidence,
    )
    capabilities[CapabilityDimension.HOSTED_MCP_CONTROL] = CapabilityClaim(
        level=CapabilityLevel.UNAVAILABLE,
        verification_status=unverified,
    )

    return ProviderCapabilityManifest(
        manifest_id="microsoft:agent_framework:agent_middleware",
        manifest_version="provider-capability-manifest/1.0",
        provider="microsoft",
        product="agent_framework",
        method=ControlMethod.AGENT_MIDDLEWARE,
        supported_versions=("1.15.0",),
        capability_matrix=capabilities,
        security_properties=SecurityProperties(
            pre_execution_capable=True,
            post_execution_capable=True,
            blocking_strength=95,
            action_fidelity=100,
            identity_quality=90,
            parameter_fidelity=100,
            target_fidelity=100,
            destination_fidelity=90,
            result_fidelity=80,
            bypass_resistance=40,
            tamper_resistance=75,
            expected_latency_ms=5_000,
            availability_profile="application_bound_function_middleware",
            required_permissions=(
                "banking_action.authorize",
                "banking_action.pre_execution",
                "banking_action.execution_report",
            ),
            privacy_impact="pseudonymous canonical action and receipt metadata",
        ),
        # The adapter remains Experimental overall. Only the three Function
        # dimensions above carry verified claims from the local proof path.
        verification_status=VerificationStatus.EXPERIMENTAL,
        verified_at=None,
        adapter_version="1.0.0",
        verification_evidence=evidence,
        official_documentation_reference=(
            "repo:docs/superpowers/specs/"
            "2026-08-14-bank-foundry-transaction-integrity-dotnet-design.md"
        ),
        required_permissions=(
            "banking_action.authorize",
            "banking_action.pre_execution",
            "banking_action.execution_report",
        ),
        deployment_requirements=(
            "Pin Microsoft.Agents.AI exactly to 1.15.0.",
            "Register HawkFunctionExecutionGate as the final middleware directly around the approved Function executor.",
            "Use a signed BankingSubjectContext and a Hawk API schema at revision 0053_banking_execution_grants or later.",
        ),
        known_blind_spots=(
            "Verified only for the local Function callback proof; no product-wide Microsoft Agent Framework or Foundry claim is inferred.",
            "Foundry model request and response gates are locally implemented but remain Experimental pending real Foundry runtime acceptance.",
            "MCP, Foundry Toolbox, APIM, OpenAPI, and direct REST bindings are locally implemented but remain Experimental pending real transport acceptance.",
            "Hosted MCP tools and hosted agent runtimes remain unavailable and unverified.",
            "Execution comparison is Hawk-observed; independent bank-service confirmation has not been accepted in a production tenant.",
            "Applications that omit or bypass the final Hawk middleware are outside inline control.",
        ),
        failure_modes=(
            "Hawk middleware omitted or ordered before a mutating middleware",
            "Hawk decision service unavailable",
            "subject context invalid, expired, or replayed",
            "execution grant expired, reused, or does not match final action material",
        ),
        privacy_implications=(
            "Hawk persists tenant-keyed fingerprints and bounded action/receipt metadata; raw bank identifiers remain in the bank-controlled process.",
        ),
        fallback_methods=(ControlMethod.GATEWAY_INLINE, ControlMethod.OBSERVE_ONLY),
    )


def _openai_adapter_manifest(adapter: object, method: ControlMethod) -> ProviderCapabilityManifest:
    """Project one OpenAI product adapter without provider-wide inheritance."""

    source = adapter.manifest
    descriptor = adapter.descriptor
    product = str(source.product)
    fallbacks = {
        "agents_sdk": (
            ControlMethod.GATEWAY_INLINE,
            ControlMethod.ENDPOINT_RUNTIME,
            ControlMethod.OBSERVE_ONLY,
        ),
        "codex": (
            ControlMethod.ENDPOINT_RUNTIME,
            ControlMethod.GATEWAY_INLINE,
            ControlMethod.OBSERVE_ONLY,
        ),
        "direct_api": (
            ControlMethod.ENDPOINT_RUNTIME,
            ControlMethod.OBSERVE_ONLY,
        ),
    }[product]
    deployment = {
        "agents_sdk": (
            "Pin and conformance-test the exact OpenAI Agents SDK version.",
            "Register Hawk on each explicit action-class boundary; function-tool guardrails do not cover other tool classes.",
        ),
        "codex": (
            "Pin the exact Codex binary version and complete real-binary allow/block acceptance.",
            "For bank enforcement, deliver the signed helper and managed requirements through MDM with managed-only hooks enabled.",
        ),
        "direct_api": (
            "Bind application traffic to the Hawk gateway/API route.",
            "Bind tool-loop authorization separately before executing provider-proposed tool calls.",
        ),
    }[product]
    supported_versions = (
        ("hawk-openai-compatible-v1",)
        if product == "direct_api" and method is ControlMethod.GATEWAY_INLINE
        else tuple(source.exact_verified_versions)
    )
    return ProviderCapabilityManifest(
        manifest_id=f"openai:{product}:{method.value}",
        # Codex's verified contract is versioned separately from the earlier
        # experimental catalog row. Existing integrations must cross the
        # admin acceptance boundary to bind this new profile and contract hash.
        manifest_version=(
            "provider-capability-manifest/1.2"
            if product == "codex" and source.verification_status is VerificationStatus.VERIFIED
            else "provider-capability-manifest/1.1"
        ),
        provider="openai",
        product=product,
        method=method,
        supported_versions=supported_versions,
        capability_matrix=dict(source.capabilities),
        security_properties=source.security_properties,
        verification_status=source.verification_status,
        verified_at=source.verified_at,
        adapter_version=descriptor.adapter_version,
        verification_evidence=(
            source.source_reference,
            "repo:apps/api/tests/test_native_control_openai_action_matrix.py",
            "repo:apps/api/tests/test_native_control_openai_adapters.py",
            *(
                (
                    "repo:apps/endpoint-agent/tests/test_codex_native_acceptance.py",
                    "repo:docs/evidence/codex-0.154.0-acceptance-result.json",
                )
                if product == "codex"
                and source.verification_status is VerificationStatus.VERIFIED
                else ()
            ),
        ),
        official_documentation_reference=source.source_reference,
        required_permissions=tuple(source.required_permissions),
        deployment_requirements=deployment,
        known_blind_spots=tuple(row.impact for row in source.known_blind_spots),
        failure_modes=tuple(source.failure_modes),
        privacy_implications=(source.security_properties.privacy_impact,),
        fallback_methods=fallbacks,
    )


def _endpoint_runtime(provider: str) -> ProviderCapabilityManifest:
    verified = VerificationStatus.VERIFIED
    unavailable = {
        dimension: (CapabilityLevel.UNAVAILABLE, VerificationStatus.UNVERIFIED)
        for dimension in CapabilityDimension
    }
    return ProviderCapabilityManifest(
        manifest_id=f"{provider}:self_hosted:endpoint_runtime",
        manifest_version="provider-capability-manifest/1.0",
        provider=provider,
        product="self_hosted",
        method=ControlMethod.ENDPOINT_RUNTIME,
        supported_versions=("explicit-hawk-client-binding-v1",),
        capability_matrix=_claims(
            {
                **unavailable,
                CapabilityDimension.DISCOVERY: (CapabilityLevel.OBSERVE, verified),
                CapabilityDimension.IDENTITY: (CapabilityLevel.OBSERVE, verified),
                CapabilityDimension.POST_EXECUTION_VISIBILITY: (CapabilityLevel.OBSERVE, verified),
            }
        ),
        security_properties=SecurityProperties(
            pre_execution_capable=False,
            post_execution_capable=True,
            blocking_strength=0,
            action_fidelity=30,
            identity_quality=65,
            parameter_fidelity=0,
            target_fidelity=0,
            destination_fidelity=0,
            result_fidelity=50,
            bypass_resistance=0,
            tamper_resistance=50,
            expected_latency_ms=30,
            availability_profile="explicit_client_binding_observation",
            required_permissions=("runtime.observe",),
            privacy_impact="canonical_action_metadata",
        ),
        verification_status=verified,
        verified_at="2026-08-11T00:00:00+00:00",
        adapter_version="1.0.0",
        verification_evidence=(
            "repo:apps/endpoint-agent/tests",
            "Explicit Hawk client binding normalizes and observes runtime metadata; no provider lifecycle or endpoint OS enforcement capability asserted.",
        ),
        official_documentation_reference="runtime-owned control point; provider-native documentation not applicable",
        required_permissions=("runtime.observe",),
        deployment_requirements=("Explicit Hawk client binding and a healthy enrolled endpoint identity are required.",),
        known_blind_spots=(
            "The explicit Hawk client binding normalizes and observes runtime metadata only; it does not prove provider tool, MCP, command, file, network, or endpoint OS authorization.",
            "Unbound processes and unmanaged alternate runtimes remain outside inline control.",
            "Endpoint OS enforcement requires separately verified endpoint-floor and native-to-endpoint permit evidence.",
        ),
        failure_modes=("Agent unhealthy", "client binding removed", "runtime route bypass"),
        privacy_implications=("Canonical action metadata is observed; raw content handling follows endpoint policy.",),
        fallback_methods=(ControlMethod.GATEWAY_INLINE, ControlMethod.OBSERVE_ONLY),
    )


def _bedrock_guardrails() -> ProviderCapabilityManifest:
    unverified = VerificationStatus.UNVERIFIED
    return ProviderCapabilityManifest(
        manifest_id="aws:bedrock_guardrails:saas_control_api",
        manifest_version="provider-capability-manifest/1.0",
        provider="aws",
        product="bedrock_guardrails",
        method=ControlMethod.SAAS_CONTROL_API,
        supported_versions=(),
        capability_matrix=_claims(
            {
                CapabilityDimension.PROMPT_CONTROL: (CapabilityLevel.EXTERNAL, unverified),
                CapabilityDimension.RESPONSE_CONTROL: (CapabilityLevel.EXTERNAL, unverified),
                CapabilityDimension.PARAMETER_BINDING: (CapabilityLevel.UNAVAILABLE, unverified),
                CapabilityDimension.TARGET_BINDING: (CapabilityLevel.UNAVAILABLE, unverified),
                CapabilityDimension.DESTINATION_BINDING: (CapabilityLevel.UNAVAILABLE, unverified),
            }
        ),
        security_properties=SecurityProperties(
            pre_execution_capable=False,
            post_execution_capable=False,
            blocking_strength=40,
            action_fidelity=25,
            identity_quality=20,
            parameter_fidelity=0,
            target_fidelity=0,
            destination_fidelity=0,
            result_fidelity=25,
            bypass_resistance=30,
            tamper_resistance=50,
            expected_latency_ms=100,
            availability_profile="provider_external",
            required_permissions=("bedrock:ApplyGuardrail",),
            privacy_impact="provider_content_evaluation",
        ),
        verification_status=unverified,
        verified_at=None,
        adapter_version="1.0.0",
        verification_evidence=("Guardrails are represented separately from Hawk exact action authorization.",),
        official_documentation_reference="official_provider_validation_required_before_enablement",
        required_permissions=("bedrock:ApplyGuardrail",),
        deployment_requirements=("Customer Bedrock invocation must explicitly apply a configured guardrail.",),
        known_blind_spots=("Does not prove exact tool, parameter, target, identity or persistent side-effect authorization.",),
        failure_modes=("Guardrail omitted from invocation", "guardrail version drift"),
        privacy_implications=("Content may be evaluated by the provider guardrail service.",),
        fallback_methods=(ControlMethod.AGENT_MIDDLEWARE, ControlMethod.GATEWAY_INLINE),
    )


def build_default_registry() -> ProviderManifestRegistry:
    from app.services.native_control.anthropic_enterprise import (
        anthropic_enterprise_provider_profiles,
    )
    from app.services.native_control.aws_bedrock import (
        aws_bedrock_provider_profiles,
    )
    from app.services.native_control.direct_cloud_provider_profiles import (
        direct_cloud_provider_matrix_profiles,
    )
    from app.services.native_control.self_hosted_runtimes import (
        self_hosted_runtime_provider_profiles,
    )

    native_products = {
        "anthropic": "claude_code",
        "openai": "codex",
        "google": "gemini_cli",
        "cursor": "cursor",
        "microsoft": "agent_framework",
        "azure": "ai_foundry",
        "aws": "bedrock_agents",
        "meta": "llama",
        "moonshot_kimi": "kimi_coding",
        "alibaba_qwen": "qwen_agent",
        "deepseek": "deepseek_agent",
    }
    manifests: list[ProviderCapabilityManifest] = []
    for provider in REQUIRED_PROVIDER_FAMILIES:
        if provider == "openai":
            from app.services.native_control.openai_adapters import (
                CodexNativeControlAdapter,
                OpenAIAgentsSDKControlAdapter,
                OpenAIDirectAPIControlAdapter,
            )

            manifests.extend(
                (
                    _openai_adapter_manifest(
                        OpenAIAgentsSDKControlAdapter(),
                        ControlMethod.SDK_MIDDLEWARE,
                    ),
                    _openai_adapter_manifest(
                        CodexNativeControlAdapter(),
                        ControlMethod.NATIVE_HOOK,
                    ),
                    _openai_adapter_manifest(
                        OpenAIDirectAPIControlAdapter(),
                        ControlMethod.GATEWAY_INLINE,
                    ),
                )
            )
            continue
        # AWS Bedrock and AgentCore have no reviewed Hawk native-hook surface.
        # Their independently modelled product boundaries are appended below;
        # do not invent a generic Bedrock Agents hook or let Classic inherit it.
        if provider == "aws":
            manifests.append(_gateway(provider))
            continue
        if provider in {"anthropic", "google"}:
            manifests.append(_cli_native_hook(provider, native_products[provider]))
        else:
            manifests.append(_native_unverified(provider, native_products[provider]))
        if provider == "microsoft":
            manifests.append(_microsoft_agent_framework_function_middleware())
        manifests.append(_gateway(provider))
    # Provider-hosted Anthropic Enterprise controls are distinct from the
    # Claude Code local hook and generic Anthropic gateway.  Their source of
    # truth is the provider-control contract; these are derived,
    # currently UNVERIFIED matrix projections only.
    manifests.extend(anthropic_enterprise_provider_profiles())
    # Direct/cloud model paths remain separate from both the generic Hawk
    # gateway and provider-native controls.  These reviewed contracts are all
    # UNVERIFIED/NOT_TESTED until exact tenant/cloud acceptance exists.
    manifests.extend(direct_cloud_provider_matrix_profiles())
    # AWS Bedrock/AgentCore products must never collapse into one generic
    # provider claim.  The canonical contracts below are projected into this
    # matrix without strengthening their still-unverified acceptance state.
    manifests.extend(aws_bedrock_provider_profiles())
    # Open and self-hosted serving stacks are model/runtime contracts, not
    # native provider hooks.  These matrix rows are derived from their
    # reviewed-but-unaccepted contracts and therefore cannot strengthen the
    # existing verified generic Hawk-gateway route.
    manifests.extend(self_hosted_runtime_provider_profiles())
    for provider in ("meta", "moonshot_kimi", "alibaba_qwen", "deepseek"):
        manifests.append(_endpoint_runtime(provider))
    return ProviderManifestRegistry(tuple(manifests))
