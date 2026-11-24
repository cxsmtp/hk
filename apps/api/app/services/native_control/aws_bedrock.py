"""Conservative AWS Bedrock and AgentCore control-boundary contracts.

These profiles are contract and Control Capability Matrix inputs, not AWS
installers or Hawk enforcement adapters.  They deliberately distinguish a
provider-hosted Bedrock/AgentCore service from a customer-controlled action,
MCP, or custom-agent execution boundary.  Every profile remains unverified
and not tested until tenant- and route-specific AWS acceptance proves allow,
block, and non-execution for its exact product, runtime, and action class.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

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
    RuntimeLocation,
    SecurityProperties,
    VerificationStatus,
)


_AWS_REVIEWED_AT = "2026-08-20T00:00:00+00:00"
_CONTRACT_EVIDENCE = (
    "repo:docs/superpowers/specs/2026-08-20-phase4-multi-provider-control-fabric-design.md",
    "repo:docs/native-controls/aws.md",
)
_NOT_TESTED = DeploymentAcceptanceResult.not_tested()
_CANONICAL_HAWK_DECISIONS = frozenset({"allow", "warn", "require_approval", "block"})


class AWSGuardrailAction(str, Enum):
    """Documented ApplyGuardrail response actions accepted by Hawk."""

    NONE = "NONE"
    GUARDRAIL_INTERVENED = "GUARDRAIL_INTERVENED"


def compose_bedrock_guardrail_decision(
    *,
    provider_action: AWSGuardrailAction | str,
    hawk_decision: str,
) -> str:
    """Preserve a provider Guardrail deny as a monotonic safety floor.

    This function does not evaluate Hawk policy. It only composes the already
    authoritative Hawk decision with the provider's content-policy outcome so
    a Hawk allow or approval state can never weaken an AWS deny.
    """

    decision = str(hawk_decision or "").strip().lower()
    if decision not in _CANONICAL_HAWK_DECISIONS:
        raise ValueError("hawk_decision_invalid")
    if not isinstance(provider_action, (AWSGuardrailAction, str)):
        raise ValueError("provider_guardrail_action_invalid")
    try:
        action = AWSGuardrailAction(provider_action)
    except ValueError:
        raise ValueError("provider_guardrail_action_invalid") from None
    if action is AWSGuardrailAction.GUARDRAIL_INTERVENED:
        return "block"
    return decision


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
    claims = _unavailable_claims()
    for dimension, level in items:
        claims[dimension] = CapabilityClaim(
            level=level,
            verification_status=VerificationStatus.UNVERIFIED,
            evidence_refs=_CONTRACT_EVIDENCE,
        )
    return claims


@dataclass(frozen=True, slots=True)
class AWSBedrockControlProfile:
    """A non-strengthening product-matrix projection of one reviewed contract."""

    contract: CapabilityManifest
    method: ControlMethod

    def provider_profile(self):
        """Derive the existing matrix row; never maintain a second truth source."""

        from app.services.native_control.manifests import ProviderCapabilityManifest

        return ProviderCapabilityManifest(
            manifest_id=f"aws:{self.contract.product}:{self.method.value}",
            manifest_version="provider-capability-manifest/1.0",
            provider="aws",
            product=self.contract.product,
            method=self.method,
            supported_versions=(),
            capability_matrix=dict(self.contract.capabilities),
            security_properties=self.contract.security_properties,
            verification_status=self.contract.verification_status,
            verified_at=self.contract.verified_at,
            adapter_version=self.contract.adapter_version,
            verification_evidence=(
                "No real AWS tenant, account, route, allow/block, and protected non-execution acceptance exists.",
                *_CONTRACT_EVIDENCE,
            ),
            official_documentation_reference=self.contract.source_reference,
            required_permissions=self.contract.required_permissions,
            deployment_requirements=(
                "Complete real AWS acceptance for the exact account, region, product, runtime, route, policy, and action class.",
                "Capture a reviewed allow, block, and protected non-execution result before Hawk Enforce.",
                "Prove direct provider and alternate-route bypass behavior for the customer deployment.",
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


def _contract(
    *,
    descriptor_id: str,
    product: str,
    method: ControlMethod,
    action_classes: tuple[ActionClass, ...],
    runtime_location: RuntimeLocation,
    deployment_family: DeploymentFamily,
    runtime: str,
    source_reference: str,
    required_permissions: tuple[str, ...],
    claims: dict[CapabilityDimension, CapabilityClaim],
    blind_spots: tuple[StructuredBlindSpot, ...],
    failure_modes: tuple[str, ...],
    pre_execution_events: tuple[str, ...] = (),
    post_execution_events: tuple[str, ...] = (),
    synchronous_decision_mechanism: str = "none; observation or context only",
    provider_deny_is_monotonic: bool = False,
) -> CapabilityManifest:
    lifecycle_events = (*pre_execution_events, *post_execution_events)
    failure_semantics = "unverified; never select for enforce"
    if provider_deny_is_monotonic:
        failure_semantics += "; provider Guardrail deny is monotonic and Hawk cannot weaken it"
    return CapabilityManifest(
        schema_version="native-control-adapter-manifest/1.0",
        descriptor_id=descriptor_id,
        provider="aws",
        product=product,
        # No AWS service version has completed deployment acceptance.  An
        # empty range is the canonical unaccepted-version representation;
        # the contract review revision remains separate in ``reviewed_at``.
        provider_version_min="",
        provider_version_max="",
        exact_verified_versions=(),
        adapter_version="1.0.0",
        verification_status=VerificationStatus.UNVERIFIED,
        verified_at=None,
        source_reference=source_reference,
        capabilities=claims,
        security_properties=SecurityProperties(
            pre_execution_capable=bool(pre_execution_events),
            post_execution_capable=bool(post_execution_events),
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
            availability_profile="aws_boundary_contract_unverified_not_tested",
            required_permissions=required_permissions,
            privacy_impact="No AWS content, customer identity, or execution evidence is claimed by Hawk before real acceptance.",
        ),
        required_permissions=required_permissions,
        event_semantics=EventSemantics(
            pre_execution_events=pre_execution_events,
            post_execution_events=post_execution_events,
            normalized_fields=("aws_route", "runtime_identity", "action_class"),
            synchronous_decision_mechanism=synchronous_decision_mechanism,
            ordering_guaranteed=False,
            runs_before_untrusted_mutators=False,
            runs_after_untrusted_mutators=False,
        ),
        known_blind_spots=blind_spots,
        failure_modes=failure_modes,
        supported_installation_modes=("customer_aws_configuration",),
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
        supported_runtime_locations=(runtime_location,),
        supported_deployment_families=(deployment_family,),
        supported_runtimes=(runtime,),
        supported_control_methods=(method,),
        supported_lifecycle_events=lifecycle_events,
        supports_action_mutation=False,
        supports_approval_pause=False,
        retry_semantics="unverified",
        failure_semantics=failure_semantics,
        privacy_profile="Hawk stores no raw AWS request, response, customer identity, or Lambda payload from this profile by default.",
        reviewed_by="hawk-provider-contract-review",
        reviewed_at=_AWS_REVIEWED_AT,
        reviewed_evidence_refs=_CONTRACT_EVIDENCE,
        deployment_acceptance=_NOT_TESTED,
    )


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
        detection_method="contract scope, real AWS deployment acceptance, and route evidence review",
        mitigation=mitigation,
        evidence=_CONTRACT_EVIDENCE,
    )


BEDROCK_MODEL_API = _contract(
    descriptor_id="aws.bedrock_model_api.customer_route",
    product="bedrock_model_api",
    method=ControlMethod.API_INTERCEPT,
    action_classes=(ActionClass.MODEL_REQUEST, ActionClass.MODEL_RESPONSE),
    runtime_location=RuntimeLocation.CUSTOMER_CLOUD,
    deployment_family=DeploymentFamily.RUNTIME,
    runtime="bedrock_model_api_customer_route",
    pre_execution_events=("before_model_request",),
    post_execution_events=("after_model_response",),
    source_reference="https://docs.aws.amazon.com/bedrock/latest/userguide/inference-api.html",
    required_permissions=("bedrock:InvokeModel", "bedrock:Converse"),
    claims=_claims(
        (CapabilityDimension.MODEL_REQUEST_CONTROL, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.MODEL_RESPONSE_CONTROL, CapabilityLevel.OBSERVE),
        (CapabilityDimension.MODEL_ROUTE_BINDING, CapabilityLevel.OBSERVE),
    ),
    blind_spots=(
        _blind_spot(
            identifier="bedrock-model-api-route-not-accepted",
            dimension=CapabilityDimension.MODEL_REQUEST_CONTROL,
            scope="customer-owned Bedrock model API route",
            condition="No exact AWS account, region, route, allow/block, and non-execution acceptance",
            impact="The customer route cannot become Hawk Enforce coverage.",
            mitigation="Bind and accept the exact customer route; prove that direct AWS provider invocation cannot bypass it.",
        ),
        _blind_spot(
            identifier="bedrock-model-api-no-tool-authorization",
            dimension=CapabilityDimension.FUNCTION_TOOL_CONTROL,
            scope="Bedrock model invocation",
            condition="A model response proposes or leads to a tool action",
            impact="Model API control does not authorize tools, arguments, targets, subjects, approvals, or execution.",
            mitigation="Use the separately accepted customer action, MCP, or target-service boundary.",
        ),
    ),
    failure_modes=("customer route omitted", "direct Bedrock API bypass", "acceptance missing or stale"),
    synchronous_decision_mechanism="customer-controlled Bedrock invocation route; unverified",
)


BEDROCK_GUARDRAIL = _contract(
    descriptor_id="aws.bedrock_guardrails.content_policy",
    product="bedrock_guardrails",
    method=ControlMethod.SAAS_CONTROL_API,
    action_classes=(ActionClass.PROMPT, ActionClass.MODEL_RESPONSE),
    runtime_location=RuntimeLocation.PROVIDER_HOSTED,
    deployment_family=DeploymentFamily.SAAS_API,
    runtime="bedrock_guardrails",
    pre_execution_events=("before_guardrail_input_evaluation",),
    post_execution_events=("after_guardrail_output_evaluation",),
    source_reference="https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-use-independent-api.html",
    required_permissions=("bedrock:ApplyGuardrail",),
    claims=_claims(
        (CapabilityDimension.PROMPT_CONTROL, CapabilityLevel.EXTERNAL),
        (CapabilityDimension.RESPONSE_CONTROL, CapabilityLevel.EXTERNAL),
        (CapabilityDimension.CONTENT_INSPECTION, CapabilityLevel.EXTERNAL),
    ),
    blind_spots=(
        _blind_spot(
            identifier="bedrock-guardrail-content-not-action-authorization",
            dimension=CapabilityDimension.FUNCTION_TOOL_CONTROL,
            scope="Bedrock Guardrails content evaluation",
            condition="Guardrails evaluates input or output content",
            impact="Content policy is not exact function, parameter, target, subject, approval, or execution authorization.",
            mitigation="Use a separately accepted customer-controlled action boundary for consequential operations.",
        ),
        _blind_spot(
            identifier="bedrock-guardrail-omission-or-direct-bypass",
            dimension=CapabilityDimension.BYPASS_DETECTION,
            scope="Bedrock invocation configuration",
            condition="A guardrail is omitted, replaced, or a direct invocation bypasses the intended route",
            impact="No Hawk prevention claim is possible for the bypassed invocation.",
            mitigation="Prove required guardrail configuration and direct-route resistance in the exact AWS deployment.",
        ),
    ),
    failure_modes=("guardrail omitted", "guardrail version drift", "direct Bedrock API bypass"),
    synchronous_decision_mechanism="provider Guardrail input/output content decision; unverified",
    provider_deny_is_monotonic=True,
)


BEDROCK_AGENTCORE = _contract(
    descriptor_id="aws.bedrock_agentcore.provider_runtime",
    product="bedrock_agentcore",
    method=ControlMethod.SAAS_CONTROL_API,
    action_classes=(ActionClass.MODEL_REQUEST,),
    runtime_location=RuntimeLocation.PROVIDER_HOSTED,
    deployment_family=DeploymentFamily.SAAS_API,
    runtime="bedrock_agentcore_runtime",
    post_execution_events=("agentcore_runtime_response_observed",),
    source_reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-how-it-works.html",
    required_permissions=("bedrock-agentcore:InvokeAgentRuntime",),
    claims=_claims(
        (CapabilityDimension.RUNTIME_IDENTITY, CapabilityLevel.OBSERVE),
        (CapabilityDimension.MODEL_ROUTE_BINDING, CapabilityLevel.OBSERVE),
        (CapabilityDimension.POST_EXECUTION_VISIBILITY, CapabilityLevel.OBSERVE),
    ),
    blind_spots=(
        _blind_spot(
            identifier="agentcore-hosting-is-not-tool-authorization",
            dimension=CapabilityDimension.FUNCTION_TOOL_CONTROL,
            scope="provider-hosted AgentCore Runtime",
            condition="AgentCore hosts customer agent or tool code",
            impact="Hosting does not infer Hawk tool, MCP, parameter, target, subject, approval, or execution authorization.",
            mitigation="Bind and accept a customer-controlled pre-execution adapter at the exact action executor.",
        ),
        _blind_spot(
            identifier="agentcore-direct-route-bypass-not-accepted",
            dimension=CapabilityDimension.BYPASS_DETECTION,
            scope="AgentCore runtime route",
            condition="Gateway, direct runtime, and alternate invocation paths have not been accepted",
            impact="Hawk cannot claim bypass resistance or Enforce eligibility.",
            mitigation="Prove the exact deployed entry path and all approved alternate routes.",
        ),
    ),
    failure_modes=("customer adapter omitted", "direct runtime route bypass", "real AWS acceptance missing"),
)


BEDROCK_ACTION_RUNTIME = _contract(
    descriptor_id="aws.bedrock_action_runtime.customer_executor",
    product="bedrock_action_runtime",
    method=ControlMethod.FUNCTION_MIDDLEWARE,
    action_classes=(ActionClass.FUNCTION_TOOL,),
    runtime_location=RuntimeLocation.CUSTOMER_CLOUD,
    deployment_family=DeploymentFamily.RUNTIME,
    runtime="bedrock_action_runtime_customer_executor",
    pre_execution_events=("before_customer_action_executor",),
    post_execution_events=("after_customer_action_executor",),
    source_reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-lambda.html",
    required_permissions=("lambda:InvokeFunction", "bedrock:InvokeAgent"),
    claims=_claims(
        (CapabilityDimension.FUNCTION_TOOL_CONTROL, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.FUNCTION_TOOL_PARAMETER_BINDING, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.FUNCTION_TOOL_TARGET_BINDING, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.RUNTIME_IDENTITY, CapabilityLevel.OBSERVE),
        (CapabilityDimension.POST_EXECUTION_VISIBILITY, CapabilityLevel.OBSERVE),
    ),
    blind_spots=(
        _blind_spot(
            identifier="bedrock-action-runtime-pre-executor-not-accepted",
            dimension=CapabilityDimension.FUNCTION_TOOL_CONTROL,
            scope="customer-owned action executor before business-operation invocation",
            condition="No real AWS pre-executor allow/block/non-execution acceptance",
            impact="The intended customer-controlled action boundary remains unavailable for Hawk Enforce.",
            mitigation="Install Hawk as the final pre-execution middleware around the customer action executor and accept its exact route.",
        ),
        _blind_spot(
            identifier="bedrock-action-runtime-post-lambda-cannot-prevent",
            dimension=CapabilityDimension.POST_EXECUTION_VERIFICATION,
            scope="Lambda/action-runtime completion",
            condition="The customer executor has already begun or completed",
            impact="Post-Lambda evidence cannot prevent the completed consequence and is never promoted as prevention.",
            mitigation="Authorize before invoking the customer executor and revalidate immediately before consequential downstream calls.",
        ),
        _blind_spot(
            identifier="bedrock-action-runtime-identity-not-customer-authority",
            dimension=CapabilityDimension.SUBJECT_BINDING,
            scope="AWS workload/runtime identity",
            condition="An IAM or runtime identity is available",
            impact="Workload identity does not prove end-customer subject, authority, or approval scope.",
            mitigation="Validate a separate trusted subject/authority assertion in the customer-controlled action service.",
        ),
    ),
    failure_modes=("middleware ordered before mutator", "post-Lambda-only observation", "direct executor bypass"),
    synchronous_decision_mechanism="customer-controlled final action executor; unverified",
)


BEDROCK_MCP = _contract(
    descriptor_id="aws.bedrock_mcp.customer_tool_loop",
    product="bedrock_mcp",
    method=ControlMethod.TOOL_LOOP_INTERCEPT,
    action_classes=(ActionClass.MCP,),
    runtime_location=RuntimeLocation.CUSTOMER_CLOUD,
    deployment_family=DeploymentFamily.RUNTIME,
    runtime="bedrock_mcp_customer_tool_loop",
    pre_execution_events=("before_customer_mcp_tool_call",),
    post_execution_events=("after_customer_mcp_tool_result",),
    source_reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agents-tools-runtime.html",
    required_permissions=("customer.mcp.invoke",),
    claims=_claims(
        (CapabilityDimension.MCP_CONTROL, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.PARAMETER_BINDING, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.TARGET_BINDING, CapabilityLevel.INLINE_BOUND),
    ),
    blind_spots=(
        _blind_spot(
            identifier="bedrock-mcp-customer-loop-not-accepted",
            dimension=CapabilityDimension.MCP_CONTROL,
            scope="customer-controlled MCP tool loop or gateway binding",
            condition="No exact MCP server, schema, tool, route, allow/block/non-execution acceptance",
            impact="MCP control remains unverified and cannot become Hawk Enforce coverage.",
            mitigation="Accept the exact customer MCP client/server path and schema fingerprint before Enforce.",
        ),
        _blind_spot(
            identifier="bedrock-mcp-hosted-tool-inference-prohibited",
            dimension=CapabilityDimension.FUNCTION_TOOL_CONTROL,
            scope="AgentCore or provider-hosted MCP target",
            condition="An MCP target is provider-hosted or directly reachable",
            impact="Provider hosting does not infer Hawk authorization of a tool, target service, or post-tool execution.",
            mitigation="Use an accepted customer-controlled MCP intercept and target-service revalidation.",
        ),
    ),
    failure_modes=("MCP tool loop omitted", "direct target bypass", "schema or route drift"),
    synchronous_decision_mechanism="customer-controlled MCP tool loop; unverified",
)


BEDROCK_AGENTCORE_MCP_GATEWAY = _contract(
    descriptor_id="aws.bedrock_agentcore_mcp_gateway.provider_hosted",
    product="bedrock_agentcore_mcp_gateway",
    method=ControlMethod.SAAS_CONTROL_API,
    action_classes=(ActionClass.MCP,),
    runtime_location=RuntimeLocation.PROVIDER_HOSTED,
    deployment_family=DeploymentFamily.SAAS_API,
    runtime="bedrock_agentcore_mcp_gateway",
    pre_execution_events=("before_agentcore_gateway_mcp_call",),
    post_execution_events=("agentcore_gateway_mcp_result_observed",),
    source_reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/use-gateway-with-policy.html",
    required_permissions=("bedrock-agentcore:InvokeGateway",),
    claims=_claims(
        (CapabilityDimension.HOSTED_MCP_CONTROL, CapabilityLevel.EXTERNAL),
        (CapabilityDimension.PROVIDER_PERMISSION_CONTEXT, CapabilityLevel.OBSERVE),
        (CapabilityDimension.POST_EXECUTION_VISIBILITY, CapabilityLevel.OBSERVE),
    ),
    blind_spots=(
        _blind_spot(
            identifier="agentcore-gateway-mcp-policy-not-accepted",
            dimension=CapabilityDimension.HOSTED_MCP_CONTROL,
            scope="provider-hosted AgentCore Gateway MCP tools/call path",
            condition="No exact gateway, policy, principal, tool, arguments, target, allow/block, and protected non-execution acceptance",
            impact="The provider-hosted gateway remains unverified and cannot become Hawk Enforce coverage.",
            mitigation="Accept the exact AgentCore Gateway and provider-policy route in the customer account before promotion.",
        ),
        _blind_spot(
            identifier="agentcore-gateway-non-tool-operations-not-policy-controlled",
            dimension=CapabilityDimension.MCP_CONTROL,
            scope="AgentCore Gateway MCP prompts and resources",
            condition="Provider policy applies to MCP tools while prompt and resource operations remain outside that policy boundary",
            impact="Hosted MCP control cannot be generalized to every MCP operation or exact Hawk parameter, target, subject, approval, and execution binding.",
            mitigation="Represent provider-hosted tools separately and compose customer MCP/runtime or target-service controls for stronger semantics.",
        ),
    ),
    failure_modes=(
        "AgentCore Gateway policy omitted or monitor-only",
        "direct target or alternate gateway bypass",
        "tool schema, principal, or route drift",
    ),
    synchronous_decision_mechanism="provider-hosted AgentCore Gateway MCP tool policy; unverified",
)


BEDROCK_KNOWLEDGE_BASE = _contract(
    descriptor_id="aws.bedrock_knowledge_base.retrieval_context",
    product="bedrock_knowledge_base",
    method=ControlMethod.SAAS_CONTROL_API,
    action_classes=(ActionClass.MODEL_REQUEST,),
    runtime_location=RuntimeLocation.PROVIDER_HOSTED,
    deployment_family=DeploymentFamily.SAAS_API,
    runtime="bedrock_knowledge_base",
    post_execution_events=("after_knowledge_base_retrieval",),
    source_reference="https://docs.aws.amazon.com/bedrock/latest/userguide/kb-how-retrieval.html",
    required_permissions=("bedrock:Retrieve", "bedrock:RetrieveAndGenerate"),
    claims=_claims(
        (CapabilityDimension.DISCOVERY, CapabilityLevel.OBSERVE),
        (CapabilityDimension.POST_EXECUTION_VISIBILITY, CapabilityLevel.OBSERVE),
    ),
    blind_spots=(
        _blind_spot(
            identifier="bedrock-knowledge-base-is-not-action-authorization",
            dimension=CapabilityDimension.FUNCTION_TOOL_CONTROL,
            scope="knowledge-base retrieval and generated context",
            condition="Retrieved material can influence an agent action",
            impact="Knowledge-base configuration does not authorize tools, parameters, targets, subjects, approvals, or execution.",
            mitigation="Compose an accepted action executor and target-service control point.",
        ),
        _blind_spot(
            identifier="bedrock-knowledge-base-direct-query-bypass",
            dimension=CapabilityDimension.BYPASS_DETECTION,
            scope="knowledge-base query routes",
            condition="Direct query or alternate API route has not been accepted",
            impact="Hawk cannot claim a governed retrieval path.",
            mitigation="Prove exact retrieval route and direct-bypass behavior in the customer account.",
        ),
    ),
    failure_modes=("direct knowledge-base query bypass", "retrieval configuration drift", "acceptance missing"),
)


BEDROCK_AGENTS_CLASSIC_EXISTING = _contract(
    descriptor_id="aws.bedrock_agents_classic.compatibility_only",
    product="bedrock_agents_classic",
    method=ControlMethod.AGENT_MIDDLEWARE,
    action_classes=(ActionClass.MODEL_REQUEST,),
    runtime_location=RuntimeLocation.PROVIDER_HOSTED,
    deployment_family=DeploymentFamily.SAAS_API,
    runtime="bedrock_agents_classic",
    post_execution_events=("classic_agent_response_observed",),
    source_reference="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-action-create.html",
    required_permissions=("bedrock:InvokeAgent",),
    claims=_unavailable_claims(),
    blind_spots=(
        _blind_spot(
            identifier="bedrock-agents-classic-maintenance-only",
            dimension=CapabilityDimension.MODEL_ROUTE_BINDING,
            scope="existing Bedrock Agents Classic deployment",
            condition="Classic is in maintenance mode and is maintained independently from AgentCore and customer action runtimes",
            impact="Classic receives compatibility-only inventory; it does not inherit AgentCore, action-runtime, or MCP control claims.",
            mitigation="Create a separately accepted Classic control path or migrate and accept the target architecture.",
        ),
        _blind_spot(
            identifier="bedrock-agents-classic-direct-bypass",
            dimension=CapabilityDimension.BYPASS_DETECTION,
            scope="Classic agent invocation and action groups",
            condition="No exact customer route and executor acceptance",
            impact="No Hawk Enforce or bypass-resistance claim is available.",
            mitigation="Validate the exact existing deployment separately; no inheritance is permitted.",
        ),
    ),
    failure_modes=("classic configuration drift", "direct action group execution", "no accepted boundary"),
)


CUSTOM_BEDROCK_AGENT = _contract(
    descriptor_id="aws.custom_bedrock_agent.customer_runtime",
    product="custom_bedrock_agent",
    method=ControlMethod.AGENT_MIDDLEWARE,
    action_classes=(ActionClass.FUNCTION_TOOL, ActionClass.MCP),
    runtime_location=RuntimeLocation.CUSTOMER_CLOUD,
    deployment_family=DeploymentFamily.RUNTIME,
    runtime="custom_bedrock_agent_customer_runtime",
    pre_execution_events=("before_customer_agent_action",),
    post_execution_events=("after_customer_agent_action",),
    source_reference="https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agents-tools-runtime.html",
    required_permissions=("customer.agent.runtime.invoke",),
    claims=_claims(
        (CapabilityDimension.FUNCTION_TOOL_CONTROL, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.MCP_CONTROL, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.PARAMETER_BINDING, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.TARGET_BINDING, CapabilityLevel.INLINE_BOUND),
        (CapabilityDimension.RUNTIME_IDENTITY, CapabilityLevel.OBSERVE),
        (CapabilityDimension.POST_EXECUTION_VISIBILITY, CapabilityLevel.OBSERVE),
    ),
    blind_spots=(
        _blind_spot(
            identifier="custom-bedrock-agent-boundary-not-accepted",
            dimension=CapabilityDimension.FUNCTION_TOOL_CONTROL,
            scope="customer-built agent and action loop hosted with Bedrock/AgentCore",
            condition="The customer does not provide a signed Hawk-bound final action gate and real AWS acceptance",
            impact="Custom-agent actions remain unverified and cannot become provider-hosted Hawk authorization.",
            mitigation="Install Hawk as final customer action middleware, validate tenant/subject separately, and accept allow/block/non-execution.",
        ),
        _blind_spot(
            identifier="custom-bedrock-agent-direct-bypass",
            dimension=CapabilityDimension.BYPASS_DETECTION,
            scope="custom agent, direct provider API, and target service routes",
            condition="An alternate route can avoid the customer action middleware",
            impact="Hawk cannot claim whole-agent coverage or Enforce eligibility.",
            mitigation="Prove required entry paths, direct-route resistance, and target-service revalidation.",
        ),
    ),
    failure_modes=("customer action gate omitted", "direct Bedrock route bypass", "target-service bypass"),
    synchronous_decision_mechanism="customer-controlled final agent action gate; unverified",
)


_PROFILES = (
    AWSBedrockControlProfile(BEDROCK_MODEL_API, ControlMethod.API_INTERCEPT),
    AWSBedrockControlProfile(BEDROCK_GUARDRAIL, ControlMethod.SAAS_CONTROL_API),
    AWSBedrockControlProfile(BEDROCK_AGENTCORE, ControlMethod.SAAS_CONTROL_API),
    AWSBedrockControlProfile(BEDROCK_ACTION_RUNTIME, ControlMethod.FUNCTION_MIDDLEWARE),
    AWSBedrockControlProfile(BEDROCK_MCP, ControlMethod.TOOL_LOOP_INTERCEPT),
    AWSBedrockControlProfile(BEDROCK_AGENTCORE_MCP_GATEWAY, ControlMethod.SAAS_CONTROL_API),
    AWSBedrockControlProfile(BEDROCK_KNOWLEDGE_BASE, ControlMethod.SAAS_CONTROL_API),
    AWSBedrockControlProfile(BEDROCK_AGENTS_CLASSIC_EXISTING, ControlMethod.AGENT_MIDDLEWARE),
    AWSBedrockControlProfile(CUSTOM_BEDROCK_AGENT, ControlMethod.AGENT_MIDDLEWARE),
)


def aws_bedrock_control_profiles() -> tuple[AWSBedrockControlProfile, ...]:
    return _PROFILES


def aws_bedrock_provider_profiles():
    return tuple(profile.provider_profile() for profile in _PROFILES)
