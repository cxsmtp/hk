from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import hashlib
import json
import re
import shutil
import subprocess
from typing import Any, Mapping

from app.core.control_engine.authorization import AuthorizationResponse
from app.services.native_control.adapter_contract import (
    AdapterDescriptor,
    AdapterError,
    AdapterErrorCode,
    AdapterMaturity,
    AdapterPipelineContext,
    CapabilityManifest,
    DeploymentFamily,
    EvidenceQuality,
    EventSemantics,
    NativeControlEvent,
    SelectionCharacteristics,
    StructuredBlindSpot,
    TimeoutBudget,
    stable_hash,
)
from app.services.native_control.contracts import (
    ActionClass,
    CapabilityClaim,
    CapabilityDimension,
    CapabilityLevel,
    ControlMethod,
    ControlPointHealth,
    DegradationMode,
    HealthState,
    RuntimeLocation,
    SecurityProperties,
    VerificationStatus,
)
from app.services.native_control.codex_acceptance_registry import (
    load_codex_acceptance_registry,
)
from app.services.native_control.openai_action_matrix import (
    OpenAIActionClass,
    OpenAIActionControlProfile,
    build_openai_action_control_matrix,
)


_ADAPTER_VERSION = "1.0.0"
_CODEX_HOOKS_VERSION = "0.154.0"
_CODEX_ACCEPTANCE_REGISTRY = load_codex_acceptance_registry()
_CODEX_ACCEPTANCE = _CODEX_ACCEPTANCE_REGISTRY.entry(
    _CODEX_HOOKS_VERSION,
    adapter_version=_ADAPTER_VERSION,
)
_CODEX_EXACT_VERIFIED_VERSIONS = _CODEX_ACCEPTANCE_REGISTRY.accepted_versions(
    adapter_version=_ADAPTER_VERSION,
)
_CODEX_CONTRACT_VERIFIED = _CODEX_ACCEPTANCE is not None
_MATRIX = build_openai_action_control_matrix()
_SENSITIVE_KEY = re.compile(
    r"(?:api[_-]?key|secret|token|password|authorization|cookie|credential|private[_-]?key)",
    re.IGNORECASE,
)


def _claim(
    level: CapabilityLevel,
    status: VerificationStatus = VerificationStatus.EXPERIMENTAL,
    *refs: str,
) -> CapabilityClaim:
    return CapabilityClaim(level=level, verification_status=status, evidence_refs=tuple(refs))


def _unknown_claims() -> dict[CapabilityDimension, CapabilityClaim]:
    return {
        dimension: _claim(CapabilityLevel.UNKNOWN, VerificationStatus.UNVERIFIED)
        for dimension in CapabilityDimension
    }


def _bounded_json(value: Any) -> None:
    try:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED) from exc
    if len(payload) > 65_536:
        raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED, safe_diagnostic="event_too_large")


def _scrub_value(value: Any, *, key: str = "", depth: int = 0) -> Any:
    if depth > 8:
        return "[DEPTH_LIMIT]"
    if _SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return value if len(value) <= 256 else f"[HASH:{stable_hash(value)}]"
    if isinstance(value, Mapping):
        return {
            str(child_key)[:128]: _scrub_value(child, key=str(child_key), depth=depth + 1)
            for child_key, child in sorted(value.items(), key=lambda row: str(row[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_scrub_value(child, key=key, depth=depth + 1) for child in value[:128]]
    return f"[TYPE:{type(value).__name__}]"


def _action_class(raw: object) -> OpenAIActionClass:
    try:
        return OpenAIActionClass(str(raw or "").strip().lower())
    except ValueError:
        return OpenAIActionClass.UNKNOWN_TOOL


def _lifecycle(product: str, event_type: str) -> str:
    value = event_type.strip().lower()
    if product == "codex":
        return {
            "userpromptsubmit": "before_model",
            "pretooluse": "before_tool",
            "permissionrequest": "approval",
            "posttooluse": "after_tool",
            "precompact": "pre_compact",
            "postcompact": "post_compact",
            "sessionstart": "session_start",
            "sessionend": "session_end",
            "subagentstart": "delegation_start",
            "subagentstop": "delegation_end",
            "stop": "after_agent",
            "interrupt": "session_interrupt",
        }.get(value, "unknown")
    return {
        "run_start": "session_start",
        "agent_start": "before_agent",
        "llm_start": "before_model",
        "function_tool_input": "before_tool",
        "tool_approval": "approval",
        "function_tool_output": "after_tool",
        "llm_end": "after_model",
        "agent_end": "after_agent",
        "handoff": "delegation",
        "run_end": "session_end",
        "responses_request": "before_model",
        "responses_chunk": "after_model",
        "tool_proposal": "before_tool",
        "tool_result": "after_tool",
    }.get(value, "unknown")


def _codex_execution_facts(raw_payload: Mapping[str, Any]) -> tuple[str, bool]:
    """Keep local Codex initiation distinct from the action's execution site."""

    location = str(raw_payload.get("execution_location") or "").strip().lower()
    if location in {"local", "local_endpoint"}:
        return "codex_cli_local", True
    if location in {"remote", "remote_agent", "provider_hosted", "customer_cloud"}:
        return "codex_remote", False
    return "codex_unknown_runtime", False


def _normalize(
    *,
    product: str,
    raw_payload: Mapping[str, Any],
    context: AdapterPipelineContext,
) -> NativeControlEvent:
    if not isinstance(raw_payload, Mapping):
        raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED)
    _bounded_json(raw_payload)
    event_type = str(raw_payload.get("event_type") or raw_payload.get("hook_event_name") or "").strip()
    if not event_type:
        raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED, safe_diagnostic="event_type_required")
    lifecycle = _lifecycle(product, event_type)
    if lifecycle == "unknown":
        raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED, safe_diagnostic="event_type_unknown")
    action_class = _action_class(raw_payload.get("tool_class") or raw_payload.get("action_class"))
    tool_name = str(raw_payload.get("tool_name") or "unknown")[:256]
    arguments = raw_payload.get("arguments", raw_payload.get("tool_input", {}))
    if not isinstance(arguments, Mapping):
        arguments = {"value_hash": stable_hash(arguments)}
    canonical_arguments = _scrub_value(arguments)
    parameter_hash = stable_hash(arguments)
    target = str(raw_payload.get("target") or raw_payload.get("workspace") or "unknown")[:512]
    destination = str(
        raw_payload.get("destination")
        or raw_payload.get("server_url")
        or raw_payload.get("mcp_server")
        or "unknown"
    )[:512]
    provider_tool_call = str(
        raw_payload.get("tool_call_id")
        or raw_payload.get("tool_use_id")
        or context.provider_event_id
    )[:512]
    agent_id = str(raw_payload.get("agent_id") or raw_payload.get("agent_name") or "unknown")[:512]
    persistent = raw_payload.get("persistent_side_effect") is True or action_class in {
        OpenAIActionClass.APPLY_PATCH,
    }
    if action_class is OpenAIActionClass.UNKNOWN_TOOL and product == "codex":
        lowered = tool_name.lower()
        action_class = (
            OpenAIActionClass.LOCAL_SHELL
            if lowered == "bash"
            else OpenAIActionClass.APPLY_PATCH
            if lowered == "apply_patch"
            else OpenAIActionClass.LOCAL_MCP
            if lowered.startswith("mcp__")
            else OpenAIActionClass.AGENT_AS_TOOL
            if lowered in {"agent", "spawn_agent"}
            else OpenAIActionClass.UNKNOWN_TOOL
        )
    if action_class is OpenAIActionClass.UNKNOWN_TOOL and lifecycle == "before_model":
        action_class = OpenAIActionClass.MODEL_REQUEST
    elif action_class is OpenAIActionClass.UNKNOWN_TOOL and lifecycle == "after_model":
        action_class = OpenAIActionClass.MODEL_RESPONSE
    action_type = (
        "prompt"
        if lifecycle in {"before_agent", "before_model"}
        else "model_response"
        if lifecycle in {"after_agent", "after_model"}
        else "tool_execution"
    )
    runtime_profile, endpoint_execution_authority = (
        _codex_execution_facts(raw_payload)
        if product == "codex"
        else ("not_applicable", False)
    )
    return NativeControlEvent(
        tenant_id=context.tenant_id,
        integration_instance_id=context.integration_instance_id,
        provider="openai",
        product=product,
        raw_provider_event_type=event_type,
        provider_event_id=context.provider_event_id,
        provider_version=context.provider_version,
        adapter_version=_ADAPTER_VERSION,
        lifecycle_stage=lifecycle,
        actor={
            **dict(context.resolved_actor),
            "agent_id_hash": stable_hash(agent_id),
        },
        session={
            "session_id": context.session_id,
            "run_id_hash": stable_hash(raw_payload.get("run_id") or context.session_id),
            "trace_id_hash": stable_hash(raw_payload.get("trace_id") or context.correlation_id),
        },
        runtime={
            "environment": context.environment,
            "credential_id": context.credential_id,
            "correlation_id": context.correlation_id,
            "execution_location": str(raw_payload.get("execution_location") or "unknown")[:64],
            "runtime_profile": runtime_profile,
            # This is an observed execution-location classification only. The
            # endpoint floor is still selected and validated independently.
            "endpoint_execution_authority": endpoint_execution_authority,
            "approval_state": str(raw_payload.get("approval_state") or "none")[:64],
            "integration_method": (
                ControlMethod.NATIVE_HOOK.value
                if product == "codex"
                else ControlMethod.GATEWAY_INLINE.value
                if product == "direct_api"
                else ControlMethod.SDK_MIDDLEWARE.value
            ),
        },
        tool={
            "name": tool_name,
            "version": str(raw_payload.get("tool_version") or "unknown")[:128],
            "fingerprint_id": stable_hash(
                {
                    "tool_name": tool_name,
                    "tool_schema": raw_payload.get("tool_schema") or {},
                    "action_class": action_class.value,
                }
            ),
        },
        # Product identity, model route and execution location are different
        # facts.  In particular, a local Codex client can submit a request to
        # a non-OpenAI model route while the consequential action executes in
        # a remote runtime.  Preserve the provider-reported route separately;
        # downstream control selection must still validate the execution
        # location rather than treating this metadata as local authority.
        model={
            "provider": str(raw_payload.get("model_provider") or "unknown")[:256],
            "name": str(raw_payload.get("model") or "unknown")[:256],
            "deployment": str(
                raw_payload.get("model_deployment")
                or raw_payload.get("model_route")
                or "unknown"
            )[:256],
        },
        mcp={
            "server_id": str(raw_payload.get("mcp_server") or "unknown")[:256],
            "server_url_hash": stable_hash(raw_payload.get("server_url") or "unknown"),
            "tool_name": tool_name if action_class in {OpenAIActionClass.LOCAL_MCP, OpenAIActionClass.HOSTED_MCP} else "unknown",
        },
        action={
            "action_type": action_type,
            "action_class": action_class.value,
            "canonical_parameters": canonical_arguments,
            "parameter_hash": parameter_hash,
            "approval_action_hash": stable_hash(
                {"tool": tool_name, "arguments": arguments, "target": target, "destination": destination}
            ),
            "business_purpose_hash": stable_hash(raw_payload.get("business_purpose") or "unknown"),
        },
        target={
            "resource": target,
            "canonical_target": target,
            "resource_hash": stable_hash(target),
        },
        destination={
            "destination": destination,
            "destination_hash": stable_hash(destination),
        },
        side_effect_class="persistent" if persistent else "read_or_ephemeral",
        persistence={"persistent_side_effect": persistent},
        provider_correlation={
            "chain_id": context.chain_id,
            "correlation_id": context.correlation_id,
            "provider_tool_call_hash": stable_hash(provider_tool_call),
        },
        timing={
            "received_at": context.received_at,
            "pre_execution": lifecycle.startswith("before_") or lifecycle == "approval",
        },
        integrity={
            "transport": context.transport.value,
            "transport_authenticated": context.transport_authenticated,
            "signature_valid": context.signature_valid,
            "nonce_hash": stable_hash(context.nonce),
        },
        policy_snapshot_id=context.policy_snapshot_id,
        policy_profile=deepcopy(context.policy_profile),
    )


def _security(
    *,
    pre: bool,
    post: bool,
    latency: int,
    blocking: int,
    bypass: int,
    privacy: str,
) -> SecurityProperties:
    return SecurityProperties(
        pre_execution_capable=pre,
        post_execution_capable=post,
        blocking_strength=blocking,
        action_fidelity=90,
        identity_quality=80,
        parameter_fidelity=90,
        target_fidelity=70,
        destination_fidelity=70,
        result_fidelity=60,
        bypass_resistance=bypass,
        tamper_resistance=80,
        expected_latency_ms=latency,
        availability_profile="synchronous_bound_control",
        required_permissions=("hawk.policy.evaluate",),
        privacy_impact=privacy,
    )


def _blind_spot(identifier: str, scope: str, impact: str, mitigation: str) -> StructuredBlindSpot:
    return StructuredBlindSpot(
        id=identifier,
        control_dimension=CapabilityDimension.BYPASS_DETECTION,
        scope=scope,
        condition=impact,
        impact=impact,
        detection_method="Hawk route, version, configuration-integrity and endpoint discovery evidence",
        mitigation=mitigation,
        evidence=("repo:apps/api/tests/test_native_control_openai_action_matrix.py",),
    )


class _OpenAIAdapterBase:
    descriptor: AdapterDescriptor
    manifest: CapabilityManifest
    matrix_method: ControlMethod

    def limitations(self) -> tuple[StructuredBlindSpot, ...]:
        return self.manifest.known_blind_spots

    def supported_versions(self) -> tuple[str, str]:
        return self.manifest.provider_version_min, self.manifest.provider_version_max

    def decision_deadline_ms(self) -> int:
        return 5_000

    def timeout_budget(self) -> TimeoutBudget:
        return TimeoutBudget(
            provider_timeout_ms=4_000,
            hawk_processing_budget_ms=500,
            response_deadline_ms=5_000,
        )

    def action_profile(self, action_class: OpenAIActionClass | str) -> OpenAIActionControlProfile:
        return _MATRIX.resolve(self.descriptor.product_family, action_class, self.matrix_method)

    def health(self) -> ControlPointHealth:
        accepted = self.manifest.verification_status is VerificationStatus.VERIFIED
        return ControlPointHealth(
            state=HealthState.HEALTHY if accepted else HealthState.UNVERIFIED,
            callback_authenticated=accepted,
            validation_current=accepted,
            evidence_flowing=accepted,
            configuration_integrity_valid=accepted,
            policy_fresh=accepted,
            observed_latency_ms=self.manifest.security_properties.expected_latency_ms,
            reason_codes=() if accepted else ("real_acceptance_required",),
        )

    def format_approval_pause(self, response: AuthorizationResponse) -> dict[str, Any]:
        if response.decision not in {"review", "require_approval", "require_second_approval"}:
            raise AdapterError(AdapterErrorCode.ENFORCEMENT_SEMANTIC_UNAVAILABLE)
        return {
            "behavior": "pause",
            "approval_kind": response.decision,
            "reason": response.reason,
            "policy_snapshot_id": response.policy_snapshot_id,
        }


class OpenAIAgentsSDKControlAdapter(_OpenAIAdapterBase):
    descriptor = AdapterDescriptor(
        adapter_id="openai.agents-sdk.control",
        provider_family="openai",
        product_family="agents_sdk",
        adapter_version=_ADAPTER_VERSION,
        deployment_families_supported=(DeploymentFamily.RUNTIME,),
        enforcement_methods_supported=(ControlMethod.SDK_MIDDLEWARE, ControlMethod.AGENT_MIDDLEWARE),
        event_schema_version="openai-agents-sdk/hawk-v1",
        minimum_hawk_version="1.0.0",
        maturity=AdapterMaturity.EXPERIMENTAL,
        description="Action-class-bound OpenAI Agents SDK guardrail and approval integration.",
    )
    matrix_method = ControlMethod.SDK_MIDDLEWARE
    _claims = _unknown_claims()
    _claims.update(
        {
            CapabilityDimension.DISCOVERY: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.IDENTITY: _claim(CapabilityLevel.OBSERVE),
            # RunHooks/AgentHooks are lifecycle observability, not an
            # authorization boundary. Action-specific guardrail claims are
            # supplied only by the OpenAI action matrix.
            CapabilityDimension.MODEL_REQUEST_CONTROL: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.MODEL_RESPONSE_CONTROL: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.POST_EXECUTION_VISIBILITY: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.EXECUTION_CORRELATION: _claim(CapabilityLevel.OBSERVE),
        }
    )
    manifest = CapabilityManifest(
        schema_version="native-control-adapter-manifest/1.0",
        descriptor_id=descriptor.adapter_id,
        provider="openai",
        product="agents_sdk",
        # Function-tool acceptance is currently bound to one reviewed SDK
        # release.  A protocol-compatible newer SDK must re-enter validation;
        # it cannot inherit this action-specific evidence by range alone.
        provider_version_min="0.20.0",
        provider_version_max="0.20.0",
        exact_verified_versions=("0.20.0",),
        adapter_version=_ADAPTER_VERSION,
        verification_status=VerificationStatus.EXPERIMENTAL,
        verified_at=None,
        source_reference="https://openai.github.io/openai-agents-python/guardrails/",
        capabilities=_claims,
        security_properties=_security(
            pre=True,
            post=True,
            latency=100,
            blocking=75,
            bypass=45,
            privacy="bounded action metadata and hashes; no hidden reasoning or raw secrets",
        ),
        required_permissions=("sdk.guardrail.register", "hawk.policy.evaluate"),
        event_semantics=EventSemantics(
            pre_execution_events=("function_tool_input", "tool_approval"),
            post_execution_events=("function_tool_output", "llm_end", "agent_end"),
            normalized_fields=(
                "identity",
                "canonical_parameters",
                "parameter_hash",
                "canonical_target",
                "target_hash",
                "destination_hash",
                "action_correlation",
            ),
            synchronous_decision_mechanism="Agents SDK function-tool input guardrail or HITL interruption",
        ),
        known_blind_spots=(
            _blind_spot(
                "openai.agents-sdk.tool-class",
                "Agents SDK non-function tool classes",
                "Function-tool guardrails do not cover hosted tools, shell, patch, computer, handoff, or Agent.as_tool.",
                "Resolve the exact action class through the OpenAI matrix and select its own verified control point.",
            ),
        ),
        failure_modes=(
            "application omits Hawk SDK binding",
            "unsupported SDK version",
            "authorization callback unavailable",
            "approval action hash changes before execution",
        ),
        supported_installation_modes=("application_dependency", "runtime_middleware"),
        supported_degradation_modes=(DegradationMode.FAIL_CLOSED,),
        execution_evidence_quality=EvidenceQuality.PROVIDER_REPORTED,
        selection_characteristics=SelectionCharacteristics(20, 45, 35, 30, 45),
    )

    def normalize_event(
        self,
        raw_payload: Mapping[str, Any],
        context: AdapterPipelineContext,
    ) -> NativeControlEvent:
        return _normalize(product="agents_sdk", raw_payload=raw_payload, context=context)

    def format_decision_response(self, response: AuthorizationResponse) -> dict[str, Any]:
        if response.decision == "allow":
            return {"behavior": "allow", "output_info": {"hawk_decision": "allow"}}
        if response.decision == "block":
            return {
                "behavior": "raise_exception",
                "message": response.reason,
                "output_info": {"hawk_decision": "block"},
            }
        if response.decision == "warn":
            return {
                "behavior": "allow",
                "output_info": {"hawk_decision": "warn", "message": response.reason},
            }
        raise AdapterError(
            AdapterErrorCode.ENFORCEMENT_SEMANTIC_UNAVAILABLE,
            safe_diagnostic=f"agents_sdk_guardrail_cannot_express:{response.decision}",
        )

    def validation_probe(self) -> dict[str, bool]:
        return {name: False for name in (
            "environment", "installation", "authentication", "replay_defense", "event_delivery",
            "normalization", "safe_allow", "safe_deny", "policy_callback", "configuration_integrity", "privacy",
        )}


class CodexNativeControlAdapter(_OpenAIAdapterBase):
    descriptor = AdapterDescriptor(
        adapter_id="openai.codex.native-hooks",
        provider_family="openai",
        product_family="codex",
        adapter_version=_ADAPTER_VERSION,
        deployment_families_supported=(DeploymentFamily.ENDPOINT,),
        enforcement_methods_supported=(ControlMethod.NATIVE_HOOK,),
        event_schema_version=f"codex-hooks/{_CODEX_HOOKS_VERSION}",
        minimum_hawk_version="1.0.0",
        maturity=(
            AdapterMaturity.PRODUCTION
            if _CODEX_CONTRACT_VERIFIED
            else AdapterMaturity.EXPERIMENTAL
        ),
        description="Hash-bound exact-version local Codex lifecycle hook adapter; hosted and cloud paths remain separate.",
    )
    matrix_method = ControlMethod.NATIVE_HOOK
    _claims = _unknown_claims()
    _claims.update(
        {
            CapabilityDimension.DISCOVERY: _claim(
                CapabilityLevel.OBSERVE,
                VerificationStatus.VERIFIED if _CODEX_CONTRACT_VERIFIED else VerificationStatus.EXPERIMENTAL,
                "repo:docs/evidence/codex-acceptance-registry.json",
            ),
            CapabilityDimension.IDENTITY: _claim(
                CapabilityLevel.OBSERVE,
                VerificationStatus.VERIFIED if _CODEX_CONTRACT_VERIFIED else VerificationStatus.EXPERIMENTAL,
                "repo:docs/evidence/codex-acceptance-registry.json",
            ),
            CapabilityDimension.PROMPT_CONTROL: _claim(
                CapabilityLevel.INLINE_BOUND,
                VerificationStatus.VERIFIED if _CODEX_CONTRACT_VERIFIED else VerificationStatus.EXPERIMENTAL,
                "repo:docs/evidence/codex-acceptance-registry.json",
            ),
            CapabilityDimension.POST_EXECUTION_VISIBILITY: _claim(CapabilityLevel.OBSERVE),
            CapabilityDimension.CONFIG_INTEGRITY: _claim(CapabilityLevel.INLINE_BOUND),
            CapabilityDimension.BYPASS_DETECTION: _claim(CapabilityLevel.OBSERVE),
        }
    )
    manifest = CapabilityManifest(
        schema_version="native-control-adapter-manifest/1.0",
        descriptor_id=descriptor.adapter_id,
        provider="openai",
        product="codex",
        provider_version_min=_CODEX_HOOKS_VERSION,
        provider_version_max=_CODEX_HOOKS_VERSION,
        exact_verified_versions=_CODEX_EXACT_VERIFIED_VERSIONS,
        adapter_version=_ADAPTER_VERSION,
        verification_status=(
            VerificationStatus.VERIFIED
            if _CODEX_CONTRACT_VERIFIED
            else VerificationStatus.EXPERIMENTAL
        ),
        verified_at=(
            _CODEX_ACCEPTANCE.evidence_timestamp
            if _CODEX_ACCEPTANCE is not None
            else None
        ),
        source_reference="repo:docs/evidence/codex-acceptance-registry.json",
        capabilities=_claims,
        security_properties=_security(
            pre=True,
            post=False,
            latency=5_000,
            blocking=80,
            bypass=55,
            privacy="bounded hashes and action metadata; raw prompt export is excluded by acceptance",
        ),
        required_permissions=("codex.hooks.configure", "hawk.callback.send"),
        event_semantics=EventSemantics(
            pre_execution_events=("UserPromptSubmit",),
            post_execution_events=(),
            normalized_fields=(
                "identity",
                "canonical_parameters",
                "parameter_hash",
                "canonical_target",
                "target_hash",
                "destination_hash",
                "action_correlation",
            ),
            synchronous_decision_mechanism="Codex synchronous command hook deny or exit code 2",
            ordering_guaranteed=False,
        ),
        known_blind_spots=(
            _blind_spot(
                "openai.codex.hosted-tool-bypass",
                "Codex hosted tools and cloud execution",
                "Hosted tools do not traverse local PreToolUse/PostToolUse and local endpoint control does not prove cloud execution control.",
                "Use gateway, provider control, or a verified remote runtime boundary.",
            ),
        ),
        failure_modes=("hook removed", "hook untrusted", "callback unavailable", "version mismatch"),
        supported_installation_modes=("user_hooks", "project_hooks", "managed_requirements_hooks"),
        supported_degradation_modes=(DegradationMode.FAIL_CLOSED,),
        execution_evidence_quality=(
            EvidenceQuality.HAWK_OBSERVED
            if _CODEX_CONTRACT_VERIFIED
            else EvidenceQuality.PROVIDER_REPORTED
        ),
        selection_characteristics=SelectionCharacteristics(25, 40, 45, 25, 40),
        supported_action_classes=(
            (ActionClass.MODEL_REQUEST,)
            if _CODEX_CONTRACT_VERIFIED
            else (ActionClass.UNKNOWN_ACTION,)
        ),
        supported_runtime_locations=(RuntimeLocation.LOCAL_ENDPOINT,),
        supported_deployment_families=(DeploymentFamily.ENDPOINT,),
        supported_runtimes=("codex_cli_local",),
        supported_control_methods=(ControlMethod.NATIVE_HOOK,),
        supported_lifecycle_events=(
            _CODEX_ACCEPTANCE.tested_events
            if _CODEX_ACCEPTANCE is not None
            else ()
        ),
        retry_semantics="fresh signed callback required for each prompt lifecycle event",
        failure_semantics="pre-model callback failure blocks in fail-secure mode",
        privacy_profile="hashed prompt/action metadata; raw prompt excluded",
        reviewed_by=("hawk-provider-contract-review" if _CODEX_CONTRACT_VERIFIED else None),
        reviewed_at=(
            _CODEX_ACCEPTANCE.evidence_timestamp
            if _CODEX_ACCEPTANCE is not None
            else None
        ),
        reviewed_evidence_refs=(
            (
                "repo:docs/evidence/codex-acceptance-registry.json",
                f"repo:{_CODEX_ACCEPTANCE.evidence_artifact}",
                f"binary-sha256:{_CODEX_ACCEPTANCE.binary_sha256}",
                f"report-sha256:{_CODEX_ACCEPTANCE.report_sha256}",
            )
            if _CODEX_ACCEPTANCE is not None
            else ()
        ),
    )

    def normalize_event(
        self,
        raw_payload: Mapping[str, Any],
        context: AdapterPipelineContext,
    ) -> NativeControlEvent:
        payload = dict(raw_payload)
        payload.setdefault("event_type", payload.get("hook_event_name"))
        return _normalize(product="codex", raw_payload=payload, context=context)

    def format_decision_response(self, response: AuthorizationResponse) -> dict[str, Any]:
        if response.decision == "block":
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": response.reason,
                }
            }
        if response.decision == "allow":
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                }
            }
        if response.decision in {"require_approval", "require_second_approval", "review"}:
            raise AdapterError(
                AdapterErrorCode.ENFORCEMENT_SEMANTIC_UNAVAILABLE,
                safe_diagnostic="PreToolUse cannot express ask; use PermissionRequest",
            )
        return {"systemMessage": response.reason}

    def detect_environment(self) -> dict[str, Any]:
        binary = shutil.which("codex")
        version = "unknown"
        binary_sha256 = "unknown"
        if binary:
            resolved = Path(binary).resolve()
            try:
                binary_sha256 = hashlib.sha256(resolved.read_bytes()).hexdigest()
            except OSError:
                binary_sha256 = "unknown"
            result = subprocess.run(
                [binary, "--version"], capture_output=True, text=True, timeout=5, check=False
            )
            match = re.search(r"(\d+\.\d+\.\d+)", result.stdout)
            if result.returncode == 0 and match:
                version = match.group(1)
        return {
            "available": bool(binary),
            "binary": str(Path(binary).resolve()) if binary else "unknown",
            "version": version,
            "binary_sha256": binary_sha256,
            "expected_binary_sha256": (
                _CODEX_ACCEPTANCE.binary_sha256 if _CODEX_ACCEPTANCE is not None else "unknown"
            ),
            "exact_version_accepted": bool(
                _CODEX_ACCEPTANCE is not None
                and version == _CODEX_ACCEPTANCE.provider_version
                and binary_sha256 == _CODEX_ACCEPTANCE.binary_sha256
            ),
        }

    def validation_probe(self) -> dict[str, bool]:
        detected = self.detect_environment()
        return {
            "environment": detected["available"] is True,
            "installation": detected["exact_version_accepted"] is True,
            "authentication": False,
            "replay_defense": False,
            "event_delivery": False,
            "normalization": True,
            "safe_allow": False,
            "safe_deny": False,
            "policy_callback": False,
            "configuration_integrity": False,
            "privacy": True,
        }


class OpenAIDirectAPIControlAdapter(_OpenAIAdapterBase):
    descriptor = AdapterDescriptor(
        adapter_id="openai.direct-api.control",
        provider_family="openai",
        product_family="direct_api",
        adapter_version=_ADAPTER_VERSION,
        deployment_families_supported=(DeploymentFamily.RUNTIME, DeploymentFamily.SAAS_API),
        enforcement_methods_supported=(
            ControlMethod.GATEWAY_INLINE,
            ControlMethod.API_INTERCEPT,
            ControlMethod.TOOL_LOOP_INTERCEPT,
        ),
        event_schema_version="openai-responses-compatible/hawk-v1",
        minimum_hawk_version="1.0.0",
        maturity=AdapterMaturity.PRODUCTION,
        description="Routed OpenAI Responses/API and customer-owned tool-loop interception.",
    )
    matrix_method = ControlMethod.GATEWAY_INLINE
    _claims = _unknown_claims()
    _claims.update(
        {
            CapabilityDimension.DISCOVERY: _claim(CapabilityLevel.OBSERVE, VerificationStatus.VERIFIED),
            CapabilityDimension.IDENTITY: _claim(CapabilityLevel.INLINE_BOUND, VerificationStatus.VERIFIED),
            CapabilityDimension.PROMPT_CONTROL: _claim(CapabilityLevel.INLINE, VerificationStatus.VERIFIED),
            CapabilityDimension.MODEL_REQUEST_CONTROL: _claim(CapabilityLevel.INLINE, VerificationStatus.VERIFIED),
            CapabilityDimension.RESPONSE_CONTROL: _claim(CapabilityLevel.INLINE, VerificationStatus.EXPERIMENTAL),
            CapabilityDimension.DIRECT_API_CONTROL: _claim(CapabilityLevel.INLINE, VerificationStatus.VERIFIED),
            CapabilityDimension.BYPASS_DETECTION: _claim(CapabilityLevel.OBSERVE, VerificationStatus.VERIFIED),
            CapabilityDimension.POST_EXECUTION_VISIBILITY: _claim(CapabilityLevel.OBSERVE, VerificationStatus.VERIFIED),
        }
    )
    manifest = CapabilityManifest(
        schema_version="native-control-adapter-manifest/1.0",
        descriptor_id=descriptor.adapter_id,
        provider="openai",
        product="direct_api",
        provider_version_min="1.0.0",
        provider_version_max="1.0.0",
        exact_verified_versions=("1.0.0",),
        adapter_version=_ADAPTER_VERSION,
        verification_status=VerificationStatus.VERIFIED,
        verified_at="2026-08-12T00:00:00+04:00",
        source_reference="repo:apps/api/tests/test_llm_response_control_chain_contract.py",
        capabilities=_claims,
        security_properties=_security(
            pre=True,
            post=True,
            latency=75,
            blocking=90,
            bypass=65,
            privacy="prompt/response/action metadata traverses the configured Hawk route",
        ),
        required_permissions=("gateway.intercept", "policy.evaluate"),
        event_semantics=EventSemantics(
            pre_execution_events=("responses_request", "tool_proposal"),
            post_execution_events=("responses_chunk", "tool_result"),
            normalized_fields=(
                "identity",
                "canonical_parameters",
                "parameter_hash",
                "canonical_target",
                "target_hash",
                "destination_hash",
                "action_correlation",
            ),
            synchronous_decision_mechanism="Hawk gateway/API intercept or customer-owned tool-loop callback",
        ),
        known_blind_spots=(
            _blind_spot(
                "openai.direct-api.route-bypass",
                "OpenAI API traffic outside the Hawk-controlled route",
                "An application can call OpenAI directly without traversing this adapter.",
                "Bind the application route and use Discovery/Endpoint evidence to report bypass paths.",
            ),
        ),
        failure_modes=("gateway bypass", "stream released before output decision", "tool loop omits Hawk callback"),
        supported_installation_modes=("gateway_route", "application_api_intercept", "tool_loop_intercept"),
        supported_degradation_modes=(DegradationMode.FAIL_CLOSED, DegradationMode.MONITOR_ONLY),
        execution_evidence_quality=EvidenceQuality.PROVIDER_REPORTED,
        selection_characteristics=SelectionCharacteristics(35, 35, 35, 45, 35),
    )

    def normalize_event(
        self,
        raw_payload: Mapping[str, Any],
        context: AdapterPipelineContext,
    ) -> NativeControlEvent:
        return _normalize(product="direct_api", raw_payload=raw_payload, context=context)

    def action_profile(
        self,
        action_class: OpenAIActionClass | str,
        *,
        method: ControlMethod = ControlMethod.GATEWAY_INLINE,
    ) -> OpenAIActionControlProfile:
        if method not in self.descriptor.enforcement_methods_supported:
            raise AdapterError(AdapterErrorCode.CAPABILITY_UNAVAILABLE)
        return _MATRIX.resolve("direct_api", action_class, method)

    def format_decision_response(self, response: AuthorizationResponse) -> dict[str, Any]:
        status = 403 if response.decision == "block" else 202 if response.decision in {
            "review", "require_approval", "require_second_approval"
        } else 200
        return {
            "status_code": status,
            "hawk": {
                "decision": response.decision,
                "control_mode": response.control_mode,
                "reason": response.reason,
                "policy_snapshot_id": response.policy_snapshot_id,
            },
        }

    def validation_probe(self) -> dict[str, bool]:
        return {name: True for name in (
            "environment", "installation", "authentication", "replay_defense", "event_delivery",
            "normalization", "safe_allow", "safe_deny", "policy_callback", "configuration_integrity", "privacy",
        )}
