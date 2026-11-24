from __future__ import annotations

"""Exact native-adapter dispatch for already-authenticated callbacks.

The HTTP callback router owns envelope authentication, replay prevention,
tenant binding, lifecycle allowlisting, policy, and evidence persistence.  This
module deliberately owns none of those boundaries.  It only resolves the
reviewed provider/product/version adapter and translates Hawk's bounded callback
wire format into that adapter's documented event schema.

An unresolved known provider/product/version is never silently represented as
an exact adapter action.  Callers may retain generic *observation* processing
for provider families that have no exact adapter, but they must not use that
fallback to enforce an exact native control claim.
"""

from dataclasses import dataclass, replace
import hashlib
import json
from typing import Any, Mapping

from app.core.control_engine.authorization import AuthorizationRequest
from app.services.native_control.adapter_contract import (
    AdapterError,
    AdapterErrorCode,
    AdapterPipelineContext,
    AdapterResolutionState,
    DeploymentFamily,
    NativeControlAdapter,
    NativeControlEvent,
    ProviderTransport,
)
from app.services.native_control.adapter_registry import AdapterResolution, NativeControlAdapterRegistry
from app.services.native_control.contracts import (
    ActionClass,
    ControlMethod,
    ProviderRuntimeContext,
    RuntimeLocation,
)


class ExactAdapterDispatchError(ValueError):
    """A known native-control contract cannot safely be dispatched exactly."""


@dataclass(frozen=True, slots=True)
class ExactAdapterDispatch:
    """A single exact adapter normalization result for one signed callback."""

    resolution: AdapterResolution
    runtime_context: ProviderRuntimeContext
    adapter_id: str | None
    normalized_event: NativeControlEvent | None

    @property
    def is_exact(self) -> bool:
        return self.adapter_id is not None and self.normalized_event is not None

    @property
    def authorization_request(self) -> AuthorizationRequest:
        if self.normalized_event is None:
            raise ExactAdapterDispatchError("exact_adapter_not_selected")
        return self.normalized_event.to_authorization_request()


_EXACT_MATCH_STATES = {
    AdapterResolutionState.EXACT_MATCH,
    AdapterResolutionState.SUPPORTED_COMPATIBLE,
}

_RUNTIME_LOCATION_BY_DEPLOYMENT_FAMILY = {
    "browser": RuntimeLocation.LOCAL_ENDPOINT,
    "endpoint": RuntimeLocation.LOCAL_ENDPOINT,
    "runtime": RuntimeLocation.CUSTOMER_RUNTIME,
    "saas_api": RuntimeLocation.CUSTOMER_CLOUD,
}

_TRANSPORT_BY_METHOD = {
    "native_hook": ProviderTransport.HTTP_CALLBACK,
    "sdk_middleware": ProviderTransport.SDK_IN_PROCESS,
    "agent_middleware": ProviderTransport.MIDDLEWARE,
    "function_middleware": ProviderTransport.MIDDLEWARE,
    "tool_loop_intercept": ProviderTransport.SDK_IN_PROCESS,
    "api_intercept": ProviderTransport.HTTP_CALLBACK,
    "gateway_inline": ProviderTransport.GATEWAY,
    "endpoint_runtime": ProviderTransport.ENDPOINT_IPC,
}

_EVENT_SCHEMA_BY_PROVIDER_PRODUCT: dict[tuple[str, str], dict[str, str]] = {
    ("anthropic", "claude_code"): {
        "before_tool": "PreToolUse",
        "permission_request": "PermissionRequest",
        "after_tool": "PostToolUse",
        "after_tool_failure": "PostToolUseFailure",
        "before_model": "UserPromptSubmit",
        "subagent_context_start": "SubagentStart",
        "subagent_context_stop": "SubagentStop",
        "session_start": "SessionStart",
        "session_end": "SessionEnd",
        "config_change": "ConfigChange",
    },
    ("google", "gemini_cli"): {
        "session_start": "SessionStart",
        "session_end": "SessionEnd",
        "before_agent": "BeforeAgent",
        "after_agent": "AfterAgent",
        "before_model": "BeforeModel",
        "after_model": "AfterModel",
        "before_tool_selection": "BeforeToolSelection",
        "before_tool": "BeforeTool",
        "after_tool": "AfterTool",
        "pre_compress": "PreCompress",
        "notification": "Notification",
    },
    ("cursor", "cursor"): {
        "session_start": "sessionStart",
        "session_end": "sessionEnd",
        "before_tool": "preToolUse",
        "after_tool": "postToolUse",
        "after_tool_failure": "postToolUseFailure",
        "subagent_start": "subagentStart",
        "subagent_stop": "subagentStop",
        "before_shell": "beforeShellExecution",
        "after_shell": "afterShellExecution",
        "before_mcp": "beforeMCPExecution",
        "after_mcp": "afterMCPExecution",
        "before_file_read": "beforeReadFile",
        "after_file_edit": "afterFileEdit",
        "before_model": "beforeSubmitPrompt",
        "pre_compact": "preCompact",
        "stop": "stop",
        "after_model": "afterAgentResponse",
        "after_agent_thought": "afterAgentThought",
        "workspace_open": "workspaceOpen",
    },
    ("openai", "codex"): {
        "before_model": "UserPromptSubmit",
        "before_tool": "PreToolUse",
        "permission_request": "PermissionRequest",
        "after_tool": "PostToolUse",
        "pre_compact": "PreCompact",
        "post_compact": "PostCompact",
        "session_start": "SessionStart",
        "session_end": "SessionEnd",
        "subagent_start": "SubagentStart",
        "subagent_stop": "SubagentStop",
        "stop": "Stop",
        "interrupt": "Interrupt",
    },
    ("openai", "agents_sdk"): {
        "session_start": "run_start",
        "before_agent": "agent_start",
        "before_model": "llm_start",
        "before_tool": "function_tool_input",
        "permission_request": "tool_approval",
        "after_tool": "function_tool_output",
        "after_model": "llm_end",
        "after_agent": "agent_end",
        "subagent_start": "handoff",
        "session_end": "run_end",
    },
    ("openai", "direct_api"): {
        "before_model": "responses_request",
        "after_model": "responses_chunk",
        "before_tool": "tool_proposal",
        "after_tool": "tool_result",
    },
}


_CANONICAL_ACTION_CLASS_BY_NATIVE_ACTION = {
    "model_request": ActionClass.MODEL_REQUEST,
    "model_response": ActionClass.MODEL_RESPONSE,
    "prompt": ActionClass.PROMPT,
    "function_tool": ActionClass.FUNCTION_TOOL,
    "hosted_web_search": ActionClass.HOSTED_TOOL,
    "hosted_file_search": ActionClass.HOSTED_TOOL,
    "hosted_code_interpreter": ActionClass.HOSTED_TOOL,
    "hosted_image_generation": ActionClass.HOSTED_TOOL,
    "hosted_mcp": ActionClass.MCP,
    "local_mcp": ActionClass.MCP,
    "mcp_tool_call": ActionClass.MCP,
    "command_execution": ActionClass.COMMAND,
    "local_shell": ActionClass.COMMAND,
    "hosted_shell": ActionClass.COMMAND,
    "file_read": ActionClass.FILE_READ,
    "file_write": ActionClass.FILE_WRITE,
    "apply_patch": ActionClass.PATCH,
    "computer_tool": ActionClass.BROWSER_TASK,
    "agent_invocation": ActionClass.DELEGATION,
    "agent_turn": ActionClass.DELEGATION,
    "agent_as_tool": ActionClass.DELEGATION,
    "handoff": ActionClass.DELEGATION,
    "approval": ActionClass.APPROVAL,
    "persistent_side_effect": ActionClass.PERSISTENT_SIDE_EFFECT,
}


# The endpoint agent never forwards a provider's raw tool arguments to Hawk.
# It signs a bounded, privacy-safe envelope of canonical hashes instead.  That
# envelope is intentionally a different wire shape from raw provider hook
# input: feeding it into a provider adapter would make an adapter hash an
# absent ``tool_input`` as ``{}``, collapsing distinct signed actions.
_HASH_ONLY_CALLBACK_SCHEMA = "hawk-native-hash-envelope/v1"
_HASH_ONLY_CALLBACK_FIELDS = frozenset(
    {
        "callback_schema",
        "provider_event_type",
        "action_type",
        "tool_name",
        "tool_class",
        "tool_version",
        "tool_fingerprint_id",
        "parameter_hash",
        "target_resource",
        "target_resource_hash",
        "destination",
        "destination_hash",
        "persistent_side_effect",
        "side_effect_class",
        "prompt_hash",
        "response_hash",
        "data_classifications",
        "mcp_server_id",
        "mcp_tool_name",
        "model",
        "provider_session_hash",
        "provider_tool_use_hash",
        "approval_action_hash",
        "permission_context_present",
        "permission_suggestions_hash",
        "workspace_hash",
        "repository_root_hash",
        "repository_common_dir_hash",
        "repository_target_hash",
        "repository_control_resolution",
        "repository_operation",
        "repository_command_shape",
        "repository_command_hash",
        "repository_destination_hash",
        "execution_status",
        "evidence_quality",
        "failure_hash",
        "provider_generation_hash",
        "provider_account_hash",
        "provider_app_version",
        "branch_hash",
        "subagent_id_hash",
        "parent_session_hash",
        "agent_type",
        "agent_id_hash",
        "run_in_background",
        "execution_location",
        "delegation_depth",
        "tail_call",
        "original_request_name_hash",
        "permission_mode",
        "config_source",
        "config_file_path_hash",
        "subagent_type",
        "is_parallel_worker",
    }
)
_RAW_PROVIDER_SHAPE_FIELDS = frozenset(
    {
        "tool_input",
        "parameters",
        "arguments",
        "cwd",
        "url",
        "path",
        "file_path",
        "tool_use_id",
        "event_type",
        "hook_event_name",
        "session_id",
        "agent_id",
        "provider_result",
        "result",
    }
)
_REQUIRED_HASH_ONLY_CALLBACK_FIELDS = frozenset(
    {
        "action_type",
        "tool_name",
        "tool_fingerprint_id",
        "parameter_hash",
        "target_resource_hash",
        "destination_hash",
    }
)
_MAX_CALLBACK_DEPTH = 8
_MAX_CALLBACK_MAPPING_FIELDS = 64
_MAX_CALLBACK_LIST_ITEMS = 64
_MAX_CALLBACK_STRING_LENGTH = 2_048
_MAX_CALLBACK_BYTES = 65_536


def _validate_bounded_callback_value(value: Any, *, depth: int = 0) -> None:
    """Reject provider-controlled structures that cannot be safely normalized.

    This check is deliberately independent of the provider adapter.  It
    protects the router/adapter seam from unbounded or deeply nested signed
    payloads without treating a signature as validation of a provider schema.
    """

    if depth > _MAX_CALLBACK_DEPTH:
        raise ExactAdapterDispatchError("provider_event_schema_too_deep")
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, str):
        if len(value) > _MAX_CALLBACK_STRING_LENGTH:
            raise ExactAdapterDispatchError("provider_event_schema_string_too_large")
        if any(ord(character) < 0x20 and character not in "\t\n\r" for character in value):
            raise ExactAdapterDispatchError("provider_event_schema_invalid_string")
        return
    if isinstance(value, Mapping):
        if len(value) > _MAX_CALLBACK_MAPPING_FIELDS:
            raise ExactAdapterDispatchError("provider_event_schema_too_wide")
        for key, nested in value.items():
            if not isinstance(key, str) or len(key) > 128:
                raise ExactAdapterDispatchError("provider_event_schema_invalid_key")
            _validate_bounded_callback_value(nested, depth=depth + 1)
        return
    if isinstance(value, (list, tuple)):
        if len(value) > _MAX_CALLBACK_LIST_ITEMS:
            raise ExactAdapterDispatchError("provider_event_schema_list_too_large")
        for nested in value:
            _validate_bounded_callback_value(nested, depth=depth + 1)
        return
    raise ExactAdapterDispatchError("provider_event_schema_non_json_value")


def _bounded_text(payload: Mapping[str, Any], key: str, *, default: str = "unknown") -> str:
    value = payload.get(key, default)
    if not isinstance(value, str):
        raise ExactAdapterDispatchError("provider_event_schema_invalid_field_type")
    normalized = value.strip()
    if not normalized:
        return default
    if len(normalized) > _MAX_CALLBACK_STRING_LENGTH:
        raise ExactAdapterDispatchError("provider_event_schema_string_too_large")
    return normalized


def _hash_only_callback_payload(
    raw_payload: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Validate and identify the endpoint's hash-only callback union member.

    Returning ``None`` means this is a raw provider-hook input and it is left
    to the selected reviewed adapter.  Hash-only and raw fields are mutually
    exclusive: a hybrid payload is rejected instead of choosing a convenient
    interpretation that could change the canonical action.
    """

    if not isinstance(raw_payload, Mapping):
        raise ExactAdapterDispatchError("provider_event_schema_unsupported")
    payload = dict(raw_payload)
    try:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ExactAdapterDispatchError("provider_event_schema_non_json_value") from exc
    if len(encoded) > _MAX_CALLBACK_BYTES:
        raise ExactAdapterDispatchError("provider_event_schema_too_large")
    _validate_bounded_callback_value(payload)

    raw_keys = set(payload).intersection(_RAW_PROVIDER_SHAPE_FIELDS)
    has_hash_schema = "callback_schema" in payload
    has_hash_material = bool(
        set(payload).intersection(
            {"parameter_hash", "target_resource_hash", "destination_hash"}
        )
    )
    if raw_keys and (has_hash_schema or has_hash_material):
        raise ExactAdapterDispatchError("provider_event_schema_mixed_raw_and_hash_only")
    if not has_hash_schema:
        if has_hash_material:
            # A payload that looks like the endpoint's privacy-safe schema
            # but omits its schema marker is not raw provider input.  Reject
            # it rather than handing it to an adapter that might recompute a
            # canonical hash from an absent raw value.
            raise ExactAdapterDispatchError("provider_event_schema_marker_required")
        return None
    if payload.get("callback_schema") != _HASH_ONLY_CALLBACK_SCHEMA:
        raise ExactAdapterDispatchError("provider_event_schema_unsupported")
    if raw_keys:
        raise ExactAdapterDispatchError("provider_event_schema_mixed_raw_and_hash_only")
    unknown = set(payload).difference(_HASH_ONLY_CALLBACK_FIELDS)
    if unknown:
        raise ExactAdapterDispatchError("provider_event_schema_unknown_field")
    missing = _REQUIRED_HASH_ONLY_CALLBACK_FIELDS.difference(payload)
    if missing:
        raise ExactAdapterDispatchError("provider_event_schema_required_field_missing")
    for key in _REQUIRED_HASH_ONLY_CALLBACK_FIELDS:
        _bounded_text(payload, key)
    if not isinstance(payload.get("persistent_side_effect", False), bool):
        raise ExactAdapterDispatchError("provider_event_schema_invalid_field_type")
    if not isinstance(payload.get("data_classifications", []), list) or not all(
        isinstance(value, str) and len(value) <= 256
        for value in payload.get("data_classifications", [])
    ):
        raise ExactAdapterDispatchError("provider_event_schema_invalid_field_type")
    if "delegation_depth" in payload:
        delegation_depth = payload["delegation_depth"]
        # Endpoint hash-only callbacks use -1 as the explicit Unknown sentinel.
        # It must remain unknown rather than being promoted to a positive depth
        # claim, while every other out-of-range or non-integer value is rejected.
        if (
            isinstance(delegation_depth, bool)
            or not isinstance(delegation_depth, int)
            or delegation_depth < -1
            or delegation_depth > 64
        ):
            raise ExactAdapterDispatchError("provider_event_schema_invalid_field_type")
    return payload


def _normalize_hash_only_endpoint_event(
    *,
    payload: Mapping[str, Any],
    context: AdapterPipelineContext,
    provider: str,
    product: str,
    provider_event_type: str,
    expected_event: str,
    adapter_version: str,
) -> NativeControlEvent:
    """Create canonical event without ever reconstructing raw provider input."""

    action_type = _bounded_text(payload, "action_type")
    tool_name = _bounded_text(payload, "tool_name")
    tool_fingerprint_id = _bounded_text(payload, "tool_fingerprint_id")
    parameter_hash = _bounded_text(payload, "parameter_hash")
    target_resource_hash = _bounded_text(payload, "target_resource_hash")
    destination_hash = _bounded_text(payload, "destination_hash")
    action_class = _CANONICAL_ACTION_CLASS_BY_NATIVE_ACTION.get(
        action_type.lower(), ActionClass.UNKNOWN_ACTION
    ).value
    persistent_side_effect = payload.get("persistent_side_effect") is True
    classifications = list(payload.get("data_classifications") or [])
    approval_action_hash = _bounded_text(payload, "approval_action_hash")
    provider_tool_use_hash = _bounded_text(payload, "provider_tool_use_hash")

    return NativeControlEvent(
        tenant_id=context.tenant_id,
        integration_instance_id=context.integration_instance_id,
        provider=provider,
        product=product,
        raw_provider_event_type=expected_event,
        provider_event_id=context.provider_event_id,
        provider_version=context.provider_version,
        adapter_version=adapter_version,
        lifecycle_stage=provider_event_type,
        actor=dict(context.resolved_actor),
        session={"session_id": context.session_id},
        runtime={
            "environment": context.environment,
            "credential_id": context.credential_id,
            "correlation_id": context.correlation_id,
            "workspace_hash": _bounded_text(payload, "workspace_hash"),
            "repository_root_hash": _bounded_text(payload, "repository_root_hash"),
            "repository_common_dir_hash": _bounded_text(payload, "repository_common_dir_hash"),
            "repository_target_hash": _bounded_text(payload, "repository_target_hash"),
            "repository_control_resolution": _bounded_text(payload, "repository_control_resolution"),
            "repository_operation": _bounded_text(payload, "repository_operation"),
            "repository_command_shape": _bounded_text(payload, "repository_command_shape"),
            "repository_command_hash": _bounded_text(payload, "repository_command_hash"),
            "repository_destination_hash": _bounded_text(payload, "repository_destination_hash"),
            "execution_location": _bounded_text(payload, "execution_location"),
            "provider_app_version": _bounded_text(
                payload, "provider_app_version", default=context.provider_version
            ),
        },
        tool={
            "name": tool_name,
            "version": _bounded_text(payload, "tool_version", default=context.provider_version),
            "fingerprint_id": tool_fingerprint_id,
        },
        model={"name": _bounded_text(payload, "model")},
        mcp={
            "server_id": _bounded_text(payload, "mcp_server_id"),
            "tool_name": _bounded_text(payload, "mcp_tool_name"),
        },
        action={
            "action_type": action_type,
            "action_class": action_class,
            # Preserve the endpoint's signed canonical material exactly.  No
            # provider adapter may hash absent raw ``tool_input`` into a
            # shared empty-object digest.
            "parameter_hash": parameter_hash,
            "approval_action_hash": approval_action_hash,
            "data_classifications": classifications,
            "prompt_hash": _bounded_text(payload, "prompt_hash"),
            "response_hash": _bounded_text(payload, "response_hash"),
            "execution_status": _bounded_text(payload, "execution_status"),
            "evidence_quality": _bounded_text(payload, "evidence_quality"),
            "failure_hash": _bounded_text(payload, "failure_hash"),
        },
        target={
            "resource": _bounded_text(payload, "target_resource"),
            "resource_hash": target_resource_hash,
        },
        destination={
            "destination": _bounded_text(payload, "destination"),
            "destination_hash": destination_hash,
        },
        side_effect_class=_bounded_text(payload, "side_effect_class"),
        persistence={
            "persistent_side_effect": persistent_side_effect,
            "run_in_background": payload.get("run_in_background") is True,
        },
        provider_correlation={
            "provider_tool_use_hash": provider_tool_use_hash,
            "chain_id": context.chain_id,
            "correlation_id": context.correlation_id,
            "provider_session_hash": _bounded_text(payload, "provider_session_hash"),
        },
        timing={
            "received_at": context.received_at,
            "pre_execution": provider_event_type.startswith("before_"),
        },
        integrity={
            "transport": context.transport.value,
            "signature_valid": context.signature_valid,
            "callback_schema": _HASH_ONLY_CALLBACK_SCHEMA,
        },
        policy_snapshot_id=context.policy_snapshot_id,
        policy_profile=dict(context.policy_profile),
    )


def _canonical_action_class(event: NativeControlEvent) -> ActionClass:
    """Derive action class only from the adapter's canonical event.

    Raw callback tool labels are provider-controlled input and must not change
    acceptance scope before the reviewed adapter has normalized them.
    """

    action = event.action if isinstance(event.action, Mapping) else {}
    value = str(action.get("action_class") or action.get("action_type") or "").strip().lower()
    try:
        return ActionClass(value)
    except ValueError:
        return _CANONICAL_ACTION_CLASS_BY_NATIVE_ACTION.get(value, ActionClass.UNKNOWN_ACTION)


def _project_adapter_payload(
    *,
    provider: str,
    product: str,
    provider_event_type: str,
    raw_payload: Mapping[str, Any],
) -> dict[str, Any]:
    expected_event = _EVENT_SCHEMA_BY_PROVIDER_PRODUCT.get((provider, product), {}).get(
        provider_event_type
    )
    if expected_event is None:
        raise ExactAdapterDispatchError("provider_event_schema_unsupported")
    payload = dict(raw_payload)
    declared_event = str(payload.get("hook_event_name") or payload.get("event_type") or "").strip()
    if declared_event and declared_event != expected_event:
        raise ExactAdapterDispatchError("provider_event_schema_mismatch")
    payload["hook_event_name"] = expected_event
    if not payload.get("target") and payload.get("target_resource"):
        payload["target"] = payload["target_resource"]
    if not payload.get("arguments") and isinstance(payload.get("parameters"), Mapping):
        payload["arguments"] = dict(payload["parameters"])
    if not payload.get("tool_input") and isinstance(payload.get("parameters"), Mapping):
        payload["tool_input"] = dict(payload["parameters"])
    return payload


def _runtime_context(
    *,
    tenant_id: str,
    integration_id: str,
    instance_key: str,
    provider: str,
    product: str,
    provider_version: str,
    adapter_version: str,
    environment: str,
    deployment_family: str,
    integration_method: str,
    runtime: str,
    model_provider: str,
    model: str,
    provider_event_type: str,
    event_id: str,
    execution_location: str = "UNKNOWN",
    deployment_reference: str = "unknown",
) -> ProviderRuntimeContext:
    provider_value = str(provider or "").strip().lower()
    product_value = str(product or "").strip().lower()
    route_digest = hashlib.sha256(
        f"{tenant_id}:{integration_id}:{event_id}".encode("utf-8")
    ).hexdigest()
    try:
        control_method = ControlMethod(str(integration_method or "").strip().lower())
    except ValueError:
        control_method = ControlMethod.OBSERVE_ONLY
    try:
        runtime_location = RuntimeLocation(str(execution_location or "").strip().lower())
    except ValueError:
        runtime_location = _RUNTIME_LOCATION_BY_DEPLOYMENT_FAMILY.get(
            str(deployment_family or "").strip().lower(), RuntimeLocation.UNKNOWN
        )
    return ProviderRuntimeContext(
        provider=provider_value,
        product=product_value,
        runtime=str(runtime or "unknown").strip().lower() or "unknown",
        # The exact adapter produces the canonical action class below.  Do
        # not use raw tool/action labels to resolve acceptance eligibility.
        action_class=ActionClass.UNKNOWN_ACTION,
        runtime_location=runtime_location,
        provider_version=str(provider_version or "unknown").strip() or "unknown",
        adapter_version=str(adapter_version or "unknown").strip() or "unknown",
        control_method=control_method,
        environment=str(environment or "unknown").strip().lower() or "unknown",
        application=product_value or "unknown",
        application_version=str(provider_version or "unknown"),
        runtime_version=str(provider_version or "unknown"),
        # Provider/product identify the application control contract. The
        # model facts are separately bound integration configuration and must
        # not be inferred from the provider application family.
        model_provider=str(model_provider or "unknown").strip().lower() or "unknown",
        model=str(model or "unknown").strip() or "unknown",
        route_identity=f"native-control:{integration_id}",
        deployment_identity=f"integration:{instance_key}",
        deployment_reference=(
            str(deployment_reference or "").strip()
            or f"native-control-integration:{integration_id}"
        ),
        lifecycle_stage=str(provider_event_type or "unknown").strip().lower() or "unknown",
        account_mode="tenant_scoped_workload",
        tenant_mode="tenant_scoped",
        route_evidence_ref=f"signed-native-callback:{route_digest}",
        route_evidence_fresh=True,
    )


def dispatch_live_callback_adapter(
    *,
    registry: NativeControlAdapterRegistry,
    tenant_id: str,
    integration_id: str,
    instance_key: str,
    provider: str,
    product: str,
    provider_version: str,
    adapter_version: str,
    environment: str,
    deployment_family: str,
    integration_method: str,
    runtime: str,
    model_provider: str = "unknown",
    model: str = "unknown",
    credential_id: str,
    event_id: str,
    provider_event_id: str,
    provider_event_type: str,
    nonce: str,
    correlation_id: str,
    session_id: str,
    chain_id: str,
    received_at: str,
    policy_snapshot_id: str,
    policy_profile: Mapping[str, Any],
    resolved_actor: Mapping[str, str],
    raw_payload: Mapping[str, Any],
    # Legacy diagnostics exercise only pure adapter normalization. They have
    # no installed integration record, so retain explicit Unknown defaults;
    # the authenticated router always supplies bound deployment facts.
    execution_location: str = "UNKNOWN",
    deployment_reference: str = "unknown",
) -> ExactAdapterDispatch:
    """Resolve and normalize one already-authenticated native callback.

    Unknown provider families return an explicit non-exact dispatch so a caller
    can retain legacy observation. Known but unsupported, newer, broken, or
    ambiguous contracts raise rather than fall through as an exact control.
    """

    runtime_context = _runtime_context(
        tenant_id=tenant_id,
        integration_id=integration_id,
        instance_key=instance_key,
        provider=provider,
        product=product,
        provider_version=provider_version,
        adapter_version=adapter_version,
        environment=environment,
        deployment_family=deployment_family,
        integration_method=integration_method,
        runtime=runtime,
        model_provider=model_provider,
        model=model,
        execution_location=execution_location,
        deployment_reference=deployment_reference,
        provider_event_type=provider_event_type,
        event_id=event_id,
    )
    # First select a single reviewed provider/product/version adapter.  It has
    # no enforcement authority until canonical event normalization supplies
    # action and lifecycle facts below.
    initial_resolution = registry.resolve(
        provider=provider,
        product=product,
        provider_version=provider_version,
        runtime_context=None,
        # The router binds dynamic deployed acceptance to this exact
        # integration. A static manifest cannot stand in for that evidence.
        require_deployment_acceptance=False,
    )
    if initial_resolution.state is AdapterResolutionState.UNKNOWN:
        return ExactAdapterDispatch(
            resolution=initial_resolution,
            runtime_context=runtime_context,
            adapter_id=None,
            normalized_event=None,
        )
    if (
        initial_resolution.state not in _EXACT_MATCH_STATES
        or len(initial_resolution.adapter_ids) != 1
    ):
        reason = (
            initial_resolution.ineligibility_reasons[0]
            if initial_resolution.ineligibility_reasons
            else initial_resolution.reason
        )
        raise ExactAdapterDispatchError(reason)
    adapter_id = initial_resolution.adapter_ids[0]
    adapter: NativeControlAdapter = registry.get(adapter_id)
    if adapter.descriptor.adapter_version != str(adapter_version or "").strip():
        raise ExactAdapterDispatchError("adapter_version_unsupported")
    try:
        control_method = ControlMethod(str(integration_method or "").strip().lower())
        family = DeploymentFamily(str(deployment_family or "").strip().lower())
    except ValueError as exc:
        raise ExactAdapterDispatchError("adapter_runtime_binding_unsupported") from exc
    if control_method not in adapter.descriptor.enforcement_methods_supported:
        raise ExactAdapterDispatchError("adapter_control_method_unsupported")
    if family not in adapter.descriptor.deployment_families_supported:
        raise ExactAdapterDispatchError("adapter_deployment_family_unsupported")
    hash_only_payload = _hash_only_callback_payload(raw_payload)
    adapter_payload: dict[str, Any] | None = None
    if hash_only_payload is None:
        adapter_payload = _project_adapter_payload(
            provider=str(provider).strip().lower(),
            product=str(product).strip().lower(),
            provider_event_type=provider_event_type,
            raw_payload=raw_payload,
        )
    context = AdapterPipelineContext(
        tenant_id=tenant_id,
        integration_instance_id=integration_id,
        credential_id=credential_id,
        environment=environment,
        provider_event_id=provider_event_id,
        correlation_id=correlation_id,
        session_id=session_id,
        chain_id=chain_id,
        provider_version=provider_version,
        policy_snapshot_id=policy_snapshot_id,
        policy_profile=dict(policy_profile),
        resolved_actor={str(key): str(value) for key, value in resolved_actor.items()},
        transport=_TRANSPORT_BY_METHOD.get(
            str(integration_method or "").strip().lower(), ProviderTransport.HTTP_CALLBACK
        ),
        # The router has already verified the signed envelope and claimed the
        # replay nonce before this bridge is invoked.
        transport_authenticated=True,
        signature_valid=True,
        nonce=nonce,
        received_at=received_at,
    )
    if hash_only_payload is not None:
        expected_event = _EVENT_SCHEMA_BY_PROVIDER_PRODUCT[(
            str(provider).strip().lower(),
            str(product).strip().lower(),
        )][provider_event_type]
        normalized_event = _normalize_hash_only_endpoint_event(
            payload=hash_only_payload,
            context=context,
            provider=str(provider).strip().lower(),
            product=str(product).strip().lower(),
            provider_event_type=provider_event_type,
            expected_event=expected_event,
            adapter_version=adapter.descriptor.adapter_version,
        )
    else:
        assert adapter_payload is not None
        try:
            normalized_event = adapter.normalize_event(adapter_payload, context)
        except AdapterError as exc:
            code = (
                exc.code.value
                if isinstance(exc.code, AdapterErrorCode)
                else AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED.value
            )
            raise ExactAdapterDispatchError(f"adapter_{code}") from exc
        except ValueError as exc:
            raise ExactAdapterDispatchError("provider_event_schema_unsupported") from exc
    if (
        normalized_event.tenant_id != tenant_id
        or normalized_event.integration_instance_id != integration_id
        or normalized_event.provider != str(provider).strip().lower()
        or normalized_event.product != str(product).strip().lower()
        or normalized_event.provider_event_id != provider_event_id
        or normalized_event.provider_version != str(provider_version).strip()
        or normalized_event.adapter_version != str(adapter_version).strip()
        or normalized_event.raw_provider_event_type
        != (
            _EVENT_SCHEMA_BY_PROVIDER_PRODUCT[
                (str(provider).strip().lower(), str(product).strip().lower())
            ][provider_event_type]
            if hash_only_payload is not None
            else str(adapter_payload["hook_event_name"]).strip()
        )
        or normalized_event.policy_snapshot_id != policy_snapshot_id
        or str(normalized_event.runtime.get("environment") or "").strip().lower()
        != str(environment).strip().lower()
        or not str(normalized_event.lifecycle_stage or "").strip()
        or str(normalized_event.lifecycle_stage).strip().lower() == "unknown"
    ):
        raise ExactAdapterDispatchError("adapter_identity_projection_invalid")
    canonical_action_class = _canonical_action_class(normalized_event)
    # The adapter's normalized action is the single canonical source used by
    # policy, selection, receipts and post-action comparison. Project the
    # derived provider-neutral class back into that event; leaving the generic
    # ``unknown`` placeholder here would let later layers select on a weaker
    # representation than the exact adapter actually proved.
    normalized_event = replace(
        normalized_event,
        # The adapter maps provider data into Hawk's canonical action.  It
        # cannot self-assert the route used to invoke it.  Project the already
        # authenticated integration facts here so the downstream selector sees
        # the same method/runtime/deployment scope that real acceptance bound.
        runtime={
            **dict(normalized_event.runtime),
            "environment": str(environment).strip().lower(),
            "integration_method": control_method.value,
            "runtime": runtime_context.runtime,
            "runtime_location": runtime_context.runtime_location.value,
            "execution_location": str(execution_location).strip().upper(),
            "deployment_family": family.value,
            "deployment_reference": runtime_context.deployment_reference,
        },
        action={
            **dict(normalized_event.action),
            "action_class": canonical_action_class.value,
        },
    )
    runtime_context = replace(
        runtime_context,
        action_class=canonical_action_class,
        lifecycle_stage=normalized_event.lifecycle_stage,
    )
    if runtime_context.action_class is not canonical_action_class:
        raise ExactAdapterDispatchError("adapter_action_class_projection_invalid")
    resolution = registry.resolve(
        provider=provider,
        product=product,
        provider_version=provider_version,
        runtime_context=runtime_context,
        require_deployment_acceptance=False,
    )
    if (
        resolution.state not in _EXACT_MATCH_STATES
        or resolution.adapter_ids != (adapter_id,)
    ):
        raise ExactAdapterDispatchError("adapter_resolution_changed_after_normalization")
    return ExactAdapterDispatch(
        resolution=resolution,
        runtime_context=runtime_context,
        adapter_id=adapter_id,
        normalized_event=normalized_event,
    )
