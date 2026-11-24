from __future__ import annotations

from typing import Any

from app.core.control_engine.authorization import AuthorizationRequest
from app.services.native_control.contracts import (
    AssuranceLevel,
    CapabilityDimension,
    ControlRequirementProfile,
    DegradationMode,
)


_EXECUTABLE_ACTIONS = {
    "tool_execution",
    "api_call",
    "agent_action",
    "command_execution",
    "file_write",
    "external_send",
    "email_send",
    "share_output",
}


def _pre_execution_capability(request: AuthorizationRequest, action_type: str) -> CapabilityDimension:
    surface = _text(request.surface)
    if action_type in {"prompt", "model_request", "chat_completion"}:
        return CapabilityDimension.PROMPT_CONTROL
    if action_type in {"response", "model_response"}:
        return CapabilityDimension.RESPONSE_CONTROL
    if surface == "mcp_gateway" or _text(request.discovery_context.get("mcp_server_id")) not in {
        "",
        "unknown",
        "none",
    }:
        return CapabilityDimension.MCP_CONTROL
    if action_type in {"command", "command_execution", "shell_command"}:
        return CapabilityDimension.COMMAND_CONTROL
    if action_type in {"file_read", "read_file"}:
        return CapabilityDimension.FILE_READ_CONTROL
    if action_type in {"file_write", "write_file"}:
        return CapabilityDimension.FILE_WRITE_CONTROL
    if action_type in {"network_request", "network_connection", "http_request"}:
        return CapabilityDimension.NETWORK_CONTROL
    return CapabilityDimension.TOOL_CONTROL


def _text(value: Any) -> str:
    return str(value or "").strip().lower()


def _minimum_assurance(request: AuthorizationRequest, *, executable: bool, persistent: bool) -> AssuranceLevel:
    derived = (
        AssuranceLevel.A5_VERIFIED
        if persistent
        else AssuranceLevel.A4_BOUND
        if executable
        else AssuranceLevel.A3_INLINE
    )
    configured = _text(request.policy_profile.get("minimum_control_assurance")).replace("_", "")
    mapping = {
        "a0": AssuranceLevel.A0_UNKNOWN,
        "a1": AssuranceLevel.A1_DISCOVERED,
        "a2": AssuranceLevel.A2_OBSERVED,
        "a3": AssuranceLevel.A3_INLINE,
        "a4": AssuranceLevel.A4_BOUND,
        "a5": AssuranceLevel.A5_VERIFIED,
    }
    requested = mapping.get(configured, derived)
    return max(derived, requested)


def _degradation_mode(request: AuthorizationRequest) -> DegradationMode:
    configured = _text(request.policy_profile.get("degraded_behavior"))
    return {
        "block": DegradationMode.FAIL_CLOSED,
        "fail_closed": DegradationMode.FAIL_CLOSED,
        "monitor": DegradationMode.MONITOR_ONLY,
        "monitor_only": DegradationMode.MONITOR_ONLY,
        "local_policy": DegradationMode.LOCAL_POLICY_ONLY,
        "local_policy_only": DegradationMode.LOCAL_POLICY_ONLY,
        "require_exception": DegradationMode.REQUIRE_EXCEPTION,
        "fail_open_with_evidence": DegradationMode.FAIL_OPEN_WITH_EVIDENCE,
    }.get(configured, DegradationMode.FAIL_CLOSED)


def derive_control_requirements(request: AuthorizationRequest) -> ControlRequirementProfile:
    """Translate the existing policy/action context into selector requirements.

    This function does not make a policy decision. It only preserves the action
    semantics and minimum-assurance configuration already produced by Hawk.
    """

    action_type = _text(request.action.get("action_type"))
    persistent = request.side_effect_context.get("persistent_side_effect") is True
    executable = action_type in _EXECUTABLE_ACTIONS
    destination = _text(request.target.get("destination"))
    # ``local`` is the canonical endpoint destination for a workspace/file
    # action. It is not an external destination and must not invent a remote
    # destination binding requirement. Hosts and URLs remain external.
    external_destination = destination not in {"", "unknown", "none", "internal", "local"}
    if persistent:
        action_class = "persistent_side_effect"
    elif action_type in {"external_send", "email_send", "share_output"} or external_destination:
        action_class = "external_data_transfer"
    elif executable:
        action_class = "action_execution"
    else:
        action_class = "model_interaction"
    raw_latency = request.policy_profile.get("maximum_control_latency_ms", 250)
    try:
        maximum_latency_ms = int(raw_latency)
    except (TypeError, ValueError):
        maximum_latency_ms = 250
    maximum_latency_ms = min(5_000, max(1, maximum_latency_ms))
    return ControlRequirementProfile(
        action_class=action_class,
        requires_pre_execution=True,
        pre_execution_capability=_pre_execution_capability(request, action_type),
        requires_identity=True,
        requires_parameter_binding=executable,
        requires_target_binding=executable,
        requires_destination_binding=external_destination or action_type in {
            "external_send",
            "email_send",
            "share_output",
        },
        requires_post_execution=persistent,
        requires_persistence_detection=persistent,
        minimum_assurance=_minimum_assurance(request, executable=executable, persistent=persistent),
        maximum_latency_ms=maximum_latency_ms,
        acceptable_degradation_modes=(_degradation_mode(request),),
    )
