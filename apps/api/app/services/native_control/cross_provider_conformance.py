"""Provider-neutral conformance projection for already-normalized actions.

This module does not route callbacks, select a control point, or make a second
policy decision.  It exercises existing provider adapters through their public
``NativeControlEvent -> AuthorizationRequest`` boundary, calls Hawk's existing
authorization evaluator once, and projects only the material that evaluator
can compare across provider-specific tool names and transport representations.

The projection is intentionally ephemeral.  Receipts retain the complete
provider-specific canonical action and its existing canonical action hash.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping

from app.core.control_engine.authorization import (
    AuthorizationRequest,
    AuthorizationResponse,
    authorize_ai_action,
)
from app.services.native_control.adapter_contract import (
    AdapterPipelineContext,
    NativeControlAdapter,
    NativeControlEvent,
    stable_hash,
)
from app.services.native_control.contracts import (
    ActionClass,
    CapabilityDimension,
    CapabilityLevel,
    ProviderVersionState,
)
from app.services.receipt_service import canonical_action_from_authorization


class ConformanceAvailability(str, Enum):
    """Truth state for the normalized semantic class, not control strength."""

    RESOLVED = "resolved"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"


_ACTION_TYPE_MAP: dict[str, ActionClass] = {
    "command_execution": ActionClass.COMMAND,
    "file_read": ActionClass.FILE_READ,
    "file_write": ActionClass.FILE_WRITE,
    "mcp_tool_call": ActionClass.MCP,
    "model_request": ActionClass.MODEL_REQUEST,
    "agent_invocation": ActionClass.DELEGATION,
    "agent_turn": ActionClass.DELEGATION,
}

_OPENAI_ACTION_CLASS_MAP: dict[str, ActionClass] = {
    "model_request": ActionClass.MODEL_REQUEST,
    "model_response": ActionClass.MODEL_RESPONSE,
    "function_tool": ActionClass.FUNCTION_TOOL,
    "local_mcp": ActionClass.MCP,
    "hosted_mcp": ActionClass.MCP,
    "local_shell": ActionClass.COMMAND,
    "hosted_shell": ActionClass.COMMAND,
    "apply_patch": ActionClass.PATCH,
    "computer_tool": ActionClass.BROWSER_TASK,
    "agent_as_tool": ActionClass.DELEGATION,
    "handoff": ActionClass.DELEGATION,
}

_CAPABILITY_FOR_ACTION_CLASS: dict[ActionClass, CapabilityDimension] = {
    ActionClass.MODEL_REQUEST: CapabilityDimension.MODEL_REQUEST_CONTROL,
    ActionClass.MODEL_RESPONSE: CapabilityDimension.MODEL_RESPONSE_CONTROL,
    ActionClass.FUNCTION_TOOL: CapabilityDimension.FUNCTION_TOOL_CONTROL,
    ActionClass.MCP: CapabilityDimension.MCP_CONTROL,
    ActionClass.COMMAND: CapabilityDimension.COMMAND_CONTROL,
    ActionClass.FILE_READ: CapabilityDimension.FILE_READ_CONTROL,
    ActionClass.FILE_WRITE: CapabilityDimension.FILE_WRITE_CONTROL,
    ActionClass.PATCH: CapabilityDimension.PATCH_CONTROL,
    ActionClass.BROWSER_TASK: CapabilityDimension.COMPUTER_CONTROL,
    ActionClass.NETWORK_ACTION: CapabilityDimension.NETWORK_CONTROL,
    ActionClass.DELEGATION: CapabilityDimension.DELEGATION_CONTROL,
}

_ACTION_PROFILE_FOR_ACTION_CLASS: dict[ActionClass, str] = {
    ActionClass.MODEL_REQUEST: "model_request",
    ActionClass.MODEL_RESPONSE: "model_response",
    ActionClass.FUNCTION_TOOL: "function_tool",
    ActionClass.MCP: "local_mcp",
    ActionClass.COMMAND: "local_shell",
    ActionClass.PATCH: "apply_patch",
    ActionClass.BROWSER_TASK: "computer_tool",
    ActionClass.DELEGATION: "agent_as_tool",
}


@dataclass(frozen=True, slots=True)
class CrossProviderConformanceOutcome:
    """One adapter outcome, grounded in its existing normalized event.

    ``canonical_action_hash`` is Hawk's normal receipt-bound hash.  It is
    expected to remain different between providers because it intentionally
    binds action and provider provenance.  ``policy_relevant_material`` is a
    non-persisted comparison view of existing request fields.  It does not
    replace the AuthorizationRequest or canonical AI Action schemas.
    """

    provider: str
    product: str
    action_class: ActionClass
    availability: ConformanceAvailability
    normalized_event: NativeControlEvent
    authorization_request: AuthorizationRequest
    authorization_response: AuthorizationResponse
    canonical_action: Mapping[str, Any]
    canonical_action_hash: str
    policy_relevant_material: Mapping[str, Any]
    version_state: str


def _text(value: object) -> str:
    return str(value or "").strip()


_UNKNOWN_IDENTITIES = frozenset({"", "unknown", "none", "null", "hashed_target", "mcp"})


def _is_known_identity(value: object) -> bool:
    return _text(value).lower() not in _UNKNOWN_IDENTITIES


def _exact_identity_and_hash(
    identity: object,
    identity_hash: object,
) -> tuple[str, str, bool]:
    canonical_identity = _text(identity)
    canonical_hash = _text(identity_hash).lower()
    if not _is_known_identity(canonical_identity):
        return "unknown", "unknown", False
    if len(canonical_hash) != 64 or any(character not in "0123456789abcdef" for character in canonical_hash):
        return canonical_identity, "unknown", False
    if stable_hash(canonical_identity) != canonical_hash:
        return canonical_identity, canonical_hash, False
    return canonical_identity, canonical_hash, True


_COMMAND_ALIASES = frozenset({"bash", "shell", "run_shell_command"})
_FILE_READ_ALIASES = frozenset({"read", "read_file"})
_FILE_WRITE_ALIASES = frozenset({"write", "write_file", "edit", "replace"})


def _semantic_tool_identity(
    event: NativeControlEvent,
    action_class: ActionClass,
) -> tuple[str, str, bool]:
    raw_name = _text(event.tool.get("name"))
    normalized_name = raw_name.lower()
    identity = "unknown"
    if action_class is ActionClass.COMMAND and normalized_name in _COMMAND_ALIASES:
        identity = "command:local_shell"
    elif action_class is ActionClass.FILE_READ and normalized_name in _FILE_READ_ALIASES:
        identity = "file:read"
    elif action_class is ActionClass.FILE_WRITE and normalized_name in _FILE_WRITE_ALIASES:
        identity = "file:write"
    elif action_class is ActionClass.MCP:
        server_id = _text(event.mcp.get("server_id"))
        tool_name = _text(event.mcp.get("tool_name"))
        if _is_known_identity(server_id) and _is_known_identity(tool_name):
            identity = f"mcp:{server_id}:{tool_name}"
    elif action_class is ActionClass.FUNCTION_TOOL and _is_known_identity(raw_name):
        identity = f"function:{raw_name}"
    elif action_class is ActionClass.DELEGATION and _is_known_identity(raw_name):
        identity = f"delegation:{raw_name}"
    elif action_class is ActionClass.PATCH and _is_known_identity(raw_name):
        identity = f"patch:{raw_name}"
    elif action_class in {ActionClass.MODEL_REQUEST, ActionClass.MODEL_RESPONSE}:
        model = _text(event.model.get("name") or event.model.get("model_id"))
        if _is_known_identity(model):
            identity = f"model:{model}"
    elif action_class is ActionClass.BROWSER_TASK and _is_known_identity(raw_name):
        identity = f"browser:{raw_name}"
    if not _is_known_identity(identity):
        return "unknown", "unknown", False
    return identity, stable_hash(identity), True


def _canonical_action_class(event: NativeControlEvent) -> ActionClass:
    explicit = _text(event.action.get("action_class")).lower()
    if explicit:
        resolved = _OPENAI_ACTION_CLASS_MAP.get(explicit)
        if resolved is not None:
            return resolved
    return _ACTION_TYPE_MAP.get(
        _text(event.action.get("action_type")).lower(),
        ActionClass.UNKNOWN_ACTION,
    )


def _capability_availability(
    adapter: NativeControlAdapter,
    action_class: ActionClass,
) -> ConformanceAvailability:
    if action_class is ActionClass.UNKNOWN_ACTION:
        return ConformanceAvailability.UNKNOWN
    dimension = _CAPABILITY_FOR_ACTION_CLASS.get(action_class)
    if dimension is None:
        return ConformanceAvailability.UNKNOWN
    claim = None
    action_profile = getattr(adapter, "action_profile", None)
    profile_key = _ACTION_PROFILE_FOR_ACTION_CLASS.get(action_class)
    if callable(action_profile) and profile_key is not None:
        try:
            profile = action_profile(profile_key)
            claim = getattr(profile, "capabilities", {}).get(dimension)
        except (TypeError, ValueError):
            # The provider did not expose this action class through its
            # reviewed matrix.  Fall through to the product-level fact rather
            # than widening the capability by inference.
            claim = None
    if claim is None:
        claim = adapter.manifest.capabilities.get(dimension)
    if claim is None or claim.level is CapabilityLevel.UNKNOWN:
        return ConformanceAvailability.UNKNOWN
    if claim.level is CapabilityLevel.UNAVAILABLE:
        return ConformanceAvailability.UNAVAILABLE
    return ConformanceAvailability.RESOLVED


def _policy_relevant_material(
    request: AuthorizationRequest,
    *,
    event: NativeControlEvent,
    action_class: ActionClass,
) -> tuple[dict[str, Any], bool]:
    """Return only comparison fields the existing deterministic kernel reads.

    Provider spellings are translated only through the explicit semantic alias
    sets above.  The resulting semantic tool identity, target identity and
    destination identity all retain exact hashes.  Literal ``unknown`` values
    remain unknown even when an upstream adapter hashed that placeholder.
    """

    tool_identity, tool_hash, tool_known = _semantic_tool_identity(event, action_class)
    target_identity, target_hash, target_known = _exact_identity_and_hash(
        event.target.get("canonical_target") or event.target.get("resource"),
        event.target.get("resource_hash"),
    )
    destination_identity, destination_hash, destination_known = _exact_identity_and_hash(
        event.destination.get("destination"),
        event.destination.get("destination_hash"),
    )
    parameter_hash = _text(request.parameters.get("parameter_hash")).lower()
    parameter_known = (
        len(parameter_hash) == 64
        and all(character in "0123456789abcdef" for character in parameter_hash)
        and parameter_hash != stable_hash("unknown")
    )
    actor_identity = _text(request.actor.get("identity_id"))
    authority_type = _text(request.authority.get("authority_type"))
    authority_source = _text(request.authority.get("authority_source"))
    trust_known = all(
        _is_known_identity(value)
        for value in (actor_identity, authority_type, authority_source)
    ) and request.authority.get("verified") is True
    material = {
        "action_class": action_class.value,
        "actor_identity": actor_identity or "unknown",
        "authority_verified": request.authority.get("verified") is True,
        "authority_type": authority_type or "unknown",
        "authority_source": authority_source or "unknown",
        "parameter_hash": parameter_hash or "unknown",
        "semantic_tool_identity": tool_identity,
        "semantic_tool_hash": tool_hash,
        "target_identity": target_identity,
        "target_hash": target_hash,
        "destination_identity": destination_identity,
        "destination_hash": destination_hash,
        "persistent_side_effect": request.side_effect_context.get("persistent_side_effect") is True,
        "asset_status": _text(request.discovery_context.get("asset_status")) or "unknown",
        "policy_snapshot_id": request.policy_snapshot_id,
    }
    return material, all(
        (
            action_class is not ActionClass.UNKNOWN_ACTION,
            tool_known,
            target_known,
            destination_known,
            parameter_known,
            trust_known,
        )
    )


def _validate_event_binding(
    *,
    adapter: NativeControlAdapter,
    context: AdapterPipelineContext,
    event: NativeControlEvent,
) -> None:
    if event.tenant_id != context.tenant_id:
        raise ValueError("adapter_tenant_override_rejected")
    if event.integration_instance_id != context.integration_instance_id:
        raise ValueError("adapter_integration_override_rejected")
    if (
        event.provider != adapter.manifest.provider
        or event.product != adapter.manifest.product
    ):
        raise ValueError("adapter_provider_product_mismatch")
    if event.provider_version != context.provider_version:
        raise ValueError("adapter_provider_version_override_rejected")
    if event.adapter_version != adapter.manifest.adapter_version:
        raise ValueError("adapter_version_override_rejected")
    trusted_actor = dict(context.resolved_actor)
    for field in (
        "identity_id",
        "identity_type",
        "authority_type",
        "authority_source",
    ):
        if _text(event.actor.get(field)) != _text(trusted_actor.get(field)):
            raise ValueError("adapter_actor_authority_override_rejected")


class CrossProviderConformanceService:
    """Exercise existing adapters without creating a second authorization path."""

    def __init__(
        self,
        *,
        policy_evaluator: Callable[[AuthorizationRequest], AuthorizationResponse] = authorize_ai_action,
    ) -> None:
        self._policy_evaluator = policy_evaluator

    def normalize(
        self,
        adapter: NativeControlAdapter,
        context: AdapterPipelineContext,
        raw_payload: Mapping[str, Any],
        *,
        expected_action_class: ActionClass | None = None,
    ) -> CrossProviderConformanceOutcome:
        """Normalize one provider payload and retain unknowns rather than guess.

        ``expected_action_class`` is an assertion made by a fixture or caller,
        never a provider override.  A mismatch leaves the adapter's actual
        semantic class intact and reports ``UNKNOWN`` or ``UNAVAILABLE``.
        """

        event = adapter.normalize_event(raw_payload, context)
        _validate_event_binding(adapter=adapter, context=context, event=event)
        request = event.to_authorization_request()
        response = self._policy_evaluator(request)
        canonical_action = canonical_action_from_authorization(request, response)
        action_class = _canonical_action_class(event)
        version_state = adapter.manifest.provider_version_state(event.provider_version)
        availability = _capability_availability(adapter, action_class)
        if expected_action_class is not None and action_class is not expected_action_class:
            expected_availability = _capability_availability(adapter, expected_action_class)
            availability = (
                ConformanceAvailability.UNAVAILABLE
                if expected_availability is ConformanceAvailability.UNAVAILABLE
                else ConformanceAvailability.UNKNOWN
            )
        material, material_complete = _policy_relevant_material(
            request,
            event=event,
            action_class=action_class,
        )
        if version_state not in {
            ProviderVersionState.EXACT_TESTED,
            ProviderVersionState.VERIFIED_COMPATIBLE_RANGE,
        }:
            availability = ConformanceAvailability.UNKNOWN
        elif not material_complete and availability is ConformanceAvailability.RESOLVED:
            availability = ConformanceAvailability.UNKNOWN
        return CrossProviderConformanceOutcome(
            provider=event.provider,
            product=event.product,
            action_class=action_class,
            availability=availability,
            normalized_event=event,
            authorization_request=request,
            authorization_response=response,
            canonical_action=canonical_action,
            canonical_action_hash=str(canonical_action["canonical_action_hash"]),
            policy_relevant_material=material,
            version_state=version_state.value,
        )

    @staticmethod
    def equivalent(
        left: CrossProviderConformanceOutcome,
        right: CrossProviderConformanceOutcome,
    ) -> bool:
        """Return true only for fully resolved matching semantic material."""

        return (
            left.availability is ConformanceAvailability.RESOLVED
            and right.availability is ConformanceAvailability.RESOLVED
            and left.action_class is right.action_class
            and dict(left.policy_relevant_material) == dict(right.policy_relevant_material)
            and left.authorization_response == right.authorization_response
        )
