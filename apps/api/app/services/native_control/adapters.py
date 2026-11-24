from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, ClassVar

from app.core.control_engine.authorization import AuthorizationRequest


MAX_PROVIDER_EVENT_BYTES = 65_536
ALLOWED_EVENT_FIELDS = {
    "callback_schema",
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
    "model",
    "provider_session_hash",
    "provider_tool_use_hash",
    "tail_call",
    "original_request_name_hash",
    "provider_event_type",
    "mcp_tool_name",
    "workspace_hash",
    "permission_mode",
    "agent_id_hash",
    "agent_type",
    "run_in_background",
    "execution_status",
    "evidence_quality",
    "failure_hash",
    "approval_action_hash",
    "permission_context_present",
    "permission_suggestions_hash",
    "config_source",
    "config_file_path_hash",
    "provider_generation_hash",
    "provider_account_hash",
    "provider_app_version",
    "branch_hash",
    "subagent_id_hash",
    "parent_session_hash",
    "subagent_type",
    "is_parallel_worker",
    "execution_location",
    "delegation_depth",
    "repository_control_resolution",
    "repository_operation",
    "repository_command_shape",
    "repository_command_hash",
    "repository_destination_hash",
    "repository_root_hash",
    "repository_common_dir_hash",
    "repository_target_hash",
}
HOSTILE_IDENTITY_FIELDS = {
    "tenant_id",
    "provider",
    "product",
    "user_id",
    "agent_id",
    "role",
    "risk",
    "approved",
    "policy",
}


@dataclass(frozen=True, slots=True)
class ProviderEventContext:
    tenant_id: str
    integration_instance_id: str
    environment: str
    credential_id: str
    event_id: str
    correlation_id: str
    session_id: str
    chain_id: str
    provider_version: str
    adapter_version: str
    integration_method: str
    resolved_actor: dict[str, str]
    policy_snapshot_id: str
    policy_profile: dict[str, Any]

    @classmethod
    def minimum_for_test(cls) -> "ProviderEventContext":
        return cls(
            tenant_id="tenant-1",
            integration_instance_id="integration-1",
            environment="test",
            credential_id="credential-1",
            event_id="event-1",
            correlation_id="correlation-1",
            session_id="session-1",
            chain_id="chain-1",
            provider_version="1.0",
            adapter_version="1.0.0",
            integration_method="gateway_inline",
            resolved_actor={
                "identity_id": "user-1",
                "identity_type": "human",
                "authority_type": "authenticated_user",
                "authority_source": "test_directory",
            },
            policy_snapshot_id="policy-1",
            policy_profile={"dependencies_healthy": True},
        )


class NativeProviderControlAdapter:
    provider: ClassVar[str]

    def __init__(self, *, product: str) -> None:
        self.product = str(product or "").strip().lower()
        if not self.product:
            raise ValueError("product_required")

    def normalize_event(
        self,
        *,
        context: ProviderEventContext,
        event: dict[str, Any],
    ) -> AuthorizationRequest:
        if not isinstance(event, dict):
            raise ValueError("provider_event_must_be_object")
        try:
            encoded = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("provider_event_must_be_json") from exc
        if len(encoded) > MAX_PROVIDER_EVENT_BYTES:
            raise ValueError("provider_event_too_large")
        unknown = sorted(set(event) - ALLOWED_EVENT_FIELDS - HOSTILE_IDENTITY_FIELDS)
        if unknown:
            raise ValueError(f"unknown_provider_event_field:{unknown[0]}")
        actor = {
            "identity_id": str(context.resolved_actor.get("identity_id") or "unknown"),
            "identity_type": str(context.resolved_actor.get("identity_type") or "unknown"),
            "session_id": context.session_id,
        }
        authority_type = str(context.resolved_actor.get("authority_type") or "unknown")
        authority_source = str(context.resolved_actor.get("authority_source") or "unknown")
        authority_verified = authority_type != "unknown" and authority_source != "unknown"
        parameter_hash = str(event.get("parameter_hash") or "unknown")
        destination = str(event.get("destination") or "unknown")
        destination_hash = str(event.get("destination_hash") or "unknown")
        target_resource = str(event.get("target_resource") or "unknown")
        target_hash = str(event.get("target_resource_hash") or "unknown")
        provider_event_type = str(event.get("provider_event_type") or "unknown")
        pre_execution = provider_event_type in {
            "before_agent",
            "before_tool",
            "before_model",
            "before_shell",
            "before_mcp",
            "before_file_read",
            "subagent_start",
        }
        route_verified = context.policy_profile.get("native_route_verified") is True
        approval_context: dict[str, Any] = {}
        if "provider_event_type" in event:
            approval_context["provider_event_type"] = provider_event_type
        if "permission_mode" in event:
            approval_context["permission_mode"] = str(event.get("permission_mode") or "unknown")
        if "approval_action_hash" in event:
            approval_context["approval_action_hash"] = str(
                event.get("approval_action_hash") or "unknown"
            )
        if event.get("permission_context_present") is True:
            approval_context["provider_permission_context"] = True
            approval_context["permission_suggestions_hash"] = str(
                event.get("permission_suggestions_hash") or "unknown"
            )
        if provider_event_type == "config_change":
            approval_context["config_source"] = str(event.get("config_source") or "unknown")
            approval_context["config_file_path_hash"] = str(
                event.get("config_file_path_hash") or "unknown"
            )
        surface = (
            "llm_gateway"
            if context.integration_method == "gateway_inline"
            else "runtime_control"
            if context.integration_method in {"native_hook", "endpoint_runtime", "agent_middleware", "tool_loop_intercept"}
            else "sdk"
        )
        return AuthorizationRequest(
            tenant_id=context.tenant_id,
            environment=context.environment,
            collector_id=f"native-control:{context.integration_instance_id}",
            action_id=context.event_id,
            chain_id=context.chain_id,
            surface=surface,
            actor=actor,
            authority={
                "verified": authority_verified,
                "authority_type": authority_type,
                "authority_source": authority_source,
            },
            runtime={
                "session_id": context.session_id,
                "correlation_id": context.correlation_id,
                "integration_instance_id": context.integration_instance_id,
                "credential_id": context.credential_id,
                "adapter_version": context.adapter_version,
                "workspace_hash": str(event.get("workspace_hash") or "unknown"),
                "permission_mode": str(event.get("permission_mode") or "unknown"),
                "agent_id_hash": str(event.get("agent_id_hash") or "unknown"),
                "agent_type": str(event.get("agent_type") or "unknown"),
                "provider_generation_hash": str(event.get("provider_generation_hash") or "unknown"),
                "provider_account_hash": str(event.get("provider_account_hash") or "unknown"),
                "provider_app_version": str(event.get("provider_app_version") or context.provider_version),
                "branch_hash": str(event.get("branch_hash") or "unknown"),
                "repository_control_resolution": str(event.get("repository_control_resolution") or "unknown"),
                "repository_operation": str(event.get("repository_operation") or "unknown"),
                "repository_command_shape": str(event.get("repository_command_shape") or "unknown"),
                "repository_command_hash": str(event.get("repository_command_hash") or "unknown"),
                "repository_destination_hash": str(event.get("repository_destination_hash") or "unknown"),
                "repository_root_hash": str(event.get("repository_root_hash") or "unknown"),
                "repository_common_dir_hash": str(event.get("repository_common_dir_hash") or "unknown"),
                "repository_target_hash": str(event.get("repository_target_hash") or "unknown"),
                "subagent_id_hash": str(event.get("subagent_id_hash") or "unknown"),
                "parent_session_hash": str(event.get("parent_session_hash") or "unknown"),
                "subagent_type": str(event.get("subagent_type") or "unknown"),
                "is_parallel_worker": event.get("is_parallel_worker") is True,
                "execution_location": str(event.get("execution_location") or "unknown"),
                "delegation_depth": (
                    int(event.get("delegation_depth"))
                    if isinstance(event.get("delegation_depth"), int)
                    else -1
                ),
            },
            purpose={},
            action={
                "action_type": str(event.get("action_type") or "unknown"),
                "action_class": str(event.get("tool_class") or "unknown_tool"),
                "risk_level": "unknown",
            },
            tool={
                "name": str(event.get("tool_name") or "unknown"),
                "version": str(event.get("tool_version") or "unknown"),
                "fingerprint_id": str(event.get("tool_fingerprint_id") or "unknown"),
            },
            parameters={"parameter_hash": parameter_hash},
            target={
                "resource": target_resource,
                "resource_hash": target_hash,
                "destination": destination,
                "destination_hash": destination_hash,
            },
            data_context={
                "prompt_hash": str(event.get("prompt_hash") or "unknown"),
                "response_hash": str(event.get("response_hash") or "unknown"),
                "classifications": list(event.get("data_classifications") or []),
                "execution_evidence_quality": str(event.get("evidence_quality") or "none"),
                "execution_status": str(event.get("execution_status") or "unknown"),
                "failure_hash": str(event.get("failure_hash") or "unknown"),
            },
            approval_context=approval_context,
            side_effect_context={
                "persistent_side_effect": event.get("persistent_side_effect") is True,
                "side_effect_class": str(event.get("side_effect_class") or "unknown"),
                "run_in_background": event.get("run_in_background") is True,
            },
            discovery_context={
                "provider": self.provider,
                "product": self.product,
                "provider_version": context.provider_version,
                "adapter_version": context.adapter_version,
                "model": str(event.get("model") or "unknown"),
                "mcp_server_id": str(event.get("mcp_server_id") or "unknown"),
                "tool_class": str(event.get("tool_class") or "unknown_tool"),
                "asset_status": "approved",
            },
            policy_snapshot_id=context.policy_snapshot_id,
            policy_profile=dict(context.policy_profile),
            path_evidence={
                "collector_inline_capable": pre_execution,
                "inline_pre_execution": pre_execution,
                "execution_prevented": (
                    pre_execution
                    and route_verified
                    and str(context.policy_profile.get("base_decision") or "").strip().lower()
                    == "block"
                ),
                "native_control_route_binding": {
                    "verified": route_verified,
                    "source": "authenticated_native_adapter",
                    "integration_instance_ids": [context.integration_instance_id],
                    "credential_id": context.credential_id,
                    "allowed_methods": [context.integration_method],
                },
            },
        )


class HawkAnthropicControlAdapter(NativeProviderControlAdapter):
    provider = "anthropic"


class HawkOpenAIControlAdapter(NativeProviderControlAdapter):
    """Compatibility-only OpenAI event normalizer.

    Product enforcement is implemented by the separate Agents SDK, Codex, and
    Direct API adapters. This class carries no provider-wide protected claim.
    """

    provider = "openai"


class HawkGoogleControlAdapter(NativeProviderControlAdapter):
    provider = "google"


class HawkCursorControlAdapter(NativeProviderControlAdapter):
    provider = "cursor"


class HawkMicrosoftControlAdapter(NativeProviderControlAdapter):
    provider = "microsoft"


class HawkAzureControlAdapter(NativeProviderControlAdapter):
    provider = "azure"


class HawkBedrockControlAdapter(NativeProviderControlAdapter):
    provider = "aws"


class HawkLlamaControlAdapter(NativeProviderControlAdapter):
    provider = "meta"


class HawkKimiControlAdapter(NativeProviderControlAdapter):
    provider = "moonshot_kimi"


class HawkQwenControlAdapter(NativeProviderControlAdapter):
    provider = "alibaba_qwen"


class HawkDeepSeekControlAdapter(NativeProviderControlAdapter):
    provider = "deepseek"


ADAPTERS = {
    adapter.provider: adapter
    for adapter in (
        HawkAnthropicControlAdapter,
        HawkOpenAIControlAdapter,
        HawkGoogleControlAdapter,
        HawkCursorControlAdapter,
        HawkMicrosoftControlAdapter,
        HawkAzureControlAdapter,
        HawkBedrockControlAdapter,
        HawkLlamaControlAdapter,
        HawkKimiControlAdapter,
        HawkQwenControlAdapter,
        HawkDeepSeekControlAdapter,
    )
}


from app.services.native_control.openai_adapters import (  # noqa: E402
    CodexNativeControlAdapter,
    OpenAIAgentsSDKControlAdapter,
    OpenAIDirectAPIControlAdapter,
)


OPENAI_PRODUCT_ADAPTERS = (
    OpenAIAgentsSDKControlAdapter,
    CodexNativeControlAdapter,
    OpenAIDirectAPIControlAdapter,
)
