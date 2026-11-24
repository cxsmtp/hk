from __future__ import annotations

import pytest

from app.services.native_control.adapters import (
    HawkAnthropicControlAdapter,
    HawkAzureControlAdapter,
    HawkBedrockControlAdapter,
    HawkCursorControlAdapter,
    HawkDeepSeekControlAdapter,
    HawkGoogleControlAdapter,
    HawkKimiControlAdapter,
    HawkLlamaControlAdapter,
    HawkMicrosoftControlAdapter,
    HawkOpenAIControlAdapter,
    HawkQwenControlAdapter,
    ProviderEventContext,
)


ADAPTERS = (
    (HawkAnthropicControlAdapter, "anthropic"),
    (HawkOpenAIControlAdapter, "openai"),
    (HawkGoogleControlAdapter, "google"),
    (HawkCursorControlAdapter, "cursor"),
    (HawkMicrosoftControlAdapter, "microsoft"),
    (HawkAzureControlAdapter, "azure"),
    (HawkBedrockControlAdapter, "aws"),
    (HawkLlamaControlAdapter, "meta"),
    (HawkKimiControlAdapter, "moonshot_kimi"),
    (HawkQwenControlAdapter, "alibaba_qwen"),
    (HawkDeepSeekControlAdapter, "deepseek"),
)


@pytest.mark.parametrize(("adapter_type", "provider"), ADAPTERS)
def test_provider_adapter_normalizes_to_existing_authorization_contract(adapter_type, provider: str) -> None:
    adapter = adapter_type(product="direct_api")
    context = ProviderEventContext(
        tenant_id="tenant-trusted",
        integration_instance_id="integration-1",
        environment="production",
        credential_id="credential-1",
        event_id="event-1",
        correlation_id="correlation-1",
        session_id="session-1",
        chain_id="chain-1",
        provider_version="1.0",
        adapter_version="1.0.0",
        integration_method="gateway_inline",
        resolved_actor={
            "identity_id": "trusted-user",
            "identity_type": "human",
            "authority_type": "authenticated_user",
            "authority_source": "tenant_directory",
        },
        policy_snapshot_id="policy-7",
        policy_profile={"dependencies_healthy": True, "base_decision": "allow"},
    )
    hostile_payload = {
        "tenant_id": "attacker-tenant",
        "provider": "attacker-provider",
        "user_id": "admin",
        "role": "owner",
        "risk": "safe",
        "approved": True,
        "action_type": "tool_execution",
        "tool_name": "github.create_pull_request",
        "tool_fingerprint_id": "github-pr-v1",
        "parameter_hash": "p" * 64,
        "target_resource": "github/repository",
        "target_resource_hash": "t" * 64,
        "destination": "github.com",
        "destination_hash": "d" * 64,
        "persistent_side_effect": True,
    }

    request = adapter.normalize_event(context=context, event=hostile_payload)

    assert request.tenant_id == "tenant-trusted"
    assert request.discovery_context["provider"] == provider
    assert request.actor["identity_id"] == "trusted-user"
    assert request.authority == {
        "verified": True,
        "authority_type": "authenticated_user",
        "authority_source": "tenant_directory",
    }
    assert request.action["risk_level"] == "unknown"
    assert request.approval_context == {}
    assert request.parameters["parameter_hash"] == "p" * 64
    assert request.target["destination_hash"] == "d" * 64


def test_adapter_rejects_unknown_or_unbounded_provider_event_fields() -> None:
    adapter = HawkOpenAIControlAdapter(product="direct_api")
    context = ProviderEventContext.minimum_for_test()

    with pytest.raises(ValueError, match="unknown_provider_event_field"):
        adapter.normalize_event(context=context, event={"action_type": "prompt", "surprise": "value"})

    with pytest.raises(ValueError, match="provider_event_too_large"):
        adapter.normalize_event(context=context, event={"action_type": "prompt", "prompt_hash": "x" * 70_000})


def test_claude_callback_projection_preserves_safe_context_and_never_labels_post_evidence_inline() -> None:
    adapter = HawkAnthropicControlAdapter(product="claude_code")
    context = ProviderEventContext.minimum_for_test()
    base = {
        "action_type": "MCP_TOOL_CALL",
        "tool_name": "mcp__github__create_pull_request",
        "tool_fingerprint_id": "f" * 64,
        "parameter_hash": "p" * 64,
        "target_resource": "workspace",
        "target_resource_hash": "t" * 64,
        "destination": "github",
        "destination_hash": "d" * 64,
        "persistent_side_effect": True,
        "side_effect_class": "persistent",
        "mcp_server_id": "github",
        "mcp_tool_name": "create_pull_request",
        "workspace_hash": "w" * 64,
        "permission_mode": "bypassPermissions",
        "agent_id_hash": "a" * 64,
        "agent_type": "Explore",
        "run_in_background": False,
        "execution_status": "pending",
        "evidence_quality": "none",
        "failure_hash": "unknown",
        "provider_event_type": "before_tool",
    }

    pre = adapter.normalize_event(context=context, event=base)
    post = adapter.normalize_event(
        context=context,
        event={
            **base,
            "provider_event_type": "after_tool",
            "execution_status": "succeeded",
            "evidence_quality": "provider_reported",
        },
    )
    permission = adapter.normalize_event(
        context=context,
        event={
            **base,
            "provider_event_type": "permission_request",
            "approval_action_hash": "q" * 64,
            "permission_context_present": True,
            "permission_suggestions_hash": "s" * 64,
        },
    )

    assert pre.runtime["workspace_hash"] == "w" * 64
    assert pre.runtime["permission_mode"] == "bypassPermissions"
    assert pre.runtime["agent_id_hash"] == "a" * 64
    assert pre.approval_context["provider_event_type"] == "before_tool"
    assert pre.discovery_context["mcp_server_id"] == "github"
    assert pre.path_evidence["inline_pre_execution"] is True
    assert post.path_evidence["inline_pre_execution"] is False
    assert post.path_evidence["collector_inline_capable"] is False
    assert post.data_context["execution_evidence_quality"] == "provider_reported"
    assert permission.path_evidence["inline_pre_execution"] is False
    assert permission.approval_context["provider_permission_context"] is True
    assert permission.approval_context["approval_action_hash"] == "q" * 64
