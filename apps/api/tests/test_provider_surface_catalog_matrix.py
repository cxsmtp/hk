from __future__ import annotations

from app.services.provider_catalog import resolve_provider
from app.services.shadow_ai.provider_catalog import infer_from_signal


def test_browser_saas_provider_resolution() -> None:
    resolved = resolve_provider(
        {
            "domain": "chat.openai.com",
            "tool_name": "ChatGPT",
            "api_endpoint": "https://chat.openai.com/",
        },
        source_surface="browser",
    )
    assert resolved["catalog_match"] is True
    assert resolved["provider_id"] == "openai_chatgpt"
    assert resolved["provider_type"] == "saas_ai"
    assert resolved["surface_policy_mode"] == "enforceable"
    assert resolved["enforcement_supported_for_source"] is True
    assert resolved["behavior_profile"] == "browser_prompt_and_data_movement_control"


def test_gateway_api_provider_resolution() -> None:
    resolved = resolve_provider(
        {
            "api_endpoint": "https://api.anthropic.com/v1/messages",
            "provider": "anthropic",
            "model_name": "claude-3.7-sonnet",
        },
        source_surface="gateway",
    )
    assert resolved["catalog_match"] is True
    assert resolved["provider_id"] == "anthropic_api"
    assert resolved["provider_type"] == "model_api"
    assert resolved["surface_policy_mode"] == "enforceable"
    assert resolved["enforcement_supported_for_source"] is True
    assert resolved["behavior_profile"] == "gateway_request_response_and_tool_control"


def test_custom_domain_identity_not_collapsed_to_provider_id() -> None:
    inferred = infer_from_signal(
        {
            "source_surface": "connector",
            "domain": "candidate-shadow.example.ai",
            "tool_name": "candidate-shadow.example.ai",
            "provider": "openai",
            "model_provider": "openai",
            "model_name": "gpt-4.1",
        }
    )
    assert inferred["canonical_key"] == "candidate-shadow.example.ai"
    assert inferred["tool_name"] == "candidate-shadow.example.ai"


def test_endpoint_local_inference_provider_resolution() -> None:
    resolved = resolve_provider(
        {
            "process_name": "ollama",
            "api_endpoint": "http://localhost:11434/api/chat",
            "domain": "localhost",
            "tool_name": "ollama",
        },
        source_surface="endpoint",
    )
    assert resolved["catalog_match"] is True
    assert resolved["provider_id"] == "ollama"
    assert resolved["provider_type"] == "local_model"
    assert resolved["surface_policy_mode"] == "monitoring_only"
    assert resolved["enforcement_supported_for_source"] is False
    assert resolved["monitoring_only_for_source"] is True


def test_aiiam_agent_framework_resolution() -> None:
    resolved = resolve_provider(
        {
            "api_endpoint": "/gateway/mcp/authorize",
            "tool_name": "mcp server",
        },
        source_surface="aiiam",
    )
    assert resolved["catalog_match"] is True
    assert resolved["provider_id"] == "mcp_tools"
    assert resolved["provider_type"] == "agent_framework"
    assert resolved["surface_policy_mode"] == "enforceable"
    assert resolved["enforcement_supported_for_source"] is True
    assert resolved["behavior_profile"] == "agent_identity_and_action_scope_enforcement"


def test_connector_provider_resolution_is_monitoring_only_mode() -> None:
    resolved = resolve_provider(
        {
            "domain": "api.openai.com",
            "provider": "openai",
            "model_name": "gpt-4.1",
            "tool_name": "openai api",
        },
        source_surface="connector",
    )
    assert resolved["catalog_match"] is True
    assert resolved["provider_id"] == "openai_api"
    assert resolved["provider_type"] == "model_api"
    assert resolved["surface_policy_mode"] == "monitoring_only"
    assert resolved["enforcement_supported_for_source"] is False
    assert resolved["monitoring_only_for_source"] is True


def test_microsoft_foundry_surface_is_first_class_but_monitoring_only_unless_routed() -> None:
    detected = resolve_provider(
        {
            "domain": "ai.azure.com",
            "api_endpoint": "https://ai.azure.com/projects/proj/agents/agent-1/runs",
            "tool_name": "Azure AI Foundry Agent",
            "provider": "azure ai foundry",
        },
        source_surface="foundry",
    )
    assert detected["catalog_match"] is True
    assert detected["provider_id"] == "microsoft_foundry"
    assert detected["provider_type"] == "agentic_platform"
    assert detected["surface_policy_mode"] == "monitoring_only"
    assert detected["enforcement_supported_for_source"] is False
    assert detected["monitoring_only_for_source"] is True

    routed = resolve_provider(
        {
            "domain": "ai.azure.com",
            "api_endpoint": "https://ai.azure.com/projects/proj/agents/agent-1/runs",
            "tool_name": "Azure AI Foundry Agent",
            "provider": "azure ai foundry",
        },
        source_surface="gateway",
    )
    assert routed["provider_id"] == "microsoft_foundry"
    assert routed["surface_policy_mode"] == "enforceable"
    assert routed["enforcement_supported_for_source"] is True


def test_microsoft_copilot_and_copilot_studio_surfaces_are_first_class_monitoring_only() -> None:
    copilot = resolve_provider(
        {
            "domain": "copilot.microsoft.com",
            "tool_name": "Microsoft 365 Copilot",
            "provider": "m365 copilot",
        },
        source_surface="copilot",
    )
    assert copilot["catalog_match"] is True
    assert copilot["provider_id"] == "microsoft_copilot"
    assert copilot["surface_policy_mode"] == "monitoring_only"
    assert copilot["enforcement_supported_for_source"] is False

    studio = resolve_provider(
        {
            "domain": "copilotstudio.microsoft.com",
            "api_endpoint": "https://copilotstudio.microsoft.com/environments/env/bots/bot-1",
            "tool_name": "Copilot Studio Agent",
            "provider": "copilot studio",
        },
        source_surface="copilot",
    )
    assert studio["catalog_match"] is True
    assert studio["provider_id"] == "microsoft_copilot_studio"
    assert studio["provider_type"] == "agentic_platform"
    assert studio["surface_policy_mode"] == "monitoring_only"
