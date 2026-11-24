from __future__ import annotations

from dataclasses import replace

from app.services.native_control.contracts import ProviderVersionState
from app.services.native_control.adapter_contract import AdapterPipelineContext
from app.services.native_control.claude_surfaces import claude_surface_control
from app.services.native_control.contracts import (
    CapabilityDimension,
    CapabilityLevel,
    VerificationStatus,
)
from app.services.native_control.openai_adapters import (
    CodexNativeControlAdapter,
    OpenAIAgentsSDKControlAdapter,
)
from app.services.native_control.openai_action_matrix import (
    OpenAIActionClass,
    build_openai_action_control_matrix,
)
from app.services.native_control.cursor_adapter import CursorAdapter
from app.services.native_control.gemini_cli_adapter import GeminiCliAdapter


def test_openai_agents_sdk_newer_version_never_inherits_exact_function_tool_evidence() -> None:
    """Function-tool evidence is reviewed for 0.20.0, not a broad SDK range."""

    manifest = OpenAIAgentsSDKControlAdapter().manifest

    assert manifest.provider_version_state("0.20.0") is ProviderVersionState.EXACT_TESTED
    assert manifest.provider_version_state("0.20.1") is ProviderVersionState.UNVERIFIED_NEWER
    assert manifest.provider_version_state("unknown") is ProviderVersionState.UNKNOWN


def test_codex_records_model_route_separately_from_remote_execution_location() -> None:
    """A local Codex client may use a non-OpenAI model route and remote executor."""

    event = CodexNativeControlAdapter().normalize_event(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "model": "claude-sonnet",
            "model_provider": "aws_bedrock",
            "model_deployment": "bedrock:us-east-1:cross-region",
            "execution_location": "remote_agent",
        },
        replace(
            AdapterPipelineContext.reference(
                tenant_id="tenant-1",
                integration_instance_id="codex-1",
                provider_event_id="codex-event-1",
            ),
            provider_version="0.137.0",
        ),
    )

    assert event.provider == "openai"
    assert event.product == "codex"
    assert event.model["provider"] == "aws_bedrock"
    assert event.model["deployment"] == "bedrock:us-east-1:cross-region"
    assert event.runtime["execution_location"] == "remote_agent"


def test_cursor_remote_machine_event_never_claims_local_endpoint_execution_authority() -> None:
    """Cursor remote execution is a distinct runtime, even when the IDE is local."""

    event = CursorAdapter().normalize_event(
        {
            "hook_event_name": "beforeShellExecution",
            "command": "git status",
            "execution_location": "remote_machine",
        },
        replace(
            AdapterPipelineContext.reference(
                tenant_id="tenant-1",
                integration_instance_id="cursor-1",
                provider_event_id="cursor-event-1",
            ),
            provider_version="2026.08.11-e8db854",
        ),
    )

    assert event.runtime["runtime_profile"] == "cursor_remote_machine"
    assert event.runtime["endpoint_execution_authority"] is False


def test_codex_remote_action_never_inherits_the_local_endpoint_floor() -> None:
    """Codex local hooks provide initiation context, not cloud execution control."""

    event = CodexNativeControlAdapter().normalize_event(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "execution_location": "remote_agent",
        },
        replace(
            AdapterPipelineContext.reference(
                tenant_id="tenant-1",
                integration_instance_id="codex-1",
                provider_event_id="codex-remote-event-1",
            ),
            provider_version="0.137.0",
        ),
    )

    assert event.runtime["runtime_profile"] == "codex_remote"
    assert event.runtime["endpoint_execution_authority"] is False


def test_claude_desktop_chat_never_inherits_claude_code_cli_hook_coverage() -> None:
    code_cli = claude_surface_control("code_cli")
    desktop_chat = claude_surface_control("desktop_chat")

    assert code_cli.native_hook_capable is True
    assert desktop_chat.native_hook_capable is False
    assert desktop_chat.control_method == "mcp_gateway_and_endpoint"


def test_gemini_post_tool_event_is_evidence_not_pre_execution_authorization() -> None:
    event = GeminiCliAdapter().normalize_event(
        {
            "hook_event_name": "AfterTool",
            "tool_name": "write_file",
            "tool_input": {"file_path": "/tmp/after.txt"},
        },
        replace(
            AdapterPipelineContext.reference(
                tenant_id="tenant-1",
                integration_instance_id="gemini-1",
                provider_event_id="gemini-after-tool-1",
            ),
            provider_version="0.54.4",
        ),
    )

    assert event.lifecycle_stage == "after_tool"
    assert event.timing["pre_execution"] is False
    assert (
        GeminiCliAdapter.manifest.capabilities[
            CapabilityDimension.POST_EXECUTION_VERIFICATION
        ].level
        is CapabilityLevel.UNAVAILABLE
    )


def test_openai_agents_function_tool_evidence_never_propagates_to_hosted_or_delegated_actions() -> None:
    matrix = build_openai_action_control_matrix()
    function = matrix.resolve(
        "agents_sdk",
        OpenAIActionClass.FUNCTION_TOOL,
        OpenAIAgentsSDKControlAdapter.matrix_method,
    )

    assert (
        function.claim(CapabilityDimension.FUNCTION_TOOL_CONTROL).verification_status
        is VerificationStatus.VERIFIED
    )
    for action_class in (
        OpenAIActionClass.HOSTED_WEB_SEARCH,
        OpenAIActionClass.HOSTED_MCP,
        OpenAIActionClass.COMPUTER_TOOL,
        OpenAIActionClass.AGENT_AS_TOOL,
        OpenAIActionClass.HANDOFF,
        OpenAIActionClass.UNKNOWN_TOOL,
    ):
        profile = matrix.resolve(
            "agents_sdk",
            action_class,
            OpenAIAgentsSDKControlAdapter.matrix_method,
        )
        assert profile.claim(CapabilityDimension.FUNCTION_TOOL_CONTROL).level is CapabilityLevel.UNAVAILABLE
        assert (
            profile.claim(CapabilityDimension.FUNCTION_TOOL_CONTROL).verification_status
            is VerificationStatus.UNVERIFIED
        )
