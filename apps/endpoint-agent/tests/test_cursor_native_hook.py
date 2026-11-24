from __future__ import annotations

import json
from pathlib import Path

from hawk_endpoint_agent.native_control.hook import (
    normalize_provider_event,
    provider_hook_output,
)
from hawk_endpoint_agent.native_control.installer import (
    NativeHookInstaller,
    cursor_hook_surface_coverage,
    cursor_settings_path,
)


def _helper(tmp_path: Path) -> Path:
    helper = tmp_path / "hawk-native-hook"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(0o700)
    return helper


def test_cursor_scope_paths_and_cloud_hook_truth_are_explicit(tmp_path: Path) -> None:
    assert cursor_settings_path("user", platform="darwin", home=tmp_path) == tmp_path / ".cursor/hooks.json"
    assert cursor_settings_path("project", platform="darwin", project_root=tmp_path) == tmp_path / ".cursor/hooks.json"
    assert str(cursor_settings_path("enterprise", platform="darwin")) == "/Library/Application Support/Cursor/hooks.json"
    assert str(cursor_settings_path("enterprise", platform="linux")) == "/etc/cursor/hooks.json"
    assert str(cursor_settings_path("enterprise", platform="win32")) == "C:\\ProgramData\\Cursor\\hooks.json"

    assert cursor_hook_surface_coverage("beforeMCPExecution", cloud_agent=False) == {
        "native_hook_covered": True,
        "reason": "cursor_local_hook_supported",
    }
    assert cursor_hook_surface_coverage("beforeMCPExecution", cloud_agent=True) == {
        "native_hook_covered": False,
        "reason": "cursor_cloud_hook_unsupported",
    }
    assert cursor_hook_surface_coverage("beforeShellExecution", cloud_agent=True)["native_hook_covered"] is True


def test_cursor_installer_is_fail_closed_idempotent_and_preserves_customer_hooks(tmp_path: Path) -> None:
    settings = tmp_path / "hooks.json"
    customer = {"command": "/opt/customer/audit", "timeout": 30}
    settings.write_text(
        json.dumps({"version": 1, "theme": "dark", "hooks": {"beforeShellExecution": [customer]}}),
        encoding="utf-8",
    )
    installer = NativeHookInstaller(provider="cursor", helper_path=_helper(tmp_path))

    first = installer.install(settings)
    second = installer.install(settings)
    payload = json.loads(settings.read_text(encoding="utf-8"))

    assert first.fingerprint == second.fingerprint
    assert payload["version"] == 1
    assert payload["theme"] == "dark"
    assert payload["hooks"]["beforeShellExecution"][1] == customer
    assert payload["hooks"]["beforeShellExecution"][0]["failClosed"] is True
    assert payload["hooks"]["beforeMCPExecution"][0]["failClosed"] is True
    assert payload["hooks"]["beforeReadFile"][0]["failClosed"] is True
    assert payload["hooks"]["beforeSubmitPrompt"][0]["failClosed"] is True
    assert payload["hooks"]["preToolUse"][0]["failClosed"] is True
    assert payload["hooks"]["preToolUse"][0]["matcher"] == "^(?!Shell$|Read$|Task$|MCP:).*"
    assert payload["hooks"]["postToolUse"][0]["matcher"] == "^(?!Shell$|Read$|Write$|Delete$|Task$|MCP:).*"
    assert payload["hooks"]["subagentStart"][0]["failClosed"] is True
    assert "failClosed" not in payload["hooks"]["afterAgentThought"][0]
    assert "--provider cursor" in payload["hooks"]["beforeShellExecution"][0]["command"]
    assert installer.detect_drift(settings, expected_fingerprint=first.fingerprint) == ()

    installer.uninstall(settings)
    restored = json.loads(settings.read_text(encoding="utf-8"))
    assert restored == {"version": 1, "theme": "dark", "hooks": {"beforeShellExecution": [customer]}}


def test_cursor_normalization_is_privacy_safe_and_correlates_workspace_identity_and_subagent() -> None:
    raw = {
        "conversation_id": "conv-private",
        "generation_id": "gen-private",
        "cursor_version": "9.9.9",
        "user_email": "bank.user@example.com",
        "model": "claude-opus-test",
        "workspace_roots": ["/private/bank/repo"],
        "transcript_path": "/private/transcript.jsonl",
        "tool_name": "Shell",
        "tool_input": {"command": "curl -H 'Authorization: sk-private-secret' https://example.invalid"},
        "tool_use_id": "tool-private",
        "subagent_id": "sub-private",
        "parent_conversation_id": "parent-private",
        "subagent_type": "explore",
        "git_branch": "private-feature",
        "is_parallel_worker": True,
        "execution_location": "local",
        "delegation_depth": 2,
        "task": "inspect private authentication design",
    }

    event = normalize_provider_event("cursor", "subagent_start", raw)

    assert event["action_type"] == "AGENT_INVOCATION"
    assert event["provider_app_version"] == "9.9.9"
    assert event["model"] == "claude-opus-test"
    assert event["execution_location"] == "local"
    assert event["is_parallel_worker"] is True
    assert event["delegation_depth"] == 2
    for field in (
        "provider_account_hash",
        "provider_session_hash",
        "provider_generation_hash",
        "workspace_hash",
        "branch_hash",
        "subagent_id_hash",
        "parent_session_hash",
    ):
        assert len(str(event[field])) == 64
    exported = str(event)
    assert "bank.user@example.com" not in exported
    assert "/private/bank/repo" not in exported
    assert "private-feature" not in exported
    assert "sk-private-secret" not in exported
    assert "inspect private authentication design" not in exported
    assert "transcript" not in exported.lower()


def test_cursor_never_exports_prompt_file_output_or_agent_thought_content() -> None:
    fixtures = (
        ("before_model", {"prompt": "private merger plan", "attachments": [{"name": "secret.pdf"}]}),
        ("before_file_read", {"file_path": "/private/secret.py", "content": "AWS_SECRET_ACCESS_KEY=private"}),
        ("after_tool", {"tool_output": "customer database contents"}),
        ("after_agent_thought", {"text": "private chain of thought", "duration_ms": 42}),
    )

    for event_name, raw in fixtures:
        event = normalize_provider_event("cursor", event_name, raw)
        exported = str(event)
        for forbidden in (
            "private merger plan",
            "secret.pdf",
            "/private/secret.py",
            "AWS_SECRET_ACCESS_KEY",
            "customer database contents",
            "private chain of thought",
        ):
            assert forbidden not in exported
        assert len(str(event["prompt_hash"])) == 64


def test_cursor_mcp_hook_is_classified_as_one_mcp_action_without_exporting_transport() -> None:
    event = normalize_provider_event(
        "cursor",
        "before_mcp",
        {
            "tool_name": "github_create_pull_request",
            "tool_input": '{"owner":"hawk","repo":"private"}',
            "url": "https://mcp.example.invalid/private-token",
        },
    )

    assert event["action_type"] == "MCP_TOOL_CALL"
    assert event["destination"] == "mcp"
    assert len(str(event["destination_hash"])) == 64
    assert "mcp.example.invalid" not in str(event)


def test_cursor_native_outputs_do_not_weaken_blocks_or_invent_mutation() -> None:
    block = {"decision": "block", "reason": "Hawk policy", "enforced": True}
    review = {"decision": "require_approval", "reason": "Approval required", "enforced": True}

    assert provider_hook_output("cursor", "before_shell", block) == {
        "permission": "deny",
        "user_message": "Hawk policy",
        "agent_message": "Hawk policy",
    }
    assert provider_hook_output("cursor", "before_mcp", review)["permission"] == "ask"
    assert provider_hook_output("cursor", "before_tool", review)["permission"] == "deny"
    assert provider_hook_output("cursor", "before_file_read", review)["permission"] == "deny"
    assert provider_hook_output("cursor", "subagent_start", review)["permission"] == "deny"
    assert provider_hook_output("cursor", "before_model", block) == {
        "continue": False,
        "user_message": "Hawk policy",
    }
    assert provider_hook_output("cursor", "after_tool", block) == {}
    assert "updated_input" not in str(provider_hook_output("cursor", "before_tool", block))
