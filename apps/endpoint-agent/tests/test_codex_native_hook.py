from __future__ import annotations

import json
from pathlib import Path

from hawk_endpoint_agent.native_control.hook import (
    normalize_provider_event,
    provider_hook_output,
)
from hawk_endpoint_agent.native_control.installer import (
    NativeHookInstaller,
    codex_managed_requirements_toml,
    codex_settings_path,
)


def _decision(value: str, *, enforced: bool = True) -> dict[str, object]:
    return {"decision": value, "reason": f"hawk:{value}", "enforced": enforced}


def test_codex_normalizes_prompt_shell_patch_mcp_and_post_evidence_separately() -> None:
    prompt = normalize_provider_event(
        "codex",
        "before_model",
        {"session_id": "private", "turn_id": "turn-1", "prompt": "do sensitive work"},
    )
    shell = normalize_provider_event(
        "codex",
        "before_tool",
        {"session_id": "private", "tool_name": "Bash", "tool_input": {"command": "echo demo"}},
    )
    patch = normalize_provider_event(
        "codex",
        "before_tool",
        {"session_id": "private", "tool_name": "apply_patch", "tool_input": {"command": "synthetic"}},
    )
    mcp = normalize_provider_event(
        "codex",
        "before_tool",
        {"session_id": "private", "tool_name": "mcp__github__create_pull_request", "tool_input": {"title": "demo"}},
    )
    post = normalize_provider_event(
        "codex",
        "after_tool",
        {"session_id": "private", "tool_name": "Bash", "tool_input": {"command": "echo demo"}, "tool_response": {"output": "secret"}},
    )

    assert prompt["action_type"] == "MODEL_REQUEST"
    assert prompt["tool_class"] == "unknown_tool"
    assert shell["action_type"] == "COMMAND_EXECUTION"
    assert shell["tool_class"] == "local_shell"
    assert patch["action_type"] == "FILE_WRITE"
    assert patch["tool_class"] == "apply_patch"
    assert mcp["action_type"] == "MCP_TOOL_CALL"
    assert mcp["tool_class"] == "local_mcp"
    assert post["evidence_quality"] == "provider_reported"
    assert "private" not in str(post)
    assert "secret" not in str(post)


def test_codex_serializes_each_native_decision_without_unsupported_ask() -> None:
    assert provider_hook_output("codex", "before_tool", _decision("block")) == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "hawk:block",
        }
    }
    assert provider_hook_output("codex", "before_tool", _decision("allow")) == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
        }
    }
    assert provider_hook_output("codex", "before_tool", _decision("warn")) == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "additionalContext": "hawk:warn",
        }
    }
    assert provider_hook_output("codex", "before_tool", _decision("require_approval"))[
        "hookSpecificOutput"
    ]["permissionDecision"] == "deny"
    assert provider_hook_output("codex", "before_model", _decision("block")) == {
        "decision": "block",
        "reason": "hawk:block",
    }
    assert provider_hook_output("codex", "after_tool", _decision("block")) == {}


def test_codex_permission_request_is_independent_from_pre_tool_authorization() -> None:
    allow = provider_hook_output("codex", "permission_request", _decision("allow"))
    deny = provider_hook_output("codex", "permission_request", _decision("require_second_approval"))

    assert allow == {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "allow"},
        }
    }
    assert deny == {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "deny", "message": "hawk:require_second_approval"},
        }
    }


def test_codex_local_installer_is_idempotent_tamper_evident_and_uninstalls_only_hawk(
    tmp_path: Path,
) -> None:
    helper = tmp_path / "hawk-native-hook"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(0o700)
    settings = tmp_path / ".codex" / "hooks.json"
    settings.parent.mkdir()
    customer = {"matcher": "^Bash$", "hooks": [{"type": "command", "command": "/safe/customer"}]}
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [customer]}}), encoding="utf-8")
    installer = NativeHookInstaller(provider="codex", helper_path=helper)

    first = installer.install(settings)
    second = installer.install(settings)
    payload = json.loads(settings.read_text(encoding="utf-8"))

    assert first.fingerprint == second.fingerprint
    assert first.changed is True
    assert second.changed is False
    assert payload["hooks"]["PreToolUse"][1] == customer
    assert set(payload["hooks"]) == {
        "SessionStart",
        "SessionEnd",
        "PreToolUse",
        "PermissionRequest",
        "PostToolUse",
        "PreCompact",
        "PostCompact",
        "UserPromptSubmit",
        "SubagentStart",
        "SubagentStop",
        "Stop",
        "Interrupt",
    }
    assert "--provider codex" in str(payload["hooks"]["PreToolUse"][0])
    assert installer.detect_drift(settings, expected_fingerprint=first.fingerprint) == ()

    payload["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] = 600
    settings.write_text(json.dumps(payload), encoding="utf-8")
    assert "hawk_hook_changed:PreToolUse" in installer.detect_drift(settings)

    installer.install(settings)
    installer.uninstall(settings)
    assert json.loads(settings.read_text(encoding="utf-8")) == {
        "hooks": {"PreToolUse": [customer]}
    }


def test_codex_interrupt_is_short_lived_and_normalised_as_session_context(
    tmp_path: Path,
) -> None:
    helper = tmp_path / "hawk-native-hook"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(0o700)
    settings = tmp_path / ".codex" / "hooks.json"
    installer = NativeHookInstaller(provider="codex", helper_path=helper)

    result = installer.install(settings)
    payload = json.loads(settings.read_text(encoding="utf-8"))
    interrupt = payload["hooks"]["Interrupt"][0]["hooks"][0]
    normalized = normalize_provider_event(
        "codex",
        "interrupt",
        {"session_id": "private", "turn_id": "turn-1"},
    )

    assert result.events[-1] == "Interrupt"
    assert interrupt["timeout"] == 1
    assert normalized["action_type"] == "SESSION_CONTEXT"
    assert normalized["persistent_side_effect"] is False
    assert "private" not in str(normalized)


def test_codex_paths_and_managed_only_requirements_are_explicit(tmp_path: Path) -> None:
    helper = tmp_path / "hawk-native-hook"
    config = tmp_path / "runtime.json"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    helper.chmod(0o700)
    config.write_text("{}", encoding="utf-8")
    config.chmod(0o600)

    assert codex_settings_path("user", platform="darwin", home=tmp_path) == tmp_path / ".codex/hooks.json"
    assert codex_settings_path("project", platform="darwin", project_root=tmp_path) == tmp_path / ".codex/hooks.json"
    assert str(codex_settings_path("managed", platform="darwin")) == "/etc/codex/requirements.toml"
    assert str(codex_settings_path("managed", platform="win32")) == r"C:\ProgramData\OpenAI\Codex\requirements.toml"

    rendered = codex_managed_requirements_toml(helper_path=helper, runtime_config_path=config)
    assert "allow_managed_hooks_only = true" in rendered
    assert "[features]\nhooks = true" in rendered
    assert "[[hooks.PreToolUse]]" in rendered
    assert "[[hooks.PermissionRequest]]" in rendered
    assert "[[hooks.UserPromptSubmit]]" in rendered
    assert "[[hooks.Interrupt]]" in rendered
    assert "timeout = 1" in rendered
    assert str(helper) in rendered
    assert str(config) in rendered
