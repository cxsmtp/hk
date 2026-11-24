from __future__ import annotations

from hawk_endpoint_agent.native_control.hook import normalize_provider_event, provider_hook_output


def test_provider_outputs_apply_real_native_block_contracts() -> None:
    decision = {"decision": "block", "reason": "persistent side effect", "enforced": True}

    assert provider_hook_output("gemini_cli", "before_tool", decision) == {
        "decision": "deny",
        "reason": "persistent side effect",
        "systemMessage": "Hawk blocked this action before execution.",
    }
    assert provider_hook_output("claude_code", "before_tool", decision) == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "persistent side effect",
        }
    }


def test_claude_outputs_preserve_warn_approval_second_approval_and_redaction_strength() -> None:
    def output(decision: str):
        return provider_hook_output(
            "claude_code",
            "before_tool",
            {"decision": decision, "reason": f"hawk:{decision}", "enforced": True},
        )["hookSpecificOutput"]

    assert output("allow")["permissionDecision"] == "allow"
    assert output("warn")["permissionDecision"] == "ask"
    assert output("review")["permissionDecision"] == "deny"
    assert output("require_approval")["permissionDecision"] == "deny"
    assert output("require_second_approval")["permissionDecision"] == "deny"
    assert output("redact")["permissionDecision"] == "deny"
    assert all("updatedInput" not in output(decision) for decision in (
        "allow", "warn", "require_approval", "require_second_approval", "redact"
    ))


def test_claude_permission_request_is_separate_from_pre_tool_authorization() -> None:
    allow = provider_hook_output(
        "claude_code",
        "permission_request",
        {"decision": "allow", "reason": "approved", "enforced": True},
    )
    deny = provider_hook_output(
        "claude_code",
        "permission_request",
        {"decision": "require_second_approval", "reason": "second approval required", "enforced": True},
    )

    assert allow == {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "allow"},
        }
    }
    assert deny == {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "deny", "message": "second approval required"},
        }
    }


def test_claude_permission_correlation_requires_exact_invocation_and_material() -> None:
    common = {
        "session_id": "session-private",
        "cwd": "/private/workspace",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_input": {"command": "/usr/bin/true", "description": "safe acceptance"},
    }
    pre = normalize_provider_event("claude_code", "before_tool", {**common, "tool_use_id": "tool-private"})
    permission = normalize_provider_event(
        "claude_code",
        "permission_request",
        {
            **common,
            "permission_suggestions": [
                {
                    "type": "addRules",
                    "rules": [{"toolName": "Bash", "ruleContent": "/usr/bin/true"}],
                    "behavior": "allow",
                    "destination": "localSettings",
                }
            ],
        },
    )
    changed = normalize_provider_event(
        "claude_code",
        "permission_request",
        {**common, "tool_input": {"command": "/usr/bin/false"}},
    )

    assert permission["provider_event_type"] == "permission_request"
    assert permission["callback_schema"] == "hawk-native-hash-envelope/v1"
    # Matching content without an invocation ID cannot inherit authorization.
    assert permission["approval_action_hash"] != pre["approval_action_hash"]
    identified_permission = normalize_provider_event(
        "claude_code", "permission_request", {**common, "tool_use_id": "tool-private"}
    )
    assert identified_permission["approval_action_hash"] == pre["approval_action_hash"]
    other_invocation = normalize_provider_event(
        "claude_code", "before_tool", {**common, "tool_use_id": "other-tool"}
    )
    assert other_invocation["approval_action_hash"] != pre["approval_action_hash"]
    changed_identified = normalize_provider_event(
        "claude_code", "permission_request",
        {**common, "tool_use_id": "tool-private", "tool_input": {"command": "/usr/bin/false"}},
    )
    assert changed_identified["approval_action_hash"] != pre["approval_action_hash"]
    assert permission["approval_action_hash"] != changed["approval_action_hash"]
    assert permission["permission_context_present"] is True
    assert len(permission["permission_suggestions_hash"]) == 64
    assert "localSettings" not in str(permission)
    assert "session-private" not in str(permission)


def test_monitor_or_after_event_never_claims_native_prevention() -> None:
    decision = {"decision": "allow", "would_decision": "block", "enforced": False}
    assert provider_hook_output("gemini_cli", "before_tool", decision)["decision"] == "allow"
    assert provider_hook_output("claude_code", "after_tool", decision) == {}


def test_claude_config_change_can_fail_closed_without_becoming_tool_authorization() -> None:
    assert provider_hook_output(
        "claude_code",
        "config_change",
        {"decision": "block", "reason": "Hawk configuration integrity unavailable", "enforced": True},
    ) == {
        "decision": "block",
        "reason": "Hawk configuration integrity unavailable",
    }


def test_claude_config_change_is_secondary_privacy_safe_integrity_telemetry() -> None:
    event = normalize_provider_event(
        "claude_code",
        "config_change",
        {
            "session_id": "private-session",
            "source": "user_settings",
            "file_path": "/Users/private/.claude/settings.json",
        },
    )

    assert event["action_type"] == "SESSION_CONTEXT"
    assert event["config_source"] == "user_settings"
    assert len(event["config_file_path_hash"]) == 64
    assert "/Users/private" not in str(event)


def test_claude_subagent_context_is_private_observation_not_authorization() -> None:
    event = normalize_provider_event(
        "claude_code",
        "subagent_context_start",
        {
            "session_id": "private-parent",
            "agent_id": "private-child",
            "agent_type": "Explore",
            "prompt": "raw delegated task",
            "transcript_path": "/private/transcript.jsonl",
        },
    )

    assert event["provider_event_type"] == "subagent_context_start"
    assert event["action_type"] == "SESSION_CONTEXT"
    assert event["evidence_quality"] == "provider_reported"
    assert event["agent_type"] == "Explore"
    assert len(event["agent_id_hash"]) == 64
    assert "private-parent" not in str(event)
    assert "private-child" not in str(event)
    assert "raw delegated task" not in str(event)
    assert "transcript" not in str(event).lower()
    assert provider_hook_output(
        "claude_code",
        "subagent_context_start",
        {"decision": "block", "reason": "not an authorization event", "enforced": True},
    ) == {}


def test_hook_normalization_hashes_parameters_and_never_exports_raw_secrets() -> None:
    raw = {
        "session_id": "session-1",
        "tool_name": "mcp__github__create_pull_request",
        "tool_input": {"title": "demo", "token": "sk-not-a-real-secret-value"},
    }
    event = normalize_provider_event("claude_code", "before_tool", raw)

    assert event["action_type"] == "MCP_TOOL_CALL"
    assert event["mcp_server_id"] == "github"
    assert event["mcp_tool_name"] == "create_pull_request"
    assert event["persistent_side_effect"] is True
    assert len(event["parameter_hash"]) == 64
    assert "sk-not-a-real-secret-value" not in str(event)
    assert "secret" in event["data_classifications"]


def test_hook_normalization_preserves_safe_claude_context_without_transcript_or_raw_inputs() -> None:
    event = normalize_provider_event(
        "claude_code",
        "before_tool",
        {
            "session_id": "private-session",
            "transcript_path": "/private/transcript.jsonl",
            "cwd": "/private/workspace",
            "permission_mode": "bypassPermissions",
            "agent_id": "agent-private",
            "agent_type": "Explore",
            "tool_name": "Bash",
            "tool_input": {
                "command": "echo synthetic",
                "description": "synthetic test",
                "timeout": 30,
                "run_in_background": True,
            },
            "tool_use_id": "tool-private",
        },
    )

    assert event["action_type"] == "COMMAND_EXECUTION"
    assert event["permission_mode"] == "bypassPermissions"
    assert event["run_in_background"] is True
    assert len(event["workspace_hash"]) == 64
    assert len(event["agent_id_hash"]) == 64
    assert event["agent_type"] == "Explore"
    assert "transcript" not in str(event).lower()
    assert "/private/workspace" not in str(event)
    assert "echo synthetic" not in str(event)


def test_unknown_claude_tools_are_not_underclassified() -> None:
    event = normalize_provider_event(
        "claude_code",
        "before_tool",
        {"tool_name": "VendorMagic", "tool_input": {"opaque": True}},
    )

    assert event["action_type"] == "UNKNOWN_TOOL_ACTION"
    assert event["side_effect_class"] == "unknown"
    assert event["persistent_side_effect"] is True


def test_claude_pre_and_post_events_have_stable_private_correlation_and_result_evidence() -> None:
    pre = normalize_provider_event(
        "claude_code",
        "before_tool",
        {
            "session_id": "session-private",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "tool_use_id": "toolu_private",
        },
    )
    post = normalize_provider_event(
        "claude_code",
        "after_tool",
        {
            "session_id": "session-private",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "tool_use_id": "toolu_private",
            "tool_response": {"stdout": "sensitive output", "stderr": "", "interrupted": False},
        },
    )

    assert pre["provider_session_hash"] == post["provider_session_hash"]
    assert pre["provider_tool_use_hash"] == post["provider_tool_use_hash"]
    assert pre["approval_action_hash"] == post["approval_action_hash"]
    assert pre["parameter_hash"] == post["parameter_hash"]
    assert pre["persistent_side_effect"] is True
    assert pre["side_effect_class"] == "persistent"
    assert len(post["response_hash"]) == 64
    assert "session-private" not in str(pre)
    assert "toolu_private" not in str(post)
    assert "sensitive output" not in str(post)


def test_missing_tool_use_id_is_explicitly_unknown_not_a_shared_empty_digest() -> None:
    first = normalize_provider_event(
        "claude_code",
        "before_tool",
        {"tool_name": "Read", "tool_input": {"path": "README.md"}},
    )
    second = normalize_provider_event(
        "claude_code",
        "before_tool",
        {"tool_name": "Read", "tool_input": {"path": "README.md"}},
    )

    assert first["provider_tool_use_hash"] == "unknown"
    assert second["provider_tool_use_hash"] == "unknown"
    assert first["approval_action_hash"] != second["approval_action_hash"]


def test_post_tool_failure_is_provider_reported_and_correlates_without_claiming_prevention() -> None:
    event = normalize_provider_event(
        "claude_code",
        "after_tool_failure",
        {
            "session_id": "session-private",
            "hook_event_name": "PostToolUseFailure",
            "tool_name": "Bash",
            "tool_input": {"command": "/usr/bin/false"},
            "tool_use_id": "toolu_private",
            "error": "synthetic failure",
            "is_interrupt": False,
        },
    )

    assert event["execution_status"] == "failed"
    assert event["evidence_quality"] == "provider_reported"
    assert provider_hook_output("claude_code", "after_tool_failure", {"decision": "block", "enforced": True}) == {}


def test_repository_tool_events_carry_signed_operation_and_hashes_for_each_provider_surface(tmp_path) -> None:
    import subprocess

    root = tmp_path / "repo"
    root.mkdir()
    (root / "tracked.txt").write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    target = root / "tracked.txt"

    events = (
        normalize_provider_event(
            "claude_code", "before_tool",
            {"cwd": str(root), "tool_name": "Read", "tool_input": {"file_path": str(target)}},
        ),
        normalize_provider_event(
            "codex", "before_tool",
            {"cwd": str(root), "tool_name": "apply_patch", "tool_input": {"file_path": str(target)}},
        ),
        normalize_provider_event(
            "cursor", "before_file_read", {"cwd": str(root), "file_path": str(target)},
        ),
    )

    assert events[0]["repository_operation"] == "READ"
    assert events[1]["repository_operation"] == "EDIT"
    assert events[2]["repository_operation"] == "READ"
    for event in events:
        assert event["repository_control_resolution"] == "resolved"
        assert len(event["repository_root_hash"]) == 64
        assert len(event["repository_common_dir_hash"]) == 64
        assert len(event["repository_target_hash"]) == 64
        assert len(event["repository_command_shape"]) <= 64
        assert str(root) not in str(event)

    for provider in ("claude_code", "codex"):
        for tool_name in ("Write", "Edit", "apply_patch"):
            write_event = normalize_provider_event(
                provider,
                "before_tool",
                {"cwd": str(root), "tool_name": tool_name, "tool_input": {"file_path": str(target)}},
            )
            assert write_event["repository_operation"] == "EDIT", (provider, tool_name)
            assert write_event["repository_control_resolution"] == "resolved"

    codex_shell = normalize_provider_event(
        "codex", "before_tool",
        {
            "tool_name": "exec_command",
            "tool_input": {"cmd": "git status", "workdir": str(root)},
        },
    )
    assert codex_shell["action_type"] == "COMMAND_EXECUTION"
    assert codex_shell["repository_operation"] == "READ"
    assert codex_shell["repository_control_resolution"] == "resolved"

    codex_patch = normalize_provider_event(
        "codex", "before_tool",
        {
            "tool_name": "apply_patch",
            "cwd": str(root),
            "tool_input": {
                "patch": "*** Begin Patch\n*** Update File: tracked.txt\n@@\n-before\n+after\n*** End Patch"
            },
        },
    )
    assert codex_patch["repository_operation"] == "EDIT"
    assert codex_patch["repository_control_resolution"] == "resolved"


def test_repository_shell_event_carries_single_github_destination_hash(tmp_path) -> None:
    import subprocess

    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(
        ["git", "-C", str(root), "remote", "add", "origin", "https://github.com/Acme/Widget.git"],
        check=True,
    )

    event = normalize_provider_event(
        "claude_code", "before_tool",
        {"cwd": str(root), "tool_name": "Bash", "tool_input": {"command": "git push origin main"}},
    )

    assert event["repository_operation"] == "PUSH"
    assert event["repository_control_resolution"] == "resolved"
    assert len(event["repository_destination_hash"]) == 64
    assert str(root) not in str(event)
    assert "git push origin main" not in str(event)

    cursor_shell = normalize_provider_event(
        "cursor", "before_shell", {"cwd": str(root), "command": "git push origin main"}
    )
    assert cursor_shell["repository_operation"] == "PUSH"
    assert cursor_shell["repository_destination_hash"] == event["repository_destination_hash"]


def test_repository_guard_classification_is_sent_to_backend_before_policy_output(tmp_path, monkeypatch, capsys) -> None:
    import io
    import json
    import subprocess
    from types import SimpleNamespace

    from hawk_endpoint_agent.native_control import hook

    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    raw = {
        "cwd": str(root),
        "tool_name": "Bash",
        "tool_input": {"command": "git status && git push origin main"},
    }
    observed = {}
    monkeypatch.setattr(hook.sys, "argv", ["hook", "--provider", "claude_code", "--event", "before_tool"])
    monkeypatch.setattr(hook.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps(raw).encode("utf-8"))))
    monkeypatch.setattr(hook, "_configuration", lambda _path: {"provider": "anthropic", "transport": "https"})
    monkeypatch.setattr(
        hook, "_signed_callback",
        lambda _config, _event, normalized: observed.setdefault("normalized", normalized) or {},
    )
    monkeypatch.setattr(
        hook, "_post_callback",
        lambda _config, _body: (observed.update(called=True) or {"decision": "allow", "enforced": True}),
    )

    hook.main()

    assert observed["called"] is True
    assert observed["normalized"]["repository_control_resolution"] == "ambiguous"
    assert "hookSpecificOutput" in json.loads(capsys.readouterr().out)


def test_non_git_workspace_still_reaches_backend_callback(tmp_path, monkeypatch, capsys) -> None:
    import io
    import json
    from types import SimpleNamespace

    from hawk_endpoint_agent.native_control import hook

    raw = {
        "cwd": str(tmp_path),
        "tool_name": "Read",
        "tool_input": {"file_path": str(tmp_path / "plain.txt")},
    }
    observed = {}
    monkeypatch.setattr(hook.sys, "argv", ["hook", "--provider", "claude_code", "--event", "before_tool"])
    monkeypatch.setattr(hook.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps(raw).encode("utf-8"))))
    monkeypatch.setattr(hook, "_configuration", lambda _path: {"provider": "anthropic", "transport": "https"})
    monkeypatch.setattr(hook, "_signed_callback", lambda _config, _event, normalized: {"normalized": normalized})
    monkeypatch.setattr(
        hook, "_post_callback",
        lambda _config, body: (observed.update(body=body) or {"decision": "allow", "enforced": True}),
    )

    hook.main()

    assert observed["body"]["normalized"]["repository_control_resolution"] == "unavailable"
    assert "hookSpecificOutput" in json.loads(capsys.readouterr().out)


def test_cursor_after_file_edit_remains_evidence_only_for_repository_authorization(tmp_path) -> None:
    import subprocess

    root = tmp_path / "repo"
    root.mkdir()
    target = root / "file.txt"
    target.write_text("edited\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(root)], check=True)

    event = normalize_provider_event("cursor", "after_file_edit", {"cwd": str(root), "file_path": str(target)})

    assert event["repository_control_resolution"] == "evidence_only"
    assert event["repository_operation"] == "UNKNOWN"
    assert event["evidence_quality"] == "provider_reported"
