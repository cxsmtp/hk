from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

from hawk_endpoint_agent.native_control.gemini_serializer import (
    GeminiHookProcessResult,
    render_gemini_hook_result,
    render_gemini_runtime_result,
)
from hawk_endpoint_agent.native_control.hook import (
    normalize_provider_event,
    provider_hook_output,
)


def test_native_hook_module_invokes_main_when_run_as_installed_helper() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "hawk_endpoint_agent.native_control.hook"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )

    assert result.returncode == 2
    assert "--provider" in result.stderr
    assert "--event" in result.stderr


def _decision(value: str, *, enforced: bool = True) -> dict[str, object]:
    return {
        "decision": value,
        "reason": f"hawk:{value}",
        "enforced": enforced,
    }


def test_gemini_strict_serializer_emits_one_compact_json_object_and_stderr_only_diagnostics() -> None:
    result = render_gemini_hook_result(
        {"decision": "allow", "systemMessage": "Hawk governed this action."},
        diagnostic="safe diagnostic",
    )

    assert result == GeminiHookProcessResult(
        stdout='{"decision":"allow","systemMessage":"Hawk governed this action."}',
        stderr="safe diagnostic",
        exit_code=0,
    )
    assert json.loads(result.stdout) == {
        "decision": "allow",
        "systemMessage": "Hawk governed this action.",
    }
    assert "diagnostic" not in result.stdout
    assert "\n" not in result.stdout


def test_gemini_strict_serializer_rejects_non_object_non_json_and_stdout_pollution() -> None:
    for invalid in ([], "allow", {"value": object()}):
        try:
            render_gemini_hook_result(invalid)  # type: ignore[arg-type]
        except ValueError as exc:
            assert str(exc).startswith("gemini_hook_output_")
        else:
            raise AssertionError("invalid hook output was accepted")

    try:
        render_gemini_hook_result({"systemMessage": "line one\nline two"})
    except ValueError as exc:
        assert str(exc) == "gemini_hook_output_control_character"
    else:
        raise AssertionError("stdout control character was accepted")


def test_gemini_exit_code_two_block_uses_empty_stdout_and_stderr_reason() -> None:
    result = render_gemini_hook_result(
        {"decision": "deny", "reason": "Hawk denied write"},
        block_transport="exit_2",
    )

    assert result.stdout == ""
    assert result.stderr == "Hawk denied write"
    assert result.exit_code == 2


def test_gemini_runtime_serializer_failure_is_explicitly_fail_closed_only_pre_action() -> None:
    pre_action = render_gemini_runtime_result(
        "before_tool",
        {"decision": "deny", "reason": "unsafe\nprovider reason"},
    )
    advisory = render_gemini_runtime_result(
        "after_tool",
        {"systemMessage": "unsafe\nprovider message"},
    )

    assert pre_action == GeminiHookProcessResult(
        stdout="",
        stderr="Hawk native output validation failed",
        exit_code=2,
    )
    assert advisory == GeminiHookProcessResult(
        stdout="{}",
        stderr="Hawk native output validation failed",
        exit_code=0,
    )


def test_gemini_json_allow_block_and_monitor_decisions_preserve_strength() -> None:
    assert provider_hook_output("gemini_cli", "before_tool", _decision("allow")) == {
        "decision": "allow",
        "systemMessage": "Hawk governed this action.",
    }
    assert provider_hook_output("gemini_cli", "before_tool", _decision("block")) == {
        "decision": "deny",
        "reason": "hawk:block",
        "systemMessage": "Hawk blocked this action before execution.",
    }
    for restrictive in ("review", "require_approval", "require_second_approval", "redact"):
        output = provider_hook_output("gemini_cli", "before_tool", _decision(restrictive))
        assert output["decision"] == "deny"
        assert output["reason"] == f"hawk:{restrictive}"
    assert provider_hook_output(
        "gemini_cli",
        "before_tool",
        _decision("block", enforced=False),
    )["decision"] == "allow"


def test_gemini_event_roles_keep_tool_authorization_filtering_and_evidence_separate() -> None:
    block = _decision("block")

    assert provider_hook_output("gemini_cli", "before_agent", block)["decision"] == "deny"
    assert provider_hook_output("gemini_cli", "before_model", block)["decision"] == "deny"
    assert provider_hook_output("gemini_cli", "before_tool_selection", block) == {}
    assert provider_hook_output("gemini_cli", "after_tool", block) == {}
    assert provider_hook_output("gemini_cli", "after_model", block) == {}
    assert provider_hook_output("gemini_cli", "after_agent", block) == {}
    assert provider_hook_output("gemini_cli", "session_start", block) == {}
    assert provider_hook_output("gemini_cli", "session_end", block) == {}
    assert provider_hook_output("gemini_cli", "pre_compress", block) == {}
    assert provider_hook_output("gemini_cli", "notification", block) == {}
    assert all(
        "tool_input" not in json.dumps(provider_hook_output("gemini_cli", event, block))
        for event in ("before_tool", "before_agent", "before_model")
    )


def test_gemini_normalizes_mcp_shell_file_prompt_model_result_and_tail_context_privately() -> None:
    common = {
        "session_id": "private-session",
        "cwd": "/private/workspace",
        "timestamp": "2026-08-12T00:00:00Z",
    }
    mcp = normalize_provider_event(
        "gemini_cli",
        "before_tool",
        {
            **common,
            "tool_name": "mcp_github_create_pull_request",
            "tool_input": {"owner": "hawk", "repo": "demo", "token": "synthetic-token-marker"},
            "original_request_name": "route_to_github",
        },
    )
    shell = normalize_provider_event(
        "gemini_cli",
        "before_tool",
        {**common, "tool_name": "run_shell_command", "tool_input": {"command": "git status"}},
    )
    read_file = normalize_provider_event(
        "gemini_cli",
        "before_tool",
        {**common, "tool_name": "read_file", "tool_input": {"file_path": "/private/demo.txt"}},
    )
    write_file = normalize_provider_event(
        "gemini_cli",
        "before_tool",
        {**common, "tool_name": "write_file", "tool_input": {"file_path": "/private/demo.txt", "content": "private"}},
    )
    before_agent = normalize_provider_event(
        "gemini_cli", "before_agent", {**common, "prompt": "private prompt"}
    )
    before_model = normalize_provider_event(
        "gemini_cli",
        "before_model",
        {**common, "llm_request": {"model": "gemini-2.5-pro", "messages": [{"role": "user", "content": "private"}]}},
    )
    after_tool = normalize_provider_event(
        "gemini_cli",
        "after_tool",
        {
            **common,
            "tool_name": "run_shell_command",
            "tool_input": {"command": "git status"},
            "tool_response": {"llmContent": "private output", "returnDisplay": "private output"},
        },
    )

    assert mcp["action_type"] == "MCP_TOOL_CALL"
    assert mcp["mcp_server_id"] == "github"
    assert mcp["mcp_tool_name"] == "create_pull_request"
    assert mcp["tail_call"] is True
    assert len(str(mcp["original_request_name_hash"])) == 64
    assert shell["action_type"] == "COMMAND_EXECUTION"
    assert read_file["action_type"] == "FILE_READ"
    assert write_file["action_type"] == "FILE_WRITE"
    assert before_agent["action_type"] == "AGENT_TURN"
    assert before_agent["provider_event_type"] == "before_agent"
    assert before_model["action_type"] == "MODEL_REQUEST"
    assert before_model["model"] == "gemini-2.5-pro"
    assert after_tool["evidence_quality"] == "provider_reported"
    assert after_tool["execution_status"] == "succeeded"
    serialized = json.dumps((mcp, shell, read_file, write_file, before_agent, before_model, after_tool))
    for private in (
        "private-session",
        "/private/workspace",
        "synthetic-token-marker",
        "private prompt",
        "private output",
        "route_to_github",
    ):
        assert private not in serialized


def test_gemini_advisory_lifecycle_events_are_observation_only() -> None:
    event_inputs = {
        "session_start": {"source": "startup"},
        "session_end": {"reason": "exit"},
        "after_agent": {"prompt": "private", "prompt_response": "private response"},
        "after_model": {"llm_response": {"candidates": [{"content": "private"}]}},
        "before_tool_selection": {"llm_request": {"model": "gemini-2.5-pro"}},
        "pre_compress": {"trigger": "auto"},
        "notification": {"notification_type": "ToolPermission", "message": "private", "details": {"tool_name": "write_file"}},
    }

    for event, payload in event_inputs.items():
        normalized = normalize_provider_event("gemini_cli", event, payload)
        assert normalized["provider_event_type"] == event
        assert normalized["persistent_side_effect"] is False
        assert normalized["evidence_quality"] == "provider_reported"
        assert "private" not in json.dumps(normalized)
