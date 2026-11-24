from __future__ import annotations

import importlib.util
import io
import hashlib
import json
import os
import re
import signal
import socket
import threading
import stat
import subprocess
import sys
import tempfile
import types
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parents[1] / "scripts"


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_masked_echo_failure_diagnostic_contains_only_bounded_synthetic_facts():
    llm = load("run_isolated_llm_provider_acceptance")
    body = {
        "final_decision": "allow", "provider_invoked": True,
        "response_control_coverage": "complete",
        "completion": "Alice Smith [[HAWK_PERSON_x_0001]] P12345678",
        "gateway_trace": {"reversible_masking": {"restored": False}},
    }
    diagnostic = llm._safe_echo_diagnostic(body)
    assert "restored_no" in diagnostic
    assert "placeholder_residue_yes" in diagnostic
    assert "name_1_passport_1_account_0" in diagnostic
    assert "Alice Smith" not in diagnostic and "P12345678" not in diagnostic


def test_final_block_proof_requires_provider_post_control_and_no_restoration():
    llm = load("run_isolated_llm_provider_acceptance")
    body = {
        "provider_invoked": True, "response_control_coverage": "complete",
        "final_decision": "block", "completion": "Response restricted by Output Guardian policy.",
        "guardian_results": [{"guardian_id": "output_guardian", "stage": "post_response", "decision": "block"}],
        "gateway_trace": {"reversible_masking": {"restored": False}, "secure_gateway": {"post_call_guard": {"decision": "allow"}}},
    }
    assert llm._final_block_boundary_proven(body)
    assert not llm._final_block_boundary_proven({**body, "provider_invoked": False})
    assert not llm._final_block_boundary_proven({**body, "gateway_trace": {"reversible_masking": {"restored": False}}})
    assert not llm._final_block_boundary_proven({**body, "guardian_results": []})


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8000", "http://127.0.0.1:3443",
    "http://0.0.0.0:53123", "https://example.com:53123",
    "http://localhost:53123", "http://127.0.0.1:0",
])
def test_isolated_api_rejects_shared_or_non_loopback_urls(url):
    mcp = load("run_isolated_mcp_client_acceptance")
    with pytest.raises(ValueError):
        mcp.validate_isolated_api_url(url)


def test_isolated_api_accepts_os_assigned_loopback_url():
    mcp = load("run_isolated_mcp_client_acceptance")
    assert mcp.validate_isolated_api_url("http://127.0.0.1:53123") == 53123


def test_temporary_database_and_config_require_private_permissions(tmp_path):
    mcp = load("run_isolated_mcp_client_acceptance")
    with tempfile.TemporaryDirectory(prefix="hawk-test-private-", dir="/private/tmp") as name:
        root = Path(name)
        database = root / "postgres-data"
        config = root / "claude-mcp.json"
        database.mkdir(mode=0o700)
        config.write_bytes(b"{}")
        os.chmod(config, 0o600)
        mcp.validate_private_paths(root, database, config)
        os.chmod(config, 0o644)
        with pytest.raises(ValueError):
            mcp.validate_private_paths(root, database, config)
        os.chmod(config, 0o600)
        outside = tmp_path / "shared-db"
        with pytest.raises(ValueError):
            mcp.validate_private_paths(root, outside, config)
        with pytest.raises(ValueError):
            mcp.validate_private_paths(tmp_path, database, config)


def test_mcp_report_requires_exact_client_correlated_revocation_and_unchanged_child_count():
    mcp = load("run_isolated_mcp_client_acceptance")
    safe_result = {"stop_reason": "end_turn", "num_turns": 1, "total_cost_usd": 0.01, "prose_code": "none", "is_error": False}
    report = {
        "client": "claude-code", "client_version": "2.1.183",
        "runs": [
            {"run_id_hash": "a" * 64, "decision": "allow", "evidence_id_hash": "1" * 64, "child_call_count": 1, "client_result_subtype": "success", "mcp_status": "connected", "exact_tool_advertised": True, "exact_tool_use_count": 1, "permission_denial_count": 0, "correlated_event": True, **safe_result},
            {"run_id_hash": "b" * 64, "decision": "allow", "evidence_id_hash": "2" * 64, "child_call_count": 2, "client_result_subtype": "success", "mcp_status": "connected", "exact_tool_advertised": True, "exact_tool_use_count": 1, "permission_denial_count": 0, "correlated_event": True, **safe_result},
            {"run_id_hash": "c" * 64, "decision": "block", "reason": "agent_session_revoked", "evidence_id_hash": "3" * 64, "child_call_count": 2, "client_result_subtype": "success", "mcp_status": "connected", "exact_tool_advertised": True, "exact_tool_use_count": 1, "permission_denial_count": 0, "correlated_event": True, **safe_result},
        ],
        "release_ready": False,
    }
    mcp.validate_mcp_report(report)
    mcp.validate_mcp_report({**report, "runs": [{**report["runs"][0], "num_turns": 0}, *report["runs"][1:]]})
    for replacement in [
        {"client": "home-made"},
        {"runs": [report["runs"][0], report["runs"][0], report["runs"][2]]},
        {"runs": [*report["runs"][:2], {**report["runs"][2], "evidence_id_hash": ""}]},
        {"runs": [*report["runs"][:2], {**report["runs"][2], "child_call_count": 3}]},
        {"runs": [*report["runs"][:2], {**report["runs"][2], "reason": "generic_error"}]},
        {"runs": [{**report["runs"][0], "exact_tool_use_count": 0}, *report["runs"][1:]]},
        {"runs": [{**report["runs"][0], "permission_denial_count": 1}, *report["runs"][1:]]},
        {"runs": [{**report["runs"][0], "correlated_event": False}, *report["runs"][1:]]},
        {"runs": [{**report["runs"][0], "mcp_status": "disconnected"}, *report["runs"][1:]]},
        {"runs": [{**report["runs"][0], "exact_tool_advertised": False}, *report["runs"][1:]]},
        {"runs": [{**report["runs"][0], "total_cost_usd": 0.06}, *report["runs"][1:]]},
        {"runs": [{**report["runs"][0], "num_turns": -1}, *report["runs"][1:]]},
        {"runs": [{**report["runs"][0], "is_error": True}, *report["runs"][1:]]},
        {"runs": [{**report["runs"][0], "prose_code": "private text"}, *report["runs"][1:]]},
        {"prompt": "sensitive raw content"},
        {"release_ready": True},
    ]:
        with pytest.raises(ValueError):
            mcp.validate_mcp_report({**report, **replacement})


def test_official_sdk_facts_are_exact_and_discard_raw_output():
    mcp = load("run_isolated_mcp_client_acceptance")
    safe = {"client": "official-mcp-typescript-sdk", "client_version": "1.29.0", "connected": True, "exact_tool_advertised": True, "exact_schema": True, "call_status": "returned", "is_error": False, "mcp_error_code": None, "reason_token": "none"}
    assert mcp.parse_official_sdk_result(json.dumps(safe).encode()) == safe
    for invalid in ({**safe, "client_version": "1.28.0"}, {**safe, "tool_content": "private-token"}, {**safe, "is_error": "false"}, {**safe, "call_status": "not_called", "is_error": True}, {**safe, "mcp_error_code": True}, {**safe, "reason_token": "raw-secret"}):
        with pytest.raises(ValueError):
            mcp.parse_official_sdk_result(json.dumps(invalid).encode())
    for data in (b"", b"not json", b"x" * (mcp.MAX_SDK_OUTPUT_BYTES + 1)):
        with pytest.raises(ValueError):
            mcp.parse_official_sdk_result(data)


def test_official_sdk_report_requires_three_correlated_distinct_real_calls():
    mcp = load("run_isolated_mcp_client_acceptance")
    common = {"connected": True, "exact_tool_advertised": True, "exact_schema": True, "correlated_event": True}
    runs = [
        {**common, "run_id_hash": "a" * 64, "event_id_hash": "1" * 64, "evidence_id_hash": "4" * 64, "decision": "allow", "child_call_count": 1, "call_status": "returned", "is_error": False},
        {**common, "run_id_hash": "b" * 64, "event_id_hash": "2" * 64, "evidence_id_hash": "5" * 64, "decision": "allow", "child_call_count": 2, "call_status": "returned", "is_error": False},
        {**common, "run_id_hash": "c" * 64, "event_id_hash": "3" * 64, "evidence_id_hash": "6" * 64, "decision": "block", "reason": "agent_session_revoked", "child_call_count": 2, "call_status": "returned", "is_error": True},
    ]
    report = {"client": "official-mcp-typescript-sdk", "client_version": "1.29.0", "runs": runs, "release_ready": False}
    mcp.validate_official_sdk_report(report)
    for changed in (
        {**runs[0], "child_call_count": 0}, {**runs[0], "exact_schema": False},
        {**runs[0], "correlated_event": False}, {**runs[2], "reason": "generic"},
        {**runs[2], "is_error": False}, {**runs[2], "child_call_count": 3},
        {**runs[2], "evidence_id_hash": runs[0]["evidence_id_hash"]},
    ):
        index = 2 if changed.get("decision") == "block" else 0
        candidate = [dict(run) for run in runs]
        candidate[index] = changed
        with pytest.raises(ValueError):
            mcp.validate_official_sdk_report({**report, "runs": candidate})
    with pytest.raises(ValueError):
        mcp.validate_official_sdk_report({**report, "release_ready": True})


def test_official_sdk_command_uses_only_private_config_and_synthetic_note(tmp_path):
    mcp = load("run_isolated_mcp_client_acceptance")
    config = tmp_path / "private.json"
    command = mcp.official_sdk_command("/usr/local/bin/node", config, "synthetic-marker")
    assert command == ["/usr/local/bin/node", str(mcp.OFFICIAL_SDK_CLIENT), str(config), "synthetic-marker"]
    assert all("token" not in item.lower() for item in command)
    with pytest.raises(ValueError):
        mcp.official_sdk_command("/usr/local/bin/node", config, "raw private text")


def test_codex_cli_private_wrapper_and_invocation_keep_authority_off_args(tmp_path):
    mcp = load("run_isolated_mcp_client_acceptance")
    with tempfile.TemporaryDirectory(prefix="hawk-codex-contract-", dir="/private/tmp") as name:
        directory = Path(name)
        config = directory / "private-mcp.json"
        config.write_text(json.dumps({"mcpServers": {"hawk_lab": {"command": "/usr/local/bin/node", "args": ["private-proxy"], "env": {"HAWK_ACCESS_TOKEN": "private-token"}}}}))
        os.chmod(config, 0o600)
        wrapper = mcp.write_codex_private_wrapper(directory, config)
        assert stat.S_IMODE(wrapper.stat().st_mode) == 0o700
        command = mcp.codex_command("/usr/local/bin/codex", wrapper=wrapper, directory=directory, note="synthetic-note", other_servers=["hawk-demo", "node_repl"])
        assert command[:8] == ["/usr/local/bin/codex", "exec", "--ephemeral", "--json", "--sandbox", "read-only", "--skip-git-repo-check", "-C"][:8]
        assert 'mcp_servers.hawk-demo.enabled=false' in command
        assert 'mcp_servers.node_repl.enabled=false' in command
        assert f'mcp_servers.hawk_lab.command={json.dumps(sys.executable)}' in command
        assert f'mcp_servers.hawk_lab.args={json.dumps([str(wrapper)])}' in command
        assert 'mcp_servers.hawk_lab.enabled_tools=["read_demo_marker"]' in command
        assert "mcp_servers.hawk_lab.required=true" in command
        assert 'mcp_servers.hawk_lab.tools.read_demo_marker.approval_mode="approve"' in command
        assert not any("approval_mode" in part and part != 'mcp_servers.hawk_lab.tools.read_demo_marker.approval_mode="approve"' for part in command)
        assert not any("approval_policy" in part or "dangerously" in part or "*" in part for part in command)
        assert "private-token" not in json.dumps(command)
        assert "ignore-user-config" not in json.dumps(command)
        assert "dangerously-bypass" not in json.dumps(command)
        assert mcp.CODEX_TOOL in command[-1]
        with pytest.raises(ValueError):
            mcp.codex_command("codex", wrapper=wrapper, directory=directory, note="bad secret text", other_servers=[])


def test_codex_wrapper_with_spaced_interpreter_runs_only_when_interpreter_explicit():
    mcp = load("run_isolated_mcp_client_acceptance")
    with tempfile.TemporaryDirectory(prefix="hawk-codex-space-path-", dir="/private/tmp") as name:
        directory = Path(name)
        config = directory / "private-mcp.json"
        config.write_text(json.dumps({"mcpServers": {"hawk_lab": {"command": "/bin/echo", "args": ["synthetic"], "env": {}}}}))
        os.chmod(config, 0o600)
        wrapper = mcp.write_codex_private_wrapper(directory, config)
        result = subprocess.run([sys.executable, str(wrapper)], cwd=directory, capture_output=True, text=True, timeout=3)
        assert result.returncode == 0 and result.stdout.strip() == "synthetic"
        if " " in sys.executable:
            with pytest.raises(FileNotFoundError):
                subprocess.run([str(wrapper)], cwd=directory, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)


def test_codex_cli_reads_only_other_mcp_server_names(tmp_path):
    mcp = load("run_isolated_mcp_client_acceptance")
    (tmp_path / "config.toml").write_text('[mcp_servers.hawk_demo]\ncommand = "private-token"\n[mcp_servers.node_repl]\ncommand = "private-other"\n')
    assert mcp.codex_other_server_names(tmp_path) == ["hawk_demo", "node_repl"]
    (tmp_path / "config.toml").write_text('[mcp_servers.hawk_lab]\ncommand = "private-token"\n')
    with pytest.raises(ValueError, match="saved_hawk_lab_config_collision"):
        mcp.codex_other_server_names(tmp_path)


def test_codex_cli_stream_and_report_require_exact_correlated_read_call():
    mcp = load("run_isolated_mcp_client_acceptance")
    stream = b'\n'.join([json.dumps({"type": "item.completed", "item": {"type": "mcp_tool_call", "server": "hawk_lab", "tool": "read_demo_marker", "status": "completed", "arguments": {"note": "private-token"}, "result": "private-content"}}).encode(), b'{"type":"turn.completed","usage":{"total_tokens":10}}'])
    facts = mcp.parse_codex_stream(stream)
    assert {key: facts[key] for key in ("exact_tool_call_count", "failed_tool_call_count", "turn_completed", "turn_failed")} == {"exact_tool_call_count": 1, "failed_tool_call_count": 0, "turn_completed": True, "turn_failed": False}
    assert "private-token" not in json.dumps(facts)
    revoked_facts = mcp.parse_codex_stream(b'{"type":"item.failed","item":{"type":"mcp_tool_call","server":"hawk_lab","tool":"read_demo_marker","status":"failed","error":"private-token"}}\n{"type":"turn.failed"}')
    assert {key: revoked_facts[key] for key in ("exact_tool_call_count", "failed_tool_call_count", "turn_completed", "turn_failed")} == {"exact_tool_call_count": 1, "failed_tool_call_count": 1, "turn_completed": False, "turn_failed": True}
    common = {"correlated_event": True}
    runs = [
        {"run_id_hash": "a" * 64, "event_id_hash": "1" * 64, "evidence_id_hash": "4" * 64, "decision": "allow", "child_call_count": 1, **{key: facts[key] for key in ("exact_tool_call_count", "failed_tool_call_count", "turn_completed", "turn_failed")}, **common},
        {"run_id_hash": "b" * 64, "event_id_hash": "2" * 64, "evidence_id_hash": "5" * 64, "decision": "allow", "child_call_count": 2, **{key: facts[key] for key in ("exact_tool_call_count", "failed_tool_call_count", "turn_completed", "turn_failed")}, **common},
        {"run_id_hash": "c" * 64, "event_id_hash": "3" * 64, "evidence_id_hash": "6" * 64, "decision": "block", "reason": "agent_session_revoked", "child_call_count": 2, **{key: revoked_facts[key] for key in ("exact_tool_call_count", "failed_tool_call_count", "turn_completed", "turn_failed")}, **common},
    ]
    report = {"client": "codex-cli", "client_version": "0.154.0", "runs": runs, "release_ready": False}
    mcp.validate_codex_report(report)
    for changed in ({"child_call_count": 0}, {"exact_tool_call_count": 0}, {"correlated_event": False}, {"evidence_id_hash": ""}):
        with pytest.raises(ValueError):
            mcp.validate_codex_report({**report, "runs": [{**runs[0], **changed}, *runs[1:]]})
    for changed in ({"failed_tool_call_count": 0}, {"reason": "generic"}, {"child_call_count": 3}):
        with pytest.raises(ValueError):
            mcp.validate_codex_report({**report, "runs": [*runs[:2], {**runs[2], **changed}]})
    with pytest.raises(ValueError):
        mcp.validate_codex_report({**report, "release_ready": True})
    for invalid in (b"", b"not-json", b"x" * (mcp.MAX_CODEX_STREAM_BYTES + 1), b'{"type":"item.completed","item":{"type":"mcp_tool_call","server":"other","tool":"read_demo_marker"}}'):
        with pytest.raises(ValueError):
            mcp.parse_codex_stream(invalid)


def test_client_diagnostics_drop_nested_content_and_private_text():
    mcp = load("run_isolated_mcp_client_acceptance")
    private = "Bearer private-token and user@example.com /Users/name/private/file"
    stream = json.dumps({
        "type": "item.failed",
        "item": {
            "type": "mcp_tool_call", "server": "hawk_lab", "tool": "read_demo_marker", "status": "failed",
            "arguments": {"note": private}, "result": {"content": private},
            "error": {"code": -32001, "message": private, "data": {"ai.hawk/error": {
                "status": "blocked", "decision": "block", "reason": "agent_session_revoked",
                "correlation_id": "00000000-0000-4000-8000-000000000001", "message": private,
            }}},
        },
    }).encode()
    facts = mcp.parse_codex_stream(stream)
    assert facts["mcp_error_code"] == -32001
    assert (facts["hawk_status"], facts["hawk_decision"], facts["hawk_reason"], facts["correlation_id_valid"]) == ("blocked", "block", "agent_session_revoked", True)
    assert "private-token" not in repr(facts) and "user@example.com" not in repr(facts) and "/Users/" not in repr(facts)
    unknown = mcp.parse_codex_stream(json.dumps({"type": "item.failed", "item": {"type": "mcp_tool_call", "server": "hawk_lab", "tool": "read_demo_marker", "error": {"data": {"ai.hawk/error": {"reason": private, "decision": private, "status": private, "correlation_id": private}}}}}).encode())
    assert (unknown["hawk_reason"], unknown["hawk_decision"], unknown["hawk_status"], unknown["correlation_id_valid"]) == ("other", "other", "other", False)
    assert "private-token" not in repr(unknown)
    claude_events = [
        {"type": "system", "subtype": "hook_error", "status": "failed", "message": private},
        {"type": "result", "subtype": "success", "is_error": False, "result": private, "num_turns": 0, "total_cost_usd": 0.0},
    ]
    claude = mcp.parse_claude_stream(b"\n".join(json.dumps(event).encode() for event in claude_events))
    assert (claude["hook_event_count"], claude["hook_error_count"]) == (1, 1)
    assert "private-token" not in repr(claude) and "user@example.com" not in repr(claude) and "/Users/" not in repr(claude)


def test_codex_cli_bounded_runner_reports_only_fixed_exit_and_stderr_category(tmp_path):
    mcp = load("run_isolated_mcp_client_acceptance")
    child = [sys.executable, "-c", "import sys; sys.stderr.write('error parsing config private-token'); sys.exit(2)"]
    with pytest.raises(RuntimeError) as exc:
        mcp.run_codex_bounded(child, cwd=tmp_path, timeout=5)
    assert str(exc.value) == "codex_client_exit_2_stdout_empty_stderr_config_invalid"
    assert "private-token" not in str(exc.value)
    with pytest.raises(RuntimeError, match="^codex_client_exit_0_stdout_empty_stderr_other$"):
        mcp.run_codex_bounded([sys.executable, "-c", "pass"], cwd=tmp_path, timeout=5)
    assert mcp.classify_codex_stderr(b"unknown private-token content") == "other"


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_codex_cli_bounded_runner_caps_both_streams_and_kills_child(tmp_path, stream):
    mcp = load("run_isolated_mcp_client_acceptance")
    marker = tmp_path / "child.pid"
    limit = mcp.MAX_CODEX_STREAM_BYTES if stream == "stdout" else mcp.MAX_CODEX_STDERR_BYTES
    child_code = "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); getattr(sys,sys.argv[2]).write('x'*int(sys.argv[3])); getattr(sys,sys.argv[2]).flush(); time.sleep(30)"
    with pytest.raises(RuntimeError, match=f"^codex_client_{stream}_oversized$"):
        mcp.run_codex_bounded([sys.executable, "-c", child_code, str(marker), stream, str(limit + 1)], cwd=tmp_path, timeout=5)
    pid = int(marker.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_sdk_failure_diagnostic_only_uses_new_exact_correlated_hawk_events():
    mcp = load("run_isolated_mcp_client_acceptance")
    since = datetime.now(timezone.utc)
    def event(*, tenant="tenant", session="session", tool="read_demo_marker", when=None, event_id="current", reason="action_outside_purpose_scope"):
        return types.SimpleNamespace(id=event_id, tenant_id=tenant, timestamp=when or since + timedelta(seconds=1), final_decision="block", final_actions={"mcp": {"session_id": session, "tool_name": tool}}, guardian_results=[{"matched_conditions": [reason, "private-token"]}], evidence_nodes_created=["evidence"])
    unrelated = [event(tenant="other"), event(session="other"), event(tool="write_demo_marker"), event(when=since - timedelta(seconds=1)), event(event_id="seen")]
    empty = mcp.safe_correlated_event_diagnostic(unrelated, tenant_id="tenant", session_id="session", since=since, seen={"seen"})
    assert empty == {"event_present": False, "decision": "none", "evidence_present": False, "reasons": [], "final_reason": "none", "guardian_codes": []}
    found = mcp.safe_correlated_event_diagnostic([*unrelated, event()], tenant_id="tenant", session_id="session", since=since, seen={"seen"})
    assert found == {"event_present": True, "decision": "block", "evidence_present": True, "reasons": ["action_outside_purpose_scope", "other"], "final_reason": "none", "guardian_codes": ["other_other"]}
    assert "private-token" not in json.dumps(found)


def test_public_authorize_preflight_uses_exact_builder_inputs_and_redacts_secrets(monkeypatch, tmp_path):
    mcp = load("run_isolated_mcp_client_acceptance")
    captured = {}
    def wire(builder_input):
        captured.update(builder_input)
        return {"ai_system_id": builder_input["aiSystemId"], "actor_id": builder_input["actorId"], "capability_token": builder_input["capabilityToken"], "tool_name": builder_input["toolName"], "session_id": builder_input["sessionId"], "tool_usage_meta": {"parameters": builder_input["argumentsObject"]}}
    monkeypatch.setattr(mcp, "capture_gateway_authorize_wire", wire)
    monkeypatch.setattr(mcp, "current_event_diagnostic", lambda *_args, **_kwargs: {"event_present": True, "evidence_present": True, "final_reason": "allow", "guardian_codes": ["mcp_scope_guard_allow"], "reasons": ["allow"]})
    class Api:
        root = tmp_path
        def request(self, method, path, *, headers, payload):
            assert (method, path) == ("POST", "/gateway/mcp/authorize")
            assert payload["capability_token"] == "private-capability"
            assert payload["tool_usage_meta"]["parameters"] == {"note": "synthetic-note"}
            assert "client_app" not in payload
            assert payload["request_id"]
            return 200, {"decision": "allow", "reason": "allow", "private": "private-token"}
    facts = mcp.run_public_authorize_preflight(Api(), owner={"tenant_id": "tenant", "access_token": "private-owner"}, system_id="system", agent_id="agent", capability="private-capability", session_id="session", fingerprint_id="fingerprint", note="synthetic-note")
    assert captured["toolFingerprintId"] == "fingerprint"
    assert captured["clientApp"] is None
    assert facts == {"stage": "public_authorize_preflight", "http_status": 200, "decision": "allow", "reason": "allow", "correlated_event": True, "evidence_present": True, "final_reason": "allow", "guardian_codes": ["mcp_scope_guard_allow"], "guardian_reasons": ["allow"], "session_reason": "none", "session_bounds_reason": "none", "pre_action_reason": "none", "pre_action_decision": "none"}
    assert "private" not in json.dumps(facts)


def test_public_preflight_4xx_5xx_classification_and_trace_redaction():
    mcp = load("run_isolated_mcp_client_acceptance")
    assert mcp.fixed_preflight_reason(422, {"detail": [{"type": "extra_forbidden", "loc": ["body", "client_app"], "input": "private-token"}]}) == "schema_extra_client_app"
    assert mcp.fixed_preflight_reason(422, {"detail": [{"type": "extra_forbidden", "loc": ["body", "other"], "input": "private-token"}]}) == "schema_validation_other"
    assert mcp.fixed_preflight_reason(403, {"detail": {"reason_code": "private-token"}}) == "client_error_other"
    assert mcp.fixed_preflight_reason(500, {"detail": "private-token"}) == "server_error"
    assert mcp.fixed_preflight_reason(200, {"reason": "private-token"}) == "other"
    assert mcp.safe_policy_projection({"session": {"reason": "agent_session_resource_scope_denied", "bounds_enforcement": {"reason": "private-token"}}, "pre_action_governance_check": {"policy": {"decision": "block", "reason": "dynamic_resource_scope_denied"}}, "private": "private-token"}) == {"session_reason": "agent_session_resource_scope_denied", "session_bounds_reason": "other", "pre_action_reason": "dynamic_resource_scope_denied", "pre_action_decision": "block"}
    raw = f'File "{mcp.ROOT}/apps/api/app/services/gateway_service.py", line 123, in mcp_authorize\nValueError: private-token\n'
    facts = mcp.sanitize_private_api_trace(raw)
    assert facts == {"exception_class": "ValueError", "module": "app/services/gateway_service.py", "function": "mcp_authorize", "line": 123}
    assert "private-token" not in json.dumps(facts)


def test_synthetic_session_declares_the_data_classification_it_authorizes():
    mcp = load("run_isolated_mcp_client_acceptance")
    context = mcp.SESSION_CONTEXT
    assert context["data_classification"] in context["allowed_data_scope"]
    assert context["environment"] == "production"


def test_claude_stream_parser_counts_exact_tool_and_drops_raw_content():
    mcp = load("run_isolated_mcp_client_acceptance")
    events = [
        {"type": "system", "subtype": "init", "mcp_servers": [{"name": "hawk_lab", "status": "connected", "secret": "private-token"}], "tools": [mcp.EXACT_TOOL], "session_id": "private-token"},
        {"type": "assistant", "message": {"content": [{"type": "text", "text": "private prompt and completion"}, {"type": "tool_use", "id": "call-1", "name": mcp.EXACT_TOOL, "input": {"secret": "private-token"}}]}},
        {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": "call-1", "name": mcp.EXACT_TOOL}]}},
        {"type": "result", "subtype": "success", "result": "private completion", "is_error": False, "permission_denials": [], "stop_reason": "end_turn", "num_turns": 2, "total_cost_usd": 0.03},
    ]
    output = mcp.parse_claude_stream(b"\n".join(json.dumps(event).encode() for event in events))
    assert {key: output[key] for key in ("result_subtype", "stop_reason", "num_turns", "total_cost_usd", "prose_code", "is_error", "exact_tool_use_count", "permission_denial_count", "mcp_status", "exact_tool_advertised")} == {"result_subtype": "success", "stop_reason": "end_turn", "num_turns": 2, "total_cost_usd": 0.03, "prose_code": "prose_without_tool_call", "is_error": False, "exact_tool_use_count": 1, "permission_denial_count": 0, "mcp_status": "connected", "exact_tool_advertised": True}
    assert output["hook_event_count"] == 0 and output["hook_error_count"] == 0
    assert "private" not in repr(output)
    denied = mcp.parse_claude_stream(b"\n".join(json.dumps(event).encode() for event in [
        {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "mcp__other__tool"}]}},
        {"type": "result", "subtype": "success", "is_error": False, "permission_denials": [{"tool_name": mcp.EXACT_TOOL, "reason": "secret"}], "num_turns": 1, "total_cost_usd": 0.01},
    ]))
    assert {key: denied[key] for key in ("result_subtype", "stop_reason", "num_turns", "total_cost_usd", "prose_code", "is_error", "exact_tool_use_count", "permission_denial_count", "mcp_status", "exact_tool_advertised")} == {"result_subtype": "success", "stop_reason": "none", "num_turns": 1, "total_cost_usd": 0.01, "prose_code": "none", "is_error": False, "exact_tool_use_count": 0, "permission_denial_count": 1, "mcp_status": "missing", "exact_tool_advertised": False}


def test_claude_init_distinguishes_disconnected_unadvertised_and_advertised_without_raw_content():
    mcp = load("run_isolated_mcp_client_acceptance")
    for status, tools, expected_status, advertised in [
        ("failed with private secret", [mcp.EXACT_TOOL], "unknown", True),
        (["private secret"], [], "unknown", False),
        ("disconnected", [], "disconnected", False),
        ("connected", [], "connected", False),
        ("connected", [mcp.EXACT_TOOL], "connected", True),
    ]:
        stream = b"\n".join(json.dumps(item).encode() for item in [
            {"type": "system", "subtype": "init", "mcp_servers": [{"name": "hawk_lab", "status": status}], "tools": tools, "private": "secret"},
            {"type": "result", "subtype": "success", "result": "secret", "is_error": False, "num_turns": 1, "total_cost_usd": 0.01},
        ])
        parsed = mcp.parse_claude_stream(stream)
        assert parsed["mcp_status"] == expected_status
        assert parsed["exact_tool_advertised"] is advertised
        assert "secret" not in repr(parsed)


def test_claude_stream_parser_rejects_malformed_and_oversized():
    mcp = load("run_isolated_mcp_client_acceptance")
    for data in (b"", b"{not-json}", b'{"type":"assistant"}', b'{"type":"result","subtype":"bad space"}', b'{"type":"system","subtype":"init","mcp_servers":{}}\n{"type":"result","subtype":"success"}', b"x" * (mcp.MAX_CLAUDE_STREAM_BYTES + 1)):
        with pytest.raises(ValueError):
            mcp.parse_claude_stream(data)


def test_claude_prose_classification_is_fixed_code_only():
    mcp = load("run_isolated_mcp_client_acceptance")
    cases = [
        ("The tool is unavailable; private token abc", "tool_unavailable"),
        ("Permission denied by policy; private token abc", "permission_or_policy"),
        ("Budget exhausted; private token abc", "budget_exhausted"),
        ("I can't help with this; private token abc", "refusal"),
        ("Here is an answer containing private token abc", "prose_without_tool_call"),
        ("   ", "none"),
    ]
    for prose, expected in cases:
        code = mcp.classify_assistant_prose(prose)
        assert code == expected
        assert "private" not in code
        assert "abc" not in code


def test_claude_failure_diagnostic_is_allowlisted_and_resanitizes_headline():
    mcp = load("run_isolated_mcp_client_acceptance")
    private = "token=private-token https://secret.example/a /Users/alice/private/file"
    client = {
        "result_subtype": "error_during_execution", "is_error": True,
        "prose_code": "permission_or_policy", "mcp_status": "failed",
        "exact_tool_advertised": True, "exact_tool_use_count": 0,
        "hook_event_count": 2, "hook_error_count": 1,
        "permission_denial_count": 1, "total_cost_usd": 0.02,
        "diagnostic_headline": private, "include_diagnostic_headline": True, "prompt": private, "completion": private,
        "arguments": {"secret": private}, "unknown_secret": private,
    }
    diagnostic = mcp.safe_claude_failure_diagnostic(2, client)
    assert set(diagnostic) == {
        "exit_code", "result_subtype", "is_error", "prose_code", "stop_reason", "num_turns", "mcp_status",
        "exact_tool_advertised", "exact_tool_use_count", "hook_event_count",
        "hook_error_count", "permission_denial_count", "total_cost_usd",
        "stderr_category", "diagnostic_headline",
    }
    assert diagnostic["exit_code"] == 2
    assert diagnostic["result_subtype"] == "error_during_execution"
    assert diagnostic["hook_event_count"] == 2
    assert diagnostic["permission_denial_count"] == 1
    assert "private-token" not in repr(diagnostic)
    assert "secret.example" not in repr(diagnostic)
    assert "/Users/" not in repr(diagnostic)
    assert "alice" not in repr(diagnostic)
    assert "unknown_secret" not in repr(diagnostic)


def test_claude_result_metadata_rejects_invalid_or_over_budget_values():
    mcp = load("run_isolated_mcp_client_acceptance")
    valid = {"type": "result", "subtype": "success", "is_error": False, "num_turns": 1, "total_cost_usd": 0.05, "stop_reason": "end_turn"}
    zero = mcp.parse_claude_stream(json.dumps({**valid, "num_turns": 0}).encode())
    assert zero["num_turns"] == 0
    assert zero["exact_tool_use_count"] == 0
    for change, reason in [
        ({"num_turns": True}, "turns_wrong_type"),
        ({"num_turns": "private"}, "turns_wrong_type"),
        ({"num_turns": -1}, "turns_below_min"),
        ({"num_turns": 101}, "turns_above_max"),
        ({"total_cost_usd": "0.01"}, "cost_wrong_type"),
        ({"total_cost_usd": float("nan")}, "cost_nonfinite"),
        ({"total_cost_usd": float("inf")}, "cost_nonfinite"),
        ({"total_cost_usd": -0.001}, "cost_negative"),
        ({"total_cost_usd": 0.051}, "cost_above_cap"),
        ({"stop_reason": "private reason"}, "malformed_stop_reason"),
    ]:
        stream = json.dumps({**valid, **change}).encode()
        with pytest.raises(ValueError, match=reason):
            mcp.parse_claude_stream(stream)


def test_claude_result_text_and_errors_are_reduced_to_fixed_codes_only():
    mcp = load("run_isolated_mcp_client_acceptance")
    base = {"type": "result", "subtype": "success", "is_error": False, "num_turns": 0, "total_cost_usd": 0.01}
    for change, expected in [
        ({"result": "The tool is unavailable; private secret 123"}, "tool_unavailable"),
        ({"errors": ["Permission denied; private secret 123"]}, "permission_or_policy"),
        ({"result": "No call was made, private secret 123"}, "prose_without_tool_call"),
        ({"result": "", "errors": []}, "none"),
    ]:
        parsed = mcp.parse_claude_stream(json.dumps({**base, **change}).encode())
        assert parsed["prose_code"] == expected
        assert parsed["num_turns"] == 0
        assert parsed["is_error"] is False
        assert "private" not in repr(parsed)
        assert "123" not in repr(parsed)
    for change, code in [
        ({"is_error": "false"}, "is_error_wrong_type"),
        ({"result": {"private": "secret"}}, "result_text_invalid"),
        ({"result": "x" * (mcp.MAX_RESULT_TEXT_CHARS + 1)}, "result_text_invalid"),
        ({"errors": [{"private": "secret"}]}, "errors_invalid"),
        ({"errors": ["x" * (mcp.MAX_RESULT_TEXT_CHARS + 1)]}, "errors_invalid"),
        ({"errors": ["x"] * 17}, "errors_invalid"),
    ]:
        with pytest.raises(ValueError, match=code):
            mcp.parse_claude_stream(json.dumps({**base, **change}).encode())


def test_exact_prompt_matches_synthetic_tool_contract_and_keeps_cli_flags(tmp_path, monkeypatch):
    mcp = load("run_isolated_mcp_client_acceptance")
    note = "isolated-mcp-0-123456789"
    prompt = mcp.build_exact_tool_prompt(note)
    assert mcp.EXACT_TOOL in prompt
    assert json.dumps({"note": note}, separators=(",", ":")) in prompt
    assert "Return no prose" in prompt
    assert "mcp__other" not in prompt
    for invalid in ("", "x" * 41, "quote'escape", "private space"):
        with pytest.raises(ValueError, match="synthetic_mcp_note_invalid"):
            mcp.build_exact_tool_prompt(invalid)
    monkeypatch.setattr(mcp, "read_synthetic_tool_contract", lambda: {"tool": {"name": "read_demo_marker", "inputSchema": {"type": "object", "required": ["note"], "properties": {"note": {"type": "string", "maxLength": 64}}, "additionalProperties": True}}})
    with pytest.raises(ValueError, match="synthetic_mcp_tool_contract_invalid"):
        mcp.build_exact_tool_prompt(note)
    command = mcp.claude_command("/usr/local/bin/claude", prompt=prompt, config=Path("/private/tmp/claude-mcp.json"))
    assert command[command.index("--allowedTools") + 1] == mcp.EXACT_TOOL
    assert command[command.index("--tools") + 1] == ""
    assert command[command.index("--max-budget-usd") + 1] == "0.05"
    assert command[command.index("--permission-mode") + 1] == "dontAsk"
    assert "--strict-mcp-config" in command
    assert "--no-session-persistence" in command


def test_claude_child_restores_only_validated_user_into_private_lab_environment(tmp_path, monkeypatch):
    mcp = load("run_isolated_mcp_client_acceptance")
    monkeypatch.setenv("USER", "local-user")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ambient-api-secret")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "ambient-oauth-secret")
    user_name = mcp.capture_local_username()
    private_environment = {
        "USER": "lab-user", "PATH": "/usr/bin:/bin",
        "DATABASE_URL": "postgresql://isolated-db",
        "REDIS_URL": "redis://127.0.0.1:62991/0",
        "MCP_CONNECTION_NONBLOCKING": "1",
        "MCP_CONNECT_TIMEOUT_MS": "250",
    }
    monkeypatch.setattr(mcp.os, "environ", private_environment)
    captured = {}

    class FakeProcess:
        def __init__(self, _command, **kwargs):
            captured.update(kwargs["env"])
            read_fd, write_fd = os.pipe()
            result = {"type": "result", "subtype": "success", "is_error": False, "num_turns": 1, "total_cost_usd": 0.01}
            os.write(write_fd, json.dumps(result).encode() + b"\n")
            os.close(write_fd)
            self.stdout = os.fdopen(read_fd, "rb")
            self.stderr = os.fdopen(os.open(os.devnull, os.O_RDONLY), "rb")

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

    monkeypatch.setattr(mcp.subprocess, "Popen", FakeProcess)
    exit_code, _ = mcp.run_claude_bounded(["claude"], cwd=tmp_path, user_name=user_name)
    assert exit_code == 0
    assert captured["USER"] == "local-user"
    assert captured["DATABASE_URL"] == private_environment["DATABASE_URL"]
    assert captured["REDIS_URL"] == private_environment["REDIS_URL"]
    assert captured["MCP_CONNECTION_NONBLOCKING"] == "0"
    assert captured["MCP_CONNECT_TIMEOUT_MS"] == "30000"
    assert private_environment["MCP_CONNECTION_NONBLOCKING"] == "1"
    assert private_environment["MCP_CONNECT_TIMEOUT_MS"] == "250"
    assert "ANTHROPIC_API_KEY" not in captured
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in captured


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_claude_bounded_runner_caps_each_stream_and_kills_process_group(tmp_path, monkeypatch, stream):
    mcp = load("run_isolated_mcp_client_acceptance")
    monkeypatch.setattr(mcp, "MAX_CLAUDE_STREAM_BYTES", 128)
    monkeypatch.setattr(mcp, "MAX_CLAUDE_STDERR_BYTES", 128)
    marker = tmp_path / "child.pid"
    child_code = "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); getattr(sys,sys.argv[2]).write('x'*256); getattr(sys,sys.argv[2]).flush(); time.sleep(30)"
    with pytest.raises(mcp.ClaudeClientExecutionError) as failure:
        mcp.run_claude_bounded([sys.executable, "-c", child_code, str(marker), stream], cwd=tmp_path, user_name="local-user", timeout=5)
    assert str(failure.value) == f"claude_client_{stream}_oversized"
    assert failure.value.stderr_category == ("none" if stream == "stdout" else "other")
    pid = int(marker.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_claude_stderr_categories_are_closed_and_never_return_raw_text():
    mcp = load("run_isolated_mcp_client_acceptance")
    cases = [
        (b"", "none"),
        (b"authentication failed private-token", "authentication"),
        (b"invalid config private-token", "configuration"),
        (b"MCP server connect failed private-token", "mcp_startup_transport"),
        (b"request timed out private-token", "timeout"),
        (b"permission denied private-token", "policy"),
        (b"unclassified private-token", "other"),
    ]
    for raw, category in cases:
        assert mcp.classify_claude_stderr(raw) == category
        assert category in mcp.CLAUDE_STDERR_CATEGORIES
        assert "private-token" not in category


def test_claude_connection_timeline_preserves_order_and_maps_unrecognized_values_to_unknown():
    mcp = load("run_isolated_mcp_client_acceptance")
    events = [
        {"type": "system", "subtype": "init", "mcp_servers": [{"name": "hawk_lab", "status": "pending", "tools": []}]},
        {"type": "system", "subtype": "init", "mcp_servers": [{"name": "hawk_lab", "status": ["connected", "private-token"], "tools": [mcp.EXACT_TOOL]}]},
        {"type": "system", "subtype": "init", "mcp_servers": [{"name": "hawk_lab", "status": "connected", "tools": [mcp.EXACT_TOOL]}]},
        {"type": "result", "subtype": "success", "is_error": False, "num_turns": 1, "total_cost_usd": 0.01},
    ]
    parsed = mcp.parse_claude_stream(b"\n".join(json.dumps(item).encode() for item in events))
    assert parsed["connection_timeline"] == [
        {"event_order": 1, "status": "pending", "value_type": "string", "exact_tool_advertised": False},
        {"event_order": 2, "status": "unknown", "value_type": "list", "exact_tool_advertised": True},
        {"event_order": 3, "status": "connected", "value_type": "string", "exact_tool_advertised": True},
    ]
    assert parsed["exact_tool_advertised"] is True
    assert parsed["mcp_status"] == "connected"
    assert "private-token" not in repr(parsed)


def test_claude_failure_snapshot_keeps_prior_hashed_proof_and_rejects_raw_fields():
    mcp = load("run_isolated_mcp_client_acceptance")
    empty_event = {"event_present": False, "decision": "none", "evidence_present": False, "reasons": [], "final_reason": "none", "guardian_codes": [], "event_id_hash": None, "evidence_id_hash": None, "session_validation_reason": "none"}
    prior = {"run_id_hash": "a" * 64, "event_id_hash": "b" * 64, "evidence_id_hash": "c" * 64, "decision": "allow", "child_call_count": 1, "client_result_subtype": "success", "stop_reason": "end_turn", "num_turns": 1, "total_cost_usd": 0.01, "prose_code": "none", "mcp_status": "connected", "exact_tool_advertised": True, "exact_tool_use_count": 1, "permission_denial_count": 0}
    snapshot = mcp.build_claude_failure_snapshot(
        reason="phase_validation_failed", completed_phases=["isolated_api_ready", "public_preflight", "client_run_1"],
        current_phase_index=2, current_run_id_hash="d" * 64,
        client={"result_subtype": "missing", "stop_reason": "none", "num_turns": None, "total_cost_usd": None, "prose_code": "none", "is_error": None, "exact_tool_use_count": 0, "permission_denial_count": 0, "mcp_status": "unknown", "exact_tool_advertised": False, "hook_event_count": 0, "hook_error_count": 0, "diagnostic_headline": "none", "connection_timeline": [{"event_order": 1, "status": "pending", "value_type": "string", "exact_tool_advertised": False}], "stderr_category": "authentication"},
        completed_runs=[prior], child_call_count=1, event_projection=empty_event, include_headline=False,
    )
    assert snapshot["completed_runs"] == [prior]
    assert snapshot["completed_runs"][0]["evidence_id_hash"] == "c" * 64
    assert snapshot["safe_client_timeline"][0]["status"] == "pending"
    assert snapshot["release_ready"] is False
    with pytest.raises(ValueError, match="claude_failure_snapshot_invalid|raw_content_in_report"):
        mcp.validate_claude_failure_snapshot({**snapshot, "safe_client_facts": {**snapshot["safe_client_facts"], "arguments": "private prompt"}})


def test_claude_timeout_kills_process_and_returns_only_safe_timeout_facts(tmp_path):
    mcp = load("run_isolated_mcp_client_acceptance")
    marker = tmp_path / "timeout-child.pid"
    child_code = "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); sys.stderr.write('private auth token'); sys.stderr.flush(); time.sleep(30)"
    with pytest.raises(mcp.ClaudeClientExecutionError) as failure:
        mcp.run_claude_bounded([sys.executable, "-c", child_code, str(marker)], cwd=tmp_path, user_name="local-user", timeout=0.2)
    assert str(failure.value) == "claude_client_timeout"
    assert failure.value.stderr_category == "timeout"
    assert failure.value.facts["mcp_status"] == "missing"
    assert "private auth token" not in repr(failure.value.facts)
    pid = int(marker.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_claude_command_confines_permission_to_exact_synthetic_tool(tmp_path):
    mcp = load("run_isolated_mcp_client_acceptance")
    command = mcp.claude_command("/usr/local/bin/claude", prompt="synthetic marker", config=tmp_path / "mcp.json")
    assert command[command.index("--allowedTools") + 1] == mcp.EXACT_TOOL
    assert command[command.index("--tools") + 1] == ""
    assert command[command.index("--permission-mode") + 1] == "dontAsk"
    assert command[command.index("--max-budget-usd") + 1] == "0.05"
    assert "--strict-mcp-config" in command
    assert "--no-session-persistence" in command
    assert command[command.index("--output-format") + 1] == "stream-json"
    assert "--verbose" in command
    differential = mcp.claude_command("/usr/local/bin/claude", prompt="synthetic marker", config=tmp_path / "mcp.json", diagnostic_without_empty_tools=True)
    assert differential == command[:command.index("--tools")] + command[command.index("--tools") + 2:]
    assert all(option not in command for option in ("--dangerously-skip-permissions", "--allow-dangerously-skip-permissions", "--safe-mode", "--bare"))


def test_llm_report_requires_exact_local_model_digest_controls_and_distinct_evidence():
    llm = load("run_isolated_llm_provider_acceptance")
    report = {
        "model": "qwen3.5:9b", "model_digest": llm.EXPECTED_DIGEST,
        "pre_provider_block": True, "provider_invoked_on_block": False,
        "real_allow": True, "response_control": True, "restart_allow": True,
        "evidence_id_hashes": ["1" * 64, "2" * 64, "3" * 64, "4" * 64],
        "masking_outbound_originals_absent": True,
        "masking_outbound_tokens_present": True,
        "masking_restored": True,
        "masking_session_isolated": True,
        "masking_repeated_occurrence_exact": True,
        "cross_tenant_provider_not_invoked": True,
        "cross_tenant_denial_response_hash": "9" * 64,
        "second_tenant_restored": True,
        "second_tenant_nonce_distinct": True,
        "second_tenant_evidence_id_hash": "a" * 64,
        "document_draft_pdf": True,
        "document_draft_docx": True,
        "document_transform_pdf": True,
        "document_transform_docx": True,
        "provider_failure_isolated": True,
        "final_block_no_restoration": True,
        "document_output_hashes": ["5" * 64, "6" * 64, "7" * 64, "8" * 64],
        "release_ready": False,
    }
    llm.validate_llm_report(report)
    for replacement in [
        {"model": "other:9b"}, {"model_digest": ""}, {"model_digest": "a" * 64},
        {"provider_invoked_on_block": True}, {"response_control": False},
        {"evidence_id_hashes": ["1" * 64] * 4},
        {"completion": "raw model content"}, {"release_ready": True},
        {"masking_outbound_originals_absent": False},
        {"masking_repeated_occurrence_exact": False},
        {"cross_tenant_provider_not_invoked": False},
        {"cross_tenant_denial_response_hash": "bad"},
        {"second_tenant_restored": False},
        {"second_tenant_nonce_distinct": False},
        {"second_tenant_evidence_id_hash": "bad"},
        {"document_transform_docx": False},
        {"document_output_hashes": ["5" * 64] * 4},
    ]:
        with pytest.raises(ValueError):
            llm.validate_llm_report({**report, **replacement})


def _controls_only_report_fixture(llm):
    def case(name, decision, invoked, delta, response_nonempty):
        return {
            "name": name, "final_decision": decision,
            "provider_invoked": invoked,
            "provider_response_nonempty": response_nonempty,
            "provider_request_delta": delta,
            "provider_capture_request_hash": None if delta == 0 else "7" * 64,
            "client_request_id_matches": True,
            "correlation_id_matches": True,
            "request_id_hash": ("1" if name == "pre_provider_block" else "2") * 64,
            "evidence_id_hash": ("3" if name == "pre_provider_block" else "4") * 64,
            "action_id_hash": ("5" if name == "pre_provider_block" else "6") * 64,
        }
    return {
        "status": "controls_only_passed",
        "scope": llm._CONTROLS_ONLY_SCOPE,
        "model": llm.MODEL,
        "model_digest": llm.EXPECTED_DIGEST,
        "evidence_source": "real_ollama",
        "preflight_passed": True,
        "cases": [
            case("pre_provider_block", "block", False, 0, False),
            case("real_ollama_allow", "allow", True, 1, True),
        ],
        "full_acceptance": False,
        "release_ready": False,
    }


def test_controls_only_report_is_separate_strict_and_never_promotes_acceptance():
    llm = load("run_isolated_llm_provider_acceptance")
    report = _controls_only_report_fixture(llm)
    llm.validate_controls_only_report(report)
    for replacement in [
        {"full_acceptance": True}, {"release_ready": True},
        {"model_digest": "0" * 64}, {"status": "acceptance_passed"},
        {"completion": "private completion"}, {"access_token": "private"},
    ]:
        with pytest.raises(ValueError):
            llm.validate_controls_only_report({**report, **replacement})
    malformed = json.loads(json.dumps(report))
    malformed["cases"][0]["provider_request_delta"] = 1
    with pytest.raises(ValueError, match="controls_only_pre_provider_block_unproven"):
        llm.validate_controls_only_report(malformed)
    malformed = json.loads(json.dumps(report))
    malformed["cases"][1]["action_id_hash"] = "not-a-hash"
    with pytest.raises(ValueError, match="controls_only_hawk_decision_correlation_unproven"):
        llm.validate_controls_only_report(malformed)
    malformed = json.loads(json.dumps(report))
    malformed["cases"][1]["provider_capture_request_hash"] = "not-a-hash"
    with pytest.raises(ValueError, match="controls_only_real_provider_allow_unproven"):
        llm.validate_controls_only_report(malformed)


def test_controls_only_case_requires_hawk_request_correlation_and_decision_ids():
    llm = load("run_isolated_llm_provider_acceptance")
    body = {
        "provider_invoked": True, "completion": "hello", "final_decision": "allow",
        "gateway_trace": {"client_request_id": "synthetic-request", "correlation_id": "synthetic-request"},
        "evidence_bundle": {"evidence_bundle_id": "synthetic-evidence"},
        "ai_action": {"action_id": "synthetic-action"},
    }
    facts = llm._controls_only_case(
        name="real_ollama_allow", body=body,
        request_id="synthetic-request", provider_request_delta=1,
        provider_capture_request_hash="a" * 64,
    )
    assert facts["client_request_id_matches"] is True
    assert facts["correlation_id_matches"] is True
    assert facts["provider_capture_request_hash"] == "a" * 64
    assert facts["provider_response_nonempty"] is True
    assert all(re.fullmatch(r"[0-9a-f]{64}", facts[key]) for key in ("request_id_hash", "evidence_id_hash", "action_id_hash"))
    assert "hello" not in repr(facts)
    body["gateway_trace"]["correlation_id"] = "different-request"
    with pytest.raises(RuntimeError, match="controls_only_gateway_correlation_mismatch"):
        llm._controls_only_case(
            name="real_ollama_allow", body=body,
            request_id="synthetic-request", provider_request_delta=1,
            provider_capture_request_hash="a" * 64,
        )


def test_controls_only_main_writes_private_separate_report_and_cleans_lab(monkeypatch, tmp_path):
    llm = load("run_isolated_llm_provider_acceptance")
    root = tmp_path / "qa"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    monkeypatch.setattr(llm, "QA_ROOT", root)
    monkeypatch.setattr(llm, "_model_digest", lambda: llm.EXPECTED_DIGEST)
    monkeypatch.setattr(llm, "_run_provider_adapter_preflight", lambda digest: {
        "status": "provider_adapter_preflight_passed", "model_digest": digest,
        "content_present": True, "canary_exact": True, "release_ready": False,
    })
    monkeypatch.setattr(llm, "_strict_control_prerequisites_available", lambda: True)
    capture = types.SimpleNamespace(base_url="http://127.0.0.1:19001/v1", facts=[], closed=False)
    capture.__enter__ = lambda: capture
    capture.__exit__ = lambda *_args: setattr(capture, "closed", True)
    monkeypatch.setattr(llm, "OllamaCaptureProxy", lambda *_args, **_kwargs: capture)
    api_state = {"stopped": False}

    class FakeApi:
        def __init__(self, *_args, **_kwargs): pass
        def prepare(self): pass
        def start(self): pass
        def stop(self): api_state["stopped"] = True

    monkeypatch.setattr(llm, "IsolatedHawkApi", FakeApi)
    monkeypatch.setattr(llm, "_setup", lambda _api: ({"X-Tenant-ID": "synthetic-tenant"}, "synthetic-system", "synthetic-policy"))

    def fake_call(_api, _headers, _system, _policy, request_id, _prompt):
        blocked = "-block-" in request_id
        if not blocked:
            capture.facts.append({"request_hash": "a" * 64})
        decision = "block" if blocked else "allow"
        return {
            "provider_invoked": not blocked,
            "completion": "Blocked by policy." if blocked else "Hello from local Ollama.",
            "final_decision": decision,
            "gateway_trace": {"client_request_id": request_id, "correlation_id": request_id},
            "evidence_bundle": {"evidence_bundle_id": "evidence-" + request_id},
            "ai_action": {"action_id": "action-" + request_id},
        }

    monkeypatch.setattr(llm, "_call", fake_call)
    artifact_dir = root / "controls-only-test"
    assert llm._controls_only_main(artifact_dir=artifact_dir) == 0
    assert api_state["stopped"] is True and capture.closed is True
    assert {path.name for path in artifact_dir.iterdir()} == {"controls-only-progress.json", "controls-only-report.json"}
    assert stat.S_IMODE(artifact_dir.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in artifact_dir.iterdir())
    report = json.loads((artifact_dir / "controls-only-report.json").read_text())
    assert report["full_acceptance"] is False and report["release_ready"] is False
    assert [case["provider_request_delta"] for case in report["cases"]] == [0, 1]
    assert "Hello from local Ollama." not in (artifact_dir / "controls-only-report.json").read_text()
    assert not (artifact_dir / "acceptance-report.json").exists()


def test_controls_only_cleanup_failure_suppresses_pass_report_and_restores_resources(monkeypatch, tmp_path):
    llm = load("run_isolated_llm_provider_acceptance")
    root = tmp_path / "qa"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    monkeypatch.setattr(llm, "QA_ROOT", root)
    monkeypatch.setattr(llm, "_model_digest", lambda: llm.EXPECTED_DIGEST)
    monkeypatch.setattr(llm, "_run_provider_adapter_preflight", lambda digest: {
        "status": "provider_adapter_preflight_passed", "model_digest": digest,
        "content_present": True, "canary_exact": True, "release_ready": False,
    })
    monkeypatch.setattr(llm, "_strict_control_prerequisites_available", lambda: True)
    capture = types.SimpleNamespace(base_url="http://127.0.0.1:19004/v1", facts=[], closed=False)
    capture.__enter__ = lambda: capture
    capture.__exit__ = lambda *_args: setattr(capture, "closed", True)
    monkeypatch.setattr(llm, "OllamaCaptureProxy", lambda *_args, **_kwargs: capture)
    api_state = {"stopped": False}

    class CleanupFailingApi:
        def __init__(self, *_args, **_kwargs): pass
        def prepare(self): pass
        def start(self): pass
        def stop(self):
            api_state["stopped"] = True
            raise RuntimeError("controls_only_lab_cleanup_failed")

    monkeypatch.setattr(llm, "IsolatedHawkApi", CleanupFailingApi)
    monkeypatch.setattr(llm, "_setup", lambda _api: ({"X-Tenant-ID": "synthetic-tenant"}, "synthetic-system", "synthetic-policy"))

    def fake_call(_api, _headers, _system, _policy, request_id, _prompt):
        blocked = "-block-" in request_id
        if not blocked:
            capture.facts.append({"request_hash": "a" * 64})
        return {
            "provider_invoked": not blocked,
            "completion": "Blocked by policy." if blocked else "Hello from local Ollama.",
            "final_decision": "block" if blocked else "allow",
            "gateway_trace": {"client_request_id": request_id, "correlation_id": request_id},
            "evidence_bundle": {"evidence_bundle_id": "evidence-" + request_id},
            "ai_action": {"action_id": "action-" + request_id},
        }

    monkeypatch.setattr(llm, "_call", fake_call)
    original_sigterm = signal.getsignal(signal.SIGTERM)
    artifact_dir = root / "controls-only-cleanup-failure"
    with pytest.raises(RuntimeError, match="controls_only_lab_cleanup_failed"):
        llm._controls_only_main(artifact_dir=artifact_dir)
    assert api_state["stopped"] is True and capture.closed is True
    assert signal.getsignal(signal.SIGTERM) is original_sigterm
    assert not (artifact_dir / "controls-only-report.json").exists()
    progress = json.loads((artifact_dir / "controls-only-progress.json").read_text())
    assert progress["status"] == "failure" and progress["release_ready"] is False


def test_controls_only_main_fails_closed_on_provider_observed_during_block_and_cleans(monkeypatch, tmp_path):
    llm = load("run_isolated_llm_provider_acceptance")
    root = tmp_path / "qa"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    monkeypatch.setattr(llm, "QA_ROOT", root)
    monkeypatch.setattr(llm, "_model_digest", lambda: llm.EXPECTED_DIGEST)
    monkeypatch.setattr(llm, "_run_provider_adapter_preflight", lambda digest: {
        "status": "provider_adapter_preflight_passed", "model_digest": digest,
        "content_present": True, "canary_exact": True, "release_ready": False,
    })
    monkeypatch.setattr(llm, "_strict_control_prerequisites_available", lambda: True)
    capture = types.SimpleNamespace(base_url="http://127.0.0.1:19002/v1", facts=[], closed=False)
    capture.__enter__ = lambda: capture
    capture.__exit__ = lambda *_args: setattr(capture, "closed", True)
    monkeypatch.setattr(llm, "OllamaCaptureProxy", lambda *_args, **_kwargs: capture)
    api_state = {"stopped": False}

    class FakeApi:
        def __init__(self, *_args, **_kwargs): pass
        def prepare(self): pass
        def start(self): pass
        def stop(self): api_state["stopped"] = True

    monkeypatch.setattr(llm, "IsolatedHawkApi", FakeApi)
    monkeypatch.setattr(llm, "_setup", lambda _api: ({"X-Tenant-ID": "synthetic-tenant"}, "synthetic-system", "synthetic-policy"))

    def fake_call(_api, _headers, _system, _policy, request_id, _prompt):
        capture.facts.append({"request_hash": "a" * 64})
        return {
            "provider_invoked": False, "completion": "Blocked by policy.",
            "final_decision": "block",
            "gateway_trace": {"client_request_id": request_id, "correlation_id": request_id},
            "evidence_bundle": {"evidence_bundle_id": "evidence"},
            "ai_action": {"action_id": "action"},
        }

    monkeypatch.setattr(llm, "_call", fake_call)
    artifact_dir = root / "controls-only-failure"
    with pytest.raises(RuntimeError, match="controls_only_pre_provider_block_unproven"):
        llm._controls_only_main(artifact_dir=artifact_dir)
    assert api_state["stopped"] is True and capture.closed is True
    assert not (artifact_dir / "controls-only-report.json").exists()
    progress = json.loads((artifact_dir / "controls-only-progress.json").read_text())
    assert progress["status"] == "failure" and progress["release_ready"] is False


def test_controls_only_preflight_failure_never_starts_the_isolated_lab(monkeypatch, tmp_path):
    llm = load("run_isolated_llm_provider_acceptance")
    root = tmp_path / "qa"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    monkeypatch.setattr(llm, "QA_ROOT", root)
    monkeypatch.setattr(llm, "_model_digest", lambda: llm.EXPECTED_DIGEST)
    monkeypatch.setattr(llm, "_run_provider_adapter_preflight", lambda _digest: {"status": "failed"})
    monkeypatch.setattr(llm, "OllamaCaptureProxy", lambda *_args, **_kwargs: pytest.fail("capture must not start after failed preflight"))
    monkeypatch.setattr(llm, "IsolatedHawkApi", lambda *_args, **_kwargs: pytest.fail("lab must not start after failed preflight"))
    artifact_dir = root / "controls-only-preflight-failure"
    with pytest.raises(RuntimeError, match="local_ollama_preflight_unproven"):
        llm._controls_only_main(artifact_dir=artifact_dir)
    progress = json.loads((artifact_dir / "controls-only-progress.json").read_text())
    assert progress["status"] == "failure" and progress["release_ready"] is False
    assert not (artifact_dir / "controls-only-report.json").exists()


def test_controls_only_main_marks_interruption_and_cleans_lab(monkeypatch, tmp_path):
    llm = load("run_isolated_llm_provider_acceptance")
    root = tmp_path / "qa"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o700)
    monkeypatch.setattr(llm, "QA_ROOT", root)
    monkeypatch.setattr(llm, "_model_digest", lambda: llm.EXPECTED_DIGEST)
    monkeypatch.setattr(llm, "_run_provider_adapter_preflight", lambda digest: {
        "status": "provider_adapter_preflight_passed", "model_digest": digest,
        "content_present": True, "canary_exact": True, "release_ready": False,
    })
    monkeypatch.setattr(llm, "_strict_control_prerequisites_available", lambda: True)
    capture = types.SimpleNamespace(base_url="http://127.0.0.1:19003/v1", closed=False)
    capture.__enter__ = lambda: capture
    capture.__exit__ = lambda *_args: setattr(capture, "closed", True)
    monkeypatch.setattr(llm, "OllamaCaptureProxy", lambda *_args, **_kwargs: capture)
    api_state = {"stopped": False}

    class InterruptingApi:
        def __init__(self, *_args, **_kwargs): pass
        def prepare(self): pass
        def start(self): raise KeyboardInterrupt
        def stop(self): api_state["stopped"] = True

    monkeypatch.setattr(llm, "IsolatedHawkApi", InterruptingApi)
    artifact_dir = root / "controls-only-interrupted"
    with pytest.raises(KeyboardInterrupt):
        llm._controls_only_main(artifact_dir=artifact_dir)
    assert api_state["stopped"] is True and capture.closed is True
    progress = json.loads((artifact_dir / "controls-only-progress.json").read_text())
    assert progress["status"] == "interrupted" and progress["release_ready"] is False
    assert not (artifact_dir / "controls-only-report.json").exists()


def test_controls_only_mode_is_mutually_exclusive_with_every_existing_mode():
    llm = load("run_isolated_llm_provider_acceptance")
    for other in (
        "--transforms-only", "--documents-only",
        "--adapter-constructor-check-child", "--adapter-preflight-child",
    ):
        with pytest.raises(SystemExit) as error:
            llm._parse_cli_args(["--controls-only", other])
        assert error.value.code == 2
    assert llm._parse_cli_args(["--controls-only"]).controls_only is True
    assert llm._parse_cli_args([]).controls_only is False


def test_ollama_capture_proxy_forwards_body_and_retains_only_sanitized_facts():
    llm = load("run_isolated_llm_provider_acceptance")
    seen = []

    class Upstream(BaseHTTPRequestHandler):
        def do_POST(self):
            data = self.rfile.read(int(self.headers["Content-Length"]))
            seen.append(data)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"choices":[{"message":{"content":"ok"}}]}')

        def log_message(self, *args):
            pass

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        with llm.OllamaCaptureProxy(f"http://127.0.0.1:{upstream.server_port}", originals=("Alice Smith",)) as proxy:
            body = b'{"messages":[{"content":"[[HAWK_PERSON_abcdefghijklmnopqrstuvwx_0001]]"}]}'
            request = urllib.request.Request(proxy.base_url + "/chat/completions", data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=5) as response:
                assert response.status == 200
            assert seen == [body]
            facts = proxy.facts[-1]
            assert facts["originals_absent"] is True
            assert facts["typed_token_count"] == 1
            assert facts["typed_token_type_counts"] == {"PERSON": 1}
            assert facts["typed_token_occurrence_counts"] == [1]
            assert facts["request_hash"] == hashlib.sha256(body).hexdigest()
            assert "Alice Smith" not in repr(proxy.facts)
            assert "[[HAWK_" not in repr(proxy.facts)
    finally:
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=2)


def test_ollama_capture_proxy_proves_repeated_typed_occurrence_without_retaining_tokens():
    llm = load("run_isolated_llm_provider_acceptance")
    class Upstream(BaseHTTPRequestHandler):
        def do_POST(self):
            size = int(self.headers.get("Content-Length") or "0")
            self.rfile.read(size)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"choices":[{"message":{"content":"ok"}}]}')

        def log_message(self, *args):
            pass

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        with llm.OllamaCaptureProxy(
            f"http://127.0.0.1:{upstream.server_port}",
            originals=("Alice Smith", "P12345678", "123456789012"),
        ) as proxy:
            nonce = "abcdefghijklmnopqrstuvwx"
            body = json.dumps({"messages": [{"content": "\n".join([
                f"Name: [[HAWK_PERSON_{nonce}_0001]]",
                f"Passport: [[HAWK_PASSPORT_{nonce}_0001]]",
                f"Account: [[HAWK_BANK_ACCOUNT_{nonce}_0001]]",
                f"Name: [[HAWK_PERSON_{nonce}_0001]]",
            ])}]}).encode()
            request = urllib.request.Request(proxy.base_url + "/chat/completions", data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=5) as response:
                assert response.status == 200
            facts = proxy.facts[-1]
            assert facts["typed_token_count"] == 4
            assert facts["typed_token_type_counts"] == {"BANK_ACCOUNT": 1, "PASSPORT": 1, "PERSON": 2}
            assert facts["typed_token_occurrence_counts"] == [1, 1, 2]
            assert "[[HAWK_" not in repr(facts)
            assert nonce not in repr(facts)
    finally:
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=2)


def test_cross_tenant_denial_hash_is_bounded_http_projection_only():
    llm = load("run_isolated_llm_provider_acceptance")
    denial = {"detail": {"code": "tenant_scope_mismatch", "message": "private tenant details"}}
    first = llm._safe_denial_response_hash(403, denial)
    second = llm._safe_denial_response_hash(404, {"detail": {"code": "tenant_scope_mismatch"}})
    assert re.fullmatch(r"[0-9a-f]{64}", first)
    assert re.fullmatch(r"[0-9a-f]{64}", second)
    assert first != second
    assert "private tenant details" not in repr(first)
    assert "tenant_scope_mismatch" not in repr(first)


def test_document_failure_diagnostic_allows_only_closed_codes_and_fixed_context():
    llm = load("run_isolated_llm_provider_acceptance")
    allowed = llm._safe_document_failure_diagnostic(
        400, {"detail": {"code": "invalid_pdf_document"}},
        mode="draft", output_format="pdf",
    )
    literal = llm._safe_document_failure_diagnostic(
        400, {"detail": "document_size_limit"}, mode="transform", output_format="docx",
    )
    assert allowed == "document_gateway_status_400_stage_documents_complete_mode_draft_format_pdf_code_invalid_pdf_document"
    assert literal.endswith("mode_transform_format_docx_code_document_size_limit")
    assert "documents_complete" in allowed


def test_document_failure_diagnostic_sanitizes_malformed_unlisted_and_oversized_bodies():
    llm = load("run_isolated_llm_provider_acceptance")
    cases = [
        (400, {"detail": {"code": "not_allowlisted", "message": "secret-token"}}, False),
        (400, {"detail": {"code": "invalid_pdf_document", "extra": "secret-map"}}, False),
        (400, {"detail": ["secret-map", "[[HAWK_PERSON_x]]"]}, False),
        (502, b"not-json secret-token [[HAWK_PERSON_x]]", False),
        (400, {"detail": {"code": "invalid_pdf_document", "message": "secret-token"}}, True),
    ]
    for status, body, oversized in cases:
        diagnostic = llm._safe_document_failure_diagnostic(status, body, mode="draft", output_format="pdf", oversized=oversized)
        assert diagnostic == f"document_gateway_status_{status}_stage_documents_complete_mode_draft_format_pdf"
        assert all(value not in diagnostic for value in ("secret-token", "secret-map", "[[HAWK_PERSON_x]]", "invalid_pdf_document"))


def test_document_call_parses_only_bounded_http_error_json(monkeypatch):
    llm = load("run_isolated_llm_provider_acceptance")

    class FakeApi:
        base_url = "http://127.0.0.1:8001"

    def allowlisted(_request, timeout):
        raise urllib.error.HTTPError(
            "http://127.0.0.1:8001/llm-gateway/documents/complete", 400, "bad", {},
            io.BytesIO(b'{"detail":{"code":"invalid_pdf_document"}}'),
        )

    monkeypatch.setattr(urllib.request, "urlopen", allowlisted)
    with pytest.raises(RuntimeError) as allowed_error:
        llm._document_call(FakeApi(), {"Authorization": "Bearer synthetic", "X-Tenant-ID": "tenant"}, "system", "policy", mode="draft", output_format="pdf", instruction="synthetic")
    assert str(allowed_error.value).endswith("mode_draft_format_pdf_code_invalid_pdf_document")

    def oversized(_request, timeout):
        raise urllib.error.HTTPError(
            "http://127.0.0.1:8001/llm-gateway/documents/complete", 400, "bad", {},
            io.BytesIO(b"x" * 4097),
        )

    monkeypatch.setattr(urllib.request, "urlopen", oversized)
    with pytest.raises(RuntimeError) as oversized_error:
        llm._document_call(FakeApi(), {"Authorization": "Bearer synthetic", "X-Tenant-ID": "tenant"}, "system", "policy", mode="draft", output_format="pdf", instruction="synthetic")
    assert str(oversized_error.value) == "document_gateway_status_400_stage_documents_complete_mode_draft_format_pdf"


def test_documents_only_flow_is_exact_order_and_four_calls():
    llm = load("run_isolated_llm_provider_acceptance")
    assert [(mode, fmt) for mode, fmt, *_rest in llm.DOCUMENT_ONLY_FLOWS] == [
        ("draft", "pdf"), ("draft", "docx"), ("transform", "pdf"), ("transform", "docx"),
    ]
    assert len(llm.DOCUMENT_ONLY_FLOWS) == 4


def test_documents_only_flow_facts_require_provider_restore_and_masking_proof():
    llm = load("run_isolated_llm_provider_acceptance")
    good = llm._documents_only_flow_facts(
        {"hawk": {"provider_invoked": True, "final_decision": "allow", "response_control_coverage": "complete", "reversible_masking": {"restored": True, "mapping_destroyed": True, "applied": True}}},
        {"originals_absent": True, "typed_token_count": 3, "structured_output_requested": True},
    )
    bad = llm._documents_only_flow_facts(
        {"hawk": {"provider_invoked": False, "final_decision": "block", "response_control_coverage": "request_only"}},
        {"originals_absent": False, "typed_token_count": 2, "structured_output_requested": False},
    )
    assert all(good[key] is True for key in ("provider_invoked", "response_control_complete", "structured_output_requested", "outbound_originals_absent", "expected_tokens", "restored", "mapping_destroyed", "applied"))
    assert any(bad[key] is False for key in ("provider_invoked", "response_control_complete", "outbound_originals_absent", "expected_tokens"))


def test_documents_only_main_stops_after_first_document_failure(monkeypatch, tmp_path):
    llm = load("run_isolated_llm_provider_acceptance")
    calls = []

    class Capture:
        base_url = "http://127.0.0.1:19001/v1"
        facts = []

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    capture = Capture()

    class Api:
        def __init__(self, *args, **kwargs):
            pass
        def prepare(self):
            calls.append("prepare")
        def start(self):
            calls.append("start")
        def stop(self):
            calls.append("stop")
            progress = json.loads((tmp_path / "failure" / "acceptance-progress.json").read_text())
            assert progress["status"] == "failure"
            assert progress["flow_index"] == progress["last_completed_flow_index"] == 1
            assert progress["flow_total"] == 4

    monkeypatch.setattr(llm, "_model_digest", lambda: llm.EXPECTED_DIGEST)
    monkeypatch.setattr(llm, "OllamaCaptureProxy", lambda *args, **kwargs: capture)
    monkeypatch.setattr(llm, "IsolatedHawkApi", Api)
    def fake_setup(api):
        calls.append("setup")
        return {"X-Tenant-ID": "tenant"}, "system", "policy"

    monkeypatch.setattr(llm, "_setup", fake_setup)

    def fake_source_files():
        calls.append("fixtures")
        return (("synthetic.pdf", b"pdf", "application/pdf"), ("synthetic.docx", b"docx", "application/docx"))

    monkeypatch.setattr(llm, "_synthetic_source_files", fake_source_files)
    monkeypatch.setattr(llm, "_checked_document_output", lambda *args, **kwargs: (b"output", "a" * 64))

    def fake_document_call(*args, **kwargs):
        calls.append((kwargs["mode"], kwargs["output_format"]))
        if len([item for item in calls if isinstance(item, tuple)]) == 2:
            raise RuntimeError("document_gateway_status_400_stage_documents_complete_mode_draft_format_docx")
        capture.facts.append({"originals_absent": True, "typed_token_count": 3, "structured_output_requested": True, "request_hash": "b" * 64})
        return {"hawk": {"provider_invoked": True, "final_decision": "allow", "response_control_coverage": "complete", "reversible_masking": {"restored": True, "mapping_destroyed": True, "applied": True}}, "document": {"block_count": 2}}

    monkeypatch.setattr(llm, "_document_call", fake_document_call)
    with pytest.raises(RuntimeError, match="document_gateway_status_400"):
        llm._documents_only_main(artifact_dir=tmp_path / "failure", evidence_source="unit_test")
    assert calls[:4] == ["prepare", "start", "setup", "fixtures"]
    assert [item for item in calls if isinstance(item, tuple)] == [("draft", "pdf"), ("draft", "docx")]
    assert "stop" in calls


def test_artifact_allocations_are_distinct_private_children(tmp_path, monkeypatch):
    llm = load("run_isolated_llm_provider_acceptance")
    monkeypatch.setattr(llm, "QA_ROOT", tmp_path / "qa-root")
    first = llm._artifact_directory(None, prefix="run-")
    second = llm._artifact_directory(None, prefix="run-")
    assert first != second
    assert first.parent == second.parent == tmp_path / "qa-root"
    assert stat.S_IMODE(first.stat().st_mode) == stat.S_IMODE(second.stat().st_mode) == 0o700


def test_artifact_directory_rejects_reuse_and_real_paths_outside_qa_root(tmp_path, monkeypatch):
    llm = load("run_isolated_llm_provider_acceptance")
    monkeypatch.setattr(llm, "QA_ROOT", tmp_path / "qa-root")
    existing = tmp_path / "existing"
    existing.mkdir(mode=0o700)
    with pytest.raises(RuntimeError, match="artifact_directory_reuse_rejected"):
        llm._artifact_directory(existing, prefix="run-", evidence_source="unit_test")
    outside = tmp_path / "real-run"
    with pytest.raises(RuntimeError, match="artifact_directory_outside_qa_root"):
        llm._artifact_directory(outside, prefix="run-", evidence_source="real_ollama")


def test_mock_document_runs_use_explicit_tmp_artifacts_without_qa_root_writes(monkeypatch, tmp_path):
    llm = load("run_isolated_llm_provider_acceptance")
    calls = []

    class Capture:
        base_url = "http://127.0.0.1:19003/v1"
        facts = []
        def __enter__(self): return self
        def __exit__(self, *args): return None

    class Api:
        def __init__(self, *args, **kwargs): pass
        def prepare(self): calls.append("prepare")
        def start(self): calls.append("start")
        def stop(self): calls.append("stop")

    capture = Capture()
    monkeypatch.setattr(llm, "QA_ROOT", tmp_path / "forbidden-qa-root")
    monkeypatch.setattr(llm, "_model_digest", lambda: llm.EXPECTED_DIGEST)
    monkeypatch.setattr(llm, "OllamaCaptureProxy", lambda *args, **kwargs: capture)
    monkeypatch.setattr(llm, "IsolatedHawkApi", Api)
    monkeypatch.setattr(llm, "_setup", lambda api: ({"X-Tenant-ID": "tenant"}, "system", "policy"))
    monkeypatch.setattr(llm, "_synthetic_source_files", lambda: (("synthetic.pdf", b"pdf", "application/pdf"), ("synthetic.docx", b"docx", "application/docx")))
    monkeypatch.setattr(llm, "_checked_document_output", lambda *args, **kwargs: (b"output", "a" * 64))
    def fake_call(*args, **kwargs):
        capture.facts.append({"originals_absent": True, "typed_token_count": 3, "structured_output_requested": True, "request_hash": "b" * 64})
        return {"hawk": {"provider_invoked": True, "final_decision": "allow", "response_control_coverage": "complete", "reversible_masking": {"restored": True, "mapping_destroyed": True, "applied": True}}, "document": {"block_count": 3}}
    monkeypatch.setattr(llm, "_document_call", fake_call)
    target = tmp_path / "unit-run"
    assert llm._documents_only_main(flows=llm.DOCUMENT_ONLY_FLOWS[2:], artifact_dir=target, evidence_source="unit_test") == 0
    assert target.is_dir()
    assert not (tmp_path / "forbidden-qa-root").exists()


@pytest.mark.parametrize("trigger", ["keyboard", "sigterm"])
def test_interruption_progress_is_persisted_before_stop(monkeypatch, tmp_path, trigger):
    llm = load("run_isolated_llm_provider_acceptance")
    original_sigterm = signal.getsignal(signal.SIGTERM)
    class Capture:
        base_url = "http://127.0.0.1:19004/v1"
        facts = []
        def __enter__(self): return self
        def __exit__(self, *args): return None
    target = tmp_path / trigger
    capture = Capture()
    class Api:
        def __init__(self, *args, **kwargs): pass
        def prepare(self):
            def lab_cleanup(_signum, _frame):
                raise SystemExit(0)
            signal.signal(signal.SIGTERM, lab_cleanup)
        def start(self):
            if trigger == "sigterm":
                signal.raise_signal(signal.SIGTERM)
            raise KeyboardInterrupt
        def stop(self):
            progress = json.loads((target / "acceptance-progress.json").read_text())
            assert progress["status"] == "interrupted"
    monkeypatch.setattr(llm, "_model_digest", lambda: llm.EXPECTED_DIGEST)
    monkeypatch.setattr(llm, "OllamaCaptureProxy", lambda *args, **kwargs: capture)
    monkeypatch.setattr(llm, "IsolatedHawkApi", Api)
    with pytest.raises(KeyboardInterrupt):
        llm._documents_only_main(artifact_dir=target, evidence_source="unit_test")
    assert signal.getsignal(signal.SIGTERM) == original_sigterm


def test_saved_document_validation_catches_disk_and_report_mismatches(tmp_path):
    llm = load("run_isolated_llm_provider_acceptance")
    source_pdf, _source_docx = llm._synthetic_source_files()
    path = tmp_path / "saved.pdf"
    path.write_bytes(source_pdf[1])
    digest = hashlib.sha256(source_pdf[1]).hexdigest()
    record = llm._validate_saved_document(path, fmt="pdf", expected_digest=digest, required_values=("Alice Smith", "P12345678", "123456789012"), block_count=1)
    assert record == {"filename": "saved.pdf", "byte_length": len(source_pdf[1]), "digest": digest}
    path.write_bytes(b"mutated")
    with pytest.raises(RuntimeError, match="document_output_hash_mismatch"):
        llm._validate_saved_document(path, fmt="pdf", expected_digest=digest, required_values=(), block_count=0)
    path.unlink()
    with pytest.raises(RuntimeError, match="document_artifact_missing"):
        llm._validate_saved_document(path, fmt="pdf", expected_digest=digest, required_values=(), block_count=0)
    path.write_bytes(b"123456")
    with pytest.raises(RuntimeError, match="document_output_too_small"):
        llm._validate_saved_document(path, fmt="pdf", expected_digest=digest, required_values=(), block_count=0)


def test_live_validator_rejects_unit_test_evidence_and_report_hash_mismatch(tmp_path):
    llm = load("run_isolated_llm_provider_acceptance")
    report = {
        "model": llm.MODEL, "model_digest": llm.EXPECTED_DIGEST, "evidence_source": "unit_test",
        "pre_provider_block": True, "provider_invoked_on_block": False, "real_allow": True,
        "response_control": True, "restart_allow": True, "evidence_id_hashes": ["1" * 64, "2" * 64, "3" * 64, "4" * 64],
        "masking_outbound_originals_absent": True, "masking_outbound_tokens_present": True, "masking_restored": True,
        "masking_repeated_occurrence_exact": True, "masking_session_isolated": True, "cross_tenant_provider_not_invoked": True,
        "cross_tenant_denial_response_hash": "9" * 64, "second_tenant_restored": True, "second_tenant_nonce_distinct": True,
        "second_tenant_evidence_id_hash": "a" * 64, "document_draft_pdf": True, "document_draft_docx": True,
        "document_transform_pdf": True, "document_transform_docx": True, "provider_failure_isolated": True,
        "final_block_no_restoration": True, "document_output_hashes": ["5" * 64, "6" * 64, "7" * 64, "8" * 64], "release_ready": False,
    }
    with pytest.raises(ValueError, match="live_evidence_source_required"):
        llm.validate_llm_report(report, live=True)
    report["evidence_source"] = "real_ollama"
    with pytest.raises(ValueError, match="live_artifact_directory_required"):
        llm.validate_llm_report(report, live=True)
    report["artifacts"] = [{"filename": f"{idx}.pdf", "byte_length": 7, "digest": digest} for idx, digest in enumerate(report["document_output_hashes"])]
    with pytest.raises(ValueError, match="document_artifact_disk_mismatch"):
        llm.validate_llm_report(report, live=True, artifact_dir=tmp_path)
    report["artifacts"][0]["filename"] = "nested/0.pdf"
    with pytest.raises(ValueError, match="document_artifact_reference_invalid"):
        llm.validate_llm_report(report, live=True, artifact_dir=tmp_path)


def test_documents_only_main_accepts_transform_subset_without_draft_calls(monkeypatch, tmp_path):
    llm = load("run_isolated_llm_provider_acceptance")
    calls = []

    class Capture:
        base_url = "http://127.0.0.1:19002/v1"
        facts = []

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    capture = Capture()

    class Api:
        def __init__(self, *args, **kwargs):
            pass

        def prepare(self):
            calls.append("prepare")

        def start(self):
            calls.append("start")

        def stop(self):
            calls.append("stop")

    monkeypatch.setattr(llm, "_model_digest", lambda: llm.EXPECTED_DIGEST)
    monkeypatch.setattr(llm, "OllamaCaptureProxy", lambda *args, **kwargs: capture)
    monkeypatch.setattr(llm, "IsolatedHawkApi", Api)
    monkeypatch.setattr(llm, "_setup", lambda api: ({"X-Tenant-ID": "tenant"}, "system", "policy"))
    monkeypatch.setattr(llm, "_synthetic_source_files", lambda: (("synthetic.pdf", b"pdf", "application/pdf"), ("synthetic.docx", b"docx", "application/docx")))
    monkeypatch.setattr(llm, "_checked_document_output", lambda *args, **kwargs: (b"output", "a" * 64))

    def fake_document_call(*args, **kwargs):
        calls.append((kwargs["mode"], kwargs["output_format"]))
        capture.facts.append({"originals_absent": True, "typed_token_count": 3, "structured_output_requested": True, "request_hash": "b" * 64})
        return {"hawk": {"provider_invoked": True, "final_decision": "allow", "response_control_coverage": "complete", "reversible_masking": {"restored": True, "mapping_destroyed": True, "applied": True}}, "document": {"block_count": 3}}

    monkeypatch.setattr(llm, "_document_call", fake_document_call)
    assert llm._documents_only_main(
        flows=llm.DOCUMENT_ONLY_FLOWS[2:], report_status="transforms_only_passed",
        artifact_dir=tmp_path / "transforms", evidence_source="unit_test",
    ) == 0
    assert [item for item in calls if isinstance(item, tuple)] == [("transform", "pdf"), ("transform", "docx")]


def test_provider_adapter_preflight_requires_exact_configuration_and_discards_content(monkeypatch):
    llm = load("run_isolated_llm_provider_acceptance")
    module = types.ModuleType("app.services.brain.providers.openai_provider")
    calls = []

    class Provider:
        def __init__(self, **kwargs):
            calls.append(kwargs)
            self.model = kwargs["model"]
            self.max_tokens = kwargs["max_tokens"]
            self.reasoning_effort = kwargs["reasoning_effort"]

        def _url(self):
            return "http://127.0.0.1:11434/v1/chat/completions"

        def generate_text(self, _system, user):
            return llm.EXPECTED_CANARY if user == llm.CANARY_PROMPT else "private completion never reported"

    module.OpenAIProvider = Provider
    monkeypatch.setitem(sys.modules, module.__name__, module)
    facts = llm._provider_adapter_preflight(llm.EXPECTED_DIGEST)
    assert facts == {"status": "provider_adapter_preflight_passed", "model": llm.MODEL, "model_digest": llm.EXPECTED_DIGEST, "content_present": True, "canary_exact": True, "release_ready": False}
    assert calls[0]["base_url"] == llm.LOCAL_PROVIDER_URL
    assert calls[0]["model"] == llm.MODEL
    assert calls[0]["max_tokens"] == 600
    assert calls[0]["reasoning_effort"] == "none"
    assert "private" not in repr(facts)
    with pytest.raises(RuntimeError, match="provider_adapter_preflight_identity_mismatch"):
        llm._provider_adapter_preflight("wrong")

    def fail(_self, _system, _user):
        raise RuntimeError("raw private completion or URL")

    monkeypatch.setattr(Provider, "generate_text", fail)
    with pytest.raises(RuntimeError) as failure:
        llm._provider_adapter_preflight(llm.EXPECTED_DIGEST)
    assert str(failure.value) == "provider_adapter_preflight_failed"


def test_provider_preflight_child_facts_are_exact_and_bounded():
    llm = load("run_isolated_llm_provider_acceptance")
    facts = {"status": "provider_adapter_preflight_passed", "model": llm.MODEL, "model_digest": llm.EXPECTED_DIGEST, "content_present": True, "canary_exact": True, "release_ready": False}
    raw = json.dumps(facts).encode()
    assert llm._validate_preflight_facts(raw, 0, llm.EXPECTED_DIGEST) == facts
    for invalid, code in [
        (raw, 2), (b"", 0), (b"raw private completion", 0),
        (json.dumps({**facts, "completion": "private"}).encode(), 0),
        (json.dumps({**facts, "model_digest": "wrong"}).encode(), 0),
        (b"x" * (llm.PREFLIGHT_MAX_BYTES + 1), 0),
    ]:
        with pytest.raises(RuntimeError):
            llm._validate_preflight_facts(invalid, code, llm.EXPECTED_DIGEST)
    with pytest.raises(RuntimeError, match="provider_adapter_preflight_canary_mismatch"):
        llm._validate_preflight_facts(json.dumps({**facts, "canary_exact": False}).encode(), 0, llm.EXPECTED_DIGEST)


def test_provider_preflight_parent_imports_no_app_modules_and_uses_private_child(monkeypatch):
    llm = load("run_isolated_llm_provider_acceptance")
    tracked = ("app.core.config", "app.db.session", "app.services.brain", "app.services.brain.providers.openai_provider")
    before = {name: sys.modules.get(name) for name in tracked}
    calls = []

    class Process:
        pass

    def fake_popen(command, **kwargs):
        calls.append((command, kwargs))
        return Process()

    facts = {"status": "provider_adapter_preflight_passed", "model": llm.MODEL, "model_digest": llm.EXPECTED_DIGEST, "content_present": True, "canary_exact": True, "release_ready": False}
    monkeypatch.setattr(llm.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(llm, "_read_preflight_child", lambda _process: (0, json.dumps(facts).encode()))
    assert llm._run_provider_adapter_preflight(llm.EXPECTED_DIGEST) == facts
    assert {name: sys.modules.get(name) for name in tracked} == before
    command, kwargs = calls[0]
    assert command[-1] == "--adapter-preflight-child"
    assert kwargs["start_new_session"] is True
    assert kwargs["stderr"] == llm.subprocess.DEVNULL
    assert kwargs["env"]["OPENAI_REASONING_EFFORT"] == "none"
    assert kwargs["env"]["LLM_MAX_TOKENS"] == "600"
    assert kwargs["env"]["OPENAI_BASE_URL"] == llm.LOCAL_PROVIDER_URL
    assert kwargs["env"]["SECRET_KEY_LOCK_ENABLED"] == "true"
    assert kwargs["env"]["SECRET_KEY_LOCK_FILE"].startswith(kwargs["cwd"] + "/")
    assert "TEST_PROFILE" not in kwargs["env"]
    assert "CELERY_BROKER_URL" not in kwargs["env"]
    assert kwargs["cwd"].startswith("/private/tmp/hawk-ollama-preflight-")


def test_real_provider_constructor_child_uses_private_lock_without_parent_imports():
    llm = load("run_isolated_llm_provider_acceptance")
    tracked = ("app.core.config", "app.db.session", "app.services.brain", "app.services.brain.providers.openai_provider")
    before_modules = {name: sys.modules.get(name) for name in tracked}
    repo_lock = llm.API / ".runtime" / "secret_key.lock"
    before_lock = hashlib.sha256(repo_lock.read_bytes()).hexdigest() if repo_lock.exists() else None
    with tempfile.TemporaryDirectory(prefix="hawk-real-child-check-", dir="/private/tmp") as name:
        root = Path(name)
        env = llm._build_preflight_child_env(root)
        assert Path(env["SECRET_KEY_LOCK_FILE"]) == root / "secret-key.lock"
        assert env["SECRET_KEY_LOCK_ENABLED"] == "true"
        result = subprocess.run(
            [sys.executable, str(Path(llm.__file__).resolve()), "--adapter-constructor-check-child"],
            cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=20, check=False,
        )
        assert result.returncode == 0
        assert json.loads(result.stdout) == {
            "status": "provider_adapter_constructor_checked", "model": llm.MODEL,
            "base_url": llm.LOCAL_PROVIDER_URL, "max_tokens": 600,
            "reasoning_effort": "none", "release_ready": False,
        }
        private_lock = root / "secret-key.lock"
        assert private_lock.is_file()
        assert stat.S_IMODE(private_lock.stat().st_mode) == 0o600
    after_lock = hashlib.sha256(repo_lock.read_bytes()).hexdigest() if repo_lock.exists() else None
    assert after_lock == before_lock
    assert {name: sys.modules.get(name) for name in tracked} == before_modules


def test_real_minimizer_preserves_fragmented_canary_and_outer_pattern_matches_output():
    llm = load("run_isolated_llm_provider_acceptance")
    with tempfile.TemporaryDirectory(prefix="hawk-canary-pattern-check-", dir="/private/tmp") as name:
        root = Path(name)
        env = llm._build_preflight_child_env(root)
        source = (
            "import json; "
            "from app.services.llm_gateway_secure.data_minimizer import minimize_prompts; "
            "from app.services.llm_gateway_service import OUTPUT_REDACT_PATTERNS; "
            f"prompt={llm.CANARY_PROMPT!r}; expected={llm.EXPECTED_CANARY!r}; "
            "_system,user,_meta=minimize_prompts(system_prompt='Answer briefly.',user_prompt=prompt,mode='strict'); "
            "print(json.dumps({'input_unchanged':user==prompt,'output_triggered':any(p.search(expected) for p in OUTPUT_REDACT_PATTERNS)}))"
        )
        result = subprocess.run(
            [sys.executable, "-c", source], cwd=root, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=20, check=False,
        )
        assert result.returncode == 0
        assert json.loads(result.stdout) == {"input_unchanged": True, "output_triggered": True}


def test_llm_preflight_failure_does_not_start_isolated_lab(monkeypatch):
    llm = load("run_isolated_llm_provider_acceptance")
    monkeypatch.setattr(llm, "_model_digest", lambda: llm.EXPECTED_DIGEST)
    monkeypatch.setattr(llm, "_run_provider_adapter_preflight", lambda _digest: (_ for _ in ()).throw(RuntimeError("provider_adapter_preflight_empty_content")))
    monkeypatch.setattr(llm, "IsolatedHawkApi", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("lab_must_not_start")))
    with pytest.raises(RuntimeError, match="provider_adapter_preflight_empty_content"):
        llm.main()


def test_llm_failure_diagnostic_exposes_only_bounded_control_codes():
    llm = load("run_isolated_llm_provider_acceptance")
    diagnostic = llm._safe_control_diagnostic({
        "final_decision": "block", "provider_invoked": False,
        "completion": "raw private completion must not appear",
        "response_control_coverage": "request_only",
        "guardian_results": [
            {"guardian_id": "authorization_kernel_v2", "reason": "no_authority", "matched_conditions": ["raw private prompt"]},
            {"guardian_id": "unsafe/name", "reason": "raw private prompt"},
        ],
        "gateway_trace": {"secure_gateway": {"pre_call_guard": {"details": {"violations": ["tls_required_https_only", "raw private prompt"]}}}},
    })
    assert "decision_block_provider_no_completion_yes_coverage_request_only" in diagnostic
    assert "authorization_kernel_v2.no_authority" in diagnostic
    assert "violations_tls_required_https_only" in diagnostic
    assert "raw" not in diagnostic
    assert "private" not in diagnostic


def test_llm_canary_failure_diagnostic_contains_flags_and_no_raw_content():
    llm = load("run_isolated_llm_provider_acceptance")
    diagnostic = llm._safe_canary_diagnostic({
        "final_decision": "allow", "provider_invoked": True,
        "completion": "api_key private secret and model text",
        "response_control_coverage": "complete",
        "guardian_results": [
            {"guardian_id": "output_guardian", "reason": "sensitive_output", "matched_conditions": ["private secret"]},
        ],
        "gateway_trace": {"secure_gateway": {
            "post_call_guard": {"details": {
                "violations": ["post_call_sensitive_output_redaction_unverified", "private secret"],
                "actions": ["post_call_sensitive_output_redacted", "private secret"],
                "redaction_applied": True,
            }},
        }},
    })
    assert "decision_allow_provider_yes_completion_yes_coverage_complete" in diagnostic
    assert "output_guardian.sensitive_output" in diagnostic
    assert "canary_present_yes_restriction_exact_no" in diagnostic
    assert "post_violations_post_call_sensitive_output_redaction_unverified" in diagnostic
    assert "post_actions_post_call_sensitive_output_redacted" in diagnostic
    assert "redaction_applied_yes" in diagnostic
    assert "api_key" not in diagnostic
    assert "private" not in diagnostic
    assert "secret" not in diagnostic
    restricted = llm._safe_canary_diagnostic({"completion": "Response restricted by Output Guardian policy."})
    assert "canary_present_no_restriction_exact_yes" in restricted


def test_llm_canary_accepts_outer_restriction_or_verified_secure_redaction_only():
    llm = load("run_isolated_llm_provider_acceptance")
    outer = {"provider_invoked": True, "final_decision": "block", "completion": "Response restricted by Output Guardian policy."}
    assert llm._canary_response_controlled(outer)
    secure = {
        "provider_invoked": True, "final_decision": "allow",
        "completion": "[REDACTED]", "response_control_coverage": "complete",
        "gateway_trace": {"secure_gateway": {"post_call_guard": {"details": {
            "actions": ["post_call_sensitive_output_redacted"],
            "violations": [], "redaction_applied": True,
        }}}},
    }
    assert llm._canary_response_controlled(secure)
    for changed in [
        {**secure, "provider_invoked": False},
        {**secure, "completion": "api_key"},
        {**secure, "response_control_coverage": "unknown"},
        {**secure, "gateway_trace": {"secure_gateway": {"post_call_guard": {"details": {**secure["gateway_trace"]["secure_gateway"]["post_call_guard"]["details"], "redaction_applied": False}}}}},
        {**secure, "gateway_trace": {"secure_gateway": {"post_call_guard": {"details": {**secure["gateway_trace"]["secure_gateway"]["post_call_guard"]["details"], "violations": ["post_call_sensitive_output_redaction_unverified"]}}}}},
    ]:
        assert not llm._canary_response_controlled(changed)


def test_local_ollama_policy_version_exact_scope_and_existing_guardians():
    llm = load("run_isolated_llm_provider_acceptance")
    original = {
        "scope": {"applies_to_risk_tiers": ["LOW", "HIGH"], "llm_gateway_security": {"minimization_mode": "strict"}},
        "enforcement_defaults": {"default_decision": "allow", "escalation": "notify"},
        "guardian_contracts": [{"id": "existing-guardian", "block_conditions": ["secret"]}],
    }
    payload = llm.build_local_policy_version(original, system_id="isolated-system", env="dev", base_url=llm.LOCAL_PROVIDER_URL)
    assert payload["scope"]["applies_to_risk_tiers"] == ["HIGH"]
    assert payload["scope"]["applies_to_actor_types"] == ["human"]
    assert payload["scope"]["applies_to_ai_system_ids"] == ["isolated-system"]
    assert payload["scope"]["llm_gateway_security"] == {"minimization_mode": "strict", "provider_allowlist": ["llama"], "allow_insecure_localhost_http": True, "reversible_masking": {"enabled": True, "restore_to_authenticated_caller": True, "mapping_ttl_seconds": 120, "max_text_chars": 60000, "documents_enabled": True, "max_document_bytes": 10485760, "max_document_pages": 100}}
    assert payload["enforcement_defaults"] == original["enforcement_defaults"]
    assert payload["guardian_contracts"] == original["guardian_contracts"]
    for changed, env, url in [
        ({**payload, "scope": {**payload["scope"], "llm_gateway_security": {"provider_allowlist": ["openai"], "allow_insecure_localhost_http": True}}}, "dev", llm.LOCAL_PROVIDER_URL),
        (payload, "prod", llm.LOCAL_PROVIDER_URL),
        (payload, "dev", "http://192.0.2.1:11434/v1"),
        (payload, "dev", "http://127.0.0.1:11435/v1"),
    ]:
        with pytest.raises(ValueError):
            llm.validate_local_policy_exception(changed, env=env, base_url=url, system_id="isolated-system")


def test_llm_setup_returns_new_scoped_policy_version_id(monkeypatch):
    llm = load("run_isolated_llm_provider_acceptance")
    app = types.ModuleType("app")
    core = types.ModuleType("app.core")
    config = types.ModuleType("app.core.config")
    config.settings = types.SimpleNamespace(env="dev", openai_base_url=llm.LOCAL_PROVIDER_URL)
    models = types.ModuleType("app.db.models")
    ai_system = types.ModuleType("app.db.models.ai_system")
    ai_system.AISystem = object
    db_package = types.ModuleType("app.db")
    session = types.ModuleType("app.db.session")
    row = types.SimpleNamespace(status="pending", metadata_json={})

    class Database:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get(self, _model, identifier):
            assert identifier == "system-1"
            return row

        def commit(self):
            pass

    session.SessionLocal = Database
    for name, module in {
        "app": app, "app.core": core, "app.core.config": config,
        "app.db": db_package, "app.db.models": models,
        "app.db.models.ai_system": ai_system, "app.db.session": session,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)

    calls = []

    class FakeApi:
        def request(self, method, path, *, headers=None, payload=None):
            calls.append((method, path, payload))
            if path == "/auth/register":
                return 200, {"tenants": [{"id": "tenant-1"}], "access_token": "synthetic", "user": {"id": "owner-1"}}
            if path == "/ai-systems":
                return 200, {"id": "system-1"}
            if path == "/policies/packs":
                return 200, {"pack": {"id": "pack-1"}, "default_version": {"id": "default-1", "scope": {}, "enforcement_defaults": {"default_decision": "allow"}, "guardian_contracts": [{"id": "guardian-1"}]}}
            assert path == "/policies/packs/pack-1/versions"
            return 200, {"id": "scoped-2", "pack_id": "pack-1", **payload}

    _headers, system_id, version_id = llm._setup(FakeApi())
    assert (system_id, version_id) == ("system-1", "scoped-2")
    assert row.status == "active"
    assert row.metadata_json["governance_state"] == "APPROVED"
    version_payload = calls[-1][2]
    assert version_payload["scope"]["applies_to_ai_system_ids"] == ["system-1"]
    assert version_payload["scope"]["llm_gateway_security"]["provider_allowlist"] == ["llama"]
    assert version_payload["guardian_contracts"] == [{"id": "guardian-1"}]


def test_lab_request_uses_bounded_default_and_explicit_chat_timeout(monkeypatch):
    lab_module = load("isolated_hawk_lab")
    lab = object.__new__(lab_module.IsolatedHawkLab)
    lab.base_url = "http://127.0.0.1:54103"
    timeouts = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b"{}"

    def fake_urlopen(_request, *, timeout):
        timeouts.append(timeout)
        return Response()

    monkeypatch.setattr(lab_module.urllib.request, "urlopen", fake_urlopen)
    assert lab.request("GET", "/health") == (200, {})
    assert lab.request("POST", "/llm-gateway/chat/complete", payload={}, timeout_seconds=90) == (200, {})
    assert timeouts == [30, 90]
    for invalid in (True, False, None, "90", 0, 0.9, 121, float("nan"), float("inf")):
        with pytest.raises(ValueError, match="invalid_lab_request_timeout"):
            lab.request("GET", "/health", timeout_seconds=invalid)
    assert timeouts == [30, 90]


def test_llm_chat_client_timeout_is_sanitized_at_call_boundary():
    llm = load("run_isolated_llm_provider_acceptance")

    class TimedOutApi:
        def request(self, method, path, *, headers=None, payload=None, timeout_seconds=None):
            assert (method, path, timeout_seconds) == ("POST", "/llm-gateway/chat/complete", 90)
            raise socket.timeout("private prompt https://secret.example/token")

    with pytest.raises(RuntimeError) as failure:
        llm._call(TimedOutApi(), {"X-Tenant-ID": "synthetic"}, "system", "policy", "run", "private prompt")
    assert str(failure.value) == "gateway_chat_client_timeout"


def test_llm_lab_never_disables_configured_controls(monkeypatch):
    llm = load("run_isolated_llm_provider_acceptance")

    class GuardSettings:
        native_control_framework = True
        trusted_control_selector = True

        def __setattr__(self, name, value):
            if name in {"native_control_framework", "trusted_control_selector"} and value is False:
                raise AssertionError(f"control weakened: {name}")
            super().__setattr__(name, value)

    settings = GuardSettings()
    app = types.ModuleType("app")
    core = types.ModuleType("app.core")
    config = types.ModuleType("app.core.config")
    config.settings = settings
    monkeypatch.setitem(sys.modules, "app", app)
    monkeypatch.setitem(sys.modules, "app.core", core)
    monkeypatch.setitem(sys.modules, "app.core.config", config)
    monkeypatch.setattr(llm, "_model_digest", lambda: llm.EXPECTED_DIGEST)
    monkeypatch.setattr(llm, "_run_provider_adapter_preflight", lambda _digest: {"status": "provider_adapter_preflight_passed", "content_present": True})

    starts = []
    stops = []

    class FakeCapture:
        def __init__(self, *_args, **_kwargs):
            self.base_url = llm.LOCAL_PROVIDER_URL

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

    monkeypatch.setattr(llm, "OllamaCaptureProxy", FakeCapture)

    class IsolatedApi:
        def __init__(self, root, *, extra_env):
            self.root = root
            assert extra_env["OPENAI_BASE_URL"] == "http://127.0.0.1:11434/v1"

        def prepare(self):
            pass

        def start(self):
            starts.append(True)

        def stop(self):
            stops.append(True)

    monkeypatch.setattr(llm, "IsolatedHawkApi", IsolatedApi)
    monkeypatch.setattr(llm, "_setup", lambda api: (_ for _ in ()).throw(RuntimeError("stopped_after_control_check")))
    with pytest.raises(RuntimeError, match="stopped_after_control_check"):
        llm.main()
    assert settings.native_control_framework is True
    assert settings.trusted_control_selector is True
    assert starts == [True]
    assert stops == [True]

    config.settings = types.SimpleNamespace(native_control_framework=False, trusted_control_selector=True)
    with pytest.raises(RuntimeError, match="strict_control_prerequisites_unavailable"):
        llm.main()
    assert starts == [True]
    assert stops == [True, True]


def test_strict_lab_rejects_shared_ports_paths_and_urls(tmp_path):
    lab_module = load("isolated_hawk_lab")
    with tempfile.TemporaryDirectory(prefix="hawk-test-lab-", dir="/private/tmp") as name:
        root = Path(name)
        for port in (0, 3000, 3443, 8000, 55432, 6379, 11434):
            with pytest.raises(ValueError):
                lab_module.validate_port(port)
        with pytest.raises(ValueError):
            lab_module.validate_owned_path(root, tmp_path / "outside")
        with pytest.raises(ValueError):
            lab_module.validate_lab_urls("sqlite:///demo.db", "redis://:pw@127.0.0.1:54102/0", root, {"postgres": 54101, "redis": 54102, "api": 54103})
        with pytest.raises(ValueError):
            lab_module.validate_lab_urls("postgresql+psycopg2://u:pw@127.0.0.1:55432/hawk_lab", "redis://:pw@127.0.0.1:54102/0", root, {"postgres": 55432, "redis": 54102, "api": 54103})
        with pytest.raises(ValueError):
            lab_module.validate_lab_urls("postgresql+psycopg2://u:pw@127.0.0.1:54101/hawk_lab", "redis://127.0.0.1:54102/0", root, {"postgres": 54101, "redis": 54102, "api": 54103})
        os.chmod(root, 0o755)
        with pytest.raises(ValueError):
            lab_module.validate_root(root)


def test_strict_lab_preparation_isolated_env_and_restores_parent(monkeypatch):
    lab_module = load("isolated_hawk_lab")
    monkeypatch.setattr(lab_module, "assigned_loopback_port", lambda excluded: next(port for port in (54101, 54102, 54103) if port not in excluded))
    prior_cwd = Path.cwd()
    prior_env = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix="hawk-test-lab-", dir="/private/tmp") as name:
        monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg2://demo@127.0.0.1:55432/demo")
        monkeypatch.setenv("TEST_PROFILE", "unit")
        prior_env = dict(os.environ)
        lab = lab_module.IsolatedHawkLab(Path(name))
        try:
            lab.prepare()
            assert Path.cwd() == Path(name)
            assert "TEST_PROFILE" not in os.environ
            assert os.environ["CONTROL_PLANE_STRICT_DEPENDENCY_CHECKS"] == "true"
            assert os.environ["NATIVE_CONTROL_FRAMEWORK"] == "true"
            assert os.environ["TRUSTED_CONTROL_SELECTOR"] == "true"
            assert "COMPONENT_TYPE" not in os.environ
            assert ":55432/" not in os.environ["DATABASE_URL"]
            assert os.environ["DATABASE_URL"].endswith("/hawk_lab")
            assert os.environ["ARTIFACT_DIR"] == str(Path(name) / "artifacts")
            assert (Path(name) / "app" / "db" / "migrations").is_dir()
            assert not (Path(name) / ".env").exists()
            assert stat.S_IMODE((Path(name) / "postgres-password").stat().st_mode) == 0o600
            assert stat.S_IMODE((Path(name) / "redis.conf").stat().st_mode) == 0o600
        finally:
            lab.stop()
        assert Path.cwd() == prior_cwd
        assert dict(os.environ) == prior_env
        with pytest.raises(ValueError, match="extra_env_may_not_override"):
            blocked = lab_module.IsolatedHawkLab(Path(name), extra_env={"DATABASE_URL": "sqlite:///demo.db"})
            blocked.prepare()


def test_strict_readiness_requires_all_actual_components():
    lab_module = load("isolated_hawk_lab")
    report = {"strict_mode": True, "healthy": True, "required_checks": sorted(lab_module.REQUIRED_CHECKS), "checks": {name: {"ok": True, "status": "ok"} for name in lab_module.REQUIRED_CHECKS}}
    lab_module.validate_strict_report(report)
    for altered in [
        {**report, "strict_mode": False},
        {**report, "required_checks": ["database"]},
        {**report, "checks": {**report["checks"], "celery_worker_component": {"ok": True, "status": "skipped"}}},
        {**report, "checks": {**report["checks"], "migrations": {"ok": False, "status": "out_of_date"}}},
    ]:
        with pytest.raises(RuntimeError):
            lab_module.validate_strict_report(altered)
    with pytest.raises(RuntimeError, match="celery_worker_component_skipped"):
        lab_module.validate_strict_report({**report, "healthy": False, "checks": {**report["checks"], "celery_worker_component": {"ok": False, "status": "skipped"}}})


def test_private_redis_wait_retries_connection_refusal_then_succeeds_and_times_out_safely(monkeypatch):
    lab_module = load("isolated_hawk_lab")
    lab = object.__new__(lab_module.IsolatedHawkLab)
    lab.processes = {}
    attempts = []
    monkeypatch.setattr(lab_module.time, "sleep", lambda _seconds: None)

    def refused_once():
        attempts.append(True)
        if len(attempts) == 1:
            raise lab_module.RedisConnectionError("private credential must not appear")
        return True

    lab._wait(refused_once, "redis", seconds=2)
    assert len(attempts) == 2

    ticks = iter((0, 0, 1))
    monkeypatch.setattr(lab_module.time, "monotonic", lambda: next(ticks))
    with pytest.raises(RuntimeError) as failure:
        lab._wait(lambda: (_ for _ in ()).throw(lab_module.RedisConnectionError("private credential must not appear")), "redis", seconds=1)
    assert str(failure.value) == "lab_redis_timeout_redis_connection_unavailable"


def test_lab_launches_real_migration_worker_beat_api_and_cleans_partial_start(monkeypatch):
    lab_module = load("isolated_hawk_lab")
    monkeypatch.setattr(lab_module, "assigned_loopback_port", lambda excluded: next(port for port in (54101, 54102, 54103) if port not in excluded))
    with tempfile.TemporaryDirectory(prefix="hawk-test-lab-", dir="/private/tmp") as name:
        lab = lab_module.IsolatedHawkLab(Path(name))
        lab.prepare()
        calls = []
        monkeypatch.setattr(lab, "_run", lambda command, label, **kwargs: calls.append(("run", label, command)))
        monkeypatch.setattr(lab, "_spawn", lambda label, command, **kwargs: calls.append(("spawn", label, command, kwargs.get("component"))))
        monkeypatch.setattr(lab, "_wait", lambda predicate, label, **kwargs: calls.append(("wait", label)))
        try:
            lab.start()
            assert [entry[1] for entry in calls if entry[0] == "run"] == ["initdb", "postgres-start", "createdb", "migrations"]
            assert [entry[1:2] + (entry[3],) for entry in calls if entry[0] == "spawn"] == [("redis", None), ("worker", "worker"), ("beat", "celery_beat"), ("api", "api")]
            migration = next(entry[2] for entry in calls if entry[1] == "migrations")
            assert migration[-1].endswith("infra/scripts/run_migrations.py")
            assert all("create_all" not in " ".join(entry[2]) for entry in calls if entry[0] == "run")
            lab.restart_api()
            assert [entry[1] for entry in calls if entry[0] == "spawn"].count("api") == 2
        finally:
            lab.stop()

    with tempfile.TemporaryDirectory(prefix="hawk-test-lab-", dir="/private/tmp") as name:
        lab = lab_module.IsolatedHawkLab(Path(name))
        lab.prepare()
        stopped = []
        monkeypatch.setattr(lab, "_run", lambda command, label, **kwargs: (_ for _ in ()).throw(RuntimeError("migration_failed")) if label == "migrations" else None)
        monkeypatch.setattr(lab, "_spawn", lambda *args, **kwargs: None)
        monkeypatch.setattr(lab, "_wait", lambda *args, **kwargs: None)
        original_stop = lab.stop
        monkeypatch.setattr(lab, "stop", lambda: (stopped.append(True), original_stop()))
        with pytest.raises(RuntimeError, match="migration_failed"):
            lab.start()
        assert stopped == [True]


def test_active_lab_sigterm_cleans_owned_state_and_restores_prior_handler(monkeypatch):
    lab_module = load("isolated_hawk_lab")
    monkeypatch.setattr(lab_module, "assigned_loopback_port", lambda excluded: next(port for port in (54101, 54102, 54103) if port not in excluded))
    prior_handler = signal.getsignal(signal.SIGTERM)
    prior_cwd = Path.cwd()
    prior_env = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix="hawk-test-lab-", dir="/private/tmp") as name:
        lab = lab_module.IsolatedHawkLab(Path(name))
        lab.prepare()
        handler = signal.getsignal(signal.SIGTERM)
        assert handler != prior_handler
        with pytest.raises(SystemExit) as terminated:
            handler(signal.SIGTERM, None)
        assert terminated.value.code == 128 + signal.SIGTERM
        assert signal.getsignal(signal.SIGTERM) == prior_handler
        assert Path.cwd() == prior_cwd
        assert dict(os.environ) == prior_env


def test_partial_postgres_start_always_attempts_owned_stop_and_restores_state(monkeypatch):
    lab_module = load("isolated_hawk_lab")
    monkeypatch.setattr(lab_module, "assigned_loopback_port", lambda excluded: next(port for port in (54101, 54102, 54103) if port not in excluded))
    prior_handler = signal.getsignal(signal.SIGTERM)
    prior_cwd = Path.cwd()
    prior_env = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix="hawk-test-lab-", dir="/private/tmp") as name:
        lab = lab_module.IsolatedHawkLab(Path(name))
        lab.prepare()
        calls = []

        def fake_run(_command, label, **_kwargs):
            calls.append(label)
            if label == "postgres-start":
                (lab.root / "postgres-data" / "postmaster.pid").write_text("synthetic-owned-pid")
                raise RuntimeError("simulated_partial_start")

        monkeypatch.setattr(lab, "_run", fake_run)
        monkeypatch.setattr(lab, "_assert_port_closed", lambda label: calls.append(f"port:{label}"))
        with pytest.raises(RuntimeError, match="simulated_partial_start"):
            lab.start()
        assert calls == ["initdb", "postgres-start", "postgres-stop", "port:postgres"]
        assert signal.getsignal(signal.SIGTERM) == prior_handler
        assert Path.cwd() == prior_cwd
        assert dict(os.environ) == prior_env


def test_postgres_stop_failure_still_closes_logs_and_restores_process_state(monkeypatch):
    lab_module = load("isolated_hawk_lab")
    monkeypatch.setattr(lab_module, "assigned_loopback_port", lambda excluded: next(port for port in (54101, 54102, 54103) if port not in excluded))
    prior_handler = signal.getsignal(signal.SIGTERM)
    prior_cwd = Path.cwd()
    prior_env = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix="hawk-test-lab-", dir="/private/tmp") as name:
        lab = lab_module.IsolatedHawkLab(Path(name))
        lab.prepare()
        lab.postgres_start_attempted = True
        (lab.root / "postgres-data" / "postmaster.pid").write_text("synthetic-owned-pid")
        output = (lab.root / "logs" / "owned.log").open("wb")
        lab.logs.append(output)
        monkeypatch.setattr(lab, "_run", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("private_pg_stop_failed")))
        monkeypatch.setattr(lab, "_assert_port_closed", lambda _label: None)
        with pytest.raises(RuntimeError, match="lab_cleanup_failed_postgres"):
            lab.stop()
        assert output.closed
        assert signal.getsignal(signal.SIGTERM) == prior_handler
        assert Path.cwd() == prior_cwd
        assert dict(os.environ) == prior_env
