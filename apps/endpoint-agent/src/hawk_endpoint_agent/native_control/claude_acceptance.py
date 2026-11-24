from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shlex
import site
import socket
import socketserver
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from hawk_endpoint_agent.auth.kms_hsm import HELPER_PROTOCOL
from hawk_endpoint_agent.native_control.installer import NativeHookInstaller, claude_settings_path


_SEMANTIC_VERSION = re.compile(r"^\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?$")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))


@dataclass(frozen=True, slots=True)
class ClaudeBinaryAcceptanceReport:
    provider_version: str
    runtime_binding_version: str
    signed_allow: bool
    allowed_action_executed: bool
    allow_post_action_correlated: bool
    post_action_evidence_quality: str
    signed_block: bool
    blocked_action_executed: bool
    block_survived_mutator_first: bool
    block_survived_mutator_last: bool
    timeout_failed_closed: bool
    config_tamper_detected: bool
    uninstall_preserved_customer_hooks: bool
    safe_mode_user_hook_bypassed: bool
    bare_mode_hook_bypassed: bool
    exact_version_verified: bool
    default_mode_pretool_blocked: bool
    accept_edits_pretool_blocked: bool
    bypass_permissions_pretool_blocked: bool
    dangerous_skip_pretool_blocked: bool
    plan_mode_status: str
    permission_request_status: str
    permission_request_correlated: bool
    permission_context_recorded: bool
    provider_allow_could_not_override_block: bool
    approval_mutation_required_reauthorization: bool
    exact_parameter_binding: bool
    user_prompt_submit_observed: bool
    user_prompt_allow_reached_model: bool
    user_prompt_block_reached_model: bool
    user_prompt_blocked_before_model: bool
    mcp_read_allowed: bool
    mcp_read_post_action_correlated: bool
    mcp_write_blocked: bool
    mcp_write_marker_created: bool
    agent_allow_pretool_observed: bool
    agent_lineage_observed: bool
    agent_block_pretool_observed: bool
    blocked_agent_spawned: bool
    remote_control_status: str
    managed_safe_mode_status: str
    config_change_status: str
    approval_action_executed: bool
    file_read_post_action_correlated: bool
    file_write_post_action_correlated: bool
    post_failure_correlated: bool
    background_pretool_blocked: bool
    session_start_observed: bool
    session_end_observed: bool
    input_mutation_supported: bool
    measured_callback_sample_count: int
    measured_callback_p50_ms: float
    measured_callback_p95_ms: float
    measured_callback_p99_ms: float
    diagnostics: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return all(
            (
                bool(_SEMANTIC_VERSION.fullmatch(self.provider_version)),
                self.runtime_binding_version == self.provider_version,
                self.signed_allow,
                self.allowed_action_executed,
                self.allow_post_action_correlated,
                self.post_action_evidence_quality == "provider_reported",
                self.signed_block,
                not self.blocked_action_executed,
                self.block_survived_mutator_first,
                self.block_survived_mutator_last,
                self.timeout_failed_closed,
                self.config_tamper_detected,
                self.uninstall_preserved_customer_hooks,
                self.safe_mode_user_hook_bypassed,
                self.bare_mode_hook_bypassed,
                self.exact_version_verified,
                self.default_mode_pretool_blocked,
                self.accept_edits_pretool_blocked,
                self.bypass_permissions_pretool_blocked,
                self.dangerous_skip_pretool_blocked,
                self.plan_mode_status in {"pretool_blocked", "provider_blocked_before_hook"},
                self.permission_request_status == "observed_interactive",
                self.permission_request_correlated,
                self.permission_context_recorded,
                self.provider_allow_could_not_override_block,
                self.approval_mutation_required_reauthorization,
                self.exact_parameter_binding,
                self.user_prompt_submit_observed,
                self.user_prompt_allow_reached_model,
                not self.user_prompt_block_reached_model,
                self.user_prompt_blocked_before_model,
                self.mcp_read_allowed,
                self.mcp_read_post_action_correlated,
                self.mcp_write_blocked,
                not self.mcp_write_marker_created,
                self.agent_allow_pretool_observed,
                self.agent_lineage_observed,
                self.agent_block_pretool_observed,
                not self.blocked_agent_spawned,
                self.remote_control_status in {
                    "verified:local_runtime_callback",
                    "unverified:interactive_authenticated_session_required",
                    "unverified:not_supported_by_binary",
                },
                self.managed_safe_mode_status in {
                    "verified:managed_source_allow_block",
                    "unverified:managed_access_required",
                    "unverified:transaction_not_run",
                },
                self.config_change_status in {
                    "observed_secondary_signal",
                    "not_observed_experimental",
                },
                not self.approval_action_executed,
                self.file_read_post_action_correlated,
                self.file_write_post_action_correlated,
                self.post_failure_correlated,
                self.background_pretool_blocked,
                self.session_start_observed,
                self.session_end_observed,
                not self.input_mutation_supported,
                self.measured_callback_sample_count > 0,
                self.measured_callback_p95_ms < 4_000,
                not self.diagnostics,
            )
        )


class _SignerState:
    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.key_reference = "hsm://hawk-acceptance/claude-code"


class _SignerHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        state: _SignerState = self.server.state  # type: ignore[attr-defined]
        header = self._recv_exact(4)
        length = struct.unpack("!I", header)[0]
        request = json.loads(self._recv_exact(length))
        payload = base64.b64decode(request.get("payload_base64") or "", validate=True)
        verb = request.get("verb")
        response: dict[str, Any] = {
            "protocol": HELPER_PROTOCOL,
            "request_id": request.get("request_id"),
            "ok": True,
            "key_id": state.key_reference,
            "algorithm": "ES256",
        }
        if request.get("protocol") != HELPER_PROTOCOL or request.get("key_reference") != state.key_reference:
            response["ok"] = False
        elif verb == "sign":
            signature = state.key.sign(payload, ec.ECDSA(hashes.SHA256()))
            response["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
        elif verb == "public":
            response["public_key_pem"] = state.key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii")
            response["hardware_backed"] = True
        elif verb == "status":
            response.update({"available": True, "hardware_backed": True})
        else:
            response["ok"] = False
        encoded = _canonical(response)
        self.request.sendall(struct.pack("!I", len(encoded)) + encoded)

    def _recv_exact(self, length: int) -> bytes:
        result = bytearray()
        while len(result) < length:
            chunk = self.request.recv(length - len(result))
            if not chunk:
                raise ConnectionError("acceptance signer closed early")
            result.extend(chunk)
        return bytes(result)


class _SignerServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, socket_path: Path, state: _SignerState) -> None:
        self.state = state
        super().__init__(str(socket_path), _SignerHandler)
        os.chmod(socket_path, 0o600)


class _CallbackState:
    def __init__(self, signer: _SignerState) -> None:
        self.signer = signer
        self.decision = "allow"
        self.decision_events = frozenset({"before_tool", "permission_request"})
        self.delay_seconds = 0.0
        self.events: list[dict[str, Any]] = []
        self.latencies_ms: list[float] = []
        self.lock = threading.Lock()

    def reset(
        self,
        *,
        decision: str,
        decision_events: frozenset[str] = frozenset({"before_tool", "permission_request"}),
        delay_seconds: float = 0.0,
    ) -> None:
        with self.lock:
            self.decision = decision
            self.decision_events = decision_events
            self.delay_seconds = delay_seconds
            self.events.clear()


class _QuietHttpHandler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return


class _CallbackHandler(_QuietHttpHandler):
    def do_POST(self) -> None:
        state: _CallbackState = self.server.state  # type: ignore[attr-defined]
        try:
            length = int(self.headers.get("Content-Length") or "0")
            body = json.loads(self.rfile.read(length))
            envelope = json.loads(base64.b64decode(body["envelope_base64"], validate=True))
            payload_bytes = base64.b64decode(body["payload_base64"], validate=True)
            payload = json.loads(payload_bytes)
            signature = _b64url_decode(str(envelope.pop("signature")))
            state.signer.key.public_key().verify(
                signature,
                _canonical(envelope),
                ec.ECDSA(hashes.SHA256()),
            )
            if hashlib.sha256(payload_bytes).hexdigest() != envelope.get("payload_hash"):
                raise ValueError("payload hash mismatch")
            if envelope.get("provider") != "anthropic" or envelope.get("product") != "claude_code":
                raise ValueError("provider binding mismatch")
            issued_at = datetime.fromisoformat(str(envelope["issued_at"]))
            latency_ms = max(0.0, (datetime.now(timezone.utc) - issued_at).total_seconds() * 1000)
            event = {
                "signature_valid": True,
                "provider_event_type": envelope.get("provider_event_type"),
                "provider_event_id": envelope.get("provider_event_id"),
                "correlation_id": envelope.get("correlation_id"),
                "session_id": envelope.get("session_id"),
                "parameter_hash": payload.get("parameter_hash"),
                "response_hash": payload.get("response_hash"),
                "action_type": payload.get("action_type"),
                "tool_name": payload.get("tool_name"),
                "permission_mode": payload.get("permission_mode"),
                "run_in_background": payload.get("run_in_background"),
                "execution_status": payload.get("execution_status"),
                "evidence_quality": payload.get("evidence_quality"),
                "approval_action_hash": payload.get("approval_action_hash"),
                "target_resource_hash": payload.get("target_resource_hash"),
                "permission_context_present": payload.get("permission_context_present"),
                "permission_suggestions_hash": payload.get("permission_suggestions_hash"),
                "config_source": payload.get("config_source"),
                "config_file_path_hash": payload.get("config_file_path_hash"),
                "agent_id_hash": payload.get("agent_id_hash"),
                "agent_type": payload.get("agent_type"),
                "subagent_id_hash": payload.get("subagent_id_hash"),
                "parent_session_hash": payload.get("parent_session_hash"),
            }
            with state.lock:
                state.events.append(event)
                state.latencies_ms.append(latency_ms)
                delay = state.delay_seconds
                decision = state.decision
                decision_events = state.decision_events
            if delay:
                time.sleep(delay)
            decision_event = envelope.get("provider_event_type") in decision_events
            effective_decision = decision if decision_event else "allow"
            response = {
                "decision": effective_decision,
                "enforced": True,
                "reason": "Hawk Claude binary acceptance policy",
                "evidence_quality": "provider_reported",
            }
            encoded = _canonical(response)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        except Exception as exc:
            encoded = _canonical({"detail": type(exc).__name__})
            try:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
            except (BrokenPipeError, ConnectionResetError):
                return


class _CallbackServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, state: _CallbackState) -> None:
        self.state = state
        super().__init__(("127.0.0.1", 0), _CallbackHandler)


class _AnthropicState:
    def __init__(self) -> None:
        self.tool_name = "Bash"
        self.tool_input: dict[str, Any] = {
            "command": "/usr/bin/true",
            "description": "Hawk native adapter acceptance marker",
        }
        self.requests = 0
        self.case_requests = 0
        self.agent_mode = False
        self.lock = threading.Lock()


def _sse(events: list[dict[str, Any]]) -> bytes:
    chunks: list[str] = []
    for event in events:
        chunks.append(f"event: {event['type']}\ndata: {json.dumps(event, separators=(',', ':'))}\n\n")
    return "".join(chunks).encode("utf-8")


class _AnthropicHandler(_QuietHttpHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        state: _AnthropicState = self.server.state  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length") or "0")
        request = json.loads(self.rfile.read(length) or b"{}")
        with state.lock:
            state.requests += 1
            state.case_requests += 1
            case_request_number = state.case_requests
            tool_name = state.tool_name
            configured_tool_input = dict(state.tool_input)
            agent_mode = state.agent_mode
        messages = request.get("messages") if isinstance(request.get("messages"), list) else []
        has_tool_result = any(
            isinstance(block, dict) and block.get("type") == "tool_result"
            for message in messages
            if isinstance(message, dict)
            for block in (message.get("content") if isinstance(message.get("content"), list) else [])
        )
        model = str(request.get("model") or "claude-sonnet-4-5")
        if has_tool_result or (agent_mode and case_request_number > 1):
            events = [
                {
                    "type": "message_start",
                    "message": {
                        "id": "msg_hawk_final",
                        "type": "message",
                        "role": "assistant",
                        "model": model,
                        "content": [],
                        "stop_reason": None,
                        "stop_sequence": None,
                        "usage": {"input_tokens": 8, "output_tokens": 1},
                    },
                },
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""},
                },
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": "Acceptance action handled."},
                },
                {"type": "content_block_stop", "index": 0},
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                    "usage": {"output_tokens": 4},
                },
                {"type": "message_stop"},
            ]
        else:
            tool_input = json.dumps(configured_tool_input, separators=(",", ":"))
            events = [
                {
                    "type": "message_start",
                    "message": {
                        "id": "msg_hawk_tool",
                        "type": "message",
                        "role": "assistant",
                        "model": model,
                        "content": [],
                        "stop_reason": None,
                        "stop_sequence": None,
                        "usage": {"input_tokens": 8, "output_tokens": 1},
                    },
                },
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {
                        "type": "tool_use",
                        "id": "toolu_hawk_acceptance",
                        "name": tool_name,
                        "input": {},
                    },
                },
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "input_json_delta", "partial_json": tool_input},
                },
                {"type": "content_block_stop", "index": 0},
                {
                    "type": "message_delta",
                    "delta": {"stop_reason": "tool_use", "stop_sequence": None},
                    "usage": {"output_tokens": 12},
                },
                {"type": "message_stop"},
            ]
        encoded = _sse(events)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(encoded)


class _AnthropicServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, state: _AnthropicState) -> None:
        self.state = state
        super().__init__(("127.0.0.1", 0), _AnthropicHandler)


@dataclass(slots=True)
class _RunningServers:
    signer: _SignerServer
    callback: _CallbackServer
    anthropic: _AnthropicServer
    threads: tuple[threading.Thread, ...]

    def close(self) -> None:
        for server in (self.callback, self.anthropic, self.signer):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)


def _start_servers(root: Path) -> tuple[_RunningServers, _SignerState, _CallbackState, _AnthropicState]:
    signer_state = _SignerState()
    signer = _SignerServer(root / "hawk-kms.sock", signer_state)
    callback_state = _CallbackState(signer_state)
    callback = _CallbackServer(callback_state)
    anthropic_state = _AnthropicState()
    anthropic = _AnthropicServer(anthropic_state)
    servers = (signer, callback, anthropic)
    threads = tuple(threading.Thread(target=server.serve_forever, daemon=True) for server in servers)
    for thread in threads:
        thread.start()
    return _RunningServers(signer, callback, anthropic, threads), signer_state, callback_state, anthropic_state


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _run_case(
    *,
    claude_binary: Path,
    root: Path,
    installer: NativeHookInstaller,
    settings_path: Path,
    callback_state: _CallbackState,
    anthropic_state: _AnthropicState,
    anthropic_url: str,
    command: str = "/usr/bin/true",
    decision: str,
    tool_name: str = "Bash",
    tool_input: dict[str, Any] | None = None,
    prompt: str = "Use the configured acceptance tool exactly once.",
    permission_mode: str | None = None,
    grant_tool_permission: bool = True,
    dangerously_skip_permissions: bool = True,
    mutator_position: str | None = None,
    mutated_command: str | None = None,
    delay_seconds: float = 0.0,
    decision_events: frozenset[str] = frozenset({"before_tool", "permission_request"}),
    mcp_config: dict[str, Any] | None = None,
    agent_mode: bool = False,
    extra_args: tuple[str, ...] = (),
) -> tuple[subprocess.CompletedProcess[str], tuple[dict[str, Any], ...]]:
    callback_state.reset(
        decision=decision,
        decision_events=decision_events,
        delay_seconds=delay_seconds,
    )
    with anthropic_state.lock:
        anthropic_state.tool_name = tool_name
        anthropic_state.tool_input = dict(
            tool_input
            if tool_input is not None
            else {
                "command": command,
                "description": "Hawk native adapter acceptance marker",
            }
        )
        anthropic_state.case_requests = 0
        anthropic_state.agent_mode = agent_mode
    _write_json(settings_path, {})
    installer.install(settings_path)
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    if mutator_position:
        if not mutated_command:
            raise ValueError("mutated command required")
        script = (
            "import json,sys; p=json.load(sys.stdin); "
            f"print(json.dumps({{'hookSpecificOutput':{{'hookEventName':'PreToolUse','permissionDecision':'allow',"
            f"'updatedInput':{{'command':{mutated_command!r},'description':'mutated acceptance'}}}}}}))"
        )
        mutator = {
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": shlex.join((sys.executable, "-c", script)), "timeout": 5}],
        }
        rows = settings["hooks"]["PreToolUse"]
        if mutator_position == "first":
            rows.insert(0, mutator)
        else:
            rows.append(mutator)
        _write_json(settings_path, settings)
    home = root / "home"
    home.mkdir(exist_ok=True, mode=0o700)
    environment = {
        **os.environ,
        "HOME": str(home),
        "ANTHROPIC_API_KEY": "hawk-local-acceptance-key",
        "ANTHROPIC_BASE_URL": anthropic_url,
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1",
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
        "PYTHONPATH": os.pathsep.join(
            filter(
                None,
                (
                    str(Path(__file__).resolve().parents[2]),
                    str(site.getusersitepackages()),
                    os.environ.get("PYTHONPATH", ""),
                ),
            )
        ),
    }
    debug_path = root / f"claude-hooks-{decision}-{mutator_position or 'plain'}-{int(delay_seconds * 1000)}.log"
    claude_args = [
            str(claude_binary),
            *extra_args,
            "-p",
            prompt,
            "--output-format",
            "stream-json",
            "--include-hook-events",
            "--verbose",
            "--debug",
            "hooks",
            "--debug-file",
            str(debug_path),
            "--tools",
            tool_name,
            "--no-session-persistence",
            "--no-chrome",
            "--settings",
            str(settings_path),
            "--strict-mcp-config",
            "--mcp-config",
            json.dumps(mcp_config or {"mcpServers": {}}, separators=(",", ":")),
            "--model",
            "claude-sonnet-4-5",
    ]
    if grant_tool_permission:
        claude_args.extend(("--allowedTools", tool_name))
    if dangerously_skip_permissions:
        claude_args.append("--dangerously-skip-permissions")
    if permission_mode:
        claude_args.extend(("--permission-mode", permission_mode))
    result = subprocess.run(
        claude_args,
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=35,
        check=False,
    )
    with callback_state.lock:
        events = tuple(dict(event) for event in callback_state.events)
    if not events and debug_path.is_file():
        result = subprocess.CompletedProcess(
            result.args,
            result.returncode,
            stdout=result.stdout,
            stderr=result.stderr + "\nHAWK_DEBUG:\n" + debug_path.read_text(encoding="utf-8", errors="replace")[-4_000:],
        )
    return result, events


def _run_interactive_permission_case(
    *,
    claude_binary: Path,
    root: Path,
    installer: NativeHookInstaller,
    settings_path: Path,
    callback_state: _CallbackState,
    anthropic_state: _AnthropicState,
    anthropic_url: str,
    command: str,
    marker: Path,
) -> tuple[tuple[dict[str, Any], ...], str]:
    """Exercise PermissionRequest through Claude's real interactive PTY path.

    Claude intentionally suppresses PermissionRequest in print mode. A PTY is
    therefore part of the acceptance contract, not a test convenience. This
    case observes Claude's provider permission context after a Hawk ``warn``.
    Hawk approval gates are exercised separately at ``PreToolUse`` because
    Claude runs matching hooks in parallel and a provider permission allow is
    not an authoritative Hawk approval.
    """

    # This run observes Claude's provider permission context after a Hawk warn.
    # Hawk review/approval decisions are denied at PreToolUse and resolved by
    # Hawk's own approval engine before the action is retried.
    callback_state.reset(decision="warn")
    tool_input = {
        "command": command,
        "description": "Hawk interactive permission acceptance marker",
    }
    with anthropic_state.lock:
        anthropic_state.tool_name = "Bash"
        anthropic_state.tool_input = dict(tool_input)
        anthropic_state.case_requests = 0
        anthropic_state.agent_mode = False

    _write_json(settings_path, {})
    installer.install(settings_path)
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    _write_json(settings_path, settings)

    home = root / "interactive-home"
    home.mkdir(exist_ok=True, mode=0o700)
    _write_json(
        home / ".claude.json",
        {
            "hasCompletedOnboarding": True,
            "theme": "dark",
            "customApiKeyResponses": {
                "approved": ["local-acceptance-key"],
                "rejected": [],
            },
            "projects": {
                str(root.resolve()): {
                    "hasTrustDialogAccepted": True,
                    "hasCompletedProjectOnboarding": True,
                }
            },
        },
    )
    environment = {
        **os.environ,
        "HOME": str(home),
        "ANTHROPIC_API_KEY": "hawk-local-acceptance-key",
        "ANTHROPIC_BASE_URL": anthropic_url,
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1",
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
        "PYTHONPATH": os.pathsep.join(
            filter(
                None,
                (
                    str(Path(__file__).resolve().parents[2]),
                    str(site.getusersitepackages()),
                    os.environ.get("PYTHONPATH", ""),
                ),
            )
        ),
    }
    debug_path = root / f"claude-hooks-interactive-{marker.stem}.log"
    arguments = [
        str(claude_binary),
        "Use the configured acceptance tool exactly once.",
        "--permission-mode",
        "default",
        "--debug",
        "hooks",
        "--debug-file",
        str(debug_path),
        "--tools",
        "Bash",
        "--no-chrome",
        "--settings",
        str(settings_path),
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--model",
        "claude-sonnet-4-5",
    ]
    process: subprocess.Popen[bytes] | None = None
    transcript = bytearray()
    config_changed = False
    try:
        process = subprocess.Popen(
            ["/usr/bin/script", "-q", "/dev/null", *arguments],
            cwd=root,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        if process.stdin is None or process.stdout is None:
            raise RuntimeError("interactive Claude PTY streams unavailable")
        os.set_blocking(process.stdout.fileno(), False)
        deadline = time.monotonic() + 25.0
        permission_observed_at: float | None = None
        api_key_prompt_answered = False
        trust_prompt_answered = False
        api_key_prompt_seen_at: float | None = None
        trust_prompt_seen_at: float | None = None
        while time.monotonic() < deadline:
            try:
                chunk = os.read(process.stdout.fileno(), 65_536)
                if chunk:
                    transcript.extend(chunk)
            except (BlockingIOError, OSError):
                pass
            with callback_state.lock:
                observed = tuple(callback_state.events)
            event_types = {event.get("provider_event_type") for event in observed}
            if "session_start" in event_types and not config_changed:
                changed_settings = json.loads(settings_path.read_text(encoding="utf-8"))
                changed_settings["env"] = {"HAWK_ACCEPTANCE_CONFIG_CHANGE": marker.stem}
                _write_json(settings_path, changed_settings)
                config_changed = True
            if "permission_request" in event_types and permission_observed_at is None:
                permission_observed_at = time.monotonic()
            if permission_observed_at is not None and (
                "config_change" in event_types or time.monotonic() - permission_observed_at >= 2.0
            ):
                break
            visible = bytes(transcript)
            if b"Detected a custom API key" in visible and not api_key_prompt_answered:
                if api_key_prompt_seen_at is None:
                    api_key_prompt_seen_at = time.monotonic()
                elif time.monotonic() - api_key_prompt_seen_at >= 0.75:
                    try:
                        # Claude defaults this screen to "No". Move to "Yes"
                        # after Ink has mounted the selector, then confirm.
                        # Claude enables application cursor mode in its Ink
                        # selector, whose Up key is ESC O A rather than CSI A.
                        process.stdin.write(b"\x1bOA")
                        process.stdin.flush()
                        time.sleep(0.15)
                        process.stdin.write(b"\r")
                        process.stdin.flush()
                    except OSError:
                        pass
                    api_key_prompt_answered = True
            elif b"Quick safety check" in visible and not trust_prompt_answered:
                if trust_prompt_seen_at is None:
                    trust_prompt_seen_at = time.monotonic()
                elif time.monotonic() - trust_prompt_seen_at >= 0.75:
                    try:
                        process.stdin.write(b"\r")
                        process.stdin.flush()
                    except OSError:
                        pass
                    trust_prompt_answered = True
            if process.poll() is not None:
                break
            time.sleep(0.05)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        try:
            if process is not None and process.stdout is not None:
                while True:
                    chunk = os.read(process.stdout.fileno(), 65_536)
                    if not chunk:
                        break
                    transcript.extend(chunk)
        except (BlockingIOError, OSError):
            pass
        if process is not None:
            if process.stdin is not None:
                process.stdin.close()
            if process.stdout is not None:
                process.stdout.close()
    with callback_state.lock:
        events = tuple(dict(event) for event in callback_state.events)
    if not events and debug_path.is_file():
        transcript.extend(debug_path.read_bytes()[-4_000:])
    return events, transcript.decode("utf-8", errors="replace")


def _events_of_type(events: tuple[dict[str, Any], ...], event_type: str) -> list[dict[str, Any]]:
    return [event for event in events if event.get("provider_event_type") == event_type]


def _pre_post_correlated(
    events: tuple[dict[str, Any], ...],
    *,
    post_event_type: str = "after_tool",
) -> bool:
    before = _events_of_type(events, "before_tool")
    after = _events_of_type(events, post_event_type)
    return bool(
        before
        and after
        and before[0].get("correlation_id") == after[0].get("correlation_id")
        and before[0].get("parameter_hash") == after[0].get("parameter_hash")
    )


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return float("inf")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * percentile)))
    return ordered[index]


def _remote_control_acceptance_status(claude_binary: Path) -> str:
    try:
        result = subprocess.run(
            [str(claude_binary), "remote-control", "--help"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unverified:not_supported_by_binary"
    output = f"{result.stdout}\n{result.stderr}".lower()
    if result.returncode != 0 or "remote" not in output:
        return "unverified:not_supported_by_binary"
    # Verifying this mode requires an authenticated interactive controller to
    # attach while the exact local runtime emits signed callbacks. Merely
    # discovering the CLI subcommand is not coverage evidence.
    return "unverified:interactive_authenticated_session_required"


def _managed_safe_mode_acceptance_status() -> str:
    managed_path = claude_settings_path("managed", platform=sys.platform)
    if not managed_path.exists():
        return "unverified:managed_access_required"
    # An existing bank-managed file is never modified by the default suite.
    # The transactional administrator acceptance is a deployment operation.
    return "unverified:transaction_not_run"


def run_claude_binary_acceptance(claude_binary: Path | str) -> ClaudeBinaryAcceptanceReport:
    binary = Path(claude_binary).expanduser().resolve()
    version_result = subprocess.run(
        [str(binary), "--version"], capture_output=True, text=True, timeout=5, check=False
    )
    version = version_result.stdout.strip().split(" ", 1)[0] if version_result.returncode == 0 else "unknown"
    diagnostics: list[str] = []
    if not _SEMANTIC_VERSION.fullmatch(version):
        diagnostics.append("provider_version_unparseable")
    exact_version_verified = version == "2.1.183"
    if not exact_version_verified:
        diagnostics.append(f"provider_version_not_verified:{version}")
    with tempfile.TemporaryDirectory(prefix="hawk-claude-acceptance-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        servers, signer_state, callback_state, anthropic_state = _start_servers(root)
        del signer_state
        try:
            helper = root / "hawk-native-hook"
            helper.write_text(
                "#!/bin/sh\nexec "
                + shlex.quote(sys.executable)
                + " -c 'from hawk_endpoint_agent.native_control.hook import main; main()' \"$@\"\n",
                encoding="utf-8",
            )
            helper.chmod(0o700)
            runtime_config = root / "native-control.json"
            _write_json(
                runtime_config,
                {
                    "api_url": f"http://127.0.0.1:{servers.callback.server_port}",
                    "tenant_id": "hawk-acceptance-tenant",
                    "integration_id": "hawk-claude-acceptance",
                    "credential_id": "hawk-claude-acceptance-key",
                    "provider": "anthropic",
                    "product": "claude_code",
                    "provider_version": version,
                    "adapter_version": "1.2.0",
                    "credential_epoch": 1,
                    "environment": "acceptance",
                    "security_profile": "development",
                    "key_provider": "kms_hsm_helper",
                    "kms_hsm_helper_path": f"unix://{root / 'hawk-kms.sock'}",
                    "kms_hsm_key_reference": "hsm://hawk-acceptance/claude-code",
                },
            )
            settings = root / "settings.json"
            _write_json(settings, {})
            installer = NativeHookInstaller(
                provider="claude_code",
                helper_path=helper,
                runtime_config_path=runtime_config,
            )
            installed = installer.install(settings)
            baseline = json.loads(settings.read_text(encoding="utf-8"))
            tampered = json.loads(json.dumps(baseline))
            tampered["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] = 5000
            _write_json(settings, tampered)
            config_tamper_detected = not installer.validate_installation(
                settings, expected_fingerprint=installed.fingerprint
            )

            customer = {
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "/opt/customer/hook", "timeout": 30}],
            }
            _write_json(settings, {"theme": "dark", "hooks": {"PreToolUse": [customer]}})
            installer.install(settings)
            installer.uninstall(settings)
            uninstall_preserved = json.loads(settings.read_text(encoding="utf-8")) == {
                "theme": "dark",
                "hooks": {"PreToolUse": [customer]},
            }
            _write_json(settings, {})

            anthropic_url = f"http://127.0.0.1:{servers.anthropic.server_port}"
            allow_marker = root / "allowed.marker"
            allow_result, allow_events = _run_case(
                claude_binary=binary,
                root=root,
                installer=installer,
                settings_path=settings,
                callback_state=callback_state,
                anthropic_state=anthropic_state,
                anthropic_url=anthropic_url,
                command=f"/usr/bin/touch {shlex.quote(str(allow_marker))}",
                decision="allow",
            )
            if allow_result.returncode != 0:
                diagnostics.append(f"allow_cli_exit:{allow_result.returncode}:{allow_result.stderr[-400:]}")
            all_lifecycle_events: list[dict[str, Any]] = list(allow_events)
            allow_pre = _events_of_type(allow_events, "before_tool")
            allow_post = _events_of_type(allow_events, "after_tool")
            signed_allow = bool(allow_pre and all(event["signature_valid"] for event in allow_events))
            if not allow_events:
                diagnostics.append(f"allow_no_hook_events:{allow_result.stderr[-2000:]}")
            allow_correlated = _pre_post_correlated(allow_events)

            blocked_executions: list[bool] = []
            mutation_results: dict[str, bool] = {}
            signed_block = False
            for position in ("first", "last"):
                blocked_marker = root / f"blocked-{position}.marker"
                mutated_marker = root / f"mutated-{position}.marker"
                block_result, block_events = _run_case(
                    claude_binary=binary,
                    root=root,
                    installer=installer,
                    settings_path=settings,
                    callback_state=callback_state,
                    anthropic_state=anthropic_state,
                    anthropic_url=anthropic_url,
                    command=f"/usr/bin/touch {shlex.quote(str(blocked_marker))}",
                    decision="block",
                    mutator_position=position,
                    mutated_command=f"/usr/bin/touch {shlex.quote(str(mutated_marker))}",
                )
                all_lifecycle_events.extend(block_events)
                if block_result.returncode != 0:
                    diagnostics.append(f"block_{position}_cli_exit:{block_result.returncode}:{block_result.stderr[-400:]}")
                before = [event for event in block_events if event["provider_event_type"] == "before_tool"]
                signed_block = signed_block or bool(before and all(event["signature_valid"] for event in block_events))
                executed = blocked_marker.exists() or mutated_marker.exists()
                blocked_executions.append(executed)
                mutation_results[position] = not executed

            dangerous_skip_pretool_blocked = bool(
                signed_block and not any(blocked_executions)
            )

            def mode_block_result(
                label: str,
                *,
                permission_mode: str | None = None,
                grant_tool_permission: bool = True,
                dangerously_skip_permissions: bool = False,
            ) -> tuple[bool, tuple[dict[str, Any], ...], bool]:
                marker = root / f"mode-{label}.marker"
                _result, events = _run_case(
                    claude_binary=binary,
                    root=root,
                    installer=installer,
                    settings_path=settings,
                    callback_state=callback_state,
                    anthropic_state=anthropic_state,
                    anthropic_url=anthropic_url,
                    command=f"/usr/bin/touch {shlex.quote(str(marker))}",
                    decision="block",
                    permission_mode=permission_mode,
                    grant_tool_permission=grant_tool_permission,
                    dangerously_skip_permissions=dangerously_skip_permissions,
                )
                all_lifecycle_events.extend(events)
                saw_pretool = bool(_events_of_type(events, "before_tool"))
                return saw_pretool and not marker.exists(), events, marker.exists()

            default_mode_pretool_blocked, _default_events, _default_executed = mode_block_result(
                "default"
            )
            accept_edits_pretool_blocked, _accept_edits_events, _accept_edits_executed = mode_block_result(
                "accept-edits",
                permission_mode="acceptEdits",
            )
            bypass_permissions_pretool_blocked, _bypass_events, _bypass_executed = mode_block_result(
                "bypass-permissions",
                permission_mode="bypassPermissions",
            )
            plan_pretool_blocked, plan_events, plan_executed = mode_block_result(
                "plan",
                permission_mode="plan",
                grant_tool_permission=False,
            )
            plan_mode_status = (
                "pretool_blocked"
                if plan_pretool_blocked
                else "provider_blocked_before_hook"
                if not plan_executed and not _events_of_type(plan_events, "before_tool")
                else "uncontrolled_execution"
            )
            if plan_mode_status == "uncontrolled_execution":
                diagnostics.append("plan_mode_action_executed")

            # A Hawk approval decision is authoritative at PreToolUse.  It is
            # denied until the out-of-band Hawk approval engine authorizes a
            # retry; provider PermissionRequest hooks cannot grant it.
            approval_marker = root / "approval.marker"
            approval_command = f"/usr/bin/touch {shlex.quote(str(approval_marker))}"
            approval_gate_result, approval_gate_events = _run_case(
                claude_binary=binary,
                root=root,
                installer=installer,
                settings_path=settings,
                callback_state=callback_state,
                anthropic_state=anthropic_state,
                anthropic_url=anthropic_url,
                command=approval_command,
                decision="require_approval",
                permission_mode="default",
                grant_tool_permission=False,
                dangerously_skip_permissions=False,
            )
            all_lifecycle_events.extend(approval_gate_events)
            approval_gate_before = _events_of_type(approval_gate_events, "before_tool")
            if approval_gate_result.returncode != 0:
                diagnostics.append(
                    "approval_gate_cli_exit:"
                    + str(approval_gate_result.returncode)
                    + ":"
                    + approval_gate_result.stderr[-400:]
                )

            # PermissionRequest is a distinct provider-native context signal.
            # Use a harmless command under Hawk warn to force Claude's real
            # interactive permission flow without treating it as Hawk approval.
            permission_context_marker = root / "permission-context.marker"
            permission_context_command = "/usr/bin/true"
            approval_events, approval_transcript = _run_interactive_permission_case(
                claude_binary=binary,
                root=root,
                installer=installer,
                settings_path=settings,
                callback_state=callback_state,
                anthropic_state=anthropic_state,
                anthropic_url=anthropic_url,
                command=permission_context_command,
                marker=permission_context_marker,
            )
            all_lifecycle_events.extend(approval_events)
            approval_before = _events_of_type(approval_events, "before_tool")
            approval_permission = _events_of_type(approval_events, "permission_request")
            permission_request_status = (
                "observed_interactive" if approval_permission else "not_observed_interactive"
            )
            if not approval_permission:
                diagnostics.append(
                    "permission_request_not_observed_interactive:"
                    + approval_transcript[:2_000].replace("\n", " ")
                    + " ...TAIL... "
                    + approval_transcript[-1_000:].replace("\n", " ")
                )
            permission_request_correlated = bool(
                approval_before
                and approval_permission
                and approval_before[0].get("approval_action_hash")
                == approval_permission[0].get("approval_action_hash")
                and approval_before[0].get("session_id")
                == approval_permission[0].get("session_id")
            )
            permission_context_recorded = bool(
                approval_permission
                and approval_permission[0].get("permission_context_present") is True
                and approval_permission[0].get("permission_suggestions_hash") not in {None, "unknown"}
            )
            provider_allow_could_not_override_block = bool(
                approval_gate_before
                and not approval_marker.exists()
                and mutation_results.get("first", False)
                and mutation_results.get("last", False)
            )
            expected_parameter_hash = hashlib.sha256(
                _canonical(
                    {
                        "command": permission_context_command,
                        "description": "Hawk interactive permission acceptance marker",
                    }
                )
            ).hexdigest()
            exact_parameter_binding = bool(
                approval_before
                and approval_permission
                and approval_before[0].get("parameter_hash") == expected_parameter_hash
                and approval_permission[0].get("parameter_hash") == expected_parameter_hash
            )
            user_prompt_submit_observed = bool(_events_of_type(approval_events, "before_model"))
            with anthropic_state.lock:
                prompt_allow_requests_before = anthropic_state.requests
            _prompt_allow_result, prompt_allow_events = _run_case(
                claude_binary=binary,
                root=root,
                installer=installer,
                settings_path=settings,
                callback_state=callback_state,
                anthropic_state=anthropic_state,
                anthropic_url=anthropic_url,
                command="/usr/bin/true",
                decision="allow",
                decision_events=frozenset({"before_model"}),
                prompt="Synthetic prompt acceptance allow. Use the configured acceptance tool once.",
            )
            all_lifecycle_events.extend(prompt_allow_events)
            with anthropic_state.lock:
                prompt_allow_requests_after = anthropic_state.requests
            user_prompt_allow_reached_model = prompt_allow_requests_after > prompt_allow_requests_before

            with anthropic_state.lock:
                prompt_block_requests_before = anthropic_state.requests
            _prompt_block_result, prompt_block_events = _run_case(
                claude_binary=binary,
                root=root,
                installer=installer,
                settings_path=settings,
                callback_state=callback_state,
                anthropic_state=anthropic_state,
                anthropic_url=anthropic_url,
                command="/usr/bin/true",
                decision="block",
                decision_events=frozenset({"before_model"}),
                prompt="Synthetic prompt acceptance block. This must not reach the model.",
            )
            all_lifecycle_events.extend(prompt_block_events)
            with anthropic_state.lock:
                prompt_block_requests_after = anthropic_state.requests
            user_prompt_block_reached_model = prompt_block_requests_after > prompt_block_requests_before
            user_prompt_blocked_before_model = bool(
                _events_of_type(prompt_block_events, "before_model")
                and not user_prompt_block_reached_model
            )
            if not user_prompt_allow_reached_model:
                diagnostics.append("user_prompt_allow_did_not_reach_model")
            if not user_prompt_blocked_before_model:
                diagnostics.append("user_prompt_block_not_proven_before_model")

            def mcp_fixture_config(marker: Path, call_log: Path) -> dict[str, Any]:
                return {
                    "mcpServers": {
                        "hawk_fixture": {
                            "type": "stdio",
                            "command": sys.executable,
                            "args": [
                                "-m",
                                "hawk_endpoint_agent.native_control.claude_mcp_fixture",
                                "--marker",
                                str(marker),
                                "--call-log",
                                str(call_log),
                            ],
                        }
                    }
                }

            mcp_read_marker = root / "mcp-read-unexpected.marker"
            mcp_read_log = root / "mcp-read.calls"
            mcp_read_result, mcp_read_events = _run_case(
                claude_binary=binary,
                root=root,
                installer=installer,
                settings_path=settings,
                callback_state=callback_state,
                anthropic_state=anthropic_state,
                anthropic_url=anthropic_url,
                decision="allow",
                tool_name="mcp__hawk_fixture__read_fixture",
                tool_input={},
                prompt="Call the read_fixture tool on the hawk_fixture MCP server exactly once.",
                mcp_config=mcp_fixture_config(mcp_read_marker, mcp_read_log),
            )
            all_lifecycle_events.extend(mcp_read_events)
            mcp_read_calls = (
                mcp_read_log.read_text(encoding="utf-8").splitlines()
                if mcp_read_log.is_file()
                else []
            )
            mcp_read_post_action_correlated = _pre_post_correlated(mcp_read_events)
            mcp_read_allowed = bool(
                "read_fixture" in mcp_read_calls
                and _events_of_type(mcp_read_events, "before_tool")
                and mcp_read_post_action_correlated
                and not mcp_read_marker.exists()
            )
            if not mcp_read_allowed:
                diagnostics.append(
                    "mcp_read_not_proven:"
                    + str(mcp_read_result.returncode)
                    + ":"
                    + mcp_read_result.stderr[-800:].replace("\n", " ")
                )

            mcp_write_marker = root / "mcp-write.marker"
            mcp_write_log = root / "mcp-write.calls"
            mcp_write_result, mcp_write_events = _run_case(
                claude_binary=binary,
                root=root,
                installer=installer,
                settings_path=settings,
                callback_state=callback_state,
                anthropic_state=anthropic_state,
                anthropic_url=anthropic_url,
                decision="block",
                tool_name="mcp__hawk_fixture__write_marker",
                tool_input={"note": "synthetic blocked write"},
                prompt="Call the write_marker tool on the hawk_fixture MCP server exactly once.",
                mcp_config=mcp_fixture_config(mcp_write_marker, mcp_write_log),
            )
            all_lifecycle_events.extend(mcp_write_events)
            mcp_write_calls = (
                mcp_write_log.read_text(encoding="utf-8").splitlines()
                if mcp_write_log.is_file()
                else []
            )
            mcp_write_marker_created = mcp_write_marker.exists()
            mcp_write_blocked = bool(
                _events_of_type(mcp_write_events, "before_tool")
                and "write_marker" not in mcp_write_calls
                and not mcp_write_marker_created
            )
            if not mcp_write_blocked:
                diagnostics.append(
                    "mcp_write_not_blocked:"
                    + str(mcp_write_result.returncode)
                    + ":"
                    + mcp_write_result.stderr[-800:].replace("\n", " ")
                )

            agent_input = {
                "description": "Synthetic Hawk delegation acceptance",
                "prompt": "Return the exact text child-ok without using tools.",
                "subagent_type": "general-purpose",
            }
            agent_allow_result, agent_allow_events = _run_case(
                claude_binary=binary,
                root=root,
                installer=installer,
                settings_path=settings,
                callback_state=callback_state,
                anthropic_state=anthropic_state,
                anthropic_url=anthropic_url,
                decision="allow",
                tool_name="Agent",
                tool_input=agent_input,
                prompt="Delegate this synthetic task to the configured Agent tool exactly once.",
                agent_mode=True,
            )
            all_lifecycle_events.extend(agent_allow_events)
            agent_allow_before = [
                event
                for event in _events_of_type(agent_allow_events, "before_tool")
                if event.get("tool_name") == "Agent"
            ]
            agent_starts = _events_of_type(agent_allow_events, "subagent_context_start")
            agent_stops = _events_of_type(agent_allow_events, "subagent_context_stop")
            agent_allow_pretool_observed = bool(agent_allow_before)
            agent_lineage_observed = bool(
                agent_starts
                and agent_stops
                and agent_starts[0].get("agent_id_hash") not in {None, "unknown"}
                and agent_starts[0].get("agent_id_hash") == agent_stops[0].get("agent_id_hash")
            )
            if not agent_allow_pretool_observed or not agent_lineage_observed:
                diagnostics.append(
                    "agent_allow_lineage_not_proven:"
                    + str(agent_allow_result.returncode)
                    + ":"
                    + agent_allow_result.stderr[-1_000:].replace("\n", " ")
                )

            agent_block_result, agent_block_events = _run_case(
                claude_binary=binary,
                root=root,
                installer=installer,
                settings_path=settings,
                callback_state=callback_state,
                anthropic_state=anthropic_state,
                anthropic_url=anthropic_url,
                decision="block",
                tool_name="Agent",
                tool_input=agent_input,
                prompt="Delegate this blocked synthetic task to the configured Agent tool exactly once.",
                agent_mode=True,
            )
            all_lifecycle_events.extend(agent_block_events)
            agent_block_pretool_observed = bool(
                event
                for event in _events_of_type(agent_block_events, "before_tool")
                if event.get("tool_name") == "Agent"
            )
            blocked_agent_spawned = bool(
                _events_of_type(agent_block_events, "subagent_context_start")
            )
            if not agent_block_pretool_observed or blocked_agent_spawned:
                diagnostics.append(
                    "agent_block_nonspawn_not_proven:"
                    + str(agent_block_result.returncode)
                    + ":"
                    + agent_block_result.stderr[-1_000:].replace("\n", " ")
                )
            config_change_status = (
                "observed_secondary_signal"
                if _events_of_type(approval_events, "config_change")
                else "not_observed_experimental"
            )

            changed_approval_marker = root / "permission-context-changed.marker"
            changed_approval_events, _changed_transcript = _run_interactive_permission_case(
                claude_binary=binary,
                root=root,
                installer=installer,
                settings_path=settings,
                callback_state=callback_state,
                anthropic_state=anthropic_state,
                anthropic_url=anthropic_url,
                command="/usr/bin/false",
                marker=changed_approval_marker,
            )
            all_lifecycle_events.extend(changed_approval_events)
            changed_permission = _events_of_type(changed_approval_events, "permission_request")
            approval_mutation_required_reauthorization = bool(
                approval_permission
                and changed_permission
                and approval_permission[0].get("approval_action_hash")
                != changed_permission[0].get("approval_action_hash")
            )

            read_target = root / "read-target.txt"
            read_target.write_text("safe acceptance content\n", encoding="utf-8")
            read_result, read_events = _run_case(
                claude_binary=binary,
                root=root,
                installer=installer,
                settings_path=settings,
                callback_state=callback_state,
                anthropic_state=anthropic_state,
                anthropic_url=anthropic_url,
                decision="allow",
                tool_name="Read",
                tool_input={"file_path": str(read_target)},
            )
            all_lifecycle_events.extend(read_events)
            if read_result.returncode != 0:
                diagnostics.append(f"read_cli_exit:{read_result.returncode}:{read_result.stderr[-400:]}")
            file_read_correlated = _pre_post_correlated(read_events)

            write_target = root / "write-target.txt"
            write_result, write_events = _run_case(
                claude_binary=binary,
                root=root,
                installer=installer,
                settings_path=settings,
                callback_state=callback_state,
                anthropic_state=anthropic_state,
                anthropic_url=anthropic_url,
                decision="allow",
                tool_name="Write",
                tool_input={"file_path": str(write_target), "content": "safe acceptance write\n"},
            )
            all_lifecycle_events.extend(write_events)
            if write_result.returncode != 0:
                diagnostics.append(f"write_cli_exit:{write_result.returncode}:{write_result.stderr[-400:]}")
            file_write_correlated = write_target.is_file() and _pre_post_correlated(write_events)

            failure_result, failure_events = _run_case(
                claude_binary=binary,
                root=root,
                installer=installer,
                settings_path=settings,
                callback_state=callback_state,
                anthropic_state=anthropic_state,
                anthropic_url=anthropic_url,
                command="/usr/bin/false",
                decision="allow",
            )
            all_lifecycle_events.extend(failure_events)
            if failure_result.returncode not in {0, 1}:
                diagnostics.append(
                    f"failure_cli_exit:{failure_result.returncode}:{failure_result.stderr[-400:]}"
                )
            post_failure_correlated = _pre_post_correlated(
                failure_events,
                post_event_type="after_tool_failure",
            )

            background_marker = root / "background.marker"
            _background_result, background_events = _run_case(
                claude_binary=binary,
                root=root,
                installer=installer,
                settings_path=settings,
                callback_state=callback_state,
                anthropic_state=anthropic_state,
                anthropic_url=anthropic_url,
                decision="block",
                tool_input={
                    "command": f"/usr/bin/touch {shlex.quote(str(background_marker))}",
                    "description": "Hawk background acceptance marker",
                    "run_in_background": True,
                },
            )
            all_lifecycle_events.extend(background_events)
            background_pretool_blocked = bool(
                any(event.get("run_in_background") is True for event in _events_of_type(background_events, "before_tool"))
                and not background_marker.exists()
            )

            timeout_marker = root / "timeout.marker"
            timeout_result, timeout_events = _run_case(
                claude_binary=binary,
                root=root,
                installer=installer,
                settings_path=settings,
                callback_state=callback_state,
                anthropic_state=anthropic_state,
                anthropic_url=anthropic_url,
                command=f"/usr/bin/touch {shlex.quote(str(timeout_marker))}",
                decision="allow",
                delay_seconds=4.2,
            )
            all_lifecycle_events.extend(timeout_events)
            if timeout_result.returncode != 0:
                diagnostics.append(f"timeout_cli_exit:{timeout_result.returncode}:{timeout_result.stderr[-400:]}")
            timeout_failed_closed = bool(timeout_events) and not timeout_marker.exists()

            safe_marker = root / "safe-mode-user-hook-bypass.marker"
            _safe_result, safe_events = _run_case(
                claude_binary=binary,
                root=root,
                installer=installer,
                settings_path=settings,
                callback_state=callback_state,
                anthropic_state=anthropic_state,
                anthropic_url=anthropic_url,
                command=f"/usr/bin/touch {shlex.quote(str(safe_marker))}",
                decision="block",
                extra_args=("--safe-mode",),
            )
            all_lifecycle_events.extend(safe_events)
            safe_mode_user_hook_bypassed = not safe_events and safe_marker.exists()

            bare_marker = root / "bare-mode-hook-bypass.marker"
            _bare_result, bare_events = _run_case(
                claude_binary=binary,
                root=root,
                installer=installer,
                settings_path=settings,
                callback_state=callback_state,
                anthropic_state=anthropic_state,
                anthropic_url=anthropic_url,
                command=f"/usr/bin/touch {shlex.quote(str(bare_marker))}",
                decision="block",
                extra_args=("--bare",),
            )
            all_lifecycle_events.extend(bare_events)
            bare_mode_hook_bypassed = not bare_events and bare_marker.exists()
            remote_control_status = _remote_control_acceptance_status(binary)
            managed_safe_mode_status = _managed_safe_mode_acceptance_status()
            latencies = list(callback_state.latencies_ms)
            if latencies:
                p50 = _percentile(latencies, 0.50)
                p95 = _percentile(latencies, 0.95)
                p99 = _percentile(latencies, 0.99)
            else:
                p50 = float("inf")
                p95 = float("inf")
                p99 = float("inf")
                diagnostics.append("no_signed_callbacks_observed")
            session_start_observed = bool(
                event
                for event in all_lifecycle_events
                if event.get("provider_event_type") == "session_start"
            )
            session_end_observed = bool(
                event
                for event in all_lifecycle_events
                if event.get("provider_event_type") == "session_end"
            )
            return ClaudeBinaryAcceptanceReport(
                provider_version=version,
                runtime_binding_version=version,
                signed_allow=signed_allow,
                allowed_action_executed=allow_marker.exists(),
                allow_post_action_correlated=allow_correlated,
                post_action_evidence_quality="provider_reported" if allow_post else "none",
                signed_block=signed_block,
                blocked_action_executed=any(blocked_executions),
                block_survived_mutator_first=mutation_results.get("first", False),
                block_survived_mutator_last=mutation_results.get("last", False),
                timeout_failed_closed=timeout_failed_closed,
                config_tamper_detected=config_tamper_detected,
                uninstall_preserved_customer_hooks=uninstall_preserved,
                safe_mode_user_hook_bypassed=safe_mode_user_hook_bypassed,
                bare_mode_hook_bypassed=bare_mode_hook_bypassed,
                exact_version_verified=exact_version_verified,
                default_mode_pretool_blocked=default_mode_pretool_blocked,
                accept_edits_pretool_blocked=accept_edits_pretool_blocked,
                bypass_permissions_pretool_blocked=bypass_permissions_pretool_blocked,
                dangerous_skip_pretool_blocked=dangerous_skip_pretool_blocked,
                plan_mode_status=plan_mode_status,
                permission_request_status=permission_request_status,
                permission_request_correlated=permission_request_correlated,
                permission_context_recorded=permission_context_recorded,
                provider_allow_could_not_override_block=provider_allow_could_not_override_block,
                approval_mutation_required_reauthorization=approval_mutation_required_reauthorization,
                exact_parameter_binding=exact_parameter_binding,
                user_prompt_submit_observed=user_prompt_submit_observed,
                user_prompt_allow_reached_model=user_prompt_allow_reached_model,
                user_prompt_block_reached_model=user_prompt_block_reached_model,
                user_prompt_blocked_before_model=user_prompt_blocked_before_model,
                mcp_read_allowed=mcp_read_allowed,
                mcp_read_post_action_correlated=mcp_read_post_action_correlated,
                mcp_write_blocked=mcp_write_blocked,
                mcp_write_marker_created=mcp_write_marker_created,
                agent_allow_pretool_observed=agent_allow_pretool_observed,
                agent_lineage_observed=agent_lineage_observed,
                agent_block_pretool_observed=agent_block_pretool_observed,
                blocked_agent_spawned=blocked_agent_spawned,
                remote_control_status=remote_control_status,
                managed_safe_mode_status=managed_safe_mode_status,
                config_change_status=config_change_status,
                approval_action_executed=approval_marker.exists(),
                file_read_post_action_correlated=file_read_correlated,
                file_write_post_action_correlated=file_write_correlated,
                post_failure_correlated=post_failure_correlated,
                background_pretool_blocked=background_pretool_blocked,
                session_start_observed=session_start_observed,
                session_end_observed=session_end_observed,
                input_mutation_supported=False,
                measured_callback_sample_count=len(latencies),
                measured_callback_p50_ms=round(p50, 3),
                measured_callback_p95_ms=round(p95, 3),
                measured_callback_p99_ms=round(p99, 3),
                diagnostics=tuple(diagnostics),
            )
        finally:
            servers.close()
