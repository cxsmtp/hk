from __future__ import annotations

import json
import os
import socket
import stat
import threading
from pathlib import Path

import pytest

from hawk_endpoint_agent.config import AgentConfig
from hawk_endpoint_agent.ipc import control_server
from hawk_endpoint_agent.ipc.control_server import ControlSocketServer


class _Dispatcher:
    def __init__(self) -> None:
        self.requests: list[dict] = []

    def evaluate_as_dict(self, request, *, adapter_path, pre_action):
        self.requests.append(dict(request))
        return {
            "action": "allow",
            "control_mode": "inline_allowed",
            "surface": request.get("surface"),
        }

    def scan_mcp_tool(self, request):
        return {
            "request_id": request["request_id"],
            "status": "completed",
            "scan_result_id": "scan-result-1",
            "tool_fingerprint_id": "fingerprint-1",
            "trust_status": "approved",
            "risk_factors": [],
            "evidence_bundle_id": "evidence-1",
            "tool_poisoning_decision": "allow",
            "idempotent_replay": False,
        }

    def governance_status(self, request):
        return {
            "schema_version": 1,
            "state": "governed",
            "label": "Governed",
            "connected": True,
            "client_app": request.get("client_app"),
            "evidence_ref": "evidence-1",
        }

    def register_agent(self, request):
        self.requests.append(dict(request))
        return {
            "status": "registered",
            "registration_id": "registration-1",
            "evidence_state": "sdk_self_registration",
            "control_state": "monitor_only",
            "active_integration_transport": request.get("active_integration_transport"),
            "evidence_ref": "evidence-registration-1",
        }


def _start(tmp_path: Path, *, max_bytes=1024, timeout=0.2, workers=4):
    config = AgentConfig(
        ipc_socket_path=str(tmp_path / "ipc" / "agent.sock"),
        security_profile="development",
    )
    config.ipc_max_request_bytes = max_bytes
    config.ipc_read_timeout_seconds = timeout
    config.ipc_max_workers = workers
    dispatcher = _Dispatcher()
    server = ControlSocketServer(config, dispatcher)
    server.start()
    return server, dispatcher


def _raw(path: Path, payload: bytes, *, timeout=1.0) -> dict:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    client.connect(str(path))
    if payload:
        client.sendall(payload)
    line = client.makefile("rb").readline()
    client.close()
    return json.loads(line.decode("utf-8"))


def _request(path: Path, payload: dict) -> dict:
    return _raw(path, (json.dumps(payload) + "\n").encode("utf-8"))


def test_decisions_require_versioned_evaluate_while_control_ops_remain_compatible(tmp_path):
    server, dispatcher = _start(tmp_path)
    try:
        assert _request(server.path, {"op": "ping"}) == {"ok": True, "pong": True}
        coverage = _request(server.path, {"op": "coverage"})
        assert coverage["ok"] is True

        missing = _request(server.path, {
            "request_id": "missing-version",
            "surface": "mcp",
            "action": "read",
        })
        assert missing == {
            "ok": False,
            "request_id": "missing-version",
            "error": "unsupported_protocol_version",
        }
        wrong_op = _request(server.path, {
            "protocol_version": 1,
            "request_id": "wrong-op",
            "op": "observe",
            "surface": "mcp",
        })
        assert wrong_op["error"] == "unsupported_operation"

        allowed = _request(server.path, {
            "protocol_version": 1,
            "request_id": "allowed-1",
            "op": "evaluate",
            "surface": "mcp",
            "action": "read",
        })
        assert allowed["ok"] is True
        assert allowed["request_id"] == "allowed-1"
        assert len(dispatcher.requests) == 1
    finally:
        server.stop()


def test_endpoint_identity_is_versioned_correlated_and_server_owned(tmp_path):
    config = AgentConfig(
        endpoint_id="endpoint-managed-1",
        user_id="user-managed-1",
        user_email="managed@example.com",
        ipc_socket_path=str(tmp_path / "ipc" / "agent.sock"),
        security_profile="development",
    )
    dispatcher = _Dispatcher()
    server = ControlSocketServer(config, dispatcher)
    server.start()
    try:
        response = _request(server.path, {
            "protocol_version": 1,
            "request_id": "identity-1",
            "op": "identity",
            "endpoint_id": "spoofed-endpoint",
            "user_id": "spoofed-user",
        })

        assert response["ok"] is True
        assert response["request_id"] == "identity-1"
        assert response["endpoint_id"] == "endpoint-managed-1"
        assert response["user_id"] == "user-managed-1"
        assert response["user_email"] == "managed@example.com"
        assert dispatcher.requests == []
    finally:
        server.stop()


def test_mcp_tool_scan_requires_request_correlation_and_returns_real_scan(tmp_path):
    server, _dispatcher = _start(tmp_path)
    try:
        missing = _request(server.path, {
            "protocol_version": 1,
            "op": "mcp_tool_scan",
            "mcp_server_id": "server-1",
            "tool_name": "read_record",
        })
        assert missing == {
            "ok": False,
            "request_id": "",
            "error": "invalid_request_id",
        }
        response = _request(server.path, {
            "protocol_version": 1,
            "request_id": "scan-request-1",
            "op": "mcp_tool_scan",
            "mcp_server_id": "server-1",
            "tool_name": "read_record",
            "tool_version": "1.0.0",
            "description": "Read one record",
            "schema": {"type": "object"},
            "examples": [],
            "manifest": {"name": "read_record"},
        })
        assert response["ok"] is True, response
        assert response["request_id"] == "scan-request-1"
        assert response["scan_result_id"] == "scan-result-1"
        assert response["tool_fingerprint_id"] == "fingerprint-1"
    finally:
        server.stop()


def test_governance_status_is_versioned_correlated_and_privacy_safe(tmp_path):
    server, _dispatcher = _start(tmp_path)
    try:
        invalid = _request(server.path, {
            "protocol_version": 1,
            "op": "governance_status",
            "client_app": "Claude Desktop",
        })
        assert invalid == {
            "ok": False,
            "request_id": "",
            "error": "invalid_request_id",
        }

        response = _request(server.path, {
            "protocol_version": 1,
            "request_id": "status-1",
            "op": "governance_status",
            "client_app": "Claude Desktop",
            "prompt": "must not be reflected",
        })
        assert response["ok"] is True
        assert response["request_id"] == "status-1"
        assert response["state"] == "governed"
        assert response["client_app"] == "Claude Desktop"
        assert "prompt" not in response
    finally:
        server.stop()


def test_agent_registration_is_correlated_secret_free_and_monitor_only(tmp_path):
    server, dispatcher = _start(tmp_path, max_bytes=4096)
    try:
        response = _request(server.path, {
            "protocol_version": 1,
            "request_id": "registration-request-1",
            "op": "register_agent",
            "agent_id": "agent-os-local",
            "agent_name": "Agent OS",
            "agent_version": "1.0.0",
            "runtime_provider": "node",
            "model_provider": "ollama",
            "model_name": "qwen3.5:9b",
            "models": ["qwen3.5:9b"],
            "detected_tools": ["web_search", "GMAIL_SEND_EMAIL"],
            "detected_actions": ["web.read", "email.send"],
            "detected_privileges": ["internet", "mailbox.write"],
            "listening_ports": [4000, 5174],
            "integration_transports": [
                {
                    "capability": "gmail",
                    "transport": "composio",
                    "destination_domain": "backend.composio.dev",
                    "active": True,
                    "evidence_basis": "runtime_configuration",
                },
                {
                    "capability": "gmail",
                    "transport": "google_direct",
                    "destination_domain": "gmail.googleapis.com",
                    "active": False,
                    "evidence_basis": "supported_binding",
                },
            ],
            "active_integration_transport": "composio",
            "control_binding": {
                "mode": "enforce",
                "pre_action_surfaces": ["llm", "developer_agent"],
            },
            "client_metadata": {
                "name": "agent-os",
                "version": "1.0.0",
                "runtime": "node",
                "runtime_version": "v24.1.0",
            },
            "process_metadata": {"pid": 123, "platform": "darwin", "architecture": "arm64"},
        })

        assert response["ok"] is True, response
        assert response["request_id"] == "registration-request-1"
        assert response["evidence_state"] == "sdk_self_registration"
        assert response["control_state"] == "monitor_only"
        assert dispatcher.requests[-1]["active_integration_transport"] == "composio"

        rejected = _request(server.path, {
            "protocol_version": 1,
            "request_id": "registration-secret-1",
            "op": "register_agent",
            "agent_id": "agent-os-local",
            "agent_name": "Agent OS",
            "token": "must-not-be-accepted",
        })
        assert rejected == {
            "ok": False,
            "request_id": "registration-secret-1",
            "error": "invalid_agent_registration",
        }
    finally:
        server.stop()


def test_strict_utf8_json_and_request_byte_limit(tmp_path):
    server, _dispatcher = _start(tmp_path, max_bytes=128)
    try:
        assert _raw(server.path, b"\xff\n")["error"] == "invalid_utf8"
        assert _raw(server.path, b'{"protocol_version":1,}\n')["error"] == "invalid_json"
        oversized = b'{"request_id":"' + (b"x" * 200) + b'"}\n'
        assert _raw(server.path, oversized)["error"] == "request_too_large"
    finally:
        server.stop()


def test_idle_connection_times_out_and_workers_are_bounded(tmp_path, monkeypatch):
    worker_occupied = threading.Event()
    begin_read = threading.Event()
    original_handle = control_server._Handler.handle

    def wait_before_read(handler):
        worker_occupied.set()
        assert begin_read.wait(2)
        original_handle(handler)

    monkeypatch.setattr(control_server._Handler, "handle", wait_before_read)
    server, _dispatcher = _start(tmp_path, timeout=0.15, workers=1)
    first = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    first.settimeout(1)
    second = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    second.settimeout(1)
    try:
        first.connect(str(server.path))
        assert worker_occupied.wait(1)
        second.connect(str(server.path))
        # Capacity rejection precedes request reading and closes the connection.
        # Do not race a write against that intentional server-side close.
        busy = json.loads(second.makefile("r").readline())
        assert busy == {"ok": False, "error": "server_busy"}
        begin_read.set()
        timed_out = json.loads(first.makefile("r").readline())
        assert timed_out == {"ok": False, "error": "read_timeout"}
    finally:
        begin_read.set()
        first.close()
        second.close()
        server.stop()


def test_socket_parent_and_socket_have_restricted_modes(tmp_path):
    server, _dispatcher = _start(tmp_path)
    try:
        assert stat.S_IMODE(server.path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(server.path.stat().st_mode) == 0o600
        assert stat.S_ISSOCK(server.path.stat().st_mode)
    finally:
        server.stop()


@pytest.mark.parametrize("stale_kind", ["file", "symlink"])
def test_server_rejects_non_socket_or_symlink_stale_path(tmp_path, stale_kind):
    socket_path = tmp_path / "ipc" / "agent.sock"
    socket_path.parent.mkdir(parents=True)
    target = tmp_path / "target"
    target.write_text("not a socket", encoding="utf-8")
    if stale_kind == "file":
        socket_path.write_text("not a socket", encoding="utf-8")
    else:
        os.symlink(target, socket_path)
    config = AgentConfig(
        ipc_socket_path=str(socket_path),
        security_profile="development",
    )
    with pytest.raises(OSError):
        ControlSocketServer(config, _Dispatcher()).start()
    assert os.path.lexists(socket_path)


def test_server_rejects_symlink_socket_parent(tmp_path):
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    os.symlink(real_parent, linked_parent)
    config = AgentConfig(
        ipc_socket_path=str(linked_parent / "agent.sock"),
        security_profile="development",
    )
    with pytest.raises(OSError):
        ControlSocketServer(config, _Dispatcher()).start()
