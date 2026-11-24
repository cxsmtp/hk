"""Local control socket.

A loopback-only unix-domain socket (mode 0600, so only the enrolled user can
connect) speaking line-delimited JSON. On-device integrations — a browser bridge,
a native hook, or an SDK embedded in an AI app — send a request describing an action
and receive the agent's decision. This is how the agent provides inline control to
local software without each one calling the Hawk backend directly.

Protocol (one JSON object per line, response is one JSON object + newline):
  {"op": "ping"}                                  -> {"ok": true, "pong": true}
  {"op": "coverage"}                              -> {"ok": true, "coverage": [...]}
  {"protocol_version": 1, "op": "identity",
   "request_id": "..."}                          -> signed enrolled identity
  {"protocol_version": 1, "op": "evaluate", ...}  -> {"ok": true, "action": ...}
  {"protocol_version": 1, "op": "mcp_tool_scan",
   "request_id": "...", ...}                       -> persistent backend scan
  {"protocol_version": 1, "op": "governance_status",
   "request_id": "...", "client_app": "Codex"}  -> signed current status
"""

from __future__ import annotations

import json
import os
import socket
import socketserver
import stat
import threading
from pathlib import Path

from ..agent_registration import AgentRegistrationError, normalize_agent_registration
from ..dispatcher import Dispatcher
from ..surfaces import Surface, coverage_manifest


_IPC_ADAPTERS = {
    Surface.BROWSER: "browser",
    Surface.MCP: "mcp",
    Surface.LLM: "llm",
    Surface.SDK: "sdk",
    Surface.DEVELOPER_AGENT: "developer_agent",
    Surface.AI_AGENT: "developer_agent",
    Surface.FOUNDRY: "foundry",
    Surface.DATA_TRANSFER: "data_transfer",
}

_MAX_REQUEST_ID_CHARS = 128
_PROTOCOL_VERSION = 1
_DEFAULT_MAX_REQUEST_BYTES = 256 * 1024
_DEFAULT_READ_TIMEOUT_SECONDS = 2.0
_DEFAULT_MAX_WORKERS = 16


def _adapter_path_for(request: dict) -> str:
    """Map a versioned IPC action surface to its managed endpoint adapter."""
    return _IPC_ADAPTERS.get(str(request.get("surface") or "").lower(), "local_ipc")


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.connection.settimeout(self.server.read_timeout_seconds)  # type: ignore[attr-defined]
        while True:
            try:
                raw = self.rfile.readline(self.server.max_request_bytes + 1)  # type: ignore[attr-defined]
            except (socket.timeout, TimeoutError, OSError):
                self._send({"ok": False, "error": "read_timeout"})
                return
            if not raw:
                return
            if len(raw) > self.server.max_request_bytes:  # type: ignore[attr-defined]
                self._send({"ok": False, "error": "request_too_large"})
                return
            if not raw.endswith(b"\n"):
                self._send({"ok": False, "error": "invalid_frame"})
                return
            try:
                line = raw.decode("utf-8", errors="strict").strip()
            except UnicodeDecodeError:
                self._send({"ok": False, "error": "invalid_utf8"})
                return
            if not line:
                continue
            try:
                request = json.loads(line)
            except json.JSONDecodeError:
                self._send({"ok": False, "error": "invalid_json"})
                continue
            if not isinstance(request, dict):
                self._send({"ok": False, "error": "expected_object"})
                continue

            op = request.get("op")
            if op == "ping":
                self._send({"ok": True, "pong": True})
                continue
            if op == "coverage":
                self._send({"ok": True, "coverage": coverage_manifest()})
                continue
            request_id = _bounded_request_id(request)
            if request.get("protocol_version") != _PROTOCOL_VERSION:
                self._send({
                    "ok": False,
                    "request_id": request_id,
                    "error": "unsupported_protocol_version",
                })
                continue
            if op == "identity":
                if not _valid_request_id(request):
                    self._send({
                        "ok": False,
                        "request_id": request_id,
                        "error": "invalid_request_id",
                    })
                    continue
                identity = self.server.endpoint_identity  # type: ignore[attr-defined]
                self._send({
                    "ok": True,
                    "request_id": request_id,
                    **identity,
                })
                continue
            if op == "mcp_tool_scan":
                if not _valid_request_id(request):
                    self._send({
                        "ok": False,
                        "request_id": request_id,
                        "error": "invalid_request_id",
                    })
                    continue
                try:
                    scan = self.server.dispatcher.scan_mcp_tool(request)  # type: ignore[attr-defined]
                    if (
                        not isinstance(scan, dict)
                        or scan.get("request_id") != request_id
                    ):
                        raise ValueError("uncorrelated MCP tool scan")
                    response = dict(scan)
                    response["ok"] = True
                    response["request_id"] = request_id
                    self._send(response)
                except Exception:  # noqa: BLE001 - scan internals are not exposed
                    self._send({
                        "ok": False,
                        "request_id": request_id,
                        "error": "mcp_tool_scan_failed",
                    })
                continue
            if op == "governance_status":
                if not _valid_request_id(request):
                    self._send({
                        "ok": False,
                        "request_id": request_id,
                        "error": "invalid_request_id",
                    })
                    continue
                try:
                    status = self.server.dispatcher.governance_status(request)  # type: ignore[attr-defined]
                    if not isinstance(status, dict):
                        raise ValueError("invalid governance status")
                    self._send({"ok": True, "request_id": request_id, **status})
                except Exception:  # noqa: BLE001 - status internals are not exposed
                    self._send({
                        "ok": False,
                        "request_id": request_id,
                        "error": "governance_status_failed",
                    })
                continue
            if op == "register_agent":
                if not _valid_request_id(request):
                    self._send({
                        "ok": False,
                        "request_id": request_id,
                        "error": "invalid_request_id",
                    })
                    continue
                try:
                    registration = normalize_agent_registration(request)
                    result = self.server.dispatcher.register_agent(registration)  # type: ignore[attr-defined]
                    if not isinstance(result, dict):
                        raise ValueError("invalid agent registration response")
                    self._send({"ok": True, "request_id": request_id, **result})
                except AgentRegistrationError:
                    self._send({
                        "ok": False,
                        "request_id": request_id,
                        "error": "invalid_agent_registration",
                    })
                except Exception:  # noqa: BLE001 - registration internals are not exposed
                    self._send({
                        "ok": False,
                        "request_id": request_id,
                        "error": "agent_registration_failed",
                    })
                continue
            if op == "native_hook":
                if not _valid_request_id(request):
                    self._send({"ok": False, "request_id": request_id, "error": "invalid_request_id"})
                    continue
                try:
                    from ..native_control.endpoint_broker import evaluate_native_hook
                    decision = evaluate_native_hook(self.server.agent_config, request)
                    self._send({"ok": True, "request_id": request_id, "decision": decision})
                except Exception:
                    self._send({"ok": False, "request_id": request_id, "error": "native_hook_failed"})
                continue
            if op != "evaluate":
                self._send({
                    "ok": False,
                    "request_id": request_id,
                    "error": "unsupported_operation",
                })
                continue
            try:
                result = self.server.dispatcher.evaluate_as_dict(  # type: ignore[attr-defined]
                    request,
                    adapter_path=_adapter_path_for(request),
                    pre_action=True,
                )
                self._send({"ok": True, "request_id": request_id, **result})
            except Exception as exc:  # noqa: BLE001 - never crash the socket on one request
                self._send({"ok": False, "request_id": request_id, "error": str(exc)})

    def _send(self, obj: dict) -> None:
        authenticator = getattr(self.server, "response_authenticator", None)  # type: ignore[attr-defined]
        if authenticator is not None:
            try:
                obj = authenticator.sign_response(obj)
            except Exception:  # noqa: BLE001 - unsigned decisions must fail closed at clients
                obj = {"ok": False, "error": "broker_auth_unavailable"}
        self.wfile.write((json.dumps(obj) + "\n").encode("utf-8"))


def _bounded_request_id(request: dict) -> str:
    value = request.get("request_id")
    return value[:_MAX_REQUEST_ID_CHARS] if isinstance(value, str) else ""


def _valid_request_id(request: dict) -> bool:
    value = request.get("request_id")
    return isinstance(value, str) and 0 < len(value) <= _MAX_REQUEST_ID_CHARS


class _ThreadingUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, *, max_workers, max_request_bytes, read_timeout_seconds):
        self.max_request_bytes = max_request_bytes
        self.read_timeout_seconds = read_timeout_seconds
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self._worker_slots.acquire(blocking=False):
            try:
                request.sendall(b'{"ok":false,"error":"server_busy"}\n')
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()


class ControlSocketServer:
    def __init__(self, config, dispatcher: Dispatcher) -> None:
        self._config = config
        self._dispatcher = dispatcher
        self._path = Path(config.ipc_socket_path).expanduser()
        self._server: _ThreadingUnixServer | None = None
        self._thread: threading.Thread | None = None
        self._socket_identity: tuple[int, int] | None = None

    @property
    def path(self) -> Path:
        return self._path

    def start(self) -> Path:
        parent = self._path.parent
        if parent.is_symlink():
            raise OSError("endpoint socket parent must not be a symlink")
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if parent.is_symlink() or not parent.is_dir():
            raise OSError("endpoint socket parent is invalid")
        parent_stat = parent.stat()
        if hasattr(os, "getuid") and parent_stat.st_uid != os.getuid():
            raise OSError("endpoint socket parent owner is invalid")
        os.chmod(parent, 0o700)

        try:
            stale = os.lstat(self._path)
        except FileNotFoundError:
            stale = None
        if stale is not None:
            if stat.S_ISLNK(stale.st_mode) or not stat.S_ISSOCK(stale.st_mode):
                raise OSError("endpoint socket path is not a stale socket")
            self._path.unlink()
        try:
            authenticator = self._dispatcher.client.local_broker_authenticator()
        except Exception:  # noqa: BLE001 - client verification will reject unsigned output
            authenticator = None
        expected_thumbprint = str(
            getattr(self._config, "ipc_trusted_device_thumbprint", "") or ""
        ).strip().lower()
        if expected_thumbprint:
            actual_thumbprint = str(
                getattr(getattr(authenticator, "identity", None), "key_thumbprint", "")
                or ""
            ).strip().lower()
            if actual_thumbprint != expected_thumbprint:
                raise OSError("endpoint local broker identity does not match its managed pin")
        elif str(getattr(self._config, "security_profile", "bank")) == "bank":
            raise OSError("bank endpoint IPC requires a managed device-key pin")

        server = _ThreadingUnixServer(
            str(self._path),
            _Handler,
            max_workers=_positive_int(self._config.ipc_max_workers, _DEFAULT_MAX_WORKERS),
            max_request_bytes=_positive_int(
                self._config.ipc_max_request_bytes,
                _DEFAULT_MAX_REQUEST_BYTES,
            ),
            read_timeout_seconds=_positive_float(
                self._config.ipc_read_timeout_seconds,
                _DEFAULT_READ_TIMEOUT_SECONDS,
            ),
        )
        server.dispatcher = self._dispatcher  # type: ignore[attr-defined]
        server.agent_config = self._config  # type: ignore[attr-defined]
        server.endpoint_identity = {  # type: ignore[attr-defined]
            "endpoint_id": str(getattr(self._config, "endpoint_id", "") or ""),
            "user_id": str(getattr(self._config, "user_id", "") or ""),
            "user_email": str(getattr(self._config, "user_email", "") or ""),
        }
        server.response_authenticator = authenticator  # type: ignore[attr-defined]
        os.chmod(self._path, 0o600)
        current = os.lstat(self._path)
        self._socket_identity = (current.st_dev, current.st_ino)
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        return self._path

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        try:
            current = os.lstat(self._path)
            if (
                self._socket_identity == (current.st_dev, current.st_ino)
                and stat.S_ISSOCK(current.st_mode)
            ):
                self._path.unlink()
        except OSError:
            pass
        self._socket_identity = None


def _positive_int(value, fallback: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return fallback
    return parsed if parsed > 0 else fallback


def _positive_float(value, fallback: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return fallback
    return parsed if parsed > 0 else fallback
