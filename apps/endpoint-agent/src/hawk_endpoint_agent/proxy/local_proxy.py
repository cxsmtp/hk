"""Loopback intercepting proxy.

Enforcement model (control-mode honest):
  * ``CONNECT`` (TLS): host-level allow/block from policy — the proxy blocks a
    destination or tunnels it, without decrypting. A blocked CONNECT is
    ``inline_prevented`` at the domain level.
  * Readable HTTP requests to known AI APIs: the body is parsed, the prompt/tool
    call is extracted and sent to the Hawk gateway via the dispatcher; a ``block``
    returns 403 before the request reaches the provider (full inline prevention).

Runs on 127.0.0.1 only. Deep TLS inspection (decrypting HTTPS to the AI APIs) is a
separate, MDM-driven step that installs a trusted CA; this proxy does host-level
TLS control plus full inspection of anything it can read.
"""

from __future__ import annotations

import http.server
import json
import select
import socket
import threading
from urllib.parse import urlsplit

from ..decision import Action
from ..dispatcher import Dispatcher
from ..policy import PolicyStore
from .classifier import build_request, classify_host


class _ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args) -> None:  # keep the agent quiet
        return

    # -- HTTPS tunneling (host-level control) ------------------------------
    def do_CONNECT(self) -> None:
        host, _, port_str = self.path.partition(":")
        port = int(port_str) if port_str.isdigit() else 443
        if self._host_blocked(host):
            self._block_connect(host)
            return
        interceptor = getattr(self.server, "interceptor", None)
        if interceptor is not None and classify_host(host) is not None:
            # Deep-inspection path: terminate TLS locally for AI hosts only, inspect
            # the plaintext, then block or forward. Non-AI hosts never reach here.
            self.send_response(200, "Connection Established")
            self.end_headers()
            try:
                interceptor.intercept(self.connection, host, port, self.server.dispatcher)
            except Exception:  # noqa: BLE001 - interception must never crash the proxy
                pass
            return
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            self.send_error(502, "Upstream unreachable")
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        self._tunnel(self.connection, upstream)

    def _tunnel(self, client: socket.socket, upstream: socket.socket) -> None:
        sockets = [client, upstream]
        try:
            while True:
                readable, _, _ = select.select(sockets, [], [], 30)
                if not readable:
                    break
                for sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        return
                    (upstream if sock is client else client).sendall(data)
        except OSError:
            pass
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    # -- readable HTTP (full inspection) -----------------------------------
    def do_GET(self) -> None:
        self._handle_http()

    def do_POST(self) -> None:
        self._handle_http()

    def do_PUT(self) -> None:
        self._handle_http()

    def do_PATCH(self) -> None:
        self._handle_http()

    def do_DELETE(self) -> None:
        self._handle_http()

    def _handle_http(self) -> None:
        parts = urlsplit(self.path if "://" in self.path else f"http://{self.headers.get('Host','')}{self.path}")
        host = parts.hostname or ""
        path = parts.path or "/"
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""

        request = build_request(host, path, body)
        if request is not None:
            decision = self.server.dispatcher.evaluate(  # type: ignore[attr-defined]
                request,
                adapter_path="local_proxy",
                pre_action=True,
            )
            if decision.action in {Action.BLOCK, Action.REDACT, Action.HOLD}:
                self._block_http(decision)
                return
        self._forward(parts, body)

    def _forward(self, parts, body: bytes) -> None:
        host = parts.hostname
        port = parts.port or 80
        if not host:
            self.send_error(400, "Bad request")
            return
        try:
            upstream = socket.create_connection((host, port), timeout=15)
        except OSError:
            self.send_error(502, "Upstream unreachable")
            return
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        lines = [f"{self.command} {path} HTTP/1.0"]
        for key, value in self.headers.items():
            if key.lower() in {"proxy-connection", "connection"}:
                continue
            lines.append(f"{key}: {value}")
        lines.append("Connection: close")
        request_bytes = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body
        try:
            upstream.sendall(request_bytes)
            while True:
                data = upstream.recv(65536)
                if not data:
                    break
                self.wfile.write(data)
        except OSError:
            pass
        finally:
            upstream.close()

    # -- helpers -----------------------------------------------------------
    def _host_blocked(self, host: str) -> bool:
        policy = self.server.policy.policy  # type: ignore[attr-defined]
        h = (host or "").strip().lower()
        if policy is not None:
            for domain in policy.blocked_domains or []:
                d = str(domain).strip().lower()
                if h == d or h.endswith("." + d):
                    return True
        return False

    def _block_connect(self, host: str) -> None:
        body = json.dumps({"error": "blocked_by_hawk", "host": host, "control": "domain_block"}).encode()
        self.send_response(403, "Blocked by Hawk")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _block_http(self, decision) -> None:
        body = json.dumps(
            {
                "error": "blocked_by_hawk",
                "action": decision.action,
                "reason": decision.reason,
                "threat_types": decision.threat_types,
                "framework_refs": decision.framework_refs,
            }
        ).encode()
        self.send_response(403, "Blocked by Hawk")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


class _ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class LocalProxy:
    def __init__(self, config, dispatcher: Dispatcher, policy: PolicyStore, *, interceptor=None) -> None:
        self._config = config
        self._dispatcher = dispatcher
        self._policy = policy
        self._interceptor = interceptor
        self._server: _ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            return (self._config.proxy_host, self._config.proxy_port)
        return self._server.server_address  # type: ignore[return-value]

    def start(self) -> tuple[str, int]:
        server = _ThreadingHTTPServer((self._config.proxy_host, self._config.proxy_port), _ProxyHandler)
        server.dispatcher = self._dispatcher  # type: ignore[attr-defined]
        server.policy = self._policy  # type: ignore[attr-defined]
        server.interceptor = self._interceptor  # type: ignore[attr-defined]
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        return server.server_address  # type: ignore[return-value]

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
