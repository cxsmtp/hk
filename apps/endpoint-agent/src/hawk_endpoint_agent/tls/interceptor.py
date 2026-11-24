"""TLS MITM interception for AI hosts.

Given a client CONNECT socket to an AI host, terminates TLS locally with a minted
leaf cert, reads the plaintext HTTP request, runs it through the dispatcher for a
decision, and either blocks (403 over TLS) or forwards to the real upstream over a
fresh TLS connection and relays the response. Only invoked for AI-classified hosts.
"""

from __future__ import annotations

import json
import socket
import ssl
from typing import Any

from ..decision import Action
from ..proxy.classifier import build_request
from .certs import CertificateAuthority

_BLOCKING = {Action.BLOCK, Action.REDACT, Action.HOLD}


def read_http_request(sock, *, max_head: int = 65536) -> tuple[str, str, dict[str, str], bytes] | None:
    """Read one HTTP request from a socket. Returns (method, path, headers, body)."""
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < max_head:
        try:
            chunk = sock.recv(4096)
        except OSError:
            return None
        if not chunk:
            break
        buf += chunk
    if b"\r\n\r\n" not in buf:
        return None
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    request_line = lines[0].decode("utf-8", errors="ignore").split(" ")
    if len(request_line) < 2:
        return None
    method, path = request_line[0], request_line[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" in line:
            key, value = line.split(b":", 1)
            headers[key.decode("utf-8", errors="ignore").strip().lower()] = value.decode("utf-8", errors="ignore").strip()
    body = rest
    length = int(headers.get("content-length", "0") or 0)
    while len(body) < length:
        try:
            chunk = sock.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        body += chunk
    return method, path, headers, body


def _block_response(decision) -> bytes:
    body = json.dumps(
        {
            "error": "blocked_by_hawk",
            "action": decision.action,
            "reason": decision.reason,
            "threat_types": decision.threat_types,
            "framework_refs": decision.framework_refs,
        }
    ).encode("utf-8")
    return (
        b"HTTP/1.1 403 Blocked by Hawk\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )


class TlsInterceptor:
    def __init__(self, ca: CertificateAuthority) -> None:
        self._ca = ca

    def available(self) -> bool:
        return self._ca.available()

    def intercept(self, client_sock, host: str, port: int, dispatcher: Any) -> None:
        cert_path, key_path = self._ca.leaf_cert(host)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_path), str(key_path))
        try:
            tls_client = context.wrap_socket(client_sock, server_side=True)
        except (ssl.SSLError, OSError):
            return  # client did not trust our CA, or handshake failed
        try:
            parsed = read_http_request(tls_client)
            if parsed is None:
                return
            method, path, headers, body = parsed
            request = build_request(host, path, body)
            if request is not None:
                decision = dispatcher.evaluate(request)
                if decision.action in _BLOCKING:
                    tls_client.sendall(_block_response(decision))
                    return
            self._forward(tls_client, host, port, method, path, headers, body)
        finally:
            try:
                tls_client.close()
            except OSError:
                pass

    def _forward(self, tls_client, host: str, port: int, method: str, path: str, headers: dict[str, str], body: bytes) -> None:
        try:
            raw = socket.create_connection((host, port), timeout=15)
            upstream = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        except (OSError, ssl.SSLError):
            try:
                tls_client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            return
        lines = [f"{method} {path} HTTP/1.1"]
        for key, value in headers.items():
            if key in {"proxy-connection", "connection"}:
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
                tls_client.sendall(data)
        except OSError:
            pass
        finally:
            upstream.close()
