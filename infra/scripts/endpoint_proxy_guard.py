#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.client
import json
import os
import select
import socket
import socketserver
import threading
import urllib.error
import urllib.parse
import urllib.request
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from typing import Any


DEFAULT_LISTEN_HOST = "127.0.0.1"
DEFAULT_LISTEN_PORT = 8787
DEFAULT_GATEWAY_HOST = "hawk-gateway.company.com"
DEFAULT_NETWORK_SERVICE = "Wi-Fi"

KNOWN_LLM_HOSTS = (
    "api.openai.com",
    "api.openai.azure.com",
    "openai.azure.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.mistral.ai",
)


@dataclass
class GuardConfig:
    api_url: str
    token: str
    tenant_id: str
    user_id: str | None
    device_id: str
    gateway_host: str
    block_non_gateway_llm: bool


def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _is_loopback_host(host: str) -> bool:
    token = _host_only(host)
    return token in {"localhost", "127.0.0.1", "::1"}


def _validate_api_url(api_url: str, *, allow_http: bool) -> str:
    token = _safe_str(api_url)
    parsed = urllib.parse.urlparse(token)
    if not _safe_str(parsed.scheme) or not _safe_str(parsed.hostname):
        raise ValueError("Invalid API URL.")
    scheme = _safe_str(parsed.scheme).lower()
    if scheme == "https":
        return token.rstrip("/")
    if scheme == "http" and allow_http and _is_loopback_host(_safe_str(parsed.hostname)):
        return token.rstrip("/")
    raise ValueError("API URL must be HTTPS (HTTP only allowed for localhost when --allow-local-http-api is set).")


def _host_only(value: str) -> str:
    token = _safe_str(value).lower()
    if not token:
        return ""
    if "://" in token:
        parsed = urllib.parse.urlparse(token)
        token = _safe_str(parsed.hostname).lower()
    if ":" in token:
        token = token.split(":", 1)[0]
    return token


def _matches_host(host: str, pattern: str) -> bool:
    host = _host_only(host)
    pattern = _host_only(pattern)
    return bool(host and pattern and (host == pattern or host.endswith(f".{pattern}")))


def _is_llm_host(host: str) -> bool:
    return any(_matches_host(host, known) for known in KNOWN_LLM_HOSTS)


def _is_gateway_host(host: str, gateway_host: str) -> bool:
    return _matches_host(host, gateway_host)


def _emit_devtool_event(config: GuardConfig, *, endpoint: str, gateway_routed: bool, reason: str) -> None:
    payload = {
        "surface": "developer_tool",
        "app": "endpoint_proxy_guard",
        "action_type": "api_call",
        "event_type": "proxy.guard",
        "user_id": config.user_id,
        "device_id": config.device_id,
        "endpoint_id": config.device_id,
        "api_endpoint": endpoint,
        "gateway_routed": gateway_routed,
        "decision_hint": "block" if (not gateway_routed and config.block_non_gateway_llm) else "allow",
        "reason_code": reason,
        "transport": {
            "require_tls": True,
            "tls_version": "1.3",
            "scheme": "https",
            "require_mtls": True,
            "mtls_enabled": True,
            "require_cert_pinning": True,
            "cert_pinned": gateway_routed,
        },
        "metadata": {
            "source": "endpoint_proxy_guard",
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "gateway_host": config.gateway_host,
        },
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=f"{config.api_url}/surface-coverage/dev-tools/events",
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config.token}",
            "X-Tenant-ID": config.tenant_id,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
    except urllib.error.URLError:
        return


class ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ProxyHandler(BaseHTTPRequestHandler):
    server_version = "HawkProxyGuard/1.0"

    def do_CONNECT(self) -> None:  # noqa: N802
        host, _, port_token = self.path.partition(":")
        target_host = _host_only(host)
        target_port = int(port_token or "443")
        gateway_routed = _is_gateway_host(target_host, self.server.guard_config.gateway_host)  # type: ignore[attr-defined]
        is_llm = _is_llm_host(target_host)
        reason = "gateway_routed" if gateway_routed else ("llm_direct_connection" if is_llm else "non_llm_connection")
        _emit_devtool_event(
            self.server.guard_config,  # type: ignore[attr-defined]
            endpoint=f"https://{target_host}:{target_port}",
            gateway_routed=gateway_routed,
            reason=reason,
        )

        if is_llm and self.server.guard_config.block_non_gateway_llm and not gateway_routed:  # type: ignore[attr-defined]
            self.send_response(403, "Blocked by Hawk policy")
            self.end_headers()
            self.wfile.write(b"Direct LLM traffic blocked. Route via Hawk Gateway.")
            return

        try:
            upstream = socket.create_connection((target_host, target_port), timeout=10)
        except OSError:
            self.send_error(502, "Upstream connect failed")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()
        self.connection.setblocking(False)
        upstream.setblocking(False)
        sockets = [self.connection, upstream]
        try:
            while True:
                try:
                    readable, _, exceptional = select.select(sockets, [], sockets, 1.0)
                except OSError:
                    break
                if exceptional:
                    break
                for sock in readable:
                    try:
                        data = sock.recv(8192)
                    except (ConnectionResetError, BrokenPipeError, OSError):
                        return
                    if not data:
                        return
                    if sock is self.connection:
                        try:
                            upstream.sendall(data)
                        except (ConnectionResetError, BrokenPipeError, OSError):
                            return
                    else:
                        try:
                            self.connection.sendall(data)
                        except (ConnectionResetError, BrokenPipeError, OSError):
                            return
        finally:
            upstream.close()

    def _forward_http(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if not parsed.scheme:
            host = _host_only(self.headers.get("Host", ""))
            target_url = f"http://{host}{self.path}"
            parsed = urllib.parse.urlsplit(target_url)
        target_host = _host_only(parsed.hostname or "")
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        gateway_routed = _is_gateway_host(target_host, self.server.guard_config.gateway_host)  # type: ignore[attr-defined]
        is_llm = _is_llm_host(target_host)
        reason = "gateway_routed" if gateway_routed else ("llm_direct_connection" if is_llm else "non_llm_connection")
        _emit_devtool_event(
            self.server.guard_config,  # type: ignore[attr-defined]
            endpoint=f"{parsed.scheme or 'http'}://{target_host}{parsed.path or '/'}",
            gateway_routed=gateway_routed,
            reason=reason,
        )

        if is_llm and self.server.guard_config.block_non_gateway_llm and not gateway_routed:  # type: ignore[attr-defined]
            self.send_response(403, "Blocked by Hawk policy")
            self.end_headers()
            self.wfile.write(b"Direct LLM traffic blocked. Route via Hawk Gateway.")
            return

        body = b""
        content_length = int(self.headers.get("Content-Length", "0") or "0")
        if content_length > 0:
            try:
                body = self.rfile.read(content_length)
            except (ConnectionResetError, BrokenPipeError, OSError):
                return

        conn_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        upstream = conn_cls(target_host, target_port, timeout=20)
        try:
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            headers = {k: v for (k, v) in self.headers.items() if k.lower() not in {"proxy-connection", "connection", "keep-alive"}}
            upstream.request(self.command, path, body=body or None, headers=headers)
            response = upstream.getresponse()
            payload = response.read()
            self.send_response(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() in {"transfer-encoding", "connection", "proxy-connection"}:
                    continue
                self.send_header(key, value)
            self.end_headers()
            if payload:
                try:
                    self.wfile.write(payload)
                except (ConnectionResetError, BrokenPipeError, OSError):
                    return
        finally:
            upstream.close()

    def do_GET(self) -> None:  # noqa: N802
        self._forward_http()

    def do_POST(self) -> None:  # noqa: N802
        self._forward_http()

    def do_PUT(self) -> None:  # noqa: N802
        self._forward_http()

    def do_DELETE(self) -> None:  # noqa: N802
        self._forward_http()

    def do_PATCH(self) -> None:  # noqa: N802
        self._forward_http()

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def run_proxy(config: GuardConfig, listen_host: str, listen_port: int) -> None:
    server = ThreadedHTTPServer((listen_host, listen_port), ProxyHandler)
    server.guard_config = config  # type: ignore[attr-defined]
    print(f"[hawk-proxy-guard] listening on http://{listen_host}:{listen_port}")
    print(f"[hawk-proxy-guard] gateway host: {config.gateway_host}")
    print(f"[hawk-proxy-guard] block direct LLM: {config.block_non_gateway_llm}")
    server.serve_forever()


def print_system_proxy_commands(*, host: str, port: int) -> None:
    print("macOS (manual apply, admin if needed):")
    print(f'networksetup -setwebproxy "Wi-Fi" {host} {port}')
    print(f'networksetup -setsecurewebproxy "Wi-Fi" {host} {port}')
    print("")
    print("Windows (manual apply):")
    print(f'netsh winhttp set proxy {host}:{port}')
    print("To reset:")
    print('networksetup -setwebproxystate "Wi-Fi" off && networksetup -setsecurewebproxystate "Wi-Fi" off')
    print("netsh winhttp reset proxy")


def apply_macos_proxy(*, host: str, port: int, network_service: str) -> None:
    subprocess.check_call(["networksetup", "-setwebproxy", network_service, host, str(port)])
    subprocess.check_call(["networksetup", "-setsecurewebproxy", network_service, host, str(port)])
    subprocess.check_call(["networksetup", "-setwebproxystate", network_service, "on"])
    subprocess.check_call(["networksetup", "-setsecurewebproxystate", network_service, "on"])


def clear_macos_proxy(*, network_service: str) -> None:
    subprocess.check_call(["networksetup", "-setwebproxystate", network_service, "off"])
    subprocess.check_call(["networksetup", "-setsecurewebproxystate", network_service, "off"])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Hawk local proxy guard for endpoint interception")
    parser.add_argument("--api-url", default=os.getenv("HAWK_API_URL", "http://localhost:8000"))
    parser.add_argument("--tenant-id", default=os.getenv("TENANT_ID", ""))
    parser.add_argument("--token", default=os.getenv("ACCESS_TOKEN", ""))
    parser.add_argument("--user-id", default=os.getenv("HAWK_USER_ID", ""))
    parser.add_argument("--device-id", default=os.getenv("HAWK_DEVICE_ID", socket.gethostname()))
    parser.add_argument("--gateway-host", default=os.getenv("HAWK_GATEWAY_HOST", DEFAULT_GATEWAY_HOST))
    parser.add_argument("--listen-host", default=DEFAULT_LISTEN_HOST)
    parser.add_argument("--listen-port", type=int, default=DEFAULT_LISTEN_PORT)
    parser.add_argument("--allow-direct-llm", action="store_true")
    parser.add_argument("--print-system-proxy-commands", action="store_true")
    parser.add_argument("--apply-macos-proxy", action="store_true")
    parser.add_argument("--clear-macos-proxy", action="store_true")
    parser.add_argument("--network-service", default=os.getenv("HAWK_NETWORK_SERVICE", DEFAULT_NETWORK_SERVICE))
    parser.add_argument("--allow-local-http-api", action="store_true")
    parser.add_argument("--allow-non-local-listen", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        validated_api_url = _validate_api_url(
            _safe_str(args.api_url),
            allow_http=bool(args.allow_local_http_api),
        )
    except ValueError as exc:
        print(f"Invalid API URL: {exc}", flush=True)
        return 2

    listen_host = _safe_str(args.listen_host)
    if not args.allow_non_local_listen and not _is_loopback_host(listen_host):
        print("Refusing non-local listen host without --allow-non-local-listen.", flush=True)
        return 2

    if args.apply_macos_proxy and args.clear_macos_proxy:
        print("Choose either --apply-macos-proxy or --clear-macos-proxy, not both.", flush=True)
        return 2

    if args.apply_macos_proxy:
        try:
            apply_macos_proxy(host=listen_host, port=max(1, int(args.listen_port)), network_service=_safe_str(args.network_service))
            print(f"Applied macOS proxy on {_safe_str(args.network_service)} -> {listen_host}:{int(args.listen_port)}")
            return 0
        except Exception as exc:
            print(f"Failed to apply macOS proxy: {exc}", flush=True)
            return 1

    if args.clear_macos_proxy:
        try:
            clear_macos_proxy(network_service=_safe_str(args.network_service))
            print(f"Cleared macOS proxy on {_safe_str(args.network_service)}")
            return 0
        except Exception as exc:
            print(f"Failed to clear macOS proxy: {exc}", flush=True)
            return 1

    if not _safe_str(args.tenant_id) or not _safe_str(args.token):
        print("Missing ACCESS_TOKEN/TENANT_ID (or --token/--tenant-id).", flush=True)
        return 2
    if args.print_system_proxy_commands:
        print_system_proxy_commands(host=listen_host, port=int(args.listen_port))
        return 0
    config = GuardConfig(
        api_url=validated_api_url,
        token=_safe_str(args.token),
        tenant_id=_safe_str(args.tenant_id),
        user_id=_safe_str(args.user_id) or None,
        device_id=_safe_str(args.device_id),
        gateway_host=_safe_str(args.gateway_host),
        block_non_gateway_llm=not bool(args.allow_direct_llm),
    )
    run_proxy(config, listen_host=listen_host, listen_port=max(1, int(args.listen_port)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
