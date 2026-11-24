#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_API_URL = "http://localhost:8000"
DEFAULT_HEARTBEAT_INTERVAL = 20
DEFAULT_REQUEST_TIMEOUT_SECONDS = 60
DEFAULT_REQUEST_RETRY_ATTEMPTS = 3
DEFAULT_LAUNCHD_LABEL = "com.hawk.endpoint_agent"

APP_KEYWORDS: dict[str, str] = {
    "slack": "Slack Desktop",
    "outlook": "Outlook Desktop",
    "teams": "Teams Desktop",
    "code": "VS Code",
    "cursor": "Cursor",
    "pycharm": "PyCharm",
    "webstorm": "WebStorm",
    "goland": "GoLand",
    "github desktop": "GitHub Desktop",
    "terminal": "Terminal",
    "iterm": "iTerm",
    "powershell": "PowerShell",
    "cmd.exe": "Windows Terminal",
    "codex": "Codex CLI",
}


@dataclass
class AgentConfig:
    api_url: str
    token: str
    tenant_id: str
    user_id: str | None
    device_id: str
    hostname: str
    os_type: str
    os_version: str
    location: str | None
    request_timeout_seconds: int
    request_retry_attempts: int
    allow_local_self_signed_tls: bool


def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _env_or_cli(value: str | None, env_key: str, default: str | None = None) -> str | None:
    if _safe_str(value):
        return _safe_str(value)
    if _safe_str(os.getenv(env_key)):
        return _safe_str(os.getenv(env_key))
    return default


def _is_loopback_host(host: str) -> bool:
    token = _safe_str(host).lower()
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


def _is_local_demo_https_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(_safe_str(url))
    host = _safe_str(parsed.hostname).lower()
    return _safe_str(parsed.scheme).lower() == "https" and (
        _is_loopback_host(host) or host.endswith(".localhost") or host == "hawk.localhost"
    )


def _json_request(
    *,
    method: str,
    url: str,
    payload: dict[str, Any],
    token: str,
    tenant_id: str,
    timeout: int = DEFAULT_REQUEST_TIMEOUT_SECONDS,
    retry_attempts: int = DEFAULT_REQUEST_RETRY_ATTEMPTS,
    allow_local_self_signed_tls: bool = False,
) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    attempts = max(1, int(retry_attempts or 1))
    ssl_context = None
    if allow_local_self_signed_tls and _is_local_demo_https_url(url):
        ssl_context = ssl._create_unverified_context()
    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(
            url=url,
            data=data,
            method=method,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
                "X-Tenant-ID": tenant_id,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as response:
                body = response.read().decode("utf-8")
            return json.loads(body) if body else {}
        except (TimeoutError, socket.timeout, ssl.SSLError, urllib.error.URLError) as exc:
            is_timeout = "timed out" in str(exc).lower()
            if not is_timeout or attempt >= attempts:
                raise
            time.sleep(0.4 * attempt)
    return {}


def _detect_processes() -> list[str]:
    try:
        import psutil  # type: ignore

        names = []
        for proc in psutil.process_iter(["name", "exe", "cmdline"]):
            try:
                name = _safe_str(proc.info.get("name") or "")
                exe = _safe_str(proc.info.get("exe") or "")
                cmd = " ".join([_safe_str(item) for item in (proc.info.get("cmdline") or []) if _safe_str(item)])
                token = name or os.path.basename(exe) or cmd
                if token:
                    names.append(token.lower())
            except Exception:
                continue
        return names
    except Exception:
        pass

    system = platform.system().lower()
    try:
        if system == "windows":
            out = subprocess.check_output(["tasklist", "/fo", "csv", "/nh"], text=True, stderr=subprocess.STDOUT)
            return [line.lower() for line in out.splitlines() if line.strip()]
        out = subprocess.check_output(["ps", "-ax", "-o", "comm="], text=True, stderr=subprocess.STDOUT)
        return [line.strip().lower() for line in out.splitlines() if line.strip()]
    except Exception:
        return []


def _canonical_running_apps(processes: list[str]) -> list[str]:
    found: set[str] = set()
    for proc in processes:
        for keyword, app_name in APP_KEYWORDS.items():
            if keyword in proc:
                found.add(app_name)
    return sorted(found) if found else ["endpoint_agent"]


def _build_agent_config(args: argparse.Namespace) -> AgentConfig:
    raw_api_url = _safe_str(_env_or_cli(args.api_url, "HAWK_API_URL", DEFAULT_API_URL))
    token = _safe_str(_env_or_cli(args.token, "ACCESS_TOKEN"))
    tenant_id = _safe_str(_env_or_cli(args.tenant_id, "TENANT_ID"))
    user_id = _env_or_cli(args.user_id, "HAWK_USER_ID")

    if not raw_api_url or not token or not tenant_id:
        raise SystemExit("Missing required config. Provide api_url, token, and tenant_id (or env: HAWK_API_URL, ACCESS_TOKEN, TENANT_ID).")
    try:
        api_url = _validate_api_url(raw_api_url, allow_http=bool(getattr(args, "allow_local_http_api", False)))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    hostname = socket.gethostname()
    device_id = _safe_str(_env_or_cli(args.device_id, "HAWK_DEVICE_ID", hostname))
    os_type = platform.system().lower()
    os_version = platform.version()
    location = _env_or_cli(args.location, "HAWK_LOCATION")
    request_timeout_seconds = int(
        _safe_str(_env_or_cli(str(getattr(args, "request_timeout", "") or ""), "HAWK_HTTP_TIMEOUT", str(DEFAULT_REQUEST_TIMEOUT_SECONDS)))
        or DEFAULT_REQUEST_TIMEOUT_SECONDS
    )
    request_retry_attempts = int(
        _safe_str(
            _env_or_cli(str(getattr(args, "request_retries", "") or ""), "HAWK_HTTP_RETRIES", str(DEFAULT_REQUEST_RETRY_ATTEMPTS))
        )
        or DEFAULT_REQUEST_RETRY_ATTEMPTS
    )
    return AgentConfig(
        api_url=api_url.rstrip("/"),
        token=token,
        tenant_id=tenant_id,
        user_id=user_id,
        device_id=device_id,
        hostname=hostname,
        os_type=os_type,
        os_version=os_version,
        location=location,
        request_timeout_seconds=max(5, request_timeout_seconds),
        request_retry_attempts=max(1, request_retry_attempts),
        allow_local_self_signed_tls=bool(getattr(args, "allow_local_self_signed_tls", False)),
    )


def send_heartbeat(
    config: AgentConfig,
    *,
    gateway_routed: bool = True,
    verbose: bool = False,
    apps_override: list[str] | None = None,
) -> dict[str, Any]:
    if apps_override:
        apps = sorted({_safe_str(item) for item in apps_override if _safe_str(item)})
    else:
        apps = _canonical_running_apps(_detect_processes())
    payload = {
        "user_id": config.user_id,
        "device_id": config.device_id,
        "hostname": config.hostname,
        "os_type": config.os_type,
        "os_version": config.os_version,
        "running_apps": apps,
        "gateway_routed": bool(gateway_routed),
        "location": config.location,
        "metadata": {"source": "endpoint_agent", "captured_at": datetime.now(timezone.utc).isoformat()},
    }
    url = f"{config.api_url}/surface-coverage/endpoint/heartbeat"
    result = _json_request(
        method="POST",
        url=url,
        payload=payload,
        token=config.token,
        tenant_id=config.tenant_id,
        timeout=config.request_timeout_seconds,
        retry_attempts=config.request_retry_attempts,
        allow_local_self_signed_tls=config.allow_local_self_signed_tls,
    )
    if verbose:
        print(json.dumps(result, indent=2))
    return result


def send_devtool_event(
    config: AgentConfig,
    *,
    app: str,
    content: str,
    api_endpoint: str,
    model: str | None,
    gateway_routed: bool,
    verbose: bool = False,
) -> dict[str, Any]:
    payload = {
        "surface": "developer_tool",
        "app": app,
        "action_type": "api_call",
        "event_type": "endpoint_agent.dev_tool",
        "user_id": config.user_id,
        "device_id": config.device_id,
        "endpoint_id": config.device_id,
        "hostname": config.hostname,
        "os_type": config.os_type,
        "os_version": config.os_version,
        "prompt_or_content": content,
        "api_endpoint": api_endpoint,
        "model": model,
        "gateway_routed": bool(gateway_routed),
        "transport": {
            "require_tls": True,
            "tls_version": "1.3",
            "scheme": "https",
            "require_mtls": True,
            "mtls_enabled": True,
        },
        "metadata": {"source": "endpoint_agent.dev_tool"},
    }
    url = f"{config.api_url}/surface-coverage/dev-tools/events"
    result = _json_request(
        method="POST",
        url=url,
        payload=payload,
        token=config.token,
        tenant_id=config.tenant_id,
        timeout=config.request_timeout_seconds,
        retry_attempts=config.request_retry_attempts,
        allow_local_self_signed_tls=config.allow_local_self_signed_tls,
    )
    if verbose:
        print(json.dumps(result, indent=2))
    return result


def _print_service_templates(config: AgentConfig) -> None:
    script = os.path.abspath(__file__)
    launch_cmd = (
        f"python3 \"{script}\" heartbeat --api-url \"{config.api_url}\" "
        f"--tenant-id \"{config.tenant_id}\" --token \"<ACCESS_TOKEN>\" --device-id \"{config.device_id}\""
    )
    print("\nmacOS launchd ProgramArguments:")
    print(json.dumps(["/usr/bin/python3", script, "heartbeat", "--api-url", config.api_url, "--tenant-id", config.tenant_id, "--token", "<ACCESS_TOKEN>", "--device-id", config.device_id], indent=2))
    print("\nWindows Task Scheduler Action:")
    print(f'powershell -NoProfile -Command "{launch_cmd}"')


def _launchd_path(label: str) -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"


def _launchd_plist_content(*, label: str, python_bin: str, script_path: str, cfg: AgentConfig, interval: int, gateway_routed: bool) -> str:
    args = [
        python_bin,
        script_path,
        "--api-url",
        cfg.api_url,
        "--tenant-id",
        cfg.tenant_id,
        "--token",
        cfg.token,
        "--device-id",
        cfg.device_id,
        "heartbeat",
        "--interval",
        str(max(5, int(interval))),
    ]
    if cfg.user_id:
        args.extend(["--user-id", cfg.user_id])
    if cfg.location:
        args.extend(["--location", cfg.location])
    if cfg.allow_local_self_signed_tls:
        args.append("--allow-local-self-signed-tls")
    if gateway_routed:
        args.append("--gateway-routed")

    arg_xml = "\n".join([f"      <string>{arg}</string>" for arg in args])
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>{label}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/hawk-endpoint-agent.out.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/hawk-endpoint-agent.err.log</string>
    <key>ProgramArguments</key>
    <array>
{arg_xml}
    </array>
  </dict>
</plist>
"""


def _install_launchd(args: argparse.Namespace) -> int:
    cfg = _build_agent_config(args)
    label = _safe_str(args.label or DEFAULT_LAUNCHD_LABEL)
    plist_path = _launchd_path(label)
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    script_path = os.path.abspath(__file__)
    python_bin = sys.executable or "/usr/bin/python3"
    content = _launchd_plist_content(
        label=label,
        python_bin=python_bin,
        script_path=script_path,
        cfg=cfg,
        interval=max(5, int(args.interval or DEFAULT_HEARTBEAT_INTERVAL)),
        gateway_routed=bool(args.gateway_routed),
    )
    plist_path.write_text(content, encoding="utf-8")
    print(f"Wrote launchd plist: {plist_path}")
    print(f"Load command: launchctl load -w \"{plist_path}\"")
    print(f"Reload command: launchctl unload -w \"{plist_path}\" && launchctl load -w \"{plist_path}\"")
    return 0


def _uninstall_launchd(args: argparse.Namespace) -> int:
    label = _safe_str(args.label or DEFAULT_LAUNCHD_LABEL)
    plist_path = _launchd_path(label)
    if plist_path.exists():
        print(f"Unload command: launchctl unload -w \"{plist_path}\"")
        plist_path.unlink(missing_ok=True)
        print(f"Removed launchd plist: {plist_path}")
        return 0
    print(f"No launchd plist found at: {plist_path}")
    return 0


def _print_windows_task(args: argparse.Namespace) -> int:
    cfg = _build_agent_config(args)
    interval = max(5, int(args.interval or DEFAULT_HEARTBEAT_INTERVAL))
    task_name = _safe_str(args.task_name or "HawkEndpointAgent")
    script_path = os.path.abspath(__file__)
    python_bin = sys.executable or "python"
    command = (
        f'schtasks /Create /SC MINUTE /MO {interval} /TN "{task_name}" /TR '
        f'"\\\"{python_bin}\\\" \\\"{script_path}\\\" --api-url \\\"{cfg.api_url}\\\" '
        f'--tenant-id \\\"{cfg.tenant_id}\\\" --token \\\"<ACCESS_TOKEN>\\\" '
        f'--device-id \\\"{cfg.device_id}\\\" heartbeat --once --gateway-routed" /F'
    )
    print("Windows Task Scheduler command:")
    print(command)
    print(f'Delete task command: schtasks /Delete /TN "{task_name}" /F')
    return 0


def _run_heartbeat_loop(args: argparse.Namespace) -> int:
    config = _build_agent_config(args)
    interval = max(5, int(args.interval or DEFAULT_HEARTBEAT_INTERVAL))
    while True:
        try:
            send_heartbeat(
                config,
                gateway_routed=bool(args.gateway_routed),
                verbose=bool(args.verbose),
                apps_override=list(args.app or []),
            )
        except urllib.error.HTTPError as exc:
            print(f"heartbeat failed (HTTP {exc.code}): {exc.reason}", file=sys.stderr)
        except Exception as exc:
            print(f"heartbeat failed: {exc}", file=sys.stderr)
        if args.once:
            return 0
        time.sleep(interval)


def _run_devtool_emit(args: argparse.Namespace) -> int:
    config = _build_agent_config(args)
    send_devtool_event(
        config,
        app=_safe_str(args.app or "codex_cli"),
        content=_safe_str(args.content),
        api_endpoint=_safe_str(args.api_endpoint or "https://api.openai.com/v1/responses"),
        model=_safe_str(args.model) or None,
        gateway_routed=bool(args.gateway_routed),
        verbose=bool(args.verbose),
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hawk endpoint agent (Mac/Windows-friendly)")
    parser.add_argument("--api-url", default=None)
    parser.add_argument("--tenant-id", default=None)
    parser.add_argument("--token", default=None)
    parser.add_argument("--user-id", default=None)
    parser.add_argument("--device-id", default=None)
    parser.add_argument("--location", default=None)
    parser.add_argument("--allow-local-http-api", action="store_true")
    parser.add_argument(
        "--allow-local-self-signed-tls",
        action="store_true",
        help="Allow the local hawk.localhost demo certificate only for loopback/.localhost API URLs.",
    )
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--request-timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT_SECONDS)
    parser.add_argument("--request-retries", type=int, default=DEFAULT_REQUEST_RETRY_ATTEMPTS)

    sub = parser.add_subparsers(dest="command", required=True)

    hb = sub.add_parser("heartbeat", help="Send endpoint heartbeat telemetry")
    hb.add_argument("--interval", type=int, default=DEFAULT_HEARTBEAT_INTERVAL)
    hb.add_argument("--once", action="store_true")
    hb.add_argument("--app", action="append", default=[])
    hb.add_argument("--gateway-routed", action="store_true", default=True)
    hb.add_argument("--no-gateway-routed", action="store_false", dest="gateway_routed")

    dev = sub.add_parser("devtool-event", help="Emit dev tool telemetry event")
    dev.add_argument("--app", default="codex_cli")
    dev.add_argument("--content", required=True)
    dev.add_argument("--api-endpoint", default="https://api.openai.com/v1/responses")
    dev.add_argument("--model", default="")
    dev.add_argument("--gateway-routed", action="store_true", default=True)
    dev.add_argument("--no-gateway-routed", action="store_false", dest="gateway_routed")

    sub.add_parser("print-service-templates", help="Print launchd/Task Scheduler templates")
    install_launchd = sub.add_parser("install-launchd", help="Install a launchd plist for heartbeat daemon mode")
    install_launchd.add_argument("--label", default=DEFAULT_LAUNCHD_LABEL)
    install_launchd.add_argument("--interval", type=int, default=DEFAULT_HEARTBEAT_INTERVAL)
    install_launchd.add_argument("--gateway-routed", action="store_true", default=True)
    install_launchd.add_argument("--no-gateway-routed", action="store_false", dest="gateway_routed")

    uninstall_launchd = sub.add_parser("uninstall-launchd", help="Remove launchd plist")
    uninstall_launchd.add_argument("--label", default=DEFAULT_LAUNCHD_LABEL)

    print_windows_task = sub.add_parser("print-windows-task", help="Print Task Scheduler command for heartbeat mode")
    print_windows_task.add_argument("--task-name", default="HawkEndpointAgent")
    print_windows_task.add_argument("--interval", type=int, default=DEFAULT_HEARTBEAT_INTERVAL)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "heartbeat":
        return _run_heartbeat_loop(args)
    if args.command == "devtool-event":
        return _run_devtool_emit(args)
    if args.command == "print-service-templates":
        cfg = _build_agent_config(args)
        _print_service_templates(cfg)
        return 0
    if args.command == "install-launchd":
        return _install_launchd(args)
    if args.command == "uninstall-launchd":
        return _uninstall_launchd(args)
    if args.command == "print-windows-task":
        return _print_windows_task(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
