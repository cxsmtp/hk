"""Reversible WinINET and WinHTTP proxy routing."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Protocol, Sequence

from .command import (
    NETSH_EXE,
    REG_EXE,
    CommandResult,
    WindowsDeploymentError,
    require_success,
)
from .state import contains_credentials


_INTERNET_SETTINGS = (
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
)
_BYPASS = "localhost;127.*;<local>"
_REGISTRY_VALUES = {
    "ProxyEnable": "REG_DWORD",
    "ProxyServer": "REG_SZ",
    "ProxyOverride": "REG_SZ",
}


class Runner(Protocol):
    def run(
        self, argv: Sequence[str], *, timeout: float = 30.0
    ) -> CommandResult: ...


def _mode(value: str) -> str:
    mode = str(value).strip().lower()
    if mode not in {"user_pilot", "managed_machine"}:
        raise ValueError("unsupported Windows deployment mode")
    return mode


def _proxy_address(host: str, port: int) -> str:
    try:
        address = ipaddress.ip_address(str(host))
        parsed_port = int(port)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid local proxy address") from exc
    if not address.is_loopback or not 1 <= parsed_port <= 65535:
        raise ValueError("Windows routing requires a local proxy address")
    return f"{address.compressed}:{parsed_port}"


def _safe_host_port(value: str) -> bool:
    if value.startswith("["):
        match = re.fullmatch(r"\[([0-9A-Fa-f:]+)\]:(\d{1,5})", value)
        if match is None:
            return False
        try:
            ipaddress.IPv6Address(match.group(1))
        except ValueError:
            return False
        port = int(match.group(2))
        return 1 <= port <= 65535
    match = re.fullmatch(r"([A-Za-z0-9.-]{1,253}):(\d{1,5})", value)
    if match is None:
        return False
    host, encoded_port = match.groups()
    if not 1 <= int(encoded_port) <= 65535:
        return False
    if host.replace(".", "").isdigit():
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            return False
        return True
    return all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in host.split(".")
    )


def _safe_proxy_spec(value: str) -> bool:
    if "=" not in value:
        return _safe_host_port(value)
    seen: set[str] = set()
    for assignment in value.split(";"):
        if assignment.count("=") != 1:
            return False
        scheme, address = assignment.split("=", 1)
        normalized = scheme.lower()
        if normalized not in {"http", "https"} or normalized in seen:
            return False
        if not _safe_host_port(address):
            return False
        seen.add(normalized)
    return bool(seen)


def _safe_bypass_spec(value: str) -> bool:
    if value == "(none)":
        return True
    return bool(value) and len(value) <= 2048 and re.fullmatch(
        r"[A-Za-z0-9.*;:<>{}\[\]-]+", value
    ) is not None


def _parse_winhttp_dump(output: str) -> dict[str, str]:
    meaningful = [
        line.strip()
        for line in output.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    reset_commands = [
        line for line in meaningful if re.fullmatch(r"(?i)reset\s+proxy", line)
    ]
    pattern = re.compile(
        r'(?i)set\s+proxy\s+proxy-server=(?:"([^"]+)"|(\S+))'
        r'(?:\s+bypass-list=(?:"([^"]*)"|(\S+)))?'
    )
    proxy_commands: list[dict[str, str]] = []
    for line in meaningful:
        match = pattern.fullmatch(line)
        if match is None:
            continue
        proxy = match.group(1) or match.group(2) or ""
        bypass = match.group(3) or match.group(4) or "(none)"
        if not _safe_proxy_spec(proxy) or not _safe_bypass_spec(bypass):
            raise WindowsDeploymentError("unsafe WinHTTP rollback value")
        proxy_commands.append({"mode": "proxy", "proxy": proxy, "bypass": bypass})
    if len(reset_commands) + len(proxy_commands) != 1:
        raise WindowsDeploymentError(
            "WinHTTP dump must contain exactly one restorable proxy command"
        )
    if reset_commands:
        return {"mode": "direct", "proxy": "", "bypass": ""}
    return proxy_commands[0]


class WindowsRouting:
    def __init__(self, runner: Runner) -> None:
        self._runner = runner

    def _run(self, argv: Sequence[str], operation: str) -> CommandResult:
        return require_success(self._runner.run(argv), operation)

    def _capture_registry_values(self) -> dict[str, dict[str, Any]]:
        result = self._run(
            [REG_EXE, "query", _INTERNET_SETTINGS],
            "capture WinINET routing",
        )
        captured: dict[str, dict[str, Any]] = {}
        for name, default_type in _REGISTRY_VALUES.items():
            match = re.search(
                rf"(?im)^\s*{re.escape(name)}\s+(REG_[A-Z_]+)\s+(.+?)\s*$",
                result.stdout,
            )
            if match is None:
                if re.search(rf"(?im)^\s*{re.escape(name)}\b", result.stdout):
                    raise WindowsDeploymentError(
                        "existing WinINET value could not be parsed safely"
                    )
                captured[name] = {
                    "exists": False,
                    "type": default_type,
                    "value": "",
                }
                continue
            value_type, value = match.groups()
            if value_type not in {"REG_DWORD", "REG_SZ", "REG_EXPAND_SZ"}:
                raise WindowsDeploymentError(
                    "unsupported WinINET rollback value type"
                )
            captured[name] = {
                "exists": True,
                "type": value_type,
                "value": value,
            }
        if contains_credentials(captured):
            raise WindowsDeploymentError("credential-bearing routing state refused")
        return captured

    def capture(self, deployment_mode: str) -> dict[str, Any]:
        mode = _mode(deployment_mode)
        if mode == "user_pilot":
            snapshot = {
                "deployment_mode": mode,
                "wininet": self._capture_registry_values(),
            }
        else:
            show_result = self._run(
                [NETSH_EXE, "winhttp", "show", "proxy"],
                "capture WinHTTP routing",
            )
            dump_result = self._run(
                [NETSH_EXE, "winhttp", "dump"],
                "dump WinHTTP routing",
            )
            if contains_credentials(show_result.stdout) or contains_credentials(
                dump_result.stdout
            ):
                raise WindowsDeploymentError(
                    "credential-bearing routing state refused"
                )
            snapshot = {
                "deployment_mode": mode,
                "winhttp_output": show_result.stdout,
                "winhttp": _parse_winhttp_dump(dump_result.stdout),
            }
        if contains_credentials(snapshot):
            raise WindowsDeploymentError("credential-bearing routing state refused")
        return snapshot

    def apply(self, deployment_mode: str, host: str, port: int) -> None:
        mode = _mode(deployment_mode)
        proxy = _proxy_address(host, port)
        if mode == "user_pilot":
            commands = (
                (
                    REG_EXE,
                    "add",
                    _INTERNET_SETTINGS,
                    "/v",
                    "ProxyServer",
                    "/t",
                    "REG_SZ",
                    "/d",
                    proxy,
                    "/f",
                ),
                (
                    REG_EXE,
                    "add",
                    _INTERNET_SETTINGS,
                    "/v",
                    "ProxyOverride",
                    "/t",
                    "REG_SZ",
                    "/d",
                    _BYPASS,
                    "/f",
                ),
                (
                    REG_EXE,
                    "add",
                    _INTERNET_SETTINGS,
                    "/v",
                    "ProxyEnable",
                    "/t",
                    "REG_DWORD",
                    "/d",
                    "1",
                    "/f",
                ),
            )
        else:
            commands = (
                (
                    NETSH_EXE,
                    "winhttp",
                    "set",
                    "proxy",
                    f"proxy-server={proxy}",
                    f"bypass-list={_BYPASS}",
                ),
            )
        for command in commands:
            self._run(command, "apply Windows proxy routing")

    def restore(self, snapshot: dict[str, Any]) -> None:
        if not isinstance(snapshot, dict) or contains_credentials(snapshot):
            raise WindowsDeploymentError("invalid credential-bearing routing snapshot")
        mode = _mode(str(snapshot.get("deployment_mode") or ""))
        if mode == "user_pilot":
            wininet = snapshot.get("wininet")
            if not isinstance(wininet, dict) or set(wininet) != set(_REGISTRY_VALUES):
                raise WindowsDeploymentError("invalid WinINET rollback snapshot")
            for name, expected_type in _REGISTRY_VALUES.items():
                captured = wininet.get(name)
                if not isinstance(captured, dict):
                    raise WindowsDeploymentError("invalid WinINET rollback snapshot")
                if captured.get("exists") is True:
                    value_type = str(captured.get("type") or "")
                    value = str(captured.get("value") or "")
                    if value_type not in {"REG_DWORD", "REG_SZ", "REG_EXPAND_SZ"}:
                        raise WindowsDeploymentError("invalid WinINET rollback type")
                    self._run(
                        [
                            REG_EXE,
                            "add",
                            _INTERNET_SETTINGS,
                            "/v",
                            name,
                            "/t",
                            value_type,
                            "/d",
                            value,
                            "/f",
                        ],
                        f"restore {name}",
                    )
                else:
                    result = self._runner.run(
                        [REG_EXE, "delete", _INTERNET_SETTINGS, "/v", name, "/f"]
                    )
                    require_success(result, f"restore absent {name}")
            return

        winhttp = snapshot.get("winhttp")
        if not isinstance(winhttp, dict) or set(winhttp) != {
            "mode",
            "proxy",
            "bypass",
        }:
            raise WindowsDeploymentError("invalid WinHTTP rollback snapshot")
        if winhttp.get("mode") == "direct":
            if winhttp.get("proxy") or winhttp.get("bypass"):
                raise WindowsDeploymentError("invalid WinHTTP direct snapshot")
            self._run(
                [NETSH_EXE, "winhttp", "reset", "proxy"],
                "restore direct WinHTTP routing",
            )
            return
        if winhttp.get("mode") != "proxy":
            raise WindowsDeploymentError("invalid WinHTTP rollback mode")
        proxy = str(winhttp.get("proxy") or "")
        bypass = str(winhttp.get("bypass") or "")
        if not _safe_proxy_spec(proxy) or not _safe_bypass_spec(bypass):
            raise WindowsDeploymentError("unsafe WinHTTP rollback value")
        self._run(
            [
                NETSH_EXE,
                "winhttp",
                "set",
                "proxy",
                f"proxy-server={proxy}",
                f"bypass-list={bypass}",
            ],
            "restore WinHTTP routing",
        )
