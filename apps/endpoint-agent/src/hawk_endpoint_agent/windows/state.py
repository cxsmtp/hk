"""Credential-free, atomic Windows deployment rollback state."""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


_FORBIDDEN_KEY_PARTS = (
    "authorization",
    "credential",
    "password",
    "private_key",
    "refresh",
    "secret",
    "token",
)
_PROXY_USERINFO = re.compile(
    r"(?i)(?:\b[a-z][a-z0-9+.-]*://)?[a-z0-9._~-]+:[^\s/@;]+@"
)


def contains_credentials(value: object, *, key: str = "") -> bool:
    normalized_key = key.strip().lower()
    if any(part in normalized_key for part in _FORBIDDEN_KEY_PARTS):
        return value not in (None, "", False, [], {})
    if isinstance(value, dict):
        return any(
            contains_credentials(item, key=str(item_key))
            for item_key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(contains_credentials(item) for item in value)
    if isinstance(value, str):
        return _PROXY_USERINFO.search(value) is not None
    return False


@dataclass(frozen=True)
class WindowsInstallState:
    version: int = 2
    deployment_mode: str = "user_pilot"
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    config_path: str = ""
    routing_snapshot: dict[str, Any] = field(default_factory=dict)
    trust_thumbprint: str = ""
    autostart_installed: bool = False
    native_driver_installed: bool = False
    native_driver_published_name: str = ""
    completed_steps: list[str] = field(default_factory=list)


class InstallStateStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def save(self, state: WindowsInstallState) -> None:
        payload = asdict(state)
        if contains_credentials(payload):
            raise ValueError("Windows rollback state must not contain credentials")
        if state.deployment_mode not in {"user_pilot", "managed_machine"}:
            raise ValueError("unsupported Windows deployment mode")
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        try:
            temporary.write_text(serialized, encoding="utf-8")
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def load(self) -> WindowsInstallState | None:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except json.JSONDecodeError as exc:
            raise ValueError("invalid Windows installation state") from exc
        if not isinstance(payload, dict):
            raise ValueError("invalid Windows installation state")
        if contains_credentials(payload):
            raise ValueError("invalid or credential-bearing Windows installation state")
        if payload.get("version") == 1:
            payload = {
                **payload,
                "version": 2,
                "native_driver_installed": False,
                "native_driver_published_name": "",
                "completed_steps": [],
            }
        expected = set(WindowsInstallState.__dataclass_fields__)
        if set(payload) != expected:
            raise ValueError("invalid or credential-bearing Windows installation state")
        try:
            state = WindowsInstallState(**payload)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid Windows installation state") from exc
        if state.version != 2 or state.deployment_mode not in {
            "user_pilot",
            "managed_machine",
        }:
            raise ValueError("unsupported Windows installation state")
        return state

    def remove(self) -> None:
        self.path.unlink(missing_ok=True)
