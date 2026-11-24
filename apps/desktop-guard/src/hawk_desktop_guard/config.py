from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any


DEFAULT_CONFIG_PATH = Path.home() / ".hawk" / "desktop-guard.json"


def _read_config_file(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _value(file_config: dict[str, Any], key: str, env_name: str, default: Any = None) -> Any:
    env_value = os.environ.get(env_name)
    if env_value not in (None, ""):
        return env_value
    return file_config.get(key, default)


def _bool_value(value: Any, *, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class DesktopGuardConfig:
    api_url: str = "http://127.0.0.1:8000"
    access_token: str | None = None
    email: str | None = None
    password: str | None = None
    tenant_id: str | None = None
    application: str = "Claude Desktop"
    desktop_app: str = "Claude"
    machine_id: str | None = None
    poll_seconds: float = 1.0
    dialog: bool = False

    @property
    def has_auth(self) -> bool:
        return bool(self.access_token or (self.email and self.password))

    @classmethod
    def from_file_and_env(cls, *, config_path: Path | None = None) -> "DesktopGuardConfig":
        file_config = _read_config_file(config_path or DEFAULT_CONFIG_PATH)
        return cls(
            api_url=str(_value(file_config, "api_url", "HAWK_API_URL", "http://127.0.0.1:8000")).rstrip("/"),
            access_token=_optional_text(_value(file_config, "access_token", "HAWK_ACCESS_TOKEN")),
            email=_optional_text(_value(file_config, "email", "HAWK_EMAIL")),
            password=_optional_text(_value(file_config, "password", "HAWK_PASSWORD")),
            tenant_id=_optional_text(_value(file_config, "tenant_id", "HAWK_TENANT_ID")),
            application=str(_value(file_config, "application", "HAWK_DESKTOP_APPLICATION", "Claude Desktop")),
            desktop_app=str(_value(file_config, "desktop_app", "HAWK_DESKTOP_APP", "Claude")),
            machine_id=_optional_text(_value(file_config, "machine_id", "HAWK_MACHINE_ID")),
            poll_seconds=float(_value(file_config, "poll_seconds", "HAWK_POLL_SECONDS", 1.0)),
            dialog=_bool_value(_value(file_config, "dialog", "HAWK_DIALOG", False)),
        )


def _optional_text(value: Any) -> str | None:
    token = str(value or "").strip()
    return token or None
