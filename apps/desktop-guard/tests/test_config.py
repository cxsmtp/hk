from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hawk_desktop_guard.config import DesktopGuardConfig


def test_config_loads_json_file_and_env_overrides(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "desktop-guard.json"
    config_path.write_text(
        json.dumps(
            {
                "api_url": "http://api.local:8000",
                "email": "owner@example.com",
                "password": "Password123!",
                "tenant_id": "tenant-file",
                "application": "Claude Desktop",
                "desktop_app": "Claude",
                "poll_seconds": 2.5,
                "dialog": True,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("HAWK_TENANT_ID", "tenant-env")
    monkeypatch.setenv("HAWK_POLL_SECONDS", "0.5")

    config = DesktopGuardConfig.from_file_and_env(config_path=config_path)

    assert config.api_url == "http://api.local:8000"
    assert config.email == "owner@example.com"
    assert config.password == "Password123!"
    assert config.tenant_id == "tenant-env"
    assert config.application == "Claude Desktop"
    assert config.desktop_app == "Claude"
    assert config.poll_seconds == 0.5
    assert config.dialog is True


def test_config_requires_token_or_credentials(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "desktop-guard.json"
    config_path.write_text(json.dumps({"api_url": "http://api.local:8000"}), encoding="utf-8")
    monkeypatch.delenv("HAWK_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("HAWK_EMAIL", raising=False)
    monkeypatch.delenv("HAWK_PASSWORD", raising=False)

    config = DesktopGuardConfig.from_file_and_env(config_path=config_path)

    assert config.has_auth is False
