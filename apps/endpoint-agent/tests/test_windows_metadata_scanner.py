from __future__ import annotations

import json

from hawk_endpoint_agent.metadata_scanner import (
    collect_platform_endpoint_metadata,
)
from hawk_endpoint_agent.windows_metadata_scanner import (
    collect_windows_endpoint_metadata,
)


class _FakeWindowsRegistry:
    def uninstall_entries(self):
        return (
            {"display_name": "Cursor", "display_version": "0.50.1"},
            {"display_name": "Codex CLI", "display_version": "0.12.0"},
            {"display_name": "Unrelated App", "display_version": "99.0"},
            {"display_name": "Claude Code", "display_version": "sk-secret"},
        )


def test_windows_registry_inventory_emits_only_allowlisted_product_facts() -> None:
    report = collect_windows_endpoint_metadata(registry=_FakeWindowsRegistry())

    products = {item["id"]: item for item in report["products"]}
    assert products["cursor"]["presence"] == "present"
    assert products["cursor"]["version"] == "0.50.1"
    assert products["codex_cli"]["presence"] == "present"
    assert products["codex_cli"]["version"] == "0.12.0"
    assert products["claude_code"]["presence"] == "present"
    assert products["claude_code"]["version"] == "unknown"
    assert report["extensions"] == []
    assert report["configurations"] == []
    assert report["network_used"] is False
    assert report["privacy"] == {
        "raw_file_contents_collected": False,
        "prompts_collected": False,
        "browser_history_collected": False,
        "cookies_collected": False,
        "secrets_or_tokens_collected": False,
        "account_identifiers_collected": False,
        "persistent_state_written": False,
    }

    serialized = json.dumps(report, sort_keys=True)
    assert "Unrelated App" not in serialized
    assert "sk-secret" not in serialized


def test_platform_selector_uses_the_windows_metadata_contract(monkeypatch) -> None:
    expected = {
        "schema_version": "hawk.endpoint_metadata.v1",
        "platform": "windows",
    }
    monkeypatch.setattr(
        "hawk_endpoint_agent.windows_metadata_scanner.collect_windows_endpoint_metadata",
        lambda: expected,
    )

    assert collect_platform_endpoint_metadata(platform="win32") is expected
