from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hawk_desktop_guard.diagnostics import build_diagnostics


class FakeCollector:
    application = "Claude Desktop"
    desktop_app = "Claude"

    def _active_window_title(self) -> str:
        return "Claude"

    def _clipboard_text(self) -> str:
        return "clipboard text"

    def collect(self):
        return None


def test_build_diagnostics_reports_active_app_clipboard_and_snapshot() -> None:
    payload = build_diagnostics(FakeCollector())

    assert payload["application"] == "Claude Desktop"
    assert payload["desktop_app"] == "Claude"
    assert payload["active_app"] == "Claude"
    assert payload["clipboard_length"] == 14
    assert payload["snapshot"] is None
