from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hawk_desktop_guard.collectors.base import ClipboardCollector


class FakeClipboardCollector(ClipboardCollector):
    def __init__(self, *, active_title: str | None, clipboard: str) -> None:
        super().__init__(application="Claude Desktop", desktop_app="Claude", os_type="test", machine_id="machine-1")
        self.active_title = active_title
        self.clipboard = clipboard

    def _clipboard_text(self) -> str:
        return self.clipboard

    def _active_window_title(self) -> str | None:
        return self.active_title


def test_clipboard_collector_ignores_clipboard_when_target_app_not_active() -> None:
    collector = FakeClipboardCollector(active_title="Notes", clipboard="Here is a prompt")

    assert collector.collect() is None


def test_clipboard_collector_collects_when_target_app_is_active() -> None:
    collector = FakeClipboardCollector(active_title="Claude", clipboard="Summarize this")

    snapshot = collector.collect()

    assert snapshot is not None
    assert snapshot.application == "Claude Desktop"
    assert snapshot.prompt_preview_redacted == "Summarize this"


def test_clipboard_collector_reads_macos_clipboard_alias() -> None:
    class MacLikeCollector(ClipboardCollector):
        def __init__(self) -> None:
            super().__init__(application="Claude Desktop", desktop_app="Claude", os_type="macos", machine_id="machine-1")
            self.commands: list[list[str]] = []

        def _active_window_title(self) -> str | None:
            return "Claude"

        def _run(self, command: list[str]) -> str:
            self.commands.append(command)
            return "Please analyze this production API key: sk-live-1234567890abcdef"

    collector = MacLikeCollector()

    snapshot = collector.collect()

    assert snapshot is not None
    assert snapshot.prompt_preview_redacted.startswith("Please analyze this production API key")
    assert collector.commands == [["pbpaste"]]
