from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hawk_desktop_guard.accessibility import MacAccessibilityController
from hawk_desktop_guard.collectors.macos import MacClaudeCollector


class FakeShell:
    def __init__(self, responses: dict[str, str]) -> None:
        self.responses = responses
        self.commands: list[list[str]] = []

    def __call__(self, command: list[str]) -> str:
        self.commands.append(command)
        script = command[-1]
        for key, value in self.responses.items():
            if key in script:
                return value
        return ""


def test_accessibility_controller_reads_focused_text() -> None:
    shell = FakeShell({"AXFocusedUIElement": "secret prompt"})
    controller = MacAccessibilityController(shell=shell)

    assert controller.read_focused_text() == "secret prompt"
    script = shell.commands[0][-1]
    assert "AXRole" in script
    assert "AXTextArea" in script
    assert "AXTextField" in script


def test_accessibility_controller_clears_focused_text() -> None:
    shell = FakeShell({"set value of focusedElement": "cleared"})
    controller = MacAccessibilityController(shell=shell)

    assert controller.clear_focused_text() is True
    script = shell.commands[0][-1]
    assert "AXRole" in script
    assert "AXTextArea" in script
    assert "AXTextField" in script


def test_accessibility_controller_uses_keyboard_fallback_when_direct_clear_fails() -> None:
    shell = FakeShell({"key code 53": "cleared"})
    controller = MacAccessibilityController(shell=shell)

    assert controller.clear_focused_text() is True
    scripts = [command[-1] for command in shell.commands]
    assert any("key code 53" in script for script in scripts)
    assert any("keystroke \"a\" using command down" in script for script in scripts)
    assert any("key code 51" in script for script in scripts)


def test_mac_collector_clear_prompt_falls_back_to_clipboard_when_accessibility_fails() -> None:
    class FakeController:
        def active_app_name(self) -> str | None:
            return "Claude"

        def read_focused_text(self) -> str:
            return "typed prompt"

        def clear_focused_text(self) -> bool:
            return False

        def accessibility_status(self) -> str:
            return "available"

    class FakeCollector(MacClaudeCollector):
        def __init__(self) -> None:
            super().__init__(
                application="Claude Desktop",
                desktop_app="Claude",
                accessibility_controller=FakeController(),
            )
            self.clipboard_clears = 0

        def _set_clipboard_text(self, value: str) -> None:
            self.clipboard_clears += 1

    collector = FakeCollector()

    collector.clear_prompt()

    assert collector.clipboard_clears == 1


def test_mac_collector_prefers_accessibility_prompt_over_clipboard() -> None:
    class FakeController:
        def active_app_name(self) -> str | None:
            return "Claude"

        def read_focused_text(self) -> str:
            return "typed secret prompt"

        def clear_focused_text(self) -> bool:
            return True

        def accessibility_status(self) -> str:
            return "available"

    collector = MacClaudeCollector(
        application="Claude Desktop",
        desktop_app="Claude",
        accessibility_controller=FakeController(),
    )

    snapshot = collector.collect()

    assert snapshot is not None
    assert snapshot.prompt_preview_redacted == "typed secret prompt"
    assert snapshot.capture_method == "macos_accessibility"


def test_mac_collector_falls_back_to_clipboard_when_accessibility_empty() -> None:
    class FakeController:
        def active_app_name(self) -> str | None:
            return "Claude"

        def read_focused_text(self) -> str:
            return ""

        def clear_focused_text(self) -> bool:
            return False

        def accessibility_status(self) -> str:
            return "permission_required"

    class FakeCollector(MacClaudeCollector):
        def _clipboard_text(self) -> str:
            return "clipboard secret prompt"

    collector = FakeCollector(
        application="Claude Desktop",
        desktop_app="Claude",
        accessibility_controller=FakeController(),
    )

    snapshot = collector.collect()

    assert snapshot is not None
    assert snapshot.prompt_preview_redacted == "clipboard secret prompt"
    assert snapshot.capture_method == "clipboard"


def test_mac_collector_does_not_use_stale_clipboard_when_accessibility_available_but_input_empty() -> None:
    class FakeController:
        def active_app_name(self) -> str | None:
            return "Claude"

        def read_focused_text(self) -> str:
            return ""

        def clear_focused_text(self) -> bool:
            return False

        def accessibility_status(self) -> str:
            return "available"

    class FakeCollector(MacClaudeCollector):
        def _clipboard_text(self) -> str:
            return "stale clipboard code"

    collector = FakeCollector(
        application="Claude Desktop",
        desktop_app="Claude",
        accessibility_controller=FakeController(),
    )

    assert collector.collect() is None


def test_mac_collector_clear_prompt_uses_accessibility_before_clipboard() -> None:
    class FakeController:
        def __init__(self) -> None:
            self.clear_calls = 0

        def active_app_name(self) -> str | None:
            return "Claude"

        def read_focused_text(self) -> str:
            return "typed prompt"

        def clear_focused_text(self) -> bool:
            self.clear_calls += 1
            return True

        def accessibility_status(self) -> str:
            return "available"

    controller = FakeController()
    collector = MacClaudeCollector(
        application="Claude Desktop",
        desktop_app="Claude",
        accessibility_controller=controller,
    )

    collector.clear_prompt()

    assert controller.clear_calls == 1
