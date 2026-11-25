from __future__ import annotations

from typing import Protocol

from ..accessibility import MacAccessibilityController
from ..models import PromptSnapshot
from .base import ClipboardCollector


class AccessibilityController(Protocol):
    def active_app_name(self) -> str | None: ...

    def read_focused_text(self) -> str: ...

    def clear_focused_text(self) -> bool: ...

    def accessibility_status(self) -> str: ...


class MacClaudeCollector(ClipboardCollector):
    def __init__(
        self,
        *,
        application: str,
        desktop_app: str,
        machine_id: str | None = None,
        accessibility_controller: AccessibilityController | None = None,
    ) -> None:
        super().__init__(application=application, desktop_app=desktop_app, os_type="macos", machine_id=machine_id)
        self.accessibility_controller = accessibility_controller or MacAccessibilityController()

    def collect(self) -> PromptSnapshot | None:
        active_window_title = self._active_window_title()
        if active_window_title and not self._is_target_app_active(active_window_title):
            return None

        focused_text = self.accessibility_controller.read_focused_text()
        if focused_text.strip():
            return PromptSnapshot(
                application=self.application,
                desktop_app=self.desktop_app,
                prompt_text=focused_text,
                capture_method="macos_accessibility",
                machine_id=self.machine_id,
                os_type=self.os_type,
                active_window_title=active_window_title,
            )
        if self.accessibility_controller.accessibility_status() == "available":
            return None
        return super().collect()

    def clear_prompt(self) -> None:
        if self.accessibility_controller.clear_focused_text():
            return
        super().clear_prompt()

    def _active_window_title(self) -> str | None:
        return self.accessibility_controller.active_app_name()
