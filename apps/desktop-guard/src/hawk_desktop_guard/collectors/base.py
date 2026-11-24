from __future__ import annotations

import os
import platform
import socket
import subprocess

from ..models import PromptSnapshot


class ClipboardCollector:
    def __init__(
        self,
        *,
        application: str,
        desktop_app: str,
        os_type: str | None = None,
        machine_id: str | None = None,
    ) -> None:
        self.application = application
        self.desktop_app = desktop_app
        self.os_type = os_type or platform.system().lower()
        self.machine_id = machine_id or socket.gethostname()

    def collect(self) -> PromptSnapshot | None:
        active_window_title = self._active_window_title()
        if active_window_title and not self._is_target_app_active(active_window_title):
            return None
        prompt = self._clipboard_text()
        if not prompt:
            return None
        return PromptSnapshot(
            application=self.application,
            desktop_app=self.desktop_app,
            prompt_text=prompt,
            prompt_preview_redacted=prompt,
            capture_method="clipboard",
            machine_id=self.machine_id,
            os_type=self.os_type,
            os_version=platform.platform(),
            hostname=socket.gethostname(),
            active_window_title=active_window_title,
        )

    def clear_prompt(self) -> None:
        self._set_clipboard_text("")

    def _clipboard_text(self) -> str:
        if os.name == "nt":
            return self._run(["powershell", "-NoProfile", "-Command", "Get-Clipboard"])
        if self.os_type in {"darwin", "macos"}:
            return self._run(["pbpaste"])
        return ""

    def _set_clipboard_text(self, value: str) -> None:
        if os.name == "nt":
            self._run(["powershell", "-NoProfile", "-Command", f"Set-Clipboard -Value {value!r}"])
        elif self.os_type in {"darwin", "macos"}:
            subprocess.run(["pbcopy"], input=value, text=True, check=False)

    def _active_window_title(self) -> str | None:
        return None

    def _is_target_app_active(self, active_window_title: str) -> bool:
        title = active_window_title.lower()
        return self.application.lower() in title or self.desktop_app.lower() in title

    @staticmethod
    def _run(command: list[str]) -> str:
        try:
            result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=2.0)
        except Exception:
            return ""
        return result.stdout.strip()
