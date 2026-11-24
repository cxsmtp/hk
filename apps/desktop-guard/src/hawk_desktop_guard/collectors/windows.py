from __future__ import annotations

from .base import ClipboardCollector


class WindowsClaudeCollector(ClipboardCollector):
    def __init__(self, *, application: str, desktop_app: str, machine_id: str | None = None) -> None:
        super().__init__(application=application, desktop_app=desktop_app, os_type="windows", machine_id=machine_id)

    def _active_window_title(self) -> str | None:
        title = self._run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-Process | Where-Object {$_.MainWindowTitle -ne ''} | Select-Object -First 1 -ExpandProperty MainWindowTitle)",
            ]
        )
        return title or None
