from __future__ import annotations

import sys

from .base import ClipboardCollector


def default_collector(*, application: str, desktop_app: str, machine_id: str | None = None):
    if sys.platform == "darwin":
        from .macos import MacClaudeCollector

        return MacClaudeCollector(application=application, desktop_app=desktop_app, machine_id=machine_id)
    if sys.platform.startswith("win"):
        from .windows import WindowsClaudeCollector

        return WindowsClaudeCollector(application=application, desktop_app=desktop_app, machine_id=machine_id)
    return ClipboardCollector(application=application, desktop_app=desktop_app, os_type=sys.platform, machine_id=machine_id)
