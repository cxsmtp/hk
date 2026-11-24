"""User-facing warning banner + action prompt.

macOS implementation shells out to ``osascript`` (no dependency). On other
platforms — or when no GUI/osascript is available — it degrades to a headless
result so callers can still record that a notice was due (``detect_only``).
"""

from __future__ import annotations

import platform
import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class BannerResult:
    shown: bool
    choice: str | None      # which action the user selected, if any
    headless: bool = False  # True when no GUI was available


def _osascript_available() -> bool:
    return platform.system() == "Darwin" and shutil.which("osascript") is not None


def show_banner(
    *,
    title: str,
    message: str,
    actions: list[str],
    default_action: str | None = None,
    timeout_seconds: int = 60,
) -> BannerResult:
    """Show a modal warning with the given action buttons; return the choice.

    ``actions`` are button labels (e.g. ["Dismiss", "Evict notetaker"]). macOS
    caps dialogs at 3 buttons, so callers should pass the two or three that matter.
    """
    buttons = actions[:3] if actions else ["Dismiss"]
    if not _osascript_available():
        return BannerResult(shown=False, choice=None, headless=True)

    default_btn = default_action if default_action in buttons else buttons[-1]
    safe_title = title.replace('"', "'")
    safe_message = message.replace('"', "'")
    button_list = ", ".join(f'"{b}"' for b in buttons)
    script = (
        f'display dialog "{safe_message}" with title "{safe_title}" '
        f'buttons {{{button_list}}} default button "{default_btn}" '
        f'with icon caution giving up after {timeout_seconds}'
    )
    try:
        completed = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            text=True,
            timeout=timeout_seconds + 5,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return BannerResult(shown=True, choice=None)

    stdout = completed.stdout or ""
    choice: str | None = None
    for token in stdout.strip().split(", "):
        if token.startswith("button returned:"):
            choice = token.split(":", 1)[1].strip()
    return BannerResult(shown=True, choice=choice)
