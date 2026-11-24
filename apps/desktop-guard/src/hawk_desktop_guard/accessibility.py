from __future__ import annotations

import subprocess
from typing import Callable


ShellRunner = Callable[[list[str]], str]


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=2.0)
    except Exception:
        return ""
    return result.stdout.strip()


class MacAccessibilityController:
    def __init__(self, *, shell: ShellRunner | None = None) -> None:
        self.shell = shell or _run

    def active_app_name(self) -> str | None:
        value = self.shell(
            [
                "osascript",
                "-e",
                'tell application "System Events" to get name of first application process whose frontmost is true',
            ]
        )
        return value or None

    def read_focused_text(self) -> str:
        script = """
tell application "System Events"
  set frontApp to first application process whose frontmost is true
  try
    set focusedElement to value of attribute "AXFocusedUIElement" of frontApp
    try
      set roleName to value of attribute "AXRole" of focusedElement
      if roleName is not "AXTextArea" and roleName is not "AXTextField" and roleName is not "AXComboBox" then
        return ""
      end if
    on error
      return ""
    end try
    try
      return value of focusedElement
    on error
      return ""
    end try
  on error
    return ""
  end try
end tell
""".strip()
        return self.shell(["osascript", "-e", script]).strip()

    def clear_focused_text(self) -> bool:
        script = """
tell application "System Events"
  set frontApp to first application process whose frontmost is true
  try
    set focusedElement to value of attribute "AXFocusedUIElement" of frontApp
    try
      set roleName to value of attribute "AXRole" of focusedElement
      if roleName is not "AXTextArea" and roleName is not "AXTextField" and roleName is not "AXComboBox" then
        return ""
      end if
    on error
      return ""
    end try
    set value of focusedElement to ""
    return "cleared"
  on error
    return ""
  end try
end tell
""".strip()
        if self.shell(["osascript", "-e", script]).strip() == "cleared":
            return True
        return self.clear_with_keyboard_fallback()

    def clear_with_keyboard_fallback(self) -> bool:
        script = """
tell application "System Events"
  try
    key code 53
    delay 0.05
    keystroke "a" using command down
    delay 0.05
    key code 51
    delay 0.05
    return "cleared"
  on error
    return ""
  end try
end tell
""".strip()
        return self.shell(["osascript", "-e", script]).strip() == "cleared"

    def accessibility_status(self) -> str:
        script = """
tell application "System Events"
  try
    get name of first application process whose frontmost is true
    return "available"
  on error
    return "permission_required"
  end try
end tell
""".strip()
        value = self.shell(["osascript", "-e", script]).strip()
        return value if value in {"available", "permission_required"} else "unknown"
