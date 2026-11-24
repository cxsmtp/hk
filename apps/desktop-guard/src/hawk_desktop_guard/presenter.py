from __future__ import annotations

import subprocess
from typing import Callable

from .models import GuardDecision, PromptSnapshot


ShellRunner = Callable[[list[str]], str]


class ConsolePresenter:
    def show(self, decision: GuardDecision, snapshot: PromptSnapshot) -> None:
        reason = ", ".join(decision.reason_codes) or "policy_decision"
        print(
            f"Hawk Desktop Guard: {decision.decision.upper()} for {snapshot.application} "
            f"({reason})"
        )

    def show_error(self, error: Exception, snapshot: PromptSnapshot) -> None:
        print(f"Hawk Desktop Guard: BACKEND ERROR for {snapshot.application} ({error})")


class MacDialogPresenter(ConsolePresenter):
    def __init__(self, *, shell: ShellRunner | None = None) -> None:
        self.shell = shell or self._run

    def show(self, decision: GuardDecision, snapshot: PromptSnapshot) -> None:
        reason = ", ".join(decision.reason_codes) or "policy_decision"
        self._dialog(
            title=f"Hawk Desktop Guard: {decision.decision.upper()}",
            message=f"{decision.decision.upper()} for {snapshot.application}\n\n{reason}",
        )

    def show_error(self, error: Exception, snapshot: PromptSnapshot) -> None:
        return None

    def _dialog(self, *, title: str, message: str) -> None:
        script = (
            f'display dialog {_applescript_string(message)} '
            f'with title {_applescript_string(title)} buttons {{"OK"}} default button "OK"'
        )
        self.shell(["osascript", "-e", script])

    @staticmethod
    def _run(command: list[str]) -> str:
        try:
            result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=10.0)
        except Exception:
            return ""
        return result.stdout.strip()


def _applescript_string(value: str) -> str:
    escaped = str(value or "").replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'
