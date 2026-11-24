"""Process control — terminate / quarantine a process (the notetaker "kick").

Termination works for processes owned by the same user (the common case for a
notetaker running on the employee's laptop). Cross-user or system processes need
root; the enforcer reports that honestly instead of silently failing.
"""

from __future__ import annotations

import os
import signal
import time
from dataclasses import dataclass


@dataclass
class TerminationResult:
    performed: bool
    pid: int
    method: str          # "sigterm" | "sigkill" | "denied" | "not_found" | "disabled"
    detail: str = ""


class ProcessControl:
    def __init__(self, *, enabled: bool) -> None:
        self._enabled = enabled

    def capability(self) -> dict[str, object]:
        return {"can_terminate_same_user": self._enabled, "requires_root_for_other_users": True}

    def terminate(self, pid: int, *, escalate_after: float = 3.0) -> TerminationResult:
        """Graceful SIGTERM, escalating to SIGKILL if the process survives."""
        if not self._enabled:
            return TerminationResult(False, pid, "disabled", "process termination disabled by policy/config")
        if pid <= 0:
            return TerminationResult(False, pid, "not_found", "invalid pid")
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return TerminationResult(False, pid, "not_found", "process already exited")
        except PermissionError:
            return TerminationResult(False, pid, "denied", "insufficient privileges (likely different user / needs root)")

        deadline = time.time() + escalate_after
        while time.time() < deadline:
            if not self._alive(pid):
                return TerminationResult(True, pid, "sigterm")
            time.sleep(0.2)

        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return TerminationResult(True, pid, "sigterm")
        except PermissionError:
            return TerminationResult(False, pid, "denied", "SIGKILL denied")
        return TerminationResult(True, pid, "sigkill")

    @staticmethod
    def _alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True
