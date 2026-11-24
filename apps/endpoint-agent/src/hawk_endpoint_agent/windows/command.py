"""Structured, shell-free Windows command execution."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Sequence


WINDOWS_SYSTEM32 = r"C:\Windows\System32"
REG_EXE = rf"{WINDOWS_SYSTEM32}\reg.exe"
NETSH_EXE = rf"{WINDOWS_SYSTEM32}\netsh.exe"
SC_EXE = rf"{WINDOWS_SYSTEM32}\sc.exe"
SCHTASKS_EXE = rf"{WINDOWS_SYSTEM32}\schtasks.exe"
CERTUTIL_EXE = rf"{WINDOWS_SYSTEM32}\certutil.exe"
PNPUTIL_EXE = rf"{WINDOWS_SYSTEM32}\pnputil.exe"
FLTMC_EXE = rf"{WINDOWS_SYSTEM32}\fltMC.exe"
_ALLOWED_EXECUTABLES = frozenset(
    {
        REG_EXE,
        NETSH_EXE,
        SC_EXE,
        SCHTASKS_EXE,
        CERTUTIL_EXE,
        PNPUTIL_EXE,
        FLTMC_EXE,
    }
)


class WindowsDeploymentError(RuntimeError):
    """A bounded Windows deployment operation could not complete safely."""


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def error_code(self) -> str:
        return "ok" if self.ok else f"exit_{self.returncode}"


class CommandRunner:
    """Execute an explicit argv without invoking a command shell."""

    def run(
        self, argv: Sequence[str], *, timeout: float = 30.0
    ) -> CommandResult:
        command = tuple(str(value) for value in argv)
        if not command or any("\x00" in value for value in command):
            raise ValueError("invalid Windows command")
        if command[0] not in _ALLOWED_EXECUTABLES:
            raise ValueError("Windows command must use a fixed System32 executable")
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise WindowsDeploymentError("Windows command could not run") from exc
        return CommandResult(
            argv=command,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )


def require_success(result: CommandResult, operation: str) -> CommandResult:
    if not result.ok:
        raise WindowsDeploymentError(f"{operation} failed ({result.error_code})")
    return result
