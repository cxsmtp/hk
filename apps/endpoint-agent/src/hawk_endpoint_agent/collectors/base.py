"""Shared collector helpers."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field


@dataclass
class ProcessInfo:
    pid: int
    name: str
    user: str = ""
    cmdline: str = ""
    parent_pid: int | None = None
    executable_path: str | None = None
    process_start_time_ns: int | None = None


@dataclass
class Connection:
    pid: int
    process_name: str
    remote_host: str
    remote_port: int = 0


@dataclass
class CollectorSnapshot:
    processes: list[ProcessInfo] = field(default_factory=list)
    connections: list[Connection] = field(default_factory=list)
    meeting_active: bool = False


def run_cmd(args: list[str], *, timeout: float = 5.0) -> str:
    """Run a command with no shell; return stdout ('' on any failure)."""
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return completed.stdout or ""
    except (subprocess.TimeoutExpired, OSError):
        return ""


def _try_psutil():
    try:
        import psutil  # type: ignore

        return psutil
    except Exception:  # noqa: BLE001
        return None
