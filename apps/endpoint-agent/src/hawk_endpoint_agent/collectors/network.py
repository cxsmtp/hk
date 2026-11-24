"""Network collector — active outbound connections keyed to a process.

psutil when available; otherwise ``lsof -i -nP``. Remote hosts are captured as-is
(IP or resolved name); notetaker/AI matching is corroborating evidence on top of
the primary process-name signal, not the sole basis for a decision.
"""

from __future__ import annotations

import re
import subprocess

from .base import Connection, ProcessInfo, _try_psutil


class ConnectionInventory(list[Connection]):
    """List-compatible observations with explicit collection completeness."""
    def __init__(self, *, status: str = "complete", error: str | None = None):
        super().__init__()
        self.collection_status = status
        self.error_code = error

_LSOF_REMOTE = re.compile(r"->([^:\s]+):(\d+)")


def list_connections(processes: list[ProcessInfo] | None = None) -> list[Connection]:
    psutil = _try_psutil()
    if psutil is not None:
        return _via_psutil(psutil)
    return _via_lsof(processes or [])


def _via_psutil(psutil) -> list[Connection]:
    out = ConnectionInventory()
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as exc:  # noqa: BLE001 - never emit raw OS exception data
        denied = isinstance(exc, PermissionError) or type(exc).__name__ == "AccessDenied"
        return ConnectionInventory(status="unavailable", error="permission_denied" if denied else "collection_failed")
    for conn in conns:
        if not conn.raddr:
            continue
        name = ""
        try:
            if conn.pid:
                name = psutil.Process(conn.pid).name()
        except Exception:  # noqa: BLE001
            name = ""
        out.append(
            Connection(
                pid=int(conn.pid or 0),
                process_name=name,
                remote_host=str(conn.raddr.ip),
                remote_port=int(conn.raddr.port or 0),
            )
        )
    return out


def _via_lsof(processes: list[ProcessInfo]) -> list[Connection]:
    by_pid = {p.pid: p.name for p in processes}
    try:
        result = subprocess.run(["lsof", "-i", "-nP"], capture_output=True, text=True, timeout=5, check=False)
    except subprocess.TimeoutExpired:
        return ConnectionInventory(status="unavailable", error="collection_timeout")
    except OSError:
        return ConnectionInventory(status="unavailable", error="collector_unavailable")
    # lsof returns 1 with no output for an empty selection; stderr is never retained.
    if result.returncode not in {0, 1} or (result.returncode == 1 and result.stderr):
        return ConnectionInventory(status="unavailable", error="collection_failed")
    raw = result.stdout
    out = ConnectionInventory(status="partial" if result.stderr else "complete",
                              error="collector_warning" if result.stderr else None)
    for line in raw.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        command = parts[0]
        try:
            pid = int(parts[1])
        except ValueError:
            continue
        match = _LSOF_REMOTE.search(line)
        if not match:
            continue
        host, port = match.group(1), match.group(2)
        out.append(
            Connection(
                pid=pid,
                process_name=by_pid.get(pid, command),
                remote_host=host,
                remote_port=int(port),
            )
        )
    return out
