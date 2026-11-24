"""Process collector — enumerate running processes.

Uses ``psutil`` when available for speed and richer metadata; otherwise falls back
to ``ps`` (present on macOS and Linux). Never raises — returns [] on failure so a
collection hiccup cannot crash the agent loop.
"""

from __future__ import annotations

from .base import ProcessInfo, run_cmd, _try_psutil


def list_processes() -> list[ProcessInfo]:
    psutil = _try_psutil()
    if psutil is not None:
        return _via_psutil(psutil)
    return _via_ps()


def _via_psutil(psutil) -> list[ProcessInfo]:
    out: list[ProcessInfo] = []
    for proc in psutil.process_iter(["pid", "ppid", "name", "username", "cmdline", "exe", "create_time"]):
        try:
            info = proc.info
            out.append(
                ProcessInfo(
                    pid=int(info.get("pid") or 0),
                    name=str(info.get("name") or ""),
                    user=str(info.get("username") or ""),
                    cmdline=" ".join(info.get("cmdline") or []),
                    parent_pid=int(info.get("ppid")) if info.get("ppid") is not None else None,
                    executable_path=str(info.get("exe") or "") or None,
                    process_start_time_ns=(
                        int(float(info.get("create_time")) * 1_000_000_000)
                        if info.get("create_time") is not None
                        else None
                    ),
                )
            )
        except Exception:  # noqa: BLE001 - a vanished/protected process is skipped
            continue
    return out


def _via_ps() -> list[ProcessInfo]:
    # pid, user, comm (short name), args (full command line)
    raw = run_cmd(["ps", "-axo", "pid=,user=,comm=,args="])
    out: list[ProcessInfo] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 3)
        if len(parts) < 3:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        user = parts[1]
        comm = parts[2]
        args = parts[3] if len(parts) > 3 else comm
        name = comm.rsplit("/", 1)[-1]
        out.append(ProcessInfo(pid=pid, name=name, user=user, cmdline=args))
    return out
