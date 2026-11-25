"""Reading and writing the API's small state files in the data folder (HAWK_DATA_DIR), so that a damaged file is never
mistaken for an empty one and a save survives a crash of the machine. Ported from CxMissionZero's src/state-file.js.

- write_state() writes a new file beside the old one, flushes it to the disk, keeps the file it replaces as
  ``<file>.bak`` (the last good copy), puts the new one in place and flushes the folder.
- read_state() gives the fallback only when there is no file and no last good copy (a new installation). A damaged
  file is put right from ``<file>.bak`` when that reads, and otherwise it stops with a StateFileError that says what
  to do. It never answers "empty" for a file that is there and cannot be read.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any


def last_good_copy(file: Path | str) -> Path:
    return Path(f"{file}.bak")


class StateFileError(RuntimeError):
    def __init__(self, file: Path, reason: str, *, holds: str = "", copy: str = "") -> None:
        bak = last_good_copy(file)
        lines = [
            f"The state file {file} {'is damaged (' + reason + ')' if reason else 'is missing'}{'. It holds ' + holds if holds else ''}.",
            f"Its last good copy, {bak}, cannot be used either ({copy})." if copy else f"There is no last good copy of it ({bak}) to use instead.",
            "Hawk AI will not start, and will not carry on as if the file were empty, so that nothing is written over it.",
            f"Restore a backup of the data folder, or start this part afresh on purpose: move {Path(file).name} out of {Path(file).parent} (somewhere safe), then start again.",
        ]
        super().__init__("\n".join(lines))
        self.file = file


def _parse(raw: bytes) -> Any:
    value = json.loads(raw.decode("utf-8").lstrip("﻿"))
    if not isinstance(value, (dict, list)):
        raise ValueError("it holds no JSON object")
    return value


def _attempt(file: Path) -> tuple[str, Any]:
    try:
        raw = file.read_bytes()
    except FileNotFoundError:
        return "missing", None
    except OSError as error:
        return "unreadable", str(error)[:160]
    try:
        return "ok", _parse(raw)
    except (ValueError, UnicodeDecodeError) as error:
        return "damaged", " ".join(str(error).split())[:160]


def read_state(file: Path | str, *, fallback: Any = None, holds: str = "") -> Any:
    file = Path(file)
    state, value = _attempt(file)
    if state == "ok":
        return value
    bak = last_good_copy(file)
    copy_state, copy_value = _attempt(bak)
    if state == "missing" and copy_state == "missing":
        return fallback
    if copy_state == "ok":
        if state != "missing":
            try:
                file.rename(file.with_name(f"{file.name}.damaged-{secrets.token_hex(4)}"))
            except OSError:
                pass
        write_state(file, copy_value, keep_last=False)
        return copy_value
    raise StateFileError(file, "" if state == "missing" else str(value), holds=holds, copy=str(copy_value or copy_state))


def _fsync_dir(directory: Path) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def write_bytes_atomic(file: Path | str, data: bytes, *, mode: int = 0o600, keep_last: bool = False) -> None:
    """Write ``data`` whole and flushed to the disk, then put it in place (the file before kept as .bak if asked)."""

    file = Path(file)
    file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = file.with_name(f".{file.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.fchmod(fd, mode)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    if keep_last and file.exists():
        try:
            os.replace(file, last_good_copy(file))
        except OSError:
            pass
    os.replace(tmp, file)
    _fsync_dir(file.parent)


def write_state(file: Path | str, value: Any, *, mode: int = 0o600, keep_last: bool = True) -> None:
    write_bytes_atomic(file, (json.dumps(value, indent=2, sort_keys=False) + "\n").encode("utf-8"), mode=mode, keep_last=keep_last)
