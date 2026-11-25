"""The updater, the API's side (ported from CxMissionZero's src/updates/companion.js).

The updater (apps/updater, the ``updater`` service of deploy/compose.yaml) is the only container with the container
engine's socket; the API never gets it. They talk through files in the folder they share (UPDATER_DIR, /updater; on
the machine ${HAWK_DATA_DIR}/updater):

  updater.json  the updater's heartbeat: it is there, it reaches the engine, it looks after Hawk AI's services;
  request.json  written here: update to {images, version} or restart (one at a time);
  status.json   written by the updater: where the update is, and how it ended;
  events.jsonl  written by the updater: every update, rollback and restart;
  ack.json      written here at every start of the API: which version runs, and since when, so the updater knows the
                new version came up.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import secrets
from pathlib import Path
from typing import Any

#: A heartbeat older than this means the updater is not running.
HEARTBEAT_FRESH_SECONDS = 90
FINISHED = {"done", "unchanged", "rolled-back", "failed", "refused"}
#: An update under way for longer than this was stopped part-way: it no longer blocks the next one.
STALE_SECONDS = 30 * 60


def updater_dir() -> Path:
    return Path(os.environ.get("UPDATER_DIR") or "/updater")


def read_json(file: Path) -> Any:
    try:
        return json.loads(Path(file).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def write_json(file: Path, value: Any, mode: int = 0o644) -> None:
    file = Path(file)
    file.parent.mkdir(parents=True, exist_ok=True)
    temp = file.with_name(f".{file.name}.{secrets.token_hex(4)}.tmp")
    temp.write_text(json.dumps(value, indent=2), encoding="utf-8")
    os.chmod(temp, mode)
    os.replace(temp, file)


def _age_seconds(iso: Any, now: dt.datetime) -> float:
    try:
        return (now - dt.datetime.fromisoformat(str(iso).replace("Z", "+00:00"))).total_seconds()
    except ValueError:
        return float("inf")


def events(directory: Path | None = None, limit: int = 30) -> list[dict[str, Any]]:
    """The updater's events, newest first."""

    try:
        lines = ((directory or updater_dir()) / "events.jsonl").read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out: list[dict[str, Any]] = []
    for line in reversed(lines):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            out.append(value)
        if len(out) >= limit:
            break
    return out


def companion_state(directory: Path | None = None, now: dt.datetime | None = None) -> dict[str, Any]:
    """What the Updates page shows: is the updater there, does it look after the services, and the last update."""

    directory = directory or updater_dir()
    now = now or dt.datetime.now(dt.timezone.utc)
    heartbeat = read_json(directory / "updater.json")
    status = read_json(directory / "status.json")
    pending = read_json(directory / "request.json")
    heartbeat = heartbeat if isinstance(heartbeat, dict) else None
    status = status if isinstance(status, dict) else None
    pending = pending if isinstance(pending, dict) else None
    connected = bool(heartbeat) and _age_seconds(heartbeat.get("at"), now) < HEARTBEAT_FRESH_SECONDS
    return {
        "connected": connected,
        "manages": bool(connected and heartbeat and heartbeat.get("manages")),
        "heartbeat": {k: heartbeat.get(k) for k in ("at", "project", "image", "engine", "engineError", "services")} if heartbeat else None,
        "status": status,
        "pending": {k: pending.get(k) for k in ("id", "action", "version", "tag", "by", "at", "automatic")} if pending else None,
        # An update the updater never finished (it was stopped part-way) does not block updates for ever.
        "busy": bool(pending) or bool(status and status.get("state") not in FINISHED and _age_seconds(status.get("startedAt"), now) < STALE_SECONDS),
    }


def request(directory: Path | None, value: dict[str, Any], now: dt.datetime | None = None) -> dict[str, Any]:
    """Ask the updater to update or restart. One at a time, and only once it is there."""

    directory = directory or updater_dir()
    state = companion_state(directory, now)
    if not state["connected"]:
        raise UpdaterUnavailable("The updater is not running: start Hawk AI with deploy/install.sh (it starts the updater with the published images), or update with deploy/install.sh.")
    if not state["manages"]:
        why = (state["heartbeat"] or {}).get("engineError") or "it does not look after Hawk AI's services yet"
        raise UpdaterUnavailable(f"The updater cannot update this installation: {why}")
    if state["busy"]:
        raise UpdaterUnavailable("An update is already under way.")
    body = {"id": secrets.token_hex(8), "at": (now or dt.datetime.now(dt.timezone.utc)).isoformat().replace("+00:00", "Z"), **value}
    write_json(directory / "request.json", body, mode=0o600)
    return body


def acknowledge_start(version: str, directory: Path | None = None) -> bool:
    """Written at every start of the API: the updater waits for it after starting a new version."""

    try:
        write_json((directory or updater_dir()) / "ack.json", {"version": version, "startedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"), "pid": os.getpid()})
        return True
    except OSError:
        return False  # a read-only or missing folder must never stop the API starting


class UpdaterUnavailable(Exception):
    status_code = 409
