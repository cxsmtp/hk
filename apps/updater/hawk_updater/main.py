"""Hawk AI's updater: the ``updater`` service of deploy/compose.yaml. CxMissionZero's update companion
(src/companion/main.js), for a stack of several containers.

It is the only container with the container engine's socket, which is as powerful as the engine itself, so it does
one thing: it reads request.json in the updater folder it shares with the API (/updater) and replaces Hawk AI's
services with the same services on the images asked for (hawk_updater/update.py), or restarts them. It listens on no
port and takes no other instruction. It runs as uid 1000 with the socket's group only, no network and no capabilities.

Files in /updater (app/services/updates/companion.py is the API's side):
  updater.json   its heartbeat, every 30 s: it is there, it reaches the engine, what the services run;
  request.json   written by the API: update to {images, version} or restart (one at a time);
  status.json    where the update is, and how it ended;
  events.jsonl   every update, rollback and restart;
  ack.json       written by the API at every start: which version runs, and since when;
  images.env     the images the stack runs after an update, for deploy/install.sh.

deploy/.env (DEPLOY_ENV_FILE, mounted on its own): its HAWK_API_IMAGE, HAWK_WEB_IMAGE and HAWK_PROXY_IMAGE are set to
the images the stack runs after every update and rollback, so `docker compose up -d` never goes back to older ones.

Environment: UPDATER_DIR (/updater), ENGINE_SOCKET (/var/run/docker.sock), TARGET_PROJECT (this container's own
compose project), UPDATE_IMAGE (ghcr.io/cxsmtp/hk), UPDATE_REGISTRY_TOKEN, UPDATE_START_TIMEOUT_SECONDS (150),
INTEGRITY_OFFLINE (allow: the file check alone when GitHub cannot be reached).
"""

from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

from hawk_updater.engine import EngineClient, EngineError
from hawk_updater.update import (
    PARKED,
    Config,
    Refused,
    append_event,
    display_version,
    find_services,
    full_update,
    now_iso,
    read_json,
    repository_of,
    restart,
    write_json,
)

DEFAULT_IMAGE = "ghcr.io/cxsmtp/hk"
HEARTBEAT_SECONDS = 30
POLL_SECONDS = 5
HISTORY = 20


def own_project(engine: EngineClient, env=os.environ) -> str:
    if env.get("TARGET_PROJECT"):
        return env["TARGET_PROJECT"]
    try:
        me = engine.inspect(env.get("HOSTNAME", ""))
        return str(((me.get("Config") or {}).get("Labels") or {}).get("com.docker.compose.project") or "hawk")
    except EngineError:
        return "hawk"


def config_from_env(engine: EngineClient, env=os.environ) -> Config:
    try:
        timeout = max(30.0, float(env.get("UPDATE_START_TIMEOUT_SECONDS") or 150))
    except ValueError:
        timeout = 150.0
    return Config(
        updater_dir=Path(env.get("UPDATER_DIR") or "/updater"),
        project=own_project(engine, env),
        image_prefix=repository_of(env.get("UPDATE_IMAGE") or DEFAULT_IMAGE),
        start_timeout=timeout,
        offline_allowed=str(env.get("INTEGRITY_OFFLINE") or "").strip().lower() == "allow",
        deploy_env=Path(env["DEPLOY_ENV_FILE"]) if env.get("DEPLOY_ENV_FILE") else None,
    )


def make_wait_ready(engine, config: Config, *, poll: float = 2.0, clock=time.time, sleep=time.sleep):
    """Ready when every new container runs (and is healthy where it has a check) and the new API wrote ack.json."""

    def wait_ready(*, since: float, version: str, containers: dict[str, str]) -> None:
        deadline = since + config.start_timeout
        waiting = "the services to start"
        while True:
            pending = []
            for service, container_id in containers.items():
                state = engine.inspect(container_id).get("State") or {}
                if not state.get("Running"):
                    raise RuntimeError(f"The new {service} stopped (exit code {state.get('ExitCode', '?')}).")
                health = (state.get("Health") or {}).get("Status")
                if health and health != "healthy":
                    pending.append(service)
            ack = read_json(config.updater_dir / "ack.json") or {}
            acked = _started_after(ack, since) and (not version or ack.get("version") == version)
            if not pending and acked:
                return
            waiting = f"{', '.join(pending)} to be healthy" if pending else "the new API to say it started"
            if clock() > deadline:
                raise RuntimeError(f"Hawk AI did not come up within {round(config.start_timeout)} s (waiting for {waiting}).")
            beat_now = read_json(config.updater_dir / "updater.json")
            if isinstance(beat_now, dict):
                write_json(config.updater_dir / "updater.json", {**beat_now, "at": now_iso()})
            sleep(poll)

    return wait_ready


def _started_after(ack: dict[str, Any], since: float) -> bool:
    import datetime as dt

    try:
        started = dt.datetime.fromisoformat(str(ack.get("startedAt")).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return False
    return started >= since - 1


def heartbeat(engine, config: Config) -> dict[str, Any]:
    beat: dict[str, Any] = {"at": now_iso(), "project": config.project, "image": config.image_prefix, "engine": "", "engineError": "", "services": {}, "manages": False}
    try:
        engine.ping()
        stack = find_services(engine, config.project, config.services)
        beat["engine"] = "ok"
        beat["services"] = {s: (c.get("Config") or {}).get("Image") or "" for s, c in stack.items()}
        wrong = [f"{s} runs {img}" for s, img in beat["services"].items() if repository_of(img) != config.repository(config.services[s])]
        missing = [s for s in config.services if s not in stack]
        if missing:
            beat["engineError"] = f"Not found in the compose project \"{config.project}\": {', '.join(missing)}."
        elif wrong:
            beat["engineError"] = f"Not Hawk AI's published images ({config.image_prefix}-…): {'; '.join(wrong)}."
        else:
            beat["manages"] = True
    except EngineError as error:
        beat["engine"] = "error"
        beat["engineError"] = str(error)
    write_json(config.updater_dir / "updater.json", beat)
    return beat


def tick(engine, config: Config, *, beat: bool = True, wait_ready=None, sleep=time.sleep) -> dict[str, Any] | None:
    """One pass: the heartbeat, then the request if there is one. Returns what was done."""

    directory = config.updater_dir
    directory.mkdir(parents=True, exist_ok=True)
    if beat:
        heartbeat(engine, config)
    request_file = directory / "request.json"
    request = read_json(request_file)
    if not isinstance(request, dict):
        if request_file.exists():
            request_file.unlink(missing_ok=True)  # unreadable: never acted on
        return None
    request_file.unlink(missing_ok=True)
    action = str(request.get("action") or "update")
    status: dict[str, Any] = {
        "id": str(request.get("id") or "")[:64],
        "action": action,
        "tag": str(request.get("tag") or "")[:80],
        "version": str(request.get("version") or "")[:20],
        "by": str(request.get("by") or "")[:200],
        "automatic": bool(request.get("automatic")),
        "state": "running",
        "step": "Starting",
        "startedAt": now_iso(),
    }

    def save(**patch: Any) -> None:
        status.update(patch, at=now_iso())
        write_json(directory / "status.json", status)
        # Still here while an update runs (it can take minutes): the heartbeat stays fresh, so the API and the
        # container's health check do not take the updater for gone.
        beat_now = read_json(directory / "updater.json")
        if isinstance(beat_now, dict):
            write_json(directory / "updater.json", {**beat_now, "at": status["at"]})

    save()
    try:
        if action == "restart":
            result = restart(engine, config, step=lambda text: save(step=text), services=request.get("services"))
        elif action == "update":
            result = full_update(engine, config, request, wait_ready=wait_ready or make_wait_ready(engine, config), step=lambda text: save(step=text), sleep=sleep)
        else:
            result = {"state": "refused", "error": "Not an update or a restart."}
    except Refused as error:
        result = {"state": "refused", "error": str(error)}
    except Exception as error:  # noqa: BLE001 - nothing was changed: it failed before stopping anything
        result = {"state": "failed", "error": str(error)}
    save(**result, step="", finishedAt=now_iso())
    event = {
        "at": now_iso(),
        "type": {"done": "switch" if action == "update" else "restart", "rolled-back": "rolled-back", "unchanged": "unchanged"}.get(result["state"], result["state"]),
        "action": action,
        "from": result.get("from", ""),
        "to": result.get("to") or status["version"],
        "by": status["by"],
        "automatic": status["automatic"],
        "error": result.get("error", ""),
        "backup": result.get("backup", ""),
    }
    append_event(directory, event)
    history_file = directory / "history.json"
    history = read_json(history_file)
    write_json(history_file, [status, *(history if isinstance(history, list) else [])][:HISTORY])
    label = display_version(event["to"]) if event["to"] else action
    error = result.get("error") or ""
    print(f"[updater] {label}: {result['state']}{f' ({error})' if error else ''}", flush=True)
    return status


def main() -> int:
    socket_path = os.environ.get("ENGINE_SOCKET") or "/var/run/docker.sock"
    engine = EngineClient(socket_path, registry_token=os.environ.get("UPDATE_REGISTRY_TOKEN") or "")
    config = config_from_env(engine)
    print(f"[updater] Looking after the compose project \"{config.project}\" ({config.image_prefix}-api, -web, -proxy) through {socket_path}; requests in {config.updater_dir}.", flush=True)
    stopping = False

    def stop(*_args: Any) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    last = 0.0
    while not stopping:
        try:
            beat = time.time() - last > HEARTBEAT_SECONDS
            if beat:
                last = time.time()
            tick(engine, config, beat=beat)
        except Exception as error:  # noqa: BLE001 - said, and the next pass tries again
            print(f"! [updater] {error}", file=sys.stderr, flush=True)
        for _ in range(POLL_SECONDS * 10):
            if stopping:
                break
            time.sleep(0.1)
    return 0


__all__ = ["PARKED", "main", "tick", "heartbeat", "make_wait_ready", "config_from_env"]

if __name__ == "__main__":
    raise SystemExit(main())
