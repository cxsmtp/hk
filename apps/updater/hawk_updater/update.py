"""A whole-stack update of Hawk AI: CxMissionZero's full image update (src/companion/full-update.js), generalised from
one container to the services of deploy/compose.yaml that run Hawk AI's own images.

  1. Check the request: only Hawk AI's images (UPDATE_IMAGE-api, -web, -proxy), by digest or by a version, latest,
     stable or commit tag. A request can never name another image, add a mount or change how a container starts.
  2. Check the stack: every service to replace (migrate, api, worker, beat, web, proxy) already runs Hawk AI's image.
  3. Pull every image while Hawk AI keeps running, and check each against the digest asked for. A failed download
     changes nothing.
  4. Check the new api image's files against its signed file list, and that list's signature (python -m
     app.cli.integrity check --origin, in a one-off container of the new image). INTEGRITY_OFFLINE=allow accepts the
     file check alone when GitHub cannot be reached. Anything else is refused, and nothing is changed.
  5. Stop the services (each finishes its work, as for any stop) and keep them aside as "<name>-previous".
  6. Take a backup with the version that ran (python -m app.cli.backup, in a one-off container of the old image).
     Without a backup, nothing is changed: the services are put back.
  7. Bring the database to the new version (the migrate service, on the new image).
  8. Start api, worker, beat, web and proxy on the new images with the same settings, and wait until every one is
     healthy and the new API has written ack.json, within UPDATE_START_TIMEOUT_SECONDS (150).
  9. Otherwise: remove the new containers, restore the database from the backup of step 6 when the migrations ran,
     put the previous containers back under their names and start them. The version is marked as failed, and is
     never installed automatically again.

Standard library only.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hawk_updater.engine import EngineError

TAG = re.compile(r"^(?:\d{1,4}\.\d{1,4}\.\d{1,4}|latest|stable|sha-[0-9a-f]{7,40})$")
VERSION = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
VERSION_LABEL = "org.opencontainers.image.version"
#: Which of Hawk AI's images each service of deploy/compose.yaml runs.
SERVICES = {"migrate": "api", "api": "api", "worker": "api", "beat": "api", "web": "web", "proxy": "proxy"}
IMAGES = ("api", "web", "proxy")
STOP_ORDER = ("proxy", "web", "beat", "worker", "api")
START_ORDER = ("api", "worker", "beat", "web", "proxy")
DEFAULT_NETWORKS = {"bridge", "podman", "default", "host", "none"}
PARKED = "-previous"
COMPOSE_LABEL = "com.docker.compose."

Step = Callable[[str], None]


class Refused(Exception):
    """The update was not started: nothing was changed."""


def now_iso(now: float | None = None) -> str:
    when = dt.datetime.fromtimestamp(time.time() if now is None else now, dt.timezone.utc)
    return when.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def display_version(version: str) -> str:
    parts = [int(p) if p.isdigit() else 0 for p in str(version or "").split(".")[:3]]
    parts += [0] * (3 - len(parts))
    return "HK-" + ".".join(f"{n:02d}" for n in parts)


def repository_of(ref: Any) -> str:
    """"ghcr.io/org/app:1.2.3" or "…@sha256:…" → "ghcr.io/org/app" (lower case)."""

    value = str(ref or "").strip().lower().split("@")[0]
    slash = value.rfind("/")
    colon = value.rfind(":")
    return value[:colon] if colon > slash else value


def image_ref_ok(ref: Any, repository: str) -> bool:
    """A reference to exactly ``repository``, by digest or by an allowed tag."""

    text = str(ref or "").strip()
    if repository_of(text) != repository.lower():
        return False
    rest = text[len(repository) :]
    if rest.startswith("@"):
        return bool(DIGEST.match(rest[1:]))
    if rest.startswith(":"):
        return bool(TAG.match(rest[1:]))
    return False


def clone_spec(container: dict[str, Any], old_image: dict[str, Any] | None, image: str, *, cmd: list[str] | None = None, one_off: bool = False) -> dict[str, Any]:
    """The create request for the same container on ``image``: what the service was started with, not what the old
    image set (its environment, labels, command and so on come from the new image instead). CxMissionZero's cloneSpec,
    plus the stop timeout and signal compose sets (stop_grace_period). A one-off container (a backup, a restore, a
    check) carries no compose labels, so compose never takes it for one of its services, and never restarts."""

    cfg = container.get("Config") or {}
    img = (old_image or {}).get("Config") or {}
    image_env = set(img.get("Env") or [])
    labels = {k: v for k, v in (cfg.get("Labels") or {}).items() if (img.get("Labels") or {}).get(k) != v}
    host = dict(container.get("HostConfig") or {})
    if one_off:
        labels = {k: v for k, v in labels.items() if not k.startswith(COMPOSE_LABEL)}
        host["RestartPolicy"] = {"Name": "no"}
        host["AutoRemove"] = False
    spec: dict[str, Any] = {
        "Image": image,
        "Env": [entry for entry in cfg.get("Env") or [] if entry not in image_env],
        "Labels": labels,
        "HostConfig": host,
    }
    same = lambda a, b: json.dumps(a) == json.dumps(b)  # noqa: E731
    if cfg.get("ExposedPorts") and not same(cfg.get("ExposedPorts"), img.get("ExposedPorts")):
        spec["ExposedPorts"] = cfg["ExposedPorts"]
    if cmd is not None:
        spec["Cmd"] = cmd
    elif cfg.get("Cmd") and not same(cfg.get("Cmd"), img.get("Cmd")):
        spec["Cmd"] = cfg["Cmd"]
    if cfg.get("Entrypoint") and not same(cfg.get("Entrypoint"), img.get("Entrypoint")):
        spec["Entrypoint"] = cfg["Entrypoint"]
    if cfg.get("User") and cfg.get("User") != img.get("User"):
        spec["User"] = cfg["User"]
    if cfg.get("WorkingDir") and cfg.get("WorkingDir") != img.get("WorkingDir"):
        spec["WorkingDir"] = cfg["WorkingDir"]
    if cfg.get("Healthcheck") and not same(cfg.get("Healthcheck"), img.get("Healthcheck")) and not one_off:
        spec["Healthcheck"] = cfg["Healthcheck"]
    if one_off:
        spec["Healthcheck"] = {"Test": ["NONE"]}
    for key in ("StopTimeout", "StopSignal"):
        if cfg.get(key) not in (None, "") and cfg.get(key) != img.get(key):
            spec[key] = cfg[key]
    networks = [(name, n) for name, n in ((container.get("NetworkSettings") or {}).get("Networks") or {}).items() if name not in DEFAULT_NETWORKS]
    if networks:
        cid = str(container.get("Id") or "")
        endpoints = {}
        for name, n in networks:
            aliases = [a for a in (n or {}).get("Aliases") or [] if not cid.startswith(a)]
            endpoints[name] = {"Aliases": aliases} if aliases and not one_off else {}
        spec["NetworkingConfig"] = {"EndpointsConfig": endpoints}
    return spec


def container_name(container: dict[str, Any]) -> str:
    return str(container.get("Name") or "").lstrip("/")


@dataclass
class Config:
    updater_dir: Path
    project: str
    image_prefix: str
    start_timeout: float = 150.0
    migrate_timeout: float = 600.0
    one_off_timeout: float = 900.0
    offline_allowed: bool = False
    stop_seconds: int = 30
    settle: float = 15.0
    services: dict[str, str] = field(default_factory=lambda: dict(SERVICES))

    def repository(self, kind: str) -> str:
        return f"{self.image_prefix}-{kind}".lower()


# ---- Files shared with the API (app/services/updates/companion.py) ---------------------------------------------------


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


def append_event(updater_dir: Path, event: dict[str, Any], keep: int = 200) -> None:
    file = Path(updater_dir) / "events.jsonl"
    lines: list[str] = []
    try:
        lines = file.read_text(encoding="utf-8").splitlines()[-(keep - 1) :]
    except OSError:
        pass
    lines.append(json.dumps(event))
    temp = file.with_name(f".events.{secrets.token_hex(4)}.tmp")
    temp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(temp, 0o644)
    os.replace(temp, file)


def events(updater_dir: Path, limit: int = 500) -> list[dict[str, Any]]:
    try:
        lines = (Path(updater_dir) / "events.jsonl").read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-limit:]:
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            out.append(value)
    return out


def failed_versions(updater_dir: Path) -> set[str]:
    """Versions that did not come up and were rolled back: never installed automatically again."""

    return {str(e.get("to")) for e in events(updater_dir) if e.get("type") == "rolled-back" and e.get("to")}


def write_pins(updater_dir: Path, images: dict[str, str], version: str) -> None:
    """The images the stack now runs, for deploy/install.sh: a later run keeps them (the page's choice wins)."""

    lines = [
        "# Written by Hawk AI's updater after an update from Settings → Updates: the images the stack runs.",
        "# deploy/install.sh keeps them. Delete this file to go back to what deploy/.env says.",
        f"HAWK_API_IMAGE={images['api']}",
        f"HAWK_WEB_IMAGE={images['web']}",
        f"HAWK_PROXY_IMAGE={images['proxy']}",
        f"HAWK_RUNNING_VERSION={version}",
    ]
    file = Path(updater_dir) / "images.env"
    temp = file.with_name(f".images.{secrets.token_hex(4)}.tmp")
    temp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(temp, 0o644)
    os.replace(temp, file)


# ---- The stack -------------------------------------------------------------------------------------------------------


def find_services(engine, project: str, services: dict[str, str]) -> dict[str, dict[str, Any]]:
    """The containers of the compose project, by service (a container kept aside as "-previous" is never one)."""

    found: dict[str, dict[str, Any]] = {}
    for summary in engine.containers([f"com.docker.compose.project={project}"]):
        labels = summary.get("Labels") or {}
        service = labels.get("com.docker.compose.service")
        names = [str(n).lstrip("/") for n in summary.get("Names") or []]
        if service not in services or any(n.endswith(PARKED) for n in names):
            continue
        if labels.get("com.docker.compose.oneoff") == "True":
            continue
        current = found.get(service)
        if current is None or (summary.get("State") == "running" and current.get("State") != "running"):
            found[service] = summary
    return {service: engine.inspect(summary["Id"]) for service, summary in found.items()}


def running_version(engine, container: dict[str, Any]) -> str:
    try:
        image = engine.inspect_image(container.get("Image") or "")
    except EngineError:
        return ""
    return str(((image.get("Config") or {}).get("Labels") or {}).get(VERSION_LABEL) or "")


def run_one_off(engine, base: dict[str, Any], base_image: dict[str, Any] | None, image: str, cmd: list[str], purpose: str, timeout: float) -> tuple[int, str]:
    """A one-off container with the service's settings (mounts, secrets, environment, network) on ``image``."""

    name = f"{container_name(base).removesuffix(PARKED)}-{purpose}-{secrets.token_hex(3)}"
    created = engine.create(name, clone_spec(base, base_image, image, cmd=cmd, one_off=True))
    try:
        engine.start(created["Id"])
        code = engine.wait(created["Id"], timeout)
        output = engine.logs(created["Id"])
        return code, output
    finally:
        try:
            engine.remove(created["Id"])
        except EngineError:
            pass


def backup_file_from(output: str) -> str:
    """The backup's path, from python -m app.cli.backup's "  → /backups/<file>.hkbackup (…)" line."""

    for line in output.splitlines():
        match = re.search(r"→\s+(\S+\.hkbackup)", line)
        if match:
            return match.group(1)
    return ""


# ---- The update ------------------------------------------------------------------------------------------------------


def check_request(config: Config, request: dict[str, Any]) -> tuple[dict[str, str], str]:
    images = request.get("images")
    if not isinstance(images, dict) or set(images) != set(IMAGES):
        raise Refused("The request names no images, or other images than Hawk AI's api, web and proxy.")
    for kind, ref in images.items():
        if not image_ref_ok(ref, config.repository(kind)):
            raise Refused(f"{str(ref)[:120]} is not {config.repository(kind)} at a digest, a version, latest, stable or a commit tag: refused.")
    version = str(request.get("version") or "")
    if version and not VERSION.match(version):
        raise Refused(f"{version[:40]} is not a version.")
    if request.get("automatic") and version in failed_versions(config.updater_dir):
        raise Refused(f"{display_version(version)} failed to start before: it is never installed automatically again.")
    return {k: str(v) for k, v in images.items()}, version


def _pull(engine, ref: str) -> dict[str, Any]:
    repository = repository_of(ref)
    if "@" in ref:
        digest = ref.split("@", 1)[1]
        engine.pull(repository, digest)
        image = engine.inspect_image(ref)
        if not any(str(d).lower() == f"{repository}@{digest}" for d in image.get("RepoDigests") or []):
            raise Refused(f"{ref} does not match the digest asked for: not installed.")
        return image
    engine.pull(repository, ref.rsplit(":", 1)[1])
    return engine.inspect_image(ref)


def integrity_verdict(code: int, output: str, offline_allowed: bool) -> str:
    """'' when the new api image may run, else why not (app/cli/integrity.py's exit codes)."""

    last = (output.strip().splitlines() or [""])[-1]
    if code == 0:
        return ""
    if code == 4 and offline_allowed:
        return ""
    if code == 4:
        return f"it is not confirmed as built by the release workflow ({last}). Allow api.github.com over HTTPS, or set INTEGRITY_OFFLINE=allow to rely on the file check alone"
    if code == 1:
        return f"its files differ from its signed file list ({last})"
    if code == 2:
        return "it has no signed file list"
    if code == 3:
        return f"it is not signed by the release workflow ({last})"
    return f"its files could not be checked (exit code {code}: {last})"


def full_update(
    engine,
    config: Config,
    request: dict[str, Any],
    *,
    wait_ready: Callable[..., None],
    step: Step = lambda _text: None,
    now: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    images, version = check_request(config, request)
    target = display_version(version) if version else str(request.get("tag") or images["api"])

    step("Looking at the services")
    stack = find_services(engine, config.project, config.services)
    missing = [s for s in config.services if s not in stack]
    if missing:
        raise Refused(f"The services {', '.join(missing)} of the compose project \"{config.project}\" were not found: start Hawk AI with deploy/install.sh first.")
    for service, container in stack.items():
        wanted = config.repository(config.services[service])
        runs = repository_of((container.get("Config") or {}).get("Image"))
        if runs != wanted:
            raise Refused(f"\"{container_name(container)}\" runs {(container.get('Config') or {}).get('Image') or 'another image'}, not {wanted}: it is not replaced. Updates from this page need the published images (HAWK_RELEASE in deploy/.env).")
    from_version = running_version(engine, stack["api"])

    pulled: dict[str, dict[str, Any]] = {}
    for kind in IMAGES:
        step(f"Downloading {images[kind]} (Hawk AI keeps running)")
        pulled[kind] = _pull(engine, images[kind])
    if all(pulled[config.services[s]].get("Id") == stack[s].get("Image") for s in stack):
        return {"state": "unchanged", "reason": f"Hawk AI already runs {target}.", "from": from_version, "to": version}
    version = version or str(((pulled["api"].get("Config") or {}).get("Labels") or {}).get(VERSION_LABEL) or "")
    target = display_version(version) if version else target

    step("Checking that it is genuine")
    old_images = {s: _inspect_image(engine, c.get("Image")) for s, c in stack.items()}
    code, output = run_one_off(engine, stack["migrate"], old_images["migrate"], images["api"], ["python", "-m", "app.cli.integrity", "check", "--origin"], "integrity", config.one_off_timeout)
    why = integrity_verdict(code, output, config.offline_allowed)
    if why:
        raise Refused(f"{target} is not installed: {why}.")
    offline_note = "files checked; who built it not confirmed (INTEGRITY_OFFLINE=allow)" if code == 4 else "files and signature checked"

    # From here on, everything is put back if any step fails.
    parked: list[str] = []
    created: dict[str, str] = {}
    migrations_ran = False
    backup = ""
    try:
        step("Stopping Hawk AI: each service finishes its work and saves")
        for service in (*STOP_ORDER, "migrate"):
            container = stack[service]
            name = container_name(container)
            try:
                engine.remove(f"{name}{PARKED}")
            except EngineError:
                pass
            if service != "migrate":
                engine.stop(container["Id"], config.stop_seconds)
            engine.rename(container["Id"], f"{name}{PARKED}")
            parked.append(service)

        step(f"Backing up before the update to {target}")
        reason = f"Before the update to {target}"
        code, output = run_one_off(engine, stack["migrate"], old_images["migrate"], stack["migrate"]["Image"], ["python", "-m", "app.cli.backup", "--trigger", reason], "backup", config.one_off_timeout)
        backup = backup_file_from(output)
        if code != 0 or not backup:
            last = (output.strip().splitlines() or ["no answer"])[-1]
            raise _NothingChanged(f"The backup before the update failed ({last}): nothing was changed.")

        step(f"Bringing the database to {target}")
        migrate = stack["migrate"]
        spec = clone_spec(migrate, old_images["migrate"], images["api"])
        made = engine.create(container_name(migrate), spec)
        created["migrate"] = made["Id"]
        engine.start(made["Id"])
        migrations_ran = True
        code = engine.wait(made["Id"], config.migrate_timeout)
        if code != 0:
            tail = (engine.logs(made["Id"], 20).strip().splitlines() or [""])[-1]
            raise RuntimeError(f"The database could not be brought to {target} (exit code {code}: {tail}).")

        step(f"Starting {target} with the same settings")
        since = now()
        for service in START_ORDER:
            container = stack[service]
            spec = clone_spec(container, old_images[service], images[config.services[service]])
            made = engine.create(container_name(container), spec)
            created[service] = made["Id"]
            engine.start(made["Id"])
        step("Waiting for every service to be healthy")
        wait_ready(since=since, version=version, containers={s: created[s] for s in START_ORDER})
        sleep(config.settle)
        for service in START_ORDER:
            state = (engine.inspect(created[service]).get("State") or {})
            if not state.get("Running"):
                raise RuntimeError(f"The new {service} stopped (exit code {state.get('ExitCode', '?')}).")
    except _NothingChanged as error:
        _put_back(engine, stack, parked, created, step=step)
        return {"state": "failed", "error": str(error), "from": from_version, "to": version}
    except Exception as error:  # noqa: BLE001 - whatever went wrong, the previous version comes back
        restored = _roll_back(engine, config, stack, old_images, parked, created, migrations_ran=migrations_ran, backup=backup, step=step)
        return {"state": "rolled-back", "error": str(error), "from": from_version, "to": version, "backup": backup, "databaseRestored": restored}

    # It runs: the previous containers are no longer needed (their images stay, to go back to from the page).
    for service in parked:
        try:
            engine.remove(f"{container_name(stack[service])}{PARKED}")
        except EngineError:
            pass
    write_pins(config.updater_dir, images, version)
    return {"state": "done", "from": from_version, "to": version, "backup": backup, "checked": offline_note}


class _NothingChanged(Exception):
    pass


def _inspect_image(engine, ref: Any) -> dict[str, Any] | None:
    try:
        return engine.inspect_image(str(ref or ""))
    except EngineError:
        return None


def _remove_created(engine, created: dict[str, str]) -> None:
    for container_id in created.values():
        try:
            engine.stop(container_id, 10)
        except EngineError:
            pass
        try:
            engine.remove(container_id)
        except EngineError:
            pass


def _put_back(engine, stack: dict[str, dict[str, Any]], parked: list[str], created: dict[str, str], *, step: Step) -> None:
    step("Going back to the previous version")
    _remove_created(engine, created)
    for service in parked:
        container = stack[service]
        engine.rename(container["Id"], container_name(container))
    for service in START_ORDER:
        if service in parked:
            engine.start(stack[service]["Id"])


def _roll_back(engine, config: Config, stack, old_images, parked: list[str], created: dict[str, str], *, migrations_ran: bool, backup: str, step: Step) -> bool:
    step("Going back to the previous version")
    _remove_created(engine, created)
    restored = False
    if migrations_ran and backup:
        step("Restoring the database from the backup taken before the update")
        code, output = run_one_off(engine, stack["migrate"], old_images["migrate"], stack["migrate"]["Image"], ["python", "-m", "app.cli.restore", backup, "--yes"], "restore", config.one_off_timeout)
        restored = code == 0
        if not restored:
            print(f"! [updater] The restore of {backup} failed (exit code {code}): {(output.strip().splitlines() or [''])[-1]}", flush=True)
    for service in parked:
        container = stack[service]
        engine.rename(container["Id"], container_name(container))
    for service in START_ORDER:
        if service in parked:
            engine.start(stack[service]["Id"])
    return restored


def restart(engine, config: Config, *, step: Step = lambda _t: None) -> dict[str, Any]:
    """Restart Hawk AI's services in order (Settings → Updates: Restart Hawk AI)."""

    stack = find_services(engine, config.project, config.services)
    for service in START_ORDER:
        if service in stack:
            step(f"Restarting {service}")
            engine.stop(stack[service]["Id"], config.stop_seconds)
            engine.start(stack[service]["Id"])
    return {"state": "done"}
