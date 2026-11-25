"""The updater (apps/updater), ported from CxMissionZero's test/companion.test.js and generalised to Hawk AI's stack:
the request (only Hawk AI's own images), the new containers' settings, the whole update in order, the rollback when the
new version does not come up in time (with the database restored from the backup taken before), what is refused with
nothing changed, a version that failed never installed automatically again, the heartbeat and the files it shares with
the API. The container engine is a fake that keeps the same state a real one would."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "updater"))

from hawk_updater import update as up  # noqa: E402
from hawk_updater.engine import EngineError, demux  # noqa: E402
from hawk_updater.main import heartbeat, make_wait_ready, tick  # noqa: E402

PREFIX = "ghcr.io/cxsmtp/hk"


def digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def ref(kind: str, version: str) -> str:
    return f"{PREFIX}-{kind}@{digest(kind + version)}"


class FakeEngine:
    """Containers and images as the Docker API answers for them, and what each one-off container prints."""

    def __init__(self, updater_dir: Path, *, running="0.2.0"):
        self.updater_dir = updater_dir
        self.calls: list[tuple] = []
        self.boxes: dict[str, dict] = {}
        self.images: dict[str, dict] = {}
        self.pull_fails: set[str] = set()
        self.healthy_versions: set[str] = {running}
        self.crashing_versions: set[str] = set()
        self.migrate_exit: dict[str, int] = {}
        self.one_off: dict[str, tuple[int, str]] = {
            "app.cli.integrity": (0, "Every file matches the list.\nSigned by https://github.com/cxsmtp/hk/.github/workflows/release.yml@refs/heads/main"),
            "app.cli.backup": (0, "Before the update: backed up\n  → /backups/hawk-ai-2026-11-25T10-00-00.hkbackup (1234 bytes, encrypted)"),
            "app.cli.restore": (0, "Restored."),
        }
        self.one_offs: list[dict] = []
        self.counter = 0
        for kind in ("api", "web", "proxy"):
            self.add_image(kind, running)
        for service, kind in up.SERVICES.items():
            self.add_container(f"hawk-{service}-1", service, ref(kind, running), running=service != "migrate")

    def add_image(self, kind: str, version: str) -> str:
        name = ref(kind, version)
        self.images[name] = {"Id": digest(f"id-{kind}-{version}"), "RepoDigests": [name], "Config": {"Labels": {up.VERSION_LABEL: version}, "Env": ["PATH=/usr/bin", f"IMAGE_ENV={version}"], "Cmd": ["default"], "User": "1000"}}
        return name

    def add_container(self, name: str, service: str, image_ref: str, running: bool = True) -> str:
        self.counter += 1
        cid = f"c{self.counter:04d}"
        image = self.images[image_ref]
        self.boxes[cid] = {
            "Id": cid,
            "Name": f"/{name}",
            "Image": image["Id"],
            "Config": {"Image": image_ref, "Env": ["PATH=/usr/bin", f"IMAGE_ENV={image['Config']['Labels'][up.VERSION_LABEL]}", "TZ=Asia/Dubai"], "Labels": {"com.docker.compose.project": "hawk", "com.docker.compose.service": service}, "Cmd": ["serve", service], "User": "1000:1000", "StopTimeout": 15, "Healthcheck": {"Test": ["CMD", "check", service]}},
            "HostConfig": {"ReadonlyRootfs": True, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"], "RestartPolicy": {"Name": "unless-stopped"}, "Mounts": [{"Type": "volume", "Source": "hawk-data", "Target": "/data"}]},
            "NetworkSettings": {"Networks": {"hawk": {"Aliases": [name, service, cid[:12]]}}},
            "State": {"Running": running, "ExitCode": 0, "Health": {"Status": "healthy"}},
        }
        return cid

    # ---- The engine's API --------------------------------------------------------------------------------------------

    def _find(self, key: str) -> dict:
        if key in self.boxes:
            return self.boxes[key]
        for c in self.boxes.values():
            if c["Name"].lstrip("/") == key:
                return c
        raise EngineError(f"No such container: {key}", 404)

    def ping(self):
        return b"OK"

    def inspect(self, key):
        return json.loads(json.dumps(self._find(key)))

    def inspect_image(self, key):
        for name, image in self.images.items():
            if key in (name, image["Id"]):
                return json.loads(json.dumps(image))
        raise EngineError(f"No such image: {key}", 404)

    def containers(self, labels):
        project = labels[0].split("=", 1)[1]
        return [{"Id": c["Id"], "Names": [c["Name"]], "Labels": c["Config"]["Labels"], "State": "running" if c["State"]["Running"] else "exited"} for c in self.boxes.values() if c["Config"]["Labels"].get("com.docker.compose.project") == project]

    def pull(self, repository, tag):
        self.calls.append(("pull", f"{repository}@{tag}"))
        if f"{repository}@{tag}" in self.pull_fails:
            raise EngineError(f"Pulling {repository}:{tag} failed: manifest unknown")
        name = f"{repository}@{tag}"
        if name not in self.images:
            raise EngineError(f"Pulling {repository}:{tag} failed: not found")

    def create(self, name, spec):
        if any(c["Name"] == f"/{name}" for c in self.boxes.values()):
            raise EngineError(f'Conflict. The container name "/{name}" is already in use', 409)
        image = self.inspect_image(spec["Image"])
        self.counter += 1
        cid = f"n{self.counter:04d}"
        version = image["Config"]["Labels"][up.VERSION_LABEL]
        self.boxes[cid] = {"Id": cid, "Name": f"/{name}", "Image": image["Id"], "Config": {"Image": spec["Image"], "Env": image["Config"]["Env"] + spec["Env"], "Labels": spec["Labels"], "Cmd": spec.get("Cmd", image["Config"]["Cmd"]), "Healthcheck": spec.get("Healthcheck")}, "HostConfig": spec["HostConfig"], "NetworkSettings": {"Networks": {}}, "State": {"Running": False, "ExitCode": 0}, "spec": spec, "version": version}
        self.calls.append(("create", name, spec["Image"]))
        return {"Id": cid}

    def start(self, cid):
        c = self._find(cid)
        self.calls.append(("start", c["Name"].lstrip("/")))
        c["State"] = {"Running": True, "ExitCode": 0}
        version = c.get("version") or c["Config"]["Labels"].get("v") or self.inspect_image(c["Image"])["Config"]["Labels"][up.VERSION_LABEL]
        service = c["Config"]["Labels"].get("com.docker.compose.service")
        cmd = (c.get("spec") or {}).get("Cmd") or []
        if len(cmd) > 2 and cmd[:2] == ["python", "-m"]:
            self.one_offs.append({"name": c["Name"].lstrip("/"), "cmd": cmd, "image": c["Config"]["Image"], "spec": c["spec"]})
            code, _ = self.one_off[cmd[2]]
            c["State"] = {"Running": False, "ExitCode": code}
            return
        if service == "migrate":
            c["State"] = {"Running": False, "ExitCode": self.migrate_exit.get(version, 0)}
            return
        if version in self.crashing_versions:
            c["State"] = {"Running": False, "ExitCode": 1}
            return
        c["State"]["Health"] = {"Status": "healthy" if version in self.healthy_versions else "starting"}
        if service == "api" and version in self.healthy_versions:
            up.write_json(self.updater_dir / "ack.json", {"version": version, "startedAt": dt.datetime.now(dt.timezone.utc).isoformat()})

    def stop(self, cid, seconds=30):
        c = self._find(cid)
        self.calls.append(("stop", c["Name"].lstrip("/")))
        c["State"] = {**c["State"], "Running": False}

    def rename(self, cid, name):
        c = self._find(cid)
        self.calls.append(("rename", c["Name"].lstrip("/"), name))
        c["Name"] = f"/{name}"

    def remove(self, cid):
        c = self._find(cid)
        self.calls.append(("remove", c["Name"].lstrip("/")))
        del self.boxes[c["Id"]]

    def wait(self, cid, timeout):
        return self._find(cid)["State"]["ExitCode"]

    def logs(self, cid, tail=200):
        cmd = (self._find(cid).get("spec") or {}).get("Cmd") or []
        if len(cmd) > 2 and cmd[2] in self.one_off:
            return self.one_off[cmd[2]][1]
        return "migrations: done"

    # ---- What the tests look at ---------------------------------------------------------------------------------------

    def running(self) -> dict[str, str]:
        """service → the version its running container runs."""

        out = {}
        for c in self.boxes.values():
            service = c["Config"]["Labels"].get("com.docker.compose.service")
            if service and c["State"].get("Running"):
                out[service] = c.get("version") or self.inspect_image(c["Image"])["Config"]["Labels"][up.VERSION_LABEL]
        return out

    def names(self) -> list[str]:
        return sorted(c["Name"].lstrip("/") for c in self.boxes.values())


def config(tmp_path, **kw) -> up.Config:
    return up.Config(updater_dir=tmp_path / "updater", project="hawk", image_prefix=PREFIX, settle=0, **kw)


def request(version="0.3.0", **kw) -> dict:
    return {"id": "r1", "action": "update", "tag": version, "version": version, "images": {k: ref(k, version) for k in ("api", "web", "proxy")}, "by": "owner@example.com", **kw}


class Clock:
    def __init__(self):
        self.now = time.time()

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def run(engine, cfg, req, clock=None):
    clock = clock or Clock()
    steps: list[str] = []
    wait = make_wait_ready(engine, cfg, poll=5, clock=clock, sleep=clock.sleep)
    result = up.full_update(engine, cfg, req, wait_ready=wait, step=steps.append, now=clock, sleep=clock.sleep)
    return result, steps


@pytest.fixture()
def world(tmp_path):
    (tmp_path / "updater").mkdir()
    engine = FakeEngine(tmp_path / "updater")
    for kind in ("api", "web", "proxy"):
        engine.add_image(kind, "0.3.0")
    engine.healthy_versions.add("0.3.0")
    return engine, config(tmp_path)


# ---- The request and the new containers' settings ----------------------------------------------------------------------


def test_only_hawk_ais_own_images_by_digest_or_an_allowed_tag():
    assert up.image_ref_ok(f"{PREFIX}-api@{digest('x')}", f"{PREFIX}-api")
    assert up.image_ref_ok(f"{PREFIX}-web:0.3.0", f"{PREFIX}-web") and up.image_ref_ok(f"{PREFIX}-web:stable", f"{PREFIX}-web")
    for bad in (f"{PREFIX}-api:../x", f"{PREFIX}-api", f"{PREFIX}-api@sha256:short", f"{PREFIX}-evil@{digest('x')}", f"docker.io/library/alpine@{digest('x')}", f"{PREFIX}-api:latest --privileged"):
        assert not up.image_ref_ok(bad, f"{PREFIX}-api"), bad
    assert up.repository_of("GHCR.io/Org/App:1.2.3") == "ghcr.io/org/app" and up.repository_of(f"localhost:5000/hk-api@{digest('x')}") == "localhost:5000/hk-api"


def test_the_new_container_keeps_what_the_service_was_started_with_and_takes_the_rest_from_the_new_image(world):
    engine, _ = world
    api = engine.inspect("hawk-api-1")
    old = engine.inspect_image(api["Config"]["Image"])
    spec = up.clone_spec(api, old, ref("api", "0.3.0"))
    assert spec["Image"] == ref("api", "0.3.0")
    assert spec["Env"] == ["TZ=Asia/Dubai"], "the old image's own environment is not carried over"
    assert spec["Cmd"] == ["serve", "api"] and spec["User"] == "1000:1000" and spec["StopTimeout"] == 15
    assert spec["HostConfig"]["ReadonlyRootfs"] is True and spec["HostConfig"]["CapDrop"] == ["ALL"] and spec["HostConfig"]["Mounts"][0]["Target"] == "/data"
    assert spec["Labels"]["com.docker.compose.service"] == "api"
    assert spec["NetworkingConfig"]["EndpointsConfig"]["hawk"]["Aliases"] == ["hawk-api-1", "api"], "the old container's own id is not an alias"
    one = up.clone_spec(api, old, ref("api", "0.3.0"), cmd=["python", "-m", "app.cli.backup"], one_off=True)
    assert not any(k.startswith("com.docker.compose.") for k in one["Labels"]), "compose never takes a one-off for one of its services"
    assert one["HostConfig"]["RestartPolicy"] == {"Name": "no"} and one["Cmd"] == ["python", "-m", "app.cli.backup"] and one["Healthcheck"] == {"Test": ["NONE"]}
    assert one["NetworkingConfig"]["EndpointsConfig"]["hawk"] == {}, "a one-off never answers as the api"


# ---- The whole update --------------------------------------------------------------------------------------------------


def test_an_update_checks_backs_up_migrates_and_starts_every_service_in_order(world):
    engine, cfg = world
    result, steps = run(engine, cfg, request())
    assert result["state"] == "done", result
    assert result["from"] == "0.2.0" and result["to"] == "0.3.0" and result["backup"] == "/backups/hawk-ai-2026-11-25T10-00-00.hkbackup"
    assert engine.running() == {s: "0.3.0" for s in ("api", "worker", "beat", "web", "proxy")}
    # The new api image's files and signature are checked first, then the backup is taken with the version that ran.
    assert [o["cmd"][2] for o in engine.one_offs] == ["app.cli.integrity", "app.cli.backup"]
    assert engine.one_offs[0]["image"] == ref("api", "0.3.0") and engine.one_offs[0]["cmd"][-1] == "--origin"
    assert engine.one_offs[1]["image"] == engine.images[ref("api", "0.2.0")]["Id"] and engine.one_offs[1]["cmd"][-1] == "Before the update to HK-00.03.00"
    order = [c for c in engine.calls if c[0] in ("pull", "stop", "start")]
    pulls = [c for c in order if c[0] == "pull"]
    assert len(pulls) == 3 and order[:3] == pulls, "everything is downloaded while Hawk AI keeps running"
    stops = [c[1] for c in engine.calls if c[0] == "stop"]
    assert stops == ["hawk-proxy-1", "hawk-web-1", "hawk-beat-1", "hawk-worker-1", "hawk-api-1"]
    starts = [c[1] for c in engine.calls if c[0] == "start" and not c[1].split("-")[-2:-1] == ["integrity"] and "backup" not in c[1] and "integrity" not in c[1]]
    assert starts == ["hawk-migrate-1", "hawk-api-1", "hawk-worker-1", "hawk-beat-1", "hawk-web-1", "hawk-proxy-1"]
    # Nothing is left aside: the previous containers are removed (their images stay to go back to).
    assert not any(n.endswith("-previous") for n in engine.names()) and len(engine.names()) == 6
    pins = (cfg.updater_dir / "images.env").read_text()
    assert f"HAWK_API_IMAGE={ref('api', '0.3.0')}" in pins and "HAWK_RUNNING_VERSION=0.3.0" in pins
    assert "Waiting for every service to be healthy" in steps


def test_a_version_that_does_not_come_up_in_time_is_rolled_back_and_its_database_restored(world):
    engine, cfg = world
    engine.healthy_versions.discard("0.3.0")  # it starts, but never turns healthy
    clock = Clock()
    result, steps = run(engine, cfg, request(), clock)
    assert result["state"] == "rolled-back", result
    assert result["error"].startswith("Hawk AI did not come up within 150 s (waiting for api, worker, beat, web, proxy to be healthy)")
    assert result["databaseRestored"] is True
    restore = [o for o in engine.one_offs if o["cmd"][2] == "app.cli.restore"]
    assert restore and restore[0]["cmd"][3:] == ["/backups/hawk-ai-2026-11-25T10-00-00.hkbackup", "--yes"]
    assert restore[0]["image"] == engine.images[ref("api", "0.2.0")]["Id"], "restored by the version that made the backup"
    assert engine.running() == {s: "0.2.0" for s in ("api", "worker", "beat", "web", "proxy")}
    assert sorted(engine.names()) == sorted(f"hawk-{s}-1" for s in up.SERVICES), "the previous containers are back under their names"
    assert not (cfg.updater_dir / "images.env").exists()
    assert "Restoring the database from the backup taken before the update" in steps


def test_a_crash_or_failed_migration_rolls_back_too(world, tmp_path):
    engine, cfg = world
    engine.crashing_versions.add("0.3.0")
    result, _ = run(engine, cfg, request())
    assert result["state"] == "rolled-back" and "The new api stopped (exit code 1)" in result["error"]
    assert engine.running()["api"] == "0.2.0"
    # A migration that fails: the database is restored from the backup (it may have been half-changed).
    engine.crashing_versions.clear()
    engine.migrate_exit["0.3.0"] = 1
    result, _ = run(engine, cfg, request())
    assert result["state"] == "rolled-back" and "The database could not be brought to HK-00.03.00 (exit code 1" in result["error"] and result["databaseRestored"] is True
    assert engine.running() == {s: "0.2.0" for s in ("api", "worker", "beat", "web", "proxy")}


def test_nothing_is_changed_for_another_image_a_failed_download_a_refused_check_or_no_backup(world):
    engine, cfg = world
    before = json.dumps(engine.boxes, sort_keys=True)
    with pytest.raises(up.Refused, match="not ghcr.io/cxsmtp/hk-api at a digest"):
        up.full_update(engine, cfg, {**request(), "images": {**request()["images"], "api": "docker.io/evil/api:latest"}}, wait_ready=lambda **kw: None)
    with pytest.raises(up.Refused, match="names no images"):
        up.full_update(engine, cfg, {"action": "update", "images": {"api": ref("api", "0.3.0")}}, wait_ready=lambda **kw: None)
    engine.pull_fails.add(ref("web", "0.3.0"))
    with pytest.raises(EngineError, match="manifest unknown"):
        run(engine, cfg, request())
    engine.pull_fails.clear()
    assert json.dumps(engine.boxes, sort_keys=True) == before
    for code, why in ((1, "its files differ from its signed file list"), (3, "it is not signed by the release workflow"), (2, "it has no signed file list"), (4, "Allow api.github.com over HTTPS, or set INTEGRITY_OFFLINE=allow")):
        engine.one_off["app.cli.integrity"] = (code, "Not signed by the release workflow: built from refs/pull/9/merge.")
        with pytest.raises(up.Refused, match=why):
            run(engine, cfg, request())
        assert engine.running()["api"] == "0.2.0"
    # INTEGRITY_OFFLINE=allow: the file check alone, when GitHub could not be asked.
    engine.one_off["app.cli.integrity"] = (4, "Who built it is not confirmed yet: GitHub could not be reached.")
    offline = up.Config(**{**cfg.__dict__, "offline_allowed": True})
    engine.one_off["app.cli.backup"] = (1, "Cannot back up: disk full")
    result, _ = run(engine, offline, request())
    assert result["state"] == "failed" and result["error"] == "The backup before the update failed (Cannot back up: disk full): nothing was changed."
    assert engine.running() == {s: "0.2.0" for s in ("api", "worker", "beat", "web", "proxy")}
    assert not any(o["cmd"][2] == "app.cli.restore" for o in engine.one_offs)
    engine.one_off["app.cli.backup"] = (0, "  → /backups/x.hkbackup (1 bytes)")
    result, _ = run(engine, offline, request())
    assert result["state"] == "done" and result["checked"].startswith("files checked; who built it not confirmed")


def test_a_stack_that_does_not_run_the_published_images_is_never_touched(world):
    engine, cfg = world
    local = engine.add_image("api", "0.2.0")
    api = engine._find("hawk-api-1")
    api["Config"]["Image"] = "hawk-api:local"
    with pytest.raises(up.Refused, match=r'"hawk-api-1" runs hawk-api:local, not ghcr.io/cxsmtp/hk-api'):
        run(engine, cfg, request())
    api["Config"]["Image"] = local
    already = request("0.2.0")
    result, _ = run(engine, cfg, already)
    assert result["state"] == "unchanged"


# ---- The updater's loop and its files -----------------------------------------------------------------------------------


def test_a_request_is_taken_once_recorded_and_a_failed_version_never_installed_automatically_again(world):
    engine, cfg = world
    engine.healthy_versions.discard("0.3.0")
    clock = Clock()
    up.write_json(cfg.updater_dir / "request.json", request(automatic=True))
    status = tick(engine, cfg, wait_ready=make_wait_ready(engine, cfg, poll=5, clock=clock, sleep=clock.sleep), sleep=clock.sleep)
    assert status["state"] == "rolled-back" and not (cfg.updater_dir / "request.json").exists()
    saved = json.loads((cfg.updater_dir / "status.json").read_text())
    assert saved["state"] == "rolled-back" and saved["finishedAt"] and saved["by"] == "owner@example.com"
    events = up.events(cfg.updater_dir)
    assert events[-1]["type"] == "rolled-back" and events[-1]["to"] == "0.3.0" and events[-1]["automatic"] is True
    assert up.failed_versions(cfg.updater_dir) == {"0.3.0"}
    # Asked automatically again: refused, and nothing is touched.
    engine.healthy_versions.add("0.3.0")
    up.write_json(cfg.updater_dir / "request.json", request(automatic=True))
    status = tick(engine, cfg, sleep=clock.sleep)
    assert status["state"] == "refused" and "failed to start before: it is never installed automatically again" in status["error"]
    assert engine.running()["api"] == "0.2.0"
    # By hand it may be tried again.
    up.write_json(cfg.updater_dir / "request.json", request())
    status = tick(engine, cfg, wait_ready=make_wait_ready(engine, cfg, poll=5, clock=clock, sleep=clock.sleep), sleep=clock.sleep)
    assert status["state"] == "done" and engine.running()["api"] == "0.3.0"
    assert up.events(cfg.updater_dir)[-1]["type"] == "switch"
    history = json.loads((cfg.updater_dir / "history.json").read_text())
    assert [h["state"] for h in history] == ["done", "refused", "rolled-back"]
    # An unreadable request is never acted on.
    (cfg.updater_dir / "request.json").write_text("{not json")
    assert tick(engine, cfg) is None and not (cfg.updater_dir / "request.json").exists()


def test_restart_and_the_heartbeat(world):
    engine, cfg = world
    beat = heartbeat(engine, cfg)
    assert beat["engine"] == "ok" and beat["manages"] is True and beat["services"]["api"] == ref("api", "0.2.0")
    up.write_json(cfg.updater_dir / "request.json", {"id": "x", "action": "restart", "by": "owner@example.com"})
    status = tick(engine, cfg, beat=False)
    assert status["state"] == "done" and status["action"] == "restart"
    assert [c[1] for c in engine.calls if c[0] == "stop"] == ["hawk-api-1", "hawk-worker-1", "hawk-beat-1", "hawk-web-1", "hawk-proxy-1"]
    assert up.events(cfg.updater_dir)[-1]["type"] == "restart"
    engine._find("hawk-web-1")["Config"]["Image"] = "hawk-web:local"
    beat = heartbeat(engine, cfg)
    assert beat["manages"] is False and "web runs hawk-web:local" in beat["engineError"]
    assert json.loads((cfg.updater_dir / "updater.json").read_text())["manages"] is False


def test_waiting_for_the_new_api_an_older_acknowledgement_does_not_count(world):
    engine, cfg = world
    clock = Clock()
    api = engine._find("hawk-api-1")
    up.write_json(cfg.updater_dir / "ack.json", {"version": "0.3.0", "startedAt": (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)).isoformat()})
    wait = make_wait_ready(engine, cfg, poll=5, clock=clock, sleep=clock.sleep)
    with pytest.raises(RuntimeError, match="waiting for the new API to say it started"):
        wait(since=clock(), version="0.3.0", containers={"api": api["Id"]})
    up.write_json(cfg.updater_dir / "ack.json", {"version": "0.3.0", "startedAt": dt.datetime.now(dt.timezone.utc).isoformat()})
    wait(since=clock.now - 60 * 5, version="0.3.0", containers={"api": api["Id"]})


def test_the_engine_client_reads_a_containers_output():
    frame = lambda stream, text: bytes([stream, 0, 0, 0]) + len(text).to_bytes(4, "big") + text.encode()  # noqa: E731
    assert demux(frame(1, "out\n") + frame(2, "err\n")) == "out\nerr\n"
    assert demux(b"plain text") == "plain text"
    assert up.backup_file_from("x\n  → /backups/hawk-ai-1.hkbackup (12 bytes)\n") == "/backups/hawk-ai-1.hkbackup"
    assert up.display_version("0.3.0") == "HK-00.03.00"


def test_the_backup_before_an_update_goes_to_the_backup_folder_with_its_reason(tmp_path, capsys, monkeypatch):
    """What the updater runs in a one-off container of the version that ran: python -m app.cli.backup --trigger."""

    from app.cli import backup as backup_cli
    from app.services import backup_service
    from app.services.backup_key import BackupKeyStore
    from tests.test_backups import DUMP, cfg_for, fill_data

    monkeypatch.setattr(backup_service, "mail_backup_copy", lambda *a, **kw: False)
    cfg = cfg_for(tmp_path)
    fill_data(cfg.data_dir)
    (cfg.data_dir / "backup-key.json").unlink()
    BackupKeyStore(data_dir=cfg.data_dir, env={}).turn_on()
    audited: list[tuple] = []
    code = backup_cli.main(["--trigger", "Before the update to HK-00.03.00"], cfg=cfg, dump=lambda url: DUMP, audit=lambda action, reason, **kw: audited.append((action, reason)))
    assert code == 0
    out = capsys.readouterr().out
    path = up.backup_file_from(out)
    assert path.startswith(str(cfg.dir)) and Path(path).is_file(), out
    assert backup_service.last_backup(cfg)["trigger"] == "Before the update to HK-00.03.00"
    assert audited and audited[0][0] == "backup.written" and audited[0][1].startswith("Before the update to HK-00.03.00 backup written to")
