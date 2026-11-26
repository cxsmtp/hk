"""Self-recovery and the diagnostics bundle (app/services/self_recovery.py, app/services/diagnostics_bundle.py,
app/api/routers/diagnostics.py): the error journal and its redaction, each recovery signature with its limit and
circuit breaker, a failed or unhealthy update rolled back and checked, an unknown failure handed to the OEM, the bundle
(its redaction, its manifest and signature, what each role gets), and tenant users never seeing the installation's raw
job errors."""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import logging
import os
import tarfile
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core import log_config
from app.db.models.audit import AuditLog
from app.db.models.job_run import ScheduledJobRun
from app.db.session import Base
from app.services import diagnostics_bundle, self_recovery
from app.services.evidence_signing import EvidenceSigning, verify_envelope
from app.services.self_recovery import NEEDS_OEM, SIGNATURES, SelfRecovery, classify_line

UTC = dt.timezone.utc
SECRET = "sk-live-abcdefghijklmnop1234567890"


def iso(moment: dt.datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Clock:
    def __init__(self) -> None:
        self.at = dt.datetime.now(UTC).replace(microsecond=0)

    def __call__(self) -> dt.datetime:
        return self.at

    def advance(self, seconds: float) -> None:
        self.at += dt.timedelta(seconds=seconds)


@pytest.fixture()
def world(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'r.sqlite3'}", connect_args={"check_same_thread": False})
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    data = tmp_path / "data"
    updater = tmp_path / "updater"
    data.mkdir()
    updater.mkdir()
    clock = Clock()
    probes: dict[str, Any] = {"database": True, "redis": True, "worker": True, "beat": True, "disk": {"freeMB": 50_000, "totalMB": 100_000, "low": False}}
    calls: dict[str, list[Any]] = {"send": [], "install": [], "bundle": [], "reconnect_db": [], "reconnect_redis": [], "locks": []}
    hooks: dict[str, Any] = {"schema": {"healthy": True}, "after_reconnect_db": None, "after_reconnect_redis": None}

    class Updates:
        def install(self, ref, *, by="", automatic=False):
            calls["install"].append((ref, by))
            return {"requested": {"id": "x"}, "version": ref}

    def reconnect_db():
        calls["reconnect_db"].append(1)
        if hooks["after_reconnect_db"] is not None:
            probes["database"] = hooks["after_reconnect_db"]

    def reconnect_redis():
        calls["reconnect_redis"].append(1)
        if hooks["after_reconnect_redis"] is not None:
            probes["redis"] = hooks["after_reconnect_redis"]

    def make(**overrides: Any) -> SelfRecovery:
        options = dict(
            data_dir=data,
            updater_dir=updater,
            session_factory=factory,
            probe=lambda sup, db: dict(probes),
            send_task=lambda task, countdown: calls["send"].append((task, countdown)),
            updates=Updates(),
            schema_check=lambda db: hooks["schema"],
            reconnect_database=reconnect_db,
            reconnect_redis=reconnect_redis,
            clear_database_locks=lambda db: calls["locks"].append(1) or 1,
            prepare_bundle=lambda db, issue: calls["bundle"].append(issue["reference"]) or {"name": "hawk-ai-diagnostics-x.tar.gz", "at": "now"},
            now=clock,
            env={},
        )
        options.update(overrides)
        return SelfRecovery(**options)

    yield SimpleNamespace(engine=engine, db=factory, data=data, updater=updater, clock=clock, probes=probes, calls=calls, hooks=hooks, make=make)
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def journal(world, *lines: dict[str, Any], service: str = "api") -> None:
    folder = world.data / "logs"
    folder.mkdir(exist_ok=True)
    with open(folder / f"errors-{service}.jsonl", "a", encoding="utf-8") as out:
        for line in lines:
            out.write(json.dumps({"at": iso(world.clock()), "level": "ERROR", "service": service, "logger": "app.x", **line}) + "\n")


def heartbeat(world, manages: bool = True) -> None:
    (world.updater / "updater.json").write_text(json.dumps({"at": iso(world.clock()), "manages": manages, "engine": "ok"}))


def issue(sup: SelfRecovery, key: str) -> dict[str, Any]:
    return sup.load()["issues"][key]


def audit_actions(world) -> list[str]:
    with world.db() as db:
        return [row.action for row in db.scalars(select(AuditLog).order_by(AuditLog.created_at)).all()]


def failed_run(world, job: str, *, tenant: str | None = None, error: str = "boom", minutes_ago: float = 1, status: str = "fail") -> str:
    at = world.clock() - dt.timedelta(minutes=minutes_ago)
    with world.db() as db:
        row = ScheduledJobRun(job_name=job, tenant_id=tenant, started_at=at, finished_at=at, status=status, error_message=error)
        db.add(row)
        db.commit()
        return row.id


# ---- The error journal -----------------------------------------------------------------------------------------------


def test_the_error_journal_keeps_error_lines_redacted_and_reads_them_back(tmp_path):
    handler = log_config.ErrorJournalHandler(service="worker", data_dir=tmp_path)
    logger = logging.getLogger("test.self_recovery.journal")
    logger.addHandler(handler)
    logger.propagate = False
    try:
        logger.info("not kept")
        try:
            raise RuntimeError(f"failed for jane.doe@example.com with Authorization: Bearer {SECRET}")
        except RuntimeError:
            logger.exception("Task broke: password=%s token=%s", "hunter2", SECRET)
    finally:
        logger.removeHandler(handler)
    text = (tmp_path / "logs" / "errors-worker.jsonl").read_text()
    assert "not kept" not in text
    for leaked in (SECRET, "hunter2", "jane.doe@example.com"):
        assert leaked not in text
    lines = log_config.read_error_journal(tmp_path)
    assert len(lines) == 1 and lines[0]["service"] == "worker" and lines[0]["error_type"] == "RuntimeError" and "Traceback" in lines[0]["trace"]
    # Small: past its size it moves to .1 (one kept).
    small = log_config.ErrorJournalHandler(service="worker", data_dir=tmp_path, max_bytes=10)
    small.emit(logging.LogRecord("x", logging.ERROR, "x", 1, "again", None, None))
    assert (tmp_path / "logs" / "errors-worker.jsonl.1").exists()
    assert len(log_config.read_error_journal(tmp_path)) == 2


@pytest.mark.parametrize(
    ("message", "signature"),
    [
        ("OSError: [Errno 28] No space left on device", "disk_low"),
        ("psycopg2.errors.DeadlockDetected: deadlock detected", "stale_lock"),
        ('psycopg2.errors.UndefinedTable: relation "users" does not exist', "migration_check"),
        ("redis.exceptions.ConnectionError: Error 111 connecting to redis:6379. Connection refused.", "redis_connection"),
        ("psycopg2.OperationalError: server closed the connection unexpectedly", "database_connection"),
        ("ValueError: something nobody has seen", "unknown"),
    ],
)
def test_error_lines_are_classified_by_signature(message, signature):
    assert classify_line({"message": message}) == signature


# ---- Each signature, its limit and its breaker -----------------------------------------------------------------------


def test_a_failed_job_is_run_again_with_backoff_then_handed_to_the_oem(world):
    sup = world.make()
    failed_run(world, "monitoring_cycle_15m", error=f"boom {SECRET}")
    sup.run()
    key = "job:monitoring_cycle_15m:-"
    assert world.calls["send"] == [("app.jobs.monitoring_jobs.run_monitoring_15m_checks", 60)]
    assert issue(sup, key)["status"] == "recovering"
    assert SECRET not in (world.data / "self-recovery.json").read_text()
    # Nothing new yet: nothing more is done.
    world.clock.advance(60)
    sup.run()
    assert len(world.calls["send"]) == 1
    # It failed again: the pause doubles before each attempt.
    failed_run(world, "monitoring_cycle_15m", minutes_ago=0)
    world.clock.advance(60)
    sup.run()
    assert len(world.calls["send"]) == 1, "within the first pause (300 s)"
    world.clock.advance(300)
    sup.run()
    assert world.calls["send"][-1] == ("app.jobs.monitoring_jobs.run_monitoring_15m_checks", 120)
    world.clock.advance(30)
    failed_run(world, "monitoring_cycle_15m", minutes_ago=0)
    world.clock.advance(571)
    sup.run()
    assert len(world.calls["send"]) == 3
    world.clock.advance(30)
    failed_run(world, "monitoring_cycle_15m", minutes_ago=0)
    world.clock.advance(1171)
    sup.run()
    assert len(world.calls["send"]) == 3, "three attempts in six hours at most"
    found = issue(sup, key)
    assert found["status"] == NEEDS_OEM and world.calls["bundle"] == [found["reference"]]
    assert sup.load()["prepared"]["reference"] == found["reference"]
    assert "self_recovery.needs_oem" in audit_actions(world) and "self_recovery.tried" in audit_actions(world)
    # It works again: recovered.
    with world.db() as db:
        db.add(ScheduledJobRun(job_name="monitoring_cycle_15m", tenant_id=None, started_at=world.clock(), finished_at=world.clock(), status="success"))
        db.commit()
    world.clock.advance(60)
    sup.run()
    assert issue(sup, key)["status"] == "recovered"


def test_a_job_that_cannot_be_run_again_is_waited_for_then_handed_over(world):
    sup = world.make()
    failed_run(world, "control_coverage_refresh", tenant="t-1")
    sup.run()
    assert world.calls["send"] == [] and issue(sup, "job:control_coverage_refresh:t-1")["status"] == "recovering"


def test_a_dropped_database_connection_is_reconnected(world):
    sup = world.make()
    world.probes["database"] = False
    world.hooks["after_reconnect_db"] = True
    sup.run()
    assert world.calls["reconnect_db"] == [1]
    assert issue(sup, "database")["status"] == "recovered"


def test_a_database_that_stays_down_runs_out_of_attempts(world):
    sup = world.make()
    world.probes["database"] = False
    for _ in range(6):
        sup.run()
        world.clock.advance(400)
    assert len(world.calls["reconnect_db"]) == 3
    assert issue(sup, "database")["status"] == NEEDS_OEM
    results = [h["result"] for h in sup.load()["history"]]
    assert results.count("failed") == 3 and "needs_oem" in results


def test_the_circuit_breaker_stops_a_kind_of_action_across_issues(world, monkeypatch):
    monkeypatch.setitem(SIGNATURES, "migration_check", SIGNATURES["migration_check"].__class__(**{**SIGNATURES["migration_check"].__dict__, "breaker_failures": 1, "max_attempts": 5}))
    sup = world.make()
    world.hooks["schema"] = {"healthy": False, "pending_migrations": ["0102"], "missing_tables": [], "missing_columns": []}
    journal(world, {"message": 'relation "x" does not exist'})
    sup.run()
    history = sup.load()["history"]
    assert any(h["result"] == "breaker-open" for h in history)
    assert issue(sup, "schema")["status"] == NEEDS_OEM
    # Another issue of the same kind is not acted on while the breaker is open.
    open_until = sup.load()["breakers"]["migration_check"]["openUntil"]
    assert open_until > iso(world.clock())
    state = sup.load()
    state["issues"]["schema"]["status"] = "open"
    sup.save(state)
    world.clock.advance(10)
    journal(world, {"message": 'relation "y" does not exist'})
    sup.run()
    assert "circuit breaker" in issue(sup, "schema")["lastResult"]


def test_a_migration_check_that_passes_is_recovered(world):
    sup = world.make()
    journal(world, {"message": "sqlite3.OperationalError: no such table: foo"})
    sup.run()
    assert issue(sup, "schema")["status"] == "recovered"
    # The same old lines are not acted on again.
    world.clock.advance(60)
    sup.run()
    assert [h["result"] for h in sup.load()["history"]].count("fixed") == 1


def test_redis_is_reconnected(world):
    sup = world.make()
    world.probes["redis"] = False
    world.hooks["after_reconnect_redis"] = True
    sup.run()
    assert world.calls["reconnect_redis"] == [1] and issue(sup, "redis")["status"] == "recovered"


@pytest.mark.parametrize(("probe", "service"), [("worker", "worker"), ("beat", "beat")])
def test_a_stuck_worker_or_scheduler_is_restarted_through_the_updater(world, probe, service):
    heartbeat(world)
    sup = world.make()
    world.probes[probe] = False
    sup.run()
    request = json.loads((world.updater / "request.json").read_text())
    assert request["action"] == "restart" and request["services"] == [service] and request["by"] == "self-recovery"
    key = probe
    assert issue(sup, key)["status"] == "recovering"
    watchdog = json.loads((world.data / "watchdog.json").read_text())
    assert any("restart" in e["message"] for e in watchdog["events"])
    # The updater took it, the heartbeat stays out of date: once more after the pause, then the OEM.
    (world.updater / "request.json").unlink()
    heartbeat(world)
    world.clock.advance(601)
    heartbeat(world)
    sup.run()
    (world.updater / "request.json").unlink()
    world.clock.advance(1201)
    heartbeat(world)
    sup.run()
    assert issue(sup, key)["status"] == NEEDS_OEM


def test_a_restart_without_the_updater_fails_and_says_why(world):
    sup = world.make()
    world.probes["worker"] = False
    sup.run()
    assert "updater is not running" in issue(sup, "worker")["lastResult"]


def test_a_full_disk_is_cleaned_within_limits(world):
    usage = {"free": 100 * 1048576, "total": 100_000 * 1048576}
    old_log = world.data / "logs" / "errors-api.jsonl.1"
    old_log.parent.mkdir()
    old_log.write_bytes(b"x" * 1000)
    os.utime(old_log, (time.time() - 3 * 86_400, time.time() - 3 * 86_400))
    young = world.data / "logs" / "errors-worker.jsonl.1"
    young.write_text("y")
    backup = world.data / "backups" / "hawk-ai-old.hkbackup"
    backup.parent.mkdir()
    backup.write_text("z")
    os.utime(backup, (time.time() - 30 * 86_400, time.time() - 30 * 86_400))

    def disk_usage(_path):
        return SimpleNamespace(free=usage["free"], total=usage["total"])

    sup = world.make(probe=lambda s, db: {"database": True, "redis": True, "worker": True, "beat": True, "disk": s.disk()}, disk_usage=disk_usage)
    original = sup.prune

    def prune():
        out = original()
        usage["free"] = 50_000 * 1048576
        return out

    sup.prune = prune  # type: ignore[method-assign]
    sup.run()
    assert not old_log.exists() and young.exists() and backup.exists()
    assert issue(sup, "disk")["status"] == "recovered"


def test_stale_locks_are_cleared(world):
    request = world.updater / "request.json"
    request.write_text(json.dumps({"id": "old", "action": "update"}))
    os.utime(request, (time.time() - 3600, time.time() - 3600))
    journal(world, {"message": "psycopg2.errors.DeadlockDetected: deadlock detected"})
    sup = world.make()
    sup.run()
    assert not request.exists() and list(world.updater.glob("request.stale-*.json"))
    assert issue(sup, "lock:updater-request")["status"] == "recovered"
    assert world.calls["locks"] == [1] and issue(sup, "lock:database")["status"] == "recovered"


def test_an_unknown_failure_goes_straight_to_the_oem_with_the_bundle_ready(world):
    sup = world.make()
    journal(world, *[{"message": f"KeyError: 'thing-{n}' in the widget", "error_type": "KeyError"} for n in range(3)])
    sup.run()
    found = [i for i in sup.load()["issues"].values() if i["signature"] == "unknown"]
    assert len(found) == 1 and found[0]["status"] == NEEDS_OEM
    assert world.calls["bundle"] == [found[0]["reference"]] and world.calls["send"] == []
    # Two of a kind are not yet an issue.
    other = world.make()
    journal(world, {"message": "TypeError: once"}, {"message": "TypeError: once"})
    other.run()
    assert len([i for i in other.load()["issues"].values() if i["signature"] == "unknown"]) == 1
    # Try again: an administrator puts it back in play.
    assert sup.retry(found[0]["reference"], by="o***@example.com")
    assert sup.load()["issues"][found[0]["key"]]["status"] == "open"


def test_install_errors_are_read_from_the_installer_and_checked(world):
    (world.updater / "install-status.json").write_text(json.dumps({"at": iso(world.clock()), "state": "failed", "reason": "api-not-ready", "action": "restarted the api"}))
    sup = world.make()
    sup.run()
    found = next(i for i in sup.load()["issues"].values() if i["signature"] == "install_failed")
    assert found["status"] == "recovered" and "running and healthy" in found["lastResult"]


# ---- Updates: a failed or unhealthy update rolled back, then checked ---------------------------------------------------


def events(world, *items: dict[str, Any]) -> None:
    with open(world.updater / "events.jsonl", "a", encoding="utf-8") as out:
        for item in items:
            out.write(json.dumps(item) + "\n")


def test_an_unhealthy_new_version_is_rolled_back_then_verified(world):
    heartbeat(world)
    (world.data / "watchdog.json").write_text(json.dumps({"problems": {}, "events": [], "healthy": {"1.0.0": "2026-01-01T00:00:00Z"}, "rolledBack": [], "lastCheckAt": ""}))
    events(world, {"at": iso(world.clock() - dt.timedelta(hours=1)), "type": "switch", "action": "update", "from": "1.0.0", "to": "1.1.0"})
    journal(world, *[{"message": f"boom {n}"} for n in range(20)])
    sup = world.make(version="1.1.0")
    sup.run()
    assert world.calls["install"] == [("1.0.0", "self-recovery")]
    key = "update-unhealthy:1.1.0"
    assert issue(sup, key)["status"] == "recovering" and issue(sup, key)["verify"]["version"] == "1.0.0"
    watchdog = json.loads((world.data / "watchdog.json").read_text())
    assert [r["version"] for r in watchdog["rolledBack"]] == ["1.1.0"] and watchdog["events"][0]["kind"] == "rollback"
    # The updater brought 1.0.0 back and it is healthy: verified.
    world.clock.advance(300)
    back = world.make(version="1.0.0")
    back.run()
    assert issue(back, key)["status"] == "recovered"
    assert any(h["result"] == "verified" for h in back.load()["history"])
    assert "self_recovery.verified" in audit_actions(world)
    # Never twice for the same version.
    assert len(world.calls["install"]) == 1


def test_a_rollback_that_does_not_come_back_needs_the_oem(world):
    heartbeat(world)
    (world.data / "watchdog.json").write_text(json.dumps({"healthy": {"1.0.0": "x"}}))
    events(world, {"at": iso(world.clock() - dt.timedelta(hours=1)), "type": "switch", "action": "update", "from": "1.0.0", "to": "1.1.0"})
    world.probes["database"] = False
    sup = world.make(version="1.1.0")
    sup.run()
    assert world.calls["install"] == [("1.0.0", "self-recovery")]
    world.clock.advance(31 * 60)
    sup.run()
    assert issue(sup, "update-unhealthy:1.1.0")["status"] == NEEDS_OEM and world.calls["bundle"]


def test_a_failed_update_is_checked_and_rolled_back_when_the_failed_version_runs(world):
    heartbeat(world)
    events(world, {"at": iso(world.clock() - dt.timedelta(minutes=10)), "type": "failed", "action": "update", "from": "1.0.0", "to": "1.1.0", "error": "pull failed"})
    healthy = world.make(version="1.0.0")
    healthy.run()
    found = next(i for i in healthy.load()["issues"].values() if i["signature"] == "update_failed")
    assert found["status"] == "recovered" and "healthy" in found["lastResult"] and world.calls["install"] == []
    # The failed version is the one running: back to the one before.
    (world.data / "self-recovery.json").unlink()
    stuck = world.make(version="1.1.0")
    stuck.run()
    assert world.calls["install"] == [("1.0.0", "self-recovery")]


def test_a_rollback_without_the_updater_needs_the_oem(world):
    (world.data / "watchdog.json").write_text(json.dumps({"healthy": {"1.0.0": "x"}}))
    events(world, {"at": iso(world.clock() - dt.timedelta(hours=1)), "type": "switch", "action": "update", "from": "1.0.0", "to": "1.1.0"})
    world.probes["database"] = False
    sup = world.make(version="1.1.0")
    sup.run()
    assert world.calls["install"] == [] and issue(sup, "update-unhealthy:1.1.0")["status"] == NEEDS_OEM


def test_beat_runs_it_every_300_seconds_on_the_default_queue():
    from app.jobs import watchdog_schedule
    from app.jobs.celery_app import celery_app

    entry = watchdog_schedule.beat_entries({})["self-recovery"]
    assert entry["task"] == "app.jobs.watchdog_jobs.self_recovery" and entry["options"] == {"queue": "default"}
    assert entry["schedule"].run_every == dt.timedelta(seconds=300)
    assert watchdog_schedule.beat_entries({"SELF_RECOVERY_EVERY_SECONDS": "60"})["self-recovery"]["schedule"].run_every == dt.timedelta(seconds=60)
    assert "self-recovery" in celery_app.conf.beat_schedule and "app.jobs.watchdog_jobs.self_recovery" in celery_app.tasks


def test_the_guard_runs_only_when_the_scheduled_run_is_late(world):
    sup = world.make()
    assert self_recovery.overdue({}, 300, world.clock())
    sup.run()
    assert not self_recovery.overdue(sup.load(), 300, world.clock())
    world.clock.advance(901)
    assert self_recovery.overdue(sup.load(), 300, world.clock())


# ---- The bundle --------------------------------------------------------------------------------------------------------


def unpack(data: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        return {m.name.split("/", 1)[1]: tar.extractfile(m).read() for m in tar.getmembers()}


def test_config_redaction_hides_every_secret():
    shown = diagnostics_bundle.redact_config(
        {
            "database_url": "postgresql+psycopg2://hawk:pw-123@postgres:5432/hawk",
            "secret_key": "abc",
            "connector_secrets_kdf_salt": "salt!",
            "openai_api_key": "",
            "receipt_signing_keys_json": "{\"k\": \"v\"}",
            "log_level": "INFO",
            "api_base_url": "https://user:pass@example.com/x?token=abc",
            "access_token_expire_minutes": 30,
            "secret_key_lock_enabled": True,
        }
    )
    assert shown["secret_key"] == "[redacted]" and shown["connector_secrets_kdf_salt"] == "[redacted]" and shown["receipt_signing_keys_json"] == "[redacted]"
    assert shown["openai_api_key"] == "" and shown["log_level"] == "INFO" and shown["access_token_expire_minutes"] == 30
    assert "pw-123" not in shown["database_url"] and "pass" not in shown["api_base_url"] and "token=abc" not in shown["api_base_url"]


def test_the_installation_bundle_is_redacted_listed_and_signed(world, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "hawk_data_dir", str(world.data))
    failed_run(world, "daily_snapshot_pack", error=f"failed for bob@example.com {SECRET}")
    failed_run(world, "control_coverage_refresh", tenant=None, error="x")
    journal(world, {"message": f"crash password={SECRET}", "trace": f"Authorization: Bearer {SECRET}"})
    (world.updater / "install.log").write_text(f"install ok\npassword={SECRET}\n")
    signing = EvidenceSigning(directory=world.data, settings_obj=SimpleNamespace(evidence_signing_backend="local"), env={})
    with world.db() as db:
        data, manifest = diagnostics_bundle.build(db, installation=True, tenant_id=None, requested_by="owner@example.com", data_dir=world.data, updater_dir=world.updater, signing=signing)
    files = unpack(data)
    for name in ("version.json", "health.json", "errors.jsonl", "jobs-failed.json", "updates.json", "watchdog.json", "self-recovery.json", "install.json", "config.json", "manifest.json", "manifest.sig.json", "keys.json"):
        assert name in files, name
    everything = b"".join(files.values()).decode()
    for leaked in (SECRET, "bob@example.com", "owner@example.com", settings.secret_key, settings.connector_secrets_key):
        assert leaked not in everything, leaked
    assert json.loads(files["config.json"])["secret_key"] == "[redacted]"
    jobs = json.loads(files["jobs-failed.json"])
    assert {j["job"] for j in jobs} == {"daily_snapshot_pack", "control_coverage_refresh"} and all(j["reference"].startswith("JOB-") for j in jobs)
    # The manifest lists every other file with its SHA-256, and its signature verifies with the published keys.
    listed = {f["path"]: f["sha256"] for f in json.loads(files["manifest.json"])["files"]}
    assert set(listed) == set(files) - {"manifest.json", "manifest.sig.json", "keys.json"}
    for name, digest in listed.items():
        assert hashlib.sha256(files[name]).hexdigest() == digest
    keys = {k["kid"]: k for k in json.loads(files["keys.json"])["keys"]}
    envelope = json.loads(files["manifest.sig.json"])
    assert verify_envelope(envelope, keys=keys, data=files["manifest.json"])["valid"] is True
    assert verify_envelope(envelope, keys=keys, data=files["manifest.json"].replace(b"installation", b"instaIlation"))["valid"] is False
    assert manifest["scope"] == "installation"


def test_a_tenant_bundle_holds_that_tenant_only(world, monkeypatch):
    from app.core.config import settings
    from app.db.models.tenant import Tenant

    monkeypatch.setattr(settings, "hawk_data_dir", str(world.data))
    with world.db() as db:
        mine, theirs = Tenant(name="Mine", slug="mine", is_active=True), Tenant(name="Theirs", slug="theirs", is_active=True)
        db.add_all([mine, theirs])
        db.commit()
        mine_id, theirs_id = mine.id, theirs.id
    failed_run(world, "control_coverage_refresh", tenant=mine_id, error="my own failure")
    failed_run(world, "control_coverage_refresh", tenant=theirs_id, error="THEIR-SECRET-FAILURE")
    failed_run(world, "daily_snapshot_pack", error="INSTALLATION-RAW-ERROR")
    journal(world, {"message": "INSTALLATION-LOG-LINE"})
    signing = EvidenceSigning(directory=world.data, settings_obj=SimpleNamespace(evidence_signing_backend="local"), env={})
    with world.db() as db:
        data, manifest = diagnostics_bundle.build(db, installation=False, tenant_id=mine_id, requested_by="a@example.com", data_dir=world.data, updater_dir=world.updater, signing=signing)
    files = unpack(data)
    assert manifest["scope"] == "tenant" and manifest["tenant"] == mine_id
    assert not {"config.json", "errors.jsonl", "updates.json", "watchdog.json", "install.json"} & set(files)
    everything = b"".join(files.values()).decode()
    for hidden in ("THEIR-SECRET-FAILURE", theirs_id, "INSTALLATION-RAW-ERROR", "INSTALLATION-LOG-LINE"):
        assert hidden not in everything
    jobs = json.loads(files["jobs-failed.json"])
    assert any(j.get("error") == "my own failure" for j in jobs)
    assert any(j["job"] == "(a job of the whole installation)" and j["reference"].startswith("JOB-") for j in jobs)


def test_a_bundle_is_prepared_when_self_recovery_gives_up(world, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "hawk_data_dir", str(world.data))
    with world.db() as db:
        for n in range(5):
            prepared = diagnostics_bundle.prepare(db, data_dir=world.data, reference=f"REC-0000000{n}", reason="x", updater_dir=world.updater, now=world.clock() + dt.timedelta(seconds=n))
    names = sorted(p.name for p in (world.data / "diagnostics").glob("*.tar.gz"))
    assert len(names) == diagnostics_bundle.PREPARED_KEPT and prepared["name"] in names
    assert diagnostics_bundle.prepared_file(world.data, prepared["name"]) is not None
    assert diagnostics_bundle.prepared_file(world.data, "../self-recovery.json") is None


# ---- The routes: who gets what; tenant users never see the installation's raw job errors -------------------------------


@pytest.fixture()
def api(world, monkeypatch):
    from fastapi.testclient import TestClient

    from app.api.routers import diagnostics as router
    from app.core.config import settings
    from app.db.session import get_db
    from app.main import app

    def override_get_db():
        db = world.db()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr("app.db.session.SessionLocal", world.db)
    monkeypatch.setattr(settings, "hawk_data_dir", str(world.data))
    monkeypatch.setitem(router._factory, "supervisor", lambda: world.make())
    client = TestClient(app, base_url="https://localhost")
    try:
        yield client
    finally:
        client.close()
        app.dependency_overrides.clear()


def register(client, email: str) -> dict[str, str]:
    response = client.post("/auth/register", json={"email": email, "password": "Password123!", "full_name": "Owner"})
    assert response.status_code == 200, response.text
    body = response.json()
    return {"Authorization": f"Bearer {body['access_token']}", "X-Tenant-ID": body["tenants"][0]["id"]}


def two_tenants(world, client) -> tuple[dict[str, str], dict[str, str]]:
    from app.db.models.tenant import Tenant

    first = register(client, "first@example.com")
    second = register(client, "second@example.com")
    with world.db() as db:
        later = db.get(Tenant, second["X-Tenant-ID"])
        later.created_at = (db.get(Tenant, first["X-Tenant-ID"]).created_at or dt.datetime.now(UTC)) + dt.timedelta(hours=1)
        db.commit()
    return first, second


def test_the_installation_admin_and_a_tenant_admin_each_get_their_own_view_and_bundle(world, api):
    first, second = two_tenants(world, api)
    failed_run(world, "daily_snapshot_pack", error="INSTALLATION-RAW-ERROR")
    failed_run(world, "control_coverage_refresh", tenant=first["X-Tenant-ID"], error="FIRST-TENANT-ERROR")
    world.make().run()

    whole = api.get("/diagnostics", headers=first).json()
    assert whole["scope"] == "installation" and whole["canRun"] is True
    assert any("INSTALLATION-RAW-ERROR" in (i["detail"] or "") for i in whole["issues"])
    own = api.get("/diagnostics", headers=second).json()
    assert own["scope"] == "tenant" and own["canRun"] is False
    text = json.dumps(own)
    assert "INSTALLATION-RAW-ERROR" not in text and "FIRST-TENANT-ERROR" not in text
    assert any(i["signature"] == "job_failed" and i["detail"] == "" and i["reference"].startswith("REC-") for i in own["issues"])

    bundle = api.get("/diagnostics/bundle", headers=second)
    assert bundle.status_code == 200 and bundle.headers["x-hawk-diagnostics-scope"] == "tenant"
    files = unpack(bundle.content)
    assert "config.json" not in files and b"INSTALLATION-RAW-ERROR" not in b"".join(files.values()) and b"FIRST-TENANT-ERROR" not in b"".join(files.values())
    whole_bundle = api.get("/diagnostics/bundle", headers=first)
    assert whole_bundle.headers["x-hawk-diagnostics-scope"] == "installation" and "config.json" in unpack(whole_bundle.content)
    with world.db() as db:
        downloads = db.scalars(select(AuditLog).where(AuditLog.action == "diagnostics.bundle_downloaded")).all()
        assert {d.tenant_id for d in downloads} == {first["X-Tenant-ID"], second["X-Tenant-ID"]}
        assert all("first@example.com" not in json.dumps(d.payload) and "second@example.com" not in json.dumps(d.payload) for d in downloads)

    # Only the installation's admins run it, try again, or get the prepared bundle.
    for method, path in (("post", "/diagnostics/recovery/run"), ("post", "/diagnostics/recovery/REC-00000000/retry"), ("get", "/diagnostics/bundle/prepared")):
        assert getattr(api, method)(path, headers=second).status_code == 403, path
    assert api.post("/diagnostics/recovery/run", headers=first).json()["scope"] == "installation"
    assert api.post("/diagnostics/recovery/REC-NOPE/retry", headers=first).status_code == 404


def test_viewers_and_strangers_get_nothing(world, api):
    from app.db.models.user import User, UserTenantRole

    owner = register(api, "owner@example.com")
    viewer = register(api, "viewer@example.com")
    with world.db() as db:
        user = db.scalar(select(User).where(User.email == "viewer@example.com"))
        db.add(UserTenantRole(user_id=user.id, tenant_id=owner["X-Tenant-ID"], role="viewer"))
        db.commit()
    as_viewer = {**viewer, "X-Tenant-ID": owner["X-Tenant-ID"]}
    for path in ("/diagnostics", "/diagnostics/bundle"):
        assert api.get(path, headers=as_viewer).status_code == 403
        assert api.get(path).status_code in (401, 403)


def test_tenant_users_see_a_plain_status_not_the_installation_s_raw_job_error(world, api):
    from app.services.brain.tools import _tool_ops_jobs_status

    first, second = two_tenants(world, api)
    run_id = failed_run(world, "daily_snapshot_pack", error="psycopg2 password=hunter2 host db-internal")
    failed_run(world, "control_coverage_refresh", tenant=second["X-Tenant-ID"], error="tenant's own error")
    items = api.get("/ops/jobs/status", headers=second).json()["items"]
    runs = {item["job_name"]: item["runs"][0] for item in items}
    plain = runs["daily_snapshot_pack"]
    assert "hunter2" not in json.dumps(items) and "db-internal" not in json.dumps(items)
    assert plain["error_message"].startswith("A background job failed at ") and self_recovery.job_reference(run_id) in plain["error_message"]
    assert plain["reference"] == self_recovery.job_reference(run_id) and plain["diagnostics_url"] == "/settings/backups#diagnostics"
    assert runs["control_coverage_refresh"]["error_message"] == "tenant's own error"
    # The assistant's tool says the same.
    with world.db() as db:
        out = _tool_ops_jobs_status(SimpleNamespace(db=db, tenant_id=second["X-Tenant-ID"]), {})
    assert "hunter2" not in json.dumps(out, default=str)
