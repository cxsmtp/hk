"""Self-recovery: Hawk AI reads its own error journal and its job records, recognises the failures it knows, and puts
them right with a safe, bounded action. When it cannot, it stops trying, says "needs OEM help" and has the diagnostics
bundle ready for the administrator to download and send (app/services/diagnostics_bundle.py).

Beat runs it every SELF_RECOVERY_EVERY_SECONDS (300; app/jobs/watchdog_jobs.py), next to the self-check
(app/services/self_check.py), whose bookkeeping (app/services/watchdog.py) it shares for update rollbacks. The API runs
it too when the worker or the scheduler has stopped answering and nothing else would (``start_guard``).

What it reads:
  - the error journal: the last ERROR lines of the API, the worker and beat (app/core/log_config.py, <data>/logs);
  - failed and dead-lettered job runs (scheduled_job_runs);
  - the database, Redis, the worker's and the scheduler's heartbeats, the free disk;
  - the updater's events (a failed or rolled-back update; a new version that is unhealthy), its stale request;
  - the installer's result (deploy/install.sh writes install-status.json in the updater folder).

The signatures it knows, what it does about each and how often (SIGNATURES): every action has a limit (attempts per
window), a pause that doubles between attempts, and a circuit breaker per signature (that many failed actions in the
window and the signature is left alone until its cool-down ends). An issue whose attempts ran out, a signature whose
breaker is open, and errors it does not recognise are marked "needs OEM help": it stops trying, prepares the
diagnostics bundle and says so on Settings → Backups & health. Every action is logged, written to the audit log
("Updates & system") and kept in its history (``self-recovery.json`` in the data folder, in every backup).
"""

from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import logging
import os
import re
import shutil
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.log_config import read_error_journal, redact_text
from app.services.privacy_sanitizer import redact_sensitive_text
from app.services.state_file import read_state, write_state
from app.version import PACKAGE_VERSION, display_version

log = logging.getLogger("hawk.self_recovery")

STATE_FILE = "self-recovery.json"
LOCK_FILE = "self-recovery.lock"
HISTORY_KEPT = 300
#: Recovered issues are forgotten after this long (their history stays).
FORGET_AFTER_SECONDS = 7 * 86_400
#: The error journal is read over this window.
JOURNAL_WINDOW_SECONDS = 30 * 60
#: The same unrecognised error this often in the window is an issue.
UNKNOWN_AFTER = 3
#: A new version with this many errors in the window is unhealthy.
UNHEALTHY_ERRORS = 20
#: Failed job runs are looked at over this window.
JOB_WINDOW_SECONDS = 6 * 3600
DISK_LOW_PERCENT = 5.0
DISK_LOW_MB = 1024
#: What the disk clean-up may remove in one go.
PRUNE_MAX_FILES = 500
PRUNE_MAX_BYTES = 2 * 1024 * 1024 * 1024
#: An updater request older than this, with no updater to take it, is a stale lock.
STALE_REQUEST_SECONDS = 30 * 60
#: After a rollback, how long the old version has to come back healthy.
VERIFY_SECONDS = 30 * 60
DIAGNOSTICS_DIR = "diagnostics"
APP_NAME = "Hawk AI"

FAILED_RUN = ("fail", "failed", "dead_letter")
OPEN, RECOVERING, RECOVERED, NEEDS_OEM = "open", "recovering", "recovered", "needs_oem"
STATUS_WORDS = {OPEN: "Found", RECOVERING: "Recovering", RECOVERED: "Recovered", NEEDS_OEM: "Needs OEM help"}


@dataclass(frozen=True)
class Signature:
    id: str
    title: str
    action: str
    #: Attempts allowed per window; 0: never acted on (needs OEM help at once).
    max_attempts: int
    window_seconds: int
    #: The pause after the first attempt; it doubles after each.
    backoff_seconds: int
    #: Failed actions in the window that open the signature's circuit breaker, and how long it stays open.
    breaker_failures: int
    cooldown_seconds: int


H = 3600
SIGNATURES: dict[str, Signature] = {
    s.id: s
    for s in (
        Signature("job_failed", "A background job failed", "Run the job again, waiting longer each time", 3, 6 * H, 300, 6, 24 * H),
        Signature("stale_lock", "A lock was left behind", "Clear the stale lock", 2, H, 120, 4, 24 * H),
        Signature("database_connection", "The database connection dropped", "Reconnect the database pool", 3, H, 60, 5, 6 * H),
        Signature("redis_connection", "The Redis connection dropped", "Reconnect to Redis", 3, H, 60, 5, 6 * H),
        Signature("worker_stuck", "The worker stopped answering", "Restart the worker through the updater", 2, 6 * H, 600, 3, 24 * H),
        Signature("beat_stuck", "The scheduler stopped answering", "Restart the scheduler through the updater", 2, 6 * H, 600, 3, 24 * H),
        Signature("disk_low", "The disk is almost full", "Remove old logs and temporary files (within limits)", 2, 6 * H, 900, 3, 24 * H),
        Signature("migration_check", "The database schema looks out of date", "Run the migration check again", 2, 6 * H, 600, 3, 24 * H),
        Signature("update_failed", "An update failed", "Check the version running and its health; roll back if the failed version is running", 2, 24 * H, 300, 2, 7 * 24 * H),
        Signature("update_unhealthy", "The new version is unhealthy", "Roll back to the previous version, then check its health", 1, 24 * H, 0, 1, 7 * 24 * H),
        Signature("install_failed", "The installer reported a problem", "Check that Hawk AI is healthy now", 3, 24 * H, 300, 3, 24 * H),
        Signature("unknown", "Errors Hawk AI does not recognise", "None: Hawk AI does not know this failure", 0, H, 0, 1, 24 * H),
    )
}

#: Errors in the journal, by signature (searched in the message, the error type and the end of the trace).
JOURNAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("disk_low", re.compile(r"No space left on device|ENOSPC|DiskFull|disk is full", re.I)),
    ("stale_lock", re.compile(r"LockNotAvailable|deadlock detected|lock timeout|could not obtain lock|database is locked", re.I)),
    ("migration_check", re.compile(r"UndefinedTable|UndefinedColumn|relation \"[^\"]+\" does not exist|no such table|no such column|column \"?[\w.]+\"? does not exist", re.I)),
    ("redis_connection", re.compile(r"redis\.exceptions\.(ConnectionError|TimeoutError)|Error \d+ connecting to [\w.-]*redis|Connection to Redis lost|Redis cannot be reached", re.I)),
    ("database_connection", re.compile(r"server closed the connection unexpectedly|could not connect to server|connection to server at .* failed|QueuePool limit|psycopg2?\.(OperationalError|InterfaceError)|terminating connection due to administrator command|SSL SYSCALL error", re.I)),
)
#: Journal lines that are not errors to classify: self-recovery's own, and task failures (read from the job records).
IGNORED_LOGGERS = ("hawk.self_recovery", "app.jobs.tasks")

#: Jobs that can be run again with nothing to give them: by the name their runs are recorded under, the task to send.
RETRYABLE: dict[str, str] = {
    "daily_snapshot_pack": "app.jobs.auditor_jobs.run_daily_snapshot_pack",
    "monitoring_cycle_15m": "app.jobs.monitoring_jobs.run_monitoring_15m_checks",
    "monitoring_cycle_hourly": "app.jobs.monitoring_jobs.run_monitoring_hourly_checks",
    "monitoring_cycle_daily": "app.jobs.monitoring_jobs.run_monitoring_daily_checks",
    "native_control_health_reconciliation": "app.jobs.native_control_jobs.reconcile_native_control_health",
    "approval_sla_timeout": "app.jobs.enforcement_jobs.run_sla_timeout_checks",
    "scheduled_backup": "app.jobs.backup_jobs.run_scheduled_backup",
}
#: Tasks beat sends with no arguments: a dead-lettered one is sent again as it is.
RETRYABLE_TASKS = frozenset(
    {
        *RETRYABLE.values(),
        "app.jobs.control_coverage_jobs.enqueue_control_coverage_refreshes",
        "app.jobs.maturity_curve_jobs.enqueue_maturity_curve_refreshes",
        "app.jobs.discovery_verification_jobs.enqueue_due_discovery_verifications",
        "app.jobs.hmair_discovery_jobs.enqueue_endpoint_metadata_inventory_reconciliation",
        "app.jobs.provider_signal_jobs.enqueue_provider_signal_retention_candidate_reports",
    }
)


def every_seconds(env: Any = None) -> int:
    env = os.environ if env is None else env
    try:
        return max(30, int(float(str(env.get("SELF_RECOVERY_EVERY_SECONDS") or 300))))
    except ValueError:
        return 300


def _iso(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse(value: Any) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def clean(text: Any, limit: int = 300) -> str:
    """Text for the state, the history and the audit log: no secrets, emails, phone numbers or line breaks."""

    return re.sub(r"\s+", " ", redact_sensitive_text(redact_text(str(text or ""), max_len=4000), max_len=limit)).strip()


def reference_for(key: str) -> str:
    """A short reference an administrator can read to the OEM, the same for the same issue."""

    return "REC-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:8].upper()


def job_reference(run_id: Any) -> str:
    """The reference of one job run: what tenant users see in place of the error, and what the bundle lists."""

    return "JOB-" + re.sub(r"[^0-9a-fA-F]", "", str(run_id or ""))[:8].upper()


def plain_job_failure(run: Any) -> str:
    """What a person sees about a background job of the whole installation that failed: when, and its reference."""

    when = getattr(run, "finished_at", None) or getattr(run, "started_at", None)
    if isinstance(when, dt.datetime):
        at = (when.astimezone(dt.timezone.utc) if when.tzinfo else when).strftime("%Y-%m-%d %H:%M UTC")
    else:
        at = "an unknown time"
    return f"A background job failed at {at}, reference {job_reference(getattr(run, 'id', ''))}. An owner or admin can download the diagnostics bundle from Settings → Backups & health and send it to the OEM."


DIAGNOSTICS_URL = "/settings/backups#diagnostics"


def _normalized(text: str) -> str:
    text = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "#", text, flags=re.I)
    text = re.sub(r"\b0x[0-9a-f]+\b|\b[0-9a-f]{12,}\b|\d+", "#", text, flags=re.I)
    return text[:120]


def classify_line(line: dict[str, Any]) -> str:
    """The signature an error line matches, or 'unknown'."""

    haystack = " ".join(str(line.get(k) or "") for k in ("message", "error_type", "trace"))
    for signature, pattern in JOURNAL_PATTERNS:
        if pattern.search(haystack):
            return signature
    return "unknown"


@dataclass
class Finding:
    key: str
    signature: str
    title: str
    detail: str
    #: When the newest evidence was seen: an issue acted on after it is not acted on again for the same evidence.
    evidence_at: str
    tenant: str = ""
    data: dict[str, Any] | None = None


@dataclass
class Outcome:
    ok: bool
    detail: str
    #: True: the action's effect shows later (a job sent again, a restart, a rollback); judged at the next run.
    pending: bool = False


def _default_session_factory() -> Callable[[], Any]:
    from app.db.session import SessionLocal

    return SessionLocal


def _redis_factory() -> Any | None:
    from app.services.self_check import _redis_factory as factory

    return factory()


def default_probe(supervisor: "SelfRecovery", db: Any) -> dict[str, Any]:
    """The database, Redis, the worker's and the scheduler's heartbeats, the disk. None: could not be told."""

    from sqlalchemy import text

    out: dict[str, Any] = {"database": None, "redis": None, "worker": None, "beat": None, "disk": supervisor.disk()}
    try:
        db.execute(text("SELECT 1"))
        out["database"] = True
    except Exception:  # noqa: BLE001
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
        out["database"] = False
    try:
        client = supervisor.redis_factory()
    except Exception:  # noqa: BLE001
        client = None
    if client is None:
        return out
    try:
        client.ping()
        out["redis"] = True
    except Exception:  # noqa: BLE001
        out["redis"] = False
        return out
    from app.services.control_plane_health_service import CELERY_BEAT_HEARTBEAT_KEY, CELERY_WORKER_HEARTBEAT_KEY, _check_celery_heartbeat

    for name, key, actor in (("worker", CELERY_WORKER_HEARTBEAT_KEY, "worker"), ("beat", CELERY_BEAT_HEARTBEAT_KEY, "beat")):
        try:
            out[name] = bool(_check_celery_heartbeat(redis_client=client, key=key, actor=actor, strict_mode=True).ok)
        except Exception:  # noqa: BLE001
            out[name] = None
    return out


def _send_task(task: str, countdown: int) -> None:
    from app.jobs.celery_app import celery_app

    route = (celery_app.conf.task_routes or {}).get(task) or {}
    celery_app.send_task(task, countdown=countdown, queue=route.get("queue") or "default")


class SelfRecovery:
    """The supervisor. What reaches outside (the database, Redis, the updater, Celery, the clock) can be handed in."""

    def __init__(
        self,
        *,
        data_dir: Path | str | None = None,
        session_factory: Callable[[], Any] | None = None,
        probe: Callable[["SelfRecovery", Any], dict[str, Any]] = default_probe,
        redis_factory: Callable[[], Any | None] = _redis_factory,
        send_task: Callable[[str, int], None] = _send_task,
        updates: Any = None,
        updater_dir: Path | str | None = None,
        version: str = PACKAGE_VERSION,
        schema_check: Callable[[Any], dict[str, Any]] | None = None,
        reconnect_database: Callable[[], None] | None = None,
        reconnect_redis: Callable[[], None] | None = None,
        clear_database_locks: Callable[[Any], int] | None = None,
        disk_usage: Callable[[Path], Any] = shutil.disk_usage,
        prepare_bundle: Callable[[Any, dict[str, Any]], dict[str, Any] | None] | None = None,
        now: Callable[[], dt.datetime] | None = None,
        env: Any = None,
    ) -> None:
        self.data_dir = Path(data_dir or settings.hawk_data_dir)
        self.session_factory = session_factory or _default_session_factory()
        self._probe = probe
        self.redis_factory = redis_factory
        self.send_task = send_task
        self._updates = updates
        self._updater_dir = Path(updater_dir) if updater_dir else None
        self.version = version
        self.schema_check = schema_check or self._schema_check
        self.reconnect_database = reconnect_database or self._reconnect_database
        self.reconnect_redis = reconnect_redis or self._reconnect_redis
        self.clear_database_locks = clear_database_locks or self._clear_database_locks
        self.disk_usage = disk_usage
        self.prepare_bundle = prepare_bundle or self._prepare_bundle
        self.now = now or (lambda: dt.datetime.now(dt.timezone.utc))
        self.env = os.environ if env is None else env
        self.file = self.data_dir / STATE_FILE

    # ---- What it is handed -----------------------------------------------------------------------------------------

    @property
    def updates(self) -> Any:
        if self._updates is None:
            from app.services.updates.service import UpdateService

            self._updates = UpdateService(data_dir=self.data_dir, updater=self.updater_dir)
        return self._updates

    @property
    def updater_dir(self) -> Path:
        from app.services.updates import companion

        return self._updater_dir or companion.updater_dir()

    # ---- The state ---------------------------------------------------------------------------------------------------

    def load(self) -> dict[str, Any]:
        try:
            raw = read_state(self.file, fallback={})
        except Exception:  # noqa: BLE001 - its own notes, made again as it runs
            raw = {}
        raw = raw if isinstance(raw, dict) else {}
        return {
            "issues": raw["issues"] if isinstance(raw.get("issues"), dict) else {},
            "history": raw["history"][:HISTORY_KEPT] if isinstance(raw.get("history"), list) else [],
            "breakers": raw["breakers"] if isinstance(raw.get("breakers"), dict) else {},
            "handled": raw["handled"] if isinstance(raw.get("handled"), dict) else {},
            "prepared": raw.get("prepared") if isinstance(raw.get("prepared"), dict) else None,
            "lastRunAt": str(raw.get("lastRunAt") or ""),
        }

    def save(self, state: dict[str, Any]) -> None:
        try:
            write_state(self.file, state, keep_last=False)
        except Exception as error:  # noqa: BLE001 - never breaks the run
            log.warning("Self-recovery could not save its notes: %s", error)

    # ---- What it reads -------------------------------------------------------------------------------------------------

    def disk(self) -> dict[str, Any] | None:
        try:
            usage = self.disk_usage(self.data_dir)
        except OSError:
            return None
        free_mb = round(usage.free / 1048576)
        total_mb = max(1, round(usage.total / 1048576))
        return {"freeMB": free_mb, "totalMB": total_mb, "low": free_mb < DISK_LOW_MB or free_mb * 100.0 / total_mb < DISK_LOW_PERCENT}

    def probe(self, db: Any) -> dict[str, Any]:
        try:
            return self._probe(self, db)
        except Exception as error:  # noqa: BLE001
            log.warning("Self-recovery could not look at the services: %s", error)
            return {}

    def journal(self) -> list[dict[str, Any]]:
        since = self.now() - dt.timedelta(seconds=JOURNAL_WINDOW_SECONDS)
        return [line for line in read_error_journal(self.data_dir, since=since, limit=2000) if not str(line.get("logger") or "").startswith(IGNORED_LOGGERS)]

    def collect(self, db: Any, probes: dict[str, Any], lines: list[dict[str, Any]]) -> list[Finding]:
        """Everything wrong now, classified."""

        now = _iso(self.now())
        found: dict[str, Finding] = {}

        def add(finding: Finding) -> None:
            found.setdefault(finding.key, finding)

        # The services.
        if probes.get("database") is False:
            add(Finding("database", "database_connection", SIGNATURES["database_connection"].title, "The database does not answer.", now))
        if probes.get("redis") is False:
            add(Finding("redis", "redis_connection", SIGNATURES["redis_connection"].title, "Redis does not answer.", now))
        if probes.get("redis") and probes.get("worker") is False:
            add(Finding("worker", "worker_stuck", SIGNATURES["worker_stuck"].title, "The worker's heartbeat is out of date.", now))
        if probes.get("redis") and probes.get("beat") is False:
            add(Finding("beat", "beat_stuck", SIGNATURES["beat_stuck"].title, "The scheduler's heartbeat is out of date.", now))
        disk = probes.get("disk") or {}
        if disk.get("low"):
            add(Finding("disk", "disk_low", SIGNATURES["disk_low"].title, f"{disk.get('freeMB')} MB free of {disk.get('totalMB')} MB.", now))

        # The error journal.
        unknown: dict[str, list[dict[str, Any]]] = {}
        for line in lines:
            signature = classify_line(line)
            if signature == "unknown":
                group = f"{line.get('logger')}|{line.get('error_type') or ''}|{_normalized(str(line.get('message') or ''))}"
                unknown.setdefault(group, []).append(line)
                continue
            key = {"disk_low": "disk", "database_connection": "database", "redis_connection": "redis", "stale_lock": "lock:database", "migration_check": "schema"}[signature]
            seen = found.get(key)
            detail = f"{line.get('service') or 'api'}: {clean(line.get('message'), 200)}"
            if seen is None:
                add(Finding(key, signature, SIGNATURES[signature].title, detail, str(line.get("at") or now)))
            elif str(line.get("at") or "") > seen.evidence_at and seen.evidence_at != now:
                seen.evidence_at = str(line.get("at"))
        for group, group_lines in unknown.items():
            if len(group_lines) < UNKNOWN_AFTER:
                continue
            last = group_lines[-1]
            key = f"unknown:{hashlib.sha256(group.encode('utf-8')).hexdigest()[:10]}"
            add(Finding(key, "unknown", SIGNATURES["unknown"].title, f"{len(group_lines)} times in 30 minutes ({last.get('service') or 'api'}, {last.get('logger')}): {clean(last.get('message'), 200)}", str(last.get("at") or now), data={"lines": len(group_lines)}))

        # Failed jobs: the last run of each job, when it failed.
        for finding in self.job_findings(db):
            add(finding)
        # The updater and the installer.
        for finding in self.update_findings(probes, lines):
            add(finding)
        stale = self.stale_request()
        if stale:
            add(stale)
        install = self.install_finding()
        if install:
            add(install)
        return list(found.values())

    def job_findings(self, db: Any) -> list[Finding]:
        from sqlalchemy import select

        from app.db.models.job_run import ScheduledJobRun

        since = self.now() - dt.timedelta(seconds=JOB_WINDOW_SECONDS)
        try:
            rows = db.scalars(select(ScheduledJobRun).where(ScheduledJobRun.started_at >= since).order_by(ScheduledJobRun.started_at.desc()).limit(2000)).all()
        except Exception:  # noqa: BLE001 - the database is a finding of its own
            try:
                db.rollback()
            except Exception:  # noqa: BLE001
                pass
            return []
        latest: dict[tuple[str, str], Any] = {}
        for row in rows:
            latest.setdefault((row.job_name, row.tenant_id or ""), row)
        out = []
        for (job, tenant), row in latest.items():
            if row.status not in FAILED_RUN:
                continue
            finished = row.finished_at or row.started_at
            if finished is not None and finished.tzinfo is None:
                finished = finished.replace(tzinfo=dt.timezone.utc)
            out.append(
                Finding(
                    f"job:{job}:{tenant or '-'}",
                    "job_failed",
                    SIGNATURES["job_failed"].title,
                    f"{job} ({row.status}, {job_reference(row.id)}): {clean(row.error_message, 200)}",
                    _iso(finished) if finished else _iso(self.now()),
                    tenant=tenant,
                    data={"job": job, "run": row.id, "reference": job_reference(row.id), "task": RETRYABLE.get(job) or (job if job in RETRYABLE_TASKS else "")},
                )
            )
        return out

    def _events(self, limit: int = 50) -> list[dict[str, Any]]:
        from app.services.updates import companion

        try:
            return companion.events(self.updater_dir, limit)
        except Exception:  # noqa: BLE001
            return []

    def update_findings(self, probes: dict[str, Any], lines: list[dict[str, Any]]) -> list[Finding]:
        from app.services.watchdog import FILE_NAME as WATCHDOG_FILE, NOTIFY_AFTER, Watchdog, rollback_target

        now = self.now()
        out: list[Finding] = []
        events = self._events()
        # An update that failed or was rolled back by the updater, in the last day.
        last = next((e for e in events if e.get("action") == "update"), None)
        if last and last.get("type") in ("failed", "rolled-back"):
            at = _parse(last.get("at"))
            if at and (now - at).total_seconds() < SIGNATURES["update_failed"].window_seconds:
                word = "was rolled back by the updater" if last["type"] == "rolled-back" else "failed"
                out.append(Finding(f"update:{last.get('at')}", "update_failed", SIGNATURES["update_failed"].title, f"The update to {display_version(str(last.get('to') or ''))} {word}: {clean(last.get('error'), 200)}", str(last.get("at")), data={"event": {k: last.get(k) for k in ("at", "type", "from", "to")}}))
        # A version that came in less than a day ago and is unhealthy: the watchdog's rule (app/services/watchdog.py).
        switched = next((e for e in events if e.get("type") == "switch" and e.get("from") and e.get("from") != self.version and e.get("to") == self.version), None)
        if switched:
            since = str(switched.get("at") or "")
            down = [name for name in ("database", "redis", "worker", "beat") if probes.get(name) is False]
            errors = [line for line in lines if str(line.get("at") or "") >= since]
            if down or len(errors) >= UNHEALTHY_ERRORS:
                watchdog = Watchdog(file=self.data_dir / WATCHDOG_FILE)
                target = rollback_target(
                    problems=[{"checks": NOTIFY_AFTER, "outside": False, "since": _iso(now)}],
                    running=self.version,
                    previous=str(switched.get("from")),
                    switched_at=since,
                    was_healthy=watchdog.was_healthy,
                    has_rolled_back=watchdog.has_rolled_back,
                    now=now,
                )
                if target:
                    why = f"{', '.join(down)} not answering" if down else f"{len(errors)} errors since it came in"
                    out.append(Finding(f"update-unhealthy:{self.version}", "update_unhealthy", SIGNATURES["update_unhealthy"].title, f"{display_version(self.version)} came in at {since[:16].replace('T', ' ')} UTC: {why}.", _iso(now), data={"target": target}))
        return out

    def stale_request(self) -> Finding | None:
        from app.services.updates import companion

        file = self.updater_dir / "request.json"
        try:
            age = time.time() - file.stat().st_mtime
        except OSError:
            return None
        if age < STALE_REQUEST_SECONDS:
            return None
        try:
            if companion.companion_state(self.updater_dir, self.now())["connected"]:
                return None
        except Exception:  # noqa: BLE001
            pass
        return Finding("lock:updater-request", "stale_lock", SIGNATURES["stale_lock"].title, f"An update or restart request has waited {round(age / 60)} minutes for an updater that is not running; it blocks every update.", _iso(self.now()))

    def install_finding(self) -> Finding | None:
        status = read_state(self.updater_dir / "install-status.json", fallback=None) if (self.updater_dir / "install-status.json").exists() else None
        if not isinstance(status, dict) or status.get("state") not in ("failed", "recovered"):
            return None
        at = _parse(status.get("at"))
        if at is None or (self.now() - at).total_seconds() > SIGNATURES["install_failed"].window_seconds:
            return None
        word = "recovered by itself" if status["state"] == "recovered" else "failed"
        action = f" (it tried: {clean(status.get('action'), 80)})" if status.get("action") else ""
        return Finding(f"install:{status.get('at')}", "install_failed", SIGNATURES["install_failed"].title, f"deploy/install.sh {word}: {clean(status.get('reason'), 120)}{action}.", str(status.get("at")), data={"install": {k: status.get(k) for k in ("at", "state", "reason", "action", "release")}})

    # ---- The actions -------------------------------------------------------------------------------------------------

    def act(self, db: Any, finding: Finding, attempt: int, probes: dict[str, Any]) -> Outcome:
        signature = finding.signature
        if signature == "job_failed":
            task = (finding.data or {}).get("task") or ""
            if not task:
                return Outcome(True, f"{(finding.data or {}).get('job')} needs what its own schedule gives it: its next run is waited for.", pending=True)
            countdown = SIGNATURES["job_failed"].backoff_seconds * (2 ** max(0, attempt - 1)) // 5
            self.send_task(task, countdown)
            return Outcome(True, f"{task.rsplit('.', 1)[-1]} sent again (starts in {countdown} s).", pending=True)
        if signature == "stale_lock":
            if finding.key == "lock:updater-request":
                file = self.updater_dir / "request.json"
                aside = self.updater_dir / f"request.stale-{self.now().strftime('%Y%m%dT%H%M%S')}.json"
                try:
                    os.replace(file, aside)
                except FileNotFoundError:
                    return Outcome(True, "The request was taken meanwhile.")
                return Outcome(not file.exists(), f"The stale request was moved aside ({aside.name}).")
            cleared = self.clear_database_locks(db)
            return Outcome(True, f"{cleared} session(s) left idle in a transaction for over 10 minutes were ended." if cleared else "No session holds a lock for long now.")
        if signature == "database_connection":
            self.reconnect_database()
            ok = bool(self.probe(db).get("database"))
            return Outcome(ok, "The pool was emptied and the database answers again." if ok else "The pool was emptied, but the database still does not answer.")
        if signature == "redis_connection":
            self.reconnect_redis()
            again = self.probe(db).get("redis")
            ok = again is not False
            return Outcome(ok, "Reconnected; Redis answers." if ok else "Reconnected, but Redis still does not answer.")
        if signature in ("worker_stuck", "beat_stuck"):
            service = "worker" if signature == "worker_stuck" else "beat"
            return self.restart_service(service)
        if signature == "disk_low":
            removed, freed = self.prune()
            disk = self.disk() or {}
            return Outcome(not disk.get("low"), f"{removed} old file(s) removed, {round(freed / 1048576)} MB freed; {disk.get('freeMB', '?')} MB free now.")
        if signature == "migration_check":
            report = self.schema_check(db)
            if report.get("healthy"):
                return Outcome(True, "The schema is up to date: the errors were passing.")
            pending = report.get("pending_migrations") or []
            missing = [*(report.get("missing_tables") or []), *(report.get("missing_columns") or [])]
            return Outcome(False, f"The schema is behind: {len(pending)} migration(s) pending, {len(missing)} table(s) or column(s) missing. Run sudo deploy/install.sh (it runs the migrations).")
        if signature == "update_failed":
            event = (finding.data or {}).get("event") or {}
            if event.get("type") == "failed" and event.get("to") == self.version and event.get("from") and event.get("from") != self.version:
                return self.roll_back(db, str(event["from"]), why=f"the update to {display_version(self.version)} failed")
            down = [name for name in ("database", "redis", "worker", "beat") if probes.get(name) is False]
            if down:
                return Outcome(False, f"{display_version(self.version)} runs, but {', '.join(down)} do(es) not answer.")
            return Outcome(True, f"{display_version(self.version)} runs and is healthy: nothing was changed by the failed update.")
        if signature == "update_unhealthy":
            return self.roll_back(db, str((finding.data or {}).get("target") or ""), why=f"{display_version(self.version)} is unhealthy")
        if signature == "install_failed":
            down = [name for name in ("database", "redis", "worker", "beat") if probes.get(name) is False]
            if down:
                return Outcome(False, f"Hawk AI runs, but {', '.join(down)} do(es) not answer.")
            return Outcome(True, f"Hawk AI {display_version(self.version)} is running and healthy now.")
        return Outcome(False, "Hawk AI does not know how to fix this.")

    def restart_service(self, service: str) -> Outcome:
        """The watchdog's path: the updater restarts the service (it alone has the container engine)."""

        from app.services.updates import companion

        try:
            sent = companion.request(self.updater_dir, {"action": "restart", "services": [service], "by": "self-recovery"}, self.now())
        except companion.UpdaterUnavailable as error:
            return Outcome(False, f"The {service} could not be restarted: {clean(error, 200)}")
        self.watchdog_event("tried", f"Self-recovery asked the updater to restart the {service} ({sent.get('id')}).", key=service)
        return Outcome(True, f"The updater was asked to restart the {service}.", pending=True)

    def roll_back(self, db: Any, target: str, *, why: str) -> Outcome:
        """Through the updater, as the self-check does (app/services/self_check.py maybe_roll_back): once per version."""

        from app.services.updates import companion
        from app.services.watchdog import FILE_NAME as WATCHDOG_FILE, Watchdog

        if not target:
            return Outcome(False, "No earlier version to go back to.")
        try:
            manages = companion.companion_state(self.updater_dir, self.now())["manages"]
        except Exception:  # noqa: BLE001
            manages = False
        if not manages:
            return Outcome(False, f"{why}, but the updater does not look after Hawk AI: roll back with deploy/install.sh.")
        watchdog = Watchdog(file=self.data_dir / WATCHDOG_FILE)
        if watchdog.has_rolled_back(self.version):
            return Outcome(True, f"Going back to {display_version(target)} was already asked for.", pending=True)
        try:
            self.updates.install(target, by="self-recovery")
        except Exception as error:  # noqa: BLE001
            return Outcome(False, f"Going back to {display_version(target)} was refused: {clean(error, 200)}")
        self.watchdog_event("rollback", f"Self-recovery: {why}; going back to {display_version(target)}.", mark_rolled_back=self.version)
        return Outcome(True, f"{why}: going back to {display_version(target)} (the updater takes a backup first).", pending=True)

    def watchdog_event(self, kind: str, message: str, *, key: str = "", mark_rolled_back: str = "") -> None:
        """An event in the self-check's notes (watchdog.json), under its lock, so the two never overwrite each other."""

        from app.services.self_check import LOCK_FILE as WATCHDOG_LOCK
        from app.services.watchdog import FILE_NAME as WATCHDOG_FILE, Watchdog

        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            with open(self.data_dir / WATCHDOG_LOCK, "a+") as lock:
                deadline = time.monotonic() + 10
                while True:
                    try:
                        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except OSError:
                        if time.monotonic() > deadline:
                            return
                        time.sleep(0.2)
                try:
                    watchdog = Watchdog(file=self.data_dir / WATCHDOG_FILE)
                    if mark_rolled_back:
                        watchdog.mark_rolled_back(mark_rolled_back, now=self.now())
                    watchdog.event(kind, message, now=self.now(), **({"key": key} if key else {}))
                finally:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass

    def prune(self) -> tuple[int, int]:
        """Old rotated error journals, half-written temporary files, older prepared bundles and stale temporary files:
        never a backup, a database file or anything younger than a day (an hour for half-written files)."""

        now = time.time()
        removed = freed = 0
        candidates: list[Path] = []
        logs = self.data_dir / "logs"
        if logs.is_dir():
            candidates += [p for p in logs.glob("*.1") if now - p.stat().st_mtime > 86_400]
        candidates += [p for p in self.data_dir.glob(".*.tmp") if now - p.stat().st_mtime > 3600]
        bundles = sorted((self.data_dir / DIAGNOSTICS_DIR).glob("hawk-ai-diagnostics-*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True) if (self.data_dir / DIAGNOSTICS_DIR).is_dir() else []
        candidates += bundles[3:]
        temp = Path(tempfile.gettempdir())
        try:
            candidates += [p for p in temp.iterdir() if p.is_file() and not p.is_symlink() and p.name.startswith(("tmp", "hawk")) and now - p.stat().st_mtime > 86_400 and p.stat().st_uid == os.getuid()]
        except OSError:
            pass
        for path in candidates:
            if removed >= PRUNE_MAX_FILES or freed >= PRUNE_MAX_BYTES:
                break
            try:
                size = path.stat().st_size
                path.unlink()
            except OSError:
                continue
            removed += 1
            freed += size
        return removed, freed

    @staticmethod
    def _schema_check(db: Any) -> dict[str, Any]:
        from app.services.schema_health_service import evaluate_schema_health

        return evaluate_schema_health(db).to_dict()

    @staticmethod
    def _reconnect_database() -> None:
        from app.db.session import engine

        engine.dispose()

    @staticmethod
    def _reconnect_redis() -> None:
        try:
            from app.jobs.celery_app import celery_app

            celery_app.pool.force_close_all()
        except Exception:  # noqa: BLE001 - a fresh connection is made at the next use
            pass

    @staticmethod
    def _clear_database_locks(db: Any) -> int:
        from sqlalchemy import text

        if db.get_bind().dialect.name != "postgresql":
            return 0
        rows = db.execute(
            text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid() "
                "AND state = 'idle in transaction' AND xact_start < now() - interval '10 minutes'"
            )
        ).all()
        db.commit()
        return len(rows)

    def _prepare_bundle(self, db: Any, issue: dict[str, Any]) -> dict[str, Any] | None:
        from app.services import diagnostics_bundle

        return diagnostics_bundle.prepare(db, data_dir=self.data_dir, reference=issue.get("reference") or "", reason=issue.get("title") or "")

    # ---- Records -----------------------------------------------------------------------------------------------------

    def remember(self, state: dict[str, Any], issue: dict[str, Any], result: str, detail: str, *, action: str = "") -> None:
        entry = {"at": _iso(self.now()), "reference": issue["reference"], "key": issue["key"], "signature": issue["signature"], "title": issue["title"], "action": action, "result": result, "detail": clean(detail), "tenant": issue.get("tenant") or ""}
        state["history"].insert(0, entry)
        state["history"] = state["history"][:HISTORY_KEPT]
        level = logging.WARNING if result in ("failed", NEEDS_OEM, "breaker-open") else logging.INFO
        log.log(level, "Self-recovery %s: %s (%s): %s", result, issue["title"], issue["reference"], entry["detail"], extra={"self_recovery_signature": issue["signature"], "self_recovery_reference": issue["reference"], "self_recovery_result": result})
        self.audit(issue, result, f"Self-recovery {result}: {issue['title']} ({issue['reference']}). {action + ': ' if action else ''}{entry['detail']}")

    def audit(self, issue: dict[str, Any], result: str, reason: str) -> None:
        try:
            from app.services.audit_service import write_audit_log

            with self.session_factory() as db:
                write_audit_log(
                    db,
                    tenant_id=issue.get("tenant") or None,
                    actor_user_id=None,
                    actor_type="system",
                    action=f"self_recovery.{result.replace('-', '_')}",
                    resource_type="system",
                    resource_id="self-recovery",
                    payload={"outcome": "failure" if result in ("failed", NEEDS_OEM, "breaker-open") else "changed", "reason": reason[:2000], "actor_id": APP_NAME, "type": "Updates & system", "reference": issue["reference"], "signature": issue["signature"]},
                )
                db.commit()
        except Exception as error:  # noqa: BLE001 - never stands in the way of recovering
            log.warning("Self-recovery could not write to the audit log: %s", error)

    # ---- One run -----------------------------------------------------------------------------------------------------

    def run(self, *, by: str = "schedule") -> dict[str, Any]:
        """Look, classify, act within the limits, escalate what cannot be fixed. Two at once never run."""

        self.data_dir.mkdir(parents=True, exist_ok=True)
        with open(self.data_dir / LOCK_FILE, "a+") as lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return {"skipped": True}
            try:
                return self._run(by)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _run(self, by: str) -> dict[str, Any]:
        state = self.load()
        now = self.now()
        at = _iso(now)
        escalated: list[dict[str, Any]] = []
        with self.session_factory() as db:
            probes = self.probe(db)
            try:
                lines = self.journal()
            except Exception:  # noqa: BLE001
                lines = []
            try:
                findings = self.collect(db, probes, lines)
            except Exception as error:  # noqa: BLE001 - a run that breaks is itself an issue
                log.warning("Self-recovery could not look: %s", error)
                findings = []
            seen = {f.key: f for f in findings}

            # What is no longer seen: recovered (after a rollback, only once the old version is back and healthy).
            for key, issue in list(state["issues"].items()):
                verify = issue.get("verify")
                if verify:
                    healthy = not [n for n in ("database", "redis", "worker", "beat") if probes.get(n) is False]
                    if self.version == verify.get("version") and healthy:
                        issue.pop("verify", None)
                        issue["status"] = RECOVERED
                        issue["recoveredAt"] = at
                        self.remember(state, issue, "verified", f"{display_version(self.version)} runs again and is healthy.")
                        continue
                    if (_parse(verify.get("deadline")) or now) <= now and issue["status"] != NEEDS_OEM:
                        issue.pop("verify", None)
                        escalated.append(self.escalate(state, issue, f"After going back, {display_version(verify.get('version') or '')} was not running and healthy within {VERIFY_SECONDS // 60} minutes."))
                    continue
                if key not in seen and issue.get("status") != RECOVERED:
                    issue["status"] = RECOVERED
                    issue["recoveredAt"] = at
                    self.remember(state, issue, "recovered", "No longer seen.")
                elif issue.get("status") == RECOVERED and (now - (_parse(issue.get("recoveredAt")) or now)).total_seconds() > FORGET_AFTER_SECONDS and key not in seen:
                    state["issues"].pop(key, None)

            for finding in findings:
                issue = state["issues"].get(finding.key)
                if issue is None:
                    issue = state["issues"][finding.key] = {
                        "key": finding.key,
                        "reference": reference_for(finding.key + ":" + finding.evidence_at[:10]),
                        "signature": finding.signature,
                        "title": finding.title,
                        "detail": clean(finding.detail),
                        "tenant": finding.tenant,
                        "firstSeen": at,
                        "lastSeen": at,
                        "status": OPEN,
                        "attempts": [],
                        "lastAction": "",
                        "lastResult": "",
                    }
                    self.remember(state, issue, "found", finding.detail)
                issue["lastSeen"] = at
                issue["detail"] = clean(finding.detail)
                if issue.get("verify"):
                    continue
                last_attempt = _parse(issue["attempts"][-1]) if issue["attempts"] else None
                # Nothing new since the last action: what it did is judged on newer evidence only.
                if last_attempt and finding.evidence_at and finding.evidence_at <= _iso(last_attempt):
                    if issue["status"] == RECOVERED:
                        continue
                    if issue["status"] == RECOVERING and not finding.evidence_at == at:
                        continue
                if issue["status"] == NEEDS_OEM:
                    continue
                if issue["status"] == RECOVERED:
                    issue["status"] = OPEN
                    issue["attempts"] = []
                    self.remember(state, issue, "found", f"Seen again: {finding.detail}")
                escalation = self.step(state, issue, finding, db, probes)
                if escalation:
                    escalated.append(escalation)

            state["lastRunAt"] = at
            state["lastRunBy"] = by
            self.save(state)
            for issue in escalated:
                try:
                    prepared = self.prepare_bundle(db, issue)
                except Exception as error:  # noqa: BLE001
                    log.warning("Self-recovery could not prepare the diagnostics bundle: %s", error)
                    prepared = None
                if prepared:
                    state["prepared"] = {**prepared, "reference": issue["reference"], "title": issue["title"]}
            if escalated:
                self.save(state)
        return {"issues": len(state["issues"]), "needsOem": [i["reference"] for i in state["issues"].values() if i.get("status") == NEEDS_OEM], "escalated": [i["reference"] for i in escalated]}

    def step(self, state: dict[str, Any], issue: dict[str, Any], finding: Finding, db: Any, probes: dict[str, Any]) -> dict[str, Any] | None:
        """One issue: act if the limits, the pause and the breaker allow; escalate when they do not. Returns the issue
        when it was escalated now."""

        signature = SIGNATURES[issue["signature"]]
        now = self.now()
        if signature.max_attempts == 0:
            return self.escalate(state, issue, f"{finding.detail} Hawk AI does not recognise this failure.")
        breaker = state["breakers"].setdefault(signature.id, {"failures": [], "openUntil": ""})
        open_until = _parse(breaker.get("openUntil"))
        if open_until and open_until > now:
            return self.escalate(state, issue, f"Actions of this kind failed {len(breaker['failures'])} times lately; they are paused until {breaker['openUntil'][:16].replace('T', ' ')} UTC (circuit breaker).")
        window_start = now - dt.timedelta(seconds=signature.window_seconds)
        attempts = [a for a in issue["attempts"] if (_parse(a) or now) >= window_start]
        issue["attempts"] = attempts
        if attempts:
            wait = signature.backoff_seconds * (2 ** (len(attempts) - 1))
            if (now - (_parse(attempts[-1]) or now)).total_seconds() < wait:
                return None
        if len(attempts) >= signature.max_attempts:
            return self.escalate(state, issue, f"{len(attempts)} attempt(s) to {signature.action.lower()} did not fix it.")
        try:
            outcome = self.act(db, finding, len(attempts) + 1, probes)
        except Exception as error:  # noqa: BLE001 - an action that breaks has failed
            try:
                db.rollback()
            except Exception:  # noqa: BLE001
                pass
            outcome = Outcome(False, f"The action failed: {clean(error, 200)}")
        issue["attempts"].append(_iso(now))
        issue["lastAction"] = signature.action
        issue["lastResult"] = clean(outcome.detail)
        if outcome.ok:
            breaker["failures"] = []
            breaker["openUntil"] = ""
            if outcome.pending:
                issue["status"] = RECOVERING
                if issue["signature"] in ("update_unhealthy", "update_failed") and "going back to" in outcome.detail.lower():
                    target = (finding.data or {}).get("target") or ((finding.data or {}).get("event") or {}).get("from") or ""
                    issue["verify"] = {"version": target, "deadline": _iso(now + dt.timedelta(seconds=VERIFY_SECONDS))}
                self.remember(state, issue, "tried", outcome.detail, action=signature.action)
            else:
                issue["status"] = RECOVERED
                issue["recoveredAt"] = _iso(now)
                self.remember(state, issue, "fixed", outcome.detail, action=signature.action)
            return None
        failures = [f for f in breaker["failures"] if (_parse(f) or now) >= window_start] + [_iso(now)]
        breaker["failures"] = failures
        self.remember(state, issue, "failed", outcome.detail, action=signature.action)
        if len(failures) >= signature.breaker_failures:
            breaker["openUntil"] = _iso(now + dt.timedelta(seconds=signature.cooldown_seconds))
            self.remember(state, issue, "breaker-open", f"{len(failures)} failed attempt(s) of this kind: no more until {breaker['openUntil'][:16].replace('T', ' ')} UTC.", action=signature.action)
            return self.escalate(state, issue, outcome.detail)
        if len(issue["attempts"]) >= signature.max_attempts:
            return self.escalate(state, issue, outcome.detail)
        issue["status"] = OPEN
        return None

    def escalate(self, state: dict[str, Any], issue: dict[str, Any], detail: str) -> dict[str, Any] | None:
        if issue.get("status") == NEEDS_OEM:
            return None
        issue["status"] = NEEDS_OEM
        issue["needsOemAt"] = _iso(self.now())
        issue["lastResult"] = clean(detail)
        self.remember(state, issue, NEEDS_OEM, f"{detail} Hawk AI stopped trying: download the diagnostics bundle on Settings → Backups & health and send it to the OEM.")
        self.watchdog_event("case", f"Self-recovery needs OEM help: {issue['title']} ({issue['reference']}).", key=issue["key"])
        return issue

    def retry(self, reference: str, *, by: str) -> bool:
        """An administrator's "Try again": the issue's attempts and its signature's breaker start afresh."""

        with open(self.data_dir / LOCK_FILE, "a+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                state = self.load()
                issue = next((i for i in state["issues"].values() if i.get("reference") == reference), None)
                if issue is None:
                    return False
                issue["status"] = OPEN
                issue["attempts"] = []
                issue.pop("verify", None)
                state["breakers"].pop(issue["signature"], None)
                self.remember(state, issue, "reset", f"Asked to try again by {by}.")
                self.save(state)
                return True
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    # ---- What the page shows ---------------------------------------------------------------------------------------

    def view(self, *, installation: bool, tenant_id: str = "") -> dict[str, Any]:
        """The issues and the history. An installation admin sees everything; a tenant's admin sees their tenant's in
        full and the installation's as plain status lines (what, when, the reference), never their detail."""

        state = self.load()

        def shown(item: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any] | None:
            own = (item.get("tenant") or "") == tenant_id and bool(tenant_id)
            if installation or own:
                return {k: item.get(k) for k in keys}
            if item.get("tenant"):
                return None  # another tenant's
            plain = {k: item.get(k) for k in keys if k in ("reference", "signature", "title", "status", "firstSeen", "lastSeen", "at", "result", "needsOemAt", "recoveredAt")}
            plain["detail"] = ""
            return plain

        issue_keys = ("reference", "signature", "title", "detail", "status", "firstSeen", "lastSeen", "lastAction", "lastResult", "needsOemAt", "recoveredAt", "tenant")
        issues = [s for s in (shown(i, issue_keys) for i in state["issues"].values()) if s]
        for item in issues:
            item["statusLabel"] = STATUS_WORDS.get(str(item.get("status")), str(item.get("status")))
            item["attempts"] = len(next((i for i in state["issues"].values() if i.get("reference") == item["reference"]), {}).get("attempts") or [])
            sig = SIGNATURES.get(str(item.get("signature")))
            item["limit"] = sig.max_attempts if sig else 0
            item["action"] = sig.action if sig else ""
        order = {NEEDS_OEM: 0, OPEN: 1, RECOVERING: 2, RECOVERED: 3}
        issues.sort(key=lambda i: (order.get(str(i.get("status")), 9), str(i.get("lastSeen") or "")), reverse=False)
        history = [s for s in (shown(h, ("at", "reference", "signature", "title", "action", "result", "detail", "tenant")) for h in state["history"]) if s][:100]
        needs = [i for i in issues if i.get("status") == NEEDS_OEM]
        return {
            "scope": "installation" if installation else "tenant",
            "lastRunAt": state["lastRunAt"],
            "everyMinutes": round(every_seconds(self.env) / 60),
            "issues": issues,
            "history": history,
            "needsOem": bool(needs),
            "needsOemReferences": [i["reference"] for i in needs],
            "prepared": state["prepared"] if installation else None,
            "signatures": [{"id": s.id, "title": s.title, "action": s.action, "maxAttempts": s.max_attempts, "windowHours": round(s.window_seconds / 3600, 1)} for s in SIGNATURES.values()],
        }


# ---- The API's guard: when the worker or the scheduler stopped, nothing else runs self-recovery ---------------------------

_guard: threading.Thread | None = None
_guard_lock = threading.Lock()


def overdue(state: dict[str, Any], every: int, now: dt.datetime) -> bool:
    last = _parse(state.get("lastRunAt"))
    return last is None or (now - last).total_seconds() > 3 * every


def start_guard(factory: Callable[[], SelfRecovery] = SelfRecovery, *, first_after: float = 120.0) -> None:
    """In the API process: every SELF_RECOVERY_EVERY_SECONDS, when the scheduled run is three times late (the worker or
    beat is down), run self-recovery here, so a stopped worker or scheduler is still restarted."""

    global _guard

    def loop() -> None:
        time.sleep(first_after)
        while True:
            every = every_seconds()
            try:
                supervisor = factory()
                if overdue(supervisor.load(), every, supervisor.now()):
                    supervisor.run(by="api-guard")
            except Exception as error:  # noqa: BLE001 - the guard never stops the API
                log.warning("Self-recovery guard: %s", error)
            time.sleep(every)

    with _guard_lock:
        if _guard is not None:
            return
        _guard = threading.Thread(target=loop, daemon=True, name="self-recovery-guard")
        _guard.start()


__all__ = [
    "DIAGNOSTICS_URL",
    "NEEDS_OEM",
    "SIGNATURES",
    "SelfRecovery",
    "classify_line",
    "every_seconds",
    "job_reference",
    "plain_job_failure",
    "reference_for",
    "start_guard",
]
