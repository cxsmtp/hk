"""The scheduled backup (app/services/backup_service.py): one minute after the scheduler starts, then every
BACKUP_INTERVAL_HOURS (default 24), as CxMissionZero's server does (src/server.js). Beat sends it, the worker runs it
(it has pg_dump and the data folder).

Backups keep running while Hawk AI is deactivated or its terms are not yet accepted: they protect the data, so this
task is a plain Celery task, not a LicensedTask (app/jobs/licence_task.py).

Each run is recorded under "scheduled_backup" in scheduled_job_runs, so the self-check (app/services/self_check.py) sees
when the last two failed.
"""

from __future__ import annotations

import datetime as dt

from celery import Task

from app.jobs.backup_schedule import TASK_NAME, FirstSoonThenEvery, beat_entry  # noqa: F401 - one place to find them
from app.jobs.celery_app import celery_app
from app.services import backup_service

#: How its runs are recorded (scheduled_job_runs), for the self-check.
RUN_NAME = "scheduled_backup"


@celery_app.task(name=TASK_NAME, base=Task, acks_late=False)
def run_scheduled_backup() -> dict:
    started = dt.datetime.now(dt.timezone.utc)
    result = backup_service.backup_to_folder("Scheduled")
    record_run(result, started)
    return result


def record_run(result: dict, started: dt.datetime) -> None:
    from app.services.job_run_service import write_scheduled_job_run

    try:
        write_scheduled_job_run(
            job_name=RUN_NAME,
            status="success" if result.get("ok") else "fail",
            started_at=started,
            finished_at=dt.datetime.now(dt.timezone.utc),
            error_message=None if result.get("ok") else str(result.get("error") or "The backup failed.")[:4000],
        )
    except Exception:  # noqa: BLE001 - the backup itself is what matters
        pass
