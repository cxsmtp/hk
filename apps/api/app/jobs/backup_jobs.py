"""The scheduled backup (app/services/backup_service.py): one minute after the scheduler starts, then every
BACKUP_INTERVAL_HOURS (default 24), as CxMissionZero's server does (src/server.js). Beat sends it, the worker runs it
(it has pg_dump and the data folder).

Backups keep running while Hawk AI is deactivated or its terms are not yet accepted: they protect the data, so this
task is a plain Celery task, not a LicensedTask (app/jobs/licence_task.py).
"""

from __future__ import annotations

from celery import Task

from app.jobs.backup_schedule import TASK_NAME, FirstSoonThenEvery, beat_entry  # noqa: F401 - one place to find them
from app.jobs.celery_app import celery_app
from app.services import backup_service


@celery_app.task(name=TASK_NAME, base=Task, acks_late=False)
def run_scheduled_backup() -> dict:
    return backup_service.backup_to_folder("Scheduled")
