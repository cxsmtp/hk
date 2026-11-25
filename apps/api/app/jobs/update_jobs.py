"""Auto-update and the scheduled software integrity check, sent by beat and run by the worker (the worker runs the api
image, so its files are the API's).

- Auto-update (app/services/updates/service.py): the first look one minute after the scheduler starts, then every
  AUTO_UPDATE_EVERY_SECONDS (900), as CxMissionZero's server does. It does nothing while auto-update is off (the
  default).
- Software integrity (app/services/integrity/service.py): every INTEGRITY_CHECK_HOURS (6); the API checks itself at
  start too.

Plain Celery tasks, not LicensedTask (app/jobs/licence_task.py): like backups, they keep a deactivated installation
safe and up to date.
"""

from __future__ import annotations

from celery import Task

from app.jobs.celery_app import celery_app
from app.jobs.update_schedule import AUTO_UPDATE_TASK, INTEGRITY_TASK, beat_entries  # noqa: F401 - one place to find them


@celery_app.task(name=AUTO_UPDATE_TASK, base=Task, acks_late=False)
def auto_update() -> dict | None:
    from app.services.updates.service import UpdateService

    result = UpdateService().auto_update()
    return {"requested": bool(result)}


@celery_app.task(name=INTEGRITY_TASK, base=Task, acks_late=False)
def check_integrity() -> dict:
    from app.services.integrity.service import IntegrityService

    result = IntegrityService().check(reason="scheduled")
    return {"state": result.get("state")}
