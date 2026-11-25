"""When auto-update and the software integrity check run (app/jobs/update_jobs.py): auto-update's first look one minute
after the scheduler starts, then every AUTO_UPDATE_EVERY_SECONDS (900); the integrity check every INTEGRITY_CHECK_HOURS
(6). Kept apart from the tasks so that app/jobs/celery_app.py can read it without importing the task module first.
"""

from __future__ import annotations

import datetime as dt
import os

from app.jobs.backup_schedule import FirstSoonThenEvery
from app.services.backup_service import _int

AUTO_UPDATE_TASK = "app.jobs.update_jobs.auto_update"
INTEGRITY_TASK = "app.jobs.update_jobs.check_integrity"
FIRST_LOOK_SECONDS = 60


def beat_entries(env=None) -> dict[str, dict]:
    env = os.environ if env is None else env
    every = _int(env, "AUTO_UPDATE_EVERY_SECONDS", 900, 60)
    try:
        hours = max(0.1, float(env.get("INTEGRITY_CHECK_HOURS") or 6))
    except ValueError:
        hours = 6.0
    return {
        "auto-update": {"task": AUTO_UPDATE_TASK, "schedule": FirstSoonThenEvery(dt.timedelta(seconds=every), first_after=FIRST_LOOK_SECONDS), "options": {"queue": "default"}},
        "software-integrity": {"task": INTEGRITY_TASK, "schedule": dt.timedelta(hours=hours), "options": {"queue": "default"}},
    }
