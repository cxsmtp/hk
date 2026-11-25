"""When the self-check and hands-off run (app/jobs/watchdog_jobs.py), as CxMissionZero's loops do
(src/routes/hands-off.js): the self-check every WATCHDOG_EVERY_SECONDS (300), first after a minute at most; the replies
every INBOX_EVERY_SECONDS (120), first after 30 seconds at most; the weekly status's turn every 5 minutes, first after 30
seconds. Kept apart from the tasks so that app/jobs/celery_app.py can read it without importing the task module first.
"""

from __future__ import annotations

import datetime as dt

from app.jobs.backup_schedule import FirstSoonThenEvery
from app.services.self_check import inbox_every_seconds, watchdog_every_seconds

SELF_CHECK_TASK = "app.jobs.watchdog_jobs.self_check"
INBOX_TASK = "app.jobs.watchdog_jobs.read_replies"
STATUS_TASK = "app.jobs.watchdog_jobs.weekly_status"
STATUS_EVERY_SECONDS = 5 * 60


def beat_entries(env=None) -> dict[str, dict]:
    watchdog = watchdog_every_seconds(env)
    inbox = inbox_every_seconds(env)
    return {
        "self-check": {"task": SELF_CHECK_TASK, "schedule": FirstSoonThenEvery(dt.timedelta(seconds=watchdog), first_after=min(60, watchdog)), "options": {"queue": "default"}},
        "hands-off-replies": {"task": INBOX_TASK, "schedule": FirstSoonThenEvery(dt.timedelta(seconds=inbox), first_after=min(30, inbox)), "options": {"queue": "default"}},
        "hands-off-weekly-status": {"task": STATUS_TASK, "schedule": FirstSoonThenEvery(dt.timedelta(seconds=STATUS_EVERY_SECONDS), first_after=30), "options": {"queue": "default"}},
    }
