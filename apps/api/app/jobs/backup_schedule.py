"""When the scheduled backup runs (app/jobs/backup_jobs.py): one minute after the scheduler starts, then every
BACKUP_INTERVAL_HOURS (default 24), as CxMissionZero's server does (src/server.js). Kept apart from the task so that
app/jobs/celery_app.py can read it without importing the task module first.
"""

from __future__ import annotations

import datetime as dt
import os

from celery.schedules import schedstate, schedule

from app.services.backup_service import _int

TASK_NAME = "app.jobs.backup_jobs.run_scheduled_backup"
FIRST_AFTER_SECONDS = 60


class FirstSoonThenEvery(schedule):
    """Due ``first_after`` after the scheduler starts (a fresh baseline), then every ``run_every``."""

    def __init__(self, run_every: dt.timedelta, first_after: float = FIRST_AFTER_SECONDS, app=None, nowfun=None) -> None:
        super().__init__(run_every=run_every, app=app, nowfun=nowfun)
        self.first_after = dt.timedelta(seconds=first_after)
        self._started: dt.datetime | None = None
        self._first_done = False

    def is_due(self, last_run_at: dt.datetime) -> schedstate:
        if not self._first_done:
            now = self.now()
            if self._started is None:
                self._started = now
            remaining = (self._started + self.first_after - now).total_seconds()
            if remaining <= 0:
                self._first_done = True
                return schedstate(True, self.run_every.total_seconds())
            return schedstate(False, remaining)
        return super().is_due(last_run_at)

    def __reduce__(self):
        return (self.__class__, (self.run_every, self.first_after.total_seconds(), None, self.nowfun))

    def __eq__(self, other: object) -> bool:
        return isinstance(other, FirstSoonThenEvery) and other.run_every == self.run_every and other.first_after == self.first_after

    def __hash__(self) -> int:
        return hash((self.run_every, self.first_after))


def beat_entry(env=None) -> dict | None:
    """The beat schedule's entry, or None when BACKUP_INTERVAL_HOURS=0 turns scheduled backups off."""

    env = os.environ if env is None else env
    hours = _int(env, "BACKUP_INTERVAL_HOURS", 24, 0)
    if hours <= 0:
        return None
    return {"task": TASK_NAME, "schedule": FirstSoonThenEvery(dt.timedelta(hours=hours)), "options": {"queue": "default"}}
