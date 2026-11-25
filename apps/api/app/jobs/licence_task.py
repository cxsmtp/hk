"""Background tasks stop while Hawk AI is deactivated (docs/activation-codes.md).

Every Celery task is a LicensedTask (app/jobs/celery_app.py). While the product licence is not active a task does
not run: it logs once and returns, without a retry, so scheduled work simply stops until an activation code is
entered, and starts again on its next run after that, with no restart.
"""

from __future__ import annotations

import logging
import threading

from celery import Task

from app.services import activation_service


logger = logging.getLogger(__name__)

_skipping = False
_skipping_lock = threading.Lock()


def _note_skipped(task_name: str) -> None:
    global _skipping
    with _skipping_lock:
        first = not _skipping
        _skipping = True
    if first:
        logger.warning(
            "Hawk AI has been deactivated: background tasks do not run until an activation code is entered (first skipped: %s).",
            task_name,
        )


def _note_active() -> None:
    global _skipping
    with _skipping_lock:
        _skipping = False


class LicensedTask(Task):
    def __call__(self, *args, **kwargs):
        if not activation_service.licence_active():
            _note_skipped(self.name)
            return None
        _note_active()
        return super().__call__(*args, **kwargs)
