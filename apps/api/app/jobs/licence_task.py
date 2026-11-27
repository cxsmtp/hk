"""Background tasks stop while Hawk AI is deactivated (/settings/guide/licence).

Every Celery task is a LicensedTask (app/jobs/celery_app.py). While the product licence is not active a task does
not run: it logs once and returns, without a retry, so scheduled work simply stops until a licence is
imported, and starts again on its next run after that, with no restart.

The same goes until an owner or admin has accepted the terms of use for the organisation (TERMS.md,
app/services/terms_service.py): as in CxMissionZero, automation is closed until then.
"""

from __future__ import annotations

import logging
import threading

from celery import Task

from app.services import activation_service, terms_service


logger = logging.getLogger(__name__)

_skipping = False
_skipping_lock = threading.Lock()
_waiting_for_terms = False


def _note_skipped(task_name: str) -> None:
    global _skipping
    with _skipping_lock:
        first = not _skipping
        _skipping = True
    if first:
        logger.warning(
            "Hawk AI has been deactivated: background tasks do not run until a .hawkai licence is imported (first skipped: %s).",
            task_name,
        )


def _note_active() -> None:
    global _skipping
    with _skipping_lock:
        _skipping = False


def _terms_accepted(task_name: str) -> bool:
    global _waiting_for_terms
    try:
        accepted = terms_service.organisation_accepted()
    except Exception:  # noqa: BLE001 - a database that is not there yet: the task's own errors say more
        return True
    with _skipping_lock:
        first = not accepted and not _waiting_for_terms
        _waiting_for_terms = not accepted
    if first:
        logger.warning(
            "Background tasks do not run until an administrator accepts the terms of use for the organisation (first skipped: %s).",
            task_name,
        )
    return accepted


class LicensedTask(Task):
    def __call__(self, *args, **kwargs):
        if not activation_service.licence_active():
            _note_skipped(self.name)
            return None
        _note_active()
        if not _terms_accepted(self.name):
            return None
        return super().__call__(*args, **kwargs)
