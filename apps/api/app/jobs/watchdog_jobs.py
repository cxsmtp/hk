"""The self-check and hands-off (app/services/self_check.py), sent by beat and run by the worker: the self-check every
WATCHDOG_EVERY_SECONDS (300), the replies to Hawk AI's emails every INBOX_EVERY_SECONDS (120), and the weekly status
when its day and hour come (looked at every 5 minutes). As in CxMissionZero, they run only while the product is active
(LicensedTask, the default), and an error in one is logged and never stops the next.
"""

from __future__ import annotations

from app.jobs.celery_app import celery_app
from app.jobs.watchdog_schedule import INBOX_TASK, SELF_CHECK_TASK, STATUS_TASK, beat_entries  # noqa: F401 - one place to find them


@celery_app.task(name=SELF_CHECK_TASK, acks_late=False)
def self_check() -> dict:
    from app.services.self_check import SelfCheck

    result = SelfCheck().run()
    return {"skipped": bool(result.get("skipped")), "problems": len(result.get("problems") or [])}


@celery_app.task(name=INBOX_TASK, acks_late=False)
def read_replies() -> dict:
    from app.services.self_check import SelfCheck

    return {"read": SelfCheck().inbox_tick()}


@celery_app.task(name=STATUS_TASK, acks_late=False)
def weekly_status() -> dict:
    from app.services.self_check import SelfCheck

    return {"sent": SelfCheck().status_tick()}
