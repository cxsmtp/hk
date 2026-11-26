"""The emailed copies of the accepted licence agreement (app/services/terms_copy_service.py), sent by beat every five
minutes: whatever waited for the email server goes out once it has been tested, and failed sends are retried with
backoff. Runs only while the product is active and the agreement accepted (LicensedTask, the default).
"""

from __future__ import annotations

from app.jobs.celery_app import celery_app

TERMS_COPY_TASK = "app.jobs.terms_jobs.send_terms_copies"
TERMS_COPY_EVERY_SECONDS = 300.0


@celery_app.task(name=TERMS_COPY_TASK, acks_late=False)
def send_terms_copies() -> dict:
    from app.db.session import engine
    from app.services import terms_copy_service

    return terms_copy_service.deliver_with(engine)
