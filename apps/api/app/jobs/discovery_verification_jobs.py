"""Bounded scheduling for Autonomous Discovery Verification."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from app.core.config import settings
from app.db.models.discovery_verification import DiscoveryVerificationEpisode
from app.db.models.tenant import Tenant
from app.db.session import SessionLocal
from app.jobs.celery_app import celery_app
from app.services.hmair.adv.continuous_validation import ContinuousValidationService
from app.services.job_run_service import tracked_scheduled_job


@celery_app.task(
    name="app.jobs.discovery_verification_jobs.run_due_discovery_verifications"
)
def run_due_discovery_verifications(tenant_id: str) -> dict[str, object]:
    if not settings.cie_core:
        return {"status": "disabled", "tenant_id": tenant_id, "scheduled": 0}
    with tracked_scheduled_job("adv_continuous_validation", tenant_id=tenant_id):
        with SessionLocal() as db:
            tenant = db.scalar(
                select(Tenant).where(
                    Tenant.id == tenant_id, Tenant.is_active.is_(True)
                )
            )
            if tenant is None:
                return {"status": "tenant_not_found", "tenant_id": tenant_id, "scheduled": 0}
            try:
                service = ContinuousValidationService()
                assertions = service.evaluate_ready(
                    db,
                    tenant_id=tenant_id,
                    evaluated_at=datetime.now(timezone.utc),
                    limit=100,
                )
                plans = service.schedule_due(
                    db,
                    tenant_id=tenant_id,
                    evaluated_at=datetime.now(timezone.utc),
                    limit=100,
                )
                db.commit()
            except Exception:
                db.rollback()
                raise
            return {
                "status": "success",
                "tenant_id": tenant_id,
                "scheduled": len(plans),
                "asserted": len(assertions),
                "episode_ids": [item.episode.episode_id for item in plans],
            }


@celery_app.task(
    name="app.jobs.discovery_verification_jobs.enqueue_due_discovery_verifications"
)
def enqueue_due_discovery_verifications() -> dict[str, object]:
    if not settings.cie_core:
        return {"status": "disabled", "enqueued": 0, "tenant_ids": []}
    with SessionLocal() as db:
        tenant_ids = sorted(
            set(
                db.scalars(
                    select(Tenant.id)
                    .join(
                        DiscoveryVerificationEpisode,
                        DiscoveryVerificationEpisode.tenant_id == Tenant.id,
                    )
                    .where(Tenant.is_active.is_(True))
                ).all()
            )
        )
    for tenant_id in tenant_ids:
        run_due_discovery_verifications.delay(tenant_id)
    return {"status": "enqueued", "enqueued": len(tenant_ids), "tenant_ids": tenant_ids}


__all__ = [
    "enqueue_due_discovery_verifications",
    "run_due_discovery_verifications",
]
