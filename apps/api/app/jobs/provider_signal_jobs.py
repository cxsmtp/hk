"""Bounded, non-destructive provider-signal retention candidate reporting."""

from __future__ import annotations

from sqlalchemy import select

from app.core.config import parse_provider_signal_retention_rollout, settings
from app.db.models.tenant import Tenant
from app.db.session import SessionLocal
from app.jobs.celery_app import celery_app
from app.services.audit_service import write_audit_log
from app.services.job_run_service import tracked_scheduled_job
from app.services.provider_signals import purge_expired_provider_signal_records


MAX_TENANTS_PER_RETENTION_REPORT = 100


@celery_app.task(name="app.jobs.provider_signal_jobs.report_provider_signal_retention_candidates")
def report_provider_signal_retention_candidates(tenant_id: str) -> dict[str, object]:
    """Create an audited candidate count; this task never deletes customer data."""

    with tracked_scheduled_job("provider_signal_retention_candidate_report", tenant_id=tenant_id):
        with SessionLocal() as db:
            tenant = db.scalar(select(Tenant).where(Tenant.id == tenant_id, Tenant.is_active.is_(True)))
            if tenant is None:
                return {"tenant_id": tenant_id, "status": "tenant_not_found", "executed": False}
            result = purge_expired_provider_signal_records(
                db,
                tenant_id=tenant_id,
                retention_days=settings.evidence_retention_days,
            )
            payload = {
                "cutoff_at": result.cutoff_at.isoformat(),
                "candidate_signal_records": result.candidate_signal_records,
                "candidate_seat_snapshots": result.candidate_seat_snapshots,
            }
            write_audit_log(
                db,
                tenant_id=tenant_id,
                actor_user_id=None,
                actor_type="system",
                action="provider_signal_retention_candidates_reported",
                resource_type="provider_signal_retention",
                resource_id="received_at",
                payload=payload,
            )
            db.commit()
            return {
                "tenant_id": tenant_id,
                "status": "candidates_reported",
                "executed": False,
                "more_remaining": result.more_remaining,
                **payload,
            }


@celery_app.task(name="app.jobs.provider_signal_jobs.enqueue_provider_signal_retention_candidate_reports")
def enqueue_provider_signal_retention_candidate_reports() -> dict[str, object]:
    """Report only for explicitly configured tenant scopes; no cross-tenant sweep."""

    rollout = parse_provider_signal_retention_rollout(settings.provider_signal_retention_rollout)
    tenant_ids = sorted(tenant_id for tenant_id, included in rollout.items() if included)
    if not tenant_ids:
        return {"status": "no_tenant_rollout", "enqueued": 0, "tenant_ids": []}
    with SessionLocal() as db:
        active_tenant_ids = sorted(
            db.scalars(
                select(Tenant.id)
                .where(Tenant.id.in_(tenant_ids), Tenant.is_active.is_(True))
                .limit(MAX_TENANTS_PER_RETENTION_REPORT)
            ).all()
        )
    for tenant_id in active_tenant_ids:
        report_provider_signal_retention_candidates.delay(tenant_id)
    return {"status": "enqueued", "enqueued": len(active_tenant_ids), "tenant_ids": active_tenant_ids}
