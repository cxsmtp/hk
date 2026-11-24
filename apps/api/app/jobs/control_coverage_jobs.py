"""Guarded materialization jobs for versioned Control Coverage snapshots."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from app.core.config import parse_control_coverage_rollout, settings
from app.db.models.tenant import Tenant
from app.db.session import SessionLocal
from app.jobs.celery_app import celery_app
from app.services.control_coverage.service import calculate_tenant_control_coverage
from app.services.job_run_service import tracked_scheduled_job


def control_coverage_enabled_for_tenant(tenant_id: str) -> bool:
    if not (
        settings.control_coverage_materialization_enabled
        and settings.control_coverage_snapshot_enabled
    ):
        return False
    rollout = parse_control_coverage_rollout(settings.control_coverage_rollout)
    return rollout.get(str(tenant_id or "").strip()) is True


@celery_app.task(name="app.jobs.control_coverage_jobs.refresh_control_coverage")
def refresh_control_coverage(tenant_id: str) -> dict[str, object]:
    if not control_coverage_enabled_for_tenant(tenant_id):
        return {
            "tenant_id": tenant_id,
            "status": "disabled",
            "paths": 0,
            "assertions": 0,
            "snapshot_id": None,
        }
    with tracked_scheduled_job("control_coverage_refresh", tenant_id=tenant_id):
        with SessionLocal() as db:
            tenant = db.scalar(
                select(Tenant).where(
                    Tenant.id == tenant_id,
                    Tenant.is_active.is_(True),
                )
            )
            if tenant is None:
                return {
                    "tenant_id": tenant_id,
                    "status": "tenant_not_found",
                    "paths": 0,
                    "assertions": 0,
                    "snapshot_id": None,
                }
            try:
                result = calculate_tenant_control_coverage(
                    db,
                    tenant_id=tenant_id,
                    now=datetime.now(timezone.utc),
                    window_days=settings.control_coverage_default_window_days,
                )
                db.commit()
            except Exception:
                db.rollback()
                raise
            return {
                "tenant_id": tenant_id,
                "status": "success",
                "paths": len(result.paths),
                "assertions": len(result.assertions),
                "snapshot_id": result.snapshot.id,
                "input_digest": result.snapshot.input_digest,
            }


@celery_app.task(name="app.jobs.control_coverage_jobs.enqueue_control_coverage_refreshes")
def enqueue_control_coverage_refreshes() -> dict[str, object]:
    if not (
        settings.control_coverage_materialization_enabled
        and settings.control_coverage_snapshot_enabled
    ):
        return {"status": "disabled", "enqueued": 0, "tenant_ids": []}
    rollout = parse_control_coverage_rollout(settings.control_coverage_rollout)
    enabled_ids = sorted(tenant_id for tenant_id, enabled in rollout.items() if enabled)
    if not enabled_ids:
        return {"status": "disabled", "enqueued": 0, "tenant_ids": []}
    with SessionLocal() as db:
        active_ids = db.scalars(
            select(Tenant.id).where(
                Tenant.id.in_(enabled_ids),
                Tenant.is_active.is_(True),
            )
        ).all()
    tenant_ids = sorted(active_ids)
    for tenant_id in tenant_ids:
        refresh_control_coverage.delay(tenant_id)
    return {"status": "enqueued", "enqueued": len(tenant_ids), "tenant_ids": tenant_ids}
