from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from app.core.config import settings
from app.db.models.tenant import Tenant
from app.db.session import SessionLocal
from app.jobs.celery_app import celery_app
from app.services.job_run_service import tracked_scheduled_job
from app.services.native_control.reconciler import reconcile_tenant_native_controls


@celery_app.task(name="app.jobs.native_control_jobs.reconcile_native_control_health")
def reconcile_native_control_health() -> dict[str, object]:
    if not settings.native_control_framework:
        return {"status": "disabled", "tenants": 0, "integrations": 0}
    with tracked_scheduled_job("native_control_health_reconciliation", tenant_id=None):
        with SessionLocal() as db:
            tenant_ids = list(
                db.scalars(select(Tenant.id).where(Tenant.is_active.is_(True)).order_by(Tenant.id)).all()
            )
        integrations = 0
        degraded = 0
        for tenant_id in tenant_ids:
            with SessionLocal() as db:
                try:
                    result = reconcile_tenant_native_controls(
                        db,
                        tenant_id=tenant_id,
                        now=datetime.now(timezone.utc),
                    )
                    integrations += int(result["reconciled"])
                    degraded += int(result["degraded"])
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
        return {
            "status": "success",
            "tenants": len(tenant_ids),
            "integrations": integrations,
            "degraded": degraded,
        }
