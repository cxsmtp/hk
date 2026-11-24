from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.db.models.tenant import Tenant
from app.db.session import SessionLocal
from app.jobs.celery_app import celery_app
from app.services.job_run_service import tracked_scheduled_job
from app.services.snapshot_service import cleanup_auditor_artifacts, create_auditor_snapshot, export_audit_artifacts


@celery_app.task(name="app.jobs.auditor_jobs.export_audit_snapshot")
def export_audit_snapshot(tenant_id: str, ai_system_id: str | None = None) -> dict:
    db = SessionLocal()
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=30)
        out = export_audit_artifacts(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            period_start=start.isoformat(),
            period_end=end.isoformat(),
        )
        snapshot = create_auditor_snapshot(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            trigger_type="scheduled_daily_export",
            payload={
                "period_start": start.isoformat(),
                "period_end": end.isoformat(),
                "artifacts": out,
            },
            actor_user_id=None,
            artifact_hash=out.get("hash"),
            artifact_relative_path=out.get("json_relative_path"),
        )
        db.commit()
        return {**out, "snapshot_id": snapshot.id}
    finally:
        db.close()


@celery_app.task(name="app.jobs.auditor_jobs.run_daily_snapshot_pack")
def run_daily_snapshot_pack() -> dict:
    with tracked_scheduled_job("daily_snapshot_pack", tenant_id=None):
        db = SessionLocal()
        try:
            tenants = db.scalars(select(Tenant).where(Tenant.is_active.is_(True))).all()
        finally:
            db.close()

        results: list[dict] = []
        for tenant in tenants:
            result = export_audit_snapshot(tenant_id=tenant.id, ai_system_id=None)
            results.append({"tenant_id": tenant.id, "snapshot_id": result.get("snapshot_id")})

        return {"tenants_processed": len(tenants), "results": results}


@celery_app.task(name="app.jobs.auditor_jobs.cleanup_auditor_export_artifacts")
def cleanup_auditor_export_artifacts(retention_days: int = 90, dry_run: bool = False) -> dict:
    with tracked_scheduled_job("auditor_artifact_cleanup", tenant_id=None):
        db = SessionLocal()
        try:
            result = cleanup_auditor_artifacts(db, retention_days=retention_days, dry_run=dry_run)
            db.commit()
            return result
        finally:
            db.close()
