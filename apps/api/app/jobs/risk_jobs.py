from __future__ import annotations

from app.jobs.celery_app import celery_app
from app.services.job_run_service import tracked_scheduled_job


@celery_app.task(name="app.jobs.risk_jobs.reconfigure_risk_runtime")
def reconfigure_risk_runtime(
    tenant_id: str,
    ai_system_id: str,
    strictness_profile: str,
    simulation_frequency: str,
    simulation_interval_minutes: int,
    reason: str = "risk_tier_change",
) -> dict:
    with tracked_scheduled_job("risk_reconfiguration_hook", tenant_id=tenant_id):
        return {
            "tenant_id": tenant_id,
            "ai_system_id": ai_system_id,
            "strictness_profile": strictness_profile,
            "simulation_frequency": simulation_frequency,
            "simulation_interval_minutes": simulation_interval_minutes,
            "reason": reason,
            "status": "reconfigured",
        }
