from pathlib import Path


def test_native_control_health_job_is_registered_and_scheduled() -> None:
    source = Path("app/jobs/celery_app.py").read_text(encoding="utf-8")
    assert "app.jobs.native_control_jobs.reconcile_native_control_health" in source
    assert '"native-control-health-every-minute"' in source
    job = Path("app/jobs/native_control_jobs.py").read_text(encoding="utf-8")
    assert "reconcile_tenant_native_controls" in job
    assert "db.commit()" in job
    assert "db.rollback()" in job

