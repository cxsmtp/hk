from __future__ import annotations

import threading
import time

from celery import Celery
from celery.schedules import crontab
from celery.signals import beat_init, heartbeat_sent, task_failure, worker_ready

from app.core.config import settings
from app.jobs import backup_schedule, update_schedule
from app.jobs.licence_task import LicensedTask
from app.services.control_plane_health_service import write_beat_heartbeat, write_worker_heartbeat
from app.services.job_run_service import write_dead_letter_job_run


celery_app = Celery(
    "ai_control_plane",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    # While Hawk AI is deactivated, tasks do not run (app/jobs/licence_task.py).
    task_cls=LicensedTask,
)

_DEFAULT_TASK_RETRY_POLICY = {
    "autoretry_for": (Exception,),
    "retry_backoff": True,
    "retry_backoff_max": 120,
    "retry_jitter": True,
    "max_retries": 5,
}

celery_app.conf.update(
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_default_retry_delay=5,
    task_annotations={
        "app.jobs.monitoring_jobs.run_all_connectors": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.monitoring_jobs.run_scheduled_monitoring_checks": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.monitoring_jobs.run_monitoring_15m_checks": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.monitoring_jobs.run_monitoring_hourly_checks": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.monitoring_jobs.run_monitoring_daily_checks": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.auditor_jobs.export_audit_snapshot": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.auditor_jobs.run_daily_snapshot_pack": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.enforcement_jobs.resolve_timed_out_approvals": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.enforcement_jobs.run_sla_timeout_checks": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.enforcement_jobs.ocr_extract_text": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.risk_jobs.reconfigure_risk_runtime": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.control_coverage_jobs.refresh_control_coverage": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.control_coverage_jobs.enqueue_control_coverage_refreshes": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.hmair_discovery_jobs.dispatch_scan": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.hmair_discovery_jobs.run_collector_assignment": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.hmair_discovery_jobs.finalize_discovery_scan": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.hmair_discovery_jobs.reconcile_endpoint_metadata_inventory": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.hmair_discovery_jobs.enqueue_endpoint_metadata_inventory_reconciliation": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.native_control_jobs.reconcile_native_control_health": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.discovery_verification_jobs.run_due_discovery_verifications": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.discovery_verification_jobs.enqueue_due_discovery_verifications": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.maturity_curve_jobs.refresh_maturity_curve": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.maturity_curve_jobs.enqueue_maturity_curve_refreshes": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.provider_signal_jobs.report_provider_signal_retention_candidates": dict(_DEFAULT_TASK_RETRY_POLICY),
        "app.jobs.provider_signal_jobs.enqueue_provider_signal_retention_candidate_reports": dict(_DEFAULT_TASK_RETRY_POLICY),
    },
)

celery_app.conf.task_routes = {
    "app.jobs.monitoring_jobs.run_all_connectors": {"queue": "monitoring"},
    "app.jobs.monitoring_jobs.run_scheduled_monitoring_checks": {"queue": "monitoring"},
    "app.jobs.monitoring_jobs.run_monitoring_15m_checks": {"queue": "monitoring"},
    "app.jobs.monitoring_jobs.run_monitoring_hourly_checks": {"queue": "monitoring"},
    "app.jobs.monitoring_jobs.run_monitoring_daily_checks": {"queue": "monitoring"},
    "app.jobs.auditor_jobs.export_audit_snapshot": {"queue": "auditor"},
    "app.jobs.auditor_jobs.run_daily_snapshot_pack": {"queue": "auditor"},
    "app.jobs.enforcement_jobs.resolve_timed_out_approvals": {"queue": "auditor"},
    "app.jobs.enforcement_jobs.run_sla_timeout_checks": {"queue": "auditor"},
    "app.jobs.enforcement_jobs.ocr_extract_text": {"queue": "auditor"},
    "app.jobs.risk_jobs.reconfigure_risk_runtime": {"queue": "monitoring"},
    "app.jobs.control_coverage_jobs.refresh_control_coverage": {"queue": "monitoring"},
    "app.jobs.control_coverage_jobs.enqueue_control_coverage_refreshes": {"queue": "monitoring"},
    "app.jobs.hmair_discovery_jobs.dispatch_scan": {"queue": "discovery"},
    "app.jobs.hmair_discovery_jobs.run_collector_assignment": {"queue": "discovery"},
    "app.jobs.hmair_discovery_jobs.finalize_discovery_scan": {"queue": "discovery"},
    "app.jobs.hmair_discovery_jobs.reconcile_endpoint_metadata_inventory": {"queue": "discovery"},
    "app.jobs.hmair_discovery_jobs.enqueue_endpoint_metadata_inventory_reconciliation": {"queue": "discovery"},
    "app.jobs.native_control_jobs.reconcile_native_control_health": {"queue": "monitoring"},
    "app.jobs.discovery_verification_jobs.run_due_discovery_verifications": {"queue": "discovery"},
    "app.jobs.discovery_verification_jobs.enqueue_due_discovery_verifications": {"queue": "discovery"},
    "app.jobs.maturity_curve_jobs.refresh_maturity_curve": {"queue": "monitoring"},
    "app.jobs.maturity_curve_jobs.enqueue_maturity_curve_refreshes": {"queue": "monitoring"},
    "app.jobs.provider_signal_jobs.report_provider_signal_retention_candidates": {"queue": "auditor"},
    "app.jobs.provider_signal_jobs.enqueue_provider_signal_retention_candidate_reports": {"queue": "auditor"},
}

celery_app.conf.timezone = "UTC"
celery_app.conf.beat_schedule = {
    "adv-continuous-validation-every-five-minutes": {
        "task": "app.jobs.discovery_verification_jobs.enqueue_due_discovery_verifications",
        "schedule": 300.0,
        "options": {"queue": "discovery"},
    },
    "hmair-endpoint-inventory-reconciliation-every-minute": {
        "task": "app.jobs.hmair_discovery_jobs.enqueue_endpoint_metadata_inventory_reconciliation",
        "schedule": 60.0,
        "options": {"queue": "discovery"},
    },
    "native-control-health-every-minute": {
        "task": "app.jobs.native_control_jobs.reconcile_native_control_health",
        "schedule": 60.0,
        "options": {"queue": "monitoring"},
    },
    "approval-sla-timeout-every-minute": {
        "task": "app.jobs.enforcement_jobs.run_sla_timeout_checks",
        "schedule": 60.0,
        "options": {"queue": "auditor"},
    },
    "monitoring-checks-every-fifteen-minutes": {
        "task": "app.jobs.monitoring_jobs.run_monitoring_15m_checks",
        "schedule": 900.0,
        "options": {"queue": "monitoring"},
    },
    "control-coverage-snapshot-refresh": {
        "task": "app.jobs.control_coverage_jobs.enqueue_control_coverage_refreshes",
        "schedule": float(settings.control_coverage_snapshot_interval_minutes * 60),
        "options": {"queue": "monitoring"},
    },
    "maturity-curve-refresh": {
        "task": "app.jobs.maturity_curve_jobs.enqueue_maturity_curve_refreshes",
        "schedule": float(settings.maturity_curve_materialization_interval_minutes * 60),
        "options": {"queue": "monitoring"},
    },
    "monitoring-hourly-cycle": {
        "task": "app.jobs.monitoring_jobs.run_monitoring_hourly_checks",
        "schedule": crontab(minute=0),
        "options": {"queue": "monitoring"},
    },
    "monitoring-daily-cycle": {
        "task": "app.jobs.monitoring_jobs.run_monitoring_daily_checks",
        "schedule": crontab(hour=1, minute=0),
        "options": {"queue": "monitoring"},
    },
    "daily-snapshot-pack": {
        "task": "app.jobs.auditor_jobs.run_daily_snapshot_pack",
        "schedule": crontab(hour=0, minute=0),
        "options": {"queue": "auditor"},
    },
    "provider-signal-retention-candidate-report": {
        "task": "app.jobs.provider_signal_jobs.enqueue_provider_signal_retention_candidate_reports",
        "schedule": crontab(hour=2, minute=30),
        "options": {"queue": "auditor"},
    },
}


_beat_heartbeat_thread_started = False
_beat_heartbeat_lock = threading.Lock()
_worker_heartbeat_thread_started = False
_worker_heartbeat_lock = threading.Lock()


def _beat_heartbeat_loop() -> None:
    interval = max(10.0, float(settings.control_plane_heartbeat_max_age_seconds) / 2.0)
    while True:
        write_beat_heartbeat()
        time.sleep(interval)


def _worker_heartbeat_loop() -> None:
    interval = max(10.0, float(settings.control_plane_heartbeat_max_age_seconds) / 2.0)
    while True:
        write_worker_heartbeat()
        time.sleep(interval)


def _hold_instance_lock(name: str) -> None:
    """A running worker or beat holds its share of Hawk AI's instance lock, so a restore refuses while it runs
    (app/services/pg_tools.py)."""

    from app.services.pg_tools import InstanceLock

    try:
        InstanceLock(settings.database_url, name=name).acquire()
    except Exception as error:  # noqa: BLE001 - said in the log; the process runs as before
        print(f"! [backup] Could not take Hawk AI's instance lock: {error}", flush=True)


@worker_ready.connect
def _on_worker_ready(**kwargs) -> None:  # pragma: no cover - exercised in running worker process
    del kwargs
    _hold_instance_lock("worker")
    write_worker_heartbeat()
    global _worker_heartbeat_thread_started
    with _worker_heartbeat_lock:
        if _worker_heartbeat_thread_started:
            return
        thread = threading.Thread(target=_worker_heartbeat_loop, daemon=True, name="celery-worker-heartbeat")
        thread.start()
        _worker_heartbeat_thread_started = True


@heartbeat_sent.connect
def _on_worker_heartbeat(**kwargs) -> None:  # pragma: no cover - exercised in running worker process
    del kwargs
    write_worker_heartbeat()


@beat_init.connect
def _on_beat_init(**kwargs) -> None:  # pragma: no cover - exercised in running beat process
    del kwargs
    _hold_instance_lock("beat")
    write_beat_heartbeat()
    global _beat_heartbeat_thread_started
    with _beat_heartbeat_lock:
        if _beat_heartbeat_thread_started:
            return
        thread = threading.Thread(target=_beat_heartbeat_loop, daemon=True, name="celery-beat-heartbeat")
        thread.start()
        _beat_heartbeat_thread_started = True


def _task_tenant_id(args: tuple | None, kwargs: dict | None) -> str | None:
    if isinstance(kwargs, dict):
        tenant_id = kwargs.get("tenant_id")
        if isinstance(tenant_id, str) and tenant_id:
            return tenant_id
    if isinstance(args, tuple) and args:
        first = args[0]
        if isinstance(first, str) and first:
            return first
    return None


@task_failure.connect
def _on_task_failure_record_dead_letter(
    sender=None,
    task_id=None,
    exception=None,
    args=None,
    kwargs=None,
    traceback=None,
    einfo=None,
    **extras,
) -> None:  # pragma: no cover - exercised in running worker process
    del traceback, einfo, extras
    task_name = getattr(sender, "name", None) or "unknown_task"
    tenant_id = _task_tenant_id(args, kwargs)
    reason = f"task_id={task_id} error={exception!r}" if exception is not None else f"task_id={task_id} error=unknown"
    try:
        write_dead_letter_job_run(job_name=task_name, tenant_id=tenant_id, error_message=reason)
    except Exception:
        return


# Ensure task modules are imported and registered.
from app.jobs import (  # noqa: E402,F401
    auditor_jobs,
    backup_jobs,
    control_coverage_jobs,
    discovery_verification_jobs,
    enforcement_jobs,
    hmair_discovery_jobs,
    maturity_curve_jobs,
    provider_signal_jobs,
    monitoring_jobs,
    native_control_jobs,
    risk_jobs,
    update_jobs,
)

# Backups (app/jobs/backup_jobs.py): one minute after beat starts, then every BACKUP_INTERVAL_HOURS (default 24).
_backup_entry = backup_schedule.beat_entry()
if _backup_entry:
    celery_app.conf.beat_schedule["scheduled-backup"] = _backup_entry

# Auto-update (off until an owner or admin turns it on) and the software integrity check (app/jobs/update_jobs.py).
celery_app.conf.beat_schedule.update(update_schedule.beat_entries())
