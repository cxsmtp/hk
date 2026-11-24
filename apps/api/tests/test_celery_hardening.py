from __future__ import annotations

import threading

import pytest

from app.jobs import celery_app as celery_module


def test_celery_retry_and_resilience_defaults_are_enabled() -> None:
    conf = celery_module.celery_app.conf
    assert bool(conf.task_acks_late) is True
    assert bool(conf.task_reject_on_worker_lost) is True
    assert int(conf.task_default_retry_delay) == 5

    annotations = dict(conf.task_annotations or {})
    expected_tasks = [
        "app.jobs.monitoring_jobs.run_all_connectors",
        "app.jobs.monitoring_jobs.run_scheduled_monitoring_checks",
        "app.jobs.monitoring_jobs.run_monitoring_15m_checks",
        "app.jobs.monitoring_jobs.run_monitoring_hourly_checks",
        "app.jobs.monitoring_jobs.run_monitoring_daily_checks",
        "app.jobs.auditor_jobs.export_audit_snapshot",
        "app.jobs.auditor_jobs.run_daily_snapshot_pack",
        "app.jobs.enforcement_jobs.resolve_timed_out_approvals",
        "app.jobs.enforcement_jobs.run_sla_timeout_checks",
        "app.jobs.risk_jobs.reconfigure_risk_runtime",
    ]
    for task_name in expected_tasks:
        policy = annotations.get(task_name)
        assert isinstance(policy, dict)
        assert bool(policy.get("retry_backoff")) is True
        assert bool(policy.get("retry_jitter")) is True
        assert int(policy.get("retry_backoff_max", 0)) == 120
        assert int(policy.get("max_retries", 0)) == 5

    beat = dict(conf.beat_schedule or {})
    assert beat["monitoring-checks-every-fifteen-minutes"]["task"] == "app.jobs.monitoring_jobs.run_monitoring_15m_checks"
    assert beat["monitoring-hourly-cycle"]["task"] == "app.jobs.monitoring_jobs.run_monitoring_hourly_checks"
    assert beat["monitoring-daily-cycle"]["task"] == "app.jobs.monitoring_jobs.run_monitoring_daily_checks"


def test_task_failure_records_dead_letter_row_with_tenant_id(monkeypatch) -> None:
    captured: dict[str, str | None] = {}

    def _stub(*, job_name: str, tenant_id: str | None, error_message: str | None):
        captured["job_name"] = job_name
        captured["tenant_id"] = tenant_id
        captured["error_message"] = error_message

    monkeypatch.setattr(celery_module, "write_dead_letter_job_run", _stub)

    class _Sender:
        name = "app.jobs.monitoring_jobs.run_all_connectors"

    celery_module._on_task_failure_record_dead_letter(
        sender=_Sender(),
        task_id="task-123",
        exception=RuntimeError("boom"),
        args=("tenant-from-args",),
        kwargs={},
    )

    assert captured["job_name"] == _Sender.name
    assert captured["tenant_id"] == "tenant-from-args"
    assert "task-123" in str(captured["error_message"])


def test_task_failure_prefers_tenant_id_in_kwargs(monkeypatch) -> None:
    captured: dict[str, str | None] = {}

    def _stub(*, job_name: str, tenant_id: str | None, error_message: str | None):
        captured["job_name"] = job_name
        captured["tenant_id"] = tenant_id
        captured["error_message"] = error_message

    monkeypatch.setattr(celery_module, "write_dead_letter_job_run", _stub)

    class _Sender:
        name = "app.jobs.auditor_jobs.export_audit_snapshot"

    celery_module._on_task_failure_record_dead_letter(
        sender=_Sender(),
        task_id="task-789",
        exception=ValueError("snap fail"),
        args=("tenant-from-args",),
        kwargs={"tenant_id": "tenant-from-kwargs"},
    )

    assert captured["job_name"] == _Sender.name
    assert captured["tenant_id"] == "tenant-from-kwargs"
    assert "snap fail" in str(captured["error_message"])


def test_worker_ready_writes_heartbeat_and_starts_one_daemon_heartbeat_loop(monkeypatch) -> None:
    writes: list[str] = []
    started_threads: list[object] = []

    class _Thread:
        def __init__(self, *, target, daemon: bool, name: str) -> None:
            self.target = target
            self.daemon = daemon
            self.name = name

        def start(self) -> None:
            started_threads.append(self)

    monkeypatch.setattr(celery_module, "write_worker_heartbeat", lambda: writes.append("worker"))
    monkeypatch.setattr(celery_module.threading, "Thread", _Thread)
    monkeypatch.setattr(celery_module, "_worker_heartbeat_thread_started", False)
    monkeypatch.setattr(celery_module, "_worker_heartbeat_lock", threading.Lock())

    celery_module._on_worker_ready()
    celery_module._on_worker_ready()

    assert writes == ["worker", "worker"]
    assert len(started_threads) == 1
    thread = started_threads[0]
    assert getattr(thread, "target") is celery_module._worker_heartbeat_loop
    assert getattr(thread, "daemon") is True
    assert getattr(thread, "name") == "celery-worker-heartbeat"


def test_worker_heartbeat_loop_refreshes_no_slower_than_half_max_age(monkeypatch) -> None:
    writes: list[str] = []
    sleeps: list[float] = []

    def _stop_after_first_interval(interval: float) -> None:
        sleeps.append(interval)
        raise RuntimeError("stop test loop")

    monkeypatch.setattr(celery_module, "write_worker_heartbeat", lambda: writes.append("worker"))
    monkeypatch.setattr(celery_module.settings, "control_plane_heartbeat_max_age_seconds", 60)
    monkeypatch.setattr(celery_module.time, "sleep", _stop_after_first_interval)

    with pytest.raises(RuntimeError, match="stop test loop"):
        celery_module._worker_heartbeat_loop()

    assert writes == ["worker"]
    assert sleeps == [30.0]
    assert sleeps[0] <= celery_module.settings.control_plane_heartbeat_max_age_seconds / 2.0
