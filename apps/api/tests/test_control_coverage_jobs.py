from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app.core.config import Settings, parse_control_coverage_rollout
from app.db.models.control_coverage import ControlCoverageAssertion, ControlCoveragePath, ControlCoverageSnapshot
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.tenant import Tenant
from app.db.session import Base


def _settings(**overrides) -> Settings:
    values = {
        "_env_file": None,
        "secret_key": "job-jwt-secret",
        "secret_key_lock_enabled": False,
        "connector_secrets_key": "job-connector-secret",
        "connector_secrets_kdf_salt": "job-kdf-salt",
        "onprem_bundle_signing_secret": "job-onprem-secret",
    }
    values.update(overrides)
    return Settings(**values)


def test_control_coverage_flags_default_off() -> None:
    configured = _settings()
    assert configured.control_coverage_materialization_enabled is False
    assert configured.control_coverage_snapshot_enabled is False
    assert configured.control_coverage_api_enabled is False
    assert configured.control_coverage_ui_enabled is False
    assert configured.control_coverage_rollout == "{}"
    assert configured.control_coverage_default_window_days == 30
    assert configured.control_coverage_snapshot_interval_minutes == 15


def test_rollout_and_ranges_are_strict() -> None:
    assert parse_control_coverage_rollout('{"tenant-a":true}') == {"tenant-a": True}
    with pytest.raises(ValueError):
        parse_control_coverage_rollout('{"tenant-a":"yes"}')
    with pytest.raises(ValidationError):
        _settings(control_coverage_default_window_days=0)
    with pytest.raises(ValidationError):
        _settings(control_coverage_snapshot_interval_minutes=4)
    with pytest.raises(ValidationError, match="explicit tenant rollout"):
        _settings(control_coverage_materialization_enabled=True)
    with pytest.raises(ValidationError, match="MATERIALIZATION_ENABLED"):
        _settings(
            control_coverage_snapshot_enabled=True,
            control_coverage_rollout='{"tenant-a":true}',
        )


def test_disabled_refresh_writes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.jobs import control_coverage_jobs as jobs

    monkeypatch.setattr(
        jobs,
        "settings",
        SimpleNamespace(
            control_coverage_materialization_enabled=False,
            control_coverage_snapshot_enabled=False,
            control_coverage_rollout="{}",
            control_coverage_default_window_days=30,
        ),
    )
    result = jobs.refresh_control_coverage("tenant-a")
    assert result == {
        "tenant_id": "tenant-a",
        "status": "disabled",
        "paths": 0,
        "assertions": 0,
        "snapshot_id": None,
    }


def test_enabled_refresh_is_transactional_and_returns_counts(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.jobs import control_coverage_jobs as jobs
    from app.services import job_run_service

    db_file = tmp_path / "control_coverage_jobs.sqlite3"
    engine = create_engine(f"sqlite+pysqlite:///{db_file}")
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    with session_factory() as db:
        db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a"))
        db.add(
            RuntimeEvent(
                event_id="event-job-1",
                tenant_id="tenant-a",
                source_surface="sdk",
                event_type="observed_action",
                metadata_json={"control_mode": "telemetry_only"},
                created_at=now,
            )
        )
        db.commit()

    monkeypatch.setattr(jobs, "SessionLocal", session_factory)
    monkeypatch.setattr(job_run_service, "SessionLocal", session_factory)
    monkeypatch.setattr(
        jobs,
        "settings",
        SimpleNamespace(
            control_coverage_materialization_enabled=True,
            control_coverage_snapshot_enabled=True,
            control_coverage_rollout='{"tenant-a":true}',
            control_coverage_default_window_days=30,
        ),
    )

    result = jobs.refresh_control_coverage("tenant-a")

    assert result["status"] == "success"
    assert result["paths"] == 1
    assert result["assertions"] == 7
    assert result["snapshot_id"]
    assert len(result["input_digest"]) == 64
    with session_factory() as db:
        assert db.scalar(select(func.count()).select_from(ControlCoveragePath)) == 1
        assert db.scalar(select(func.count()).select_from(ControlCoverageAssertion)) == 7
        assert db.scalar(select(func.count()).select_from(ControlCoverageSnapshot)) == 1
    engine.dispose()
