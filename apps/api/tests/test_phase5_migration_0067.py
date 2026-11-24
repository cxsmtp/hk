from __future__ import annotations

from pathlib import Path
import shutil

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

from app.core.config import settings


def _alembic_config(tmp_path, monkeypatch) -> tuple[Config, str]:
    api_root = Path(__file__).resolve().parents[1]
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase5-0067.sqlite3'}"
    clean_migrations = tmp_path / "migrations"
    shutil.copytree(
        api_root / "app/db/migrations",
        clean_migrations,
        ignore=shutil.ignore_patterns("._*", "__pycache__"),
    )
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    config = Config(str(api_root / "app/db/migrations/alembic.ini"))
    config.set_main_option("script_location", str(clean_migrations))
    config.set_main_option("sqlalchemy.url", database_url)
    return config, database_url


def test_0067_accepts_v2_assertions_without_relabelling_or_losing_v1(tmp_path, monkeypatch) -> None:
    config, database_url = _alembic_config(tmp_path, monkeypatch)
    command.upgrade(config, "0066_phase5_execution_lifecycle")
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(text("INSERT INTO tenants (id, name, slug, is_active) VALUES ('coverage-tenant', 'Coverage', 'coverage-tenant', 1)"))
            connection.execute(
                text(
                    """
                    INSERT INTO control_coverage_paths
                    (id, tenant_id, path_key, key_version, asset_ref, identity_type,
                     identity_ref, runtime_ref, deployment_surface_ref, destination_type,
                     destination_ref, lifecycle_status, source_refs)
                    VALUES
                    ('coverage-path', 'coverage-tenant', 'path-v1', '1.0', 'application:test',
                     'user', 'user:test', 'runtime:test', 'runtime:test', 'tool',
                     'tool:test', 'active', '[]')
                    """
                )
            )
            connection.execute(
                text(
                    """
                    INSERT INTO control_coverage_assertions
                    (id, tenant_id, path_id, dimension, state, reason_code, explanation,
                     methodology_version, evaluator_version, evidence_refs, source_watermark, observed_at)
                    VALUES
                    ('v1-assertion', 'coverage-tenant', 'coverage-path', 'authorization', 'covered',
                     'verified_inline_decision', 'legacy V1 evidence', 'control-coverage/1.0',
                     'control-coverage-evaluator/1.0', '["decision_receipt:v1"]', 'watermark-v1', CURRENT_TIMESTAMP)
                    """
                )
            )
            connection.execute(
                text(
                    """
                    INSERT INTO control_coverage_snapshots
                    (id, tenant_id, methodology_version, window_start, window_end, input_digest,
                     headline_counts, headline_score, dimension_summaries, input_watermarks,
                     diagnostics, freshness_status)
                    VALUES
                    ('v1-snapshot', 'coverage-tenant', 'control-coverage/1.0', CURRENT_TIMESTAMP,
                     CURRENT_TIMESTAMP, 'd' || printf('%063d', 0), '{}', NULL, '{}', '{}',
                     '{}', 'current')
                    """
                )
            )
    finally:
        engine.dispose()

    command.upgrade(config, "0067_phase5_control_coverage")
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO control_coverage_assertions
                    (id, tenant_id, path_id, dimension, state, reason_code, explanation,
                     methodology_version, evaluator_version, evidence_refs, source_watermark, observed_at)
                    VALUES
                    ('v2-assertion', 'coverage-tenant', 'coverage-path', 'subject_binding', 'unknown',
                     'insufficient_evidence', 'signed proof unavailable', 'control-coverage/2.0',
                     'control-coverage-evaluator/2.0', '[]', 'watermark-v2', CURRENT_TIMESTAMP)
                    """
                )
            )
            legacy = connection.execute(
                text("SELECT methodology_version, dimension, state FROM control_coverage_assertions WHERE id = 'v1-assertion'")
            ).one()
            assert legacy == ("control-coverage/1.0", "authorization", "covered")
            assert connection.execute(
                text("SELECT methodology_version FROM control_coverage_snapshots WHERE id = 'v1-snapshot'")
            ).scalar_one() == "control-coverage/1.0"

        with pytest.raises(RuntimeError, match="V2 coverage assertions exist"):
            command.downgrade(config, "0066_phase5_execution_lifecycle")
    finally:
        engine.dispose()
