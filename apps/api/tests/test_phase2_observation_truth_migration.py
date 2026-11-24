from __future__ import annotations

from datetime import datetime, timezone
from importlib import import_module
import json
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
import pytest
import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError


MIGRATION_MODULE = (
    "app.db.migrations.versions.0054_discovery_observation_truth"
)


def _invoke(
    engine: sa.Engine,
    migration: object,
    operation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with engine.connect() as connection:
        context = MigrationContext.configure(connection)
        monkeypatch.setattr(migration, "op", Operations(context))
        with context.begin_transaction(_per_migration=True):
            getattr(migration, operation)()


def _legacy_database(path: Path) -> sa.Engine:
    engine = sa.create_engine(f"sqlite:///{path}")
    metadata = sa.MetaData()
    sa.Table(
        "discovery_observations",
        metadata,
        sa.Column("observation_id", sa.String(128), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TRIGGER trg_discovery_observations_immutable_update "
            "BEFORE UPDATE ON discovery_observations BEGIN "
            "SELECT RAISE(ABORT, 'immutable_table:discovery_observations'); END"
        )
        connection.exec_driver_sql(
            "CREATE TRIGGER trg_discovery_observations_immutable_delete "
            "BEFORE DELETE ON discovery_observations BEGIN "
            "SELECT RAISE(ABORT, 'immutable_table:discovery_observations'); END"
        )
        stamp = datetime(2026, 8, 15, 8, 30, tzinfo=timezone.utc)
        connection.execute(
            sa.text(
                "INSERT INTO discovery_observations "
                "(observation_id, tenant_id, observed_at, created_at) "
                "VALUES (:observation_id, :tenant_id, :observed_at, :created_at)"
            ),
            {
                "observation_id": "legacy-observation",
                "tenant_id": "tenant-phase2",
                "observed_at": stamp,
                "created_at": stamp,
            },
        )
    return engine


def test_0054_is_linear_after_banking_and_forward_only() -> None:
    migration = import_module(MIGRATION_MODULE)
    source = Path(migration.__file__).read_text(encoding="utf-8")

    assert migration.revision == "0054_discovery_obs_truth"
    assert migration.down_revision == "0053_banking_execution_grants"
    assert len(migration.revision) <= 32
    assert 'op.drop_table("discovery_observations")' not in source
    assert "DELETE FROM discovery_observations" not in source.upper()


def test_0054_backfills_unknown_truth_and_preserves_immutability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = import_module(MIGRATION_MODULE)
    engine = _legacy_database(tmp_path / "phase2-observation-truth.sqlite3")

    _invoke(engine, migration, "upgrade", monkeypatch)

    inspector = inspect(engine)
    columns = {column["name"]: column for column in inspector.get_columns(
        "discovery_observations"
    )}
    assert set(migration.OBSERVATION_TRUTH_COLUMNS) <= set(columns)
    assert all(
        not columns[name]["nullable"]
        for name in migration.REQUIRED_OBSERVATION_TRUTH_COLUMNS
    )
    assert {
        index["name"] for index in inspector.get_indexes("discovery_observations")
    } >= {
        "idx_discovery_observation_tenant_surface_time",
        "idx_discovery_observation_tenant_verification_time",
    }

    with engine.connect() as connection:
        row = connection.execute(
            sa.text(
                "SELECT source_surface, subject_reference, normalized_signal_json, "
                "received_at, observed_state, verification_state, source_trust, "
                "collection_scope_json, parser_version, schema_version, "
                "evidence_mode, evidence_mutability, contradiction_state, "
                "contradiction_references_json, created_at "
                "FROM discovery_observations WHERE observation_id='legacy-observation'"
            )
        ).mappings().one()
        triggers = {
            item[0]
            for item in connection.exec_driver_sql(
                "SELECT name FROM sqlite_master "
                "WHERE type='trigger' AND tbl_name='discovery_observations'"
            )
        }

    assert row["source_surface"] == "unknown"
    assert row["subject_reference"] is None
    assert json.loads(row["normalized_signal_json"]) == {}
    assert row["received_at"] == row["created_at"]
    assert row["observed_state"] == "unknown"
    assert row["verification_state"] == "unknown"
    assert row["source_trust"] == "unknown"
    assert json.loads(row["collection_scope_json"]) == {}
    assert row["parser_version"] == "legacy-unknown"
    assert row["schema_version"] == "1.0"
    assert row["evidence_mode"] == "unknown"
    assert row["evidence_mutability"] == "unknown"
    assert row["contradiction_state"] == "unknown"
    assert json.loads(row["contradiction_references_json"]) == []
    assert triggers == {
        "trg_discovery_observations_immutable_update",
        "trg_discovery_observations_immutable_delete",
    }

    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "UPDATE discovery_observations SET source_surface='endpoint' "
                "WHERE observation_id='legacy-observation'"
            )


def test_0054_enforces_truth_taxonomies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = import_module(MIGRATION_MODULE)
    engine = _legacy_database(tmp_path / "phase2-observation-checks.sqlite3")
    _invoke(engine, migration, "upgrade", monkeypatch)

    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "INSERT INTO discovery_observations "
                "(observation_id, tenant_id, observed_at, created_at, "
                "source_surface) VALUES "
                "('forged-observation', 'tenant-phase2', CURRENT_TIMESTAMP, "
                "CURRENT_TIMESTAMP, 'marketing_claim')"
            )
