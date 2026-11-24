from __future__ import annotations

from pathlib import Path
import shutil

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import Column, MetaData, String, Table, create_engine, inspect, text


API_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_CONFIG = API_ROOT / "app/db/migrations/alembic.ini"
PREVIOUS_REVISION = "0087_allow_covered_stale_control_coverage"
INTERMEDIATE_REVISION = "0088_provider_signal_records"
CURRENT_REVISION = "0089_provider_signal_lifecycle"


def _config(tmp_path: Path, database_url: str) -> Config:
    clean_migrations = tmp_path / "migrations"
    shutil.copytree(
        API_ROOT / "app/db/migrations",
        clean_migrations,
        ignore=shutil.ignore_patterns("._*", "__pycache__"),
    )
    config = Config(str(ALEMBIC_CONFIG))
    config.set_main_option("script_location", str(clean_migrations))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def test_provider_signal_migration_round_trip(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'provider-signals.sqlite3'}"
    from app.core.config import settings

    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    engine = create_engine(database_url)
    try:
        metadata = MetaData()
        Table("tenants", metadata, Column("id", String(36), primary_key=True))
        Table("connectors", metadata, Column("id", String(36), primary_key=True))
        Table("users", metadata, Column("id", String(36), primary_key=True))
        metadata.create_all(engine)
    finally:
        engine.dispose()

    config = _config(tmp_path, database_url)
    command.stamp(config, PREVIOUS_REVISION)
    command.upgrade(config, CURRENT_REVISION)

    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        assert "provider_signal_records" in inspector.get_table_names()
        assert {
            "idx_provider_signal_tenant_provider_time",
            "idx_provider_signal_tenant_kind_time",
            "idx_provider_signal_tenant_user_time",
            "idx_provider_signal_tenant_client_time",
            "idx_provider_signal_tenant_received",
        } <= {index["name"] for index in inspector.get_indexes("provider_signal_records")}
        assert "projection_refs" in {
            column["name"] for column in inspector.get_columns("provider_signal_records")
        }
        assert "provider_seat_snapshots" in inspector.get_table_names()
        assert {
            "total_licensed_seats",
            "never_used_seats",
            "unknown_activity_seats",
            "completeness",
            "authority_reference",
        } <= {column["name"] for column in inspector.get_columns("provider_seat_snapshots")}
        assert {
            "idx_provider_seat_tenant_provider_time",
            "idx_provider_seat_tenant_received",
        } <= {index["name"] for index in inspector.get_indexes("provider_seat_snapshots")}
        assert "raw_prompt" not in {
            column["name"] for column in inspector.get_columns("provider_signal_records")
        }
    finally:
        engine.dispose()

    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(text("INSERT INTO tenants (id) VALUES ('tenant-a')"))
            connection.execute(
                text(
                    "INSERT INTO provider_seat_snapshots "
                    "(id, tenant_id, provider, product, source_type, source_schema_version, source_record_id, dedup_key, "
                    "authority_reference, total_licensed_seats, assigned_seats, active_seats, inactive_seats, never_used_seats, "
                    "unknown_activity_seats, completeness, observed_at) "
                    "VALUES ('seat-a', 'tenant-a', 'anthropic', 'claude_code', 'provider_admin', '1.0', 'seat-a', 'a', "
                    "'provider-admin-export', 1, 1, 1, 0, 0, 0, 'COMPLETE', CURRENT_TIMESTAMP)"
                )
            )
        with pytest.raises(RuntimeError, match="Cannot downgrade provider signal lifecycle"):
            command.downgrade(config, INTERMEDIATE_REVISION)
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM provider_seat_snapshots"))
            connection.execute(
                text(
                    "INSERT INTO provider_signal_records "
                    "(id, tenant_id, provider, product, source_type, source_schema_version, source_record_id, dedup_key, "
                    "record_kind, occurred_at, projection_refs, payload) "
                    "VALUES ('signal-a', 'tenant-a', 'anthropic', 'claude_code', 'provider_admin', '1.0', 'signal-a', 'b', "
                    "'tool', CURRENT_TIMESTAMP, '{\"projection_mode\":\"CONFIGURATION_INVENTORY\"}', '{}')"
                )
            )
        with pytest.raises(RuntimeError, match="Cannot downgrade provider signal lifecycle"):
            command.downgrade(config, INTERMEDIATE_REVISION)
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM provider_signal_records"))
    finally:
        engine.dispose()

    command.downgrade(config, INTERMEDIATE_REVISION)
    engine = create_engine(database_url)
    try:
        tables = inspect(engine).get_table_names()
        assert "provider_signal_records" in tables
        assert "provider_seat_snapshots" not in tables
        assert "projection_refs" not in {
            column["name"] for column in inspect(engine).get_columns("provider_signal_records")
        }
    finally:
        engine.dispose()

    command.upgrade(config, CURRENT_REVISION)
