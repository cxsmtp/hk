"""Round-trip proof for audited HMAIR target references."""

from __future__ import annotations

from pathlib import Path
import shutil

from alembic import command
from alembic.config import Config
from sqlalchemy import Column, MetaData, String, Table, create_engine, inspect, text

from app.core.config import settings


API_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_CONFIG = API_ROOT / "app/db/migrations/alembic.ini"
PREVIOUS_REVISION = "0085_hmair_production_deep_scan"
CURRENT_REVISION = "0086_expand_audit_resource_reference"


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


def test_hmair_audit_reference_migration_preserves_full_target_id(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'audit-reference.sqlite3'}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    engine = create_engine(database_url)
    try:
        baseline = MetaData()
        Table(
            "audit_logs",
            baseline,
            Column("id", String(36), primary_key=True),
            Column("resource_id", String(36), nullable=False),
        )
        baseline.create_all(engine)
    finally:
        engine.dispose()

    config = _config(tmp_path, database_url)
    command.stamp(config, PREVIOUS_REVISION)
    command.upgrade(config, CURRENT_REVISION)

    engine = create_engine(database_url)
    try:
        resource_id_column = next(
            column
            for column in inspect(engine).get_columns("audit_logs")
            if column["name"] == "resource_id"
        )
        assert resource_id_column["type"].length == 128
        long_target_id = "hmair-surface-target-" + ("a" * 40)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO audit_logs (id, resource_id) "
                    "VALUES (:id, :resource_id)"
                ),
                {"id": "00000000-0000-4000-8000-000000000086", "resource_id": long_target_id},
            )
        with engine.connect() as connection:
            assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == CURRENT_REVISION
    finally:
        engine.dispose()
