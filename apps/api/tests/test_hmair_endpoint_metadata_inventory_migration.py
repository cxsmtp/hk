"""Focused round-trip proof for bounded endpoint metadata inventory persistence."""

from __future__ import annotations

from pathlib import Path
import re
import shutil

from alembic import command
from alembic.config import Config
from sqlalchemy import Column, MetaData, String, Table, create_engine, inspect, text

from app.core.config import settings


API_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_CONFIG = API_ROOT / "app/db/migrations/alembic.ini"
PREVIOUS_REVISION = "0083_user_visibility_prompt_explorer"
CURRENT_REVISION = "0084_hmair_endpoint_metadata_inventory"
INVENTORY_TABLES = {
    "endpoint_metadata_inventory_runs",
    "endpoint_metadata_inventory_assignments",
}
HMAIR_MIGRATION_FILES = (
    API_ROOT / "app/db/migrations/versions/0084_hmair_endpoint_metadata_inventory.py",
    API_ROOT / "app/db/migrations/versions/0085_hmair_production_deep_scan.py",
)


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


def test_hmair_migration_identifiers_fit_postgresql_limit() -> None:
    identifiers: list[str] = []
    for migration_file in HMAIR_MIGRATION_FILES:
        text_content = migration_file.read_text()
        identifiers.extend(re.findall(r'name="([^"]+)"', text_content))
        identifiers.extend(re.findall(r'"(idx_[^"]+)"', text_content))
    assert identifiers
    assert not [identifier for identifier in identifiers if len(identifier) > 63]


def test_inventory_migration_upgrades_downgrades_and_reupgrades(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'endpoint-inventory.sqlite3'}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    engine = create_engine(database_url)
    try:
        baseline = MetaData()
        Table("tenants", baseline, Column("id", String(36), primary_key=True))
        Table("users", baseline, Column("id", String(36), primary_key=True))
        Table(
            "endpoint_device_identities",
            baseline,
            Column("id", String(36), primary_key=True),
        )
        baseline.create_all(engine)
    finally:
        engine.dispose()

    config = _config(tmp_path, database_url)
    command.stamp(config, PREVIOUS_REVISION)
    command.upgrade(config, CURRENT_REVISION)
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        assert INVENTORY_TABLES <= set(inspector.get_table_names())
        assert {
            "tenant_id",
            "request_idempotency_key",
            "endpoint_denominator",
            "expires_at",
            "limitations_json",
        } <= {
            column["name"]
            for column in inspector.get_columns("endpoint_metadata_inventory_runs")
        }
        assert {
            "tenant_id",
            "inventory_run_id",
            "endpoint_device_identity_id",
            "status",
            "scan_id",
        } <= {
            column["name"]
            for column in inspector.get_columns("endpoint_metadata_inventory_assignments")
        }
        with engine.connect() as connection:
            assert (
                connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == CURRENT_REVISION
            )
    finally:
        engine.dispose()

    command.downgrade(config, PREVIOUS_REVISION)
    engine = create_engine(database_url)
    try:
        assert not (INVENTORY_TABLES & set(inspect(engine).get_table_names()))
    finally:
        engine.dispose()

    command.upgrade(config, CURRENT_REVISION)
