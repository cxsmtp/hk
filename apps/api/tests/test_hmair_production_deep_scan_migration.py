"""Round-trip proof for additive Deep Scan persistence."""

from __future__ import annotations

from pathlib import Path
import shutil

from alembic import command
from alembic.config import Config
from sqlalchemy import Column, MetaData, String, Table, create_engine, inspect, text

from app.core.config import settings


API_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_CONFIG = API_ROOT / "app/db/migrations/alembic.ini"
PREVIOUS_REVISION = "0084_hmair_endpoint_metadata_inventory"
CURRENT_REVISION = "0085_hmair_production_deep_scan"


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


def test_deep_scan_migration_upgrades_downgrades_and_reupgrades(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'deep-scan.sqlite3'}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    engine = create_engine(database_url)
    try:
        baseline = MetaData()
        Table("tenants", baseline, Column("id", String(36), primary_key=True))
        Table(
            "discovery_targets",
            baseline,
            Column("target_id", String(128), primary_key=True),
            Column("tenant_id", String(36), nullable=False),
        )
        Table(
            "endpoint_metadata_inventory_runs",
            baseline,
            Column("id", String(36), primary_key=True),
            Column("tenant_id", String(36), nullable=False),
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
        target_columns = {
            column["name"] for column in inspector.get_columns("discovery_targets")
        }
        run_columns = {
            column["name"]
            for column in inspector.get_columns("endpoint_metadata_inventory_runs")
        }
        assert "coverage_baseline_json" in target_columns
        assert {"parent_scan_id", "parent_assignment_id"} <= run_columns
        assert {
            "idx_ep_meta_inv_run_tenant_parent_scan",
            "idx_ep_meta_inv_run_tenant_parent_assignment",
        } <= {
            index["name"]
            for index in inspector.get_indexes("endpoint_metadata_inventory_runs")
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
        inspector = inspect(engine)
        assert "coverage_baseline_json" not in {
            column["name"] for column in inspector.get_columns("discovery_targets")
        }
        assert not {"parent_scan_id", "parent_assignment_id"} & {
            column["name"]
            for column in inspector.get_columns("endpoint_metadata_inventory_runs")
        }
    finally:
        engine.dispose()

    command.upgrade(config, CURRENT_REVISION)
