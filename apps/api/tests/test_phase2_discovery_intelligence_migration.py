from __future__ import annotations

from importlib import import_module
from pathlib import Path
import shutil

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from app.core.config import settings


API_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_CONFIG = API_ROOT / "app/db/migrations/alembic.ini"
MIGRATION_MODULE = "app.db.migrations.versions.0058_discovery_intelligence"
H1_ACCEPTANCE_REVISION = "0061_autonomous_discovery_verification"


EXPECTED = {
    "discovery_asset_usage_facts": {
        "usage_fact_id", "tenant_id", "asset_id", "actor_type",
        "actor_reference_hash", "usage_state", "event_count",
        "first_observed_at", "last_observed_at", "source_surface",
        "evidence_node_id", "confidence", "verification_state", "freshness",
        "telemetry_complete", "methodology_id", "limitations_json",
        "idempotency_key", "input_digest", "created_at",
    },
    "discovery_shadow_classifications": {
        "classification_id", "tenant_id", "asset_id", "management_class",
        "shadow_type", "severity", "confidence", "verification_state",
        "primary_evidence_node_id", "evidence_node_ids_json",
        "first_observed_at", "last_observed_at", "methodology_id",
        "limitations_json", "idempotency_key", "input_digest", "created_at",
    },
    "discovery_asset_findings": {
        "finding_id", "tenant_id", "asset_id", "finding_type", "severity",
        "confidence", "verification_state", "primary_evidence_node_id",
        "evidence_node_ids_json", "first_seen_at", "last_seen_at",
        "remediation", "verification_action", "coverage_impact", "dedupe_key",
        "occurrence_count", "status", "created_at", "updated_at",
    },
}


def test_fresh_upgrade_builds_phase2_usage_shadow_and_findings(
    tmp_path: Path, monkeypatch
) -> None:
    database_path = tmp_path / "phase2-intelligence.sqlite3"
    database_url = f"sqlite+pysqlite:///{database_path}"
    clean_migrations = tmp_path / "migrations"
    shutil.copytree(
        API_ROOT / "app/db/migrations",
        clean_migrations,
        ignore=shutil.ignore_patterns("._*", "__pycache__"),
    )
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    config = Config(str(ALEMBIC_CONFIG))
    config.set_main_option("script_location", str(clean_migrations))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, H1_ACCEPTANCE_REVISION)
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        for table_name, expected_columns in EXPECTED.items():
            assert {
                column["name"] for column in inspector.get_columns(table_name)
            } == expected_columns
            assert all(
                tuple(index["column_names"])[0] == "tenant_id"
                for index in inspector.get_indexes(table_name)
            )
        with engine.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar_one() == H1_ACCEPTANCE_REVISION
            trigger_names = {
                row[0]
                for row in connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type='trigger'"
                )
            }
            assert {
                "trg_discovery_usage_immutable_update",
                "trg_discovery_usage_immutable_delete",
                "trg_discovery_shadow_class_immutable_update",
                "trg_discovery_shadow_class_immutable_delete",
            } <= trigger_names
    finally:
        engine.dispose()

    migration = import_module(MIGRATION_MODULE)
    assert migration.revision == "0058_discovery_intelligence"
    assert migration.down_revision == "0057_discovery_attribution"
