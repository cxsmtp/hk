from __future__ import annotations

from pathlib import Path
import shutil

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from app.core.config import settings


API_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_CONFIG = API_ROOT / "app/db/migrations/alembic.ini"


EXPECTED = {
    "discovery_asset_reachability": {
        "reachability_id", "tenant_id", "asset_id", "target_category",
        "target_reference_hash", "reachability_state", "evidence_node_id",
        "confidence", "verification_state", "freshness", "observed_usage",
        "first_observed_at", "last_observed_at", "limitations_json",
        "idempotency_key", "input_digest", "created_at",
    },
    "discovery_asset_identity_links": {
        "identity_link_id", "tenant_id", "asset_id", "identity_type",
        "identity_reference_hash", "access_state", "evidence_node_id",
        "confidence", "verification_state", "usage_proven", "first_observed_at",
        "last_observed_at", "idempotency_key", "input_digest", "created_at",
    },
    "discovery_asset_ownership_assertions": {
        "ownership_assertion_id", "tenant_id", "asset_id", "owner_type",
        "owner_reference_hash", "ownership_state", "evidence_node_id",
        "confidence", "verification_state", "first_observed_at",
        "last_observed_at", "idempotency_key", "input_digest", "created_at",
    },
}


def test_fresh_upgrade_builds_0057_attribution_and_capability_truth(
    tmp_path: Path, monkeypatch
) -> None:
    database_path = tmp_path / "phase2-attribution.sqlite3"
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
    command.upgrade(config, "0057_discovery_attribution")
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        for table, columns in EXPECTED.items():
            assert {item["name"] for item in inspector.get_columns(table)} == columns
        capability_columns = {
            item["name"] for item in inspector.get_columns("discovery_ai_capabilities")
        }
        assert {
            "verification_state", "freshness", "observed_usage",
            "declared_only", "inferred_only",
        } <= capability_columns
        with engine.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar_one() == "0057_discovery_attribution"
            triggers = {
                row[0]
                for row in connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type='trigger'"
                )
            }
            assert {
                "trg_discovery_ai_capabilities_immutable_update",
                "trg_discovery_ai_capabilities_immutable_delete",
            } <= triggers
    finally:
        engine.dispose()
