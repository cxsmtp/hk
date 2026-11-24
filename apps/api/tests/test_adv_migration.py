from __future__ import annotations

from importlib import import_module
from pathlib import Path
import shutil

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DatabaseError

from app.core.config import settings


API_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_CONFIG = API_ROOT / "app/db/migrations/alembic.ini"
EXPECTED_ADV_TABLES = {
    "discovery_verification_policies",
    "discovery_verification_policy_requirements",
    "discovery_verification_episodes",
    "discovery_verification_attempts",
    "discovery_verification_results",
    "discovery_verification_assertions",
    "discovery_verification_events",
}


def test_0061_migration_follows_erg_and_declares_append_only_adv_schema() -> None:
    migration = import_module(
        "app.db.migrations.versions.0061_autonomous_discovery_verification"
    )
    assert migration.revision == "0061_autonomous_discovery_verification"
    assert migration.down_revision == "0060_evidence_resolution_graph"
    assert set(migration.TABLES) == EXPECTED_ADV_TABLES
    assert migration.IMMUTABLE_TABLES == migration.TABLES


def test_fresh_upgrade_to_0061_creates_adv_bindings_and_immutable_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_path = tmp_path / "adv.sqlite3"
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

    command.upgrade(config, "0061_autonomous_discovery_verification")
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        assert EXPECTED_ADV_TABLES <= set(inspector.get_table_names())
        for table_name in EXPECTED_ADV_TABLES:
            assert inspector.get_indexes(table_name)
            assert all(
                tuple(index["column_names"])[0] == "tenant_id"
                for index in inspector.get_indexes(table_name)
            )
        task_columns = {
            item["name"]
            for item in inspector.get_columns("discovery_verification_tasks")
        }
        assert {
            "verification_episode_id",
            "verification_requirement_id",
            "task_contract_version",
        } <= task_columns

        with engine.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar_one() == "0061_autonomous_discovery_verification"
            trigger_names = {
                row[0]
                for row in connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type='trigger'"
                )
            }
            immutable = {
                name
                for name in trigger_names
                if name.startswith("trg_adv_") and "immutable" in name
            }
            assert len(immutable) == 14
            assert {
                "trg_adv_policy_predecessor_sequence",
                "trg_adv_episode_predecessor_sequence",
                "trg_adv_result_predecessor_sequence",
                "trg_adv_assertion_predecessor_sequence",
            } <= trigger_names

        with engine.begin() as connection:
            tenant_id = "00000000-0000-0000-0000-000000000001"
            connection.execute(
                text(
                    "INSERT INTO tenants (id, name, slug, is_active, platform_mode) "
                    "VALUES (:tenant, 'ADV migration', 'adv-migration', true, 'enforce')"
                ),
                {"tenant": tenant_id},
            )
            connection.execute(
                text(
                    "INSERT INTO discovery_verification_policies ("
                    "policy_record_id, tenant_id, policy_id, version, "
                    "ecosystem_classes_json, environments_json, "
                    "minimum_evidence_quality, minimum_confidence, "
                    "minimum_source_diversity, assertion_ttl_seconds, "
                    "rescan_interval_seconds, effective_from, effective_until, "
                    "methodology_version, actor_id, idempotency_key, input_digest"
                    ") VALUES ("
                    ":record, :tenant, 'default', 1, '[]', '[]', 0.8, 0.8, "
                    "1, 3600, 1800, CURRENT_TIMESTAMP, NULL, '1.0.0', 'system', "
                    "'adv-migration-policy', :digest)"
                ),
                {"record": "00000000-0000-0000-0000-000000000061", "tenant": tenant_id, "digest": "a" * 64},
            )
        with engine.begin() as connection, pytest.raises(DatabaseError):
            connection.execute(
                text(
                    "INSERT INTO discovery_verification_policies ("
                    "policy_record_id, tenant_id, policy_id, version, "
                    "predecessor_policy_record_id, ecosystem_classes_json, "
                    "environments_json, minimum_evidence_quality, "
                    "minimum_confidence, minimum_source_diversity, "
                    "assertion_ttl_seconds, rescan_interval_seconds, "
                    "effective_from, effective_until, methodology_version, "
                    "actor_id, idempotency_key, input_digest) VALUES ("
                    ":record, :tenant, 'default', 3, :predecessor, '[]', '[]', "
                    "0.8, 0.8, 1, 3600, 1800, CURRENT_TIMESTAMP, NULL, "
                    "'1.0.0', 'system', 'adv-invalid-sequence', :digest)"
                ),
                {
                    "record": "00000000-0000-0000-0000-000000000062",
                    "tenant": tenant_id,
                    "predecessor": "00000000-0000-0000-0000-000000000061",
                    "digest": "b" * 64,
                },
            )
        with engine.begin() as connection, pytest.raises(DatabaseError):
            connection.execute(
                text(
                    "UPDATE discovery_verification_policies SET actor_id='tampered' "
                    "WHERE idempotency_key='adv-migration-policy'"
                )
            )
    finally:
        engine.dispose()
