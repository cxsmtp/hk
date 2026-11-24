from __future__ import annotations

from importlib import import_module
from pathlib import Path
import shutil

from alembic import command
from alembic.config import Config
import sqlalchemy as sa
from sqlalchemy import create_engine, inspect

from app.core.config import settings


API_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_CONFIG = API_ROOT / "app/db/migrations/alembic.ini"
MIGRATION_MODULE = "app.db.migrations.versions.0055_discovery_assets_resolution"
H1_ACCEPTANCE_REVISION = "0061_autonomous_discovery_verification"

EXPECTED_TABLE_COLUMNS = {
    "discovery_ai_assets": {
        "asset_id", "tenant_id", "asset_type", "canonical_name", "provider",
        "product", "framework", "version", "deployment_family",
        "technical_surface", "environment", "approved_status",
        "lifecycle_status", "shadow_ai_status", "first_seen_at", "last_seen_at",
        "resolution_confidence", "evidence_bundle_id", "projection_version",
        "created_at", "updated_at",
    },
    "discovery_evidence_claims": {
        "claim_id", "tenant_id", "claim_type", "subject_observation_id",
        "subject_asset_id", "source_observation_id", "evidence_node_id",
        "claim_result", "claim_method", "limitations_json", "confidence",
        "freshness", "observed_at", "idempotency_key", "input_digest",
        "created_at",
    },
    "discovery_asset_history_events": {
        "history_event_id", "tenant_id", "event_type", "reversal_of_event_id",
        "actor_id", "actor_role", "reason", "evidence_claim_id",
        "idempotency_key", "input_digest", "created_at",
    },
    "discovery_resolution_decisions": {
        "decision_id", "tenant_id", "canonical_asset_id", "history_event_id",
        "operation_index", "action", "matched_signals_json",
        "conflicting_signals_json", "confidence", "algorithm_version",
        "evidence_claim_id", "idempotency_key", "input_digest", "created_at",
    },
    "discovery_resolution_decision_observations": {
        "decision_observation_id", "tenant_id", "decision_id", "observation_id",
        "ordinal", "created_at",
    },
    "discovery_observation_asset_links": {
        "link_id", "tenant_id", "observation_id", "asset_id", "decision_id",
        "history_event_id", "link_kind", "sequence_no", "predecessor_link_id",
        "reversal_of_link_id", "created_at",
    },
    "discovery_asset_fingerprints": {
        "fingerprint_id", "tenant_id", "asset_id", "source_observation_id",
        "evidence_claim_id", "fingerprint_version", "chain_sequence",
        "supersedes_fingerprint_id", "input_digest", "component_hashes_json",
        "detected_products_json", "detected_frameworks_json",
        "detected_models_json", "detected_protocols_json",
        "detected_capabilities_json", "observed_destinations_json", "confidence",
        "drift_summary_json", "created_at",
    },
    "discovery_ai_capabilities": {
        "capability_id", "tenant_id", "asset_id", "source_observation_id",
        "evidence_claim_id", "capability_name", "capability_state",
        "extractor_version", "assertion_sequence", "supersedes_capability_id",
        "input_digest", "confidence", "first_observed_at", "last_observed_at",
        "created_at",
    },
    "discovery_asset_history_members": {
        "history_member_id", "tenant_id", "history_event_id", "asset_id",
        "member_role", "ordinal", "created_at",
    },
}

PHASE2_CAPABILITY_TRUTH_COLUMNS = {
    "verification_state",
    "freshness",
    "observed_usage",
    "declared_only",
    "inferred_only",
}


def test_0055_models_match_the_approved_nine_table_manifest() -> None:
    models = import_module("app.db.models.ai_asset")

    assert set(models.H1B_TABLE_MODELS) == set(EXPECTED_TABLE_COLUMNS)
    for table_name, model in models.H1B_TABLE_MODELS.items():
        table = model.__table__
        expected = EXPECTED_TABLE_COLUMNS[table_name]
        if table_name == "discovery_ai_capabilities":
            expected = expected | PHASE2_CAPABILITY_TRUTH_COLUMNS
        assert set(table.columns.keys()) == expected
        assert tuple(column.name for column in table.primary_key) == (
            models.H1B_PRIMARY_KEYS[table_name],
        )
        assert all(
            tuple(column.name for column in index.columns)[0] == "tenant_id"
            for index in table.indexes
        )
        for constraint in table.foreign_key_constraints:
            local_columns = tuple(
                element.parent.name for element in constraint.elements
            )
            if tuple(element.target_fullname for element in constraint.elements) == (
                "tenants.id",
            ):
                continue
            assert local_columns[0] == "tenant_id"


def test_0055_is_linear_and_freezes_the_exact_manifest() -> None:
    migration = import_module(MIGRATION_MODULE)

    assert migration.revision == "0055_discovery_assets_res"
    assert migration.down_revision == "0054_discovery_obs_truth"
    assert tuple(migration.H1B_TABLES) == tuple(EXPECTED_TABLE_COLUMNS)
    assert set(migration.APPEND_ONLY_TABLES) == set(EXPECTED_TABLE_COLUMNS) - {
        "discovery_ai_assets"
    }
    assert len(migration.INDEXES) == 24
    assert all(columns[0] == "tenant_id" for _, _, columns in migration.INDEXES)


def test_fresh_sqlite_upgrade_builds_0055_and_immutability(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database_path = tmp_path / "phase2-assets.sqlite3"
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
        assert set(EXPECTED_TABLE_COLUMNS) <= set(inspector.get_table_names())
        for table_name, expected_columns in EXPECTED_TABLE_COLUMNS.items():
            actual_columns = {
                column["name"] for column in inspector.get_columns(table_name)
            }
            if table_name == "discovery_ai_capabilities":
                expected_columns = expected_columns | PHASE2_CAPABILITY_TRUTH_COLUMNS
            assert actual_columns == expected_columns
        with engine.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar_one() == H1_ACCEPTANCE_REVISION
            trigger_names = {
                row[0]
                for row in connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type='trigger' "
                    "AND (name LIKE 'trg_discovery_%_immutable_%' "
                    "OR name='trg_discovery_ai_assets_no_delete')"
                )
            }
    finally:
        engine.dispose()

    migration = import_module(MIGRATION_MODULE)
    expected_0055_triggers = {"trg_discovery_ai_assets_no_delete"}
    for token in migration._SQLITE_TRIGGER_TOKEN.values():
        expected_0055_triggers.add(f"trg_{token}_immutable_update")
        expected_0055_triggers.add(f"trg_{token}_immutable_delete")
    assert expected_0055_triggers <= trigger_names
    assert len(expected_0055_triggers) == 17
