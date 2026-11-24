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
MIGRATION_MODULE = "app.db.migrations.versions.0056_discovery_resolution_graph"
H1_ACCEPTANCE_REVISION = "0061_autonomous_discovery_verification"

EXPECTED = {
    "discovery_asset_hypotheses": {
        "hypothesis_id", "tenant_id", "hypothesis_type", "state", "label",
        "candidate_key_hash", "confidence", "verification_state", "freshness",
        "contradiction_state", "evidence_node_id", "promoted_asset_id",
        "first_observed_at", "last_observed_at", "version", "idempotency_key",
        "input_digest", "created_at", "updated_at",
    },
    "discovery_hypothesis_transitions": {
        "transition_id", "tenant_id", "hypothesis_id", "from_state", "to_state",
        "evidence_node_id", "actor_id", "reason", "idempotency_key",
        "input_digest", "created_at",
    },
    "discovery_resolution_graph_nodes": {
        "graph_node_id", "tenant_id", "node_class", "subject_reference",
        "idempotency_key", "input_digest", "created_at",
    },
    "discovery_resolution_graph_edges": {
        "edge_id", "tenant_id", "from_node_id", "to_node_id", "edge_type",
        "evidence_node_id", "confidence", "verification_state", "freshness",
        "contradiction_state", "first_observed_at", "last_observed_at",
        "idempotency_key", "input_digest", "created_at",
    },
    "discovery_verification_tasks": {
        "task_id", "tenant_id", "hypothesis_id", "task_type", "status",
        "method", "scope_json", "rate_limit_key", "priority", "max_attempts",
        "attempt_count", "expires_at", "claimed_by", "claimed_at",
        "completed_at", "result_evidence_node_id", "limitations_json",
        "idempotency_key", "input_digest", "created_at", "updated_at",
    },
}


def test_0056_models_match_resolution_manifest() -> None:
    models = import_module("app.db.models.discovery_resolution")
    assert set(models.RESOLUTION_TABLE_MODELS) == set(EXPECTED)
    for name, model in models.RESOLUTION_TABLE_MODELS.items():
        # Later additive migrations may extend a 0056 table without replacing
        # the original Phase 2 contract.
        assert EXPECTED[name] <= set(model.__table__.columns.keys())
        assert all(tuple(index.columns)[0].name == "tenant_id" for index in model.__table__.indexes)


def test_fresh_sqlite_upgrade_builds_0056(tmp_path: Path, monkeypatch) -> None:
    database_path = tmp_path / "phase2-resolution.sqlite3"
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
        for table, columns in EXPECTED.items():
            assert columns <= {
                item["name"] for item in inspector.get_columns(table)
            }
        with engine.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar_one() == H1_ACCEPTANCE_REVISION
    finally:
        engine.dispose()

    migration = import_module(MIGRATION_MODULE)
    assert migration.revision == "0056_discovery_resolution_graph"
    assert migration.down_revision == "0055_discovery_assets_res"
