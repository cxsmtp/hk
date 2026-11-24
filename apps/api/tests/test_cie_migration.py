from __future__ import annotations

from importlib import import_module
from pathlib import Path
import shutil
from types import SimpleNamespace

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from app.core.config import settings


API_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_CONFIG = API_ROOT / "app/db/migrations/alembic.ini"


def test_0059_migration_declares_append_only_cie_schema() -> None:
    migration = import_module(
        "app.db.migrations.versions.0059_capability_inference_engine"
    )
    assert migration.revision == "0059_capability_inference_engine"
    assert migration.down_revision == "0058_discovery_intelligence"
    assert set(migration.TABLES) == {
        "discovery_capability_inference_runs",
        "discovery_capability_evidence",
        "discovery_capability_genomes",
        "discovery_capability_events",
    }
    assert migration.IMMUTABLE_TABLES == migration.TABLES


def test_0059_postgresql_taxonomy_replacement_never_recreates_graph_tables(monkeypatch) -> None:
    """PostgreSQL must alter only the check constraints referenced by 0059."""
    migration = import_module("app.db.migrations.versions.0059_capability_inference_engine")

    class RecordingOp:
        def __init__(self) -> None:
            self.dropped: list[tuple[str, str, str]] = []
            self.created: list[tuple[str, str, str]] = []

        def get_bind(self):
            return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

        def batch_alter_table(self, *_args, **_kwargs):
            raise AssertionError("PostgreSQL taxonomy replacement must not batch-recreate a graph table")

        def drop_constraint(self, name: str, table_name: str, *, type_: str) -> None:
            self.dropped.append((name, table_name, type_))

        def create_check_constraint(self, name: str, table_name: str, condition: str) -> None:
            self.created.append((name, table_name, condition))

    op = RecordingOp()
    monkeypatch.setattr(migration, "op", op)

    migration._extend_resolution_graph_taxonomy()
    migration._restore_resolution_graph_taxonomy()

    assert op.dropped == [
        ("ck_discovery_resolution_graph_edge_type", "discovery_resolution_graph_edges", "check"),
        ("ck_discovery_resolution_graph_node_class", "discovery_resolution_graph_nodes", "check"),
        ("ck_discovery_resolution_graph_edge_type", "discovery_resolution_graph_edges", "check"),
        ("ck_discovery_resolution_graph_node_class", "discovery_resolution_graph_nodes", "check"),
    ]
    assert [entry[:2] for entry in op.created] == [
        ("ck_discovery_resolution_graph_edge_type", "discovery_resolution_graph_edges"),
        ("ck_discovery_resolution_graph_node_class", "discovery_resolution_graph_nodes"),
        ("ck_discovery_resolution_graph_edge_type", "discovery_resolution_graph_edges"),
        ("ck_discovery_resolution_graph_node_class", "discovery_resolution_graph_nodes"),
    ]


def test_fresh_upgrade_to_0059_creates_guarded_tables(
    tmp_path: Path, monkeypatch
) -> None:
    database_path = tmp_path / "cie.sqlite3"
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
    command.upgrade(config, "0059_capability_inference_engine")
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        assert {
            "discovery_capability_inference_runs",
            "discovery_capability_evidence",
            "discovery_capability_genomes",
            "discovery_capability_events",
        } <= set(inspector.get_table_names())
        for table_name in (
            "discovery_capability_inference_runs",
            "discovery_capability_evidence",
            "discovery_capability_genomes",
            "discovery_capability_events",
        ):
            assert all(
                tuple(index["column_names"])[0] == "tenant_id"
                for index in inspector.get_indexes(table_name)
            )
        with engine.connect() as connection:
            assert connection.exec_driver_sql(
                "SELECT version_num FROM alembic_version"
            ).scalar_one() == "0059_capability_inference_engine"
            trigger_names = {
                row[0]
                for row in connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type='trigger'"
                )
            }
            assert len({name for name in trigger_names if name.startswith("trg_cie_")}) == 8
    finally:
        engine.dispose()
