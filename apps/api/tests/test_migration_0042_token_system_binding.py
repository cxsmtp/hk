from __future__ import annotations

import shutil
from importlib import import_module
from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import event, inspect

from app.core.config import settings


def _engine(path: Path) -> sa.Engine:
    engine = sa.create_engine(f"sqlite+pysqlite:///{path}")

    @event.listens_for(engine, "connect")
    def _foreign_keys(connection, _record):  # type: ignore[no-untyped-def]
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


def _legacy_schema(engine: sa.Engine) -> None:
    metadata = sa.MetaData()
    tenants = sa.Table("tenants", metadata, sa.Column("id", sa.String(36), primary_key=True))
    systems = sa.Table("ai_systems", metadata, sa.Column("id", sa.String(36), primary_key=True))
    agents = sa.Table(
        "agent_identities",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
    )
    tokens = sa.Table(
        "capability_tokens",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("agent_identity_id", sa.String(36), sa.ForeignKey("agent_identities.id"), nullable=False),
    )
    delegations = sa.Table(
        "agent_delegations",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("parent_token_id", sa.String(36), sa.ForeignKey("capability_tokens.id"), nullable=False),
        sa.Column("child_token_id", sa.String(36), sa.ForeignKey("capability_tokens.id"), nullable=False),
        sa.Column("ai_system_id", sa.String(36), sa.ForeignKey("ai_systems.id"), nullable=True),
    )
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(tenants.insert(), {"id": "tenant-a"})
        connection.execute(systems.insert(), [{"id": "system-a"}, {"id": "system-b"}])
        connection.execute(agents.insert(), [{"id": "agent-a", "tenant_id": "tenant-a"}, {"id": "agent-b", "tenant_id": "tenant-a"}])
        connection.execute(tokens.insert(), [
            {"id": "token-exact", "tenant_id": "tenant-a", "agent_identity_id": "agent-a"},
            {"id": "token-conflict", "tenant_id": "tenant-a", "agent_identity_id": "agent-a"},
            {"id": "token-helper-a", "tenant_id": "tenant-a", "agent_identity_id": "agent-b"},
            {"id": "token-helper-b", "tenant_id": "tenant-a", "agent_identity_id": "agent-b"},
            {"id": "token-orphan", "tenant_id": "tenant-a", "agent_identity_id": "agent-b"},
        ])
        connection.execute(delegations.insert(), [
            {"id": "edge-a", "tenant_id": "tenant-a", "parent_token_id": "token-exact", "child_token_id": "token-conflict", "ai_system_id": "system-a"},
            {"id": "edge-b", "tenant_id": "tenant-a", "parent_token_id": "token-conflict", "child_token_id": "token-helper-b", "ai_system_id": "system-b"},
        ])


def _config(tmp_path: Path, database_path: Path) -> Config:
    api_root = Path(__file__).resolve().parents[1]
    migration_copy = tmp_path / "migrations"
    shutil.copytree(api_root / "app/db/migrations", migration_copy, ignore=shutil.ignore_patterns("._*", "__pycache__"))
    config = Config(str(api_root / "app/db/migrations/alembic.ini"))
    config.set_main_option("script_location", str(migration_copy))
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{database_path}")
    return config


def test_0042_upgrade_downgrade_upgrade_on_disposable_database(tmp_path, monkeypatch) -> None:
    database_path = tmp_path / "token-system.sqlite3"
    engine = _engine(database_path)
    _legacy_schema(engine)
    database_url = f"sqlite+pysqlite:///{database_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    config = _config(tmp_path, database_path)
    command.stamp(config, "0041_tenant_guardian_sim")

    command.upgrade(config, "0042_token_system_binding")
    inspector = inspect(engine)
    column = next(item for item in inspector.get_columns("capability_tokens") if item["name"] == "ai_system_id")
    assert column["nullable"] is True
    assert "idx_token_ai_system" in {item["name"] for item in inspector.get_indexes("capability_tokens")}
    assert any(item["referred_table"] == "ai_systems" for item in inspector.get_foreign_keys("capability_tokens"))
    with engine.connect() as connection:
        bindings = dict(connection.execute(sa.text("SELECT id, ai_system_id FROM capability_tokens ORDER BY id")).all())
    assert bindings["token-exact"] == "system-a"
    assert bindings["token-conflict"] is None
    assert bindings["token-orphan"] is None

    command.downgrade(config, "0041_tenant_guardian_sim")
    assert "ai_system_id" not in {item["name"] for item in inspect(engine).get_columns("capability_tokens")}
    command.upgrade(config, "0042_token_system_binding")
    assert "ai_system_id" in {item["name"] for item in inspect(engine).get_columns("capability_tokens")}
    with engine.connect() as connection:
        rebound = dict(connection.execute(sa.text("SELECT id, ai_system_id FROM capability_tokens ORDER BY id")).all())
    assert rebound["token-exact"] == "system-a"
    assert rebound["token-conflict"] is None
    assert rebound["token-orphan"] is None
    engine.dispose()


def test_migration_graph_has_one_short_alembic_head() -> None:
    migration = import_module("app.db.migrations.versions.0042_token_system_binding")
    assert len(migration.revision) <= 32
    config = Config(str(Path(__file__).resolve().parents[1] / "app/db/migrations/alembic.ini"))
    heads = ScriptDirectory.from_config(config).get_heads()
    assert heads == ["0093_activation_state"]
    assert all(len(head) <= 128 for head in heads)
