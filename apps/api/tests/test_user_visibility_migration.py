"""Focused upgrade/downgrade proof for User Visibility persistence."""

from __future__ import annotations

from pathlib import Path
import shutil

from alembic import command
from alembic.config import Config
from sqlalchemy import Column, MetaData, String, Table, create_engine, inspect, text

from app.core.config import settings


API_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_CONFIG = API_ROOT / "app/db/migrations/alembic.ini"
PREVIOUS_REVISION = "0082_policy_pack_platform"
CURRENT_REVISION = "0083_user_visibility_prompt_explorer"
VISIBILITY_TABLES = {
    "user_visibility_access_grants",
    "user_visibility_content_access_grants",
}


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


def test_user_visibility_upgrade_downgrade_reupgrade_from_0082(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'user-visibility.sqlite3'}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    engine = create_engine(database_url)
    try:
        baseline = MetaData()
        Table("tenants", baseline, Column("id", String(36), primary_key=True))
        Table("users", baseline, Column("id", String(36), primary_key=True))
        Table("ai_actions", baseline, Column("action_id", String(64), primary_key=True))
        baseline.create_all(engine)
    finally:
        engine.dispose()

    config = _config(tmp_path, database_url)
    command.stamp(config, PREVIOUS_REVISION)
    command.upgrade(config, CURRENT_REVISION)
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        assert VISIBILITY_TABLES <= set(inspector.get_table_names())
        assert {"tenant_id", "user_id", "capabilities", "department_scope", "expires_at", "active"} <= {
            column["name"] for column in inspector.get_columns("user_visibility_access_grants")
        }
        assert {"tenant_id", "requester_user_id", "action_id", "purpose", "reason", "expires_at", "consumed_at"} <= {
            column["name"] for column in inspector.get_columns("user_visibility_content_access_grants")
        }
        assert {"user_visibility_full_content_reveal_enabled", "user_visibility_prompt_retention_days"} <= {
            column["name"] for column in inspector.get_columns("tenants")
        }
        with engine.connect() as connection:
            assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == CURRENT_REVISION
    finally:
        engine.dispose()

    command.downgrade(config, PREVIOUS_REVISION)
    engine = create_engine(database_url)
    try:
        assert not (VISIBILITY_TABLES & set(inspect(engine).get_table_names()))
    finally:
        engine.dispose()

    command.upgrade(config, CURRENT_REVISION)
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == CURRENT_REVISION
    finally:
        engine.dispose()
