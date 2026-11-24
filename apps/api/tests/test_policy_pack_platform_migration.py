"""Focused upgrade/downgrade proof for Policy Pack Platform persistence."""

from __future__ import annotations

from pathlib import Path
import shutil

from alembic import command
from alembic.config import Config
from sqlalchemy import Column, MetaData, String, Table, create_engine, inspect, text

from app.core.config import settings


API_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_CONFIG = API_ROOT / "app/db/migrations/alembic.ini"
PREVIOUS_REVISION = "0081_maturity_curve_review_and_pattern_context"
CURRENT_REVISION = "0082_policy_pack_platform"
PACK_TABLES = {
    "policy_pack_platform_entitlements",
    "policy_pack_definitions",
    "policy_pack_templates",
    "policy_pack_instances",
    "policy_pack_assignments",
    "policy_pack_user_groups",
    "policy_pack_group_memberships",
    "policy_pack_updates",
    "policy_pack_simulations",
    "policy_pack_exceptions",
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


def test_policy_pack_platform_upgrade_downgrade_reupgrade_from_0081(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'policy-pack-platform.sqlite3'}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    engine = create_engine(database_url)
    try:
        baseline = MetaData()
        Table("tenants", baseline, Column("id", String(36), primary_key=True))
        Table("users", baseline, Column("id", String(36), primary_key=True))
        Table("policy_packs", baseline, Column("id", String(36), primary_key=True))
        Table("policy_versions", baseline, Column("id", String(36), primary_key=True))
        baseline.create_all(engine)
    finally:
        engine.dispose()

    config = _config(tmp_path, database_url)
    command.stamp(config, PREVIOUS_REVISION)
    command.upgrade(config, CURRENT_REVISION)
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        assert PACK_TABLES <= set(inspector.get_table_names())
        assert {"tenant_id", "definition_id", "runtime_policy_pack_id", "effective_policy_version_id", "lineage"} <= {
            column["name"] for column in inspector.get_columns("policy_pack_instances")
        }
        assert {"condition_tree", "decision", "non_overridable", "explicit_revocation"} <= {
            column["name"] for column in inspector.get_columns("policy_pack_templates")
        }
        with engine.connect() as connection:
            assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == CURRENT_REVISION
    finally:
        engine.dispose()

    command.downgrade(config, PREVIOUS_REVISION)
    engine = create_engine(database_url)
    try:
        assert not (PACK_TABLES & set(inspect(engine).get_table_names()))
    finally:
        engine.dispose()

    command.upgrade(config, CURRENT_REVISION)
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == CURRENT_REVISION
    finally:
        engine.dispose()
