"""Runtime acceptance for the additive Maturity Curve migration only.

The historical chain has an unrelated SQLite limitation in revision 0072.
This test starts from the immediately preceding 0079 schema boundary so it
proves 0080 itself upgrades, downgrades, and re-upgrades without modifying the
older migration chain.
"""

from __future__ import annotations

from pathlib import Path
import shutil

from alembic import command
from alembic.config import Config
from sqlalchemy import Column, MetaData, String, Table, create_engine, inspect, text

from app.core.config import settings


API_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_CONFIG = API_ROOT / "app/db/migrations/alembic.ini"
PREVIOUS_REVISION = "0079_instruction_tool_provenance_integration"
CURRENT_REVISION = "0081_maturity_curve_review_and_pattern_context"

MATURITY_TABLES = {
    "tenant_maturity_entitlements",
    "maturity_scopes",
    "maturity_observation_windows",
    "maturity_assessments",
    "maturity_usage_baselines",
    "maturity_observed_usage_patterns",
    "maturity_policy_recommendations",
    "maturity_recommendation_reviews",
    "maturity_policy_simulations",
    "maturity_policy_rollouts",
    "maturity_rollout_transitions",
    "maturity_policy_exceptions",
    "maturity_policy_effectiveness_snapshots",
    "maturity_executive_snapshots",
}


def _config(tmp_path: Path, database_url: str) -> Config:
    """Mirror the existing migration tests' AppleDouble-safe script loading."""

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


def test_maturity_curve_0080_upgrade_downgrade_reupgrade_from_0079(tmp_path, monkeypatch) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'maturity-0080.sqlite3'}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)

    engine = create_engine(database_url)
    try:
        baseline = MetaData()
        Table("tenants", baseline, Column("id", String(36), primary_key=True))
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
        assert MATURITY_TABLES <= set(inspector.get_table_names())
        assert {"pattern_type", "approval_state", "risk_state", "control_state"} <= {
            column["name"] for column in inspector.get_columns("maturity_observed_usage_patterns")
        }
        assert {"review_state", "review_reason", "reviewed_by_ref", "reviewed_at"} <= {
            column["name"] for column in inspector.get_columns("maturity_policy_recommendations")
        }
        assert {"rollout_stage"} <= {
            column["name"] for column in inspector.get_columns("maturity_policy_rollouts")
        }
        assert {"report"} <= {
            column["name"] for column in inspector.get_columns("maturity_executive_snapshots")
        }
        with engine.connect() as connection:
            assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == CURRENT_REVISION
    finally:
        engine.dispose()

    command.downgrade(config, PREVIOUS_REVISION)
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        assert not (MATURITY_TABLES & set(inspector.get_table_names()))
    finally:
        engine.dispose()

    command.upgrade(config, CURRENT_REVISION)
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == CURRENT_REVISION
    finally:
        engine.dispose()
