from __future__ import annotations

from pathlib import Path
import shutil

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def test_0066_upgrade_persists_execution_and_approval_lifecycle_tables(tmp_path, monkeypatch) -> None:
    from app.core.config import settings

    api_root = Path(__file__).resolve().parents[1]
    database_url = f"sqlite+pysqlite:///{tmp_path / 'phase5-0066.sqlite3'}"
    migrations = tmp_path / "migrations"
    shutil.copytree(
        api_root / "app/db/migrations",
        migrations,
        ignore=shutil.ignore_patterns("._*", "__pycache__"),
    )
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    config = Config(str(api_root / "app/db/migrations/alembic.ini"))
    config.set_main_option("script_location", str(migrations))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "0066_phase5_execution_lifecycle")

    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        assert {
            "decision_receipt_v2_extensions",
            "execution_permits_v2",
            "execution_permit_attempts_v2",
            "execution_permit_transitions_v2",
            "approval_binding_v2_extensions",
            "approval_authority_events_v2",
            "approval_authority_projections_v2",
        } <= tables
        permit_columns = {column["name"] for column in inspector.get_columns("execution_permits_v2")}
        assert {"permit_id", "action_id", "attempt_id", "state", "signed_envelope", "expires_at"} <= permit_columns
        approval_columns = {column["name"] for column in inspector.get_columns("approval_binding_v2_extensions")}
        assert {"approval_request_id", "binding_id", "canonical_action_hash", "signed_envelope"} <= approval_columns
    finally:
        engine.dispose()
