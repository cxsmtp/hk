from __future__ import annotations

from importlib import import_module
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


def test_0076_is_single_head_and_has_reversible_collective_tables() -> None:
    api_root = Path(__file__).resolve().parents[1]
    config = Config(str(api_root / "app/db/migrations/alembic.ini"))
    config.set_main_option("script_location", str(api_root / "app/db/migrations"))
    assert ScriptDirectory.from_config(config).get_heads() == ["0094_first_run_and_terms"]
    migration = import_module("app.db.migrations.versions.0076_agent_collective_security")
    assert migration.down_revision == "0075_account_boundary_production_core"
    source = (api_root / "app/db/migrations/versions/0076_agent_collective_security.py").read_text(
        encoding="utf-8"
    )
    for table in (
        "agent_collective_contexts",
        "agent_collective_communication_events",
        "agent_collective_security_signals",
        "agent_collective_root_revocations",
    ):
        assert f'op.create_table(\n        "{table}"' in source
        assert f'op.drop_table("{table}")' in source
