from __future__ import annotations

import ast
from io import StringIO
from pathlib import Path
import shutil
from importlib import import_module

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

from app.db.models.policy import GuardianContractBindingV2, GuardianContractV2
from app.db.models.simulation import Control
from app.db.models.tenant import Tenant
from app.core.config import settings
from app.services.schema_health_service import evaluate_schema_health


API_ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_CONFIG = API_ROOT / "app/db/migrations/alembic.ini"


def _clean_migration_config(tmp_path: Path, database_url: str) -> Config:
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


def test_first_long_revision_expands_postgres_version_capacity(
    tmp_path: Path, monkeypatch,
) -> None:
    migration = import_module(
        "app.db.migrations.versions.0003_enforcement_determinism_fields"
    )
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    monkeypatch.setattr(
        migration.op,
        "alter_column",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    migration._ensure_alembic_version_capacity("postgresql")
    migration._ensure_alembic_version_capacity("sqlite")

    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args == ("alembic_version", "version_num")
    assert kwargs["type_"].length == migration.ALEMBIC_VERSION_LENGTH
    config = _clean_migration_config(
        tmp_path,
        f"sqlite+pysqlite:///{tmp_path / 'revision-capacity.sqlite3'}",
    )
    assert migration.ALEMBIC_VERSION_LENGTH >= max(
        len(revision.revision)
        for revision in ScriptDirectory.from_config(config).walk_revisions()
    )


def test_connector_boolean_backfill_compiles_as_postgres_booleans() -> None:
    migration = import_module(
        "app.db.migrations.versions.0007_sim_templates_integrations"
    )
    statements = migration._connector_boolean_backfills()
    compiled = [
        str(
            statement.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        ).lower()
        for statement in statements
    ]

    assert len(compiled) == 2
    assert any("set enabled=true" in statement for statement in compiled)
    assert any("set is_stub=false" in statement for statement in compiled)
    source = (
        API_ROOT
        / "app/db/migrations/versions/0007_sim_templates_integrations.py"
    ).read_text(encoding="utf-8")
    assert "SET enabled = 1" not in source
    assert "SET is_stub = 0" not in source


def test_migrations_use_current_single_statement_op_execute_contract() -> None:
    versions = API_ROOT / "app/db/migrations/versions"
    violations: list[str] = []
    for path in sorted(versions.glob("*.py")):
        if path.name.startswith("._"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "op"
                and node.func.attr == "execute"
            ):
                continue
            if len(node.args) != 1 or node.keywords:
                violations.append(f"{path.name}:{node.lineno}")

    assert violations == []


def test_postgres_migration_chain_compiles_offline_through_0024(
    tmp_path: Path, monkeypatch,
) -> None:
    database_url = (
        "postgresql+psycopg2://hawk_preflight:unused@127.0.0.1/hawk_preflight"
    )
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    output = StringIO()
    config = _clean_migration_config(tmp_path, database_url)
    config.output_buffer = output

    command.upgrade(config, "0024_ai_iam_agent_action_control", sql=True)

    assert "0024_ai_iam_agent_action_control" in output.getvalue()


def test_fresh_sqlite_database_upgrades_to_current_healthy_schema(
    tmp_path: Path, monkeypatch,
) -> None:
    database_path = tmp_path / "fresh-hawk.sqlite3"
    database_url = f"sqlite+pysqlite:///{database_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    config = _clean_migration_config(tmp_path, database_url)
    command.upgrade(config, "head")

    expected_heads = set(ScriptDirectory.from_config(config).get_heads())
    engine = create_engine(database_url)
    try:
        with engine.connect() as connection:
            current_heads = {
                str(row[0])
                for row in connection.execute(text("SELECT version_num FROM alembic_version"))
            }
        with Session(engine) as session:
            report = evaluate_schema_health(session)

            tenant = Tenant(name="Fresh migration tenant", slug="fresh-migration")
            session.add(tenant)
            session.flush()
            session.add(
                GuardianContractV2(
                    tenant_id=tenant.id,
                    id="fresh-migration-guardian",
                    name="Fresh migration guardian",
                )
            )
            session.flush()
            session.add(
                GuardianContractBindingV2(
                    tenant_id=tenant.id,
                    guardian_contract_id="fresh-migration-guardian",
                )
            )
            session.flush()
            session.add(
                Control(
                    id="FRESH-MIGRATION-CONTROL",
                    tenant_id=tenant.id,
                    name="Fresh migration control",
                    category="validation",
                )
            )
            session.flush()
    finally:
        engine.dispose()

    assert current_heads == expected_heads
    assert report.healthy, report.to_dict()
