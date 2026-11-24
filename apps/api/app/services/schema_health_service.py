from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session


ALEMBIC_RELATIVE_PATH = Path("app/db/migrations/alembic.ini")


@dataclass(frozen=True)
class ColumnRequirement:
    table: str
    column: str


@dataclass
class SchemaHealthReport:
    healthy: bool
    migration_current_heads: list[str] = field(default_factory=list)
    migration_expected_heads: list[str] = field(default_factory=list)
    pending_migrations: list[str] = field(default_factory=list)
    missing_tables: list[str] = field(default_factory=list)
    missing_columns: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "healthy": self.healthy,
            "migration_current_heads": self.migration_current_heads,
            "migration_expected_heads": self.migration_expected_heads,
            "pending_migrations": self.pending_migrations,
            "missing_tables": self.missing_tables,
            "missing_columns": self.missing_columns,
            "notes": self.notes,
        }


def _api_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _alembic_ini() -> Path:
    return _api_root() / ALEMBIC_RELATIVE_PATH


def _resolve_table_name(existing: set[str], candidates: list[str]) -> str | None:
    for candidate in candidates:
        if candidate in existing:
            return candidate
    return None


def _required_table_aliases() -> dict[str, list[str]]:
    return {
        "findings": ["findings"],
        "runtime_events": ["runtime_events"],
        "policies": ["policies", "policy_versions", "policy_packs"],
        "policy_assignments": ["policy_assignments", "policy_scopes", "policy_scope_assignments"],
        "users": ["users", "user_registry"],
        "devices": ["devices", "deployment_endpoints"],
    }


def _required_columns() -> list[ColumnRequirement]:
    return [
        ColumnRequirement("findings", "agent_id"),
        ColumnRequirement("findings", "user_id"),
        ColumnRequirement("findings", "machine_id"),
        ColumnRequirement("findings", "policy_id"),
        ColumnRequirement("findings", "decision"),
        ColumnRequirement("runtime_events", "user_id"),
        ColumnRequirement("runtime_events", "machine_id"),
        ColumnRequirement("runtime_events", "browser_type"),
        ColumnRequirement("runtime_events", "application"),
        ColumnRequirement("runtime_events", "decision"),
    ]


def evaluate_schema_health(db: Session) -> SchemaHealthReport:
    missing_tables: list[str] = []
    missing_columns: list[str] = []
    notes: list[str] = []
    current_heads: list[str] = []
    expected_heads: list[str] = []
    pending_migrations: list[str] = []

    bind = db.get_bind()
    inspector = inspect(bind)
    existing_tables = set(inspector.get_table_names())
    resolved_tables: dict[str, str] = {}

    aliases = _required_table_aliases()
    for logical_table, candidates in aliases.items():
        resolved = _resolve_table_name(existing_tables, candidates)
        if resolved is None:
            # policy_assignments is represented by scoped rules when explicit table isn't present.
            if logical_table == "policy_assignments":
                if "policy_versions" in existing_tables:
                    columns = {row["name"] for row in inspector.get_columns("policy_versions")}
                    if "scope" in columns:
                        notes.append("policy_assignments resolved via policy_versions.scope scoped_rules")
                        continue
            missing_tables.append(logical_table)
            continue
        resolved_tables[logical_table] = resolved
        if logical_table != resolved:
            notes.append(f"{logical_table} resolved as {resolved}")

    for requirement in _required_columns():
        table_name = resolved_tables.get(requirement.table, requirement.table)
        if table_name not in existing_tables:
            missing_columns.append(f"{requirement.table}.{requirement.column}")
            continue
        table_columns = {row["name"] for row in inspector.get_columns(table_name)}
        if requirement.column not in table_columns:
            missing_columns.append(f"{requirement.table}.{requirement.column}")

    try:
        context = MigrationContext.configure(db.connection())
        current_heads = sorted(set(context.get_current_heads()))
    except SQLAlchemyError as exc:
        notes.append(f"migration current head query failed: {exc}")
    except Exception as exc:  # noqa: BLE001
        notes.append(f"migration current head context failed: {exc}")

    alembic_ini = _alembic_ini()
    if not alembic_ini.exists():
        notes.append(f"missing alembic config: {alembic_ini}")
    else:
        try:
            config = Config(str(alembic_ini))
            script = ScriptDirectory.from_config(config)
            expected_heads = sorted(set(script.get_heads()))
        except Exception as exc:  # noqa: BLE001
            notes.append(f"migration expected head load failed: {exc}")

    if expected_heads and current_heads:
        pending_migrations = sorted(set(expected_heads) - set(current_heads))
        if set(expected_heads) != set(current_heads):
            notes.append(
                f"migration heads mismatch expected={expected_heads} current={current_heads}"
            )

    healthy = not missing_tables and not missing_columns and not pending_migrations
    return SchemaHealthReport(
        healthy=healthy,
        migration_current_heads=current_heads,
        migration_expected_heads=expected_heads,
        pending_migrations=pending_migrations,
        missing_tables=missing_tables,
        missing_columns=missing_columns,
        notes=notes,
    )
