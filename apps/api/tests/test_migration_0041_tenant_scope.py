from __future__ import annotations

import shutil
from datetime import datetime, timezone
from importlib import import_module
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy import event

from app.core.config import settings


EXPECTED_SYSTEM_CONTROL_IDS = {
    "PROMPT_INJECTION_DETECTION",
    "JAILBREAK_DETECTION",
    "SENSITIVE_DATA_DETECTION",
    "PII_EXFILTRATION_PREVENTION",
    "FILE_UPLOAD_INSPECTION",
    "OCR_DATA_EXTRACTION_CONTROL",
    "RAG_POISONING_DETECTION",
    "MODEL_OUTPUT_VALIDATION",
    "MODEL_ACCESS_CONTROL",
    "MODEL_INTEGRITY_CHECK",
    "SHADOW_AI_DETECTION",
    "AI_SYSTEM_INVENTORY_CONTROL",
    "AI_IDENTITY_BINDING",
    "NON_HUMAN_IDENTITY_CONTROL",
    "TOKEN_SCOPE_ENFORCEMENT",
    "PRIVILEGE_DRIFT_DETECTION",
    "TOOL_CALL_VALIDATION",
    "TOOL_MISUSE_PREVENTION",
    "AGENT_ACTION_AUTHORIZATION",
    "CHAIN_OF_ACTION_VALIDATION",
    "CROSS_AGENT_BOUNDARY_CONTROL",
    "CONTEXT_LEAKAGE_DETECTION",
    "POLICY_ENFORCEMENT_CONTROL",
    "RISK_CLASSIFICATION_CONTROL",
}


def _sqlite_engine(database_path: Path) -> sa.Engine:
    engine = sa.create_engine(f"sqlite+pysqlite:///{database_path}")

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _connection_record):  # type: ignore[no-untyped-def]
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


def _legacy_schema(
    engine: sa.Engine,
    *,
    orphan_guardian: bool = False,
    multi_tenant: bool = False,
) -> None:
    metadata = sa.MetaData()
    tenants = sa.Table("tenants", metadata, sa.Column("id", sa.String(36), primary_key=True))
    ai_systems = sa.Table("ai_systems", metadata, sa.Column("id", sa.String(36), primary_key=True))
    policy_versions = sa.Table("policy_versions", metadata, sa.Column("id", sa.String(36), primary_key=True))
    guardians = sa.Table(
        "guardian_contract_v2",
        metadata,
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("version", sa.String(16), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("trigger_conditions", sa.JSON(), nullable=False),
        sa.Column("block_conditions", sa.JSON(), nullable=False),
        sa.Column("mandatory_actions", sa.JSON(), nullable=False),
        sa.Column("escalation_path", sa.JSON(), nullable=False),
        sa.Column("evidence_requirements", sa.JSON(), nullable=False),
        sa.Column("framework_mappings", sa.JSON(), nullable=False),
        sa.Column("canonical_policy", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    bindings = sa.Table(
        "guardian_contract_binding_v2",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("guardian_contract_id", sa.String(128), sa.ForeignKey("guardian_contract_v2.id"), nullable=False),
        sa.Column("ai_system_id", sa.String(36), sa.ForeignKey("ai_systems.id"), nullable=True),
        sa.Column("policy_version_id", sa.String(36), sa.ForeignKey("policy_versions.id"), nullable=True),
        sa.Column("enforcement_strength", sa.String(16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    controls = sa.Table(
        "controls",
        metadata,
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=True),
        sa.Column("is_global", sa.Boolean(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("mapped_framework_refs", sa.JSON(), nullable=False),
        sa.Column("risk_tags", sa.JSON(), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("enforcement_points", sa.JSON(), nullable=False),
        sa.Column("detection_methods", sa.JSON(), nullable=False),
        sa.Column("response_actions", sa.JSON(), nullable=False),
        sa.Column("evidence_types", sa.JSON(), nullable=False),
        sa.Column("remediation_templates", sa.JSON(), nullable=False),
        sa.Column("success_criteria", sa.JSON(), nullable=False),
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    maturity = sa.Table(
        "control_maturity",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("control_id", sa.String(36), sa.ForeignKey("controls.id"), nullable=False),
    )
    conflicts = sa.Table(
        "control_conflicts",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("control_id", sa.String(36), sa.ForeignKey("controls.id"), nullable=False),
    )
    resolutions = sa.Table(
        "conflict_resolutions",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("control_id", sa.String(36), sa.ForeignKey("controls.id"), nullable=False),
        sa.Column(
            "conflict_id",
            sa.String(36),
            sa.ForeignKey("control_conflicts.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    metadata.create_all(engine)

    now = datetime(2026, 7, 21, tzinfo=timezone.utc)
    contract_id = "unsafe-orphan" if orphan_guardian else "tenant-custom"
    with engine.begin() as connection:
        connection.execute(tenants.insert(), {"id": "tenant-1"})
        if multi_tenant:
            connection.execute(tenants.insert(), {"id": "tenant-2"})
        connection.execute(ai_systems.insert(), {"id": "ai-1"})
        connection.execute(policy_versions.insert(), {"id": "policy-1"})
        guardian_rows = [
            {
                "id": "prompt_injection_guard",
                "version": "2.0",
                "name": "System default",
                "trigger_conditions": [],
                "block_conditions": [],
                "mandatory_actions": {},
                "escalation_path": {},
                "evidence_requirements": {},
                "framework_mappings": {},
                "canonical_policy": {},
                "created_at": now,
            },
            {
                "id": contract_id,
                "version": "2.0",
                "name": "Custom",
                "trigger_conditions": [],
                "block_conditions": [],
                "mandatory_actions": {},
                "escalation_path": {},
                "evidence_requirements": {},
                "framework_mappings": {},
                "canonical_policy": {},
                "created_at": now,
            },
        ]
        connection.execute(guardians.insert(), guardian_rows)
        if not orphan_guardian:
            connection.execute(
                bindings.insert(),
                {
                    "id": "binding-1",
                    "tenant_id": "tenant-1",
                    "guardian_contract_id": contract_id,
                    "ai_system_id": None,
                    "policy_version_id": None,
                    "enforcement_strength": "strict",
                    "enabled": True,
                    "created_at": now,
                    "updated_at": now,
                },
            )
            if multi_tenant:
                connection.execute(
                    bindings.insert(),
                    {
                        "id": "binding-system-tenant-1",
                        "tenant_id": "tenant-1",
                        "guardian_contract_id": "prompt_injection_guard",
                        "ai_system_id": None,
                        "policy_version_id": None,
                        "enforcement_strength": "strict",
                        "enabled": True,
                        "created_at": now,
                        "updated_at": now,
                    },
                )
        base_control = {
            "name": "Control",
            "category": "validation",
            "description": "test",
            "mapped_framework_refs": [],
            "risk_tags": [],
            "severity": "high",
            "enforcement_points": [],
            "detection_methods": [],
            "response_actions": [],
            "evidence_types": [],
            "remediation_templates": [],
            "success_criteria": {},
            "created_at": now,
            "updated_at": now,
        }
        global_ids = EXPECTED_SYSTEM_CONTROL_IDS if multi_tenant else {"PROMPT_INJECTION_DETECTION"}
        connection.execute(
            controls.insert(),
            [
                *[
                    {
                        **base_control,
                        "id": control_id,
                        "tenant_id": "tenant-1" if multi_tenant else None,
                        "is_global": True,
                    }
                    for control_id in sorted(global_ids)
                ],
                {
                    **base_control,
                    "id": "tenant-private",
                    "tenant_id": "tenant-1",
                    "is_global": False,
                },
            ],
        )
        connection.execute(
            maturity.insert(),
            {"id": "maturity-1", "tenant_id": "tenant-1", "control_id": "PROMPT_INJECTION_DETECTION"},
        )
        if multi_tenant:
            connection.execute(
                maturity.insert(),
                {"id": "maturity-2", "tenant_id": "tenant-2", "control_id": "PROMPT_INJECTION_DETECTION"},
            )
        connection.execute(
            conflicts.insert(),
            {"id": "conflict-1", "tenant_id": "tenant-1", "control_id": "PROMPT_INJECTION_DETECTION"},
        )
        connection.execute(
            resolutions.insert(),
            {
                "id": "resolution-1",
                "tenant_id": "tenant-1",
                "control_id": "PROMPT_INJECTION_DETECTION",
                "conflict_id": "conflict-1",
            },
        )


def _config(*, repo_api_root: Path, clean_script_dir: Path, database_path: Path) -> Config:
    config = Config(str(repo_api_root / "app/db/migrations/alembic.ini"))
    config.set_main_option("script_location", str(clean_script_dir))
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{database_path}")
    return config


def _assert_conflict_resolution_fk_set_null(inspector) -> None:
    foreign_key = next(
        item
        for item in inspector.get_foreign_keys("conflict_resolutions")
        if item.get("referred_table") == "control_conflicts"
    )
    assert str((foreign_key.get("options") or {}).get("ondelete") or "").upper() == "SET NULL"


def _clean_migration_tree(tmp_path: Path) -> tuple[Path, Path]:
    repo_api_root = Path(__file__).resolve().parents[1]
    source = repo_api_root / "app/db/migrations"
    destination = tmp_path / "migrations"
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns("._*", "__pycache__"))
    return repo_api_root, destination


def test_0041_upgrade_downgrade_upgrade_on_disposable_database(tmp_path, monkeypatch) -> None:
    repo_api_root, migrations = _clean_migration_tree(tmp_path)
    database_path = tmp_path / "roundtrip.sqlite3"
    engine = _sqlite_engine(database_path)
    _legacy_schema(engine)
    database_url = f"sqlite+pysqlite:///{database_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    config = _config(repo_api_root=repo_api_root, clean_script_dir=migrations, database_path=database_path)
    command.stamp(config, "0040_agentic_action_integrity")

    command.upgrade(config, "0041_tenant_guardian_sim")
    inspector = inspect(engine)
    assert inspector.get_pk_constraint("guardian_contract_v2")["constrained_columns"] == ["tenant_id", "id"]
    assert inspector.get_pk_constraint("controls")["constrained_columns"] == ["id", "tenant_id"]
    _assert_conflict_resolution_fk_set_null(inspector)
    with engine.connect() as connection:
        assert connection.scalar(sa.text("SELECT COUNT(*) FROM guardian_contract_v2 WHERE tenant_id IS NULL")) == 0
        assert connection.scalar(sa.text("SELECT COUNT(*) FROM controls WHERE tenant_id IS NULL")) == 0
        assert connection.scalar(sa.text("SELECT COUNT(*) FROM controls WHERE is_global = 1")) == 0
        assert connection.scalar(sa.text("PRAGMA foreign_keys")) == 1
        assert connection.scalar(sa.text("SELECT COUNT(*) FROM control_conflicts")) == 1
        assert connection.scalar(sa.text("SELECT COUNT(*) FROM conflict_resolutions")) == 1

    command.downgrade(config, "0040_agentic_action_integrity")
    downgraded_inspector = inspect(engine)
    assert downgraded_inspector.get_pk_constraint("guardian_contract_v2")["constrained_columns"] == ["id"]
    assert downgraded_inspector.get_pk_constraint("controls")["constrained_columns"] == ["id"]
    _assert_conflict_resolution_fk_set_null(downgraded_inspector)
    command.upgrade(config, "0041_tenant_guardian_sim")
    upgraded_inspector = inspect(engine)
    assert upgraded_inspector.get_pk_constraint("guardian_contract_v2")["constrained_columns"] == ["tenant_id", "id"]
    _assert_conflict_resolution_fk_set_null(upgraded_inspector)
    with engine.connect() as connection:
        assert connection.scalar(sa.text("PRAGMA foreign_keys")) == 1
        assert connection.scalar(sa.text("SELECT COUNT(*) FROM control_conflicts")) == 1
        assert connection.scalar(sa.text("SELECT COUNT(*) FROM conflict_resolutions")) == 1
    engine.dispose()


def test_0041_revision_fits_alembic_version_column() -> None:
    migration = import_module(
        "app.db.migrations.versions.0041_tenant_scope_guardian_simulation_controls"
    )
    assert len(migration.revision) <= 32
    assert migration.SYSTEM_CONTROL_IDS == EXPECTED_SYSTEM_CONTROL_IDS


def test_0041_postgres_fk_operation_shape_is_direct_and_dependency_safe() -> None:
    migration = import_module(
        "app.db.migrations.versions.0041_tenant_scope_guardian_simulation_controls"
    )
    shape = migration._control_fk_operation_shape("postgresql")
    assert shape["mode"] == "direct"
    assert shape["drop"][0] == ("conflict_resolutions", "control_conflicts")
    assert shape["drop"].index(("conflict_resolutions", "controls")) < shape["drop"].index(
        ("control_conflicts", "controls")
    )
    assert shape["create"].index(("control_conflicts", "controls", "CASCADE")) < shape["create"].index(
        ("conflict_resolutions", "control_conflicts", "SET NULL")
    )


def test_0041_preserves_system_global_visibility_for_every_existing_tenant(tmp_path, monkeypatch) -> None:
    repo_api_root, migrations = _clean_migration_tree(tmp_path)
    database_path = tmp_path / "multi-tenant.sqlite3"
    engine = _sqlite_engine(database_path)
    _legacy_schema(engine, multi_tenant=True)
    database_url = f"sqlite+pysqlite:///{database_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    config = _config(repo_api_root=repo_api_root, clean_script_dir=migrations, database_path=database_path)
    command.stamp(config, "0040_agentic_action_integrity")
    command.upgrade(config, "0041_tenant_guardian_sim")

    with engine.connect() as connection:
        guardian_tenants = connection.execute(
            sa.text(
                "SELECT tenant_id FROM guardian_contract_v2 "
                "WHERE id='prompt_injection_guard' ORDER BY tenant_id"
            )
        ).scalars().all()
        global_counts = dict(
            connection.execute(
                sa.text(
                    "SELECT id, COUNT(*) AS tenant_count FROM controls "
                    "WHERE id != 'tenant-private' GROUP BY id ORDER BY id"
                )
            ).all()
        )
        private_tenants = connection.execute(
            sa.text("SELECT tenant_id FROM controls WHERE id='tenant-private' ORDER BY tenant_id")
        ).scalars().all()
    assert guardian_tenants == ["tenant-1", "tenant-2"]
    assert set(global_counts) == EXPECTED_SYSTEM_CONTROL_IDS
    assert set(global_counts.values()) == {2}
    assert private_tenants == ["tenant-1"]
    engine.dispose()


def test_0041_aborts_for_unowned_custom_guardian(tmp_path, monkeypatch) -> None:
    repo_api_root, migrations = _clean_migration_tree(tmp_path)
    database_path = tmp_path / "unsafe.sqlite3"
    engine = _sqlite_engine(database_path)
    _legacy_schema(engine, orphan_guardian=True)
    database_url = f"sqlite+pysqlite:///{database_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(settings, "database_url", database_url)
    config = _config(repo_api_root=repo_api_root, clean_script_dir=migrations, database_path=database_path)
    command.stamp(config, "0040_agentic_action_integrity")

    with pytest.raises(RuntimeError, match="has no trusted tenant mapping"):
        command.upgrade(config, "0041_tenant_guardian_sim")
    engine.dispose()
