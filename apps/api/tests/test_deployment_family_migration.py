from __future__ import annotations

from datetime import datetime, timezone
from importlib import import_module
from pathlib import Path
import re

from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.config import Config
from alembic.script import ScriptDirectory
import pytest
import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from app.services.deployment_family_contracts import (
    DeploymentFamily,
    TECHNICAL_SURFACE_FAMILY_MAP,
)


API_ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = (
    API_ROOT
    / "app/db/migrations/versions/0046_deployment_family_experience.py"
)

LEGACY_COLUMNS = {
    "id",
    "tenant_id",
    "source_kind",
    "source_id",
    "name",
    "surface_type",
    "deployment_mode",
    "environment",
    "status",
    "capability_profile",
    "capability_sources",
    "health_status",
    "health_reason",
    "first_seen_at",
    "last_seen_at",
    "last_heartbeat_at",
    "metadata_json",
    "created_at",
    "updated_at",
}

LEGACY_INDEXES = {
    "idx_deployment_surface_tenant_status": ["tenant_id", "status"],
    "idx_deployment_surface_tenant_type": ["tenant_id", "surface_type"],
    "idx_deployment_surface_tenant_seen": ["tenant_id", "last_seen_at"],
}

EXPECTED_CHECK_VALUES = {
    "ck_deployment_surface_family": {
        "browser",
        "endpoint",
        "runtime",
        "saas_api",
        "unknown",
    },
    "ck_deployment_surface_hosting_mode": {
        "saas",
        "hybrid",
        "private_cloud",
        "on_premises",
        "unknown",
    },
    "ck_deployment_surface_control_capability": {
        "inline",
        "warn_only",
        "monitor_only",
        "external_required",
        "unknown",
    },
    "ck_deployment_surface_evidence_capability": {
        "complete",
        "partial",
        "metadata_only",
        "none",
        "unknown",
    },
    "ck_deployment_surface_containment_capability": {
        "direct",
        "surface_limited",
        "external",
        "none",
        "unknown",
    },
    "ck_deployment_surface_bypass_capability": {
        "supported",
        "unsupported",
        "unknown",
    },
    "ck_deployment_surface_health_status": {
        "healthy",
        "warning",
        "degraded",
        "offline",
        "stale",
        "unknown",
    },
}

AMBIGUOUS_SURFACE_TYPES = (
    "unmapped_surface",
    "LLM_GATEWAY",
    " llm_gateway",
    "llm_gateway ",
    "my_llm_gateway",
    "llm-gateway",
)


def _sqlite_engine_with_foreign_keys(path: Path) -> sa.Engine:
    engine = sa.create_engine(f"sqlite+pysqlite:///{path}")
    sa.event.listen(
        engine,
        "connect",
        lambda dbapi_connection, _connection_record: dbapi_connection.execute(
            "PRAGMA foreign_keys=ON"
        ),
    )
    return engine


def _legacy_schema(engine: sa.Engine) -> tuple[sa.Table, sa.Table]:
    metadata = sa.MetaData()
    tenants = sa.Table(
        "tenants",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
    )
    surfaces = sa.Table(
        "deployment_surfaces",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("source_kind", sa.String(32), nullable=False),
        sa.Column("source_id", sa.String(128), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("surface_type", sa.String(64), nullable=False),
        sa.Column("deployment_mode", sa.String(64), nullable=False),
        sa.Column("environment", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("capability_profile", sa.JSON(), nullable=False),
        sa.Column("capability_sources", sa.JSON(), nullable=False),
        sa.Column("health_status", sa.String(32), nullable=False),
        sa.Column("health_reason", sa.String(128), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "health_status IN ('healthy','warning','degraded','offline','unknown')",
            name="ck_deployment_surface_health_status",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "source_kind",
            "source_id",
            name="uq_deployment_surface_tenant_source",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "id",
            name="uq_deployment_surface_tenant_id",
        ),
    )
    paths = sa.Table(
        "control_coverage_paths",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("path_key", sa.String(64), nullable=False),
        sa.Column("key_version", sa.String(16), nullable=False),
        sa.Column("asset_ref", sa.String(255), nullable=False),
        sa.Column("identity_type", sa.String(32), nullable=False),
        sa.Column("identity_ref", sa.String(255), nullable=False),
        sa.Column("runtime_ref", sa.String(255), nullable=False),
        sa.Column("deployment_surface_id", sa.String(36), nullable=True),
        sa.Column("deployment_surface_ref", sa.String(255), nullable=False),
        sa.Column("destination_type", sa.String(32), nullable=False),
        sa.Column("destination_ref", sa.String(255), nullable=False),
        sa.Column("lifecycle_status", sa.String(32), nullable=False),
        sa.Column("source_refs", sa.JSON(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "deployment_surface_id"],
            ["deployment_surfaces.tenant_id", "deployment_surfaces.id"],
            name="fk_control_coverage_path_tenant_surface",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "id",
            name="uq_control_coverage_path_tenant_id",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "path_key",
            name="uq_control_coverage_path_tenant_key",
        ),
    )
    sa.Index(
        "idx_deployment_surface_tenant_status",
        surfaces.c.tenant_id,
        surfaces.c.status,
    )
    sa.Index(
        "idx_deployment_surface_tenant_type",
        surfaces.c.tenant_id,
        surfaces.c.surface_type,
    )
    sa.Index(
        "idx_deployment_surface_tenant_seen",
        surfaces.c.tenant_id,
        surfaces.c.last_seen_at,
    )
    sa.Index(
        "idx_control_coverage_path_tenant_seen",
        paths.c.tenant_id,
        paths.c.last_seen_at,
    )
    sa.Index(
        "idx_control_coverage_path_tenant_asset",
        paths.c.tenant_id,
        paths.c.asset_ref,
    )
    sa.Index(
        "idx_control_coverage_path_tenant_identity",
        paths.c.tenant_id,
        paths.c.identity_ref,
    )
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(tenants.insert(), {"id": "tenant-a"})
    return surfaces, paths


def _seed_surfaces(engine: sa.Engine, surfaces: sa.Table) -> None:
    now = datetime.now(timezone.utc)
    rows = []
    for index, surface_type in enumerate(
        (*TECHNICAL_SURFACE_FAMILY_MAP.keys(), *AMBIGUOUS_SURFACE_TYPES)
    ):
        rows.append(
            {
                "id": f"surface-{index}",
                "tenant_id": "tenant-a",
                "source_kind": "test",
                "source_id": f"source-{index}",
                "name": surface_type,
                "surface_type": surface_type,
                "deployment_mode": "monitor_only",
                "environment": "test",
                "status": "active",
                "capability_profile": {"containment": "end_to_end"},
                "capability_sources": [f"source:{index}"],
                "health_status": "healthy",
                "health_reason": "test",
                "first_seen_at": now,
                "last_seen_at": now,
                "last_heartbeat_at": now,
                "metadata_json": {"provider": "must-not-be-backfilled"},
                "created_at": now,
                "updated_at": now,
            }
        )
    with engine.begin() as connection:
        connection.execute(surfaces.insert(), rows)


def _seed_path(engine: sa.Engine, paths: sa.Table) -> None:
    now = datetime.now(timezone.utc)
    with engine.begin() as connection:
        connection.execute(
            paths.insert(),
            {
                "id": "path-1",
                "tenant_id": "tenant-a",
                "path_key": "path-key-1",
                "key_version": "1.0",
                "asset_ref": "asset:1",
                "identity_type": "user",
                "identity_ref": "user:1",
                "runtime_ref": "runtime:1",
                "deployment_surface_id": "surface-0",
                "deployment_surface_ref": "test:source-0",
                "destination_type": "tool",
                "destination_ref": "tool:1",
                "lifecycle_status": "active",
                "source_refs": ["test:path-1"],
                "first_seen_at": now,
                "last_seen_at": now,
                "created_at": now,
                "updated_at": now,
            },
        )


def _invoke(
    engine: sa.Engine,
    migration: object,
    operation_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with engine.connect() as connection:
        context = MigrationContext.configure(connection)
        monkeypatch.setattr(migration, "op", Operations(context))
        with context.begin_transaction(_per_migration=True):
            getattr(migration, operation_name)()


def _assert_sqlite_referential_integrity(
    engine: sa.Engine,
    *,
    expected_surface_count: int,
) -> None:
    with engine.connect() as connection:
        assert connection.exec_driver_sql(
            "PRAGMA foreign_keys"
        ).scalar_one() == 1
        assert connection.exec_driver_sql(
            "PRAGMA defer_foreign_keys"
        ).scalar_one() == 0
        assert connection.exec_driver_sql(
            "PRAGMA foreign_key_check"
        ).all() == []
        surface_foreign_key = [
            (row[3], row[4], row[6])
            for row in connection.exec_driver_sql(
                "PRAGMA foreign_key_list('control_coverage_paths')"
            ).all()
            if row[2] == "deployment_surfaces"
        ]
        assert surface_foreign_key == [
            ("tenant_id", "tenant_id", "RESTRICT"),
            ("deployment_surface_id", "id", "RESTRICT"),
        ]
        assert connection.exec_driver_sql(
            "SELECT COUNT(*) FROM deployment_surfaces"
        ).scalar_one() == expected_surface_count
        assert connection.exec_driver_sql(
            "SELECT COUNT(*) FROM control_coverage_paths"
        ).scalar_one() == 1
        linked_surface = connection.exec_driver_sql(
            "SELECT deployment_surface_id "
            "FROM control_coverage_paths WHERE id='path-1'"
        ).scalar_one()
    assert linked_surface == "surface-0"


def _indexes(engine: sa.Engine) -> dict[str, list[str]]:
    return {
        index["name"]: index["column_names"]
        for index in inspect(engine).get_indexes("deployment_surfaces")
    }


def _checks(engine: sa.Engine) -> dict[str, set[str]]:
    return {
        constraint["name"]: set(
            re.findall(r"'([^']+)'", str(constraint["sqltext"]))
        )
        for constraint in inspect(engine).get_check_constraints(
            "deployment_surfaces"
        )
    }


def _assert_invalid_update_rejected(
    engine: sa.Engine,
    *,
    column_name: str,
) -> None:
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    f"UPDATE deployment_surfaces "
                    f"SET {column_name}='forged_value'"
                )
            )


def test_0046_source_is_linear_additive_and_matches_the_closed_d1_mapping() -> None:
    migration = import_module(
        "app.db.migrations.versions.0046_deployment_family_experience"
    )
    source = MIGRATION_PATH.read_text(encoding="utf-8")

    assert MIGRATION_PATH.name == "0046_deployment_family_experience.py"
    assert migration.revision == "0046_deployment_family_exp"
    assert migration.down_revision == "0045_control_coverage"
    assert migration.SURFACE_FAMILY_BACKFILL == dict(
        TECHNICAL_SURFACE_FAMILY_MAP
    )
    assert set(migration.SURFACE_FAMILY_BACKFILL) == set(
        TECHNICAL_SURFACE_FAMILY_MAP
    )
    assert "surface_type" not in {
        field for field in migration.NORMALIZED_COLUMNS
    }
    assert "deployment_mode" not in {
        field for field in migration.NORMALIZED_COLUMNS
    }
    assert 'op.drop_table("deployment_surfaces")' not in source


def test_0046_upgrade_downgrade_upgrade_is_sqlite_safe_and_conservative(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = import_module(
        "app.db.migrations.versions.0046_deployment_family_experience"
    )
    engine = _sqlite_engine_with_foreign_keys(
        tmp_path / "deployment-family.sqlite3"
    )
    surfaces, paths = _legacy_schema(engine)
    _seed_surfaces(engine, surfaces)
    _seed_path(engine, paths)
    seeded_surface_count = (
        len(TECHNICAL_SURFACE_FAMILY_MAP) + len(AMBIGUOUS_SURFACE_TYPES)
    )
    _assert_sqlite_referential_integrity(
        engine,
        expected_surface_count=seeded_surface_count,
    )

    _invoke(engine, migration, "upgrade", monkeypatch)
    _assert_sqlite_referential_integrity(
        engine,
        expected_surface_count=seeded_surface_count,
    )
    inspector = inspect(engine)
    column_names = {
        column["name"] for column in inspector.get_columns("deployment_surfaces")
    }
    assert LEGACY_COLUMNS <= column_names
    assert set(migration.NORMALIZED_COLUMNS) <= column_names
    indexes = _indexes(engine)
    assert LEGACY_INDEXES.items() <= indexes.items()
    assert indexes["idx_deployment_surface_tenant_family"] == [
        "tenant_id",
        "deployment_family",
    ]
    assert indexes["idx_deployment_surface_tenant_health"] == [
        "tenant_id",
        "health_status",
    ]
    checks = _checks(engine)
    assert {
        name: checks[name]
        for name in EXPECTED_CHECK_VALUES
    } == EXPECTED_CHECK_VALUES

    now = datetime.now(timezone.utc)
    with engine.begin() as connection:
        connection.execute(
            surfaces.insert(),
            {
                "id": "surface-legacy-writer",
                "tenant_id": "tenant-a",
                "source_kind": "legacy_writer",
                "source_id": "legacy-writer",
                "name": "Legacy writer",
                "surface_type": "llm_gateway",
                "deployment_mode": "monitor_only",
                "environment": "test",
                "status": "active",
                "capability_profile": {},
                "capability_sources": [],
                "health_status": "healthy",
                "health_reason": "test",
                "first_seen_at": now,
                "last_seen_at": now,
                "last_heartbeat_at": None,
                "metadata_json": {},
                "created_at": now,
                "updated_at": now,
            },
        )

    with engine.connect() as connection:
        actual_families = dict(
            connection.execute(
                sa.text(
                    "SELECT surface_type, deployment_family "
                    "FROM deployment_surfaces "
                    "WHERE id != 'surface-legacy-writer'"
                )
            ).all()
        )
        source_row = connection.execute(
            sa.text(
                "SELECT deployment_mode, capability_profile, capability_sources, "
                "hosting_mode, provider, containment_capability "
                "FROM deployment_surfaces "
                "WHERE surface_type='llm_gateway' AND source_kind='test'"
            )
        ).one()
        legacy_writer = connection.execute(
            sa.text(
                "SELECT deployment_family, hosting_mode, "
                "control_capability, evidence_capability, "
                "containment_capability, bypass_detection_capability "
                "FROM deployment_surfaces "
                "WHERE id='surface-legacy-writer'"
            )
        ).one()
    assert actual_families == {
        **{
            surface: family.value
            for surface, family in TECHNICAL_SURFACE_FAMILY_MAP.items()
        },
        **{
            surface: DeploymentFamily.UNKNOWN.value
            for surface in AMBIGUOUS_SURFACE_TYPES
        },
    }
    assert source_row[0] == "monitor_only"
    assert "end_to_end" in source_row[1]
    assert "source:" in source_row[2]
    assert source_row[3:] == ("unknown", None, "unknown")
    assert legacy_writer == (
        "unknown",
        "unknown",
        "unknown",
        "unknown",
        "unknown",
        "unknown",
    )
    _assert_sqlite_referential_integrity(
        engine,
        expected_surface_count=seeded_surface_count + 1,
    )

    for column_name in (
        "deployment_family",
        "hosting_mode",
        "control_capability",
        "evidence_capability",
        "containment_capability",
        "bypass_detection_capability",
        "health_status",
    ):
        _assert_invalid_update_rejected(
            engine,
            column_name=column_name,
        )

    with engine.begin() as connection:
        connection.execute(
            sa.text(
                "UPDATE deployment_surfaces SET health_status='stale' "
                "WHERE surface_type='llm_gateway'"
            )
        )

    _invoke(engine, migration, "downgrade", monkeypatch)
    _assert_sqlite_referential_integrity(
        engine,
        expected_surface_count=seeded_surface_count + 1,
    )
    downgraded_columns = {
        column["name"]
        for column in inspect(engine).get_columns("deployment_surfaces")
    }
    assert LEGACY_COLUMNS == downgraded_columns
    assert not (set(migration.NORMALIZED_COLUMNS) & downgraded_columns)
    assert LEGACY_INDEXES.items() <= _indexes(engine).items()
    assert _checks(engine)["ck_deployment_surface_health_status"] == {
        "healthy",
        "warning",
        "degraded",
        "offline",
        "unknown",
    }
    with engine.connect() as connection:
        restored = connection.execute(
            sa.text(
                "SELECT surface_type, deployment_mode, health_status "
                "FROM deployment_surfaces "
                "WHERE surface_type='llm_gateway' AND source_kind='test'"
            )
        ).one()
    assert restored == ("llm_gateway", "monitor_only", "unknown")

    _invoke(engine, migration, "upgrade", monkeypatch)
    _assert_sqlite_referential_integrity(
        engine,
        expected_surface_count=seeded_surface_count + 1,
    )
    assert set(migration.NORMALIZED_COLUMNS) <= {
        column["name"]
        for column in inspect(engine).get_columns("deployment_surfaces")
    }
    assert LEGACY_INDEXES.items() <= _indexes(engine).items()
    assert {
        name: _checks(engine)[name]
        for name in EXPECTED_CHECK_VALUES
    } == EXPECTED_CHECK_VALUES
    engine.dispose()


def test_0046_downgrade_is_safe_with_populated_v1_foreign_keys_enforced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = import_module(
        "app.db.migrations.versions.0046_deployment_family_experience"
    )
    engine = _sqlite_engine_with_foreign_keys(
        tmp_path / "deployment-family-downgrade.sqlite3"
    )
    surfaces, paths = _legacy_schema(engine)
    _seed_surfaces(engine, surfaces)
    _seed_path(engine, paths)
    seeded_surface_count = (
        len(TECHNICAL_SURFACE_FAMILY_MAP) + len(AMBIGUOUS_SURFACE_TYPES)
    )
    _invoke(
        engine,
        migration,
        "upgrade",
        monkeypatch,
    )
    _assert_sqlite_referential_integrity(
        engine,
        expected_surface_count=seeded_surface_count,
    )

    _invoke(engine, migration, "downgrade", monkeypatch)
    _assert_sqlite_referential_integrity(
        engine,
        expected_surface_count=seeded_surface_count,
    )
    engine.dispose()


def test_current_revision_is_the_sole_short_migration_head() -> None:
    config = Config(
        str(
            API_ROOT / "app/db/migrations/alembic.ini"
        )
    )
    config.set_main_option(
        "script_location",
        str(API_ROOT / "app/db/migrations"),
    )
    scripts = ScriptDirectory.from_config(config)
    heads = scripts.get_heads()

    assert heads == ["0099_iam_roles"]
    assert [revision.revision for revision in scripts.iterate_revisions(heads[0], "0089_provider_signal_lifecycle")] == [
        "0099_iam_roles",
        "0097_audit_chain",
        "0096_signin_hardening",
        "0094_first_run_and_terms",
        "0093_activation_state",
        "0092_github_repository_runtime_controls",
        "0091_exec_mcp_device_auth",
        "0090_github_repo_access",
    ]
    assert all(len(head) <= 128 for head in heads)
