"""Contract tests for the additive HMAIR discovery persistence migration."""

from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from importlib import import_module
from io import StringIO
from itertools import product
from pathlib import Path
import re
from typing import Any, Iterator

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory
import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError


API_ROOT = Path(__file__).resolve().parents[1]
MIGRATION_MODULE = (
    "app.db.migrations.versions.0047_discovery_scan_observations"
)
HMAIR_TABLES = {
    "discovery_scans",
    "discovery_targets",
    "discovery_collectors",
    "discovery_scan_targets",
    "discovery_scan_assignments",
    "discovery_observations",
}

EXPECTED_COLUMNS = {
    "discovery_scans": {
        "scan_id": (36, False),
        "tenant_id": (36, False),
        "name": (255, False),
        "requested_by": (36, True),
        "scan_type": (32, False),
        "scope_json": (None, False),
        "safety_profile": (64, False),
        "request_idempotency_key": (128, False),
        "request_digest": (64, False),
        "status": (32, False),
        "dry_run": (None, False),
        "started_at": (None, True),
        "completed_at": (None, True),
        "cancelled_at": (None, True),
        "observations_count": (None, False),
        "assets_created": (None, False),
        "assets_updated": (None, False),
        "assets_unresolved": (None, False),
        "warnings_json": (None, False),
        "errors_json": (None, False),
        "coverage_summary_json": (None, False),
        "evidence_bundle_id": (36, True),
        "rescan_of_scan_id": (36, True),
        "created_at": (None, False),
        "updated_at": (None, False),
    },
    "discovery_targets": {
        "target_id": (128, False),
        "tenant_id": (36, False),
        "target_type": (32, False),
        "identifier": (512, False),
        "environment": (64, False),
        "owner_hint": (255, True),
        "credentials_reference": (255, True),
        "permitted_methods_json": (None, False),
        "exclusions_json": (None, False),
        "rate_limit": (None, False),
        "active_scan_allowed": (None, False),
        "sensitive_scope": (None, False),
        "last_scanned_at": (None, True),
        "created_at": (None, False),
        "updated_at": (None, False),
    },
    "discovery_collectors": {
        "collector_id": (128, False),
        "tenant_id": (36, False),
        "collector_type": (64, False),
        "version": (64, False),
        "supported_targets_json": (None, False),
        "active_capabilities_json": (None, False),
        "passive_capabilities_json": (None, False),
        "permissions_required_json": (None, False),
        "sensitive_data_accessed_json": (None, False),
        "health": (32, False),
        "last_success_at": (None, True),
        "last_failure_at": (None, True),
        "data_residency": (128, False),
        "control_capability": (32, False),
        "schema_version": (32, False),
        "limitations_json": (None, False),
        "declaration_hash": (64, False),
        "created_at": (None, False),
        "updated_at": (None, False),
    },
    "discovery_scan_targets": {
        "tenant_id": (36, False),
        "scan_id": (36, False),
        "target_id": (128, False),
        "created_at": (None, False),
        "updated_at": (None, False),
    },
    "discovery_scan_assignments": {
        "assignment_id": (36, False),
        "tenant_id": (36, False),
        "scan_id": (36, False),
        "target_id": (128, False),
        "collector_id": (128, False),
        "status": (32, False),
        "warning": (500, True),
        "error": (500, True),
        "started_at": (None, True),
        "completed_at": (None, True),
        "observations_count": (None, False),
        "created_at": (None, False),
        "updated_at": (None, False),
    },
}

EXPECTED_COLUMNS["discovery_observations"] = {
    "observation_id": (128, False),
    "tenant_id": (36, False),
    "assignment_id": (36, False),
    "scan_id": (36, False),
    "collector_id": (128, False),
    "collector_type": (64, False),
    "collector_version": (64, False),
    "target_id": (128, False),
    "observed_at": (None, False),
    "observation_type": (128, False),
    "candidate_asset_type": (64, False),
    "identifiers_json": (None, False),
    "attributes_json": (None, False),
    "configuration_summary_json": (None, False),
    "usage_summary_json": (None, False),
    "capability_hints_json": (None, False),
    "identity_hints_json": (None, False),
    "relationship_hints_json": (None, False),
    "evidence_reference": (255, False),
    "evidence_hash": (64, False),
    "signature_status": (32, False),
    "confidence": (None, False),
    "freshness": (32, False),
    "sensitivity": (32, False),
    "redaction_status": (32, False),
    "idempotency_key": (64, False),
    "payload_digest": (64, False),
    "created_at": (None, False),
    "updated_at": (None, False),
}

EXPECTED_INDEXES = {
    "discovery_scans": {
        ("tenant_id", "status"),
        ("tenant_id", "created_at"),
        ("tenant_id", "rescan_of_scan_id"),
    },
    "discovery_targets": {
        ("tenant_id", "target_type"),
        ("tenant_id", "last_scanned_at"),
    },
    "discovery_collectors": {
        ("tenant_id", "collector_type"),
        ("tenant_id", "health"),
    },
    "discovery_scan_targets": {("tenant_id", "target_id")},
    "discovery_scan_assignments": {
        ("tenant_id", "scan_id", "status"),
        ("tenant_id", "collector_id", "status"),
    },
    "discovery_observations": {
        ("tenant_id", "scan_id", "observed_at"),
        ("tenant_id", "collector_id", "observed_at"),
        ("tenant_id", "observation_type", "observed_at"),
        ("tenant_id", "freshness", "observed_at"),
        ("tenant_id", "assignment_id"),
    },
}

SCAN_TYPES = {
    "full_enterprise",
    "targeted",
    "incremental",
    "verification",
    "scheduled",
    "collector_specific",
}
SCAN_STATUSES = {
    "queued",
    "running",
    "partially_complete",
    "complete",
    "failed",
    "cancelled",
}
TARGET_TYPES = {
    "endpoint_group",
    "browser_tenant",
    "cloud_subscription",
    "cloud_project",
    "kubernetes_cluster",
    "saas_tenant",
    "identity_tenant",
    "repository_org",
    "repository",
    "network_range",
    "dns_domain",
    "api_gateway",
    "database_platform",
    "ai_provider_account",
    "mcp_environment",
    "llm_gateway",
    "runtime_environment",
}
COLLECTOR_HEALTH = {"healthy", "warning", "degraded", "offline", "unknown"}
CONTROL_CAPABILITIES = {
    "inline",
    "warn_only",
    "monitor_only",
    "external_required",
    "unknown",
}
ASSIGNMENT_STATUSES = {
    "pending",
    "running",
    "complete",
    "failed",
    "cancelled",
    "unsupported",
    "permission_denied",
    "rate_limited",
    "stale",
    "empty",
}
FRESHNESS_VALUES = {"fresh", "stale", "expired", "unknown"}
HASH_A = "a" * 64
HASH_B = "b" * 64
FULL_ALPHABET_HASH = "0123456789abcdef" * 4
NOW = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)

DATETIME_COLUMNS = {
    "discovery_scans": {
        "started_at",
        "completed_at",
        "cancelled_at",
        "created_at",
        "updated_at",
    },
    "discovery_targets": {"last_scanned_at", "created_at", "updated_at"},
    "discovery_collectors": {
        "last_success_at",
        "last_failure_at",
        "created_at",
        "updated_at",
    },
    "discovery_scan_targets": {"created_at", "updated_at"},
    "discovery_scan_assignments": {
        "started_at",
        "completed_at",
        "created_at",
        "updated_at",
    },
    "discovery_observations": {"observed_at", "created_at", "updated_at"},
}

SCAN_LIFECYCLE_VALID = {
    ("queued", False, False, False),
    ("running", True, False, False),
    ("complete", True, True, False),
    ("partially_complete", True, True, False),
    ("failed", False, True, False),
    ("failed", True, True, False),
    ("cancelled", False, False, True),
    ("cancelled", True, False, True),
}
SCAN_LIFECYCLE_CASES = sorted(
    (
        (status, started, completed, cancelled)
        for status in SCAN_STATUSES
        for started, completed, cancelled in product((False, True), repeat=3)
    ),
    key=str,
)

TERMINAL_ASSIGNMENT_STATUSES = ASSIGNMENT_STATUSES - {"pending", "running"}
ASSIGNMENT_LIFECYCLE_VALID = {
    ("pending", False, False),
    ("running", True, False),
    *{
        (status, started, True)
        for status in TERMINAL_ASSIGNMENT_STATUSES
        for started in (False, True)
    },
}
ASSIGNMENT_LIFECYCLE_CASES = sorted(
    (
        (status, started, completed)
        for status in ASSIGNMENT_STATUSES
        for started, completed in product((False, True), repeat=2)
    ),
    key=str,
)


def _migration() -> Any:
    return import_module(MIGRATION_MODULE)


def _sqlite_engine(path: Path) -> sa.Engine:
    engine = sa.create_engine(f"sqlite+pysqlite:///{path}")

    @sa.event.listens_for(engine, "connect")
    def _enable_foreign_keys(connection: Any, _record: Any) -> None:
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


def _create_parent_schema(engine: sa.Engine) -> None:
    metadata = sa.MetaData()
    sa.Table("tenants", metadata, sa.Column("id", sa.String(36), primary_key=True))
    sa.Table(
        "users",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
    )
    sa.Table(
        "evidence_nodes",
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.UniqueConstraint(
            "tenant_id", "id", name="uq_evidence_nodes_tenant_id"
        ),
    )
    sa.Table(
        "preexisting_sentinel",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
    )
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(
            sa.text("INSERT INTO tenants (id) VALUES ('tenant-a'), ('tenant-b')")
        )
        connection.execute(
            sa.text(
                "INSERT INTO users (id, tenant_id) VALUES "
                "('user-a', 'tenant-a'), ('user-b', 'tenant-b')"
            )
        )
        connection.execute(
            sa.text(
                "INSERT INTO evidence_nodes (id, tenant_id) VALUES "
                "('evidence-a', 'tenant-a'), ('evidence-b', 'tenant-b')"
            )
        )
        connection.execute(sa.text("INSERT INTO preexisting_sentinel (id) VALUES (1)"))


def _invoke(
    engine: sa.Engine,
    migration: Any,
    operation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with engine.connect() as connection:
        context = MigrationContext.configure(connection)
        monkeypatch.setattr(migration, "op", Operations(context))
        with context.begin_transaction(_per_migration=True):
            getattr(migration, operation)()


@pytest.fixture
def migrated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[sa.Engine, Any]]:
    engine = _sqlite_engine(tmp_path / "hmair-discovery.sqlite3")
    _create_parent_schema(engine)
    migration = _migration()
    _invoke(engine, migration, "upgrade", monkeypatch)
    try:
        yield engine, migration
    finally:
        engine.dispose()


def _columns(engine: sa.Engine, table_name: str) -> dict[str, dict[str, Any]]:
    return {
        column["name"]: column
        for column in sa.inspect(engine).get_columns(table_name)
    }


def _foreign_keys(engine: sa.Engine, table_name: str) -> set[tuple[Any, ...]]:
    return {
        (
            tuple(foreign_key["constrained_columns"]),
            foreign_key["referred_table"],
            tuple(foreign_key["referred_columns"]),
            (foreign_key.get("options") or {}).get("ondelete"),
        )
        for foreign_key in sa.inspect(engine).get_foreign_keys(table_name)
    }


def _unique_columns(engine: sa.Engine, table_name: str) -> set[tuple[str, ...]]:
    return {
        tuple(constraint["column_names"])
        for constraint in sa.inspect(engine).get_unique_constraints(table_name)
    }


def _hmair_schema_signature(engine: sa.Engine) -> dict[str, Any]:
    inspector = sa.inspect(engine)
    signature: dict[str, Any] = {}
    for table_name in sorted(HMAIR_TABLES):
        columns = tuple(
            (
                column["name"],
                str(column["type"]),
                column["nullable"],
                str(column.get("default")),
                column.get("primary_key", 0),
            )
            for column in inspector.get_columns(table_name)
        )
        uniques = tuple(
            sorted(
                [
                    (
                        constraint.get("name"),
                        tuple(constraint["column_names"]),
                    )
                    for constraint in inspector.get_unique_constraints(table_name)
                ],
                key=repr,
            )
        )
        foreign_keys = tuple(
            sorted(
                [
                    (
                        foreign_key.get("name"),
                        tuple(foreign_key["constrained_columns"]),
                        foreign_key["referred_table"],
                        tuple(foreign_key["referred_columns"]),
                        tuple(sorted((foreign_key.get("options") or {}).items())),
                    )
                    for foreign_key in inspector.get_foreign_keys(table_name)
                ],
                key=repr,
            )
        )
        indexes = tuple(
            sorted(
                [
                    (
                        index["name"],
                        tuple(index["column_names"]),
                        bool(index.get("unique")),
                    )
                    for index in inspector.get_indexes(table_name)
                ],
                key=repr,
            )
        )
        checks = tuple(
            sorted(
                [
                    (
                        check.get("name"),
                        " ".join(str(check["sqltext"]).split()).lower(),
                    )
                    for check in inspector.get_check_constraints(table_name)
                ],
                key=repr,
            )
        )
        signature[table_name] = {
            "columns": columns,
            "primary_key": tuple(
                inspector.get_pk_constraint(table_name)["constrained_columns"]
            ),
            "uniques": uniques,
            "foreign_keys": foreign_keys,
            "indexes": indexes,
            "checks": checks,
        }
    with engine.connect() as connection:
        signature["__triggers__"] = tuple(
            connection.exec_driver_sql(
                "SELECT name, sql FROM sqlite_master "
                "WHERE type='trigger' AND name LIKE "
                "'trg_discovery_observations_immutable_%' ORDER BY name"
            ).all()
        )
    return signature


def _is_now_default(value: Any) -> bool:
    normalized = re.sub(r"[\s()]", "", str(value).lower())
    return normalized in {"current_timestamp", "now"}


def test_now_default_normalization_rejects_quoted_literals() -> None:
    assert _is_now_default("CURRENT_TIMESTAMP")
    assert _is_now_default("now()")
    assert not _is_now_default("'now'")
    assert not _is_now_default("'current_timestamp'")


@contextmanager
def _rejects_integrity() -> Iterator[None]:
    with pytest.raises(IntegrityError):
        yield


def _insert(engine: sa.Engine, table_name: str, values: dict[str, Any]) -> None:
    table = sa.Table(table_name, sa.MetaData(), autoload_with=engine)
    with engine.begin() as connection:
        connection.execute(table.insert(), values)


def _insert_scan(
    engine: sa.Engine,
    *,
    scan_id: str,
    tenant_id: str,
    request_key: str | None = None,
    **overrides: Any,
) -> None:
    values: dict[str, Any] = {
        "scan_id": scan_id,
        "tenant_id": tenant_id,
        "name": f"Scan {scan_id}",
        "requested_by": None,
        "scan_type": "targeted",
        "scope_json": {"target": scan_id},
        "safety_profile": "metadata-only",
        "request_idempotency_key": request_key or f"request-{scan_id}",
        "request_digest": HASH_A,
    }
    values.update(overrides)
    _insert(engine, "discovery_scans", values)


def _insert_target(
    engine: sa.Engine, *, target_id: str, tenant_id: str, **overrides: Any
) -> None:
    values: dict[str, Any] = {
        "target_id": target_id,
        "tenant_id": tenant_id,
        "target_type": "runtime_environment",
        "identifier": f"runtime://{target_id}",
        "environment": "test",
        "permitted_methods_json": ["metadata_api"],
        "rate_limit": 100,
    }
    values.update(overrides)
    _insert(engine, "discovery_targets", values)


def _insert_collector(
    engine: sa.Engine,
    *,
    collector_id: str,
    tenant_id: str,
    **overrides: Any,
) -> None:
    values: dict[str, Any] = {
        "collector_id": collector_id,
        "tenant_id": tenant_id,
        "collector_type": "runtime_metadata",
        "version": "1.0.0",
        "supported_targets_json": ["runtime_environment"],
        "active_capabilities_json": [],
        "passive_capabilities_json": ["metadata"],
        "permissions_required_json": ["read_metadata"],
        "sensitive_data_accessed_json": [],
        "health": "healthy",
        "data_residency": "customer-region",
        "control_capability": "monitor_only",
        "schema_version": "1.0",
        "limitations_json": [],
        "declaration_hash": HASH_A,
    }
    values.update(overrides)
    _insert(engine, "discovery_collectors", values)


def _insert_scan_target(
    engine: sa.Engine, *, tenant_id: str, scan_id: str, target_id: str
) -> None:
    _insert(
        engine,
        "discovery_scan_targets",
        {"tenant_id": tenant_id, "scan_id": scan_id, "target_id": target_id},
    )


def _insert_assignment(
    engine: sa.Engine,
    *,
    assignment_id: str,
    tenant_id: str,
    scan_id: str,
    target_id: str,
    collector_id: str,
    **overrides: Any,
) -> None:
    values: dict[str, Any] = {
        "assignment_id": assignment_id,
        "tenant_id": tenant_id,
        "scan_id": scan_id,
        "target_id": target_id,
        "collector_id": collector_id,
    }
    values.update(overrides)
    _insert(engine, "discovery_scan_assignments", values)


def _insert_observation(
    engine: sa.Engine,
    *,
    observation_id: str,
    tenant_id: str,
    assignment_id: str,
    scan_id: str,
    target_id: str,
    collector_id: str,
    idempotency_key: str = HASH_A,
    **overrides: Any,
) -> None:
    values: dict[str, Any] = {
        "observation_id": observation_id,
        "tenant_id": tenant_id,
        "assignment_id": assignment_id,
        "scan_id": scan_id,
        "collector_id": collector_id,
        "collector_type": "runtime_metadata",
        "collector_version": "1.0.0",
        "target_id": target_id,
        "observed_at": NOW,
        "observation_type": "runtime.metadata",
        "candidate_asset_type": "ai_runtime",
        "identifiers_json": {"resource_hash": HASH_A},
        "attributes_json": {},
        "configuration_summary_json": {},
        "usage_summary_json": {},
        "capability_hints_json": [],
        "identity_hints_json": [],
        "relationship_hints_json": [],
        "evidence_reference": "evidence://observation",
        "evidence_hash": HASH_A,
        "signature_status": "vendor_extension_value",
        "confidence": 0.75,
        "freshness": "fresh",
        "sensitivity": "vendor_extension_value",
        "redaction_status": "vendor_extension_value",
        "idempotency_key": idempotency_key,
        "payload_digest": HASH_B,
    }
    values.update(overrides)
    _insert(engine, "discovery_observations", values)


def _seed_graph(
    engine: sa.Engine,
    *,
    tenant_id: str = "tenant-a",
    suffix: str = "a",
    with_observation: bool = True,
) -> dict[str, str]:
    ids = {
        "scan_id": f"scan-{suffix}",
        "target_id": f"target-{suffix}",
        "collector_id": f"collector-{suffix}",
        "assignment_id": f"assignment-{suffix}",
        "observation_id": f"observation-{suffix}",
    }
    _insert_scan(engine, scan_id=ids["scan_id"], tenant_id=tenant_id)
    _insert_target(engine, target_id=ids["target_id"], tenant_id=tenant_id)
    _insert_collector(
        engine, collector_id=ids["collector_id"], tenant_id=tenant_id
    )
    _insert_scan_target(
        engine,
        tenant_id=tenant_id,
        scan_id=ids["scan_id"],
        target_id=ids["target_id"],
    )
    _insert_assignment(
        engine,
        assignment_id=ids["assignment_id"],
        tenant_id=tenant_id,
        scan_id=ids["scan_id"],
        target_id=ids["target_id"],
        collector_id=ids["collector_id"],
    )
    if with_observation:
        _insert_observation(
            engine,
            observation_id=ids["observation_id"],
            tenant_id=tenant_id,
            assignment_id=ids["assignment_id"],
            scan_id=ids["scan_id"],
            target_id=ids["target_id"],
            collector_id=ids["collector_id"],
        )
    return ids


def _extract_literals(sql: str) -> set[str]:
    return set(re.findall(r"'([^']+)'", sql))


def _trigger_names(engine: sa.Engine) -> set[str]:
    with engine.connect() as connection:
        return {
            row[0]
            for row in connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            ).all()
        }


def test_revision_extends_deployment_family_head() -> None:
    migration = _migration()
    assert migration.revision == "0047_discovery_scan_obs"
    assert migration.down_revision == "0046_deployment_family_exp"
    assert migration.branch_labels is None
    assert migration.depends_on is None
    assert len(migration.revision) <= 32


def test_upgrade_creates_only_the_six_exact_hmair_tables(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    names = set(sa.inspect(engine).get_table_names())
    assert HMAIR_TABLES <= names
    assert names == HMAIR_TABLES | {
        "tenants",
        "users",
        "evidence_nodes",
        "preexisting_sentinel",
    }


def test_columns_lengths_nullability_and_primary_keys_are_exact(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    expected_primary_keys = {
        "discovery_scans": ["scan_id"],
        "discovery_targets": ["target_id"],
        "discovery_collectors": ["collector_id"],
        "discovery_scan_targets": ["tenant_id", "scan_id", "target_id"],
        "discovery_scan_assignments": ["assignment_id"],
        "discovery_observations": ["observation_id"],
    }
    for table_name, expected in EXPECTED_COLUMNS.items():
        actual = _columns(engine, table_name)
        assert set(actual) == set(expected)
        for name, (length, nullable) in expected.items():
            assert actual[name]["nullable"] is nullable, (table_name, name)
            if length is not None:
                assert actual[name]["type"].length == length, (table_name, name)
        assert (
            sa.inspect(engine).get_pk_constraint(table_name)["constrained_columns"]
            == expected_primary_keys[table_name]
        )


def test_json_numeric_boolean_and_datetime_types_are_not_widened(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    json_columns = {
        table_name: {
            name for name in columns if name.endswith("_json")
        }
        for table_name, columns in EXPECTED_COLUMNS.items()
    }
    for table_name, names in json_columns.items():
        actual = _columns(engine, table_name)
        for name in names:
            assert isinstance(actual[name]["type"], sa.JSON), (table_name, name)
    assert isinstance(_columns(engine, "discovery_targets")["rate_limit"]["type"], sa.Integer)
    for name in ("active_scan_allowed", "sensitive_scope"):
        assert isinstance(_columns(engine, "discovery_targets")[name]["type"], sa.Boolean)
    assert isinstance(_columns(engine, "discovery_scans")["dry_run"]["type"], sa.Boolean)
    for table_name, names in {
        "discovery_scans": {
            "observations_count", "assets_created", "assets_updated", "assets_unresolved"
        },
        "discovery_scan_assignments": {"observations_count"},
    }.items():
        for name in names:
            assert isinstance(_columns(engine, table_name)[name]["type"], sa.BigInteger)
    assert isinstance(
        _columns(engine, "discovery_observations")["confidence"]["type"],
        sa.Float,
    )


def test_all_21_datetime_columns_are_exact_by_table(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    assert sum(len(names) for names in DATETIME_COLUMNS.values()) == 21
    for table_name, expected_names in DATETIME_COLUMNS.items():
        actual = _columns(engine, table_name)
        actual_names = {
            name
            for name, column in actual.items()
            if isinstance(column["type"], sa.DateTime)
        }
        assert actual_names == expected_names


def test_server_defaults_materialize_exact_conservative_shapes(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    _insert_scan(engine, scan_id="scan-default", tenant_id="tenant-a")
    _insert_target(engine, target_id="target-default", tenant_id="tenant-a")
    _insert_collector(
        engine, collector_id="collector-default", tenant_id="tenant-a"
    )
    _insert_scan_target(
        engine,
        tenant_id="tenant-a",
        scan_id="scan-default",
        target_id="target-default",
    )
    _insert_assignment(
        engine,
        assignment_id="assignment-default",
        tenant_id="tenant-a",
        scan_id="scan-default",
        target_id="target-default",
        collector_id="collector-default",
    )
    scan = sa.Table("discovery_scans", sa.MetaData(), autoload_with=engine)
    target = sa.Table("discovery_targets", sa.MetaData(), autoload_with=engine)
    assignment = sa.Table(
        "discovery_scan_assignments", sa.MetaData(), autoload_with=engine
    )
    with engine.connect() as connection:
        scan_row = connection.execute(sa.select(scan)).mappings().one()
        target_row = connection.execute(sa.select(target)).mappings().one()
        assignment_row = connection.execute(sa.select(assignment)).mappings().one()
    assert scan_row["status"] == "queued"
    assert scan_row["dry_run"] is False
    assert [scan_row[name] for name in (
        "observations_count", "assets_created", "assets_updated", "assets_unresolved"
    )] == [0, 0, 0, 0]
    assert scan_row["warnings_json"] == []
    assert scan_row["errors_json"] == []
    assert scan_row["coverage_summary_json"] == {}
    assert target_row["exclusions_json"] == []
    assert target_row["active_scan_allowed"] is False
    assert target_row["sensitive_scope"] is False
    assert assignment_row["status"] == "pending"
    assert assignment_row["observations_count"] == 0
    timestamp_default_count = 0
    for table_name in HMAIR_TABLES:
        columns = _columns(engine, table_name)
        for name in ("created_at", "updated_at"):
            assert _is_now_default(columns[name]["default"]), (table_name, name)
            timestamp_default_count += 1
    assert timestamp_default_count == 12


def test_unique_constraints_are_exact_and_tenant_safe(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    expected = {
        "discovery_scans": {
            ("tenant_id", "scan_id"),
            ("tenant_id", "request_idempotency_key"),
        },
        "discovery_targets": {("tenant_id", "target_id")},
        "discovery_collectors": {("tenant_id", "collector_id")},
        "discovery_scan_targets": set(),
        "discovery_scan_assignments": {
            ("tenant_id", "assignment_id"),
            ("tenant_id", "scan_id", "target_id", "collector_id"),
            (
                "tenant_id",
                "assignment_id",
                "scan_id",
                "target_id",
                "collector_id",
            ),
        },
        "discovery_observations": {
            ("tenant_id", "observation_id"),
            ("tenant_id", "scan_id", "collector_id", "idempotency_key"),
        },
    }
    for table_name, constraints in expected.items():
        assert _unique_columns(engine, table_name) == constraints


def test_foreign_keys_are_exact_with_approved_delete_rules(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    expected = {
        "discovery_scans": {
            (("tenant_id",), "tenants", ("id",), "CASCADE"),
            (("requested_by",), "users", ("id",), "SET NULL"),
            (
                ("tenant_id", "rescan_of_scan_id"),
                "discovery_scans",
                ("tenant_id", "scan_id"),
                "RESTRICT",
            ),
            (
                ("tenant_id", "evidence_bundle_id"),
                "evidence_nodes",
                ("tenant_id", "id"),
                "RESTRICT",
            ),
        },
        "discovery_targets": {
            (("tenant_id",), "tenants", ("id",), "CASCADE")
        },
        "discovery_collectors": {
            (("tenant_id",), "tenants", ("id",), "CASCADE")
        },
        "discovery_scan_targets": {
            (("tenant_id",), "tenants", ("id",), "CASCADE"),
            (
                ("tenant_id", "scan_id"),
                "discovery_scans",
                ("tenant_id", "scan_id"),
                "CASCADE",
            ),
            (
                ("tenant_id", "target_id"),
                "discovery_targets",
                ("tenant_id", "target_id"),
                "RESTRICT",
            ),
        },
        "discovery_scan_assignments": {
            (("tenant_id",), "tenants", ("id",), "CASCADE"),
            (
                ("tenant_id", "scan_id", "target_id"),
                "discovery_scan_targets",
                ("tenant_id", "scan_id", "target_id"),
                "CASCADE",
            ),
            (
                ("tenant_id", "collector_id"),
                "discovery_collectors",
                ("tenant_id", "collector_id"),
                "RESTRICT",
            ),
        },
        "discovery_observations": {
            (("tenant_id",), "tenants", ("id",), "CASCADE"),
            (
                ("tenant_id", "scan_id"),
                "discovery_scans",
                ("tenant_id", "scan_id"),
                "RESTRICT",
            ),
            (
                ("tenant_id", "target_id"),
                "discovery_targets",
                ("tenant_id", "target_id"),
                "RESTRICT",
            ),
            (
                ("tenant_id", "collector_id"),
                "discovery_collectors",
                ("tenant_id", "collector_id"),
                "RESTRICT",
            ),
            (
                (
                    "tenant_id",
                    "assignment_id",
                    "scan_id",
                    "target_id",
                    "collector_id",
                ),
                "discovery_scan_assignments",
                (
                    "tenant_id",
                    "assignment_id",
                    "scan_id",
                    "target_id",
                    "collector_id",
                ),
                "RESTRICT",
            ),
        },
    }
    for table_name, foreign_keys in expected.items():
        assert _foreign_keys(engine, table_name) == foreign_keys


def test_operational_indexes_are_exact_and_tenant_first(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    for table_name, expected in EXPECTED_INDEXES.items():
        actual = sa.inspect(engine).get_indexes(table_name)
        assert {tuple(index["column_names"]) for index in actual} == expected
        assert all(not bool(index.get("unique")) for index in actual)
        assert all(columns[0] == "tenant_id" for columns in expected)


def _literal_sets(engine: sa.Engine, table_name: str) -> list[set[str]]:
    return [
        _extract_literals(str(check["sqltext"]))
        for check in sa.inspect(engine).get_check_constraints(table_name)
    ]


def test_closed_vocabularies_are_exact_and_open_vocabularies_remain_open(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    for expected in (SCAN_TYPES, SCAN_STATUSES):
        assert expected in _literal_sets(engine, "discovery_scans")
    assert TARGET_TYPES in _literal_sets(engine, "discovery_targets")
    for expected in (COLLECTOR_HEALTH, CONTROL_CAPABILITIES):
        assert expected in _literal_sets(engine, "discovery_collectors")
    assert ASSIGNMENT_STATUSES in _literal_sets(
        engine, "discovery_scan_assignments"
    )
    assert FRESHNESS_VALUES in _literal_sets(engine, "discovery_observations")

    _seed_graph(engine, suffix="open-vocab")
    with engine.connect() as connection:
        row = connection.execute(
            sa.text(
                "SELECT signature_status, sensitivity, redaction_status "
                "FROM discovery_observations "
                "WHERE observation_id='observation-open-vocab'"
            )
        ).one()
    assert row == (
        "vendor_extension_value",
        "vendor_extension_value",
        "vendor_extension_value",
    )


@pytest.mark.parametrize(
    ("scan_type", "is_valid"),
    [*((value, True) for value in sorted(SCAN_TYPES)), ("forged", False)],
)
def test_scan_type_vocabulary_is_enforced_at_runtime(
    migrated: tuple[sa.Engine, Any], scan_type: str, is_valid: bool
) -> None:
    engine, _migration_object = migrated

    def insert() -> None:
        _insert_scan(
            engine,
            scan_id=f"scan-type-{scan_type}",
            tenant_id="tenant-a",
            scan_type=scan_type,
        )

    if is_valid:
        insert()
    else:
        with _rejects_integrity():
            insert()


@pytest.mark.parametrize(
    ("target_type", "is_valid"),
    [*((value, True) for value in sorted(TARGET_TYPES)), ("forged", False)],
)
def test_target_type_vocabulary_is_enforced_at_runtime(
    migrated: tuple[sa.Engine, Any], target_type: str, is_valid: bool
) -> None:
    engine, _migration_object = migrated

    def insert() -> None:
        _insert_target(
            engine,
            target_id=f"target-type-{target_type}",
            tenant_id="tenant-a",
            target_type=target_type,
        )

    if is_valid:
        insert()
    else:
        with _rejects_integrity():
            insert()


@pytest.mark.parametrize(
    ("field", "value", "is_valid"),
    [
        *(("health", value, True) for value in sorted(COLLECTOR_HEALTH)),
        *(("control_capability", value, True) for value in sorted(CONTROL_CAPABILITIES)),
        ("health", "forged", False),
        ("control_capability", "forged", False),
    ],
)
def test_collector_vocabularies_are_enforced_at_runtime(
    migrated: tuple[sa.Engine, Any], field: str, value: str, is_valid: bool
) -> None:
    engine, _migration_object = migrated

    def insert() -> None:
        _insert_collector(
            engine,
            collector_id=f"collector-{field}-{value}",
            tenant_id="tenant-a",
            **{field: value},
        )

    if is_valid:
        insert()
    else:
        with _rejects_integrity():
            insert()


def test_invalid_scan_and_assignment_statuses_are_rejected_at_runtime(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    with _rejects_integrity():
        _insert_scan(
            engine,
            scan_id="scan-invalid-status",
            tenant_id="tenant-a",
            status="forged",
        )
    ids = _seed_graph(engine, suffix="invalid-status", with_observation=False)
    assignments = sa.Table(
        "discovery_scan_assignments", sa.MetaData(), autoload_with=engine
    )
    with _rejects_integrity():
        with engine.begin() as connection:
            connection.execute(
                assignments.update()
                .where(assignments.c.assignment_id == ids["assignment_id"])
                .values(status="forged")
            )


@pytest.mark.parametrize(
    ("freshness", "is_valid"),
    [*((value, True) for value in sorted(FRESHNESS_VALUES)), ("forged", False)],
)
def test_freshness_vocabulary_is_enforced_at_runtime(
    migrated: tuple[sa.Engine, Any], freshness: str, is_valid: bool
) -> None:
    engine, _migration_object = migrated
    ids = _seed_graph(engine, suffix=f"freshness-{freshness}", with_observation=False)

    def insert() -> None:
        _insert_observation(
            engine,
            observation_id=f"observation-freshness-{freshness}",
            tenant_id="tenant-a",
            assignment_id=ids["assignment_id"],
            scan_id=ids["scan_id"],
            target_id=ids["target_id"],
            collector_id=ids["collector_id"],
            freshness=freshness,
        )

    if is_valid:
        insert()
    else:
        with _rejects_integrity():
            insert()


def test_all_five_hash_columns_accept_the_full_lowercase_hex_alphabet(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    _insert_scan(
        engine,
        scan_id="scan-full-alphabet-hash",
        tenant_id="tenant-a",
        request_digest=FULL_ALPHABET_HASH,
    )
    _insert_collector(
        engine,
        collector_id="collector-full-alphabet-hash",
        tenant_id="tenant-a",
        declaration_hash=FULL_ALPHABET_HASH,
    )
    ids = _seed_graph(engine, suffix="hex-observation", with_observation=False)
    _insert_observation(
        engine,
        observation_id="observation-full-alphabet-hash",
        tenant_id="tenant-a",
        assignment_id=ids["assignment_id"],
        scan_id=ids["scan_id"],
        target_id=ids["target_id"],
        collector_id=ids["collector_id"],
        evidence_hash=FULL_ALPHABET_HASH,
        idempotency_key=FULL_ALPHABET_HASH,
        payload_digest=FULL_ALPHABET_HASH,
    )


@pytest.mark.parametrize(
    ("table_name", "helper", "field"),
    [
        ("discovery_scans", _insert_scan, "request_digest"),
        ("discovery_collectors", _insert_collector, "declaration_hash"),
    ],
)
@pytest.mark.parametrize(
    "invalid_hash",
    ["a" * 63, "a" * 65, "A" * 64, ("a" * 63) + "g"],
)
def test_scan_and_collector_hashes_require_exact_lowercase_sha256(
    migrated: tuple[sa.Engine, Any],
    table_name: str,
    helper: Any,
    field: str,
    invalid_hash: str,
) -> None:
    engine, _migration_object = migrated
    del table_name
    identifier = f"invalid-{field}-{invalid_hash[:2]}-{len(invalid_hash)}"
    kwargs = {
        "tenant_id": "tenant-a",
        field: invalid_hash,
    }
    if helper is _insert_scan:
        kwargs["scan_id"] = identifier
    else:
        kwargs["collector_id"] = identifier
    with _rejects_integrity():
        helper(engine, **kwargs)


@pytest.mark.parametrize("field", ["evidence_hash", "idempotency_key", "payload_digest"])
@pytest.mark.parametrize(
    "invalid_hash",
    ["a" * 63, "a" * 65, "A" * 64, ("a" * 63) + "z"],
)
def test_observation_hash_fields_require_exact_lowercase_sha256(
    migrated: tuple[sa.Engine, Any], field: str, invalid_hash: str
) -> None:
    engine, _migration_object = migrated
    ids = _seed_graph(engine, suffix=f"hash-{field}", with_observation=False)
    kwargs = {field: invalid_hash}
    if field == "idempotency_key":
        kwargs["idempotency_key"] = invalid_hash
    with _rejects_integrity():
        _insert_observation(
            engine,
            observation_id=f"observation-{field}",
            tenant_id="tenant-a",
            assignment_id=ids["assignment_id"],
            scan_id=ids["scan_id"],
            target_id=ids["target_id"],
            collector_id=ids["collector_id"],
            **kwargs,
        )


@pytest.mark.parametrize("rate_limit", [0, 10001])
def test_target_rate_limit_rejects_values_outside_inclusive_bounds(
    migrated: tuple[sa.Engine, Any], rate_limit: int
) -> None:
    engine, _migration_object = migrated
    with _rejects_integrity():
        _insert_target(
            engine,
            target_id=f"target-rate-{rate_limit}",
            tenant_id="tenant-a",
            rate_limit=rate_limit,
        )


@pytest.mark.parametrize("rate_limit", [1, 10000])
def test_target_rate_limit_accepts_both_boundaries(
    migrated: tuple[sa.Engine, Any], rate_limit: int
) -> None:
    engine, _migration_object = migrated
    _insert_target(
        engine,
        target_id=f"target-rate-{rate_limit}",
        tenant_id="tenant-a",
        rate_limit=rate_limit,
    )


@pytest.mark.parametrize("confidence", [-0.0001, 1.0001])
def test_observation_confidence_rejects_values_outside_inclusive_bounds(
    migrated: tuple[sa.Engine, Any], confidence: float
) -> None:
    engine, _migration_object = migrated
    ids = _seed_graph(engine, suffix=f"confidence-{confidence}", with_observation=False)
    with _rejects_integrity():
        _insert_observation(
            engine,
            observation_id=f"observation-confidence-{confidence}",
            tenant_id="tenant-a",
            assignment_id=ids["assignment_id"],
            scan_id=ids["scan_id"],
            target_id=ids["target_id"],
            collector_id=ids["collector_id"],
            confidence=confidence,
        )


@pytest.mark.parametrize("confidence", [0.0, 1.0])
def test_observation_confidence_accepts_both_boundaries(
    migrated: tuple[sa.Engine, Any], confidence: float
) -> None:
    engine, _migration_object = migrated
    ids = _seed_graph(engine, suffix=f"confidence-{confidence}", with_observation=False)
    _insert_observation(
        engine,
        observation_id=f"observation-confidence-{confidence}",
        tenant_id="tenant-a",
        assignment_id=ids["assignment_id"],
        scan_id=ids["scan_id"],
        target_id=ids["target_id"],
        collector_id=ids["collector_id"],
        confidence=confidence,
    )


@pytest.mark.parametrize(
    "counter",
    ["observations_count", "assets_created", "assets_updated", "assets_unresolved"],
)
def test_scan_counters_cannot_be_negative(
    migrated: tuple[sa.Engine, Any], counter: str
) -> None:
    engine, _migration_object = migrated
    with _rejects_integrity():
        _insert_scan(
            engine,
            scan_id=f"scan-negative-{counter}",
            tenant_id="tenant-a",
            **{counter: -1},
        )


def test_assignment_observation_count_cannot_be_negative(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    ids = _seed_graph(engine, suffix="negative-assignment", with_observation=False)
    assignments = sa.Table(
        "discovery_scan_assignments", sa.MetaData(), autoload_with=engine
    )
    with _rejects_integrity():
        with engine.begin() as connection:
            connection.execute(
                assignments.update()
                .where(assignments.c.assignment_id == ids["assignment_id"])
                .values(observations_count=-1)
            )


def test_rescan_cannot_refer_to_itself(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    with _rejects_integrity():
        _insert_scan(
            engine,
            scan_id="scan-self",
            tenant_id="tenant-a",
            rescan_of_scan_id="scan-self",
        )


@pytest.mark.parametrize(
    ("status", "started", "completed", "cancelled"),
    SCAN_LIFECYCLE_CASES,
)
def test_scan_lifecycle_full_truth_table(
    migrated: tuple[sa.Engine, Any],
    status: str,
    started: bool,
    completed: bool,
    cancelled: bool,
) -> None:
    engine, _migration_object = migrated
    values = {
        "scan_id": f"scan-{status}-{int(started)}{int(completed)}{int(cancelled)}",
        "tenant_id": "tenant-a",
        "status": status,
        "started_at": NOW if started else None,
        "completed_at": NOW if completed else None,
        "cancelled_at": NOW if cancelled else None,
    }
    if (status, started, completed, cancelled) in SCAN_LIFECYCLE_VALID:
        _insert_scan(engine, **values)
    else:
        with _rejects_integrity():
            _insert_scan(engine, **values)


@pytest.mark.parametrize(
    ("status", "started", "completed"),
    ASSIGNMENT_LIFECYCLE_CASES,
)
def test_assignment_lifecycle_full_truth_table(
    migrated: tuple[sa.Engine, Any],
    status: str,
    started: bool,
    completed: bool,
) -> None:
    engine, _migration_object = migrated
    status_code = sorted(ASSIGNMENT_STATUSES).index(status)
    suffix = f"al-{status_code}-{int(started)}{int(completed)}"
    ids = _seed_graph(engine, suffix=suffix, with_observation=False)
    assert len(ids["assignment_id"]) <= 36
    assignments = sa.Table(
        "discovery_scan_assignments", sa.MetaData(), autoload_with=engine
    )

    def update_assignment() -> None:
        with engine.begin() as connection:
            connection.execute(
                assignments.update()
                .where(assignments.c.assignment_id == ids["assignment_id"])
                .values(
                    status=status,
                    started_at=NOW if started else None,
                    completed_at=NOW if completed else None,
                )
            )

    if (status, started, completed) in ASSIGNMENT_LIFECYCLE_VALID:
        update_assignment()
    else:
        with _rejects_integrity():
            update_assignment()


def test_idempotency_and_work_uniqueness_are_tenant_scoped(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    _insert_scan(
        engine,
        scan_id="scan-a-one",
        tenant_id="tenant-a",
        request_key="same-request",
    )
    with _rejects_integrity():
        _insert_scan(
            engine,
            scan_id="scan-a-two",
            tenant_id="tenant-a",
            request_key="same-request",
        )
    _insert_scan(
        engine,
        scan_id="scan-b-one",
        tenant_id="tenant-b",
        request_key="same-request",
    )

    ids = _seed_graph(engine, suffix="retry", with_observation=False)
    _insert_observation(
        engine,
        observation_id="observation-retry-one",
        tenant_id="tenant-a",
        assignment_id=ids["assignment_id"],
        scan_id=ids["scan_id"],
        target_id=ids["target_id"],
        collector_id=ids["collector_id"],
    )
    with _rejects_integrity():
        _insert_observation(
            engine,
            observation_id="observation-retry-two",
            tenant_id="tenant-a",
            assignment_id=ids["assignment_id"],
            scan_id=ids["scan_id"],
            target_id=ids["target_id"],
            collector_id=ids["collector_id"],
        )
    with _rejects_integrity():
        _insert_assignment(
            engine,
            assignment_id="assignment-retry-two",
            tenant_id="tenant-a",
            scan_id=ids["scan_id"],
            target_id=ids["target_id"],
            collector_id=ids["collector_id"],
        )


def test_requested_user_delete_sets_scan_reference_to_null(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    _insert_scan(
        engine,
        scan_id="scan-requested-by",
        tenant_id="tenant-a",
        requested_by="user-a",
    )
    with engine.begin() as connection:
        connection.execute(sa.text("DELETE FROM users WHERE id='user-a'"))
    with engine.connect() as connection:
        requested_by = connection.execute(
            sa.text(
                "SELECT requested_by FROM discovery_scans "
                "WHERE scan_id='scan-requested-by'"
            )
        ).scalar_one()
    assert requested_by is None


def test_physical_object_primary_keys_are_globally_unique(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    ids_a = _seed_graph(engine, tenant_id="tenant-a", suffix="global-a")
    ids_b = _seed_graph(engine, tenant_id="tenant-b", suffix="global-b")

    with _rejects_integrity():
        _insert_scan(
            engine,
            scan_id=ids_a["scan_id"],
            tenant_id="tenant-b",
            request_key="duplicate-global-scan",
        )
    with _rejects_integrity():
        _insert_target(
            engine,
            target_id=ids_a["target_id"],
            tenant_id="tenant-b",
        )
    with _rejects_integrity():
        _insert_collector(
            engine,
            collector_id=ids_a["collector_id"],
            tenant_id="tenant-b",
        )

    _insert_target(
        engine, target_id="target-global-b-extra", tenant_id="tenant-b"
    )
    _insert_scan_target(
        engine,
        tenant_id="tenant-b",
        scan_id=ids_b["scan_id"],
        target_id="target-global-b-extra",
    )
    with _rejects_integrity():
        _insert_assignment(
            engine,
            assignment_id=ids_a["assignment_id"],
            tenant_id="tenant-b",
            scan_id=ids_b["scan_id"],
            target_id="target-global-b-extra",
            collector_id=ids_b["collector_id"],
        )
    with _rejects_integrity():
        _insert_observation(
            engine,
            observation_id=ids_a["observation_id"],
            tenant_id="tenant-b",
            assignment_id=ids_b["assignment_id"],
            scan_id=ids_b["scan_id"],
            target_id=ids_b["target_id"],
            collector_id=ids_b["collector_id"],
            idempotency_key=HASH_B,
        )


def test_composite_foreign_keys_reject_every_cross_tenant_path(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    ids_a = _seed_graph(
        engine, tenant_id="tenant-a", suffix="tenant-a", with_observation=False
    )
    ids_b = _seed_graph(
        engine, tenant_id="tenant-b", suffix="tenant-b", with_observation=False
    )

    with _rejects_integrity():
        _insert_scan(
            engine,
            scan_id="scan-cross-rescan",
            tenant_id="tenant-a",
            rescan_of_scan_id=ids_b["scan_id"],
        )
    with _rejects_integrity():
        _insert_scan(
            engine,
            scan_id="scan-cross-evidence",
            tenant_id="tenant-a",
            evidence_bundle_id="evidence-b",
        )
    with _rejects_integrity():
        _insert_scan_target(
            engine,
            tenant_id="tenant-a",
            scan_id=ids_a["scan_id"],
            target_id=ids_b["target_id"],
        )

    _insert_target(engine, target_id="target-a-extra", tenant_id="tenant-a")
    _insert_scan_target(
        engine,
        tenant_id="tenant-a",
        scan_id=ids_a["scan_id"],
        target_id="target-a-extra",
    )
    with _rejects_integrity():
        _insert_assignment(
            engine,
            assignment_id="assignment-cross-collector",
            tenant_id="tenant-a",
            scan_id=ids_a["scan_id"],
            target_id="target-a-extra",
            collector_id=ids_b["collector_id"],
        )

    with _rejects_integrity():
        _insert_observation(
            engine,
            observation_id="observation-cross-assignment",
            tenant_id="tenant-a",
            assignment_id=ids_b["assignment_id"],
            scan_id=ids_a["scan_id"],
            target_id=ids_a["target_id"],
            collector_id=ids_a["collector_id"],
        )


def test_evidence_bundle_width_is_36_and_tenant_match_is_enforced(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    column = _columns(engine, "discovery_scans")["evidence_bundle_id"]
    assert column["type"].length == 36
    _insert_scan(
        engine,
        scan_id="scan-evidence-valid",
        tenant_id="tenant-a",
        evidence_bundle_id="evidence-a",
    )
    with _rejects_integrity():
        _insert_scan(
            engine,
            scan_id="scan-evidence-cross-tenant",
            tenant_id="tenant-a",
            evidence_bundle_id="evidence-b",
        )


def test_sqlite_foreign_keys_are_enabled_and_consistent(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    _seed_graph(engine, suffix="foreign-key-check")
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []


def test_sqlite_installs_both_exact_immutable_observation_triggers(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    assert _trigger_names(engine) == {
        "trg_discovery_observations_immutable_update",
        "trg_discovery_observations_immutable_delete",
    }
    with engine.connect() as connection:
        trigger_sql = " ".join(
            row[0]
            for row in connection.exec_driver_sql(
                "SELECT sql FROM sqlite_master "
                "WHERE type='trigger' AND name LIKE "
                "'trg_discovery_observations_immutable_%'"
            ).all()
        )
    assert trigger_sql.count("immutable_table:discovery_observations") == 2


def test_observation_update_and_delete_are_rejected(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    ids = _seed_graph(engine, suffix="immutable")
    with pytest.raises(
        sa.exc.DBAPIError, match="immutable_table:discovery_observations"
    ):
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    "UPDATE discovery_observations SET confidence=0.5 "
                    "WHERE observation_id=:observation_id"
                ),
                {"observation_id": ids["observation_id"]},
            )
    with pytest.raises(
        sa.exc.DBAPIError, match="immutable_table:discovery_observations"
    ):
        with engine.begin() as connection:
            connection.execute(
                sa.text(
                    "DELETE FROM discovery_observations "
                    "WHERE observation_id=:observation_id"
                ),
                {"observation_id": ids["observation_id"]},
            )


def test_cascade_driven_observation_delete_aborts_and_rolls_back_everything(
    migrated: tuple[sa.Engine, Any],
) -> None:
    engine, _migration_object = migrated
    ids = _seed_graph(engine, suffix="cascade-rollback")
    with pytest.raises(
        sa.exc.DBAPIError, match="immutable_table:discovery_observations"
    ):
        with engine.begin() as connection:
            connection.execute(
                sa.text("DELETE FROM tenants WHERE id='tenant-a'")
            )
    with engine.connect() as connection:
        assert connection.execute(
            sa.text("SELECT COUNT(*) FROM tenants WHERE id='tenant-a'")
        ).scalar_one() == 1
        assert connection.execute(
            sa.text(
                "SELECT COUNT(*) FROM discovery_scans WHERE scan_id=:scan_id"
            ),
            {"scan_id": ids["scan_id"]},
        ).scalar_one() == 1
        assert connection.execute(
            sa.text(
                "SELECT COUNT(*) FROM discovery_observations "
                "WHERE observation_id=:observation_id"
            ),
            {"observation_id": ids["observation_id"]},
        ).scalar_one() == 1


class _RecordingOperations:
    def __init__(self, wrapped: Operations) -> None:
        self.wrapped = wrapped
        self.events: list[tuple[str, str]] = []

    def drop_table(self, table_name: str, *args: Any, **kwargs: Any) -> Any:
        self.events.append(("drop_table", table_name))
        return self.wrapped.drop_table(table_name, *args, **kwargs)

    def drop_index(self, index_name: str, *args: Any, **kwargs: Any) -> Any:
        self.events.append(("drop_index", index_name))
        return self.wrapped.drop_index(index_name, *args, **kwargs)

    def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
        self.events.append(("execute", str(statement)))
        return self.wrapped.execute(statement, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.wrapped, name)


def test_downgrade_removes_only_hmair_objects_in_dependency_order_and_reupgrades(
    migrated: tuple[sa.Engine, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, migration = migrated
    initial_signature = _hmair_schema_signature(engine)
    inspector = sa.inspect(engine)
    index_names = {
        index["name"]
        for table_name in HMAIR_TABLES
        for index in inspector.get_indexes(table_name)
    }
    with engine.connect() as connection:
        context = MigrationContext.configure(connection)
        recorder = _RecordingOperations(Operations(context))
        monkeypatch.setattr(migration, "op", recorder)
        with context.begin_transaction(_per_migration=True):
            migration.downgrade()

    drop_tables = [value for kind, value in recorder.events if kind == "drop_table"]
    assert drop_tables == [
        "discovery_observations",
        "discovery_scan_assignments",
        "discovery_scan_targets",
        "discovery_scans",
        "discovery_collectors",
        "discovery_targets",
    ]
    dropped_indexes = {
        value for kind, value in recorder.events if kind == "drop_index"
    }
    assert dropped_indexes == index_names
    drop_trigger_events = [
        (index, value.lower())
        for index, (kind, value) in enumerate(recorder.events)
        if kind == "execute" and "drop trigger" in value.lower()
    ]
    drop_trigger_names = Counter()
    for _index, statement in drop_trigger_events:
        match = re.search(
            r"drop\s+trigger(?:\s+if\s+exists)?\s+"
            r"[\"']?([a-z0-9_]+)[\"']?",
            statement,
        )
        assert match is not None
        drop_trigger_names[match.group(1)] += 1
    assert drop_trigger_names == Counter(
        {
            "trg_discovery_observations_immutable_update": 1,
            "trg_discovery_observations_immutable_delete": 1,
        }
    )
    drop_index_positions = [
        index
        for index, event in enumerate(recorder.events)
        if event[0] == "drop_index"
    ]
    assert drop_index_positions
    first_table = next(
        index
        for index, event in enumerate(recorder.events)
        if event[0] == "drop_table"
    )
    assert max(index for index, _statement in drop_trigger_events) < min(
        drop_index_positions
    )
    assert max(drop_index_positions) < first_table

    names = set(sa.inspect(engine).get_table_names())
    assert not (names & HMAIR_TABLES)
    assert {"tenants", "users", "evidence_nodes", "preexisting_sentinel"} <= names
    assert not {
        "trg_discovery_observations_immutable_update",
        "trg_discovery_observations_immutable_delete",
    } & _trigger_names(engine)
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
        assert connection.exec_driver_sql(
            "SELECT COUNT(*) FROM preexisting_sentinel"
        ).scalar_one() == 1

    _invoke(engine, migration, "upgrade", monkeypatch)
    assert set(sa.inspect(engine).get_table_names()) == HMAIR_TABLES | {
        "tenants",
        "users",
        "evidence_nodes",
        "preexisting_sentinel",
    }
    assert _trigger_names(engine) == {
        "trg_discovery_observations_immutable_update",
        "trg_discovery_observations_immutable_delete",
    }
    assert _hmair_schema_signature(engine) == initial_signature


def _offline_postgresql_sql(
    operation: str, monkeypatch: pytest.MonkeyPatch
) -> str:
    migration = _migration()
    output = StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={"as_sql": True, "output_buffer": output},
    )
    monkeypatch.setattr(migration, "op", Operations(context))
    getattr(migration, operation)()
    return output.getvalue()


def _postgresql_check_clauses(sql: str) -> list[str]:
    clauses: list[str] = []
    for match in re.finditer(r"\bcheck\s*\(", sql):
        depth = 1
        cursor = match.end()
        quote: str | None = None
        while cursor < len(sql) and depth:
            character = sql[cursor]
            if quote is not None:
                if character == quote:
                    if cursor + 1 < len(sql) and sql[cursor + 1] == quote:
                        cursor += 2
                        continue
                    quote = None
            elif character in {"'", '"'}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
            cursor += 1
        assert depth == 0
        clauses.append(sql[match.start() : cursor])
    return clauses


def test_offline_postgresql_ddl_uses_one_shared_function_trigger_without_recreation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    upgrade_sql = _offline_postgresql_sql("upgrade", monkeypatch).lower()
    for table_name in HMAIR_TABLES:
        assert f"create table {table_name}" in upgrade_sql
    assert upgrade_sql.count("timestamp with time zone") == 21
    timestamp_defaults = re.findall(
        r"\b(created_at|updated_at)\s+timestamp with time zone\s+"
        r"default\s+(?:now\(\)|current_timestamp(?:\(\))?)\s+not null",
        upgrade_sql,
    )
    assert Counter(timestamp_defaults) == Counter({"created_at": 6, "updated_at": 6})
    assert not re.search(r"\bglob\b", upgrade_sql)
    check_clauses = _postgresql_check_clauses(upgrade_sql)
    for hash_column in (
        "request_digest",
        "declaration_hash",
        "evidence_hash",
        "idempotency_key",
        "payload_digest",
    ):
        assert any(
            re.search(rf"\b{re.escape(hash_column)}\b", clause)
            for clause in check_clauses
        )
    assert upgrade_sql.count("create trigger trg_discovery_observations_immutable") == 1
    assert "before update or delete on discovery_observations" in upgrade_sql
    assert "execute function deny_immutable_table_mutation()" in upgrade_sql
    assert upgrade_sql.count("deny_immutable_table_mutation") == 1
    assert "create function" not in upgrade_sql
    assert "create or replace function" not in upgrade_sql
    assert "drop function" not in upgrade_sql

    downgrade_sql = _offline_postgresql_sql("downgrade", monkeypatch).lower()
    assert "drop trigger" in downgrade_sql
    assert "trg_discovery_observations_immutable" in downgrade_sql
    assert "drop function" not in downgrade_sql
    trigger_drops = list(
        re.finditer(
            r"drop\s+trigger(?:\s+if\s+exists)?\s+"
            r'"?trg_discovery_observations_immutable"?',
            downgrade_sql,
        )
    )
    assert len(trigger_drops) == 1
    created_indexes = set(
        re.findall(r'create\s+index\s+"?([a-z0-9_]+)"?\s+on', upgrade_sql)
    )
    dropped_index_matches = list(
        re.finditer(r'drop\s+index(?:\s+if\s+exists)?\s+"?([a-z0-9_]+)"?', downgrade_sql)
    )
    assert len(created_indexes) == sum(len(indexes) for indexes in EXPECTED_INDEXES.values())
    assert Counter(match.group(1) for match in dropped_index_matches) == Counter(
        {name: 1 for name in created_indexes}
    )
    positions = [
        downgrade_sql.index(f"drop table {table_name}")
        for table_name in (
            "discovery_observations",
            "discovery_scan_assignments",
            "discovery_scan_targets",
            "discovery_scans",
            "discovery_collectors",
            "discovery_targets",
        )
    ]
    assert positions == sorted(positions)
    assert trigger_drops[0].start() < min(
        match.start() for match in dropped_index_matches
    )
    assert max(match.start() for match in dropped_index_matches) < positions[0]


@pytest.mark.parametrize("operation", ["upgrade", "downgrade"])
def test_unsupported_dialect_fails_before_emitting_any_ddl(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    migration = _migration()
    output = StringIO()
    context = MigrationContext.configure(
        dialect_name="mysql", opts={"as_sql": True, "output_buffer": output}
    )
    monkeypatch.setattr(migration, "op", Operations(context))
    with pytest.raises(Exception) as error:
        getattr(migration, operation)()
    message = str(error.value).lower()
    assert re.search(r"unsupported dialect:\s*mysql", message)
    assert output.getvalue() == ""


def test_current_revision_is_the_sole_short_migration_head() -> None:
    config = Config(str(API_ROOT / "app/db/migrations/alembic.ini"))
    config.set_main_option("script_location", str(API_ROOT / "app/db/migrations"))
    heads = ScriptDirectory.from_config(config).get_heads()
    assert heads == ["0104_desc_controls"]
    assert all(len(head) <= 128 for head in heads)
