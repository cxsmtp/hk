from __future__ import annotations

from importlib import import_module
import re

import sqlalchemy as sa


def _portable_hash_check(column: str) -> str:
    stripped = column
    for character in "0123456789abcdef":
        stripped = f"replace({stripped}, '{character}', '')"
    return (
        f"length({column}) = 64 AND {column} = lower({column}) "
        f"AND {stripped} = ''"
    )


TABLE_MODELS = {
    "discovery_scans": "DiscoveryScan",
    "discovery_targets": "DiscoveryTarget",
    "discovery_collectors": "DiscoveryCollector",
    "discovery_scan_targets": "DiscoveryScanTarget",
    "discovery_scan_assignments": "DiscoveryScanAssignment",
    "discovery_observations": "DiscoveryObservation",
}

TIMESTAMPS = {
    "created_at": (sa.DateTime, None, False),
    "updated_at": (sa.DateTime, None, False),
}

COLUMNS = {
    "discovery_scans": {
        "scan_id": (sa.String, 36, False),
        "tenant_id": (sa.String, 36, False),
        "name": (sa.String, 255, False),
        "requested_by": (sa.String, 36, True),
        "scan_type": (sa.String, 32, False),
        "scope_json": (sa.JSON, None, False),
        "safety_profile": (sa.String, 64, False),
        "request_idempotency_key": (sa.String, 128, False),
        "request_digest": (sa.String, 64, False),
        "status": (sa.String, 32, False),
        "dry_run": (sa.Boolean, None, False),
        "started_at": (sa.DateTime, None, True),
        "completed_at": (sa.DateTime, None, True),
        "cancelled_at": (sa.DateTime, None, True),
        "observations_count": (sa.BigInteger, None, False),
        "assets_created": (sa.BigInteger, None, False),
        "assets_updated": (sa.BigInteger, None, False),
        "assets_unresolved": (sa.BigInteger, None, False),
        "warnings_json": (sa.JSON, None, False),
        "errors_json": (sa.JSON, None, False),
        "coverage_summary_json": (sa.JSON, None, False),
        "evidence_bundle_id": (sa.String, 36, True),
        "rescan_of_scan_id": (sa.String, 36, True),
        **TIMESTAMPS,
    },
    "discovery_targets": {
        "target_id": (sa.String, 128, False),
        "tenant_id": (sa.String, 36, False),
        "target_type": (sa.String, 32, False),
        "identifier": (sa.String, 512, False),
        "environment": (sa.String, 64, False),
        "owner_hint": (sa.String, 255, True),
        "credentials_reference": (sa.String, 255, True),
        "permitted_methods_json": (sa.JSON, None, False),
        "exclusions_json": (sa.JSON, None, False),
        "rate_limit": (sa.Integer, None, False),
        "active_scan_allowed": (sa.Boolean, None, False),
        "sensitive_scope": (sa.Boolean, None, False),
        "last_scanned_at": (sa.DateTime, None, True),
        **TIMESTAMPS,
    },
    "discovery_collectors": {
        "collector_id": (sa.String, 128, False),
        "tenant_id": (sa.String, 36, False),
        "collector_type": (sa.String, 64, False),
        "version": (sa.String, 64, False),
        "supported_targets_json": (sa.JSON, None, False),
        "active_capabilities_json": (sa.JSON, None, False),
        "passive_capabilities_json": (sa.JSON, None, False),
        "permissions_required_json": (sa.JSON, None, False),
        "sensitive_data_accessed_json": (sa.JSON, None, False),
        "health": (sa.String, 32, False),
        "last_success_at": (sa.DateTime, None, True),
        "last_failure_at": (sa.DateTime, None, True),
        "data_residency": (sa.String, 128, False),
        "control_capability": (sa.String, 32, False),
        "schema_version": (sa.String, 32, False),
        "limitations_json": (sa.JSON, None, False),
        "declaration_hash": (sa.String, 64, False),
        **TIMESTAMPS,
    },
    "discovery_scan_targets": {
        "tenant_id": (sa.String, 36, False),
        "scan_id": (sa.String, 36, False),
        "target_id": (sa.String, 128, False),
        **TIMESTAMPS,
    },
    "discovery_scan_assignments": {
        "assignment_id": (sa.String, 36, False),
        "tenant_id": (sa.String, 36, False),
        "scan_id": (sa.String, 36, False),
        "target_id": (sa.String, 128, False),
        "collector_id": (sa.String, 128, False),
        "status": (sa.String, 32, False),
        "warning": (sa.String, 500, True),
        "error": (sa.String, 500, True),
        "started_at": (sa.DateTime, None, True),
        "completed_at": (sa.DateTime, None, True),
        "observations_count": (sa.BigInteger, None, False),
        **TIMESTAMPS,
    },
    "discovery_observations": {
        "observation_id": (sa.String, 128, False),
        "tenant_id": (sa.String, 36, False),
        "assignment_id": (sa.String, 36, False),
        "scan_id": (sa.String, 36, False),
        "collector_id": (sa.String, 128, False),
        "collector_type": (sa.String, 64, False),
        "collector_version": (sa.String, 64, False),
        "target_id": (sa.String, 128, False),
        "source_surface": (sa.String, 32, False),
        "subject_reference": (sa.String, 255, True),
        "normalized_signal_json": (sa.JSON, None, False),
        "observed_at": (sa.DateTime, None, False),
        "received_at": (sa.DateTime, None, False),
        "observation_type": (sa.String, 128, False),
        "candidate_asset_type": (sa.String, 64, False),
        "observed_state": (sa.String, 32, False),
        "identifiers_json": (sa.JSON, None, False),
        "attributes_json": (sa.JSON, None, False),
        "configuration_summary_json": (sa.JSON, None, False),
        "usage_summary_json": (sa.JSON, None, False),
        "capability_hints_json": (sa.JSON, None, False),
        "identity_hints_json": (sa.JSON, None, False),
        "relationship_hints_json": (sa.JSON, None, False),
        "evidence_reference": (sa.String, 255, False),
        "evidence_hash": (sa.String, 64, False),
        "signature_status": (sa.String, 32, False),
        "confidence": (sa.Float, None, False),
        "freshness": (sa.String, 32, False),
        "verification_state": (sa.String, 32, False),
        "source_trust": (sa.String, 16, False),
        "collection_scope_json": (sa.JSON, None, False),
        "parser_version": (sa.String, 64, False),
        "schema_version": (sa.String, 32, False),
        "evidence_mode": (sa.String, 16, False),
        "evidence_mutability": (sa.String, 16, False),
        "contradiction_state": (sa.String, 32, False),
        "contradiction_references_json": (sa.JSON, None, False),
        "sensitivity": (sa.String, 32, False),
        "redaction_status": (sa.String, 32, False),
        "idempotency_key": (sa.String, 64, False),
        "payload_digest": (sa.String, 64, False),
        **TIMESTAMPS,
    },
}

PRIMARY_KEYS = {
    "discovery_scans": ("scan_id",),
    "discovery_targets": ("target_id",),
    "discovery_collectors": ("collector_id",),
    "discovery_scan_targets": ("tenant_id", "scan_id", "target_id"),
    "discovery_scan_assignments": ("assignment_id",),
    "discovery_observations": ("observation_id",),
}

UNIQUES = {
    "discovery_scans": {
        "uq_discovery_scan_tenant_id": ("tenant_id", "scan_id"),
        "uq_discovery_scan_tenant_request": ("tenant_id", "request_idempotency_key"),
    },
    "discovery_targets": {"uq_discovery_target_tenant_id": ("tenant_id", "target_id")},
    "discovery_collectors": {"uq_discovery_collector_tenant_id": ("tenant_id", "collector_id")},
    "discovery_scan_targets": {},
    "discovery_scan_assignments": {
        "uq_discovery_assignment_tenant_id": ("tenant_id", "assignment_id"),
        "uq_discovery_assignment_tenant_work": ("tenant_id", "scan_id", "target_id", "collector_id"),
        "uq_discovery_assignment_observation_parent": (
            "tenant_id", "assignment_id", "scan_id", "target_id", "collector_id"
        ),
    },
    "discovery_observations": {
        "uq_discovery_observation_tenant_id": ("tenant_id", "observation_id"),
        "uq_discovery_observation_retry": ("tenant_id", "scan_id", "collector_id", "idempotency_key"),
    },
}

CHECKS = {
    "discovery_scans": {
        "ck_discovery_scan_type", "ck_discovery_scan_status",
        "ck_discovery_scan_counters", "ck_discovery_scan_request_digest",
        "ck_discovery_scan_not_self_rescan", "ck_discovery_scan_lifecycle",
    },
    "discovery_targets": {"ck_discovery_target_type", "ck_discovery_target_rate_limit"},
    "discovery_collectors": {
        "ck_discovery_collector_health", "ck_discovery_collector_control_capability",
        "ck_discovery_collector_declaration_hash",
    },
    "discovery_scan_targets": set(),
    "discovery_scan_assignments": {
        "ck_discovery_assignment_status", "ck_discovery_assignment_observations_count",
        "ck_discovery_assignment_lifecycle",
    },
    "discovery_observations": {
        "ck_discovery_observation_confidence", "ck_discovery_observation_freshness",
        "ck_discovery_observation_source_surface",
        "ck_discovery_observation_observed_state",
        "ck_discovery_observation_verification_state",
        "ck_discovery_observation_source_trust",
        "ck_discovery_observation_evidence_mode",
        "ck_discovery_observation_evidence_mutability",
        "ck_discovery_observation_contradiction_state",
        "ck_discovery_observation_evidence_hash", "ck_discovery_observation_idempotency_key",
        "ck_discovery_observation_payload_digest",
    },
}

CHECK_SQL = {
    "discovery_scans": {
        "ck_discovery_scan_type":
            "scan_type IN ('full_enterprise','targeted','incremental','verification','scheduled','collector_specific')",
        "ck_discovery_scan_status":
            "status IN ('queued','running','partially_complete','complete','failed','cancelled')",
        "ck_discovery_scan_counters":
            "observations_count >= 0 AND assets_created >= 0 AND assets_updated >= 0 AND assets_unresolved >= 0",
        "ck_discovery_scan_request_digest": _portable_hash_check("request_digest"),
        "ck_discovery_scan_not_self_rescan":
            "rescan_of_scan_id IS NULL OR rescan_of_scan_id <> scan_id",
        "ck_discovery_scan_lifecycle":
            "(status = 'queued' AND started_at IS NULL AND completed_at IS NULL AND cancelled_at IS NULL) OR "
            "(status = 'running' AND started_at IS NOT NULL AND completed_at IS NULL AND cancelled_at IS NULL) OR "
            "(status IN ('complete','partially_complete') AND started_at IS NOT NULL AND completed_at IS NOT NULL "
            "AND cancelled_at IS NULL) OR (status = 'failed' AND completed_at IS NOT NULL AND cancelled_at IS NULL) OR "
            "(status = 'cancelled' AND completed_at IS NULL AND cancelled_at IS NOT NULL)",
    },
    "discovery_targets": {
        "ck_discovery_target_type":
            "target_type IN ('endpoint_group','browser_tenant','cloud_subscription','cloud_project','kubernetes_cluster',"
            "'saas_tenant','identity_tenant','repository_org','repository','network_range','dns_domain','api_gateway',"
            "'database_platform','ai_provider_account','mcp_environment','llm_gateway','runtime_environment')",
        "ck_discovery_target_rate_limit": "rate_limit >= 1 AND rate_limit <= 10000",
    },
    "discovery_collectors": {
        "ck_discovery_collector_health":
            "health IN ('healthy','warning','degraded','offline','unknown')",
        "ck_discovery_collector_control_capability":
            "control_capability IN ('inline','warn_only','monitor_only','external_required','unknown')",
        "ck_discovery_collector_declaration_hash": _portable_hash_check("declaration_hash"),
    },
    "discovery_scan_targets": {},
    "discovery_scan_assignments": {
        "ck_discovery_assignment_status":
            "status IN ('pending','running','complete','failed','cancelled','unsupported','permission_denied',"
            "'rate_limited','stale','empty')",
        "ck_discovery_assignment_observations_count": "observations_count >= 0",
        "ck_discovery_assignment_lifecycle":
            "(status = 'pending' AND started_at IS NULL AND completed_at IS NULL) OR "
            "(status = 'running' AND started_at IS NOT NULL AND completed_at IS NULL) OR "
            "(status IN ('complete','failed','cancelled','unsupported','permission_denied','rate_limited','stale','empty') "
            "AND completed_at IS NOT NULL)",
    },
    "discovery_observations": {
        "ck_discovery_observation_confidence": "confidence >= 0.0 AND confidence <= 1.0",
        "ck_discovery_observation_freshness": "freshness IN ('fresh','stale','expired','unknown')",
        "ck_discovery_observation_source_surface": (
            "source_surface IN ('endpoint','browser','cloud','saas','identity',"
            "'source_code','ci_cd','network','dns','api_gateway','service_mesh',"
            "'mcp','database','vector_store','model_endpoint','runtime',"
            "'kubernetes','container','unknown')"
        ),
        "ck_discovery_observation_observed_state": (
            "observed_state IN ('installed','configured','enabled','reachable',"
            "'observed','actively_used','inferred','unknown')"
        ),
        "ck_discovery_observation_verification_state": (
            "verification_state IN ('verified','partially_verified','inferred',"
            "'contradicted','stale','unknown')"
        ),
        "ck_discovery_observation_source_trust": (
            "source_trust IN ('strong','medium','weak','unknown')"
        ),
        "ck_discovery_observation_evidence_mode": (
            "evidence_mode IN ('direct','inferred','unknown')"
        ),
        "ck_discovery_observation_evidence_mutability": (
            "evidence_mutability IN ('immutable','mutable','unknown')"
        ),
        "ck_discovery_observation_contradiction_state": (
            "contradiction_state IN ('none','supported','contradicted',"
            "'unresolved','unknown')"
        ),
        "ck_discovery_observation_evidence_hash": _portable_hash_check("evidence_hash"),
        "ck_discovery_observation_idempotency_key": _portable_hash_check("idempotency_key"),
        "ck_discovery_observation_payload_digest": _portable_hash_check("payload_digest"),
    },
}

FOREIGN_KEYS = {
    "discovery_scans": {
        (None, ("tenant_id",), ("tenants.id",), "CASCADE"),
        (None, ("requested_by",), ("users.id",), "SET NULL"),
        ("fk_discovery_scan_tenant_rescan", ("tenant_id", "rescan_of_scan_id"),
         ("discovery_scans.tenant_id", "discovery_scans.scan_id"), "RESTRICT"),
        ("fk_discovery_scan_tenant_evidence_bundle", ("tenant_id", "evidence_bundle_id"),
         ("evidence_nodes.tenant_id", "evidence_nodes.id"), "RESTRICT"),
    },
    "discovery_targets": {(None, ("tenant_id",), ("tenants.id",), "CASCADE")},
    "discovery_collectors": {(None, ("tenant_id",), ("tenants.id",), "CASCADE")},
    "discovery_scan_targets": {
        (None, ("tenant_id",), ("tenants.id",), "CASCADE"),
        ("fk_discovery_scan_target_tenant_scan", ("tenant_id", "scan_id"),
         ("discovery_scans.tenant_id", "discovery_scans.scan_id"), "CASCADE"),
        ("fk_discovery_scan_target_tenant_target", ("tenant_id", "target_id"),
         ("discovery_targets.tenant_id", "discovery_targets.target_id"), "RESTRICT"),
    },
    "discovery_scan_assignments": {
        (None, ("tenant_id",), ("tenants.id",), "CASCADE"),
        ("fk_discovery_assignment_tenant_scan_target", ("tenant_id", "scan_id", "target_id"),
         ("discovery_scan_targets.tenant_id", "discovery_scan_targets.scan_id",
          "discovery_scan_targets.target_id"), "CASCADE"),
        ("fk_discovery_assignment_tenant_collector", ("tenant_id", "collector_id"),
         ("discovery_collectors.tenant_id", "discovery_collectors.collector_id"), "RESTRICT"),
    },
    "discovery_observations": {
        (None, ("tenant_id",), ("tenants.id",), "CASCADE"),
        ("fk_discovery_observation_tenant_scan", ("tenant_id", "scan_id"),
         ("discovery_scans.tenant_id", "discovery_scans.scan_id"), "RESTRICT"),
        ("fk_discovery_observation_tenant_target", ("tenant_id", "target_id"),
         ("discovery_targets.tenant_id", "discovery_targets.target_id"), "RESTRICT"),
        ("fk_discovery_observation_tenant_collector", ("tenant_id", "collector_id"),
         ("discovery_collectors.tenant_id", "discovery_collectors.collector_id"), "RESTRICT"),
        ("fk_discovery_observation_assignment_tuple",
         ("tenant_id", "assignment_id", "scan_id", "target_id", "collector_id"),
         ("discovery_scan_assignments.tenant_id", "discovery_scan_assignments.assignment_id",
          "discovery_scan_assignments.scan_id", "discovery_scan_assignments.target_id",
          "discovery_scan_assignments.collector_id"), "RESTRICT"),
    },
}

SERVER_DEFAULTS = {
    "discovery_scans": {
        "status": "queued", "dry_run": "false", "observations_count": "0",
        "assets_created": "0", "assets_updated": "0", "assets_unresolved": "0",
        "warnings_json": "[]", "errors_json": "[]", "coverage_summary_json": "{}",
    },
    "discovery_targets": {"exclusions_json": "[]", "active_scan_allowed": "false", "sensitive_scope": "false"},
    "discovery_collectors": {},
    "discovery_scan_targets": {},
    "discovery_scan_assignments": {"status": "pending", "observations_count": "0"},
    "discovery_observations": {},
}


def _load_exported_models() -> tuple[object, dict[str, type]]:
    module = import_module("app.db.models.discovery_canonical")
    from app.db.models import (
        DiscoveryCollector,
        DiscoveryObservation,
        DiscoveryScan,
        DiscoveryScanAssignment,
        DiscoveryScanTarget,
        DiscoveryTarget,
    )

    exported = {
        "discovery_scans": DiscoveryScan,
        "discovery_targets": DiscoveryTarget,
        "discovery_collectors": DiscoveryCollector,
        "discovery_scan_targets": DiscoveryScanTarget,
        "discovery_scan_assignments": DiscoveryScanAssignment,
        "discovery_observations": DiscoveryObservation,
    }
    return module, exported


def _load_tables() -> dict[str, sa.Table]:
    _module, models = _load_exported_models()

    return {name: model.__table__ for name, model in models.items()}


def _default_text(column: sa.Column) -> str:
    assert column.server_default is not None
    return str(column.server_default.arg).lower().replace("'", "").replace("::json", "")


def _normalized_sql(value: object) -> str:
    return " ".join(str(value).split())


def test_canonical_module_exports_and_registers_exactly_six_models() -> None:
    module, exported = _load_exported_models()
    from app.db.session import Base

    declared = {
        value.__table__.name: value
        for value in vars(module).values()
        if isinstance(value, type)
        and value.__module__ == module.__name__
        and hasattr(value, "__table__")
    }
    assert set(declared) == set(TABLE_MODELS)
    assert {name: model.__name__ for name, model in declared.items()} == TABLE_MODELS
    assert exported == declared
    assert set(TABLE_MODELS) <= set(Base.metadata.tables)
    assert all(Base.metadata.tables[name] is declared[name].__table__ for name in TABLE_MODELS)


def test_0047_columns_types_lengths_nullability_and_server_defaults_are_preserved() -> None:
    for table_name, table in _load_tables().items():
        expected = COLUMNS[table_name]
        assert set(expected) <= set(table.c.keys())
        for column_name, (type_class, length, nullable) in expected.items():
            column = table.c[column_name]
            assert isinstance(column.type, type_class), (table_name, column_name, column.type)
            assert getattr(column.type, "length", None) == length
            assert column.nullable is nullable
            if isinstance(column.type, sa.DateTime):
                assert column.type.timezone is True

        expected_defaults = {**SERVER_DEFAULTS[table_name], "created_at": "now()", "updated_at": "now()"}
        actual_default_columns = {
            column.name
            for column in table.c
            if column.name in expected and column.server_default is not None
        }
        assert actual_default_columns == set(expected_defaults)
        for column_name, value in expected_defaults.items():
            assert _default_text(table.c[column_name]) == value


def test_all_six_models_use_timestamp_mixin_and_never_generate_id() -> None:
    _module, models = _load_exported_models()
    from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin

    for table_name, model in models.items():
        assert TimestampMixin in model.__mro__
        assert UUIDPrimaryKeyMixin not in model.__mro__
        assert "id" not in model.__table__.c
        assert tuple(column.name for column in model.__table__.primary_key) == PRIMARY_KEYS[table_name]
        assert model.__table__.c.created_at.onupdate is None
        assert model.__table__.c.updated_at.onupdate is not None
        assert _normalized_sql(model.__table__.c.updated_at.onupdate.arg).lower() == "now()"


def test_unique_check_and_foreign_key_contracts_match_current_discovery_schema() -> None:
    for table_name, table in _load_tables().items():
        uniques = {
            constraint.name: tuple(column.name for column in constraint.columns)
            for constraint in table.constraints
            if isinstance(constraint, sa.UniqueConstraint)
        }
        checks = {
            constraint.name: _normalized_sql(constraint.sqltext)
            for constraint in table.constraints
            if isinstance(constraint, sa.CheckConstraint)
        }
        foreign_keys = {
            (
                constraint.name,
                tuple(element.parent.name for element in constraint.elements),
                tuple(element.target_fullname for element in constraint.elements),
                constraint.ondelete,
            )
            for constraint in table.foreign_key_constraints
        }
        assert uniques == UNIQUES[table_name]
        assert set(checks) == CHECKS[table_name]
        assert checks == {
            name: _normalized_sql(sqltext)
            for name, sqltext in CHECK_SQL[table_name].items()
        }
        assert foreign_keys == FOREIGN_KEYS[table_name]


def test_indexes_match_discovery_migration_manifests_and_are_tenant_first() -> None:
    migration = import_module("app.db.migrations.versions.0047_discovery_scan_observations")
    truth_migration = import_module(
        "app.db.migrations.versions.0054_discovery_observation_truth"
    )
    expected = {
        table_name: {
            index_name: tuple(column_names)
            for index_name, index_table, column_names in migration.INDEXES
            if index_table == table_name
        }
        for table_name in TABLE_MODELS
    }
    expected["discovery_observations"].update(
        {
            index_name: tuple(columns)
            for index_name, columns in truth_migration._INDEXES
        }
    )
    for table_name, table in _load_tables().items():
        actual = {
            index.name: tuple(column.name for column in index.columns)
            for index in table.indexes
        }
        assert actual == expected[table_name]
        assert all(columns[0] == "tenant_id" for columns in actual.values())
        assert all(index.unique is False for index in table.indexes)


def test_all_six_tables_compile_portably_for_postgresql() -> None:
    from sqlalchemy.dialects import postgresql
    from sqlalchemy.schema import CreateTable

    tables = _load_tables()
    ddl_by_table = {
        name: str(CreateTable(table).compile(dialect=postgresql.dialect()))
        for name, table in tables.items()
    }
    combined = "\n".join(ddl_by_table.values())

    assert re.search(r"\bGLOB\b", combined, flags=re.IGNORECASE) is None
    hash_constraints = {
        "ck_discovery_scan_request_digest",
        "ck_discovery_collector_declaration_hash",
        "ck_discovery_observation_evidence_hash",
        "ck_discovery_observation_idempotency_key",
        "ck_discovery_observation_payload_digest",
    }
    assert all(f"CONSTRAINT {name}" in combined for name in hash_constraints)

    for table_name, table in tables.items():
        ddl = ddl_by_table[table_name]
        for column in table.c:
            if isinstance(column.type, sa.DateTime):
                assert re.search(
                    rf"\b{re.escape(column.name)}\s+TIMESTAMP WITH TIME ZONE\b",
                    ddl,
                    flags=re.IGNORECASE,
                )
            if column.server_default is not None:
                assert re.search(
                    rf"\b{re.escape(column.name)}\b[^,]*\bDEFAULT\b",
                    ddl,
                    flags=re.IGNORECASE,
                )


def test_json_columns_keep_approved_physical_names() -> None:
    for table_name, table in _load_tables().items():
        expected_json = {
            name for name, (type_class, _length, _nullable) in COLUMNS[table_name].items()
            if type_class is sa.JSON
        }
        actual_json = {column.name for column in table.c if isinstance(column.type, sa.JSON)}
        assert expected_json <= actual_json
        assert all(name.endswith("_json") for name in actual_json)
