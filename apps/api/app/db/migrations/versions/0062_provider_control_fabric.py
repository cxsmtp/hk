"""Persist deployment-bound Provider Control Fabric acceptance.

Revision ID: 0062_provider_control_fabric
Revises: 0061_autonomous_discovery_verification
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0062_provider_control_fabric"
down_revision = "0061_autonomous_discovery_verification"
branch_labels = None
depends_on = None


ACCEPTANCE_STATES = (
    "REAL_BINARY_ACCEPTED",
    "REAL_ENTERPRISE_TENANT_ACCEPTED",
    "REAL_CLOUD_RUNTIME_ACCEPTED",
    "SYNTHETIC_ONLY",
    "DOCS_ONLY",
    "NOT_TESTED",
)
REAL_ACCEPTANCE_STATES = ACCEPTANCE_STATES[:3]
HEALTH_STATES = (
    "healthy",
    "degraded",
    "unhealthy",
    "unverified",
    "version_mismatch",
    "tampered",
    "policy_stale",
    "not_installed",
    "unknown",
)
EXECUTION_LOCATIONS = (
    "LOCAL_ENDPOINT",
    "CUSTOMER_RUNTIME",
    "CUSTOMER_CLOUD",
    "PROVIDER_HOSTED",
    "REMOTE_AGENT",
    "MIXED",
    "UNKNOWN",
)
REAL_ACCEPTANCE_RUNTIME_LOCATIONS = {
    "REAL_BINARY_ACCEPTED": ("LOCAL_ENDPOINT",),
    "REAL_ENTERPRISE_TENANT_ACCEPTED": ("PROVIDER_HOSTED", "REMOTE_AGENT"),
    "REAL_CLOUD_RUNTIME_ACCEPTED": ("CUSTOMER_RUNTIME", "CUSTOMER_CLOUD", "MIXED"),
}
REAL_VALIDATION_SCOPE_TEXT_FIELDS = (
    "deployment_environment",
    "provider",
    "product",
    "runtime",
    "model_provider",
    "model",
    "route_identity",
    "deployment_identity",
    "deployment_reference",
    "acceptance_run_id",
    "provider_version",
    "adapter_version",
)
REAL_VALIDATION_ARRAY_LIMITS = {
    "action_classes": 256,
    "control_methods": 256,
    "lifecycle_events": 256,
    "evidence_refs": 1024,
}


def _dialect() -> str:
    value = op.get_bind().dialect.name
    if value not in {"sqlite", "postgresql"}:
        raise RuntimeError(f"Unsupported dialect: {value}")
    return value


def _json_default(value: str, dialect: str) -> sa.TextClause:
    return sa.text(f"'{value}'{'::json' if dialect == 'postgresql' else ''}")


def _hash_check(column: str, dialect: str) -> str:
    del dialect
    remaining = column
    for character in "0123456789abcdef":
        remaining = f"replace({remaining}, '{character}', '')"
    return (
        f"{column} IS NULL OR (length({column}) = 64 AND {column} = lower({column}) "
        f"AND length({remaining}) = 0)"
    )


def _state_list(states: tuple[str, ...]) -> str:
    return ",".join(f"'{state}'" for state in states)


def _known_scope_text_check(column: str) -> str:
    return (
        f"{column} IS NOT NULL AND trim({column}) <> '' "
        f"AND lower(trim({column})) <> 'unknown'"
    )


def _real_state_location_check() -> str:
    allowed = " OR ".join(
        "(acceptance_state = "
        f"'{state}' AND execution_location IN ({_state_list(locations)}))"
        for state, locations in REAL_ACCEPTANCE_RUNTIME_LOCATIONS.items()
    )
    return f"acceptance_state NOT IN ({_state_list(REAL_ACCEPTANCE_STATES)}) OR ({allowed})"


def _real_scope_check() -> str:
    text_fields = " AND ".join(
        _known_scope_text_check(field)
        for field in REAL_VALIDATION_SCOPE_TEXT_FIELDS
    )
    arrays = " AND ".join(
        f"length(CAST({field} AS TEXT)) > 2"
        for field in REAL_VALIDATION_ARRAY_LIMITS
    )
    return (
        f"acceptance_state NOT IN ({_state_list(REAL_ACCEPTANCE_STATES)}) OR ("
        f"safe_synthetic = false AND {text_fields} AND execution_location <> 'UNKNOWN' "
        f"AND contract_hash IS NOT NULL AND {arrays} "
        "AND result = 'passed' AND allow_result = 'passed' AND block_result = 'passed' "
        "AND non_execution_result = 'passed')"
    )


def _sqlite_whitespace_stripped(expression: str) -> str:
    return (
        "trim(replace(replace(replace(coalesce("
        f"{expression}, ''), char(9), ''), char(10), ''), char(13), ''))"
    )


def _sqlite_scope_text_invalid(expression: str) -> str:
    normalized = _sqlite_whitespace_stripped(expression)
    return f"length({normalized}) = 0 OR lower({normalized}) = 'unknown'"


def _sqlite_scope_array_invalid(column: str, maximum: int) -> str:
    return (
        f"json_valid(NEW.{column}) = 0 OR json_type(NEW.{column}) <> 'array' "
        f"OR json_array_length(NEW.{column}) = 0 OR EXISTS ("
        f"SELECT 1 FROM json_each(NEW.{column}) "
        f"WHERE type <> 'text' OR length({_sqlite_whitespace_stripped('value')}) = 0 "
        f"OR length(value) > {maximum})"
    )


def _sqlite_scope_guard_condition() -> str:
    invalid_text = " OR ".join(
        _sqlite_scope_text_invalid(f"NEW.{field}")
        for field in REAL_VALIDATION_SCOPE_TEXT_FIELDS
    )
    invalid_arrays = " OR ".join(
        _sqlite_scope_array_invalid(field, maximum)
        for field, maximum in REAL_VALIDATION_ARRAY_LIMITS.items()
    )
    location_match = _real_state_location_check().replace(
        "acceptance_state", "NEW.acceptance_state"
    ).replace("execution_location", "NEW.execution_location")
    return (
        f"({invalid_text}) OR ({invalid_arrays}) "
        "OR NEW.safe_synthetic <> 0 OR NEW.result <> 'passed' "
        "OR NEW.allow_result <> 'passed' OR NEW.block_result <> 'passed' "
        "OR NEW.non_execution_result <> 'passed' OR NEW.contract_hash IS NULL "
        f"OR NOT ({location_match})"
    )


def _postgres_whitespace_stripped(expression: str) -> str:
    return (
        "btrim(replace(replace(replace(coalesce("
        f"{expression}, ''), chr(9), ''), chr(10), ''), chr(13), ''))"
    )


def _postgres_scope_array_invalid(column: str, maximum: int) -> str:
    value = "item.value #>> '{}'"
    return (
        f"jsonb_typeof(NEW.{column}::jsonb) <> 'array' "
        f"OR jsonb_array_length(NEW.{column}::jsonb) = 0 OR EXISTS ("
        f"SELECT 1 FROM jsonb_array_elements(NEW.{column}::jsonb) AS item(value) "
        f"WHERE jsonb_typeof(item.value) <> 'string' "
        f"OR length({_postgres_whitespace_stripped(value)}) = 0 "
        f"OR length({value}) > {maximum})"
    )


def _add_profile_columns(dialect: str) -> None:
    op.add_column(
        "control_capability_profiles",
        sa.Column("runtime", sa.String(length=128), nullable=False, server_default="unknown"),
    )
    op.add_column(
        "control_capability_profiles",
        sa.Column(
            "supported_action_classes",
            sa.JSON(),
            nullable=False,
            server_default=_json_default("[]", dialect),
        ),
    )
    op.add_column(
        "control_capability_profiles",
        sa.Column(
            "supported_control_methods",
            sa.JSON(),
            nullable=False,
            server_default=_json_default("[]", dialect),
        ),
    )
    op.add_column(
        "control_capability_profiles",
        sa.Column("contract_hash", sa.String(length=64), nullable=True),
    )


def _add_integration_columns() -> None:
    op.add_column(
        "native_control_integrations",
        sa.Column(
            "model_provider",
            sa.String(length=128),
            nullable=False,
            server_default="unknown",
        ),
    )
    op.add_column(
        "native_control_integrations",
        sa.Column(
            "model",
            sa.String(length=255),
            nullable=False,
            server_default="unknown",
        ),
    )
    op.add_column(
        "native_control_integrations",
        sa.Column("runtime", sa.String(length=128), nullable=False, server_default="unknown"),
    )
    op.add_column(
        "native_control_integrations",
        sa.Column(
            "execution_location",
            sa.String(length=32),
            nullable=False,
            server_default="UNKNOWN",
        ),
    )
    op.add_column(
        "native_control_integrations",
        sa.Column(
            "deployment_reference",
            sa.String(length=255),
            nullable=False,
            server_default="unknown",
        ),
    )
    op.add_column(
        "native_control_integrations",
        sa.Column("contract_hash", sa.String(length=64), nullable=True),
    )


def _add_validation_columns(dialect: str) -> None:
    columns: tuple[sa.Column[object], ...] = (
        sa.Column(
            "acceptance_state",
            sa.String(length=40),
            nullable=False,
            server_default="NOT_TESTED",
        ),
        sa.Column(
            "deployment_environment",
            sa.String(length=64),
            nullable=False,
            server_default="unknown",
        ),
        sa.Column("provider", sa.String(length=64), nullable=False, server_default="unknown"),
        sa.Column("product", sa.String(length=128), nullable=False, server_default="unknown"),
        sa.Column("runtime", sa.String(length=128), nullable=False, server_default="unknown"),
        sa.Column("model_provider", sa.String(length=128), nullable=False, server_default="unknown"),
        sa.Column("model", sa.String(length=255), nullable=False, server_default="unknown"),
        sa.Column("route_identity", sa.String(length=255), nullable=False, server_default="unknown"),
        sa.Column("deployment_identity", sa.String(length=255), nullable=False, server_default="unknown"),
        sa.Column(
            "execution_location",
            sa.String(length=32),
            nullable=False,
            server_default="UNKNOWN",
        ),
        sa.Column(
            "deployment_reference",
            sa.String(length=255),
            nullable=False,
            server_default="unknown",
        ),
        sa.Column("action_classes", sa.JSON(), nullable=False, server_default=_json_default("[]", dialect)),
        sa.Column("control_methods", sa.JSON(), nullable=False, server_default=_json_default("[]", dialect)),
        sa.Column("lifecycle_events", sa.JSON(), nullable=False, server_default=_json_default("[]", dialect)),
        sa.Column("provider_version", sa.String(length=64), nullable=True),
        sa.Column("adapter_version", sa.String(length=64), nullable=True),
        sa.Column("contract_hash", sa.String(length=64), nullable=True),
        sa.Column("acceptance_run_id", sa.String(length=128), nullable=True),
        sa.Column(
            "allow_result",
            sa.String(length=16),
            nullable=False,
            server_default="not_tested",
        ),
        sa.Column(
            "block_result",
            sa.String(length=16),
            nullable=False,
            server_default="not_tested",
        ),
        sa.Column(
            "non_execution_result",
            sa.String(length=16),
            nullable=False,
            server_default="not_tested",
        ),
    )
    for column in columns:
        op.add_column("native_control_validations", column)


def _backfill_validation_scope() -> None:
    op.execute(
        "UPDATE native_control_validations "
        "SET acceptance_state = CASE "
        "WHEN safe_synthetic = true THEN 'SYNTHETIC_ONLY' "
        "ELSE 'NOT_TESTED' END"
    )
    op.execute(
        "UPDATE native_control_validations AS validation "
        "SET deployment_environment = COALESCE(("
        "SELECT integration.environment FROM native_control_integrations AS integration "
        "WHERE integration.tenant_id = validation.tenant_id "
        "AND integration.id = validation.integration_instance_id"
        "), 'unknown'), "
        "provider = COALESCE(("
        "SELECT integration.provider FROM native_control_integrations AS integration "
        "WHERE integration.tenant_id = validation.tenant_id "
        "AND integration.id = validation.integration_instance_id"
        "), 'unknown'), "
        "product = COALESCE(("
        "SELECT integration.product FROM native_control_integrations AS integration "
        "WHERE integration.tenant_id = validation.tenant_id "
        "AND integration.id = validation.integration_instance_id"
        "), 'unknown'), "
        "provider_version = ("
        "SELECT integration.provider_version FROM native_control_integrations AS integration "
        "WHERE integration.tenant_id = validation.tenant_id "
        "AND integration.id = validation.integration_instance_id"
        "), "
        "adapter_version = ("
        "SELECT integration.adapter_version FROM native_control_integrations AS integration "
        "WHERE integration.tenant_id = validation.tenant_id "
        "AND integration.id = validation.integration_instance_id"
        ")"
    )


def _profile_constraints(dialect: str) -> tuple[tuple[str, str], ...]:
    return (
        ("ck_control_profile_contract_hash", _hash_check("contract_hash", dialect)),
        (
            "ck_control_profile_action_classes_bytes",
            "length(CAST(supported_action_classes AS TEXT)) <= 8192",
        ),
        (
            "ck_control_profile_control_methods_bytes",
            "length(CAST(supported_control_methods AS TEXT)) <= 8192",
        ),
    )


def _integration_constraints(dialect: str) -> tuple[tuple[str, str], ...]:
    return (
        (
            "ck_native_integration_health",
            f"health_state IN ({_state_list(HEALTH_STATES)})",
        ),
        (
            "ck_native_integration_execution_location",
            f"execution_location IN ({_state_list(EXECUTION_LOCATIONS)})",
        ),
        ("ck_native_integration_contract_hash", _hash_check("contract_hash", dialect)),
    )


def _validation_constraints(dialect: str) -> tuple[tuple[str, str], ...]:
    real_states = _state_list(REAL_ACCEPTANCE_STATES)
    acceptance_states = _state_list(ACCEPTANCE_STATES)
    execution_locations = _state_list(EXECUTION_LOCATIONS)
    return (
        (
            "ck_native_validation_acceptance_state",
            f"acceptance_state IN ({acceptance_states})",
        ),
        (
            "ck_native_validation_execution_location",
            f"execution_location IN ({execution_locations})",
        ),
        (
            "ck_native_validation_acceptance_results",
            "allow_result IN ('passed','failed','not_tested','not_applicable') "
            "AND block_result IN ('passed','failed','not_tested','not_applicable') "
            "AND non_execution_result IN ('passed','failed','not_tested','not_applicable')",
        ),
        (
            "ck_native_validation_real_not_synthetic",
            f"acceptance_state NOT IN ({real_states}) OR safe_synthetic = false",
        ),
        (
            "ck_native_validation_real_scope",
            _real_scope_check(),
        ),
        (
            "ck_native_validation_real_state_location",
            _real_state_location_check(),
        ),
        ("ck_native_validation_contract_hash", _hash_check("contract_hash", dialect)),
        (
            "ck_native_validation_scope_bytes",
            "length(CAST(action_classes AS TEXT)) <= 8192 "
            "AND length(CAST(control_methods AS TEXT)) <= 8192 "
            "AND length(CAST(lifecycle_events AS TEXT)) <= 8192 "
            "AND length(CAST(evidence_refs AS TEXT)) <= 8192",
        ),
    )


def _create_validation_immutability_triggers(dialect: str) -> None:
    if dialect == "sqlite":
        for action in ("update", "delete"):
            op.execute(
                f"CREATE TRIGGER trg_native_validation_immutable_{action} "
                f"BEFORE {action.upper()} ON native_control_validations "
                "BEGIN SELECT RAISE(ABORT, 'immutable_table:native_control_validations'); END"
            )
        return
    op.execute(
        "CREATE TRIGGER trg_native_validation_immutable "
        "BEFORE UPDATE OR DELETE ON native_control_validations "
        "FOR EACH ROW EXECUTE FUNCTION deny_immutable_table_mutation()"
    )


def _drop_validation_immutability_triggers(dialect: str) -> None:
    if dialect == "sqlite":
        for action in ("update", "delete"):
            op.execute(f"DROP TRIGGER IF EXISTS trg_native_validation_immutable_{action}")
        return
    op.execute("DROP TRIGGER IF EXISTS trg_native_validation_immutable ON native_control_validations")


def _create_validation_scope_guards(dialect: str) -> None:
    if dialect == "sqlite":
        op.execute(
            "CREATE TRIGGER trg_native_validation_scope_guard_insert "
            "BEFORE INSERT ON native_control_validations "
            f"WHEN NEW.acceptance_state IN ({_state_list(REAL_ACCEPTANCE_STATES)}) "
            f"AND ({_sqlite_scope_guard_condition()}) "
            "BEGIN SELECT RAISE(ABORT, 'native_control_validation_real_scope_invalid'); END"
        )
        return

    invalid_text = " OR ".join(
        f"length({_postgres_whitespace_stripped(f'NEW.{field}')}) = 0 "
        f"OR lower({_postgres_whitespace_stripped(f'NEW.{field}')}) = 'unknown'"
        for field in REAL_VALIDATION_SCOPE_TEXT_FIELDS
    )
    invalid_arrays = " OR ".join(
        _postgres_scope_array_invalid(field, maximum)
        for field, maximum in REAL_VALIDATION_ARRAY_LIMITS.items()
    )
    location_match = _real_state_location_check().replace(
        "acceptance_state", "NEW.acceptance_state"
    ).replace("execution_location", "NEW.execution_location")
    op.execute(
        "CREATE FUNCTION hawk_validate_native_control_validation_scope() "
        "RETURNS trigger AS $$ BEGIN "
        f"IF NEW.acceptance_state IN ({_state_list(REAL_ACCEPTANCE_STATES)}) AND ("
        f"({invalid_text}) OR ({invalid_arrays}) "
        "OR NEW.safe_synthetic <> false OR NEW.result <> 'passed' "
        "OR NEW.allow_result <> 'passed' OR NEW.block_result <> 'passed' "
        "OR NEW.non_execution_result <> 'passed' OR NEW.contract_hash IS NULL "
        f"OR NOT ({location_match})"
        ") THEN RAISE EXCEPTION 'native_control_validation_real_scope_invalid'; END IF; "
        "RETURN NEW; END; $$ LANGUAGE plpgsql"
    )
    op.execute(
        "CREATE TRIGGER trg_native_validation_scope_guard "
        "BEFORE INSERT OR UPDATE ON native_control_validations "
        "FOR EACH ROW EXECUTE FUNCTION hawk_validate_native_control_validation_scope()"
    )


def _drop_validation_scope_guards(dialect: str) -> None:
    if dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS trg_native_validation_scope_guard_insert")
        return
    op.execute("DROP TRIGGER IF EXISTS trg_native_validation_scope_guard ON native_control_validations")
    op.execute("DROP FUNCTION IF EXISTS hawk_validate_native_control_validation_scope()")


def _create_constraints(dialect: str) -> None:
    profile_constraints = _profile_constraints(dialect)
    integration_constraints = _integration_constraints(dialect)
    validation_constraints = _validation_constraints(dialect)
    if dialect == "sqlite":
        with op.batch_alter_table(
            "control_capability_profiles",
            recreate="always",
            reflect_kwargs={"resolve_fks": False},
        ) as batch:
            for name, condition in profile_constraints:
                batch.create_check_constraint(name, condition)
        with op.batch_alter_table(
            "native_control_integrations",
            recreate="always",
            reflect_kwargs={"resolve_fks": False},
        ) as batch:
            batch.drop_constraint("ck_native_integration_health", type_="check")
            for name, condition in integration_constraints:
                batch.create_check_constraint(name, condition)
        with op.batch_alter_table(
            "native_control_validations",
            recreate="always",
            reflect_kwargs={"resolve_fks": False},
        ) as batch:
            for name, condition in validation_constraints:
                batch.create_check_constraint(name, condition)
            batch.create_unique_constraint(
                "uq_native_validation_tenant_acceptance_run",
                ["tenant_id", "integration_instance_id", "acceptance_run_id"],
            )
        return

    for name, condition in profile_constraints:
        op.create_check_constraint(name, "control_capability_profiles", condition)
    op.drop_constraint("ck_native_integration_health", "native_control_integrations", type_="check")
    for name, condition in integration_constraints:
        op.create_check_constraint(name, "native_control_integrations", condition)
    for name, condition in validation_constraints:
        op.create_check_constraint(name, "native_control_validations", condition)
    op.create_unique_constraint(
        "uq_native_validation_tenant_acceptance_run",
        "native_control_validations",
        ["tenant_id", "integration_instance_id", "acceptance_run_id"],
    )


def upgrade() -> None:
    dialect = _dialect()
    _add_profile_columns(dialect)
    _add_integration_columns()
    _add_validation_columns(dialect)
    _backfill_validation_scope()
    _create_constraints(dialect)
    _create_validation_immutability_triggers(dialect)
    _create_validation_scope_guards(dialect)


def _drop_constraints(dialect: str) -> None:
    profile_constraints = _profile_constraints(dialect)
    integration_constraints = _integration_constraints(dialect)
    validation_constraints = _validation_constraints(dialect)
    original_health = (
        "health_state IN ('healthy','degraded','unhealthy','unverified',"
        "'version_mismatch','tampered')"
    )
    # The prior revision cannot represent these conservative health facts. A
    # deliberate downgrade therefore maps them to its only truthful legacy
    # non-green state before restoring the former closed constraint.
    op.execute(
        "UPDATE native_control_integrations SET health_state = 'unverified' "
        "WHERE health_state IN ('policy_stale','not_installed','unknown')"
    )
    if dialect == "sqlite":
        with op.batch_alter_table(
            "native_control_validations",
            recreate="always",
            reflect_kwargs={"resolve_fks": False},
        ) as batch:
            batch.drop_constraint("uq_native_validation_tenant_acceptance_run", type_="unique")
            for name, _condition in reversed(validation_constraints):
                batch.drop_constraint(name, type_="check")
        with op.batch_alter_table(
            "native_control_integrations",
            recreate="always",
            reflect_kwargs={"resolve_fks": False},
        ) as batch:
            for name, _condition in reversed(integration_constraints):
                batch.drop_constraint(name, type_="check")
            batch.create_check_constraint("ck_native_integration_health", original_health)
        with op.batch_alter_table(
            "control_capability_profiles",
            recreate="always",
            reflect_kwargs={"resolve_fks": False},
        ) as batch:
            for name, _condition in reversed(profile_constraints):
                batch.drop_constraint(name, type_="check")
        return

    op.drop_constraint(
        "uq_native_validation_tenant_acceptance_run",
        "native_control_validations",
        type_="unique",
    )
    for name, _condition in reversed(validation_constraints):
        op.drop_constraint(name, "native_control_validations", type_="check")
    for name, _condition in reversed(integration_constraints):
        op.drop_constraint(name, "native_control_integrations", type_="check")
    op.create_check_constraint(
        "ck_native_integration_health",
        "native_control_integrations",
        original_health,
    )
    for name, _condition in reversed(profile_constraints):
        op.drop_constraint(name, "control_capability_profiles", type_="check")


def downgrade() -> None:
    dialect = _dialect()
    _drop_validation_scope_guards(dialect)
    _drop_validation_immutability_triggers(dialect)
    _drop_constraints(dialect)
    if dialect == "sqlite":
        with op.batch_alter_table(
            "native_control_validations",
            recreate="always",
            reflect_kwargs={"resolve_fks": False},
        ) as batch:
            for column in (
                "non_execution_result",
                "block_result",
                "allow_result",
                "acceptance_run_id",
                "contract_hash",
                "adapter_version",
                "provider_version",
                "lifecycle_events",
                "control_methods",
                "action_classes",
                "deployment_reference",
                "execution_location",
                "deployment_identity",
                "route_identity",
                "model",
                "model_provider",
                "runtime",
                "product",
                "provider",
                "deployment_environment",
                "acceptance_state",
            ):
                batch.drop_column(column)
        with op.batch_alter_table(
            "native_control_integrations",
            recreate="always",
            reflect_kwargs={"resolve_fks": False},
        ) as batch:
            for column in (
                "contract_hash",
                "model",
                "model_provider",
                "deployment_reference",
                "execution_location",
                "runtime",
            ):
                batch.drop_column(column)
        with op.batch_alter_table(
            "control_capability_profiles",
            recreate="always",
            reflect_kwargs={"resolve_fks": False},
        ) as batch:
            for column in (
                "contract_hash",
                "supported_control_methods",
                "supported_action_classes",
                "runtime",
            ):
                batch.drop_column(column)
        return

    for column in (
        "non_execution_result",
        "block_result",
        "allow_result",
        "acceptance_run_id",
        "contract_hash",
        "adapter_version",
        "provider_version",
        "lifecycle_events",
        "control_methods",
        "action_classes",
        "deployment_reference",
        "execution_location",
        "deployment_identity",
        "route_identity",
        "model",
        "model_provider",
        "runtime",
        "product",
        "provider",
        "deployment_environment",
        "acceptance_state",
    ):
        op.drop_column("native_control_validations", column)
    for column in (
        "contract_hash",
        "model",
        "model_provider",
        "deployment_reference",
        "execution_location",
        "runtime",
    ):
        op.drop_column("native_control_integrations", column)
    for column in (
        "contract_hash",
        "supported_control_methods",
        "supported_action_classes",
        "runtime",
    ):
        op.drop_column("control_capability_profiles", column)
