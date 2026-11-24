"""Add evidence-backed Phase 2 discovery observation truth.

Revision ID: 0054_discovery_obs_truth
Revises: 0053_banking_execution_grants
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0054_discovery_obs_truth"
down_revision = "0053_banking_execution_grants"
branch_labels = None
depends_on = None


OBSERVATION_TRUTH_COLUMNS: tuple[str, ...] = (
    "source_surface",
    "subject_reference",
    "normalized_signal_json",
    "received_at",
    "observed_state",
    "verification_state",
    "source_trust",
    "collection_scope_json",
    "parser_version",
    "schema_version",
    "evidence_mode",
    "evidence_mutability",
    "contradiction_state",
    "contradiction_references_json",
)

REQUIRED_OBSERVATION_TRUTH_COLUMNS: tuple[str, ...] = tuple(
    column for column in OBSERVATION_TRUTH_COLUMNS if column != "subject_reference"
)

_CHECK_CONSTRAINTS: tuple[tuple[str, str], ...] = (
    (
        "ck_discovery_observation_source_surface",
        "source_surface IN ("
        "'endpoint','browser','cloud','saas','identity','source_code',"
        "'ci_cd','network','dns','api_gateway','service_mesh','mcp',"
        "'database','vector_store','model_endpoint','runtime',"
        "'kubernetes','container','unknown')",
    ),
    (
        "ck_discovery_observation_observed_state",
        "observed_state IN ("
        "'installed','configured','enabled','reachable','observed',"
        "'actively_used','inferred','unknown')",
    ),
    (
        "ck_discovery_observation_verification_state",
        "verification_state IN ("
        "'verified','partially_verified','inferred','contradicted',"
        "'stale','unknown')",
    ),
    (
        "ck_discovery_observation_source_trust",
        "source_trust IN ('strong','medium','weak','unknown')",
    ),
    (
        "ck_discovery_observation_evidence_mode",
        "evidence_mode IN ('direct','inferred','unknown')",
    ),
    (
        "ck_discovery_observation_evidence_mutability",
        "evidence_mutability IN ('immutable','mutable','unknown')",
    ),
    (
        "ck_discovery_observation_contradiction_state",
        "contradiction_state IN ("
        "'none','supported','contradicted','unresolved','unknown')",
    ),
)

_INDEXES: tuple[tuple[str, list[str]], ...] = (
    (
        "idx_discovery_observation_tenant_surface_time",
        ["tenant_id", "source_surface", "observed_at"],
    ),
    (
        "idx_discovery_observation_tenant_verification_time",
        ["tenant_id", "verification_state", "observed_at"],
    ),
)


def _dialect_name() -> str:
    name = op.get_bind().dialect.name
    if name not in {"sqlite", "postgresql"}:
        raise RuntimeError(f"Unsupported dialect: {name}")
    return name


def _json_default(value: str, dialect: str) -> sa.TextClause:
    suffix = "::json" if dialect == "postgresql" else ""
    return sa.text(f"'{value}'{suffix}")


def _drop_immutability_triggers(dialect: str) -> None:
    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS trg_discovery_observations_immutable "
            "ON discovery_observations"
        )
        return
    op.execute(
        "DROP TRIGGER IF EXISTS trg_discovery_observations_immutable_update"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trg_discovery_observations_immutable_delete"
    )


def _create_immutability_triggers(dialect: str) -> None:
    if dialect == "postgresql":
        op.execute(
            "CREATE TRIGGER trg_discovery_observations_immutable "
            "BEFORE UPDATE OR DELETE ON discovery_observations "
            "FOR EACH ROW EXECUTE FUNCTION deny_immutable_table_mutation()"
        )
        return
    op.execute(
        "CREATE TRIGGER trg_discovery_observations_immutable_update "
        "BEFORE UPDATE ON discovery_observations BEGIN "
        "SELECT RAISE(ABORT, 'immutable_table:discovery_observations'); END"
    )
    op.execute(
        "CREATE TRIGGER trg_discovery_observations_immutable_delete "
        "BEFORE DELETE ON discovery_observations BEGIN "
        "SELECT RAISE(ABORT, 'immutable_table:discovery_observations'); END"
    )


def _add_truth_columns(dialect: str) -> None:
    columns: tuple[sa.Column[object], ...] = (
        sa.Column(
            "source_surface",
            sa.String(length=32),
            server_default=sa.text("'unknown'"),
            nullable=False,
        ),
        sa.Column("subject_reference", sa.String(length=255), nullable=True),
        sa.Column(
            "normalized_signal_json",
            sa.JSON(),
            server_default=_json_default("{}", dialect),
            nullable=False,
        ),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "observed_state",
            sa.String(length=32),
            server_default=sa.text("'unknown'"),
            nullable=False,
        ),
        sa.Column(
            "verification_state",
            sa.String(length=32),
            server_default=sa.text("'unknown'"),
            nullable=False,
        ),
        sa.Column(
            "source_trust",
            sa.String(length=16),
            server_default=sa.text("'unknown'"),
            nullable=False,
        ),
        sa.Column(
            "collection_scope_json",
            sa.JSON(),
            server_default=_json_default("{}", dialect),
            nullable=False,
        ),
        sa.Column(
            "parser_version",
            sa.String(length=64),
            server_default=sa.text("'legacy-unknown'"),
            nullable=False,
        ),
        sa.Column(
            "schema_version",
            sa.String(length=32),
            server_default=sa.text("'1.0'"),
            nullable=False,
        ),
        sa.Column(
            "evidence_mode",
            sa.String(length=16),
            server_default=sa.text("'unknown'"),
            nullable=False,
        ),
        sa.Column(
            "evidence_mutability",
            sa.String(length=16),
            server_default=sa.text("'unknown'"),
            nullable=False,
        ),
        sa.Column(
            "contradiction_state",
            sa.String(length=32),
            server_default=sa.text("'unknown'"),
            nullable=False,
        ),
        sa.Column(
            "contradiction_references_json",
            sa.JSON(),
            server_default=_json_default("[]", dialect),
            nullable=False,
        ),
    )
    for column in columns:
        op.add_column("discovery_observations", column)


def _bind_constraints_and_received_at(dialect: str) -> None:
    if dialect == "sqlite":
        with op.batch_alter_table(
            "discovery_observations",
            recreate="always",
            reflect_kwargs={"resolve_fks": False},
        ) as batch_op:
            batch_op.alter_column(
                "received_at",
                existing_type=sa.DateTime(timezone=True),
                existing_nullable=True,
                nullable=False,
                server_default=sa.func.now(),
            )
            for name, condition in _CHECK_CONSTRAINTS:
                batch_op.create_check_constraint(name, condition)
        return

    op.alter_column(
        "discovery_observations",
        "received_at",
        existing_type=sa.DateTime(timezone=True),
        existing_nullable=True,
        nullable=False,
        server_default=sa.func.now(),
    )
    for name, condition in _CHECK_CONSTRAINTS:
        op.create_check_constraint(name, "discovery_observations", condition)


def upgrade() -> None:
    dialect = _dialect_name()
    _drop_immutability_triggers(dialect)
    _add_truth_columns(dialect)
    op.execute(
        "UPDATE discovery_observations SET received_at = created_at "
        "WHERE received_at IS NULL"
    )
    _bind_constraints_and_received_at(dialect)
    for index_name, columns in _INDEXES:
        op.create_index(index_name, "discovery_observations", columns)
    _create_immutability_triggers(dialect)


def downgrade() -> None:
    dialect = _dialect_name()
    _drop_immutability_triggers(dialect)
    for index_name, _columns in reversed(_INDEXES):
        op.drop_index(index_name, table_name="discovery_observations")

    if dialect == "sqlite":
        with op.batch_alter_table(
            "discovery_observations",
            recreate="always",
            reflect_kwargs={"resolve_fks": False},
        ) as batch_op:
            for name, _condition in reversed(_CHECK_CONSTRAINTS):
                batch_op.drop_constraint(name, type_="check")
            for column_name in reversed(OBSERVATION_TRUTH_COLUMNS):
                batch_op.drop_column(column_name)
    else:
        for name, _condition in reversed(_CHECK_CONSTRAINTS):
            op.drop_constraint(
                name, "discovery_observations", type_="check"
            )
        for column_name in reversed(OBSERVATION_TRUTH_COLUMNS):
            op.drop_column("discovery_observations", column_name)

    _create_immutability_triggers(dialect)
