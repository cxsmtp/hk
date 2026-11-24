"""Persist composed native semantic and endpoint control plans.

Revision ID: 0063_composed_control_plan_persistence
Revises: 0062_provider_control_fabric
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0063_composed_control_plan_persistence"
down_revision = "0062_provider_control_fabric"
branch_labels = None
depends_on = None


def _dialect() -> str:
    dialect = op.get_bind().dialect.name
    if dialect not in {"sqlite", "postgresql"}:
        raise RuntimeError(f"Unsupported dialect: {dialect}")
    return dialect


def _json_default(value: str, dialect: str) -> sa.TextClause:
    return sa.text(f"'{value}'{'::json' if dialect == 'postgresql' else ''}")


def _hash_check(column: str, dialect: str) -> str:
    if dialect == "postgresql":
        return f"{column} IS NULL OR {column} ~ '^[0-9a-f]{{64}}$'"
    return (
        f"{column} IS NULL OR (length({column}) = 64 "
        f"AND {column} NOT GLOB '*[^0-9a-f]*')"
    )


def _columns(dialect: str) -> tuple[sa.Column[object], ...]:
    return (
        sa.Column("canonical_action_hash", sa.String(length=64), nullable=True),
        sa.Column(
            "provider_runtime_context",
            sa.JSON(),
            nullable=False,
            server_default=_json_default("{}", dialect),
        ),
        sa.Column("provider_runtime_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("control_plan_id", sa.String(length=64), nullable=True),
        sa.Column("control_plan_digest", sa.String(length=64), nullable=True),
        sa.Column(
            "control_plan_material",
            sa.JSON(),
            nullable=False,
            server_default=_json_default("{}", dialect),
        ),
        sa.Column(
            "mandatory_enforcement_floor_requirements",
            sa.JSON(),
            nullable=False,
            server_default=_json_default("[]", dialect),
        ),
        sa.Column(
            "selected_mandatory_floors",
            sa.JSON(),
            nullable=False,
            server_default=_json_default("[]", dialect),
        ),
        sa.Column("semantic_primary_control_point_id", sa.String(length=128), nullable=True),
        sa.Column(
            "secondary_context_points",
            sa.JSON(),
            nullable=False,
            server_default=_json_default("[]", dialect),
        ),
        sa.Column(
            "verification_points",
            sa.JSON(),
            nullable=False,
            server_default=_json_default("[]", dialect),
        ),
        sa.Column(
            "unsatisfied_mandatory_floors",
            sa.JSON(),
            nullable=False,
            server_default=_json_default("[]", dialect),
        ),
        sa.Column(
            "rejected_mandatory_floor_candidates",
            sa.JSON(),
            nullable=False,
            server_default=_json_default("{}", dialect),
        ),
        sa.Column(
            "control_requirement_unsatisfied",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "control_plan_reason_codes",
            sa.JSON(),
            nullable=False,
            server_default=_json_default("[]", dialect),
        ),
        sa.Column(
            "degradation_policy",
            sa.JSON(),
            nullable=False,
            server_default=_json_default("{}", dialect),
        ),
        sa.Column(
            "failure_behavior",
            sa.String(length=64),
            nullable=False,
            server_default="fail_closed",
        ),
        sa.Column("plan_issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("plan_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "contract_hashes",
            sa.JSON(),
            nullable=False,
            server_default=_json_default("{}", dialect),
        ),
    )


def _constraints(dialect: str) -> tuple[tuple[str, str], ...]:
    return (
        ("ck_native_selection_canonical_action_hash", _hash_check("canonical_action_hash", dialect)),
        ("ck_native_selection_runtime_fingerprint", _hash_check("provider_runtime_fingerprint", dialect)),
        ("ck_native_selection_plan_digest", _hash_check("control_plan_digest", dialect)),
        (
            "ck_native_selection_plan_material_bytes",
            "length(CAST(control_plan_material AS TEXT)) <= 32768",
        ),
        (
            "ck_native_selection_runtime_context_bytes",
            "length(CAST(provider_runtime_context AS TEXT)) <= 8192",
        ),
        (
            "ck_native_selection_plan_time_order",
            "plan_expires_at > plan_issued_at",
        ),
        (
            "ck_native_selection_plan_lifetime",
            (
                "plan_expires_at <= plan_issued_at + INTERVAL '5 minutes'"
                if dialect == "postgresql"
                else "julianday(plan_expires_at) <= "
                "julianday(plan_issued_at) + (5.0 / 1440.0)"
            ),
        ),
    )


def _backfill_plan_times(dialect: str) -> None:
    if dialect == "postgresql":
        op.execute(
            "UPDATE native_control_selections SET "
            "plan_issued_at = COALESCE(selected_at, CURRENT_TIMESTAMP), "
            "plan_expires_at = COALESCE(selected_at, CURRENT_TIMESTAMP) + "
            "INTERVAL '5 minutes' "
            "WHERE plan_issued_at IS NULL OR plan_expires_at IS NULL"
        )
        return
    op.execute(
        "UPDATE native_control_selections SET "
        "plan_issued_at = COALESCE(selected_at, CURRENT_TIMESTAMP), "
        "plan_expires_at = datetime(COALESCE(selected_at, CURRENT_TIMESTAMP), '+5 minutes') "
        "WHERE plan_issued_at IS NULL OR plan_expires_at IS NULL"
    )


def _create_selection_immutability_triggers(dialect: str) -> None:
    if dialect == "postgresql":
        op.execute(
            "CREATE TRIGGER trg_native_control_selections_immutable "
            "BEFORE UPDATE OR DELETE ON native_control_selections "
            "FOR EACH ROW EXECUTE FUNCTION deny_immutable_table_mutation()"
        )
        return
    for action in ("update", "delete"):
        op.execute(
            f"CREATE TRIGGER trg_native_control_selections_immutable_{action} "
            f"BEFORE {action.upper()} ON native_control_selections "
            "BEGIN SELECT RAISE(ABORT, 'immutable_table:native_control_selections'); END"
        )


def _drop_selection_immutability_triggers(dialect: str) -> None:
    if dialect == "postgresql":
        op.execute(
            "DROP TRIGGER IF EXISTS trg_native_control_selections_immutable "
            "ON native_control_selections"
        )
        return
    for action in ("update", "delete"):
        op.execute(
            f"DROP TRIGGER IF EXISTS trg_native_control_selections_immutable_{action}"
        )


def upgrade() -> None:
    dialect = _dialect()
    for column in _columns(dialect):
        op.add_column("native_control_selections", column)
    _backfill_plan_times(dialect)
    constraints = _constraints(dialect)
    if dialect == "sqlite":
        with op.batch_alter_table(
            "native_control_selections",
            recreate="always",
            reflect_kwargs={"resolve_fks": False},
        ) as batch:
            for name, condition in constraints:
                batch.create_check_constraint(name, condition)
            batch.create_unique_constraint(
                "uq_native_selection_tenant_action_plan_digest",
                ["tenant_id", "action_id", "control_plan_digest"],
            )
            batch.create_index(
                "idx_native_selection_tenant_canonical_action",
                ["tenant_id", "canonical_action_hash", "selected_at"],
            )
            batch.alter_column("plan_issued_at", nullable=False)
            batch.alter_column("plan_expires_at", nullable=False)
        _create_selection_immutability_triggers(dialect)
        return
    op.alter_column("native_control_selections", "plan_issued_at", nullable=False)
    op.alter_column("native_control_selections", "plan_expires_at", nullable=False)
    for name, condition in constraints:
        op.create_check_constraint(name, "native_control_selections", condition)
    op.create_unique_constraint(
        "uq_native_selection_tenant_action_plan_digest",
        "native_control_selections",
        ["tenant_id", "action_id", "control_plan_digest"],
    )
    op.create_index(
        "idx_native_selection_tenant_canonical_action",
        "native_control_selections",
        ["tenant_id", "canonical_action_hash", "selected_at"],
    )
    _create_selection_immutability_triggers(dialect)


def downgrade() -> None:
    dialect = _dialect()
    _drop_selection_immutability_triggers(dialect)
    constraints = _constraints(dialect)
    columns = tuple(column.name for column in _columns(dialect))
    if dialect == "sqlite":
        with op.batch_alter_table(
            "native_control_selections",
            recreate="always",
            reflect_kwargs={"resolve_fks": False},
        ) as batch:
            batch.drop_index("idx_native_selection_tenant_canonical_action")
            batch.drop_constraint(
                "uq_native_selection_tenant_action_plan_digest", type_="unique"
            )
            for name, _condition in reversed(constraints):
                batch.drop_constraint(name, type_="check")
            for name in reversed(columns):
                batch.drop_column(name)
        return
    op.drop_index("idx_native_selection_tenant_canonical_action", table_name="native_control_selections")
    op.drop_constraint(
        "uq_native_selection_tenant_action_plan_digest",
        "native_control_selections",
        type_="unique",
    )
    for name, _condition in reversed(constraints):
        op.drop_constraint(name, "native_control_selections", type_="check")
    for name in reversed(columns):
        op.drop_column("native_control_selections", name)
