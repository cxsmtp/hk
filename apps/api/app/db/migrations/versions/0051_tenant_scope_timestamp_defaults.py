"""Restore timestamp defaults on tenant-scoped governance tables.

Revision ID: 0051_tenant_scope_timestamp_defaults
Revises: 0050_native_control_health_observations
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0051_tenant_scope_timestamp_defaults"
down_revision = "0050_native_control_health_observations"
branch_labels = None
depends_on = None


_TABLE_COLUMNS = {
    "guardian_contract_v2": ("created_at",),
    "guardian_contract_binding_v2": ("created_at", "updated_at"),
    "controls": ("created_at", "updated_at"),
}


def _set_defaults(*, enabled: bool) -> None:
    default = sa.func.now() if enabled else None
    bind = op.get_bind()
    dialect_name = bind.dialect.name
    inspector = sa.inspect(bind)
    available_tables = set(inspector.get_table_names())
    for table_name, column_names in _TABLE_COLUMNS.items():
        # Historical acceptance fixtures may legitimately be stamped at the
        # prior revision with only the tables needed by the feature under
        # test. An additive default repair must never manufacture an unrelated
        # governance table or fail merely because that unrelated table is
        # absent.
        if table_name not in available_tables:
            continue
        available_columns = {
            column["name"] for column in inspector.get_columns(table_name)
        }
        present_columns = tuple(
            column_name
            for column_name in column_names
            if column_name in available_columns
        )
        if not present_columns:
            continue
        if dialect_name == "sqlite":
            with op.batch_alter_table(table_name, recreate="always") as batch_op:
                for column_name in present_columns:
                    batch_op.alter_column(
                        column_name,
                        existing_type=sa.DateTime(timezone=True),
                        existing_nullable=False,
                        server_default=default,
                    )
            continue
        for column_name in present_columns:
            op.alter_column(
                table_name,
                column_name,
                existing_type=sa.DateTime(timezone=True),
                existing_nullable=False,
                server_default=default,
            )


def upgrade() -> None:
    _set_defaults(enabled=True)


def downgrade() -> None:
    _set_defaults(enabled=False)
