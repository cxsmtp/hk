"""Add fail-closed Account Boundary production-core fields.

Revision ID: 0075_account_boundary_production_core
Revises: 0074_ai_account_boundary
"""

from alembic import op
import sqlalchemy as sa


revision = "0075_account_boundary_production_core"
down_revision = "0074_ai_account_boundary"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Additive nullable/defaulted fields preserve historical rows as UNKNOWN / unverified.
    op.add_column("ai_account_session_permits", sa.Column("signing_algorithm", sa.String(16), nullable=True))
    integration_column = sa.Column(
        "account_boundary_integration_id", sa.String(36), nullable=True
    )
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("ai_account_sessions") as batch_op:
            batch_op.add_column(integration_column)
            batch_op.create_foreign_key(
                "fk_ai_account_session_integration",
                "account_boundary_integrations",
                ["account_boundary_integration_id"],
                ["id"],
                ondelete="RESTRICT",
            )
            batch_op.create_index(
                "idx_ai_account_session_tenant_integration",
                ["tenant_id", "account_boundary_integration_id"],
            )
    else:
        op.add_column("ai_account_sessions", integration_column)
        op.create_foreign_key(
            "fk_ai_account_session_integration",
            "ai_account_sessions",
            "account_boundary_integrations",
            ["account_boundary_integration_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        op.create_index(
            "idx_ai_account_session_tenant_integration",
            "ai_account_sessions",
            ["tenant_id", "account_boundary_integration_id"],
        )
    op.add_column("ai_account_session_permits", sa.Column("signed_envelope", sa.JSON(), nullable=False, server_default=sa.text("'{}'")))
    op.add_column("ai_account_session_permits", sa.Column("max_uses", sa.Integer(), nullable=False, server_default="1"))
    op.add_column("ai_account_session_permits", sa.Column("consumed_state", sa.String(32), nullable=False, server_default="UNCONSUMED"))
    op.add_column("ai_account_session_permits", sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("idx_ai_account_permit_tenant_consumed", "ai_account_session_permits", ["tenant_id", "consumed_state"])

    op.add_column("account_access_receipts", sa.Column("signing_key_id", sa.String(128), nullable=True))
    op.add_column("account_access_receipts", sa.Column("signing_algorithm", sa.String(16), nullable=True))
    op.add_column("account_access_receipts", sa.Column("signed_envelope", sa.JSON(), nullable=False, server_default=sa.text("'{}'")))

    op.add_column("account_boundary_integrations", sa.Column("lifecycle_state", sa.String(32), nullable=False, server_default="DISCOVER"))
    op.add_column("account_boundary_integrations", sa.Column("provider_version", sa.String(128), nullable=True))
    op.add_column("account_boundary_integrations", sa.Column("route_health", sa.String(32), nullable=False, server_default="UNKNOWN"))
    op.create_index("idx_account_boundary_integration_tenant_lifecycle", "account_boundary_integrations", ["tenant_id", "lifecycle_state"])

    op.add_column("account_boundary_validations", sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("account_boundary_validations", sa.Column("route_health", sa.String(32), nullable=False, server_default="UNKNOWN"))
    op.add_column("account_boundary_validations", sa.Column("provider_version", sa.String(128), nullable=True))
    op.add_column("account_boundary_validations", sa.Column("signed_envelope", sa.JSON(), nullable=False, server_default=sa.text("'{}'")))
    op.add_column("account_boundary_validations", sa.Column("signing_key_id", sa.String(128), nullable=True))
    op.add_column("account_boundary_validations", sa.Column("signing_algorithm", sa.String(16), nullable=True))
    op.create_index("idx_account_boundary_validation_current", "account_boundary_validations", ["tenant_id", "provider", "product", "surface", "valid_until"])


def downgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("ai_account_sessions") as batch_op:
            batch_op.drop_index("idx_ai_account_session_tenant_integration")
            batch_op.drop_constraint(
                "fk_ai_account_session_integration", type_="foreignkey"
            )
            batch_op.drop_column("account_boundary_integration_id")
    else:
        op.drop_index(
            "idx_ai_account_session_tenant_integration",
            table_name="ai_account_sessions",
        )
        op.drop_constraint(
            "fk_ai_account_session_integration",
            "ai_account_sessions",
            type_="foreignkey",
        )
        op.drop_column("ai_account_sessions", "account_boundary_integration_id")
    op.drop_index("idx_account_boundary_validation_current", table_name="account_boundary_validations")
    for name in ("signing_algorithm", "signing_key_id", "signed_envelope", "provider_version", "route_health", "valid_until"):
        op.drop_column("account_boundary_validations", name)
    op.drop_index("idx_account_boundary_integration_tenant_lifecycle", table_name="account_boundary_integrations")
    for name in ("route_health", "provider_version", "lifecycle_state"):
        op.drop_column("account_boundary_integrations", name)
    for name in ("signed_envelope", "signing_algorithm", "signing_key_id"):
        op.drop_column("account_access_receipts", name)
    op.drop_index("idx_ai_account_permit_tenant_consumed", table_name="ai_account_session_permits")
    for name in ("consumed_at", "consumed_state", "max_uses", "signed_envelope", "signing_algorithm"):
        op.drop_column("ai_account_session_permits", name)
