"""Add tenant-safe User Visibility grant persistence.

Revision ID: 0083_user_visibility_prompt_explorer
Revises: 0082_policy_pack_platform
"""

from alembic import op
import sqlalchemy as sa


revision = "0083_user_visibility_prompt_explorer"
down_revision = "0082_policy_pack_platform"
branch_labels = None
depends_on = None


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    ]


def upgrade() -> None:
    with op.batch_alter_table("tenants") as batch_op:
        batch_op.add_column(
            sa.Column(
                "user_visibility_full_content_reveal_enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch_op.add_column(
            sa.Column(
                "user_visibility_prompt_retention_days",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch_op.create_check_constraint(
            "ck_tenant_user_visibility_prompt_retention_days",
            "user_visibility_prompt_retention_days >= 0",
        )
    op.create_table(
        "user_visibility_access_grants",
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("department_scope", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("granted_by_user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("id", sa.String(36), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("length(trim(reason)) > 0", name="ck_user_visibility_access_grant_reason"),
    )
    op.create_index(
        "idx_user_visibility_access_grant_tenant_user_active_expiry",
        "user_visibility_access_grants",
        ["tenant_id", "user_id", "active", "expires_at"],
    )

    op.create_table(
        "user_visibility_content_access_grants",
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("requester_user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action_id", sa.String(64), sa.ForeignKey("ai_actions.action_id", ondelete="CASCADE"), nullable=False),
        sa.Column("purpose", sa.String(64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.String(36), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("length(trim(purpose)) > 0", name="ck_user_visibility_content_grant_purpose"),
        sa.CheckConstraint("length(trim(reason)) > 0", name="ck_user_visibility_content_grant_reason"),
    )
    op.create_index(
        "idx_user_visibility_content_grant_tenant_requester_expiry",
        "user_visibility_content_access_grants",
        ["tenant_id", "requester_user_id", "expires_at"],
    )
    op.create_index(
        "idx_user_visibility_content_grant_tenant_action",
        "user_visibility_content_access_grants",
        ["tenant_id", "action_id"],
    )


def downgrade() -> None:
    op.drop_index("idx_user_visibility_content_grant_tenant_action", table_name="user_visibility_content_access_grants")
    op.drop_index("idx_user_visibility_content_grant_tenant_requester_expiry", table_name="user_visibility_content_access_grants")
    op.drop_table("user_visibility_content_access_grants")
    op.drop_index("idx_user_visibility_access_grant_tenant_user_active_expiry", table_name="user_visibility_access_grants")
    op.drop_table("user_visibility_access_grants")
    with op.batch_alter_table("tenants") as batch_op:
        batch_op.drop_constraint("ck_tenant_user_visibility_prompt_retention_days", type_="check")
        batch_op.drop_column("user_visibility_prompt_retention_days")
        batch_op.drop_column("user_visibility_full_content_reveal_enabled")
