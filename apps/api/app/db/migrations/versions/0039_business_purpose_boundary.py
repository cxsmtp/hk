"""business purpose boundary policy configuration

Revision ID: 0039_business_purpose_boundary
Revises: 0038_pilot_schema_hardening
Create Date: 2026-06-19 10:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "0039_business_purpose_boundary"
down_revision = "0038_pilot_schema_hardening"
branch_labels = None
depends_on = None


def _has_table(table_names: set[str], table_name: str) -> bool:
    return table_name in table_names


def _has_index(inspector, table_name: str, index_name: str) -> bool:
    return index_name in {item.get("name") for item in inspector.get_indexes(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())

    if not _has_table(table_names, "tenant_sector_profiles"):
        op.create_table(
            "tenant_sector_profiles",
            sa.Column("tenant_id", sa.String(), nullable=False),
            sa.Column("sector", sa.String(length=64), nullable=False, server_default="generic_enterprise"),
            sa.Column("sub_sector", sa.String(length=128), nullable=True),
            sa.Column("strictness", sa.String(length=16), nullable=False, server_default="review"),
            sa.Column("regulated_data_types", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("approved_business_purposes", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("blocked_business_purposes", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("approved_destinations", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("blocked_destinations", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("coding_policy_id", sa.String(length=128), nullable=True),
            sa.Column("sql_policy_id", sa.String(length=128), nullable=True),
            sa.Column("exception_policy_id", sa.String(length=128), nullable=True),
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_tenant_sector_profiles_tenant", "tenant_sector_profiles", ["tenant_id"])
        op.create_index("idx_tenant_sector_profiles_tenant_sector", "tenant_sector_profiles", ["tenant_id", "sector"])

    if not _has_table(table_names, "business_function_profiles"):
        op.create_table(
            "business_function_profiles",
            sa.Column("tenant_id", sa.String(), nullable=False),
            sa.Column("name", sa.String(length=64), nullable=False),
            sa.Column("description", sa.Text(), nullable=False, server_default=""),
            sa.Column("allowed_purposes", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("blocked_purposes", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("allowed_actions", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("review_required_actions", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("blocked_actions", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("allowed_destinations", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("blocked_destinations", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("coding_policy_override", sa.JSON(), nullable=True),
            sa.Column("sql_policy_override", sa.JSON(), nullable=True),
            sa.Column("strictness_override", sa.String(length=16), nullable=True),
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_business_function_profiles_tenant", "business_function_profiles", ["tenant_id"])
        op.create_index("idx_business_function_profiles_tenant_name", "business_function_profiles", ["tenant_id", "name"])

    if not _has_table(table_names, "user_business_function_mappings"):
        op.create_table(
            "user_business_function_mappings",
            sa.Column("tenant_id", sa.String(), nullable=False),
            sa.Column("user_id", sa.String(), nullable=True),
            sa.Column("email", sa.String(length=320), nullable=True),
            sa.Column("group_name", sa.String(length=255), nullable=True),
            sa.Column("idp_group_id", sa.String(length=255), nullable=True),
            sa.Column("claim_name", sa.String(length=128), nullable=True),
            sa.Column("claim_value", sa.String(length=255), nullable=True),
            sa.Column("business_function", sa.String(length=64), nullable=False, server_default="unknown"),
            sa.Column("role_name", sa.String(length=128), nullable=True),
            sa.Column("department", sa.String(length=128), nullable=True),
            sa.Column("team", sa.String(length=128), nullable=True),
            sa.Column("policy_groups", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("source", sa.String(length=32), nullable=False, server_default="manual"),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_user_business_function_mappings_tenant", "user_business_function_mappings", ["tenant_id"])
        op.create_index("idx_user_business_function_mappings_user", "user_business_function_mappings", ["tenant_id", "user_id"])
        op.create_index("idx_user_business_function_mappings_email", "user_business_function_mappings", ["tenant_id", "email"])
        op.create_index(
            "idx_user_business_function_mappings_claim",
            "user_business_function_mappings",
            ["tenant_id", "claim_name", "claim_value"],
        )

    if not _has_table(table_names, "business_purpose_sessions"):
        op.create_table(
            "business_purpose_sessions",
            sa.Column("tenant_id", sa.String(), nullable=False),
            sa.Column("user_id", sa.String(), nullable=False),
            sa.Column("declared_purpose", sa.Text(), nullable=False, server_default=""),
            sa.Column("purpose_category", sa.String(length=64), nullable=False, server_default="unknown"),
            sa.Column("business_function", sa.String(length=64), nullable=False, server_default="unknown"),
            sa.Column("approved_scope", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_business_purpose_sessions_tenant_user", "business_purpose_sessions", ["tenant_id", "user_id"])
        op.create_index("idx_business_purpose_sessions_tenant_status", "business_purpose_sessions", ["tenant_id", "status"])

    if not _has_table(table_names, "purpose_exceptions"):
        op.create_table(
            "purpose_exceptions",
            sa.Column("tenant_id", sa.String(), nullable=False),
            sa.Column("user_id", sa.String(), nullable=False),
            sa.Column("business_function", sa.String(length=64), nullable=False, server_default="unknown"),
            sa.Column("requested_purpose", sa.Text(), nullable=False, server_default=""),
            sa.Column("requested_action", sa.String(length=128), nullable=False, server_default="unknown"),
            sa.Column("justification", sa.Text(), nullable=False, server_default=""),
            sa.Column("approved_by", sa.String(), nullable=True),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["approved_by"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_purpose_exceptions_tenant_user", "purpose_exceptions", ["tenant_id", "user_id"])
        op.create_index("idx_purpose_exceptions_tenant_status", "purpose_exceptions", ["tenant_id", "status"])

    inspector = inspect(bind)
    for table_name, index_name, columns in (
        ("tenant_sector_profiles", "idx_tenant_sector_profiles_tenant", ["tenant_id"]),
        ("tenant_sector_profiles", "idx_tenant_sector_profiles_tenant_sector", ["tenant_id", "sector"]),
        ("business_function_profiles", "idx_business_function_profiles_tenant", ["tenant_id"]),
        ("business_function_profiles", "idx_business_function_profiles_tenant_name", ["tenant_id", "name"]),
        ("user_business_function_mappings", "idx_user_business_function_mappings_tenant", ["tenant_id"]),
        ("user_business_function_mappings", "idx_user_business_function_mappings_user", ["tenant_id", "user_id"]),
        ("user_business_function_mappings", "idx_user_business_function_mappings_email", ["tenant_id", "email"]),
        ("user_business_function_mappings", "idx_user_business_function_mappings_claim", ["tenant_id", "claim_name", "claim_value"]),
        ("business_purpose_sessions", "idx_business_purpose_sessions_tenant_user", ["tenant_id", "user_id"]),
        ("business_purpose_sessions", "idx_business_purpose_sessions_tenant_status", ["tenant_id", "status"]),
        ("purpose_exceptions", "idx_purpose_exceptions_tenant_user", ["tenant_id", "user_id"]),
        ("purpose_exceptions", "idx_purpose_exceptions_tenant_status", ["tenant_id", "status"]),
    ):
        if table_name in set(inspector.get_table_names()) and not _has_index(inspector, table_name, index_name):
            op.create_index(index_name, table_name, columns)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())

    for table_name, index_name in (
        ("purpose_exceptions", "idx_purpose_exceptions_tenant_status"),
        ("purpose_exceptions", "idx_purpose_exceptions_tenant_user"),
        ("business_purpose_sessions", "idx_business_purpose_sessions_tenant_status"),
        ("business_purpose_sessions", "idx_business_purpose_sessions_tenant_user"),
        ("user_business_function_mappings", "idx_user_business_function_mappings_claim"),
        ("user_business_function_mappings", "idx_user_business_function_mappings_email"),
        ("user_business_function_mappings", "idx_user_business_function_mappings_user"),
        ("user_business_function_mappings", "idx_user_business_function_mappings_tenant"),
        ("business_function_profiles", "idx_business_function_profiles_tenant_name"),
        ("business_function_profiles", "idx_business_function_profiles_tenant"),
        ("tenant_sector_profiles", "idx_tenant_sector_profiles_tenant_sector"),
        ("tenant_sector_profiles", "idx_tenant_sector_profiles_tenant"),
    ):
        if table_name in table_names and _has_index(inspector, table_name, index_name):
            op.drop_index(index_name, table_name=table_name)

    for table_name in (
        "purpose_exceptions",
        "business_purpose_sessions",
        "user_business_function_mappings",
        "business_function_profiles",
        "tenant_sector_profiles",
    ):
        if table_name in table_names:
            op.drop_table(table_name)
