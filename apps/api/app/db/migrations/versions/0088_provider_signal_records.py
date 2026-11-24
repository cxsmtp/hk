"""Add sanitized provider signal records.

Revision ID: 0088_provider_signal_records
Revises: 0087_allow_covered_stale_control_coverage
"""

from alembic import op
import sqlalchemy as sa


revision = "0088_provider_signal_records"
down_revision = "0087_allow_covered_stale_control_coverage"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "provider_signal_records",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("connector_id", sa.String(36), nullable=True),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("product", sa.String(128), nullable=False),
        sa.Column("source_type", sa.String(48), nullable=False),
        sa.Column("source_schema_version", sa.String(32), nullable=False),
        sa.Column("source_record_id", sa.String(255), nullable=False),
        sa.Column("dedup_key", sa.String(64), nullable=False),
        sa.Column("record_kind", sa.String(32), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("watermark", sa.String(255), nullable=True),
        sa.Column("user_id", sa.String(36), nullable=True),
        sa.Column("department", sa.String(128), nullable=True),
        sa.Column("client", sa.String(128), nullable=True),
        sa.Column("model", sa.String(128), nullable=True),
        sa.Column("session_ref", sa.String(255), nullable=True),
        sa.Column("evidence_quality", sa.String(32), nullable=False, server_default="UNKNOWN"),
        sa.Column("payload", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "record_kind IN ('capability','usage','spend','prompt','tool','meeting','client_session')",
            name="ck_provider_signal_record_kind",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["connector_id"], ["connectors.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("tenant_id", "dedup_key", name="uq_provider_signal_tenant_dedup"),
    )
    op.create_index(
        "idx_provider_signal_tenant_provider_time",
        "provider_signal_records",
        ["tenant_id", "provider", "occurred_at"],
    )
    op.create_index(
        "idx_provider_signal_tenant_kind_time",
        "provider_signal_records",
        ["tenant_id", "record_kind", "occurred_at"],
    )
    op.create_index(
        "idx_provider_signal_tenant_user_time",
        "provider_signal_records",
        ["tenant_id", "user_id", "occurred_at"],
    )
    op.create_index(
        "idx_provider_signal_tenant_client_time",
        "provider_signal_records",
        ["tenant_id", "client", "occurred_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_provider_signal_tenant_client_time", table_name="provider_signal_records")
    op.drop_index("idx_provider_signal_tenant_user_time", table_name="provider_signal_records")
    op.drop_index("idx_provider_signal_tenant_kind_time", table_name="provider_signal_records")
    op.drop_index("idx_provider_signal_tenant_provider_time", table_name="provider_signal_records")
    op.drop_table("provider_signal_records")
