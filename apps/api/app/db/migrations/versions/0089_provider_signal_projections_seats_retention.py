"""Add provider-signal projection references and authoritative seat snapshots.

Revision ID: 0089_provider_signal_lifecycle
Revises: 0088_provider_signal_records
"""

from alembic import op
import sqlalchemy as sa


revision = "0089_provider_signal_lifecycle"
down_revision = "0088_provider_signal_records"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("provider_signal_records") as batch:
        batch.add_column(
            sa.Column(
                "projection_refs",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            )
        )
    op.create_index(
        "idx_provider_signal_tenant_received",
        "provider_signal_records",
        ["tenant_id", "received_at"],
    )
    op.create_table(
        "provider_seat_snapshots",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("connector_id", sa.String(36), nullable=True),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("product", sa.String(128), nullable=False),
        sa.Column("source_type", sa.String(48), nullable=False),
        sa.Column("source_schema_version", sa.String(32), nullable=False),
        sa.Column("source_record_id", sa.String(255), nullable=False),
        sa.Column("dedup_key", sa.String(64), nullable=False),
        sa.Column("billing_group", sa.String(128), nullable=True),
        sa.Column("authority_reference", sa.String(255), nullable=False),
        sa.Column("total_licensed_seats", sa.Integer(), nullable=False),
        sa.Column("assigned_seats", sa.Integer(), nullable=False),
        sa.Column("active_seats", sa.Integer(), nullable=False),
        sa.Column("inactive_seats", sa.Integer(), nullable=False),
        sa.Column("never_used_seats", sa.Integer(), nullable=False),
        sa.Column("unknown_activity_seats", sa.Integer(), nullable=False),
        sa.Column("completeness", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("evidence_quality", sa.String(32), nullable=False, server_default="UNKNOWN"),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("source_type IN ('provider_admin')", name="ck_provider_seat_authoritative_source"),
        sa.CheckConstraint("assigned_seats >= 0", name="ck_provider_seat_assigned_nonnegative"),
        sa.CheckConstraint("active_seats >= 0", name="ck_provider_seat_active_nonnegative"),
        sa.CheckConstraint("inactive_seats >= 0", name="ck_provider_seat_inactive_nonnegative"),
        sa.CheckConstraint("never_used_seats >= 0", name="ck_provider_seat_never_used_nonnegative"),
        sa.CheckConstraint("unknown_activity_seats >= 0", name="ck_provider_seat_unknown_activity_nonnegative"),
        sa.CheckConstraint("total_licensed_seats >= 0", name="ck_provider_seat_total_licensed_nonnegative"),
        sa.CheckConstraint(
            "assigned_seats = active_seats + inactive_seats + never_used_seats + unknown_activity_seats",
            name="ck_provider_seat_population_reconciles",
        ),
        sa.CheckConstraint("total_licensed_seats >= assigned_seats", name="ck_provider_seat_total_gte_assigned"),
        sa.CheckConstraint("completeness IN ('COMPLETE','PARTIAL','UNKNOWN')", name="ck_provider_seat_completeness"),
        sa.CheckConstraint("completeness != 'COMPLETE' OR total_licensed_seats = assigned_seats", name="ck_provider_seat_complete_reconciles"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["connector_id"], ["connectors.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("tenant_id", "dedup_key", name="uq_provider_seat_tenant_dedup"),
    )
    op.create_index(
        "idx_provider_seat_tenant_provider_time",
        "provider_seat_snapshots",
        ["tenant_id", "provider", "product", "observed_at"],
    )
    op.create_index(
        "idx_provider_seat_tenant_received",
        "provider_seat_snapshots",
        ["tenant_id", "received_at"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    seat_count = bind.execute(sa.text("SELECT COUNT(1) FROM provider_seat_snapshots")).scalar_one()
    projected_count = bind.execute(
        sa.text(
            "SELECT COUNT(1) FROM provider_signal_records "
            "WHERE projection_refs IS NOT NULL "
            "AND CAST(projection_refs AS TEXT) NOT IN ('{}', 'null', 'NULL', '')"
        )
    ).scalar_one()
    if seat_count or projected_count:
        raise RuntimeError(
            "Cannot downgrade provider signal lifecycle while seat snapshots or projection references exist. "
            "Remove derived lifecycle data through an approved retention/migration procedure first."
        )
    op.drop_index("idx_provider_seat_tenant_received", table_name="provider_seat_snapshots")
    op.drop_index("idx_provider_seat_tenant_provider_time", table_name="provider_seat_snapshots")
    op.drop_table("provider_seat_snapshots")
    op.drop_index("idx_provider_signal_tenant_received", table_name="provider_signal_records")
    with op.batch_alter_table("provider_signal_records") as batch:
        batch.drop_column("projection_refs")
