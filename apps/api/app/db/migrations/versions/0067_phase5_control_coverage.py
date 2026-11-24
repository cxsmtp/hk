"""Phase 5 product projections and Control Coverage methodology union.

Revision ID: 0067_phase5_control_coverage
Revises: 0066_phase5_execution_lifecycle
"""

from alembic import op
import sqlalchemy as sa


revision = "0067_phase5_control_coverage"
down_revision = "0066_phase5_execution_lifecycle"
branch_labels = None
depends_on = None


_V1 = ("discovery", "identity", "authorization", "evidence", "deployment", "runtime", "bypass")
_V2 = (
    "subject_binding", "resource_binding", "purpose_binding", "authority_binding", "parameter_binding", "target_binding", "destination_binding",
    "approval_binding", "execution_visibility", "execution_verification", "persistence_tracking", "delegation_integrity", "outcome_verification",
)
_ALL_DIMENSIONS_SQL = ",".join(repr(value) for value in (*_V1, *_V2))


def upgrade() -> None:
    # ControlCoverageAssertion remains the sole authority. Existing V1 snapshots
    # retain their methodology version and are never relabelled as V2.
    with op.batch_alter_table("control_coverage_assertions") as batch:
        batch.drop_constraint("ck_control_coverage_assertion_dimension", type_="check")
        batch.create_check_constraint("ck_control_coverage_assertion_dimension", f"dimension IN ({_ALL_DIMENSIONS_SQL})")
    with op.batch_alter_table("runtime_events") as batch:
        batch.create_unique_constraint("uq_runtime_events_tenant_event_id", ["tenant_id", "event_id"])
    op.create_table(
        "action_integrity_detail_projections",
        sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("action_id", sa.String(64), nullable=False), sa.Column("runtime_event_id", sa.String(36), nullable=False),
        sa.Column("schema_version", sa.String(16), nullable=False, server_default="1.0"), sa.Column("projection", sa.JSON(), nullable=False),
        sa.Column("source_watermark", sa.String(128), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["tenant_id", "runtime_event_id"], ["runtime_events.tenant_id", "runtime_events.event_id"], name="fk_phase5_detail_runtime_event", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("tenant_id", "action_id", "runtime_event_id"),
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if inspector.has_table("action_integrity_detail_projections") and bind.execute(sa.text("SELECT 1 FROM action_integrity_detail_projections LIMIT 1")).first() is not None:
        raise RuntimeError("refusing Phase 5 downgrade: Action Detail projections exist")
    if bind.execute(sa.text(f"SELECT 1 FROM control_coverage_assertions WHERE dimension IN ({','.join(repr(value) for value in _V2)}) LIMIT 1")).first() is not None:
        raise RuntimeError("refusing Phase 5 downgrade: V2 coverage assertions exist")
    op.drop_table("action_integrity_detail_projections")
    with op.batch_alter_table("control_coverage_assertions") as batch:
        batch.drop_constraint("ck_control_coverage_assertion_dimension", type_="check")
        batch.create_check_constraint("ck_control_coverage_assertion_dimension", f"dimension IN ({','.join(repr(value) for value in _V1)})")
    with op.batch_alter_table("runtime_events") as batch:
        batch.drop_constraint("uq_runtime_events_tenant_event_id", type_="unique")
