"""Add durable execution-effect closure and delivery fences.

Revision ID: 0077_execution_effect_closure
Revises: 0076_agent_collective_security
"""

from alembic import op
import sqlalchemy as sa


revision = "0077_execution_effect_closure"
down_revision = "0076_agent_collective_security"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "effect_delivery_fences_v2",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("effect_identity_hash", sa.String(64), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("state_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("active_reservation_id", sa.String(36), nullable=True),
        sa.Column("last_reservation_id", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "effect_identity_hash", name="uq_effect_fence_tenant_identity"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_effect_fence_tenant_id"),
        sa.CheckConstraint("state_version > 0", name="ck_effect_fence_state_version"),
    )
    op.create_index("idx_effect_fence_tenant_state", "effect_delivery_fences_v2", ["tenant_id", "state"])

    op.create_table(
        "effect_reservations_v2",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("fence_id", sa.String(36), nullable=False),
        sa.Column("action_id", sa.String(64), nullable=False),
        sa.Column("canonical_action_hash", sa.String(64), nullable=False),
        sa.Column("material_fields_hash", sa.String(64), nullable=False),
        sa.Column("decision_receipt_id", sa.String(36), nullable=False),
        sa.Column("approval_binding_id", sa.String(36), nullable=True),
        sa.Column("execution_permit_id", sa.String(36), nullable=False),
        sa.Column("attempt_id", sa.String(36), nullable=False),
        sa.Column("actor_principal_ref", sa.String(255), nullable=False),
        sa.Column("executing_principal_ref", sa.String(255), nullable=False),
        sa.Column("represented_subject_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("authority_ref", sa.String(255), nullable=False),
        sa.Column("provider_ref", sa.String(255), nullable=False),
        sa.Column("resource_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("target_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("destination_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("value_hashes", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("side_effect", sa.String(128), nullable=False),
        sa.Column("persistence", sa.String(64), nullable=False),
        sa.Column("effect_identity_hash", sa.String(64), nullable=False),
        sa.Column("manifest_hash", sa.String(64), nullable=False),
        sa.Column("effect_manifest", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("manifest_match_mode", sa.String(32), nullable=False, server_default="EXACT"),
        sa.Column("policy_epoch", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(32), nullable=False, server_default="RESERVED"),
        sa.Column("state_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("closure_outcome", sa.String(32), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("provider_idempotency_key", sa.String(128), nullable=False),
        sa.Column("provider_effect_ref", sa.String(255), nullable=True),
        sa.Column("worker_ref", sa.String(255), nullable=True),
        sa.Column("predecessor_reservation_id", sa.String(36), nullable=True),
        sa.Column("successor_reason", sa.String(128), nullable=True),
        sa.Column("prior_terminal_state", sa.String(32), nullable=True),
        sa.Column("no_effect_evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("material_differences", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("last_execution_receipt_id", sa.String(36), nullable=True),
        sa.Column("history_head_transition_id", sa.String(36), nullable=False),
        sa.Column("history_head_transition_hash", sa.String(64), nullable=False),
        sa.Column("history_head_sequence", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("reconstruction_status", sa.String(16), nullable=False, server_default="VERIFIED"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("terminal_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["tenant_id", "fence_id"], ["effect_delivery_fences_v2.tenant_id", "effect_delivery_fences_v2.id"],
            name="fk_effect_reservation_fence", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "execution_permit_id"], ["execution_permits_v2.tenant_id", "execution_permits_v2.permit_id"],
            name="fk_effect_reservation_permit", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "predecessor_reservation_id"], ["effect_reservations_v2.tenant_id", "effect_reservations_v2.id"],
            name="fk_effect_reservation_predecessor", ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_effect_reservation_tenant_id"),
        sa.UniqueConstraint("tenant_id", "execution_permit_id", name="uq_effect_reservation_permit"),
        sa.CheckConstraint("state_version > 0", name="ck_effect_reservation_state_version"),
        sa.CheckConstraint("history_head_sequence > 0", name="ck_effect_reservation_history_sequence"),
    )
    op.create_index("idx_effect_reservation_tenant_state", "effect_reservations_v2", ["tenant_id", "state"])
    op.create_index("idx_effect_reservation_tenant_identity", "effect_reservations_v2", ["tenant_id", "effect_identity_hash"])

    op.create_table(
        "effect_reservation_transitions_v2",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("reservation_id", sa.String(36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("from_state", sa.String(32), nullable=False),
        sa.Column("to_state", sa.String(32), nullable=False),
        sa.Column("prior_state_version", sa.Integer(), nullable=False),
        sa.Column("new_state_version", sa.Integer(), nullable=False),
        sa.Column("prior_transition_id", sa.String(36), nullable=True),
        sa.Column("prior_transition_hash", sa.String(64), nullable=True),
        sa.Column("worker_ref", sa.String(255), nullable=True),
        sa.Column("provider_effect_ref", sa.String(255), nullable=True),
        sa.Column("execution_receipt_id", sa.String(36), nullable=True),
        sa.Column("evidence_quality", sa.String(32), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("reason_code", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("algorithm", sa.String(16), nullable=False),
        sa.Column("signing_key_id", sa.String(64), nullable=False),
        sa.Column("signature", sa.String(128), nullable=False),
        sa.Column("signed_envelope", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.ForeignKeyConstraint(
            ["tenant_id", "reservation_id"], ["effect_reservations_v2.tenant_id", "effect_reservations_v2.id"],
            name="fk_effect_transition_reservation", ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "reservation_id", "prior_transition_id"],
            ["effect_reservation_transitions_v2.tenant_id", "effect_reservation_transitions_v2.reservation_id", "effect_reservation_transitions_v2.id"],
            name="fk_effect_transition_prior", ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("tenant_id", "reservation_id", "id", name="uq_effect_transition_reservation_id"),
        sa.UniqueConstraint("tenant_id", "reservation_id", "sequence", name="uq_effect_transition_sequence"),
        sa.UniqueConstraint("tenant_id", "reservation_id", "new_state_version", name="uq_effect_transition_state_version"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_effect_transition_idempotency"),
    )

    op.create_table(
        "execution_permit_effect_bindings_v2",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("permit_id", sa.String(36), nullable=False),
        sa.Column("reservation_id", sa.String(36), nullable=False),
        sa.Column("manifest_hash", sa.String(64), nullable=False),
        sa.Column("effect_identity_hash", sa.String(64), nullable=False),
        sa.Column("policy_epoch", sa.Integer(), nullable=False),
        sa.Column("algorithm", sa.String(16), nullable=False),
        sa.Column("signing_key_id", sa.String(64), nullable=False),
        sa.Column("signature", sa.String(128), nullable=False),
        sa.Column("signed_envelope", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["tenant_id", "permit_id"], ["execution_permits_v2.tenant_id", "execution_permits_v2.permit_id"],
            name="fk_effect_binding_permit", ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "reservation_id"], ["effect_reservations_v2.tenant_id", "effect_reservations_v2.id"],
            name="fk_effect_binding_reservation", ondelete="CASCADE",
        ),
        sa.UniqueConstraint("tenant_id", "permit_id", name="uq_effect_binding_permit"),
        sa.UniqueConstraint("tenant_id", "reservation_id", name="uq_effect_binding_reservation"),
    )

    op.add_column("execution_receipt_v2_extensions", sa.Column("effect_reservation_id", sa.String(36), nullable=True))
    op.add_column("execution_receipt_v2_extensions", sa.Column("effect_closure_state", sa.String(32), nullable=True))
    op.add_column("execution_receipt_v2_extensions", sa.Column("provider_effect_ref", sa.String(255), nullable=True))
    op.add_column(
        "execution_receipt_v2_extensions",
        sa.Column("effect_evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column("execution_receipt_v2_extensions", sa.Column("recovery_sequence", sa.Integer(), nullable=True))
    op.create_index(
        "idx_execution_receipt_v2_effect_reservation",
        "execution_receipt_v2_extensions",
        ["tenant_id", "effect_reservation_id"],
    )


def downgrade() -> None:
    op.drop_index("idx_execution_receipt_v2_effect_reservation", table_name="execution_receipt_v2_extensions")
    op.drop_column("execution_receipt_v2_extensions", "recovery_sequence")
    op.drop_column("execution_receipt_v2_extensions", "effect_evidence_refs")
    op.drop_column("execution_receipt_v2_extensions", "provider_effect_ref")
    op.drop_column("execution_receipt_v2_extensions", "effect_closure_state")
    op.drop_column("execution_receipt_v2_extensions", "effect_reservation_id")
    op.drop_table("execution_permit_effect_bindings_v2")
    op.drop_table("effect_reservation_transitions_v2")
    op.drop_index("idx_effect_reservation_tenant_identity", table_name="effect_reservations_v2")
    op.drop_index("idx_effect_reservation_tenant_state", table_name="effect_reservations_v2")
    op.drop_table("effect_reservations_v2")
    op.drop_index("idx_effect_fence_tenant_state", table_name="effect_delivery_fences_v2")
    op.drop_table("effect_delivery_fences_v2")
