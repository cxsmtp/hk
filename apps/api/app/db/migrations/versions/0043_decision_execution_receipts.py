"""signed decision and execution receipts

Revision ID: 0043_decision_execution_receipts
Revises: 0042_token_system_binding
"""

from alembic import op
import sqlalchemy as sa


revision = "0043_decision_execution_receipts"
down_revision = "0042_token_system_binding"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("evidence_nodes") as batch:
        batch.create_unique_constraint("uq_evidence_nodes_tenant_id", ["tenant_id", "id"])
    with op.batch_alter_table("approval_bindings") as batch:
        batch.add_column(sa.Column("receipt_material_hash", sa.String(length=64), nullable=True))
        batch.create_unique_constraint("uq_approval_bindings_tenant_id", ["tenant_id", "id"])
    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("canonical_action_id", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("execution_attempt_id", sa.String(length=128), nullable=True))
        batch.create_index(
            "idx_findings_tenant_canonical_action",
            ["tenant_id", "canonical_action_id"],
            unique=False,
        )
        batch.create_index(
            "idx_findings_tenant_execution_attempt",
            ["tenant_id", "execution_attempt_id"],
            unique=False,
        )

    op.create_table(
        "decision_receipts",
        sa.Column("receipt_id", sa.String(length=36), primary_key=True),
        sa.Column("schema_version", sa.String(length=16), nullable=False, server_default="1.0"),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("action_id", sa.String(length=64), nullable=False),
        sa.Column("chain_id", sa.String(length=64), nullable=False),
        sa.Column("canonical_action_hash", sa.String(length=64), nullable=False),
        sa.Column("actor_hash", sa.String(length=64), nullable=False),
        sa.Column("authority_hash", sa.String(length=64), nullable=False),
        sa.Column("purpose_hash", sa.String(length=64), nullable=False),
        sa.Column("tool_fingerprint", sa.String(length=128), nullable=False),
        sa.Column("parameter_hash", sa.String(length=128), nullable=False),
        sa.Column("target_resource_hash", sa.String(length=128), nullable=False),
        sa.Column("destination_hash", sa.String(length=128), nullable=False),
        sa.Column("side_effect_class", sa.String(length=64), nullable=False),
        sa.Column("approval_binding_hash", sa.String(length=128), nullable=False),
        sa.Column("approval_binding_id", sa.String(length=36), nullable=True),
        sa.Column("policy_snapshot_id", sa.String(length=64), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("control_mode", sa.String(length=32), nullable=False),
        sa.Column("transformations", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signature", sa.String(length=64), nullable=False),
        sa.Column("signing_key_id", sa.String(length=64), nullable=False),
        sa.Column("collector_id", sa.String(length=128), nullable=False),
        sa.Column("canonical_action_evidence_node_id", sa.String(length=36), nullable=False),
        sa.Column("evidence_node_id", sa.String(length=36), nullable=True),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "approval_binding_id"],
            ["approval_bindings.tenant_id", "approval_bindings.id"],
            name="fk_decision_receipt_tenant_approval",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "evidence_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_decision_receipt_tenant_evidence",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "canonical_action_evidence_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_decision_receipt_tenant_canonical_evidence",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_decision_receipts_tenant_idempotency"),
        sa.UniqueConstraint("tenant_id", "receipt_id", name="uq_decision_receipts_tenant_receipt"),
    )
    op.create_index("idx_decision_receipts_tenant_action", "decision_receipts", ["tenant_id", "action_id"])
    op.create_index("idx_decision_receipts_tenant_key", "decision_receipts", ["tenant_id", "signing_key_id"])

    op.create_table(
        "execution_receipts",
        sa.Column("receipt_id", sa.String(length=36), primary_key=True),
        sa.Column("schema_version", sa.String(length=16), nullable=False, server_default="1.0"),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("action_id", sa.String(length=64), nullable=False),
        sa.Column("decision_receipt_id", sa.String(length=36), nullable=False),
        sa.Column("execution_attempt_id", sa.String(length=128), nullable=False),
        sa.Column("actual_tool_fingerprint", sa.String(length=128), nullable=False),
        sa.Column("actual_parameter_hash", sa.String(length=128), nullable=False),
        sa.Column("actual_target_resource_hash", sa.String(length=128), nullable=False),
        sa.Column("actual_destination_hash", sa.String(length=128), nullable=False),
        sa.Column("actual_authority_hash", sa.String(length=64), nullable=False),
        sa.Column("actual_side_effect_class", sa.String(length=64), nullable=False),
        sa.Column("downstream_objects", sa.JSON(), nullable=False),
        sa.Column("execution_status", sa.String(length=32), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collector_id", sa.String(length=128), nullable=False),
        sa.Column("signature", sa.String(length=64), nullable=False),
        sa.Column("signing_key_id", sa.String(length=64), nullable=False),
        sa.Column("evidence_node_id", sa.String(length=36), nullable=True),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "decision_receipt_id"],
            ["decision_receipts.tenant_id", "decision_receipts.receipt_id"],
            name="fk_execution_receipt_tenant_decision",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "evidence_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_execution_receipt_tenant_evidence",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_execution_receipts_tenant_idempotency"),
        sa.UniqueConstraint("tenant_id", "receipt_id", name="uq_execution_receipts_tenant_receipt"),
        sa.UniqueConstraint(
            "tenant_id",
            "decision_receipt_id",
            "execution_attempt_id",
            name="uq_execution_receipts_tenant_decision_attempt",
        ),
    )
    op.create_index("idx_execution_receipts_tenant_action", "execution_receipts", ["tenant_id", "action_id"])
    op.create_index(
        "idx_execution_receipts_tenant_decision",
        "execution_receipts",
        ["tenant_id", "decision_receipt_id"],
    )

    op.create_table(
        "execution_integrity_results",
        sa.Column("result_id", sa.String(length=36), primary_key=True),
        sa.Column("schema_version", sa.String(length=16), nullable=False, server_default="1.0"),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("action_id", sa.String(length=64), nullable=False),
        sa.Column("decision_receipt_id", sa.String(length=36), nullable=False),
        sa.Column("execution_receipt_id", sa.String(length=36), nullable=True),
        sa.Column("execution_attempt_id", sa.String(length=128), nullable=False),
        sa.Column("result", sa.String(length=32), nullable=False),
        sa.Column("drift_fields", sa.JSON(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("response_action", sa.String(length=32), nullable=False),
        sa.Column("signature", sa.String(length=64), nullable=False),
        sa.Column("signing_key_id", sa.String(length=64), nullable=False),
        sa.Column("evidence_bundle_id", sa.String(length=36), nullable=True),
        sa.Column("superseded_evidence_node_id", sa.String(length=36), nullable=True),
        sa.Column("superseded_integrity_body_hash", sa.String(length=64), nullable=True),
        sa.Column("superseded_integrity_signature", sa.String(length=64), nullable=True),
        sa.Column("supersession_evidence_node_id", sa.String(length=36), nullable=True),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "decision_receipt_id"],
            ["decision_receipts.tenant_id", "decision_receipts.receipt_id"],
            name="fk_execution_integrity_tenant_decision",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "execution_receipt_id"],
            ["execution_receipts.tenant_id", "execution_receipts.receipt_id"],
            name="fk_execution_integrity_tenant_execution",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "evidence_bundle_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_execution_integrity_tenant_evidence",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_execution_integrity_tenant_idempotency"),
        sa.UniqueConstraint(
            "tenant_id",
            "decision_receipt_id",
            "execution_attempt_id",
            name="uq_execution_integrity_tenant_decision_attempt",
        ),
        sa.CheckConstraint(
            "result IN ('matched','drift_detected','execution_unknown','incomplete')",
            name="ck_execution_integrity_result_closed",
        ),
    )
    op.create_index(
        "idx_execution_integrity_tenant_action",
        "execution_integrity_results",
        ["tenant_id", "action_id"],
    )
    op.create_index(
        "idx_execution_integrity_tenant_result",
        "execution_integrity_results",
        ["tenant_id", "result"],
    )


def downgrade() -> None:
    op.drop_table("execution_integrity_results")
    op.drop_table("execution_receipts")
    op.drop_table("decision_receipts")
    with op.batch_alter_table("findings") as batch:
        batch.drop_index("idx_findings_tenant_execution_attempt")
        batch.drop_index("idx_findings_tenant_canonical_action")
        batch.drop_column("execution_attempt_id")
        batch.drop_column("canonical_action_id")
    with op.batch_alter_table("approval_bindings") as batch:
        batch.drop_constraint("uq_approval_bindings_tenant_id", type_="unique")
        batch.drop_column("receipt_material_hash")
    with op.batch_alter_table("evidence_nodes") as batch:
        batch.drop_constraint("uq_evidence_nodes_tenant_id", type_="unique")
