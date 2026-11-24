"""Add instruction provenance and dynamic-tool lifecycle bindings.

Revision ID: 0078_instruction_tool_provenance
Revises: 0077_execution_effect_closure
"""

from alembic import op
import sqlalchemy as sa


revision = "0078_instruction_tool_provenance"
down_revision = "0077_execution_effect_closure"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "instruction_provenance_sets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(255), nullable=False),
        sa.Column("action_id", sa.String(255), nullable=False),
        sa.Column("parent_set_id", sa.String(36), nullable=True),
        sa.Column("handoff_ref", sa.String(255), nullable=True),
        sa.Column("inherited_record_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_instruction_provenance_set_tenant_id"),
        sa.UniqueConstraint("tenant_id", "run_id", "action_id", name="uq_instruction_provenance_run_action"),
    )
    op.create_index("idx_instruction_provenance_set_action", "instruction_provenance_sets", ["tenant_id", "action_id"])

    op.create_table(
        "instruction_provenance_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("provenance_set_id", sa.String(36), nullable=False),
        sa.Column("source_type", sa.String(64), nullable=False),
        sa.Column("source_ref", sa.String(512), nullable=False),
        sa.Column("originating_principal_ref", sa.String(255), nullable=False),
        sa.Column("represented_subject_ref", sa.String(255), nullable=True),
        sa.Column("trust_state", sa.String(32), nullable=False),
        sa.Column("requested_semantic", sa.String(64), nullable=False),
        sa.Column("authority_semantic", sa.String(64), nullable=False),
        sa.Column("influenced", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("authority_granted", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("instruction_fingerprint", sa.String(64), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("derivation_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "provenance_set_id"],
            ["instruction_provenance_sets.tenant_id", "instruction_provenance_sets.id"],
            name="fk_instruction_provenance_record_set",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "authority_semantic IN ('INFLUENCE_ONLY','AUTHORIZED_ACTION_SOURCE','CONTEXT_ONLY','AUTHORITY_UNKNOWN')",
            name="ck_instruction_provenance_authority_semantic",
        ),
    )
    op.create_index("idx_instruction_provenance_record_set", "instruction_provenance_records", ["tenant_id", "provenance_set_id"])
    op.create_index("idx_instruction_provenance_record_source", "instruction_provenance_records", ["tenant_id", "source_type"])

    op.create_table(
        "open_weight_attribution_evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("provenance_set_id", sa.String(36), nullable=False),
        sa.Column("source_record_id", sa.String(36), nullable=False),
        sa.Column("attribution_ref", sa.String(512), nullable=False),
        sa.Column("confidence", sa.String(32), nullable=False),
        sa.Column("evidence_class", sa.String(32), nullable=False, server_default="ADVISORY_CORRELATED"),
        sa.Column("can_grant_authority", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "provenance_set_id"],
            ["instruction_provenance_sets.tenant_id", "instruction_provenance_sets.id"],
            name="fk_open_weight_attribution_set",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_record_id"], ["instruction_provenance_records.id"],
            name="fk_open_weight_attribution_record", ondelete="CASCADE",
        ),
    )
    op.create_index("idx_open_weight_attribution_set", "open_weight_attribution_evidence", ["tenant_id", "provenance_set_id"])

    op.create_table(
        "tool_principal_bindings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("visible_name", sa.String(255), nullable=False),
        sa.Column("principal_type", sa.String(64), nullable=False),
        sa.Column("principal_ref", sa.String(255), nullable=False),
        sa.Column("origin", sa.String(512), nullable=True),
        sa.Column("runtime_ref", sa.String(255), nullable=True),
        sa.Column("application_ref", sa.String(255), nullable=True),
        sa.Column("publisher_ref", sa.String(255), nullable=True),
        sa.Column("registration_source", sa.String(255), nullable=True),
        sa.Column("tool_identity_hash", sa.String(64), nullable=False),
        sa.Column("material_fingerprint", sa.String(64), nullable=False),
        sa.Column("schema_fingerprint", sa.String(64), nullable=False),
        sa.Column("material_bundle", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("cosmetic_metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("lifecycle_version", sa.String(64), nullable=False),
        sa.Column("lifecycle_state", sa.String(32), nullable=False, server_default="QUARANTINED"),
        sa.Column("state_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("capability_ref", sa.String(255), nullable=False),
        sa.Column("trust_state", sa.String(32), nullable=False, server_default="UNKNOWN"),
        sa.Column("evidence_quality", sa.String(64), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_tool_principal_binding_tenant_id"),
        sa.UniqueConstraint("tenant_id", "tool_identity_hash", name="uq_tool_principal_identity"),
        sa.CheckConstraint("state_version > 0", name="ck_tool_principal_state_version"),
        sa.CheckConstraint(
            "lifecycle_state IN ('DISCOVERED','QUARANTINED','VALIDATING','VALIDATED','AVAILABLE','CHANGED','STALE','REVOKED','REJECTED')",
            name="ck_tool_principal_lifecycle_state",
        ),
    )
    op.create_index("idx_tool_principal_tenant_state", "tool_principal_bindings", ["tenant_id", "lifecycle_state"])
    op.create_index("idx_tool_principal_tenant_principal", "tool_principal_bindings", ["tenant_id", "principal_ref"])

    op.create_table(
        "tool_lifecycle_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("binding_id", sa.String(36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("from_state", sa.String(32), nullable=False),
        sa.Column("to_state", sa.String(32), nullable=False),
        sa.Column("prior_material_fingerprint", sa.String(64), nullable=True),
        sa.Column("current_material_fingerprint", sa.String(64), nullable=False),
        sa.Column("actor_ref", sa.String(255), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "binding_id"], ["tool_principal_bindings.tenant_id", "tool_principal_bindings.id"],
            name="fk_tool_lifecycle_event_binding", ondelete="CASCADE",
        ),
        sa.UniqueConstraint("tenant_id", "binding_id", "sequence", name="uq_tool_lifecycle_event_sequence"),
    )
    op.create_index("idx_tool_lifecycle_event_binding", "tool_lifecycle_events", ["tenant_id", "binding_id"])

    op.create_table(
        "tool_action_provenance_bindings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("action_id", sa.String(255), nullable=False),
        sa.Column("tool_binding_id", sa.String(36), nullable=False),
        sa.Column("provenance_set_id", sa.String(36), nullable=False),
        sa.Column("tool_identity_hash", sa.String(64), nullable=False),
        sa.Column("material_fingerprint", sa.String(64), nullable=False),
        sa.Column("schema_fingerprint", sa.String(64), nullable=False),
        sa.Column("lifecycle_version", sa.String(64), nullable=False),
        sa.Column("provenance_record_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("decision_receipt_id", sa.String(255), nullable=True),
        sa.Column("execution_permit_id", sa.String(255), nullable=True),
        sa.Column("execution_receipt_id", sa.String(255), nullable=True),
        sa.Column("actual_tool_identity_hash", sa.String(64), nullable=True),
        sa.Column("actual_material_fingerprint", sa.String(64), nullable=True),
        sa.Column("actual_identity_observed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("comparison_state", sa.String(32), nullable=False, server_default="UNVERIFIED"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "tool_binding_id"], ["tool_principal_bindings.tenant_id", "tool_principal_bindings.id"],
            name="fk_tool_action_provenance_tool", ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "provenance_set_id"], ["instruction_provenance_sets.tenant_id", "instruction_provenance_sets.id"],
            name="fk_tool_action_provenance_set", ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("tenant_id", "action_id", name="uq_tool_action_provenance_action"),
    )
    op.create_index("idx_tool_action_provenance_tool", "tool_action_provenance_bindings", ["tenant_id", "tool_binding_id"])


def downgrade() -> None:
    op.drop_index("idx_tool_action_provenance_tool", table_name="tool_action_provenance_bindings")
    op.drop_table("tool_action_provenance_bindings")
    op.drop_index("idx_tool_lifecycle_event_binding", table_name="tool_lifecycle_events")
    op.drop_table("tool_lifecycle_events")
    op.drop_index("idx_tool_principal_tenant_principal", table_name="tool_principal_bindings")
    op.drop_index("idx_tool_principal_tenant_state", table_name="tool_principal_bindings")
    op.drop_table("tool_principal_bindings")
    op.drop_index("idx_open_weight_attribution_set", table_name="open_weight_attribution_evidence")
    op.drop_table("open_weight_attribution_evidence")
    op.drop_index("idx_instruction_provenance_record_source", table_name="instruction_provenance_records")
    op.drop_index("idx_instruction_provenance_record_set", table_name="instruction_provenance_records")
    op.drop_table("instruction_provenance_records")
    op.drop_index("idx_instruction_provenance_set_action", table_name="instruction_provenance_sets")
    op.drop_table("instruction_provenance_sets")
