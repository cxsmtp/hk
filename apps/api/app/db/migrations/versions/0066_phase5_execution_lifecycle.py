"""Phase 5 immutable V2 decision, approval, permit and execution lifecycle.

Revision ID: 0066_phase5_execution_lifecycle
Revises: 0065_phase5_action_integrity_core
"""

from alembic import op
import sqlalchemy as sa


revision = "0066_phase5_execution_lifecycle"
down_revision = "0065_phase5_action_integrity_core"
branch_labels = None
depends_on = None


_LIFECYCLE_TABLES = (
    "outcome_verifications_v2", "expected_outcomes_v2", "delegation_lifecycle_events_v2", "delegation_contexts_v2",
    "persistent_effect_transitions_v2", "persistent_effects_v2", "action_plan_steps_v2", "action_plans_v2",
    "execution_comparisons_v2", "execution_receipt_v2_extensions", "execution_permit_transitions_v2",
    "execution_permit_attempts_v2", "execution_permits_v2", "approval_authority_projections_v2",
    "approval_authority_events_v2", "approval_binding_v2_extensions", "decision_receipt_v2_extensions",
    "banking_execution_grant_v2_links",
)


def _refuse_downgrade_when_authority_exists() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    for table in _LIFECYCLE_TABLES:
        if inspector.has_table(table) and bind.execute(sa.text(f'SELECT 1 FROM "{table}" LIMIT 1')).first() is not None:
            raise RuntimeError(f"refusing Phase 5 downgrade: signed authority data exists in {table}")


def upgrade() -> None:
    # SQLite requires a batch table rewrite for the tenant composite key that
    # makes the subsequent tenant-scoped foreign keys enforceable.
    with op.batch_alter_table("approval_requests") as batch:
        batch.add_column(sa.Column("decision_version", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("authority_schema_version", sa.String(16), nullable=True))
        batch.create_unique_constraint("uq_approval_requests_tenant_id", ["tenant_id", "id"])
        batch.create_check_constraint("ck_phase5_approval_request_version", "decision_version >= 0")

    op.create_table(
        "decision_receipt_v2_extensions",
        sa.Column("receipt_id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("action_id", sa.String(64), nullable=False), sa.Column("canonical_action_hash", sa.String(64), nullable=False),
        sa.Column("material_fields_hash", sa.String(64), nullable=False), sa.Column("policy_epoch", sa.Integer(), nullable=False),
        sa.Column("control_plan_digest", sa.String(64), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("algorithm", sa.String(16), nullable=False), sa.Column("signing_key_id", sa.String(64), nullable=False), sa.Column("signature", sa.String(128), nullable=False),
        sa.Column("signed_envelope", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id", "receipt_id"], ["decision_receipts.tenant_id", "decision_receipts.receipt_id"], name="fk_phase5_decision_receipt_v2", ondelete="CASCADE"),
        sa.CheckConstraint("policy_epoch > 0", name="ck_phase5_decision_positive_epoch"),
    )
    op.create_table(
        "approval_binding_v2_extensions",
        sa.Column("approval_request_id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("binding_id", sa.String(36), nullable=False), sa.Column("canonical_action_hash", sa.String(64), nullable=False),
        sa.Column("material_fields_hash", sa.String(64), nullable=False), sa.Column("profile_selection_id", sa.String(36), nullable=True),
        sa.Column("profile_selection_hash", sa.String(64), nullable=True), sa.Column("control_plan_digest", sa.String(64), nullable=True),
        sa.Column("policy_epoch", sa.Integer(), nullable=False), sa.Column("use_limit", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("permitted_variation_envelope_id", sa.String(36), nullable=False),
        sa.Column("permitted_variation_hash", sa.String(64), nullable=False), sa.Column("permitted_variation_envelope", sa.JSON(), nullable=False),
        sa.Column("trusted_approval_rendering_hash", sa.String(64), nullable=False), sa.Column("decision_idempotency_key", sa.String(128), nullable=False),
        sa.Column("binding_hash", sa.String(64), nullable=False), sa.Column("signed_envelope", sa.JSON(), nullable=False),
        sa.Column("algorithm", sa.String(16), nullable=False), sa.Column("signing_key_id", sa.String(64), nullable=False), sa.Column("signature", sa.String(128), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id", "approval_request_id"], ["approval_requests.tenant_id", "approval_requests.id"], name="fk_phase5_approval_request_v2", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "binding_id", name="uq_phase5_approval_binding_id"),
        sa.CheckConstraint("policy_epoch > 0", name="ck_phase5_approval_positive_epoch"), sa.CheckConstraint("use_limit > 0 AND use_limit <= 100", name="ck_phase5_approval_use_limit"),
    )
    op.create_table(
        "approval_authority_events_v2",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("approval_request_id", sa.String(36), nullable=False), sa.Column("binding_id", sa.String(36), nullable=True),
        sa.Column("sequence", sa.Integer(), nullable=False), sa.Column("event_type", sa.String(32), nullable=False), sa.Column("decision", sa.String(16), nullable=True),
        sa.Column("request_version", sa.Integer(), nullable=False), sa.Column("body_hash", sa.String(64), nullable=False),
        sa.Column("prior_event_id", sa.String(36), nullable=True), sa.Column("prior_event_hash", sa.String(64), nullable=True),
        sa.Column("idempotency_key", sa.String(128), nullable=False), sa.Column("reason_code", sa.String(128), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False), sa.Column("algorithm", sa.String(16), nullable=False),
        sa.Column("signing_key_id", sa.String(64), nullable=False), sa.Column("signature", sa.String(128), nullable=False), sa.Column("signed_envelope", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id", "approval_request_id"], ["approval_requests.tenant_id", "approval_requests.id"], name="fk_phase5_approval_event_request", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "approval_request_id", "sequence", name="uq_phase5_approval_event_sequence"),
        sa.UniqueConstraint("tenant_id", "approval_request_id", "idempotency_key", name="uq_phase5_approval_idempotency"),
    )
    op.create_table(
        "approval_authority_projections_v2",
        sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("approval_request_id", sa.String(36), nullable=False),
        sa.Column("state", sa.String(32), nullable=False), sa.Column("uses_consumed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("state_version", sa.Integer(), nullable=False, server_default="0"), sa.Column("reconstruction_status", sa.String(16), nullable=False, server_default="VERIFIED"),
        sa.Column("history_head_event_id", sa.String(36), nullable=True), sa.Column("history_head_event_hash", sa.String(64), nullable=True),
        sa.Column("history_head_sequence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["tenant_id", "approval_request_id"], ["approval_requests.tenant_id", "approval_requests.id"], name="fk_phase5_approval_projection_request", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("tenant_id", "approval_request_id"),
    )
    op.create_table(
        "execution_permit_attempts_v2",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("attempt_id", sa.String(36), nullable=False),
        sa.Column("action_id", sa.String(64), nullable=False), sa.Column("canonical_action_hash", sa.String(64), nullable=False), sa.Column("material_fields_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.UniqueConstraint("tenant_id", "attempt_id", name="uq_phase5_attempt_tenant_attempt"),
    )
    op.create_table(
        "execution_permits_v2",
        sa.Column("permit_id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("action_id", sa.String(64), nullable=False),
        sa.Column("attempt_id", sa.String(36), nullable=False), sa.Column("decision_receipt_id", sa.String(36), nullable=True), sa.Column("approval_binding_id", sa.String(36), nullable=True),
        sa.Column("permitted_variation_hash", sa.String(64), nullable=True), sa.Column("canonical_action_hash", sa.String(64), nullable=False), sa.Column("material_fields_hash", sa.String(64), nullable=False),
        sa.Column("policy_epoch", sa.Integer(), nullable=False), sa.Column("control_plan_digest", sa.String(64), nullable=True),
        sa.Column("action_plan_binding_type", sa.String(32), nullable=False, server_default="STANDALONE"), sa.Column("action_plan_id", sa.String(36), nullable=True), sa.Column("action_plan_digest", sa.String(64), nullable=True), sa.Column("action_plan_step_id", sa.String(36), nullable=True), sa.Column("action_plan_step_digest", sa.String(64), nullable=True),
        sa.Column("algorithm", sa.String(16), nullable=False), sa.Column("signing_key_id", sa.String(64), nullable=False), sa.Column("signature", sa.String(128), nullable=False), sa.Column("signed_envelope", sa.JSON(), nullable=False),
        sa.Column("state", sa.String(32), nullable=False, server_default="ISSUED"), sa.Column("state_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("claim_id", sa.String(36), nullable=True), sa.Column("claimed_by_ref", sa.String(255), nullable=True), sa.Column("claim_lease_expires_at", sa.DateTime(timezone=True), nullable=True), sa.Column("reconstruction_status", sa.String(16), nullable=False, server_default="VERIFIED"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.UniqueConstraint("tenant_id", "permit_id", name="uq_execution_permits_v2_tenant_permit"),
        sa.CheckConstraint("policy_epoch > 0", name="ck_phase5_permit_positive_epoch"),
    )
    op.create_table(
        "execution_permit_transitions_v2",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("permit_id", sa.String(36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False), sa.Column("from_state", sa.String(32), nullable=False), sa.Column("to_state", sa.String(32), nullable=False),
        sa.Column("prior_state_version", sa.Integer(), nullable=False), sa.Column("new_state_version", sa.Integer(), nullable=False), sa.Column("claim_id", sa.String(36), nullable=True), sa.Column("claimed_by_ref", sa.String(255), nullable=True), sa.Column("claim_lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executor_invocation_state", sa.String(32), nullable=False), sa.Column("reason_code", sa.String(128), nullable=True), sa.Column("idempotency_key", sa.String(128), nullable=False), sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("algorithm", sa.String(16), nullable=False), sa.Column("signing_key_id", sa.String(64), nullable=False), sa.Column("signature", sa.String(128), nullable=False), sa.Column("signed_envelope", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id", "permit_id"], ["execution_permits_v2.tenant_id", "execution_permits_v2.permit_id"], name="fk_phase5_permit_transition", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "permit_id", "sequence", name="uq_phase5_permit_transition_sequence"), sa.UniqueConstraint("tenant_id", "permit_id", "idempotency_key", name="uq_phase5_permit_transition_idempotency"),
    )
    op.create_table("execution_receipt_v2_extensions", sa.Column("receipt_id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("attempt_id", sa.String(36), nullable=False), sa.Column("permit_id", sa.String(36), nullable=True), sa.Column("canonical_action_hash", sa.String(64), nullable=False), sa.Column("actual_material_fields_hash", sa.String(64), nullable=False), sa.Column("terminal_state", sa.String(32), nullable=False), sa.Column("evidence_quality", sa.String(32), nullable=False), sa.Column("algorithm", sa.String(16), nullable=False), sa.Column("signing_key_id", sa.String(64), nullable=False), sa.Column("signature", sa.String(128), nullable=False), sa.Column("signed_envelope", sa.JSON(), nullable=False), sa.ForeignKeyConstraint(["tenant_id", "receipt_id"], ["execution_receipts.tenant_id", "execution_receipts.receipt_id"], name="fk_phase5_execution_receipt_v2", ondelete="CASCADE"))
    op.create_table("execution_comparisons_v2", sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("attempt_id", sa.String(36), nullable=False), sa.Column("decision_receipt_id", sa.String(36), nullable=True), sa.Column("execution_receipt_id", sa.String(36), nullable=True), sa.Column("result", sa.String(32), nullable=False), sa.Column("material_differences", sa.JSON(), nullable=False), sa.Column("unresolved_fields", sa.JSON(), nullable=False), sa.Column("algorithm", sa.String(16), nullable=False), sa.Column("signing_key_id", sa.String(64), nullable=False), sa.Column("signature", sa.String(128), nullable=False), sa.Column("signed_envelope", sa.JSON(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")), sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.UniqueConstraint("tenant_id", "attempt_id", name="uq_phase5_comparison_attempt"))
    op.create_table("action_plans_v2", sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("parent_action_id", sa.String(64), nullable=False), sa.Column("plan_id", sa.String(36), nullable=False), sa.Column("plan_version", sa.Integer(), nullable=False), sa.Column("plan_digest", sa.String(64), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("algorithm", sa.String(16), nullable=False), sa.Column("signing_key_id", sa.String(64), nullable=False), sa.Column("signature", sa.String(128), nullable=False), sa.Column("signed_envelope", sa.JSON(), nullable=False), sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.UniqueConstraint("tenant_id", "plan_id", name="uq_phase5_plan_id"), sa.UniqueConstraint("tenant_id", "parent_action_id", "plan_version", name="uq_phase5_plan_parent_version"))
    op.create_table("action_plan_steps_v2", sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("plan_id", sa.String(36), nullable=False), sa.Column("step_id", sa.String(36), nullable=False), sa.Column("step_sequence", sa.Integer(), nullable=False), sa.Column("step_digest", sa.String(64), nullable=False), sa.Column("child_action_id", sa.String(64), nullable=False), sa.Column("authority_mode", sa.String(32), nullable=False), sa.Column("unbound_material_fields_hash", sa.String(64), nullable=False), sa.ForeignKeyConstraint(["tenant_id", "plan_id"], ["action_plans_v2.tenant_id", "action_plans_v2.plan_id"], name="fk_phase5_plan_step_plan", ondelete="CASCADE"), sa.UniqueConstraint("tenant_id", "plan_id", "step_sequence", name="uq_phase5_plan_step_sequence"), sa.UniqueConstraint("tenant_id", "step_id", name="uq_phase5_plan_step_id"))
    op.create_table("persistent_effects_v2", sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("action_id", sa.String(64), nullable=False), sa.Column("attempt_id", sa.String(36), nullable=False), sa.Column("execution_receipt_id", sa.String(36), nullable=True), sa.Column("downstream_object_hash", sa.String(64), nullable=False), sa.Column("expected_object_state_hash", sa.String(64), nullable=False), sa.Column("state", sa.String(32), nullable=False), sa.Column("state_version", sa.Integer(), nullable=False, server_default="0"), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("algorithm", sa.String(16), nullable=False), sa.Column("signing_key_id", sa.String(64), nullable=False), sa.Column("signature", sa.String(128), nullable=False), sa.Column("signed_envelope", sa.JSON(), nullable=False), sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.UniqueConstraint("tenant_id", "action_id", "attempt_id", "downstream_object_hash", name="uq_phase5_effect_attempt_object"), sa.UniqueConstraint("tenant_id", "id", name="uq_phase5_effect_tenant_id"))
    op.create_table("persistent_effect_transitions_v2", sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("effect_id", sa.String(36), nullable=False), sa.Column("sequence", sa.Integer(), nullable=False), sa.Column("from_state", sa.String(32), nullable=False), sa.Column("to_state", sa.String(32), nullable=False), sa.Column("prior_state_version", sa.Integer(), nullable=False), sa.Column("new_state_version", sa.Integer(), nullable=False), sa.Column("evidence_quality", sa.String(32), nullable=False), sa.Column("idempotency_key", sa.String(128), nullable=False), sa.Column("algorithm", sa.String(16), nullable=False), sa.Column("signing_key_id", sa.String(64), nullable=False), sa.Column("signature", sa.String(128), nullable=False), sa.ForeignKeyConstraint(["tenant_id", "effect_id"], ["persistent_effects_v2.tenant_id", "persistent_effects_v2.id"], name="fk_phase5_effect_transition", ondelete="CASCADE"), sa.UniqueConstraint("tenant_id", "effect_id", "sequence", name="uq_phase5_effect_transition_sequence"), sa.UniqueConstraint("tenant_id", "effect_id", "idempotency_key", name="uq_phase5_effect_transition_idempotency"))
    op.create_table("delegation_contexts_v2", sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("delegation_context_id", sa.String(36), nullable=False), sa.Column("parent_action_id", sa.String(64), nullable=False), sa.Column("source_principal_ref", sa.String(255), nullable=False), sa.Column("destination_principal_ref", sa.String(255), nullable=False), sa.Column("authority_scope_hash", sa.String(64), nullable=False), sa.Column("depth", sa.Integer(), nullable=False), sa.Column("state", sa.String(32), nullable=False, server_default="REGISTERED"), sa.Column("state_version", sa.Integer(), nullable=False, server_default="0"), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("algorithm", sa.String(16), nullable=False), sa.Column("signing_key_id", sa.String(64), nullable=False), sa.Column("signature", sa.String(128), nullable=False), sa.Column("signed_envelope", sa.JSON(), nullable=False), sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.UniqueConstraint("tenant_id", "delegation_context_id", name="uq_phase5_delegation_context"))
    op.create_table("delegation_lifecycle_events_v2", sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("delegation_context_id", sa.String(36), nullable=False), sa.Column("sequence", sa.Integer(), nullable=False), sa.Column("event_type", sa.String(32), nullable=False), sa.Column("from_state", sa.String(32), nullable=False), sa.Column("to_state", sa.String(32), nullable=False), sa.Column("prior_state_version", sa.Integer(), nullable=False), sa.Column("new_state_version", sa.Integer(), nullable=False), sa.Column("idempotency_key", sa.String(128), nullable=False), sa.Column("algorithm", sa.String(16), nullable=False), sa.Column("signing_key_id", sa.String(64), nullable=False), sa.Column("signature", sa.String(128), nullable=False), sa.ForeignKeyConstraint(["tenant_id", "delegation_context_id"], ["delegation_contexts_v2.tenant_id", "delegation_contexts_v2.delegation_context_id"], name="fk_phase5_delegation_event_context", ondelete="CASCADE"), sa.UniqueConstraint("tenant_id", "delegation_context_id", "sequence", name="uq_phase5_delegation_event_sequence"), sa.UniqueConstraint("tenant_id", "delegation_context_id", "idempotency_key", name="uq_phase5_delegation_event_idempotency"))
    op.create_table("expected_outcomes_v2", sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("outcome_contract_id", sa.String(36), nullable=False), sa.Column("action_id", sa.String(64), nullable=False), sa.Column("expected_state_hash", sa.String(64), nullable=True), sa.Column("verification_deadline", sa.DateTime(timezone=True), nullable=False), sa.Column("algorithm", sa.String(16), nullable=False), sa.Column("signing_key_id", sa.String(64), nullable=False), sa.Column("signature", sa.String(128), nullable=False), sa.Column("signed_envelope", sa.JSON(), nullable=False), sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.UniqueConstraint("tenant_id", "outcome_contract_id", name="uq_phase5_outcome_contract"))
    op.create_table("outcome_verifications_v2", sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("verification_id", sa.String(36), nullable=False), sa.Column("action_id", sa.String(64), nullable=False), sa.Column("attempt_id", sa.String(36), nullable=False), sa.Column("outcome_contract_id", sa.String(36), nullable=False), sa.Column("execution_receipt_id", sa.String(36), nullable=True), sa.Column("result", sa.String(32), nullable=False), sa.Column("verification_source_set_hash", sa.String(64), nullable=False), sa.Column("evidence_quality", sa.String(32), nullable=False), sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False), sa.Column("algorithm", sa.String(16), nullable=False), sa.Column("signing_key_id", sa.String(64), nullable=False), sa.Column("signature", sa.String(128), nullable=False), sa.Column("signed_envelope", sa.JSON(), nullable=False), sa.ForeignKeyConstraint(["tenant_id", "outcome_contract_id"], ["expected_outcomes_v2.tenant_id", "expected_outcomes_v2.outcome_contract_id"], name="fk_phase5_verification_outcome", ondelete="CASCADE"), sa.UniqueConstraint("tenant_id", "attempt_id", "outcome_contract_id", "verification_source_set_hash", name="uq_phase5_outcome_verification_source"))
    op.create_table("banking_execution_grant_v2_links", sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("banking_execution_grant_id", sa.String(36), nullable=False), sa.Column("execution_permit_id", sa.String(36), nullable=False), sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"), sa.PrimaryKeyConstraint("tenant_id", "banking_execution_grant_id"), sa.UniqueConstraint("tenant_id", "execution_permit_id", name="uq_phase5_banking_permit_link"))
    # These histories are append-only evidence, separate from permit state.
    # 0066 has not been deployed: define their complete registry shape here so
    # a later migration does not need to reinterpret partial lifecycle rows.
    with op.batch_alter_table("execution_permit_attempts_v2") as batch:
        batch.add_column(sa.Column("action_plan_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("action_plan_step_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("decision_receipt_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("execution_permit_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("state_version", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("next_sequence", sa.Integer(), nullable=False, server_default="1"))
        batch.add_column(sa.Column("terminal_execution_receipt_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")))
        batch.add_column(sa.Column("terminal_at", sa.DateTime(timezone=True), nullable=True))
        batch.create_check_constraint("ck_phase5_action_attempt_sequence", "state_version >= 0 AND next_sequence > 0")
    with op.batch_alter_table("action_plans_v2") as batch:
        batch.add_column(sa.Column("resource_boundary_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("target_boundary_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("destination_boundary_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("max_total_executions", sa.Integer(), nullable=False, server_default="1"))
        batch.add_column(sa.Column("completion_rule", sa.String(32), nullable=False, server_default="ALL_REQUIRED"))
        batch.add_column(sa.Column("compensation_action_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")))
        batch.create_check_constraint("ck_phase5_plan_max_executions", "max_total_executions > 0 AND max_total_executions <= 100")
    with op.batch_alter_table("action_plan_steps_v2") as batch:
        batch.add_column(sa.Column("expected_child_action_class", sa.String(64), nullable=True))
        batch.add_column(sa.Column("required", sa.Boolean(), nullable=False, server_default=sa.true()))
        batch.add_column(sa.Column("permitted_predecessor_step_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")))
        batch.add_column(sa.Column("max_executions", sa.Integer(), nullable=False, server_default="1"))
        batch.add_column(sa.Column("resource_boundary_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("target_boundary_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("destination_boundary_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("compensation_action_ref", sa.String(128), nullable=True))
        batch.create_check_constraint("ck_phase5_plan_step_max_executions", "max_executions > 0 AND max_executions <= 100")
    op.create_table(
        "action_execution_transitions_v2",
        sa.Column("id", sa.String(36), primary_key=True), sa.Column("tenant_id", sa.String(36), nullable=False), sa.Column("action_id", sa.String(64), nullable=False), sa.Column("attempt_id", sa.String(36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False), sa.Column("from_state", sa.String(32), nullable=False), sa.Column("to_state", sa.String(32), nullable=False), sa.Column("prior_state_version", sa.Integer(), nullable=False), sa.Column("new_state_version", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(64), nullable=False), sa.Column("source_event_ref", sa.String(128), nullable=True), sa.Column("evidence_refs", sa.JSON(), nullable=False), sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False), sa.Column("received_at", sa.DateTime(timezone=True), nullable=False), sa.Column("reason_code", sa.String(128), nullable=True), sa.Column("idempotency_key", sa.String(128), nullable=False), sa.Column("supersedes_transition_id", sa.String(36), nullable=True), sa.Column("prior_transition_id", sa.String(36), nullable=True), sa.Column("prior_transition_hash", sa.String(64), nullable=True), sa.Column("algorithm", sa.String(16), nullable=False), sa.Column("signing_key_id", sa.String(64), nullable=False), sa.Column("signature", sa.String(128), nullable=False), sa.Column("signed_envelope", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id", "attempt_id"], ["execution_permit_attempts_v2.tenant_id", "execution_permit_attempts_v2.attempt_id"], name="fk_phase5_action_transition_attempt", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "attempt_id", "prior_transition_id"], ["action_execution_transitions_v2.tenant_id", "action_execution_transitions_v2.attempt_id", "action_execution_transitions_v2.id"], name="fk_phase5_action_transition_prior", ondelete="RESTRICT"),
        sa.UniqueConstraint("tenant_id", "attempt_id", "sequence", name="uq_phase5_action_transition_sequence"), sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_phase5_action_transition_idempotency"), sa.UniqueConstraint("tenant_id", "attempt_id", "id", name="uq_phase5_action_transition_attempt_id"),
        sa.CheckConstraint("sequence > 0 AND new_state_version = prior_state_version + 1", name="ck_phase5_action_transition_version"),
    )
    with op.batch_alter_table("persistent_effects_v2") as batch:
        for column in (
            sa.Column("owner_ref", sa.String(255), nullable=True), sa.Column("scope_hash", sa.String(64), nullable=True), sa.Column("current_observed_object_hash", sa.String(64), nullable=True), sa.Column("evidence_quality", sa.String(32), nullable=True), sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True), sa.Column("verification_valid_until", sa.DateTime(timezone=True), nullable=True), sa.Column("recovery_requires_remediation", sa.Boolean(), nullable=False, server_default=sa.false()), sa.Column("recovery_basis", sa.String(32), nullable=True), sa.Column("remediation_action_id", sa.String(64), nullable=True), sa.Column("remediation_attempt_id", sa.String(36), nullable=True), sa.Column("remediation_execution_receipt_id", sa.String(36), nullable=True), sa.Column("remediation_outcome_verification_id", sa.String(36), nullable=True), sa.Column("history_head_transition_id", sa.String(36), nullable=True), sa.Column("history_head_transition_hash", sa.String(64), nullable=True), sa.Column("history_head_sequence", sa.Integer(), nullable=False, server_default="0"), sa.Column("reconstruction_status", sa.String(16), nullable=False, server_default="VERIFIED"), sa.Column("terminal_at", sa.DateTime(timezone=True), nullable=True),
        ):
            batch.add_column(column)
    with op.batch_alter_table("persistent_effect_transitions_v2") as batch:
        for column in (
            sa.Column("prior_transition_id", sa.String(36), nullable=True), sa.Column("prior_transition_hash", sa.String(64), nullable=True), sa.Column("transition_kind", sa.String(32), nullable=False, server_default="STATE_CHANGE"), sa.Column("observed_object_hash", sa.String(64), nullable=True), sa.Column("verification_source_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")), sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True), sa.Column("verification_valid_until", sa.DateTime(timezone=True), nullable=True), sa.Column("recovery_basis", sa.String(32), nullable=False, server_default="NONE"), sa.Column("remediation_action_id", sa.String(64), nullable=True), sa.Column("remediation_attempt_id", sa.String(36), nullable=True), sa.Column("remediation_execution_receipt_id", sa.String(36), nullable=True), sa.Column("remediation_outcome_verification_id", sa.String(36), nullable=True), sa.Column("reason_code", sa.String(128), nullable=True), sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")), sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")), sa.Column("signed_envelope", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        ):
            batch.add_column(column)
        batch.create_unique_constraint("uq_phase5_effect_transition_state_version", ["tenant_id", "effect_id", "new_state_version"])
        batch.create_unique_constraint("uq_phase5_effect_transition_effect_id", ["tenant_id", "effect_id", "id"])
        batch.create_foreign_key("fk_phase5_effect_transition_prior", "persistent_effect_transitions_v2", ["tenant_id", "effect_id", "prior_transition_id"], ["tenant_id", "effect_id", "id"], ondelete="RESTRICT")
        batch.create_check_constraint("ck_phase5_effect_transition_version", "sequence > 0 AND new_state_version = prior_state_version + 1")
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in ("action_execution_transitions_v2", "persistent_effect_transitions_v2"):
            op.execute(sa.text(f"CREATE FUNCTION phase5_no_{table}_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'phase5 append-only history'; END; $$"))
            op.execute(sa.text(f"CREATE TRIGGER trg_no_{table}_mutation BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION phase5_no_{table}_mutation()"))
    elif bind.dialect.name == "sqlite":
        for table in ("action_execution_transitions_v2", "persistent_effect_transitions_v2"):
            op.execute(sa.text(f"CREATE TRIGGER trg_no_{table}_update BEFORE UPDATE ON {table} BEGIN SELECT RAISE(ABORT, 'phase5 append-only history'); END"))
            op.execute(sa.text(f"CREATE TRIGGER trg_no_{table}_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT, 'phase5 append-only history'); END"))


def downgrade() -> None:
    _refuse_downgrade_when_authority_exists()
    for table in _LIFECYCLE_TABLES:
        op.drop_table(table)
    with op.batch_alter_table("approval_requests") as batch:
        batch.drop_constraint("ck_phase5_approval_request_version", type_="check")
        batch.drop_constraint("uq_approval_requests_tenant_id", type_="unique")
        batch.drop_column("authority_schema_version")
        batch.drop_column("decision_version")
