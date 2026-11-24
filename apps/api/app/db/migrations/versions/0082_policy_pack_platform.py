"""Add tenant-safe Policy Pack Platform persistence.

Revision ID: 0082_policy_pack_platform
Revises: 0081_maturity_curve_review_and_pattern_context
"""

from alembic import op
import sqlalchemy as sa


revision = "0082_policy_pack_platform"
down_revision = "0081_maturity_curve_review_and_pattern_context"
branch_labels = None
depends_on = None


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
    ]


def upgrade() -> None:
    op.create_table(
        "policy_pack_platform_entitlements",
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("package_tier", sa.String(16), nullable=False, server_default="secure"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("id", sa.String(36), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", name="uq_policy_pack_platform_entitlement_tenant"),
        sa.CheckConstraint("package_tier IN ('secure','control','assurance','enterprise')", name="ck_policy_pack_platform_entitlement_tier"),
    )
    op.create_table(
        "policy_pack_definitions",
        sa.Column("publisher_tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True),
        sa.Column("publisher_ref", sa.String(128), nullable=False, server_default="hawk"),
        sa.Column("stable_pack_id", sa.String(128), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("vertical", sa.String(128), nullable=False, server_default="universal"),
        sa.Column("department_persona", sa.String(128), nullable=False, server_default="all"),
        sa.Column("pack_family", sa.String(128), nullable=False, server_default="general"),
        sa.Column("maturity_status", sa.String(32), nullable=False, server_default="draft"),
        sa.Column("package_entitlement", sa.String(16), nullable=False, server_default="secure"),
        sa.Column("applicable_jurisdictions", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("framework_mappings", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("inherited_pack_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("required_signals", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("required_control_capabilities", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("supported_deployment_surfaces", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("default_parameters", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("customization_schema", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("simulation_required", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("default_rollout", sa.String(32), nullable=False, server_default="MONITORING"),
        sa.Column("exception_guidance", sa.Text(), nullable=False, server_default=""),
        sa.Column("known_blind_spots", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("owner_publisher", sa.String(255), nullable=False, server_default="hawk"),
        sa.Column("release_notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("state", sa.String(16), nullable=False, server_default="DRAFT"),
        sa.Column("id", sa.String(36), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("publisher_ref", "stable_pack_id", "version", name="uq_policy_pack_definition_publisher_version"),
        sa.CheckConstraint("state IN ('DRAFT','PUBLISHED','DEPRECATED','WITHDRAWN')", name="ck_policy_pack_definition_state"),
        sa.CheckConstraint("package_entitlement IN ('secure','control','assurance','enterprise')", name="ck_policy_pack_definition_entitlement"),
    )
    op.create_index("idx_policy_pack_definition_tenant", "policy_pack_definitions", ["publisher_tenant_id", "state"])
    op.create_index("idx_policy_pack_definition_catalog", "policy_pack_definitions", ["stable_pack_id", "version", "state"])

    op.create_table(
        "policy_pack_templates",
        sa.Column("definition_id", sa.String(36), sa.ForeignKey("policy_pack_definitions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("template_id", sa.String(128), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("condition_tree", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("obligations", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("applicable_surfaces", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("required_fields", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("required_control_capabilities", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("default_mode", sa.String(32), nullable=False, server_default="monitor"),
        sa.Column("recommended_mature_mode", sa.String(32), nullable=False, server_default="enforce"),
        sa.Column("criticality", sa.String(32), nullable=False, server_default="medium"),
        sa.Column("override_behavior", sa.String(64), nullable=False, server_default="customer_override_allowed"),
        sa.Column("exception_rules", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("simulation_expectations", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("evidence_requirements", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("human_explanation", sa.Text(), nullable=False, server_default=""),
        sa.Column("reference_mappings", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("non_overridable", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("explicit_revocation", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("id", sa.String(36), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("definition_id", "template_id", name="uq_policy_pack_template_definition_template"),
        sa.CheckConstraint("decision IN ('allow','warn','block','redact','require_approval','require_justification','hold_for_approval')", name="ck_policy_pack_template_decision"),
    )
    op.create_index("idx_policy_pack_template_definition", "policy_pack_templates", ["definition_id", "template_id"])

    op.create_table(
        "policy_pack_instances",
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("definition_id", sa.String(36), sa.ForeignKey("policy_pack_definitions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("source_pack_id", sa.String(128), nullable=False),
        sa.Column("source_pack_version", sa.String(64), nullable=False),
        sa.Column("selected_vertical", sa.String(128), nullable=False, server_default="universal"),
        sa.Column("selected_department_persona", sa.String(128), nullable=False, server_default="all"),
        sa.Column("selected_applications", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("selected_surfaces", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("customer_parameters", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("local_overrides", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("disabled_template_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("added_customer_templates", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("rollout", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("runtime_policy_pack_id", sa.String(36), sa.ForeignKey("policy_packs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("effective_policy_version_id", sa.String(36), sa.ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("previous_effective_policy_version_id", sa.String(36), sa.ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("last_simulation_id", sa.String(36), nullable=True),
        sa.Column("update_available", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("owner_ref", sa.String(255), nullable=False),
        sa.Column("approver_ref", sa.String(255), nullable=True),
        sa.Column("state", sa.String(32), nullable=False, server_default="DRAFT"),
        sa.Column("lineage", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("id", sa.String(36), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_policy_pack_instance_tenant_id"),
        sa.CheckConstraint("state IN ('DRAFT','SIMULATING','REVIEW_REQUIRED','MONITORING','WARNING','APPROVAL_ENFORCED','ENFORCED','PAUSED','UPDATE_AVAILABLE','CONFLICTED','ROLLED_BACK','EXPIRED')", name="ck_policy_pack_instance_state"),
    )
    op.create_index("idx_policy_pack_instance_tenant_state", "policy_pack_instances", ["tenant_id", "state"])
    op.create_index("idx_policy_pack_instance_definition", "policy_pack_instances", ["tenant_id", "definition_id"])

    op.create_table(
        "policy_pack_assignments",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("instance_id", sa.String(36), nullable=False),
        sa.Column("assignment_key", sa.String(64), nullable=False),
        sa.Column("targets", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("precedence_layer", sa.Integer(), nullable=False, server_default="1000"),
        sa.Column("inherited_path", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("id", sa.String(36), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["tenant_id", "instance_id"], ["policy_pack_instances.tenant_id", "policy_pack_instances.id"], name="fk_policy_pack_assignment_tenant_instance", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "instance_id", "assignment_key", name="uq_policy_pack_assignment_key"),
    )
    op.create_index("idx_policy_pack_assignment_tenant_instance", "policy_pack_assignments", ["tenant_id", "instance_id", "active"])

    op.create_table(
        "policy_pack_user_groups",
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("group_key", sa.String(128), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("group_type", sa.String(32), nullable=False),
        sa.Column("membership_rule", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("nested_group_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("source_ref", sa.String(255), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("id", sa.String(36), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_policy_pack_user_group_tenant_id"),
        sa.UniqueConstraint("tenant_id", "group_key", name="uq_policy_pack_user_group_key"),
        sa.CheckConstraint("group_type IN ('scim','static','dynamic_attribute','role_persona','application_user','privileged_user','temporary_rollout','security_behavior','nested')", name="ck_policy_pack_user_group_type"),
    )
    op.create_index("idx_policy_pack_user_group_tenant_type", "policy_pack_user_groups", ["tenant_id", "group_type", "active"])
    op.create_table(
        "policy_pack_group_memberships",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("group_id", sa.String(36), nullable=False),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(32), nullable=False, server_default="static"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("id", sa.String(36), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["tenant_id", "group_id"], ["policy_pack_user_groups.tenant_id", "policy_pack_user_groups.id"], name="fk_policy_pack_group_membership_tenant_group", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "group_id", "user_id", name="uq_policy_pack_group_membership"),
    )
    op.create_index("idx_policy_pack_group_membership_user", "policy_pack_group_memberships", ["tenant_id", "user_id", "active"])

    op.create_table(
        "policy_pack_updates",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("instance_id", sa.String(36), nullable=False),
        sa.Column("previous_definition_id", sa.String(36), sa.ForeignKey("policy_pack_definitions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("new_definition_id", sa.String(36), sa.ForeignKey("policy_pack_definitions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("comparison", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("requires_resimulation", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("state", sa.String(16), nullable=False, server_default="AVAILABLE"),
        sa.Column("reviewed_by_ref", sa.String(255), nullable=True),
        sa.Column("review_reason", sa.Text(), nullable=True),
        sa.Column("id", sa.String(36), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["tenant_id", "instance_id"], ["policy_pack_instances.tenant_id", "policy_pack_instances.id"], name="fk_policy_pack_update_tenant_instance", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "instance_id", "new_definition_id", name="uq_policy_pack_update_instance_definition"),
        sa.CheckConstraint("state IN ('AVAILABLE','ACCEPTED','REJECTED','CONFLICTED','SUPERSEDED')", name="ck_policy_pack_update_state"),
    )
    op.create_index("idx_policy_pack_update_tenant_state", "policy_pack_updates", ["tenant_id", "state"])
    op.create_table(
        "policy_pack_simulations",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("instance_id", sa.String(36), nullable=False),
        sa.Column("policy_version_id", sa.String(36), sa.ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("outcome_counts", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("scope_breakdown", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("status", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["tenant_id", "instance_id"], ["policy_pack_instances.tenant_id", "policy_pack_instances.id"], name="fk_policy_pack_simulation_tenant_instance", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "instance_id", "input_digest", name="uq_policy_pack_simulation_input"),
        sa.CheckConstraint("status IN ('PENDING','PASSED','PARTIAL','FAILED')", name="ck_policy_pack_simulation_state"),
        sa.CheckConstraint("sample_count >= 0", name="ck_policy_pack_simulation_sample_count"),
    )
    op.create_index("idx_policy_pack_simulation_instance", "policy_pack_simulations", ["tenant_id", "instance_id", "created_at"])
    op.create_table(
        "policy_pack_exceptions",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("instance_id", sa.String(36), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("requested_by_ref", sa.String(255), nullable=False),
        sa.Column("approved_by_ref", sa.String(255), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="APPROVED"),
        sa.Column("id", sa.String(36), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["tenant_id", "instance_id"], ["policy_pack_instances.tenant_id", "policy_pack_instances.id"], name="fk_policy_pack_exception_tenant_instance", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_policy_pack_exception_tenant_id"),
        sa.CheckConstraint("status IN ('REQUESTED','APPROVED','REJECTED','REVOKED','EXPIRED')", name="ck_policy_pack_exception_state"),
    )
    op.create_index("idx_policy_pack_exception_tenant_instance", "policy_pack_exceptions", ["tenant_id", "instance_id", "status", "expires_at"])


def downgrade() -> None:
    for index, table in (
        ("idx_policy_pack_exception_tenant_instance", "policy_pack_exceptions"),
        ("idx_policy_pack_simulation_instance", "policy_pack_simulations"),
        ("idx_policy_pack_update_tenant_state", "policy_pack_updates"),
        ("idx_policy_pack_group_membership_user", "policy_pack_group_memberships"),
        ("idx_policy_pack_user_group_tenant_type", "policy_pack_user_groups"),
        ("idx_policy_pack_assignment_tenant_instance", "policy_pack_assignments"),
        ("idx_policy_pack_instance_definition", "policy_pack_instances"),
        ("idx_policy_pack_instance_tenant_state", "policy_pack_instances"),
        ("idx_policy_pack_template_definition", "policy_pack_templates"),
        ("idx_policy_pack_definition_catalog", "policy_pack_definitions"),
        ("idx_policy_pack_definition_tenant", "policy_pack_definitions"),
    ):
        op.drop_index(index, table_name=table)
    for table in (
        "policy_pack_exceptions",
        "policy_pack_simulations",
        "policy_pack_updates",
        "policy_pack_group_memberships",
        "policy_pack_user_groups",
        "policy_pack_assignments",
        "policy_pack_instances",
        "policy_pack_templates",
        "policy_pack_definitions",
        "policy_pack_platform_entitlements",
    ):
        op.drop_table(table)
