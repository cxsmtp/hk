"""Add External Capability Integrity state.

Revision ID: 0073_external_capability_integrity
Revises: 0072_phase8_control_coverage
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0073_external_capability_integrity"
down_revision = "0072_phase8_control_coverage"
branch_labels = None
depends_on = None


def _json_default(value: str) -> sa.TextClause:
    return sa.text(f"'{value}'")


def upgrade() -> None:
    op.create_table(
        "external_capability_identities",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("capability_ref", sa.String(255), nullable=False),
        sa.Column("capability_type", sa.String(32), nullable=False),
        sa.Column("configured_locator", sa.String(512), nullable=False),
        sa.Column("registry_source", sa.String(255), nullable=True),
        sa.Column("registry_identity", sa.String(255), nullable=True),
        sa.Column("publisher_identity", sa.String(255), nullable=True),
        sa.Column("observed_endpoint", sa.String(512), nullable=True),
        sa.Column("observed_identity", sa.JSON(), nullable=False, server_default=_json_default("{}")),
        sa.Column("component_fingerprints", sa.JSON(), nullable=False, server_default=_json_default("{}")),
        sa.Column("material_fingerprint", sa.String(64), nullable=False),
        sa.Column("baseline_id", sa.String(36), nullable=True),
        sa.Column("baseline_material_fingerprint", sa.String(64), nullable=True),
        sa.Column("trust_state", sa.String(32), nullable=False, server_default="UNKNOWN"),
        sa.Column("capability_epoch", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("evidence_quality", sa.String(64), nullable=False, server_default="UNKNOWN"),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("drift_summary", sa.JSON(), nullable=False, server_default=_json_default("{}")),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("revoked_by_ref", sa.String(255), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_sequence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "capability_type IN ('MCP_SERVER','MCP_TOOL','SKILL','PLUGIN','SUB_AGENT','EXTERNAL_INSTRUCTION','API_SERVICE')",
            name="ck_eci_identity_type",
        ),
        sa.CheckConstraint(
            "trust_state IN ('UNKNOWN','TRUSTED_CURRENT','STALE','REGRESSED','REVOKED')",
            name="ck_eci_identity_trust_state",
        ),
        sa.CheckConstraint("capability_epoch > 0", name="ck_eci_identity_epoch_positive"),
        sa.CheckConstraint("last_observed_sequence >= 0", name="ck_eci_identity_sequence_nonnegative"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "capability_ref", name="uq_eci_capability_ref"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_eci_identity_tenant_id"),
    )
    op.create_index("idx_eci_identity_tenant_state", "external_capability_identities", ["tenant_id", "trust_state"])
    op.create_index("idx_eci_identity_tenant_type", "external_capability_identities", ["tenant_id", "capability_type"])

    op.create_table(
        "external_capability_baselines",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("capability_id", sa.String(36), nullable=False),
        sa.Column("baseline_version", sa.Integer(), nullable=False),
        sa.Column("material_fingerprint", sa.String(64), nullable=False),
        sa.Column("component_fingerprints", sa.JSON(), nullable=False, server_default=_json_default("{}")),
        sa.Column("observed_identity", sa.JSON(), nullable=False, server_default=_json_default("{}")),
        sa.Column("verification_source", sa.String(255), nullable=False),
        sa.Column("evidence_quality", sa.String(64), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("control_assertion_ids", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("capability_epoch", sa.Integer(), nullable=False),
        sa.Column("trust_state", sa.String(32), nullable=False, server_default="TRUSTED_CURRENT"),
        sa.Column("accepted_by_ref", sa.String(255), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "trust_state IN ('UNKNOWN','TRUSTED_CURRENT','STALE','REGRESSED','REVOKED')",
            name="ck_eci_baseline_trust_state",
        ),
        sa.CheckConstraint("baseline_version > 0", name="ck_eci_baseline_version_positive"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "capability_id", "baseline_version", name="uq_eci_baseline_version"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_eci_baseline_tenant_id"),
    )
    op.create_index("idx_eci_baseline_capability", "external_capability_baselines", ["tenant_id", "capability_id"])

    op.create_table(
        "external_capability_drifts",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("capability_id", sa.String(36), nullable=False),
        sa.Column("drift_hash", sa.String(64), nullable=False),
        sa.Column("drift_type", sa.String(64), nullable=False),
        sa.Column("previous_fingerprint", sa.String(64), nullable=False),
        sa.Column("current_fingerprint", sa.String(64), nullable=False),
        sa.Column("changed_fields", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("affected_assertion_ids", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("drift_signal_id", sa.String(36), nullable=True),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("status", sa.String(16), nullable=False, server_default="OPEN"),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "drift_type IN ('CAPABILITY_IDENTITY_DRIFT','CAPABILITY_PROVENANCE_DRIFT','MCP_DRIFT','TOOL_DRIFT','SCHEMA_DRIFT','CONTROL_CAPABILITY_DRIFT')",
            name="ck_eci_drift_type",
        ),
        sa.CheckConstraint("status IN ('OPEN','REVALIDATED','REVOKED')", name="ck_eci_drift_status"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "drift_hash", name="uq_eci_drift_hash"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_eci_drift_tenant_id"),
    )
    op.create_index("idx_eci_drift_capability", "external_capability_drifts", ["tenant_id", "capability_id", "status"])

    op.create_table(
        "external_capability_validation_links",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("capability_id", sa.String(36), nullable=False),
        sa.Column("validation_run_id", sa.String(36), nullable=True),
        sa.Column("drift_id", sa.String(36), nullable=True),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=_json_default("[]")),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "capability_id", "validation_run_id", name="uq_eci_validation_link"),
    )
    op.create_index("idx_eci_validation_capability", "external_capability_validation_links", ["tenant_id", "capability_id"])


def downgrade() -> None:
    op.drop_index("idx_eci_validation_capability", table_name="external_capability_validation_links")
    op.drop_table("external_capability_validation_links")
    op.drop_index("idx_eci_drift_capability", table_name="external_capability_drifts")
    op.drop_table("external_capability_drifts")
    op.drop_index("idx_eci_baseline_capability", table_name="external_capability_baselines")
    op.drop_table("external_capability_baselines")
    op.drop_index("idx_eci_identity_tenant_type", table_name="external_capability_identities")
    op.drop_index("idx_eci_identity_tenant_state", table_name="external_capability_identities")
    op.drop_table("external_capability_identities")
