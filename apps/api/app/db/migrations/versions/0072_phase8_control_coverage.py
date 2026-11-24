"""Add Phase 8 evidence-backed executive Control Coverage.

Revision ID: 0072_phase8_control_coverage
Revises: 0071_phase7_activity_lineage
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0072_phase8_control_coverage"
down_revision = "0071_phase7_activity_lineage"
branch_labels = None
depends_on = None


def _snapshot_columns() -> tuple[sa.Column[object], ...]:
    """Return fresh additive columns for the existing snapshot table.

    SQLite cannot alter an existing table to add constraints, so its path uses
    Alembic's batch recreation.  PostgreSQL retains the direct, additive DDL
    that this migration originally used.
    """

    return (
        sa.Column("scope_id", sa.String(36), nullable=True),
        sa.Column("previous_snapshot_id", sa.String(36), nullable=True),
        sa.Column(
            "snapshot_kind", sa.String(32), nullable=False, server_default="path_coverage"
        ),
        sa.Column(
            "source_versions", sa.JSON(), nullable=False, server_default=sa.text("'{}'")
        ),
        sa.Column(
            "assessment_totals", sa.JSON(), nullable=False, server_default=sa.text("'{}'")
        ),
        sa.Column(
            "applicable_requirement_count", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column(
            "unknown_population", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column(
            "gap_summary", sa.JSON(), nullable=False, server_default=sa.text("'{}'")
        ),
        sa.Column(
            "comparison_summary", sa.JSON(), nullable=False, server_default=sa.text("'{}'")
        ),
    )


def upgrade() -> None:
    op.create_table(
        "coverage_scopes",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("scope_type", sa.String(32), nullable=False),
        sa.Column("scope_key", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("filters", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "scope_type IN ('tenant','business_unit','department','application','asset','agent','provider','deployment_surface','environment','domain_profile','action_class','critical_action')",
            name="ck_coverage_scope_type",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_coverage_scope_tenant_id"),
        sa.UniqueConstraint("tenant_id", "scope_type", "scope_key", name="uq_coverage_scope_tenant_key"),
    )
    op.create_index("idx_coverage_scope_tenant_type", "coverage_scopes", ["tenant_id", "scope_type"])

    if op.get_bind().dialect.name == "sqlite":
        # SQLite requires one recreate operation for added unique and foreign
        # key constraints; direct ALTER TABLE fails before the HMAIR head.
        with op.batch_alter_table("control_coverage_snapshots", recreate="always") as batch:
            batch.create_unique_constraint(
                "uq_control_coverage_snapshot_tenant_id", ["tenant_id", "id"]
            )
            for column in _snapshot_columns():
                batch.add_column(column)
            batch.create_foreign_key(
                "fk_coverage_snapshot_tenant_scope",
                "coverage_scopes",
                ["tenant_id", "scope_id"],
                ["tenant_id", "id"],
                ondelete="RESTRICT",
            )
            batch.create_foreign_key(
                "fk_coverage_snapshot_tenant_previous",
                "control_coverage_snapshots",
                ["tenant_id", "previous_snapshot_id"],
                ["tenant_id", "id"],
                ondelete="RESTRICT",
            )
    else:
        op.create_unique_constraint(
            "uq_control_coverage_snapshot_tenant_id",
            "control_coverage_snapshots",
            ["tenant_id", "id"],
        )
        for column in _snapshot_columns():
            op.add_column("control_coverage_snapshots", column)
        op.create_foreign_key(
            "fk_coverage_snapshot_tenant_scope",
            "control_coverage_snapshots",
            "coverage_scopes",
            ["tenant_id", "scope_id"],
            ["tenant_id", "id"],
            ondelete="RESTRICT",
        )
        op.create_foreign_key(
            "fk_coverage_snapshot_tenant_previous",
            "control_coverage_snapshots",
            "control_coverage_snapshots",
            ["tenant_id", "previous_snapshot_id"],
            ["tenant_id", "id"],
            ondelete="RESTRICT",
        )

    op.create_table(
        "control_coverage_assessments",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("scope_id", sa.String(36), nullable=False),
        sa.Column("snapshot_id", sa.String(36), nullable=False),
        sa.Column("assessment_key", sa.String(128), nullable=False),
        sa.Column("asset_ref", sa.String(255), nullable=False),
        sa.Column("action_class", sa.String(128), nullable=False),
        sa.Column("action_path_ref", sa.String(255), nullable=False),
        sa.Column("domain_profile_ref", sa.String(255), nullable=True),
        sa.Column("deployment_surface", sa.String(32), nullable=False),
        sa.Column("dimension", sa.String(128), nullable=False),
        sa.Column("requirement_ref", sa.String(255), nullable=False),
        sa.Column("applicability_state", sa.String(24), nullable=False),
        sa.Column("applicability_reason", sa.String(512), nullable=False),
        sa.Column("deployment_state", sa.String(24), nullable=False),
        sa.Column("capability_state", sa.String(24), nullable=False),
        sa.Column("assurance_state", sa.String(24), nullable=False),
        sa.Column("evidence_quality", sa.String(64), nullable=False),
        sa.Column("coverage_state", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(128), nullable=False),
        sa.Column("explanation", sa.String(1000), nullable=False),
        sa.Column("control_plan_ref", sa.String(255), nullable=True),
        sa.Column("expected_control_points", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("contributing_control_points", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("missing_contributions", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("bypass_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("validation_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("lineage_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("source_versions", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("criticality", sa.String(16), nullable=False, server_default="medium"),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.String(36), nullable=False),
        sa.CheckConstraint("applicability_state IN ('applicable','not_applicable','unknown')", name="ck_coverage_assessment_applicability"),
        sa.CheckConstraint("deployment_state IN ('present','configured','missing','unknown')", name="ck_coverage_assessment_deployment"),
        sa.CheckConstraint("capability_state IN ('verified','partial','unverified','experimental','unsupported','unknown')", name="ck_coverage_assessment_capability"),
        sa.CheckConstraint("assurance_state IN ('current','stale','regressed','unknown')", name="ck_coverage_assessment_assurance"),
        sa.CheckConstraint("coverage_state IN ('covered_current','covered_stale','partially_covered','configured_unvalidated','regressed','gap','unsupported','unknown','not_applicable')", name="ck_coverage_assessment_state"),
        sa.CheckConstraint("criticality IN ('info','low','medium','high','critical')", name="ck_coverage_assessment_criticality"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "scope_id"], ["coverage_scopes.tenant_id", "coverage_scopes.id"], name="fk_coverage_assessment_tenant_scope", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "snapshot_id"], ["control_coverage_snapshots.tenant_id", "control_coverage_snapshots.id"], name="fk_coverage_assessment_tenant_snapshot", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_control_coverage_assessment_tenant_id"),
        sa.UniqueConstraint("tenant_id", "snapshot_id", "assessment_key", name="uq_coverage_assessment_snapshot_key"),
    )
    op.create_index("idx_coverage_assessment_snapshot_state", "control_coverage_assessments", ["tenant_id", "snapshot_id", "coverage_state"])
    op.create_index("idx_coverage_assessment_asset_action", "control_coverage_assessments", ["tenant_id", "asset_ref", "action_class"])
    op.create_index("idx_coverage_assessment_surface_dimension", "control_coverage_assessments", ["tenant_id", "deployment_surface", "dimension"])

    op.create_table(
        "control_coverage_gaps",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("scope_id", sa.String(36), nullable=False),
        sa.Column("snapshot_id", sa.String(36), nullable=False),
        sa.Column("assessment_id", sa.String(36), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("priority", sa.String(2), nullable=False),
        sa.Column("cause", sa.String(512), nullable=False),
        sa.Column("recommended_action", sa.String(512), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("owner_ref", sa.String(255), nullable=True),
        sa.Column("remediation_ref", sa.String(255), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("priority IN ('P0','P1','P2','P3')", name="ck_coverage_gap_priority"),
        sa.CheckConstraint("status IN ('open','resolved')", name="ck_coverage_gap_status"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "scope_id"], ["coverage_scopes.tenant_id", "coverage_scopes.id"], name="fk_coverage_gap_tenant_scope", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "snapshot_id"], ["control_coverage_snapshots.tenant_id", "control_coverage_snapshots.id"], name="fk_coverage_gap_tenant_snapshot", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "assessment_id"], ["control_coverage_assessments.tenant_id", "control_coverage_assessments.id"], name="fk_coverage_gap_tenant_assessment", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "snapshot_id", "assessment_id", name="uq_coverage_gap_assessment"),
    )
    op.create_index("idx_coverage_gap_snapshot_priority", "control_coverage_gaps", ["tenant_id", "snapshot_id", "priority"])


def downgrade() -> None:
    op.drop_index("idx_coverage_gap_snapshot_priority", table_name="control_coverage_gaps")
    op.drop_table("control_coverage_gaps")
    op.drop_index("idx_coverage_assessment_surface_dimension", table_name="control_coverage_assessments")
    op.drop_index("idx_coverage_assessment_asset_action", table_name="control_coverage_assessments")
    op.drop_index("idx_coverage_assessment_snapshot_state", table_name="control_coverage_assessments")
    op.drop_table("control_coverage_assessments")
    snapshot_columns = (
        "comparison_summary", "gap_summary", "unknown_population", "applicable_requirement_count",
        "assessment_totals", "source_versions", "snapshot_kind", "previous_snapshot_id", "scope_id",
    )
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("control_coverage_snapshots", recreate="always") as batch:
            batch.drop_constraint("fk_coverage_snapshot_tenant_previous", type_="foreignkey")
            batch.drop_constraint("fk_coverage_snapshot_tenant_scope", type_="foreignkey")
            for column in snapshot_columns:
                batch.drop_column(column)
            batch.drop_constraint("uq_control_coverage_snapshot_tenant_id", type_="unique")
    else:
        op.drop_constraint("fk_coverage_snapshot_tenant_previous", "control_coverage_snapshots", type_="foreignkey")
        op.drop_constraint("fk_coverage_snapshot_tenant_scope", "control_coverage_snapshots", type_="foreignkey")
        for column in snapshot_columns:
            op.drop_column("control_coverage_snapshots", column)
        op.drop_constraint("uq_control_coverage_snapshot_tenant_id", "control_coverage_snapshots", type_="unique")
    op.drop_index("idx_coverage_scope_tenant_type", table_name="coverage_scopes")
    op.drop_table("coverage_scopes")
