"""path-native Control Coverage projections

Revision ID: 0045_control_coverage
Revises: 0044_canonical_evidence_bundles
"""

from alembic import op
import sqlalchemy as sa


revision = "0045_control_coverage"
down_revision = "0044_canonical_evidence_bundles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "deployment_surfaces",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("source_kind", sa.String(length=32), nullable=False),
        sa.Column("source_id", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("surface_type", sa.String(length=64), nullable=False),
        sa.Column("deployment_mode", sa.String(length=64), nullable=False),
        sa.Column("environment", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("capability_profile", sa.JSON(), nullable=False),
        sa.Column("capability_sources", sa.JSON(), nullable=False),
        sa.Column("health_status", sa.String(length=32), nullable=False),
        sa.Column("health_reason", sa.String(length=128), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "health_status IN ('healthy','warning','degraded','offline','unknown')",
            name="ck_deployment_surface_health_status",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_deployment_surface_tenant_id"),
        sa.UniqueConstraint("tenant_id", "source_kind", "source_id", name="uq_deployment_surface_tenant_source"),
    )
    op.create_index("idx_deployment_surface_tenant_status", "deployment_surfaces", ["tenant_id", "status"])
    op.create_index("idx_deployment_surface_tenant_type", "deployment_surfaces", ["tenant_id", "surface_type"])
    op.create_index("idx_deployment_surface_tenant_seen", "deployment_surfaces", ["tenant_id", "last_seen_at"])

    op.create_table(
        "control_coverage_paths",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("path_key", sa.String(length=64), nullable=False),
        sa.Column("key_version", sa.String(length=16), nullable=False),
        sa.Column("asset_ref", sa.String(length=255), nullable=False),
        sa.Column("identity_type", sa.String(length=32), nullable=False),
        sa.Column("identity_ref", sa.String(length=255), nullable=False),
        sa.Column("runtime_ref", sa.String(length=255), nullable=False),
        sa.Column("deployment_surface_id", sa.String(length=36), nullable=True),
        sa.Column("deployment_surface_ref", sa.String(length=255), nullable=False),
        sa.Column("destination_type", sa.String(length=32), nullable=False),
        sa.Column("destination_ref", sa.String(length=255), nullable=False),
        sa.Column("lifecycle_status", sa.String(length=32), nullable=False),
        sa.Column("source_refs", sa.JSON(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "deployment_surface_id"],
            ["deployment_surfaces.tenant_id", "deployment_surfaces.id"],
            name="fk_control_coverage_path_tenant_surface",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_control_coverage_path_tenant_id"),
        sa.UniqueConstraint("tenant_id", "path_key", name="uq_control_coverage_path_tenant_key"),
    )
    op.create_index("idx_control_coverage_path_tenant_seen", "control_coverage_paths", ["tenant_id", "last_seen_at"])
    op.create_index("idx_control_coverage_path_tenant_asset", "control_coverage_paths", ["tenant_id", "asset_ref"])
    op.create_index("idx_control_coverage_path_tenant_identity", "control_coverage_paths", ["tenant_id", "identity_ref"])

    op.create_table(
        "control_coverage_assertions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("path_id", sa.String(length=36), nullable=False),
        sa.Column("dimension", sa.String(length=32), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column("explanation", sa.String(length=500), nullable=False),
        sa.Column("methodology_version", sa.String(length=32), nullable=False),
        sa.Column("evaluator_version", sa.String(length=32), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
        sa.Column("source_watermark", sa.String(length=128), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "dimension IN ('discovery','identity','authorization','evidence','deployment','runtime','bypass')",
            name="ck_control_coverage_assertion_dimension",
        ),
        sa.CheckConstraint(
            "state IN ('covered','not_covered','unknown','not_applicable')",
            name="ck_control_coverage_assertion_state",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "path_id"],
            ["control_coverage_paths.tenant_id", "control_coverage_paths.id"],
            name="fk_control_coverage_assertion_tenant_path",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "path_id",
            "dimension",
            "methodology_version",
            name="uq_control_coverage_assertion_current",
        ),
    )
    op.create_index(
        "idx_control_coverage_assertion_tenant_state",
        "control_coverage_assertions",
        ["tenant_id", "dimension", "state"],
    )
    op.create_index(
        "idx_control_coverage_assertion_tenant_valid",
        "control_coverage_assertions",
        ["tenant_id", "valid_until"],
    )

    op.create_table(
        "control_coverage_snapshots",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("methodology_version", sa.String(length=32), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("input_digest", sa.String(length=64), nullable=False),
        sa.Column("headline_counts", sa.JSON(), nullable=False),
        sa.Column("headline_score", sa.Float(), nullable=True),
        sa.Column("dimension_summaries", sa.JSON(), nullable=False),
        sa.Column("input_watermarks", sa.JSON(), nullable=False),
        sa.Column("diagnostics", sa.JSON(), nullable=False),
        sa.Column("freshness_status", sa.String(length=32), nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "headline_score IS NULL OR (headline_score >= 0 AND headline_score <= 100)",
            name="ck_control_coverage_snapshot_score",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "methodology_version",
            "window_start",
            "window_end",
            "input_digest",
            name="uq_control_coverage_snapshot_input",
        ),
    )
    op.create_index(
        "idx_control_coverage_snapshot_tenant_time",
        "control_coverage_snapshots",
        ["tenant_id", "computed_at"],
    )


def downgrade() -> None:
    op.drop_table("control_coverage_assertions")
    op.drop_table("control_coverage_snapshots")
    op.drop_table("control_coverage_paths")
    op.drop_table("deployment_surfaces")
