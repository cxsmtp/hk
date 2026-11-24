"""Add bounded Phase 7 AI activity lineage and investigations.

Revision ID: 0071_phase7_activity_lineage
Revises: 0070_phase6_continuous_assurance
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0071_phase7_activity_lineage"
down_revision = "0070_phase6_continuous_assurance"
branch_labels = None
depends_on = None


_NODE_TYPES = (
    "'HUMAN','EXTERNAL_USER','AGENT','SERVICE','WORKLOAD','AI_APPLICATION','MODEL','RUNTIME','TOOL',"
    "'MCP_SERVER','MCP_TOOL','API','CONTROL_POINT','POLICY','APPROVAL','DECISION_RECEIPT',"
    "'EXECUTION_PERMIT','EXECUTION_RECEIPT','RESOURCE','TARGET','DESTINATION','PERSISTENT_EFFECT',"
    "'VALIDATION_RUN','DRIFT_SIGNAL','OUTCOME','ACTION'"
)
_EDGE_TYPES = (
    "'INITIATED','ACTING_ON_BEHALF_OF','REPRESENTS','DELEGATED_TO','EXECUTED_BY','CALLED','USED_MODEL',"
    "'USED_TOOL','ROUTED_THROUGH','CONTROLLED_BY','AUTHORISED_BY','APPROVED_BY','PERMITTED_BY','TARGETED',"
    "'READ','MODIFIED','CREATED','DELETED','SENT_TO','PRODUCED','VERIFIED_BY','DRIFTED_FROM',"
    "'CREATED_PERSISTENT_EFFECT','TRIGGERED','VALIDATED_BY','PARENT_OF'"
)
_CERTAINTY = "'CONFIRMED','CORRELATED','INFERRED','UNKNOWN'"


def upgrade() -> None:
    op.create_table(
        "activity_lineages",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("lineage_key", sa.String(64), nullable=False),
        sa.Column("source_watermark", sa.String(64), nullable=False),
        sa.Column("schema_version", sa.String(16), nullable=False, server_default="1.0"),
        sa.Column("seed_action_id", sa.String(64), nullable=False),
        sa.Column("seed_runtime_event_id", sa.String(36), nullable=False),
        sa.Column("root_action_id", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="PARTIAL"),
        sa.Column("blind_spots", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("id", sa.String(36), nullable=False),
        sa.CheckConstraint("status IN ('COMPLETE','PARTIAL')", name="ck_phase7_lineage_status"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_phase7_lineage_tenant_id"),
        sa.UniqueConstraint("tenant_id", "lineage_key", "source_watermark", name="uq_phase7_lineage_snapshot"),
    )
    op.create_index("idx_phase7_lineage_action", "activity_lineages", ["tenant_id", "seed_action_id", "created_at"])
    op.create_index("idx_phase7_lineage_event", "activity_lineages", ["tenant_id", "seed_runtime_event_id"])

    op.create_table(
        "activity_lineage_nodes",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("lineage_id", sa.String(36), nullable=False),
        sa.Column("node_key", sa.String(64), nullable=False),
        sa.Column("node_type", sa.String(32), nullable=False),
        sa.Column("authority_type", sa.String(64), nullable=False),
        sa.Column("authority_id", sa.String(255), nullable=False),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column("certainty", sa.String(16), nullable=False),
        sa.Column("evidence_quality", sa.String(64), nullable=False, server_default="UNKNOWN"),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
        sa.Column("safe_attributes", sa.JSON(), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.String(36), nullable=False),
        sa.CheckConstraint(f"node_type IN ({_NODE_TYPES})", name="ck_phase7_node_type"),
        sa.CheckConstraint(f"certainty IN ({_CERTAINTY})", name="ck_phase7_node_certainty"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "lineage_id"], ["activity_lineages.tenant_id", "activity_lineages.id"],
            name="fk_phase7_node_lineage", ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "lineage_id", "id", name="uq_phase7_node_tenant_id"),
        sa.UniqueConstraint("tenant_id", "lineage_id", "node_key", name="uq_phase7_lineage_node_key"),
    )
    op.create_index("idx_phase7_node_authority", "activity_lineage_nodes", ["tenant_id", "authority_type", "authority_id"])
    op.create_index("idx_phase7_node_lineage_ordinal", "activity_lineage_nodes", ["tenant_id", "lineage_id", "ordinal"])

    op.create_table(
        "activity_lineage_edges",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("lineage_id", sa.String(36), nullable=False),
        sa.Column("edge_key", sa.String(64), nullable=False),
        sa.Column("from_node_id", sa.String(36), nullable=False),
        sa.Column("to_node_id", sa.String(36), nullable=False),
        sa.Column("edge_type", sa.String(40), nullable=False),
        sa.Column("certainty", sa.String(16), nullable=False),
        sa.Column("evidence_quality", sa.String(64), nullable=False, server_default="UNKNOWN"),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
        sa.Column("safe_attributes", sa.JSON(), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.String(36), nullable=False),
        sa.CheckConstraint(f"edge_type IN ({_EDGE_TYPES})", name="ck_phase7_edge_type"),
        sa.CheckConstraint(f"certainty IN ({_CERTAINTY})", name="ck_phase7_edge_certainty"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "lineage_id"], ["activity_lineages.tenant_id", "activity_lineages.id"],
            name="fk_phase7_edge_lineage", ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "from_node_id"],
            ["activity_lineage_nodes.tenant_id", "activity_lineage_nodes.lineage_id", "activity_lineage_nodes.id"],
            name="fk_phase7_edge_from_node", ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "to_node_id"],
            ["activity_lineage_nodes.tenant_id", "activity_lineage_nodes.lineage_id", "activity_lineage_nodes.id"],
            name="fk_phase7_edge_to_node", ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "lineage_id", "edge_key", name="uq_phase7_lineage_edge_key"),
    )
    op.create_index("idx_phase7_edge_from", "activity_lineage_edges", ["tenant_id", "lineage_id", "from_node_id"])
    op.create_index("idx_phase7_edge_to", "activity_lineage_edges", ["tenant_id", "lineage_id", "to_node_id"])

    op.create_table(
        "activity_investigations",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("lineage_id", sa.String(36), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("owner_ref", sa.String(255), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="OPEN"),
        sa.Column("seed_action_id", sa.String(64), nullable=False),
        sa.Column("seed_runtime_event_id", sa.String(36), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("saved_query", sa.JSON(), nullable=False),
        sa.Column("time_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("time_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("status IN ('OPEN','IN_REVIEW','RESOLVED','CLOSED')", name="ck_phase7_investigation_status"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "lineage_id"], ["activity_lineages.tenant_id", "activity_lineages.id"],
            name="fk_phase7_investigation_lineage", ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_phase7_investigation_tenant_id"),
    )
    op.create_index("idx_phase7_investigation_owner", "activity_investigations", ["tenant_id", "owner_ref", "status"])

    op.create_table(
        "activity_investigation_findings",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("investigation_id", sa.String(36), nullable=False),
        sa.Column("finding_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("reason_code", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="OPEN"),
        sa.Column("lineage_node_ids", sa.JSON(), nullable=False),
        sa.Column("lineage_edge_ids", sa.JSON(), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("status IN ('OPEN','RESOLVED','DISMISSED')", name="ck_phase7_finding_status"),
        sa.CheckConstraint("severity IN ('info','low','medium','high','critical')", name="ck_phase7_finding_severity"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "investigation_id"], ["activity_investigations.tenant_id", "activity_investigations.id"],
            name="fk_phase7_finding_investigation", ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_phase7_finding_tenant_id"),
    )
    op.create_index(
        "idx_phase7_finding_investigation", "activity_investigation_findings",
        ["tenant_id", "investigation_id", "status"],
    )


def downgrade() -> None:
    op.drop_index("idx_phase7_finding_investigation", table_name="activity_investigation_findings")
    op.drop_table("activity_investigation_findings")
    op.drop_index("idx_phase7_investigation_owner", table_name="activity_investigations")
    op.drop_table("activity_investigations")
    op.drop_index("idx_phase7_edge_to", table_name="activity_lineage_edges")
    op.drop_index("idx_phase7_edge_from", table_name="activity_lineage_edges")
    op.drop_table("activity_lineage_edges")
    op.drop_index("idx_phase7_node_lineage_ordinal", table_name="activity_lineage_nodes")
    op.drop_index("idx_phase7_node_authority", table_name="activity_lineage_nodes")
    op.drop_table("activity_lineage_nodes")
    op.drop_index("idx_phase7_lineage_event", table_name="activity_lineages")
    op.drop_index("idx_phase7_lineage_action", table_name="activity_lineages")
    op.drop_table("activity_lineages")
