"""agentic action integrity chain controls

Revision ID: 0040_agentic_action_integrity
Revises: 0039_business_purpose_boundary
Create Date: 2026-06-19 12:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "0040_agentic_action_integrity"
down_revision = "0039_business_purpose_boundary"
branch_labels = None
depends_on = None


def _has_table(table_names: set[str], table_name: str) -> bool:
    return table_name in table_names


def _create_index(name: str, table: str, columns: list[str]) -> None:
    inspector = inspect(op.get_bind())
    existing = {item.get("name") for item in inspector.get_indexes(table)}
    if name not in existing:
        op.create_index(name, table, columns)


def upgrade() -> None:
    bind = op.get_bind()
    table_names = set(inspect(bind).get_table_names())

    if not _has_table(table_names, "ai_action_chains"):
        op.create_table(
            "ai_action_chains",
            sa.Column("tenant_id", sa.String(), nullable=False),
            sa.Column("chain_id", sa.String(length=64), nullable=False),
            sa.Column("root_action_id", sa.String(length=64), nullable=True),
            sa.Column("root_user_intent_id", sa.String(length=64), nullable=True),
            sa.Column("chain_integrity_status", sa.String(length=32), nullable=False, server_default="unknown"),
            sa.Column("chain_risk_score", sa.Float(), nullable=False, server_default="0"),
            sa.Column("metadata_json", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("tenant_id", "chain_id", name="uq_ai_action_chains_tenant_chain"),
        )
        op.create_index("idx_ai_action_chains_tenant_status", "ai_action_chains", ["tenant_id", "chain_integrity_status"])

    if not _has_table(table_names, "chain_events"):
        op.create_table(
            "chain_events",
            sa.Column("tenant_id", sa.String(), nullable=False),
            sa.Column("chain_id", sa.String(length=64), nullable=False),
            sa.Column("action_id", sa.String(length=64), nullable=True),
            sa.Column("event_type", sa.String(length=64), nullable=False),
            sa.Column("actor_type", sa.String(length=32), nullable=True),
            sa.Column("actor_id", sa.String(length=128), nullable=True),
            sa.Column("source_id", sa.String(length=128), nullable=True),
            sa.Column("destination_id", sa.String(length=128), nullable=True),
            sa.Column("source_trust_level", sa.String(length=32), nullable=True),
            sa.Column("destination_trust_level", sa.String(length=32), nullable=True),
            sa.Column("payload_ref", sa.String(length=128), nullable=True),
            sa.Column("canonical_object_ref", sa.String(length=128), nullable=True),
            sa.Column("taint_labels", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("policy_decision_id", sa.String(length=64), nullable=True),
            sa.Column("evidence_bundle_id", sa.String(), nullable=True),
            sa.Column("metadata_json", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["evidence_bundle_id"], ["evidence_nodes.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_chain_events_tenant_chain", "chain_events", ["tenant_id", "chain_id"])
        op.create_index("idx_chain_events_tenant_action", "chain_events", ["tenant_id", "action_id"])
        op.create_index("idx_chain_events_tenant_type", "chain_events", ["tenant_id", "event_type"])

    if not _has_table(table_names, "deferred_side_effects"):
        op.create_table(
            "deferred_side_effects",
            sa.Column("tenant_id", sa.String(), nullable=False),
            sa.Column("chain_id", sa.String(length=64), nullable=False),
            sa.Column("action_id", sa.String(length=64), nullable=True),
            sa.Column("agent_id", sa.String(length=128), nullable=True),
            sa.Column("side_effect_type", sa.String(length=64), nullable=False),
            sa.Column("target_system", sa.String(length=128), nullable=True),
            sa.Column("target_resource", sa.String(length=255), nullable=True),
            sa.Column("persistence_duration", sa.String(length=64), nullable=True),
            sa.Column("external_destination", sa.String(length=255), nullable=True),
            sa.Column("created_object_id", sa.String(length=128), nullable=True),
            sa.Column("monitoring_status", sa.String(length=32), nullable=False, server_default="pending"),
            sa.Column("approval_required", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("policy_decision_id", sa.String(length=64), nullable=True),
            sa.Column("evidence_bundle_id", sa.String(), nullable=True),
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["evidence_bundle_id"], ["evidence_nodes.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_deferred_side_effects_tenant_chain", "deferred_side_effects", ["tenant_id", "chain_id"])
        op.create_index("idx_deferred_side_effects_tenant_action", "deferred_side_effects", ["tenant_id", "action_id"])
        op.create_index("idx_deferred_side_effects_tenant_type", "deferred_side_effects", ["tenant_id", "side_effect_type"])

    if not _has_table(table_names, "taint_labels"):
        op.create_table(
            "taint_labels",
            sa.Column("tenant_id", sa.String(), nullable=False),
            sa.Column("chain_id", sa.String(length=64), nullable=False),
            sa.Column("action_id", sa.String(length=64), nullable=True),
            sa.Column("source_type", sa.String(length=64), nullable=False, server_default="unknown"),
            sa.Column("source_ref", sa.String(length=128), nullable=True),
            sa.Column("trust_level", sa.String(length=32), nullable=False, server_default="unknown"),
            sa.Column("taint_type", sa.String(length=64), nullable=False, server_default="unknown"),
            sa.Column("propagated_to_action_ids", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("verified_by_human", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_taint_labels_tenant_chain", "taint_labels", ["tenant_id", "chain_id"])
        op.create_index("idx_taint_labels_tenant_action", "taint_labels", ["tenant_id", "action_id"])
        op.create_index("idx_taint_labels_tenant_source", "taint_labels", ["tenant_id", "source_type"])

    if not _has_table(table_names, "agent_touchpoint_edges"):
        op.create_table(
            "agent_touchpoint_edges",
            sa.Column("tenant_id", sa.String(), nullable=False),
            sa.Column("source_node_type", sa.String(length=32), nullable=False),
            sa.Column("source_node_id", sa.String(length=128), nullable=False),
            sa.Column("target_node_type", sa.String(length=32), nullable=False),
            sa.Column("target_node_id", sa.String(length=128), nullable=False),
            sa.Column("edge_type", sa.String(length=64), nullable=False),
            sa.Column("chain_id", sa.String(length=64), nullable=True),
            sa.Column("action_id", sa.String(length=64), nullable=True),
            sa.Column("risk_level", sa.String(length=16), nullable=False, server_default="low"),
            sa.Column("control_mode", sa.String(length=32), nullable=False, server_default="detected_only"),
            sa.Column("evidence_bundle_id", sa.String(), nullable=True),
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["evidence_bundle_id"], ["evidence_nodes.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "idx_agent_touchpoint_edges_tenant_source",
            "agent_touchpoint_edges",
            ["tenant_id", "source_node_type", "source_node_id"],
        )
        op.create_index(
            "idx_agent_touchpoint_edges_tenant_target",
            "agent_touchpoint_edges",
            ["tenant_id", "target_node_type", "target_node_id"],
        )
        op.create_index("idx_agent_touchpoint_edges_tenant_chain", "agent_touchpoint_edges", ["tenant_id", "chain_id"])

    if not _has_table(table_names, "blast_radius_snapshots"):
        op.create_table(
            "blast_radius_snapshots",
            sa.Column("tenant_id", sa.String(), nullable=False),
            sa.Column("subject_type", sa.String(length=32), nullable=False),
            sa.Column("subject_id", sa.String(length=128), nullable=False),
            sa.Column("reachable_tools_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("reachable_mcp_servers_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("reachable_saas_apps_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("reachable_repos_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("reachable_data_sources_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("high_risk_actions_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("persistent_side_effects_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("external_destinations_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("delegation_depth_max", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("data_access_score", sa.Float(), nullable=False, server_default="0"),
            sa.Column("tool_action_score", sa.Float(), nullable=False, server_default="0"),
            sa.Column("privilege_score", sa.Float(), nullable=False, server_default="0"),
            sa.Column("persistence_score", sa.Float(), nullable=False, server_default="0"),
            sa.Column("external_exfiltration_score", sa.Float(), nullable=False, server_default="0"),
            sa.Column("delegation_score", sa.Float(), nullable=False, server_default="0"),
            sa.Column("overall_blast_radius_score", sa.Float(), nullable=False, server_default="0"),
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "idx_blast_radius_snapshots_tenant_subject",
            "blast_radius_snapshots",
            ["tenant_id", "subject_type", "subject_id"],
        )
        op.create_index("idx_blast_radius_snapshots_tenant_calculated", "blast_radius_snapshots", ["tenant_id", "calculated_at"])

    if not _has_table(table_names, "approval_bindings"):
        op.create_table(
            "approval_bindings",
            sa.Column("tenant_id", sa.String(), nullable=False),
            sa.Column("chain_id", sa.String(length=64), nullable=False),
            sa.Column("action_id", sa.String(length=64), nullable=True),
            sa.Column("approval_id", sa.String(length=64), nullable=False),
            sa.Column("canonical_action_hash", sa.String(length=128), nullable=False),
            sa.Column("signed_receipt", sa.String(length=128), nullable=False),
            sa.Column("material_fields", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("approver_user_id", sa.String(), nullable=True),
            sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
            sa.Column("invalidation_reason", sa.String(length=255), nullable=True),
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["approver_user_id"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_approval_bindings_tenant_chain", "approval_bindings", ["tenant_id", "chain_id"])
        op.create_index("idx_approval_bindings_tenant_approval", "approval_bindings", ["tenant_id", "approval_id"])
        op.create_index("idx_approval_bindings_tenant_status", "approval_bindings", ["tenant_id", "status"])

    if not _has_table(table_names, "tool_fingerprints"):
        op.create_table(
            "tool_fingerprints",
            sa.Column("tenant_id", sa.String(), nullable=False),
            sa.Column("mcp_server_id", sa.String(length=128), nullable=False),
            sa.Column("tool_name", sa.String(length=128), nullable=False),
            sa.Column("tool_version", sa.String(length=64), nullable=False, server_default="unknown"),
            sa.Column("manifest_hash", sa.String(length=128), nullable=False),
            sa.Column("description_hash", sa.String(length=128), nullable=False),
            sa.Column("schema_hash", sa.String(length=128), nullable=False),
            sa.Column("examples_hash", sa.String(length=128), nullable=False),
            sa.Column("approved_hash", sa.String(length=128), nullable=True),
            sa.Column("trust_status", sa.String(length=32), nullable=False, server_default="unknown"),
            sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("approved_by", sa.String(), nullable=True),
            sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["approved_by"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("tenant_id", "mcp_server_id", "tool_name", "tool_version", name="uq_tool_fingerprint_version"),
        )
        op.create_index("idx_tool_fingerprints_tenant_tool", "tool_fingerprints", ["tenant_id", "tool_name"])
        op.create_index("idx_tool_fingerprints_tenant_status", "tool_fingerprints", ["tenant_id", "trust_status"])

    if not _has_table(table_names, "tool_scan_results"):
        op.create_table(
            "tool_scan_results",
            sa.Column("tenant_id", sa.String(), nullable=False),
            sa.Column("chain_id", sa.String(length=64), nullable=True),
            sa.Column("tool_fingerprint_id", sa.String(), nullable=False),
            sa.Column("mcp_server_id", sa.String(length=128), nullable=False),
            sa.Column("tool_name", sa.String(length=128), nullable=False),
            sa.Column("trust_status", sa.String(length=32), nullable=False),
            sa.Column("risk_factors", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("evidence_node_id", sa.String(), nullable=True),
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["tool_fingerprint_id"], ["tool_fingerprints.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["evidence_node_id"], ["evidence_nodes.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_tool_scan_results_tenant_tool", "tool_scan_results", ["tenant_id", "tool_name"])
        op.create_index("idx_tool_scan_results_tenant_chain", "tool_scan_results", ["tenant_id", "chain_id"])

    if not _has_table(table_names, "jit_grant_bindings"):
        op.create_table(
            "jit_grant_bindings",
            sa.Column("tenant_id", sa.String(), nullable=False),
            sa.Column("chain_id", sa.String(length=64), nullable=False),
            sa.Column("agent_id", sa.String(length=128), nullable=False),
            sa.Column("requested_scope", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("approved_scope", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("identity_provider", sa.String(length=64), nullable=True),
            sa.Column("grant_type", sa.String(length=64), nullable=False, server_default="temporary"),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("task_binding_hash", sa.String(length=128), nullable=False),
            sa.Column("privilege_delta", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("persistence_risk", sa.String(length=32), nullable=False, server_default="none"),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
            sa.Column("policy_decision_id", sa.String(length=64), nullable=True),
            sa.Column("evidence_bundle_id", sa.String(), nullable=True),
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["evidence_bundle_id"], ["evidence_nodes.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_jit_grant_bindings_tenant_chain", "jit_grant_bindings", ["tenant_id", "chain_id"])
        op.create_index("idx_jit_grant_bindings_tenant_agent", "jit_grant_bindings", ["tenant_id", "agent_id"])
        op.create_index("idx_jit_grant_bindings_tenant_status", "jit_grant_bindings", ["tenant_id", "status"])


def downgrade() -> None:
    for table in (
        "jit_grant_bindings",
        "tool_scan_results",
        "tool_fingerprints",
        "approval_bindings",
        "blast_radius_snapshots",
        "agent_touchpoint_edges",
        "taint_labels",
        "deferred_side_effects",
        "chain_events",
        "ai_action_chains",
    ):
        op.drop_table(table)
