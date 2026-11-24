"""Add evidence resolution graph, hypotheses, and safe verification work.

Revision ID: 0056_discovery_resolution_graph
Revises: 0055_discovery_assets_res
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0056_discovery_resolution_graph"
down_revision = "0055_discovery_assets_res"
branch_labels = None
depends_on = None


TABLES = (
    "discovery_asset_hypotheses",
    "discovery_hypothesis_transitions",
    "discovery_resolution_graph_nodes",
    "discovery_resolution_graph_edges",
    "discovery_verification_tasks",
)


def _dialect() -> str:
    value = op.get_bind().dialect.name
    if value not in {"sqlite", "postgresql"}:
        raise RuntimeError(f"Unsupported dialect: {value}")
    return value


def _tenant_fk(name: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["tenant_id"], ["tenants.id"], name=name, ondelete="CASCADE"
    )


def _hash_check(column: str, dialect: str) -> str:
    if dialect == "postgresql":
        return f"{column} ~ '^[0-9a-f]{{64}}$'"
    return f"length({column}) = 64 AND {column} NOT GLOB '*[^0-9a-f]*'"


def _json_default(value: str, dialect: str) -> sa.TextClause:
    return sa.text(f"'{value}'{'::json' if dialect == 'postgresql' else ''}")


def upgrade() -> None:
    dialect = _dialect()
    hypothesis_types = (
        "'ai_application','agent','model_endpoint','mcp_server','rag_system',"
        "'coding_assistant','unknown_ai_workload'"
    )
    hypothesis_states = (
        "'observed','hypothesized','verifying','confirmed','rejected','ambiguous'"
    )
    node_classes = (
        "'observation','hypothesis','ai_asset','identity','runtime','model','tool',"
        "'mcp_server','data_asset','network_destination','repository',"
        "'cloud_resource','saas_app'"
    )
    edge_types = (
        "'supports','contradicts','observed_on','runs_on','used_by','calls',"
        "'connects_to','depends_on','authenticates_as','hosted_in','exposes',"
        "'accesses','possibly_same_as','replaces','split_from','merged_from'"
    )
    task_types = (
        "'endpoint_confirm','process_confirm','package_confirm',"
        "'cloud_resource_confirm','saas_admin_confirm','identity_confirm',"
        "'network_confirm','repo_confirm','mcp_confirm','model_endpoint_confirm',"
        "'usage_confirm','owner_confirm','runtime_confirm'"
    )
    safe_methods = (
        "'endpoint_metadata','process_metadata','package_metadata','cloud_metadata',"
        "'saas_admin_metadata','identity_metadata','network_metadata',"
        "'repository_metadata','mcp_metadata','model_metadata','usage_aggregate',"
        "'owner_directory','runtime_metadata'"
    )

    op.create_table(
        "discovery_asset_hypotheses",
        sa.Column("hypothesis_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("hypothesis_type", sa.String(64), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column("candidate_key_hash", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("verification_state", sa.String(32), nullable=False),
        sa.Column("freshness", sa.String(32), nullable=False),
        sa.Column("contradiction_state", sa.String(32), nullable=False),
        sa.Column("evidence_node_id", sa.String(36), nullable=False),
        sa.Column("promoted_asset_id", sa.String(36), nullable=True),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_discovery_asset_hypothesis_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "evidence_node_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_discovery_asset_hypothesis_tenant_evidence", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "promoted_asset_id"], ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"], name="fk_discovery_asset_hypothesis_tenant_asset", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("hypothesis_id"),
        sa.UniqueConstraint("tenant_id", "hypothesis_id", name="uq_discovery_asset_hypothesis_tenant_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_discovery_asset_hypothesis_tenant_idempotency"),
        sa.UniqueConstraint("tenant_id", "candidate_key_hash", name="uq_discovery_asset_hypothesis_tenant_candidate"),
        sa.CheckConstraint(f"hypothesis_type IN ({hypothesis_types})", name="ck_discovery_asset_hypothesis_type"),
        sa.CheckConstraint(f"state IN ({hypothesis_states})", name="ck_discovery_asset_hypothesis_state"),
        sa.CheckConstraint("verification_state IN ('verified','partially_verified','inferred','unknown')", name="ck_discovery_asset_hypothesis_verification"),
        sa.CheckConstraint("freshness IN ('fresh','stale','expired','unknown')", name="ck_discovery_asset_hypothesis_freshness"),
        sa.CheckConstraint("contradiction_state IN ('none','possible','confirmed','resolved','unknown')", name="ck_discovery_asset_hypothesis_contradiction"),
        sa.CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_discovery_asset_hypothesis_confidence"),
        sa.CheckConstraint("first_observed_at <= last_observed_at", name="ck_discovery_asset_hypothesis_seen_order"),
        sa.CheckConstraint("version >= 1", name="ck_discovery_asset_hypothesis_version"),
        sa.CheckConstraint("(state = 'confirmed') OR promoted_asset_id IS NULL", name="ck_discovery_asset_hypothesis_promotion_state"),
        sa.CheckConstraint(_hash_check("candidate_key_hash", dialect), name="ck_discovery_asset_hypothesis_candidate_hash"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_discovery_asset_hypothesis_input_digest"),
    )
    op.create_index("idx_discovery_asset_hypothesis_tenant_state", "discovery_asset_hypotheses", ["tenant_id", "state", "last_observed_at", "hypothesis_id"])
    op.create_index("idx_discovery_asset_hypothesis_tenant_type", "discovery_asset_hypotheses", ["tenant_id", "hypothesis_type", "confidence", "hypothesis_id"])
    op.create_index("idx_discovery_asset_hypothesis_tenant_evidence", "discovery_asset_hypotheses", ["tenant_id", "evidence_node_id", "hypothesis_id"])

    op.create_table(
        "discovery_hypothesis_transitions",
        sa.Column("transition_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("hypothesis_id", sa.String(36), nullable=False),
        sa.Column("from_state", sa.String(32), nullable=True),
        sa.Column("to_state", sa.String(32), nullable=False),
        sa.Column("evidence_node_id", sa.String(36), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_discovery_hypothesis_transition_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "hypothesis_id"], ["discovery_asset_hypotheses.tenant_id", "discovery_asset_hypotheses.hypothesis_id"], name="fk_discovery_hypothesis_transition_tenant_hypothesis", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "evidence_node_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_discovery_hypothesis_transition_tenant_evidence", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("transition_id"),
        sa.UniqueConstraint("tenant_id", "transition_id", name="uq_discovery_hypothesis_transition_tenant_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_discovery_hypothesis_transition_tenant_idempotency"),
        sa.CheckConstraint(f"(from_state IS NULL OR from_state IN ({hypothesis_states})) AND to_state IN ({hypothesis_states})", name="ck_discovery_hypothesis_transition_states"),
        sa.CheckConstraint("length(trim(actor_id)) BETWEEN 1 AND 128", name="ck_discovery_hypothesis_transition_actor"),
        sa.CheckConstraint("length(trim(reason)) BETWEEN 1 AND 500", name="ck_discovery_hypothesis_transition_reason"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_discovery_hypothesis_transition_digest"),
    )
    op.create_index("idx_discovery_hypothesis_transition_tenant_hypothesis", "discovery_hypothesis_transitions", ["tenant_id", "hypothesis_id", "created_at", "transition_id"])

    op.create_table(
        "discovery_resolution_graph_nodes",
        sa.Column("graph_node_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("node_class", sa.String(64), nullable=False),
        sa.Column("subject_reference", sa.String(500), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_discovery_resolution_graph_node_tenant"),
        sa.PrimaryKeyConstraint("graph_node_id"),
        sa.UniqueConstraint("tenant_id", "graph_node_id", name="uq_discovery_resolution_graph_node_tenant_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_discovery_resolution_graph_node_tenant_idempotency"),
        sa.UniqueConstraint("tenant_id", "node_class", "subject_reference", name="uq_discovery_resolution_graph_node_subject"),
        sa.CheckConstraint(f"node_class IN ({node_classes})", name="ck_discovery_resolution_graph_node_class"),
        sa.CheckConstraint("length(trim(subject_reference)) BETWEEN 1 AND 500", name="ck_discovery_resolution_graph_node_reference"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_discovery_resolution_graph_node_digest"),
    )
    op.create_index("idx_discovery_resolution_graph_node_tenant_class", "discovery_resolution_graph_nodes", ["tenant_id", "node_class", "graph_node_id"])

    op.create_table(
        "discovery_resolution_graph_edges",
        sa.Column("edge_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("from_node_id", sa.String(36), nullable=False),
        sa.Column("to_node_id", sa.String(36), nullable=False),
        sa.Column("edge_type", sa.String(64), nullable=False),
        sa.Column("evidence_node_id", sa.String(36), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("verification_state", sa.String(32), nullable=False),
        sa.Column("freshness", sa.String(32), nullable=False),
        sa.Column("contradiction_state", sa.String(32), nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_discovery_resolution_graph_edge_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "from_node_id"], ["discovery_resolution_graph_nodes.tenant_id", "discovery_resolution_graph_nodes.graph_node_id"], name="fk_discovery_resolution_graph_edge_tenant_from", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "to_node_id"], ["discovery_resolution_graph_nodes.tenant_id", "discovery_resolution_graph_nodes.graph_node_id"], name="fk_discovery_resolution_graph_edge_tenant_to", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "evidence_node_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_discovery_resolution_graph_edge_tenant_evidence", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("edge_id"),
        sa.UniqueConstraint("tenant_id", "edge_id", name="uq_discovery_resolution_graph_edge_tenant_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_discovery_resolution_graph_edge_tenant_idempotency"),
        sa.CheckConstraint(f"edge_type IN ({edge_types})", name="ck_discovery_resolution_graph_edge_type"),
        sa.CheckConstraint("from_node_id <> to_node_id", name="ck_discovery_resolution_graph_edge_self"),
        sa.CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_discovery_resolution_graph_edge_confidence"),
        sa.CheckConstraint("verification_state IN ('verified','partially_verified','inferred','unknown')", name="ck_discovery_resolution_graph_edge_verification"),
        sa.CheckConstraint("freshness IN ('fresh','stale','expired','unknown')", name="ck_discovery_resolution_graph_edge_freshness"),
        sa.CheckConstraint("contradiction_state IN ('none','possible','confirmed','resolved','unknown')", name="ck_discovery_resolution_graph_edge_contradiction"),
        sa.CheckConstraint("first_observed_at <= last_observed_at", name="ck_discovery_resolution_graph_edge_seen_order"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_discovery_resolution_graph_edge_digest"),
    )
    op.create_index("idx_discovery_resolution_graph_edge_tenant_from", "discovery_resolution_graph_edges", ["tenant_id", "from_node_id", "edge_type", "edge_id"])
    op.create_index("idx_discovery_resolution_graph_edge_tenant_to", "discovery_resolution_graph_edges", ["tenant_id", "to_node_id", "edge_type", "edge_id"])
    op.create_index("idx_discovery_resolution_graph_edge_tenant_evidence", "discovery_resolution_graph_edges", ["tenant_id", "evidence_node_id", "edge_id"])

    op.create_table(
        "discovery_verification_tasks",
        sa.Column("task_id", sa.String(36), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("hypothesis_id", sa.String(36), nullable=False),
        sa.Column("task_type", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("method", sa.String(64), nullable=False),
        sa.Column("scope_json", sa.JSON(), nullable=False),
        sa.Column("rate_limit_key", sa.String(255), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("attempt_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_by", sa.String(255), nullable=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result_evidence_node_id", sa.String(36), nullable=True),
        sa.Column("limitations_json", sa.JSON(), server_default=_json_default("[]", dialect), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        _tenant_fk("fk_discovery_verification_task_tenant"),
        sa.ForeignKeyConstraint(["tenant_id", "hypothesis_id"], ["discovery_asset_hypotheses.tenant_id", "discovery_asset_hypotheses.hypothesis_id"], name="fk_discovery_verification_task_tenant_hypothesis", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tenant_id", "result_evidence_node_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_discovery_verification_task_tenant_evidence", ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("task_id"),
        sa.UniqueConstraint("tenant_id", "task_id", name="uq_discovery_verification_task_tenant_id"),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_discovery_verification_task_tenant_idempotency"),
        sa.CheckConstraint(f"task_type IN ({task_types})", name="ck_discovery_verification_task_type"),
        sa.CheckConstraint("status IN ('pending','claimed','succeeded','failed','expired','cancelled')", name="ck_discovery_verification_task_status"),
        sa.CheckConstraint(f"method IN ({safe_methods})", name="ck_discovery_verification_task_method"),
        sa.CheckConstraint("priority BETWEEN 0 AND 100", name="ck_discovery_verification_task_priority"),
        sa.CheckConstraint("max_attempts BETWEEN 1 AND 5", name="ck_discovery_verification_task_max_attempts"),
        sa.CheckConstraint("attempt_count >= 0 AND attempt_count <= max_attempts", name="ck_discovery_verification_task_attempts"),
        sa.CheckConstraint("length(CAST(scope_json AS TEXT)) <= 8192", name="ck_discovery_verification_task_scope_bytes"),
        sa.CheckConstraint("length(CAST(limitations_json AS TEXT)) <= 4096", name="ck_discovery_verification_task_limitations_bytes"),
        sa.CheckConstraint(_hash_check("input_digest", dialect), name="ck_discovery_verification_task_digest"),
    )
    op.create_index("idx_discovery_verification_task_tenant_status", "discovery_verification_tasks", ["tenant_id", "status", "priority", "expires_at", "task_id"])
    op.create_index("idx_discovery_verification_task_tenant_hypothesis", "discovery_verification_tasks", ["tenant_id", "hypothesis_id", "status", "task_id"])
    op.create_index("idx_discovery_verification_task_tenant_rate", "discovery_verification_tasks", ["tenant_id", "rate_limit_key", "status", "task_id"])


def downgrade() -> None:
    _dialect()
    for name, table in (
        ("idx_discovery_verification_task_tenant_rate", "discovery_verification_tasks"),
        ("idx_discovery_verification_task_tenant_hypothesis", "discovery_verification_tasks"),
        ("idx_discovery_verification_task_tenant_status", "discovery_verification_tasks"),
        ("idx_discovery_resolution_graph_edge_tenant_evidence", "discovery_resolution_graph_edges"),
        ("idx_discovery_resolution_graph_edge_tenant_to", "discovery_resolution_graph_edges"),
        ("idx_discovery_resolution_graph_edge_tenant_from", "discovery_resolution_graph_edges"),
        ("idx_discovery_resolution_graph_node_tenant_class", "discovery_resolution_graph_nodes"),
        ("idx_discovery_hypothesis_transition_tenant_hypothesis", "discovery_hypothesis_transitions"),
        ("idx_discovery_asset_hypothesis_tenant_evidence", "discovery_asset_hypotheses"),
        ("idx_discovery_asset_hypothesis_tenant_type", "discovery_asset_hypotheses"),
        ("idx_discovery_asset_hypothesis_tenant_state", "discovery_asset_hypotheses"),
    ):
        op.drop_index(name, table_name=table)
    for table in reversed(TABLES):
        op.drop_table(table)
