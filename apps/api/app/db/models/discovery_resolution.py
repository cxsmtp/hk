from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKeyConstraint,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


def _hash_check(column: str) -> str:
    stripped = column
    for character in "0123456789abcdef":
        stripped = f"replace({stripped}, '{character}', '')"
    return (
        f"length({column}) = 64 AND {column} = lower({column}) "
        f"AND {stripped} = ''"
    )


HYPOTHESIS_TYPES = (
    "'ai_application','agent','model_endpoint','mcp_server','rag_system',"
    "'coding_assistant','unknown_ai_workload'"
)
HYPOTHESIS_STATES = (
    "'observed','hypothesized','verifying','confirmed','rejected','ambiguous'"
)
GRAPH_NODE_CLASSES = (
    "'observation','hypothesis','ai_asset','identity','runtime','model','tool',"
    "'mcp_server','data_asset','network_destination','repository',"
    "'cloud_resource','saas_app','capability','provider','configuration',"
    "'marketplace','extension','dependency','project','database','process',"
    "'mcp','usage','user','service_account','application','environment',"
    "'permission','relationship','ai_ecosystem'"
)
GRAPH_EDGE_TYPES = (
    "'supports','contradicts','observed_on','runs_on','used_by','calls',"
    "'connects_to','depends_on','authenticates_as','hosted_in','exposes',"
    "'accesses','possibly_same_as','replaces','split_from','merged_from',"
    "'observed_by','uses','invokes','provides','connected_to','same_identity',"
    "'same_runtime','same_repository','same_configuration','same_provider',"
    "'same_project','same_user','potential_match','resolved_match',"
    "'historical_match'"
)
VERIFICATION_TASK_TYPES = (
    "'endpoint_confirm','process_confirm','package_confirm',"
    "'cloud_resource_confirm','saas_admin_confirm','identity_confirm',"
    "'network_confirm','repo_confirm','mcp_confirm','model_endpoint_confirm',"
    "'usage_confirm','owner_confirm','runtime_confirm'"
)
SAFE_VERIFICATION_METHODS = (
    "'endpoint_metadata','process_metadata','package_metadata','cloud_metadata',"
    "'saas_admin_metadata','identity_metadata','network_metadata',"
    "'repository_metadata','mcp_metadata','model_metadata','usage_aggregate',"
    "'owner_directory','runtime_metadata'"
)


class DiscoveryAssetHypothesis(Base):
    __tablename__ = "discovery_asset_hypotheses"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_discovery_asset_hypothesis_tenant", ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "evidence_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_discovery_asset_hypothesis_tenant_evidence",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "promoted_asset_id"],
            ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"],
            name="fk_discovery_asset_hypothesis_tenant_asset",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "tenant_id", "hypothesis_id",
            name="uq_discovery_asset_hypothesis_tenant_id",
        ),
        UniqueConstraint(
            "tenant_id", "idempotency_key",
            name="uq_discovery_asset_hypothesis_tenant_idempotency",
        ),
        UniqueConstraint(
            "tenant_id", "candidate_key_hash",
            name="uq_discovery_asset_hypothesis_tenant_candidate",
        ),
        CheckConstraint(
            f"hypothesis_type IN ({HYPOTHESIS_TYPES})",
            name="ck_discovery_asset_hypothesis_type",
        ),
        CheckConstraint(
            f"state IN ({HYPOTHESIS_STATES})",
            name="ck_discovery_asset_hypothesis_state",
        ),
        CheckConstraint(
            "verification_state IN ('verified','partially_verified','inferred','unknown')",
            name="ck_discovery_asset_hypothesis_verification",
        ),
        CheckConstraint(
            "freshness IN ('fresh','stale','expired','unknown')",
            name="ck_discovery_asset_hypothesis_freshness",
        ),
        CheckConstraint(
            "contradiction_state IN ('none','possible','confirmed','resolved','unknown')",
            name="ck_discovery_asset_hypothesis_contradiction",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_discovery_asset_hypothesis_confidence",
        ),
        CheckConstraint(
            "first_observed_at <= last_observed_at",
            name="ck_discovery_asset_hypothesis_seen_order",
        ),
        CheckConstraint(
            "version >= 1", name="ck_discovery_asset_hypothesis_version",
        ),
        CheckConstraint(
            "(state = 'confirmed') OR promoted_asset_id IS NULL",
            name="ck_discovery_asset_hypothesis_promotion_state",
        ),
        CheckConstraint(
            _hash_check("candidate_key_hash"),
            name="ck_discovery_asset_hypothesis_candidate_hash",
        ),
        CheckConstraint(
            _hash_check("input_digest"),
            name="ck_discovery_asset_hypothesis_input_digest",
        ),
        Index(
            "idx_discovery_asset_hypothesis_tenant_state", "tenant_id",
            "state", "last_observed_at", "hypothesis_id",
        ),
        Index(
            "idx_discovery_asset_hypothesis_tenant_type", "tenant_id",
            "hypothesis_type", "confidence", "hypothesis_id",
        ),
        Index(
            "idx_discovery_asset_hypothesis_tenant_evidence", "tenant_id",
            "evidence_node_id", "hypothesis_id",
        ),
    )

    hypothesis_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    hypothesis_type: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    candidate_key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    verification_state: Mapped[str] = mapped_column(String(32), nullable=False)
    freshness: Mapped[str] = mapped_column(String(32), nullable=False)
    contradiction_state: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    promoted_asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, server_default=text("1"), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class DiscoveryHypothesisTransition(Base):
    __tablename__ = "discovery_hypothesis_transitions"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_discovery_hypothesis_transition_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "hypothesis_id"], ["discovery_asset_hypotheses.tenant_id", "discovery_asset_hypotheses.hypothesis_id"], name="fk_discovery_hypothesis_transition_tenant_hypothesis", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "evidence_node_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_discovery_hypothesis_transition_tenant_evidence", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "transition_id", name="uq_discovery_hypothesis_transition_tenant_id"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_discovery_hypothesis_transition_tenant_idempotency"),
        CheckConstraint(f"(from_state IS NULL OR from_state IN ({HYPOTHESIS_STATES})) AND to_state IN ({HYPOTHESIS_STATES})", name="ck_discovery_hypothesis_transition_states"),
        CheckConstraint("length(trim(actor_id)) BETWEEN 1 AND 128", name="ck_discovery_hypothesis_transition_actor"),
        CheckConstraint("length(trim(reason)) BETWEEN 1 AND 500", name="ck_discovery_hypothesis_transition_reason"),
        CheckConstraint(_hash_check("input_digest"), name="ck_discovery_hypothesis_transition_digest"),
        Index("idx_discovery_hypothesis_transition_tenant_hypothesis", "tenant_id", "hypothesis_id", "created_at", "transition_id"),
    )

    transition_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    hypothesis_id: Mapped[str] = mapped_column(String(36), nullable=False)
    from_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_state: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryResolutionGraphNode(Base):
    __tablename__ = "discovery_resolution_graph_nodes"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_discovery_resolution_graph_node_tenant", ondelete="CASCADE"),
        UniqueConstraint("tenant_id", "graph_node_id", name="uq_discovery_resolution_graph_node_tenant_id"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_discovery_resolution_graph_node_tenant_idempotency"),
        UniqueConstraint("tenant_id", "node_class", "subject_reference", name="uq_discovery_resolution_graph_node_subject"),
        CheckConstraint(f"node_class IN ({GRAPH_NODE_CLASSES})", name="ck_discovery_resolution_graph_node_class"),
        CheckConstraint("length(trim(subject_reference)) BETWEEN 1 AND 500", name="ck_discovery_resolution_graph_node_reference"),
        CheckConstraint(_hash_check("input_digest"), name="ck_discovery_resolution_graph_node_digest"),
        Index("idx_discovery_resolution_graph_node_tenant_class", "tenant_id", "node_class", "graph_node_id"),
    )

    graph_node_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    node_class: Mapped[str] = mapped_column(String(64), nullable=False)
    subject_reference: Mapped[str] = mapped_column(String(500), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryResolutionGraphEdge(Base):
    __tablename__ = "discovery_resolution_graph_edges"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_discovery_resolution_graph_edge_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "from_node_id"], ["discovery_resolution_graph_nodes.tenant_id", "discovery_resolution_graph_nodes.graph_node_id"], name="fk_discovery_resolution_graph_edge_tenant_from", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "to_node_id"], ["discovery_resolution_graph_nodes.tenant_id", "discovery_resolution_graph_nodes.graph_node_id"], name="fk_discovery_resolution_graph_edge_tenant_to", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "evidence_node_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_discovery_resolution_graph_edge_tenant_evidence", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "predecessor_edge_id"], ["discovery_resolution_graph_edges.tenant_id", "discovery_resolution_graph_edges.edge_id"], name="fk_discovery_resolution_graph_edge_tenant_predecessor", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "edge_id", name="uq_discovery_resolution_graph_edge_tenant_id"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_discovery_resolution_graph_edge_tenant_idempotency"),
        UniqueConstraint("tenant_id", "predecessor_edge_id", name="uq_discovery_resolution_graph_edge_tenant_predecessor"),
        CheckConstraint(f"edge_type IN ({GRAPH_EDGE_TYPES})", name="ck_discovery_resolution_graph_edge_type"),
        CheckConstraint("from_node_id <> to_node_id", name="ck_discovery_resolution_graph_edge_self"),
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_discovery_resolution_graph_edge_confidence"),
        CheckConstraint("base_confidence >= 0.0 AND base_confidence <= 1.0", name="ck_discovery_resolution_graph_edge_base_confidence"),
        CheckConstraint("observation_quality_factor IS NULL OR (observation_quality_factor >= 0.0 AND observation_quality_factor <= 1.0)", name="ck_discovery_resolution_graph_edge_observation_quality"),
        CheckConstraint("collector_quality_factor IS NULL OR (collector_quality_factor >= 0.0 AND collector_quality_factor <= 1.0)", name="ck_discovery_resolution_graph_edge_collector_quality"),
        CheckConstraint("relationship_weight > 0.0 AND relationship_weight <= 10.0", name="ck_discovery_resolution_graph_edge_weight"),
        CheckConstraint(
            "edge_sequence >= 1 AND (predecessor_edge_id IS NOT NULL OR edge_sequence = 1)",
            name="ck_discovery_resolution_graph_edge_sequence",
        ),
        CheckConstraint("verification_state IN ('verified','partially_verified','inferred','unknown')", name="ck_discovery_resolution_graph_edge_verification"),
        CheckConstraint("freshness IN ('fresh','stale','expired','unknown')", name="ck_discovery_resolution_graph_edge_freshness"),
        CheckConstraint("contradiction_state IN ('none','possible','confirmed','resolved','unknown')", name="ck_discovery_resolution_graph_edge_contradiction"),
        CheckConstraint("first_observed_at <= last_observed_at", name="ck_discovery_resolution_graph_edge_seen_order"),
        CheckConstraint(_hash_check("input_digest"), name="ck_discovery_resolution_graph_edge_digest"),
        Index("idx_discovery_resolution_graph_edge_tenant_from", "tenant_id", "from_node_id", "edge_type", "edge_id"),
        Index("idx_discovery_resolution_graph_edge_tenant_to", "tenant_id", "to_node_id", "edge_type", "edge_id"),
        Index("idx_discovery_resolution_graph_edge_tenant_evidence", "tenant_id", "evidence_node_id", "edge_id"),
        Index("idx_discovery_resolution_graph_edge_tenant_predecessor", "tenant_id", "predecessor_edge_id", "edge_id"),
    )

    edge_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    from_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    to_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    edge_type: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    collector_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source_surface: Mapped[str] = mapped_column(
        String(64), server_default=text("'unknown'"), nullable=False
    )
    signal_class: Mapped[str] = mapped_column(
        String(64), server_default=text("'unknown'"), nullable=False
    )
    base_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    observation_quality_factor: Mapped[float | None] = mapped_column(Float, nullable=True)
    collector_quality_factor: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    relationship_weight: Mapped[float] = mapped_column(Float, nullable=False)
    relationship_rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    relationship_rule_version: Mapped[str] = mapped_column(String(32), nullable=False)
    decay_policy_id: Mapped[str] = mapped_column(String(128), nullable=False)
    decay_policy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    verification_state: Mapped[str] = mapped_column(String(32), nullable=False)
    freshness: Mapped[str] = mapped_column(String(32), nullable=False)
    contradiction_state: Mapped[str] = mapped_column(String(32), nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_validated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    edge_schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    edge_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    predecessor_edge_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryVerificationTask(Base):
    __tablename__ = "discovery_verification_tasks"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_discovery_verification_task_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "hypothesis_id"], ["discovery_asset_hypotheses.tenant_id", "discovery_asset_hypotheses.hypothesis_id"], name="fk_discovery_verification_task_tenant_hypothesis", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "result_evidence_node_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_discovery_verification_task_tenant_evidence", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "verification_episode_id"], ["discovery_verification_episodes.tenant_id", "discovery_verification_episodes.episode_id"], name="fk_discovery_verification_task_tenant_episode", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "verification_requirement_id"], ["discovery_verification_policy_requirements.tenant_id", "discovery_verification_policy_requirements.requirement_record_id"], name="fk_discovery_verification_task_tenant_requirement", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "task_id", name="uq_discovery_verification_task_tenant_id"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_discovery_verification_task_tenant_idempotency"),
        CheckConstraint(f"task_type IN ({VERIFICATION_TASK_TYPES})", name="ck_discovery_verification_task_type"),
        CheckConstraint("status IN ('pending','claimed','succeeded','failed','expired','cancelled')", name="ck_discovery_verification_task_status"),
        CheckConstraint(f"method IN ({SAFE_VERIFICATION_METHODS})", name="ck_discovery_verification_task_method"),
        CheckConstraint("priority BETWEEN 0 AND 100", name="ck_discovery_verification_task_priority"),
        CheckConstraint("max_attempts BETWEEN 1 AND 5", name="ck_discovery_verification_task_max_attempts"),
        CheckConstraint("attempt_count >= 0 AND attempt_count <= max_attempts", name="ck_discovery_verification_task_attempts"),
        CheckConstraint("length(CAST(scope_json AS TEXT)) <= 8192", name="ck_discovery_verification_task_scope_bytes"),
        CheckConstraint("length(CAST(limitations_json AS TEXT)) <= 4096", name="ck_discovery_verification_task_limitations_bytes"),
        CheckConstraint(_hash_check("input_digest"), name="ck_discovery_verification_task_digest"),
        Index("idx_discovery_verification_task_tenant_status", "tenant_id", "status", "priority", "expires_at", "task_id"),
        Index("idx_discovery_verification_task_tenant_hypothesis", "tenant_id", "hypothesis_id", "status", "task_id"),
        Index("idx_discovery_verification_task_tenant_rate", "tenant_id", "rate_limit_key", "status", "task_id"),
        Index("idx_discovery_verification_task_tenant_episode", "tenant_id", "verification_episode_id", "verification_requirement_id", "task_id"),
    )

    task_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    hypothesis_id: Mapped[str] = mapped_column(String(36), nullable=False)
    verification_episode_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    verification_requirement_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    task_contract_version: Mapped[str] = mapped_column(String(32), server_default=text("'legacy'"), nullable=False)
    task_type: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    method: Mapped[str] = mapped_column(String(64), nullable=False)
    scope_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    rate_limit_key: Mapped[str] = mapped_column(String(255), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    claimed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result_evidence_node_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    limitations_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


RESOLUTION_TABLE_MODELS = {
    model.__tablename__: model
    for model in (
        DiscoveryAssetHypothesis,
        DiscoveryHypothesisTransition,
        DiscoveryResolutionGraphNode,
        DiscoveryResolutionGraphEdge,
        DiscoveryVerificationTask,
    )
}


__all__ = [
    "DiscoveryAssetHypothesis",
    "DiscoveryHypothesisTransition",
    "DiscoveryResolutionGraphNode",
    "DiscoveryResolutionGraphEdge",
    "DiscoveryVerificationTask",
    "RESOLUTION_TABLE_MODELS",
]
