from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
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
    return f"length({column}) = 64 AND {column} = lower({column}) AND {stripped} = ''"


def _json_limit(column: str, limit: int) -> str:
    return f"length(CAST({column} AS TEXT)) <= {limit}"


class DiscoveryHypothesisEvaluation(Base):
    __tablename__ = "discovery_hypothesis_evaluations"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_erg_eval_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "hypothesis_id"], ["discovery_asset_hypotheses.tenant_id", "discovery_asset_hypotheses.hypothesis_id"], name="fk_erg_eval_tenant_hypothesis", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "inference_run_id"], ["discovery_capability_inference_runs.tenant_id", "discovery_capability_inference_runs.inference_run_id"], name="fk_erg_eval_tenant_run", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "predecessor_evaluation_id"], ["discovery_hypothesis_evaluations.tenant_id", "discovery_hypothesis_evaluations.evaluation_id"], name="fk_erg_eval_tenant_predecessor", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "evaluation_id", name="uq_erg_eval_tenant_id"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_erg_eval_tenant_idempotency"),
        UniqueConstraint("tenant_id", "hypothesis_id", "evaluation_sequence", name="uq_erg_eval_tenant_sequence"),
        UniqueConstraint("tenant_id", "input_digest", name="uq_erg_eval_tenant_digest"),
        CheckConstraint("evaluation_sequence >= 1", name="ck_erg_eval_sequence"),
        CheckConstraint("base_confidence >= 0.0 AND base_confidence <= 1.0", name="ck_erg_eval_base_confidence"),
        CheckConstraint("effective_confidence IS NULL OR (effective_confidence >= 0.0 AND effective_confidence <= 1.0)", name="ck_erg_eval_effective_confidence"),
        CheckConstraint("evidence_quality IS NULL OR (evidence_quality >= 0.0 AND evidence_quality <= 1.0)", name="ck_erg_eval_quality"),
        CheckConstraint("source_diversity >= 0 AND source_diversity <= 64", name="ck_erg_eval_sources"),
        CheckConstraint("threshold_considered >= 0.0 AND threshold_considered <= 1.0", name="ck_erg_eval_threshold"),
        CheckConstraint("recommended_action IN ('create_ecosystem','attach_observation','reject_observation','manual_review','unknown')", name="ck_erg_eval_action"),
        CheckConstraint("first_observed_at <= last_observed_at AND last_observed_at <= validated_at", name="ck_erg_eval_time_order"),
        CheckConstraint(_hash_check("input_digest"), name="ck_erg_eval_digest"),
        CheckConstraint(_json_limit("required_anchors_json", 16384), name="ck_erg_eval_anchors_bytes"),
        CheckConstraint(_json_limit("required_anchor_results_json", 16384), name="ck_erg_eval_anchor_results_bytes"),
        CheckConstraint(_json_limit("limitations_json", 8192), name="ck_erg_eval_limitations_bytes"),
        Index("idx_erg_eval_tenant_hypothesis", "tenant_id", "hypothesis_id", "evaluation_sequence", "evaluation_id"),
        Index("idx_erg_eval_tenant_action", "tenant_id", "recommended_action", "validated_at", "evaluation_id"),
    )

    evaluation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    hypothesis_id: Mapped[str] = mapped_column(String(36), nullable=False)
    inference_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    predecessor_evaluation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    evaluation_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    candidate_ecosystem_class: Mapped[str] = mapped_column(String(128), nullable=False)
    required_anchors_json: Mapped[list] = mapped_column(JSON, nullable=False)
    required_anchor_results_json: Mapped[list] = mapped_column(JSON, nullable=False)
    base_confidence: Mapped[float] = mapped_column(Float, nullable=False)
    effective_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence_quality: Mapped[float | None] = mapped_column(Float, nullable=True)
    source_diversity: Mapped[int] = mapped_column(Integer, nullable=False)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence_methodology_id: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence_methodology_version: Mapped[str] = mapped_column(String(32), nullable=False)
    decay_policy_id: Mapped[str] = mapped_column(String(128), nullable=False)
    decay_policy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    threshold_considered: Mapped[float] = mapped_column(Float, nullable=False)
    recommended_action: Mapped[str] = mapped_column(String(32), nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    validated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    limitations_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryHypothesisEvaluationEdge(Base):
    __tablename__ = "discovery_hypothesis_evaluation_edges"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_erg_eval_edge_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "evaluation_id"], ["discovery_hypothesis_evaluations.tenant_id", "discovery_hypothesis_evaluations.evaluation_id"], name="fk_erg_eval_edge_tenant_eval", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "graph_edge_id"], ["discovery_resolution_graph_edges.tenant_id", "discovery_resolution_graph_edges.edge_id"], name="fk_erg_eval_edge_tenant_graph", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "evaluation_edge_id", name="uq_erg_eval_edge_tenant_id"),
        UniqueConstraint("tenant_id", "evaluation_id", "graph_edge_id", name="uq_erg_eval_edge_tenant_member"),
        CheckConstraint("contribution IN ('supporting','contradicting','unknown')", name="ck_erg_eval_edge_contribution"),
        CheckConstraint(_hash_check("input_digest"), name="ck_erg_eval_edge_digest"),
        Index("idx_erg_eval_edge_tenant_eval", "tenant_id", "evaluation_id", "contribution", "evaluation_edge_id"),
        Index("idx_erg_eval_edge_tenant_graph", "tenant_id", "graph_edge_id", "evaluation_edge_id"),
    )

    evaluation_edge_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    evaluation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    graph_edge_id: Mapped[str] = mapped_column(String(36), nullable=False)
    contribution: Mapped[str] = mapped_column(String(32), nullable=False)
    required_anchor: Mapped[bool] = mapped_column(Boolean, nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryCollectorQualitySnapshot(Base):
    __tablename__ = "discovery_collector_quality_snapshots"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_erg_collector_quality_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "collector_id"], ["discovery_collectors.tenant_id", "discovery_collectors.collector_id"], name="fk_erg_collector_quality_tenant_collector", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "snapshot_id", name="uq_erg_collector_quality_tenant_id"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_erg_collector_quality_tenant_idempotency"),
        UniqueConstraint("tenant_id", "input_digest", name="uq_erg_collector_quality_tenant_digest"),
        CheckConstraint("quality IS NULL OR (quality >= 0.0 AND quality <= 1.0)", name="ck_erg_collector_quality_value"),
        CheckConstraint("input_count >= 0 AND validated_count >= 0 AND validated_count <= input_count", name="ck_erg_collector_quality_counts"),
        CheckConstraint(_hash_check("input_digest"), name="ck_erg_collector_quality_digest"),
        CheckConstraint(_json_limit("input_summary_json", 16384), name="ck_erg_collector_quality_input_bytes"),
        CheckConstraint(_json_limit("limitations_json", 8192), name="ck_erg_collector_quality_limitations_bytes"),
        Index("idx_erg_collector_quality_tenant_collector", "tenant_id", "collector_id", "calculated_at", "snapshot_id"),
    )

    snapshot_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    collector_id: Mapped[str] = mapped_column(String(128), nullable=False)
    quality: Mapped[float | None] = mapped_column(Float, nullable=True)
    input_count: Mapped[int] = mapped_column(Integer, nullable=False)
    validated_count: Mapped[int] = mapped_column(Integer, nullable=False)
    freshness: Mapped[str] = mapped_column(String(32), nullable=False)
    signature_state: Mapped[str] = mapped_column(String(32), nullable=False)
    methodology_id: Mapped[str] = mapped_column(String(128), nullable=False)
    methodology_version: Mapped[str] = mapped_column(String(32), nullable=False)
    input_summary_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    limitations_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryObservationQualitySnapshot(Base):
    __tablename__ = "discovery_observation_quality_snapshots"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_erg_observation_quality_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "observation_id"], ["discovery_observations.tenant_id", "discovery_observations.observation_id"], name="fk_erg_observation_quality_tenant_observation", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "collector_quality_snapshot_id"], ["discovery_collector_quality_snapshots.tenant_id", "discovery_collector_quality_snapshots.snapshot_id"], name="fk_erg_observation_quality_tenant_collector", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "snapshot_id", name="uq_erg_observation_quality_tenant_id"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_erg_observation_quality_tenant_idempotency"),
        UniqueConstraint("tenant_id", "input_digest", name="uq_erg_observation_quality_tenant_digest"),
        CheckConstraint("quality IS NULL OR (quality >= 0.0 AND quality <= 1.0)", name="ck_erg_observation_quality_value"),
        CheckConstraint(_hash_check("input_digest"), name="ck_erg_observation_quality_digest"),
        CheckConstraint(_json_limit("quality_factors_json", 16384), name="ck_erg_observation_quality_factors_bytes"),
        CheckConstraint(_json_limit("limitations_json", 8192), name="ck_erg_observation_quality_limitations_bytes"),
        Index("idx_erg_observation_quality_tenant_observation", "tenant_id", "observation_id", "calculated_at", "snapshot_id"),
    )

    snapshot_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    observation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    collector_quality_snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False)
    quality: Mapped[float | None] = mapped_column(Float, nullable=True)
    freshness: Mapped[str] = mapped_column(String(32), nullable=False)
    signature_state: Mapped[str] = mapped_column(String(32), nullable=False)
    validation_state: Mapped[str] = mapped_column(String(32), nullable=False)
    methodology_id: Mapped[str] = mapped_column(String(128), nullable=False)
    methodology_version: Mapped[str] = mapped_column(String(32), nullable=False)
    quality_factors_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    limitations_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryAIEcosystem(Base):
    __tablename__ = "discovery_ai_ecosystems"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_erg_ecosystem_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "capability_genome_id"], ["discovery_capability_genomes.tenant_id", "discovery_capability_genomes.genome_id"], name="fk_erg_ecosystem_tenant_genome", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "supersedes_record_id"], ["discovery_ai_ecosystems.tenant_id", "discovery_ai_ecosystems.ecosystem_record_id"], name="fk_erg_ecosystem_tenant_predecessor", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "ecosystem_record_id", name="uq_erg_ecosystem_tenant_record"),
        UniqueConstraint("tenant_id", "ecosystem_id", "resolution_version", name="uq_erg_ecosystem_tenant_version"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_erg_ecosystem_tenant_idempotency"),
        CheckConstraint("resolution_version >= 1", name="ck_erg_ecosystem_version"),
        CheckConstraint("confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)", name="ck_erg_ecosystem_confidence"),
        CheckConstraint("evidence_quality IS NULL OR (evidence_quality >= 0.0 AND evidence_quality <= 1.0)", name="ck_erg_ecosystem_quality"),
        CheckConstraint("lifecycle_state IN ('candidate','active','superseded','rejected','split','unknown')", name="ck_erg_ecosystem_lifecycle"),
        CheckConstraint("resolution_state IN ('hypothesized','resolved','manual_review','unknown','reversed')", name="ck_erg_ecosystem_resolution"),
        CheckConstraint("outstanding_contradictions >= 0", name="ck_erg_ecosystem_contradictions"),
        CheckConstraint("first_observed_at <= last_observed_at AND last_observed_at <= last_validated_at", name="ck_erg_ecosystem_time_order"),
        CheckConstraint(_hash_check("input_digest"), name="ck_erg_ecosystem_digest"),
        CheckConstraint(_json_limit("limitations_json", 8192), name="ck_erg_ecosystem_limitations_bytes"),
        Index("idx_erg_ecosystem_tenant_id", "tenant_id", "ecosystem_id", "resolution_version", "ecosystem_record_id"),
        Index("idx_erg_ecosystem_tenant_state", "tenant_id", "lifecycle_state", "resolution_state", "last_validated_at", "ecosystem_record_id"),
    )

    ecosystem_record_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    ecosystem_id: Mapped[str] = mapped_column(String(36), nullable=False)
    resolution_version: Mapped[int] = mapped_column(Integer, nullable=False)
    supersedes_record_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    canonical_name: Mapped[str] = mapped_column(String(255), nullable=False)
    ecosystem_class: Mapped[str] = mapped_column(String(128), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False)
    resolution_state: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence_quality: Mapped[float | None] = mapped_column(Float, nullable=True)
    capability_genome_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_validated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    methodology_id: Mapped[str] = mapped_column(String(128), nullable=False)
    methodology_version: Mapped[str] = mapped_column(String(32), nullable=False)
    limitations_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    outstanding_contradictions: Mapped[int] = mapped_column(Integer, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryEcosystemMembership(Base):
    __tablename__ = "discovery_ecosystem_memberships"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_erg_membership_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "ecosystem_record_id"], ["discovery_ai_ecosystems.tenant_id", "discovery_ai_ecosystems.ecosystem_record_id"], name="fk_erg_membership_tenant_ecosystem", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "graph_node_id"], ["discovery_resolution_graph_nodes.tenant_id", "discovery_resolution_graph_nodes.graph_node_id"], name="fk_erg_membership_tenant_graph", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "evidence_node_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_erg_membership_tenant_evidence", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "predecessor_membership_id"], ["discovery_ecosystem_memberships.tenant_id", "discovery_ecosystem_memberships.membership_id"], name="fk_erg_membership_tenant_predecessor", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "membership_id", name="uq_erg_membership_tenant_id"),
        UniqueConstraint("tenant_id", "ecosystem_id", "graph_node_id", "membership_sequence", name="uq_erg_membership_tenant_sequence"),
        CheckConstraint("membership_sequence >= 1", name="ck_erg_membership_sequence"),
        CheckConstraint("membership_state IN ('active','superseded','rejected','historical')", name="ck_erg_membership_state"),
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_erg_membership_confidence"),
        CheckConstraint(_hash_check("input_digest"), name="ck_erg_membership_digest"),
        CheckConstraint(_json_limit("limitations_json", 8192), name="ck_erg_membership_limitations_bytes"),
        Index("idx_erg_membership_tenant_ecosystem", "tenant_id", "ecosystem_id", "membership_state", "membership_id"),
        Index("idx_erg_membership_tenant_graph", "tenant_id", "graph_node_id", "membership_state", "membership_id"),
    )

    membership_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    ecosystem_record_id: Mapped[str] = mapped_column(String(36), nullable=False)
    ecosystem_id: Mapped[str] = mapped_column(String(36), nullable=False)
    graph_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    member_type: Mapped[str] = mapped_column(String(64), nullable=False)
    membership_state: Mapped[str] = mapped_column(String(32), nullable=False)
    membership_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    predecessor_membership_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    evidence_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    verification_state: Mapped[str] = mapped_column(String(32), nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    limitations_json: Mapped[list] = mapped_column(JSON, server_default=text("'[]'"), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryEcosystemResolutionEvent(Base):
    __tablename__ = "discovery_ecosystem_resolution_events"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_erg_resolution_event_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "evidence_node_id"], ["evidence_nodes.tenant_id", "evidence_nodes.id"], name="fk_erg_resolution_event_tenant_evidence", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "reverses_event_id"], ["discovery_ecosystem_resolution_events.tenant_id", "discovery_ecosystem_resolution_events.resolution_event_id"], name="fk_erg_resolution_event_tenant_reversal", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "resolution_event_id", name="uq_erg_resolution_event_tenant_id"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_erg_resolution_event_tenant_idempotency"),
        CheckConstraint("action IN ('create','attach','reject','merge','split','reversal','manual_review','unknown')", name="ck_erg_resolution_event_action"),
        CheckConstraint("operator_role IN ('owner','admin','operator','system')", name="ck_erg_resolution_event_role"),
        CheckConstraint("confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)", name="ck_erg_resolution_event_confidence"),
        CheckConstraint(_hash_check("input_digest"), name="ck_erg_resolution_event_digest"),
        CheckConstraint(_json_limit("source_ecosystem_ids_json", 16384), name="ck_erg_resolution_event_source_bytes"),
        CheckConstraint(_json_limit("result_ecosystem_ids_json", 16384), name="ck_erg_resolution_event_result_bytes"),
        CheckConstraint(_json_limit("before_memberships_json", 65536), name="ck_erg_resolution_event_before_bytes"),
        CheckConstraint(_json_limit("after_memberships_json", 65536), name="ck_erg_resolution_event_after_bytes"),
        Index("idx_erg_resolution_event_tenant_time", "tenant_id", "occurred_at", "resolution_event_id"),
        Index("idx_erg_resolution_event_tenant_action", "tenant_id", "action", "occurred_at", "resolution_event_id"),
    )

    resolution_event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    source_ecosystem_ids_json: Mapped[list] = mapped_column(JSON, nullable=False)
    result_ecosystem_ids_json: Mapped[list] = mapped_column(JSON, nullable=False)
    before_memberships_json: Mapped[list] = mapped_column(JSON, nullable=False)
    after_memberships_json: Mapped[list] = mapped_column(JSON, nullable=False)
    subject_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    evidence_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    reason: Mapped[str] = mapped_column(String(1000), nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    operator_id: Mapped[str] = mapped_column(String(128), nullable=False)
    operator_role: Mapped[str] = mapped_column(String(32), nullable=False)
    methodology_id: Mapped[str] = mapped_column(String(128), nullable=False)
    methodology_version: Mapped[str] = mapped_column(String(32), nullable=False)
    reverses_event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DiscoveryEcosystemHistoryMember(Base):
    __tablename__ = "discovery_ecosystem_history_members"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], name="fk_erg_history_member_tenant", ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "resolution_event_id"], ["discovery_ecosystem_resolution_events.tenant_id", "discovery_ecosystem_resolution_events.resolution_event_id"], name="fk_erg_history_member_tenant_event", ondelete="RESTRICT"),
        ForeignKeyConstraint(["tenant_id", "graph_node_id"], ["discovery_resolution_graph_nodes.tenant_id", "discovery_resolution_graph_nodes.graph_node_id"], name="fk_erg_history_member_tenant_graph", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "history_member_id", name="uq_erg_history_member_tenant_id"),
        UniqueConstraint("tenant_id", "resolution_event_id", "side", "ecosystem_id", "graph_node_id", name="uq_erg_history_member_tenant_fact"),
        CheckConstraint("side IN ('before','after')", name="ck_erg_history_member_side"),
        CheckConstraint(_hash_check("input_digest"), name="ck_erg_history_member_digest"),
        CheckConstraint(_json_limit("membership_snapshot_json", 32768), name="ck_erg_history_member_snapshot_bytes"),
        Index("idx_erg_history_member_tenant_event", "tenant_id", "resolution_event_id", "side", "history_member_id"),
        Index("idx_erg_history_member_tenant_ecosystem", "tenant_id", "ecosystem_id", "history_member_id"),
    )

    history_member_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    resolution_event_id: Mapped[str] = mapped_column(String(36), nullable=False)
    side: Mapped[str] = mapped_column(String(16), nullable=False)
    ecosystem_id: Mapped[str] = mapped_column(String(36), nullable=False)
    graph_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    membership_snapshot_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


ERG_TABLE_MODELS = {
    model.__tablename__: model
    for model in (
        DiscoveryHypothesisEvaluation,
        DiscoveryHypothesisEvaluationEdge,
        DiscoveryCollectorQualitySnapshot,
        DiscoveryObservationQualitySnapshot,
        DiscoveryAIEcosystem,
        DiscoveryEcosystemMembership,
        DiscoveryEcosystemResolutionEvent,
        DiscoveryEcosystemHistoryMember,
    )
}


__all__ = [
    "ERG_TABLE_MODELS",
    "DiscoveryAIEcosystem",
    "DiscoveryCollectorQualitySnapshot",
    "DiscoveryEcosystemHistoryMember",
    "DiscoveryEcosystemMembership",
    "DiscoveryEcosystemResolutionEvent",
    "DiscoveryHypothesisEvaluation",
    "DiscoveryHypothesisEvaluationEdge",
    "DiscoveryObservationQualitySnapshot",
]
