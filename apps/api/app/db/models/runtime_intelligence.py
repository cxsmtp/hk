from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import DateTime, Float, ForeignKey, ForeignKeyConstraint, Index, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class RuntimeEvent(Base):
    __tablename__ = "runtime_events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "event_id", name="uq_runtime_events_tenant_event_id"),
        Index("idx_runtime_events_tenant_created", "tenant_id", "created_at"),
        Index("idx_runtime_events_tenant_source", "tenant_id", "source_surface"),
        Index("idx_runtime_events_tenant_type", "tenant_id", "event_type"),
        Index("idx_runtime_events_tenant_decision", "tenant_id", "decision"),
        Index("idx_runtime_events_tenant_ai", "tenant_id", "ai_system_id"),
        Index("idx_runtime_events_correlation", "correlation_id"),
        Index("idx_runtime_events_context", "tenant_id", "context_id"),
        Index("idx_runtime_events_chain", "tenant_id", "chain_id"),
        Index("idx_runtime_events_entity", "tenant_id", "entity_type", "entity_id"),
        Index("idx_runtime_events_tenant_bundle", "tenant_id", "evidence_bundle_id"),
        ForeignKeyConstraint(
            ["tenant_id", "evidence_bundle_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_runtime_events_tenant_bundle",
            ondelete="SET NULL",
        ),
    )

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    source_surface: Mapped[str] = mapped_column(String(16), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    ai_system_id: Mapped[Optional[str]] = mapped_column(ForeignKey("ai_systems.id", ondelete="SET NULL"), nullable=True)
    app_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    machine_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    browser_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    application: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    decision: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    risk_tier: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    policy_version_id: Mapped[Optional[str]] = mapped_column(ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True)
    governance_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    confidence_tier: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    evidence_node_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence_bundle_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    context_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    chain_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    parent_action_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    entity_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    entity_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class RuntimeBehaviorEdge(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "runtime_behavior_edges"
    __table_args__ = (
        Index("idx_runtime_behavior_edges_tenant_event", "tenant_id", "event_id"),
        Index("idx_runtime_behavior_edges_tenant_ai", "tenant_id", "ai_system_id"),
        Index("idx_runtime_behavior_edges_tenant_relation", "tenant_id", "relationship_type"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    event_id: Mapped[Optional[str]] = mapped_column(ForeignKey("runtime_events.event_id", ondelete="CASCADE"), nullable=True)
    ai_system_id: Mapped[Optional[str]] = mapped_column(ForeignKey("ai_systems.id", ondelete="SET NULL"), nullable=True)
    source_node_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_node_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source_node_label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    target_node_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_node_id: Mapped[str] = mapped_column(String(128), nullable=False)
    target_node_label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_node_id: Mapped[Optional[str]] = mapped_column(ForeignKey("evidence_nodes.id", ondelete="SET NULL"), nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class RuntimeSimulationTrigger(Base, TimestampMixin):
    __tablename__ = "runtime_simulation_triggers"
    __table_args__ = (
        Index("idx_runtime_triggers_tenant_status", "tenant_id", "status"),
        Index("idx_runtime_triggers_tenant_ai", "tenant_id", "ai_system_id"),
        Index("idx_runtime_triggers_tenant_reason", "tenant_id", "reason_code"),
    )

    trigger_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ai_system_id: Mapped[Optional[str]] = mapped_column(ForeignKey("ai_systems.id", ondelete="SET NULL"), nullable=True)
    event_id: Mapped[Optional[str]] = mapped_column(ForeignKey("runtime_events.event_id", ondelete="SET NULL"), nullable=True)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    target_pack: Mapped[str] = mapped_column(String(64), nullable=False)
    related_control_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence_node_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    schedule_decision_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("simulation_schedule_decisions.id", ondelete="SET NULL"),
        nullable=True,
    )


class RuntimeGovernanceRecommendation(Base):
    __tablename__ = "runtime_governance_recommendations"
    __table_args__ = (
        Index("idx_runtime_recos_tenant_status", "tenant_id", "status"),
        Index("idx_runtime_recos_tenant_ai", "tenant_id", "ai_system_id"),
        Index("idx_runtime_recos_tenant_type", "tenant_id", "recommendation_type"),
    )

    recommendation_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    event_id: Mapped[str] = mapped_column(ForeignKey("runtime_events.event_id", ondelete="CASCADE"), nullable=False)
    ai_system_id: Mapped[Optional[str]] = mapped_column(ForeignKey("ai_systems.id", ondelete="SET NULL"), nullable=True)
    recommendation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="med")
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="proposed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class RuntimePattern(Base, TimestampMixin):
    __tablename__ = "runtime_patterns"
    __table_args__ = (
        UniqueConstraint("tenant_id", "type", name="uq_runtime_patterns_tenant_type"),
        Index("idx_runtime_patterns_tenant_type", "tenant_id", "type"),
        Index("idx_runtime_patterns_tenant_severity", "tenant_id", "severity"),
        Index("idx_runtime_patterns_tenant_updated", "tenant_id", "updated_at"),
    )

    pattern_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    type: Mapped[str] = mapped_column(String(128), nullable=False)
    frequency: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="low")
    affected_entities: Mapped[list] = mapped_column(JSON, nullable=False, default=list)


class ContextNode(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "context_nodes"
    __table_args__ = (
        UniqueConstraint("tenant_id", "context_id", "type", "entity_id", name="uq_context_nodes_tenant_context_entity"),
        Index("idx_context_nodes_tenant_context", "tenant_id", "context_id"),
        Index("idx_context_nodes_tenant_type", "tenant_id", "type"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    context_id: Mapped[str] = mapped_column(String(64), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(128), nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ContextEdge(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "context_edges"
    __table_args__ = (
        Index("idx_context_edges_tenant_context", "tenant_id", "context_id"),
        Index("idx_context_edges_tenant_relation", "tenant_id", "relation_type"),
        Index("idx_context_edges_tenant_chain", "tenant_id", "chain_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    context_id: Mapped[str] = mapped_column(String(64), nullable=False)
    from_node: Mapped[str] = mapped_column(ForeignKey("context_nodes.id", ondelete="CASCADE"), nullable=False)
    to_node: Mapped[str] = mapped_column(ForeignKey("context_nodes.id", ondelete="CASCADE"), nullable=False)
    relation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    parent_action_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class AIActionChain(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "ai_action_chains"
    __table_args__ = (
        UniqueConstraint("tenant_id", "chain_id", name="uq_ai_action_chains_tenant_chain"),
        Index("idx_ai_action_chains_tenant_status", "tenant_id", "chain_integrity_status"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    chain_id: Mapped[str] = mapped_column(String(64), nullable=False)
    root_action_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    root_user_intent_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    chain_integrity_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    chain_risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())


class ChainEvent(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "chain_events"
    __table_args__ = (
        Index("idx_chain_events_tenant_chain", "tenant_id", "chain_id"),
        Index("idx_chain_events_tenant_action", "tenant_id", "action_id"),
        Index("idx_chain_events_tenant_type", "tenant_id", "event_type"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    chain_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    actor_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    source_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    destination_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    source_trust_level: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    destination_trust_level: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    payload_ref: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    canonical_object_ref: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    taint_labels: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    policy_decision_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    evidence_bundle_id: Mapped[Optional[str]] = mapped_column(ForeignKey("evidence_nodes.id", ondelete="SET NULL"), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class DeferredSideEffect(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "deferred_side_effects"
    __table_args__ = (
        Index("idx_deferred_side_effects_tenant_chain", "tenant_id", "chain_id"),
        Index("idx_deferred_side_effects_tenant_action", "tenant_id", "action_id"),
        Index("idx_deferred_side_effects_tenant_type", "tenant_id", "side_effect_type"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    chain_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    side_effect_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_system: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    target_resource: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    persistence_duration: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    external_destination: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_object_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    monitoring_status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    approval_required: Mapped[bool] = mapped_column(nullable=False, default=True)
    policy_decision_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    evidence_bundle_id: Mapped[Optional[str]] = mapped_column(ForeignKey("evidence_nodes.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class TaintLabel(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "taint_labels"
    __table_args__ = (
        Index("idx_taint_labels_tenant_chain", "tenant_id", "chain_id"),
        Index("idx_taint_labels_tenant_action", "tenant_id", "action_id"),
        Index("idx_taint_labels_tenant_source", "tenant_id", "source_type"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    chain_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    source_ref: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    trust_level: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    taint_type: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    propagated_to_action_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    verified_by_human: Mapped[bool] = mapped_column(nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class AgentTouchpointEdge(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "agent_touchpoint_edges"
    __table_args__ = (
        Index("idx_agent_touchpoint_edges_tenant_source", "tenant_id", "source_node_type", "source_node_id"),
        Index("idx_agent_touchpoint_edges_tenant_target", "tenant_id", "target_node_type", "target_node_id"),
        Index("idx_agent_touchpoint_edges_tenant_chain", "tenant_id", "chain_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    source_node_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_node_id: Mapped[str] = mapped_column(String(128), nullable=False)
    target_node_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_node_id: Mapped[str] = mapped_column(String(128), nullable=False)
    edge_type: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    action_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="low")
    control_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="detected_only")
    evidence_bundle_id: Mapped[Optional[str]] = mapped_column(ForeignKey("evidence_nodes.id", ondelete="SET NULL"), nullable=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class BlastRadiusSnapshot(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "blast_radius_snapshots"
    __table_args__ = (
        Index("idx_blast_radius_snapshots_tenant_subject", "tenant_id", "subject_type", "subject_id"),
        Index("idx_blast_radius_snapshots_tenant_calculated", "tenant_id", "calculated_at"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False)
    reachable_tools_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reachable_mcp_servers_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reachable_saas_apps_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reachable_repos_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reachable_data_sources_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_risk_actions_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    persistent_side_effects_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    external_destinations_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    delegation_depth_max: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    data_access_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    tool_action_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    privilege_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    persistence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    external_exfiltration_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    delegation_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    overall_blast_radius_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
