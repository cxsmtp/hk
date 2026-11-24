"""Tenant-scoped aggregate security state for existing agent delegations.

These records do not replace Phase 5 delegation authority or Phase 7 lineage.
They retain only collective constraints, visible communication evidence,
deterministic signals, and delegation-root revocation audit state.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class AgentCollectiveContext(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "agent_collective_contexts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "delegation_root_context_id"],
            ["delegation_contexts_v2.tenant_id", "delegation_contexts_v2.delegation_context_id"],
            name="fk_agent_collective_delegation_root",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "tenant_id", "id", name="uq_agent_collective_tenant_id"
        ),
        UniqueConstraint(
            "tenant_id",
            "delegation_root_context_id",
            name="uq_agent_collective_root",
        ),
        CheckConstraint(
            "status IN ('ACTIVE','RESTRICTED','ABANDONED','REVOKED')",
            name="ck_agent_collective_status",
        ),
        CheckConstraint("state_version >= 0", name="ck_agent_collective_state_version"),
        CheckConstraint("agent_count > 0", name="ck_agent_collective_agent_count"),
        CheckConstraint("maximum_depth > 0", name="ck_agent_collective_depth"),
        CheckConstraint("maximum_fan_out >= 0", name="ck_agent_collective_fanout"),
        CheckConstraint("retry_count >= 0", name="ck_agent_collective_retry_count"),
        CheckConstraint("failure_count >= 0", name="ck_agent_collective_failure_count"),
        Index("idx_agent_collective_tenant_status", "tenant_id", "status"),
        Index("idx_agent_collective_tenant_root_action", "tenant_id", "root_action_id"),
    )

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    delegation_root_context_id: Mapped[str] = mapped_column(String(36), nullable=False)
    root_action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    originating_actor_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    represented_subject_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    business_purpose_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    root_objective_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    authority_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    constraint_set: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    member_agent_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    member_delegation_context_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    active_principal_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    observed_channel_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    shared_store_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    observed_tool_classes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    observed_external_destinations: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    active_consequential_action_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    authorized_action_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    retry_fingerprints: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    agent_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    maximum_depth: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    maximum_fan_out: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ACTIVE")
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentCommunicationEvent(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "agent_collective_communication_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "collective_id"],
            ["agent_collective_contexts.tenant_id", "agent_collective_contexts.id"],
            name="fk_agent_collective_communication_context",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "decision IN ('ALLOW','MONITOR','REQUIRE_APPROVAL','BLOCK','UNKNOWN')",
            name="ck_agent_collective_communication_decision",
        ),
        CheckConstraint(
            "operation IN ('SEND','RECEIVE','WRITE','READ','UNKNOWN')",
            name="ck_agent_collective_communication_operation",
        ),
        Index(
            "idx_agent_collective_communication_resource",
            "tenant_id",
            "collective_id",
            "shared_resource_ref",
            "occurred_at",
        ),
        Index(
            "idx_agent_collective_communication_channel",
            "tenant_id",
            "channel_type",
            "channel_ref",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    collective_id: Mapped[str] = mapped_column(String(36), nullable=False)
    writer_agent_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reader_agent_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    channel_type: Mapped[str] = mapped_column(String(32), nullable=False)
    channel_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    operation: Mapped[str] = mapped_column(String(16), nullable=False)
    decision: Mapped[str] = mapped_column(String(24), nullable=False)
    shared_resource_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    originating_objective_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    instruction_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    authority_context_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    evidence_quality: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    runtime_event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class CollectiveSecuritySignal(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "agent_collective_security_signals"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "collective_id"],
            ["agent_collective_contexts.tenant_id", "agent_collective_contexts.id"],
            name="fk_agent_collective_signal_context",
            ondelete="CASCADE",
        ),
        Index(
            "idx_agent_collective_signal_type",
            "tenant_id",
            "collective_id",
            "signal_type",
            "occurred_at",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    collective_id: Mapped[str] = mapped_column(String(36), nullable=False)
    signal_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    agent_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reason_code: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    safe_context: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    monitoring_signal_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    runtime_event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class DelegationRootRevocation(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "agent_collective_root_revocations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "collective_id"],
            ["agent_collective_contexts.tenant_id", "agent_collective_contexts.id"],
            name="fk_agent_collective_revocation_context",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "tenant_id", "collective_id", name="uq_agent_collective_root_revocation"
        ),
        Index("idx_agent_collective_revocation_root", "tenant_id", "delegation_root_context_id"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    collective_id: Mapped[str] = mapped_column(String(36), nullable=False)
    delegation_root_context_id: Mapped[str] = mapped_column(String(36), nullable=False)
    actor_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(128), nullable=False)
    affected_agent_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    affected_action_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    affected_authority_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    runtime_event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
