from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class AgentIdentity(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "agent_identities"
    __table_args__ = (Index("idx_agent_tenant", "tenant_id"),)

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), default="", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    owner_attested_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    owner_attestation_expiry: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    max_chain_depth: Mapped[int] = mapped_column(default=3, nullable=False)
    capability_inheritance: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    action_scope: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    tool_registry: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    external_system_access: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    agent_type: Mapped[str] = mapped_column(String(32), default="workflow_agent", nullable=False)
    autonomy_level: Mapped[str] = mapped_column(String(16), default="medium", nullable=False)


class CapabilityToken(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "capability_tokens"
    __table_args__ = (
        Index("idx_token_tenant", "tenant_id"),
        Index("idx_token_agent", "agent_identity_id"),
        Index("idx_token_ai_system", "ai_system_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    agent_identity_id: Mapped[str] = mapped_column(ForeignKey("agent_identities.id", ondelete="CASCADE"), nullable=False)
    ai_system_id: Mapped[Optional[str]] = mapped_column(ForeignKey("ai_systems.id", ondelete="SET NULL"), nullable=True)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    scopes: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    chain_depth: Mapped[int] = mapped_column(default=0, nullable=False)
    issued_by_user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)


class AgentActionBaseline(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "agent_action_baselines"
    __table_args__ = (
        UniqueConstraint("tenant_id", "agent_identity_id", "action", name="uq_agent_action_baseline"),
        Index("idx_agent_action_baseline_tenant_agent", "tenant_id", "agent_identity_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    agent_identity_id: Mapped[str] = mapped_column(ForeignKey("agent_identities.id", ondelete="CASCADE"), nullable=False)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    baseline_rate_per_hour: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    current_window_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_anomaly_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class AgentDelegation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "agent_delegations"
    __table_args__ = (
        Index("idx_agent_delegation_tenant_parent", "tenant_id", "parent_agent_identity_id"),
        Index("idx_agent_delegation_tenant_child", "tenant_id", "child_agent_identity_id"),
        Index("idx_agent_delegation_tenant_status", "tenant_id", "status"),
        UniqueConstraint(
            "tenant_id",
            "parent_agent_identity_id",
            "child_agent_identity_id",
            "parent_token_id",
            "child_token_id",
            name="uq_agent_delegation_link",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    parent_agent_identity_id: Mapped[str] = mapped_column(ForeignKey("agent_identities.id", ondelete="CASCADE"), nullable=False)
    child_agent_identity_id: Mapped[str] = mapped_column(ForeignKey("agent_identities.id", ondelete="CASCADE"), nullable=False)
    ai_system_id: Mapped[Optional[str]] = mapped_column(ForeignKey("ai_systems.id", ondelete="SET NULL"), nullable=True)
    parent_token_id: Mapped[str] = mapped_column(ForeignKey("capability_tokens.id", ondelete="CASCADE"), nullable=False)
    child_token_id: Mapped[str] = mapped_column(ForeignKey("capability_tokens.id", ondelete="CASCADE"), nullable=False)
    action_scope: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    chain_depth: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class JITGrantBinding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "jit_grant_bindings"
    __table_args__ = (
        Index("idx_jit_grant_bindings_tenant_chain", "tenant_id", "chain_id"),
        Index("idx_jit_grant_bindings_tenant_agent", "tenant_id", "agent_id"),
        Index("idx_jit_grant_bindings_tenant_status", "tenant_id", "status"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    chain_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False)
    requested_scope: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    approved_scope: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    identity_provider: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    grant_type: Mapped[str] = mapped_column(String(64), nullable=False, default="temporary")
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    task_binding_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    privilege_delta: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    persistence_risk: Mapped[str] = mapped_column(String(32), nullable=False, default="none")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    policy_decision_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    evidence_bundle_id: Mapped[Optional[str]] = mapped_column(ForeignKey("evidence_nodes.id", ondelete="SET NULL"), nullable=True)
