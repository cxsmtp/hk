from __future__ import annotations

from typing import Optional

from sqlalchemy import DateTime, Float, ForeignKey, ForeignKeyConstraint, Index, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import UUIDPrimaryKeyMixin
from app.db.session import Base


class ControlMaturity(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "control_maturity"
    __table_args__ = (
        ForeignKeyConstraint(
            ["control_id", "tenant_id"],
            ["controls.id", "controls.tenant_id"],
            ondelete="CASCADE",
            name="fk_control_maturity_tenant_control",
        ),
        UniqueConstraint("tenant_id", "ai_system_id", "control_id", name="uq_control_maturity"),
        Index("idx_maturity_tenant_system", "tenant_id", "ai_system_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ai_system_id: Mapped[str] = mapped_column(ForeignKey("ai_systems.id", ondelete="CASCADE"), nullable=False)
    control_id: Mapped[str] = mapped_column(String(36), nullable=False)

    technical_enforcement_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    simulation_pass_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    coverage_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    maturity_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="needs_review")
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    confidence_inputs: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    updated_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class ControlMaturityHistory(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "control_maturity_history"
    __table_args__ = (
        ForeignKeyConstraint(
            ["control_id", "tenant_id"],
            ["controls.id", "controls.tenant_id"],
            ondelete="CASCADE",
            name="fk_control_maturity_history_tenant_control",
        ),
        Index("idx_maturity_history_tenant", "tenant_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ai_system_id: Mapped[str] = mapped_column(ForeignKey("ai_systems.id", ondelete="CASCADE"), nullable=False)
    control_id: Mapped[str] = mapped_column(String(36), nullable=False)

    technical_enforcement_score: Mapped[float] = mapped_column(Float, nullable=False)
    simulation_pass_rate: Mapped[float] = mapped_column(Float, nullable=False)
    coverage_score: Mapped[float] = mapped_column(Float, nullable=False)
    maturity_score: Mapped[float] = mapped_column(Float, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="needs_review")
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    confidence_inputs: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ControlConflict(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "control_conflicts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["control_id", "tenant_id"],
            ["controls.id", "controls.tenant_id"],
            ondelete="CASCADE",
            name="fk_control_conflicts_tenant_control",
        ),
        Index("idx_control_conflicts_tenant_status", "tenant_id", "status"),
        Index("idx_control_conflicts_control", "tenant_id", "ai_system_id", "control_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ai_system_id: Mapped[str] = mapped_column(ForeignKey("ai_systems.id", ondelete="CASCADE"), nullable=False)
    control_id: Mapped[str] = mapped_column(String(36), nullable=False)

    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    reason: Mapped[str] = mapped_column(String(255), nullable=False, default="contradictory_evidence")
    positive_signals: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    negative_signals: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    latest_signal_at: Mapped[Optional[str]] = mapped_column(DateTime(timezone=True), nullable=True)
    evidence_node_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    detected_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    resolved_at: Mapped[Optional[str]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolution_decision: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    resolution_notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    audit_log_id: Mapped[Optional[str]] = mapped_column(ForeignKey("audit_logs.id", ondelete="SET NULL"), nullable=True)


class ConflictResolution(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "conflict_resolutions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["control_id", "tenant_id"],
            ["controls.id", "controls.tenant_id"],
            ondelete="CASCADE",
            name="fk_conflict_resolutions_tenant_control",
        ),
        Index("idx_conflict_resolution_tenant_control", "tenant_id", "ai_system_id", "control_id"),
        Index("idx_conflict_resolution_conflict", "conflict_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ai_system_id: Mapped[str] = mapped_column(ForeignKey("ai_systems.id", ondelete="CASCADE"), nullable=False)
    control_id: Mapped[str] = mapped_column(String(36), nullable=False)
    conflict_id: Mapped[Optional[str]] = mapped_column(ForeignKey("control_conflicts.id", ondelete="SET NULL"), nullable=True)
    chosen_evidence_id: Mapped[Optional[str]] = mapped_column(ForeignKey("evidence_nodes.id", ondelete="SET NULL"), nullable=True)
    discarded_evidence_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
