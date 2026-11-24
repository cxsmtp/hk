from __future__ import annotations

from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import UUIDPrimaryKeyMixin
from app.db.session import Base


class BrainSession(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "brain_session"
    __table_args__ = (
        Index("idx_brain_session_tenant", "tenant_id"),
        Index("idx_brain_session_user", "user_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class BrainPlanRecord(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "brain_plan"
    __table_args__ = (
        Index("idx_brain_plan_session", "session_id"),
    )

    session_id: Mapped[str] = mapped_column(ForeignKey("brain_session.id", ondelete="CASCADE"), nullable=False)
    question: Mapped[str] = mapped_column(Text, nullable=False)
    plan_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class BrainToolCall(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "brain_tool_call"
    __table_args__ = (
        Index("idx_brain_tool_call_plan", "plan_id"),
        Index("idx_brain_tool_call_tool", "tool_name"),
    )

    plan_id: Mapped[str] = mapped_column(ForeignKey("brain_plan.id", ondelete="CASCADE"), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    args_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    result_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    started_at: Mapped[str] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at: Mapped[str] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class BrainModelCall(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "brain_model_call"
    __table_args__ = (
        Index("idx_brain_model_call_plan", "plan_id"),
        Index("idx_brain_model_call_task", "task_type"),
        Index("idx_brain_model_call_provider", "provider"),
    )

    plan_id: Mapped[str] = mapped_column(ForeignKey("brain_plan.id", ondelete="CASCADE"), nullable=False)
    task_type: Mapped[str] = mapped_column(String(32), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    prompt_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    output_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    output_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class BrainArbitration(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "brain_arbitration"
    __table_args__ = (
        Index("idx_brain_arbitration_plan", "plan_id"),
        Index("idx_brain_arbitration_task", "task_type"),
    )

    plan_id: Mapped[str] = mapped_column(ForeignKey("brain_plan.id", ondelete="CASCADE"), nullable=False)
    task_type: Mapped[str] = mapped_column(String(32), nullable=False)
    winner: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    dissenters_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    reason_codes_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
