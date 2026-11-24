"""Persistence used only to scope User Visibility access and prompt reveals."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class UserVisibilityAccessGrant(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "user_visibility_access_grants"
    __table_args__ = (
        CheckConstraint("length(trim(reason)) > 0", name="ck_user_visibility_access_grant_reason"),
        Index(
            "idx_user_visibility_access_grant_tenant_user_active_expiry",
            "tenant_id",
            "user_id",
            "active",
            "expires_at",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    capabilities: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    department_scope: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    granted_by_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class UserVisibilityContentAccessGrant(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "user_visibility_content_access_grants"
    __table_args__ = (
        CheckConstraint("length(trim(purpose)) > 0", name="ck_user_visibility_content_grant_purpose"),
        CheckConstraint("length(trim(reason)) > 0", name="ck_user_visibility_content_grant_reason"),
        Index(
            "idx_user_visibility_content_grant_tenant_requester_expiry",
            "tenant_id",
            "requester_user_id",
            "expires_at",
        ),
        Index("idx_user_visibility_content_grant_tenant_action", "tenant_id", "action_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    requester_user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    action_id: Mapped[str] = mapped_column(ForeignKey("ai_actions.action_id", ondelete="CASCADE"), nullable=False)
    purpose: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
