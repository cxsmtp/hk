from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, CheckConstraint, DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class AISystemApprovalPolicy(Base):
    """A tenant's approval workflow for AI systems (app/services/ai_system_approval_service.py).

    ``config`` holds, for each risk tier, how many distinct people must approve, whether the requester may approve
    their own request, which roles may approve, and which approval scopes (blanket, one-time, time-bound) an approver
    may choose. No row means the defaults.
    """

    __tablename__ = "ai_system_approval_policies"

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    revision: Mapped[int] = mapped_column(nullable=False, default=0)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_by: Mapped[str] = mapped_column(String(320), nullable=False, default="")


class AISystemApprovalGrant(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One standing approval of an AI system, issued when an approval request (approval_requests) reached the number
    of distinct approvers its tier's policy needs.

    ``scope``: blanket (until revoked), one_time (consumed by the first governed use) or time_bound (ends at
    ``expires_at``). ``state`` moves from ACTIVE to CONSUMED, EXPIRED, REVOKED or SUPERSEDED (a newer approval of the
    same system replaced it), never back. ``origin`` is "workflow", or "upgrade" for a system that was already approved
    before the workflow existed (carried over as blanket; no approval request).
    """

    __tablename__ = "ai_system_approval_grants"
    __table_args__ = (
        CheckConstraint("scope IN ('blanket','one_time','time_bound')", name="ck_ai_system_approval_grant_scope"),
        CheckConstraint(
            "state IN ('ACTIVE','CONSUMED','EXPIRED','REVOKED','SUPERSEDED')", name="ck_ai_system_approval_grant_state"
        ),
        CheckConstraint("scope <> 'time_bound' OR expires_at IS NOT NULL", name="ck_ai_system_approval_grant_expiry"),
        Index("idx_ai_system_approval_grant_tenant_state", "tenant_id", "state"),
        Index("idx_ai_system_approval_grant_system", "tenant_id", "ai_system_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ai_system_id: Mapped[str] = mapped_column(ForeignKey("ai_systems.id", ondelete="CASCADE"), nullable=False)
    approval_request_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("approval_requests.id", ondelete="SET NULL"), nullable=True
    )
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="ACTIVE")
    risk_tier: Mapped[str] = mapped_column(String(16), nullable=False, default="")
    origin: Mapped[str] = mapped_column(String(16), nullable=False, default="workflow")
    requested_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    approver_user_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    end_reason: Mapped[str] = mapped_column(String(255), nullable=False, default="")


__all__ = ["AISystemApprovalGrant", "AISystemApprovalPolicy"]
