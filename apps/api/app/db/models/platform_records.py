"""Records the platform keeps besides the audit log (migration 0097):

- ``user_activity``: what people do in the console (CxMissionZero's src/activity-log.js): who, when, from where, the
  action, the names of the fields a change touched (never their values), status and time taken. Not chained.
- ``support_tickets``, ``support_counters``, ``support_settings``: Get help's support cases and enhancement requests
  (CxMissionZero's src/support.js), their numbers, and where requests go (the portal, or email).
- ``connector_calls``: every call a connector makes to an outside service (FTR Command Center's "CxOne API audit",
  server/activity.js): method, host, path without its query, status, time, tenant and connector.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, Boolean, DateTime, Index, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import UUIDPrimaryKeyMixin
from app.db.session import Base


class UserActivity(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "user_activity"
    __table_args__ = (Index("idx_user_activity_tenant_at", "tenant_id", "at"),)

    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    user: Mapped[str] = mapped_column(String(254), nullable=False, default="")
    name: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    role: Mapped[str] = mapped_column(String(60), nullable=False, default="")
    ip: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="action")
    action: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    target: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    fields: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    method: Mapped[str] = mapped_column(String(8), nullable=False, default="")
    route: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)


class SupportTicket(Base):
    __tablename__ = "support_tickets"
    __table_args__ = (Index("idx_support_tickets_requester_created", "requester_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    subject: Mapped[str] = mapped_column(String(200), nullable=False)
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="new")
    requester_id: Mapped[str] = mapped_column(String(36), nullable=False)
    requester_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    requester_email: Mapped[str] = mapped_column(String(320), nullable=False, default="")
    page: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    version: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    messages: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    history: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class SupportCounter(Base):
    __tablename__ = "support_counters"

    kind: Mapped[str] = mapped_column(String(16), primary_key=True)
    value: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class SupportSettings(Base):
    __tablename__ = "support_settings"

    tenant_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    mode: Mapped[str] = mapped_column(String(16), nullable=False, default="portal")
    email: Mapped[str] = mapped_column(String(320), nullable=False, default="")
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_by: Mapped[str] = mapped_column(String(320), nullable=False, default="")


class ConnectorCall(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "connector_calls"
    __table_args__ = (Index("idx_connector_calls_tenant_at", "tenant_id", "at"),)

    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    connector: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    connector_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    method: Mapped[str] = mapped_column(String(10), nullable=False, default="")
    host: Mapped[str] = mapped_column(String(253), nullable=False, default="")
    path: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    ok: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    ms: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
