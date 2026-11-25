"""Roles, teams and self-join rules, per tenant (FTR Command Center's iam.json roles, teams.json and settings.selfJoin;
app/services/iam_service.py). A person's role and team in a tenant are on their membership (user_tenant_roles)."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import JSON, Boolean, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class IamRole(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A role of a tenant. The five built-in roles (owner, admin, auditor, operator, viewer) need no row: a row for one
    holds its new name or, for the three that are not locked, its changed permissions (``permissions`` NULL: the
    defaults of app/core/permissions.py, so a permission added later reaches the built-in roles by itself)."""

    __tablename__ = "iam_roles"
    __table_args__ = (UniqueConstraint("tenant_id", "key", name="uq_iam_roles_tenant_key"),)

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    #: What memberships carry in ``role``: a built-in id, or role-<8 hex> for a role someone made.
    key: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(60), nullable=False)
    description: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    permissions: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    builtin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class IamTeam(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A team of a tenant: teams form a tree (Global → EMEA → EMEA North); a team has leaders (FTR server/teams.js)."""

    __tablename__ = "iam_teams"
    __table_args__ = (Index("idx_iam_teams_tenant", "tenant_id"),)

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    region: Mapped[str] = mapped_column(String(60), nullable=False, default="")
    parent_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    leader_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)


class IamJoinSettings(Base, TimestampMixin):
    """Joining by oneself, for one tenant (FTR CC-01.116.00, People → Sign-in): off until an owner or admin turns it
    on; the email domains that may join, and the roles they may choose."""

    __tablename__ = "iam_join_settings"

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    domains: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    roles: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    updated_by: Mapped[str] = mapped_column(Text, nullable=False, default="")
