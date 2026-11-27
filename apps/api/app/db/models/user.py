from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, false, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class User(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("sso_issuer", "sso_subject", name="uq_users_sso_identity"),)

    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Set for the generated first administrator and by reset_admin (app/services/first_run_service.py): until they
    # choose their own password, every signed-in route but /auth/me and /auth/me/password answers 403.
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false(), nullable=False)

    # Sign-in (/settings/guide/people-and-access, ported from CxMissionZero's src/iam.js and src/mfa.js).
    # Wrong passwords (and wrong two-step codes) in a row: 5 lock the account for 15 minutes.
    failed_logins: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"), nullable=False)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Signed out everywhere at this moment (a password reset): access tokens issued before it are refused.
    signed_out_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Two-step sign-in: the TOTP secret (encrypted, app/services/connector_secret_service.py), when it was turned on,
    # the step of the last code used (a code works once) and the recovery codes' SHA-256 hashes (a JSON list).
    mfa_secret: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mfa_enabled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    mfa_last_step: Mapped[int] = mapped_column(BigInteger, default=0, server_default=text("0"), nullable=False)
    mfa_recovery: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Single sign-on: the identity provider's account this person is linked to, by (issuer, subject).
    sso_issuer: Mapped[Optional[str]] = mapped_column(String(300), nullable=True)
    sso_subject: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # The password rule (app/services/password_policy.py): when the password was last set (None: before migration
    # 0104, counted from created_at) and the bcrypt hashes of the earlier ones, newest first (a JSON list).
    password_changed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    password_history: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    tenant_roles = relationship("UserTenantRole", back_populates="user", cascade="all,delete-orphan")


class UserTenantRole(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "user_tenant_roles"
    __table_args__ = (
        UniqueConstraint("user_id", "tenant_id", name="uq_user_tenant_role"),
        Index("idx_user_tenant_tenant", "tenant_id"),
    )

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    # People, teams and roles (FTR Command Center's people.js; app/services/iam_service.py), per tenant: the person's
    # team, title and whom they report to, and, for someone who joined by themselves, what they chose and who reviewed it.
    team_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    title: Mapped[str] = mapped_column(String(120), default="", server_default="", nullable=False)
    manager_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    joined_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    joined_role: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    joined_team_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    user = relationship("User", back_populates="tenant_roles")


class RefreshToken(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "refresh_tokens"
    __table_args__ = (
        Index("idx_refresh_user", "user_id"),
        Index("idx_refresh_tenant", "tenant_id"),
    )

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
