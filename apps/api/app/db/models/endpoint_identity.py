from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, JSON, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class EndpointDeviceIdentity(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Public, revocable identity for one enrolled endpoint.

    Private keys and bearer credentials are deliberately absent from this schema.
    """

    __tablename__ = "endpoint_device_identities"
    __table_args__ = (
        UniqueConstraint("tenant_id", "endpoint_id", name="uq_endpoint_identity_tenant_endpoint"),
        UniqueConstraint("key_thumbprint", name="uq_endpoint_identity_key_thumbprint"),
        Index("idx_endpoint_identity_tenant_status", "tenant_id", "status"),
        Index("idx_endpoint_identity_assigned_user", "tenant_id", "assigned_user_id"),
    )

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    endpoint_id: Mapped[str] = mapped_column(String(128), nullable=False)
    assigned_user_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    public_key_pem: Mapped[str] = mapped_column(String(2048), nullable=False)
    key_thumbprint: Mapped[str] = mapped_column(String(64), nullable=False)
    key_provider: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    enrolled_by_user_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    last_authenticated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_user_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    revocation_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)


class EndpointEnrollmentAuthorization(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Hashed, short-lived, single-use permission to enroll a device key."""

    __tablename__ = "endpoint_enrollment_authorizations"
    __table_args__ = (
        UniqueConstraint("code_hash", name="uq_endpoint_enrollment_code_hash"),
        UniqueConstraint("nonce_hash", name="uq_endpoint_enrollment_nonce_hash"),
        Index("idx_endpoint_enrollment_tenant_expiry", "tenant_id", "expires_at"),
    )

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    endpoint_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    assigned_user_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    issued_by_user_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class EndpointAuthChallenge(Base, UUIDPrimaryKeyMixin):
    """Hashed, short-lived, single-use authentication challenge."""

    __tablename__ = "endpoint_auth_challenges"
    __table_args__ = (
        UniqueConstraint("nonce_hash", name="uq_endpoint_auth_challenge_nonce_hash"),
        Index("idx_endpoint_auth_challenge_identity_expiry", "device_identity_id", "expires_at"),
    )

    device_identity_id: Mapped[str] = mapped_column(
        ForeignKey("endpoint_device_identities.id", ondelete="CASCADE"), nullable=False
    )
    nonce_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class EndpointProofReplay(Base, UUIDPrimaryKeyMixin):
    """Short-lived replay ledger shared by all API workers."""

    __tablename__ = "endpoint_proof_replays"
    __table_args__ = (
        UniqueConstraint("proof_hash", name="uq_endpoint_proof_hash"),
        Index("idx_endpoint_proof_identity_expiry", "device_identity_id", "expires_at"),
    )

    device_identity_id: Mapped[str] = mapped_column(
        ForeignKey("endpoint_device_identities.id", ondelete="CASCADE"), nullable=False
    )
    proof_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
