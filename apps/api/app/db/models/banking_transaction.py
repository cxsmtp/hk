from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import UUIDPrimaryKeyMixin
from app.db.session import Base


class BankingSubjectBinding(Base, UUIDPrimaryKeyMixin):
    """Replay-safe binding of one bank assertion nonce to one Hawk transaction."""

    __tablename__ = "banking_subject_bindings"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "issuer",
            "nonce_hash",
            name="uq_banking_subject_binding_tenant_issuer_nonce",
        ),
        Index("idx_banking_subject_binding_expiry", "expires_at"),
        Index(
            "idx_banking_subject_binding_transaction",
            "tenant_id",
            "ai_transaction_id",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    nonce_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    context_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    ai_transaction_id: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class BankingExecutionGrant(Base, UUIDPrimaryKeyMixin):
    """Short-lived, single-use capability issued by the final server gate."""

    __tablename__ = "banking_execution_grants"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "decision_receipt_id",
            "execution_attempt_id",
            name="uq_banking_execution_grant_tenant_decision_attempt",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "decision_receipt_id"],
            ["decision_receipts.tenant_id", "decision_receipts.receipt_id"],
            name="fk_banking_execution_grant_tenant_decision",
            ondelete="CASCADE",
        ),
        Index(
            "idx_banking_execution_grant_expiry",
            "tenant_id",
            "expires_at",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    decision_receipt_id: Mapped[str] = mapped_column(String(36), nullable=False)
    execution_attempt_id: Mapped[str] = mapped_column(String(128), nullable=False)
    canonical_action: Mapped[dict] = mapped_column(JSON, nullable=False)
    canonical_action_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    execution_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    execution_receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    integrity_result_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
