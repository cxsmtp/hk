from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, JSON, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


PROVIDER_SIGNAL_KINDS = (
    "capability",
    "usage",
    "spend",
    "prompt",
    "tool",
    "meeting",
    "client_session",
)

PROVIDER_SEAT_SOURCES = (
    "provider_admin",
)


class ProviderSignalRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Sanitized, source-preserving provider observation.

    The typed payload contains normalized metadata only. The ingestion contract
    rejects credentials, authentication material, and raw prompt content before
    this record can be constructed.
    """

    __tablename__ = "provider_signal_records"
    __table_args__ = (
        UniqueConstraint("tenant_id", "dedup_key", name="uq_provider_signal_tenant_dedup"),
        CheckConstraint(
            "record_kind IN ('capability','usage','spend','prompt','tool','meeting','client_session')",
            name="ck_provider_signal_record_kind",
        ),
        Index("idx_provider_signal_tenant_provider_time", "tenant_id", "provider", "occurred_at"),
        Index("idx_provider_signal_tenant_kind_time", "tenant_id", "record_kind", "occurred_at"),
        Index("idx_provider_signal_tenant_user_time", "tenant_id", "user_id", "occurred_at"),
        Index("idx_provider_signal_tenant_client_time", "tenant_id", "client", "occurred_at"),
    )

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    connector_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("connectors.id", ondelete="SET NULL"), nullable=True
    )
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    product: Mapped[str] = mapped_column(String(128), nullable=False)
    source_type: Mapped[str] = mapped_column(String(48), nullable=False)
    source_schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    source_record_id: Mapped[str] = mapped_column(String(255), nullable=False)
    dedup_key: Mapped[str] = mapped_column(String(64), nullable=False)
    record_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    watermark: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    user_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    department: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    client: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    model: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    session_ref: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    evidence_quality: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # References only: downstream authorities retain their own state, history,
    # retention and access controls. This record never becomes a second source
    # of truth for MCP integrity, runtime activity, lineage or coverage.
    projection_refs: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class ProviderSeatSnapshot(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Authoritative provider-admin seat inventory snapshot.

    Individual seat assignments are intentionally out of scope. The snapshot is
    a tenant-scoped aggregate whose authority is limited to the declared
    provider-admin source and observed scope.
    """

    __tablename__ = "provider_seat_snapshots"
    __table_args__ = (
        UniqueConstraint("tenant_id", "dedup_key", name="uq_provider_seat_tenant_dedup"),
        CheckConstraint(
            "source_type IN ('provider_admin')",
            name="ck_provider_seat_authoritative_source",
        ),
        CheckConstraint("assigned_seats >= 0", name="ck_provider_seat_assigned_nonnegative"),
        CheckConstraint("active_seats >= 0", name="ck_provider_seat_active_nonnegative"),
        CheckConstraint("inactive_seats >= 0", name="ck_provider_seat_inactive_nonnegative"),
        CheckConstraint("never_used_seats >= 0", name="ck_provider_seat_never_used_nonnegative"),
        CheckConstraint("unknown_activity_seats >= 0", name="ck_provider_seat_unknown_activity_nonnegative"),
        CheckConstraint("total_licensed_seats >= 0", name="ck_provider_seat_total_licensed_nonnegative"),
        CheckConstraint(
            "assigned_seats = active_seats + inactive_seats + never_used_seats + unknown_activity_seats",
            name="ck_provider_seat_population_reconciles",
        ),
        CheckConstraint("total_licensed_seats >= assigned_seats", name="ck_provider_seat_total_gte_assigned"),
        CheckConstraint(
            "completeness IN ('COMPLETE','PARTIAL','UNKNOWN')",
            name="ck_provider_seat_completeness",
        ),
        CheckConstraint(
            "completeness != 'COMPLETE' OR total_licensed_seats = assigned_seats",
            name="ck_provider_seat_complete_reconciles",
        ),
        Index("idx_provider_seat_tenant_provider_time", "tenant_id", "provider", "product", "observed_at"),
        Index("idx_provider_seat_tenant_received", "tenant_id", "received_at"),
    )

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    connector_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("connectors.id", ondelete="SET NULL"), nullable=True
    )
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    product: Mapped[str] = mapped_column(String(128), nullable=False)
    source_type: Mapped[str] = mapped_column(String(48), nullable=False)
    source_schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    source_record_id: Mapped[str] = mapped_column(String(255), nullable=False)
    dedup_key: Mapped[str] = mapped_column(String(64), nullable=False)
    billing_group: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    authority_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    total_licensed_seats: Mapped[int] = mapped_column(nullable=False)
    assigned_seats: Mapped[int] = mapped_column(nullable=False)
    active_seats: Mapped[int] = mapped_column(nullable=False)
    inactive_seats: Mapped[int] = mapped_column(nullable=False)
    never_used_seats: Mapped[int] = mapped_column(nullable=False)
    unknown_activity_seats: Mapped[int] = mapped_column(nullable=False)
    completeness: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")
    evidence_quality: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
