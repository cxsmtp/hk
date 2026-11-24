"""Tenant-scoped, metadata-only endpoint inventory orchestration.

These rows coordinate bounded work that an already enrolled endpoint chooses to
perform after receiving its own authenticated policy.  They are not a command
queue and do not create endpoint reachability or coverage claims beyond the
eligible enrolled-device denominator captured on the run.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class EndpointMetadataInventoryRun(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "endpoint_metadata_inventory_runs"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "request_idempotency_key",
            name="uq_endpoint_metadata_inventory_run_request",
        ),
        CheckConstraint(
            "status IN ('queued','running','complete','partially_complete',"
            "'failed','cancelled','expired')",
            name="ck_endpoint_metadata_inventory_run_status",
        ),
        CheckConstraint(
            "endpoint_denominator >= 1",
            name="ck_endpoint_metadata_inventory_run_denominator",
        ),
        Index(
            "idx_endpoint_metadata_inventory_run_tenant_status_expiry",
            "tenant_id",
            "status",
            "expires_at",
        ),
        Index(
            "idx_endpoint_metadata_inventory_run_tenant_parent_scan",
            "tenant_id",
            "parent_scan_id",
        ),
        Index(
            "idx_endpoint_metadata_inventory_run_tenant_parent_assignment",
            "tenant_id",
            "parent_assignment_id",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    requested_by_user_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    request_idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    endpoint_denominator: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    limitations_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    parent_scan_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    parent_assignment_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    cancelled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class EndpointMetadataInventoryAssignment(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "endpoint_metadata_inventory_assignments"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "inventory_run_id",
            "endpoint_device_identity_id",
            name="uq_endpoint_metadata_inventory_assignment_scope",
        ),
        CheckConstraint(
            "status IN ('pending','delivered','complete','failed','expired','cancelled')",
            name="ck_endpoint_metadata_inventory_assignment_status",
        ),
        CheckConstraint(
            "observations_count >= 0",
            name="ck_endpoint_metadata_inventory_assignment_observations",
        ),
        Index(
            "idx_endpoint_metadata_inventory_assignment_run_status",
            "inventory_run_id",
            "status",
        ),
        Index(
            "idx_endpoint_metadata_inventory_assignment_tenant_endpoint_status",
            "tenant_id",
            "endpoint_device_identity_id",
            "status",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    inventory_run_id: Mapped[str] = mapped_column(
        ForeignKey("endpoint_metadata_inventory_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    endpoint_device_identity_id: Mapped[str] = mapped_column(
        ForeignKey("endpoint_device_identities.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    scan_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    observations_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    delivered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
