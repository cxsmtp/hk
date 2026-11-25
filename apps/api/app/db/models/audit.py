from __future__ import annotations

from typing import Optional

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, JSON, String, event, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import UUIDPrimaryKeyMixin
from app.db.session import Base


class AuditLog(Base, UUIDPrimaryKeyMixin):
    """The audit log: append-only (database triggers refuse UPDATE and DELETE, migration 0002) and tamper-evident
    (migration 0097, app/services/audit_chain.py). Every entry written since 0097 carries its place in its chain
    (``chain``: the tenant's id, or ``system``), a sequence number, the previous entry's MAC and its own: an
    HMAC-SHA256 over that previous MAC and the entry, keyed by ``audit.key`` in the data folder (CxMissionZero's
    src/audit-log.js). Entries written before 0097 have no MAC and are reported as such by the check."""

    __tablename__ = "audit_logs"
    __table_args__ = (Index("uq_audit_logs_chain_seq", "chain", "seq", unique=True),)

    tenant_id: Mapped[Optional[str]] = mapped_column(ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True, index=True)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    actor_user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    chain: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    seq: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    prev_mac: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    mac: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


class AuditChainHead(Base):
    """The last entry of each audit chain: its sequence number and MAC. Appending takes this row's lock (an UPDATE),
    so the api and the worker never number two entries alike or chain them out of order."""

    __tablename__ = "audit_chain_heads"

    chain: Mapped[str] = mapped_column(String(64), primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    mac: Mapped[str] = mapped_column(String(64), nullable=False, default="genesis")


@event.listens_for(AuditLog, "before_update", propagate=True)
def _prevent_audit_update(mapper, connection, target):
    raise ValueError("AuditLog is immutable and append-only")


@event.listens_for(AuditLog, "before_delete", propagate=True)
def _prevent_audit_delete(mapper, connection, target):
    raise ValueError("AuditLog is immutable and append-only")


@event.listens_for(AuditLog, "before_insert", propagate=True)
def _chain_audit_entry(mapper, connection, target):
    # Imported here: the chain needs the key in the data folder (app/services/audit_chain.py).
    from app.services.audit_chain import chain_entry

    chain_entry(connection, target)
