"""Requests from data subjects (Settings → Compliance → Data requests; app/services/data_subject_requests.py, migration
0106): a person asks the organisation running Hawk AI to see, correct or erase their personal data, raises a grievance
or nominates someone to act for them (India's DPDP Act 2023 s.11-14 and Rules 2025 R.14; the UAE PDPL, Federal
Decree-Law 45/2021, Art. 13-15).

- ``data_subject_requests``: one row per request of a tenant: its kind, who it is about, when it was received and is
  due (30 days by default, set per tenant), its status, who handles it and how it ended.
- ``data_subject_request_events``: the request's trail, append-only (never changed or deleted: the ORM refuses here,
  database triggers in the migration): every status change, note, export and erasure, with who and when.
- ``data_subject_request_settings``: per tenant, how many days a request has before it is due, and the grievance
  contact the organisation publishes (DPDP s.8(9), R.9).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text, event, func, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.access import ImmutableRecordError
from app.db.models.base import UUIDPrimaryKeyMixin
from app.db.session import Base


class DataSubjectRequest(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "data_subject_requests"
    __table_args__ = (
        Index("idx_dsr_tenant_status", "tenant_id", "status"),
        Index("idx_dsr_tenant_due", "tenant_id", "due_at"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    # access | correction | erasure | grievance | nomination
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    # dpdp | pdpl | other: the law the person asked under (it sets nothing else here).
    law: Mapped[str] = mapped_column(String(16), nullable=False, default="other", server_default="other")
    # Who it is about: their email (lower case) and any other identifier the organisation knows them by. After an
    # erasure the email is replaced by the account's pseudonym; ``subject_hash`` (SHA-256 of the email as received)
    # still proves which address a request was about if the person asks again.
    subject_email: Mapped[str] = mapped_column(String(320), nullable=False, default="", server_default="")
    subject_identifier: Mapped[str] = mapped_column(String(200), nullable=False, default="", server_default="")
    subject_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="", server_default="")
    # The tenant member the email matched when the request was recorded (None: nobody here by that address).
    subject_user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    channel: Mapped[str] = mapped_column(String(32), nullable=False, default="", server_default="")
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # received | verifying | in_progress | completed | refused
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="received", server_default="received")
    refusal_reason: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    handled_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    handled_by_email: Mapped[str] = mapped_column(String(320), nullable=False, default="", server_default="")
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_by_email: Mapped[str] = mapped_column(String(320), nullable=False, default="", server_default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class DataSubjectRequestEvent(Base, UUIDPrimaryKeyMixin):
    """One step of a request's trail. Never changed or deleted."""

    __tablename__ = "data_subject_request_events"
    __table_args__ = (Index("idx_dsr_event_request_at", "request_id", "at"),)

    request_id: Mapped[str] = mapped_column(ForeignKey("data_subject_requests.id"), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    actor_user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    actor_email: Mapped[str] = mapped_column(String(320), nullable=False, default="", server_default="")
    # created | status | note | assigned | exported | erased
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    from_status: Mapped[str] = mapped_column(String(16), nullable=False, default="", server_default="")
    to_status: Mapped[str] = mapped_column(String(16), nullable=False, default="", server_default="")
    note: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


@event.listens_for(DataSubjectRequestEvent, "before_update")
def _event_is_not_changed(mapper, connection, target) -> None:  # noqa: ARG001
    raise ImmutableRecordError("A data request's trail is append-only: an event cannot be changed.")


@event.listens_for(DataSubjectRequestEvent, "before_delete")
def _event_is_not_deleted(mapper, connection, target) -> None:  # noqa: ARG001
    raise ImmutableRecordError("A data request's trail is append-only: an event cannot be deleted.")


class DataSubjectRequestSettings(Base):
    __tablename__ = "data_subject_request_settings"

    tenant_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    due_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30, server_default=text("30"))
    grievance_contact: Mapped[str] = mapped_column(String(320), nullable=False, default="", server_default="")
    updated_by_email: Mapped[str] = mapped_column(String(320), nullable=False, default="", server_default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
