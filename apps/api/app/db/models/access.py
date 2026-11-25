from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import UUIDPrimaryKeyMixin
from app.db.session import Base


class TermsAcceptance(Base, UUIDPrimaryKeyMixin):
    """Who accepted the terms of use (TERMS.md), and which text (app/services/terms_service.py).

    CxMissionZero keeps this in DATA_DIR/terms.json: ``{organisation, organisationName, users}``. Hawk runs several
    processes, so it is kept here: one row per acceptance. ``scope`` is ``organisation`` (an owner or admin, or
    ACCEPT_TERMS, for the whole installation) or ``user`` (one person). Only rows whose ``text_hash`` is the hash of
    the current text count, so changed terms are asked for again.
    """

    __tablename__ = "terms_acceptances"
    __table_args__ = (
        Index("idx_terms_acceptance_scope_hash", "scope", "text_hash"),
        Index("idx_terms_acceptance_user", "user_id"),
    )

    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, default="")
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    text_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    ip: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    via: Mapped[str] = mapped_column(String(32), nullable=False, default="page")
    everyone: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    organisation_name: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class FirstRunState(Base):
    """The pending first-administrator setup code (FIRST_ADMIN=setup-code): one row, id 1.

    CxMissionZero keeps the code in the server's memory. Hawk's API may run as several processes, so only its SHA-256
    is kept here, written at start-up under the bootstrap lock and cleared once POST /setup has used it.
    """

    __tablename__ = "first_run_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    setup_code_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
