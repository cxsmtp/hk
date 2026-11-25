from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func, text
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


class SignInPolicy(Base):
    """The sign-in rules an administrator sets for the whole installation (Settings → Sign-in): one row, id 1.

    CxMissionZero keeps them in iam.json (policy.passwordReset, policy.twoStepRequired, policy.twoStepResetFor,
    policy.sso). Hawk's identity provider itself (issuer, client id and secret) stays in its OIDC_* configuration;
    who may sign in through it is kept here (docs/sign-in.md).
    """

    __tablename__ = "sign_in_policy"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    # Who may reset a forgotten password by email: "everyone", "not-admins" or "off".
    password_reset: Mapped[str] = mapped_column(String(16), nullable=False, default="everyone", server_default="everyone")
    two_step_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))
    # The RESET_TWO_STEP value last used, so it works once for a person.
    two_step_reset_for: Mapped[str] = mapped_column(String(320), nullable=False, default="", server_default="")
    # Single sign-on: "existing" (only people already here) or "create" (added at their first sign-on with sso_role).
    sso_provision: Mapped[str] = mapped_column(String(16), nullable=False, default="existing", server_default="existing")
    sso_role: Mapped[str] = mapped_column(String(32), nullable=False, default="viewer", server_default="viewer")
    # Email domains allowed (a JSON list); none listed: any.
    sso_domains: Mapped[str] = mapped_column(Text, nullable=False, default="[]", server_default="[]")
    sso_require_verified_email: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=text("true"))
    sso_password_admins_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))
    # The fingerprint of the SMTP_* settings an administrator sent a test email with (CxMissionZero's isVerified).
    smtp_verified: Mapped[str] = mapped_column(String(64), nullable=False, default="", server_default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
