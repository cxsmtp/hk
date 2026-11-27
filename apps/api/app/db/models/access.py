from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, event, func, text
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
    # 0103_terms_acceptance: who accepted, as they typed it, and where from. ``authorised``: an administrator confirmed
    # they accept on behalf of the company and are authorised to. The text itself is in terms_texts (by text_hash).
    full_name: Mapped[str] = mapped_column(String(200), nullable=False, default="", server_default="")
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    user_agent: Mapped[str] = mapped_column(String(512), nullable=False, default="", server_default="")
    authorised: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=text("false"))


@event.listens_for(TermsAcceptance, "before_update")
def _acceptance_is_not_changed(mapper, connection, target) -> None:  # noqa: ARG001
    """An acceptance is a record of what someone agreed to: it is never edited (there is no API for it either)."""

    raise ImmutableRecordError("A terms acceptance is a permanent record and cannot be changed.")


@event.listens_for(TermsAcceptance, "before_delete")
def _acceptance_is_not_deleted(mapper, connection, target) -> None:  # noqa: ARG001
    raise ImmutableRecordError("A terms acceptance is a permanent record and cannot be deleted.")


class ImmutableRecordError(RuntimeError):
    pass


class TermsTextRecord(Base):
    """The exact rendered text of each version of the terms that was accepted (TERMS.md with the licensor's details
    written in), by its SHA-256, so the accepted copy can be shown, emailed and exported after the terms change."""

    __tablename__ = "terms_texts"

    text_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class TermsCopyEmail(Base, UUIDPrimaryKeyMixin):
    """The emailed copy of an accepted licence agreement (app/services/terms_copy_service.py): queued at acceptance and
    sent once the email server is set up and tested, retried with backoff. A re-send adds a row."""

    __tablename__ = "terms_copy_emails"
    __table_args__ = (Index("idx_terms_copy_email_status", "status", "next_attempt_at"),)

    acceptance_id: Mapped[str] = mapped_column(ForeignKey("terms_acceptances.id"), nullable=False, index=True)
    to_email: Mapped[str] = mapped_column(String(320), nullable=False)
    # queued (waiting for the email server or its next try), sent, or failed (gave up after MAX_ATTEMPTS).
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued", server_default="queued")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    next_attempt_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(String(500), nullable=False, default="", server_default="")
    requested_by: Mapped[str] = mapped_column(String(320), nullable=False, default="", server_default="")
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


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


class CompliancePolicy(Base):
    """Settings → Compliance (/settings/guide/compliance, migration 0104): one row, id 1.

    How long the user activity and connector API activity are kept (never under 180 days: CERT-In's directions of
    28 April 2022; the audit log itself is never deleted), the data location statement shown in About and in the
    incident report, and the contact an incident report names.
    """

    __tablename__ = "compliance_policy"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    activity_retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=365, server_default=text("365"))
    connector_retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=180, server_default=text("180"))
    data_location: Mapped[str] = mapped_column(String(200), nullable=False, default="", server_default="")
    incident_contact: Mapped[str] = mapped_column(String(320), nullable=False, default="", server_default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class ComplianceAttestation(Base, UUIDPrimaryKeyMixin):
    """What a tenant's owner or admin recorded about one requirement of a framework pack (Settings → Compliance,
    app/services/compliance_packs, migration 0105): ``in_place`` (the organisation's own process or control exists;
    ``note`` and ``reference`` say where its evidence is) or ``not_applicable`` (out of scope, with the reason). It
    stands until ``expires_at`` (a year by default), when it must be reviewed. Every change is in the audit log; the
    row holds the latest only.
    """

    __tablename__ = "compliance_attestations"
    __table_args__ = (Index("uq_compliance_attestation", "tenant_id", "pack_id", "requirement_id", unique=True),)

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    pack_id: Mapped[str] = mapped_column(String(64), nullable=False)
    requirement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    note: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    reference: Mapped[str] = mapped_column(String(500), nullable=False, default="", server_default="")
    attested_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    attested_by_email: Mapped[str] = mapped_column(String(320), nullable=False, default="", server_default="")
    attested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class SignInPolicy(Base):
    """The sign-in rules an administrator sets for the whole installation (Settings → Sign-in): one row, id 1.

    CxMissionZero keeps them in iam.json (policy.passwordReset, policy.twoStepRequired, policy.twoStepResetFor,
    policy.sso). Hawk's identity provider itself (issuer, client id and secret) stays in its OIDC_* configuration;
    who may sign in through it is kept here (/settings/guide/people-and-access).
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
    # The password rule (app/services/password_policy.py, migration 0104): shortest length, how many kinds of character
    # (0 = any; 3 = three of lower case, upper case, digits, symbols), how many earlier passwords may not come back
    # (0 = only the current one), and how many days a password lasts before it must be changed (0 = no limit).
    password_min_length: Mapped[int] = mapped_column(Integer, nullable=False, default=12, server_default=text("12"))
    password_classes: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    password_history: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    password_max_age_days: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default=text("0"))
    # Minutes without activity before a sign-in ends; None: SESSION_IDLE_MINUTES.
    session_idle_minutes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # The notice shown on the sign-in page before anyone signs in (authorised use only, monitoring); "" for none.
    banner_text: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
