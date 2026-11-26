"""The licence agreement and terms of use (TERMS.md), first ported from CxMissionZero's src/terms.js.

TERMS.md is a template: the licensor's name, address and notice email, the governing law, the disputes forum and
the fixed liability cap come from one place, the LICENSOR_LEGAL_NAME, LICENSOR_ADDRESS, LICENSOR_NOTICE_EMAIL,
GOVERNING_LAW, DISPUTE_FORUM and LIABILITY_CAP_NO_FEES settings (deploy/.env), with the defaults in TERMS_DEFAULTS.
What is shown, accepted, hashed (SHA-256) and emailed is the rendered text, so a new version of TERMS.md or a
change to one of those settings is asked for again.

Who accepts what:

- Every owner or admin accepts the whole agreement for the organisation, giving the company's name, their own full
  name and email, and confirming they are authorised to accept on the company's behalf (scope ``organisation``). The
  first such acceptance opens Hawk AI; each other administrator accepts the same way at their own next sign-in.
- Everyone else accepts the terms of use for users (Schedule 2 of the agreement), once an administrator has accepted
  the agreement for the organisation (scope ``user``).
- ACCEPT_TERMS=<email>: the person deploying accepts for the organisation and everyone using this installation (for
  automated setups), recorded with that name.

Each acceptance is a permanent row in terms_acceptances (never changed or deleted), with the exact text in
terms_texts, an entry in the audit log, and, for the agreement, an emailed copy (app/services/terms_copy_service.py).

Until the organisation has accepted, the console and the API are closed (app/core/access_gate.py) and background
tasks do not run (app/jobs/licence_task.py). Health, the licence and first-run setup stay open.
"""

from __future__ import annotations

import hashlib
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.access import TermsAcceptance, TermsTextRecord
from app.db.models.user import User, UserTenantRole


#: TERMS.md: the repository root in a checkout, /workspace in the API image (infra/Dockerfile.api).
TERMS_FILE = Path(__file__).resolve().parents[4] / "TERMS.md"

#: First, in green, wherever the terms appear: what Hawk AI talks to, and nothing else (CxMissionZero's
#: ON_PREMISE_NOTICE, adapted).
ON_PREMISE_NOTICE = (
    "Runs on your own servers and sends your data to no one: it connects only to the services you connect it to "
    "(your AI providers, identity provider, code hosts and the other integrations an administrator sets up). "
    "No telemetry, no analytics, nothing calls home, and you can monitor its traffic to check."
)

#: What the {{NAME}} placeholders in TERMS.md read when their setting is empty. Kept in this one place.
TERMS_DEFAULTS: dict[str, str] = {
    "LICENSOR_LEGAL_NAME": "the licensor named in your order or activation code",
    "LICENSOR_ADDRESS": "as stated in your order or activation code",
    "LICENSOR_NOTICE_EMAIL": "the notice email address stated in your order or activation code",
    "GOVERNING_LAW": "the federal laws of the United Arab Emirates as applied in the Emirate of Dubai",
    "DISPUTE_FORUM": (
        "arbitration administered by the Dubai International Arbitration Centre (DIAC) under the DIAC Arbitration "
        "Rules in force when the request for arbitration is filed, which are incorporated by reference into this "
        "clause; the tribunal shall consist of one (1) arbitrator; the seat, or legal place, of arbitration shall be "
        "Dubai, United Arab Emirates (onshore Dubai, and not the Dubai International Financial Centre); and the "
        "language of the arbitration shall be English"
    ),
    "LIABILITY_CAP_NO_FEES": "five hundred UAE dirhams (AED 500)",
}

_PLACEHOLDER = re.compile(r"\{\{([A-Z_]+)\}\}")
_EMAIL = re.compile(r"^(?=.{3,254}$)[^\s@<>\"]+@[^\s@<>\"]+\.[^\s@<>\"]+$")
#: Roles that may accept the terms for the organisation: CxMissionZero's Admin is a tenant's owner or admin here.
ORGANISATION_ROLES = frozenset({"owner", "admin"})
#: The heading of the part of the agreement every user accepts (Schedule 2).
USER_TERMS_HEADING = "## Schedule 2"


def clean_name(value: Any, limit: int = 120) -> str:
    """A name typed on the terms page: one line, at most ``limit`` characters."""

    text = re.sub(r"[\u0000-\u001f\u007f]", " ", str(value or ""))
    return re.sub(r"\s+", " ", text).strip()[:limit]


def clean_email(value: Any) -> str:
    email = clean_name(value, 254).lower()
    return email if _EMAIL.match(email) else ""


def _setting(name: str) -> str:
    """One setting as written into the terms: one line, no placeholder braces, no trailing full stop."""

    raw = clean_name(getattr(settings, name.lower(), "") or "", 800).replace("{{", "").replace("}}", "")
    raw = raw.rstrip(" .")
    return raw or TERMS_DEFAULTS[name]


def values() -> dict[str, str]:
    """The licensor's details and forum, as written into the terms (settings, else TERMS_DEFAULTS)."""

    return {name: _setting(name) for name in TERMS_DEFAULTS}


def render(template: str, given: dict[str, str] | None = None) -> str:
    given = given if given is not None else values()
    return _PLACEHOLDER.sub(lambda m: given.get(m.group(1), m.group(0)), template)


class TermsText:
    """One rendered text of the terms: its version (the "Version x.y" line) and SHA-256."""

    def __init__(self, text: str) -> None:
        self.text = text
        match = re.search(r"^Version ([\w.]+)", text, re.MULTILINE)
        self.version = match.group(1) if match else "1"
        self.hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

    @property
    def short_hash(self) -> str:
        return self.hash[:16]


@lru_cache(maxsize=1)
def _template() -> str:
    return TERMS_FILE.read_text(encoding="utf-8")


@lru_cache(maxsize=8)
def _rendered(template: str, items: tuple[tuple[str, str], ...]) -> TermsText:
    return TermsText(render(template, dict(items)))


def current() -> TermsText:
    return _rendered(_template(), tuple(sorted(values().items())))


def user_terms(text: str) -> str:
    """The terms of use for users (Schedule 2), as non-administrators are shown them."""

    start = text.find(f"\n{USER_TERMS_HEADING}")
    if start < 0:
        return text
    rest = text[start + 1 :]
    end = rest.find("\n## ", 3)
    return (rest if end < 0 else rest[:end]).strip() + "\n"


def remember_text(db: Session, terms: TermsText) -> None:
    """Keep the exact text accepted (once per hash), so the accepted copy outlives a later version."""

    if db.get(TermsTextRecord, terms.hash) is None:
        db.add(TermsTextRecord(text_hash=terms.hash, version=terms.version, text=terms.text))
        db.flush()


def accepted_text(db: Session, acceptance: TermsAcceptance) -> str | None:
    """The exact text this acceptance was for (None if not kept: accepted before 0103_terms_acceptance)."""

    row = db.get(TermsTextRecord, acceptance.text_hash)
    if row is not None:
        return row.text
    terms = current()
    return terms.text if terms.hash == acceptance.text_hash else None


#: Once the organisation has accepted a text, it stays accepted for that text (no query per background task).
_organisation_accepted_hash: str | None = None


def organisation(db: Session) -> TermsAcceptance | None:
    """The organisation's latest acceptance of the current terms, or None."""

    return db.scalar(
        select(TermsAcceptance)
        .where(TermsAcceptance.scope == "organisation", TermsAcceptance.text_hash == current().hash)
        .order_by(TermsAcceptance.accepted_at.desc())
        .limit(1)
    )


def organisation_accepted(db: Session | None = None) -> bool:
    """Whether the organisation accepted the current terms (for background tasks: opens its own session if needed)."""

    global _organisation_accepted_hash
    terms_hash = current().hash
    if _organisation_accepted_hash == terms_hash:
        return True
    if db is None:
        from app.db.session import SessionLocal

        with SessionLocal() as own:
            accepted = organisation(own) is not None
    else:
        accepted = organisation(db) is not None
    if accepted:
        _organisation_accepted_hash = terms_hash
    return accepted


def user_acceptance(db: Session, user_id: str) -> TermsAcceptance | None:
    """This person's own acceptance of the current terms (the agreement or the terms of use), or None."""

    return db.scalar(
        select(TermsAcceptance)
        .where(TermsAcceptance.user_id == user_id, TermsAcceptance.text_hash == current().hash)
        .order_by(TermsAcceptance.accepted_at.desc())
        .limit(1)
    )


def may_accept_for_organisation(db: Session, user: User) -> bool:
    return (
        db.scalar(
            select(UserTenantRole.id)
            .where(UserTenantRole.user_id == user.id, UserTenantRole.role.in_(ORGANISATION_ROLES))
            .limit(1)
        )
        is not None
    )


def accepted_by(db: Session, user: User, org: TermsAcceptance | None = None) -> bool:
    """Whether this person accepted what they must for the current terms: the agreement itself for an owner or admin,
    the terms of use for anyone else (or the deployer accepted for everyone with ACCEPT_TERMS)."""

    org = org if org is not None else organisation(db)
    if org is None:
        return False
    if org.everyone:
        return True
    mine = user_acceptance(db, user.id)
    if mine is None:
        return False
    if may_accept_for_organisation(db, user):
        return mine.scope == "organisation"
    return True


def gate_open_for(db: Session, user: User) -> bool:
    """Whether this person may use Hawk AI now: the organisation and they have accepted the current terms."""

    return accepted_by(db, user)


def organisation_name(db: Session) -> str:
    """The organisation's name, as the owner or admin who accepted the terms gave it (kept when the terms change)."""

    name = db.scalar(
        select(TermsAcceptance.organisation_name)
        .where(TermsAcceptance.organisation_name.is_not(None), TermsAcceptance.organisation_name != "")
        .order_by(TermsAcceptance.accepted_at.desc())
        .limit(1)
    )
    # ORGANISATION_NAME: the organisation's name (else the owner or admin gives it when accepting the terms).
    return name or clean_name(os.environ.get("ORGANISATION_NAME"))


def accept_for_organisation(
    db: Session,
    *,
    by: str,
    ip: str = "",
    via: str = "page",
    everyone: bool = False,
    name: str = "",
    user_id: str | None = None,
    full_name: str = "",
    tenant_id: str | None = None,
    user_agent: str = "",
    authorised: bool = False,
) -> TermsAcceptance:
    """The whole agreement, accepted for the organisation; its copy is queued to be emailed to ``by``."""

    from app.services import terms_copy_service

    terms = current()
    remember_text(db, terms)
    row = TermsAcceptance(
        scope="organisation",
        user_id=user_id,
        email=by,
        version=terms.version,
        text_hash=terms.hash,
        ip=ip[:64],
        via=via,
        everyone=everyone,
        organisation_name=clean_name(name) or None,
        full_name=clean_name(full_name, 200),
        tenant_id=tenant_id,
        user_agent=clean_name(user_agent, 512),
        authorised=authorised,
    )
    db.add(row)
    db.flush()
    if clean_email(by):
        terms_copy_service.queue(db, row, requested_by=by)
    return row


def accept_for_user(
    db: Session,
    *,
    user_id: str,
    email: str,
    ip: str = "",
    full_name: str = "",
    tenant_id: str | None = None,
    user_agent: str = "",
) -> TermsAcceptance:
    terms = current()
    remember_text(db, terms)
    row = TermsAcceptance(
        scope="user",
        user_id=user_id,
        email=email,
        version=terms.version,
        text_hash=terms.hash,
        ip=ip[:64],
        via="page",
        everyone=False,
        full_name=clean_name(full_name, 200),
        tenant_id=tenant_id,
        user_agent=clean_name(user_agent, 512),
    )
    db.add(row)
    db.flush()
    return row


def accept_from_environment(db: Session, value: str | None) -> bool:
    """ACCEPT_TERMS=<email>: accepted for the organisation and everyone, by that person. True when newly recorded."""

    email = str(value or "").strip()
    if not email:
        return False
    if not _EMAIL.match(email):
        raise ValueError(
            "ACCEPT_TERMS must be the email address of the person accepting the licence agreement (TERMS.md) for the organisation."
        )
    org = organisation(db)
    if org is not None and org.everyone and org.email == email:
        return False
    accept_for_organisation(
        db,
        by=email,
        via="ACCEPT_TERMS",
        everyone=True,
        name=clean_name(os.environ.get("ORGANISATION_NAME")),
        authorised=True,
    )
    return True


def acceptance_view(acceptance: TermsAcceptance) -> dict[str, Any]:
    """One acceptance record, as the API, the auditor's export and the emailed copy show it."""

    return {
        "id": acceptance.id,
        "scope": acceptance.scope,
        "version": acceptance.version,
        "hash": acceptance.text_hash,
        "companyName": acceptance.organisation_name or "",
        "fullName": acceptance.full_name or "",
        "email": acceptance.email,
        "userId": acceptance.user_id,
        "tenantId": acceptance.tenant_id,
        "authorised": bool(acceptance.authorised),
        "everyone": bool(acceptance.everyone),
        "via": acceptance.via,
        "ip": acceptance.ip,
        "userAgent": acceptance.user_agent or "",
        "acceptedAt": acceptance.accepted_at.isoformat() if acceptance.accepted_at else None,
    }


def describe(db: Session, user: User) -> dict[str, Any]:
    """Where this person stands, for /auth/me (CxMissionZero's describeMe().terms)."""

    org = organisation(db)
    admin = may_accept_for_organisation(db, user)
    return {
        "version": current().version,
        "organisationAccepted": org is not None,
        "accepted": org is not None and accepted_by(db, user, org),
        "canAcceptForOrganisation": admin,
        # What this person accepts: the whole agreement (an owner or admin) or the terms of use for users.
        "scope": "organisation" if admin else "user",
    }
