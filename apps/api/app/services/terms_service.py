"""The terms of use (TERMS.md), ported from CxMissionZero's src/terms.js.

Accepted by an owner or admin for the organisation before anyone can use Hawk AI, then by each person before they
first use it. Acceptance is tied to the exact text (its hash), so changed terms are asked for again. Kept in the
terms_acceptances table (CxMissionZero: DATA_DIR/terms.json); every acceptance is also in the audit log.

ACCEPT_TERMS=<email>: the person deploying accepts for the organisation and everyone using this installation (for
automated setups), recorded with that name.

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

from app.db.models.access import TermsAcceptance
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

_EMAIL = re.compile(r"^[^\s@<>\"]+@[^\s@<>\"]+\.[^\s@<>\"]+$")
#: Roles that may accept the terms for the organisation: CxMissionZero's Admin is a tenant's owner or admin here.
ORGANISATION_ROLES = frozenset({"owner", "admin"})


def clean_name(value: Any) -> str:
    """An organisation's name: one line, at most 120 characters."""

    text = re.sub(r"[\u0000-\u001f\u007f]", " ", str(value or ""))
    return re.sub(r"\s+", " ", text).strip()[:120]


class TermsText:
    def __init__(self, text: str) -> None:
        self.text = text
        match = re.search(r"^Version ([\w.]+)", text, re.MULTILINE)
        self.version = match.group(1) if match else "1"
        self.hash = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


@lru_cache(maxsize=1)
def current() -> TermsText:
    return TermsText(TERMS_FILE.read_text(encoding="utf-8"))


#: Once the organisation has accepted a text, it stays accepted for that text (no query per background task).
_organisation_accepted_hash: str | None = None


def organisation(db: Session) -> TermsAcceptance | None:
    """The organisation's acceptance of the current terms, or None."""

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
    return db.scalar(
        select(TermsAcceptance)
        .where(
            TermsAcceptance.scope == "user",
            TermsAcceptance.user_id == user_id,
            TermsAcceptance.text_hash == current().hash,
        )
        .order_by(TermsAcceptance.accepted_at.desc())
        .limit(1)
    )


def accepted_by(db: Session, user_id: str, org: TermsAcceptance | None = None) -> bool:
    """Whether this person accepted the current terms (or the deployer accepted for everyone)."""

    org = org if org is not None else organisation(db)
    if org is None:
        return False
    if org.everyone:
        return True
    return user_acceptance(db, user_id) is not None


def may_accept_for_organisation(db: Session, user: User) -> bool:
    return (
        db.scalar(
            select(UserTenantRole.id)
            .where(UserTenantRole.user_id == user.id, UserTenantRole.role.in_(ORGANISATION_ROLES))
            .limit(1)
        )
        is not None
    )


def gate_open_for(db: Session, user: User) -> bool:
    """Whether this person may use Hawk AI now: the organisation and they have accepted the current terms."""

    return accepted_by(db, user.id)


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


def accept_for_organisation(db: Session, *, by: str, ip: str = "", via: str = "page", everyone: bool = False, name: str = "", user_id: str | None = None) -> TermsAcceptance:
    terms = current()
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
    )
    db.add(row)
    db.flush()
    return row


def accept_for_user(db: Session, *, user_id: str, email: str, ip: str = "") -> TermsAcceptance:
    terms = current()
    row = TermsAcceptance(scope="user", user_id=user_id, email=email, version=terms.version, text_hash=terms.hash, ip=ip[:64], via="page", everyone=False)
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
            "ACCEPT_TERMS must be the email address of the person accepting the terms of use (TERMS.md) for the organisation."
        )
    org = organisation(db)
    if org is not None and org.everyone and org.email == email:
        return False
    accept_for_organisation(db, by=email, via="ACCEPT_TERMS", everyone=True)
    return True


def describe(db: Session, user: User) -> dict[str, Any]:
    """Where this person stands, for /auth/me (CxMissionZero's describeMe().terms)."""

    org = organisation(db)
    return {
        "version": current().version,
        "organisationAccepted": org is not None,
        "accepted": org is not None and accepted_by(db, user.id, org),
        "canAcceptForOrganisation": may_accept_for_organisation(db, user),
    }
