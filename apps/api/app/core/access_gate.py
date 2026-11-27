"""The gate every signed-in route passes after the token (app/core/auth.py), ported from CxMissionZero's
requireSession (src/routes/guards.js).

- A person with a temporary password (the generated first administrator, or after reset_admin) must choose their
  own before anything else: 403 ``password_change_required``.
- Until an owner or admin has accepted the terms of use (TERMS.md) for the organisation, and then until each person
  has accepted them for themselves, Hawk AI is closed: 403 ``terms_required``.

The console turns these two answers into the change-password and terms pages. Health, the licence and first-run
setup are not signed-in routes, so they stay open.
"""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.db.models.user import User
from app.services import terms_service


#: The licence (app/api/routers/licence.py): an administrator can import one on the deactivation page before
#: choosing a new password or accepting the terms (the routes check who may themselves).
LICENCE_ROUTES = frozenset({"/licence/status", "/licence/request", "/licence/import"})
#: Routes someone who must change their password may still use.
PASSWORD_CHANGE_ROUTES = frozenset({"/auth/me", "/auth/me/password", *LICENCE_ROUTES})
#: Routes usable before the terms of use are accepted: reading and accepting them, one's own account, the licence.
TERMS_ROUTES = frozenset({"/auth/me", "/auth/me/password", "/terms", "/terms/accept", *LICENCE_ROUTES})

PASSWORD_CHANGE_REQUIRED = "password_change_required"
TERMS_REQUIRED = "terms_required"


class AccessRequired(Exception):
    """Raised from get_current_user; answered by access_required_response (registered in app/main.py)."""

    def __init__(self, content: dict) -> None:
        super().__init__(content.get("error", ""))
        self.content = content


def access_required_response(_request: Request, exc: AccessRequired) -> JSONResponse:
    return JSONResponse(status_code=403, content=exc.content, headers={"Cache-Control": "no-store"})


def enforce(request: Request | None, db: Session, user: User) -> None:
    path = request.url.path if request is not None else ""
    if user.must_change_password and path not in PASSWORD_CHANGE_ROUTES:
        raise AccessRequired(
            {"error": "Choose a new password before continuing.", "code": PASSWORD_CHANGE_REQUIRED, "mustChangePassword": True}
        )
    if path in TERMS_ROUTES or terms_service.gate_open_for(db, user):
        return
    if terms_service.organisation(db) is not None:
        message = "Accept the terms of use to continue."
    elif terms_service.may_accept_for_organisation(db, user):
        message = "Accept the terms of use for your organisation to continue."
    else:
        message = "An administrator must accept the terms of use before Hawk AI can be used."
    raise AccessRequired({"error": message, "code": TERMS_REQUIRED, "termsRequired": True})
