"""Settings → Hands-off (owners and admins) and the "Yes, do it" page of Hawk AI's emailed links: the routes under
/hands-off (/api/hands-off from the browser). Ported from CxMissionZero's src/routes/hands-off.js
(registerHandsOffPageRoutes, and /a/:token).

- GET /hands-off: the settings, whether email and the server address are ready, and the self-check.
- PUT /hands-off: the answers, saved in one go (turn on, change, or turn off with ``handsOff.on: false``).
- POST /hands-off/status: send the weekly status now. POST /hands-off/check: a self-check now.
- GET /hands-off/health: the self-check alone (Settings → Backups & health shows it).
- POST /hands-off/link and /hands-off/link/confirm: open to anyone with a link (the token is signed and expires after
  30 days). The first only says what the link would do; only the second, the "Yes, do it" button, does it, so a mail
  scanner that opens every link never acts.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services import hands_off
from app.services.self_check import SelfCheck

router = APIRouter(tags=["hands-off"])
admin_only = require_permission("settings.manage")
NO_STORE = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}

#: Injected by tests; otherwise made for each request (its state is in files and the database).
_factory: dict[str, Any] = {}


def checker() -> SelfCheck:
    return _factory["self_check"]() if "self_check" in _factory else SelfCheck()


def _by(ctx: TenantContext) -> str:
    return ctx.user.email if ctx.user else "an administrator"


def _refused(message: str, status: int) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message, "detail": message})


def _view(db: Session, check: SelfCheck) -> dict[str, Any]:
    from app.services.password_reset_service import link_base

    current = hands_off.load(check.data_dir)
    return {
        "handsOff": current,
        "canSave": True,
        "ready": {"smtp": check.mail_ready(db), "serverUrl": bool(link_base())},
        "paused": hands_off.is_paused(current, check.now()),
        "commands": hands_off.COMMANDS,
        "health": check.health_view(),
    }


@router.get("/hands-off")
def hands_off_status(ctx: TenantContext = Depends(admin_only), db: Session = Depends(get_db)):
    del ctx
    return JSONResponse(_view(db, checker()), headers=NO_STORE)


@router.put("/hands-off")
def hands_off_save(body: Annotated[dict[str, Any] | None, Body()] = None, ctx: TenantContext = Depends(admin_only), db: Session = Depends(get_db)):
    """The answers, saved in one go: what to do, who, when, and replies."""

    body = body or {}
    incoming = body.get("handsOff") if isinstance(body.get("handsOff"), dict) else {}
    check = checker()
    before = hands_off.load(check.data_dir)
    try:
        after = hands_off.save({**incoming, "on": incoming.get("on") is not False}, check.data_dir)
    except hands_off.HandsOffError as error:
        return _refused(error.message, error.status_code)
    state = ("changed" if before["on"] else "turned on") if after["on"] else "turned off"
    SelfCheck.audit(
        db,
        "hands_off.settings",
        f"Hands-off {state}: status to {len(after['statusTo'])} people, replies {'read' if after['replies'] else 'not read'}.",
        actor=_by(ctx),
        tenant_id=ctx.tenant.id,
    )
    db.commit()
    return JSONResponse(_view(db, check), headers=NO_STORE)


@router.post("/hands-off/status")
def hands_off_send_status(ctx: TenantContext = Depends(admin_only), db: Session = Depends(get_db)):
    del ctx
    check = checker()
    to = hands_off.load(check.data_dir)["statusTo"]
    if not to:
        return _refused("Add who gets the weekly status first.", 400)
    if not check.mail_ready(db):
        return _refused("Set up and test the email server first (Settings → Sign-in).", 409)
    return {"sent": check.send_status(db, to)}


@router.post("/hands-off/check")
async def hands_off_check(ctx: TenantContext = Depends(admin_only)):
    del ctx
    check = checker()
    await run_in_threadpool(check.run)
    return JSONResponse({"health": check.health_view()}, headers=NO_STORE)


@router.get("/hands-off/health")
def hands_off_health(ctx: TenantContext = Depends(admin_only)):
    del ctx
    return JSONResponse({"health": checker().health_view()}, headers=NO_STORE)


# ---- The emailed links: open to anyone who has one -------------------------------------------------------------------


@router.post("/hands-off/link")
def hands_off_link(body: Annotated[dict[str, Any] | None, Body()] = None):
    """What a link would do, for whom: nothing is done."""

    found = checker().describe_link(str((body or {}).get("token") or ""))
    if not found["ok"]:
        return JSONResponse({**found, "error": found["message"]}, status_code=404, headers=NO_STORE)
    return JSONResponse(found, headers=NO_STORE)


@router.post("/hands-off/link/confirm")
async def hands_off_link_confirm(body: Annotated[dict[str, Any] | None, Body()] = None):
    """"Yes, do it": what the link says, for the person it was sent to."""

    result = await run_in_threadpool(checker().follow_link, str((body or {}).get("token") or ""))
    content = {k: v for k, v in result.items() if k != "status"}
    if not result["ok"]:
        content["error"] = result["message"]
    return JSONResponse(content, status_code=result["status"], headers=NO_STORE)
