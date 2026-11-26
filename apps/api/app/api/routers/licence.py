"""The product licence and the activation codes (app/services/activation_service.py, /settings/guide/licence).

Ported from CxMissionZero's src/routes/licence.js.

- /licence: whether Hawk AI works, and a product code entered on the deactivation page. Open to everyone (the
  licence gate lets these two through), so refused codes are limited.
- /activation: Settings → Activation codes, for a tenant's owners and admins.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from fastapi import APIRouter, Body, Depends, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services import activation_service, refusal_audit
from app.services.activation_service import ISSUER_KEYS, parse_ms
from app.services.audit_service import write_audit_log


router = APIRouter(tags=["licence"])
logger = logging.getLogger(__name__)

#: A code is a few hundred characters: anything longer is cut, as in CxMissionZero.
MAX_CODE_LENGTH = 4000
#: Tries a minute from one address on the open route.
TRIES_PER_MINUTE = 10
TOO_MANY_TRIES = "Too many tries. Wait a minute, then enter the code again."


def _code_from(body: dict[str, Any] | None) -> str:
    value = (body or {}).get("code")
    return ("" if value is None else str(value)).strip()[:MAX_CODE_LENGTH]


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


class _Tries:
    """A few tries a minute from one address: a code cannot be guessed, but there is no reason to let anyone try."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_ip: dict[str, list[float]] = {}

    def allow(self, ip: str, now: float) -> bool:
        with self._lock:
            recent = [t for t in self._by_ip.get(ip, []) if now - t < 60_000]
            if len(recent) >= TRIES_PER_MINUTE:
                return False
            self._by_ip[ip] = [*recent, now]
            if len(self._by_ip) > 1000:
                self._by_ip.clear()
            return True

    def clear(self) -> None:
        with self._lock:
            self._by_ip.clear()


licence_tries = _Tries()
#: The shared limit of app/services/refusal_audit.py (10 a minute per address, 40 in all).
licence_refusals = refusal_audit.lister("licence")


def _activation_details(result: dict[str, Any]) -> dict[str, Any]:
    details = {
        "id": result["id"],
        "org": result["org"],
        "scope": result["scope"],
        "action": result.get("action") or "activate",
        "expires": result["expires"],
    }
    if result["scope"] == "tenants":
        details["maxTenants"] = result["maxTenants"]
        details["maxUsers"] = result.get("maxUsers")
    return details


def _audit(
    db: Session,
    *,
    outcome: str,
    reason: str,
    actor: str,
    action: str,
    tenant_id: str | None = None,
    actor_user_id: str | None = None,
    result: dict[str, Any] | None = None,
) -> None:
    payload: dict[str, Any] = {"outcome": outcome, "reason": reason, "actor_id": actor}
    if result is not None and result.get("id"):
        payload["activation"] = _activation_details(result)
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human" if actor_user_id else "system",
        action=action,
        resource_type="activation_code",
        resource_id=str((result or {}).get("id") or "-")[:128],
        payload=payload,
    )


# ---- The product licence: whether Hawk AI works, and a product code entered on the deactivation page ----------
# Open to anyone who reaches the server: only a code the maintainer signed can do anything here.


@router.get("/licence")
def licence(response: Response, db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    product = activation_service.load_store(db).product()
    db.commit()
    return {"active": product["active"], "until": product["until"], "message": product["message"]}


@router.post("/licence/activate")
def licence_activate(request: Request, body: dict[str, Any] | None = Body(default=None), db: Session = Depends(get_db)):
    ip = _client_ip(request)
    now = activation_service.now_ms()
    if not licence_tries.allow(ip, now):
        logger.warning("Product activation code refused: too many tries from this address", extra={"client_ip": ip, "reason_code": "rate_limited"})
        return JSONResponse(status_code=429, content={"error": TOO_MANY_TRIES}, headers={"Cache-Control": "no-store"})
    result = activation_service.check_code(_code_from(body))
    store = activation_service.load_store(db, for_update=True)
    by = f"deactivation page ({ip})"
    # In date by the licence's own clock too (never earlier than the latest time it has seen).
    passed = bool(result["valid"]) and (parse_ms(result["expires"]) or 0) <= store.now()
    # Open to everyone: only a code that runs longer than the one in force, and was not issued before it, is taken.
    stale = store.refusal(result, must_extend=True) if result["valid"] and result["scope"] == "product" and not passed else ""
    if not result["valid"] or result["scope"] != "product" or passed or stale:
        if not result["valid"]:
            reason = result.get("reason") or "This activation code is not valid."
        elif result["scope"] != "product":
            reason = "This is not a Hawk AI activation code."
        elif passed:
            reason = f"This activation code ended on {result['expires'][:10]}."
        else:
            reason = stale
        listed, left_out = licence_refusals.listed(f"address {ip}", now)
        if left_out:
            _audit(
                db,
                outcome="refused",
                reason=f"{left_out} more refused product activation codes in the minute before were not listed one by one (too many at once).",
                actor="Hawk AI server",
                action="licence.activation_code.refused_unlisted",
            )
        if listed:
            _audit(db, outcome="refused", reason=f"Product activation code refused: {reason}", actor=by, action="licence.activation_code.refused")
        db.commit()
        return JSONResponse(status_code=400, content={"error": reason}, headers={"Cache-Control": "no-store"})
    store.record(result, by)
    _audit(
        db,
        outcome="changed",
        reason=f"Product activation code applied: Hawk AI works until {result['expires'][:10]} ({result['org']}).",
        actor=by,
        action="licence.activation_code.applied",
        result=result,
    )
    product = store.product()
    db.commit()
    return {"active": product["active"], "until": product["until"]}


# ---- Activation codes (Settings → Activation codes): what the maintainer has unlocked ---------------------------


def _activation_view(store: activation_service.ActivationStore) -> dict[str, Any]:
    return {
        # Only owners and admins reach this page, and they may change it.
        "canManage": True,
        "keyConfigured": len(ISSUER_KEYS) > 0,
        "tenants": store.tenants(),
        "product": store.product(),
        "history": store.history()[:10],
    }


def _applied(result: dict[str, Any]) -> str:
    until = result["expires"][:10]
    if result["scope"] == "product":
        return f"Hawk AI activated for {result['org']} until {until}"
    users = f", with up to {result['maxUsers']} active users in each" if result.get("maxUsers") else ""
    return f"several tenants unlocked for {result['org']}: up to {result['maxTenants']}{users}, until {until}"


@router.get("/activation")
def activation(response: Response, db: Session = Depends(get_db), ctx: TenantContext = Depends(require_permission("activation.manage"))):
    del ctx
    response.headers["Cache-Control"] = "no-store"
    view = _activation_view(activation_service.load_store(db))
    db.commit()
    return view


@router.post("/activation")
def apply_activation(
    body: dict[str, Any] | None = Body(default=None),
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_permission("activation.manage")),
):
    result = activation_service.check_code(_code_from(body))
    actor = ctx.user.email if ctx.user else ""
    audit = {"actor": actor, "tenant_id": ctx.tenant.id, "actor_user_id": ctx.user.id if ctx.user else None}
    # A deactivation code (a feature scope) is honoured even when it is itself past its date.
    usable = result["valid"] or (result.get("expired") and result.get("action") == "deactivate")
    if not usable:
        _audit(db, outcome="refused", reason=f"Activation code refused: {result.get('reason')}", action="activation.code.refused", **audit)
        db.commit()
        return JSONResponse(status_code=400, content={"error": result.get("reason") or "This activation code is not valid."})
    store = activation_service.load_store(db, for_update=True)
    # An older code entered again would undo the one in force (a shorter date, fewer tenants).
    stale = store.refusal(result)
    if stale:
        _audit(db, outcome="refused", reason=f"Activation code refused: {stale}", action="activation.code.refused", **audit)
        db.commit()
        return JSONResponse(status_code=400, content={"error": stale})
    what = _applied(result)
    store.record(result, actor)
    _audit(db, outcome="changed", reason=f"Activation code applied: {what}.", action="activation.code.applied", result=result, **audit)
    view = _activation_view(store)
    db.commit()
    return {"applied": what, **view}
