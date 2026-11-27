"""The product licence (app/services/activation_service.py, /settings/guide/licence).

- GET /licence: whether Hawk AI works, until when, and this installation's ID. Open to everyone (the licence gate
  lets it through): the deactivation page asks it before anyone signs in.
- GET /licence/status: the whole picture for a tenant's owners and admins (Settings → Licence, and the deactivation
  page once an administrator has signed in): the installation ID, the trial, the licence in force, the history.
- GET /licence/request: the ``.hawkai-request`` file an administrator sends to the owner of Hawk AI, who makes a
  licence for this installation from it. Nothing secret is in it.
- POST /licence/import: a ``.hawkai`` licence file (multipart, field ``file``), imported by an administrator of the
  installation. It works on the deactivation page too: the licence gate lets these routes and sign-in through.
"""

from __future__ import annotations

import json
import socket
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, File, Response, UploadFile
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.installation import default_tenant, is_installation_admin, require_installation_admin
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.tenant import Tenant
from app.db.session import get_db
from app.services import activation_service
from app.services.activation_service import ISSUER_KEYS
from app.services.audit_service import write_audit_log


router = APIRouter(tags=["licence"])

NO_STORE = {"Cache-Control": "no-store"}


def _licence_details(result: dict[str, Any]) -> dict[str, Any]:
    details = {key: result.get(key) for key in ("id", "org", "installationId", "scopes", "issued", "expires")}
    if "tenants" in (result.get("scopes") or []):
        details["maxTenants"] = result.get("maxTenants")
        details["maxUsers"] = result.get("maxUsers")
    return details


def _audit(db: Session, ctx: TenantContext, *, outcome: str, reason: str, action: str, result: dict[str, Any] | None = None, filename: str = "") -> None:
    payload: dict[str, Any] = {"outcome": outcome, "reason": reason, "actor_id": ctx.user.email if ctx.user else ""}
    if filename:
        payload["file"] = filename[:200]
    if result and result.get("id"):
        payload["licence"] = _licence_details(result)
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human",
        action=action,
        resource_type="licence",
        resource_id=str((result or {}).get("id") or "-")[:128],
        payload=payload,
    )


def _organisation(db: Session) -> str:
    from app.services import terms_service

    try:
        accepted = terms_service.organisation(db)
    except Exception:  # noqa: BLE001 - terms not set up: the first tenant's name
        accepted = None
    if accepted is not None and getattr(accepted, "organisation_name", ""):
        return str(accepted.organisation_name)
    tenant_id = default_tenant(db)
    tenant = db.get(Tenant, tenant_id) if tenant_id else None
    return tenant.name if tenant else ""


def _view(db: Session, store: activation_service.ActivationStore, *, can_manage: bool) -> dict[str, Any]:
    product = store.product()
    trial = store.trial()
    return {
        # Owners and admins reach this; the licence is the whole server's, so only its administrators import one
        # (app/core/installation.py).
        "canManage": can_manage,
        "keyConfigured": len(ISSUER_KEYS) > 0,
        "installationId": product["installationId"],
        "trial": {"start": trial["start"], "end": trial["end"], "active": product["trial"]},
        "licence": store.licence(),
        "tenants": store.tenants(),
        "product": product,
        "history": store.history()[:10],
        "maxFileBytes": activation_service.MAX_FILE_BYTES,
    }


@router.get("/licence")
def licence(response: Response, db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    product = activation_service.load_store(db).product()
    db.commit()
    return {
        "active": product["active"],
        "until": product["until"],
        "trial": product["trial"],
        "installationId": product["installationId"],
        "message": product["message"],
    }


@router.get("/licence/status")
def licence_status(response: Response, db: Session = Depends(get_db), ctx: TenantContext = Depends(require_permission("activation.manage"))):
    response.headers["Cache-Control"] = "no-store"
    view = _view(db, activation_service.load_store(db), can_manage=is_installation_admin(db, ctx))
    db.commit()
    return view


@router.get("/licence/request")
def licence_request(db: Session = Depends(get_db), ctx: TenantContext = Depends(require_permission("activation.manage"))):
    from app.version import APP_VERSION

    store = activation_service.load_store(db)
    product = store.product()
    public_url = str(settings.web_origin or "").strip()
    host = urlparse(public_url).hostname if public_url else ""
    request_file = {
        "format": activation_service.REQUEST_FORMAT,
        "v": 1,
        "installationId": product["installationId"],
        "organisation": _organisation(db),
        "hostname": host or socket.gethostname(),
        "publicUrl": public_url,
        "version": APP_VERSION,
        "trialEnds": product["trialEnds"],
        "requestedAt": activation_service.iso(activation_service.now_ms()),
        "requestedBy": ctx.user.email if ctx.user else "",
    }
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human",
        action="licence.request.downloaded",
        resource_type="licence",
        resource_id=product["installationId"][:128],
        payload={"outcome": "read", "reason": f"Licence request for installation {product['installationId']} downloaded."},
    )
    db.commit()
    name = f"hawk-ai-{product['installationId']}{activation_service.REQUEST_EXTENSION}"
    return Response(
        content=json.dumps(request_file, indent=2) + "\n",
        media_type="application/json",
        headers={**NO_STORE, "Content-Disposition": f'attachment; filename="{name}"'},
    )


def _imported(result: dict[str, Any]) -> str:
    what = f"Hawk AI licensed to {result['org']} until {result['expires'][:10]}"
    if "tenants" in result["scopes"]:
        users = f", with up to {result['maxUsers']} active users in each" if result.get("maxUsers") else ""
        what += f", for up to {activation_service.plural(result['maxTenants'], 'tenant')}{users}"
    return what


@router.post("/licence/import")
def licence_import(
    file: UploadFile | None = File(default=None),
    db: Session = Depends(get_db),
    ctx: TenantContext = Depends(require_installation_admin("activation.manage")),
):
    filename = (file.filename or "") if file is not None else ""
    data = file.file.read(activation_service.MAX_FILE_BYTES + 1) if file is not None else None
    by = ctx.user.email if ctx.user else ""
    store = activation_service.load_store(db, for_update=True)
    code, refused = activation_service.licence_from_file(data, filename)
    result: dict[str, Any] = {}
    if not refused:
        result = store.check(code)
        if not result["valid"]:
            refused = result.get("reason") or activation_service.NOT_VALID
    if refused:
        store.record_refusal(result, refused, by)
        _audit(db, ctx, outcome="refused", reason=f"Licence refused: {refused}", action="licence.import.refused", result=result, filename=filename)
        db.commit()
        return JSONResponse(status_code=400, content={"error": refused}, headers=NO_STORE)
    what = _imported(result)
    store.record(result, by)
    _audit(db, ctx, outcome="changed", reason=f"Licence imported: {what}.", action="licence.imported", result=result, filename=filename)
    view = _view(db, store, can_manage=True)
    db.commit()
    return JSONResponse(content={"imported": what, **view}, headers=NO_STORE)
