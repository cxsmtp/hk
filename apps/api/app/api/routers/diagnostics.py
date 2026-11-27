"""Settings → Backups & health: self-recovery and the diagnostics bundle (app/services/self_recovery.py,
app/services/diagnostics_bundle.py), under /diagnostics (/api/… from the browser).

Who sees what (roles are per tenant, app/core/permissions.py): the owners and admins of the installation's first tenant
are the installation's admins and see everything, the bundle included; the owners and admins of another tenant (who
hold system.update in it) see their own tenant's issues in full, the installation's as plain lines with a reference,
and download a bundle of their own tenant only. Everyone else: 403. Every download is in the audit log.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from app.core.log_config import mask_email
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services import diagnostics_bundle
from app.services.self_recovery import SelfRecovery

router = APIRouter(prefix="/diagnostics", tags=["diagnostics"])
admins = require_permission("system.update")

#: Injected by tests; otherwise made for each request (it reads its state from files).
_factory: dict[str, Any] = {}

INSTALLATION_ONLY = "Only the owners and admins of the installation's first tenant can do this for the whole installation."


def supervisor() -> SelfRecovery:
    return _factory["supervisor"]() if "supervisor" in _factory else SelfRecovery()


def _by(ctx: TenantContext) -> str:
    return ctx.user.email if ctx.user else "an administrator"


def _audit(db: Session, ctx: TenantContext, action: str, reason: str, details: dict[str, Any]) -> None:
    from app.services.audit_service import write_audit_log

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human",
        action=action,
        resource_type="system",
        resource_id="diagnostics",
        payload={"outcome": "info", "reason": reason, "actor_id": mask_email(_by(ctx)), "type": "Updates & system", "details": details},
    )
    db.commit()


@router.get("")
def diagnostics_status(ctx: TenantContext = Depends(admins), db: Session = Depends(get_db)):
    installation = diagnostics_bundle.is_installation_admin(db, ctx)
    view = supervisor().view(installation=installation, tenant_id=ctx.tenant.id)
    return JSONResponse({**view, "canRun": installation}, headers={"Cache-Control": "no-store"})


@router.get("/bundle")
async def diagnostics_bundle_download(ctx: TenantContext = Depends(admins), db: Session = Depends(get_db)):
    """The bundle: the installation's for its admins, the tenant's own for another tenant's admins."""

    installation = diagnostics_bundle.is_installation_admin(db, ctx)
    sup = supervisor()
    view = sup.view(installation=installation, tenant_id=ctx.tenant.id)
    reference = (view.get("needsOemReferences") or [""])[0]
    data, manifest = await run_in_threadpool(
        diagnostics_bundle.build,
        db,
        installation=installation,
        tenant_id=ctx.tenant.id,
        requested_by=_by(ctx),
        data_dir=sup.data_dir,
        updater_dir=sup.updater_dir,
        reference=reference,
    )
    now = dt.datetime.now(dt.timezone.utc)
    name = diagnostics_bundle.bundle_name(now, reference)
    digest = hashlib.sha256(data).hexdigest()
    _audit(db, ctx, "diagnostics.bundle_downloaded", f"Diagnostics bundle downloaded ({manifest['scope']}).", {"scope": manifest["scope"], "name": name, "sha256": digest, "files": len(manifest["files"]), "reference": reference})
    return Response(content=data, media_type="application/gzip", headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store", "X-Hawk-Diagnostics-Scope": manifest["scope"], "X-Hawk-Diagnostics-SHA256": digest})


@router.get("/bundle/prepared")
def diagnostics_prepared_download(ctx: TenantContext = Depends(admins), db: Session = Depends(get_db)):
    """The bundle self-recovery made when it gave up (what the logs said at that moment): the installation's admins."""

    if not diagnostics_bundle.is_installation_admin(db, ctx):
        raise HTTPException(status_code=403, detail=INSTALLATION_ONLY)
    sup = supervisor()
    prepared = sup.load().get("prepared") or {}
    path = diagnostics_bundle.prepared_file(sup.data_dir, str(prepared.get("name") or ""))
    if path is None:
        raise HTTPException(status_code=404, detail="No bundle has been prepared.")
    data = path.read_bytes()
    _audit(db, ctx, "diagnostics.bundle_downloaded", "Prepared diagnostics bundle downloaded (installation).", {"scope": "installation", "name": path.name, "sha256": hashlib.sha256(data).hexdigest(), "prepared": True, "reference": prepared.get("reference")})
    return Response(content=data, media_type="application/gzip", headers={"Content-Disposition": f'attachment; filename="{path.name}"', "Cache-Control": "no-store", "X-Hawk-Diagnostics-Scope": "installation"})


@router.post("/recovery/run")
async def diagnostics_run(ctx: TenantContext = Depends(admins), db: Session = Depends(get_db)):
    """Run self-recovery now (it runs by itself every few minutes)."""

    if not diagnostics_bundle.is_installation_admin(db, ctx):
        raise HTTPException(status_code=403, detail=INSTALLATION_ONLY)
    sup = supervisor()
    result = await run_in_threadpool(sup.run, by=f"asked by {mask_email(_by(ctx))}")
    return {**sup.view(installation=True, tenant_id=ctx.tenant.id), "canRun": True, "skipped": bool(result.get("skipped"))}


@router.post("/recovery/{reference}/retry")
def diagnostics_retry(reference: str, ctx: TenantContext = Depends(admins), db: Session = Depends(get_db)):
    """Try again: an issue that needed the OEM gets its attempts back (after the OEM's advice, say)."""

    if not diagnostics_bundle.is_installation_admin(db, ctx):
        raise HTTPException(status_code=403, detail=INSTALLATION_ONLY)
    sup = supervisor()
    if not sup.retry(reference[:20], by=mask_email(_by(ctx))):
        raise HTTPException(status_code=404, detail="No such issue.")
    return {**sup.view(installation=True, tenant_id=ctx.tenant.id), "canRun": True}
