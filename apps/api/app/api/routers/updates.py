"""Settings → Updates (owners and admins): the routes under /updates and /integrity (/api/… from the browser).
Ported from CxMissionZero's src/routes/updates.js (/api/system/update…, /api/integrity, /api/system/report), with the
route names of FTR Command Center's Updates page (server/updates.js: /api/updates, /api/integrity).

What the page shows (the running version, the published ones, the updater, auto-update, software integrity), Check for
updates, Update now / Roll back to this (the updater does it: app/services/updates/), auto-update's settings, Restart
Hawk AI, the troubleshooting report, and Check now for software integrity. Everything is audited as "Updates & system".
"""

from __future__ import annotations

import datetime as dt
import os
import platform
import shutil
import time
from typing import Any

from fastapi import APIRouter, Body, Depends
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from app.core.installation import require_installation_admin
from app.core.rbac import holds, require_permission
from app.core.tenant import TenantContext, require_tenant
from app.services.integrity.service import IntegrityService, audit_system
from app.services.updates.registry import UpdateError
from app.services.updates.service import UpdateService, oneline
from app.version import APP_VERSION

router = APIRouter(tags=["updates"])
admin_only = require_permission("system.update")
#: Writes change the whole server: only its administrators (app/core/installation.py).
installation_admin = require_installation_admin("system.update")
STARTED = time.time()

#: Injected by tests; otherwise made for each request (they read their state from files).
_factory: dict[str, Any] = {}


def updates_service() -> UpdateService:
    return _factory["updates"]() if "updates" in _factory else UpdateService()


def integrity_service() -> IntegrityService:
    return _factory["integrity"]() if "integrity" in _factory else IntegrityService()


def _by(ctx: TenantContext) -> str:
    return ctx.user.email if ctx.user else "an administrator"


def _error(error: UpdateError) -> JSONResponse:
    return JSONResponse(status_code=error.status, content={"error": str(error), "detail": str(error)})


def _integrity_view(service: IntegrityService) -> dict[str, Any]:
    return {**(service.last or {"state": "checking", "summary": "The first check runs a few seconds after start."}), "repository": service.repository}


def _view(updates: UpdateService) -> dict[str, Any]:
    return {**updates.status(), "integrity": _integrity_view(updates.integrity)}


@router.get("/updates")
def updates_status(ctx: TenantContext = Depends(admin_only)):
    del ctx
    return JSONResponse(_view(updates_service()), headers={"Cache-Control": "no-store"})


@router.post("/updates/check")
async def updates_check(ctx: TenantContext = Depends(installation_admin)):
    del ctx
    updates = updates_service()
    await run_in_threadpool(updates.check)
    return _view(updates)


@router.post("/updates/install")
async def updates_install(body: dict[str, Any] = Body(default_factory=dict), ctx: TenantContext = Depends(installation_admin)):
    """Update now, or Roll back to this: one version for every image, checked, then installed by the updater."""

    ref = str(body.get("version") or body.get("ref") or "").strip()
    if not ref:
        return JSONResponse(status_code=400, content={"error": "Choose a version.", "detail": "Choose a version."})
    updates = updates_service()
    by = _by(ctx)
    try:
        result = await run_in_threadpool(updates.install, ref, by=by)
    except UpdateError as error:
        updates.record(outcome="failure", reason=oneline(f"Update to {ref} refused: {error}"), by=by, details={"tag": ref})
        return _error(error)
    return JSONResponse(status_code=202, content={**_view(updates), "requested": result["requested"], "to": result["version"]})


@router.put("/updates/settings")
def updates_settings(body: dict[str, Any] = Body(default_factory=dict), ctx: TenantContext = Depends(installation_admin)):
    """Auto-update on or off, its hour (0 to 23, or any time) and the channel it follows; saved as they change."""

    updates = updates_service()
    patch: dict[str, Any] = {}
    if "auto" in body:
        patch["auto"] = body.get("auto") is True
    if "windowHour" in body:
        hour = body.get("windowHour")
        if hour in (None, ""):
            patch["windowHour"] = None
        else:
            try:
                value = int(hour)
            except (TypeError, ValueError):
                value = -1
            if not (0 <= value <= 23) or isinstance(hour, bool) or (isinstance(hour, float) and not hour.is_integer()):
                return JSONResponse(status_code=400, content={"error": "The hour is 0 to 23, or any time.", "detail": "The hour is 0 to 23, or any time."})
            patch["windowHour"] = value
    if "channel" in body:
        if body.get("channel") not in ("latest", "stable"):
            return JSONResponse(status_code=400, content={"error": "The channel is latest or stable.", "detail": "The channel is latest or stable."})
        patch["channel"] = body["channel"]
    settings = updates.save_settings(patch)
    hour = settings["windowHour"]
    updates.record(
        outcome="changed",
        reason=f"Auto-update {'on' if settings['auto'] else 'off'}{'' if hour is None else f', at {hour:02d}:00'}, following {settings['channel']}.",
        by=_by(ctx),
        details={k: settings[k] for k in ("auto", "windowHour", "channel")},
    )
    return _view(updates)


@router.post("/updates/restart")
def updates_restart(ctx: TenantContext = Depends(installation_admin)):
    updates = updates_service()
    try:
        return updates.restart(by=_by(ctx))
    except UpdateError as error:
        return _error(error)


@router.get("/updates/report")
def updates_report(ctx: TenantContext = Depends(admin_only)):
    """Everything worth knowing when something is wrong, without secrets: for the admin, or to send to whoever helps."""

    updates = updates_service()
    status = updates.status()
    disk = None
    try:
        usage = shutil.disk_usage(updates.data_dir)
        disk = {"freeMB": round(usage.free / 1048576), "totalMB": round(usage.total / 1048576)}
    except OSError:
        pass
    https = None
    try:
        from app.services import https_runtime

        manager = https_runtime.manager()
        https = {"mode": manager.mode, "selfSigned": manager.self_signed}
    except Exception:  # noqa: BLE001 - only what the report shows
        pass
    last_backup = None
    try:
        from app.services import backup_service

        last = backup_service.last_backup() or {}
        last_backup = {k: last.get(k) for k in ("at", "ok", "name", "trigger", "error") if k in last}
    except Exception:  # noqa: BLE001
        pass
    integrity = updates.integrity.last or {}
    report = {
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "version": APP_VERSION,
        "packageVersion": status["running"]["version"],
        "image": status["image"],
        "updater": {k: (status["updater"].get(k)) for k in ("connected", "manages", "heartbeat", "status", "busy")},
        "events": status["events"],
        "failed": status["failed"],
        "settings": {k: status["settings"][k] for k in ("auto", "windowHour", "channel", "lastAutoAt", "lastAutoResult")},
        "lastCheck": {k: (status["lastCheck"] or {}).get(k) for k in ("at", "error", "warning")},
        "integrity": {k: integrity.get(k) for k in ("at", "state", "summary", "digest", "version", "commit")},
        "python": platform.python_version(),
        "platform": f"{platform.system().lower()}/{platform.machine()}",
        "uptimeSeconds": round(time.time() - STARTED),
        "disk": disk,
        "https": https,
        "lastBackup": last_backup,
        "timeZone": status["serverTime"]["zone"],
        "offline": status["offline"],
        "hostname": os.environ.get("HAWK_HOST") or "",
    }
    audit_system("updates.report", "Troubleshooting report downloaded.", actor=_by(ctx), actor_user_id=ctx.user.id if ctx.user else None)
    name = f"hawk-ai-report-{report['generatedAt'][:10]}.json"
    return JSONResponse(report, headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})


@router.get("/integrity")
def integrity_status(ctx: TenantContext = Depends(admin_only)):
    del ctx
    return JSONResponse(_integrity_view(integrity_service()), headers={"Cache-Control": "no-store"})


@router.post("/integrity/check")
async def integrity_check(ctx: TenantContext = Depends(installation_admin)):
    service = integrity_service()
    last = service.last
    recent = False
    if last:
        try:
            at = dt.datetime.fromisoformat(str(last.get("at")).replace("Z", "+00:00"))
            recent = (dt.datetime.now(dt.timezone.utc) - at).total_seconds() < 60
        except ValueError:
            recent = False
    result = last if recent and last else await run_in_threadpool(service.check, reason=f"asked by {_by(ctx)}")
    return {**result, "repository": service.repository}


@router.get("/integrity/notice")
def integrity_notice(ctx: TenantContext = Depends(require_tenant)):
    """Owners and admins see an alert while the state is Files changed or Not signed by the release workflow."""

    if not holds(ctx, "system.update"):
        return {"notice": None}
    try:
        return {"notice": integrity_service().notice()}
    except Exception:  # noqa: BLE001 - a notice is never in the way of a page
        return {"notice": None}
