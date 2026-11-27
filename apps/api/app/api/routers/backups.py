"""Settings → Backups & health (owners and admins): the routes under /backups (/api/backups from the browser). Ported
from CxMissionZero's src/routes/backups.js (encryption, the backup key, the staged restore) with the routes and the
"Ready for production?" checks of FTR Command Center's page (server/routes/backups.js, server/readiness.js).

What the page shows (the backup folder, the backups, the last backup, encryption and its key), a backup now, each
backup to download, and a restore: the uploaded file is checked and staged, and applied when Hawk AI next starts,
before api, worker and beat run (app/cli/prestart.py). The scheduled backup, the copy to the backup mailbox and the
backup before a stop are in app/services/backup_service.py.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import socket
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body, Depends, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.installation import require_installation_admin
from app.core.rbac import holds, require_permission
from app.core.tenant import TenantContext, require_tenant
from app.db.models.audit import AuditLog
from app.db.models.user import User, UserTenantRole
from app.db.session import get_db
from app.services import backup_archive as archive
from app.services import backup_service, mailer
from app.services.audit_service import write_audit_log
from app.services.state_file import read_state, write_state

router = APIRouter(tags=["backups"])
admin_only = require_permission("backup.manage")
#: Writes change the whole server: only its administrators (app/core/installation.py).
installation_admin = require_installation_admin("backup.manage")

#: A backup uploaded on the page: 200 MB at most (a larger one is restored on the server, /settings/guide/install).
MAX_RESTORE_UPLOAD_BYTES = 200 * 1024 * 1024
TOO_LARGE = "That backup is too large to upload here (200 MB at most). Restore it on the server itself with python -m app.cli.restore (/settings/guide/backups)."
NO_KEY = "This server has no backup key: backup encryption has not been turned on."
READINESS_FILE = "readiness.json"


def _actor(ctx: TenantContext) -> str:
    return ctx.user.email if ctx.user else "an administrator"


def _audit(db: Session, ctx: TenantContext, *, action: str, reason: str, outcome: str = "info", details: dict[str, Any] | None = None) -> None:
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human" if ctx.user else "system",
        action=action,
        resource_type="backup",
        resource_id="backup",
        payload={"outcome": outcome, "reason": reason, "actor_id": _actor(ctx), **({"backup": details} if details else {})},
    )
    db.commit()


def _recovered(data_dir: Path) -> list[dict[str, Any]]:
    """State files that could not be read at a start and were put right from their last good copy
    (app/services/state_file.py keeps the damaged one as <file>.damaged-<id>)."""

    out = []
    if not data_dir.is_dir():
        return out
    for path in sorted(data_dir.rglob("*.damaged-*")):
        if any(part.startswith("replaced-") for part in path.relative_to(data_dir).parts):
            continue
        try:
            at = dt.datetime.fromtimestamp(path.stat().st_mtime, dt.timezone.utc).isoformat().replace("+00:00", "Z")
        except OSError:
            continue
        target = str(path.relative_to(data_dir)).split(".damaged-")[0]
        out.append({"at": at, "target": target, "action": "recover.restored", "details": {"backup": f"{target}.bak", "kept": path.name}})
    return out[-20:]


def _view(cfg: backup_service.BackupConfig) -> dict[str, Any]:
    store = backup_service.key_store(cfg)
    encryption = store.status()
    mailbox = backup_service.backup_mailbox()
    return {
        "backups": archive.list_backups(cfg.dir)[:30],
        "sealed": encryption["encrypted"],
        "sealedBy": "environment" if encryption["source"] == "passphrase" else "key" if encryption["source"] == "key" else "",
        "dir": str(cfg.dir),
        "separate": not cfg.same_disk,
        "last": backup_service.last_backup(cfg),
        "recovered": _recovered(cfg.data_dir),
        "dataDir": str(cfg.data_dir),
        "intervalHours": cfg.interval_hours,
        "keep": cfg.keep,
        "encryption": encryption,
        "pendingRestore": (cfg.data_dir / archive.PENDING_RESTORE).exists(),
        "mailbox": {"email": mailbox["email"], "mailReady": mailer.smtp_settings() is not None},
    }


@router.get("/backups")
def backups_status(ctx: TenantContext = Depends(admin_only)):
    del ctx
    return JSONResponse(_view(backup_service.config()), headers={"Cache-Control": "no-store"})


@router.get("/backups/notice")
def backups_notice(ctx: TenantContext = Depends(require_tenant)):
    """What owners and admins are told on every page until they act (the key is not saved, backups are plain)."""

    if not holds(ctx, "backup.manage"):
        return {"notice": None}
    try:
        return {"notice": backup_service.key_store().status()["notice"]}
    except Exception:  # noqa: BLE001 - a notice is never in the way of a page
        return {"notice": None}


@router.post("/backups")
async def backups_now(db: Session = Depends(get_db), ctx: TenantContext = Depends(installation_admin)):
    """Back up now (FTR's "Back up now"; CxMissionZero's "Back up to folder now")."""

    cfg = backup_service.config()
    tenant_id = ctx.tenant.id
    user_id = ctx.user.id if ctx.user else None
    result = await run_in_threadpool(backup_service.backup_to_folder, "Manual", actor=_actor(ctx), actor_user_id=user_id, tenant_id=tenant_id, cfg=cfg)
    del db
    if not result.get("ok"):
        return JSONResponse(status_code=500, content={"error": f"Backup failed: {result.get('error')}"})
    return {"name": result["name"], "backups": archive.list_backups(cfg.dir)[:30], "last": result}


@router.post("/backups/key/show")
def backup_key_show(db: Session = Depends(get_db), ctx: TenantContext = Depends(installation_admin)):
    """The server's own backup key, shown on request only; each showing is audited (never the key)."""

    store = backup_service.key_store()
    key = store.reveal()
    if not key:
        return JSONResponse(status_code=409, content={"error": NO_KEY})
    _audit(db, ctx, action="backup.key.shown", reason="Backup key shown.")
    status = store.status()
    return JSONResponse({"key": key, "createdAt": status["keyCreatedAt"], "saved": status["keySaved"], "host": socket.gethostname()}, headers={"Cache-Control": "no-store"})


@router.post("/backups/key/confirm")
def backup_key_confirm(db: Session = Depends(get_db), ctx: TenantContext = Depends(installation_admin)):
    """"I have saved it": an admin kept the backup key somewhere other than this server."""

    store = backup_service.key_store()
    if not store.confirm_saved(by=_actor(ctx)):
        return JSONResponse(status_code=409, content={"error": NO_KEY})
    _audit(db, ctx, action="backup.key.confirmed", reason="Backup key confirmed as saved somewhere other than this server.", outcome="changed")
    return {"encryption": store.status()}


@router.post("/backups/encryption")
def backup_encryption(body: dict[str, Any] | None = Body(default=None), db: Session = Depends(get_db), ctx: TenantContext = Depends(installation_admin)):
    """Turn backup encryption on, on an installation whose backups were plain: the server makes its backup key now."""

    if not isinstance(body, dict) or body.get("on") is not True:
        return JSONResponse(status_code=400, content={"error": "Backup encryption can be turned on here. To keep backups plain, set BACKUP_ENCRYPTION=off on the server."})
    store = backup_service.key_store()
    before = store.status()
    if before["source"] == "passphrase":
        return JSONResponse(status_code=409, content={"error": "Backups are already encrypted, with BACKUP_PASSPHRASE."})
    if before["optedOut"]:
        return JSONResponse(status_code=409, content={"error": "BACKUP_ENCRYPTION=off is set on the server: remove it and restart to encrypt backups."})
    if store.turn_on(by=_actor(ctx)):
        _audit(db, ctx, action="backup.encryption.on", reason="Backup encryption turned on: backups are encrypted with this server's backup key from now on.", outcome="changed")
    return {"encryption": store.status()}


@router.post("/backups/restore")
async def backup_restore(request: Request, check: str = "", db: Session = Depends(get_db), ctx: TenantContext = Depends(installation_admin)):
    """Upload a backup. ?check=1 only reads it and says what it holds. Otherwise it is staged and applied at the next
    start: a running Hawk AI would write over a database and files restored under it."""

    body = await request.body()
    if len(body) > MAX_RESTORE_UPLOAD_BYTES:
        return JSONResponse(status_code=413, content={"error": TOO_LARGE})
    given = str(request.headers.get("x-backup-passphrase") or "")
    store = backup_service.key_store()
    try:
        # What the person typed first, then what this server encrypts with: a backup of its own opens without asking.
        bundle = await run_in_threadpool(archive.read_backup, body, passphrases=[given, *store.candidates()])
    except archive.BackupError as error:
        needs_key = isinstance(error, archive.BackupKeyError)
        message = (
            "This backup is encrypted, and this server's own backup key or passphrase does not open it. Give the backup key of the server that made it (saved from its Settings → Backups & health), or the BACKUP_PASSPHRASE that server had."
            if needs_key and not given
            else str(error)
        )
        if check != "1":
            _audit(db, ctx, action="backup.restore.refused", reason=f"Restore refused: {message}", outcome="refused")
        return JSONResponse(status_code=400, content={"error": message, "needsKey": needs_key})
    info = archive.describe_backup(bundle)
    if check == "1":
        return {"backup": info}
    cfg = backup_service.config()
    await run_in_threadpool(archive.stage_restore, bundle, cfg.data_dir)
    _audit(
        db,
        ctx,
        action="backup.restore.staged",
        reason=f"Restore staged from the backup of {info['createdAt']}: applied at the next restart.",
        outcome="changed",
        details={"createdAt": info["createdAt"], "host": info["host"], "files": info["files"], "sha256": info["sha256"]},
    )
    return {"backup": info, "staged": True, "restartRequired": True}


@router.delete("/backups/restore")
def backup_restore_cancel(db: Session = Depends(get_db), ctx: TenantContext = Depends(installation_admin)):
    pending = backup_service.config().data_dir / archive.PENDING_RESTORE
    if pending.exists():
        pending.unlink(missing_ok=True)
        _audit(db, ctx, action="backup.restore.cancelled", reason="Staged restore cancelled.", outcome="changed")
    return {"pendingRestore": False}


# ---- Ready for production? (FTR's server/readiness.js, the checks Hawk AI can answer) ------------------------------

DAY = 24 * 3600


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def readiness(facts: dict[str, Any], now: float | None = None) -> dict[str, Any]:
    """What an admin would want put right before the server is opened to more people, each with where it is put right.
    It only reads. ``facts``: backups (newest first), backupSeparate, backupSealed, restores, https {mode, selfSigned},
    mailReady, disk {freeMB, totalMB}, admins, accepted (id → {detail, by, at})."""

    now = dt.datetime.now(dt.timezone.utc).timestamp() if now is None else now
    out: list[dict[str, Any]] = []

    def add(id_: str, title: str, state: str, detail: str, where: str = "") -> None:
        out.append({"id": id_, "title": title, "state": state, "detail": detail, "where": where})

    last = facts["backups"][0] if facts["backups"] else None
    age = now - dt.datetime.fromisoformat(last["at"].replace("Z", "+00:00")).timestamp() if last else float("inf")
    add("backup.recent", "A backup in the last day", "ok" if age <= 26 * 3600 else "todo", f"The newest is from {last['at'][:16].replace('T', ' ')} UTC." if last else "There is no backup yet: take one now.", "/settings/backups")
    add("backup.separate", "Backups kept away from the data", "ok" if facts["backupSeparate"] else "todo", "They go to their own place (BACKUP_DIR)." if facts["backupSeparate"] else "They are in the data volume itself: losing that disk loses both. Mount a second volume or a share and set BACKUP_DIR.", "/settings/backups")
    add("backup.sealed", "Backups sealed with a passphrase", "ok" if facts["backupSealed"] else "todo", "A backup cannot be read without its passphrase." if facts["backupSealed"] else "Anyone who gets a backup file can read it. Turn backup encryption on.", "/settings/backups")
    restores = int(facts["restores"])
    add("backup.restored", "A restore tried", "ok" if restores else "note", f"{_plural(restores, 'restore')} in the audit log." if restores else "No restore is in the audit log. Try one of your backups on a second copy of the server, so the first time is not the day it is needed.", "/settings/backups")
    https = facts.get("https") or {}
    mode = https.get("mode")
    add(
        "https.trusted",
        "A certificate browsers trust",
        "todo" if mode == "http" or https.get("selfSigned") else "ok",
        "It answers over plain http: turn HTTPS on." if mode == "http" else "It is self-signed: every browser warns, and pages are not kept between visits. Upload your own, or get one from Let’s Encrypt." if https.get("selfSigned") else "The certificate is not self-signed.",
        "/settings/https",
    )
    add("email.ready", "Email is set up", "ok" if facts["mailReady"] else "todo", "Backups can be emailed and administrators told when Hawk AI stops." if facts["mailReady"] else "Without it the backup mailbox and the email when Hawk AI stops are not sent (Settings → Email (SMTP)).", "/settings/email")
    if facts.get("disk"):
        d = facts["disk"]
        add("disk.free", "Room on the disk", "ok" if d["freeMB"] > 1024 else "todo", f"{d['freeMB']:,} MB free of {d['totalMB']:,} MB.", "/settings/backups")
    admins = int(facts["admins"])
    add("people.admins", "More than one Admin", "ok" if admins >= 2 else "todo", f"{admins} Admins." if admins >= 2 else "One Admin only: if they are away or locked out, nobody can manage the server.", "")
    for check in out:
        yes = (facts.get("accepted") or {}).get(check["id"])
        if check["state"] == "note":
            check["canAccept"] = True
            if yes and yes.get("detail") == check["detail"]:
                check.update({"state": "ok", "accepted": {"by": yes.get("by"), "at": yes.get("at")}})
    return {"checks": out, "todo": len([c for c in out if c["state"] == "todo"]), "notes": len([c for c in out if c["state"] == "note"])}


def _facts(db: Session, ctx: TenantContext, cfg: backup_service.BackupConfig) -> dict[str, Any]:
    from app.services import https_runtime

    store = backup_service.key_store(cfg)
    try:
        status = https_runtime.manager().status([])
        cert = status.get("certificate") or {}
        https = {"mode": status.get("mode"), "selfSigned": cert.get("source") == "self-signed" or cert.get("trust") == "self-signed"}
    except Exception:  # noqa: BLE001 - HTTPS not managed here (a laptop)
        https = {}
    admins = db.scalar(
        select(func.count(func.distinct(UserTenantRole.user_id)))
        .join(User, User.id == UserTenantRole.user_id)
        .where(UserTenantRole.tenant_id == ctx.tenant.id, UserTenantRole.role.in_(("owner", "admin")), User.is_active.is_(True))
    )
    restores = db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "backup.restored"))
    try:
        accepted = read_state(cfg.data_dir / READINESS_FILE, fallback={}) or {}
    except Exception:  # noqa: BLE001
        accepted = {}
    return {
        "backups": archive.list_backups(cfg.dir),
        "backupSeparate": not cfg.same_disk,
        "backupSealed": store.status()["encrypted"],
        "restores": int(restores or 0),
        "https": https,
        "mailReady": mailer.smtp_settings() is not None,
        "disk": backup_service.disk(cfg),
        "admins": int(admins or 0),
        "accepted": accepted if isinstance(accepted, dict) else {},
    }


@router.get("/backups/readiness")
def backups_readiness(db: Session = Depends(get_db), ctx: TenantContext = Depends(admin_only)):
    return readiness(_facts(db, ctx, backup_service.config()))


@router.put("/backups/readiness/{check_id}")
def backups_readiness_accept(check_id: str, body: dict[str, Any] | None = Body(default=None), db: Session = Depends(get_db), ctx: TenantContext = Depends(installation_admin)):
    """"As meant" (shown as ready until what was found changes), or "Ask again"."""

    cfg = backup_service.config()
    current = {c["id"]: c for c in readiness(_facts(db, ctx, cfg))["checks"]}
    check = current.get(check_id)
    if not check or not check.get("canAccept") and not check.get("accepted"):
        return JSONResponse(status_code=404, content={"error": "No such check to keep as meant."})
    try:
        accepted = read_state(cfg.data_dir / READINESS_FILE, fallback={}) or {}
    except Exception:  # noqa: BLE001
        accepted = {}
    if isinstance(body, dict) and body.get("accept"):
        accepted[check_id] = {"detail": check["detail"], "by": _actor(ctx), "at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")}
    else:
        accepted.pop(check_id, None)
    write_state(cfg.data_dir / READINESS_FILE, accepted)
    return {"ok": True}


_NAME = re.compile(r"^hawk-ai-[\w-]+\.hkbackup$")


@router.get("/backups/{name}")
def backup_download(name: str, db: Session = Depends(get_db), ctx: TenantContext = Depends(installation_admin)):
    """One of the backups, to download (as it is: encrypted when it was made encrypted)."""

    cfg = backup_service.config()
    path = cfg.dir / name
    if not _NAME.match(name) or not path.is_file():
        return JSONResponse(status_code=404, content={"error": "No such backup."})
    _audit(db, ctx, action="backup.downloaded", reason=f"Backup {name} downloaded.", details={"name": name, "size": os.path.getsize(path)})
    return FileResponse(path, media_type="application/octet-stream", filename=name, headers={"Cache-Control": "no-store"})
