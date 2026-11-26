"""The diagnostics bundle: one .tar.gz an administrator downloads from Settings → Backups & health and sends to the OEM.

What is in it (``manifest.json`` lists every file with its SHA-256; ``manifest.sig.json`` is the manifest's signature
made with the installation's evidence-signing key, app/services/evidence_signing.py; ``keys.json`` its public keys, so
the OEM can check offline that the bundle came from this installation and was not changed: tools/verify_evidence.py,
or any Ed25519/ES256 library):

  The installation's (owners and admins of the installation's first tenant):
    version.json        the versions running, Python, the platform;
    health.json         the database, Redis, the worker's and the scheduler's heartbeats, the disk, the schema, integrity;
    errors.jsonl        the error journal of the API, the worker and beat, last 24 hours (app/core/log_config.py);
    jobs-failed.json    failed and dead-lettered job runs, last 7 days, each with its reference (JOB-…);
    updates.json        the updater, its events (updates, rollbacks, restarts), versions that failed, auto-update;
    watchdog.json       the self-check's problems and events (app/services/watchdog.py);
    self-recovery.json  the issues self-recovery found, what it did, and what needs the OEM (app/services/self_recovery.py);
    install.json        the installer's last result and its log (deploy/install.sh);
    config.json         the settings in force, every secret, key and password replaced by "[redacted]".
  A tenant's owner or admin gets the same for their own tenant only: version.json, health.json (up or not, nothing
  more), their tenant's failed jobs, and self-recovery as their page shows it; the installation's errors appear there as
  plain lines with a reference, never their text.

Never in it: a secret, a key, a password, a token, prompt text or customer records. Every text that came from an error
goes through the log redaction (app/core/log_config.py redact_text) and the privacy redaction (emails, phone numbers,
card numbers: app/services/privacy_sanitizer.py), and is cut short.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import os
import platform
import re
import shutil
import tarfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from app.core.log_config import REDACTED, mask_email, read_error_journal, redact_text, redact_value
from app.services.self_recovery import DIAGNOSTICS_DIR, SelfRecovery, clean, job_reference
from app.version import APP_VERSION, PACKAGE_VERSION, display_version

FORMAT = "hawk-diagnostics/v1"
SIGNED_ARTIFACT = "hawk-diagnostics-manifest"
PREPARED_KEPT = 3
JOBS_DAYS = 7
ERRORS_HOURS = 24
#: Parts of a setting's name that make its value a secret (beyond the log redaction's own list).
SECRET_PARTS = ("password", "passwd", "secret", "token", "key", "salt", "pepper", "credential", "dsn", "private", "cookie", "authorization", "signature", "_json", "auth_header")
_URL_USERINFO = re.compile(r"([a-z][a-z0-9+.-]*://)[^/@\s]+@", re.I)
_NAME = re.compile(r"^hawk-ai-diagnostics-[0-9TZ-]+-[A-Z0-9-]+\.tar\.gz$")


def _iso(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def redact_config(values: Mapping[str, Any]) -> dict[str, Any]:
    """The settings in force, with every secret replaced: numbers and yes/no as they are, a value whose name says it is
    a secret as "[redacted]" (or "" when not set), credentials in a URL taken out, the rest through the log redaction."""

    out: dict[str, Any] = {}
    for key in sorted(values):
        value = values[key]
        name = str(key).lower()
        if value is None or isinstance(value, (bool, int, float)):
            out[key] = value
            continue
        if any(part in name for part in SECRET_PARTS) or redact_value(name, "x") == REDACTED:
            out[key] = REDACTED if value not in ("", [], {}, ()) else ""
            continue
        text = value if isinstance(value, str) else json.dumps(value, default=str, sort_keys=True)
        out[key] = redact_text(_URL_USERINFO.sub(rf"\1{REDACTED}@", text), max_len=500)
    return out


def default_tenant(db: Any) -> str | None:
    from app.services.self_check import SelfCheck

    return SelfCheck.default_tenant(db)


def is_installation_admin(db: Any, ctx: Any) -> bool:
    """Roles are per tenant (app/core/permissions.py): the installation's admins are the owners and admins (those who
    hold system.update) of its first tenant, the one cases about the server itself are raised in (self-check)."""

    from app.core.rbac import holds

    return holds(ctx, "system.update") and bool(ctx.tenant) and ctx.tenant.id == default_tenant(db)


def _dump(value: Any) -> bytes:
    return (json.dumps(value, indent=2, default=str, ensure_ascii=False) + "\n").encode("utf-8")


def _failed_runs(db: Any, *, tenant_id: str | None, installation: bool, now: dt.datetime) -> list[dict[str, Any]]:
    from sqlalchemy import or_, select

    from app.db.models.job_run import ScheduledJobRun

    query = select(ScheduledJobRun).where(ScheduledJobRun.status.in_(("fail", "failed", "dead_letter")), ScheduledJobRun.started_at >= now - dt.timedelta(days=JOBS_DAYS))
    if not installation:
        query = query.where(or_(ScheduledJobRun.tenant_id == tenant_id, ScheduledJobRun.tenant_id.is_(None)))
    rows = db.scalars(query.order_by(ScheduledJobRun.started_at.desc()).limit(500)).all()
    out = []
    for row in rows:
        own = installation or (tenant_id and row.tenant_id == tenant_id)
        item: dict[str, Any] = {"reference": job_reference(row.id), "status": row.status, "finished_at": row.finished_at.isoformat() if row.finished_at else None}
        if own:
            item.update({"job": row.job_name, "tenant_id": row.tenant_id, "started_at": row.started_at.isoformat() if row.started_at else None, "error": clean(row.error_message, 500)})
        else:
            item.update({"job": "(a job of the whole installation)", "error": ""})
        out.append(item)
    return out


def _health(db: Any, data_dir: Path, *, detailed: bool) -> dict[str, Any]:
    supervisor = SelfRecovery(data_dir=data_dir)
    probes = supervisor.probe(db)
    out: dict[str, Any] = {name: probes.get(name) for name in ("database", "redis", "worker", "beat")}
    if not detailed:
        out["overall"] = "degraded" if any(v is False for v in out.values()) else "ok"
        return out
    out["disk"] = probes.get("disk")
    try:
        from app.services.schema_health_service import evaluate_schema_health

        out["schema"] = evaluate_schema_health(db).to_dict()
    except Exception as error:  # noqa: BLE001
        out["schema"] = {"error": clean(error)}
    try:
        from app.services.integrity.service import IntegrityService

        last = IntegrityService(data_dir=data_dir).last or {}
        out["integrity"] = {k: last.get(k) for k in ("at", "state", "summary", "version", "commit")}
    except Exception as error:  # noqa: BLE001
        out["integrity"] = {"error": clean(error)}
    try:
        from app.services import backup_service

        last = backup_service.last_backup() or {}
        out["lastBackup"] = {k: (clean(last.get(k)) if k == "error" else last.get(k)) for k in ("at", "ok", "trigger", "error") if k in last}
    except Exception:  # noqa: BLE001
        out["lastBackup"] = None
    return out


def _updates(data_dir: Path, updater_dir: Path) -> dict[str, Any]:
    from app.services.updates import companion
    from app.services.updates.service import UpdateService

    def tidy(event: dict[str, Any]) -> dict[str, Any]:
        return {k: (clean(v) if k == "error" else mask_email(v) if k == "by" else v) for k, v in event.items() if k in ("at", "type", "action", "from", "to", "by", "automatic", "error", "backup")}

    state = companion.companion_state(updater_dir)
    out: dict[str, Any] = {
        "updater": {"connected": state["connected"], "manages": state["manages"], "busy": state["busy"], "heartbeat": state["heartbeat"], "status": tidy(state["status"] or {}), "pending": {k: v for k, v in (state["pending"] or {}).items() if k != "by"}},
        "events": [tidy(e) for e in companion.events(updater_dir, 100)],
    }
    try:
        service = UpdateService(data_dir=data_dir, updater=updater_dir)
        out["failedVersions"] = sorted(service.failed_versions())
        out["settings"] = {k: (clean(v) if k == "lastAutoResult" else v) for k, v in service.settings().items()}
        check = service.last_check if isinstance(service.last_check, dict) else {}
        out["lastCheck"] = {"at": check.get("at"), "error": clean(check.get("error")), "warning": clean(check.get("warning"))}
    except Exception as error:  # noqa: BLE001
        out["error"] = clean(error)
    return out


def _watchdog(data_dir: Path) -> dict[str, Any]:
    from app.services.watchdog import FILE_NAME, Watchdog

    state = Watchdog(file=data_dir / FILE_NAME).state
    return {
        "lastCheckAt": state["lastCheckAt"],
        "problems": [{"key": k, **{f: (clean(v) if f == "detail" else v) for f, v in p.items()}} for k, p in state["problems"].items()],
        "events": [{k: (clean(v) if k == "message" else v) for k, v in e.items()} for e in state["events"]],
        "healthyVersions": state["healthy"],
        "rolledBack": state["rolledBack"],
    }


def _install(updater_dir: Path) -> dict[str, Any]:
    out: dict[str, Any] = {"status": None, "log": []}
    try:
        status = json.loads((updater_dir / "install-status.json").read_text(encoding="utf-8"))
        out["status"] = {k: clean(v) for k, v in status.items()} if isinstance(status, dict) else None
    except (OSError, ValueError):
        pass
    try:
        lines = (updater_dir / "install.log").read_text(encoding="utf-8", errors="replace").splitlines()[-300:]
        out["log"] = [clean(line, 400) for line in lines]
    except OSError:
        pass
    return out


def _errors(data_dir: Path, now: dt.datetime) -> bytes:
    lines = read_error_journal(data_dir, since=now - dt.timedelta(hours=ERRORS_HOURS), limit=2000)
    out = io.StringIO()
    for line in lines:
        safe = {k: (clean(v, 500) if k == "message" else clean(v, 3000) if k == "trace" else v) for k, v in line.items() if k in ("at", "level", "service", "logger", "message", "request_id", "task_id", "task_name", "tenant_id", "error_type", "route", "status", "trace")}
        out.write(json.dumps(safe, ensure_ascii=False, default=str) + "\n")
    return out.getvalue().encode("utf-8")


def _config() -> dict[str, Any]:
    from app.core.config import settings

    values = settings.model_dump()
    for name in ("LOG_FORMAT", "LOG_LEVEL", "TZ", "HAWK_RELEASE", "COMPONENT_TYPE", "SELF_RECOVERY_EVERY_SECONDS", "WATCHDOG_EVERY_SECONDS"):
        if os.environ.get(name):
            values.setdefault(f"env:{name}", os.environ[name])
    return redact_config(values)


def build(
    db: Any,
    *,
    installation: bool,
    tenant_id: str | None,
    requested_by: str = "",
    data_dir: Path | str | None = None,
    updater_dir: Path | str | None = None,
    signing: Any = None,
    reference: str = "",
    now: dt.datetime | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """The bundle (a .tar.gz) and its manifest."""

    from app.core.config import settings
    from app.services.updates import companion

    now = now or dt.datetime.now(dt.timezone.utc)
    data_dir = Path(data_dir or settings.hawk_data_dir)
    updater_dir = Path(updater_dir) if updater_dir else companion.updater_dir()
    files: dict[str, bytes] = {}

    def add(name: str, make: Any) -> None:
        try:
            value = make()
        except Exception as error:  # noqa: BLE001 - one part that cannot be read never stops the rest
            try:
                db.rollback()
            except Exception:  # noqa: BLE001
                pass
            value = {"error": f"This part could not be read: {clean(error)}"}
        files[name] = value if isinstance(value, bytes) else _dump(value)

    add("version.json", lambda: {"product": "Hawk AI", "version": APP_VERSION, "packageVersion": PACKAGE_VERSION, "label": display_version(PACKAGE_VERSION), "python": platform.python_version(), "platform": f"{platform.system().lower()}/{platform.machine()}"})
    add("health.json", lambda: _health(db, data_dir, detailed=installation))
    add("jobs-failed.json", lambda: _failed_runs(db, tenant_id=tenant_id, installation=installation, now=now))
    add("self-recovery.json", lambda: SelfRecovery(data_dir=data_dir, updater_dir=updater_dir).view(installation=installation, tenant_id=tenant_id or ""))
    if installation:
        add("errors.jsonl", lambda: _errors(data_dir, now))
        add("updates.json", lambda: _updates(data_dir, updater_dir))
        add("watchdog.json", lambda: _watchdog(data_dir))
        add("install.json", lambda: _install(updater_dir))
        add("config.json", _config)
        try:
            disk = shutil.disk_usage(data_dir)
            files["health.json"] = _dump({**json.loads(files["health.json"]), "dataDisk": {"freeMB": round(disk.free / 1048576), "totalMB": round(disk.total / 1048576)}})
        except (OSError, ValueError):
            pass

    from app.services.evidence_signing import EvidenceSigning, EvidenceSigningError

    signer = signing or EvidenceSigning(directory=data_dir)
    keys: dict[str, Any] | None = None
    manifest = {
        "format": FORMAT,
        "product": "Hawk AI",
        "version": APP_VERSION,
        "generatedAt": _iso(now),
        "scope": "installation" if installation else "tenant",
        "tenant": None if installation else tenant_id,
        "requestedBy": mask_email(requested_by),
        "reference": reference,
        "redaction": "Secrets, keys, passwords and tokens replaced; emails, phone numbers and card numbers replaced; no prompt text or customer records.",
        "files": [{"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)} for name, data in sorted(files.items())],
        "signature": {"file": "manifest.sig.json", "keys": "keys.json", "artifact": SIGNED_ARTIFACT},
    }
    manifest_bytes = _dump(manifest)
    out_files = {**files, "manifest.json": manifest_bytes}
    try:
        envelope = signer.sign_bytes(manifest_bytes, artifact=SIGNED_ARTIFACT, now=now)
        out_files["manifest.sig.json"] = _dump(envelope)
        # Read after signing: a new installation's key is made by its first signature.
        keys = signer.public_keys()
    except (EvidenceSigningError, OSError) as error:
        out_files["manifest.sig-unavailable.txt"] = f"The manifest could not be signed: {clean(error)}\n".encode("utf-8")
        try:
            keys = signer.public_keys()
        except Exception:  # noqa: BLE001
            keys = None
    if keys is not None:
        out_files["keys.json"] = _dump(keys)

    buffer = io.BytesIO()
    folder = f"hawk-ai-diagnostics-{now.strftime('%Y%m%dT%H%M%SZ')}"
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, data in sorted(out_files.items()):
            info = tarfile.TarInfo(f"{folder}/{name}")
            info.size = len(data)
            info.mtime = int(now.timestamp())
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue(), manifest


def bundle_name(now: dt.datetime, reference: str = "") -> str:
    tag = re.sub(r"[^A-Z0-9-]", "", (reference or "MANUAL").upper()) or "MANUAL"
    return f"hawk-ai-diagnostics-{now.strftime('%Y%m%dT%H%M%SZ')}-{tag}.tar.gz"


def prepare(db: Any, *, data_dir: Path | str, reference: str, reason: str = "", updater_dir: Path | str | None = None, now: dt.datetime | None = None) -> dict[str, Any]:
    """The installation's bundle made now, when self-recovery gives up, and kept in <data>/diagnostics (the newest
    PREPARED_KEPT): what the logs said at that moment stays downloadable even after they move on."""

    now = now or dt.datetime.now(dt.timezone.utc)
    data_dir = Path(data_dir)
    data, manifest = build(db, installation=True, tenant_id=None, requested_by="self-recovery", data_dir=data_dir, updater_dir=updater_dir, reference=reference, now=now)
    folder = data_dir / DIAGNOSTICS_DIR
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = bundle_name(now, reference)
    target = folder / name
    temp = folder / f".{name}.tmp"
    temp.write_bytes(data)
    os.chmod(temp, 0o600)
    os.replace(temp, target)
    for old in sorted(folder.glob("hawk-ai-diagnostics-*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)[PREPARED_KEPT:]:
        try:
            old.unlink()
        except OSError:
            pass
    return {"name": name, "at": _iso(now), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "reason": clean(reason, 120)}


def prepared_file(data_dir: Path | str, name: str) -> Path | None:
    """A prepared bundle by its name, only ever inside <data>/diagnostics."""

    if not _NAME.match(str(name or "")):
        return None
    path = Path(data_dir) / DIAGNOSTICS_DIR / name
    return path if path.is_file() else None


__all__ = ["FORMAT", "SIGNED_ARTIFACT", "build", "bundle_name", "is_installation_admin", "prepare", "prepared_file", "redact_config"]
