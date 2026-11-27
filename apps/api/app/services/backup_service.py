"""Backups and restores of a whole Hawk AI: what CxMissionZero's src/server.js does around src/backup.js, in Hawk's
shape (PostgreSQL plus the API's data folder, several containers).

- **Where and how many.** Backups go to BACKUP_DIR (default <data folder>/backups) and the newest BACKUP_KEEP
  (default 14) are kept. The page warns while they share a disk with the data.
- **When.** One minute after the scheduler starts, then every BACKUP_INTERVAL_HOURS (default 24): a Celery beat entry
  (app/jobs/backup_jobs.py), run by the worker. By hand from Settings → Backups & health, or
  ``python -m app.cli.backup``. And before the API stops (``last_words``).
- **Encrypted** with BACKUP_PASSPHRASE, else the server's own backup key, else plain (app/services/backup_key.py);
  new or existing installation is decided once, at the first start (``decide_once``).
- **The backup mailbox.** With BACKUP_EMAIL every encrypted backup up to 15 MB is emailed there; a new, empty server
  with BACKUP_EMAIL_PASSWORD and the passphrase finds the newest one and restores itself
  (``restore_from_mailbox_at_start``, run by app/cli/prestart.py before api, worker and beat start).
- **Restore** (``restore_bundle``): a dump of the database as it is now and every file of the data folder go aside to
  replaced-<time>/ first, never deleted; then the backup's database and files take their place. A restore from the
  page is staged and applied at the next start, before anything else runs (``apply_pending_restore``).
"""

from __future__ import annotations

import datetime as dt
import logging
import os
import shutil
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.services import backup_archive as archive
from app.services import pg_tools
from app.services.backup_key import BackupKeyStore, canonical_backup_key, env_secret
from app.services.mail_inbox import BACKUP_SUBJECT, MailboxAccount, find_backup_in_mailbox
from app.services.state_file import read_state, write_state

log = logging.getLogger("hawk.backup")

#: The largest backup that is attached to an email (most mail servers refuse much more).
MAX_ATTACHMENT_BYTES = 15 * 1024 * 1024
#: How long a new server waits for the backup mailbox before it starts fresh.
MAILBOX_TIMEOUT_SECONDS = 90
LAST_FILE = "backup-last.json"
LAST_WORDS_FILE = "last-words.json"
SYSTEM = "Hawk AI"

AuditFn = Callable[..., None]


def _say(line: str) -> None:
    print(line, flush=True)


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _int(env: Mapping[str, str], name: str, default: int, minimum: int) -> int:
    try:
        return max(minimum, int(float(str(env.get(name) if env.get(name) not in (None, "") else default))))
    except ValueError:
        return default


@dataclass(frozen=True)
class BackupConfig:
    data_dir: Path
    dir: Path
    explicit_dir: bool
    interval_hours: int
    keep: int
    database_url: str

    @property
    def same_disk(self) -> bool:
        """Do the backups share a disk with the data (the page warns)? Yes unless BACKUP_DIR names another device."""

        if not self.explicit_dir:
            return True
        try:
            self.dir.resolve().relative_to(self.data_dir.resolve())
            return True
        except ValueError:
            pass
        try:
            probe = self.dir if self.dir.exists() else self.dir.parent
            return os.stat(probe).st_dev == os.stat(self.data_dir).st_dev
        except OSError:
            return True


def config(env: Mapping[str, str] | None = None) -> BackupConfig:
    env = os.environ if env is None else env
    data_dir = Path(settings.hawk_data_dir)
    explicit = str(env.get("BACKUP_DIR") or "").strip()
    return BackupConfig(
        data_dir=data_dir,
        dir=Path(explicit).resolve() if explicit else (data_dir / "backups").resolve(),
        explicit_dir=bool(explicit),
        interval_hours=_int(env, "BACKUP_INTERVAL_HOURS", 24, 0),
        keep=_int(env, "BACKUP_KEEP", 14, 1),
        database_url=settings.database_url,
    )


def key_store(cfg: BackupConfig | None = None) -> BackupKeyStore:
    return BackupKeyStore(data_dir=(cfg or config()).data_dir)


def sealed_with(store: BackupKeyStore) -> str:
    """What a backup made now is encrypted with, in words for an email or the log (never the secret itself)."""

    return "BACKUP_PASSPHRASE" if store.source == "passphrase" else "this server's backup key"


def same_secret(store: BackupKeyStore) -> str:
    return (
        "the same BACKUP_PASSPHRASE"
        if store.source == "passphrase"
        else "BACKUP_PASSPHRASE set to this server's backup key (an owner or admin saved it from Settings → Backups & health; it is never emailed)"
    )


# ---- The audit log --------------------------------------------------------------------------------------------------


def audit_to_database(action: str, reason: str, *, outcome: str = "info", actor: str = SYSTEM, actor_user_id: str | None = None, tenant_id: str | None = None, details: dict[str, Any] | None = None) -> None:
    """Write a backup event to the audit log (the key itself never is)."""

    try:
        from app.db.session import SessionLocal
        from app.services.audit_service import write_audit_log

        with SessionLocal() as db:
            write_audit_log(
                db,
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                actor_type="human" if actor_user_id else "system",
                action=action,
                resource_type="backup",
                resource_id="backup",
                payload={"outcome": outcome, "reason": reason, "actor_id": actor, **({"backup": details} if details else {})},
            )
            db.commit()
    except Exception as error:  # noqa: BLE001 - never in the way of the backup itself
        log.warning("[backup] Could not write to the audit log: %s", error)


# ---- New or existing installation ------------------------------------------------------------------------------------


def has_people(database_url: str | None = None) -> bool:
    url = database_url or settings.database_url
    if pg_tools.is_postgres(url) and not pg_tools.has_tables(url):
        return False
    from app.db.session import SessionLocal
    from app.services.first_run_service import has_users

    with SessionLocal() as db:
        return has_users(db)


def decide_once(cfg: BackupConfig | None = None, *, people: Callable[[], bool] | None = None, say: Callable[[str], None] = _say) -> dict[str, Any] | None:
    """New or existing installation, decided once before anything of this start is loaded, restored or written."""

    cfg = cfg or config()
    store = key_store(cfg)
    decision = store.decide(backup_dir=cfg.dir, has_people=people or (lambda: has_people(cfg.database_url)))
    if not decision:
        return None
    if decision["decidedBy"] == "new-installation":
        say("[backup] A new installation: every backup is encrypted with this server's own backup key. An owner or admin saves the key somewhere else under Settings → Backups & health: without it, a backup cannot be opened if this server is lost.")
    elif decision["decidedBy"] == "existing-installation":
        rest = ", encrypted with BACKUP_PASSPHRASE" if store.source == "passphrase" else ", not encrypted, until an owner or admin turns encryption on under Settings → Backups & health"
        say(f"[backup] This installation has data from before ({decision['found']}): its backups are left as they were{rest}.")
    else:
        say("[backup] BACKUP_ENCRYPTION=off: backups are not encrypted.")
    return decision


# ---- Making a backup -------------------------------------------------------------------------------------------------


def last_backup(cfg: BackupConfig | None = None) -> dict[str, Any] | None:
    cfg = cfg or config()
    try:
        value = read_state(cfg.data_dir / LAST_FILE, fallback=None)
    except Exception:  # noqa: BLE001 - only what the page shows
        return None
    return value if isinstance(value, dict) else None


def _remember(cfg: BackupConfig, value: dict[str, Any]) -> None:
    try:
        write_state(cfg.data_dir / LAST_FILE, value, keep_last=False)
    except OSError as error:
        log.warning("[backup] Could not note the last backup: %s", error)


def build_backup(cfg: BackupConfig, store: BackupKeyStore, *, dump: Callable[[str], bytes] | None = None, dump_timeout: float = 600) -> tuple[bytes, dict[str, Any]]:
    """A backup made now: the database (pg_dump) and the data folder, sealed as the server's settings say."""

    from app.version import APP_VERSION

    database = None
    if dump is not None:
        database = dump(cfg.database_url)
    elif pg_tools.is_postgres(cfg.database_url):
        database = pg_tools.dump_database(cfg.database_url, timeout=dump_timeout)
    return archive.create_backup(
        data_dir=cfg.data_dir,
        database_dump=database,
        passphrase=store.secret(),
        backup_dir=cfg.dir,
        app_secrets=archive.application_secrets(),
        app_version=APP_VERSION,
    )


#: What pg_dump says when PostgreSQL is stopping, or already gone, as the API stops with it.
DATABASE_STOPPING = (
    "the database system is shutting down",
    "connection refused",
    "could not translate host name",
    "server closed the connection unexpectedly",
)


def database_is_stopping(error: BaseException) -> bool:
    text = str(error).lower()
    return any(sign in text for sign in DATABASE_STOPPING)


def backup_to_folder(
    trigger: str,
    *,
    actor: str = SYSTEM,
    actor_user_id: str | None = None,
    tenant_id: str | None = None,
    cfg: BackupConfig | None = None,
    audit: AuditFn = audit_to_database,
    dump: Callable[[str], bytes] | None = None,
    mail: bool = True,
    dump_timeout: float = 600,
    database_may_be_stopping: bool = False,
) -> dict[str, Any]:
    """Write a backup into BACKUP_DIR, keeping the newest BACKUP_KEEP; audited, and copied to the backup mailbox.
    ``database_may_be_stopping``: the backup taken while Hawk AI stops, when PostgreSQL may be stopping with it; a
    database that is gone is then a skipped backup, not a failed one."""

    cfg = cfg or config()
    store = key_store(cfg)
    try:
        buffer, summary = build_backup(cfg, store, dump=dump, dump_timeout=dump_timeout)
        file, removed = archive.write_backup_to(cfg.dir, buffer, keep=cfg.keep)
        last = {"at": summary["createdAt"], "ok": True, "file": str(file), "name": file.name, "size": summary["size"], "files": summary["files"], "encrypted": summary["encrypted"], "trigger": trigger}
        _remember(cfg, last)
        audit(
            "backup.written",
            f"{trigger} backup written to {file} ({summary['files']} files{', encrypted' if summary['encrypted'] else ''}).",
            actor=actor,
            actor_user_id=actor_user_id,
            tenant_id=tenant_id,
            details={"file": str(file), **summary, "removed": removed},
        )
        log.info(
            "Backup written: %s",
            file.name,
            extra={"trigger": trigger, "size_bytes": summary.get("size"), "files": summary.get("files"), "encrypted": bool(summary.get("encrypted")), "removed": len(removed or [])},
        )
        if mail:
            try:
                mail_backup_copy(file, summary, trigger, cfg=cfg, store=store, audit=audit)
            except Exception as error:  # noqa: BLE001
                log.warning("[backup] Could not email the backup: %s", error)
        return last
    except Exception as error:  # noqa: BLE001 - said on the page, in the log and the audit log
        if database_may_be_stopping and database_is_stopping(error):
            # `docker compose restart` stops every service at once, so PostgreSQL is often already going when the API
            # takes its backup before stopping. Nothing failed that anyone can put right: the newest backup is kept as
            # the last one, and the error journal (self-recovery) and the audit log are left alone.
            log.warning("[backup] %s backup skipped: the database was stopping too (%s).", trigger, str(error).strip().splitlines()[-1][:200], extra={"trigger": trigger})
            return {"at": _now_iso(), "ok": False, "skipped": True, "error": str(error)[:500], "trigger": trigger}
        last = {"at": _now_iso(), "ok": False, "error": str(error)[:500], "trigger": trigger}
        _remember(cfg, last)
        audit("backup.failed", f"{trigger} backup to {cfg.dir} failed: {str(error)[:300]}", outcome="failed", actor=actor, actor_user_id=actor_user_id, tenant_id=tenant_id)
        log.error("! [backup] Backup failed (%s): %s", trigger, error, exc_info=True, extra={"trigger": trigger})
        return last


def backup_mailbox(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    env = os.environ if env is None else env
    email = str(env.get("BACKUP_EMAIL") or "").strip().lower()
    try:
        port = int(str(env.get("BACKUP_EMAIL_IMAP_PORT") or "993"))
    except ValueError:
        port = 993
    return {
        "email": email,
        "password": env_secret("BACKUP_EMAIL_PASSWORD", env),
        "host": str(env.get("BACKUP_EMAIL_IMAP_HOST") or env.get("SMTP_HOST") or "").strip(),
        "port": port,
        "user": str(env.get("BACKUP_EMAIL_USER") or env.get("BACKUP_EMAIL") or "").strip(),
    }


def mail_backup_copy(file: Path, summary: Mapping[str, Any], trigger: str, *, cfg: BackupConfig, store: BackupKeyStore, audit: AuditFn = audit_to_database, send: Callable[..., Any] | None = None) -> bool:
    """A copy of a backup to the backup mailbox (BACKUP_EMAIL), so a new server can bring it back by itself. Encrypted
    backups only: never one that holds the passwords and keys in the clear, and never the key with it."""

    from app.services import mailer

    mailbox = backup_mailbox()
    if not mailbox["email"]:
        return False
    if not summary.get("encrypted"):
        log.warning("! [backup] BACKUP_EMAIL is set, but backups are not encrypted: turn encryption on under Settings → Backups & health (or set BACKUP_PASSPHRASE) to email them.")
        return False
    if int(summary.get("size") or 0) > MAX_ATTACHMENT_BYTES:
        audit("backup.email.skipped", f"{trigger} backup not emailed to {mailbox['email']}: {round(int(summary['size']) / 1048576)} MB is too large to attach.", outcome="failed")
        return False
    if send is None and mailer.smtp_settings() is None:
        log.warning("! [backup] BACKUP_EMAIL is set, but no mail server is (Settings → Email (SMTP), or SMTP_HOST): backups are not emailed.")
        return False
    name = Path(file).name
    when = str(summary["createdAt"])[:16].replace("T", " ")
    subject = f"{BACKUP_SUBJECT} {when} UTC"
    text = "\n\n".join(
        [
            f"{trigger} backup of Hawk AI, encrypted with {sealed_with(store)}: {name}.",
            f"Keep this email. A new Hawk AI started with BACKUP_EMAIL, BACKUP_EMAIL_PASSWORD and {same_secret(store)} finds the newest backup here and restores it by itself.",
            f"Files: {summary['files']}\nSize: {max(1, round(int(summary['size']) / 1024))} KB",
        ]
    )
    (send or mailer.send_mail)([mailbox["email"]], subject=subject, text=text, attachments=[(name, Path(file).read_bytes(), "application/octet-stream")])
    audit("backup.emailed", f"{trigger} backup emailed to {mailbox['email']} ({name}).")
    return True


# ---- Before stopping ("last words") ---------------------------------------------------------------------------------


def administrators() -> list[str]:
    from sqlalchemy import select

    from app.db.models.user import User, UserTenantRole
    from app.db.session import SessionLocal

    with SessionLocal() as db:
        rows = db.scalars(
            select(User.email).join(UserTenantRole, UserTenantRole.user_id == User.id).where(UserTenantRole.role.in_(("owner", "admin")), User.is_active.is_(True))
        ).all()
    return sorted({str(r) for r in rows if r})


def last_words(
    reason: str,
    deadline: float,
    *,
    cfg: BackupConfig | None = None,
    env: Mapping[str, str] | None = None,
    audit: AuditFn = audit_to_database,
    dump: Callable[[str], bytes] | None = None,
    send: Callable[..., Any] | None = None,
    admins: Callable[[], list[str]] = administrators,
    now: Callable[[], float] = time.time,
) -> dict[str, Any]:
    """Before the API stops for a reason nobody here asked for (the service stopped, a crash): a backup in the backup
    folder, and an email to the administrators with how to bring it back. The copy is attached only when it is
    encrypted; otherwise the email says where it is. The key is never in the email. At most one such email every
    LAST_WORDS_EVERY_HOURS (6). Never raises, and never waits past ``deadline`` (time.monotonic())."""

    from app.services import mailer

    env = os.environ if env is None else env
    cfg = cfg or config()
    result: dict[str, Any] = {"backup": None, "mailed": 0, "throttled": False}
    store = key_store(cfg)
    remaining = max(1.0, deadline - time.monotonic())
    backup = backup_to_folder(f"Before stopping ({reason})", cfg=cfg, audit=audit, dump=dump, mail=send is None, dump_timeout=remaining, database_may_be_stopping=True)
    result["backup"] = backup
    if not backup.get("ok"):
        backup = None
    try:
        every = max(0.0, float(env.get("LAST_WORDS_EVERY_HOURS") or 6)) * 3600
    except ValueError:
        every = 6 * 3600.0
    previous: dict[str, Any] = {}
    try:
        previous = read_state(cfg.data_dir / LAST_WORDS_FILE, fallback={}) or {}
    except Exception:  # noqa: BLE001
        previous = {}
    try:
        then = dt.datetime.fromisoformat(str(previous.get("at")).replace("Z", "+00:00")).timestamp() if previous.get("at") else None
    except ValueError:
        then = None
    if then is not None and now() - then < every:
        result["throttled"] = True
        return result
    if send is None and mailer.smtp_settings(env) is None:
        return result
    try:
        write_state(cfg.data_dir / LAST_WORDS_FILE, {"at": dt.datetime.fromtimestamp(now(), dt.timezone.utc).isoformat().replace("+00:00", "Z"), "reason": reason}, keep_last=False)
    except OSError:
        pass
    attach = bool(backup and backup.get("encrypted") and int(backup.get("size") or 0) <= MAX_ATTACHMENT_BYTES)
    name = backup["name"] if backup else ""
    keyed = bool(backup and backup.get("encrypted")) and store.source == "key"
    when = dt.datetime.fromtimestamp(now(), dt.timezone.utc).strftime("%Y-%m-%d %H:%M")
    if backup:
        if attach:
            saved = f"Its data was backed up just before, and the backup is attached ({name}, encrypted with {sealed_with(store)})."
        elif backup.get("encrypted"):
            saved = f"Its data was backed up just before, to {backup['file']} on the server. It is too large to attach."
        else:
            saved = f"Its data was backed up just before, to {backup['file']} on the server. It is not attached because it is not encrypted: it holds the passwords and keys. Turn encryption on under Settings → Backups & health (or set BACKUP_PASSPHRASE) to get an encrypted copy by email next time."
    else:
        saved = "It could not write a backup before stopping. Its data folder and database are still there."
    lines = [
        f"Hawk AI stopped ({reason}) at {when} UTC.",
        saved,
        "To bring it back: start Hawk AI again (sudo deploy/install.sh). Nothing needs restoring while its volumes are there.",
        (
            "If the data is lost: install Hawk AI on a server, copy this backup to it, and restore it with the backup key an owner or admin saved from Settings → Backups & health (it is not in this email): see Restore in /settings/guide/install. The backup brings back every person, setting and the audit log."
            if keyed
            else "If the data is lost: install Hawk AI on a server with the same BACKUP_PASSPHRASE, copy this backup to it, and restore it: see Restore in /settings/guide/install. The backup brings back every person, setting and the audit log."
        ),
    ]
    if keyed and not store.status()["keySaved"]:
        lines.append("Nobody has confirmed saving the backup key yet. While the data is still there, start Hawk AI again and save the key from Settings → Backups & health: without it, this backup cannot be opened.")
    attachments = [(name, Path(backup["file"]).read_bytes(), "application/octet-stream")] if attach and backup else []
    subject = f"Hawk AI stopped: {'a copy of its data is safe' if backup else 'it could not back up its data'}"

    def deliver() -> None:
        try:
            people = admins()
        except Exception as error:  # noqa: BLE001
            log.warning("[backup] Could not list the administrators: %s", error)
            return
        for address in people:
            try:
                (send or mailer.send_mail)([address], subject=subject, text="\n\n".join(lines), attachments=attachments)
                result["mailed"] += 1
            except Exception as error:  # noqa: BLE001
                log.warning("[backup] Could not email %s: %s", address, error)

    worker = threading.Thread(target=deliver, daemon=True, name="hawk-last-words")
    worker.start()
    worker.join(max(0.0, deadline - time.monotonic()))
    return result


# ---- Restoring ------------------------------------------------------------------------------------------------------


def _stamp() -> tuple[dt.datetime, str]:
    moment = dt.datetime.now(dt.timezone.utc)
    return moment, moment.isoformat(timespec="milliseconds").replace("+00:00", "Z").replace(":", "-").replace(".", "-")


def restore_bundle(
    bundle: Mapping[str, Any],
    *,
    cfg: BackupConfig | None = None,
    restore_db: Callable[[str, bytes], None] | None = None,
    dump: Callable[[str], bytes] | None = None,
    env: Mapping[str, str] | None = None,
    on_file: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Put a checked backup in place: the database as it is now goes to replaced-<time>/database.pgdump and every file
    of the data folder to replaced-<time>/, then the backup's database and files take their place."""

    env = os.environ if env is None else env
    cfg = cfg or config()
    moment, stamp = _stamp()
    replaced = cfg.data_dir / f"replaced-{stamp}"
    postgres = pg_tools.is_postgres(cfg.database_url)
    new_db = archive.member(bundle, archive.DATABASE_MEMBER)
    old_db: bytes | None = None
    if new_db is not None and (dump is not None or (postgres and pg_tools.has_tables(cfg.database_url))):
        old_db = (dump or pg_tools.dump_database)(cfg.database_url)
        replaced.mkdir(parents=True, exist_ok=True, mode=0o700)
        archive.write_privately(replaced / archive.DATABASE_MEMBER, old_db)
    if new_db is not None:
        put = restore_db or (pg_tools.restore_database if postgres else None)
        if put is None:
            raise archive.BackupError("This backup holds a PostgreSQL database, and this server's database is not PostgreSQL.")
        # One transaction (app/services/pg_tools.py): if it fails, the database is as it was and no file is touched.
        put(cfg.database_url, new_db)
    files = archive.restore_data_files(bundle, data_dir=cfg.data_dir, now=moment, backup_dir=cfg.dir, on_file=on_file)
    if files["replacedDir"] is None and replaced.exists():
        files["replacedDir"] = str(replaced)
    # The application keys the restored database was written with. When they differ from this server's, they are put
    # where an administrator copies them into the deployment's secrets (/settings/guide/backups).
    differing = []
    for name in archive.SECRET_NAMES:
        value = archive.member(bundle, f"secrets/{name}")
        if value is not None and value.decode("utf-8") != str(env.get(name) or ""):
            differing.append(name)
    if differing:
        folder = cfg.data_dir / "restored-secrets"
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        for name in differing:
            archive.write_privately(folder / name.lower(), archive.member(bundle, f"secrets/{name}") or b"")
    return {**archive.describe_backup(bundle), **files, "databaseRestored": new_db is not None, "secretsDiffer": differing}


def secrets_instructions(result: Mapping[str, Any]) -> list[str]:
    names = [str(n).lower() for n in result.get("secretsDiffer") or []]
    if not names:
        return []
    return [
        f"The backup was made with other application keys than this server's ({', '.join(names)}): the restored database needs them.",
        "They are in the data folder, under restored-secrets/. On the server (HAWK_DATA_DIR is /var/lib/hawk-ai unless deploy/.env says otherwise), copy them over the deployment's own and start again:",
        "  docker compose -f deploy/compose.yaml stop api worker beat",
        "  sudo docker compose -f deploy/compose.yaml cp api:/data/restored-secrets /tmp/hawk-restored-secrets",
        "  sudo sh -c 'cd /tmp/hawk-restored-secrets && for f in *; do install -o 1000 -g 1000 -m 0600 \"$f\" /var/lib/hawk-ai/secrets/\"$f\"; done; rm -rf /tmp/hawk-restored-secrets'",
        "  docker compose -f deploy/compose.yaml run --rm --no-deps api rm -rf /data/restored-secrets /run/hawk/secret_key.lock",
        "  sudo deploy/install.sh",
    ]


def apply_pending_restore(cfg: BackupConfig | None = None, **kwargs: Any) -> dict[str, Any] | None:
    """A restore staged from the page (or found in the backup mailbox) is applied here, at the next start, before api,
    worker and beat run. Returns what was restored, or None."""

    cfg = cfg or config()
    pending = cfg.data_dir / archive.PENDING_RESTORE
    if not pending.exists():
        return None
    log.info("Applying the restore staged from Settings → Backups & health")
    try:
        bundle = archive.read_backup(pending.read_bytes())
        result = restore_bundle(bundle, cfg=cfg, **kwargs)
    except Exception:
        log.error("! [backup] The staged restore could not be applied", exc_info=True)
        raise
    pending.unlink(missing_ok=True)
    log.info(
        "Restore applied",
        extra={"database_restored": bool(result.get("databaseRestored")), "secrets_differ": len(result.get("secretsDiffer") or [])},
    )
    return result


def is_fresh(cfg: BackupConfig, *, people: Callable[[], bool] | None = None) -> bool:
    """Only a new, empty server restores itself from the backup mailbox: nobody in the database, nothing staged."""

    if (cfg.data_dir / archive.PENDING_RESTORE).exists():
        return False
    try:
        return not (people or (lambda: has_people(cfg.database_url)))()
    except Exception:  # noqa: BLE001 - in doubt, never replace anything
        return False


def restore_from_mailbox_at_start(
    cfg: BackupConfig | None = None,
    *,
    env: Mapping[str, str] | None = None,
    people: Callable[[], bool] | None = None,
    find: Callable[..., dict[str, Any] | None] = find_backup_in_mailbox,
    timeout: float = MAILBOX_TIMEOUT_SECONDS,
    say: Callable[[str], None] = _say,
) -> dict[str, Any] | None:
    """A new server with BACKUP_EMAIL, BACKUP_EMAIL_PASSWORD and BACKUP_PASSPHRASE brings back the newest backup in the
    mailbox that opens with the passphrase: it is staged here and applied by apply_pending_restore() just after."""

    env = os.environ if env is None else env
    cfg = cfg or config()
    mailbox = backup_mailbox(env)
    passphrase = env_secret("BACKUP_PASSPHRASE", env)
    if not (mailbox["email"] and mailbox["password"] and mailbox["host"] and passphrase):
        return None
    if not is_fresh(cfg, people=people):
        return None
    say(f"[data] A new server: looking for a backup in {mailbox['email']}…")
    opened: dict[str, Any] = {}

    def opens(buffer: bytes) -> bool:
        if not archive.is_sealed(buffer):
            return False
        try:
            opened["bundle"] = archive.read_backup(buffer, passphrase=passphrase)
            return True
        except archive.BackupError:
            return False

    outcome: dict[str, Any] = {}

    def look() -> None:
        try:
            outcome["found"] = find(MailboxAccount(host=mailbox["host"], port=mailbox["port"], user=mailbox["user"], password=mailbox["password"]), opens)
        except Exception as error:  # noqa: BLE001
            outcome["error"] = error

    thread = threading.Thread(target=look, daemon=True, name="hawk-backup-mailbox")
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        say(f"! [data] Could not read the backup mailbox {mailbox['email']} (the mailbox did not answer within {int(timeout)} seconds): starting fresh.")
        return None
    if "error" in outcome:
        say(f"! [data] Could not read the backup mailbox {mailbox['email']} ({outcome['error']}): starting fresh.")
        return None
    found = outcome.get("found")
    if not found or "bundle" not in opened:
        say(f"[data] No backup that opens with BACKUP_PASSPHRASE in {mailbox['email']}: starting fresh.")
        return None
    archive.stage_restore(opened["bundle"], cfg.data_dir)
    say(f"[data] Found {found['name']} in {mailbox['email']}: restoring it.")
    return {"name": found["name"], "date": found.get("date") or "", "mailbox": mailbox["email"], "passphrase_is_key": bool(canonical_backup_key(passphrase))}


def disk(cfg: BackupConfig) -> dict[str, int] | None:
    try:
        usage = shutil.disk_usage(cfg.data_dir)
    except OSError:
        return None
    return {"freeMB": usage.free // (1024 * 1024), "totalMB": usage.total // (1024 * 1024)}
