"""What runs once before api, worker and beat start (the ``migrate`` service of deploy/compose.yaml), in CxMissionZero's
order (src/server.js, before anything loads):

1. new or existing installation, for backup encryption, decided once (app/services/backup_key.py);
2. a new, empty server with BACKUP_EMAIL, BACKUP_EMAIL_PASSWORD and BACKUP_PASSPHRASE restores the newest backup from
   the backup mailbox (90 s at most, reading only);
3. a restore staged from Settings → Backups & health (or found in step 2) is applied, unless api, worker or beat still
   run (they hold Hawk AI's instance lock): then it stays staged, and the log says how to apply it;
4. the database is brought to this version (infra/scripts/run_migrations.py), so a backup from an older version is
   brought up to date too;
5. the restore is written to the audit log of the restored database.

    python -m app.cli.prestart
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

from app.services import backup_archive as archive
from app.services import backup_service, pg_tools
from app.services.backup_key import BackupKeyStore, env_secret

MIGRATIONS = Path(__file__).resolve().parents[4] / "infra" / "scripts" / "run_migrations.py"


def say(line: str) -> None:
    print(line, flush=True)


def run_migrations() -> None:
    runpy.run_path(str(MIGRATIONS), run_name="__main__")


def main(argv: list[str] | None = None, *, cfg: backup_service.BackupConfig | None = None, migrate=run_migrations, lock_factory=pg_tools.RestoreLock, audit=backup_service.audit_to_database, **restore_options) -> int:
    del argv
    cfg = cfg or backup_service.config()
    cfg.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup_service.decide_once(cfg, say=say)
    from_mailbox = None
    try:
        from_mailbox = backup_service.restore_from_mailbox_at_start(cfg, say=say)
    except Exception as error:  # noqa: BLE001 - a new server starts fresh rather than not at all
        say(f"! [data] Could not look in the backup mailbox ({error}): starting fresh.")
    restored = None
    if (cfg.data_dir / archive.PENDING_RESTORE).exists():
        lock = lock_factory(cfg.database_url)
        try:
            if not lock.try_acquire():
                say("! [data] A restore is staged, but Hawk AI is still running (api, worker or beat): it was not applied. Stop them and start again: docker compose -f deploy/compose.yaml stop api worker beat, then docker compose -f deploy/compose.yaml up -d")
            else:
                try:
                    restored = backup_service.apply_pending_restore(cfg, **restore_options)
                except Exception as error:  # noqa: BLE001 - said, and the staged backup stays for the next start
                    say(f"! [data] The staged restore could not be applied: {error}")
        finally:
            lock.release()
    if restored:
        say(f"[data] Restored the database and {len(restored['restored'])} data folder file(s) from the backup of {restored['createdAt']}.")
        if restored.get("replacedDir"):
            say(f"[data] What it replaced is in {restored['replacedDir']}.")
        if from_mailbox and from_mailbox.get("passphrase_is_key"):
            BackupKeyStore(data_dir=cfg.data_dir).adopt(env_secret("BACKUP_PASSPHRASE"))
        for line in backup_service.secrets_instructions(restored):
            say(line)
    migrate()
    if restored:
        via = f", found by itself in the backup mailbox {from_mailbox['mailbox']} ({from_mailbox['name']})" if from_mailbox else ""
        audit(
            "backup.restored",
            f"State restored from the backup of {restored['createdAt']} (host {restored['host']}){via}.",
            outcome="changed",
            details={"createdAt": restored["createdAt"], "host": restored["host"], "files": restored["files"], "sha256": restored["sha256"]},
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
