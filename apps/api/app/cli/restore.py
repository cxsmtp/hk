"""Rebuild Hawk AI from a backup. Ported from CxMissionZero's scripts/restore.mjs.

    python -m app.cli.restore <backup file> [--yes] [--force]

Without --yes it only checks the backup and shows what it holds (it can run next to a running Hawk AI):

    docker compose -f deploy/compose.yaml exec api python -m app.cli.restore /backups/<file>.hkbackup

With --yes it restores. The database as it is now and every file of the data folder are moved to
replaced-<time>/ in the data folder first, never deleted. A running api, worker or beat would keep writing over
what is restored, so the restore takes Hawk AI's instance lock alone first and refuses while any of them runs (they
each hold a share of it, app/services/pg_tools.py); PostgreSQL itself stays up. Stop them, restore from a one-off
container of the same image, and start again (/settings/guide/backups):

    docker compose -f deploy/compose.yaml stop api worker beat
    docker compose -f deploy/compose.yaml run --rm --no-deps api python -m app.cli.restore /backups/<file>.hkbackup --yes
    sudo deploy/install.sh

--force restores without looking at the lock: only when Hawk AI is certainly not running.

An encrypted backup opens with BACKUP_PASSPHRASE: the passphrase the server that made it had, or that server's backup
key (saved from Settings → Backups & health). A backup this data folder's own server made opens without it. Restored
into a data folder that has decided nothing about backup encryption yet (a rebuilt server) with a server's backup key,
the folder keeps that key: the rebuilt server goes on encrypting its backups with the key already saved.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.services import backup_archive as archive
from app.services import backup_service, pg_tools
from app.services.backup_key import BackupKeyStore, canonical_backup_key, env_secret

STOP = "docker compose -f deploy/compose.yaml stop api worker beat"


def main(
    argv: list[str] | None = None,
    *,
    cfg: backup_service.BackupConfig | None = None,
    lock_factory: Callable[[str], Any] = pg_tools.RestoreLock,
    restore: Callable[..., dict[str, Any]] = backup_service.restore_bundle,
    audit: Callable[..., None] = backup_service.audit_to_database,
) -> int:
    args = sys.argv[1:] if argv is None else argv
    flags = {a for a in args if a.startswith("--")}
    files = [a for a in args if not a.startswith("--")]
    if not files:
        print("Usage: python -m app.cli.restore <backup file> [--yes] [--force]", file=sys.stderr)
        return 2
    cfg = cfg or backup_service.config()

    # What may open an encrypted backup: BACKUP_PASSPHRASE (a passphrase, or a server's backup key), then the backup key
    # this data folder already holds (a backup this same server made).
    own: BackupKeyStore | None
    try:
        own = BackupKeyStore(data_dir=cfg.data_dir)
    except Exception:  # noqa: BLE001 - its key file cannot be read: the restore goes on with what was given
        own = None
    given = env_secret("BACKUP_PASSPHRASE")
    secrets = [s for s in dict.fromkeys([given, own.reveal() if own else ""]) if s]

    opened_with = ""
    try:
        buffer = Path(files[0]).read_bytes()
        sealed = archive.is_sealed(buffer)
        if not sealed or not secrets:
            bundle = archive.read_backup(buffer)
        else:
            bundle = None
            for secret in secrets:
                try:
                    bundle = archive.read_backup(buffer, passphrase=secret)
                    opened_with = secret
                    break
                except archive.BackupKeyError:
                    if secret == secrets[-1]:
                        raise
    except archive.BackupKeyError as error:
        if error.code == "BACKUP_KEY_NEEDED":
            print("Cannot restore: this backup is encrypted, and no backup key or passphrase was given.", file=sys.stderr)
        else:
            what = "the BACKUP_PASSPHRASE given" if given else "this data folder's own backup key"
            print(f"Cannot restore: this backup is encrypted, and it did not open with {what}. The key or passphrase is wrong, or the backup is damaged.", file=sys.stderr)
        print("It opens with the backup key of the server that made it (an owner or admin saved it from Settings → Backups & health), or with the BACKUP_PASSPHRASE that server had.", file=sys.stderr)
        print("Give it in BACKUP_PASSPHRASE and run this again:", file=sys.stderr)
        print("  docker compose -f deploy/compose.yaml run --rm --no-deps -e BACKUP_PASSPHRASE=<the key> api python -m app.cli.restore <backup file>", file=sys.stderr)
        print("Nothing was written.", file=sys.stderr)
        return 1
    except (archive.BackupError, OSError) as error:
        print(f"Cannot restore: {error}", file=sys.stderr)
        return 1

    info = archive.describe_backup(bundle)
    print(f"Backup from {info['createdAt']} (host {info['host']}{', Hawk AI ' + info['appVersion'] if info['appVersion'] else ''}): {info['files']} files, {info['bytes']} bytes, checksum OK.")
    print(f"  database: {'yes (' + str(round(info['databaseBytes'] / 1024)) + ' KB)' if info['hasDatabase'] else 'no'}; data folder files: {info['dataFiles']}; application keys: {'yes' if info['hasSecrets'] else 'no'}")
    print(f"  target data folder: {cfg.data_dir}")
    if "--yes" not in flags:
        print(f"\nNothing written. Stop Hawk AI ({STOP}), then run again with --yes to restore (/settings/guide/backups).")
        return 0

    lock = None
    if "--force" in flags:
        print("\n--force: restoring without checking whether Hawk AI is running on this database.")
    else:
        lock = lock_factory(cfg.database_url)
        try:
            got = lock.try_acquire()
        except Exception as error:  # noqa: BLE001
            print(f"Cannot restore: the database did not answer ({error}). Nothing was written.", file=sys.stderr)
            return 1
        if not got:
            holders = lock.holders()
            lock.release()
            print(f"\nCannot restore: Hawk AI is running on this database ({holders or 'at least one'} of api, worker and beat).", file=sys.stderr)
            print(f"Stop them first ({STOP}), then run this again. Nothing was written.", file=sys.stderr)
            print("If they are certainly not running any more, add --force to restore anyway.", file=sys.stderr)
            return 1
    try:
        done = restore(bundle, cfg=cfg)
        kept_key = False
        if sealed and own is not None and not own.decided:
            kept_key = own.adopt(opened_with)
    except Exception as error:  # noqa: BLE001
        print(f"Cannot restore: {error}", file=sys.stderr)
        return 1
    finally:
        if lock is not None:
            lock.release()
    audit(
        "backup.restored",
        f"State restored from the backup of {info['createdAt']} (host {info['host']}) from the command line.",
        outcome="changed",
        details={"createdAt": info["createdAt"], "host": info["host"], "files": info["files"], "sha256": info["sha256"]},
    )
    print(f"\nRestored {'the database and ' if done.get('databaseRestored') else ''}{len(done['restored'])} data folder file(s).")
    if done.get("replacedDir"):
        print(f"What was there before (the database as {archive.DATABASE_MEMBER}, and the files) is in {done['replacedDir']}.")
    if kept_key:
        print("This server goes on encrypting its backups with the same backup key.")
    elif sealed and own is not None and not own.decided and not canonical_backup_key(opened_with):
        print("The backup was encrypted with a passphrase: start Hawk AI with the same BACKUP_PASSPHRASE to keep its backups encrypted.")
        print("Without it they are not encrypted until an owner or admin turns encryption on (Settings → Backups & health).")
    instructions = backup_service.secrets_instructions(done)
    for line in instructions:
        print(line)
    if not instructions:
        print("Start Hawk AI again: sudo deploy/install.sh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
