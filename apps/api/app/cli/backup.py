"""Back up the whole of Hawk AI into one file, with it running or stopped. Ported from CxMissionZero's
scripts/backup.mjs.

    python -m app.cli.backup [output file or folder]
    docker compose -f deploy/compose.yaml exec api python -m app.cli.backup

Default output: BACKUP_DIR (/backups in the containers; ${HAWK_DATA_DIR}/backups on the host by default). The backup is encrypted as the server's own are: with
BACKUP_PASSPHRASE when set, else with the server's backup key (in the data folder) when encryption is on, else not at
all. BACKUP_ENCRYPTION=off keeps it plain. Whether this installation is new or existing is the server's to decide, at
its start: this only reads it.
"""

from __future__ import annotations

import sys
from pathlib import Path

from app.services import backup_archive as archive
from app.services import backup_service
from app.services.backup_key import BackupKeyStore


def main(argv: list[str] | None = None, *, cfg: backup_service.BackupConfig | None = None, dump=None, audit=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    cfg = cfg or backup_service.config()
    if not cfg.data_dir.exists():
        print(f"No data folder at {cfg.data_dir}. Set HAWK_DATA_DIR to the API's data folder.", file=sys.stderr)
        return 1
    if "--trigger" in args:
        # A backup into BACKUP_DIR with the server's own bookkeeping (the newest BACKUP_KEEP kept, the last backup on
        # Settings → Backups & health, the audit log): the updater's backup before every version switch
        # (apps/updater), with its reason, e.g. --trigger "Before the update to HK-00.02.00".
        at = args.index("--trigger")
        trigger = (args[at + 1] if at + 1 < len(args) else "").strip() or "Manual"
        result = backup_service.backup_to_folder(trigger[:120], cfg=cfg, dump=dump, **({"audit": audit} if audit else {}))
        if not result.get("ok"):
            print(f"Cannot back up: {result.get('error')}", file=sys.stderr)
            return 1
        print(f"{trigger[:120]}: backed up the database and the data folder ({result.get('files')} files)")
        print(f"  → {result.get('file')} ({result.get('size')} bytes{', encrypted' if result.get('encrypted') else ''})")
        return 0
    try:
        store = BackupKeyStore(data_dir=cfg.data_dir)
    except Exception as error:  # noqa: BLE001 - the key file is there and cannot be read: said, and nothing is written
        print(f"Cannot back up: {error}", file=sys.stderr)
        return 1
    target = Path(args[0]) if args else cfg.dir
    is_folder = (target.exists() and target.is_dir()) or (bool(args) and args[0].endswith("/")) or not args
    out = target / archive.backup_file_name() if is_folder else target
    out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        buffer, summary = backup_service.build_backup(cfg, store, dump=dump)
        # Prove it reads back before saying it worked.
        info = archive.describe_backup(archive.read_backup(buffer, passphrase=store.secret()))
    except Exception as error:  # noqa: BLE001
        print(f"Cannot back up: {error}", file=sys.stderr)
        return 1
    archive.write_privately(out, buffer)
    sealed = f", encrypted with {'BACKUP_PASSPHRASE' if store.source == 'passphrase' else 'the server' + chr(39) + 's backup key'}" if summary["encrypted"] else ""
    print(f"Backed up the database and {info['dataFiles']} data folder file(s) ({summary['bytes']} bytes) from {cfg.data_dir}")
    print(f"  → {out.resolve()} ({summary['size']} bytes{sealed})")
    print(f"  checksum {summary['sha256'][:16]}…")
    if store.source == "key" and not store.status()["keySaved"]:
        print("  Nobody has confirmed saving the backup key yet: an owner or admin saves it from Settings → Backups & health. Without it this backup cannot be opened on another server.")
    if not summary["encrypted"]:
        print("  Not encrypted: it holds password hashes, connector keys and certificate keys. Keep it where only administrators can read it, or turn encryption on (Settings → Backups & health, or BACKUP_PASSPHRASE).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
