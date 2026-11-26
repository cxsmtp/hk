"""Backups: one file that holds everything needed to rebuild this server from scratch. Ported from CxMissionZero's
src/backup.js; Hawk's state is a PostgreSQL database plus the API's data folder (HAWK_DATA_DIR, /data in the
container), so a backup holds:

- ``database.pgdump``: the database, as ``pg_dump --format=custom`` writes it (app/services/pg_tools.py);
- ``data/<path>``: every file of the data folder (the HTTPS choices and certificates, the Let's Encrypt account,
  activation state, the audit key, the evidence signing keys…), but never the backup key itself, the backups, what a restore put aside, the first
  administrator's one-time password file, or a save that never finished;
- ``secrets/<name>``: the application keys the database depends on (connector secrets, signing keys), so that a
  backup restored on a new server can still read what it holds.

Format: gzip of a JSON bundle
  {format, version, createdAt, host, appVersion, files: {name: {data (base64), size, sha256}}, sha256}
where ``sha256`` covers every file's name, hash and size, so a damaged backup is refused rather than half-restored.
With a passphrase the gzip is sealed with AES-256-GCM (key from scrypt): the backup holds password hashes, the
connector keys and certificate keys, so keep unencrypted backups somewhere only administrators can read. The
passphrase is BACKUP_PASSPHRASE, or else the server's own backup key (app/services/backup_key.py), which a new
installation makes at its first start.

Restore writes the files back into the data folder; whatever was there is moved aside to replaced-<time>/ first,
never deleted (app/services/backup_service.py also puts a dump of the database there before it is replaced).
"""

from __future__ import annotations

import base64
import datetime as dt
import gzip
import hashlib
import json
import os
import re
import secrets
import socket
import zlib
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.services.backup_key import SEALED_MAGIC, canonical_backup_key

BACKUP_FORMAT = "hawk-ai-backup"
SEALED_FORMAT = "hawk-ai-backup-sealed"
BACKUP_EXTENSION = ".hkbackup"
BACKUP_PREFIX = "hawk-ai-"
DATABASE_MEMBER = "database.pgdump"
PENDING_RESTORE = "restore-pending.hkbackup"
#: The most a backup may unpack to (CxMissionZero's 512 MB).
MAX_UNPACKED_BYTES = 512 * 1024 * 1024
#: scrypt as Node's scryptSync() runs it by default (N=16384, r=8, p=1), as CxMissionZero seals with.
SCRYPT = {"n": 16384, "r": 8, "p": 1}

#: The application keys a backup carries (the environment names, read from Docker secrets at start).
SECRET_NAMES = (
    "SECRET_KEY",
    "SECRET_KEY_LOCK_PEPPER",
    "CONNECTOR_SECRETS_KEY",
    "CONNECTOR_SECRETS_KDF_SALT",
    "ENFORCEMENT_PAYLOADS_KEY",
    "ONPREM_BUNDLE_SIGNING_SECRET",
)

#: What in the data folder is never part of a backup, and never moved aside by a restore (top-level names).
KEEP_OUT = {
    "backup-key.json",  # the backup key: never in a backup (a restore leaves this server's own key as it is)
    "backups",  # the default BACKUP_DIR
    PENDING_RESTORE,
    "first-admin-password.txt",  # the first administrator's one-time password: never in a backup
    "last-words.json",
    "backup-last.json",
    "restored-secrets",
    "evidence-signing.lock",  # only a lock (app/services/evidence_signing.py); evidence-signing.json itself is backed up
}
_PART = re.compile(r"^[\w.-]+$")


class BackupError(Exception):
    """A backup that cannot be read or restored, with a message complete on its own (for the page and the CLI)."""

    status = 400


class BackupKeyError(BackupError):
    """A backup that needs a key: none was given (``BACKUP_KEY_NEEDED``), or none of those given opens it
    (``BACKUP_KEY_WRONG``)."""

    def __init__(self, code: str) -> None:
        super().__init__(
            "This backup is encrypted, and no backup key or passphrase was given. It opens with the backup key of the server that made it (saved from Settings → Backups & health), or with the BACKUP_PASSPHRASE that server had."
            if code == "BACKUP_KEY_NEEDED"
            else "This backup did not open: wrong backup key or passphrase, or the backup is damaged. It opens only with the backup key of the server that made it (saved from Settings → Backups & health), or with the BACKUP_PASSPHRASE that server had."
        )
        self.code = code


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now_iso(now: dt.datetime | None = None) -> str:
    moment = now or dt.datetime.now(dt.timezone.utc)
    return moment.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _stamp(now: dt.datetime | None = None) -> str:
    return re.sub(r"[:.]", "-", _now_iso(now))


def write_privately(target: Path, data: bytes) -> None:
    """Write ``data`` beside ``target`` under a name nobody can guess, created only if nothing has that name yet,
    readable by this server's user alone, flushed, then renamed over ``target`` in one step."""

    target = Path(target)
    tmp = target.with_name(f"{target.name}.{secrets.token_hex(12)}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, target)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def manifest_hash(files: Mapping[str, Mapping[str, Any]]) -> str:
    lines = [f"{name} {files[name]['sha256']} {files[name]['size']}" for name in sorted(files)]
    return sha256("\n".join(lines).encode("utf-8"))


def _kept_out(rel_parts: list[str], extra: Iterable[str] = ()) -> bool:
    top = rel_parts[0]
    name = rel_parts[-1]
    return (
        top in KEEP_OUT
        or top in set(extra)
        or top.startswith("replaced-")
        or top.startswith(f"{PENDING_RESTORE}.")
        or name.startswith(".")
        or name.endswith(".tmp")
        or name.endswith(".partial")
        or name.endswith(".bak")
        or ".damaged-" in name
    )


def _backup_dir_name(data_dir: Path, backup_dir: Path | str | None) -> list[str]:
    """The backup folder's top-level name, when it is inside the data folder (it is never backed up)."""

    if not backup_dir:
        return []
    try:
        rel = Path(backup_dir).resolve().relative_to(Path(data_dir).resolve())
    except ValueError:
        return []
    return [rel.parts[0]] if rel.parts else []


def collect_data_files(data_dir: Path | str, *, backup_dir: Path | str | None = None) -> list[tuple[str, Path]]:
    """Every file of the data folder a backup holds: [(name, path)], names as data/<relative path>."""

    root = Path(data_dir)
    extra = _backup_dir_name(root, backup_dir)
    found: list[tuple[str, Path]] = []
    if not root.is_dir():
        return found
    for current, dirs, files in os.walk(root):
        rel_dir = Path(current).relative_to(root)
        dirs[:] = sorted(d for d in dirs if not _kept_out([*rel_dir.parts, d], extra) and _PART.match(d))
        for name in sorted(files):
            parts = [*rel_dir.parts, name]
            path = Path(current) / name
            if _kept_out(parts, extra) or not _PART.match(name) or path.is_symlink() or not path.is_file():
                continue
            found.append(("data/" + "/".join(parts), path))
    return found


def application_secrets(env: Mapping[str, str] | None = None) -> dict[str, bytes]:
    env = os.environ if env is None else env
    return {name: str(env.get(name)).encode("utf-8") for name in SECRET_NAMES if env.get(name)}


def create_backup(
    *,
    data_dir: Path | str,
    database_dump: bytes | None,
    passphrase: str = "",
    backup_dir: Path | str | None = None,
    app_secrets: Mapping[str, bytes] | None = None,
    app_version: str = "",
    now: dt.datetime | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Build a backup. Returns (buffer, summary)."""

    files: dict[str, dict[str, Any]] = {}

    def add(name: str, data: bytes) -> None:
        files[name] = {"data": base64.b64encode(data).decode("ascii"), "size": len(data), "sha256": sha256(data)}

    if database_dump is not None:
        add(DATABASE_MEMBER, database_dump)
    for name, path in collect_data_files(data_dir, backup_dir=backup_dir):
        add(name, path.read_bytes())
    for name, value in sorted((app_secrets or {}).items()):
        add(f"secrets/{name}", value)
    created = _now_iso(now)
    bundle = {
        "format": BACKUP_FORMAT,
        "version": 1,
        "createdAt": created,
        "host": socket.gethostname(),
        "appVersion": app_version,
        "files": files,
        "sha256": manifest_hash(files),
    }
    buffer = gzip.compress(json.dumps(bundle).encode("utf-8"), mtime=0)
    if passphrase:
        buffer = seal(buffer, passphrase)
    return buffer, {
        "createdAt": created,
        "files": len(files),
        "bytes": sum(f["size"] for f in files.values()),
        "size": len(buffer),
        "sha256": bundle["sha256"],
        "encrypted": bool(passphrase),
        "database": database_dump is not None,
    }


def is_sealed(buffer: bytes) -> bool:
    """Is this an encrypted backup? Only those are emailed, and only those are restored from a mailbox."""

    return bytes(buffer[: len(SEALED_MAGIC)]) == SEALED_MAGIC


def _derive(secret: str, salt: bytes) -> bytes:
    return hashlib.scrypt(secret.encode("utf-8"), salt=salt, dklen=32, maxmem=64 * 1024 * 1024, **SCRYPT)


def seal(plain: bytes, passphrase: str) -> bytes:
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(12)
    sealed = AESGCM(_derive(passphrase, salt)).encrypt(iv, plain, None)
    data, tag = sealed[:-16], sealed[-16:]
    header = json.dumps(
        {"format": SEALED_FORMAT, "kdf": "scrypt", "salt": base64.b64encode(salt).decode(), "iv": base64.b64encode(iv).decode(), "tag": base64.b64encode(tag).decode()},
        separators=(",", ":"),
    )
    return SEALED_MAGIC + header.encode("utf-8") + b"\n" + data


def _unseal(buffer: bytes, secrets_to_try: list[str]) -> bytes:
    rest = buffer[len(SEALED_MAGIC) :]
    newline = rest.find(b"\n")
    try:
        header = json.loads(rest[:newline].decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise BackupError("Not a Hawk AI backup (or the file is damaged).") from None
    if not isinstance(header, dict) or header.get("format") != SEALED_FORMAT:
        raise BackupError("Not a Hawk AI backup.")
    if not secrets_to_try:
        raise BackupKeyError("BACKUP_KEY_NEEDED")
    try:
        salt = base64.b64decode(header["salt"])
        iv = base64.b64decode(header["iv"])
        tag = base64.b64decode(header["tag"])
    except (KeyError, ValueError, TypeError):
        raise BackupError("Not a Hawk AI backup (or the file is damaged).") from None
    body = rest[newline + 1 :]
    for secret in secrets_to_try:
        try:
            return AESGCM(_derive(secret, salt)).decrypt(iv, body + tag, None)
        except Exception:  # noqa: BLE001 - the next secret, then "wrong key"
            continue
    raise BackupKeyError("BACKUP_KEY_WRONG")


def secrets_to_try(given: Iterable[str]) -> list[str]:
    """Each secret as given, then, when it is a server's backup key typed another way (lower case, spaces for
    dashes), the key as the server wrote it."""

    out: list[str] = []
    for secret in given:
        if not secret:
            continue
        for candidate in (str(secret), canonical_backup_key(secret)):
            if candidate and candidate not in out:
                out.append(candidate)
    return out


def safe_name(name: str) -> bool:
    """Only the names a backup can legitimately hold: no path out of the data folder, nothing kept out of a backup."""

    if name == DATABASE_MEMBER:
        return True
    parts = name.split("/")
    if parts[0] == "secrets":
        return len(parts) == 2 and parts[1] in SECRET_NAMES
    if parts[0] != "data" or len(parts) < 2:
        return False
    rest = parts[1:]
    if any(not _PART.match(p) or p in (".", "..") for p in rest):
        return False
    return not _kept_out(rest)


def read_backup(
    buffer: bytes,
    *,
    passphrase: str = "",
    passphrases: Iterable[str] = (),
    max_unpacked_bytes: int = MAX_UNPACKED_BYTES,
) -> dict[str, Any]:
    """Read and check a backup. Raises BackupError with a readable reason; returns the bundle. An encrypted backup
    opens with ``passphrase`` or any of ``passphrases``; without one that fits it raises BackupKeyError."""

    data = bytes(buffer)
    if is_sealed(data):
        data = _unseal(data, secrets_to_try([passphrase, *passphrases]))
    try:
        # Capped, so a small file that unpacks to gigabytes cannot exhaust the server's memory.
        inflater = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
        raw = inflater.decompress(data, max_unpacked_bytes + 1)
        if len(raw) > max_unpacked_bytes:
            raise BackupError(
                f"This backup unpacks to more than {round(max_unpacked_bytes / 1024 / 1024)} MB, more than any Hawk AI backup holds. It is damaged or not a Hawk AI backup."
            )
        if not inflater.eof:
            raise ValueError("truncated")
        bundle = json.loads(raw.decode("utf-8"))
    except BackupError:
        raise
    except Exception:  # noqa: BLE001 - one message for every way a file is not a backup
        raise BackupError("Not a Hawk AI backup (or the file is damaged).") from None
    if not isinstance(bundle, dict) or bundle.get("format") != BACKUP_FORMAT or not isinstance(bundle.get("files"), dict):
        raise BackupError("Not a Hawk AI backup.")
    # The messages below name only what has been checked to be harmless: a whole version number, and a file name
    # that passed safe_name(). Nothing else read from the backup is echoed back (or audited).
    version = bundle.get("version")
    if version != 1:
        newer = isinstance(version, int) and not isinstance(version, bool) and version > 1
        raise BackupError(f"Backup version {version} is newer than this server understands." if newer else "This backup's version is not one this server understands.")
    for name, file in bundle["files"].items():
        if not isinstance(name, str) or not safe_name(name):
            raise BackupError("Backup contains an unexpected file name: a path out of the data folder, or a file no Hawk AI backup holds.")
        try:
            raw_file = base64.b64decode(file["data"], validate=True)
            size_ok = len(raw_file) == int(file["size"])
            hash_ok = sha256(raw_file) == file["sha256"]
        except Exception:  # noqa: BLE001
            size_ok = hash_ok = False
        if not (size_ok and hash_ok):
            raise BackupError(f"Backup file {name} is damaged (checksum mismatch).")
    if manifest_hash(bundle["files"]) != bundle.get("sha256"):
        raise BackupError("Backup contents do not match its checksum.")
    return bundle


def member(bundle: Mapping[str, Any], name: str) -> bytes | None:
    file = bundle["files"].get(name)
    return base64.b64decode(file["data"]) if file else None


def describe_backup(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """What a backup holds, for showing before a restore."""

    names = list(bundle["files"])
    created = str(bundle.get("createdAt") or "")
    database = bundle["files"].get(DATABASE_MEMBER)
    return {
        # Shown, logged and audited: a time as create_backup() writes it (else none), and a host name as plain text.
        "createdAt": created if re.fullmatch(r"\d{4}-\d{2}-\d{2}T[\d:.]{8,12}Z", created) else "",
        "host": re.sub(r"[\x00-\x1f\x7f  ]+", " ", str(bundle.get("host") or ""))[:255],
        "appVersion": re.sub(r"[^\w.+-]", "", str(bundle.get("appVersion") or ""))[:40],
        "files": len(names),
        "bytes": sum(int(f["size"]) for f in bundle["files"].values()),
        "hasDatabase": database is not None,
        "databaseBytes": int(database["size"]) if database else 0,
        "dataFiles": len([n for n in names if n.startswith("data/")]),
        "hasSecrets": any(n.startswith("secrets/") for n in names),
        "sha256": bundle.get("sha256"),
    }


def move_aside_data(data_dir: Path | str, *, now: dt.datetime | None = None, backup_dir: Path | str | None = None) -> Path | None:
    """Move everything a restore replaces out of the data folder into replaced-<time>/ (never deleted). Returns that
    folder, or None when there was nothing to move."""

    root = Path(data_dir)
    extra = _backup_dir_name(root, backup_dir)
    replaced = root / f"replaced-{_stamp(now)}"
    moved = False
    for name in sorted(os.listdir(root)) if root.is_dir() else []:
        if name in KEEP_OUT or name in extra or name.startswith("replaced-") or name.startswith(PENDING_RESTORE):
            continue
        replaced.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.replace(root / name, replaced / name)
        moved = True
    return replaced if moved else None


def restore_data_files(
    bundle: Mapping[str, Any],
    *,
    data_dir: Path | str,
    now: dt.datetime | None = None,
    backup_dir: Path | str | None = None,
    replaced_dir: Path | None = None,
    on_file: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Write a backup's data folder files into the data folder. Files already there are moved to
    <data_dir>/replaced-<time>/ first. Returns {restored, replacedDir}."""

    root = Path(data_dir).resolve()
    # Every name is checked before anything is touched (here too, not only in read_backup), so whatever hands this a
    # bundle, no name leads out of the data folder.
    plan: list[tuple[str, Path, dict[str, Any]]] = []
    for name, file in bundle["files"].items():
        if not name.startswith("data/"):
            continue
        target = (root / name[len("data/") :]).resolve()
        if not safe_name(name) or root not in target.parents:
            raise BackupError("Backup contains an unexpected file name.")
        plan.append((name, target, file))
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    moved = move_aside_data(root, now=now, backup_dir=backup_dir)
    restored: list[str] = []
    for name, target, file in plan:
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_privately(target, base64.b64decode(file["data"]))
        restored.append(name)
        if on_file:
            on_file(name)
    return {"restored": restored, "replacedDir": str(moved or replaced_dir) if (moved or replaced_dir) else None}


def backup_file_name(now: dt.datetime | None = None) -> str:
    """Timestamped file name for a backup."""

    return f"{BACKUP_PREFIX}{_stamp(now)[:19]}{BACKUP_EXTENSION}"


def list_backups(directory: Path | str | None) -> list[dict[str, Any]]:
    """Backups in a folder, newest first."""

    if not directory or not Path(directory).is_dir():
        return []
    out = []
    for name in os.listdir(directory):
        if not (name.startswith(BACKUP_PREFIX) and name.endswith(BACKUP_EXTENSION)):
            continue
        try:
            stat = (Path(directory) / name).stat()
        except OSError:
            continue
        at = dt.datetime.fromtimestamp(stat.st_mtime, dt.timezone.utc)
        out.append({"name": name, "size": stat.st_size, "bytes": stat.st_size, "at": _now_iso(at)})
    return sorted(out, key=lambda b: b["name"], reverse=True)


def prune(directory: Path | str, keep: int) -> list[str]:
    """Keep the newest ``keep`` backups (at least one) in ``directory``; returns the names removed."""

    removed = []
    for old in list_backups(directory)[max(1, keep) :]:
        try:
            (Path(directory) / old["name"]).unlink()
            removed.append(old["name"])
        except OSError:
            pass
    return removed


def write_backup_to(directory: Path | str, buffer: bytes, *, keep: int = 14, now: dt.datetime | None = None) -> tuple[Path, list[str]]:
    """Write a backup into ``directory``, keeping the newest ``keep``. Returns (file, removed)."""

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    file = directory / backup_file_name(now)
    write_privately(file, buffer)
    return file, prune(directory, keep)


def stage_restore(bundle: Mapping[str, Any], data_dir: Path | str) -> Path:
    """Stage a checked backup to be applied at the next start (decrypted: it sits in the data folder, 0600, beside the
    same secrets)."""

    pending = Path(data_dir) / PENDING_RESTORE
    Path(data_dir).mkdir(parents=True, exist_ok=True, mode=0o700)
    write_privately(pending, gzip.compress(json.dumps(bundle).encode("utf-8"), mtime=0))
    return pending


__all__ = [
    "BACKUP_EXTENSION",
    "BACKUP_FORMAT",
    "BackupError",
    "BackupKeyError",
    "DATABASE_MEMBER",
    "MAX_UNPACKED_BYTES",
    "PENDING_RESTORE",
    "SECRET_NAMES",
    "application_secrets",
    "backup_file_name",
    "collect_data_files",
    "create_backup",
    "describe_backup",
    "is_sealed",
    "list_backups",
    "member",
    "move_aside_data",
    "prune",
    "read_backup",
    "restore_data_files",
    "safe_name",
    "seal",
    "stage_restore",
    "write_backup_to",
    "write_privately",
]
