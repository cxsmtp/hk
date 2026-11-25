"""The server's own backup key: what encrypts every backup when nobody gave a BACKUP_PASSPHRASE. Ported from
CxMissionZero's src/backup-key.js.

A backup holds the database (people, password hashes, activation, connector secrets) and the API's data folder (the
HTTPS choices and certificate keys). Encrypted by default:

- A NEW installation makes a key of its own at its first start and encrypts every backup with it, in the same format a
  passphrase gives: ``BACKUP_PASSPHRASE=<the key>`` opens such a backup anywhere.
- An EXISTING installation is left as it was: its backups stay plain until an owner or admin turns encryption on
  (Settings → Backups & health), which makes the key then.
- BACKUP_PASSPHRASE, when set, wins: backups are encrypted with it and the key here is not used.
- BACKUP_ENCRYPTION=off keeps backups plain on purpose (a passphrase still wins).

New or existing is decided once, at the first start that finds no decision, and written to backup-key.json in the data
folder (0600, no last good copy: it holds a secret). It is never decided again. "New" means nothing from before is
there: no state file in the data folder (or a last good copy of one), no certificate folder with something in it,
nothing a restore left, no plain backup in the backup folder, and nobody in the database. Anything else is an existing
installation, so a doubt always ends in "leave it as it was", never in encrypting the backups of people who hold no key
for them.

The key is not part of a backup, is never emailed and never logged. An owner or admin reads it on the Settings page and
keeps it somewhere else: without it (or this server's data folder), a backup cannot be opened.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import secrets
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from app.services.state_file import read_state, write_state

BACKUP_KEY_FILE = "backup-key.json"

#: Letters and digits that are not mistaken for one another when read or typed (no I, O, 0, 1).
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
GROUPS = 8
GROUP_SIZE = 4

SEALED_MAGIC = b"HKBK1\n"


def _now_iso(now: dt.datetime | None = None) -> str:
    moment = now or dt.datetime.now(dt.timezone.utc)
    return moment.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def generate_backup_key() -> str:
    """A new key: 8 groups of 4 letters and digits (160 random bits), e.g. K7QM-2HXD-…"""

    # 32 symbols: the low five bits of a random byte pick one, each equally likely.
    symbols = [ALPHABET[byte & 31] for byte in secrets.token_bytes(GROUPS * GROUP_SIZE)]
    return "-".join("".join(symbols[i * GROUP_SIZE : (i + 1) * GROUP_SIZE]) for i in range(GROUPS))


def canonical_backup_key(text: Any) -> str:
    """The key as it is stored, from the way someone typed it (lower case, spaces, no dashes): '' when the text is not
    a backup key at all (a passphrase of the admin's own, for instance)."""

    symbols = re.sub(r"[\s-]+", "", str(text or "").upper())
    if len(symbols) != GROUPS * GROUP_SIZE or any(s not in ALPHABET for s in symbols):
        return ""
    return "-".join(symbols[i : i + GROUP_SIZE] for i in range(0, len(symbols), GROUP_SIZE))


def encryption_opted_out(env: Mapping[str, str] | None = None) -> bool:
    """BACKUP_ENCRYPTION=off (or 0, false, no): backups are left plain on purpose."""

    env = os.environ if env is None else env
    return bool(re.fullmatch(r"(off|0|false|no)", str(env.get("BACKUP_ENCRYPTION") or "").strip(), re.IGNORECASE))


def env_secret(name: str, env: Mapping[str, str] | None = None) -> str:
    """A secret setting from the environment, or from the file ``<NAME>_FILE`` names (Docker secrets)."""

    env = os.environ if env is None else env
    value = str(env.get(name) or "")
    if value:
        return value
    file = str(env.get(f"{name}_FILE") or "").strip()
    if file:
        try:
            return Path(file).read_text(encoding="utf-8").strip()
        except OSError:
            return ""
    return ""


def _is_plain_backup_file(file: Path) -> bool:
    try:
        with open(file, "rb") as handle:
            return handle.read(len(SEALED_MAGIC)) != SEALED_MAGIC
    except OSError:
        # Cannot be read: counted as a plain backup, so the doubt ends in "leave it as it was".
        return True


#: What a state file of any version is called: <name>.json or .key, its .bak, or one put aside as damaged.
STATE_LIKE = re.compile(r"\.(json|jsonl|key|crt|pem|pfx|csr)(\.bak|\.damaged-.*)?$")
#: A save that never finished (app/services/state_file.py): not state.
HALF_SAVED = re.compile(r"\.tmp$")
#: Folders, beside the files, that only a server which has run leaves something in (certificates, ACME keys).
WORK_DIRS = ("tls",)


def _entries(directory: Path) -> list[str]:
    try:
        return sorted(os.listdir(directory))
    except OSError:
        return []


def earlier_state(*, data_dir: Path | str, backup_dir: Path | str = "", has_people: Callable[[], bool] | None = None) -> str:
    """What this installation holds from before, as a few words for the server's log; '' when nothing (a new
    installation). Looked at before the server has loaded or written anything of its own."""

    data_dir = Path(data_dir)
    if has_people is not None:
        try:
            if has_people():
                return "people in the database"
        except Exception:  # noqa: BLE001 - a database that cannot be asked: the doubt ends in "existing"
            return "a database that could not be asked"
    for folder in WORK_DIRS:
        if _entries(data_dir / folder):
            return f"{folder}/"
    for name in _entries(data_dir):
        if name == BACKUP_KEY_FILE or HALF_SAVED.search(name):
            continue
        if STATE_LIKE.search(name) or name.startswith("replaced-") or name.startswith("restore-pending"):
            return name
    folders = {Path(data_dir / "backups").resolve()}
    if backup_dir:
        folders.add(Path(backup_dir).resolve())
    for folder in sorted(folders):
        for name in _entries(folder):
            if name.endswith(".hkbackup") and _is_plain_backup_file(folder / name):
                return f"a backup that is not encrypted ({name})"
    return ""


class BackupKeyStore:
    """The decision and the key, in <data folder>/backup-key.json."""

    def __init__(self, *, data_dir: Path | str, env: Mapping[str, str] | None = None) -> None:
        self.file = Path(data_dir) / BACKUP_KEY_FILE
        self.env = os.environ if env is None else env
        state = read_state(self.file, fallback=None, holds="the key this server encrypts its backups with")
        self._state: dict[str, Any] | None = state if isinstance(state, dict) else None

    def reload(self) -> None:
        state = read_state(self.file, fallback=None, holds="the key this server encrypts its backups with")
        self._state = state if isinstance(state, dict) else None

    def _save(self) -> None:
        write_state(self.file, self._state, mode=0o600, keep_last=False)

    @property
    def decided(self) -> bool:
        """Has new-or-existing been decided for this data folder?"""

        return bool((self._state or {}).get("mode"))

    def decide(self, *, backup_dir: Path | str = "", has_people: Callable[[], bool] | None = None, now: dt.datetime | None = None) -> dict[str, Any] | None:
        """Decide, once, whether this is a new installation (encrypted from the first backup) or an existing one (left
        plain until an admin turns encryption on). Returns what was decided, or None when it already had been."""

        if self.decided:
            return None
        found = earlier_state(data_dir=self.file.parent, backup_dir=backup_dir, has_people=has_people)
        opted_out = encryption_opted_out(self.env)
        encrypt = not found and not opted_out
        at = _now_iso(now)
        self._state = {
            "version": 1,
            "mode": "encrypted" if encrypt else "plain",
            "decidedAt": at,
            "decidedBy": "existing-installation" if found else "opt-out" if opted_out else "new-installation",
            **({"key": generate_backup_key(), "keyCreatedAt": at, "savedAt": None, "savedBy": ""} if encrypt else {}),
        }
        self._save()
        return {"mode": self._state["mode"], "decidedBy": self._state["decidedBy"], "found": found}

    def adopt(self, key: str, *, now: dt.datetime | None = None) -> bool:
        """Keep the key a restore was opened with (app/cli/restore.py), when this folder has decided nothing yet."""

        canonical = canonical_backup_key(key)
        if self.decided or not canonical:
            return False
        at = _now_iso(now)
        self._state = {"version": 1, "mode": "encrypted", "decidedAt": at, "decidedBy": "restore", "key": canonical, "keyCreatedAt": at, "savedAt": at, "savedBy": "restore"}
        self._save()
        return True

    @property
    def _passphrase(self) -> str:
        return env_secret("BACKUP_PASSPHRASE", self.env)

    @property
    def source(self) -> str:
        """What encrypts a backup made now: 'passphrase' (BACKUP_PASSPHRASE), 'key' (the server's own), or 'none'."""

        if self._passphrase:
            return "passphrase"
        if encryption_opted_out(self.env):
            return "none"
        state = self._state or {}
        return "key" if state.get("mode") == "encrypted" and state.get("key") else "none"

    def secret(self) -> str:
        """The secret a backup is sealed with; '' for a plain backup. Never logged, never sent anywhere."""

        source = self.source
        if source == "passphrase":
            return self._passphrase
        if source == "key":
            return str((self._state or {})["key"])
        return ""

    def candidates(self) -> list[str]:
        """Every secret a backup of this server may open with, the likeliest first (for a restore)."""

        out: list[str] = []
        for value in (self._passphrase, str((self._state or {}).get("key") or "")):
            if value and value not in out:
                out.append(value)
        return out

    def reveal(self) -> str:
        """The key itself, for the admin who asked to see it; '' when the server has none."""

        return str((self._state or {}).get("key") or "")

    def turn_on(self, *, by: str = "", now: dt.datetime | None = None) -> bool:
        """Turn encryption on (an admin, on an installation whose backups were plain). Makes the key when there is none."""

        state = self._state or {}
        if state.get("mode") == "encrypted" and state.get("key"):
            return False
        at = _now_iso(now)
        self._state = {
            "version": 1,
            **state,
            "mode": "encrypted",
            "turnedOnAt": at,
            "turnedOnBy": by,
            "key": state.get("key") or generate_backup_key(),
            "keyCreatedAt": state.get("keyCreatedAt") or at,
            "savedAt": None,
            "savedBy": "",
        }
        self._save()
        return True

    def confirm_saved(self, *, by: str = "", now: dt.datetime | None = None) -> bool:
        """An admin says they have saved the key somewhere else."""

        if not (self._state or {}).get("key"):
            return False
        self._state = {**(self._state or {}), "savedAt": _now_iso(now), "savedBy": by}
        self._save()
        return True

    def status(self) -> dict[str, Any]:
        """What the page may know (never the key)."""

        source = self.source
        opted_out = encryption_opted_out(self.env)
        state = self._state or {}
        has_key = bool(state.get("key"))
        saved = bool(state.get("savedAt"))
        return {
            "encrypted": source != "none",
            "source": source,
            "optedOut": opted_out,
            "hasKey": has_key,
            "keySaved": saved,
            "keySavedAt": state.get("savedAt"),
            "keySavedBy": state.get("savedBy") or "",
            "keyCreatedAt": state.get("keyCreatedAt"),
            # An admin can turn encryption on from the page: nothing in the environment decides it, and it is off.
            "canTurnOn": source == "none" and not opted_out,
            # What admins are told until they act: the key is in use and nobody confirmed saving it, or backups are
            # plain (not when they are plain on purpose).
            "notice": "save-key" if source == "key" and not saved else "not-encrypted" if source == "none" and not opted_out else None,
        }


__all__ = [
    "ALPHABET",
    "BACKUP_KEY_FILE",
    "BackupKeyStore",
    "SEALED_MAGIC",
    "canonical_backup_key",
    "earlier_state",
    "encryption_opted_out",
    "env_secret",
    "generate_backup_key",
]
