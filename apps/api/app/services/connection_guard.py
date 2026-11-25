"""The last connection settings known to work, so a changed connection that does not work can be put back. Ported
from CxMissionZero's src/connection-guard.js, for Hawk AI's Checkmarx One connectors (the analogue of MZ's
Checkmarx One integration).

Whenever the self-check (app/services/self_check.py) finds a Checkmarx One connector working, its settings become the
"last known good" ones. When a changed connector does not work, the self-check puts the last known good settings back
(once while the problem lasts) and says so in the audit log.

Hawk AI's email server is set in the environment (SMTP_*), not on a page, so there is no mail setting to put back: MZ's
guard for the mail server has nothing to guard here.

Kept in ``connection-guard.json`` in the data folder, owner-readable only. The connector's secrets stay as the
database holds them, encrypted with CONNECTOR_SECRETS_KEY; no copy of the file before is kept.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.services.state_file import read_state, write_state

FILE_NAME = "connection-guard.json"


def _file(data_dir: Path | str | None = None) -> Path:
    return Path(data_dir or settings.hawk_data_dir) / FILE_NAME


def _fingerprint(config: Any, encrypted_secrets: Any) -> str:
    raw = json.dumps({"config": config or {}, "secrets": encrypted_secrets or ""}, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class ConnectionGuard:
    def __init__(self, data_dir: Path | str | None = None) -> None:
        self.file = _file(data_dir)
        raw = read_state(self.file, fallback={}, holds="the last Checkmarx One connector settings known to work")
        self._lkg: dict[str, Any] = dict(raw.get("lkg") or {}) if isinstance(raw, dict) else {}

    def _save(self) -> None:
        write_state(self.file, {"lkg": self._lkg}, keep_last=False)

    def last_good(self, connector_id: str) -> dict[str, Any] | None:
        entry = self._lkg.get(str(connector_id))
        return dict(entry) if isinstance(entry, dict) else None

    def remember(self, connector: Any, now: dt.datetime | None = None) -> None:
        """Remember a connector's settings that just worked."""

        fingerprint = _fingerprint(connector.config, connector.encrypted_secrets)
        entry = self._lkg.get(str(connector.id))
        if isinstance(entry, dict) and entry.get("fingerprint") == fingerprint:
            return
        self._lkg[str(connector.id)] = {
            "fingerprint": fingerprint,
            "config": dict(connector.config or {}),
            "encryptedSecrets": connector.encrypted_secrets or "",
            "at": (now or dt.datetime.now(dt.timezone.utc)).isoformat(timespec="seconds").replace("+00:00", "Z"),
        }
        self._save()

    def pending(self, connector: Any) -> bool:
        """Does the connector hold settings other than the last ones that worked?"""

        entry = self.last_good(connector.id)
        return bool(entry) and entry.get("fingerprint") != _fingerprint(connector.config, connector.encrypted_secrets)

    def put_back(self, connector: Any) -> bool:
        """Put the last known good settings back on the connector (the caller commits). True when something changed."""

        entry = self.last_good(connector.id)
        if not entry or not self.pending(connector):
            return False
        connector.config = dict(entry.get("config") or {})
        connector.encrypted_secrets = entry.get("encryptedSecrets") or None
        return True


__all__ = ["ConnectionGuard", "FILE_NAME"]
