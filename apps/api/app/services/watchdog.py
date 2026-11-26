"""The self-check's bookkeeping, ported from CxMissionZero's src/watchdog.js: which problems are open, since when, what
was tried, when to tell people and when to raise a support case. The checks and the repairs are in
app/services/self_check.py (MZ's src/routes/hands-off.js).

- A problem seen on one check is noted; on the second check in a row the administrators get an email (Hawk AI has
  tried to fix it by then).
- On the third, if auto-update is on and the server reached the internet on its last update check, a support case is
  raised by itself, and the email asks an administrator to forward it to the maintainer.
- A problem that clears is "recovered": whoever was told hears so.
- A version that came in less than a day ago and broke what worked before is put back to the previous version (once),
  when the updater looks after the services. An outage on the far side (5xx, 429, timeouts, unreachable) is not blamed
  on it.

Kept in ``watchdog.json`` in the data folder (HAWK_DATA_DIR), which is in every backup. A file that cannot be read
starts the self-check from nothing, as in MZ: these are its own notes, made again as it runs, and the self-check never
breaks the app.
"""

from __future__ import annotations

import copy
import datetime as dt
import errno
import logging
import socket
import ssl
from pathlib import Path
from typing import Any, Callable

from app.services.state_file import read_state, write_state

#: Every watchdog event (a problem found, a repair tried or that worked, a case raised, a rollback) is also a log line.
logger = logging.getLogger(__name__)
_EVENT_LEVELS = {"problem": logging.WARNING, "tried": logging.WARNING, "rollback": logging.WARNING, "case": logging.WARNING}

NOTIFY_AFTER = 2
CASE_AFTER = 3
EVENTS_KEPT = 200
DAY_SECONDS = 86_400
FILE_NAME = "watchdog.json"


def _iso(now: dt.datetime | None = None) -> str:
    moment = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(value: Any) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def _empty() -> dict[str, Any]:
    return {"problems": {}, "events": [], "healthy": {}, "rolledBack": [], "lastCheckAt": ""}


class Watchdog:
    def __init__(self, *, file: Path | str) -> None:
        self.file = Path(file)
        self._state = self._load()

    def _load(self) -> dict[str, Any]:
        try:
            raw = read_state(self.file, fallback={})
        except Exception:  # noqa: BLE001 - the self-check never breaks the app
            return _empty()
        if not isinstance(raw, dict):
            return _empty()
        return {
            "problems": raw["problems"] if isinstance(raw.get("problems"), dict) else {},
            "events": raw["events"][:EVENTS_KEPT] if isinstance(raw.get("events"), list) else [],
            "healthy": raw["healthy"] if isinstance(raw.get("healthy"), dict) else {},
            "rolledBack": raw["rolledBack"] if isinstance(raw.get("rolledBack"), list) else [],
            "lastCheckAt": str(raw.get("lastCheckAt") or ""),
        }

    def _save(self) -> None:
        try:
            # No last good copy is kept: these notes are made again as the self-check runs (MZ: keepLast false).
            write_state(self.file, self._state, keep_last=False)
        except Exception:  # noqa: BLE001 - the self-check never breaks the app
            pass

    @property
    def state(self) -> dict[str, Any]:
        return copy.deepcopy(self._state)

    def problems(self) -> list[dict[str, Any]]:
        """Open problems, oldest first."""

        return sorted(({"key": k, **copy.deepcopy(p)} for k, p in self._state["problems"].items()), key=lambda p: p["since"])

    def problem(self, key: str) -> dict[str, Any] | None:
        open_ = self._state["problems"].get(key)
        return {"key": key, **copy.deepcopy(open_)} if open_ else None

    def events(self, limit: int = 50) -> list[dict[str, Any]]:
        return copy.deepcopy(self._state["events"][:limit])

    def _event(self, entry: dict[str, Any]) -> None:
        try:
            fields = {"watchdog_event": entry.get("kind"), "problem_key": entry.get("key") or None}
            if entry.get("tenant"):
                fields["tenant_id"] = entry["tenant"]
            logger.log(_EVENT_LEVELS.get(str(entry.get("kind")), logging.INFO), "Watchdog %s: %s", entry.get("kind"), entry.get("message"), extra={k: v for k, v in fields.items() if v})
        except Exception:  # noqa: BLE001 - the log line never stands in the way of the watchdog
            pass
        self._state["events"].insert(0, entry)
        self._state["events"] = self._state["events"][:EVENTS_KEPT]

    def event(self, kind: str, message: str, now: dt.datetime | None = None, **fields: Any) -> None:
        self._event({"at": _iso(now), "kind": kind, "message": message, **fields})
        self._save()

    def record(self, found: list[dict[str, Any]], *, version: str = "", now: dt.datetime | None = None) -> dict[str, list[dict[str, Any]]]:
        """The result of one check: ``found`` is every problem seen now ({key, title, detail, tenant, outside}).
        Returns what changed: {started, continuing, recovered} (each a list of problems)."""

        at = _iso(now)
        seen = {p["key"]: p for p in found}
        started: list[dict[str, Any]] = []
        continuing: list[dict[str, Any]] = []
        recovered: list[dict[str, Any]] = []
        for key in list(self._state["problems"]):
            if key in seen:
                continue
            open_ = self._state["problems"].pop(key)
            recovered.append({"key": key, **open_, "recoveredAt": at})
            self._event({"at": at, "kind": "recovered", "key": key, "message": f"{open_['title']}: working again.", "tenant": open_.get("tenant") or ""})
        for key, p in seen.items():
            open_ = self._state["problems"].get(key)
            if open_:
                open_["checks"] += 1
                open_["lastAt"] = at
                open_["detail"] = p.get("detail") or open_["detail"]
                open_["outside"] = bool(p.get("outside"))
                continuing.append({"key": key, **copy.deepcopy(open_)})
            else:
                self._state["problems"][key] = {
                    "title": p["title"],
                    "detail": p.get("detail") or "",
                    "tenant": p.get("tenant") or "",
                    "outside": bool(p.get("outside")),
                    "since": at,
                    "lastAt": at,
                    "checks": 1,
                    "version": version,
                    "tried": [],
                    "notifiedAt": "",
                    "caseId": "",
                }
                started.append({"key": key, **copy.deepcopy(self._state["problems"][key])})
                self._event({"at": at, "kind": "problem", "key": key, "message": f"{p['title']}: {p.get('detail') or ''}".strip(), "tenant": p.get("tenant") or ""})
        # A version is "healthy" once a whole check passes while it runs.
        if not found and version:
            self._state["healthy"][version] = at
        self._state["lastCheckAt"] = at
        self._save()
        return {"started": started, "continuing": continuing, "recovered": recovered}

    def resolve(self, key: str, now: dt.datetime | None = None) -> None:
        """A problem put right by a repair: closed now, without waiting for the next check."""

        open_ = self._state["problems"].pop(key, None)
        if not open_:
            return
        self._event({"at": _iso(now), "kind": "recovered", "key": key, "message": f"{open_['title']}: fixed by itself.", "tenant": open_.get("tenant") or ""})
        self._save()

    def tried(self, key: str, repair: str, outcome: str, now: dt.datetime | None = None) -> None:
        """Remember a repair that was tried for a problem (each is tried once while it lasts)."""

        open_ = self._state["problems"].get(key)
        if open_ is not None and repair not in open_["tried"]:
            open_["tried"].append(repair)
        self._event({"at": _iso(now), "kind": "healed" if outcome == "fixed" else "tried", "key": key, "message": f"{repair}: {outcome}.", "tenant": (open_ or {}).get("tenant") or ""})
        self._save()

    def has_tried(self, key: str, repair: str) -> bool:
        return repair in ((self._state["problems"].get(key) or {}).get("tried") or [])

    def mark_notified(self, key: str, now: dt.datetime | None = None) -> None:
        if key in self._state["problems"]:
            self._state["problems"][key]["notifiedAt"] = _iso(now)
        self._save()

    def mark_case(self, key: str, case_id: str) -> None:
        if key in self._state["problems"]:
            self._state["problems"][key]["caseId"] = case_id
        self._save()

    def forget_case(self, case_id: str) -> None:
        """Forget a problem's case once it is closed, so a new occurrence raises a new one."""

        for p in self._state["problems"].values():
            if p.get("caseId") == case_id:
                p["caseId"] = ""
        self._save()

    def was_healthy(self, version: str) -> bool:
        return bool(self._state["healthy"].get(version))

    def mark_rolled_back(self, version: str, now: dt.datetime | None = None) -> None:
        self._state["rolledBack"].append({"version": version, "at": _iso(now)})
        self._save()

    def has_rolled_back(self, version: str) -> bool:
        return any(r.get("version") == version for r in self._state["rolledBack"])


#: Errors that say the far side cannot be reached (MZ's OUTSIDE_CODES, as Python sees them).
_OUTSIDE_ERRNOS = {errno.ECONNREFUSED, errno.ECONNRESET, errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH}


def outside_fault(error: BaseException | None) -> bool:
    """Is this error the far side's, whatever version of Hawk AI runs? An answer of 5xx or 429, a timeout, or a host
    that cannot be reached. A 401, 403 or 404 is not: a new version could have broken how it signs in or what it asks."""

    if error is None:
        return False
    status = getattr(error, "http_status", None) or getattr(error, "status_code", None)
    response = getattr(error, "response", None)
    if not status and response is not None:
        status = getattr(response, "status_code", None)
    try:
        status = int(status or 0)
    except (TypeError, ValueError):
        status = 0
    if status >= 500 or status == 429:
        return True
    if getattr(error, "timed_out", False):
        return True
    try:
        import httpx

        if isinstance(error, (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError)):
            return True
    except ImportError:  # pragma: no cover
        pass
    if isinstance(error, ssl.SSLError):
        return False
    if isinstance(error, (TimeoutError, socket.timeout, socket.gaierror, ConnectionRefusedError, ConnectionResetError)):
        return True
    if isinstance(error, OSError) and error.errno in _OUTSIDE_ERRNOS:
        return True
    cause = error.__cause__ or error.__context__
    return outside_fault(cause) if cause is not None and cause is not error else False


def should_notify(p: dict[str, Any]) -> bool:
    """Tell the administrators about this problem now?"""

    return p["checks"] >= NOTIFY_AFTER and not p.get("notifiedAt")


def should_raise_case(p: dict[str, Any], *, auto_update: bool, online: bool) -> bool:
    """Raise a support case for it now? Only with auto-update on and the internet reachable."""

    return p["checks"] >= CASE_AFTER and not p.get("caseId") and bool(auto_update) and bool(online)


def rollback_target(
    *,
    problems: list[dict[str, Any]],
    running: str,
    previous: str,
    switched_at: str,
    was_healthy: Callable[[str], bool],
    has_rolled_back: Callable[[str], bool],
    now: dt.datetime | None = None,
) -> str:
    """The version to go back to, or '': the running version came in less than a day ago, a problem started after it
    did, the previous version passed a whole check, and this version was not rolled back from before. A problem on the
    far side (answering 5xx or 429, timing out or out of reach) never counts: going back a version cannot fix it."""

    if not previous or not switched_at or previous == running or has_rolled_back(running):
        return ""
    since = parse_iso(switched_at)
    if since is None:
        return ""
    now = now or dt.datetime.now(dt.timezone.utc)
    if (now - since).total_seconds() > DAY_SECONDS:
        return ""
    after = [p for p in problems if p["checks"] >= NOTIFY_AFTER and not p.get("outside") and (parse_iso(p["since"]) or since) >= since]
    return previous if after and was_healthy(previous) else ""


__all__ = [
    "CASE_AFTER",
    "FILE_NAME",
    "NOTIFY_AFTER",
    "Watchdog",
    "outside_fault",
    "parse_iso",
    "rollback_target",
    "should_notify",
    "should_raise_case",
]
