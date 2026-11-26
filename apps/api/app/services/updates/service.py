"""Settings → Updates: everything an owner or admin needs after deployment without signing in to the server. Ported
from CxMissionZero's src/updates/service.js, for Hawk AI's several images and its updater (app/services/updates/
companion.py, apps/updater):

- Check: the versions published for Hawk AI's images (every release, newest first), from the registry's tags, with no
  cap. Version tags never move, so what one check reads is remembered: the next check reads only new tags, ``latest``
  and ``stable``.
- Install any of them, newer or older, in one click: the images' digests are read from the registry and their build
  attestations checked (only what the release workflow built and signed is installed), then the updater takes a
  backup, pulls, migrates, recreates the services in order and rolls back by itself if they do not come up.
- Auto-update (off until an owner or admin turns it on): a minute after start, then every AUTO_UPDATE_EVERY_SECONDS
  (900), it looks for a newer release on the channel chosen (``latest`` or ``stable``) and installs it, in an optional
  hour of the day in the server's time zone, never one that already failed to start.
- Restart, and a troubleshooting report.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
from pathlib import Path
from typing import Any, Callable
from zoneinfo import ZoneInfo

import logging

import httpx

from app.services.integrity.service import IntegrityService, audit_system, offline_allowed
from app.services.updates import companion
from app.services.updates.registry import DEFAULT_IMAGE, ImageRegistry, UpdateError, parse_image
from app.version import PACKAGE_VERSION, display_version

VERSION = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")
#: What may be installed: a version, latest, stable or a commit tag (CxMissionZero's TAG, with the stable channel).
INSTALLABLE = re.compile(r"^(?:\d{1,4}\.\d{1,4}\.\d{1,4}|latest|stable|sha-[0-9a-f]{7,40})$")
IMAGES = ("api", "web", "proxy")
CHANNELS = ("latest", "stable")
VERSION_LABEL = "org.opencontainers.image.version"
#: Registry reads a check may make for tags it has not seen before; the rest follow on the next check.
NEW_READS_PER_CHECK = 150
SETTINGS_FILE = "update-settings.json"
CACHE_FILE = "update-published.json"
#: Outside its hour, auto-update still looks at most this often, so the page can say what is waiting.
LOOK_OUTSIDE_HOUR_SECONDS = 55 * 60

Record = Callable[..., None]

logger = logging.getLogger(__name__)


def compare_versions(a: str, b: str) -> int:
    """-1, 0 or 1, comparing "1.0.27"-style versions."""

    def parts(v: str) -> list[int]:
        out = []
        for p in str(v).split(".")[:3]:
            try:
                out.append(int(p))
            except ValueError:
                out.append(0)
        return out + [0] * (3 - len(out))

    pa, pb = parts(a), parts(b)
    return (pa > pb) - (pa < pb)


def _read(file: Path, fallback: Any) -> Any:
    try:
        return json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return fallback


def _write(file: Path, value: Any) -> None:
    file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = file.with_name(f".{file.name}.{os.getpid()}.tmp")
    temp.write_text(json.dumps(value, indent=2), encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, file)


def _iso(now: dt.datetime) -> str:
    return now.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse(iso: Any) -> dt.datetime | None:
    try:
        return dt.datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return None


def server_zone() -> dt.tzinfo:
    """The server's time zone (TZ on the containers, deploy/.env): the install hour is in it."""

    name = str(os.environ.get("TZ") or "").strip()
    if name:
        try:
            return ZoneInfo(name)
        except Exception:  # noqa: BLE001 - an unknown zone falls back to the system's
            pass
    return dt.datetime.now().astimezone().tzinfo or dt.timezone.utc


def zone_name(zone: dt.tzinfo) -> str:
    return getattr(zone, "key", None) or dt.datetime.now(zone).tzname() or "server time"


def oneline(text: Any) -> str:
    """Text for the audit log on one line: no line breaks or control characters to forge another entry with."""

    return re.sub(r"[\u0000-\u001f\u007f  ]+", " ", str(text or ""))[:2000]


class UpdateService:
    def __init__(
        self,
        *,
        running_version: str = PACKAGE_VERSION,
        image: str | None = None,
        token: str | None = None,
        client: httpx.Client | None = None,
        arch: str | None = None,
        data_dir: str | Path | None = None,
        updater: str | Path | None = None,
        integrity: IntegrityService | None = None,
        record: Record | None = None,
        offline: bool | None = None,
        zone: dt.tzinfo | None = None,
    ) -> None:
        self.running_version = running_version
        prefix = str(image or os.environ.get("UPDATE_IMAGE") or DEFAULT_IMAGE).strip()
        registry, repository = parse_image(prefix)
        self.image = f"{registry}/{repository}"
        self.token = token if token is not None else str(os.environ.get("UPDATE_REGISTRY_TOKEN") or "").strip()
        self.client = client
        self.arch = arch
        self.data_dir = Path(data_dir or os.environ.get("HAWK_DATA_DIR") or "/data")
        self.updater = Path(updater) if updater else companion.updater_dir()
        self.integrity = integrity or IntegrityService(data_dir=self.data_dir, client=client)
        self.record = record or self._record
        self.offline = offline_allowed() if offline is None else offline
        self.zone = zone or server_zone()
        self.last_check = _read(self.data_dir / CACHE_FILE, None)

    def images(self) -> dict[str, str]:
        return {kind: f"{self.image}-{kind}" for kind in IMAGES}

    def registry(self, kind: str = "api") -> ImageRegistry:
        return ImageRegistry(self.images()[kind], token=self.token, client=self.client, arch=self.arch)

    # ---- Settings ----------------------------------------------------------------------------------------------------

    def settings(self) -> dict[str, Any]:
        s = _read(self.data_dir / SETTINGS_FILE, {})
        s = s if isinstance(s, dict) else {}
        hour = s.get("windowHour")
        return {
            "auto": s.get("auto") is True,
            "windowHour": hour if isinstance(hour, int) and not isinstance(hour, bool) and 0 <= hour <= 23 else None,
            "channel": s.get("channel") if s.get("channel") in CHANNELS else "latest",
            "lastAutoAt": s.get("lastAutoAt"),
            "lastAutoResult": s.get("lastAutoResult") or "",
        }

    def save_settings(self, patch: dict[str, Any]) -> dict[str, Any]:
        merged = {**self.settings(), **patch}
        _write(self.data_dir / SETTINGS_FILE, merged)
        return self.settings()

    # ---- What the page shows -------------------------------------------------------------------------------------------

    def failed_versions(self) -> set[str]:
        """Versions that did not come up (the updater rolled them back): never installed automatically again."""

        return {str(e.get("to")) for e in companion.events(self.updater, 500) if e.get("type") == "rolled-back" and e.get("to")}

    def channel_version(self, channel: str) -> dict[str, Any] | None:
        """The newest version on a channel: ``latest`` the newest release, ``stable`` the one the maintainer promoted."""

        versions = (self.last_check or {}).get("versions") or []
        if channel == "stable":
            return next((v for v in versions if "stable" in (v.get("tags") or [])), None)
        return versions[0] if versions else None

    def status(self) -> dict[str, Any]:
        settings = self.settings()
        latest = self.channel_version(settings["channel"])
        check = self.last_check
        now = dt.datetime.now(self.zone)
        return {
            "image": self.image,
            "images": self.images(),
            "running": {"version": self.running_version, "label": display_version(self.running_version)},
            "updater": companion.companion_state(self.updater),
            "events": companion.events(self.updater, 30),
            "lastCheck": {"at": check.get("at"), "error": check.get("error") or "", "warning": check.get("warning") or "", "versions": check.get("versions") or []} if isinstance(check, dict) else None,
            "updateAvailable": bool(latest and compare_versions(latest["version"], self.running_version) > 0),
            "latest": latest,
            "settings": settings,
            "failed": sorted(self.failed_versions()),
            "offline": self.offline,
            # The hour auto-update waits for is the server's: say which zone that is, and its time now.
            "serverTime": {"zone": zone_name(self.zone), "hour": now.hour, "minute": now.minute},
        }

    # ---- Check ---------------------------------------------------------------------------------------------------------

    def check(self) -> dict[str, Any]:
        """The versions published for Hawk AI's images: each version tag's build, newest first, one row per version, with
        which one ``latest`` and ``stable`` point at."""

        registry = self.registry("api")
        previous = self.last_check if isinstance(self.last_check, dict) else {}
        try:
            tags = registry.tags()
            version_tags = sorted((t for t in tags if VERSION.match(t)), key=lambda t: [int(n) for n in t.split(".")], reverse=True)
            channels = [t for t in CHANNELS if t in tags]
            wanted = [*version_tags, *channels]
            # Version tags never move: what was read once is kept. Only latest and stable are read every time.
            remembered = previous.get("byTag") or {}
            known = {v.get("digest"): v for v in previous.get("versions") or [] if v.get("digest")}
            by_tag: dict[str, dict[str, Any]] = {}
            problems: list[str] = []
            files_error = ""
            reads = 0
            for tag in wanted:
                kept = remembered.get(tag) if tag not in CHANNELS else None
                if kept and kept.get("digest"):
                    by_tag[tag] = kept
                    continue
                if reads >= NEW_READS_PER_CHECK:
                    continue
                reads += 1
                try:
                    digest = registry.manifest(tag)["digest"]
                except UpdateError as error:
                    problems.append(str(error))
                    continue
                cached = known.get(digest) or {}
                by_tag[tag] = {"digest": digest, "version": tag if VERSION.match(tag) else cached.get("version", ""), "created": cached.get("created", ""), "revision": cached.get("revision", "")}
            version_of = {by_tag[t]["digest"]: t for t in version_tags if t in by_tag}
            # The build date and commit are in the image's configuration. One failed read is enough: the rest would fail
            # the same way (ghcr.io serves it from pkg-containers.githubusercontent.com).
            for tag in wanted:
                entry = by_tag.get(tag)
                if not entry or files_error:
                    continue
                entry["version"] = entry.get("version") or version_of.get(entry["digest"], "")
                if entry["version"] and entry.get("created"):
                    continue
                if reads >= NEW_READS_PER_CHECK and tag not in remembered:
                    continue
                reads += 1
                try:
                    image = registry.image(entry["digest"])
                except UpdateError as error:
                    files_error = str(error)
                    continue
                if not VERSION.match(entry.get("version") or ""):
                    entry["version"] = str(image["labels"].get(VERSION_LABEL) or "")
                entry["created"] = image["created"]
                entry["revision"] = str(image["labels"].get("org.opencontainers.image.revision") or "")[:12]
            by_version: dict[str, dict[str, Any]] = {}
            for tag in wanted:
                entry = by_tag.get(tag)
                if not entry:
                    continue
                entry["version"] = entry.get("version") or version_of.get(entry["digest"], "")
                if not VERSION.match(entry["version"]):
                    continue
                row = by_version.setdefault(entry["version"], {"version": entry["version"], "label": display_version(entry["version"]), "digest": entry["digest"], "created": entry.get("created", ""), "revision": entry.get("revision", ""), "tags": []})
                row["created"] = row["created"] or entry.get("created", "")
                row["revision"] = row["revision"] or entry.get("revision", "")
                row["tags"].append(tag)
            versions = sorted(by_version.values(), key=lambda r: [int(n) for n in r["version"].split(".")], reverse=True)
            unread = len([t for t in wanted if t not in by_tag])
            error = ""
            if not versions:
                error = files_error or (problems[0] if problems else "") or ("No published version could be read." if tags else "No versions are published for this image.")
            warning = " ".join(
                w
                for w in (
                    f"The versions are listed, but this server could not read the image files: {files_error} Installing needs that; until then, update with deploy/install.sh." if versions and files_error else "",
                    f"{unread} older build(s) are still to be read: Check for updates again to list them." if versions and unread else "",
                )
                if w
            )
            self.last_check = {
                "at": _iso(dt.datetime.now(dt.timezone.utc)),
                "versions": versions,
                "byTag": {t: e for t, e in by_tag.items() if t not in CHANNELS and e.get("version")},
                # Installing needs the image files: auto-update waits while they cannot be read.
                "filesError": files_error,
                # Nothing found is never "up to date": it says why.
                "error": error,
                "warning": warning,
            }
            if error:
                logger.warning("Update check: %s", error)
            else:
                logger.info("Update check: %d version(s) published, newest %s", len(versions), versions[0]["version"], extra={"running_version": self.running_version})
        except UpdateError as error:
            logger.warning("Update check failed: %s", error)
            self.last_check = {**(previous or {"versions": []}), "at": _iso(dt.datetime.now(dt.timezone.utc)), "error": str(error)}
        try:
            _write(self.data_dir / CACHE_FILE, self.last_check)
        except OSError:
            pass
        return self.status()

    # ---- Install -------------------------------------------------------------------------------------------------------

    def resolve(self, ref: str) -> dict[str, Any]:
        """The digests of ``ref`` for every image, and its version, from the registry."""

        digests = {kind: self.registry(kind).manifest(ref)["digest"] for kind in IMAGES}
        version = ref if VERSION.match(ref) else ""
        if not version:
            row = next((v for v in (self.last_check or {}).get("versions") or [] if v.get("digest") == digests["api"]), None)
            version = row["version"] if row else ""
        if not version:
            labels = self.registry("api").image(digests["api"])["labels"]
            version = str(labels.get(VERSION_LABEL) or "")
        if not VERSION.match(version):
            raise UpdateError(f"{ref} names no version Hawk AI can read.", 422)
        return {"version": version, "digests": digests, "images": {kind: f"{self.images()[kind]}@{digests[kind]}" for kind in IMAGES}}

    def genuine(self, digests: dict[str, str], version: str) -> str:
        """Every image's build attestation checked: anything not signed by the release workflow is refused.
        INTEGRITY_OFFLINE=allow accepts the images when GitHub cannot be reached to confirm who signed them (the updater
        still checks the new api image's files against their list)."""

        notes = []
        for kind, digest in digests.items():
            digest_hex = digest.split(":", 1)[1]
            origin = self.integrity.verify_origin(digest_hex)
            if origin.get("ok"):
                notes.append(kind)
                continue
            if origin.get("reachable") is False and self.offline:
                return f"who built it was not confirmed ({origin.get('reason')}; INTEGRITY_OFFLINE=allow)"
            hint = " Allow api.github.com over HTTPS, or set INTEGRITY_OFFLINE=allow to rely on the file check alone." if origin.get("reachable") is False else ""
            raise UpdateError(f"{display_version(version)} ({kind}) is not confirmed as built by the release workflow: {origin.get('reason')}.{hint}", 422)
        return "every image signed by the release workflow"

    def install(self, ref: str, *, by: str = "", automatic: bool = False) -> dict[str, Any]:
        """Check, then ask the updater to install ``ref`` (newer or older). The updater does the rest."""

        ref = str(ref or "").strip()
        if not INSTALLABLE.match(ref):
            raise UpdateError("Choose a version: a version (like 0.2.0), latest, stable or a commit tag.", 400)
        state = companion.companion_state(self.updater)
        if state["busy"]:
            raise UpdateError("An update is already under way.", 409)
        if not state["connected"]:
            raise UpdateError("The updater is not running: updates from this page need it (deploy/README.md: Updates). Update with deploy/install.sh meanwhile.", 409)
        if not state["manages"]:
            raise UpdateError(f"The updater cannot update this installation: {(state['heartbeat'] or {}).get('engineError') or 'it does not look after Hawk AI yet'}", 409)
        try:
            # Before an install, the running image is checked again (CxMissionZero: "before install or switch").
            self.integrity.check(reason="before an update")
        except Exception:  # noqa: BLE001 - the check is recorded; it never holds up an install of a genuine version
            pass
        target = self.resolve(ref)
        genuine = self.genuine(target["digests"], target["version"])
        try:
            sent = companion.request(self.updater, {"action": "update", "tag": ref, "version": target["version"], "images": target["images"], "by": by, "automatic": automatic})
        except companion.UpdaterUnavailable as error:
            raise UpdateError(str(error), 409) from error
        going = "back" if compare_versions(target["version"], self.running_version) < 0 else "to"
        logger.info(
            "Update to %s asked of the updater",
            target["version"],
            extra={"running_version": self.running_version, "tag": ref, "automatic": automatic, "update_request_id": sent.get("id")},
        )
        self.record(
            outcome="changed",
            reason=oneline(f"Update {'back ' if going == 'back' else ''}to {display_version(target['version'])} asked of the updater ({ref}; {genuine}){' automatically' if automatic else ''}."),
            by=by,
            details={"version": target["version"], "tag": ref, "images": target["images"], "id": sent["id"]},
        )
        return {"requested": sent, "version": target["version"]}

    def restart(self, *, by: str = "") -> dict[str, Any]:
        try:
            sent = companion.request(self.updater, {"action": "restart", "by": by})
        except companion.UpdaterUnavailable as error:
            raise UpdateError(str(error), 409) from error
        logger.info("Restart asked of the updater", extra={"update_request_id": sent.get("id")})
        self.record(outcome="changed", reason="Hawk AI restarted from Settings → Updates.", by=by, details={"id": sent["id"]})
        return {"restarting": True}

    # ---- Auto-update ---------------------------------------------------------------------------------------------------

    def auto_update(self, now: dt.datetime | None = None) -> dict[str, Any] | None:
        """Install the newest version on the chosen channel when it is newer, in the chosen hour, never one that failed.
        Every look leaves a line on the page saying what it found and, when it waits, what for and until when."""

        now = now or dt.datetime.now(dt.timezone.utc)
        settings = self.settings()
        if not settings["auto"]:
            return None

        def say(result: str) -> None:
            logger.info("Auto-update: %s", result)
            self.save_settings({"lastAutoAt": _iso(now), "lastAutoResult": result})

        # The updater's heartbeat is fresh or not now, whatever moment this look is for.
        state = companion.companion_state(self.updater)
        if not state["connected"] or not state["manages"]:
            why = (state["heartbeat"] or {}).get("engineError") if state["connected"] else "the updater is not running"
            say(f"Cannot install: {why or 'the updater does not look after Hawk AI yet'}. Update with deploy/install.sh")
            return None
        # A job that never finished does not block auto-update for ever.
        if state["busy"]:
            return None
        local = now.astimezone(self.zone)
        in_window = settings["windowHour"] is None or local.hour == settings["windowHour"]
        last = _parse(settings["lastAutoAt"])
        if not in_window and last and (now - last).total_seconds() < LOOK_OUTSIDE_HOUR_SECONDS:
            return None
        self.check()
        failed = self.failed_versions()
        channel = settings["channel"]
        if channel == "stable":
            stable = self.channel_version("stable")
            candidates = [stable] if stable else []
        else:
            candidates = (self.last_check or {}).get("versions") or []
        candidate = next((v for v in candidates if compare_versions(v["version"], self.running_version) > 0 and v["version"] not in failed), None)
        if not candidate:
            error = (self.last_check or {}).get("error")
            say(f"Check failed: {error}" if error else "Up to date" if channel == "latest" else "Up to date with stable")
            return None
        label = display_version(candidate["version"])
        if (self.last_check or {}).get("filesError"):
            # It would fail the same way every 15 minutes: wait, and say why.
            say(f"{label} is published, but this server cannot download it: {self.last_check['filesError']}")
            return None
        if not in_window:
            say(f"{label} is ready: it installs at {settings['windowHour']:02d}:00 ({zone_name(self.zone)}), or use Update now")
            return None
        say(f"Installing {label}")
        try:
            return self.install(candidate["version"], by="auto-update", automatic=True)
        except UpdateError as error:
            say(f"{label} was not installed: {error}")
            return None

    @staticmethod
    def _record(*, outcome: str, reason: str, by: str = "", details: dict[str, Any] | None = None) -> None:
        audit_system("updates.changed" if outcome == "changed" else "updates.failed" if outcome == "failure" else "updates.info", reason, outcome=outcome, details=details, actor=by or "Hawk AI")
