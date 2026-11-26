"""Is the code running here exactly what this repository's release workflow built? Ported from CxMissionZero's
src/integrity/service.js.

- Files: every file of the running image against the file list the build wrote (integrity.json); a changed, missing
  or added file is found at once, with no network.
- Origin: GitHub's build attestation of that file list (signed by the release workflow with Sigstore, recorded in its
  public log) is fetched from api.github.com and checked here (sigstore.py). Once confirmed for a file list, that
  answer is kept in the data folder (integrity-origin.json), so a server without internet still knows after a restart.

Checked at start and every INTEGRITY_CHECK_HOURS (6), on "Check now", and before an update is installed. States:
genuine, tampered (files differ), not-genuine (no valid signature for the file list), unconfirmed (files match; GitHub
could not be asked yet), unsigned (no file list: a development copy, built from this checkout rather than by the
release workflow).

Hawk AI runs several processes from the api image (api, worker, beat): the last result is kept in the data folder
(integrity-last.json), so the page, the worker's scheduled check and the check before an update see the same one.
The same verify_origin() checks the attestation of an image digest before an update (app/services/updates/).
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import logging
import os
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.services.integrity.manifest import compare_files, read_manifest
from app.services.integrity.sigstore import RELEASE_REFS, RELEASE_WORKFLOW, verify_bundle
from app.version import VERSION_FILE, display_version

log = logging.getLogger("hawk.integrity")

#: The repository whose release workflow builds Hawk AI (github.com/cxsmtp/hk).
SOURCE_REPOSITORY = "cxsmtp/hk"
API = "https://api.github.com"
TRUSTED_ROOT_FILE = Path(__file__).with_name("trusted_root.json")
ORIGIN_FILE = "integrity-origin.json"
LAST_FILE = "integrity-last.json"
FIRST = 20
STATES = ("genuine", "tampered", "not-genuine", "unconfirmed", "unsigned")
#: The states owners and admins are alerted to (CxMissionZero: changed or unsigned).
ALERT_STATES = ("tampered", "not-genuine")

Record = Callable[..., None]


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def app_root() -> Path:
    """Where the running image's files and its integrity.json are: /workspace in the api image, the repository root in
    a checkout (which has no file list: a development copy)."""

    return Path(os.environ.get("HAWK_INTEGRITY_ROOT") or VERSION_FILE.parent)


def _production() -> bool:
    from app.core.config import settings

    env = str(settings.env or "").strip().lower()
    return env in {"prod", "production"} or settings.deployment_topology == "single_node_compose"


def offline_allowed() -> bool:
    """INTEGRITY_OFFLINE=allow: a server that cannot reach api.github.com installs with the file check alone."""

    return str(os.environ.get("INTEGRITY_OFFLINE") or "").strip().lower() == "allow"


def check_hours() -> float:
    try:
        return max(0.1, float(os.environ.get("INTEGRITY_CHECK_HOURS") or 6))
    except ValueError:
        return 6.0


def trusted_root() -> dict[str, Any]:
    # Tests only (never in production): another trust root, as the JSON itself (nothing is read from a path it names).
    test_root = os.environ.get("HAWK_INTEGRITY_TRUST_ROOT")
    if test_root and not _production():
        return json.loads(test_root)
    return json.loads(TRUSTED_ROOT_FILE.read_text(encoding="utf-8"))


def outbound_url_problem(url: str, *, allow_loopback_http: bool = False) -> str:
    """An address from GitHub's answer is called only over https (plain http to this machine in tests), and never a
    link-local or cloud metadata address (CxMissionZero's src/outbound-url.js, for this one use)."""

    try:
        parts = urlsplit(url)
    except ValueError:
        return "is not an address"
    host = (parts.hostname or "").lower()
    if not host:
        return "has no host"
    loopback = host in {"localhost", "127.0.0.1", "::1"}
    if parts.scheme != "https" and not (allow_loopback_http and loopback and parts.scheme == "http"):
        return "is not https"
    try:
        address = ipaddress.ip_address(host)
        if address.is_link_local or str(address) in {"169.254.169.254", "fd00:ec2::254"}:
            return "is a link-local or cloud metadata address"
    except ValueError:
        if host in {"metadata.google.internal", "metadata"}:
            return "is a cloud metadata address"
    return ""


def _trim(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": result["ok"],
        "checked": result["checked"],
        "changed": result["changed"][:FIRST],
        "missing": result["missing"][:FIRST],
        "extra": result["extra"][:FIRST],
        "counts": {"changed": len(result["changed"]), "missing": len(result["missing"]), "extra": len(result["extra"])},
    }


def _read_json(file: Path) -> Any:
    try:
        return json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _write_json(file: Path, value: Any) -> None:
    try:
        file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temp = file.with_name(f".{file.name}.{os.getpid()}.tmp")
        temp.write_text(json.dumps(value), encoding="utf-8")
        os.chmod(temp, 0o600)
        os.replace(temp, file)
    except OSError as error:
        log.warning("[integrity] Could not write %s: %s", file, error)


def audit_system(action: str, reason: str, *, outcome: str = "info", details: dict[str, Any] | None = None, actor: str = "Hawk AI", actor_user_id: str | None = None) -> None:
    """An entry of type "Updates & system" in the audit log (CxMissionZero's audit type "system")."""

    try:
        from app.db.session import SessionLocal
        from app.services.audit_service import write_audit_log

        with SessionLocal() as db:
            write_audit_log(
                db,
                tenant_id=None,
                actor_user_id=actor_user_id,
                actor_type="human" if actor_user_id else "system",
                action=action,
                resource_type="system",
                resource_id="updates",
                payload={"outcome": outcome, "reason": reason, "actor_id": actor, "type": "Updates & system", **({"details": details} if details else {})},
            )
            db.commit()
    except Exception as error:  # noqa: BLE001 - never in the way of the check or the update itself
        log.warning("[integrity] Could not write to the audit log: %s", error)


class IntegrityService:
    def __init__(
        self,
        *,
        app_dir: str | Path | None = None,
        data_dir: str | Path | None = None,
        repository: str | None = None,
        client: httpx.Client | None = None,
        token: str | None = None,
        record: Record | None = None,
        trusted: dict[str, Any] | None = None,
        api: str | None = None,
        timeout: float = 15.0,
        workflow: str = RELEASE_WORKFLOW,
        refs=RELEASE_REFS,
    ) -> None:
        testing = not _production()
        self.app_dir = Path(app_dir) if app_dir else app_root()
        self.data_dir = Path(data_dir or os.environ.get("HAWK_DATA_DIR") or "/data")
        self.repository = repository or (os.environ.get("HAWK_SOURCE_REPOSITORY") if testing else None) or SOURCE_REPOSITORY
        self.api = (api or (os.environ.get("HAWK_INTEGRITY_API") if testing else None) or API).rstrip("/")
        self.client = client
        self.token = token if token is not None else str(os.environ.get("GITHUB_TOKEN") or "").strip()
        self.record = record or self._record
        self._trusted = trusted
        self.timeout = timeout
        self.workflow = workflow
        self.refs = refs
        self._testing = testing
        self._lock = threading.Lock()

    # ---- Where results are kept ----------------------------------------------------------------------------------

    @property
    def trusted(self) -> dict[str, Any]:
        if self._trusted is None:
            self._trusted = trusted_root()
        return self._trusted

    @property
    def last(self) -> dict[str, Any] | None:
        value = _read_json(self.data_dir / LAST_FILE)
        return value if isinstance(value, dict) and value.get("state") in STATES else None

    def _cached(self, digest: str) -> dict[str, Any] | None:
        value = _read_json(self.data_dir / ORIGIN_FILE)
        entry = value.get(digest) if isinstance(value, dict) else None
        return entry if isinstance(entry, dict) and entry.get("ok") else None

    def _remember(self, digest: str, result: dict[str, Any]) -> None:
        value = _read_json(self.data_dir / ORIGIN_FILE)
        kept = value if isinstance(value, dict) else {}
        kept[digest] = result
        _write_json(self.data_dir / ORIGIN_FILE, dict(list(kept.items())[-20:]))

    # ---- GitHub's attestations -----------------------------------------------------------------------------------

    def _get(self, url: str, headers: dict[str, str]) -> httpx.Response:
        if self.client is not None:
            return self.client.get(url, headers=headers, timeout=self.timeout)
        with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
            return client.get(url, headers=headers)

    def verify_origin(self, digest: str) -> dict[str, Any]:
        """GitHub's attestations of a file list or an image (by its SHA-256), each checked; the first good one wins."""

        cached = self._cached(digest)
        if cached:
            return {**cached, "cached": True}
        url = f"{self.api}/repos/{self.repository}/attestations/sha256:{digest}"
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "hawk-ai-integrity"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            response = self._get(url, headers)
        except httpx.HTTPError as error:
            return {"ok": False, "reachable": False, "reason": f"GitHub could not be reached ({type(error).__name__}: {error})"}
        if response.status_code == 404:
            return {"ok": False, "reachable": True, "reason": "GitHub has no build attestation for this file list"}
        if response.status_code >= 400:
            return {"ok": False, "reachable": False, "reason": f"GitHub answered {response.status_code}"}
        try:
            body = response.json()
        except ValueError:
            body = {}
        first_reason = ""
        for item in (body.get("attestations") if isinstance(body, dict) else None) or []:
            bundle = item.get("bundle") if isinstance(item, dict) else None
            if not bundle and isinstance(item, dict) and item.get("bundle_url"):
                bundle = self._download(item["bundle_url"])
            if not bundle:
                continue
            result = verify_bundle(bundle, digest=digest, trusted_root=self.trusted, repository=self.repository, workflow=self.workflow, refs=self.refs)
            if result.get("ok"):
                self._remember(digest, result)
                return result
            first_reason = first_reason or str(result.get("reason") or "")
        return {"ok": False, "reachable": True, "reason": first_reason or "GitHub has no build attestation for this file list"}

    def _download(self, url: Any) -> Any:
        # The address comes from GitHub's answer: https (a local mock only in tests), never a link-local or metadata one.
        if not isinstance(url, str) or outbound_url_problem(url, allow_loopback_http=self._testing):
            return None
        try:
            response = self._get(url, {"User-Agent": "hawk-ai-integrity"})
            return response.json() if response.status_code < 400 else None
        except (httpx.HTTPError, ValueError):
            return None

    # ---- The check -----------------------------------------------------------------------------------------------

    def check(self, *, reason: str = "scheduled") -> dict[str, Any]:
        """Files and origin of the running image. One check at a time in a process; the result is kept for all."""

        with self._lock:
            return self._check(reason)

    def _check(self, reason: str) -> dict[str, Any]:
        at = now_iso()
        read = read_manifest(self.app_dir)
        if read is None:
            result: dict[str, Any] = {
                "at": at,
                "state": "unsigned",
                "summary": "No signed file list: this copy was not built by the release workflow (a development copy, built from the source).",
            }
        elif read.get("error"):
            result = {"at": at, "state": "tampered", "digest": read["digest"], "summary": read["error"]}
        else:
            manifest = read["manifest"]
            files = _trim(compare_files(self.app_dir, manifest))
            origin = self.verify_origin(read["digest"])
            base = {"at": at, "version": manifest.get("version") or "", "commit": manifest.get("commit") or "", "image": manifest.get("image") or "", "digest": read["digest"], "files": files, "origin": origin}
            if not files["ok"]:
                counts = files["counts"]
                n = counts["changed"] + counts["missing"] + counts["extra"]
                result = {**base, "state": "tampered", "summary": f"{'1 file differs' if n == 1 else f'{n} files differ'} from what the release workflow built ({counts['changed']} changed, {counts['missing']} missing, {counts['extra']} added)."}
            elif origin.get("ok"):
                ref = str(origin.get("ref") or "")
                for prefix in ("refs/heads/", "refs/tags/"):
                    ref = ref.removeprefix(prefix)
                signed = str(origin.get("signedAt") or "")[:16].replace("T", " ")
                result = {**base, "state": "genuine", "summary": f"Genuine: all {files['checked']} files are exactly what {origin.get('repository')}'s release workflow built from {ref} (commit {str(origin.get('commit') or '')[:12]}), signed {signed} UTC and recorded in Sigstore's public log."}
            elif origin.get("reachable") is False:
                result = {**base, "state": "unconfirmed", "summary": f"All {files['checked']} files match their list; who built it is not confirmed yet: {origin.get('reason')}."}
            else:
                result = {**base, "state": "not-genuine", "summary": f"The files match their list, but the list is not signed by {self.repository}'s release workflow: {origin.get('reason')}."}
        before = (self.last or {}).get("state")
        result = {**result, "reason": reason, "repository": self.repository}
        fields = {"state": result["state"], "check_reason": reason, "previous_state": before or None, "version": result.get("version") or None}
        if result["state"] in ALERT_STATES:
            log.error("Software integrity check: %s", result["state"], extra=fields)
        elif result["state"] == "genuine":
            log.info("Software integrity check: genuine", extra=fields)
        else:
            log.warning("Software integrity check: %s", result["state"], extra=fields)
        _write_json(self.data_dir / LAST_FILE, result)
        if result["state"] != before and result["state"] in ALERT_STATES:
            self.record(outcome="failure", reason=f"Software integrity: {result['summary']}", details={"state": result["state"], "digest": result.get("digest"), "files": result.get("files")})
        elif result["state"] == "genuine" and before != "genuine":
            self.record(outcome="info", reason=f"Software integrity: {result['summary']}", details={"state": result["state"], "digest": result.get("digest"), "commit": (result.get("origin") or {}).get("commit")})
        return result

    @staticmethod
    def _record(*, outcome: str, reason: str, details: dict[str, Any] | None = None) -> None:
        if outcome == "failure":
            print(f"! [integrity] {reason}", flush=True)
        audit_system("integrity.checked", reason, outcome=outcome, details=details)

    # ---- What owners and admins are told ---------------------------------------------------------------------------

    def notice(self) -> dict[str, Any] | None:
        last = self.last
        if last and last.get("state") in ALERT_STATES:
            return {"state": last["state"], "summary": last.get("summary") or ""}
        return None


def is_release(root: str | Path | None = None) -> bool:
    """A release image carries the list of its files (integrity.json); a development copy does not (CxMissionZero's
    RELEASE in src/activation.js)."""

    return (Path(root) if root else app_root()).joinpath("integrity.json").is_file()


def label(version: str) -> str:
    return display_version(version) if version else "—"


_timer: threading.Timer | None = None


def start_in_background(service: IntegrityService | None = None, *, first_after: float = 5.0) -> None:
    """The API's own check, a few seconds after it starts (the 6-hourly one is a beat task: app/jobs/update_jobs.py)."""

    global _timer

    def run() -> None:
        try:
            (service or IntegrityService()).check(reason="start")
        except Exception as error:  # noqa: BLE001 - a failed check never stops the API
            log.warning("[integrity] The check at start failed: %s", error)

    _timer = threading.Timer(first_after, run)
    _timer.daemon = True
    _timer.start()
