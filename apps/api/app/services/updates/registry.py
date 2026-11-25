"""Reading Hawk AI's own images from their registry, for Settings → Updates (ported from CxMissionZero's
src/updates/registry.js). Only the registry's answers are read here: the tags, each tag's digest, and the image's
configuration (its version, build date and commit). Pulling is the container engine's, through the updater.

Everything is content-addressed: a blob is checked against its sha256 digest before it is used.
"""

from __future__ import annotations

import base64
import hashlib
import json
import platform
import re
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx

from app.services.integrity.service import outbound_url_problem

#: Where Hawk AI's images come from: <UPDATE_IMAGE>-api, -web and -proxy.
DEFAULT_IMAGE = "ghcr.io/cxsmtp/hk"
ACCEPT_INDEX = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)
TAG = re.compile(r"^[\w][\w.-]{0,127}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PLATFORM_ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}


class UpdateError(Exception):
    def __init__(self, message: str, status: int = 502) -> None:
        super().__init__(message)
        self.status = status


def parse_image(image: str) -> tuple[str, str]:
    """ghcr.io/owner/name (a tag or digest after it is ignored) → (registry, repository)."""

    text = re.sub(r"^https?://", "", str(image or "").strip())
    text = re.sub(r"@sha256:[0-9a-f]+$", "", text, flags=re.I)
    if text.rfind(":") > text.rfind("/"):
        text = text[: text.rfind(":")]
    parts = text.split("/")
    host = parts[0] if parts else ""
    if len(parts) < 2 or not re.match(r"^[a-z0-9.-]+(:\d+)?$", host, re.I) or not ("." in host or ":" in host or host == "localhost"):
        raise UpdateError(f"Not an image name with its registry (like ghcr.io/owner/name): {image}", 400)
    repository = "/".join(parts[1:]).lower()
    if not re.match(r"^[a-z0-9]+(?:[._/-][a-z0-9]+)*$", repository):
        raise UpdateError(f"Not an image name: {image}", 400)
    return host.lower(), repository


def is_image_ref(ref: Any) -> bool:
    return isinstance(ref, str) and bool(TAG.match(ref) or DIGEST.match(ref))


def _site_of(host: str) -> str:
    """The site a host belongs to (its last two labels), for "is the sign-in service the registry's own?"."""

    return ".".join(re.sub(r":\d+$", "", host.lower()).split(".")[-2:])


def machine_arch() -> str:
    return PLATFORM_ARCH.get(platform.machine().lower(), platform.machine().lower())


class ImageRegistry:
    """A registry reader for one image. ``client`` is injectable for tests; ``token`` is only for a private copy."""

    def __init__(self, image: str, *, token: str = "", client: httpx.Client | None = None, arch: str | None = None, timeout: float = 60.0) -> None:
        self.registry, self.repository = parse_image(image)
        if "metadata" in outbound_url_problem(f"https://{self.registry}/"):
            raise UpdateError(f"{self.registry} is a link-local or cloud metadata address, never a registry.", 400)
        self.name = f"{self.registry}/{self.repository}"
        self._token = token
        self._bearer = ""
        self._client = client
        self.arch = arch or machine_arch()
        self.timeout = timeout

    @property
    def base(self) -> str:
        local = re.match(r"^(localhost|127\.0\.0\.1)(:\d+)?$", self.registry)
        return f"{'http' if local else 'https'}://{self.registry}/v2/{self.repository}"

    def _send(self, url: str, headers: dict[str, str]) -> httpx.Response:
        if self._client is not None:
            return self._client.get(url, headers=headers, timeout=self.timeout, follow_redirects=True)
        with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
            return client.get(url, headers=headers)

    def _get(self, path: str, *, accept: str = "", retried: bool = False) -> httpx.Response:
        headers = {"User-Agent": "hawk-ai-update"}
        if accept:
            headers["Accept"] = accept
        if self._bearer:
            headers["Authorization"] = f"Bearer {self._bearer}"
        try:
            response = self._send(f"{self.base}{path}", headers)
        except httpx.HTTPError as error:
            raise UpdateError(f"Could not reach {self.registry}: {error}. The server needs to reach {self.registry} (and, for GitHub, pkg-containers.githubusercontent.com) over HTTPS.") from error
        if response.status_code == 401 and not retried:
            self._authenticate(response.headers.get("www-authenticate") or "")
            return self._get(path, accept=accept, retried=True)
        if response.status_code == 404:
            raise UpdateError(f"{self.name}: not found ({path.split('/')[-1]}).", 404)
        if response.status_code >= 400:
            # Image files are often served from another host (ghcr.io sends them to pkg-containers.githubusercontent.com).
            host = urlsplit(str(response.url)).netloc or self.registry
            elsewhere = f" ({self.registry} sends image files there; a proxy or firewall in between may block it: allow {host} over HTTPS)" if host != self.registry else ""
            raise UpdateError(f"{host} answered {response.status_code} for {path.split('/')[-1][:19]}{elsewhere}.")
        return response

    def _authenticate(self, challenge: str) -> None:
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        if not re.match(r"^bearer", challenge, re.I) or not params.get("realm"):
            raise UpdateError(f"{self.registry} refused the request and did not say how to sign in.", 401)
        # The sign-in address comes from the registry's answer: https (plain http only on this machine), never a
        # link-local or metadata address, and the registry token only to the registry's own site.
        problem = outbound_url_problem(params["realm"], allow_loopback_http=True)
        if problem:
            raise UpdateError(f"{self.registry} asked to sign in at an address the server does not call (it {problem}).", 401)
        realm = urlsplit(params["realm"])
        own_site = _site_of(realm.hostname or "") == _site_of(self.registry)
        query = {"scope": params.get("scope") or f"repository:{self.repository}:pull"}
        if params.get("service"):
            query["service"] = params["service"]
        url = f"{params['realm']}{'&' if '?' in params['realm'] else '?'}{urlencode(query)}"
        headers = {"User-Agent": "hawk-ai-update"}
        if self._token and own_site:
            headers["Authorization"] = "Basic " + base64.b64encode(f"token:{self._token}".encode()).decode()
        try:
            response = self._send(url, headers)
            body = response.json() if response.status_code < 400 else {}
        except (httpx.HTTPError, ValueError) as error:
            raise UpdateError(f"Could not sign in to {self.registry}: {error}") from error
        token = (body or {}).get("token") or (body or {}).get("access_token")
        if not token:
            hint = " with the token given" if self._token else " without a token (is the image private? set UPDATE_REGISTRY_TOKEN)"
            raise UpdateError(f"{self.registry} did not allow reading {self.repository}{hint}.", 401)
        self._bearer = token

    def _json(self, path: str, accept: str) -> tuple[Any, str]:
        response = self._get(path, accept=accept)
        if len(response.content) > 4 * 1024 * 1024:
            raise UpdateError("The registry answer is too large.")
        try:
            body = json.loads(response.content.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as error:
            raise UpdateError("The registry sent something that is not JSON.") from error
        digest = response.headers.get("docker-content-digest") or ("sha256:" + hashlib.sha256(response.content).hexdigest())
        return body, digest

    def blob(self, digest: str, max_bytes: int = 2 * 1024 * 1024) -> bytes:
        if not DIGEST.match(digest):
            raise UpdateError(f"Not a sha256 digest: {digest}")
        response = self._get(f"/blobs/{digest}")
        data = response.content
        if len(data) > max_bytes:
            raise UpdateError(f"A blob is larger than expected ({len(data)} bytes).")
        actual = "sha256:" + hashlib.sha256(data).hexdigest()
        if actual != digest:
            raise UpdateError(f"A blob did not match its digest (expected {digest[:19]}…, got {actual[:19]}…).")
        return data

    def tags(self) -> list[str]:
        body, _ = self._json("/tags/list?n=1000", "application/json")
        return [t for t in (body.get("tags") if isinstance(body, dict) else None) or [] if isinstance(t, str) and TAG.match(t)]

    def manifest(self, ref: str = "latest") -> dict[str, str]:
        """The digest of ``ref`` as published (the image index, what the release workflow signs) and the digest of its
        build for this server's architecture: enough to list versions and to update."""

        if not is_image_ref(ref):
            raise UpdateError(f"Not a tag: {ref}", 400)
        body, digest = self._json(f"/manifests/{ref}", ACCEPT_INDEX)
        if not isinstance(body, dict) or not isinstance(body.get("manifests"), list):
            return {"digest": digest, "platform": digest}
        match = next((m for m in body["manifests"] if (m.get("platform") or {}).get("os") == "linux" and (m.get("platform") or {}).get("architecture") == self.arch), None)
        if not match or not DIGEST.match(str(match.get("digest") or "")):
            raise UpdateError(f"{ref} has no build for linux/{self.arch}.", 404)
        return {"digest": digest, "platform": match["digest"]}

    def image(self, ref: str = "latest") -> dict[str, Any]:
        """The image for ``ref`` on this server's architecture: {digest, labels, created}."""

        found = self.manifest(ref)
        body, _ = self._json(f"/manifests/{found['platform']}", ACCEPT_INDEX)
        config_digest = ((body or {}).get("config") or {}).get("digest") if isinstance(body, dict) else None
        if not config_digest:
            raise UpdateError(f"{ref} is not an image manifest.")
        config = json.loads(self.blob(config_digest).decode("utf-8"))
        return {"digest": found["digest"], "platform": found["platform"], "labels": (config.get("config") or {}).get("Labels") or {}, "created": config.get("created") or ""}
