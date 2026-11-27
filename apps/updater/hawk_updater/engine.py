"""The container engine's API (Docker's, or Podman's Docker-compatible one) over its Unix socket. Ported from
CxMissionZero's src/companion/engine.js, with what Hawk AI's update needs on top: list one compose project's
containers, wait for a one-off container to exit and read its output.

Standard library only.
"""

from __future__ import annotations

import base64
import http.client
import json
import socket
from typing import Any
from urllib.parse import quote, urlencode

API = "/v1.41"


class EngineError(Exception):
    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float) -> None:
        super().__init__("engine", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


def demux(raw: bytes) -> str:
    """A container's output as the engine streams it without a terminal: 8-byte frame headers, then the bytes."""

    out = bytearray()
    at = 0
    while at + 8 <= len(raw) and raw[at] in (0, 1, 2) and raw[at + 1 : at + 4] == b"\x00\x00\x00":
        size = int.from_bytes(raw[at + 4 : at + 8], "big")
        out += raw[at + 8 : at + 8 + size]
        at += 8 + size
    if at < len(raw):
        out += raw[at:]
    return out.decode("utf-8", errors="replace")


class EngineClient:
    def __init__(self, socket_path: str, *, registry_token: str = "", timeout: float = 120.0) -> None:
        self.socket_path = socket_path
        self._token = registry_token
        self.timeout = timeout

    def request(self, method: str, path: str, *, body: Any = None, headers: dict[str, str] | None = None, timeout: float | None = None, raw: bool = False) -> Any:
        payload = None if body is None else json.dumps(body).encode("utf-8")
        wait = self.timeout if timeout is None else timeout
        connection = _UnixConnection(self.socket_path, wait)
        try:
            sent = {"Host": "engine", **(headers or {})}
            if payload is not None:
                sent["Content-Type"] = "application/json"
            connection.request(method, API + path, body=payload, headers=sent)
            response = connection.getresponse()
            data = response.read()
        except socket.timeout as error:
            raise EngineError(f"No answer from the container engine within {round(wait)} s.") from error
        except OSError as error:
            raise EngineError(f"Cannot reach the container engine at {self.socket_path}: {error}") from error
        finally:
            connection.close()
        text = data.decode("utf-8", errors="replace")
        if response.status >= 400:
            message = text.strip() or f"The engine answered {response.status}."
            try:
                detail = json.loads(text)
                if isinstance(detail, dict):
                    message = str(detail.get("message") or detail.get("cause") or message)
            except ValueError:
                pass
            raise EngineError(message[:300], response.status)
        if raw:
            return data
        if not text:
            return None
        try:
            return json.loads(text)
        except ValueError:
            return text

    def ping(self) -> Any:
        return self.request("GET", "/_ping", timeout=10, raw=True)

    def inspect(self, name_or_id: str) -> dict[str, Any]:
        return self.request("GET", f"/containers/{quote(name_or_id, safe='')}/json")

    def inspect_image(self, ref: str) -> dict[str, Any]:
        return self.request("GET", f"/images/{quote(ref, safe='')}/json")

    def containers(self, labels: list[str]) -> list[dict[str, Any]]:
        query = urlencode({"all": "1", "filters": json.dumps({"label": labels})})
        return self.request("GET", f"/containers/json?{query}") or []

    def pull(self, repository: str, tag_or_digest: str) -> None:
        """Pull repository:tag (or @sha256:…); the answer streams progress lines, any of which may carry the error."""

        host = repository.split("/")[0]
        headers = {}
        if self._token:
            auth = json.dumps({"username": "token", "password": self._token, "serveraddress": host}).encode()
            headers["X-Registry-Auth"] = base64.urlsafe_b64encode(auth).decode().rstrip("=")
        query = urlencode({"fromImage": repository, "tag": tag_or_digest})
        text = self.request("POST", f"/images/create?{query}", headers=headers, timeout=15 * 60, raw=True).decode("utf-8", errors="replace")
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if isinstance(event, dict) and (event.get("error") or event.get("errorDetail")):
                detail = (event.get("errorDetail") or {}).get("message") or event.get("error")
                raise EngineError(f"Pulling {repository}:{tag_or_digest} failed: {detail}")

    def create(self, name: str, spec: dict[str, Any]) -> dict[str, Any]:
        """Create the container; on more than one network (deploy/compose.yaml's api, worker, beat and migrate are on
        ``hawk`` and ``hawk-internal``), with the first, then connected to the others before it starts: API 1.41
        takes one network at create."""

        endpoints = dict(((spec.get("NetworkingConfig") or {}).get("EndpointsConfig")) or {})
        if len(endpoints) <= 1:
            return self.request("POST", f"/containers/create?{urlencode({'name': name})}", body=spec)
        first, *others = endpoints.items()
        made = self.request("POST", f"/containers/create?{urlencode({'name': name})}", body={**spec, "NetworkingConfig": {"EndpointsConfig": dict([first])}})
        for network, endpoint in others:
            self.request("POST", f"/networks/{quote(network, safe='')}/connect", body={"Container": made["Id"], "EndpointConfig": endpoint or {}})
        return made

    def start(self, container_id: str) -> None:
        try:
            self.request("POST", f"/containers/{quote(container_id, safe='')}/start")
        except EngineError as error:
            if error.status != 304:
                raise

    def stop(self, container_id: str, seconds: int = 30) -> None:
        """Stop, giving the service ``seconds`` to finish its work and save (a 304 means already stopped)."""

        try:
            self.request("POST", f"/containers/{quote(container_id, safe='')}/stop?t={seconds}", timeout=seconds + 30)
        except EngineError as error:
            if error.status != 304:
                raise

    def rename(self, container_id: str, name: str) -> None:
        self.request("POST", f"/containers/{quote(container_id, safe='')}/rename?{urlencode({'name': name})}")

    def remove(self, container_id: str) -> None:
        self.request("DELETE", f"/containers/{quote(container_id, safe='')}?force=true")

    def wait(self, container_id: str, timeout: float) -> int:
        """The exit code of a container once it stops (raises EngineError when it takes longer than ``timeout``)."""

        answer = self.request("POST", f"/containers/{quote(container_id, safe='')}/wait", timeout=timeout)
        return int((answer or {}).get("StatusCode", -1))

    def logs(self, container_id: str, tail: int = 200) -> str:
        data = self.request("GET", f"/containers/{quote(container_id, safe='')}/logs?stdout=1&stderr=1&tail={tail}", raw=True)
        return demux(data or b"")
