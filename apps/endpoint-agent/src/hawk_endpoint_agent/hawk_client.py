"""Authenticated client to the real Hawk backend control endpoints.

Every method maps to an endpoint that exists in the Hawk API (verified against the
running service): the agent does not invent control surfaces. Standard-library
``urllib`` only, so the agent has no third-party network stack to trust. Every
request uses a short-lived device token plus a fresh proof-of-possession proof.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from . import __version__
from .auth.session import (
    EndpointAuthError,
    EndpointAuthSession,
    EndpointAuthUnavailable,
)
from .config import AgentConfig


class HawkUnavailable(Exception):
    """Raised when the backend cannot be reached (drives fail-secure resolution)."""


class HawkApiError(Exception):
    def __init__(self, status: int, body: Any) -> None:
        super().__init__(f"Hawk API error {status}")
        self.status = status
        self.body = body


_MCP_SCAN_TRUST_STATUSES = {"approved", "unknown", "changed"}
_MCP_SCAN_DECISIONS = {"allow", "warn", "redact", "hold_for_approval", "block"}


class HawkClient:
    def __init__(
        self,
        config: AgentConfig,
        *,
        auth_session: EndpointAuthSession | Any | None = None,
    ) -> None:
        self._config = config
        self._base = config.api_base_url.rstrip("/")
        self._auth = auth_session or EndpointAuthSession(config=config)

    # -- transport ---------------------------------------------------------
    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        url = f"{self._base}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        last_exc: Exception | None = None
        network_attempts = 0
        auth_retried = False
        while network_attempts < max(1, self._config.http_retry_attempts):
            try:
                with self._auth.authenticated_headers(method, url) as auth_headers:
                    headers = {
                        "Content-Type": "application/json",
                        "X-Tenant-ID": self._config.tenant_id,
                        "X-Hawk-Agent": f"hawk-endpoint-agent/{__version__}",
                        "X-Endpoint-Id": self._config.endpoint_id,
                        **auth_headers,
                    }
                    request = urllib.request.Request(
                        url, data=data, method=method, headers=headers
                    )
                    with urllib.request.urlopen(
                        request, timeout=self._config.http_timeout_seconds
                    ) as response:
                        raw = response.read().decode("utf-8")
                        return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as exc:  # server answered with 4xx/5xx
                try:
                    parsed = json.loads(exc.read().decode("utf-8") or "{}")
                except Exception:  # noqa: BLE001
                    parsed = {"detail": "non-json error body"}
                if exc.code == 401 and not auth_retried:
                    auth_retried = True
                    self._auth.invalidate()
                    try:
                        self._auth.renew(force=True)
                    except EndpointAuthUnavailable as auth_exc:
                        raise HawkUnavailable("endpoint authentication unavailable") from auth_exc
                    except EndpointAuthError as auth_exc:
                        raise HawkApiError(401, {"detail": "endpoint authentication failed"}) from auth_exc
                    continue
                raise HawkApiError(exc.code, parsed) from exc
            except EndpointAuthUnavailable as exc:
                raise HawkUnavailable("endpoint authentication unavailable") from exc
            except EndpointAuthError as exc:
                raise HawkApiError(401, {"detail": "endpoint authentication failed"}) from exc
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
                last_exc = exc
                network_attempts += 1
                continue
        raise HawkUnavailable(str(last_exc) if last_exc else "backend unreachable")

    # -- policy ------------------------------------------------------------
    def sync_policy(self) -> dict[str, Any]:
        """Fetch the endpoint policy bundle (server is the source of truth)."""
        return self._request("GET", "/endpoint-agent/policy")

    def heartbeat(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/endpoint-agent/heartbeat", payload)

    # -- inline control decisions -----------------------------------------
    def intercept_llm(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Inline LLM/prompt evaluation -> block / warn / redact / allow."""
        return self._request("POST", "/endpoint-agent/decision/llm", payload)

    def authorize_mcp(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Authorize a local agent / MCP tool action -> block / allow / scope."""
        response = self._request("POST", "/endpoint-agent/decision/mcp", payload)
        if not isinstance(response, dict):
            raise HawkApiError(502, {"detail": "invalid MCP authorization response"})
        scope_returned = any(
            str(response.get(field) or "").strip().lower() == "scope"
            for field in ("final_decision", "decision")
        )
        if scope_returned and response.get("constraints_enforced") is not True:
            return {
                **response,
                "decision": "block",
                "final_decision": "block",
                "reason": "MCP scope constraints were not proven enforced",
                "reason_code": "mcp_scope_constraints_unverified",
            }
        return response

    def scan_mcp_tool(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Persistently scan one MCP descriptor through the backend registry."""
        request_id = payload.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            raise HawkApiError(400, {"detail": "MCP scan request_id is required"})
        response = self._request(
            "POST",
            "/endpoint-agent/decision/mcp/tools/scan",
            payload,
        )
        if not _valid_mcp_scan_response(response, request_id=request_id):
            raise HawkApiError(502, {"detail": "invalid MCP tool scan response"})
        return response

    def check_data_transfer(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Copy/paste / upload DLP decision -> allow / warn / block / require_justification."""
        return self._request("POST", "/endpoint-agent/decision/data-transfer", payload)

    def eval_interaction(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Desktop interaction (prompt) DLP eval -> decision."""
        return self._request("POST", "/endpoint-agent/decision/interaction", payload)

    def evaluate_notetaker(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Server-authoritative notetaker decision -> allow / warn / block (+ eviction)."""
        return self._request("POST", "/endpoint-agent/notetaker/evaluate", payload)

    # -- discovery / telemetry --------------------------------------------
    def report_discovery(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/endpoint-agent/telemetry", payload)

    def report_evidence(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/endpoint-agent/evidence", payload)

    def report_hmair_snapshot(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Submit one explicitly requested, metadata-only HMAIR lab snapshot."""
        response = self._request(
            "POST",
            "/endpoint-agent/discovery/snapshots",
            payload,
        )
        if not _valid_hmair_snapshot_receipt(response):
            raise HawkApiError(502, {"detail": "invalid HMAIR snapshot receipt"})
        return response

    def report_hmair_inventory_failure(
        self, assignment_id: str, code: str
    ) -> dict[str, Any]:
        """Report a code-only failure for a server-issued inventory assignment."""

        return self._request(
            "POST",
            f"/endpoint-agent/discovery/metadata-inventory-assignments/{assignment_id}/failure",
            {"code": code},
        )

    def auth_status(self) -> dict[str, Any]:
        return self._auth.status()

    def local_broker_authenticator(self):
        """Expose only the response-signing facade for local IPC peer proof."""
        return self._auth.local_broker_authenticator()

    def close(self) -> None:
        close = getattr(self._auth, "close", None)
        if callable(close):
            close()


def _valid_mcp_scan_response(response: Any, *, request_id: str) -> bool:
    if not isinstance(response, dict):
        return False
    return (
        response.get("request_id") == request_id
        and response.get("status") == "completed"
        and isinstance(response.get("scan_result_id"), str)
        and bool(response["scan_result_id"].strip())
        and isinstance(response.get("tool_fingerprint_id"), str)
        and bool(response["tool_fingerprint_id"].strip())
        and isinstance(response.get("evidence_bundle_id"), str)
        and bool(response["evidence_bundle_id"].strip())
        and str(response.get("trust_status") or "").strip().lower()
        in _MCP_SCAN_TRUST_STATUSES
        and str(response.get("tool_poisoning_decision") or "").strip().lower()
        in _MCP_SCAN_DECISIONS
        and isinstance(response.get("risk_factors"), list)
        and all(isinstance(factor, str) for factor in response["risk_factors"])
        and isinstance(response.get("idempotent_replay"), bool)
    )


def _valid_hmair_snapshot_receipt(response: Any) -> bool:
    if not isinstance(response, dict):
        return False
    return (
        isinstance(response.get("scan_id"), str)
        and bool(response["scan_id"].strip())
        and response.get("status") in {"complete", "completed"}
        and type(response.get("observations_count")) is int
        and response["observations_count"] >= 0
        and response.get("endpoint_denominator") == 1
        and isinstance(response.get("limitations"), list)
        and all(isinstance(item, str) and item for item in response["limitations"])
    )
