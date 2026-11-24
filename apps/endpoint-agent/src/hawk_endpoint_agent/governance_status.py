"""Privacy-safe, evidence-backed status for the local governance companion.

This is a bounded in-memory projection, not a second evidence store.  It contains
only identifiers, counters, provenance, and the latest finalized decision needed
to render truthful local status.  Raw interaction content is never copied.
"""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
from threading import Lock
import math
import time
from typing import Any, Callable

from .decision import ControlMode, Decision

_INLINE_MODES = {
    ControlMode.INLINE_ALLOWED,
    ControlMode.INLINE_PREVENTED,
    ControlMode.WARNED,
    ControlMode.SCOPED,
}
_MONITOR_MODES = {
    ControlMode.MONITOR_WOULD_ALLOW,
    ControlMode.MONITOR_WOULD_WARN,
    ControlMode.MONITOR_WOULD_REVIEW,
    ControlMode.MONITOR_WOULD_BLOCK,
    ControlMode.DETECT_ONLY,
    ControlMode.TELEMETRY_ONLY,
}


def _text(value: Any, limit: int = 256) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()[:limit]
    return cleaned or None


def _count(value: Any, *, maximum: int = 1_000_000_000) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return min(parsed, maximum) if parsed >= 0 else None


def _money(value: Any, *, maximum: float = 1_000_000_000.0) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) and 0 <= parsed <= maximum else None


def _cost_usage(request: dict[str, Any]) -> dict[str, Any]:
    usage = request.get("usage") if isinstance(request.get("usage"), dict) else {}
    source = request.get("cost") if isinstance(request.get("cost"), dict) else {}
    if not source and isinstance(usage.get("cost"), dict):
        source = usage["cost"]
    cost_source = str(source.get("source") or request.get("cost_source") or "").strip().lower()
    allowed_sources = {
        "provider_billed",
        "provider_reported",
        "customer_rate_card",
        "calculated_estimate",
    }
    amount = _money(source.get("amount")) if cost_source in allowed_sources else None
    currency = str(source.get("currency") or "").strip().upper()
    if len(currency) != 3 or not currency.isalpha():
        currency = ""
    if amount is None or not currency:
        return {"amount": None, "currency": None, "provenance": "unknown", "source": "unknown"}
    exact = (
        request.get("cost_usage_verified") is True
        and cost_source in {"provider_billed", "provider_reported"}
    )
    return {
        "amount": amount,
        "currency": currency,
        "provenance": "exact" if exact else "estimated",
        "source": cost_source,
    }


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


class GovernanceStatusStore:
    """Bounded latest-session view for trusted local UI consumers."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.time,
        ttl_seconds: float = 30.0,
        max_sessions: int = 64,
    ) -> None:
        self._clock = clock
        self._ttl_seconds = max(1.0, float(ttl_seconds))
        self._max_sessions = max(1, int(max_sessions))
        self._entries: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._lock = Lock()

    def record(
        self,
        request: dict[str, Any],
        decision: Decision,
        *,
        adapter_path: str,
    ) -> None:
        now = float(self._clock())
        client_app = self._client_app(request)
        session_id = _text(request.get("session_id"))
        key = f"{client_app.casefold()}\0{(session_id or '').casefold()}"
        evidence_ref = _text(decision.evidence_ref)
        control_mode = _text(decision.control_mode, 64) or ControlMode.UNKNOWN
        state = self._state(control_mode, evidence_ref)
        usage = request.get("usage") if isinstance(request.get("usage"), dict) else {}
        total_tokens = _count(usage.get("total_tokens"))
        if total_tokens is None:
            total_tokens = _count(request.get("token_count"))
        provenance = "unknown"
        if total_tokens is not None:
            provenance = (
                "exact"
                if request.get("token_usage_verified") is True
                and str(request.get("token_usage_provenance") or "").lower() == "exact"
                else "estimated"
            )

        with self._lock:
            prior = self._entries.pop(key, None) or {}
            available_tools = _count(request.get("available_tools_count"), maximum=100_000)
            if available_tools is None:
                available_tools = _count(request.get("tool_count"), maximum=100_000)
            if available_tools is None:
                available_tools = prior.get("available_tool_count")
            entry = {
                "schema_version": 1,
                "state": state,
                "label": self._label(state),
                "connected": True,
                "client_app": client_app,
                "adapter_path": _text(adapter_path, 64) or "unknown",
                "server_id": _text(request.get("mcp_server_id")),
                "session_id": session_id,
                "available_tool_count": available_tools,
                "tool_call_count": min(int(prior.get("tool_call_count") or 0) + 1, 1_000_000_000),
                "token_usage": {"total": total_tokens, "provenance": provenance},
                "cost_usage": _cost_usage(request),
                "latest_decision": _text(decision.action, 64) or "unknown",
                "control_mode": control_mode,
                "policy_id": _text(decision.detail.get("policy_id") or decision.detail.get("policy_version_id")),
                "evidence_ref": evidence_ref,
                "reason": _text(decision.reason, 256) or "unknown",
                "last_activity_at": _iso(now),
                "expires_at": _iso(now + self._ttl_seconds),
                "_recorded_epoch": now,
            }
            self._entries[key] = entry
            while len(self._entries) > self._max_sessions:
                self._entries.popitem(last=False)

    def status(self, client_app: str | None = None) -> dict[str, Any]:
        requested = _text(client_app) or "Unknown client"
        now = float(self._clock())
        with self._lock:
            candidates = [
                entry
                for entry in reversed(self._entries.values())
                if client_app is None or entry["client_app"].casefold() == requested.casefold()
            ]
            entry = dict(candidates[0]) if candidates else None
        if entry is None or now - float(entry.pop("_recorded_epoch")) > self._ttl_seconds:
            return self._unknown(requested)
        return entry

    @staticmethod
    def _client_app(request: dict[str, Any]) -> str:
        for key in ("client_app", "client_application", "desktop_app", "app"):
            value = _text(request.get(key))
            if value:
                return value
        return "Unknown client"

    @staticmethod
    def _state(control_mode: str, evidence_ref: str | None) -> str:
        if not evidence_ref:
            return "unknown"
        if control_mode == ControlMode.INLINE_PREVENTED:
            return "blocked"
        if control_mode in _MONITOR_MODES:
            return "monitor"
        if control_mode in _INLINE_MODES:
            return "governed"
        return "unknown"

    @staticmethod
    def _label(state: str) -> str:
        return {
            "governed": "Governed",
            "blocked": "Blocked",
            "monitor": "Monitor",
            "unknown": "Unknown",
        }.get(state, "Unknown")

    @staticmethod
    def _unknown(client_app: str) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "state": "unknown",
            "label": "Unknown",
            "connected": True,
            "client_app": client_app,
            "adapter_path": None,
            "server_id": None,
            "session_id": None,
            "available_tool_count": None,
            "tool_call_count": 0,
            "token_usage": {"total": None, "provenance": "unknown"},
            "cost_usage": {"amount": None, "currency": None, "provenance": "unknown", "source": "unknown"},
            "latest_decision": "unknown",
            "control_mode": ControlMode.UNKNOWN,
            "policy_id": None,
            "evidence_ref": None,
            "reason": "no_fresh_verified_decision",
            "last_activity_at": None,
            "expires_at": None,
        }
