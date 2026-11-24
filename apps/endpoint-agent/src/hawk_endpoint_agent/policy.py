"""Policy store — server-authoritative, TTL-bounded, fail-secure.

Drift prevention: the effective policy is always the backend's. The agent caches
the last good policy on disk with an integrity hash and a fetch timestamp. While
the backend is reachable, decisions are live. While it is not, the agent uses the
cached policy until ``policy_ttl_seconds`` elapses, after which it falls back to
the configured fail-secure posture rather than an unbounded stale policy.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

from .config import AgentConfig
from .decision import Action, ControlMode, Decision
from .hawk_client import HawkClient, HawkUnavailable, HawkApiError


@dataclass
class EndpointPolicy:
    platform_mode: str = "enforce"           # enforce | discovery | monitor
    notetaker: dict[str, Any] = field(default_factory=dict)
    modules: dict[str, bool] = field(default_factory=dict)
    blocked_domains: list[str] = field(default_factory=list)
    warn_domains: list[str] = field(default_factory=list)
    hmair_metadata_inventory: dict[str, str] | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_backend(cls, payload: dict[str, Any]) -> "EndpointPolicy":
        return cls(
            platform_mode=str(payload.get("platform_mode") or "enforce"),
            notetaker=dict(payload.get("notetaker_policy") or payload.get("notetaker") or {}),
            modules=dict(payload.get("modules") or {}),
            blocked_domains=list(payload.get("blocked_domains") or []),
            warn_domains=list(payload.get("warn_domains") or []),
            hmair_metadata_inventory=_metadata_inventory_directive(
                payload.get("hmair_metadata_inventory")
            ),
            raw=dict(payload),
        )


def _metadata_inventory_directive(value: object) -> dict[str, str] | None:
    """Accept only the bounded, server-issued metadata inventory shape."""

    if not isinstance(value, dict) or set(value) != {
        "assignment_id",
        "inventory_run_id",
        "mode",
        "expires_at",
    }:
        return None
    assignment_id = value.get("assignment_id")
    inventory_run_id = value.get("inventory_run_id")
    mode = value.get("mode")
    expires_at = value.get("expires_at")
    if (
        type(assignment_id) is not str
        or type(inventory_run_id) is not str
        or mode != "metadata_only"
        or type(expires_at) is not str
    ):
        return None
    try:
        assignment_id = str(UUID(assignment_id))
        inventory_run_id = str(UUID(inventory_run_id))
        parsed_expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if parsed_expiry.tzinfo is None or parsed_expiry.utcoffset() is None:
        return None
    return {
        "assignment_id": assignment_id,
        "inventory_run_id": inventory_run_id,
        "mode": "metadata_only",
        "expires_at": parsed_expiry.isoformat(),
    }


def _hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def endpoint_mode_for_platform_mode(value: str | None) -> str | None:
    """Map only recognized server-authoritative modes to the local control plane."""
    normalized = str(value or "").strip().lower()
    if normalized in {"discovery", "monitor"}:
        return "monitor"
    if normalized == "enforce":
        return "enforce"
    return None


class PolicyStore:
    def __init__(self, config: AgentConfig, client: HawkClient) -> None:
        self._config = config
        self._client = client
        self._cache_path = Path(config.policy_cache_path).expanduser()
        self._policy: EndpointPolicy | None = None
        self._fetched_at: float = 0.0
        self._stale: bool = False
        self._load_cache()

    # -- lifecycle ---------------------------------------------------------
    def refresh(self) -> bool:
        """Fetch a fresh policy from the backend. Returns True on success."""
        try:
            payload = self._client.sync_policy()
        except (HawkUnavailable, HawkApiError):
            self._stale = True
            return False
        self._policy = EndpointPolicy.from_backend(payload)
        self._fetched_at = time.time()
        self._stale = False
        self._write_cache(payload)
        return True

    def age_seconds(self) -> float:
        return time.time() - self._fetched_at if self._fetched_at else float("inf")

    def is_fresh(self) -> bool:
        return self._policy is not None and self.age_seconds() <= self._config.policy_ttl_seconds

    @property
    def policy(self) -> EndpointPolicy | None:
        return self._policy

    @property
    def stale(self) -> bool:
        return self._stale or not self.is_fresh()

    # -- fail-secure resolution -------------------------------------------
    def fail_secure_decision(self, *, surface: str, reason: str) -> Decision:
        """Decision used when there is no fresh policy and the backend is down."""
        mode = self._config.fail_secure_mode
        if mode == "block":
            action, mode_label = Action.BLOCK, ControlMode.INLINE_PREVENTED
        elif mode == "warn":
            action, mode_label = Action.WARN, ControlMode.WARNED
        else:
            action, mode_label = Action.ALLOW, ControlMode.TELEMETRY_ONLY
        return Decision(
            action=action,
            control_mode=mode_label,
            reason=f"fail_secure:{mode}:{reason}",
            source="fail_secure_cache" if self._policy is not None else "fail_secure_default",
            detail={"surface": surface, "policy_age_seconds": round(self.age_seconds(), 1)},
        )

    def notetaker_policy(self) -> dict[str, Any]:
        if self._policy is not None:
            return dict(self._policy.notetaker)
        return {
            "action": self._config.notetaker_default_action,
            "allow_eviction": self._config.notetaker_allow_eviction,
            "banner": True,
        }

    def module_enabled(self, name: str) -> bool:
        if self._policy is not None and name in self._policy.modules:
            return bool(self._policy.modules[name])
        return name in self._config.enabled_modules

    # -- cache -------------------------------------------------------------
    def _write_cache(self, payload: dict[str, Any]) -> None:
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            # A work directive is deliberately memory-only. The established
            # policy cache remains useful for enforcement but must never cause
            # an inventory retry after a restart without a fresh policy pull.
            cache_payload = dict(payload)
            cache_payload.pop("hmair_metadata_inventory", None)
            envelope = {
                "fetched_at": self._fetched_at,
                "hash": _hash(cache_payload),
                "payload": cache_payload,
            }
            tmp = self._cache_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(envelope), encoding="utf-8")
            os.chmod(tmp, 0o600)
            tmp.replace(self._cache_path)
        except OSError:
            pass  # cache is best-effort; absence just means no offline policy

    def _load_cache(self) -> None:
        try:
            envelope = json.loads(self._cache_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            return
        if _hash(payload) != envelope.get("hash"):
            return  # tampered / corrupt cache -> ignore, force fail-secure
        self._policy = EndpointPolicy.from_backend(payload)
        self._fetched_at = float(envelope.get("fetched_at") or 0.0)
        self._stale = True
