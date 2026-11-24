"""Local monitor/enforce semantics and action-scoped adapter posture."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from threading import Lock
from typing import Any

from .decision import Action, ControlMode, Decision

MODES = ("monitor", "enforce")
ADAPTER_PATHS = (
    "browser",
    "mcp",
    "llm",
    "sdk",
    "developer_agent",
    "foundry",
    "data_transfer",
    "local_proxy",
    "local_ipc",
)

_MONITOR_MODE = {
    Action.ALLOW: ControlMode.MONITOR_WOULD_ALLOW,
    Action.WARN: ControlMode.MONITOR_WOULD_WARN,
    Action.SCOPE: ControlMode.MONITOR_WOULD_ALLOW,
    Action.REDACT: ControlMode.MONITOR_WOULD_BLOCK,
    Action.HOLD: ControlMode.MONITOR_WOULD_REVIEW,
    Action.BLOCK: ControlMode.MONITOR_WOULD_BLOCK,
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class EndpointControlPlane:
    """Apply endpoint mode while preserving the server's canonical verdict."""

    def __init__(self, *, mode: str = "monitor", mode_path: str | Path | None = None) -> None:
        if mode not in MODES:
            raise ValueError(f"unsupported endpoint mode: {mode}")
        self._mode = mode
        self._mode_store = ModeStore(mode_path, default=mode) if mode_path else None
        self._lock = Lock()
        self._adapters: dict[str, dict[str, Any]] = {
            path: self._new_adapter() for path in ADAPTER_PATHS
        }

    @property
    def mode(self) -> str:
        if self._mode_store is not None:
            return self._mode_store.get()
        return self._mode

    def set_mode(self, mode: str) -> None:
        if mode not in MODES:
            raise ValueError(f"unsupported endpoint mode: {mode}")
        self._mode = mode
        if self._mode_store is not None:
            self._mode_store.set(mode)

    def set_ready(self, adapter_path: str, ready: bool) -> None:
        with self._lock:
            state = self._adapters.setdefault(adapter_path, self._new_adapter())
            state["ready"] = bool(ready)

    def finalize(
        self,
        *,
        request: dict[str, Any],
        decision: Decision,
        adapter_path: str,
        pre_action: bool,
    ) -> Decision:
        del request  # raw request content must not be retained by posture tracking
        original_action = decision.action
        detail = dict(decision.detail)
        detail.update(
            {
                "adapter_path": adapter_path,
                "endpoint_mode": self._mode,
                "pre_action_verified": bool(pre_action),
            }
        )

        active_mode = self.mode
        detail["endpoint_mode"] = active_mode
        if active_mode == "monitor":
            detail["would_action"] = original_action
            result = replace(
                decision,
                action=Action.ALLOW,
                control_mode=_MONITOR_MODE.get(original_action, ControlMode.MONITOR_WOULD_ALLOW),
                enforced=False,
                detail=detail,
            )
        else:
            result = replace(
                decision,
                control_mode=self._enforce_mode(original_action, pre_action=pre_action),
                enforced=bool(pre_action and original_action in {Action.BLOCK, Action.REDACT}),
                detail=detail,
            )

        self._record_adapter(adapter_path, result.control_mode, pre_action=pre_action)
        return result

    def posture(self) -> dict[str, Any]:
        with self._lock:
            adapters = {path: dict(state) for path, state in self._adapters.items()}
        active_mode = self.mode
        if active_mode == "monitor":
            for state in adapters.values():
                state["authorization_covered"] = False
                state["last_pre_action_decision_at"] = None
        return {"mode": active_mode, "adapters": adapters}

    @staticmethod
    def _new_adapter() -> dict[str, Any]:
        return {
            "ready": False,
            "authorization_covered": False,
            "last_pre_action_decision_at": None,
            "last_observation_at": None,
            "last_control_mode": ControlMode.UNKNOWN,
        }

    @staticmethod
    def _enforce_mode(action: str, *, pre_action: bool) -> str:
        if not pre_action:
            if action in {Action.BLOCK, Action.REDACT, Action.HOLD}:
                return ControlMode.DETECT_ONLY
            return ControlMode.TELEMETRY_ONLY
        if action in {Action.BLOCK, Action.REDACT}:
            return ControlMode.INLINE_PREVENTED
        if action == Action.HOLD:
            return ControlMode.REVIEW_REQUIRED
        if action == Action.WARN:
            return ControlMode.WARNED
        if action == Action.SCOPE:
            return ControlMode.SCOPED
        return ControlMode.INLINE_ALLOWED

    def _record_adapter(self, adapter_path: str, control_mode: str, *, pre_action: bool) -> None:
        now = _utcnow()
        with self._lock:
            state = self._adapters.setdefault(adapter_path, self._new_adapter())
            state["ready"] = True
            state["last_observation_at"] = now
            state["last_control_mode"] = control_mode
            if pre_action and self.mode == "enforce":
                state["authorization_covered"] = True
                state["last_pre_action_decision_at"] = now
            elif self.mode == "monitor":
                state["authorization_covered"] = False
                state["last_pre_action_decision_at"] = None


class ModeStore:
    """Small atomic 0600 state file shared by the service and operator CLI."""

    def __init__(self, path: str | Path, *, default: str = "monitor") -> None:
        if default not in MODES:
            raise ValueError(f"unsupported endpoint mode: {default}")
        self.path = Path(path).expanduser()
        self.default = default

    def get(self) -> str:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            mode = str(payload.get("mode") or "")
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return self.default
        return mode if mode in MODES else self.default

    def set(self, mode: str) -> None:
        if mode not in MODES:
            raise ValueError(f"unsupported endpoint mode: {mode}")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"schema_version": 1, "mode": mode, "updated_at": _utcnow()}
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)
        os.chmod(self.path, 0o600)
