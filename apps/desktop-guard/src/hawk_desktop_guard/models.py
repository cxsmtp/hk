from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any


def _text(value: Any) -> str | None:
    token = str(value or "").strip()
    return token or None


@dataclass(frozen=True)
class PromptSnapshot:
    application: str
    desktop_app: str
    prompt_text: str
    prompt_preview_redacted: str
    capture_method: str
    machine_id: str | None = None
    user_id: str | None = None
    user_email: str | None = None
    os_type: str | None = None
    os_version: str | None = None
    hostname: str | None = None
    active_window_title: str | None = None
    input_signal_types: list[str] = field(default_factory=list)

    @property
    def prompt_hash(self) -> str:
        material = self.prompt_preview_redacted or self.prompt_text
        return sha256(material.encode("utf-8")).hexdigest()

    def to_api_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "application": self.application,
            "desktop_app": self.desktop_app,
            "prompt_hash": self.prompt_hash,
            "raw_prompt": self.prompt_text,
            "prompt_preview_redacted": self.prompt_preview_redacted,
            "capture_method": self.capture_method,
            "machine_id": self.machine_id,
            "user_id": self.user_id,
            "user_email": self.user_email,
            "os_type": self.os_type,
            "os_version": self.os_version,
            "hostname": self.hostname,
            "active_window_title": self.active_window_title,
            "input_signal_types": list(self.input_signal_types),
            "prompt_storage_mode": "redacted_preview_only",
        }
        return {key: value for key, value in payload.items() if value not in (None, "", [])}


@dataclass(frozen=True)
class GuardDecision:
    decision: str
    tier: str
    reason_codes: list[str]
    runtime_event_id: str | None
    finding_id: str | None
    correlation_id: str | None = None
    policy_version: str | None = None
    platform_mode: str | None = None

    @classmethod
    def from_api(cls, payload: dict[str, Any]) -> "GuardDecision":
        return cls(
            decision=str(payload.get("decision") or "allow").strip().lower() or "allow",
            tier=str(payload.get("tier") or "").strip() or "unknown",
            reason_codes=[str(item) for item in (payload.get("reason_codes") or [])],
            runtime_event_id=_text(payload.get("runtime_event_id")),
            finding_id=_text(payload.get("finding_id")),
            correlation_id=_text(payload.get("correlation_id")),
            policy_version=_text(payload.get("policy_version")),
            platform_mode=_text(payload.get("platform_mode")),
        )
