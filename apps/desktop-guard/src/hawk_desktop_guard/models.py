from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

from .redaction import redact_prompt


def _text(value: Any) -> str | None:
    token = str(value or "").strip()
    return token or None


@dataclass(frozen=True)
class PromptSnapshot:
    """A prompt seen on this machine.

    ``prompt_text`` stays on the machine: local checks use it, and it is sent to the API only when full-prompt capture
    is turned on (config ``full_prompt_capture`` / HAWK_DESKTOP_FULL_PROMPT_CAPTURE, off by default). The API
    otherwise gets ``prompt_preview_redacted`` (redacted locally, then shortened; see redaction.py) and the types of
    what was redacted."""

    application: str
    desktop_app: str
    prompt_text: str
    capture_method: str
    machine_id: str | None = None
    user_id: str | None = None
    user_email: str | None = None
    os_type: str | None = None
    os_version: str | None = None
    hostname: str | None = None
    active_window_title: str | None = None
    input_signal_types: list[str] = field(default_factory=list)
    prompt_preview_redacted: str = field(init=False)
    redacted_entity_types: tuple[str, ...] = field(init=False)
    prompt_preview_truncated: bool = field(init=False)

    def __post_init__(self) -> None:
        redacted = redact_prompt(self.prompt_text)
        object.__setattr__(self, "prompt_preview_redacted", redacted.preview)
        object.__setattr__(self, "redacted_entity_types", redacted.entity_types)
        object.__setattr__(self, "prompt_preview_truncated", redacted.truncated)

    @property
    def prompt_hash(self) -> str:
        # The whole prompt: two prompts that differ only after the preview's limit are not the same prompt.
        return sha256(self.prompt_text.encode("utf-8")).hexdigest()

    def to_api_payload(self, *, full_prompt_capture: bool = False) -> dict[str, Any]:
        """What the API gets. ``full_prompt_capture``: the documented opt-in that also sends the whole prompt, labelled
        prompt_storage_mode "full"; otherwise only the redacted preview, labelled "redacted_preview_only"."""

        payload: dict[str, Any] = {
            "application": self.application,
            "desktop_app": self.desktop_app,
            "prompt_hash": self.prompt_hash,
            "raw_prompt": self.prompt_text if full_prompt_capture else None,
            "prompt_preview_redacted": self.prompt_preview_redacted,
            "redacted_entity_types": list(self.redacted_entity_types),
            "prompt_preview_truncated": True if self.prompt_preview_truncated else None,
            "prompt_length": len(self.prompt_text),
            "capture_method": self.capture_method,
            "machine_id": self.machine_id,
            "user_id": self.user_id,
            "user_email": self.user_email,
            "os_type": self.os_type,
            "os_version": self.os_version,
            "hostname": self.hostname,
            "active_window_title": self.active_window_title,
            "input_signal_types": list(self.input_signal_types),
            "prompt_storage_mode": "full" if full_prompt_capture else "redacted_preview_only",
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
