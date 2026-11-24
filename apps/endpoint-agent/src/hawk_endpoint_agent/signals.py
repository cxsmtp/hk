"""Signal model — what collectors emit and modules evaluate.

A signal is an *observation*, never a verdict. Signals are sent to the backend
for a decision (server-authoritative) and are also the unit of local evidence.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


class SignalKind:
    PROCESS = "process"
    AUDIO_CAPTURE = "audio_capture"
    NETWORK_EGRESS = "network_egress"
    MEETING_STATE = "meeting_state"
    AI_INTERACTION = "ai_interaction"       # prompt/response to an AI system
    DATA_TRANSFER = "data_transfer"         # copy/paste / upload
    AI_APP_DISCOVERED = "ai_app_discovered"  # shadow-AI discovery
    AGENT_ACTION = "agent_action"           # local agent / MCP tool call
    NOTETAKER = "notetaker"


@dataclass
class Signal:
    kind: str
    subject: str                    # e.g. process name, domain, tool name
    attributes: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    ts: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "subject": self.subject,
            "attributes": self.attributes,
            "confidence": round(self.confidence, 4),
            "ts": self.ts,
        }
