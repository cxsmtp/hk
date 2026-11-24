from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class AIAction:
    action_id: str
    user_id: str | None = None
    endpoint_id: str | None = None
    ai_app: str | None = None
    model: str | None = None
    prompt: str | None = None
    file: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    source_surface: str = "unknown"
    timestamp: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "user_id": self.user_id,
            "endpoint_id": self.endpoint_id,
            "ai_app": self.ai_app,
            "model": self.model,
            "prompt": self.prompt,
            "file": dict(self.file or {}),
            "metadata": dict(self.metadata or {}),
            "source_surface": self.source_surface,
            "timestamp": self.timestamp,
        }


@dataclass(slots=True)
class ControlResult:
    control_id: str
    triggered: bool
    confidence_score: float
    severity_weight: float
    risk_score: float
    reasoning: str
    evidence_refs: list[str] = field(default_factory=list)
    risk_tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "triggered": bool(self.triggered),
            "confidence_score": float(self.confidence_score),
            "severity_weight": float(self.severity_weight),
            "risk_score": float(self.risk_score),
            "reasoning": self.reasoning,
            "evidence_refs": list(self.evidence_refs or []),
            "risk_tags": list(self.risk_tags or []),
        }


@dataclass(slots=True)
class ControlDecision:
    action_id: str
    decision: str
    total_risk_score: float
    triggered_controls: list[str] = field(default_factory=list)
    evaluated_controls: list[ControlResult] = field(default_factory=list)
    dominant_control: str | None = None
    reasoning: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    risk_tags: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "decision": self.decision,
            "total_risk_score": float(self.total_risk_score),
            "triggered_controls": list(self.triggered_controls or []),
            "evaluated_controls": [row.to_dict() for row in self.evaluated_controls],
            "dominant_control": self.dominant_control,
            "reasoning": self.reasoning,
            "evidence_refs": list(self.evidence_refs or []),
            "risk_tags": list(self.risk_tags or []),
            "timestamp": self.timestamp,
        }

