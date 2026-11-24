"""Decision + control-mode model, mirroring the Hawk gateway semantics.

The endpoint agent speaks the same decision vocabulary as the LLM / MCP gateways
so that a decision returned by the backend maps 1:1 onto an endpoint action, and
so aggregation across controls uses identical precedence (no local re-interpretation
that could drift from the server).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# Ordered strongest -> weakest. Matches AGGREGATION_PRECEDENCE in the gateway.
AGGREGATION_PRECEDENCE: tuple[str, ...] = (
    "block",
    "hold_for_approval",
    "redact",
    "scope",
    "warn",
    "allow",
)

_RANK = {decision: index for index, decision in enumerate(AGGREGATION_PRECEDENCE)}


class Action:
    ALLOW = "allow"
    WARN = "warn"
    SCOPE = "scope"  # allowed but constrained to policy scope
    REDACT = "redact"
    HOLD = "hold_for_approval"
    BLOCK = "block"


class ControlMode:
    """How the endpoint actually enforced a decision — Hawk 'control-mode honesty'."""

    INLINE_PREVENTED = "inline_prevented"  # action stopped before it completed
    INLINE_ALLOWED = "inline_allowed"      # evaluated and permitted inline
    WARNED = "warned"                      # user warned (banner) but action continued
    SCOPED = "scoped"                      # permitted within a constrained scope
    DETECT_ONLY = "detect_only"            # observed post-hoc; OS could not pre-empt
    TELEMETRY_ONLY = "telemetry_only"      # recorded only
    EXTERNAL_REQUIRED = "external_required"  # needs an out-of-band actor to enforce
    EXTERNAL_ACTION_TRIGGERED = "external_action_triggered"  # endpoint/external control was invoked
    REVIEW_REQUIRED = "review_required"
    READY = "ready"
    UNKNOWN = "unknown"
    MONITOR_WOULD_ALLOW = "monitor_would_allow"
    MONITOR_WOULD_WARN = "monitor_would_warn"
    MONITOR_WOULD_REVIEW = "monitor_would_review"
    MONITOR_WOULD_BLOCK = "monitor_would_block"


# Which control mode an endpoint can honestly claim for a decision it *did* enforce.
_ENFORCED_MODE = {
    Action.ALLOW: ControlMode.INLINE_ALLOWED,
    Action.WARN: ControlMode.WARNED,
    Action.SCOPE: ControlMode.SCOPED,
    Action.REDACT: ControlMode.INLINE_PREVENTED,
    Action.HOLD: ControlMode.EXTERNAL_REQUIRED,
    Action.BLOCK: ControlMode.INLINE_PREVENTED,
}


@dataclass
class Decision:
    """A single control decision. ``source`` records where it came from so the
    provenance is auditable (``backend`` vs ``fail_secure_cache`` vs ``fail_secure_default``)."""

    action: str
    control_mode: str
    reason: str
    source: str = "backend"
    confidence: float = 1.0
    threat_types: list[str] = field(default_factory=list)
    framework_refs: dict[str, Any] = field(default_factory=dict)
    evidence_ref: str | None = None
    enforced: bool = False  # set True once the endpoint actually applied it
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def is_blocking(self) -> bool:
        return self.action in {Action.BLOCK, Action.HOLD, Action.REDACT}

    @property
    def requires_user_notice(self) -> bool:
        return self.action in {Action.BLOCK, Action.WARN, Action.HOLD, Action.SCOPE}

    def honest_mode_for(self, os_can_prevent: bool) -> str:
        """Return the control mode the endpoint can *honestly* claim.

        If the OS cannot actually pre-empt the action, a ``block`` degrades to
        ``detect_only`` rather than falsely reporting prevention.
        """
        if self.action in {Action.BLOCK, Action.REDACT} and not os_can_prevent:
            return ControlMode.DETECT_ONLY
        return _ENFORCED_MODE.get(self.action, ControlMode.TELEMETRY_ONLY)


def rank(action: str) -> int:
    return _RANK.get(str(action or "").strip().lower(), _RANK["allow"])


def aggregate(actions: list[str]) -> str:
    """Return the strongest action by gateway precedence."""
    strongest = "allow"
    for action in actions:
        if rank(action) < rank(strongest):
            strongest = str(action or "allow").strip().lower()
    return strongest


def merge(decisions: list[Decision], *, default_reason: str = "aggregated") -> Decision:
    """Merge multiple control decisions into one, strongest-wins."""
    if not decisions:
        return Decision(action=Action.ALLOW, control_mode=ControlMode.INLINE_ALLOWED, reason="no_controls_triggered")
    winner = min(decisions, key=lambda d: rank(d.action))
    threat_types = sorted({t for d in decisions for t in d.threat_types})
    winner.threat_types = threat_types
    if not winner.reason:
        winner.reason = default_reason
    return winner
