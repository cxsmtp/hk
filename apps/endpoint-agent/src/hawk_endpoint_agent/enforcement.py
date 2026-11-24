"""Inline enforcement orchestrator.

Every capability module funnels through here so there is exactly one place that:
  * calls the backend for a decision (server-authoritative — no drift),
  * maps the backend response onto the shared Decision model,
  * applies the configured fail-secure posture when the backend is unreachable,
  * records the *honest* control mode for the surface (whether the endpoint could
    truly pre-empt the action, or only detect it).
"""

from __future__ import annotations

from typing import Any, Callable

from .config import AgentConfig
from .decision import Action, ControlMode, Decision
from .hawk_client import HawkApiError, HawkUnavailable
from .policy import PolicyStore

# Surfaces where the agent can actually pre-empt an action before it completes.
# On surfaces it can only observe, a "block" is honestly downgraded to detect_only.
_PREVENTABLE_SURFACES = {"llm_prompt", "data_transfer", "agent_action"}

_CONTROL_MODE = {
    Action.ALLOW: ControlMode.INLINE_ALLOWED,
    Action.WARN: ControlMode.WARNED,
    Action.SCOPE: ControlMode.SCOPED,
    Action.REDACT: ControlMode.INLINE_PREVENTED,
    Action.HOLD: ControlMode.EXTERNAL_REQUIRED,
    Action.BLOCK: ControlMode.INLINE_PREVENTED,
}

_APPROVAL_DECISIONS = {
    "review",
    "require_approval",
    "require_second_approval",
    "step_up",
}


def decision_from_response(response: dict[str, Any], *, surface: str) -> Decision:
    """Map a Hawk gateway/DLP response onto a Decision."""
    backend_action = str(
        response.get("final_decision") or response.get("decision") or ""
    ).strip().lower()
    if backend_action in _APPROVAL_DECISIONS:
        action = Action.HOLD
    elif backend_action in _CONTROL_MODE:
        action = backend_action
    else:
        action = Action.BLOCK

    guardian_results = response.get("guardian_results") or []
    threat_types = sorted(
        {t for g in guardian_results if isinstance(g, dict) for t in (g.get("threat_types") or [])}
    )
    frameworks = {}
    detectors = (response.get("final_actions") or {}).get("threat_detectors") if isinstance(response.get("final_actions"), dict) else None
    if isinstance(detectors, dict):
        frameworks = detectors.get("frameworks") or {}
    pre_action = response.get("pre_action_governance_check")
    if not isinstance(pre_action, dict):
        pre_action = {}
    pre_action_evidence = pre_action.get("evidence")
    if not isinstance(pre_action_evidence, dict):
        pre_action_evidence = {}
    evidence_refs = [
        str(item).strip()
        for item in (pre_action_evidence.get("evidence_refs") or [])
        if str(item).strip()
    ]
    pre_action_policy = pre_action.get("policy")
    if not isinstance(pre_action_policy, dict):
        pre_action_policy = {}
    policy_version_id = (
        response.get("policy_version_id")
        or pre_action_policy.get("policy_version_id")
        or pre_action_policy.get("id")
    )

    os_can_prevent = surface in _PREVENTABLE_SURFACES
    control_mode = _CONTROL_MODE.get(action, ControlMode.TELEMETRY_ONLY)
    if action in {Action.BLOCK, Action.REDACT} and not os_can_prevent:
        control_mode = ControlMode.DETECT_ONLY

    detail = {"surface": surface}
    if policy_version_id:
        detail["policy_version_id"] = str(policy_version_id)
        detail["policy_id"] = str(policy_version_id)

    return Decision(
        action=action,
        control_mode=control_mode,
        reason=str(response.get("reason_code") or response.get("reason") or "policy_evaluation"),
        source="backend",
        threat_types=threat_types,
        framework_refs=frameworks,
        evidence_ref=response.get("evidence_bundle_id") or response.get("audit_log_id") or response.get("evidence_node_id") or (evidence_refs[0] if evidence_refs else None),
        detail=detail,
    )


class EnforcementOrchestrator:
    def __init__(self, config: AgentConfig, policy: PolicyStore) -> None:
        self._config = config
        self._policy = policy

    def evaluate(
        self,
        *,
        endpoint: Callable[[dict[str, Any]], dict[str, Any]],
        payload: dict[str, Any],
        surface: str,
    ) -> Decision:
        """Call the backend endpoint for a decision; fail secure if unreachable."""
        if self._policy.policy is not None and self._policy.policy.platform_mode in {"discovery", "monitor"}:
            # In discovery/monitor mode the backend still evaluates, but the agent
            # will not block; it records what it *would* have done.
            pass
        try:
            response = endpoint(payload)
        except (HawkUnavailable, HawkApiError) as exc:
            decision = self._policy.fail_secure_decision(surface=surface, reason=type(exc).__name__)
            decision.detail["error"] = str(exc)
            return decision
        return decision_from_response(response, surface=surface)

    def platform_mode(self) -> str:
        if self._policy.policy is not None:
            return self._policy.policy.platform_mode
        return "enforce"
