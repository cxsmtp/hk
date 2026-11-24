from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.observability import get_correlation_id, log_structured
from app.db.models.ai_system import AISystem
from app.db.models.audit import AuditLog
from app.db.models.evidence import EvidenceNode
from app.services.policy_service import get_latest_policy_for_ai_system


RISK_TIER_STRICTNESS_PROFILE: dict[str, str] = {
    "MINIMAL": "baseline",
    "LIMITED": "moderate",
    "HIGH": "strict",
    "RESTRICTED": "maximum",
    "PROHIBITED": "blocked",
    # Backward compatibility for earlier tier naming.
    "LOW": "baseline",
    "MEDIUM": "moderate",
    "CRITICAL": "maximum",
}

RISK_TIER_SIMULATION_FREQUENCY: dict[str, str] = {
    "MINIMAL": "monthly",
    "LIMITED": "weekly",
    "HIGH": "daily",
    "RESTRICTED": "hourly",
    "PROHIBITED": "blocked",
    # Backward compatibility for earlier tier naming.
    "LOW": "monthly",
    "MEDIUM": "weekly",
    "CRITICAL": "hourly",
}

SIMULATION_FREQUENCY_INTERVAL_MINUTES: dict[str, int] = {
    "monthly": 60 * 24 * 30,
    "weekly": 60 * 24 * 7,
    "daily": 60 * 24,
    "hourly": 60,
    "blocked": 0,
}

STRICTNESS_RANK: dict[str, int] = {
    "baseline": 0,
    "moderate": 1,
    "strict": 2,
    "maximum": 3,
    "blocked": 4,
}


@dataclass(frozen=True)
class RiskPropagationHook:
    tenant_id: str
    ai_system_id: str
    strictness_profile: str
    simulation_frequency: str
    simulation_interval_minutes: int
    reason: str


def normalize_risk_tier(risk_tier: str | None) -> str:
    return (risk_tier or "").strip().upper()


def strictness_profile_for_risk_tier(risk_tier: str | None) -> str:
    tier = normalize_risk_tier(risk_tier)
    return RISK_TIER_STRICTNESS_PROFILE.get(tier, "baseline")


def simulation_frequency_for_risk_tier(risk_tier: str | None) -> str:
    tier = normalize_risk_tier(risk_tier)
    return RISK_TIER_SIMULATION_FREQUENCY.get(tier, "monthly")


def simulation_interval_minutes_for_frequency(frequency: str) -> int:
    return SIMULATION_FREQUENCY_INTERVAL_MINUTES.get(str(frequency).strip().lower(), 60 * 24 * 30)


def _audit_posture_degraded(
    *,
    previous_strictness: str,
    current_strictness: str,
    previous_lifecycle_state: str | None,
    current_lifecycle_state: str | None,
) -> bool:
    prev_rank = STRICTNESS_RANK.get(previous_strictness, 0)
    current_rank = STRICTNESS_RANK.get(current_strictness, 0)
    lifecycle_changed = (previous_lifecycle_state or "").strip().lower() != (current_lifecycle_state or "").strip().lower()
    current_lifecycle = (current_lifecycle_state or "").strip().lower()
    return current_rank > prev_rank or (lifecycle_changed and current_lifecycle != "active")


def apply_risk_propagation(
    db: Session,
    *,
    ai_system: AISystem,
    previous_risk_tier: str | None,
    previous_lifecycle_state: str | None,
    hook_sink: list[RiskPropagationHook] | None = None,
) -> bool:
    current_risk = normalize_risk_tier(ai_system.risk_tier)
    previous_risk = normalize_risk_tier(previous_risk_tier)
    current_lifecycle = (ai_system.status or "").strip().lower()
    previous_lifecycle = (previous_lifecycle_state or "").strip().lower()

    risk_changed = current_risk != previous_risk
    lifecycle_changed = current_lifecycle != previous_lifecycle
    if not risk_changed and not lifecycle_changed:
        return False

    strictness_profile = strictness_profile_for_risk_tier(ai_system.risk_tier)
    previous_strictness_profile = strictness_profile_for_risk_tier(previous_risk_tier)
    simulation_frequency = simulation_frequency_for_risk_tier(ai_system.risk_tier)
    simulation_interval_minutes = simulation_interval_minutes_for_frequency(simulation_frequency)
    policy = get_latest_policy_for_ai_system(db, ai_system.tenant_id, ai_system, actor_type="human")
    guardian_count = len(policy.guardian_contracts or []) if policy else 0
    now = datetime.now(timezone.utc).isoformat()

    posture_degraded = _audit_posture_degraded(
        previous_strictness=previous_strictness_profile,
        current_strictness=strictness_profile,
        previous_lifecycle_state=previous_lifecycle_state,
        current_lifecycle_state=ai_system.status,
    )

    metadata = dict(ai_system.metadata_json or {})
    propagation_payload = {
        "previous_risk_tier": previous_risk_tier,
        "current_risk_tier": ai_system.risk_tier,
        "previous_lifecycle_state": previous_lifecycle_state,
        "current_lifecycle_state": ai_system.status,
        "strictness_profile": strictness_profile,
        "simulation_frequency": simulation_frequency,
        "simulation_interval_minutes": simulation_interval_minutes,
        "guardian_policy_version_id": policy.id if policy else None,
        "guardian_count": guardian_count,
        "risk_changed": risk_changed,
        "lifecycle_changed": lifecycle_changed,
        "audit_posture_degraded": posture_degraded,
        "propagated_at": now,
    }
    metadata["enforcement_profile"] = strictness_profile
    metadata["simulation_frequency"] = simulation_frequency
    metadata["simulation_interval_minutes"] = simulation_interval_minutes
    metadata["guardian_matrix_reloaded_at"] = now
    metadata["guardian_policy_version_id"] = policy.id if policy else None
    metadata["guardian_count"] = guardian_count
    metadata["audit_posture_status"] = "degraded" if posture_degraded else "stable"
    metadata["last_risk_propagation"] = propagation_payload
    ai_system.metadata_json = metadata

    correlation_id = get_correlation_id()
    audit = AuditLog(
        tenant_id=ai_system.tenant_id,
        correlation_id=correlation_id,
        actor_user_id=None,
        actor_type="system",
        action="risk_propagation",
        resource_type="ai_system",
        resource_id=ai_system.id,
        payload=propagation_payload,
    )
    evidence = EvidenceNode(
        tenant_id=ai_system.tenant_id,
        correlation_id=correlation_id,
        node_type="risk_propagation",
        signal_type="risk_propagation",
        label=f"Risk propagation for {ai_system.id}",
        payload=propagation_payload,
    )
    db.add(audit)
    db.add(evidence)

    if hook_sink is not None and risk_changed:
        hook_sink.append(
            RiskPropagationHook(
                tenant_id=ai_system.tenant_id,
                ai_system_id=ai_system.id,
                strictness_profile=strictness_profile,
                simulation_frequency=simulation_frequency,
                simulation_interval_minutes=simulation_interval_minutes,
                reason="risk_tier_change",
            )
        )
    return True


def _enqueue_risk_reconfigure_hook(hook: RiskPropagationHook) -> None:
    from app.jobs.risk_jobs import reconfigure_risk_runtime

    reconfigure_risk_runtime.delay(
        tenant_id=hook.tenant_id,
        ai_system_id=hook.ai_system_id,
        strictness_profile=hook.strictness_profile,
        simulation_frequency=hook.simulation_frequency,
        simulation_interval_minutes=hook.simulation_interval_minutes,
        reason=hook.reason,
    )


def dispatch_risk_propagation_hooks(hooks: list[RiskPropagationHook]) -> None:
    if not hooks:
        return

    for hook in hooks:
        if settings.env == "test":
            log_structured(
                "risk_reconfigure_hook_skipped_test_env",
                tenant_id=hook.tenant_id,
                ai_system_id=hook.ai_system_id,
                strictness_profile=hook.strictness_profile,
                simulation_frequency=hook.simulation_frequency,
            )
            continue
        try:
            _enqueue_risk_reconfigure_hook(hook)
        except Exception as exc:
            log_structured(
                "risk_reconfigure_hook_enqueue_failed",
                tenant_id=hook.tenant_id,
                ai_system_id=hook.ai_system_id,
                strictness_profile=hook.strictness_profile,
                simulation_frequency=hook.simulation_frequency,
                error=str(exc),
            )
