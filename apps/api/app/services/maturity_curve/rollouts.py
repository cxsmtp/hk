"""Approval-gated maturity policy rollout lifecycle.

The lifecycle owns no independent enforcement engine.  Approval creates an
ordinary ``PolicyPack``/``PolicyVersion`` from the exact reviewed draft; the
existing policy runtime remains the only runtime decision authority.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.maturity_curve import (
    MaturityPolicyRecommendation,
    MaturityPolicyRollout,
    MaturityPolicySimulation,
    MaturityRolloutTransition,
)
from app.db.models.policy import PolicyPack, PolicyVersion
from app.services.maturity_curve.entitlements import require_maturity_capability
from app.services.maturity_curve.service import _bounded_refs, _canonical_digest


ALLOWED_TRANSITIONS: Final[dict[str, set[str]]] = {
    "DRAFT": {"REVIEW", "REJECTED", "EXPIRED"},
    "REVIEW": {"APPROVED", "REJECTED", "EXPIRED"},
    "APPROVED": {"SHADOW", "EXPIRED"},
    "SHADOW": {"ENFORCE", "PAUSED", "ROLLED_BACK"},
    "ENFORCE": {"MONITOR", "PAUSED", "ROLLED_BACK"},
    "MONITOR": {"PAUSED", "ROLLED_BACK"},
    "PAUSED": {"SHADOW", "ROLLED_BACK"},
    "REJECTED": set(),
    "ROLLED_BACK": set(),
    "EXPIRED": set(),
}
ROLLOUT_STAGES: Final[set[str]] = {"monitor", "notify", "warn", "require_approval", "enforce", "validate"}
_STAGE_STRENGTH: Final[dict[str, int]] = {"monitor": 0, "notify": 1, "warn": 2, "require_approval": 3, "enforce": 4}


def _now(now: datetime | None) -> datetime:
    current = now or datetime.now(timezone.utc)
    return current if current.tzinfo is not None else current.replace(tzinfo=timezone.utc)


def _load_rollout_context(
    db: Session,
    *,
    tenant_id: str,
    recommendation_id: str,
) -> MaturityPolicyRecommendation:
    recommendation = db.scalar(
        select(MaturityPolicyRecommendation).where(
            MaturityPolicyRecommendation.tenant_id == tenant_id,
            MaturityPolicyRecommendation.id == recommendation_id,
        )
    )
    if recommendation is None:
        raise ValueError("maturity_recommendation_not_found")
    return recommendation


def _rollout_digest(
    recommendation: MaturityPolicyRecommendation,
    *,
    state: str,
    mode: str,
    rollout_stage: str,
) -> str:
    return _canonical_digest(
        {
            "recommendation_id": recommendation.id,
            "recommendation_digest": recommendation.recommendation_digest,
            "candidate_policy_version_id": recommendation.candidate_policy_version_id,
            "state": state,
            "mode": mode,
            "rollout_stage": rollout_stage,
        }
    )


def _record_transition(
    db: Session,
    *,
    rollout: MaturityPolicyRollout,
    from_state: str | None,
    to_state: str,
    actor_ref: str,
    reason: str,
    evidence_refs: list[str],
) -> None:
    db.add(
        MaturityRolloutTransition(
            tenant_id=rollout.tenant_id,
            rollout_id=rollout.id,
            from_state=from_state,
            to_state=to_state,
            actor_ref=actor_ref or None,
            reason=str(reason or "").strip()[:500],
            evidence_refs=_bounded_refs(evidence_refs, maximum=100),
        )
    )


def create_policy_rollout(
    db: Session,
    *,
    tenant_id: str,
    recommendation_id: str,
    actor_ref: str,
) -> MaturityPolicyRollout:
    """Create or return the immutable start of an approval-gated lifecycle."""

    require_maturity_capability(db, tenant_id=tenant_id, capability="approval_workflow")
    recommendation = _load_rollout_context(db, tenant_id=tenant_id, recommendation_id=recommendation_id)
    existing = db.scalar(
        select(MaturityPolicyRollout).where(
            MaturityPolicyRollout.tenant_id == tenant_id,
            MaturityPolicyRollout.recommendation_id == recommendation.id,
        )
    )
    if existing is not None:
        return existing
    rollout = MaturityPolicyRollout(
        tenant_id=tenant_id,
        scope_id=recommendation.scope_id,
        recommendation_id=recommendation.id,
        policy_version_id=recommendation.candidate_policy_version_id,
        state="DRAFT",
        mode="monitor",
        rollout_stage="monitor",
        rollout_digest=_rollout_digest(recommendation, state="DRAFT", mode="monitor", rollout_stage="monitor"),
        requested_by_ref=str(actor_ref or "").strip() or None,
    )
    db.add(rollout)
    db.flush()
    _record_transition(
        db,
        rollout=rollout,
        from_state=None,
        to_state="DRAFT",
        actor_ref=actor_ref,
        reason="maturity_policy_rollout_created",
        evidence_refs=[f"maturity_policy_recommendation:{recommendation.id}"],
    )
    db.flush()
    return rollout


def _passed_simulation(db: Session, *, tenant_id: str, recommendation_id: str) -> MaturityPolicySimulation | None:
    return db.scalar(
        select(MaturityPolicySimulation)
        .where(
            MaturityPolicySimulation.tenant_id == tenant_id,
            MaturityPolicySimulation.recommendation_id == recommendation_id,
            MaturityPolicySimulation.passed.is_(True),
        )
        .order_by(MaturityPolicySimulation.created_at.desc(), MaturityPolicySimulation.id.desc())
    )


def _latest_active_policy_version(db: Session, *, tenant_id: str) -> tuple[PolicyPack, PolicyVersion] | None:
    """Return the version that existing runtime selection would choose.

    A Maturity rollout must layer on this immutable policy authority rather
    than activate a standalone pack that silently displaces it.
    """

    row = db.execute(
        select(PolicyPack, PolicyVersion)
        .join(PolicyVersion, PolicyVersion.pack_id == PolicyPack.id)
        .where(
            PolicyPack.tenant_id == tenant_id,
            PolicyVersion.tenant_id == tenant_id,
            PolicyPack.status == "active",
        )
        .order_by(PolicyVersion.created_at.desc(), PolicyVersion.id.desc())
        .limit(1)
    ).first()
    if row is None:
        return None
    return row[0], row[1]


def _derived_version_label(base_version: str, digest: str, *, suffix: str) -> str:
    """Keep immutable version identifiers readable and within the existing limit."""

    return f"{str(base_version or 'policy')[:12]}-{suffix}-{digest[:12]}"[:32]


def _next_policy_version_timestamp(
    db: Session,
    *,
    tenant_id: str,
    pack_id: str,
    minimum: datetime,
) -> datetime:
    """Preserve immutable runtime selection ordering across fast transitions."""

    latest = db.scalar(
        select(PolicyVersion.created_at)
        .where(PolicyVersion.tenant_id == tenant_id, PolicyVersion.pack_id == pack_id)
        .order_by(PolicyVersion.created_at.desc(), PolicyVersion.id.desc())
        .limit(1)
    )
    if latest is None:
        return minimum
    if latest.tzinfo is None:
        latest = latest.replace(tzinfo=timezone.utc)
    if minimum.tzinfo is None:
        minimum = minimum.replace(tzinfo=timezone.utc)
    return latest + timedelta(microseconds=1) if latest >= minimum else minimum


def _maturity_metadata(version: PolicyVersion) -> dict[str, object]:
    contract = version.contract_json if isinstance(version.contract_json, dict) else {}
    metadata = contract.get("maturity_curve")
    return dict(metadata) if isinstance(metadata, dict) else {}


def _policy_version_from_maturity_draft(
    db: Session,
    *,
    recommendation: MaturityPolicyRecommendation,
    actor_ref: str,
    now: datetime,
) -> PolicyVersion:
    scoped_rules = recommendation.policy_draft.get("scoped_rules") if isinstance(recommendation.policy_draft, dict) else None
    if not isinstance(scoped_rules, list) or not scoped_rules:
        raise ValueError("maturity_recommendation_has_no_scoped_rules")

    active = _latest_active_policy_version(db, tenant_id=recommendation.tenant_id)
    if active is None:
        pack = PolicyPack(
            tenant_id=recommendation.tenant_id,
            name=f"Maturity draft: {recommendation.title}"[:255],
            description="Evidence-backed Maturity Curve draft. It remains inactive until the approved rollout reaches Enforce.",
            status="draft",
        )
        db.add(pack)
        db.flush()
        scope = {"scoped_rules": deepcopy(scoped_rules)}
        contract = {
            "profile": "maturity_curve",
            "source_recommendation_id": recommendation.id,
            "recommendation_digest": recommendation.recommendation_digest,
            "created_by_ref": str(actor_ref or ""),
            "scope": scope,
            "enforcement_defaults": {"default_decision": "warn"},
            "guardian_contracts": [],
            "maturity_curve": {
                "source_recommendation_id": recommendation.id,
                "recommendation_digest": recommendation.recommendation_digest,
                "owns_policy_pack": True,
            },
        }
        version = PolicyVersion(
            tenant_id=recommendation.tenant_id,
            pack_id=pack.id,
            version=f"maturity-{recommendation.recommendation_digest[:12]}",
            created_by=None,
            created_at=now,
            scope=scope,
            enforcement_defaults={"default_decision": "warn"},
            guardian_contracts=[],
            contract_json=contract,
        )
        db.add(version)
        db.flush()
        return version

    pack, base = active
    scope = deepcopy(base.scope) if isinstance(base.scope, dict) else {}
    existing_rules = scope.get("scoped_rules") if isinstance(scope.get("scoped_rules"), list) else []
    existing_rule_ids = {
        str(rule.get("rule_id") or "").strip()
        for rule in existing_rules
        if isinstance(rule, dict)
    }
    appended_rules = [
        deepcopy(rule)
        for rule in scoped_rules
        if not isinstance(rule, dict) or str(rule.get("rule_id") or "").strip() not in existing_rule_ids
    ]
    scope["scoped_rules"] = [*deepcopy(existing_rules), *appended_rules]
    contract = deepcopy(base.contract_json) if isinstance(base.contract_json, dict) else {}
    contract["scope"] = deepcopy(scope)
    contract["enforcement_defaults"] = deepcopy(base.enforcement_defaults or {})
    contract["guardian_contracts"] = deepcopy(base.guardian_contracts or [])
    contract["maturity_curve"] = {
        "source_recommendation_id": recommendation.id,
        "recommendation_digest": recommendation.recommendation_digest,
        "source_policy_version_id": base.id,
        "owns_policy_pack": False,
        "added_rule_ids": [
            str(rule.get("rule_id") or "")
            for rule in appended_rules
            if isinstance(rule, dict)
        ],
    }
    version = PolicyVersion(
        tenant_id=recommendation.tenant_id,
        pack_id=pack.id,
        version=_derived_version_label(base.version, recommendation.recommendation_digest, suffix="maturity"),
        created_by=base.created_by,
        created_at=now,
        scope=scope,
        enforcement_defaults=deepcopy(base.enforcement_defaults or {}),
        guardian_contracts=deepcopy(base.guardian_contracts or []),
        contract_json=contract,
    )
    db.add(version)
    db.flush()
    return version


def _ensure_versioned_policy(
    db: Session,
    *,
    recommendation: MaturityPolicyRecommendation,
    actor_ref: str,
    now: datetime,
) -> PolicyVersion:
    if recommendation.candidate_policy_version_id:
        existing = db.scalar(
            select(PolicyVersion).where(
                PolicyVersion.tenant_id == recommendation.tenant_id,
                PolicyVersion.id == recommendation.candidate_policy_version_id,
            )
        )
        if existing is not None:
            return existing
        raise ValueError("maturity_candidate_policy_version_not_found")
    version = _policy_version_from_maturity_draft(
        db,
        recommendation=recommendation,
        actor_ref=actor_ref,
        now=now,
    )
    recommendation.candidate_policy_version_id = version.id
    return version


def _recommendation_decision(recommendation: MaturityPolicyRecommendation) -> str:
    draft = recommendation.policy_draft if isinstance(recommendation.policy_draft, dict) else {}
    rules = draft.get("scoped_rules") if isinstance(draft.get("scoped_rules"), list) else []
    for rule in rules:
        effect = rule.get("effect") if isinstance(rule, dict) else None
        decision = str(effect.get("decision") or "").strip().lower() if isinstance(effect, dict) else ""
        if decision:
            return decision
    return "warn"


def _phase_decision(stage: str, recommendation: MaturityPolicyRecommendation) -> str:
    if stage in {"notify", "warn"}:
        return "warn"
    if stage == "require_approval":
        return "require_approval"
    return _recommendation_decision(recommendation)


def _default_rollout_stage(recommendation: MaturityPolicyRecommendation) -> str:
    decision = _recommendation_decision(recommendation)
    return decision if decision in {"warn", "require_approval"} else "enforce"


def _phase_version_from_candidate(
    db: Session,
    *,
    recommendation: MaturityPolicyRecommendation,
    rollout: MaturityPolicyRollout,
    stage: str,
    now: datetime,
) -> PolicyVersion:
    """Create a short-lived immutable rollout-phase policy version.

    The phase version changes only Maturity-owned rule effects. Existing rules
    and their precedence remain untouched. It lets a reviewable block proposal
    begin as warn or approval instead of being activated as a block early.
    """

    if stage == "enforce":
        version = _ensure_versioned_policy(db, recommendation=recommendation, actor_ref=rollout.requested_by_ref or "", now=now)
        return version
    candidate_id = str(recommendation.candidate_policy_version_id or rollout.policy_version_id or "").strip()
    candidate = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.tenant_id == recommendation.tenant_id,
            PolicyVersion.id == candidate_id,
        )
    )
    if candidate is None:
        candidate = _ensure_versioned_policy(db, recommendation=recommendation, actor_ref=rollout.requested_by_ref or "", now=now)
    metadata = _maturity_metadata(candidate)
    owned_ids = {
        str(item).strip()
        for item in metadata.get("added_rule_ids", [])
        if str(item).strip()
    }
    if not owned_ids:
        draft = recommendation.policy_draft if isinstance(recommendation.policy_draft, dict) else {}
        owned_ids = {
            str(rule.get("rule_id") or "").strip()
            for rule in (draft.get("scoped_rules") or [])
            if isinstance(rule, dict) and str(rule.get("rule_id") or "").strip()
        }
    scope = deepcopy(candidate.scope) if isinstance(candidate.scope, dict) else {}
    rules = scope.get("scoped_rules") if isinstance(scope.get("scoped_rules"), list) else []
    updated_rules: list[dict] = []
    for raw_rule in rules:
        rule = deepcopy(raw_rule) if isinstance(raw_rule, dict) else raw_rule
        if isinstance(rule, dict) and str(rule.get("rule_id") or "").strip() in owned_ids:
            effect = deepcopy(rule.get("effect") or {}) if isinstance(rule.get("effect"), dict) else {}
            effect["decision"] = _phase_decision(stage, recommendation)
            effect["reason_code"] = f"maturity_rollout_{stage}"
            rule["effect"] = effect
        updated_rules.append(rule)
    scope["scoped_rules"] = updated_rules
    contract = deepcopy(candidate.contract_json) if isinstance(candidate.contract_json, dict) else {}
    phase_metadata = dict(_maturity_metadata(candidate))
    phase_metadata["rollout_stage"] = stage
    phase_metadata["phase_source_policy_version_id"] = candidate.id
    contract["scope"] = deepcopy(scope)
    contract["maturity_curve"] = phase_metadata
    version = PolicyVersion(
        tenant_id=candidate.tenant_id,
        pack_id=candidate.pack_id,
        version=_derived_version_label(candidate.version, f"{candidate.id}{stage}", suffix="phase"),
        created_by=candidate.created_by,
        # Existing scoped-policy selection orders by creation time. Keep this
        # phase version unambiguously newer than every preceding phase.
        created_at=_next_policy_version_timestamp(
            db,
            tenant_id=candidate.tenant_id,
            pack_id=candidate.pack_id,
            minimum=now,
        ),
        scope=scope,
        enforcement_defaults=deepcopy(candidate.enforcement_defaults or {}),
        guardian_contracts=deepcopy(candidate.guardian_contracts or []),
        contract_json=contract,
    )
    db.add(version)
    db.flush()
    return version


def _restore_pre_maturity_policy_if_current(
    db: Session,
    *,
    tenant_id: str,
    version: PolicyVersion,
    now: datetime,
) -> PolicyVersion | None:
    """Append an immutable restore version only if this rollout is current.

    Rollback never retires a shared policy pack. If a later policy version has
    already superseded this rollout, no restoration is needed and Hawk leaves
    that later authority untouched.
    """

    metadata = _maturity_metadata(version)
    source_id = str(metadata.get("source_policy_version_id") or "").strip()
    if not source_id or bool(metadata.get("owns_policy_pack")):
        return None
    current = _latest_active_policy_version(db, tenant_id=tenant_id)
    if current is None or current[1].id != version.id:
        return None
    base = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.tenant_id == tenant_id,
            PolicyVersion.id == source_id,
            PolicyVersion.pack_id == version.pack_id,
        )
    )
    if base is None:
        raise ValueError("maturity_rollout_restore_source_not_found")
    contract = deepcopy(base.contract_json) if isinstance(base.contract_json, dict) else {}
    contract["maturity_curve_rollback"] = {
        "rolled_back_policy_version_id": version.id,
        "restored_source_policy_version_id": base.id,
    }
    restored = PolicyVersion(
        tenant_id=tenant_id,
        pack_id=base.pack_id,
        version=_derived_version_label(base.version, version.id.replace("-", ""), suffix="restore"),
        created_by=base.created_by,
        # Make restoration unambiguously newer than an existing phase version.
        created_at=_next_policy_version_timestamp(
            db,
            tenant_id=base.tenant_id,
            pack_id=base.pack_id,
            minimum=now,
        ),
        scope=deepcopy(base.scope or {}),
        enforcement_defaults=deepcopy(base.enforcement_defaults or {}),
        guardian_contracts=deepcopy(base.guardian_contracts or []),
        contract_json=contract,
    )
    db.add(restored)
    db.flush()
    return restored


def transition_policy_rollout(
    db: Session,
    *,
    tenant_id: str,
    rollout_id: str,
    target_state: str,
    actor_ref: str,
    reason: str,
    rollout_stage: str | None = None,
    now: datetime | None = None,
) -> MaturityPolicyRollout:
    """Move a rollout through Review → Approval → Shadow → Enforce.

    No state mutation bypasses the approved transition graph.  Enforce is
    unavailable without a passed simulation and an exact persisted policy
    version.
    """

    require_maturity_capability(db, tenant_id=tenant_id, capability="approval_workflow")
    rollout = db.scalar(
        select(MaturityPolicyRollout).where(
            MaturityPolicyRollout.tenant_id == tenant_id,
            MaturityPolicyRollout.id == rollout_id,
        )
    )
    if rollout is None:
        raise ValueError("maturity_rollout_not_found")
    recommendation = _load_rollout_context(db, tenant_id=tenant_id, recommendation_id=rollout.recommendation_id)
    current = str(rollout.state or "").upper()
    target = str(target_state or "").upper()
    same_state_enforcement_escalation = current == "ENFORCE" and target == "ENFORCE"
    if target not in ALLOWED_TRANSITIONS.get(current, set()) and not same_state_enforcement_escalation:
        raise ValueError("maturity_rollout_transition_not_allowed")
    timestamp = _now(now)
    requested_stage = str(rollout_stage or "").strip().lower()
    if requested_stage and requested_stage not in ROLLOUT_STAGES:
        raise ValueError("maturity_rollout_stage_not_supported")
    if same_state_enforcement_escalation:
        if not requested_stage or requested_stage not in _STAGE_STRENGTH:
            raise ValueError("maturity_rollout_enforce_stage_not_supported")
        current_strength = _STAGE_STRENGTH.get(str(rollout.rollout_stage or "monitor").lower(), -1)
        if _STAGE_STRENGTH[requested_stage] <= current_strength:
            raise ValueError("maturity_rollout_stage_must_escalate")

    if target == "APPROVED":
        if rollout.requested_by_ref and str(rollout.requested_by_ref) == str(actor_ref or "").strip():
            raise ValueError("maturity_rollout_self_approval_not_allowed")
        simulation = _passed_simulation(db, tenant_id=tenant_id, recommendation_id=recommendation.id)
        if simulation is None:
            raise ValueError("maturity_rollout_requires_passed_simulation")
        version = _ensure_versioned_policy(
            db,
            recommendation=recommendation,
            actor_ref=actor_ref,
            now=timestamp,
        )
        rollout.policy_version_id = version.id
        rollout.approved_by_ref = str(actor_ref or "").strip() or None
        rollout.approved_at = timestamp
        recommendation.status = "APPROVED"
    elif target in {"SHADOW", "ENFORCE"}:
        if not rollout.policy_version_id:
            raise ValueError("maturity_rollout_requires_versioned_policy")
        simulation = _passed_simulation(db, tenant_id=tenant_id, recommendation_id=recommendation.id)
        if simulation is None:
            raise ValueError("maturity_rollout_requires_passed_simulation")
        if target == "ENFORCE":
            effective_stage = requested_stage or _default_rollout_stage(recommendation)
            if effective_stage not in {"notify", "warn", "require_approval", "enforce"}:
                raise ValueError("maturity_rollout_enforce_stage_not_supported")
            version = db.scalar(
                select(PolicyVersion).where(
                    PolicyVersion.tenant_id == tenant_id,
                    PolicyVersion.id == rollout.policy_version_id,
                )
            )
            if version is None:
                raise ValueError("maturity_rollout_policy_version_not_found")
            if effective_stage != "enforce":
                version = _phase_version_from_candidate(
                    db,
                    recommendation=recommendation,
                    rollout=rollout,
                    stage=effective_stage,
                    now=timestamp,
                )
                rollout.policy_version_id = version.id
            pack = db.scalar(
                select(PolicyPack).where(
                    PolicyPack.tenant_id == tenant_id,
                    PolicyPack.id == version.pack_id,
                )
            )
            if pack is None:
                raise ValueError("maturity_rollout_policy_pack_not_found")
            pack.status = "active"
            rollout.effective_at = timestamp
    elif target == "ROLLED_BACK":
        if rollout.policy_version_id:
            version = db.scalar(
                select(PolicyVersion).where(
                    PolicyVersion.tenant_id == tenant_id,
                    PolicyVersion.id == rollout.policy_version_id,
                )
            )
            if version is not None:
                pack = db.scalar(
                    select(PolicyPack).where(
                        PolicyPack.tenant_id == tenant_id,
                        PolicyPack.id == version.pack_id,
                    )
                )
                if pack is not None:
                    metadata = _maturity_metadata(version)
                    if bool(metadata.get("owns_policy_pack")):
                        pack.status = "retired"
                    else:
                        restored = _restore_pre_maturity_policy_if_current(
                            db,
                            tenant_id=tenant_id,
                            version=version,
                            now=timestamp,
                        )
                        if restored is not None:
                            reason = f"{str(reason or '').strip()[:400]} | restored_policy_version:{restored.id}"
        rollout.rollback_reason = str(reason or "").strip()[:2000] or "maturity_rollout_rolled_back"

    previous_state = current
    rollout.state = target
    rollout.mode = "shadow" if target == "SHADOW" else "enforce" if target in {"ENFORCE", "MONITOR"} else "monitor"
    if target == "SHADOW":
        rollout.rollout_stage = "monitor"
    elif target == "ENFORCE":
        rollout.rollout_stage = requested_stage or _default_rollout_stage(recommendation)
    elif target == "MONITOR":
        rollout.rollout_stage = "validate"
    elif target in {"PAUSED", "ROLLED_BACK"}:
        rollout.rollout_stage = "monitor"
    elif requested_stage:
        rollout.rollout_stage = requested_stage
    rollout.rollout_digest = _rollout_digest(
        recommendation,
        state=target,
        mode=rollout.mode,
        rollout_stage=rollout.rollout_stage,
    )
    _record_transition(
        db,
        rollout=rollout,
        from_state=previous_state,
        to_state=target,
        actor_ref=actor_ref,
        reason=reason,
        evidence_refs=[
            f"maturity_policy_recommendation:{recommendation.id}",
            *(
                [f"policy_version:{rollout.policy_version_id}"]
                if rollout.policy_version_id
                else []
            ),
        ],
    )
    db.flush()
    return rollout
