from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.discovery_resolution import (
    DiscoveryAssetHypothesis,
    DiscoveryHypothesisTransition,
)
from app.db.models.evidence import EvidenceNode
from app.services.hmair.contracts import canonical_json_bytes


HYPOTHESIS_TYPES = frozenset(
    {
        "ai_application",
        "agent",
        "model_endpoint",
        "mcp_server",
        "rag_system",
        "coding_assistant",
        "unknown_ai_workload",
    }
)
TRANSITIONS = {
    "observed": frozenset({"hypothesized"}),
    "hypothesized": frozenset({"verifying", "rejected", "ambiguous"}),
    "verifying": frozenset({"confirmed", "rejected", "ambiguous"}),
    "ambiguous": frozenset({"verifying", "rejected"}),
    "confirmed": frozenset(),
    "rejected": frozenset(),
}


class HypothesisConflict(RuntimeError):
    """Hypothesis input, lifecycle, or evidence authority is invalid."""


def _digest(domain: str, material: dict[str, object]) -> str:
    hasher = hashlib.sha256()
    hasher.update(domain.encode("ascii"))
    hasher.update(canonical_json_bytes(material))
    return hasher.hexdigest()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise HypothesisConflict("hypothesis timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _evidence(db: Session, *, tenant_id: str, evidence_node_id: str) -> EvidenceNode:
    row = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.id == evidence_node_id,
        )
    )
    if row is None:
        raise HypothesisConflict("hypothesis evidence is unavailable")
    return row


def create_hypothesis(
    db: Session,
    *,
    tenant_id: str,
    hypothesis_type: str,
    label: str,
    candidate_key_hash: str,
    confidence: float,
    verification_state: str,
    freshness: str,
    contradiction_state: str,
    evidence_node_id: str,
    observed_at: datetime,
    idempotency_key: str,
) -> DiscoveryAssetHypothesis:
    if hypothesis_type not in HYPOTHESIS_TYPES:
        raise HypothesisConflict("unsupported hypothesis type")
    if not label or label != label.strip() or len(label) > 255:
        raise HypothesisConflict("hypothesis label is invalid")
    if len(candidate_key_hash) != 64 or any(
        character not in "0123456789abcdef" for character in candidate_key_hash
    ):
        raise HypothesisConflict("candidate key must be a lowercase SHA-256")
    if type(confidence) is not float or not 0.0 <= confidence <= 1.0:
        raise HypothesisConflict("hypothesis confidence is invalid")
    if verification_state not in {
        "verified", "partially_verified", "inferred", "unknown"
    }:
        raise HypothesisConflict("hypothesis verification state is invalid")
    if freshness not in {"fresh", "stale", "expired", "unknown"}:
        raise HypothesisConflict("hypothesis freshness is invalid")
    if contradiction_state not in {
        "none", "possible", "confirmed", "resolved", "unknown"
    }:
        raise HypothesisConflict("hypothesis contradiction state is invalid")
    if not idempotency_key or len(idempotency_key) > 128:
        raise HypothesisConflict("hypothesis idempotency key is invalid")
    observed_at = _utc(observed_at)
    _evidence(db, tenant_id=tenant_id, evidence_node_id=evidence_node_id)
    material = {
        "tenant_id": tenant_id,
        "hypothesis_type": hypothesis_type,
        "label": label,
        "candidate_key_hash": candidate_key_hash,
        "confidence": confidence,
        "verification_state": verification_state,
        "freshness": freshness,
        "contradiction_state": contradiction_state,
        "evidence_node_id": evidence_node_id,
        "observed_at": observed_at.isoformat(),
    }
    input_digest = _digest("hawk:discovery:hypothesis:v1", material)
    existing = db.scalar(
        select(DiscoveryAssetHypothesis).where(
            DiscoveryAssetHypothesis.tenant_id == tenant_id,
            DiscoveryAssetHypothesis.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        if existing.input_digest != input_digest:
            raise HypothesisConflict("hypothesis idempotency conflict")
        return existing
    same_candidate = db.scalar(
        select(DiscoveryAssetHypothesis).where(
            DiscoveryAssetHypothesis.tenant_id == tenant_id,
            DiscoveryAssetHypothesis.candidate_key_hash == candidate_key_hash,
        )
    )
    if same_candidate is not None:
        if same_candidate.input_digest != input_digest:
            raise HypothesisConflict("candidate evidence requires explicit review")
        return same_candidate

    row = DiscoveryAssetHypothesis(
        hypothesis_id=str(uuid4()),
        tenant_id=tenant_id,
        hypothesis_type=hypothesis_type,
        state="observed",
        label=label,
        candidate_key_hash=candidate_key_hash,
        confidence=confidence,
        verification_state=verification_state,
        freshness=freshness,
        contradiction_state=contradiction_state,
        evidence_node_id=evidence_node_id,
        promoted_asset_id=None,
        first_observed_at=observed_at,
        last_observed_at=observed_at,
        version=1,
        idempotency_key=idempotency_key,
        input_digest=input_digest,
    )
    db.add(row)
    db.flush()
    transition_material = {
        "tenant_id": tenant_id,
        "hypothesis_id": row.hypothesis_id,
        "from_state": None,
        "to_state": "observed",
        "evidence_node_id": evidence_node_id,
        "actor_id": "discovery-observation",
        "reason": "Evidence-backed candidate observed",
    }
    db.add(
        DiscoveryHypothesisTransition(
            transition_id=str(uuid4()),
            tenant_id=tenant_id,
            hypothesis_id=row.hypothesis_id,
            from_state=None,
            to_state="observed",
            evidence_node_id=evidence_node_id,
            actor_id="discovery-observation",
            reason="Evidence-backed candidate observed",
            idempotency_key=_digest(
                "hawk:discovery:hypothesis-initial-key:v1", transition_material
            ),
            input_digest=_digest(
                "hawk:discovery:hypothesis-transition:v1", transition_material
            ),
        )
    )
    db.flush()
    return row


def transition_hypothesis(
    db: Session,
    *,
    tenant_id: str,
    hypothesis_id: str,
    target_state: str,
    evidence_node_id: str,
    actor_id: str,
    reason: str,
    idempotency_key: str,
) -> DiscoveryAssetHypothesis:
    existing_transition = db.scalar(
        select(DiscoveryHypothesisTransition).where(
            DiscoveryHypothesisTransition.tenant_id == tenant_id,
            DiscoveryHypothesisTransition.idempotency_key == idempotency_key,
        )
    )
    if existing_transition is not None:
        if (
            existing_transition.hypothesis_id != hypothesis_id
            or existing_transition.to_state != target_state
            or existing_transition.evidence_node_id != evidence_node_id
            or existing_transition.actor_id != actor_id
            or existing_transition.reason != reason
        ):
            raise HypothesisConflict("hypothesis transition idempotency conflict")
        row = db.scalar(
            select(DiscoveryAssetHypothesis).where(
                DiscoveryAssetHypothesis.tenant_id == tenant_id,
                DiscoveryAssetHypothesis.hypothesis_id == hypothesis_id,
            )
        )
        if row is None:
            raise HypothesisConflict("hypothesis is unavailable")
        return row
    statement = select(DiscoveryAssetHypothesis).where(
        DiscoveryAssetHypothesis.tenant_id == tenant_id,
        DiscoveryAssetHypothesis.hypothesis_id == hypothesis_id,
    )
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        statement = statement.with_for_update()
    row = db.scalar(statement)
    if row is None:
        raise HypothesisConflict("hypothesis is unavailable")
    if target_state not in TRANSITIONS.get(row.state, frozenset()):
        raise HypothesisConflict("unsupported hypothesis lifecycle transition")
    if not actor_id or actor_id != actor_id.strip() or len(actor_id) > 128:
        raise HypothesisConflict("hypothesis actor is invalid")
    if not reason or reason != reason.strip() or len(reason) > 500:
        raise HypothesisConflict("hypothesis transition reason is invalid")
    _evidence(db, tenant_id=tenant_id, evidence_node_id=evidence_node_id)
    material = {
        "tenant_id": tenant_id,
        "hypothesis_id": hypothesis_id,
        "from_state": row.state,
        "to_state": target_state,
        "evidence_node_id": evidence_node_id,
        "actor_id": actor_id,
        "reason": reason,
    }
    transition = DiscoveryHypothesisTransition(
        transition_id=str(uuid4()),
        tenant_id=tenant_id,
        hypothesis_id=hypothesis_id,
        from_state=row.state,
        to_state=target_state,
        evidence_node_id=evidence_node_id,
        actor_id=actor_id,
        reason=reason,
        idempotency_key=idempotency_key,
        input_digest=_digest("hawk:discovery:hypothesis-transition:v1", material),
    )
    db.add(transition)
    row.state = target_state
    row.version += 1
    row.evidence_node_id = evidence_node_id
    if target_state in {"confirmed", "rejected"}:
        row.verification_state = "verified"
    elif target_state in {"verifying", "ambiguous"}:
        row.verification_state = "partially_verified"
    else:
        row.verification_state = "inferred"
    db.flush()
    return row


__all__ = [
    "HypothesisConflict",
    "create_hypothesis",
    "transition_hypothesis",
]
