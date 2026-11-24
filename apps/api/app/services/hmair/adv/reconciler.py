from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.discovery_verification import (
    DiscoveryVerificationEpisode,
    DiscoveryVerificationEvent,
    DiscoveryVerificationResult,
)
from app.services.hmair.contracts import canonical_json_bytes


class VerificationReconciliationConflict(RuntimeError):
    """Accepted ADV evidence cannot be attached to its canonical chain."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise VerificationReconciliationConflict("reconciliation time must be timezone-aware")
    return value.astimezone(timezone.utc)


class VerificationEvidenceReconciler:
    """Attach ADV facts to the existing ecosystem timeline without inventing evidence."""

    def reconcile(
        self,
        db: Session,
        *,
        tenant_id: str,
        result_id: str,
        reconciled_at: datetime,
        idempotency_key: str,
    ) -> DiscoveryVerificationEvent:
        at = _utc(reconciled_at)
        result = db.scalar(
            select(DiscoveryVerificationResult).where(
                DiscoveryVerificationResult.tenant_id == tenant_id,
                DiscoveryVerificationResult.result_id == result_id,
            )
        )
        if result is None:
            raise VerificationReconciliationConflict("verification result is unavailable")
        episode = db.scalar(
            select(DiscoveryVerificationEpisode).where(
                DiscoveryVerificationEpisode.tenant_id == tenant_id,
                DiscoveryVerificationEpisode.episode_id == result.episode_id,
            )
        )
        if episode is None:
            raise VerificationReconciliationConflict("verification episode is unavailable")
        event_type = {
            "verified": "evidence_added",
            "contradicted": "verification_contradicted",
        }.get(result.outcome, "verification_updated")
        material: dict[str, object] = {
            "tenant_id": tenant_id,
            "result_id": result_id,
            "result_input_digest": result.input_digest,
            "event_type": event_type,
            "reconciled_at": at.isoformat(),
        }
        digest = hashlib.sha256(
            b"hawk:discovery:verification-reconciliation:v1"
            + canonical_json_bytes(material)
        ).hexdigest()
        existing = db.scalar(
            select(DiscoveryVerificationEvent).where(
                DiscoveryVerificationEvent.tenant_id == tenant_id,
                DiscoveryVerificationEvent.idempotency_key == idempotency_key,
            )
        )
        if existing is not None:
            if existing.input_digest != digest:
                raise VerificationReconciliationConflict("reconciliation idempotency conflict")
            return existing
        event = DiscoveryVerificationEvent(
            event_id=str(uuid4()), tenant_id=tenant_id,
            ecosystem_id=episode.ecosystem_id,
            ecosystem_record_id=episode.ecosystem_record_id,
            episode_id=episode.episode_id, assertion_id=None,
            event_type=event_type, occurred_at=at,
            actor_id=result.source_identity, actor_type="collector",
            evidence_node_ids_json=list(result.evidence_node_ids_json),
            before_json={},
            after_json={
                "result_id": result.result_id,
                "requirement_record_id": result.requirement_record_id,
                "outcome": result.outcome,
            },
            reason=f"Accepted {result.outcome} verification result",
            idempotency_key=idempotency_key, input_digest=digest,
        )
        db.add(event)
        db.flush()
        return event


__all__ = ["VerificationEvidenceReconciler", "VerificationReconciliationConflict"]
