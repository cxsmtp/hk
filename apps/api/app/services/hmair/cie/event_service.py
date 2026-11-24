from __future__ import annotations

import hashlib
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.capability_inference import (
    DiscoveryCapabilityEvent,
    DiscoveryCapabilityGenome,
)
from app.services.hmair.cie.contracts import CapabilityDriftEvent
from app.services.hmair.contracts import canonical_json_bytes


class CapabilityEventService:
    def record_drift(
        self,
        db: Session,
        *,
        tenant_id: str,
        previous: DiscoveryCapabilityGenome | None,
        current: DiscoveryCapabilityGenome,
        evidence_references: tuple[str, ...],
        occurred_at,
    ) -> tuple[CapabilityDriftEvent, ...]:
        if current.tenant_id != tenant_id or (
            previous is not None and previous.tenant_id != tenant_id
        ):
            raise ValueError("genome drift must remain in tenant scope")
        if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
            raise ValueError("drift timestamp must be timezone-aware")
        changes = self._changes(previous=previous, current=current)
        events: list[CapabilityDriftEvent] = []
        for event_type, entity_reference, before, after in changes:
            material = {
                "tenant_id": tenant_id,
                "current_genome_id": current.genome_id,
                "previous_genome_id": previous.genome_id if previous else None,
                "event_type": event_type,
                "entity_reference": entity_reference,
                "before": before,
                "after": after,
                "evidence_references": tuple(sorted(set(evidence_references))),
                "occurred_at": occurred_at.isoformat(),
            }
            input_digest = hashlib.sha256(
                b"hawk:cie:capability-event:v1\x00" + canonical_json_bytes(material)
            ).hexdigest()
            existing = db.scalar(
                select(DiscoveryCapabilityEvent).where(
                    DiscoveryCapabilityEvent.tenant_id == tenant_id,
                    DiscoveryCapabilityEvent.input_digest == input_digest,
                )
            )
            if existing is None:
                event_id = str(
                    uuid5(NAMESPACE_URL, f"hawk:cie-event:v1:{tenant_id}:{input_digest}")
                )
                existing = DiscoveryCapabilityEvent(
                    event_id=event_id,
                    tenant_id=tenant_id,
                    subject_reference_hash=current.subject_reference_hash,
                    genome_id=current.genome_id,
                    previous_genome_id=previous.genome_id if previous else None,
                    event_type=event_type,
                    entity_reference=entity_reference,
                    before_json=before,
                    after_json=after,
                    evidence_references_json=list(sorted(set(evidence_references))),
                    occurred_at=occurred_at,
                    input_digest=input_digest,
                )
                db.add(existing)
                db.flush()
            events.append(
                CapabilityDriftEvent(
                    event_id=existing.event_id,
                    subject_reference_hash=existing.subject_reference_hash,
                    genome_id=existing.genome_id,
                    previous_genome_id=existing.previous_genome_id,
                    event_type=existing.event_type,
                    entity_reference=existing.entity_reference,
                    before=existing.before_json,
                    after=existing.after_json,
                    evidence_references=tuple(existing.evidence_references_json),
                    occurred_at=existing.occurred_at,
                    input_digest=existing.input_digest,
                )
            )
        return tuple(events)

    @staticmethod
    def _changes(
        *,
        previous: DiscoveryCapabilityGenome | None,
        current: DiscoveryCapabilityGenome,
    ) -> tuple[tuple[str, str, dict, dict], ...]:
        if previous is None:
            previous_capabilities: dict[str, dict] = {}
        else:
            previous_capabilities = {
                item["capability_id"]: item for item in previous.capabilities_json
            }
        current_capabilities = {
            item["capability_id"]: item for item in current.capabilities_json
        }
        changes: list[tuple[str, str, dict, dict]] = []
        for capability_id in sorted(set(current_capabilities) - set(previous_capabilities)):
            changes.append(("capability_added", capability_id, {}, current_capabilities[capability_id]))
        for capability_id in sorted(set(previous_capabilities) - set(current_capabilities)):
            changes.append(("capability_removed", capability_id, previous_capabilities[capability_id], {}))
        for capability_id in sorted(set(previous_capabilities) & set(current_capabilities)):
            before = previous_capabilities[capability_id]
            after = current_capabilities[capability_id]
            if before.get("confidence") != after.get("confidence"):
                changes.append(
                    (
                        "confidence_changed",
                        capability_id,
                        {"confidence": before.get("confidence")},
                        {"confidence": after.get("confidence")},
                    )
                )
        if previous is not None:
            before_dependencies = set(previous.dependencies_json)
            after_dependencies = set(current.dependencies_json)
            for dependency in sorted(after_dependencies - before_dependencies):
                changes.append(("dependency_added", dependency, {}, {"present": True}))
            for dependency in sorted(before_dependencies - after_dependencies):
                changes.append(("dependency_removed", dependency, {"present": True}, {}))
            dimensions = (
                ("marketplace_changed", "marketplace", previous.marketplace_json, current.marketplace_json),
                ("provider_changed", "provider", previous.providers_json, current.providers_json),
                ("model_changed", "model", previous.models_json, current.models_json),
                ("runtime_changed", "runtime", previous.runtime_json, current.runtime_json),
                ("data_changed", "data", previous.data_json, current.data_json),
                ("identity_changed", "identity", previous.identity_json, current.identity_json),
                ("permission_changed", "permission", previous.permissions_json, current.permissions_json),
                ("usage_changed", "usage", previous.usage_json, current.usage_json),
            )
            for event_type, entity, before_values, after_values in dimensions:
                if tuple(before_values) != tuple(after_values):
                    changes.append(
                        (
                            event_type,
                            entity,
                            {"values": list(before_values)},
                            {"values": list(after_values)},
                        )
                    )
        if previous is None or previous.genome_digest != current.genome_digest:
            changes.append(
                (
                    "genome_changed",
                    "genome",
                    {"digest": previous.genome_digest} if previous else {},
                    {"digest": current.genome_digest},
                )
            )
        return tuple(changes)


__all__ = ["CapabilityEventService"]
