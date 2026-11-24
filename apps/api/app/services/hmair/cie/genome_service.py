from __future__ import annotations

import hashlib
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.capability_inference import (
    DiscoveryCapabilityGenome,
    DiscoveryCapabilityInferenceRun,
)
from app.services.hmair.cie.contracts import (
    CapabilityGenomeContext,
    CapabilityInferenceResult,
)
from app.services.hmair.contracts import canonical_json_bytes


class CapabilityGenomeService:
    def persist_snapshot(
        self,
        db: Session,
        *,
        tenant_id: str,
        run: DiscoveryCapabilityInferenceRun,
        result: CapabilityInferenceResult,
        context: CapabilityGenomeContext,
    ) -> DiscoveryCapabilityGenome:
        if run.tenant_id != tenant_id or run.subject_reference_hash != result.subject_reference_hash:
            raise ValueError("genome run is outside the inference subject")
        if tuple(run.observation_ids_json) != result.observation_ids:
            raise ValueError("genome run observations do not match inference")
        replay = db.scalar(
            select(DiscoveryCapabilityGenome).where(
                DiscoveryCapabilityGenome.tenant_id == tenant_id,
                DiscoveryCapabilityGenome.inference_run_id == run.inference_run_id,
            )
        )
        if replay is not None:
            return replay

        capability_by_id: dict[str, object] = {}
        for evaluation in result.evaluations:
            existing = capability_by_id.get(evaluation.capability_id)
            if existing is None or (
                evaluation.confidence,
                evaluation.source_diversity,
                evaluation.rule_id,
            ) > (
                existing.confidence,
                existing.source_diversity,
                existing.rule_id,
            ):
                capability_by_id[evaluation.capability_id] = evaluation
        capabilities = [
            {
                "capability_id": item.capability_id,
                "family": item.family.value,
                "confidence": item.confidence,
                "verification_state": item.verification_state,
                "freshness": item.freshness,
                "source_diversity": item.source_diversity,
                "rule_id": item.rule_id,
                "rule_version": item.rule_version,
                "calibration_version": item.calibration_version,
                "last_validated_at": item.last_validated_at.isoformat(),
            }
            for _capability_id, item in sorted(capability_by_id.items())
        ]
        context_material = context.model_dump(mode="json")
        material = {
            "subject_reference_hash": result.subject_reference_hash,
            "capabilities": capabilities,
            "context": context_material,
        }
        genome_digest = hashlib.sha256(
            b"hawk:cie:capability-genome:v1\x00" + canonical_json_bytes(material)
        ).hexdigest()
        current = db.scalar(
            select(DiscoveryCapabilityGenome)
            .where(
                DiscoveryCapabilityGenome.tenant_id == tenant_id,
                DiscoveryCapabilityGenome.subject_reference_hash == result.subject_reference_hash,
            )
            .order_by(
                DiscoveryCapabilityGenome.genome_version.desc(),
                DiscoveryCapabilityGenome.genome_id.desc(),
            )
            .limit(1)
        )
        genome_version = current.genome_version + 1 if current else 1
        genome_id = str(
            uuid5(
                NAMESPACE_URL,
                f"hawk:cie-genome:v1:{tenant_id}:{run.inference_run_id}",
            )
        )
        row = DiscoveryCapabilityGenome(
            genome_id=genome_id,
            tenant_id=tenant_id,
            inference_run_id=run.inference_run_id,
            subject_reference_hash=result.subject_reference_hash,
            genome_version=genome_version,
            supersedes_genome_id=(current.genome_id if current else None),
            genome_digest=genome_digest,
            capabilities_json=capabilities,
            dependencies_json=list(context.dependencies),
            permissions_json=list(context.permissions),
            reachability_json=list(context.reachability),
            usage_json=list(context.usage),
            models_json=list(context.models),
            providers_json=list(context.providers),
            runtime_json=list(context.runtime),
            data_json=list(context.data),
            marketplace_json=list(context.marketplace),
            identity_json=list(context.identity),
            first_observed_at=result.first_observed_at,
            last_observed_at=result.last_observed_at,
        )
        db.add(row)
        db.flush()
        return row


__all__ = ["CapabilityGenomeService"]

