from __future__ import annotations

import hashlib
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.capability_inference import (
    DiscoveryCapabilityEvidence,
    DiscoveryCapabilityInferenceRun,
)
from app.db.models.discovery_canonical import DiscoveryObservation
from app.db.models.evidence import EvidenceNode
from app.services.hmair.cie.contracts import CapabilityInferenceResult
from app.services.hmair.contracts import canonical_json_bytes


class CIEPersistenceConflict(RuntimeError):
    """An idempotency identity was reused with different inference material."""


class CIEPersistenceScopeError(RuntimeError):
    """Inference evidence is absent or outside the requested tenant."""


def _digest(domain: bytes, material: object) -> str:
    return hashlib.sha256(domain + b"\x00" + canonical_json_bytes(material)).hexdigest()


def _id(domain: str, material: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"hawk:{domain}:{material}"))


class CapabilityEvidenceService:
    def persist_result(
        self,
        db: Session,
        *,
        tenant_id: str,
        evidence_node_id: str,
        result: CapabilityInferenceResult,
        idempotency_key: str,
    ) -> tuple[DiscoveryCapabilityInferenceRun, tuple[DiscoveryCapabilityEvidence, ...]]:
        if not idempotency_key or len(idempotency_key) > 128:
            raise CIEPersistenceScopeError("idempotency key is invalid")
        evidence = db.scalar(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == tenant_id,
                EvidenceNode.id == evidence_node_id,
            )
        )
        if evidence is None or evidence.node_type != "bundle":
            raise CIEPersistenceScopeError("tenant-scoped evidence bundle is required")
        observation_ids = tuple(sorted(result.observation_ids))
        observations = tuple(
            db.scalars(
                select(DiscoveryObservation.observation_id)
                .where(
                    DiscoveryObservation.tenant_id == tenant_id,
                    DiscoveryObservation.observation_id.in_(observation_ids),
                )
                .order_by(DiscoveryObservation.observation_id)
            )
        )
        if observations != observation_ids:
            raise CIEPersistenceScopeError("inference observations are outside tenant scope")
        material = {
            "tenant_id": tenant_id,
            "evidence_node_id": evidence_node_id,
            "result": result.model_dump(mode="json"),
        }
        input_digest = _digest(b"hawk:cie:inference-input:v1", material)
        existing = db.scalar(
            select(DiscoveryCapabilityInferenceRun).where(
                DiscoveryCapabilityInferenceRun.tenant_id == tenant_id,
                DiscoveryCapabilityInferenceRun.idempotency_key == idempotency_key,
            )
        )
        if existing is not None:
            if existing.input_digest != input_digest:
                raise CIEPersistenceConflict("inference idempotency conflict")
            rows = tuple(
                db.scalars(
                    select(DiscoveryCapabilityEvidence)
                    .where(
                        DiscoveryCapabilityEvidence.tenant_id == tenant_id,
                        DiscoveryCapabilityEvidence.inference_run_id == existing.inference_run_id,
                    )
                    .order_by(DiscoveryCapabilityEvidence.rule_id)
                )
            )
            return existing, rows

        current = db.scalar(
            select(DiscoveryCapabilityInferenceRun)
            .where(
                DiscoveryCapabilityInferenceRun.tenant_id == tenant_id,
                DiscoveryCapabilityInferenceRun.subject_reference_hash == result.subject_reference_hash,
            )
            .order_by(
                DiscoveryCapabilityInferenceRun.run_sequence.desc(),
                DiscoveryCapabilityInferenceRun.inference_run_id.desc(),
            )
            .limit(1)
        )
        inference_run_id = _id("cie-inference-run:v1", f"{tenant_id}:{idempotency_key}")
        output_digest = _digest(
            b"hawk:cie:inference-output:v1", result.model_dump(mode="json")
        )
        run = DiscoveryCapabilityInferenceRun(
            inference_run_id=inference_run_id,
            tenant_id=tenant_id,
            evidence_node_id=evidence_node_id,
            subject_reference_hash=result.subject_reference_hash,
            observation_ids_json=list(observation_ids),
            engine_version=result.engine_version,
            catalog_version=result.catalog_version,
            ruleset_version=result.ruleset_version,
            run_sequence=(current.run_sequence + 1 if current else 1),
            supersedes_run_id=(current.inference_run_id if current else None),
            recommended_asset_type=result.recommended_asset_type,
            recommended_ecosystem=result.recommended_ecosystem,
            first_observed_at=result.first_observed_at,
            last_observed_at=result.last_observed_at,
            validated_at=result.validated_at,
            limitations_json=list(result.limitations),
            idempotency_key=idempotency_key,
            input_digest=input_digest,
            output_digest=output_digest,
        )
        db.add(run)
        db.flush()
        rows: list[DiscoveryCapabilityEvidence] = []
        for evaluation in result.evaluations:
            evaluation_material = evaluation.model_dump(mode="json")
            row = DiscoveryCapabilityEvidence(
                capability_evidence_id=_id(
                    "cie-capability-evidence:v1",
                    f"{tenant_id}:{inference_run_id}:{evaluation.rule_id}",
                ),
                tenant_id=tenant_id,
                inference_run_id=inference_run_id,
                capability_id=evaluation.capability_id,
                family=evaluation.family.value,
                rule_id=evaluation.rule_id,
                rule_version=evaluation.rule_version,
                calibration_version=evaluation.calibration_version,
                confidence=evaluation.confidence,
                supporting_signal_ids_json=list(evaluation.supporting_signal_ids),
                conflicting_signal_ids_json=list(evaluation.conflicting_signal_ids),
                unknown_predicates_json=list(evaluation.unknown_predicates),
                source_diversity=evaluation.source_diversity,
                freshness=evaluation.freshness,
                verification_state=evaluation.verification_state,
                last_validated_at=evaluation.last_validated_at,
                explanation=evaluation.explanation,
                limitations_json=list(evaluation.limitations),
                recommended_asset_type=evaluation.recommended_asset_type,
                recommended_ecosystem=evaluation.recommended_ecosystem,
                evidence_digest=_digest(
                    b"hawk:cie:capability-evidence:v1", evaluation_material
                ),
            )
            db.add(row)
            rows.append(row)
        db.flush()
        return run, tuple(rows)


__all__ = [
    "CIEPersistenceConflict",
    "CIEPersistenceScopeError",
    "CapabilityEvidenceService",
]

