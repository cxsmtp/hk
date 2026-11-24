from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.capability_inference import DiscoveryCapabilityGenome
from app.db.models.discovery_canonical import DiscoveryObservation
from app.services.hmair.cie.contracts import (
    CapabilityGenomeContext,
    CapabilityGraphProjection,
    CapabilityInferenceOptions,
    CapabilityPipelineResult,
)
from app.services.hmair.cie.evidence_service import CapabilityEvidenceService
from app.services.hmair.cie.event_service import CapabilityEventService
from app.services.hmair.cie.genome_service import CapabilityGenomeService
from app.services.hmair.cie.graph_service import CapabilityGraphService
from app.services.hmair.cie.service import CapabilityInferenceEngine
from app.services.hmair.cie.signal_normalizer import SignalNormalizer
from app.services.hmair.evidence_fusion_service import fuse_observations


class CapabilityInferencePipeline:
    """One caller-owned transaction from observations to immutable CIE evidence."""

    def run(
        self,
        db: Session,
        *,
        tenant_id: str,
        observation_ids: tuple[str, ...],
        validated_at: datetime,
        idempotency_key: str,
        options: CapabilityInferenceOptions | None = None,
        genome_context: CapabilityGenomeContext | None = None,
    ) -> CapabilityPipelineResult:
        options = options or CapabilityInferenceOptions()
        fusion = fuse_observations(
            db, tenant_id=tenant_id, observation_ids=observation_ids
        )
        observations = tuple(
            db.scalars(
                select(DiscoveryObservation)
                .where(
                    DiscoveryObservation.tenant_id == tenant_id,
                    DiscoveryObservation.observation_id.in_(fusion.observation_ids),
                )
                .order_by(DiscoveryObservation.observation_id)
            )
        )
        signals = SignalNormalizer().normalize_many(observations)
        inference = CapabilityInferenceEngine().infer_signals(
            signals=signals,
            validated_at=validated_at,
            options=options,
        )
        run, evidence_rows = CapabilityEvidenceService().persist_result(
            db,
            tenant_id=tenant_id,
            evidence_node_id=fusion.bundle_id,
            result=inference,
            idempotency_key=idempotency_key,
        )
        graph = CapabilityGraphProjection.empty()
        if options.dependency_graph:
            graph = CapabilityGraphService().project(
                db,
                tenant_id=tenant_id,
                evidence_node_id=fusion.bundle_id,
                result=inference,
                signals=signals,
            )
        genome_id: str | None = None
        event_ids: tuple[str, ...] = ()
        if options.genome:
            if genome_context is None:
                genome_context = CapabilityGenomeContext(
                    dependencies=(), permissions=(), reachability=(), usage=(),
                    models=(), providers=(), runtime=(), data=(), marketplace=(),
                    identity=(),
                )
            genome = CapabilityGenomeService().persist_snapshot(
                db,
                tenant_id=tenant_id,
                run=run,
                result=inference,
                context=genome_context,
            )
            genome_id = genome.genome_id
            if options.drift:
                previous = None
                if genome.supersedes_genome_id:
                    previous = db.scalar(
                        select(DiscoveryCapabilityGenome).where(
                            DiscoveryCapabilityGenome.tenant_id == tenant_id,
                            DiscoveryCapabilityGenome.genome_id == genome.supersedes_genome_id,
                        )
                    )
                events = CapabilityEventService().record_drift(
                    db,
                    tenant_id=tenant_id,
                    previous=previous,
                    current=genome,
                    evidence_references=(fusion.bundle_id,),
                    occurred_at=validated_at,
                )
                event_ids = tuple(item.event_id for item in events)
        return CapabilityPipelineResult(
            inference=inference,
            inference_run_id=run.inference_run_id,
            evidence_node_id=fusion.bundle_id,
            capability_evidence_ids=tuple(
                item.capability_evidence_id for item in evidence_rows
            ),
            graph=graph,
            genome_id=genome_id,
            event_ids=event_ids,
        )


__all__ = ["CapabilityInferencePipeline"]

