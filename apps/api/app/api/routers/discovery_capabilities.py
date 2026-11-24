from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.capability_inference import (
    DiscoveryCapabilityEvidence,
    DiscoveryCapabilityEvent,
    DiscoveryCapabilityGenome,
    DiscoveryCapabilityInferenceRun,
)
from app.db.session import get_db
from app.services.hmair.cie.catalog import (
    CAPABILITY_CATALOG,
    CATALOG_VERSION,
    RULESET_VERSION,
)
from app.services.hmair.cie.service import ENGINE_VERSION


router = APIRouter(
    prefix="/discovery/capability-inference",
    tags=["discovery-capability-inference"],
)


class CatalogItemResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capability_id: str
    family: str
    description: str
    risk: str
    rule_ids: list[str]


class CatalogResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    engine_version: str
    catalog_version: str
    ruleset_version: str
    methodology: str
    capabilities: list[CatalogItemResponse]


class CapabilityEvidenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capability_evidence_id: str
    capability_id: str
    family: str
    rule_id: str
    rule_version: str
    calibration_version: str
    confidence: float
    supporting_signal_ids: list[str]
    conflicting_signal_ids: list[str]
    unknown_predicates: list[str]
    source_diversity: int
    freshness: str
    verification_state: str
    last_validated_at: datetime
    explanation: str
    limitations: list[str]


class InferenceRunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    inference_run_id: str
    subject_reference_hash: str
    observation_ids: list[str]
    evidence_node_id: str
    engine_version: str
    catalog_version: str
    ruleset_version: str
    run_sequence: int
    supersedes_run_id: str | None
    recommended_asset_type: str
    recommended_ecosystem: str
    first_observed_at: datetime
    last_observed_at: datetime
    validated_at: datetime
    limitations: list[str]
    output_digest: str
    evidence: list[CapabilityEvidenceResponse]


class GenomeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    genome_id: str
    inference_run_id: str
    subject_reference_hash: str
    genome_version: int
    supersedes_genome_id: str | None
    genome_digest: str
    capabilities: list[dict]
    dependencies: list[str]
    permissions: list[str]
    reachability: list[str]
    usage: list[str]
    models: list[str]
    providers: list[str]
    runtime: list[str]
    data: list[str]
    marketplace: list[str]
    identity: list[str]
    first_observed_at: datetime
    last_observed_at: datetime


class CapabilityEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    genome_id: str
    previous_genome_id: str | None
    event_type: str
    entity_reference: str
    before: dict
    after: dict
    evidence_references: list[str]
    occurred_at: datetime


def _require_cie() -> None:
    if not settings.cie_core:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Capability Inference Engine is not enabled",
        )


def _evidence_response(row: DiscoveryCapabilityEvidence) -> CapabilityEvidenceResponse:
    return CapabilityEvidenceResponse(
        capability_evidence_id=row.capability_evidence_id,
        capability_id=row.capability_id,
        family=row.family,
        rule_id=row.rule_id,
        rule_version=row.rule_version,
        calibration_version=row.calibration_version,
        confidence=row.confidence,
        supporting_signal_ids=list(row.supporting_signal_ids_json),
        conflicting_signal_ids=list(row.conflicting_signal_ids_json),
        unknown_predicates=list(row.unknown_predicates_json),
        source_diversity=row.source_diversity,
        freshness=row.freshness,
        verification_state=row.verification_state,
        last_validated_at=row.last_validated_at,
        explanation=row.explanation,
        limitations=list(row.limitations_json),
    )


def _run_response(
    row: DiscoveryCapabilityInferenceRun,
    evidence: list[DiscoveryCapabilityEvidence],
) -> InferenceRunResponse:
    return InferenceRunResponse(
        inference_run_id=row.inference_run_id,
        subject_reference_hash=row.subject_reference_hash,
        observation_ids=list(row.observation_ids_json),
        evidence_node_id=row.evidence_node_id,
        engine_version=row.engine_version,
        catalog_version=row.catalog_version,
        ruleset_version=row.ruleset_version,
        run_sequence=row.run_sequence,
        supersedes_run_id=row.supersedes_run_id,
        recommended_asset_type=row.recommended_asset_type,
        recommended_ecosystem=row.recommended_ecosystem,
        first_observed_at=row.first_observed_at,
        last_observed_at=row.last_observed_at,
        validated_at=row.validated_at,
        limitations=list(row.limitations_json),
        output_digest=row.output_digest,
        evidence=[_evidence_response(item) for item in evidence],
    )


@router.get("/catalog", response_model=CatalogResponse)
def get_catalog(
    _ctx: TenantContext = Depends(require_role(min_role="viewer")),
) -> CatalogResponse:
    return CatalogResponse(
        enabled=settings.cie_core,
        engine_version=ENGINE_VERSION,
        catalog_version=CATALOG_VERSION,
        ruleset_version=RULESET_VERSION,
        methodology="Deterministic product-neutral rules with explicit conservative confidence caps.",
        capabilities=[
            CatalogItemResponse(
                capability_id=item.capability_id,
                family=item.family.value,
                description=item.description,
                risk=item.risk,
                rule_ids=list(item.rule_ids),
            )
            for item in CAPABILITY_CATALOG.values()
        ],
    )


@router.get("/runs", response_model=list[InferenceRunResponse])
def list_runs(
    limit: int = Query(default=100, ge=1, le=200),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> list[InferenceRunResponse]:
    _require_cie()
    rows = list(
        db.scalars(
            select(DiscoveryCapabilityInferenceRun)
            .where(DiscoveryCapabilityInferenceRun.tenant_id == ctx.tenant.id)
            .order_by(
                DiscoveryCapabilityInferenceRun.validated_at.desc(),
                DiscoveryCapabilityInferenceRun.inference_run_id.desc(),
            )
            .limit(limit)
        )
    )
    return [_run_response(row, []) for row in rows]


@router.get("/runs/{run_id}", response_model=InferenceRunResponse)
def get_run(
    run_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> InferenceRunResponse:
    _require_cie()
    row = db.scalar(
        select(DiscoveryCapabilityInferenceRun).where(
            DiscoveryCapabilityInferenceRun.tenant_id == ctx.tenant.id,
            DiscoveryCapabilityInferenceRun.inference_run_id == run_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Inference run not found")
    evidence = list(
        db.scalars(
            select(DiscoveryCapabilityEvidence)
            .where(
                DiscoveryCapabilityEvidence.tenant_id == ctx.tenant.id,
                DiscoveryCapabilityEvidence.inference_run_id == run_id,
            )
            .order_by(DiscoveryCapabilityEvidence.rule_id)
        )
    )
    return _run_response(row, evidence)


@router.get("/subjects/{subject_hash}/genomes", response_model=list[GenomeResponse])
def list_genomes(
    subject_hash: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> list[GenomeResponse]:
    _require_cie()
    rows = list(
        db.scalars(
            select(DiscoveryCapabilityGenome)
            .where(
                DiscoveryCapabilityGenome.tenant_id == ctx.tenant.id,
                DiscoveryCapabilityGenome.subject_reference_hash == subject_hash,
            )
            .order_by(DiscoveryCapabilityGenome.genome_version.desc())
        )
    )
    return [
        GenomeResponse(
            genome_id=row.genome_id,
            inference_run_id=row.inference_run_id,
            subject_reference_hash=row.subject_reference_hash,
            genome_version=row.genome_version,
            supersedes_genome_id=row.supersedes_genome_id,
            genome_digest=row.genome_digest,
            capabilities=list(row.capabilities_json),
            dependencies=list(row.dependencies_json),
            permissions=list(row.permissions_json),
            reachability=list(row.reachability_json),
            usage=list(row.usage_json),
            models=list(row.models_json),
            providers=list(row.providers_json),
            runtime=list(row.runtime_json),
            data=list(row.data_json),
            marketplace=list(row.marketplace_json),
            identity=list(row.identity_json),
            first_observed_at=row.first_observed_at,
            last_observed_at=row.last_observed_at,
        )
        for row in rows
    ]


@router.get("/subjects/{subject_hash}/events", response_model=list[CapabilityEventResponse])
def list_events(
    subject_hash: str,
    limit: int = Query(default=200, ge=1, le=500),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> list[CapabilityEventResponse]:
    _require_cie()
    rows = list(
        db.scalars(
            select(DiscoveryCapabilityEvent)
            .where(
                DiscoveryCapabilityEvent.tenant_id == ctx.tenant.id,
                DiscoveryCapabilityEvent.subject_reference_hash == subject_hash,
            )
            .order_by(
                DiscoveryCapabilityEvent.occurred_at.desc(),
                DiscoveryCapabilityEvent.event_id.desc(),
            )
            .limit(limit)
        )
    )
    return [
        CapabilityEventResponse(
            event_id=row.event_id,
            genome_id=row.genome_id,
            previous_genome_id=row.previous_genome_id,
            event_type=row.event_type,
            entity_reference=row.entity_reference,
            before=row.before_json,
            after=row.after_json,
            evidence_references=list(row.evidence_references_json),
            occurred_at=row.occurred_at,
        )
        for row in rows
    ]


__all__ = ["router"]

