from __future__ import annotations

import hashlib
import json

from pydantic import Field

from app.services.hmair.contracts import StrictContract
from app.services.hmair.exposure.contracts import (
    ExposureDimension,
    ExposureFactor,
    FreshnessState,
    VerificationStatus,
)
from app.services.hmair.exposure.source_reader import ExposureSourceSnapshot


DEFAULT_REQUIRED_DIMENSIONS = (
    ExposureDimension.CAPABILITY,
    ExposureDimension.REACHABILITY,
    ExposureDimension.PERMISSION,
    ExposureDimension.IDENTITY,
    ExposureDimension.GOVERNANCE,
    ExposureDimension.CONTROL_COVERAGE,
)

FAILED_AUTHORITY_DIMENSIONS = {
    "discovery_capability": (ExposureDimension.CAPABILITY,),
    "discovery_identity": (ExposureDimension.IDENTITY,),
    "discovery_ownership": (ExposureDimension.IDENTITY,),
    "discovery_reachability": (ExposureDimension.REACHABILITY,),
    "discovery_usage": (ExposureDimension.USAGE,),
    "shadow_classification": (ExposureDimension.GOVERNANCE,),
    "control_coverage": (ExposureDimension.CONTROL_COVERAGE,),
    "evidence_resolution_graph": (
        ExposureDimension.DATA,
        ExposureDimension.PERMISSION,
        ExposureDimension.REACHABILITY,
        ExposureDimension.RUNTIME,
        ExposureDimension.PROVIDER,
        ExposureDimension.MODEL,
    ),
    "decision_receipt": (ExposureDimension.AI_ACTION,),
}


class AssembledExposureInput(StrictContract):
    asset_id: str = Field(min_length=1, max_length=36)
    input_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    factors: tuple[ExposureFactor, ...] = Field(max_length=4096)
    source_ids: tuple[str, ...] = Field(max_length=4096)
    failed_authorities: tuple[str, ...] = Field(default=(), max_length=32)
    truncated: bool = False


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class ExposureInputAssembler:
    def assemble(
        self,
        snapshot: ExposureSourceSnapshot,
        *,
        required_dimensions: tuple[ExposureDimension, ...] = DEFAULT_REQUIRED_DIMENSIONS,
    ) -> AssembledExposureInput:
        factors = [
            ExposureFactor(
                dimension=row.dimension,
                source_type=row.source_type,
                source_id=row.source_id,
                state=row.state,
                evidence_refs=row.evidence_refs,
                related_source_refs=row.related_source_refs,
                confidence=row.confidence,
                verification_status=row.verification_status,
                freshness=row.freshness,
                observed_at=row.observed_at,
                validated_at=row.validated_at,
                methodology_id=row.methodology_id,
                collector_group=row.collector_group,
                limitations=row.limitations,
            )
            for row in snapshot.raw_sources
        ]
        for authority in snapshot.failed_authorities:
            for dimension in FAILED_AUTHORITY_DIMENSIONS.get(authority, ()):
                factors.append(
                    ExposureFactor(
                        dimension=dimension,
                        source_type="failed_authority",
                        source_id=f"failed:{authority}:{dimension.value}",
                        state="unknown",
                        evidence_refs=(),
                        confidence=None,
                        verification_status=VerificationStatus.UNKNOWN,
                        freshness=FreshnessState.UNKNOWN,
                        methodology_id="ai-exposure-authority-failure/1.0",
                        limitations=(f"source_authority_failed:{authority}",),
                    )
                )
        present = {item.dimension for item in factors}
        for dimension in sorted(set(required_dimensions) - present, key=lambda item: item.value):
            factors.append(
                ExposureFactor(
                    dimension=dimension,
                    source_type="missing_authority",
                    source_id=f"missing:{dimension.value}",
                    state="unknown",
                    evidence_refs=(),
                    confidence=None,
                    verification_status=VerificationStatus.UNKNOWN,
                    freshness=FreshnessState.UNKNOWN,
                    methodology_id="ai-exposure-missing-authority/1.0",
                    limitations=(f"{dimension.value}_authority_unavailable",),
                )
            )
        ordered = tuple(
            sorted(
                factors,
                key=lambda item: (
                    item.dimension.value,
                    item.source_type,
                    item.source_id,
                    item.state,
                    _canonical_bytes(item.model_dump(mode="json")),
                ),
            )
        )
        material = {
            "asset_id": snapshot.asset.asset_id,
            "as_of": snapshot.as_of.isoformat(),
            "sources": [item.model_dump(mode="json") for item in ordered],
            "failed_authorities": sorted(snapshot.failed_authorities),
            "truncated": snapshot.truncated,
        }
        digest = hashlib.sha256(
            b"hawk:ai-exposure-input:v1" + _canonical_bytes(material)
        ).hexdigest()
        return AssembledExposureInput(
            asset_id=snapshot.asset.asset_id,
            input_digest=digest,
            factors=ordered,
            source_ids=tuple(sorted(set(snapshot.source_ids))),
            failed_authorities=tuple(sorted(set(snapshot.failed_authorities))),
            truncated=snapshot.truncated,
        )


__all__ = [
    "AssembledExposureInput",
    "DEFAULT_REQUIRED_DIMENSIONS",
    "FAILED_AUTHORITY_DIMENSIONS",
    "ExposureInputAssembler",
]
