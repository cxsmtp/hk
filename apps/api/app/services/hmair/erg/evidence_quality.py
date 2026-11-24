from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.discovery_canonical import DiscoveryCollector, DiscoveryObservation
from app.db.models.evidence_resolution import (
    DiscoveryCollectorQualitySnapshot,
    DiscoveryObservationQualitySnapshot,
)
from app.services.hmair.contracts import canonical_json_bytes


QUALITY_SNAPSHOT_METHODOLOGY_ID = "erg-exposed-quality-factors"
QUALITY_SNAPSHOT_METHODOLOGY_VERSION = "1.0.0"


class EvidenceQualityConflict(RuntimeError):
    """Quality snapshot inputs are invalid, out of scope, or conflicting."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise EvidenceQualityConflict("quality snapshot time must be timezone-aware")
    return value.astimezone(timezone.utc)


def _digest(domain: str, material: dict[str, object]) -> str:
    return hashlib.sha256(domain.encode("ascii") + canonical_json_bytes(material)).hexdigest()


def _uuid(domain: str, tenant_id: str, digest: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"hawk:{domain}:v1:{tenant_id}:{digest}"))


class EvidenceQualitySnapshots:
    """Persist transparent collector and observation-quality calculations."""

    def record_collector(
        self,
        db: Session,
        *,
        tenant_id: str,
        collector_id: str,
        input_count: int,
        validated_count: int,
        freshness: str,
        signature_state: str,
        calculated_at: datetime,
        idempotency_key: str,
    ) -> DiscoveryCollectorQualitySnapshot:
        calculated_at = _utc(calculated_at)
        if input_count < 0 or validated_count < 0 or validated_count > input_count:
            raise EvidenceQualityConflict("collector validation counts are invalid")
        if db.scalar(select(DiscoveryCollector).where(
            DiscoveryCollector.tenant_id == tenant_id,
            DiscoveryCollector.collector_id == collector_id,
        )) is None:
            raise EvidenceQualityConflict("collector is outside tenant scope")
        validation_ratio = round(validated_count / input_count, 12) if input_count else None
        limitations: list[str] = []
        quality = validation_ratio
        if input_count == 0:
            limitations.append("collector_quality_denominator_empty")
        if signature_state != "verified":
            quality = None
            limitations.append("collector_signature_unverified")
        if freshness == "unknown":
            quality = None
            limitations.append("collector_freshness_unknown")
        summary = {
            "input_count": input_count,
            "validated_count": validated_count,
            "validation_ratio": validation_ratio,
        }
        material = {
            "tenant_id": tenant_id,
            "collector_id": collector_id,
            "input_summary": summary,
            "freshness": freshness,
            "signature_state": signature_state,
            "quality": quality,
            "limitations": limitations,
            "calculated_at": calculated_at.isoformat(),
            "idempotency_key": idempotency_key,
        }
        digest = _digest("hawk:erg:collector-quality:v1", material)
        replay = db.scalar(select(DiscoveryCollectorQualitySnapshot).where(
            DiscoveryCollectorQualitySnapshot.tenant_id == tenant_id,
            DiscoveryCollectorQualitySnapshot.idempotency_key == idempotency_key,
        ))
        if replay is not None:
            if replay.input_digest != digest:
                raise EvidenceQualityConflict("collector quality idempotency conflict")
            return replay
        row = DiscoveryCollectorQualitySnapshot(
            snapshot_id=_uuid("erg-collector-quality", tenant_id, digest),
            tenant_id=tenant_id,
            collector_id=collector_id,
            quality=quality,
            input_count=input_count,
            validated_count=validated_count,
            freshness=freshness,
            signature_state=signature_state,
            methodology_id=QUALITY_SNAPSHOT_METHODOLOGY_ID,
            methodology_version=QUALITY_SNAPSHOT_METHODOLOGY_VERSION,
            input_summary_json=summary,
            limitations_json=limitations,
            calculated_at=calculated_at,
            idempotency_key=idempotency_key,
            input_digest=digest,
        )
        db.add(row)
        db.flush()
        return row

    def record_observation(
        self,
        db: Session,
        *,
        tenant_id: str,
        observation_id: str,
        collector_quality_snapshot_id: str,
        factors: dict[str, float | None],
        freshness: str,
        signature_state: str,
        validation_state: str,
        calculated_at: datetime,
        idempotency_key: str,
    ) -> DiscoveryObservationQualitySnapshot:
        calculated_at = _utc(calculated_at)
        if not factors or any(
            value is not None and not 0.0 <= value <= 1.0
            for value in factors.values()
        ):
            raise EvidenceQualityConflict("observation quality factors are invalid")
        if db.scalar(select(DiscoveryObservation).where(
            DiscoveryObservation.tenant_id == tenant_id,
            DiscoveryObservation.observation_id == observation_id,
        )) is None:
            raise EvidenceQualityConflict("observation is outside tenant scope")
        collector = db.scalar(select(DiscoveryCollectorQualitySnapshot).where(
            DiscoveryCollectorQualitySnapshot.tenant_id == tenant_id,
            DiscoveryCollectorQualitySnapshot.snapshot_id == collector_quality_snapshot_id,
        ))
        if collector is None:
            raise EvidenceQualityConflict("collector quality is outside tenant scope")
        exposed = {**dict(sorted(factors.items())), "collector_quality": collector.quality}
        limitations: list[str] = []
        quality: float | None
        if any(value is None for value in exposed.values()):
            quality = None
            limitations.append("quality_factor_unknown")
        else:
            quality = min(float(value) for value in exposed.values() if value is not None)
        if signature_state != "verified" or validation_state != "verified":
            quality = None
            limitations.append("observation_validation_unverified")
        if freshness == "unknown":
            quality = None
            limitations.append("observation_freshness_unknown")
        quality_factors = {
            "calculation": "minimum",
            "factors": exposed,
        }
        material = {
            "tenant_id": tenant_id,
            "observation_id": observation_id,
            "collector_quality_snapshot_id": collector_quality_snapshot_id,
            "quality_factors": quality_factors,
            "freshness": freshness,
            "signature_state": signature_state,
            "validation_state": validation_state,
            "quality": quality,
            "limitations": sorted(set(limitations)),
            "calculated_at": calculated_at.isoformat(),
            "idempotency_key": idempotency_key,
        }
        digest = _digest("hawk:erg:observation-quality:v1", material)
        replay = db.scalar(select(DiscoveryObservationQualitySnapshot).where(
            DiscoveryObservationQualitySnapshot.tenant_id == tenant_id,
            DiscoveryObservationQualitySnapshot.idempotency_key == idempotency_key,
        ))
        if replay is not None:
            if replay.input_digest != digest:
                raise EvidenceQualityConflict("observation quality idempotency conflict")
            return replay
        row = DiscoveryObservationQualitySnapshot(
            snapshot_id=_uuid("erg-observation-quality", tenant_id, digest),
            tenant_id=tenant_id,
            observation_id=observation_id,
            collector_quality_snapshot_id=collector_quality_snapshot_id,
            quality=quality,
            freshness=freshness,
            signature_state=signature_state,
            validation_state=validation_state,
            methodology_id=QUALITY_SNAPSHOT_METHODOLOGY_ID,
            methodology_version=QUALITY_SNAPSHOT_METHODOLOGY_VERSION,
            quality_factors_json=quality_factors,
            limitations_json=sorted(set(limitations)),
            calculated_at=calculated_at,
            idempotency_key=idempotency_key,
            input_digest=digest,
        )
        db.add(row)
        db.flush()
        return row


__all__ = ["EvidenceQualityConflict", "EvidenceQualitySnapshots"]
