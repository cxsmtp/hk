from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_asset import DiscoveryAIAsset
from app.db.models.discovery_intelligence import DiscoveryAssetFinding
from app.db.models.evidence import EvidenceNode
from app.services.hmair.governance_contracts import H5_FINDING_CATALOG


def _utc(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def upsert_discovery_finding(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    finding_type: str,
    severity: str,
    confidence: float,
    verification_state: str,
    evidence_node_ids: tuple[str, ...],
    first_seen_at: datetime,
    last_seen_at: datetime,
    remediation: str,
    verification_action: str,
    coverage_impact: str,
    dedupe_key: str,
) -> DiscoveryAssetFinding:
    if not finding_type or len(finding_type) > 64:
        raise ValueError("discovery finding type is invalid")
    if severity not in {"low", "medium", "high", "critical"}:
        raise ValueError("discovery finding severity is invalid")
    if type(confidence) is not float or not 0.0 <= confidence <= 1.0:
        raise ValueError("discovery finding confidence is invalid")
    if verification_state not in {
        "verified", "partially_verified", "inferred", "contradicted", "stale", "unknown"
    }:
        raise ValueError("discovery finding verification is invalid")
    if not evidence_node_ids or len(evidence_node_ids) > 64 or len(set(evidence_node_ids)) != len(evidence_node_ids):
        raise ValueError("discovery finding evidence is invalid")
    for value, label in (
        (remediation, "remediation"),
        (verification_action, "verification action"),
        (coverage_impact, "coverage impact"),
    ):
        if not value or len(value) > 1000:
            raise ValueError(f"discovery finding {label} is invalid")
    if not dedupe_key or len(dedupe_key) > 128:
        raise ValueError("discovery finding dedupe key is invalid")
    first = _utc(first_seen_at, field_name="first_seen_at")
    last = _utc(last_seen_at, field_name="last_seen_at")
    if first > last:
        raise ValueError("discovery finding timestamps are out of order")
    asset = db.scalar(
        select(DiscoveryAIAsset).where(
            DiscoveryAIAsset.tenant_id == tenant_id,
            DiscoveryAIAsset.asset_id == asset_id,
        )
    )
    evidence_count = len(
        db.scalars(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == tenant_id,
                EvidenceNode.id.in_(evidence_node_ids),
            )
        ).all()
    )
    if asset is None or evidence_count != len(evidence_node_ids):
        raise ValueError("discovery finding authority is unavailable")
    existing = db.scalar(
        select(DiscoveryAssetFinding).where(
            DiscoveryAssetFinding.tenant_id == tenant_id,
            DiscoveryAssetFinding.dedupe_key == dedupe_key,
        )
    )
    if existing is not None:
        if existing.asset_id != asset_id or existing.finding_type != finding_type:
            raise ValueError("discovery finding dedupe conflict")
        severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        if severity_rank[severity] > severity_rank[existing.severity]:
            existing.severity = severity
        existing.confidence = max(existing.confidence, confidence)
        existing.last_seen_at = max(_utc(existing.last_seen_at, field_name="stored_last_seen_at"), last)
        existing.occurrence_count += 1
        existing.evidence_node_ids_json = list(
            dict.fromkeys([*existing.evidence_node_ids_json, *evidence_node_ids])
        )[:64]
        existing.remediation = remediation
        existing.verification_action = verification_action
        existing.coverage_impact = coverage_impact
        db.flush()
        return existing
    row = DiscoveryAssetFinding(
        finding_id=str(uuid4()),
        tenant_id=tenant_id,
        asset_id=asset_id,
        finding_type=finding_type,
        severity=severity,
        confidence=confidence,
        verification_state=verification_state,
        primary_evidence_node_id=evidence_node_ids[0],
        evidence_node_ids_json=list(evidence_node_ids),
        first_seen_at=first,
        last_seen_at=last,
        remediation=remediation,
        verification_action=verification_action,
        coverage_impact=coverage_impact,
        dedupe_key=dedupe_key,
        occurrence_count=1,
        status="open",
    )
    db.add(row)
    db.flush()
    return row


def upsert_h5_discovery_finding(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    finding_type: str,
    confidence: float,
    verification_state: str,
    evidence_node_ids: tuple[str, ...],
    first_seen_at: datetime,
    last_seen_at: datetime,
    dedupe_key: str,
    severity: str | None = None,
) -> DiscoveryAssetFinding:
    """Persist one closed-catalog H5 finding through the existing lifecycle."""

    definition = H5_FINDING_CATALOG.get(finding_type)
    if definition is None:
        raise ValueError("H5 discovery finding type is not in the approved catalog")
    return upsert_discovery_finding(
        db,
        tenant_id=tenant_id,
        asset_id=asset_id,
        finding_type=finding_type,
        severity=severity or definition.default_severity,
        confidence=confidence,
        verification_state=verification_state,
        evidence_node_ids=evidence_node_ids,
        first_seen_at=first_seen_at,
        last_seen_at=last_seen_at,
        remediation=definition.remediation,
        verification_action=definition.verification_action,
        coverage_impact=definition.coverage_impact,
        dedupe_key=dedupe_key,
    )


__all__ = ["upsert_discovery_finding", "upsert_h5_discovery_finding"]
