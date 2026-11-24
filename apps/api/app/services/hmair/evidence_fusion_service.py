from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.discovery_canonical import DiscoveryObservation, DiscoveryScan
from app.db.models.evidence import EvidenceEdge, EvidenceNode
from app.services.hmair.contracts import (
    EvidenceClaimCreate,
    StrictContract,
    canonical_json_bytes,
)
from app.services.hmair.evidence_claim_service import persist_evidence_claim
from app.services.hmair.normalization_service import normalize_observation


FUSION_SCHEMA_VERSION = "phase-x-evidence-fusion-1.1"


class EvidenceFusionScopeError(RuntimeError):
    """The requested observation set is incomplete or outside tenant scope."""


class EvidenceFusionConflict(RuntimeError):
    """Deterministic evidence identity was reused with altered material."""


class EvidenceFusionResult(StrictContract):
    bundle_id: str
    observation_ids: tuple[str, ...]
    observation_node_ids: tuple[str, ...]
    source_surfaces: tuple[str, ...]
    direct_observation_count: int
    inferred_observation_count: int
    unknown_evidence_count: int
    confidence_facts: tuple[float, ...]
    freshness_counts: dict[str, int]
    verification_counts: dict[str, int]
    contradiction_state: str
    contradiction_references: tuple[str, ...]
    limitations: tuple[str, ...]
    first_seen_at: datetime
    last_seen_at: datetime
    schema_version: str


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _sha256(domain: bytes, material: object) -> str:
    return hashlib.sha256(domain + b"\x00" + canonical_json_bytes(material)).hexdigest()


def _deterministic_id(domain: str, material: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"hawk:{domain}:{material}"))


def _require_or_create_node(
    db: Session,
    *,
    node_id: str,
    tenant_id: str,
    correlation_id: str,
    node_type: str,
    signal_type: str,
    label: str,
    payload: dict[str, object],
) -> EvidenceNode:
    existing = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.id == node_id,
        )
    )
    if existing is not None:
        expected = {
            "correlation_id": correlation_id,
            "node_type": node_type,
            "signal_type": signal_type,
            "label": label,
            "payload": payload,
        }
        actual = {
            "correlation_id": existing.correlation_id,
            "node_type": existing.node_type,
            "signal_type": existing.signal_type,
            "label": existing.label,
            "payload": existing.payload,
        }
        if canonical_json_bytes(actual) != canonical_json_bytes(expected):
            raise EvidenceFusionConflict("evidence node material conflict")
        return existing
    row = EvidenceNode(
        id=node_id,
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        node_type=node_type,
        signal_type=signal_type,
        label=label,
        payload=payload,
    )
    db.add(row)
    db.flush()
    return row


def _require_or_create_edge(
    db: Session,
    *,
    edge_id: str,
    tenant_id: str,
    from_node_id: str,
    to_node_id: str,
    integrity_key: str,
    payload: dict[str, object],
) -> EvidenceEdge:
    existing = db.scalar(
        select(EvidenceEdge).where(
            EvidenceEdge.tenant_id == tenant_id,
            EvidenceEdge.id == edge_id,
        )
    )
    if existing is not None:
        expected = {
            "from_node_id": from_node_id,
            "to_node_id": to_node_id,
            "edge_type": "bundle_member",
            "integrity_key": integrity_key,
            "payload": payload,
        }
        actual = {
            "from_node_id": existing.from_node_id,
            "to_node_id": existing.to_node_id,
            "edge_type": existing.edge_type,
            "integrity_key": existing.integrity_key,
            "payload": existing.payload,
        }
        if canonical_json_bytes(actual) != canonical_json_bytes(expected):
            raise EvidenceFusionConflict("evidence edge material conflict")
        return existing
    row = EvidenceEdge(
        id=edge_id,
        tenant_id=tenant_id,
        from_node_id=from_node_id,
        to_node_id=to_node_id,
        edge_type="bundle_member",
        integrity_key=integrity_key,
        payload=payload,
    )
    db.add(row)
    db.flush()
    return row


def _contradiction_state(rows: tuple[DiscoveryObservation, ...]) -> str:
    states = {row.contradiction_state for row in rows}
    for state in ("contradicted", "unresolved", "unknown", "supported"):
        if state in states:
            return state
    return "none"


def fuse_observations(
    db: Session,
    *,
    tenant_id: str,
    observation_ids: tuple[str, ...],
) -> EvidenceFusionResult:
    requested_ids = tuple(sorted(set(observation_ids)))
    if not requested_ids or len(requested_ids) != len(observation_ids):
        raise EvidenceFusionScopeError(
            "observation set must be non-empty and contain unique identifiers"
        )
    rows = tuple(
        db.scalars(
            select(DiscoveryObservation)
            .where(
                DiscoveryObservation.tenant_id == tenant_id,
                DiscoveryObservation.observation_id.in_(requested_ids),
            )
            .order_by(DiscoveryObservation.observation_id)
        )
    )
    if tuple(row.observation_id for row in rows) != requested_ids:
        raise EvidenceFusionScopeError(
            "one or more observations are unavailable in tenant scope"
        )

    normalized = tuple(normalize_observation(row) for row in rows)
    observation_node_ids: list[str] = []
    for row, fact in zip(rows, normalized, strict=True):
        node_id = _deterministic_id(
            "discovery-observation-node:v2",
            f"{tenant_id}:{row.observation_id}:{fact.normalization_digest}",
        )
        payload: dict[str, object] = {
            "schema_version": FUSION_SCHEMA_VERSION,
            "observation_id": row.observation_id,
            "normalization_digest": fact.normalization_digest,
            "collector_id": row.collector_id,
            "collector_type": row.collector_type,
            "collector_version": row.collector_version,
            "target_id": row.target_id,
            "source_surface": row.source_surface,
            "signal_type": row.observation_type,
            "candidate_asset_type": row.candidate_asset_type,
            "observed_state": row.observed_state,
            "evidence_reference": row.evidence_reference,
            "evidence_hash": row.evidence_hash,
            "evidence_mode": row.evidence_mode,
            "signature_status": row.signature_status,
            "confidence": float(row.confidence),
            "freshness": row.freshness,
            "verification_state": row.verification_state,
            "source_trust": row.source_trust,
            "contradiction_state": row.contradiction_state,
            "contradiction_references": sorted(
                row.contradiction_references_json
            ),
            # Retain the bounded collection denominator and exclusions with
            # the evidence. Without it, a direct endpoint observation could
            # be misread as a wider coverage claim during later review.
            "collection_scope": row.collection_scope_json,
            "observed_at": _utc(row.observed_at).isoformat(),
        }
        _require_or_create_node(
            db,
            node_id=node_id,
            tenant_id=tenant_id,
            correlation_id=row.scan_id,
            node_type="discovery_observation",
            signal_type=row.observation_type,
            label=f"{row.source_surface} discovery observation",
            payload=payload,
        )
        observation_node_ids.append(node_id)

    source_surfaces = tuple(sorted({row.source_surface for row in rows}))
    evidence_modes = Counter(row.evidence_mode for row in rows)
    freshness_counts = dict(sorted(Counter(row.freshness for row in rows).items()))
    verification_counts = dict(
        sorted(Counter(row.verification_state for row in rows).items())
    )
    contradiction_state = _contradiction_state(rows)
    contradiction_references = tuple(
        sorted(
            {
                reference
                for row in rows
                for reference in row.contradiction_references_json
            }
        )
    )
    limitations: list[str] = []
    if len(source_surfaces) == 1:
        limitations.append("single_source_only")
    if evidence_modes.get("inferred", 0):
        limitations.append("contains_inferred_evidence")
    if evidence_modes.get("unknown", 0):
        limitations.append("contains_unknown_evidence")
    if contradiction_state not in {"none", "supported"}:
        limitations.append("contradictory_evidence_requires_resolution")
    if any(row.freshness != "fresh" for row in rows):
        limitations.append("contains_non_fresh_evidence")

    bundle_material = {
        "schema_version": FUSION_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "observation_ids": requested_ids,
        "normalization_digests": tuple(
            fact.normalization_digest for fact in normalized
        ),
    }
    bundle_digest = _sha256(
        b"hawk:hmair:evidence-bundle:v1", bundle_material
    )
    bundle_id = _deterministic_id(
        "discovery-evidence-bundle:v1", f"{tenant_id}:{bundle_digest}"
    )
    first_seen_at = min(_utc(row.observed_at) for row in rows)
    last_seen_at = max(_utc(row.observed_at) for row in rows)
    bundle_payload: dict[str, object] = {
        "schema_version": FUSION_SCHEMA_VERSION,
        "bundle_digest": bundle_digest,
        "observation_ids": list(requested_ids),
        "source_surfaces": list(source_surfaces),
        "source_diversity_count": len(source_surfaces),
        "direct_observation_count": evidence_modes.get("direct", 0),
        "inferred_observation_count": evidence_modes.get("inferred", 0),
        "unknown_evidence_count": evidence_modes.get("unknown", 0),
        "confidence_facts": sorted(float(row.confidence) for row in rows),
        "freshness_counts": freshness_counts,
        "verification_counts": verification_counts,
        "contradiction_state": contradiction_state,
        "contradiction_references": list(contradiction_references),
        "limitations": limitations,
        "first_seen_at": first_seen_at.isoformat(),
        "last_seen_at": last_seen_at.isoformat(),
        "aggregate_confidence_score": None,
    }
    _require_or_create_node(
        db,
        node_id=bundle_id,
        tenant_id=tenant_id,
        correlation_id=f"fusion:{bundle_digest[:32]}",
        node_type="bundle",
        signal_type="discovery.evidence_fusion",
        label="Multi-surface discovery evidence bundle",
        payload=bundle_payload,
    )
    for ordinal, (row, node_id) in enumerate(
        zip(rows, observation_node_ids, strict=True)
    ):
        edge_material = {
            "bundle_id": bundle_id,
            "member_node_id": node_id,
            "evidence_hash": row.evidence_hash,
            "ordinal": ordinal,
        }
        integrity_key = _sha256(
            b"hawk:hmair:evidence-bundle-member:v1", edge_material
        )
        edge_id = _deterministic_id(
            "discovery-evidence-edge:v1",
            f"{tenant_id}:{bundle_id}:{node_id}:{integrity_key}",
        )
        _require_or_create_edge(
            db,
            edge_id=edge_id,
            tenant_id=tenant_id,
            from_node_id=bundle_id,
            to_node_id=node_id,
            integrity_key=integrity_key,
            payload={
                "schema_version": FUSION_SCHEMA_VERSION,
                "observation_id": row.observation_id,
                "ordinal": ordinal,
                "evidence_hash": row.evidence_hash,
            },
        )
        claim_result = (
            "contradicted"
            if row.contradiction_state == "contradicted"
            else (
                "unresolved"
                if row.contradiction_state in {"unresolved", "unknown"}
                else "supported"
            )
        )
        claim_key = _sha256(
            b"hawk:hmair:fused-observation-claim:v1",
            {
                "tenant_id": tenant_id,
                "bundle_id": bundle_id,
                "observation_id": row.observation_id,
            },
        )
        persist_evidence_claim(
            db,
            tenant_id=tenant_id,
            payload=EvidenceClaimCreate(
                claim_type="candidate_observation",
                subject_observation_id=row.observation_id,
                subject_asset_id=None,
                source_observation_id=row.observation_id,
                evidence_node_id=bundle_id,
                claim_result=claim_result,
                claim_method=FUSION_SCHEMA_VERSION,
                limitations=tuple(limitations),
                confidence=float(row.confidence),
                freshness=row.freshness,
                observed_at=_utc(row.observed_at),
                idempotency_key=claim_key,
            ),
        )

    return EvidenceFusionResult(
        bundle_id=bundle_id,
        observation_ids=requested_ids,
        observation_node_ids=tuple(observation_node_ids),
        source_surfaces=source_surfaces,
        direct_observation_count=evidence_modes.get("direct", 0),
        inferred_observation_count=evidence_modes.get("inferred", 0),
        unknown_evidence_count=evidence_modes.get("unknown", 0),
        confidence_facts=tuple(
            sorted(float(row.confidence) for row in rows)
        ),
        freshness_counts=freshness_counts,
        verification_counts=verification_counts,
        contradiction_state=contradiction_state,
        contradiction_references=contradiction_references,
        limitations=tuple(limitations),
        first_seen_at=first_seen_at,
        last_seen_at=last_seen_at,
        schema_version=FUSION_SCHEMA_VERSION,
    )


def fuse_scan_observations(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
) -> EvidenceFusionResult:
    scan = db.scalar(
        select(DiscoveryScan).where(
            DiscoveryScan.tenant_id == tenant_id,
            DiscoveryScan.scan_id == scan_id,
        )
    )
    if scan is None:
        raise EvidenceFusionScopeError("discovery scan is unavailable")
    observation_ids = tuple(
        db.scalars(
            select(DiscoveryObservation.observation_id)
            .where(
                DiscoveryObservation.tenant_id == tenant_id,
                DiscoveryObservation.scan_id == scan_id,
            )
            .order_by(DiscoveryObservation.observation_id)
        )
    )
    result = fuse_observations(
        db,
        tenant_id=tenant_id,
        observation_ids=observation_ids,
    )
    # This is a current projection pointer. Prior immutable bundle nodes and
    # member edges remain intact and reproducible when later evidence arrives.
    scan.evidence_bundle_id = result.bundle_id
    db.flush()
    return result


__all__ = [
    "EvidenceFusionConflict",
    "EvidenceFusionResult",
    "EvidenceFusionScopeError",
    "FUSION_SCHEMA_VERSION",
    "fuse_observations",
    "fuse_scan_observations",
]
