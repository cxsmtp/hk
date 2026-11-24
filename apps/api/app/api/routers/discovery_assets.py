from __future__ import annotations

import base64
import binascii
from collections import defaultdict
from datetime import datetime
import hashlib
import hmac
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session, aliased

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.config import settings
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.ai_asset import (
    DiscoveryAIAsset,
    DiscoveryAICapability,
    DiscoveryAssetHistoryEvent,
    DiscoveryAssetHistoryMember,
    DiscoveryObservationAssetLink,
)
from app.db.models.discovery_canonical import DiscoveryObservation
from app.db.models.discovery_attribution import (
    DiscoveryAssetIdentityLink,
    DiscoveryAssetOwnershipAssertion,
    DiscoveryAssetReachability,
)
from app.db.models.discovery_intelligence import (
    DiscoveryAssetFinding,
    DiscoveryAssetUsageFact,
    DiscoveryShadowClassification,
)
from app.db.session import get_db
from app.services.hmair.discovery_context_service import get_discovery_context
from app.services.hmair.evidence_claim_service import EvidenceClaimScopeError


router = APIRouter(prefix="/discovery/assets", tags=["discovery-intelligence"])
_EVIDENCE_CURSOR_CONTEXT = b"hawk-hmair-asset-evidence-cursor-v1\x00"


class AssetSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str
    asset_type: str
    canonical_name: str
    provider: str | None
    product: str | None
    framework: str | None
    version: str | None
    deployment_family: str | None
    technical_surface: str | None
    environment: str | None
    approved_status: str
    lifecycle_status: str
    shadow_ai_status: str
    resolution_state: str
    resolution_confidence: float
    resolution_methodology_id: str
    usage_state: str
    usage_verification_state: str
    shadow_type: str | None
    owner_state: str
    capabilities_count: int
    identities_count: int
    reachability_count: int
    findings_open: int
    first_seen_at: datetime
    last_seen_at: datetime


class UsageFactResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    usage_fact_id: str
    actor_type: str
    actor_reference_hash: str | None
    usage_state: str
    event_count: int
    first_observed_at: datetime | None
    last_observed_at: datetime | None
    source_surface: str
    evidence_node_id: str
    confidence: float
    verification_state: str
    freshness: str
    telemetry_complete: bool
    methodology_id: str
    limitations: list[str]


class CapabilityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capability_id: str
    name: str
    state: str
    confidence: float
    verification_state: str
    freshness: str
    observed_usage: bool
    declared_only: bool
    inferred_only: bool
    evidence_claim_id: str


class AssetEvidenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observation_id: str
    observed_at: datetime
    source_surface: str
    observation_type: str
    candidate_asset_type: str
    observed_state: str
    evidence_reference: str
    evidence_hash: str
    signature_status: str
    confidence: float
    freshness: str
    verification_state: str
    source_trust: str
    evidence_mode: str
    contradiction_state: str
    link_kind: str
    link_sequence: int


class AssetEvidenceListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[AssetEvidenceResponse]
    total: int
    next_cursor: str | None


class AssetHistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    history_event_id: str
    event_type: str
    reversal_of_event_id: str | None
    actor_role: str
    reason: str
    evidence_claim_id: str
    member_role: str
    member_ordinal: int
    created_at: datetime


class ReachabilityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reachability_id: str
    target_category: str
    target_reference_hash: str
    state: str
    confidence: float
    verification_state: str
    freshness: str
    observed_usage: bool
    evidence_node_id: str
    limitations: list[str]


class IdentityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_link_id: str
    identity_type: str
    identity_reference_hash: str
    access_state: str
    usage_proven: bool
    confidence: float
    verification_state: str
    evidence_node_id: str


class OwnershipResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ownership_assertion_id: str
    owner_type: str
    owner_reference_hash: str | None
    state: str
    confidence: float
    verification_state: str
    evidence_node_id: str


class ShadowClassificationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    classification_id: str
    management_class: str
    shadow_type: str
    severity: str
    confidence: float
    verification_state: str
    evidence_node_ids: list[str]
    first_observed_at: datetime
    last_observed_at: datetime
    methodology_id: str
    limitations: list[str]


class DiscoveryFindingResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    asset_id: str
    finding_type: str
    severity: str
    confidence: float
    verification_state: str
    evidence_node_ids: list[str]
    first_seen_at: datetime
    last_seen_at: datetime
    remediation: str
    verification_action: str
    coverage_impact: str
    occurrence_count: int
    status: str


class AssetDetailResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset: AssetSummaryResponse
    usage: list[UsageFactResponse]
    capabilities: list[CapabilityResponse]
    reachability: list[ReachabilityResponse]
    identities: list[IdentityResponse]
    ownership: list[OwnershipResponse]
    shadow_classifications: list[ShadowClassificationResponse]
    findings: list[DiscoveryFindingResponse]


def _resolution_state(confidence: float) -> str:
    # This threshold is intentionally public through resolution_methodology_id.
    if confidence >= 0.85:
        return "confirmed"
    if confidence >= 0.60:
        return "probable"
    return "ambiguous"


def _finding_response(row: DiscoveryAssetFinding) -> DiscoveryFindingResponse:
    return DiscoveryFindingResponse(
        finding_id=row.finding_id,
        asset_id=row.asset_id,
        finding_type=row.finding_type,
        severity=row.severity,
        confidence=float(row.confidence),
        verification_state=row.verification_state,
        evidence_node_ids=list(row.evidence_node_ids_json),
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
        remediation=row.remediation,
        verification_action=row.verification_action,
        coverage_impact=row.coverage_impact,
        occurrence_count=row.occurrence_count,
        status=row.status,
    )


def _latest_by_asset(rows: list[Any], *, id_attr: str) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for row in rows:
        key = row.asset_id
        current = output.get(key)
        if current is None or (row.created_at, getattr(row, id_attr)) > (
            current.created_at,
            getattr(current, id_attr),
        ):
            output[key] = row
    return output


def _summaries(
    db: Session, *, tenant_id: str, assets: list[DiscoveryAIAsset]
) -> list[AssetSummaryResponse]:
    if not assets:
        return []
    asset_ids = [row.asset_id for row in assets]
    usage_rows = list(
        db.scalars(
            select(DiscoveryAssetUsageFact).where(
                DiscoveryAssetUsageFact.tenant_id == tenant_id,
                DiscoveryAssetUsageFact.asset_id.in_(asset_ids),
            )
        )
    )
    shadow_rows = list(
        db.scalars(
            select(DiscoveryShadowClassification).where(
                DiscoveryShadowClassification.tenant_id == tenant_id,
                DiscoveryShadowClassification.asset_id.in_(asset_ids),
            )
        )
    )
    owner_rows = list(
        db.scalars(
            select(DiscoveryAssetOwnershipAssertion).where(
                DiscoveryAssetOwnershipAssertion.tenant_id == tenant_id,
                DiscoveryAssetOwnershipAssertion.asset_id.in_(asset_ids),
            )
        )
    )
    latest_usage = _latest_by_asset(usage_rows, id_attr="usage_fact_id")
    latest_shadow = _latest_by_asset(shadow_rows, id_attr="classification_id")
    latest_owner = _latest_by_asset(owner_rows, id_attr="ownership_assertion_id")

    def _count(model: Any, key: str) -> dict[str, int]:
        return {
            asset_id: int(count)
            for asset_id, count in db.execute(
                select(model.asset_id, func.count())
                .where(model.tenant_id == tenant_id, model.asset_id.in_(asset_ids))
                .group_by(model.asset_id)
            )
        }

    capabilities = _count(DiscoveryAICapability, "capability_id")
    identities = _count(DiscoveryAssetIdentityLink, "identity_link_id")
    reachability = _count(DiscoveryAssetReachability, "reachability_id")
    findings = {
        asset_id: int(count)
        for asset_id, count in db.execute(
            select(DiscoveryAssetFinding.asset_id, func.count())
            .where(
                DiscoveryAssetFinding.tenant_id == tenant_id,
                DiscoveryAssetFinding.asset_id.in_(asset_ids),
                DiscoveryAssetFinding.status.in_(["open", "reviewing"]),
            )
            .group_by(DiscoveryAssetFinding.asset_id)
        )
    }
    output: list[AssetSummaryResponse] = []
    for row in assets:
        usage = latest_usage.get(row.asset_id)
        shadow = latest_shadow.get(row.asset_id)
        owner = latest_owner.get(row.asset_id)
        confidence = float(row.resolution_confidence)
        output.append(
            AssetSummaryResponse(
                asset_id=row.asset_id,
                asset_type=row.asset_type,
                canonical_name=row.canonical_name,
                provider=row.provider,
                product=row.product,
                framework=row.framework,
                version=row.version,
                deployment_family=row.deployment_family,
                technical_surface=row.technical_surface,
                environment=row.environment,
                approved_status=row.approved_status,
                lifecycle_status=row.lifecycle_status,
                shadow_ai_status=row.shadow_ai_status,
                resolution_state=_resolution_state(confidence),
                resolution_confidence=confidence,
                resolution_methodology_id=(
                    "phase2-resolution-confidence-v1:confirmed>=0.85;"
                    "probable>=0.60;otherwise=ambiguous"
                ),
                usage_state=usage.usage_state if usage else "unknown",
                usage_verification_state=(
                    usage.verification_state if usage else "unknown"
                ),
                shadow_type=shadow.shadow_type if shadow else None,
                owner_state=owner.ownership_state if owner else "unknown",
                capabilities_count=capabilities.get(row.asset_id, 0),
                identities_count=identities.get(row.asset_id, 0),
                reachability_count=reachability.get(row.asset_id, 0),
                findings_open=findings.get(row.asset_id, 0),
                first_seen_at=row.first_seen_at,
                last_seen_at=row.last_seen_at,
            )
        )
    return output


@router.get("", response_model=ListEnvelope[AssetSummaryResponse])
def list_assets(
    asset_type: str | None = Query(default=None, max_length=64),
    shadow_status: str | None = Query(default=None, max_length=32),
    usage_state: str | None = Query(default=None, max_length=32),
    verification_state: str | None = Query(default=None, max_length=32),
    search: str | None = Query(default=None, max_length=128),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> ListEnvelope[AssetSummaryResponse]:
    query = select(DiscoveryAIAsset).where(
        DiscoveryAIAsset.tenant_id == ctx.tenant.id
    )
    if asset_type:
        query = query.where(DiscoveryAIAsset.asset_type == asset_type)
    if shadow_status:
        query = query.where(DiscoveryAIAsset.shadow_ai_status == shadow_status)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.where(
            or_(
                DiscoveryAIAsset.canonical_name.ilike(pattern),
                DiscoveryAIAsset.provider.ilike(pattern),
                DiscoveryAIAsset.product.ilike(pattern),
            )
        )
    assets = list(
        db.scalars(
            query.order_by(
                DiscoveryAIAsset.last_seen_at.desc(),
                DiscoveryAIAsset.asset_id.desc(),
            )
        )
    )
    summaries = _summaries(db, tenant_id=ctx.tenant.id, assets=assets)
    if usage_state:
        summaries = [item for item in summaries if item.usage_state == usage_state]
    if verification_state:
        summaries = [
            item for item in summaries if item.resolution_state == verification_state
        ]
    items, total, safe_page, safe_size = paginate_rows(
        summaries, page=page, page_size=page_size
    )
    return ListEnvelope[AssetSummaryResponse](
        items=items, total=total, page=safe_page, page_size=safe_size
    )


def _asset_or_404(db: Session, *, tenant_id: str, asset_id: str) -> DiscoveryAIAsset:
    row = db.scalar(
        select(DiscoveryAIAsset).where(
            DiscoveryAIAsset.tenant_id == tenant_id,
            DiscoveryAIAsset.asset_id == asset_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    return row


def _cursor_encode(*, tenant_id: str, asset_id: str, row: DiscoveryObservation) -> str:
    payload = json.dumps(
        {
            "tenant_id": tenant_id,
            "asset_id": asset_id,
            "observed_at": row.observed_at.isoformat(),
            "observation_id": row.observation_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signature = hmac.new(
        str(settings.secret_key).encode("utf-8"),
        _EVIDENCE_CURSOR_CONTEXT + payload,
        hashlib.sha256,
    ).digest()
    encoded_payload = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    encoded_signature = (
        base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    )
    return f"v1.{encoded_payload}.{encoded_signature}"


def _cursor_decode(
    value: str, *, tenant_id: str, asset_id: str
) -> tuple[datetime, str]:
    try:
        version, encoded_payload, encoded_signature = value.split(".", 2)
        if version != "v1":
            raise ValueError("unsupported cursor")
        payload = base64.b64decode(
            encoded_payload + "=" * (-len(encoded_payload) % 4),
            altchars=b"-_",
            validate=True,
        )
        signature = base64.b64decode(
            encoded_signature + "=" * (-len(encoded_signature) % 4),
            altchars=b"-_",
            validate=True,
        )
        expected = hmac.new(
            str(settings.secret_key).encode("utf-8"),
            _EVIDENCE_CURSOR_CONTEXT + payload,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("invalid cursor signature")
        decoded = json.loads(payload)
        if not isinstance(decoded, dict) or set(decoded) != {
            "tenant_id",
            "asset_id",
            "observed_at",
            "observation_id",
        }:
            raise ValueError("invalid cursor payload")
        if decoded["tenant_id"] != tenant_id or decoded["asset_id"] != asset_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Not Found"
            )
        observation_id = decoded["observation_id"]
        if not isinstance(observation_id, str) or not 1 <= len(observation_id) <= 128:
            raise ValueError("invalid cursor observation")
        return datetime.fromisoformat(decoded["observed_at"]), observation_id
    except HTTPException:
        raise
    except (
        TypeError,
        ValueError,
        UnicodeDecodeError,
        binascii.Error,
        json.JSONDecodeError,
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid evidence cursor",
        ) from None


@router.get("/{asset_id}", response_model=AssetDetailResponse)
def get_asset_detail(
    asset_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> AssetDetailResponse:
    asset = _asset_or_404(db, tenant_id=ctx.tenant.id, asset_id=asset_id)
    summary = _summaries(db, tenant_id=ctx.tenant.id, assets=[asset])[0]
    usage = list(
        db.scalars(
            select(DiscoveryAssetUsageFact)
            .where(
                DiscoveryAssetUsageFact.tenant_id == ctx.tenant.id,
                DiscoveryAssetUsageFact.asset_id == asset_id,
            )
            .order_by(DiscoveryAssetUsageFact.created_at.desc())
        )
    )
    capabilities = list(
        db.scalars(
            select(DiscoveryAICapability)
            .where(
                DiscoveryAICapability.tenant_id == ctx.tenant.id,
                DiscoveryAICapability.asset_id == asset_id,
            )
            .order_by(
                DiscoveryAICapability.capability_name,
                DiscoveryAICapability.assertion_sequence.desc(),
            )
        )
    )
    reachability = list(db.scalars(select(DiscoveryAssetReachability).where(DiscoveryAssetReachability.tenant_id == ctx.tenant.id, DiscoveryAssetReachability.asset_id == asset_id).order_by(DiscoveryAssetReachability.created_at.desc())))
    identities = list(db.scalars(select(DiscoveryAssetIdentityLink).where(DiscoveryAssetIdentityLink.tenant_id == ctx.tenant.id, DiscoveryAssetIdentityLink.asset_id == asset_id).order_by(DiscoveryAssetIdentityLink.created_at.desc())))
    ownership = list(db.scalars(select(DiscoveryAssetOwnershipAssertion).where(DiscoveryAssetOwnershipAssertion.tenant_id == ctx.tenant.id, DiscoveryAssetOwnershipAssertion.asset_id == asset_id).order_by(DiscoveryAssetOwnershipAssertion.created_at.desc())))
    classifications = list(db.scalars(select(DiscoveryShadowClassification).where(DiscoveryShadowClassification.tenant_id == ctx.tenant.id, DiscoveryShadowClassification.asset_id == asset_id).order_by(DiscoveryShadowClassification.created_at.desc())))
    findings = list(db.scalars(select(DiscoveryAssetFinding).where(DiscoveryAssetFinding.tenant_id == ctx.tenant.id, DiscoveryAssetFinding.asset_id == asset_id).order_by(DiscoveryAssetFinding.last_seen_at.desc())))
    return AssetDetailResponse(
        asset=summary,
        usage=[
            UsageFactResponse(
                usage_fact_id=row.usage_fact_id,
                actor_type=row.actor_type,
                actor_reference_hash=row.actor_reference_hash,
                usage_state=row.usage_state,
                event_count=row.event_count,
                first_observed_at=row.first_observed_at,
                last_observed_at=row.last_observed_at,
                source_surface=row.source_surface,
                evidence_node_id=row.evidence_node_id,
                confidence=float(row.confidence),
                verification_state=row.verification_state,
                freshness=row.freshness,
                telemetry_complete=row.telemetry_complete,
                methodology_id=row.methodology_id,
                limitations=list(row.limitations_json),
            )
            for row in usage
        ],
        capabilities=[
            CapabilityResponse(
                capability_id=row.capability_id,
                name=row.capability_name,
                state=row.capability_state,
                confidence=float(row.confidence),
                verification_state=row.verification_state,
                freshness=row.freshness,
                observed_usage=row.observed_usage,
                declared_only=row.declared_only,
                inferred_only=row.inferred_only,
                evidence_claim_id=row.evidence_claim_id,
            )
            for row in capabilities
        ],
        reachability=[
            ReachabilityResponse(
                reachability_id=row.reachability_id,
                target_category=row.target_category,
                target_reference_hash=row.target_reference_hash,
                state=row.reachability_state,
                confidence=float(row.confidence),
                verification_state=row.verification_state,
                freshness=row.freshness,
                observed_usage=row.observed_usage,
                evidence_node_id=row.evidence_node_id,
                limitations=list(row.limitations_json),
            )
            for row in reachability
        ],
        identities=[
            IdentityResponse(
                identity_link_id=row.identity_link_id,
                identity_type=row.identity_type,
                identity_reference_hash=row.identity_reference_hash,
                access_state=row.access_state,
                usage_proven=row.usage_proven,
                confidence=float(row.confidence),
                verification_state=row.verification_state,
                evidence_node_id=row.evidence_node_id,
            )
            for row in identities
        ],
        ownership=[
            OwnershipResponse(
                ownership_assertion_id=row.ownership_assertion_id,
                owner_type=row.owner_type,
                owner_reference_hash=row.owner_reference_hash,
                state=row.ownership_state,
                confidence=float(row.confidence),
                verification_state=row.verification_state,
                evidence_node_id=row.evidence_node_id,
            )
            for row in ownership
        ],
        shadow_classifications=[
            ShadowClassificationResponse(
                classification_id=row.classification_id,
                management_class=row.management_class,
                shadow_type=row.shadow_type,
                severity=row.severity,
                confidence=float(row.confidence),
                verification_state=row.verification_state,
                evidence_node_ids=list(row.evidence_node_ids_json),
                first_observed_at=row.first_observed_at,
                last_observed_at=row.last_observed_at,
                methodology_id=row.methodology_id,
                limitations=list(row.limitations_json),
            )
            for row in classifications
        ],
        findings=[_finding_response(row) for row in findings],
    )


@router.get("/{asset_id}/evidence", response_model=AssetEvidenceListResponse)
def get_asset_evidence(
    asset_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None, max_length=1024),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> AssetEvidenceListResponse:
    _asset_or_404(db, tenant_id=ctx.tenant.id, asset_id=asset_id)
    successor = aliased(DiscoveryObservationAssetLink)
    terminal = ~select(successor.link_id).where(
        successor.tenant_id == DiscoveryObservationAssetLink.tenant_id,
        successor.observation_id == DiscoveryObservationAssetLink.observation_id,
        successor.predecessor_link_id == DiscoveryObservationAssetLink.link_id,
    ).exists()
    conditions = [
        DiscoveryObservationAssetLink.tenant_id == ctx.tenant.id,
        DiscoveryObservationAssetLink.asset_id == asset_id,
        terminal,
    ]
    if cursor is not None:
        observed_at, observation_id = _cursor_decode(
            cursor, tenant_id=ctx.tenant.id, asset_id=asset_id
        )
        conditions.append(
            or_(
                DiscoveryObservation.observed_at < observed_at,
                and_(
                    DiscoveryObservation.observed_at == observed_at,
                    DiscoveryObservation.observation_id > observation_id,
                ),
            )
        )
    query = (
        select(DiscoveryObservationAssetLink, DiscoveryObservation)
        .join(
            DiscoveryObservation,
            and_(
                DiscoveryObservation.tenant_id
                == DiscoveryObservationAssetLink.tenant_id,
                DiscoveryObservation.observation_id
                == DiscoveryObservationAssetLink.observation_id,
            ),
        )
        .where(*conditions)
        .order_by(
            DiscoveryObservation.observed_at.desc(),
            DiscoveryObservation.observation_id.asc(),
        )
        .limit(limit + 1)
    )
    rows = list(db.execute(query))
    has_more = len(rows) > limit
    page_rows = rows[:limit]
    total = int(
        db.scalar(
            select(func.count(DiscoveryObservationAssetLink.link_id)).where(
                DiscoveryObservationAssetLink.tenant_id == ctx.tenant.id,
                DiscoveryObservationAssetLink.asset_id == asset_id,
                terminal,
            )
        )
        or 0
    )
    items = [
        AssetEvidenceResponse(
            observation_id=observation.observation_id,
            observed_at=observation.observed_at,
            source_surface=observation.source_surface,
            observation_type=observation.observation_type,
            candidate_asset_type=observation.candidate_asset_type,
            observed_state=observation.observed_state,
            evidence_reference=observation.evidence_reference,
            evidence_hash=observation.evidence_hash,
            signature_status=observation.signature_status,
            confidence=float(observation.confidence),
            freshness=observation.freshness,
            verification_state=observation.verification_state,
            source_trust=observation.source_trust,
            evidence_mode=observation.evidence_mode,
            contradiction_state=observation.contradiction_state,
            link_kind=link.link_kind,
            link_sequence=int(link.sequence_no),
        )
        for link, observation in page_rows
    ]
    return AssetEvidenceListResponse(
        items=items,
        total=total,
        next_cursor=(
            _cursor_encode(
                tenant_id=ctx.tenant.id,
                asset_id=asset_id,
                row=page_rows[-1][1],
            )
            if has_more and page_rows
            else None
        ),
    )


@router.get("/{asset_id}/capabilities", response_model=ListEnvelope[CapabilityResponse])
def get_asset_capabilities(
    asset_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> ListEnvelope[CapabilityResponse]:
    _asset_or_404(db, tenant_id=ctx.tenant.id, asset_id=asset_id)
    total = int(
        db.scalar(
            select(func.count(DiscoveryAICapability.capability_id)).where(
                DiscoveryAICapability.tenant_id == ctx.tenant.id,
                DiscoveryAICapability.asset_id == asset_id,
            )
        )
        or 0
    )
    rows = list(
        db.scalars(
            select(DiscoveryAICapability)
            .where(
                DiscoveryAICapability.tenant_id == ctx.tenant.id,
                DiscoveryAICapability.asset_id == asset_id,
            )
            .order_by(
                DiscoveryAICapability.capability_name,
                DiscoveryAICapability.assertion_sequence.desc(),
            )
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    )
    items = [
        CapabilityResponse(
            capability_id=row.capability_id,
            name=row.capability_name,
            state=row.capability_state,
            confidence=float(row.confidence),
            verification_state=row.verification_state,
            freshness=row.freshness,
            observed_usage=row.observed_usage,
            declared_only=row.declared_only,
            inferred_only=row.inferred_only,
            evidence_claim_id=row.evidence_claim_id,
        )
        for row in rows
    ]
    return ListEnvelope[CapabilityResponse](
        items=items, total=total, page=page, page_size=page_size
    )


@router.get("/{asset_id}/history", response_model=ListEnvelope[AssetHistoryResponse])
def get_asset_history(
    asset_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> ListEnvelope[AssetHistoryResponse]:
    _asset_or_404(db, tenant_id=ctx.tenant.id, asset_id=asset_id)
    member_scope = [
        DiscoveryAssetHistoryMember.tenant_id == ctx.tenant.id,
        DiscoveryAssetHistoryMember.asset_id == asset_id,
    ]
    total = int(
        db.scalar(
            select(func.count(DiscoveryAssetHistoryMember.history_member_id)).where(
                *member_scope
            )
        )
        or 0
    )
    rows = list(
        db.execute(
            select(DiscoveryAssetHistoryEvent, DiscoveryAssetHistoryMember)
            .join(
                DiscoveryAssetHistoryMember,
                and_(
                    DiscoveryAssetHistoryMember.tenant_id
                    == DiscoveryAssetHistoryEvent.tenant_id,
                    DiscoveryAssetHistoryMember.history_event_id
                    == DiscoveryAssetHistoryEvent.history_event_id,
                ),
            )
            .where(
                DiscoveryAssetHistoryEvent.tenant_id == ctx.tenant.id,
                DiscoveryAssetHistoryMember.asset_id == asset_id,
            )
            .order_by(
                DiscoveryAssetHistoryEvent.created_at.desc(),
                DiscoveryAssetHistoryEvent.history_event_id.desc(),
                DiscoveryAssetHistoryMember.ordinal.asc(),
            )
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    )
    items = [
        AssetHistoryResponse(
            history_event_id=event.history_event_id,
            event_type=event.event_type,
            reversal_of_event_id=event.reversal_of_event_id,
            actor_role=event.actor_role,
            reason=event.reason,
            evidence_claim_id=event.evidence_claim_id,
            member_role=member.member_role,
            member_ordinal=int(member.ordinal),
            created_at=event.created_at,
        )
        for event, member in rows
    ]
    return ListEnvelope[AssetHistoryResponse](
        items=items, total=total, page=page, page_size=page_size
    )


@router.get("/{asset_id}/context", response_model=dict[str, Any])
def get_asset_context(
    asset_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        return get_discovery_context(
            db, tenant_id=ctx.tenant.id, asset_id=asset_id
        )
    except EvidenceClaimScopeError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Not Found"
        ) from None


__all__ = [
    "AssetEvidenceListResponse",
    "AssetEvidenceResponse",
    "AssetHistoryResponse",
    "AssetDetailResponse",
    "AssetSummaryResponse",
    "DiscoveryFindingResponse",
    "get_asset_capabilities",
    "get_asset_context",
    "get_asset_detail",
    "get_asset_evidence",
    "get_asset_history",
    "list_assets",
    "router",
]
