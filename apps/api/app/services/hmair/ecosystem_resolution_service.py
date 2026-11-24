from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, aliased

from app.db.models.ai_asset import (
    DiscoveryAIAsset,
    DiscoveryObservationAssetLink,
)
from app.db.models.discovery_canonical import DiscoveryObservation
from app.db.models.discovery_resolution import (
    DiscoveryResolutionGraphEdge,
    DiscoveryResolutionGraphNode,
)
from app.db.models.evidence_resolution import (
    DiscoveryAIEcosystem,
    DiscoveryEcosystemMembership,
)
from app.services.hmair.contracts import StrictContract, canonical_json_bytes


ECOSYSTEM_ALGORITHM_VERSION = "phase-x-ecosystem-resolution-1.0"
ERG_COMPATIBILITY_ALGORITHM_VERSION = "erg-canonical-ecosystem-projection-1.0"
_RELATIONSHIP_EDGE_TYPES = frozenset(
    {
        "observed_on",
        "runs_on",
        "used_by",
        "calls",
        "connects_to",
        "depends_on",
        "authenticates_as",
        "hosted_in",
        "exposes",
        "accesses",
    }
)


class AIEcosystemProjection(StrictContract):
    ecosystem_id: str
    asset_ids: tuple[str, ...]
    asset_types: tuple[str, ...]
    provider: str
    environment: str
    confidence: float
    resolution_method: str
    evidence_refs: tuple[str, ...]
    discovery_sources: tuple[str, ...]
    first_seen_at: datetime
    last_seen_at: datetime
    limitations: tuple[str, ...]
    enrichment: dict[str, Any]
    algorithm_version: str


class _UnionFind:
    def __init__(self, values: tuple[str, ...]) -> None:
        self.parent = {value: value for value in values}

    def find(self, value: str) -> str:
        parent = self.parent[value]
        if parent != value:
            self.parent[value] = self.find(parent)
        return self.parent[value]

    def union(self, left: str, right: str) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        winner, loser = sorted((left_root, right_root))
        self.parent[loser] = winner


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _asset_reference(reference: str, assets: dict[str, DiscoveryAIAsset]) -> str | None:
    candidate = reference[6:] if reference.startswith("asset:") else reference
    return candidate if candidate in assets else None


def _common_value(values: set[str]) -> str:
    nonempty = {value for value in values if value}
    if not nonempty:
        return "unknown"
    if len(nonempty) == 1:
        return next(iter(nonempty))
    return "mixed"


def _current_discovery_sources(
    db: Session, *, tenant_id: str
) -> dict[str, set[str]]:
    successor = aliased(DiscoveryObservationAssetLink)
    rows = db.execute(
        select(
            DiscoveryObservationAssetLink.asset_id,
            DiscoveryObservation.source_surface,
        )
        .join(
            DiscoveryObservation,
            (DiscoveryObservation.tenant_id
             == DiscoveryObservationAssetLink.tenant_id)
            & (DiscoveryObservation.observation_id
               == DiscoveryObservationAssetLink.observation_id),
        )
        .where(
            DiscoveryObservationAssetLink.tenant_id == tenant_id,
            DiscoveryObservationAssetLink.asset_id.is_not(None),
            ~select(successor.link_id)
            .where(
                successor.tenant_id
                == DiscoveryObservationAssetLink.tenant_id,
                successor.observation_id
                == DiscoveryObservationAssetLink.observation_id,
                successor.predecessor_link_id
                == DiscoveryObservationAssetLink.link_id,
            )
            .exists(),
        )
    )
    output: dict[str, set[str]] = defaultdict(set)
    for asset_id, source_surface in rows:
        if asset_id and source_surface:
            output[str(asset_id)].add(str(source_surface))
    return output


def _enrichment(
    rows: tuple[DiscoveryAIAsset, ...],
    *,
    provider: str,
    environment: str,
    evidence_refs: tuple[str, ...],
) -> dict[str, Any]:
    products = sorted({row.product for row in rows if row.product})
    frameworks = sorted({row.framework for row in rows if row.framework})
    surfaces = sorted(
        {row.technical_surface for row in rows if row.technical_surface}
    )
    deployment_families = sorted(
        {row.deployment_family for row in rows if row.deployment_family}
    )
    return {
        "provider": {
            "value": provider if provider != "unknown" else None,
            "state": "observed" if provider != "unknown" else "unknown",
            "evidence_refs": list(evidence_refs),
        },
        "environment": {
            "value": environment if environment != "unknown" else None,
            "state": "observed" if environment != "unknown" else "unknown",
            "evidence_refs": list(evidence_refs),
        },
        "products": {
            "values": products,
            "state": "observed" if products else "unknown",
        },
        "frameworks": {
            "values": frameworks,
            "state": "observed" if frameworks else "unknown",
        },
        "technical_surfaces": {
            "values": surfaces,
            "state": "observed" if surfaces else "unknown",
        },
        "deployment_families": {
            "values": deployment_families,
            "state": "observed" if deployment_families else "unknown",
        },
        "external_ownership": {"value": None, "state": "unknown"},
        "licensing_and_pricing": {"value": None, "state": "unknown"},
        "regulatory_context": {"value": None, "state": "unknown"},
    }


def _canonical_erg_projection(
    db: Session,
    *,
    tenant_id: str,
    assets: dict[str, DiscoveryAIAsset],
) -> tuple[AIEcosystemProjection, ...]:
    """Project canonical ERG records through the legacy read contract.

    This prevents the older union-find grouping algorithm from competing with
    persisted ERG resolution once canonical ecosystems exist.
    """
    rows = tuple(
        db.scalars(
            select(DiscoveryAIEcosystem)
            .where(DiscoveryAIEcosystem.tenant_id == tenant_id)
            .order_by(
                DiscoveryAIEcosystem.ecosystem_id,
                DiscoveryAIEcosystem.resolution_version.desc(),
            )
        )
    )
    latest: dict[str, DiscoveryAIEcosystem] = {}
    for row in rows:
        latest.setdefault(row.ecosystem_id, row)
    active = tuple(
        sorted(
            (row for row in latest.values() if row.lifecycle_state == "active"),
            key=lambda row: row.ecosystem_id,
        )
    )
    if not active:
        return ()

    membership_rows = tuple(
        db.scalars(
            select(DiscoveryEcosystemMembership)
            .where(DiscoveryEcosystemMembership.tenant_id == tenant_id)
            .order_by(
                DiscoveryEcosystemMembership.ecosystem_id,
                DiscoveryEcosystemMembership.graph_node_id,
                DiscoveryEcosystemMembership.membership_sequence.desc(),
            )
        )
    )
    latest_memberships: dict[tuple[str, str], DiscoveryEcosystemMembership] = {}
    for membership in membership_rows:
        latest_memberships.setdefault(
            (membership.ecosystem_id, membership.graph_node_id), membership
        )
    node_rows = tuple(
        db.scalars(
            select(DiscoveryResolutionGraphNode).where(
                DiscoveryResolutionGraphNode.tenant_id == tenant_id
            )
        )
    )
    nodes = {row.graph_node_id: row for row in node_rows}
    edge_rows = tuple(
        db.scalars(
            select(DiscoveryResolutionGraphEdge).where(
                DiscoveryResolutionGraphEdge.tenant_id == tenant_id
            )
        )
    )
    historical_edge_ids = {
        row.predecessor_edge_id for row in edge_rows if row.predecessor_edge_id
    }
    current_edges = tuple(
        row for row in edge_rows if row.edge_id not in historical_edge_ids
    )

    output: list[AIEcosystemProjection] = []
    for ecosystem in active:
        members = tuple(
            row
            for (ecosystem_id, _), row in latest_memberships.items()
            if ecosystem_id == ecosystem.ecosystem_id
            and row.membership_state == "active"
        )
        node_ids = {row.graph_node_id for row in members}
        asset_ids = tuple(
            sorted(
                asset_id
                for member in members
                if (node := nodes.get(member.graph_node_id)) is not None
                and node.node_class == "ai_asset"
                and (asset_id := _asset_reference(node.subject_reference, assets))
                is not None
            )
        )
        asset_rows = tuple(assets[asset_id] for asset_id in asset_ids)
        provider = _common_value({row.provider or "" for row in asset_rows})
        environment = _common_value({row.environment or "" for row in asset_rows})
        related_edges = tuple(
            row
            for row in current_edges
            if row.from_node_id in node_ids or row.to_node_id in node_ids
        )
        evidence_refs = tuple(
            sorted(
                {row.evidence_node_id for row in members}
                | {row.evidence_node_id for row in related_edges}
            )
        )
        discovery_sources = tuple(
            sorted({row.source_surface for row in related_edges})
        )
        limitations = list(ecosystem.limitations_json)
        if not asset_ids:
            limitations.append(
                "canonical ecosystem has no current AI-asset graph membership"
            )
        if not discovery_sources:
            limitations.append("collector source surface is unknown")
        output.append(
            AIEcosystemProjection(
                ecosystem_id=ecosystem.ecosystem_id,
                asset_ids=asset_ids,
                asset_types=tuple(sorted({row.asset_type for row in asset_rows})),
                provider=provider,
                environment=environment,
                confidence=float(ecosystem.confidence or 0.0),
                resolution_method="canonical_evidence_resolution_graph",
                evidence_refs=evidence_refs,
                discovery_sources=discovery_sources,
                first_seen_at=_utc(ecosystem.first_observed_at),
                last_seen_at=_utc(ecosystem.last_observed_at),
                limitations=tuple(sorted(set(limitations))),
                enrichment=_enrichment(
                    asset_rows,
                    provider=provider,
                    environment=environment,
                    evidence_refs=evidence_refs,
                ),
                algorithm_version=ERG_COMPATIBILITY_ALGORITHM_VERSION,
            )
        )
    return tuple(output)


def resolve_ai_ecosystems(
    db: Session,
    *,
    tenant_id: str,
) -> tuple[AIEcosystemProjection, ...]:
    asset_rows = tuple(
        db.scalars(
            select(DiscoveryAIAsset)
            .where(DiscoveryAIAsset.tenant_id == tenant_id)
            .order_by(DiscoveryAIAsset.asset_id)
        )
    )
    assets = {row.asset_id: row for row in asset_rows}
    canonical = _canonical_erg_projection(db, tenant_id=tenant_id, assets=assets)
    if canonical:
        return canonical
    if not assets:
        return ()

    graph_nodes = tuple(
        db.scalars(
            select(DiscoveryResolutionGraphNode).where(
                DiscoveryResolutionGraphNode.tenant_id == tenant_id
            )
        )
    )
    node_ids = tuple(row.graph_node_id for row in graph_nodes)
    union = _UnionFind(node_ids)
    asset_nodes: dict[str, list[str]] = defaultdict(list)
    for node in graph_nodes:
        if node.node_class != "ai_asset":
            continue
        asset_id = _asset_reference(node.subject_reference, assets)
        if asset_id is not None:
            asset_nodes[asset_id].append(node.graph_node_id)
    for graph_ids in asset_nodes.values():
        for graph_id in graph_ids[1:]:
            union.union(graph_ids[0], graph_id)

    qualifying_edges = tuple(
        db.scalars(
            select(DiscoveryResolutionGraphEdge).where(
                DiscoveryResolutionGraphEdge.tenant_id == tenant_id,
                DiscoveryResolutionGraphEdge.edge_type.in_(
                    _RELATIONSHIP_EDGE_TYPES
                ),
                DiscoveryResolutionGraphEdge.verification_state.in_(
                    ("verified", "partially_verified")
                ),
                DiscoveryResolutionGraphEdge.freshness == "fresh",
                DiscoveryResolutionGraphEdge.contradiction_state.in_(
                    ("none", "resolved")
                ),
            )
        )
    )
    known_node_ids = set(node_ids)
    for edge in qualifying_edges:
        if edge.from_node_id in known_node_ids and edge.to_node_id in known_node_ids:
            union.union(edge.from_node_id, edge.to_node_id)

    grouped_assets: dict[str, list[DiscoveryAIAsset]] = defaultdict(list)
    for asset_id, asset in assets.items():
        if asset_nodes.get(asset_id):
            group_key = f"graph:{union.find(asset_nodes[asset_id][0])}"
        else:
            group_key = f"standalone:{asset_id}"
        grouped_assets[group_key].append(asset)

    component_evidence: dict[str, set[str]] = defaultdict(set)
    component_confidence: dict[str, list[float]] = defaultdict(list)
    for edge in qualifying_edges:
        if edge.from_node_id not in known_node_ids:
            continue
        key = f"graph:{union.find(edge.from_node_id)}"
        component_evidence[key].add(edge.evidence_node_id)
        component_confidence[key].append(float(edge.confidence))

    source_by_asset = _current_discovery_sources(db, tenant_id=tenant_id)
    output: list[AIEcosystemProjection] = []
    for group_key, mutable_rows in grouped_assets.items():
        rows = tuple(sorted(mutable_rows, key=lambda row: row.asset_id))
        asset_ids = tuple(row.asset_id for row in rows)
        provider = _common_value({row.provider or "" for row in rows})
        environment = _common_value({row.environment or "" for row in rows})
        evidence_refs = tuple(
            sorted(
                component_evidence.get(group_key, set())
                | {row.evidence_bundle_id for row in rows}
            )
        )
        sources = {
            source
            for row in rows
            for source in source_by_asset.get(row.asset_id, set())
        }
        limitations: list[str] = []
        if not sources:
            projection_sources = {
                value
                for row in rows
                for value in (row.technical_surface, row.deployment_family)
                if value
            }
            sources = {f"asset_projection:{value}" for value in projection_sources}
            limitations.append(
                "discovery sources limited to canonical asset projection"
            )
        connected_asset_count = len(rows)
        if connected_asset_count > 1:
            resolution_method = "verified_evidence_graph_component"
            confidence = min(component_confidence.get(group_key, [0.0]))
        else:
            resolution_method = "unconnected_canonical_asset"
            confidence = 0.0
            limitations.append(
                "matching provider and environment are not connection evidence"
            )
        if provider == "unknown":
            limitations.append("provider is unknown")
        if environment == "unknown":
            limitations.append("environment is unknown")
        limitations.extend(
            (
                "external ownership enrichment is unknown",
                "licensing and pricing enrichment is unknown",
                "regulatory enrichment is unknown",
            )
        )
        ecosystem_material = {
            "tenant_id": tenant_id,
            "asset_ids": asset_ids,
            "algorithm_version": ECOSYSTEM_ALGORITHM_VERSION,
        }
        ecosystem_id = hashlib.sha256(
            b"hawk:hmair:ecosystem:v1\x00"
            + canonical_json_bytes(ecosystem_material)
        ).hexdigest()[:32]
        output.append(
            AIEcosystemProjection(
                ecosystem_id=ecosystem_id,
                asset_ids=asset_ids,
                asset_types=tuple(sorted({row.asset_type for row in rows})),
                provider=provider,
                environment=environment,
                confidence=confidence,
                resolution_method=resolution_method,
                evidence_refs=evidence_refs,
                discovery_sources=tuple(sorted(sources)),
                first_seen_at=min(_utc(row.first_seen_at) for row in rows),
                last_seen_at=max(_utc(row.last_seen_at) for row in rows),
                limitations=tuple(limitations),
                enrichment=_enrichment(
                    rows,
                    provider=provider,
                    environment=environment,
                    evidence_refs=evidence_refs,
                ),
                algorithm_version=ECOSYSTEM_ALGORITHM_VERSION,
            )
        )
    return tuple(sorted(output, key=lambda row: row.asset_ids))


__all__ = [
    "AIEcosystemProjection",
    "ECOSYSTEM_ALGORITHM_VERSION",
    "ERG_COMPATIBILITY_ALGORITHM_VERSION",
    "resolve_ai_ecosystems",
]
