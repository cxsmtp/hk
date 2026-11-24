from __future__ import annotations

import hashlib

from app.services.hmair.contracts import canonical_json_bytes
from app.services.hmair.exposure.contracts import (
    ExposureConclusion,
    ExposureDimension,
    ExposureFactor,
    ExposureGraph,
    ExposureGraphEdge,
    ExposureGraphEdgeType,
    ExposureGraphNode,
    ExposureGraphNodeType,
)
from app.services.hmair.exposure.reasoning_rules import ExposureRuleResult


_NODE_TYPE_BY_DIMENSION = {
    ExposureDimension.CAPABILITY: ExposureGraphNodeType.CAPABILITY,
    ExposureDimension.IDENTITY: ExposureGraphNodeType.IDENTITY,
    ExposureDimension.PERMISSION: ExposureGraphNodeType.PERMISSION,
    ExposureDimension.USAGE: ExposureGraphNodeType.USAGE,
    ExposureDimension.REACHABILITY: ExposureGraphNodeType.REACHABILITY,
    ExposureDimension.RUNTIME: ExposureGraphNodeType.RUNTIME,
    ExposureDimension.PROVIDER: ExposureGraphNodeType.PROVIDER,
    ExposureDimension.MODEL: ExposureGraphNodeType.MODEL,
    ExposureDimension.DATA: ExposureGraphNodeType.DATA,
    ExposureDimension.CONTROL_COVERAGE: ExposureGraphNodeType.CONTROL_COVERAGE,
    ExposureDimension.GOVERNANCE: ExposureGraphNodeType.POLICY,
    ExposureDimension.AI_ACTION: ExposureGraphNodeType.AI_ACTION,
}


def _digest(domain: bytes, material: object) -> str:
    return hashlib.sha256(domain + canonical_json_bytes(material)).hexdigest()


def _factor_key(factor: ExposureFactor) -> tuple[str, str, str, str, bytes]:
    return (
        factor.dimension.value,
        factor.source_type,
        factor.source_id,
        factor.state,
        canonical_json_bytes(factor.model_dump(mode="json")),
    )


def _edge_type(factor: ExposureFactor) -> ExposureGraphEdgeType:
    state = factor.state.casefold()
    state_parts = tuple(part for part in state.split(":") if part)
    if factor.dimension is ExposureDimension.DATA:
        return ExposureGraphEdgeType.CAN_ACCESS
    if factor.dimension is ExposureDimension.PERMISSION:
        if any(
            marker in state
            for marker in ("denied", "none", "not_authorized", "blocked", "revoked")
        ):
            return ExposureGraphEdgeType.BLOCKED
        return ExposureGraphEdgeType.CAN_ACCESS
    if factor.dimension is ExposureDimension.IDENTITY:
        return ExposureGraphEdgeType.OBSERVED
    if factor.dimension is ExposureDimension.AI_ACTION:
        return (
            ExposureGraphEdgeType.BLOCKED
            if "block" in state or "deny" in state
            else ExposureGraphEdgeType.AUTHORIZED
        )
    if factor.dimension in {
        ExposureDimension.GOVERNANCE,
        ExposureDimension.CONTROL_COVERAGE,
    }:
        if "unknown" in state_parts or "owner_unknown" in state_parts:
            return ExposureGraphEdgeType.OBSERVED
        if factor.dimension is ExposureDimension.GOVERNANCE:
            head = state_parts[0] if state_parts else ""
            if head in {"unapproved", "ungoverned", "unmanaged", "personal"}:
                return ExposureGraphEdgeType.UNGOVERNED
            if head in {"approved", "governed", "governed_inline", "managed"}:
                return ExposureGraphEdgeType.GOVERNED
            return ExposureGraphEdgeType.OBSERVED
        if state_parts and state_parts[0] == "containment":
            capability = state_parts[1] if len(state_parts) > 1 else "unknown"
            if capability in {"external", "none"}:
                return ExposureGraphEdgeType.UNGOVERNED
            if capability in {"direct", "surface_limited"}:
                return ExposureGraphEdgeType.GOVERNED
            return ExposureGraphEdgeType.OBSERVED
        assertion = state_parts[1] if len(state_parts) > 1 else "unknown"
        if assertion == "not_covered" or "monitor_only" in state_parts:
            return ExposureGraphEdgeType.UNGOVERNED
        if assertion == "covered":
            return ExposureGraphEdgeType.GOVERNED
        return ExposureGraphEdgeType.OBSERVED
    if factor.dimension is ExposureDimension.CAPABILITY:
        return ExposureGraphEdgeType.OBSERVED
    if factor.dimension is ExposureDimension.REACHABILITY:
        if any(
            marker in state
            for marker in ("not_reachable", "unreachable", "denied", "no_reach", "blocked")
        ):
            return ExposureGraphEdgeType.BLOCKED
        return ExposureGraphEdgeType.CAN_ACCESS
    if factor.dimension in {
        ExposureDimension.RUNTIME,
        ExposureDimension.PROVIDER,
        ExposureDimension.MODEL,
        ExposureDimension.USAGE,
    }:
        return ExposureGraphEdgeType.USES
    return ExposureGraphEdgeType.OBSERVED


def _bounded_limitations(
    limitations: set[str], *, required_marker: str | None = None
) -> tuple[str, ...]:
    ordered = tuple(sorted(limitations))
    if len(ordered) <= 32:
        return ordered
    if required_marker is None or required_marker not in limitations:
        return ordered[:32]
    retained = tuple(item for item in ordered if item != required_marker)[:31]
    return tuple(sorted((*retained, required_marker)))


def build_exposure_graph(
    *,
    asset_id: str,
    conclusion: ExposureRuleResult | ExposureConclusion,
    factors: tuple[ExposureFactor, ...],
    max_nodes: int = 200,
    max_edges: int = 400,
) -> ExposureGraph:
    """Build a bounded, read-only explanation graph from exact source refs."""

    if not asset_id or len(asset_id) > 36:
        raise ValueError("asset_id must be a bounded exact asset reference")
    if not 1 <= max_nodes <= 200:
        raise ValueError("max_nodes must be between 1 and 200")
    if not 1 <= max_edges <= 400:
        raise ValueError("max_edges must be between 1 and 400")

    selected = tuple(
        sorted(
            set(factors),
            key=_factor_key,
        )
    )
    available_node_slots = max(0, max_nodes - 1)
    projected_factors = selected[:available_node_slots]
    projection_truncated = False
    root_refs = tuple(sorted(conclusion.evidence_refs))[:64]
    root_limitations = set(conclusion.limitations)
    if len(conclusion.evidence_refs) > len(root_refs):
        projection_truncated = True
        root_limitations.add("root_evidence_refs_truncated")
    root = ExposureGraphNode(
        node_id=f"asset:{asset_id}",
        node_type=ExposureGraphNodeType.AI_ASSET,
        source_type="discovery_asset",
        source_id=asset_id,
        label=f"AI asset {asset_id}",
        verification_status=conclusion.verification_status,
        evidence_refs=root_refs,
        limitations=_bounded_limitations(
            root_limitations,
            required_marker=(
                "root_evidence_refs_truncated"
                if "root_evidence_refs_truncated" in root_limitations
                else None
            ),
        ),
    )

    factor_nodes: list[ExposureGraphNode] = []
    edges: list[ExposureGraphEdge] = []
    for factor in projected_factors:
        exact_path_refs = tuple(
            sorted(
                reference
                for reference in factor.related_source_refs
                if reference.startswith("control_coverage_path:")
            )
        )
        node_id = "factor:" + _digest(
            b"hawk:ai-exposure-graph-node:v1",
            {
                "dimension": factor.dimension.value,
                "source_type": factor.source_type,
                "source_id": factor.source_id,
                "exact_path_refs": exact_path_refs,
            },
        )
        factor_limitations = set(factor.limitations)
        source_refs = tuple(
            [f"{factor.source_type}:{factor.source_id}", *exact_path_refs]
        )[:64]
        if 1 + len(exact_path_refs) > len(source_refs):
            projection_truncated = True
            factor_limitations.add("graph_source_refs_truncated")
        bounded_factor_limitations = _bounded_limitations(
            factor_limitations,
            required_marker=(
                "graph_source_refs_truncated"
                if "graph_source_refs_truncated" in factor_limitations
                else None
            ),
        )
        factor_nodes.append(
            ExposureGraphNode(
                node_id=node_id,
                node_type=_NODE_TYPE_BY_DIMENSION[factor.dimension],
                source_type=factor.source_type,
                source_id=factor.source_id,
                label=f"{factor.dimension.value}: {factor.state}",
                verification_status=factor.verification_status,
                evidence_refs=tuple(sorted(factor.evidence_refs)),
                limitations=bounded_factor_limitations,
            )
        )
        edge_type = _edge_type(factor)
        edges.append(
            ExposureGraphEdge(
                edge_id=_digest(
                    b"hawk:ai-exposure-graph-edge:v1",
                    {
                        "category_id": conclusion.category_id,
                        "edge_type": edge_type.value,
                        "source_node_id": root.node_id,
                        "target_node_id": node_id,
                        "source_refs": source_refs,
                    },
                ),
                edge_type=edge_type,
                source_node_id=root.node_id,
                target_node_id=node_id,
                source_refs=source_refs,
                evidence_refs=tuple(sorted(factor.evidence_refs)),
                verification_status=factor.verification_status,
                limitations=bounded_factor_limitations,
            )
        )

    projected_edges = tuple(sorted(edges, key=lambda item: item.edge_id)[:max_edges])
    truncated = (
        projection_truncated
        or len(selected) > len(projected_factors)
        or len(edges) > len(projected_edges)
    )
    return ExposureGraph(
        nodes=(root,) + tuple(sorted(factor_nodes, key=lambda item: item.node_id)),
        edges=projected_edges,
        truncated=truncated,
    )


__all__ = ["build_exposure_graph"]
