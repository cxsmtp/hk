from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import sys
import textwrap

from app.services.hmair.exposure.contracts import (
    ExposureDimension,
    ExposureExtent,
    ExposureFactor,
    ExposureGraphEdgeType,
    ExposureGraphNodeType,
    FreshnessState,
    VerificationStatus,
)
from app.services.hmair.exposure.exposure_graph import build_exposure_graph
from app.services.hmair.exposure.reasoning_rules import ExposureRuleResult


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)


def _factor(
    dimension: ExposureDimension,
    state: str,
    index: int,
    *,
    verification: VerificationStatus = VerificationStatus.VERIFIED,
) -> ExposureFactor:
    return ExposureFactor(
        dimension=dimension,
        source_type=f"authority_{dimension.value}",
        source_id=f"source-{dimension.value}-{index}",
        state=state,
        evidence_refs=(f"evidence-{dimension.value}-{index}",),
        confidence=0.9,
        verification_status=verification,
        freshness=FreshnessState.FRESH,
        observed_at=NOW,
        validated_at=NOW,
        methodology_id="graph-test/1.0",
        collector_group=dimension.value,
        limitations=("source_payload_not_copied",),
    )


def _result(factors: tuple[ExposureFactor, ...]) -> ExposureRuleResult:
    return ExposureRuleResult(
        category_id="coding_exposure",
        category_version="1.0.0",
        methodology_version="1.0.0",
        extent=ExposureExtent.MATERIAL,
        proven_lower_bound=ExposureExtent.MATERIAL,
        contributors=factors,
        contradictions=(),
        unknown_dimensions=(),
        confidence=0.9,
        verification_status=VerificationStatus.VERIFIED,
        evidence_quality=None,
        collector_diversity=min(len(factors), 64),
        evidence_refs=tuple(item.evidence_refs[0] for item in factors),
        reasoning_trace=("material_exposure_supported",),
        limitations=("evidence_quality_authority_unavailable",),
    )


def test_graph_projects_only_approved_nodes_edges_and_exact_source_refs() -> None:
    factors = (
        _factor(ExposureDimension.CAPABILITY, "filesystem_write", 1),
        _factor(ExposureDimension.IDENTITY, "workload_identity:active", 2),
        _factor(ExposureDimension.PERMISSION, "write", 3),
        _factor(ExposureDimension.USAGE, "high_usage", 4),
        _factor(ExposureDimension.REACHABILITY, "internet:verified", 5),
        _factor(ExposureDimension.RUNTIME, "agent_runtime", 6),
        _factor(ExposureDimension.PROVIDER, "anthropic", 7),
        _factor(ExposureDimension.MODEL, "claude", 8),
        _factor(ExposureDimension.DATA, "restricted", 9),
        _factor(ExposureDimension.CONTROL_COVERAGE, "authorization:covered", 10),
        _factor(ExposureDimension.GOVERNANCE, "governed_inline", 11),
        _factor(ExposureDimension.AI_ACTION, "block:inline", 12),
    )
    graph = build_exposure_graph(
        asset_id="11111111-1111-4111-8111-111111111111",
        conclusion=_result(factors),
        factors=factors,
    )

    assert {node.node_type for node in graph.nodes} == {
        ExposureGraphNodeType.AI_ASSET,
        ExposureGraphNodeType.CAPABILITY,
        ExposureGraphNodeType.IDENTITY,
        ExposureGraphNodeType.PERMISSION,
        ExposureGraphNodeType.USAGE,
        ExposureGraphNodeType.REACHABILITY,
        ExposureGraphNodeType.RUNTIME,
        ExposureGraphNodeType.PROVIDER,
        ExposureGraphNodeType.MODEL,
        ExposureGraphNodeType.DATA,
        ExposureGraphNodeType.CONTROL_COVERAGE,
        ExposureGraphNodeType.POLICY,
        ExposureGraphNodeType.AI_ACTION,
    }
    assert ExposureGraphEdgeType.BLOCKED in {edge.edge_type for edge in graph.edges}
    factor_nodes = [node for node in graph.nodes if node.node_type is not ExposureGraphNodeType.AI_ASSET]
    assert {node.source_id for node in factor_nodes} == {item.source_id for item in factors}
    assert all(edge.source_refs for edge in graph.edges)
    assert all(edge.source_node_id != edge.target_node_id for edge in graph.edges)

    serialized = graph.model_dump(mode="json")
    forbidden = {"payload", "raw_payload", "prompt", "content", "secret", "token"}
    assert forbidden.isdisjoint(serialized)
    assert all(forbidden.isdisjoint(node) for node in serialized["nodes"])
    assert all(forbidden.isdisjoint(edge) for edge in serialized["edges"])


def test_graph_is_deterministic_bounded_and_marks_truncation() -> None:
    factors = tuple(
        _factor(ExposureDimension.CAPABILITY, f"capability_{index}", index)
        for index in range(210)
    )
    conclusion = _result(factors)

    first = build_exposure_graph(
        asset_id="22222222-2222-4222-8222-222222222222",
        conclusion=conclusion,
        factors=tuple(reversed(factors)),
        max_nodes=8,
        max_edges=5,
    )
    second = build_exposure_graph(
        asset_id="22222222-2222-4222-8222-222222222222",
        conclusion=conclusion,
        factors=factors,
        max_nodes=8,
        max_edges=5,
    )

    assert first == second
    assert len(first.nodes) == 8
    assert len(first.edges) == 5
    assert first.truncated is True


def test_graph_marks_internal_reference_projection_truncation() -> None:
    factor = _factor(ExposureDimension.CONTROL_COVERAGE, "authorization:covered", 1)
    conclusion = _result((factor,)).model_copy(
        update={"evidence_refs": tuple(f"evidence-{index:03d}" for index in range(65))}
    )
    graph = build_exposure_graph(
        asset_id="77777777-7777-4777-8777-777777777777",
        conclusion=conclusion,
        factors=(factor,),
    )

    assert graph.truncated is True
    assert "root_evidence_refs_truncated" in graph.nodes[0].limitations
    assert len(graph.nodes[0].evidence_refs) == 64

    path_factor = factor.model_copy(
        update={
            "related_source_refs": tuple(
                f"control_coverage_path:path-{index:03d}" for index in range(64)
            )
        }
    )
    path_graph = build_exposure_graph(
        asset_id="88888888-8888-4888-8888-888888888888",
        conclusion=_result((path_factor,)),
        factors=(path_factor,),
    )

    assert path_graph.truncated is True
    assert len(path_graph.edges[0].source_refs) == 64
    assert "graph_source_refs_truncated" in path_graph.edges[0].limitations


def test_graph_never_labels_negative_or_unknown_evidence_as_access_or_governed() -> None:
    factors = (
        _factor(ExposureDimension.PERMISSION, "not_authorized", 1),
        _factor(ExposureDimension.REACHABILITY, "filesystem:not_reachable", 2),
        _factor(ExposureDimension.GOVERNANCE, "unmanaged:confirmed_shadow", 3),
        _factor(ExposureDimension.CONTROL_COVERAGE, "authorization:unknown", 4),
        _factor(ExposureDimension.CONTROL_COVERAGE, "containment:external", 5),
        _factor(ExposureDimension.IDENTITY, "workload_identity:active", 6),
    )

    graph = build_exposure_graph(
        asset_id="33333333-3333-4333-8333-333333333333",
        conclusion=_result(factors),
        factors=factors,
    )
    edge_by_source = {
        edge.source_refs[0]: edge.edge_type for edge in graph.edges
    }

    assert edge_by_source["authority_permission:source-permission-1"] is ExposureGraphEdgeType.BLOCKED
    assert edge_by_source["authority_reachability:source-reachability-2"] is ExposureGraphEdgeType.BLOCKED
    assert edge_by_source["authority_governance:source-governance-3"] is ExposureGraphEdgeType.UNGOVERNED
    assert edge_by_source["authority_control_coverage:source-control_coverage-4"] is ExposureGraphEdgeType.OBSERVED
    assert edge_by_source["authority_control_coverage:source-control_coverage-5"] is ExposureGraphEdgeType.UNGOVERNED
    assert edge_by_source["authority_identity:source-identity-6"] is ExposureGraphEdgeType.OBSERVED


def test_graph_keeps_shared_surface_paths_unique_and_traceable() -> None:
    first = _factor(ExposureDimension.CONTROL_COVERAGE, "containment:direct:control:inline", 1).model_copy(
        update={"related_source_refs": ("control_coverage_path:path-a",)}
    )
    second = _factor(ExposureDimension.CONTROL_COVERAGE, "containment:direct:control:inline", 2).model_copy(
        update={
            "source_id": first.source_id,
            "related_source_refs": ("control_coverage_path:path-b",),
        }
    )

    graph = build_exposure_graph(
        asset_id="44444444-4444-4444-8444-444444444444",
        conclusion=_result((first, second)),
        factors=(first, second),
    )
    factor_nodes = tuple(
        node for node in graph.nodes if node.node_type is not ExposureGraphNodeType.AI_ASSET
    )

    assert len(factor_nodes) == 2
    assert len({node.node_id for node in factor_nodes}) == 2
    assert len({edge.edge_id for edge in graph.edges}) == 2
    assert {
        reference
        for edge in graph.edges
        for reference in edge.source_refs
        if reference.startswith("control_coverage_path:")
    } == {"control_coverage_path:path-a", "control_coverage_path:path-b"}


def test_graph_serialization_is_stable_across_python_hash_seeds() -> None:
    script = textwrap.dedent(
        """
        from datetime import datetime, timezone
        from app.services.hmair.exposure.contracts import ExposureDimension, ExposureExtent, ExposureFactor, FreshnessState, VerificationStatus
        from app.services.hmair.exposure.exposure_graph import build_exposure_graph
        from app.services.hmair.exposure.reasoning_rules import ExposureRuleResult

        now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
        base = dict(
            dimension=ExposureDimension.CONTROL_COVERAGE,
            source_type="deployment_surface",
            source_id="shared-surface",
            state="containment:direct:control:inline",
            evidence_refs=("evidence",),
            confidence=0.9,
            verification_status=VerificationStatus.VERIFIED,
            freshness=FreshnessState.FRESH,
            observed_at=now,
            validated_at=now,
            methodology_id="determinism/1.0",
        )
        factors = tuple({
            ExposureFactor(**base, related_source_refs=("control_coverage_path:path-a",)),
            ExposureFactor(**base, related_source_refs=("control_coverage_path:path-b",)),
        })
        conclusion = ExposureRuleResult(
            category_id="coding_exposure",
            category_version="1.0.0",
            methodology_version="1.2.0",
            extent=ExposureExtent.MATERIAL,
            proven_lower_bound=ExposureExtent.MATERIAL,
            contributors=factors,
            contradictions=(),
            unknown_dimensions=(),
            confidence=0.9,
            verification_status=VerificationStatus.VERIFIED,
            evidence_quality=None,
            collector_diversity=1,
            evidence_refs=("evidence",),
            reasoning_trace=("deterministic",),
            limitations=(),
        )
        graph = build_exposure_graph(
            asset_id="66666666-6666-4666-8666-666666666666",
            conclusion=conclusion,
            factors=factors,
        )
        print(graph.model_dump_json())
        """
    )
    api_root = Path(__file__).resolve().parents[1]
    outputs = []
    for seed in ("1", "2"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = str(api_root)
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
            timeout=10,
        )
        outputs.append(completed.stdout)

    assert outputs[0] == outputs[1]
