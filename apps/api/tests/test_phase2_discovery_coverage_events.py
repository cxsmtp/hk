from __future__ import annotations

from datetime import datetime, timezone

from app.services.control_coverage.discovery_coverage import (
    DiscoveryCoverageDimension,
    DiscoveryCoverageProjection,
    DiscoveryDenominatorTruth,
)
from app.services.control_graph_service import (
    discovery_coverage_change_events,
    project_discovery_coverage_relationships,
)
from app.services.findings_service import discovery_coverage_gap_candidates


NOW = datetime(2026, 8, 15, 13, 0, tzinfo=timezone.utc)


def _dimension(name: str, *, covered=(), not_covered=(), unknown=(), evidence=("evidence_node:node-1",)):
    return DiscoveryCoverageDimension(
        name=name,
        covered_count=len(covered),
        not_covered_count=len(not_covered),
        unknown_count=len(unknown),
        covered_asset_ids=tuple(covered),
        not_covered_asset_ids=tuple(not_covered),
        unknown_asset_ids=tuple(unknown),
        score=None,
        score_withheld_reason="enterprise_denominator_not_established",
        methodology=f"{name} evidence methodology",
        evidence_refs=tuple(evidence),
        missing_evidence=tuple(f"asset:{item}:{name}" for item in (*not_covered, *unknown)),
        improvement_actions=(f"Improve {name} evidence.",),
    )


def _projection(*, identity_unknown: bool) -> DiscoveryCoverageProjection:
    return DiscoveryCoverageProjection(
        tenant_id="tenant-a",
        methodology_version="discovery-coverage/2.0",
        generated_at=NOW,
        denominator=DiscoveryDenominatorTruth(
            status="inferred",
            known_assets=1,
            unresolved_hypotheses=0,
            inaccessible_sources=0,
            stale_sources=0,
            unknown_sources=(),
            unsupported_sources=(),
            enterprise_denominator_complete=False,
            evidence_ref="discovery_scan:scan-1",
            explanation="Enterprise denominator is not established.",
        ),
        dimensions={
            "discovery": _dimension("discovery", covered=("asset-1",)),
            "identity": _dimension(
                "identity",
                unknown=("asset-1",) if identity_unknown else (),
                not_covered=() if identity_unknown else ("asset-1",),
            ),
            "usage": _dimension("usage", covered=("asset-1",)),
            "authorization": _dimension("authorization", unknown=("asset-1",)),
            "evidence": _dimension("evidence", covered=("asset-1",)),
            "containment": _dimension("containment", unknown=("asset-1",)),
            "bypass_detection": _dimension("bypass_detection", unknown=("asset-1",)),
        },
        limitations=("Scores withheld.",),
    )


def test_graph_projection_keeps_covered_uncovered_and_unknown_states_exact() -> None:
    relationships = project_discovery_coverage_relationships(
        _projection(identity_unknown=True)
    )
    assert len(relationships) == 7
    states = {(item["dimension"], item["coverage_state"]) for item in relationships}
    assert states == {
        ("discovery", "covered"),
        ("identity", "unknown"),
        ("usage", "covered"),
        ("authorization", "unknown"),
        ("evidence", "covered"),
        ("containment", "unknown"),
        ("bypass_detection", "unknown"),
    }
    assert all(item["evidence_refs"] == ["evidence_node:node-1"] for item in relationships)
    assert all(item["authorization_effect"] == "none" for item in relationships)


def test_change_events_are_evidence_bound_and_do_not_recast_unknown_as_blocked() -> None:
    events = discovery_coverage_change_events(
        _projection(identity_unknown=True),
        _projection(identity_unknown=False),
    )
    assert events == [
        {
            "tenant_id": "tenant-a",
            "asset_id": "asset-1",
            "dimension": "identity",
            "previous_state": "unknown",
            "current_state": "not_covered",
            "evidence_refs": ["evidence_node:node-1"],
            "methodology_version": "discovery-coverage/2.0",
            "observed_at": NOW.isoformat(),
            "authorization_effect": "none",
        }
    ]


def test_gap_candidates_separate_uncovered_findings_from_unknown_verification() -> None:
    unknown_candidates = discovery_coverage_gap_candidates(
        _projection(identity_unknown=True)
    )
    assert unknown_candidates[0]["candidate_kind"] == "verification_required"
    assert unknown_candidates[0]["coverage_state"] == "unknown"

    uncovered_candidates = discovery_coverage_gap_candidates(
        _projection(identity_unknown=False)
    )
    identity_candidate = next(
        item for item in uncovered_candidates if item["dimension"] == "identity"
    )
    assert identity_candidate["candidate_kind"] == "coverage_gap"
    assert identity_candidate["coverage_state"] == "not_covered"
    assert identity_candidate["auto_persist"] is False
