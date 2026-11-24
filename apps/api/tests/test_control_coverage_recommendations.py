from __future__ import annotations

from app.services.control_coverage.recommendations import (
    CapabilityProfileView,
    CoverageAssertionView,
    CoverageFindingView,
    CoveragePathView,
    build_blind_spots,
    rank_deployment_improvements,
)


def _path(path_id: str = "p1") -> CoveragePathView:
    return CoveragePathView(path_id=path_id, source_refs=(f"runtime_event:event-{path_id}",))


def _finding(
    finding_id: str,
    *,
    path_id: str | None,
    evidence_id: str,
    kind: str,
    source_ref: str | None = None,
) -> CoverageFindingView:
    return CoverageFindingView(
        finding_id=finding_id,
        kind=kind,
        path_id=path_id,
        source_ref=source_ref,
        evidence_ids=(evidence_id,),
    )


def _assertion(
    assertion_id: str,
    *,
    path_id: str,
    dimension: str,
    state: str = "not_covered",
) -> CoverageAssertionView:
    return CoverageAssertionView(
        assertion_id=assertion_id,
        path_id=path_id,
        dimension=dimension,
        state=state,
        evidence_refs=(f"runtime_event:event-{path_id}",),
    )


def test_unknown_catalog_entry_is_not_a_tenant_blind_spot() -> None:
    assert build_blind_spots(paths=[], findings=[], assertions=[]) == []


def test_confirmed_unmanaged_path_keeps_evidence_reference() -> None:
    result = build_blind_spots(
        paths=[_path("p1")],
        findings=[_finding("f1", path_id="p1", evidence_id="e1", kind="unprotected_path")],
        assertions=[_assertion("a1", path_id="p1", dimension="deployment")],
    )
    assert result[0].evidence_refs == ("evidence:e1", "finding:f1")
    assert result[0].path_id == "p1"


def test_finding_requires_evidence_and_a_path_or_source_observation_link() -> None:
    missing_evidence = CoverageFindingView(
        finding_id="f1",
        kind="unprotected_path",
        path_id="p1",
        source_ref=None,
        evidence_ids=(),
    )
    unlinked = _finding("f2", path_id="missing", evidence_id="e2", kind="bypass")
    unsupported = _finding("f3", path_id="p1", evidence_id="e3", kind="generic_risk")
    assert build_blind_spots(
        paths=[_path("p1")],
        findings=[missing_evidence, unlinked, unsupported],
        assertions=[_assertion("a1", path_id="p1", dimension="deployment")],
    ) == []


def test_source_observation_can_resolve_a_path_without_claiming_catalog_absence() -> None:
    result = build_blind_spots(
        paths=[_path("p1")],
        findings=[
            _finding(
                "f1",
                path_id=None,
                evidence_id="e1",
                kind="unmanaged_browser",
                source_ref="runtime_event:event-p1",
            )
        ],
        assertions=[_assertion("a1", path_id="p1", dimension="deployment")],
    )
    assert [item.path_id for item in result] == ["p1"]


def test_recommendations_count_distinct_addressable_assertions() -> None:
    assertions = [
        _assertion("a1", path_id="p1", dimension="authorization"),
        _assertion("a1", path_id="p1", dimension="authorization"),
        _assertion("a2", path_id="p2", dimension="authorization", state="unknown"),
        _assertion("a3", path_id="p2", dimension="evidence"),
        _assertion("covered", path_id="p3", dimension="authorization", state="covered"),
    ]
    profiles = [
        CapabilityProfileView(
            deployment_type="inline_gateway",
            capability_profile={
                "inline_authorization": "yes",
                "evidence_generation": "full",
            },
            prerequisites=("Route supported traffic through the gateway.",),
        ),
        CapabilityProfileView(
            deployment_type="monitoring_connector",
            capability_profile={"inline_authorization": "no", "evidence_generation": "partial"},
            prerequisites=(),
        ),
    ]

    result = rank_deployment_improvements(assertions=assertions, capability_profiles=profiles)

    assert result[0].deployment_type == "inline_gateway"
    assert result[0].addressable_assertion_count == len(set(result[0].assertion_ids)) == 3
    assert result[0].impacted_path_count == 2
    assert result[0].conditional is True
    monitoring = next(item for item in result if item.deployment_type == "monitoring_connector")
    assert monitoring.assertion_ids == ("a3",)


def test_profiles_without_a_closed_requirement_match_are_omitted() -> None:
    result = rank_deployment_improvements(
        assertions=[_assertion("a1", path_id="p1", dimension="authorization")],
        capability_profiles=[
            CapabilityProfileView(
                deployment_type="unknown_proxy",
                capability_profile={"inline_authorization": "unknown"},
            )
        ],
    )
    assert result == []
