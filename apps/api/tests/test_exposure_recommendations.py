from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from app.core.control_coverage import CoverageState
from app.services.hmair.exposure.category_catalog import load_category_catalog
from app.services.hmair.exposure.contracts import (
    ExposureDimension,
    ExposureExtent,
    ExposureFactor,
    FreshnessState,
    VerificationStatus,
)
from app.services.hmair.exposure.reasoning_rules import ExposureRuleResult
from app.services.hmair.exposure.recommendations import (
    CAPABILITY_ROUTES,
    build_recommendations,
    project_exposure_coverage,
)


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
WEB_APP = Path(__file__).parents[2] / "web" / "src" / "app"


def _factor(
    state: str,
    index: int,
    *,
    source_type: str = "control_coverage_assertion",
    verification: VerificationStatus = VerificationStatus.VERIFIED,
    freshness: FreshnessState = FreshnessState.FRESH,
    related_refs: tuple[str, ...] = (),
) -> ExposureFactor:
    return ExposureFactor(
        dimension=ExposureDimension.CONTROL_COVERAGE,
        source_type=source_type,
        source_id=f"coverage-source-{index}",
        state=state,
        evidence_refs=(f"evidence-{index}",),
        related_source_refs=related_refs,
        confidence=None,
        verification_status=verification,
        freshness=freshness,
        observed_at=NOW,
        validated_at=NOW,
        methodology_id="control-coverage/1.0",
        collector_group="control_coverage",
    )


def _result(
    extent: ExposureExtent = ExposureExtent.MATERIAL,
    *,
    contributors: tuple[ExposureFactor, ...] = (),
) -> ExposureRuleResult:
    return ExposureRuleResult(
        category_id="coding_exposure",
        category_version="1.0.0",
        methodology_version="1.0.0",
        extent=extent,
        proven_lower_bound=extent,
        contributors=contributors,
        contradictions=(),
        unknown_dimensions=(),
        confidence=0.87,
        verification_status=VerificationStatus.VERIFIED,
        evidence_quality=None,
        collector_diversity=2,
        evidence_refs=("evidence-capability", "evidence-reachability"),
        reasoning_trace=("material_exposure_supported",),
        limitations=("evidence_quality_authority_unavailable",),
    )


def test_coverage_binds_exact_paths_and_assertions_without_second_score() -> None:
    factors = (
        _factor(
            "discovery:covered:verified_discovery_observation",
            1,
            related_refs=(
                "control_coverage_path:path-discovery",
                "control_coverage_assertion:assertion-discovery",
            ),
        ),
        _factor(
            "authorization:covered:verified_inline_decision",
            2,
            related_refs=(
                "control_coverage_path:path-authorization",
                "control_coverage_assertion:assertion-authorization",
            ),
        ),
        _factor(
            "evidence:covered:verified_execution_evidence",
            3,
            related_refs=(
                "control_coverage_path:path-evidence",
                "control_coverage_assertion:assertion-evidence",
            ),
        ),
        _factor(
            "containment:direct:control:inline",
            4,
            source_type="deployment_surface",
            related_refs=("control_coverage_path:path-containment",),
        ),
    )
    projection = project_exposure_coverage(factors)

    assert projection.discover.state is CoverageState.COVERED
    assert projection.authorize.state is CoverageState.COVERED
    assert projection.prove.state is CoverageState.COVERED
    assert projection.contain.state is CoverageState.COVERED
    assert projection.authorize.path_ids == ("path-authorization",)
    assert projection.authorize.assertion_ids == ("assertion-authorization",)
    assert not hasattr(projection, "score")


def test_monitor_only_is_not_authorization_and_deployment_is_not_containment() -> None:
    factors = (
        _factor(
            "authorization:covered:monitor_only_surface",
            1,
            related_refs=("control_coverage_path:path-monitor",),
        ),
        _factor(
            "deployment:covered:deployment_surface_active",
            2,
            related_refs=("control_coverage_path:path-deployed",),
        ),
    )
    projection = project_exposure_coverage(factors)

    assert projection.authorize.state is CoverageState.NOT_COVERED
    assert projection.authorize.control_mode == "monitor_only"
    assert projection.contain.state is CoverageState.UNKNOWN
    assert "containment_evidence_unavailable" in projection.contain.blind_spots


def test_monitor_only_real_representation_grounds_exact_path_recommendations() -> None:
    monitor = _factor(
        "authorization:covered",
        101,
        related_refs=(
            "control_coverage_path:path-monitor-real",
            "coverage_reason:monitor_only_surface",
        ),
    )
    coverage = project_exposure_coverage((monitor,))
    definition = next(
        item for item in load_category_catalog().categories
        if item.category_id == "coding_exposure"
    )

    recommendations = build_recommendations(
        definition=definition,
        result=_result(contributors=(monitor,)),
        coverage=coverage,
    )

    assert coverage.authorize.state is CoverageState.NOT_COVERED
    assert coverage.authorize.control_mode == "monitor_only"
    assert recommendations
    assert all(
        "control_coverage_path:path-monitor-real" in item.source_refs
        for item in recommendations
    )


def test_stale_assertions_are_unknown_and_external_containment_is_dependency() -> None:
    factors = (
        _factor(
            "evidence:covered:verified_execution_evidence",
            1,
            freshness=FreshnessState.EXPIRED,
            related_refs=("control_coverage_path:path-stale",),
        ),
        _factor(
            "containment:external:control:external_required",
            2,
            source_type="deployment_surface",
            related_refs=("control_coverage_path:path-external",),
        ),
    )
    projection = project_exposure_coverage(factors)

    assert projection.prove.state is CoverageState.UNKNOWN
    assert "stale_or_expired_assertion" in projection.prove.blind_spots
    assert projection.contain.state is CoverageState.NOT_COVERED
    assert projection.contain.external_control_dependency == "deployment_surface:coverage-source-2"
    assert "external_containment_dependency" in projection.contain.blind_spots


def test_conflicting_verified_coverage_assertions_resolve_to_unknown() -> None:
    factors = (
        _factor(
            "authorization:covered:verified_inline_decision",
            1,
            related_refs=("control_coverage_path:path-conflict",),
        ),
        _factor(
            "authorization:not_covered:verified_inline_gap",
            2,
            related_refs=("control_coverage_path:path-conflict",),
        ),
    )

    projection = project_exposure_coverage(factors)

    assert projection.authorize.state is CoverageState.UNKNOWN
    assert "conflicting_coverage_assertions" in projection.authorize.blind_spots


def test_conflicting_verified_containment_assertions_resolve_to_unknown() -> None:
    factors = (
        _factor(
            "containment:direct:control:inline",
            1,
            source_type="deployment_surface",
            related_refs=("control_coverage_path:path-conflict",),
        ),
        _factor(
            "containment:none:control:unknown",
            2,
            source_type="deployment_surface",
            related_refs=("control_coverage_path:path-conflict",),
        ),
    )

    projection = project_exposure_coverage(factors)

    assert projection.contain.state is CoverageState.UNKNOWN
    assert "conflicting_containment_evidence" in projection.contain.blind_spots


def test_conflicting_unknown_coverage_does_not_ground_gap_recommendations() -> None:
    factors = (
        _factor(
            "authorization:covered:verified_inline_decision",
            1,
            related_refs=("control_coverage_path:path-conflict",),
        ),
        _factor(
            "authorization:not_covered:verified_inline_gap",
            2,
            related_refs=("control_coverage_path:path-conflict",),
        ),
    )
    coverage = project_exposure_coverage(factors)
    definition = next(
        item for item in load_category_catalog().categories
        if item.category_id == "coding_exposure"
    )

    recommendations = build_recommendations(
        definition=definition,
        result=_result(contributors=factors),
        coverage=coverage,
    )

    assert coverage.authorize.state is CoverageState.UNKNOWN
    assert recommendations == ()


def test_absent_containment_proof_is_unknown() -> None:
    projection = project_exposure_coverage(())
    assert projection.contain.state is CoverageState.UNKNOWN
    assert projection.contain.freshness is FreshnessState.UNKNOWN


def test_every_recommendation_maps_to_a_real_existing_product_route() -> None:
    catalog = load_category_catalog()
    catalog_capabilities = {
        capability
        for category in catalog.categories
        for capability in category.recommendation_capabilities
    }
    assert set(CAPABILITY_ROUTES) == catalog_capabilities
    for route in CAPABILITY_ROUTES.values():
        path = route.split("?", maxsplit=1)[0]
        route_directory = WEB_APP / path.lstrip("/")
        assert (route_directory / "page.tsx").is_file(), route


def test_recommendations_are_deterministic_qualitative_and_evidence_bound() -> None:
    definition = next(
        item for item in load_category_catalog().categories
        if item.category_id == "coding_exposure"
    )
    capability = ExposureFactor(
        dimension=ExposureDimension.CAPABILITY,
        source_type="discovery_capability",
        source_id="capability-filesystem",
        state="filesystem_write",
        evidence_refs=("evidence-capability",),
        confidence=0.9,
        verification_status=VerificationStatus.VERIFIED,
        freshness=FreshnessState.FRESH,
        observed_at=NOW,
        validated_at=NOW,
        methodology_id="capability/1.0",
        collector_group="capability",
    )
    authorization_gap = _factor(
        "authorization:not_covered:verified_inline_gap",
        99,
        related_refs=("control_coverage_path:path-gap",),
    )
    coverage = project_exposure_coverage((authorization_gap,))
    grounded = _result(contributors=(capability, authorization_gap))
    first = build_recommendations(
        definition=definition,
        result=grounded,
        coverage=coverage,
    )
    second = build_recommendations(
        definition=definition,
        result=grounded,
        coverage=coverage,
    )

    assert first == second
    assert [item.capability for item in first] == sorted(definition.recommendation_capabilities)
    assert all(item.product_route == CAPABILITY_ROUTES[item.capability] for item in first)
    assert all(item.source_refs for item in first)
    assert all(
        any(reference.startswith(("discovery_capability:", "control_coverage_assertion:")) for reference in item.source_refs)
        for item in first
    )
    assert all(
        "control_coverage_path:path-gap" in item.source_refs
        for item in first
    )
    assert all("@path:" in item.target_control_path for item in first)
    assert all("%" not in item.expected_effect for item in first)
    assert all("score" not in item.expected_effect.casefold() for item in first)


def test_recommendation_identity_is_bound_to_rule_version_and_exact_path() -> None:
    definition = next(
        item for item in load_category_catalog().categories
        if item.category_id == "coding_exposure"
    )
    gap = _factor(
        "authorization:not_covered:verified_inline_gap",
        100,
        related_refs=("control_coverage_path:path-rule-binding",),
    )
    coverage = project_exposure_coverage((gap,))
    first_result = _result(contributors=(gap,))
    second_result = first_result.model_copy(update={"methodology_version": "9.9.9"})

    first = build_recommendations(
        definition=definition,
        result=first_result,
        coverage=coverage,
    )
    second = build_recommendations(
        definition=definition,
        result=second_result,
        coverage=coverage,
    )

    assert first
    assert {item.recommendation_id for item in first}.isdisjoint(
        {item.recommendation_id for item in second}
    )
    assert all(
        "control_coverage_path:path-rule-binding" in item.source_refs
        for item in first
    )


def test_none_extent_emits_no_recommendations() -> None:
    definition = next(
        item for item in load_category_catalog().categories
        if item.category_id == "coding_exposure"
    )
    assert build_recommendations(
        definition=definition,
        result=_result(ExposureExtent.NONE),
        coverage=project_exposure_coverage(()),
    ) == ()


def test_unknown_without_a_specific_proven_gap_emits_no_recommendations() -> None:
    definition = next(
        item for item in load_category_catalog().categories
        if item.category_id == "coding_exposure"
    )
    assert build_recommendations(
        definition=definition,
        result=_result(ExposureExtent.UNKNOWN),
        coverage=project_exposure_coverage(()),
    ) == ()
