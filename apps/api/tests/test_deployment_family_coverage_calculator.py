from __future__ import annotations

from datetime import datetime, timezone

from app.core.deployment_family_coverage import (
    DIMENSION_ORDER,
    FAMILY_ORDER,
    METHODOLOGY_VERSION,
    ContainmentEvidence,
    DimensionAssertion,
    calculate_family_coverage,
    evaluate_containment,
)


CALCULATED_AT = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)


def _assertion(
    *,
    path_id: str,
    dimension: str,
    state: str,
    family: str = "runtime",
    quality: str = "verified",
    stale: bool = False,
    conflicting: bool = False,
    evidence_refs: tuple[str, ...] = ("runtime_event:event-1",),
) -> DimensionAssertion:
    return DimensionAssertion(
        path_id=path_id,
        family=family,
        dimension=dimension,
        state=state,
        evidence_quality=quality,
        stale=stale,
        conflicting=conflicting,
        evidence_refs=evidence_refs,
    )


def test_contract_order_methodology_and_empty_population_are_explicit() -> None:
    result = calculate_family_coverage(
        (),
        calculated_at=CALCULATED_AT,
        input_watermarks={"runtime_event": "none"},
        diagnostics=("missing_current_control_coverage_snapshot",),
    )

    assert METHODOLOGY_VERSION == "deployment-family-coverage/1.0"
    assert tuple(item.family for item in result.families) == FAMILY_ORDER
    assert tuple(item.name for item in result.families[0].dimensions) == DIMENSION_ORDER
    assert result.calculated_at is CALCULATED_AT
    assert result.diagnostics == ("missing_current_control_coverage_snapshot",)
    assert result.overall.status == "insufficient_data"
    assert result.overall.percentage_nullable is None
    assert result.overall.confidence == "unknown"
    for family in result.families:
        assert family.overall.status == "insufficient_data"
        assert family.overall.percentage_nullable is None
        assert family.estate_unknown_percentage_nullable is None
        for dimension in family.dimensions:
            assert dimension.total_known_eligible_count == 0
            assert dimension.percentage_nullable is None
            assert dimension.status == "insufficient_data"


def test_unknown_stays_in_denominator_not_applicable_is_excluded_and_overall_microaggregates() -> None:
    assertions = []
    for dimension in DIMENSION_ORDER:
        assertions.extend(
            (
                _assertion(path_id="covered", dimension=dimension, state="covered"),
                _assertion(path_id="unknown", dimension=dimension, state="unknown"),
                _assertion(
                    path_id="excluded",
                    dimension=dimension,
                    state="not_applicable",
                ),
            )
        )

    result = calculate_family_coverage(
        assertions,
        calculated_at=CALCULATED_AT,
        input_watermarks={"runtime_event": "event-1"},
    )
    runtime = next(item for item in result.families if item.family == "runtime")

    for dimension in runtime.dimensions:
        assert dimension.covered_count == 1
        assert dimension.not_covered_count == 0
        assert dimension.unknown_count == 1
        assert dimension.excluded_count == 1
        assert dimension.total_known_eligible_count == 2
        assert dimension.percentage_nullable == 50.0
        assert dimension.status == "sufficient_data"
        assert dimension.confidence == "medium"

    assert runtime.overall.status == "sufficient_data"
    assert runtime.overall.covered_count == 6
    assert runtime.overall.unknown_count == 6
    assert runtime.overall.excluded_count == 6
    assert runtime.overall.percentage_nullable == 50.0
    assert runtime.estate_unknown_percentage_nullable == 50.0
    assert runtime.overall.confidence == "medium"
    assert result.overall.percentage_nullable == 50.0


def test_overall_score_is_absent_until_every_dimension_is_sufficient() -> None:
    result = calculate_family_coverage(
        (
            _assertion(
                path_id="path-1",
                dimension="discovery",
                state="covered",
                family="browser",
            ),
        ),
        calculated_at=CALCULATED_AT,
        input_watermarks={},
    )
    browser = result.families[0]

    assert browser.dimensions[0].percentage_nullable == 100.0
    assert browser.overall.status == "insufficient_data"
    assert browser.overall.percentage_nullable is None
    assert result.overall.percentage_nullable is None


def test_confidence_precedence_requires_explicit_quality_and_stale_or_conflict_wins() -> None:
    assertions = []
    for dimension in DIMENSION_ORDER:
        assertions.append(
            _assertion(path_id="path-1", dimension=dimension, state="covered")
        )
    assertions.append(
        _assertion(
            path_id="path-2",
            dimension="identity",
            state="not_covered",
            quality="metadata_only",
        )
    )
    assertions.append(
        _assertion(
            path_id="path-2",
            dimension="authorization",
            state="unknown",
            stale=True,
        )
    )

    result = calculate_family_coverage(
        assertions,
        calculated_at=CALCULATED_AT,
        input_watermarks={},
    )
    runtime = next(item for item in result.families if item.family == "runtime")
    by_name = {item.name: item for item in runtime.dimensions}

    assert by_name["discovery"].confidence == "high"
    assert by_name["identity"].confidence == "low"
    assert by_name["authorization"].confidence == "unknown"
    assert runtime.overall.confidence == "unknown"


def test_partial_or_metadata_only_evidence_cannot_independently_grant_covered() -> None:
    for quality in ("partial", "metadata_only"):
        result = calculate_family_coverage(
            (
                _assertion(
                    path_id=f"path-{quality}",
                    dimension="discovery",
                    state="covered",
                    quality=quality,
                ),
            ),
            calculated_at=CALCULATED_AT,
            input_watermarks={},
        )
        discovery = next(
            item for item in result.families if item.family == "runtime"
        ).dimensions[0]

        assert discovery.covered_count == 0
        assert discovery.unknown_count == 1
        assert discovery.confidence == "low"


def test_entirely_unknown_missing_evidence_has_unknown_not_medium_confidence() -> None:
    result = calculate_family_coverage(
        (
            _assertion(
                path_id="missing",
                dimension="discovery",
                state="unknown",
                evidence_refs=(),
            ),
        ),
        calculated_at=CALCULATED_AT,
        input_watermarks={},
    )
    discovery = next(
        item for item in result.families if item.family == "runtime"
    ).dimensions[0]

    assert discovery.status == "sufficient_data"
    assert discovery.unknown_count == 1
    assert discovery.confidence == "unknown"


def test_evidence_refs_are_safe_bounded_deterministic_and_duplicate_conflicts_are_conservative() -> None:
    safe_refs = tuple(f"evidence:node-{index:02d}" for index in range(30))
    assertions = (
        _assertion(
            path_id="same-path",
            dimension="discovery",
            state="covered",
            family="not-a-family",
            evidence_refs=(
                *reversed(safe_refs),
                "https://example.invalid/leak?token=secret",
                "runtime_event:bad\nheader",
                "decision_receipt:" + ("x" * 300),
                "evidence:",
            ),
        ),
        _assertion(
            path_id="same-path",
            dimension="discovery",
            state="not_covered",
            family="unknown",
            evidence_refs=("runtime_event:event-1",),
        ),
        _assertion(
            path_id="ignored",
            dimension="not-a-dimension",
            state="covered",
        ),
    )

    first = calculate_family_coverage(
        assertions,
        calculated_at=CALCULATED_AT,
        input_watermarks={},
    )
    second = calculate_family_coverage(
        tuple(reversed(assertions)),
        calculated_at=CALCULATED_AT,
        input_watermarks={},
    )
    unknown_first = next(item for item in first.families if item.family == "unknown")
    unknown_second = next(item for item in second.families if item.family == "unknown")
    discovery = unknown_first.dimensions[0]

    assert discovery.unknown_count == 1
    assert discovery.confidence == "unknown"
    assert len(discovery.evidence_refs) == 20
    assert all("?" not in ref and "\n" not in ref for ref in discovery.evidence_refs)
    assert "evidence:" not in discovery.evidence_refs
    assert unknown_first.as_dict() == unknown_second.as_dict()


def test_output_watermarks_reject_secret_url_and_control_character_values() -> None:
    result = calculate_family_coverage(
        (),
        calculated_at=CALCULATED_AT,
        input_watermarks={
            "runtime_event": "12345678-1234-1234-1234-123456789012",
            "ai_action": "Bearer secret-material",
            "decision_receipt": "https://example.invalid/receipt",
            "execution_receipt": "receipt\ninjected",
            "deployment_surface": "none",
            "control_coverage_snapshot": "12345678-1234-1234-1234-123456789012",
            "control_coverage_input_digest": "a" * 64,
            "control_coverage_computed_at": "2026-07-27T12:00:00+00:00",
            "deployment_family_calculated_at": "2026-07-27T12:00:00+00:00",
        },
    )

    assert result.input_watermarks == {
        "control_coverage_computed_at": "2026-07-27T12:00:00+00:00",
        "control_coverage_input_digest": "a" * 64,
        "control_coverage_snapshot": "12345678-1234-1234-1234-123456789012",
        "deployment_family_calculated_at": "2026-07-27T12:00:00+00:00",
        "deployment_surface": "none",
        "runtime_event": "12345678-1234-1234-1234-123456789012",
    }


def test_one_path_dimension_cannot_be_double_counted_across_families() -> None:
    result = calculate_family_coverage(
        (
            _assertion(
                path_id="same-path",
                family="browser",
                dimension="discovery",
                state="covered",
            ),
            _assertion(
                path_id="same-path",
                family="runtime",
                dimension="discovery",
                state="covered",
            ),
        ),
        calculated_at=CALCULATED_AT,
        input_watermarks={},
    )
    browser = next(item for item in result.families if item.family == "browser")
    runtime = next(item for item in result.families if item.family == "runtime")
    unknown = next(item for item in result.families if item.family == "unknown")

    assert browser.dimensions[0].total_known_eligible_count == 0
    assert runtime.dimensions[0].total_known_eligible_count == 0
    assert unknown.dimensions[0].unknown_count == 1
    assert unknown.dimensions[0].confidence == "unknown"


def test_stale_conflicting_or_missing_refs_downgrade_applicable_assertions() -> None:
    result = calculate_family_coverage(
        (
            _assertion(
                path_id="stale-not-covered",
                dimension="discovery",
                state="not_covered",
                stale=True,
            ),
            _assertion(
                path_id="conflicting-covered",
                dimension="identity",
                state="covered",
                conflicting=True,
            ),
            _assertion(
                path_id="missing-ref-covered",
                dimension="authorization",
                state="covered",
                evidence_refs=(),
            ),
            _assertion(
                path_id="missing-ref-not-covered",
                dimension="evidence",
                state="not_covered",
                evidence_refs=(),
            ),
        ),
        calculated_at=CALCULATED_AT,
        input_watermarks={},
    )
    runtime = next(item for item in result.families if item.family == "runtime")
    by_name = {item.name: item for item in runtime.dimensions}

    for dimension in ("discovery", "identity", "authorization", "evidence"):
        assert by_name[dimension].covered_count == 0
        assert by_name[dimension].not_covered_count == 0
        assert by_name[dimension].unknown_count == 1
        assert by_name[dimension].confidence == "unknown"


def test_containment_requires_current_operational_verified_path_linkage() -> None:
    assert evaluate_containment(
        ContainmentEvidence(
            capability="direct",
            health_status="healthy",
            verified_block_inline_prevented=True,
            evidence_refs=("decision_receipt:receipt-1",),
        )
    ).state == "covered"
    assert evaluate_containment(
        ContainmentEvidence(
            capability="surface_limited",
            health_status="warning",
            verified_block_inline_prevented=True,
            evidence_refs=("decision_receipt:receipt-2",),
        )
    ).state == "covered"

    assert evaluate_containment(
        ContainmentEvidence(
            capability="direct",
            health_status="healthy",
            verified_block_inline_prevented=False,
        )
    ).state == "unknown"
    assert evaluate_containment(
        ContainmentEvidence(
            capability="direct",
            health_status="healthy",
            verified_block_inline_prevented=True,
        )
    ).state == "unknown"


def test_hostile_truthy_and_noncanonical_typed_values_never_grant_coverage() -> None:
    class StrSubclass(str):
        pass

    for evidence in (
        ContainmentEvidence(
            capability="direct",
            health_status="healthy",
            verified_block_inline_prevented="true",  # type: ignore[arg-type]
        ),
        ContainmentEvidence(
            capability=" direct ",
            health_status="healthy",
            verified_block_inline_prevented=True,
        ),
        ContainmentEvidence(
            capability="DIRECT",
            health_status="healthy",
            verified_block_inline_prevented=True,
        ),
        ContainmentEvidence(
            capability=StrSubclass("direct"),
            health_status="healthy",
            verified_block_inline_prevented=True,
        ),
        ContainmentEvidence(
            capability="direct",
            health_status=StrSubclass("healthy"),
            verified_block_inline_prevented=True,
        ),
    ):
        assert evaluate_containment(evidence).state == "unknown"

    result = calculate_family_coverage(
        (
            _assertion(
                path_id="padded-state",
                dimension="discovery",
                state=" covered ",
            ),
            _assertion(
                path_id="mixed-dimension",
                dimension="Discovery",
                state="covered",
            ),
            _assertion(
                path_id="subclass-quality",
                dimension="identity",
                state="covered",
                quality=StrSubclass("verified"),
            ),
            _assertion(
                path_id="subclass-family",
                dimension="evidence",
                state="covered",
                family=StrSubclass("runtime"),
                evidence_refs=(StrSubclass("evidence:node-1"),),
            ),
        ),
        calculated_at=CALCULATED_AT,
        input_watermarks={},
    )
    runtime = next(item for item in result.families if item.family == "runtime")
    unknown = next(item for item in result.families if item.family == "unknown")

    assert runtime.dimensions[0].unknown_count == 1
    assert runtime.dimensions[0].confidence == "unknown"
    assert runtime.dimensions[1].confidence == "unknown"
    assert unknown.dimensions[3].covered_count == 0
    assert unknown.dimensions[3].unknown_count == 1
    assert unknown.dimensions[3].evidence_refs == ()
    assert evaluate_containment(
        ContainmentEvidence(
            capability="external",
            health_status="healthy",
            verified_block_inline_prevented=True,
        )
    ).state == "unknown"
    assert evaluate_containment(
        ContainmentEvidence(
            capability="none",
            health_status="healthy",
            authorization_monitor_only_proven=True,
            evidence_refs=("runtime_event:event-1",),
        )
    ).state == "not_covered"
    assert evaluate_containment(
        ContainmentEvidence(
            capability="direct",
            health_status="degraded",
            verified_block_inline_prevented=True,
            deployment_offline_proven=True,
            evidence_refs=("runtime_event:event-1",),
        )
    ).state == "not_covered"
    assert evaluate_containment(
        ContainmentEvidence(
            capability="direct",
            health_status="stale",
            verified_block_inline_prevented=True,
        )
    ).state == "unknown"
    assert evaluate_containment(
        ContainmentEvidence(
            capability="direct",
            health_status="offline",
            verified_block_inline_prevented=True,
            deployment_offline_proven=True,
            evidence_refs=("runtime_event:event-1",),
        )
    ).state == "not_covered"
    assert evaluate_containment(
        ContainmentEvidence(
            capability="none",
            health_status="healthy",
            authorization_monitor_only_proven=True,
        )
    ).state == "unknown"
    assert evaluate_containment(
        ContainmentEvidence(
            capability="direct",
            health_status="healthy",
            verified_block_inline_prevented=True,
            conflicting=True,
        )
    ).state == "unknown"
