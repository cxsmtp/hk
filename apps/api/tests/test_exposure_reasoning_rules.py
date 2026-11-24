from __future__ import annotations

from datetime import datetime, timezone
import inspect

import pytest

from app.services.hmair.exposure.category_catalog import load_category_catalog
from app.services.hmair.exposure.contracts import (
    ExposureDimension,
    ExposureExtent,
    ExposureFactor,
    FreshnessState,
    VerificationStatus,
)
from app.services.hmair.exposure.reasoning_rules import evaluate_category


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
RANK = {
    ExposureExtent.NONE: 0,
    ExposureExtent.LIMITED: 1,
    ExposureExtent.MATERIAL: 2,
    ExposureExtent.BROAD: 3,
    ExposureExtent.UNKNOWN: -1,
}


def _definition(category_id: str = "coding_exposure"):
    return next(
        item for item in load_category_catalog().categories
        if item.category_id == category_id
    )


def _factor(
    dimension: ExposureDimension,
    state: str,
    *,
    source_id: str | None = None,
    confidence: float | None = 0.9,
    verification: VerificationStatus = VerificationStatus.VERIFIED,
    freshness: FreshnessState = FreshnessState.FRESH,
    collector: str | None = None,
    path_id: str | None = "path-a",
) -> ExposureFactor:
    return ExposureFactor(
        dimension=dimension,
        source_type=f"test_{dimension.value}",
        source_id=source_id or f"{dimension.value}-{state}",
        state=state,
        evidence_refs=(f"evidence-{source_id or dimension.value}",),
        related_source_refs=(f"control_coverage_path:{path_id}",) if path_id else (),
        confidence=confidence,
        verification_status=verification,
        freshness=freshness,
        observed_at=NOW,
        validated_at=NOW,
        methodology_id="exposure-test/1.0",
        collector_group=collector or dimension.value,
    )


def _base(*, permission: str = "write", reachability: str = "filesystem:verified"):
    return (
        _factor(ExposureDimension.CAPABILITY, "filesystem_write", confidence=0.94),
        _factor(ExposureDimension.REACHABILITY, reachability, confidence=0.92),
        _factor(ExposureDimension.PERMISSION, permission, confidence=0.88),
        _factor(ExposureDimension.IDENTITY, "workload_identity:active", confidence=0.9),
        _factor(ExposureDimension.GOVERNANCE, "unapproved", confidence=0.86),
        _factor(
            ExposureDimension.CONTROL_COVERAGE,
            "authorization:not_covered",
            confidence=0.91,
        ),
    )


def _evaluate(factors: tuple[ExposureFactor, ...]):
    return evaluate_category(
        definition=_definition(),
        factors=factors,
        methodology_version="1.0.0",
    )


def test_verified_capability_reach_and_usable_authority_are_material() -> None:
    result = _evaluate(_base())
    assert result.extent is ExposureExtent.MATERIAL
    assert result.proven_lower_bound is ExposureExtent.MATERIAL
    assert result.confidence == 0.86


def test_verified_exact_runtime_path_is_not_poisoned_by_asset_runtime_fallback() -> None:
    factors = (
        _factor(ExposureDimension.CAPABILITY, "process_execution"),
        _factor(ExposureDimension.RUNTIME, "runtime_observed", source_id="verified-runtime"),
        _factor(
            ExposureDimension.RUNTIME,
            "runtime_observed",
            source_id="asset-runtime-fallback",
            verification=VerificationStatus.PARTIALLY_VERIFIED,
        ).model_copy(update={"source_type": "discovery_asset"}),
        _factor(ExposureDimension.REACHABILITY, "filesystem:verified"),
        _factor(ExposureDimension.PERMISSION, "write"),
        _factor(ExposureDimension.IDENTITY, "workload_identity:active"),
        _factor(ExposureDimension.GOVERNANCE, "approved").model_copy(
            update={"source_type": "discovery_asset"}
        ),
        _factor(ExposureDimension.CONTROL_COVERAGE, "authorization:covered"),
    )

    result = evaluate_category(
        definition=_definition("runtime_exposure"),
        factors=factors,
        methodology_version="1.0.0",
    )

    assert result.extent is ExposureExtent.MATERIAL
    assert all(
        item.source_id != "asset-runtime-fallback" for item in result.contributors
    )
    assert any(
        item.dimension is ExposureDimension.GOVERNANCE
        and item.source_type == "discovery_asset"
        for item in result.contributors
    )


def test_verified_exact_provider_path_is_not_poisoned_by_asset_provider_fallback() -> None:
    factors = (
        _factor(ExposureDimension.CAPABILITY, "provider_api_access"),
        _factor(ExposureDimension.PROVIDER, "provider_observed", source_id="verified-provider"),
        _factor(
            ExposureDimension.PROVIDER,
            "provider_observed",
            source_id="asset-provider-fallback",
            verification=VerificationStatus.PARTIALLY_VERIFIED,
        ).model_copy(update={"source_type": "discovery_asset"}),
        _factor(ExposureDimension.REACHABILITY, "internet:verified"),
        _factor(ExposureDimension.IDENTITY, "workload_identity:active"),
        _factor(ExposureDimension.GOVERNANCE, "approved").model_copy(
            update={"source_type": "discovery_asset"}
        ),
        _factor(ExposureDimension.CONTROL_COVERAGE, "authorization:covered"),
    )

    result = evaluate_category(
        definition=_definition("external_ai_exposure"),
        factors=factors,
        methodology_version="1.0.0",
    )

    assert result.extent is ExposureExtent.MATERIAL
    assert all(
        item.source_id != "asset-provider-fallback" for item in result.contributors
    )


def test_verified_constraints_are_limited() -> None:
    result = _evaluate(_base(permission="scoped_read", reachability="internal:verified"))
    assert result.extent is ExposureExtent.LIMITED


def test_same_path_conflicting_control_coverage_is_unknown() -> None:
    factors = tuple(
        item.model_copy(
            update={
                "state": "authorization:covered",
                "source_type": "control_coverage_assertion",
            }
        )
        if item.dimension is ExposureDimension.CONTROL_COVERAGE
        else item
        for item in _base()
    ) + (
        _factor(
            ExposureDimension.CONTROL_COVERAGE,
            "authorization:not_covered",
            source_id="authorization-conflict",
        ).model_copy(update={"source_type": "control_coverage_assertion"}),
    )

    result = _evaluate(factors)

    assert result.extent is ExposureExtent.UNKNOWN
    assert result.verification_status is VerificationStatus.CONTRADICTED
    assert {
        item.state for item in result.contradictions
        if item.dimension is ExposureDimension.CONTROL_COVERAGE
    } == {"authorization:covered", "authorization:not_covered"}


def test_same_path_conflicting_governance_is_unknown() -> None:
    factors = tuple(
        item.model_copy(update={"state": "approved", "source_type": "discovery_asset"})
        if item.dimension is ExposureDimension.GOVERNANCE
        else item
        for item in _base()
    ) + (
        _factor(
            ExposureDimension.GOVERNANCE,
            "unmanaged:confirmed_shadow",
            source_id="shadow-governance-conflict",
        ),
    )

    result = _evaluate(factors)

    assert result.extent is ExposureExtent.UNKNOWN
    assert result.verification_status is VerificationStatus.CONTRADICTED
    assert {
        item.state for item in result.contradictions
        if item.dimension is ExposureDimension.GOVERNANCE
    } == {"approved", "unmanaged:confirmed_shadow"}


def test_verified_broad_reach_authority_and_usage_are_broad() -> None:
    factors = _base(permission="admin") + (
        _factor(ExposureDimension.REACHABILITY, "internet:verified", source_id="internet"),
        _factor(ExposureDimension.IDENTITY, "service_principal:active", source_id="identity-2"),
        _factor(ExposureDimension.USAGE, "high_usage", source_id="usage-high"),
    )
    result = _evaluate(factors)
    assert result.extent is ExposureExtent.BROAD


def test_duplicate_broad_facts_on_one_path_do_not_prove_broad_scale() -> None:
    factors = _base(permission="admin", reachability="internet:verified") + (
        _factor(
            ExposureDimension.REACHABILITY,
            "internet:verified",
            source_id="duplicate-reach",
            path_id="path-a",
        ),
        _factor(
            ExposureDimension.IDENTITY,
            "service_principal:active",
            source_id="duplicate-identity",
            path_id="path-a",
        ),
    )
    assert _evaluate(factors).extent is ExposureExtent.MATERIAL


def test_two_distinct_broad_paths_prove_broad_scale() -> None:
    first = _base(permission="admin", reachability="internet:verified")
    second = tuple(
        item.model_copy(
            update={
                "source_id": f"{item.source_id}-b",
                "related_source_refs": ("control_coverage_path:path-b",),
            }
        )
        for item in _base(permission="admin", reachability="internet:verified")
    )
    assert _evaluate(first + second).extent is ExposureExtent.BROAD


def test_two_broad_context_paths_with_removed_identities_remain_limited() -> None:
    first = tuple(
        item.model_copy(update={"state": "removed"})
        if item.dimension is ExposureDimension.IDENTITY
        else item
        for item in _base(permission="admin", reachability="internet:verified")
    )
    second = tuple(
        item.model_copy(
            update={
                "source_id": f"{item.source_id}-b",
                "state": (
                    "removed"
                    if item.dimension is ExposureDimension.IDENTITY
                    else item.state
                ),
                "related_source_refs": ("control_coverage_path:path-b",),
            }
        )
        for item in _base(permission="admin", reachability="internet:verified")
    )

    assert _evaluate(first + second).extent is ExposureExtent.LIMITED


def test_none_requires_verified_non_reachability() -> None:
    factors = tuple(
        _factor(item.dimension, "filesystem:not_reachable")
        if item.dimension is ExposureDimension.REACHABILITY else item
        for item in _base()
    )
    result = _evaluate(factors)
    assert result.extent is ExposureExtent.NONE
    inferred = tuple(
        item.model_copy(update={"verification_status": VerificationStatus.INFERRED})
        if item.dimension is ExposureDimension.REACHABILITY else item
        for item in factors
    )
    assert _evaluate(inferred).extent is ExposureExtent.UNKNOWN


def test_verified_non_reachability_with_missing_required_evidence_is_unknown() -> None:
    factors = tuple(
        _factor(item.dimension, "filesystem:not_reachable")
        if item.dimension is ExposureDimension.REACHABILITY else item
        for item in _base()
        if item.dimension not in {ExposureDimension.PERMISSION, ExposureDimension.IDENTITY}
    )
    result = _evaluate(factors)
    assert result.extent is ExposureExtent.UNKNOWN
    assert result.proven_lower_bound is None
    assert set(result.unknown_dimensions) >= {
        ExposureDimension.PERMISSION,
        ExposureDimension.IDENTITY,
    }


def test_verified_non_reachability_with_unverified_required_evidence_is_unknown() -> None:
    factors = tuple(
        item.model_copy(update={"verification_status": VerificationStatus.INFERRED})
        if item.dimension is ExposureDimension.IDENTITY
        else _factor(item.dimension, "filesystem:not_reachable")
        if item.dimension is ExposureDimension.REACHABILITY
        else item
        for item in _base()
    )
    result = _evaluate(factors)
    assert result.extent is ExposureExtent.UNKNOWN
    assert result.proven_lower_bound is None
    assert "required_evidence_not_fully_verified" in result.limitations


def test_verified_identity_removal_constrains_even_broad_admin_context() -> None:
    factors = tuple(
        item.model_copy(update={"state": "removed"})
        if item.dimension is ExposureDimension.IDENTITY
        else item.model_copy(update={"state": "internet:verified"})
        if item.dimension is ExposureDimension.REACHABILITY
        else item.model_copy(update={"state": "admin"})
        if item.dimension is ExposureDimension.PERMISSION
        else item
        for item in _base()
    ) + (
        _factor(ExposureDimension.USAGE, "high_usage", source_id="usage-high"),
    )

    result = _evaluate(factors)

    assert result.extent is ExposureExtent.LIMITED
    assert result.proven_lower_bound is ExposureExtent.LIMITED
    assert "verified_identity_removed" in result.reasoning_trace


@pytest.mark.parametrize(
    "verification",
    (VerificationStatus.INFERRED, VerificationStatus.PARTIALLY_VERIFIED),
)
def test_unverified_high_usage_cannot_promote_broad(
    verification: VerificationStatus,
) -> None:
    factors = tuple(
        item.model_copy(update={"state": "internet:verified"})
        if item.dimension is ExposureDimension.REACHABILITY
        else item.model_copy(update={"state": "admin"})
        if item.dimension is ExposureDimension.PERMISSION
        else item
        for item in _base()
    ) + (
        _factor(
            ExposureDimension.USAGE,
            "high_usage",
            source_id=f"usage-{verification.value}",
            verification=verification,
        ),
    )

    assert _evaluate(factors).extent is ExposureExtent.MATERIAL


def test_missing_required_fact_is_unknown_not_zero() -> None:
    factors = tuple(
        item for item in _base() if item.dimension is not ExposureDimension.PERMISSION
    )
    result = _evaluate(factors)
    assert result.extent is ExposureExtent.UNKNOWN
    assert ExposureDimension.PERMISSION in result.unknown_dimensions
    assert result.confidence is None
    assert result.verification_status is VerificationStatus.UNKNOWN


def test_unlinked_factors_cannot_produce_an_exact_exposure_extent() -> None:
    result = _evaluate(
        tuple(item.model_copy(update={"related_source_refs": ()}) for item in _base())
    )
    assert result.extent is ExposureExtent.UNKNOWN
    assert result.proven_lower_bound is None
    assert "exact_exposure_path_unavailable" in result.limitations


def test_factors_from_different_paths_are_never_borrowed() -> None:
    factors = (
        _factor(
            ExposureDimension.CAPABILITY,
            "filesystem_write",
            source_id="capability-a",
            path_id="path-a",
        ),
        _factor(
            ExposureDimension.REACHABILITY,
            "internet:verified",
            source_id="reach-b",
            path_id="path-b",
        ),
        _factor(
            ExposureDimension.PERMISSION,
            "admin",
            source_id="permission-b",
            path_id="path-b",
        ),
        _factor(
            ExposureDimension.IDENTITY,
            "service_principal:active",
            source_id="identity-b",
            path_id="path-b",
        ),
        _factor(
            ExposureDimension.GOVERNANCE,
            "unapproved",
            source_id="governance-b",
            path_id="path-b",
        ),
        _factor(
            ExposureDimension.CONTROL_COVERAGE,
            "authorization:not_covered",
            source_id="coverage-b",
            path_id="path-b",
        ),
    )
    result = _evaluate(factors)
    assert result.extent is ExposureExtent.UNKNOWN
    assert set(result.unknown_dimensions) >= {
        ExposureDimension.REACHABILITY,
        ExposureDimension.PERMISSION,
        ExposureDimension.IDENTITY,
    }
    assert "reach-b" not in {item.source_id for item in result.contributors}


def test_failed_required_authority_withholds_exact_extent_even_with_other_evidence() -> None:
    failed = ExposureFactor(
        dimension=ExposureDimension.REACHABILITY,
        source_type="failed_authority",
        source_id="failed:discovery_reachability:reachability",
        state="unknown",
        verification_status=VerificationStatus.UNKNOWN,
        freshness=FreshnessState.UNKNOWN,
        methodology_id="ai-exposure-authority-failure/1.0",
        limitations=("source_authority_failed:discovery_reachability",),
    )
    result = _evaluate(_base() + (failed,))
    assert result.extent is ExposureExtent.UNKNOWN
    assert ExposureDimension.REACHABILITY in result.unknown_dimensions


def test_composite_unknown_state_never_counts_as_current_evidence() -> None:
    factors = tuple(
        item.model_copy(update={"state": "filesystem:unknown"})
        if item.dimension is ExposureDimension.REACHABILITY
        else item
        for item in _base()
    )
    result = _evaluate(factors)
    assert result.extent is ExposureExtent.UNKNOWN
    assert ExposureDimension.REACHABILITY in result.unknown_dimensions


def test_added_permission_identity_reach_or_usage_never_reduces_extent() -> None:
    baseline = _evaluate(_base(permission="scoped_read", reachability="internal:verified"))
    additions = (
        _factor(ExposureDimension.PERMISSION, "admin", source_id="permission-admin"),
        _factor(ExposureDimension.IDENTITY, "service_principal:active", source_id="identity-extra"),
        _factor(ExposureDimension.REACHABILITY, "internet:verified", source_id="reach-extra"),
        _factor(ExposureDimension.USAGE, "high_usage", source_id="usage-extra"),
    )
    current = _base(permission="scoped_read", reachability="internal:verified")
    previous = baseline
    for addition in additions:
        current += (addition,)
        result = _evaluate(current)
        assert RANK[result.extent] >= RANK[previous.extent]
        previous = result


def test_governance_improvement_does_not_erase_capability() -> None:
    before = _evaluate(_base())
    after_factors = tuple(
        item.model_copy(update={"state": "governed_inline"})
        if item.dimension is ExposureDimension.GOVERNANCE else item
        for item in _base()
    )
    after = _evaluate(after_factors)
    assert after.extent is before.extent


def test_verified_required_contradiction_returns_unknown() -> None:
    factors = _base() + (
        _factor(
            ExposureDimension.PERMISSION,
            "contradicted",
            source_id="permission-conflict",
            verification=VerificationStatus.CONTRADICTED,
        ),
    )
    result = _evaluate(factors)
    assert result.extent is ExposureExtent.UNKNOWN
    assert result.contradictions


def test_confidence_is_minimum_and_missing_confidence_stays_unknown() -> None:
    result = _evaluate(_base())
    assert result.confidence == min(item.confidence for item in _base() if item.confidence is not None)
    missing = tuple(
        item.model_copy(update={"confidence": None})
        if item.dimension is ExposureDimension.IDENTITY else item
        for item in _base()
    )
    assert _evaluate(missing).confidence is None


def test_risk_score_is_not_a_reasoning_input() -> None:
    signature = inspect.signature(evaluate_category)
    assert "risk_score" not in signature.parameters
    before_fixture = {"factors": _base(), "risk_score": 0.0}
    after_fixture = {"factors": _base(), "risk_score": 1.0}
    assert _evaluate(before_fixture["factors"]) == _evaluate(after_fixture["factors"])


def test_large_bounded_factor_population_returns_truncated_result_not_validation_error() -> None:
    optional = tuple(
        _factor(
            ExposureDimension.RUNTIME,
            "runtime_observed",
            source_id=f"runtime-{index:03d}",
            collector=f"runtime-collector-{index:03d}",
        )
        for index in range(251)
    )

    result = _evaluate(_base() + optional)

    assert result.extent is ExposureExtent.MATERIAL
    assert len(result.contributors) == 256
    assert result.collector_diversity == 64
    assert "category_contributors_truncated" in result.limitations
    assert "category_evidence_refs_truncated" in result.limitations
    assert "collector_diversity_capped" in result.limitations
    assert {
        ExposureDimension.CAPABILITY,
        ExposureDimension.REACHABILITY,
        ExposureDimension.PERMISSION,
        ExposureDimension.IDENTITY,
        ExposureDimension.GOVERNANCE,
        ExposureDimension.CONTROL_COVERAGE,
    }.issubset({item.dimension for item in result.contributors})
