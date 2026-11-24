from __future__ import annotations

import pytest

from app.core.control_coverage import (
    DEFAULT_CONTROL_COVERAGE_WINDOW_DAYS,
    METHODOLOGY_VERSION,
    AssertionCounts,
    CoverageDimension,
    CoverageState,
    calculate_score,
)


def test_contract_has_seven_unweighted_dimensions() -> None:
    assert [item.value for item in CoverageDimension] == [
        "discovery",
        "identity",
        "authorization",
        "evidence",
        "deployment",
        "runtime",
        "bypass",
    ]
    assert METHODOLOGY_VERSION == "control-coverage/1.0"
    assert DEFAULT_CONTROL_COVERAGE_WINDOW_DAYS == 30


def test_unknown_remains_in_denominator() -> None:
    counts = AssertionCounts(covered=2, not_covered=1, unknown=1, not_applicable=99)
    assert counts.denominator == 4
    assert calculate_score(counts) == 50.0


def test_empty_applicable_population_is_unknown() -> None:
    assert calculate_score(AssertionCounts(not_applicable=7)) is None


def test_counts_reject_negative_values() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        AssertionCounts(covered=-1)


def test_only_not_applicable_is_excluded() -> None:
    assert CoverageState.NOT_APPLICABLE.value == "not_applicable"
    counts = AssertionCounts(covered=1, not_covered=1, unknown=2, not_applicable=5)
    assert counts.denominator == 4


def test_score_rounds_to_two_decimal_places() -> None:
    assert calculate_score(AssertionCounts(covered=1, not_covered=2)) == 33.33
