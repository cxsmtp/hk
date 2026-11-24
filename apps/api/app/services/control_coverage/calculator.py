"""Pure aggregation for path-native Control Coverage assertions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from app.core.control_coverage import AssertionCounts, CoverageDimension, CoverageState, calculate_score


@dataclass(frozen=True)
class AssertionView:
    assertion_id: str
    path_id: str
    asset_ref: str
    identity_ref: str
    runtime_ref: str
    deployment_surface_ref: str
    dimension: str
    state: str


@dataclass(frozen=True)
class CoverageSummary:
    headline_counts: AssertionCounts
    headline_score: float | None
    dimensions: dict[str, dict[str, object]]


def _counts(rows: Iterable[AssertionView]) -> AssertionCounts:
    values = [row.state for row in rows]
    allowed = {item.value for item in CoverageState}
    invalid = sorted(set(values) - allowed)
    if invalid:
        raise ValueError(f"unknown coverage states: {', '.join(invalid)}")
    return AssertionCounts(
        covered=values.count(CoverageState.COVERED.value),
        not_covered=values.count(CoverageState.NOT_COVERED.value),
        unknown=values.count(CoverageState.UNKNOWN.value),
        not_applicable=values.count(CoverageState.NOT_APPLICABLE.value),
    )


def summarize_assertions(
    assertions: Iterable[AssertionView],
    *,
    dimensions: Sequence[str] | None = None,
    **filters: str,
) -> CoverageSummary:
    selected = [row for row in assertions if all(getattr(row, key) == value for key, value in filters.items())]
    valid_dimensions = set(dimensions or [item.value for item in CoverageDimension])
    invalid_dimensions = sorted({row.dimension for row in selected} - valid_dimensions)
    if invalid_dimensions:
        raise ValueError(f"unknown coverage dimensions: {', '.join(invalid_dimensions)}")

    dimension_rows: dict[str, list[AssertionView]] = {item: [] for item in valid_dimensions}
    for row in selected:
        dimension_rows[row.dimension].append(row)

    per_dimension: dict[str, dict[str, object]] = {}
    for dimension, rows in dimension_rows.items():
        dimension_counts = _counts(rows)
        per_dimension[dimension] = {
            "counts": dimension_counts.as_dict(),
            "score": calculate_score(dimension_counts),
        }
    headline = _counts(selected)
    return CoverageSummary(headline, calculate_score(headline), per_dimension)
