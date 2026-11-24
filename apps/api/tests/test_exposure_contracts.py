from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.services.hmair.exposure.contracts import (
    CalculationStatus,
    ExposureCoverageDimension,
    ExposureCoverageProjection,
    ExposureDimension,
    ExposureExtent,
    ExposureFactor,
    ExposureProjection,
    FreshnessState,
    VerificationStatus,
)


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
HEX_DIGEST = "a" * 64


def test_exposure_extent_is_not_risk_severity() -> None:
    values = {item.value for item in ExposureExtent}
    assert values == {"none", "limited", "material", "broad", "unknown"}
    assert not ({"critical", "high", "medium", "low"} & values)


def test_factor_is_strict_immutable_bounded_and_normalizes_utc() -> None:
    factor = ExposureFactor(
        dimension=ExposureDimension.CAPABILITY,
        source_type="discovery_capability",
        source_id="capability-1",
        state="filesystem_write",
        evidence_refs=("evidence-1",),
        confidence=0.91,
        verification_status=VerificationStatus.VERIFIED,
        freshness=FreshnessState.FRESH,
        observed_at=NOW,
        validated_at=NOW,
        methodology_id="cie/1.0",
        collector_group="endpoint",
    )
    assert factor.observed_at == NOW
    with pytest.raises(ValidationError):
        ExposureFactor(
            **factor.model_dump(),
            unexpected="forbidden",
        )
    with pytest.raises(ValidationError):
        ExposureFactor(
            **{
                **factor.model_dump(),
                "observed_at": datetime(2026, 8, 20, 12, 0),
            }
        )
    with pytest.raises(ValidationError):
        ExposureFactor(
            **{
                **factor.model_dump(),
                "evidence_refs": tuple(f"evidence-{index}" for index in range(65)),
            }
        )
    with pytest.raises(ValidationError):
        factor.state = "changed"  # type: ignore[misc]


def test_coverage_keeps_each_question_and_unknown_state_distinct() -> None:
    unknown = ExposureCoverageDimension(
        state="unknown",
        freshness=FreshnessState.UNKNOWN,
        blind_spots=("no_exact_containment_proof",),
    )
    coverage = ExposureCoverageProjection(
        discover=unknown,
        authorize=unknown,
        prove=unknown,
        contain=unknown,
    )
    assert coverage.contain.state.value == "unknown"
    assert coverage.authorize.state.value != "covered"


def test_projection_requires_aware_time_digest_and_no_aggregate_score() -> None:
    projection = ExposureProjection(
        asset_id="asset-1",
        as_of=NOW,
        calculation_status=CalculationStatus.COMPLETE,
        reasoning_methodology_id="ai-exposure-reasoning/1.0",
        reasoning_rule_version="1.0.0",
        category_catalog_version="1.0.0",
        source_input_digest=HEX_DIGEST,
        exposures=(),
        extent_distribution={extent: 0 for extent in ExposureExtent},
    )
    payload = projection.model_dump(mode="json")
    assert "score" not in payload
    assert "risk_severity" not in payload
    with pytest.raises(ValidationError):
        ExposureProjection(
            **{
                **projection.model_dump(),
                "as_of": datetime(2026, 8, 20, 12, 0),
            }
        )
    with pytest.raises(ValidationError):
        ExposureProjection(
            **{
                **projection.model_dump(),
                "source_input_digest": "not-a-digest",
            }
        )

