from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum

from pydantic import Field, field_validator, model_validator

from app.core.control_coverage import CoverageState
from app.services.hmair.contracts import StrictContract


_SHA256_PATTERN = r"^[0-9a-f]{64}$"


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("exposure timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _bounded_unique(values: tuple[str, ...], *, field_name: str) -> tuple[str, ...]:
    normalized = tuple(item.strip() for item in values)
    if any(not item or len(item) > 255 for item in normalized):
        raise ValueError(f"{field_name} must contain bounded non-empty references")
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field_name} must not contain duplicates")
    return normalized


class ExposureExtent(StrEnum):
    NONE = "none"
    LIMITED = "limited"
    MATERIAL = "material"
    BROAD = "broad"
    UNKNOWN = "unknown"


class ExposureDimension(StrEnum):
    CAPABILITY = "capability"
    DATA = "data"
    RUNTIME = "runtime"
    PROVIDER = "provider"
    MODEL = "model"
    IDENTITY = "identity"
    PERMISSION = "permission"
    REACHABILITY = "reachability"
    USAGE = "usage"
    GOVERNANCE = "governance"
    CONTROL_COVERAGE = "control_coverage"
    AI_ACTION = "ai_action"


class VerificationStatus(StrEnum):
    VERIFIED = "verified"
    PARTIALLY_VERIFIED = "partially_verified"
    INFERRED = "inferred"
    CONTRADICTED = "contradicted"
    STALE = "stale"
    UNKNOWN = "unknown"


class FreshnessState(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class CalculationStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


class ExposureGraphNodeType(StrEnum):
    AI_ASSET = "ai_asset"
    CAPABILITY = "capability"
    IDENTITY = "identity"
    PERMISSION = "permission"
    USAGE = "usage"
    REACHABILITY = "reachability"
    RUNTIME = "runtime"
    PROVIDER = "provider"
    MODEL = "model"
    DATA = "data"
    CONTROL_COVERAGE = "control_coverage"
    POLICY = "policy"
    AI_ACTION = "ai_action"


class ExposureGraphEdgeType(StrEnum):
    CAN_ACCESS = "can_access"
    USES = "uses"
    INVOKES = "invokes"
    OWNS = "owns"
    OBSERVED = "observed"
    GOVERNED = "governed"
    AUTHORIZED = "authorized"
    BLOCKED = "blocked"
    UNGOVERNED = "ungoverned"


class ExposureTimelineEventType(StrEnum):
    EXPOSURE_INCREASED = "exposure_increased"
    EXPOSURE_REDUCED = "exposure_reduced"
    EXPOSURE_VERIFIED = "exposure_verified"
    EXPOSURE_CHANGED = "exposure_changed"
    EXPOSURE_COVERAGE_IMPROVED = "exposure_coverage_improved"
    EXPOSURE_COVERAGE_REDUCED = "exposure_coverage_reduced"
    RECOMMENDATION_GENERATED = "recommendation_generated"


class ExposureFactor(StrictContract):
    dimension: ExposureDimension
    source_type: str = Field(min_length=1, max_length=64)
    source_id: str = Field(min_length=1, max_length=255)
    state: str = Field(min_length=1, max_length=64)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=64)
    related_source_refs: tuple[str, ...] = Field(default=(), max_length=64)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    verification_status: VerificationStatus
    freshness: FreshnessState
    observed_at: datetime | None = None
    validated_at: datetime | None = None
    methodology_id: str = Field(min_length=1, max_length=128)
    collector_group: str | None = Field(default=None, max_length=128)
    limitations: tuple[str, ...] = Field(default=(), max_length=32)

    @field_validator("observed_at", "validated_at")
    @classmethod
    def timestamps_are_aware(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _aware_utc(value)

    @field_validator("evidence_refs", "related_source_refs", "limitations")
    @classmethod
    def collections_are_bounded(cls, value: tuple[str, ...], info) -> tuple[str, ...]:  # type: ignore[no-untyped-def]
        return _bounded_unique(value, field_name=info.field_name)

    @model_validator(mode="after")
    def validation_does_not_precede_observation(self) -> "ExposureFactor":
        if self.observed_at and self.validated_at and self.validated_at < self.observed_at:
            raise ValueError("exposure validation cannot precede observation")
        return self


class ExposureCoverageDimension(StrictContract):
    state: CoverageState
    path_ids: tuple[str, ...] = Field(default=(), max_length=64)
    assertion_ids: tuple[str, ...] = Field(default=(), max_length=128)
    control_mode: str | None = Field(default=None, max_length=32)
    external_control_dependency: str | None = Field(default=None, max_length=128)
    blind_spots: tuple[str, ...] = Field(default=(), max_length=32)
    freshness: FreshnessState

    @field_validator("path_ids", "assertion_ids", "blind_spots")
    @classmethod
    def collections_are_bounded(cls, value: tuple[str, ...], info) -> tuple[str, ...]:  # type: ignore[no-untyped-def]
        return _bounded_unique(value, field_name=info.field_name)


class ExposureCoverageProjection(StrictContract):
    discover: ExposureCoverageDimension
    authorize: ExposureCoverageDimension
    prove: ExposureCoverageDimension
    contain: ExposureCoverageDimension


class ExposureRecommendation(StrictContract):
    recommendation_id: str = Field(pattern=_SHA256_PATTERN)
    capability: str = Field(min_length=1, max_length=64)
    governance_action: str = Field(min_length=1, max_length=255)
    affected_category_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=500)
    target_control_path: str = Field(min_length=1, max_length=255)
    prerequisites: tuple[str, ...] = Field(default=(), max_length=32)
    expected_effect: str = Field(min_length=1, max_length=255)
    product_route: str = Field(min_length=1, max_length=255)
    source_refs: tuple[str, ...] = Field(default=(), max_length=64)

    @field_validator("prerequisites", "source_refs")
    @classmethod
    def collections_are_bounded(cls, value: tuple[str, ...], info) -> tuple[str, ...]:  # type: ignore[no-untyped-def]
        return _bounded_unique(value, field_name=info.field_name)


class ExposureConclusion(StrictContract):
    category_id: str = Field(min_length=1, max_length=64)
    category_version: str = Field(min_length=1, max_length=32)
    label: str = Field(min_length=1, max_length=128)
    extent: ExposureExtent
    proven_lower_bound: ExposureExtent | None = None
    capability_refs: tuple[str, ...] = Field(default=(), max_length=64)
    data_refs: tuple[str, ...] = Field(default=(), max_length=64)
    runtime_refs: tuple[str, ...] = Field(default=(), max_length=64)
    provider_refs: tuple[str, ...] = Field(default=(), max_length=64)
    model_refs: tuple[str, ...] = Field(default=(), max_length=64)
    identity_refs: tuple[str, ...] = Field(default=(), max_length=64)
    permission_refs: tuple[str, ...] = Field(default=(), max_length=64)
    reachability_refs: tuple[str, ...] = Field(default=(), max_length=64)
    usage_refs: tuple[str, ...] = Field(default=(), max_length=64)
    governance_state: str = Field(min_length=1, max_length=64)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence_count: int = Field(ge=0, le=10000)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=256)
    evidence_quality: float | None = Field(default=None, ge=0.0, le=1.0)
    verification_status: VerificationStatus
    collector_diversity: int = Field(ge=0, le=64)
    last_validation: datetime | None = None
    contributors: tuple[ExposureFactor, ...] = Field(default=(), max_length=256)
    contradictions: tuple[ExposureFactor, ...] = Field(default=(), max_length=128)
    unknown_dimensions: tuple[ExposureDimension, ...] = Field(default=(), max_length=16)
    reasoning_trace: tuple[str, ...] = Field(default=(), max_length=64)
    coverage: ExposureCoverageProjection
    recommendations: tuple[ExposureRecommendation, ...] = Field(default=(), max_length=32)
    limitations: tuple[str, ...] = Field(default=(), max_length=64)

    @field_validator("last_validation")
    @classmethod
    def last_validation_is_aware(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _aware_utc(value)

    @field_validator(
        "capability_refs",
        "data_refs",
        "runtime_refs",
        "provider_refs",
        "model_refs",
        "identity_refs",
        "permission_refs",
        "reachability_refs",
        "usage_refs",
        "evidence_refs",
        "reasoning_trace",
        "limitations",
    )
    @classmethod
    def collections_are_bounded(cls, value: tuple[str, ...], info) -> tuple[str, ...]:  # type: ignore[no-untyped-def]
        return _bounded_unique(value, field_name=info.field_name)


class ExposureGraphNode(StrictContract):
    node_id: str = Field(min_length=1, max_length=255)
    node_type: ExposureGraphNodeType
    source_type: str = Field(min_length=1, max_length=64)
    source_id: str = Field(min_length=1, max_length=255)
    label: str = Field(min_length=1, max_length=255)
    verification_status: VerificationStatus
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=64)
    limitations: tuple[str, ...] = Field(default=(), max_length=32)


class ExposureGraphEdge(StrictContract):
    edge_id: str = Field(pattern=_SHA256_PATTERN)
    edge_type: ExposureGraphEdgeType
    source_node_id: str = Field(min_length=1, max_length=255)
    target_node_id: str = Field(min_length=1, max_length=255)
    source_refs: tuple[str, ...] = Field(min_length=1, max_length=64)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=64)
    verification_status: VerificationStatus
    limitations: tuple[str, ...] = Field(default=(), max_length=32)


class ExposureGraph(StrictContract):
    nodes: tuple[ExposureGraphNode, ...] = Field(max_length=200)
    edges: tuple[ExposureGraphEdge, ...] = Field(max_length=400)
    truncated: bool = False


class ExposureTimelineEntry(StrictContract):
    event_id: str = Field(pattern=_SHA256_PATTERN)
    event_type: ExposureTimelineEventType
    category_id: str = Field(min_length=1, max_length=64)
    occurred_at: datetime
    before_extent: ExposureExtent | None = None
    after_extent: ExposureExtent | None = None
    changed_factors: tuple[str, ...] = Field(default=(), max_length=64)
    source_event_refs: tuple[str, ...] = Field(min_length=1, max_length=64)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=64)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    limitations: tuple[str, ...] = Field(default=(), max_length=32)

    @field_validator("occurred_at")
    @classmethod
    def event_time_is_aware(cls, value: datetime) -> datetime:
        return _aware_utc(value)


class ExposureProjection(StrictContract):
    asset_id: str = Field(min_length=1, max_length=36)
    as_of: datetime
    calculation_status: CalculationStatus
    reasoning_methodology_id: str = Field(min_length=1, max_length=128)
    reasoning_rule_version: str = Field(min_length=1, max_length=32)
    category_catalog_version: str = Field(min_length=1, max_length=32)
    source_input_digest: str = Field(pattern=_SHA256_PATTERN)
    exposures: tuple[ExposureConclusion, ...] = Field(default=(), max_length=64)
    extent_distribution: dict[ExposureExtent, int]
    unknown_dimensions: tuple[ExposureDimension, ...] = Field(default=(), max_length=16)
    failed_authorities: tuple[str, ...] = Field(default=(), max_length=32)
    conflicts: tuple[str, ...] = Field(default=(), max_length=64)
    limitations: tuple[str, ...] = Field(default=(), max_length=64)
    truncated: bool = False

    @field_validator("as_of")
    @classmethod
    def projection_time_is_aware(cls, value: datetime) -> datetime:
        return _aware_utc(value)

    @field_validator("failed_authorities", "conflicts", "limitations")
    @classmethod
    def collections_are_bounded(cls, value: tuple[str, ...], info) -> tuple[str, ...]:  # type: ignore[no-untyped-def]
        return _bounded_unique(value, field_name=info.field_name)

    @model_validator(mode="after")
    def distribution_is_exact(self) -> "ExposureProjection":
        if set(self.extent_distribution) != set(ExposureExtent):
            raise ValueError("extent distribution must contain every exposure extent")
        if any(count < 0 for count in self.extent_distribution.values()):
            raise ValueError("extent distribution counts cannot be negative")
        if sum(self.extent_distribution.values()) != len(self.exposures):
            raise ValueError("extent distribution must match exposure conclusions")
        return self


__all__ = [
    "CalculationStatus",
    "CoverageState",
    "ExposureConclusion",
    "ExposureCoverageDimension",
    "ExposureCoverageProjection",
    "ExposureDimension",
    "ExposureExtent",
    "ExposureFactor",
    "ExposureGraph",
    "ExposureGraphEdge",
    "ExposureGraphEdgeType",
    "ExposureGraphNode",
    "ExposureGraphNodeType",
    "ExposureProjection",
    "ExposureRecommendation",
    "ExposureTimelineEntry",
    "ExposureTimelineEventType",
    "FreshnessState",
    "VerificationStatus",
]
