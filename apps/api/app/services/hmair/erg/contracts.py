from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import Field, field_validator, model_validator

from app.services.hmair.contracts import StrictContract


class EvidenceDecayPolicy(StrictContract):
    policy_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=32)
    signal_class: str = Field(min_length=1, max_length=64)
    fresh_days: int = Field(ge=0, le=3650)
    stale_days: int = Field(ge=0, le=3650)
    fresh_factor: float = Field(ge=0.0, le=1.0)
    stale_factor: float = Field(ge=0.0, le=1.0)
    expired_factor: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_windows_and_factors(self) -> "EvidenceDecayPolicy":
        if self.stale_days < self.fresh_days:
            raise ValueError("stale window cannot precede fresh window")
        if not self.fresh_factor >= self.stale_factor >= self.expired_factor:
            raise ValueError("decay factors must be monotonically non-increasing")
        return self


class EdgeConfidenceInput(StrictContract):
    edge_id: str = Field(min_length=1, max_length=128)
    signal_class: str = Field(min_length=1, max_length=64)
    source_surface: str = Field(min_length=1, max_length=64)
    collector_id: str = Field(min_length=1, max_length=128)
    base_confidence: float = Field(ge=0.0, le=1.0)
    relationship_weight: float = Field(gt=0.0, le=10.0)
    observation_quality: float | None = Field(default=None, ge=0.0, le=1.0)
    collector_quality: float | None = Field(default=None, ge=0.0, le=1.0)
    observed_at: datetime
    last_validated_at: datetime
    validation_state: str = Field(
        pattern=r"^(verified|partially_verified|inferred|contradicted|stale|unknown)$"
    )
    contradiction_state: str = Field(
        pattern=r"^(none|possible|confirmed|resolved|unknown|unresolved)$"
    )
    declared_freshness: str = Field(pattern=r"^(fresh|stale|expired|unknown)$")
    relationship_rule_id: str = Field(min_length=1, max_length=128)
    relationship_rule_version: str = Field(min_length=1, max_length=32)

    @field_validator("observed_at", "last_validated_at")
    @classmethod
    def timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("edge timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def time_order(self) -> "EdgeConfidenceInput":
        if self.observed_at > self.last_validated_at:
            raise ValueError("edge validation cannot precede observation")
        return self


class EdgeConfidenceEvaluation(StrictContract):
    edge_id: str
    signal_class: str
    source_surface: str
    collector_id: str
    base_confidence: float
    observation_quality_factor: float | None
    collector_quality_factor: float | None
    decay_factor: float | None
    decay_policy_id: str | None
    decay_policy_version: str | None
    relationship_weight: float
    effective_confidence: float | None
    edge_quality: float | None
    freshness: str
    validation_state: str
    contradiction_state: str
    automatic_resolution_eligible: bool
    evaluated_at: datetime
    limitations: tuple[str, ...] = Field(max_length=64)

    @field_validator("evaluated_at")
    @classmethod
    def evaluation_time_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evaluation time must be timezone-aware")
        return value.astimezone(timezone.utc)


class EvidenceQualityAggregate(StrictContract):
    evidence_quality: float | None = Field(default=None, ge=0.0, le=1.0)
    total_weight: float = Field(ge=0.0)
    contributor_edge_ids: tuple[str, ...] = Field(max_length=2048)
    unknown_edge_ids: tuple[str, ...] = Field(max_length=2048)
    methodology_id: str = Field(min_length=1, max_length=128)
    methodology_version: str = Field(min_length=1, max_length=32)


class ResolutionConfidenceEvaluation(StrictContract):
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence_quality: float | None = Field(default=None, ge=0.0, le=1.0)
    weighted_supporting_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    source_diversity: int = Field(ge=0, le=64)
    source_diversity_cap: float = Field(ge=0.0, le=1.0)
    anchor_confidence_floor: float | None = Field(default=None, ge=0.0, le=1.0)
    freshness_validation_cap: float | None = Field(default=None, ge=0.0, le=1.0)
    contradiction_cap: float | None = Field(default=None, ge=0.0, le=1.0)
    rule_cap: float = Field(gt=0.0, le=1.0)
    create_threshold: float = Field(ge=0.0, le=1.0)
    attach_threshold: float = Field(ge=0.0, le=1.0)
    create_eligible: bool
    attach_eligible: bool
    recommended_action: str = Field(
        pattern=r"^(create_ecosystem|attach_observation|manual_review|unknown)$"
    )
    supporting_edge_ids: tuple[str, ...] = Field(max_length=2048)
    source_surfaces: tuple[str, ...] = Field(max_length=64)
    limitations: tuple[str, ...] = Field(max_length=128)
    calculation: dict[str, Any]


class ERGGraphProjection(StrictContract):
    node_ids: tuple[str, ...] = Field(max_length=10000)
    current_edge_ids: tuple[str, ...] = Field(max_length=20000)
    historical_edge_ids: tuple[str, ...] = Field(max_length=20000)
    generated_at: datetime

    @field_validator("generated_at")
    @classmethod
    def generated_time_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("graph projection timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)


class EvidenceTimelineItem(StrictContract):
    event_id: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=64)
    drift_category: str = Field(min_length=1, max_length=64)
    source_type: str = Field(min_length=1, max_length=64)
    source_reference: str = Field(min_length=1, max_length=255)
    occurred_at: datetime
    changed_resolution: bool
    ecosystem_ids: tuple[str, ...] = Field(max_length=128)
    evidence_references: tuple[str, ...] = Field(max_length=2048)
    summary: str = Field(min_length=1, max_length=1000)
    before: dict[str, Any]
    after: dict[str, Any]

    @field_validator("occurred_at")
    @classmethod
    def timeline_time_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


__all__ = [
    "EdgeConfidenceEvaluation",
    "EdgeConfidenceInput",
    "EvidenceDecayPolicy",
    "EvidenceQualityAggregate",
    "ResolutionConfidenceEvaluation",
    "ERGGraphProjection",
    "EvidenceTimelineItem",
]
