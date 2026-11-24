from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum

from pydantic import Field, field_validator, model_validator

from app.services.hmair.contracts import StrictContract


class DiscoveryStage(StrEnum):
    OBSERVED = "observed"
    CANDIDATE = "candidate"
    HYPOTHESIS = "hypothesis"
    VERIFICATION = "verification"
    VERIFIED = "verified"
    CONTINUOUSLY_VALIDATED = "continuously_validated"


class VerificationOutcome(StrEnum):
    VERIFIED = "verified"
    FAILED = "failed"
    CONTRADICTED = "contradicted"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("verification timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


class VerificationTaskResult(StrictContract):
    requirement_id: str = Field(min_length=1, max_length=128)
    task_id: str = Field(min_length=36, max_length=36)
    outcome: VerificationOutcome
    evidence_node_ids: tuple[str, ...] = Field(default=(), max_length=32)
    observed_at: datetime
    validated_at: datetime
    limitations: tuple[str, ...] = Field(default=(), max_length=32)

    @field_validator("observed_at", "validated_at")
    @classmethod
    def timestamps_are_aware(cls, value: datetime) -> datetime:
        return _aware_utc(value)

    @model_validator(mode="after")
    def validation_follows_observation(self) -> "VerificationTaskResult":
        if self.validated_at < self.observed_at:
            raise ValueError("verification validation cannot precede observation")
        return self


class ADVStateProjection(StrictContract):
    stage: DiscoveryStage | None
    limitations: tuple[str, ...] = Field(default=(), max_length=64)
    evaluated_at: datetime

    @field_validator("evaluated_at")
    @classmethod
    def evaluation_is_aware(cls, value: datetime) -> datetime:
        return _aware_utc(value)


__all__ = [
    "ADVStateProjection",
    "DiscoveryStage",
    "VerificationOutcome",
    "VerificationTaskResult",
]
