from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import Field, field_validator

from app.services.hmair.contracts import StrictContract


_SHA256_PATTERN = r"^[0-9a-f]{64}$"


class CIESignalType(StrEnum):
    EXECUTABLE = "executable"
    PACKAGE = "package"
    DEPENDENCY = "dependency"
    RUNTIME = "runtime"
    CONFIGURATION = "configuration"
    REPOSITORY = "repository"
    SDK = "sdk"
    API = "api"
    PROVIDER = "provider"
    NETWORK = "network"
    DNS = "dns"
    IDENTITY = "identity"
    PROCESS = "process"
    FILESYSTEM = "filesystem"
    MARKETPLACE = "marketplace"
    EXTENSION = "extension"
    MODEL = "model"
    MCP = "mcp"
    TOOL = "tool"
    DATABASE = "database"
    VECTOR_STORE = "vector_store"
    PROMPT_STORE = "prompt_store"
    MEMORY = "memory"
    USAGE = "usage"


class CapabilityFamily(StrEnum):
    CODING = "coding"
    RESEARCH = "research"
    CUSTOMER_SUPPORT = "customer_support"
    OFFICE_PRODUCTIVITY = "office_productivity"
    CONTENT = "content"
    ANALYTICS = "analytics"
    DEVOPS = "devops"
    INFRASTRUCTURE = "infrastructure"
    DATA_SCIENCE = "data_science"
    RAG = "rag"
    MEMORY = "memory"
    WORKFLOW_AUTOMATION = "workflow_automation"
    MODEL_HOSTING = "model_hosting"
    SECURITY = "security"
    CLOUD_ADMINISTRATION = "cloud_administration"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class NormalizedCapabilitySignal(StrictContract):
    signal_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=36)
    observation_id: str = Field(min_length=1, max_length=128)
    collector_id: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=64)
    signal_type: CIESignalType
    timestamp: datetime
    confidence: float = Field(ge=0.0, le=1.0)
    attributes: dict[str, Any] = Field(max_length=128)
    facts: tuple[str, ...] = Field(max_length=128)
    relationship_hints: tuple[dict[str, Any], ...] = Field(max_length=128)
    evidence_reference: str = Field(min_length=1, max_length=255)
    evidence_hash: str = Field(pattern=_SHA256_PATTERN)
    freshness: str = Field(pattern=r"^(fresh|stale|expired|unknown)$")
    verification_state: str = Field(
        pattern=r"^(verified|partially_verified|inferred|contradicted|stale|unknown)$"
    )
    source_trust: str = Field(pattern=r"^(strong|medium|weak|unknown)$")
    contradiction_state: str = Field(
        pattern=r"^(none|supported|contradicted|unresolved|unknown)$"
    )
    product_hint: str | None = Field(default=None, max_length=128)

    @field_validator("timestamp")
    @classmethod
    def timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("signal timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)

    @field_validator("facts")
    @classmethod
    def canonical_facts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(value)))
        if any(not item or item != item.strip() or len(item) > 128 for item in normalized):
            raise ValueError("signal facts must be bounded canonical strings")
        return normalized


class CapabilityDefinition(StrictContract):
    capability_id: str = Field(min_length=1, max_length=64)
    family: CapabilityFamily
    description: str = Field(min_length=1, max_length=500)
    risk: str = Field(pattern=r"^(low|medium|high|critical)$")
    rule_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    version: str = Field(min_length=1, max_length=32)


class CapabilityRule(StrictContract):
    rule_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=32)
    capability_id: str = Field(min_length=1, max_length=64)
    required_all: tuple[str, ...] = Field(max_length=32)
    required_any: tuple[tuple[str, ...], ...] = Field(max_length=16)
    optional: tuple[str, ...] = Field(max_length=32)
    contradictions: tuple[str, ...] = Field(max_length=32)
    base_confidence_cap: float = Field(gt=0.0, lt=1.0)
    recommended_asset_type: str = Field(min_length=1, max_length=64)
    recommended_ecosystem: str = Field(min_length=1, max_length=128)
    explanation: str = Field(min_length=1, max_length=1000)
    calibration_version: str = Field(min_length=1, max_length=64)


class CapabilityEvaluation(StrictContract):
    capability_id: str = Field(min_length=1, max_length=64)
    family: CapabilityFamily
    rule_id: str = Field(min_length=1, max_length=128)
    rule_version: str = Field(min_length=1, max_length=32)
    calibration_version: str = Field(min_length=1, max_length=64)
    confidence: float = Field(ge=0.0, le=1.0)
    supporting_signal_ids: tuple[str, ...] = Field(max_length=256)
    conflicting_signal_ids: tuple[str, ...] = Field(max_length=256)
    unknown_predicates: tuple[str, ...] = Field(max_length=128)
    source_diversity: int = Field(ge=0, le=64)
    freshness: str = Field(pattern=r"^(fresh|stale|expired|unknown)$")
    verification_state: str = Field(
        pattern=r"^(verified|partially_verified|inferred|contradicted|unknown)$"
    )
    last_validated_at: datetime
    explanation: str = Field(min_length=1, max_length=1000)
    limitations: tuple[str, ...] = Field(max_length=128)
    recommended_asset_type: str = Field(min_length=1, max_length=64)
    recommended_ecosystem: str = Field(min_length=1, max_length=128)

    @field_validator("last_validated_at")
    @classmethod
    def validation_time_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("validation time must be timezone-aware")
        return value.astimezone(timezone.utc)


class CapabilityInferenceOptions(StrictContract):
    genome: bool = False
    marketplace: bool = False
    dependency_graph: bool = False
    drift: bool = False


class CapabilityInferenceResult(StrictContract):
    subject_reference_hash: str = Field(pattern=_SHA256_PATTERN)
    observation_ids: tuple[str, ...] = Field(min_length=1, max_length=1000)
    evaluations: tuple[CapabilityEvaluation, ...] = Field(max_length=256)
    product_explanations: tuple[str, ...] = Field(max_length=64)
    recommended_asset_type: str = Field(min_length=1, max_length=64)
    recommended_ecosystem: str = Field(min_length=1, max_length=128)
    engine_version: str = Field(min_length=1, max_length=64)
    catalog_version: str = Field(min_length=1, max_length=64)
    ruleset_version: str = Field(min_length=1, max_length=64)
    first_observed_at: datetime
    last_observed_at: datetime
    validated_at: datetime
    limitations: tuple[str, ...] = Field(max_length=128)

    @field_validator("first_observed_at", "last_observed_at", "validated_at")
    @classmethod
    def result_time_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("inference timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)


class CapabilityGraphProjection(StrictContract):
    node_ids: tuple[str, ...] = ()
    edge_ids: tuple[str, ...] = ()
    dependency_refs: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    @classmethod
    def empty(cls) -> "CapabilityGraphProjection":
        return cls()


class CapabilityGenomeContext(StrictContract):
    dependencies: tuple[str, ...] = Field(max_length=256)
    permissions: tuple[str, ...] = Field(max_length=256)
    reachability: tuple[str, ...] = Field(max_length=256)
    usage: tuple[str, ...] = Field(max_length=256)
    models: tuple[str, ...] = Field(max_length=256)
    providers: tuple[str, ...] = Field(max_length=256)
    runtime: tuple[str, ...] = Field(max_length=256)
    data: tuple[str, ...] = Field(max_length=256)
    marketplace: tuple[str, ...] = Field(max_length=256)
    identity: tuple[str, ...] = Field(max_length=256)

    @field_validator(
        "dependencies", "permissions", "reachability", "usage", "models",
        "providers", "runtime", "data", "marketplace", "identity",
    )
    @classmethod
    def canonical_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(value)))
        if any(not item or item != item.strip() or len(item) > 255 for item in normalized):
            raise ValueError("genome context values must be bounded canonical strings")
        return normalized


class CapabilityGenomeSnapshot(StrictContract):
    genome_id: str = Field(min_length=1, max_length=36)
    subject_reference_hash: str = Field(pattern=_SHA256_PATTERN)
    genome_version: int = Field(ge=1)
    supersedes_genome_id: str | None = Field(default=None, max_length=36)
    genome_digest: str = Field(pattern=_SHA256_PATTERN)
    capabilities: tuple[dict[str, Any], ...] = Field(max_length=256)
    context: CapabilityGenomeContext
    first_observed_at: datetime
    last_observed_at: datetime

    @field_validator("first_observed_at", "last_observed_at")
    @classmethod
    def genome_time_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("genome timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)


class CapabilityDriftEvent(StrictContract):
    event_id: str = Field(min_length=1, max_length=36)
    subject_reference_hash: str = Field(pattern=_SHA256_PATTERN)
    genome_id: str = Field(min_length=1, max_length=36)
    previous_genome_id: str | None = Field(default=None, max_length=36)
    event_type: str = Field(
        pattern=r"^(capability_added|capability_removed|confidence_changed|dependency_added|dependency_removed|marketplace_changed|provider_changed|model_changed|runtime_changed|data_changed|identity_changed|permission_changed|usage_changed|repository_changed|configuration_changed|genome_changed)$"
    )
    entity_reference: str = Field(min_length=1, max_length=255)
    before: dict[str, Any]
    after: dict[str, Any]
    evidence_references: tuple[str, ...] = Field(max_length=256)
    occurred_at: datetime
    input_digest: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("occurred_at")
    @classmethod
    def event_time_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)


class CapabilityPipelineResult(StrictContract):
    inference: CapabilityInferenceResult
    inference_run_id: str = Field(min_length=1, max_length=36)
    evidence_node_id: str = Field(min_length=1, max_length=36)
    capability_evidence_ids: tuple[str, ...] = Field(max_length=256)
    graph: CapabilityGraphProjection
    genome_id: str | None = Field(default=None, max_length=36)
    event_ids: tuple[str, ...] = Field(max_length=512)


__all__ = [
    "CIESignalType",
    "CapabilityDefinition",
    "CapabilityEvaluation",
    "CapabilityFamily",
    "CapabilityGraphProjection",
    "CapabilityGenomeContext",
    "CapabilityGenomeSnapshot",
    "CapabilityDriftEvent",
    "CapabilityPipelineResult",
    "CapabilityInferenceOptions",
    "CapabilityInferenceResult",
    "CapabilityRule",
    "NormalizedCapabilitySignal",
]
