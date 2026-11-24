"""Strict public contracts for HMAIR H5 governance projections.

The persisted H1-H4 records remain authoritative.  These contracts provide the
exact H5 vocabulary without rewriting older stored state names or creating a
second policy, finding, evidence, or graph authority.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import MappingProxyType
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from app.services.hmair.contracts import SourceSurface, StrictContract


H5_USAGE_STATES = (
    "no_usage_observed",
    "historical_usage",
    "active_usage",
    "high_frequency_usage",
    "service_usage",
    "unknown_usage",
)
H5_SHADOW_STATES = (
    "approved",
    "approved_but_uncontrolled",
    "known_unapproved",
    "suspected_shadow",
    "confirmed_shadow",
    "personal_account",
    "owner_unknown",
    "unknown",
)
H5_REACHABILITY_STATES = (
    "configured",
    "observed",
    "inferred",
    "simulated",
    "blocked",
    "unknown",
)
H5_REACHABILITY_TARGET_TYPES = (
    "model",
    "mcp_server",
    "tool",
    "saas",
    "api",
    "database",
    "vector_database",
    "source_repository",
    "secret_reference",
    "cloud_identity",
    "external_network",
    "customer_data_system",
    "persistent_side_effect",
)
H5_CONTROL_COVERAGE_DIMENSIONS = (
    "discovery",
    "identity",
    "usage",
    "authorization",
    "evidence",
    "containment",
    "bypass_detection",
)
H5_CHANGE_EVENT_TYPES = (
    "AI_ASSET_DISCOVERED",
    "AI_ASSET_CHANGED",
    "AI_ASSET_BECAME_ACTIVE",
    "AI_ASSET_OWNER_CHANGED",
    "AI_CAPABILITY_ADDED",
    "AI_USAGE_INCREASED",
    "AI_IDENTITY_CHANGED",
    "AI_REACHABILITY_CHANGED",
    "AI_FINGERPRINT_DRIFT",
    "SHADOW_AI_CONFIRMED",
    "CONTROL_COVERAGE_REDUCED",
)

H5UsageState = Literal[
    "no_usage_observed",
    "historical_usage",
    "active_usage",
    "high_frequency_usage",
    "service_usage",
    "unknown_usage",
]
H5ShadowState = Literal[
    "approved",
    "approved_but_uncontrolled",
    "known_unapproved",
    "suspected_shadow",
    "confirmed_shadow",
    "personal_account",
    "owner_unknown",
    "unknown",
]
H5ReachabilityState = Literal[
    "configured", "observed", "inferred", "simulated", "blocked", "unknown"
]
H5CoverageState = Literal["covered", "not_covered", "unknown"]
H5ControlCapability = Literal[
    "inline", "warn_only", "monitor_only", "external_required", "unknown"
]
H5ReachabilityTargetType = Literal[
    "model",
    "mcp_server",
    "tool",
    "saas",
    "api",
    "database",
    "vector_database",
    "source_repository",
    "secret_reference",
    "cloud_identity",
    "external_network",
    "customer_data_system",
    "persistent_side_effect",
]


class H5FindingDefinition(StrictContract):
    finding_type: str = Field(min_length=1, max_length=64)
    default_severity: Literal["low", "medium", "high", "critical"]
    remediation: str = Field(min_length=1, max_length=1000)
    verification_action: str = Field(min_length=1, max_length=1000)
    coverage_impact: str = Field(min_length=1, max_length=1000)


def _finding(
    finding_type: str,
    severity: Literal["low", "medium", "high", "critical"],
    remediation: str,
    verification_action: str,
    coverage_impact: str,
) -> H5FindingDefinition:
    return H5FindingDefinition(
        finding_type=finding_type,
        default_severity=severity,
        remediation=remediation,
        verification_action=verification_action,
        coverage_impact=coverage_impact,
    )


_FINDINGS = (
    _finding("SHADOW_AI_CONFIRMED", "high", "Route the evidenced asset to governance review and an approved control path.", "Revalidate ownership, approval, usage, and path-control evidence.", "Discovery, authorization, containment, and bypass-detection coverage may be reduced."),
    _finding("SUSPECTED_SHADOW_AI", "medium", "Collect an independent source and resolve governance status before enforcement.", "Corroborate usage and approval evidence from an independent source.", "Discovery and authorization coverage remain uncertain."),
    _finding("AI_ASSET_OWNER_UNKNOWN", "medium", "Assign and verify an accountable business or technical owner.", "Resolve ownership against an authoritative directory or repository source.", "Identity and authorization coverage remain incomplete."),
    _finding("AI_USAGE_IDENTITY_UNKNOWN", "high", "Bind observed use to a human, service, workload, application, or agent identity.", "Correlate current usage with an authoritative identity source.", "Identity and usage coverage are reduced."),
    _finding("UNAPPROVED_AI_SAAS", "high", "Review the SaaS asset and either approve a bounded route or restrict its use.", "Verify tenant, account, owner, approval, and current activity.", "Authorization and containment coverage may be absent."),
    _finding("PERSONAL_AI_ACCOUNT", "high", "Move business activity to an approved enterprise account or restrict the personal account.", "Verify account class, represented user, device, and current usage.", "Identity, authorization, and containment coverage may be reduced."),
    _finding("UNAPPROVED_DEVELOPER_AI", "high", "Approve a repository-scoped developer workflow or restrict the unapproved tool.", "Verify tool, repository ownership, actor, and active use.", "Authorization, containment, and bypass coverage may be reduced."),
    _finding("UNKNOWN_MCP_SERVER", "high", "Quarantine or review the MCP server before consequential tool use.", "Verify server identity, fingerprint, schema, publisher, and destinations.", "Discovery, authorization, containment, and bypass coverage are uncertain."),
    _finding("UNKNOWN_AI_RUNTIME", "high", "Identify and govern the runtime before allowing consequential actions.", "Verify runtime identity, owner, model, tools, and action path.", "Discovery, identity, and containment coverage are uncertain."),
    _finding("UNPROTECTED_LLM_ROUTE", "high", "Route model traffic through a current supported control point.", "Validate the exact model route and pre-execution control capability.", "Authorization and containment coverage are not established."),
    _finding("UNPROTECTED_MCP_ROUTE", "high", "Route MCP traffic through a current governed gateway or supported native control.", "Validate the exact server, tool, actor, and control route.", "Authorization, containment, and bypass coverage are not established."),
    _finding("AI_ENABLED_DATABASE_UNGOVERNED", "critical", "Restrict the AI-enabled database path until purpose, identity, and query controls are verified.", "Verify database metadata, identity, permission, and control path without reading raw records.", "Authorization, evidence, and containment coverage are reduced."),
    _finding("AI_ASSET_USAGE_WITHOUT_AUTHORIZATION", "critical", "Require an approved authority and control path for the observed usage.", "Correlate current usage with approval, policy, identity, and decision evidence.", "Authorization coverage is not established."),
    _finding("AI_FINGERPRINT_DRIFT", "high", "Revalidate the changed asset before trusting prior approvals or controls.", "Compare the current versioned fingerprint with its accepted predecessor.", "Discovery, evidence, and containment coverage may be stale."),
    _finding("HIGH_RISK_AI_CAPABILITY_DISCOVERED", "high", "Review and constrain the high-risk capability before consequential use.", "Verify capability evidence, authority, target, destination, and side effects.", "Authorization and containment requirements increase."),
    _finding("DISCOVERY_SOURCE_STALE", "medium", "Restore or revalidate the stale discovery source.", "Obtain a fresh signed source health and completion record.", "Affected coverage dimensions remain unknown or stale."),
    _finding("AI_ESTATE_BLIND_SPOT", "high", "Connect or authorize an appropriate source and establish its denominator.", "Verify supported scope, permissions, health, freshness, and completion.", "Discovery coverage is unknown for the affected scope."),
)
H5_FINDING_CATALOG = MappingProxyType(
    {item.finding_type: item for item in _FINDINGS}
)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("H5 timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _canonical_refs(value: tuple[str, ...]) -> tuple[str, ...]:
    if not value or len(value) > 128:
        raise ValueError("H5 evidence references must be present and bounded")
    canonical = tuple(sorted(set(value)))
    if any(not item or item != item.strip() or len(item) > 255 for item in canonical):
        raise ValueError("H5 evidence references are invalid")
    return canonical


class H5UsageProjection(StrictContract):
    tenant_id: str = Field(min_length=1, max_length=36)
    asset_id: str = Field(min_length=1, max_length=36)
    state: H5UsageState
    actor_class: Literal["human", "service_agent", "unknown"]
    actor_type: Literal["human", "agent", "service", "workload", "automation", "unknown"]
    actor_reference_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    business_unit_reference_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    geography: str = Field(min_length=1, max_length=64)
    environment: str = Field(min_length=1, max_length=64)
    account_class: Literal["enterprise", "personal", "external", "anonymous", "unknown"]
    governance_class: Literal["sanctioned", "shadow", "unknown"]
    event_count: int = Field(ge=0)
    first_observed_at: datetime | None = None
    last_observed_at: datetime | None = None
    window_start: datetime
    window_end: datetime
    telemetry_complete: bool
    evidence_refs: tuple[str, ...]
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str = Field(min_length=1, max_length=1000)
    limitations: tuple[str, ...] = Field(default=(), max_length=32)

    _evidence = field_validator("evidence_refs")(_canonical_refs)
    _first = field_validator("first_observed_at")(
        lambda value: None if value is None else _utc(value)
    )
    _last = field_validator("last_observed_at")(
        lambda value: None if value is None else _utc(value)
    )
    _start = field_validator("window_start")(_utc)
    _end = field_validator("window_end")(_utc)

    @model_validator(mode="after")
    def valid_usage_shape(self) -> Self:
        if self.window_start > self.window_end:
            raise ValueError("H5 usage window is out of order")
        if (self.first_observed_at is None) != (self.last_observed_at is None):
            raise ValueError("H5 usage activity timestamps must be supplied together")
        if self.first_observed_at and self.first_observed_at > self.last_observed_at:
            raise ValueError("H5 usage activity timestamps are out of order")
        if self.event_count == 0 and self.first_observed_at is not None:
            raise ValueError("H5 zero usage cannot carry activity timestamps")
        if self.event_count > 0 and self.first_observed_at is None:
            raise ValueError("H5 observed usage requires activity timestamps")
        if self.actor_type == "unknown" and self.actor_reference_hash is not None:
            raise ValueError("H5 unknown actor cannot carry an identity")
        if self.actor_type != "unknown" and self.actor_reference_hash is None:
            raise ValueError("H5 known actor requires a pseudonymous identity")
        return self


class H5ShadowClassification(StrictContract):
    tenant_id: str = Field(min_length=1, max_length=36)
    asset_id: str = Field(min_length=1, max_length=36)
    state: H5ShadowState
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_refs: tuple[str, ...]
    independent_sources: tuple[str, ...] = Field(default=(), max_length=32)
    explanation: str = Field(min_length=1, max_length=1000)
    change_condition: str = Field(min_length=1, max_length=1000)
    limitations: tuple[str, ...] = Field(default=(), max_length=32)

    _evidence = field_validator("evidence_refs")(_canonical_refs)


class H5AssetUsageView(StrictContract):
    asset_id: str = Field(min_length=1, max_length=36)
    actor_reference_hashes: tuple[str, ...] = Field(max_length=500)
    event_count: int = Field(ge=0)


class H5ActorUsageView(StrictContract):
    actor_reference_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    asset_ids: tuple[str, ...] = Field(max_length=500)
    event_count: int = Field(ge=0)


class H5UsageAggregate(StrictContract):
    dimension: Literal[
        "business_unit",
        "geography",
        "environment",
        "time_window",
        "account_class",
        "governance_class",
        "actor_class",
    ]
    key: str = Field(min_length=1, max_length=128)
    asset_count: int = Field(ge=0)
    actor_count: int = Field(ge=0)
    event_count: int = Field(ge=0)


class H5UsageViews(StrictContract):
    tenant_id: str = Field(min_length=1, max_length=36)
    assets_by_actor: tuple[H5ActorUsageView, ...] = Field(max_length=500)
    actors_by_asset: tuple[H5AssetUsageView, ...] = Field(max_length=500)
    aggregates: tuple[H5UsageAggregate, ...] = Field(max_length=500)
    limitations: tuple[str, ...] = Field(default=(), max_length=32)


class H5ReachabilityProjection(StrictContract):
    tenant_id: str = Field(min_length=1, max_length=36)
    asset_id: str = Field(min_length=1, max_length=36)
    target_type: H5ReachabilityTargetType
    target_reference_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: H5ReachabilityState
    source_surface: SourceSurface
    observed_usage: bool
    control_capability: H5ControlCapability
    first_seen_at: datetime
    last_seen_at: datetime
    evidence_refs: tuple[str, ...]
    confidence: float = Field(ge=0.0, le=1.0)
    limitations: tuple[str, ...] = Field(default=(), max_length=32)

    _first = field_validator("first_seen_at")(_utc)
    _last = field_validator("last_seen_at")(_utc)
    _evidence = field_validator("evidence_refs")(_canonical_refs)

    @model_validator(mode="after")
    def truthful_reachability(self) -> Self:
        if self.first_seen_at > self.last_seen_at:
            raise ValueError("H5 reachability timestamps are out of order")
        if self.observed_usage and self.state not in {"observed", "blocked"}:
            raise ValueError("observed reachability cannot be represented as configured, inferred, simulated, or unknown")
        return self


class AcceptedGovernanceClaim(StrictContract):
    tenant_id: str = Field(min_length=1, max_length=36)
    claim_id: str = Field(min_length=1, max_length=128)
    subject_asset_id: str = Field(min_length=1, max_length=36)
    target_type: str = Field(min_length=1, max_length=64)
    target_reference_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    relationship_type: str = Field(min_length=1, max_length=64)
    admission_state: Literal["accepted", "rejected", "contradicted", "unknown"]
    evidence_state: Literal["confirmed", "observed", "correlated", "inferred", "unknown"]
    freshness: Literal["fresh", "stale", "expired", "unknown"]
    source_surface: SourceSurface
    evidence_refs: tuple[str, ...]
    confidence: float = Field(ge=0.0, le=1.0)
    first_seen_at: datetime
    last_seen_at: datetime

    _first = field_validator("first_seen_at")(_utc)
    _last = field_validator("last_seen_at")(_utc)
    _evidence = field_validator("evidence_refs")(_canonical_refs)

    @model_validator(mode="after")
    def valid_claim_time(self) -> Self:
        if self.first_seen_at > self.last_seen_at:
            raise ValueError("H5 claim timestamps are out of order")
        return self


class H5GraphRelationship(StrictContract):
    tenant_id: str = Field(min_length=1, max_length=36)
    from_type: Literal["ai_asset"] = "ai_asset"
    from_ref: str = Field(min_length=1, max_length=36)
    relationship_type: str = Field(min_length=1, max_length=64)
    to_type: str = Field(min_length=1, max_length=64)
    to_ref: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_state: Literal["confirmed", "observed", "correlated", "inferred"]
    source_surface: SourceSurface
    evidence_refs: tuple[str, ...]
    confidence: float = Field(ge=0.0, le=1.0)
    first_seen_at: datetime
    last_seen_at: datetime
    authorization_effect: Literal["none"] = "none"

    _first = field_validator("first_seen_at")(_utc)
    _last = field_validator("last_seen_at")(_utc)
    _evidence = field_validator("evidence_refs")(_canonical_refs)


class GovernanceAssetSnapshot(StrictContract):
    tenant_id: str = Field(min_length=1, max_length=36)
    asset_id: str = Field(min_length=1, max_length=36)
    active: bool
    owner_reference_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    identity_reference_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    capability_ids: tuple[str, ...] = Field(default=(), max_length=128)
    usage_count: int = Field(ge=0)
    reachability_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    fingerprint_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    shadow_state: H5ShadowState
    coverage_states: tuple[tuple[str, H5CoverageState], ...]
    evidence_refs: tuple[str, ...]
    observed_at: datetime

    _observed = field_validator("observed_at")(_utc)
    _evidence = field_validator("evidence_refs")(_canonical_refs)

    @field_validator("capability_ids")
    @classmethod
    def canonical_capabilities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        canonical = tuple(sorted(set(value)))
        if any(not item or item != item.strip() or len(item) > 64 for item in canonical):
            raise ValueError("H5 capability IDs are invalid")
        return canonical

    @field_validator("coverage_states")
    @classmethod
    def exact_coverage_dimensions(
        cls, value: tuple[tuple[str, H5CoverageState], ...]
    ) -> tuple[tuple[str, H5CoverageState], ...]:
        if tuple(name for name, _ in value) != H5_CONTROL_COVERAGE_DIMENSIONS:
            raise ValueError("H5 coverage states must contain the seven dimensions in canonical order")
        return value


class H5ChangeEvent(StrictContract):
    tenant_id: str = Field(min_length=1, max_length=36)
    asset_id: str = Field(min_length=1, max_length=36)
    event_type: Literal[
        "AI_ASSET_DISCOVERED",
        "AI_ASSET_CHANGED",
        "AI_ASSET_BECAME_ACTIVE",
        "AI_ASSET_OWNER_CHANGED",
        "AI_CAPABILITY_ADDED",
        "AI_USAGE_INCREASED",
        "AI_IDENTITY_CHANGED",
        "AI_REACHABILITY_CHANGED",
        "AI_FINGERPRINT_DRIFT",
        "SHADOW_AI_CONFIRMED",
        "CONTROL_COVERAGE_REDUCED",
    ]
    before_state: str = Field(min_length=1, max_length=500)
    after_state: str = Field(min_length=1, max_length=500)
    evidence_refs: tuple[str, ...]
    observed_at: datetime
    input_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_effect: Literal["none"] = "none"

    _observed = field_validator("observed_at")(_utc)
    _evidence = field_validator("evidence_refs")(_canonical_refs)


class IncrementalAssetDigest(StrictContract):
    asset_id: str = Field(min_length=1, max_length=36)
    input_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class IncrementalEnrichmentPlan(StrictContract):
    tenant_id: str = Field(min_length=1, max_length=36)
    scan_type: Literal["incremental"] = "incremental"
    selected_asset_ids: tuple[str, ...] = Field(max_length=500)
    unchanged_asset_ids: tuple[str, ...] = Field(max_length=500)
    remaining_changed: int = Field(ge=0)
    cursor_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    idempotency_key: str = Field(min_length=1, max_length=128)
    requested_at: datetime
    limitations: tuple[str, ...] = Field(default=(), max_length=32)

    _requested = field_validator("requested_at")(_utc)


__all__ = [
    "AcceptedGovernanceClaim",
    "GovernanceAssetSnapshot",
    "H5ChangeEvent",
    "H5FindingDefinition",
    "H5GraphRelationship",
    "H5ReachabilityProjection",
    "H5ShadowClassification",
    "H5ActorUsageView",
    "H5AssetUsageView",
    "H5UsageAggregate",
    "H5UsageProjection",
    "H5UsageViews",
    "H5_CHANGE_EVENT_TYPES",
    "H5_CONTROL_COVERAGE_DIMENSIONS",
    "H5_FINDING_CATALOG",
    "H5_REACHABILITY_STATES",
    "H5_REACHABILITY_TARGET_TYPES",
    "H5_SHADOW_STATES",
    "H5_USAGE_STATES",
    "IncrementalAssetDigest",
    "IncrementalEnrichmentPlan",
]
