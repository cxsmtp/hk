from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re

from pydantic import Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.models.ai_asset import (
    DiscoveryAIAsset,
    DiscoveryAICapability,
    DiscoveryEvidenceClaim,
)
from app.db.models.activity_audit import AIAction
from app.db.models.control_coverage import (
    ControlCoverageAssertion,
    ControlCoveragePath,
    DeploymentSurface,
)
from app.db.models.discovery_attribution import (
    DiscoveryAssetIdentityLink,
    DiscoveryAssetOwnershipAssertion,
    DiscoveryAssetReachability,
)
from app.db.models.discovery_intelligence import (
    DiscoveryAssetUsageFact,
    DiscoveryShadowClassification,
)
from app.db.models.discovery_resolution import (
    DiscoveryResolutionGraphEdge,
    DiscoveryResolutionGraphNode,
)
from app.db.models.evidence import DecisionReceipt
from app.db.models.runtime_intelligence import RuntimeEvent
from app.services.hmair.contracts import StrictContract
from app.services.hmair.exposure.contracts import (
    ExposureDimension,
    FreshnessState,
    VerificationStatus,
)


class ExposureAssetUnavailable(LookupError):
    pass


EXPOSURE_SOURCE_AUTHORITIES = (
    "discovery_asset",
    "discovery_capability",
    "discovery_identity",
    "discovery_ownership",
    "discovery_reachability",
    "discovery_usage",
    "shadow_classification",
    "control_coverage",
    "evidence_resolution_graph",
    "decision_receipt",
)
_MAX_RAW_SOURCES = 4000
_MAX_PATH_CONTEXT_RECORDS = 12
_MAX_PATH_SOURCE_REFS = 256
_MAX_SOURCE_EVIDENCE_REFS = 64
_ASSET_GOVERNANCE_STATES = frozenset(
    {
        "approved",
        "conditionally_approved",
        "exception",
        "unapproved",
        "expired_approval",
        "unknown",
    }
)

_ERG_AUTHORITATIVE_EDGE_TYPES = {
    ExposureDimension.PERMISSION: frozenset({"accesses"}),
    ExposureDimension.DATA: frozenset({"accesses"}),
    ExposureDimension.RUNTIME: frozenset({"runs_on", "uses"}),
    ExposureDimension.PROVIDER: frozenset({"uses", "hosted_in"}),
    ExposureDimension.MODEL: frozenset({"uses", "invokes", "calls"}),
    ExposureDimension.REACHABILITY: frozenset(
        {"connects_to", "connected_to", "calls"}
    ),
    ExposureDimension.IDENTITY: frozenset({"authenticates_as"}),
}


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _asset_governance_state(value: str | None) -> tuple[str, bool]:
    normalized = str(value or "unknown").strip().casefold()
    if normalized in _ASSET_GOVERNANCE_STATES:
        return normalized, True
    return "unknown", False


def _verification(value: str | None) -> VerificationStatus:
    normalized = str(value or "unknown").casefold()
    aliases = {
        "partial": VerificationStatus.PARTIALLY_VERIFIED,
        "partially_verified": VerificationStatus.PARTIALLY_VERIFIED,
    }
    if normalized in aliases:
        return aliases[normalized]
    try:
        return VerificationStatus(normalized)
    except ValueError:
        return VerificationStatus.UNKNOWN


def _freshness(value: str | None) -> FreshnessState:
    try:
        return FreshnessState(str(value or "unknown").casefold())
    except ValueError:
        return FreshnessState.UNKNOWN


def _derived_freshness(observed_at: datetime | None, as_of: datetime) -> FreshnessState:
    observed = _aware(observed_at)
    evaluated = _aware(as_of)
    if observed is None or evaluated is None or observed > evaluated:
        return FreshnessState.UNKNOWN
    age = evaluated - observed
    if age <= timedelta(days=90):
        return FreshnessState.FRESH
    if age <= timedelta(days=180):
        return FreshnessState.STALE
    return FreshnessState.EXPIRED


def _effective_freshness(
    reported: str | None,
    observed_at: datetime | None,
    as_of: datetime,
) -> FreshnessState:
    reported_state = _freshness(reported)
    derived_state = _derived_freshness(observed_at, as_of)
    strength = {
        FreshnessState.UNKNOWN: 0,
        FreshnessState.EXPIRED: 1,
        FreshnessState.STALE: 2,
        FreshnessState.FRESH: 3,
    }
    return min((reported_state, derived_state), key=lambda item: strength[item])


_ERG_STATE_MARKERS = {
    "identity": (
        "revoked",
        "removed",
        "disabled",
        "unknown",
        "active",
        "assigned",
        "configured",
        "observed",
    ),
    "permission": (
        "not_authorized",
        "metadata_only",
        "scoped_read",
        "read_only",
        "unrestricted",
        "write_all",
        "constrained",
        "elevated",
        "revoked",
        "removed",
        "blocked",
        "denied",
        "limited",
        "admin",
        "owner",
        "execute",
        "write",
        "read",
        "none",
    ),
    "network_destination": (
        "not_reachable",
        "cross_environment",
        "unreachable",
        "constrained",
        "no_reach",
        "internal",
        "external",
        "blocked",
        "denied",
        "scoped",
        "internet",
        "public",
        "global",
        "local",
        "reachable",
        "observed",
    ),
}

_RUNTIME_CAPABILITY_MAP: dict[str, tuple[str, ...]] = {
    "file_read": ("filesystem_read",),
    "filesystem_read": ("filesystem_read",),
    "file_write": ("filesystem_write",),
    "filesystem_write": ("filesystem_write",),
    "file_upload": ("file_upload",),
    "upload": ("file_upload",),
    "file_download": ("file_download",),
    "download": ("file_download",),
    "process_execution": ("process_execution",),
    "process_execute": ("process_execution",),
    "terminal_execution": ("terminal_execution",),
    "shell_execution": ("shell_execution",),
    "code_execution": ("code_execution",),
    "mcp_tool_call": ("mcp_tool_invocation",),
    "tool_call": ("tool_execution",),
    "api_call": ("api_call",),
    "email_send": ("email_send",),
    "database_read": ("database_read",),
    "database_write": ("database_write",),
    "agent_execution": ("agent_execution",),
    "credential_access": ("credential_access",),
    "crm_access": ("crm_access",),
    "developer_tooling": ("developer_tooling",),
    "external_ai_access": ("external_ai_access",),
    "external_data_retrieval": ("external_data_retrieval",),
    "external_side_effect": ("external_side_effect",),
    "financial_data_access": ("financial_data_access",),
    "local_model_connection": ("local_model_connection",),
    "model_configuration": ("model_configuration",),
    "model_hosting": ("model_hosting",),
    "payment_access": ("payment_access",),
    "pii_access": ("pii_access",),
    "provider_api_access": ("provider_api_access",),
    "query_execution": ("query_execution",),
    "resource_mutation": ("resource_mutation",),
    "token_access": ("token_access",),
    "trade_execution": ("trade_execution",),
    "web_search": ("web_search",),
}


def _source_ref_ids(
    references_by_path: dict[str, set[str]],
    prefix: str,
) -> tuple[str, ...]:
    marker = f"{prefix}:"
    return tuple(
        sorted(
            {
                reference[len(marker):]
                for references in references_by_path.values()
                for reference in references
                if reference.startswith(marker)
                and len(reference) > len(marker)
            }
        )
    )


def _erg_state(node_class: str, subject_reference: str) -> str:
    """Project only reviewed reasoning markers, never arbitrary ERG material."""

    normalized = subject_reference.casefold().replace("-", "_").replace(" ", "_")
    if normalized == "unknown":
        return "unknown"
    tokens = set(re.findall(r"[a-z0-9]+(?:_[a-z0-9]+)*", normalized))
    for marker in _ERG_STATE_MARKERS.get(node_class, ()):
        if normalized == marker or marker in tokens:
            return marker
    return f"{node_class}_observed"[:64]


class ExposureAssetSource(StrictContract):
    tenant_id: str = Field(min_length=1, max_length=36)
    asset_id: str = Field(min_length=1, max_length=36)
    asset_type: str = Field(min_length=1, max_length=64)
    provider: str | None = Field(default=None, max_length=255)
    technical_surface: str | None = Field(default=None, max_length=128)
    deployment_family: str | None = Field(default=None, max_length=64)
    environment: str | None = Field(default=None, max_length=64)
    governance_state: str = Field(min_length=1, max_length=64)
    resolution_confidence: float = Field(ge=0.0, le=1.0)
    evidence_bundle_id: str = Field(min_length=1, max_length=36)
    last_seen_at: datetime

    @field_validator("last_seen_at")
    @classmethod
    def timestamp_is_aware(cls, value: datetime) -> datetime:
        return _aware(value)  # type: ignore[return-value]


class ExposureSourceRecord(StrictContract):
    tenant_id: str = Field(min_length=1, max_length=36)
    authority: str = Field(min_length=1, max_length=64)
    source_type: str = Field(min_length=1, max_length=64)
    source_id: str = Field(min_length=1, max_length=255)
    dimension: ExposureDimension
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
        return _aware(value)


class ExposureSourceSnapshot(StrictContract):
    asset: ExposureAssetSource
    as_of: datetime
    raw_sources: tuple[ExposureSourceRecord, ...] = Field(max_length=4096)
    failed_authorities: tuple[str, ...] = Field(default=(), max_length=32)
    truncated: bool = False

    @field_validator("as_of")
    @classmethod
    def as_of_is_aware(cls, value: datetime) -> datetime:
        aware = _aware(value)
        if aware is None:
            raise ValueError("exposure as-of timestamp is required")
        return aware

    @property
    def source_ids(self) -> tuple[str, ...]:
        return tuple(item.source_id for item in self.raw_sources)


class ExposureSourceReader:
    def __init__(self, *, max_records_per_authority: int = 256) -> None:
        if not 1 <= max_records_per_authority <= 1024:
            raise ValueError("source authority bound must be between 1 and 1024")
        self.max_records_per_authority = max_records_per_authority

    def read(
        self,
        db: Session,
        *,
        tenant_id: str,
        asset_id: str,
        as_of: datetime,
    ) -> ExposureSourceSnapshot:
        asset = db.scalar(
            select(DiscoveryAIAsset).where(
                DiscoveryAIAsset.tenant_id == tenant_id,
                DiscoveryAIAsset.asset_id == asset_id,
                DiscoveryAIAsset.first_seen_at <= as_of,
            )
        )
        if asset is None:
            raise ExposureAssetUnavailable("asset is unavailable")

        sources: list[ExposureSourceRecord] = []
        truncated = False
        query_limit = self.max_records_per_authority + 1
        failed_authorities: set[str] = set()

        def read_rows(authority: str, statement) -> tuple[object, ...]:  # type: ignore[no-untyped-def]
            try:
                with db.begin_nested():
                    return tuple(db.scalars(statement))
            except SQLAlchemyError:
                failed_authorities.add(authority)
                return ()

        def bounded(rows: tuple[object, ...]) -> tuple[object, ...]:
            nonlocal truncated
            if len(rows) > self.max_records_per_authority:
                truncated = True
                return rows[: self.max_records_per_authority]
            return rows

        def bounded_string_refs(
            values: object,
            *,
            max_references: int,
        ) -> tuple[str, ...]:
            nonlocal truncated
            if not isinstance(values, (list, tuple)):
                truncated = True
                return ()
            if len(values) > max_references:
                truncated = True
            valid_references: set[str] = set()
            for item in values:
                if not isinstance(item, str):
                    truncated = True
                    continue
                reference = item.strip()
                if not reference or len(reference) > 255:
                    truncated = True
                    continue
                valid_references.add(reference)
            references = tuple(sorted(valid_references))
            if len(references) > max_references:
                truncated = True
                return references[:max_references]
            return references

        def bounded_evidence_refs(values: object) -> tuple[str, ...]:
            return bounded_string_refs(
                values,
                max_references=_MAX_SOURCE_EVIDENCE_REFS,
            )

        ranked_capabilities = (
            select(
                DiscoveryAICapability.capability_id.label("capability_id"),
                func.row_number()
                .over(
                    partition_by=DiscoveryAICapability.capability_name,
                    order_by=(
                        DiscoveryAICapability.assertion_sequence.desc(),
                        DiscoveryAICapability.capability_id,
                    ),
                )
                .label("row_number"),
            )
            .where(
                DiscoveryAICapability.tenant_id == tenant_id,
                DiscoveryAICapability.asset_id == asset_id,
                DiscoveryAICapability.last_observed_at <= as_of,
            )
            .subquery()
        )
        capabilities = read_rows(
            "discovery_capability",
            select(DiscoveryAICapability)
            .join(
                ranked_capabilities,
                ranked_capabilities.c.capability_id
                == DiscoveryAICapability.capability_id,
            )
            .where(ranked_capabilities.c.row_number == 1)
            .order_by(DiscoveryAICapability.capability_name)
            .limit(query_limit),
        )
        capability_claim_ids = tuple(
            row.evidence_claim_id
            for row in capabilities
            if isinstance(row, DiscoveryAICapability)
        )
        capability_claims = (
            read_rows(
                "discovery_capability",
                select(DiscoveryEvidenceClaim)
                .where(
                    DiscoveryEvidenceClaim.tenant_id == tenant_id,
                    DiscoveryEvidenceClaim.claim_id.in_(capability_claim_ids),
                    DiscoveryEvidenceClaim.observed_at <= as_of,
                )
                .order_by(DiscoveryEvidenceClaim.claim_id)
                .limit(query_limit),
            )
            if capability_claim_ids
            else ()
        )
        capability_claims_by_id = {
            row.claim_id: row
            for row in bounded(capability_claims)
            if isinstance(row, DiscoveryEvidenceClaim)
        }
        for row in bounded(capabilities):
            assert isinstance(row, DiscoveryAICapability)
            claim = capability_claims_by_id.get(row.evidence_claim_id)
            sources.append(
                ExposureSourceRecord(
                    tenant_id=tenant_id,
                    authority="discovery_capability",
                    source_type="discovery_capability",
                    source_id=row.capability_id,
                    dimension=ExposureDimension.CAPABILITY,
                    state=(
                        row.capability_name.casefold()
                        if row.capability_state != "denied"
                        else "denied"
                    ),
                    evidence_refs=tuple(
                        sorted(
                            {
                                row.evidence_claim_id,
                                *(
                                    (claim.evidence_node_id,)
                                    if claim is not None and claim.evidence_node_id
                                    else ()
                                ),
                            }
                        )
                    ),
                    confidence=float(row.confidence),
                    verification_status=_verification(row.verification_state),
                    freshness=_effective_freshness(row.freshness, row.last_observed_at, as_of),
                    observed_at=row.last_observed_at,
                    validated_at=row.last_observed_at,
                    methodology_id=row.extractor_version,
                    collector_group="capability_inference",
                    limitations=("declared_only",) if row.declared_only else (),
                )
            )

        reachability = read_rows(
            "discovery_reachability",
            select(DiscoveryAssetReachability)
            .where(
                DiscoveryAssetReachability.tenant_id == tenant_id,
                DiscoveryAssetReachability.asset_id == asset_id,
                DiscoveryAssetReachability.last_observed_at <= as_of,
            )
            .order_by(
                DiscoveryAssetReachability.last_observed_at.desc(),
                DiscoveryAssetReachability.reachability_id,
            )
            .limit(query_limit),
        )
        for row in bounded(reachability):
            assert isinstance(row, DiscoveryAssetReachability)
            sources.append(
                ExposureSourceRecord(
                    tenant_id=tenant_id,
                    authority="discovery_reachability",
                    source_type="discovery_reachability",
                    source_id=row.reachability_id,
                    dimension=ExposureDimension.REACHABILITY,
                    state=(
                        "unknown"
                        if row.reachability_state == "unknown"
                        else f"{row.target_category}:{row.reachability_state}"
                    ),
                    evidence_refs=(row.evidence_node_id,),
                    confidence=float(row.confidence),
                    verification_status=(
                        VerificationStatus.UNKNOWN
                        if row.reachability_state == "potential"
                        else _verification(row.verification_state)
                    ),
                    freshness=_effective_freshness(row.freshness, row.last_observed_at, as_of),
                    observed_at=row.last_observed_at,
                    validated_at=row.last_observed_at,
                    methodology_id="discovery-reachability/1.0",
                    collector_group="reachability",
                    limitations=(
                        ("reachability_source_limitations_present",)
                        if row.limitations_json
                        else ()
                    ),
                )
            )

        identities = read_rows(
            "discovery_identity",
            select(DiscoveryAssetIdentityLink)
            .where(
                DiscoveryAssetIdentityLink.tenant_id == tenant_id,
                DiscoveryAssetIdentityLink.asset_id == asset_id,
                DiscoveryAssetIdentityLink.last_observed_at <= as_of,
            )
            .order_by(
                DiscoveryAssetIdentityLink.last_observed_at.desc(),
                DiscoveryAssetIdentityLink.identity_link_id,
            )
            .limit(query_limit),
        )
        for row in bounded(identities):
            assert isinstance(row, DiscoveryAssetIdentityLink)
            sources.append(
                ExposureSourceRecord(
                    tenant_id=tenant_id,
                    authority="discovery_identity",
                    source_type="discovery_identity",
                    source_id=row.identity_link_id,
                    dimension=ExposureDimension.IDENTITY,
                    state=(
                        "unknown"
                        if row.access_state == "unknown"
                        else f"{row.identity_type}:{row.access_state}"
                    ),
                    evidence_refs=(row.evidence_node_id,),
                    confidence=float(row.confidence),
                    verification_status=_verification(row.verification_state),
                    freshness=_derived_freshness(row.last_observed_at, as_of),
                    observed_at=row.last_observed_at,
                    validated_at=row.last_observed_at,
                    methodology_id="discovery-identity/1.0",
                    collector_group="identity",
                    limitations=("freshness_derived_from_last_seen_90d",),
                )
            )

        ownership = read_rows(
            "discovery_ownership",
            select(DiscoveryAssetOwnershipAssertion)
            .where(
                DiscoveryAssetOwnershipAssertion.tenant_id == tenant_id,
                DiscoveryAssetOwnershipAssertion.asset_id == asset_id,
                DiscoveryAssetOwnershipAssertion.last_observed_at <= as_of,
            )
            .order_by(
                DiscoveryAssetOwnershipAssertion.last_observed_at.desc(),
                DiscoveryAssetOwnershipAssertion.ownership_assertion_id,
            )
            .limit(query_limit),
        )
        for row in bounded(ownership):
            assert isinstance(row, DiscoveryAssetOwnershipAssertion)
            sources.append(
                ExposureSourceRecord(
                    tenant_id=tenant_id,
                    authority="discovery_ownership",
                    source_type="discovery_ownership",
                    source_id=row.ownership_assertion_id,
                    dimension=ExposureDimension.IDENTITY,
                    state=(
                        "unknown"
                        if row.ownership_state == "unknown"
                        else f"owner:{row.ownership_state}"
                    ),
                    evidence_refs=(row.evidence_node_id,),
                    confidence=float(row.confidence),
                    verification_status=_verification(row.verification_state),
                    freshness=_derived_freshness(row.last_observed_at, as_of),
                    observed_at=row.last_observed_at,
                    validated_at=row.last_observed_at,
                    methodology_id="discovery-ownership/1.0",
                    collector_group="ownership",
                    limitations=("freshness_derived_from_last_seen_90d",),
                )
            )

        usage = read_rows(
            "discovery_usage",
            select(DiscoveryAssetUsageFact)
            .where(
                DiscoveryAssetUsageFact.tenant_id == tenant_id,
                DiscoveryAssetUsageFact.asset_id == asset_id,
                DiscoveryAssetUsageFact.last_observed_at <= as_of,
            )
            .order_by(
                DiscoveryAssetUsageFact.last_observed_at.desc(),
                DiscoveryAssetUsageFact.usage_fact_id,
            )
            .limit(query_limit),
        )
        for row in bounded(usage):
            assert isinstance(row, DiscoveryAssetUsageFact)
            sources.append(
                ExposureSourceRecord(
                    tenant_id=tenant_id,
                    authority="discovery_usage",
                    source_type="discovery_usage",
                    source_id=row.usage_fact_id,
                    dimension=ExposureDimension.USAGE,
                    state=row.usage_state,
                    evidence_refs=(row.evidence_node_id,),
                    confidence=float(row.confidence),
                    verification_status=_verification(row.verification_state),
                    freshness=_effective_freshness(row.freshness, row.last_observed_at, as_of),
                    observed_at=row.last_observed_at,
                    validated_at=row.last_observed_at,
                    methodology_id=row.methodology_id,
                    collector_group=row.source_surface,
                    limitations=(
                        ("usage_source_limitations_present",)
                        if row.limitations_json
                        else ()
                    ),
                )
            )

        shadow = read_rows(
            "shadow_classification",
            select(DiscoveryShadowClassification)
            .where(
                DiscoveryShadowClassification.tenant_id == tenant_id,
                DiscoveryShadowClassification.asset_id == asset_id,
                DiscoveryShadowClassification.last_observed_at <= as_of,
            )
            .order_by(
                DiscoveryShadowClassification.last_observed_at.desc(),
                DiscoveryShadowClassification.classification_id,
            )
            .limit(query_limit),
        )
        for row in bounded(shadow):
            assert isinstance(row, DiscoveryShadowClassification)
            sources.append(
                ExposureSourceRecord(
                    tenant_id=tenant_id,
                    authority="shadow_classification",
                    source_type="shadow_classification",
                    source_id=row.classification_id,
                    dimension=ExposureDimension.GOVERNANCE,
                    state=(
                        "unknown"
                        if "unknown" in {row.management_class, row.shadow_type}
                        else f"{row.management_class}:{row.shadow_type}"
                    ),
                    evidence_refs=bounded_evidence_refs(row.evidence_node_ids_json),
                    confidence=float(row.confidence),
                    verification_status=_verification(row.verification_state),
                    freshness=_derived_freshness(row.last_observed_at, as_of),
                    observed_at=row.last_observed_at,
                    validated_at=row.last_observed_at,
                    methodology_id=row.methodology_id,
                    collector_group="shadow_classification",
                    limitations=(
                        ("shadow_source_limitations_present",)
                        if row.limitations_json
                        else ()
                    ),
                )
            )
            shadow_selector = (
                "unknown_ai_usage"
                if row.shadow_type == "unknown_ai_workload"
                else "unmanaged_ai_access"
            )
            sources.append(
                ExposureSourceRecord(
                    tenant_id=tenant_id,
                    authority="shadow_classification",
                    source_type="shadow_capability_projection",
                    source_id=f"{row.classification_id}:{shadow_selector}",
                    dimension=ExposureDimension.CAPABILITY,
                    state=shadow_selector,
                    evidence_refs=bounded_evidence_refs(row.evidence_node_ids_json),
                    confidence=float(row.confidence),
                    verification_status=_verification(row.verification_state),
                    freshness=_derived_freshness(row.last_observed_at, as_of),
                    observed_at=row.last_observed_at,
                    validated_at=row.last_observed_at,
                    methodology_id="shadow-exposure-selector/1.0",
                    collector_group="shadow_classification",
                    limitations=("semantic_exposure_path_not_bound",),
                )
            )

        path_asset_refs = {
            asset_id.casefold(),
            f"discovery_asset:{asset_id.casefold()}",
        }
        paths = read_rows(
            "control_coverage",
            select(ControlCoveragePath)
            .where(
                ControlCoveragePath.tenant_id == tenant_id,
                ControlCoveragePath.asset_ref.in_(tuple(sorted(path_asset_refs))),
                ControlCoveragePath.last_seen_at <= as_of,
            )
            .order_by(ControlCoveragePath.last_seen_at.desc(), ControlCoveragePath.id)
            .limit(query_limit),
        )
        bounded_paths = bounded(paths)
        path_ids = tuple(str(row.id) for row in bounded_paths if isinstance(row, ControlCoveragePath))
        path_source_refs: dict[str, set[str]] = {}
        for row in bounded_paths:
            if not isinstance(row, ControlCoveragePath):
                continue
            path_source_refs[str(row.id)] = set(
                bounded_string_refs(
                    row.source_refs,
                    max_references=_MAX_PATH_SOURCE_REFS,
                )
            )
        path_evidence_refs: dict[str, set[str]] = {
            path_id: set() for path_id in path_source_refs
        }
        runtime_event_ids = _source_ref_ids(path_source_refs, "runtime_event")
        if len(runtime_event_ids) > self.max_records_per_authority:
            truncated = True
            runtime_event_ids = runtime_event_ids[: self.max_records_per_authority]
        runtime_events = (
            read_rows(
                "control_coverage",
                select(RuntimeEvent)
                .where(
                    RuntimeEvent.tenant_id == tenant_id,
                    RuntimeEvent.event_id.in_(runtime_event_ids),
                    RuntimeEvent.created_at <= as_of,
                )
                .order_by(RuntimeEvent.created_at.desc(), RuntimeEvent.event_id)
                .limit(query_limit),
            )
            if runtime_event_ids
            else ()
        )
        action_ids = _source_ref_ids(path_source_refs, "ai_action")
        if len(action_ids) > self.max_records_per_authority:
            truncated = True
            action_ids = action_ids[: self.max_records_per_authority]
        actions = (
            read_rows(
                "control_coverage",
                select(AIAction)
                .where(
                    AIAction.tenant_id == tenant_id,
                    AIAction.action_id.in_(action_ids),
                    AIAction.timestamp <= as_of,
                )
                .order_by(AIAction.timestamp.desc(), AIAction.action_id)
                .limit(query_limit),
            )
            if action_ids
            else ()
        )
        runtime_events_by_ref = {
            f"runtime_event:{row.event_id}": row
            for row in bounded(runtime_events)
            if isinstance(row, RuntimeEvent)
        }
        actions_by_ref = {
            f"ai_action:{row.action_id}": row
            for row in bounded(actions)
            if isinstance(row, AIAction)
        }
        for path in bounded_paths:
            if not isinstance(path, ControlCoveragePath):
                continue
            path_ref = f"control_coverage_path:{path.id}"
            source_records = tuple(
                runtime_events_by_ref.get(reference)
                or actions_by_ref.get(reference)
                for reference in sorted(path_source_refs.get(str(path.id), set()))
            )
            source_records = tuple(
                sorted(
                    (item for item in source_records if item is not None),
                    key=lambda item: (
                        "runtime_event" if isinstance(item, RuntimeEvent) else "ai_action",
                        item.event_id if isinstance(item, RuntimeEvent) else item.action_id,
                    ),
                )
            )
            if len(source_records) > _MAX_PATH_CONTEXT_RECORDS:
                truncated = True
                source_records = source_records[:_MAX_PATH_CONTEXT_RECORDS]
            event_evidence_candidates: list[object] = []
            for item in source_records:
                if isinstance(item, RuntimeEvent):
                    event_evidence_candidates.extend(
                        bounded_evidence_refs(item.evidence_node_ids)
                    )
                for attribute in ("evidence_node_id", "evidence_bundle_id"):
                    reference = getattr(item, attribute, None)
                    if reference is not None:
                        event_evidence_candidates.append(reference)
            event_evidence = bounded_evidence_refs(event_evidence_candidates)
            path_evidence_refs[str(path.id)].update(event_evidence)
            freshness = _derived_freshness(path.last_seen_at, as_of)
            verified_context = (
                VerificationStatus.PARTIALLY_VERIFIED
                if source_records and freshness is FreshnessState.FRESH
                else VerificationStatus.UNKNOWN
            )
            identity_known = (
                path.identity_type != "unknown"
                and not path.identity_ref.startswith("unknown_identity:")
            )
            destination_known = (
                path.destination_type != "unknown"
                and not path.destination_ref.startswith("unknown_destination:")
            )
            for source_type, source_id, dimension, state, known in (
                (
                    "control_coverage_path",
                    f"{path.id}:identity",
                    ExposureDimension.IDENTITY,
                    f"{path.identity_type}:active"[:64],
                    identity_known,
                ),
                (
                    "control_coverage_path",
                    f"{path.id}:destination",
                    ExposureDimension.REACHABILITY,
                    (f"{path.destination_type}:reachable" if destination_known else "unknown")[:64],
                    destination_known,
                ),
                (
                    "control_coverage_path",
                    f"{path.id}:runtime",
                    ExposureDimension.RUNTIME,
                    "runtime_observed",
                    not path.runtime_ref.startswith("unknown_runtime:"),
                ),
            ):
                sources.append(
                    ExposureSourceRecord(
                        tenant_id=tenant_id,
                        authority="control_coverage",
                        source_type=source_type,
                        source_id=source_id,
                        dimension=dimension,
                        state=state,
                        evidence_refs=event_evidence,
                        related_source_refs=(path_ref,),
                        confidence=None,
                        verification_status=(verified_context if known else VerificationStatus.UNKNOWN),
                        freshness=freshness,
                        observed_at=path.last_seen_at,
                        validated_at=None,
                        methodology_id="control-coverage-path-context/1.0",
                        collector_group="control_coverage",
                        limitations=("path_context_is_observed_not_independently_verified",),
                    )
                )
            for item in source_records:
                operation = (
                    item.event_type if isinstance(item, RuntimeEvent) else item.action_type
                ).casefold()
                capabilities = _RUNTIME_CAPABILITY_MAP.get(operation)
                if capabilities is None:
                    continue
                observed_at = item.created_at if isinstance(item, RuntimeEvent) else item.timestamp
                for capability in capabilities:
                    sources.append(
                        ExposureSourceRecord(
                        tenant_id=tenant_id,
                        authority="control_coverage",
                        source_type=(
                            "runtime_event_path_context"
                            if isinstance(item, RuntimeEvent)
                            else "ai_action_path_context"
                        ),
                        source_id=(
                            item.event_id
                            if isinstance(item, RuntimeEvent)
                            else item.action_id
                        ),
                        dimension=ExposureDimension.CAPABILITY,
                        state=capability,
                        evidence_refs=event_evidence,
                        related_source_refs=(path_ref,),
                        confidence=None,
                        verification_status=verified_context,
                        freshness=freshness,
                        observed_at=observed_at,
                        validated_at=None,
                        methodology_id="control-coverage-path-capability/1.0",
                        collector_group="control_coverage",
                        limitations=("runtime_operation_is_observed_not_independently_verified",),
                        )
                    )
        if path_ids:
            ranked_assertions = (
                select(
                    ControlCoverageAssertion.id.label("assertion_id"),
                    func.row_number()
                    .over(
                        partition_by=(
                            ControlCoverageAssertion.path_id,
                            ControlCoverageAssertion.dimension,
                        ),
                        order_by=(
                            ControlCoverageAssertion.evaluated_at.desc(),
                            ControlCoverageAssertion.observed_at.desc(),
                            ControlCoverageAssertion.id,
                        ),
                    )
                    .label("row_number"),
                )
                .where(
                    ControlCoverageAssertion.tenant_id == tenant_id,
                    ControlCoverageAssertion.path_id.in_(path_ids),
                    ControlCoverageAssertion.observed_at <= as_of,
                    ControlCoverageAssertion.evaluated_at <= as_of,
                )
                .subquery()
            )
            assertions = read_rows(
                "control_coverage",
                select(ControlCoverageAssertion)
                .join(
                    ranked_assertions,
                    ranked_assertions.c.assertion_id == ControlCoverageAssertion.id,
                )
                .where(ranked_assertions.c.row_number == 1)
                .order_by(
                    ControlCoverageAssertion.observed_at.desc(),
                    ControlCoverageAssertion.id,
                )
                .limit(query_limit),
            )
            for row in bounded(assertions):
                assert isinstance(row, ControlCoverageAssertion)
                observed_at = _aware(row.observed_at)
                evaluated_at = _aware(row.evaluated_at)
                if (
                    observed_at is None
                    or evaluated_at is None
                    or evaluated_at < observed_at
                ):
                    failed_authorities.add("control_coverage")
                    truncated = True
                    continue
                freshness = (
                    FreshnessState.FRESH
                    if row.valid_until is None or _aware(row.valid_until) >= _aware(as_of)
                    else FreshnessState.EXPIRED
                )
                sources.append(
                    ExposureSourceRecord(
                        tenant_id=tenant_id,
                        authority="control_coverage",
                        source_type="control_coverage_assertion",
                        source_id=str(row.id),
                        dimension=ExposureDimension.CONTROL_COVERAGE,
                        state=f"{row.dimension}:{row.state}",
                        evidence_refs=bounded_evidence_refs(row.evidence_refs),
                        related_source_refs=(
                            f"control_coverage_assertion:{row.id}",
                            f"control_coverage_path:{row.path_id}",
                            f"coverage_reason:{row.reason_code}",
                        ),
                        confidence=None,
                        verification_status=(
                            VerificationStatus.VERIFIED
                            if row.state in {"covered", "not_covered"}
                            else VerificationStatus.UNKNOWN
                        ),
                        freshness=freshness,
                        observed_at=observed_at,
                        validated_at=evaluated_at,
                        methodology_id=row.methodology_version,
                        collector_group="control_coverage",
                    )
                )

            surface_path_ids: dict[str, list[str]] = {}
            for path in bounded_paths:
                if isinstance(path, ControlCoveragePath) and path.deployment_surface_id:
                    surface_path_ids.setdefault(path.deployment_surface_id, []).append(str(path.id))
            if surface_path_ids:
                surfaces = read_rows(
                    "control_coverage",
                    select(DeploymentSurface)
                    .where(
                        DeploymentSurface.tenant_id == tenant_id,
                        DeploymentSurface.id.in_(tuple(sorted(surface_path_ids))),
                        DeploymentSurface.last_seen_at <= as_of,
                        (
                            DeploymentSurface.last_health_check_at.is_(None)
                            | (DeploymentSurface.last_health_check_at <= as_of)
                        ),
                        (
                            DeploymentSurface.last_heartbeat_at.is_(None)
                            | (DeploymentSurface.last_heartbeat_at <= as_of)
                        ),
                    )
                    .order_by(DeploymentSurface.id)
                    .limit(query_limit),
                )
                for surface in bounded(surfaces):
                    assert isinstance(surface, DeploymentSurface)
                    observed_at = (
                        surface.last_health_check_at
                        or surface.last_heartbeat_at
                        or surface.last_seen_at
                    )
                    freshness = _derived_freshness(observed_at, as_of)
                    known_containment = surface.containment_capability in {
                        "direct",
                        "surface_limited",
                        "external",
                        "none",
                    }
                    healthy = surface.health_status == "healthy"
                    for path_id in sorted(surface_path_ids.get(str(surface.id), ())):
                        sources.append(
                            ExposureSourceRecord(
                                tenant_id=tenant_id,
                                authority="control_coverage",
                                source_type="deployment_surface",
                                source_id=str(surface.id),
                                dimension=ExposureDimension.CONTROL_COVERAGE,
                                state=(
                                    f"containment:{surface.containment_capability}:"
                                    f"control:{surface.control_capability}"
                                )[:64],
                                evidence_refs=(),
                                related_source_refs=(f"control_coverage_path:{path_id}",),
                                confidence=None,
                                verification_status=(
                                    VerificationStatus.VERIFIED
                                    if known_containment
                                    and healthy
                                    and freshness is FreshnessState.FRESH
                                    else VerificationStatus.UNKNOWN
                                ),
                                freshness=freshness,
                                observed_at=observed_at,
                                validated_at=surface.last_health_check_at,
                                methodology_id="deployment-surface-containment/1.0",
                                collector_group="control_coverage",
                                limitations=(
                                    ()
                                    if healthy
                                    else (f"surface_health:{surface.health_status}",)
                                ),
                            )
                        )

        asset_graph_nodes = read_rows(
            "evidence_resolution_graph",
            select(DiscoveryResolutionGraphNode)
            .where(
                DiscoveryResolutionGraphNode.tenant_id == tenant_id,
                DiscoveryResolutionGraphNode.node_class == "ai_asset",
                DiscoveryResolutionGraphNode.subject_reference == asset_id,
                DiscoveryResolutionGraphNode.created_at <= as_of,
            )
            .order_by(DiscoveryResolutionGraphNode.graph_node_id)
            .limit(query_limit),
        )
        asset_graph_node_ids = tuple(row.graph_node_id for row in bounded(asset_graph_nodes))
        if asset_graph_node_ids:
            graph_edges = read_rows(
                "evidence_resolution_graph",
                select(DiscoveryResolutionGraphEdge)
                .where(
                    DiscoveryResolutionGraphEdge.tenant_id == tenant_id,
                    DiscoveryResolutionGraphEdge.from_node_id.in_(asset_graph_node_ids),
                    DiscoveryResolutionGraphEdge.last_observed_at <= as_of,
                    DiscoveryResolutionGraphEdge.last_validated_at <= as_of,
                )
                .order_by(
                    DiscoveryResolutionGraphEdge.last_validated_at.desc(),
                    DiscoveryResolutionGraphEdge.edge_id,
                )
                .limit(query_limit),
            )
            bounded_edges = bounded(graph_edges)
            historical_edge_ids = {
                row.predecessor_edge_id
                for row in bounded_edges
                if row.predecessor_edge_id is not None
            }
            valid_edges: list[DiscoveryResolutionGraphEdge] = []
            for row in bounded_edges:
                observed_at = _aware(row.last_observed_at)
                validated_at = _aware(row.last_validated_at)
                if (
                    observed_at is None
                    or validated_at is None
                    or validated_at < observed_at
                ):
                    failed_authorities.add("evidence_resolution_graph")
                    truncated = True
                    continue
                valid_edges.append(row)
            current_edges = tuple(
                row for row in valid_edges if row.edge_id not in historical_edge_ids
            )
            target_ids = tuple(row.to_node_id for row in current_edges)
            targets = (
                read_rows(
                    "evidence_resolution_graph",
                    select(DiscoveryResolutionGraphNode)
                    .where(
                        DiscoveryResolutionGraphNode.tenant_id == tenant_id,
                        DiscoveryResolutionGraphNode.graph_node_id.in_(target_ids),
                        DiscoveryResolutionGraphNode.created_at <= as_of,
                    )
                    .order_by(DiscoveryResolutionGraphNode.graph_node_id)
                    .limit(query_limit),
                )
                if target_ids
                else ()
            )
            targets_by_id = {row.graph_node_id: row for row in targets}
            graph_dimensions = {
                "permission": ExposureDimension.PERMISSION,
                "data_asset": ExposureDimension.DATA,
                "runtime": ExposureDimension.RUNTIME,
                "provider": ExposureDimension.PROVIDER,
                "model": ExposureDimension.MODEL,
                "network_destination": ExposureDimension.REACHABILITY,
                "identity": ExposureDimension.IDENTITY,
            }
            for row in current_edges:
                target = targets_by_id.get(row.to_node_id)
                if target is None or target.node_class not in graph_dimensions:
                    continue
                dimension = graph_dimensions[target.node_class]
                if row.edge_type not in _ERG_AUTHORITATIVE_EDGE_TYPES[dimension]:
                    continue
                verification = (
                    VerificationStatus.CONTRADICTED
                    if row.contradiction_state == "confirmed"
                    else _verification(row.verification_state)
                )
                sources.append(
                    ExposureSourceRecord(
                        tenant_id=tenant_id,
                        authority="evidence_resolution_graph",
                        source_type="erg_relationship",
                        source_id=row.edge_id,
                        dimension=dimension,
                        state=_erg_state(target.node_class, target.subject_reference),
                        evidence_refs=(row.evidence_node_id,),
                        related_source_refs=(f"erg_node:{target.graph_node_id}",),
                        confidence=float(row.confidence),
                        verification_status=verification,
                        freshness=_effective_freshness(row.freshness, row.last_observed_at, as_of),
                        observed_at=row.last_observed_at,
                        validated_at=row.last_validated_at,
                        methodology_id=(
                            f"{row.relationship_rule_id}/{row.relationship_rule_version}"
                        )[:128],
                        collector_group=row.collector_id or row.source_surface,
                        limitations=(
                            (f"erg_contradiction:{row.contradiction_state}",)
                            if row.contradiction_state not in {"none", "resolved"}
                            else ()
                        ),
                    )
                )

        decision_receipts = (
            read_rows(
                "decision_receipt",
                select(DecisionReceipt)
                .where(
                    DecisionReceipt.tenant_id == tenant_id,
                    DecisionReceipt.action_id.in_(action_ids),
                    DecisionReceipt.issued_at <= as_of,
                )
                .order_by(DecisionReceipt.issued_at.desc(), DecisionReceipt.receipt_id)
                .limit(query_limit),
            )
            if action_ids
            else ()
        )
        for row in bounded(decision_receipts):
            assert isinstance(row, DecisionReceipt)
            exact_path_refs = tuple(
                sorted(
                    f"control_coverage_path:{path_id}"
                    for path_id, references in path_source_refs.items()
                    if f"ai_action:{row.action_id}" in references
                )
            )
            if not exact_path_refs:
                continue
            receipt_limitations = {
                "receipt_signature_validation_not_reperformed",
                "block_scope_is_exact_action_only",
            }
            if len(exact_path_refs) > 64:
                exact_path_refs = ()
                receipt_limitations.add("path_binding_cardinality_exceeded")
                truncated = True
            evidence_refs = tuple(
                sorted(
                    {
                        reference
                        for reference in (
                            row.evidence_node_id,
                            row.canonical_action_evidence_node_id,
                            row.policy_snapshot_evidence_node_id,
                            row.evidence_bundle_id,
                        )
                        if reference
                    }
                )
            )
            sources.append(
                ExposureSourceRecord(
                    tenant_id=tenant_id,
                    authority="decision_receipt",
                    source_type="decision_receipt",
                    source_id=row.receipt_id,
                    dimension=ExposureDimension.AI_ACTION,
                    state=f"{row.decision}:{row.control_mode}",
                    evidence_refs=evidence_refs,
                    related_source_refs=exact_path_refs,
                    confidence=None,
                    verification_status=VerificationStatus.PARTIALLY_VERIFIED,
                    freshness=(
                        FreshnessState.FRESH
                        if _aware(row.expires_at) >= _aware(as_of)
                        else FreshnessState.EXPIRED
                    ),
                    observed_at=row.issued_at,
                    validated_at=row.issued_at,
                    methodology_id=f"decision-receipt/{row.schema_version}",
                    collector_group=row.collector_id,
                    limitations=tuple(sorted(receipt_limitations)),
                )
            )

        governance_state, governance_state_recognized = _asset_governance_state(
            asset.approved_status
        )
        asset_source = ExposureAssetSource(
            tenant_id=tenant_id,
            asset_id=asset.asset_id,
            asset_type=asset.asset_type,
            provider=asset.provider,
            technical_surface=asset.technical_surface,
            deployment_family=asset.deployment_family,
            environment=asset.environment,
            governance_state=governance_state,
            resolution_confidence=float(asset.resolution_confidence),
            evidence_bundle_id=asset.evidence_bundle_id,
            last_seen_at=asset.last_seen_at,
        )
        asset_current_at_clock = _aware(asset.last_seen_at) <= _aware(as_of)
        if asset_current_at_clock:
            sources.append(
                ExposureSourceRecord(
                tenant_id=tenant_id,
                authority="discovery_asset",
                source_type="discovery_asset",
                source_id=asset.asset_id,
                dimension=ExposureDimension.GOVERNANCE,
                state=governance_state,
                evidence_refs=(asset.evidence_bundle_id,),
                confidence=float(asset.resolution_confidence),
                verification_status=(
                    VerificationStatus.UNKNOWN
                    if governance_state == "unknown"
                    else VerificationStatus.VERIFIED
                ),
                freshness=_derived_freshness(asset.last_seen_at, as_of),
                observed_at=asset.last_seen_at,
                validated_at=asset.last_seen_at,
                methodology_id="discovery-asset/1.0",
                collector_group="asset_resolution",
                limitations=tuple(
                    sorted(
                        {"freshness_derived_from_last_seen_90d"}
                        | (
                            {"unrecognized_governance_state"}
                            if not governance_state_recognized
                            else set()
                        )
                    )
                ),
                )
            )
        if asset_current_at_clock and (
            asset.technical_surface or asset.deployment_family or asset.asset_type
        ):
            sources.append(
                ExposureSourceRecord(
                    tenant_id=tenant_id,
                    authority="discovery_asset",
                    source_type="discovery_asset",
                    source_id=f"{asset.asset_id}:runtime",
                    dimension=ExposureDimension.RUNTIME,
                    state="runtime_observed",
                    evidence_refs=(asset.evidence_bundle_id,),
                    confidence=float(asset.resolution_confidence),
                    verification_status=VerificationStatus.PARTIALLY_VERIFIED,
                    freshness=_derived_freshness(asset.last_seen_at, as_of),
                    observed_at=asset.last_seen_at,
                    validated_at=asset.last_seen_at,
                    methodology_id="discovery-asset/1.0",
                    collector_group="asset_resolution",
                    limitations=("freshness_derived_from_last_seen_90d",),
                )
            )
        if asset_current_at_clock and asset.provider:
            sources.append(
                ExposureSourceRecord(
                    tenant_id=tenant_id,
                    authority="discovery_asset",
                    source_type="discovery_asset",
                    source_id=f"{asset.asset_id}:provider",
                    dimension=ExposureDimension.PROVIDER,
                    state="provider_observed",
                    evidence_refs=(asset.evidence_bundle_id,),
                    confidence=float(asset.resolution_confidence),
                    verification_status=VerificationStatus.PARTIALLY_VERIFIED,
                    freshness=_derived_freshness(asset.last_seen_at, as_of),
                    observed_at=asset.last_seen_at,
                    validated_at=asset.last_seen_at,
                    methodology_id="discovery-asset/1.0",
                    collector_group="asset_resolution",
                    limitations=("freshness_derived_from_last_seen_90d",),
                )
            )

        path_bound_sources: list[ExposureSourceRecord] = []
        evidence_path_index: dict[str, set[str]] = {}
        for path_id, references in path_evidence_refs.items():
            for reference in references:
                evidence_path_index.setdefault(reference, set()).add(path_id)
        for source in sources:
            existing = set(source.related_source_refs)
            candidates = {
                f"{source.source_type}:{source.source_id}",
                *(
                    reference
                    for reference in source.related_source_refs
                    if not reference.startswith("control_coverage_path:")
                ),
            }
            matched_paths = {
                path_id
                for path_id, references in path_source_refs.items()
                if candidates.intersection(references)
            }
            if source.source_type != "decision_receipt":
                for evidence_reference in source.evidence_refs:
                    evidence_paths = evidence_path_index.get(evidence_reference, set())
                    if len(evidence_paths) == 1:
                        matched_paths.update(evidence_paths)
            matched_path_refs = {
                f"control_coverage_path:{path_id}" for path_id in matched_paths
            }
            projected_limitations = set(source.limitations)
            if len(existing | matched_path_refs) > 64:
                existing = {
                    reference
                    for reference in existing
                    if not reference.startswith("control_coverage_path:")
                }
                projected_limitations.add("path_binding_cardinality_exceeded")
            else:
                existing.update(matched_path_refs)
            path_bound_sources.append(
                source.model_copy(
                    update={
                        "related_source_refs": tuple(sorted(existing)),
                        "limitations": tuple(sorted(projected_limitations)),
                    }
                )
            )

        ordered = tuple(
            sorted(
                path_bound_sources,
                key=lambda item: (
                    item.dimension.value,
                    item.source_type,
                    item.source_id,
                    item.state,
                    item.related_source_refs,
                    item.evidence_refs,
                ),
            )
        )
        if len(ordered) > _MAX_RAW_SOURCES:
            ordered = ordered[:_MAX_RAW_SOURCES]
            truncated = True
        return ExposureSourceSnapshot(
            asset=asset_source,
            as_of=as_of,
            raw_sources=ordered,
            failed_authorities=tuple(sorted(failed_authorities)),
            truncated=truncated,
        )


__all__ = [
    "ExposureAssetSource",
    "ExposureAssetUnavailable",
    "EXPOSURE_SOURCE_AUTHORITIES",
    "ExposureSourceReader",
    "ExposureSourceRecord",
    "ExposureSourceSnapshot",
]
