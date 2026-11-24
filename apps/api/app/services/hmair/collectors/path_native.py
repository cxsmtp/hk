from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, ClassVar

from pydantic import Field, model_validator

from app.services.hmair.collector_registry import CollectorRegistry
from app.services.hmair.collector_sdk import (
    CollectorHealthReport,
    CollectorRecord,
    ConnectivityResult,
    DiscoveryTargetView,
    ScopeItem,
)
from app.services.hmair.contracts import (
    CollectorDeclaration,
    ContradictionState,
    DiscoveryObservationInput,
    DiscoveryTargetType,
    EvidenceMode,
    EvidenceMutability,
    FactVerificationState,
    ObservationFreshness,
    ObservationType,
    ObservedFactState,
    SourceSurface,
    SourceTrust,
    StrictContract,
)


class PathNativeSignal(StrictContract):
    observation_id: str = Field(min_length=1, max_length=128)
    scan_id: str = Field(min_length=1, max_length=36)
    target_id: str = Field(min_length=1, max_length=128)
    subject_reference: str | None = Field(default=None, max_length=255)
    raw_signal_type: ObservationType
    asset_candidate_type: str = Field(min_length=1, max_length=64)
    observed_state: ObservedFactState
    normalized_signal: Mapping[str, Any] = Field(max_length=128)
    identifiers: Mapping[str, str] = Field(max_length=64)
    configuration_summary: Mapping[str, Any] = Field(max_length=128)
    usage_summary: Mapping[str, Any] = Field(max_length=128)
    capability_hints: tuple[str, ...] = Field(max_length=64)
    identity_hints: tuple[Mapping[str, Any], ...] = Field(max_length=64)
    relationship_hints: tuple[Mapping[str, Any], ...] = Field(max_length=128)
    evidence_reference: str = Field(min_length=1, max_length=255)
    evidence_hash: str = Field(min_length=64, max_length=64)
    observed_at: datetime
    confidence: float = Field(ge=0.0, le=1.0)
    freshness: ObservationFreshness
    verification_state: FactVerificationState
    source_trust: SourceTrust
    collection_scope: Mapping[str, Any] = Field(max_length=128)
    evidence_mode: EvidenceMode
    evidence_mutability: EvidenceMutability
    contradiction_state: ContradictionState
    contradiction_references: tuple[str, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def enforce_canonical_privacy_boundary(self) -> "PathNativeSignal":
        forbidden_keys = {
            "source_code",
            "file_content",
            "tool_arguments",
            "tool_result",
            "browser_history",
            "page_body",
            "database_row",
            "vector_content",
        }
        pending: list[object] = [
            self.normalized_signal,
            self.configuration_summary,
            self.usage_summary,
            self.identity_hints,
            self.relationship_hints,
            self.collection_scope,
        ]
        while pending:
            value = pending.pop()
            if isinstance(value, Mapping):
                for key, nested in value.items():
                    if key.casefold() in forbidden_keys:
                        raise ValueError(
                            "path-native discovery accepts metadata only"
                        )
                    pending.append(nested)
            elif isinstance(value, (tuple, list)):
                pending.extend(value)
        DiscoveryObservationInput(
            observation_id=self.observation_id,
            scan_id=self.scan_id,
            collector_id="phase2-path-validator",
            collector_type="phase2_path",
            collector_version="1.0.0",
            target_id=self.target_id,
            source_surface="unknown",
            subject_reference=self.subject_reference,
            raw_signal_type=self.raw_signal_type,
            normalized_signal=self.normalized_signal,
            observed_at=self.observed_at,
            asset_candidate_type=self.asset_candidate_type,
            observed_state=self.observed_state,
            identifiers=self.identifiers,
            attributes={},
            configuration_summary=self.configuration_summary,
            usage_summary=self.usage_summary,
            capability_hints=self.capability_hints,
            identity_hints=self.identity_hints,
            relationship_hints=self.relationship_hints,
            evidence_reference=self.evidence_reference,
            evidence_hash=self.evidence_hash,
            signature_status="unverified",
            confidence=self.confidence,
            freshness=self.freshness,
            verification_state=self.verification_state,
            source_trust=self.source_trust,
            collection_scope=self.collection_scope,
            parser_version="phase2-path-v1",
            schema_version="2.0",
            evidence_mode=self.evidence_mode,
            evidence_mutability=self.evidence_mutability,
            contradiction_state=self.contradiction_state,
            contradiction_references=self.contradiction_references,
            sensitivity="metadata",
            redaction_status="not_required",
        )
        return self


class PathNativeCollector:
    collector_type: ClassVar[str]
    collector_id: ClassVar[str]
    source_surface: ClassVar[SourceSurface]
    supported_target: ClassVar[DiscoveryTargetType]
    passive_capabilities: ClassVar[tuple[str, ...]]
    permissions_required: ClassVar[tuple[str, ...]]
    limitations: ClassVar[tuple[str, ...]]

    def __init__(self, *, signals: tuple[PathNativeSignal, ...] = ()) -> None:
        if type(signals) is not tuple or any(
            type(item) is not PathNativeSignal for item in signals
        ):
            raise TypeError("path-native signals must be an exact typed tuple")
        self._signals = signals
        declaration_material = {
            "collector_id": self.collector_id,
            "collector_type": self.collector_type,
            "source_surface": self.source_surface.value,
            "target": self.supported_target.value,
            "version": "1.0.0",
        }
        declaration_hash = hashlib.sha256(
            json.dumps(
                declaration_material, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        self.declaration = CollectorDeclaration(
            collector_id=self.collector_id,
            collector_type=self.collector_type,
            version="1.0.0",
            supported_targets=(self.supported_target,),
            active_capabilities=(),
            passive_capabilities=self.passive_capabilities,
            permissions_required=self.permissions_required,
            sensitive_data_accessed=(),
            health="healthy" if signals else "unknown",
            last_success_at=(
                max(item.observed_at for item in signals) if signals else None
            ),
            last_failure_at=None,
            data_residency="tenant_region",
            control_capability="monitor_only",
            schema_version="2.0",
            limitations=self.limitations,
            declaration_hash=declaration_hash,
        )

    def validate_configuration(self, configuration: Mapping[str, Any]) -> None:
        if not isinstance(configuration, Mapping) or configuration:
            raise ValueError("path-native adapters accept no secret configuration")

    def test_connectivity(self, target: DiscoveryTargetView) -> ConnectivityResult:
        supported = target.target_type == self.supported_target
        return ConnectivityResult(
            reachable=supported,
            status="available" if supported else "unsupported",
            checked_at=datetime.now(timezone.utc),
            safe_message=(
                "Existing Hawk telemetry binding is available"
                if supported
                else "Target surface is unsupported by this adapter"
            ),
        )

    def enumerate_scope(self, target: DiscoveryTargetView) -> tuple[ScopeItem, ...]:
        if target.target_type != self.supported_target:
            return ()
        return (
            ScopeItem(
                scope_id=target.target_id,
                scope_type=target.target_type.value,
                permitted_methods=("metadata",),
            ),
        )

    def _records(self) -> tuple[CollectorRecord, ...]:
        return tuple(
            CollectorRecord(
                record_type=item.raw_signal_type.value,
                source_reference=item.subject_reference or "subject:unknown",
                observed_at=item.observed_at,
                safe_summary=(
                    f"{self.source_surface.value} metadata observation"
                ),
            )
            for item in self._signals
        )

    def collect_inventory(self, scope: ScopeItem) -> tuple[CollectorRecord, ...]:
        del scope
        return self._records()

    def collect_configuration(self, scope: ScopeItem) -> tuple[CollectorRecord, ...]:
        del scope
        return self._records()

    def collect_usage(self, scope: ScopeItem) -> tuple[CollectorRecord, ...]:
        del scope
        return tuple(
            record
            for record, signal in zip(self._records(), self._signals, strict=True)
            if signal.observed_state is ObservedFactState.ACTIVELY_USED
        )

    def collect_identity_hints(self, scope: ScopeItem) -> tuple[CollectorRecord, ...]:
        del scope
        return tuple(
            record
            for record, signal in zip(self._records(), self._signals, strict=True)
            if signal.identity_hints
        )

    def collect_relationship_hints(self, scope: ScopeItem) -> tuple[CollectorRecord, ...]:
        del scope
        return tuple(
            record
            for record, signal in zip(self._records(), self._signals, strict=True)
            if signal.relationship_hints
        )

    def emit_observations(self) -> tuple[DiscoveryObservationInput, ...]:
        return tuple(
            DiscoveryObservationInput(
                observation_id=item.observation_id,
                scan_id=item.scan_id,
                collector_id=self.collector_id,
                collector_type=self.collector_type,
                collector_version="1.0.0",
                target_id=item.target_id,
                source_surface=self.source_surface,
                subject_reference=item.subject_reference,
                raw_signal_type=item.raw_signal_type,
                normalized_signal=item.normalized_signal,
                observed_at=item.observed_at,
                asset_candidate_type=item.asset_candidate_type,
                observed_state=item.observed_state,
                identifiers=item.identifiers,
                attributes={},
                configuration_summary=item.configuration_summary,
                usage_summary=item.usage_summary,
                capability_hints=item.capability_hints,
                identity_hints=item.identity_hints,
                relationship_hints=item.relationship_hints,
                evidence_reference=item.evidence_reference,
                evidence_hash=item.evidence_hash,
                signature_status=(
                    "verified"
                    if item.source_trust is SourceTrust.STRONG
                    else "unverified"
                ),
                confidence=item.confidence,
                freshness=item.freshness,
                verification_state=item.verification_state,
                source_trust=item.source_trust,
                collection_scope=item.collection_scope,
                parser_version="phase2-path-v1",
                schema_version="2.0",
                evidence_mode=item.evidence_mode,
                evidence_mutability=item.evidence_mutability,
                contradiction_state=item.contradiction_state,
                contradiction_references=item.contradiction_references,
                sensitivity="metadata",
                redaction_status="not_required",
            )
            for item in self._signals
        )

    def report_health(self) -> CollectorHealthReport:
        return CollectorHealthReport(
            health="healthy" if self._signals else "unknown",
            checked_at=datetime.now(timezone.utc),
            safe_message=(
                "Bounded telemetry is available"
                if self._signals
                else "No telemetry has been supplied to this default-off adapter"
            ),
        )

    def report_limitations(self) -> tuple[str, ...]:
        return self.limitations


def register_path_native_collectors(
    registry: CollectorRegistry, *, enabled: bool
) -> None:
    if not enabled:
        return
    from app.services.hmair.collectors.browser import BrowserPathCollector
    from app.services.hmair.collectors.endpoint import EndpointPathCollector
    from app.services.hmair.collectors.llm_gateway import LLMGatewayPathCollector
    from app.services.hmair.collectors.mcp_gateway import MCPGatewayPathCollector

    for collector_type, collector in (
        ("phase2_endpoint", EndpointPathCollector()),
        ("phase2_browser", BrowserPathCollector()),
        ("phase2_mcp_gateway", MCPGatewayPathCollector()),
        ("phase2_llm_gateway", LLMGatewayPathCollector()),
    ):
        registry.register(collector_type, collector)


def register_controlled_breadth_collectors(
    registry: CollectorRegistry, *, enabled: bool
) -> None:
    if not enabled:
        return
    from app.services.hmair.collectors.aws_gcp import (
        AWSAIDiscoveryCollector,
        GCPAIDiscoveryCollector,
    )
    from app.services.hmair.collectors.azure import AzureAIDiscoveryCollector
    from app.services.hmair.collectors.data import DataAIDiscoveryCollector
    from app.services.hmair.collectors.network import NetworkAIDiscoveryCollector
    from app.services.hmair.collectors.repository_ci import (
        RepositoryAIDiscoveryCollector,
    )
    from app.services.hmair.collectors.saas_identity import (
        IdentityAIDiscoveryCollector,
        SaaSAIDiscoveryCollector,
    )

    collectors = (
        AzureAIDiscoveryCollector(),
        AWSAIDiscoveryCollector(),
        GCPAIDiscoveryCollector(),
        SaaSAIDiscoveryCollector(),
        IdentityAIDiscoveryCollector(),
        RepositoryAIDiscoveryCollector(),
        NetworkAIDiscoveryCollector(),
        DataAIDiscoveryCollector(),
    )
    for collector in collectors:
        registry.register(collector.collector_type, collector)


def register_h4_profile_collectors(
    registry: CollectorRegistry, *, enabled: bool
) -> None:
    """Register declarations for the closed H4 catalog.

    Registration is deliberately not evidence-bearing.  Default instances
    contain no observations and therefore report unknown health.
    """

    if not enabled:
        return
    from app.services.hmair.collectors.h4_catalog import H4_COLLECTOR_PROFILES
    from app.services.hmair.collectors.h4_metadata import H4MetadataCollector

    for profile in H4_COLLECTOR_PROFILES:
        collector = H4MetadataCollector(profile=profile)
        registry.register(collector.collector_type, collector)


__all__ = [
    "PathNativeCollector",
    "PathNativeSignal",
    "register_controlled_breadth_collectors",
    "register_h4_profile_collectors",
    "register_path_native_collectors",
]
