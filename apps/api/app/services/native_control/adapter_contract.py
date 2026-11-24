from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import math
import re
from typing import Any, Mapping, Protocol, runtime_checkable

from app.core.control_engine.authorization import AuthorizationRequest, AuthorizationResponse
from app.services.native_control.contracts import (
    AssuranceLevel,
    ActionClass,
    CapabilityClaim,
    CapabilityDimension,
    CapabilityLevel,
    ControlMethod,
    ControlPointHealth,
    DegradationMode,
    DeploymentAcceptanceState,
    HealthState,
    ProviderRuntimeContext,
    ProviderVersionState,
    RuntimeLocation,
    SecurityProperties,
    VerificationStatus,
)
from app.services.native_control.versioning import version_in_verified_range


class AdapterContractError(ValueError):
    """A provider adapter attempted to cross a Hawk-owned trust boundary."""


class AdapterMaturity(str, Enum):
    REFERENCE = "reference"
    EXPERIMENTAL = "experimental"
    PRODUCTION = "production"


class DeploymentFamily(str, Enum):
    BROWSER = "browser"
    ENDPOINT = "endpoint"
    RUNTIME = "runtime"
    SAAS_API = "saas_api"


class ProviderTransport(str, Enum):
    HTTP_CALLBACK = "http_callback"
    LOCAL_HELPER = "local_helper"
    SDK_IN_PROCESS = "sdk_in_process"
    RUNTIME_SIDECAR = "runtime_sidecar"
    MIDDLEWARE = "middleware"
    GATEWAY = "gateway"
    BROWSER_MESSAGE = "browser_message"
    ENDPOINT_IPC = "endpoint_ipc"


class AdapterResolutionState(str, Enum):
    EXACT_MATCH = "exact_match"
    SUPPORTED_COMPATIBLE = "supported_compatible"
    UNVERIFIED_NEWER = "unverified_newer"
    UNSUPPORTED_OLDER = "unsupported_older"
    BROKEN = "broken"
    AMBIGUOUS = "ambiguous"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class EvidenceQuality(str, Enum):
    NONE = "none"
    PROVIDER_REPORTED = "provider_reported"
    HAWK_OBSERVED = "hawk_observed"
    HAWK_EXTERNALLY_VERIFIED = "hawk_externally_verified"


class AdapterErrorCode(str, Enum):
    UNSUPPORTED_PROVIDER_VERSION = "unsupported_provider_version"
    INSTALLATION_CONFLICT = "installation_conflict"
    AUTHENTICATION_FAILURE = "authentication_failure"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    EVENT_SCHEMA_UNSUPPORTED = "event_schema_unsupported"
    CONTROL_TIMEOUT = "control_timeout"
    CONFIG_TAMPERED = "config_tampered"
    INTEGRATION_UNHEALTHY = "integration_unhealthy"
    REMOTE_POLICY_REQUIRED = "remote_policy_required"
    ENFORCEMENT_SEMANTIC_UNAVAILABLE = "enforcement_semantic_unavailable"


class AdapterError(RuntimeError):
    def __init__(self, code: AdapterErrorCode, *, safe_diagnostic: str = "") -> None:
        super().__init__(code.value)
        self.code = code
        self.safe_diagnostic = str(safe_diagnostic or "")[:256]


@dataclass(frozen=True, slots=True)
class TimeoutBudget:
    provider_timeout_ms: int
    hawk_processing_budget_ms: int
    response_deadline_ms: int

    def __post_init__(self) -> None:
        values = (self.provider_timeout_ms, self.hawk_processing_budget_ms, self.response_deadline_ms)
        if any(not isinstance(value, int) or value <= 0 or value > 60_000 for value in values):
            raise ValueError("timeout_budget_invalid")
        if self.provider_timeout_ms + self.hawk_processing_budget_ms > self.response_deadline_ms:
            raise ValueError("timeout_budget_exceeds_response_deadline")

    @property
    def remaining_network_budget_ms(self) -> int:
        return self.response_deadline_ms - self.provider_timeout_ms - self.hawk_processing_budget_ms


@dataclass(frozen=True, slots=True)
class SecretReference:
    value: str

    def __post_init__(self) -> None:
        token = str(self.value or "").strip()
        allowed = ("kms://", "hsm://", "pkcs11://", "secret://", "vault://")
        if not token.startswith(allowed) or len(token) > 512 or any(char.isspace() for char in token):
            raise ValueError("secret_reference_must_be_opaque")

    @property
    def scheme(self) -> str:
        return self.value.split("://", 1)[0]


@dataclass(frozen=True, slots=True)
class AdapterDescriptor:
    adapter_id: str
    provider_family: str
    product_family: str
    adapter_version: str
    deployment_families_supported: tuple[DeploymentFamily, ...]
    enforcement_methods_supported: tuple[ControlMethod, ...]
    event_schema_version: str
    minimum_hawk_version: str
    maturity: AdapterMaturity
    description: str

    def __post_init__(self) -> None:
        for name in (
            "adapter_id",
            "provider_family",
            "product_family",
            "adapter_version",
            "event_schema_version",
            "minimum_hawk_version",
            "description",
        ):
            if not str(getattr(self, name) or "").strip():
                raise ValueError(f"adapter_descriptor_{name}_required")
        if not self.deployment_families_supported:
            raise ValueError("adapter_descriptor_deployment_family_required")
        if not self.enforcement_methods_supported:
            raise ValueError("adapter_descriptor_enforcement_method_required")
        if any(not isinstance(value, DeploymentFamily) for value in self.deployment_families_supported):
            raise ValueError("adapter_descriptor_deployment_family_invalid")
        if any(not isinstance(value, ControlMethod) for value in self.enforcement_methods_supported):
            raise ValueError("adapter_descriptor_enforcement_method_invalid")


@dataclass(frozen=True, slots=True)
class StructuredBlindSpot:
    id: str
    control_dimension: CapabilityDimension
    scope: str
    condition: str
    impact: str
    detection_method: str
    mitigation: str
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        values = (
            self.id,
            self.scope,
            self.condition,
            self.impact,
            self.detection_method,
            self.mitigation,
        )
        if any(not str(value or "").strip() for value in values):
            raise ValueError("blind_spot_fields_required")
        if not isinstance(self.control_dimension, CapabilityDimension):
            raise ValueError("blind_spot_control_dimension_invalid")


@dataclass(frozen=True, slots=True)
class EventSemantics:
    pre_execution_events: tuple[str, ...] = ()
    post_execution_events: tuple[str, ...] = ()
    normalized_fields: tuple[str, ...] = ()
    synchronous_decision_mechanism: str | None = None
    ordering_guaranteed: bool = False
    runs_before_untrusted_mutators: bool = False
    runs_after_untrusted_mutators: bool = False


@dataclass(frozen=True, slots=True)
class SelectionCharacteristics:
    latency_cost: int
    operational_complexity: int
    required_privilege: int
    privacy_impact: int
    deployment_friction: int

    def total(self) -> int:
        values = (
            self.latency_cost,
            self.operational_complexity,
            self.required_privilege,
            self.privacy_impact,
            self.deployment_friction,
        )
        if any(value < 0 or value > 100 for value in values):
            raise ValueError("selection_characteristic_out_of_range")
        return sum(values)


def _bounded_contract_value(value: str, *, field_name: str, maximum: int = 1024) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum or any(character in text for character in "\r\n\x00"):
        raise ValueError(f"{field_name}_invalid")
    return text


_UNORDERED_CONTRACT_FIELDS = frozenset(
    {
        "evidence",
        "evidence_refs",
        "exact_verified_versions",
        "failure_modes",
        "known_blind_spots",
        "required_account_modes",
        "required_permissions",
        "required_tenant_modes",
        "reviewed_evidence_refs",
        "supported_action_classes",
        "supported_control_methods",
        "supported_degradation_modes",
        "supported_deployment_families",
        "supported_installation_modes",
        "supported_lifecycle_events",
        "supported_runtimes",
        "supported_runtime_locations",
    }
)


def _canonical_contract_json(value: Any, *, field_name: str | None = None) -> Any:
    """Return strictly JSON-native contract material with stable set semantics."""

    if isinstance(value, Enum):
        return value.value
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError("contract_material_non_finite_float")
        return value
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: _canonical_contract_json(
                getattr(value, item.name),
                field_name=item.name,
            )
            for item in fields(value)
        }
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = str(
                key.value if isinstance(key, Enum) else key
            )
            if normalized_key in normalized:
                raise TypeError("contract_material_duplicate_mapping_key")
            normalized[normalized_key] = _canonical_contract_json(
                item,
                field_name=normalized_key,
            )
        return {key: normalized[key] for key in sorted(normalized)}
    if isinstance(value, (list, tuple, set, frozenset)):
        normalized_items = [
            _canonical_contract_json(item)
            for item in value
        ]
        if isinstance(value, (set, frozenset)) or field_name in _UNORDERED_CONTRACT_FIELDS:
            return sorted(
                normalized_items,
                key=lambda item: json.dumps(
                    item,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ),
            )
        return normalized_items
    raise TypeError(f"contract_material_non_json:{type(value).__name__}")


def _strict_contract_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _is_real_acceptance(state: DeploymentAcceptanceState) -> bool:
    return state in {
        DeploymentAcceptanceState.REAL_BINARY_ACCEPTED,
        DeploymentAcceptanceState.REAL_ENTERPRISE_TENANT_ACCEPTED,
        DeploymentAcceptanceState.REAL_CLOUD_RUNTIME_ACCEPTED,
    }


@dataclass(frozen=True, slots=True)
class DeploymentAcceptanceResult:
    """Immutable deployed acceptance evidence, separate from reviewed contract claims."""

    state: DeploymentAcceptanceState
    environment: str
    provider: str
    product: str
    runtime: str
    action_classes: tuple[ActionClass, ...]
    control_method: ControlMethod
    provider_version: str
    adapter_version: str
    contract_fingerprint: str
    acceptance_run_ref: str
    evidence_refs: tuple[str, ...]
    lifecycle_events: tuple[str, ...]
    allow_verified: bool
    block_verified: bool
    protected_callback_not_executed: bool
    deployment_reference: str = "unknown"
    model_provider: str = "unknown"
    model: str = "unknown"
    route_identity: str = "unknown"
    deployment_identity: str = "unknown"

    def __post_init__(self) -> None:
        if not isinstance(self.state, DeploymentAcceptanceState):
            raise ValueError("deployment_acceptance_state_invalid")
        if not isinstance(self.control_method, ControlMethod):
            raise ValueError("deployment_acceptance_control_method_invalid")
        for field_name in (
            "environment",
            "provider",
            "product",
            "runtime",
            "provider_version",
            "adapter_version",
            "acceptance_run_ref",
            "deployment_reference",
            "model_provider",
            "model",
            "route_identity",
            "deployment_identity",
        ):
            _bounded_contract_value(getattr(self, field_name), field_name=field_name)
        if (
            not isinstance(self.action_classes, tuple)
            or not self.action_classes
            or any(not isinstance(value, ActionClass) for value in self.action_classes)
            or len(set(self.action_classes)) != len(self.action_classes)
        ):
            raise ValueError("deployment_acceptance_action_classes_invalid")
        if _is_real_acceptance(self.state) and ActionClass.UNKNOWN_ACTION in self.action_classes:
            raise ValueError("real_deployment_acceptance_action_classes_unknown")
        if (
            not isinstance(self.evidence_refs, tuple)
            or len(self.evidence_refs) > 32
            or any(not isinstance(value, str) for value in self.evidence_refs)
            or len(set(self.evidence_refs)) != len(self.evidence_refs)
            or any(
                not _bounded_contract_value(value, field_name="evidence_reference")
                for value in self.evidence_refs
            )
        ):
            raise ValueError("deployment_acceptance_evidence_invalid")
        if (
            not isinstance(self.lifecycle_events, tuple)
            or len(self.lifecycle_events) > 32
            or any(not isinstance(value, str) for value in self.lifecycle_events)
            or len(set(self.lifecycle_events)) != len(self.lifecycle_events)
            or any(
                not _bounded_contract_value(value, field_name="lifecycle_event", maximum=128)
                for value in self.lifecycle_events
            )
        ):
            raise ValueError("deployment_acceptance_lifecycle_invalid")
        if any(
            not isinstance(value, bool)
            for value in (
                self.allow_verified,
                self.block_verified,
                self.protected_callback_not_executed,
            )
        ):
            raise ValueError("deployment_acceptance_outcomes_invalid")
        if _is_real_acceptance(self.state):
            if any(
                getattr(self, field_name).strip().lower() == "unknown"
                for field_name in (
                    "model_provider",
                    "model",
                    "route_identity",
                    "deployment_identity",
                )
            ):
                raise ValueError("real_deployment_acceptance_scope_required")
            if (
                not re.fullmatch(r"[0-9a-f]{64}", self.contract_fingerprint)
                or not self.evidence_refs
                or not self.allow_verified
                or not self.block_verified
                or not self.protected_callback_not_executed
                or self.deployment_reference == "unknown"
            ):
                raise ValueError("real_deployment_acceptance_evidence_required")
        elif self.contract_fingerprint not in {"", "unknown"} and not re.fullmatch(
            r"[0-9a-f]{64}", self.contract_fingerprint
        ):
            raise ValueError("deployment_acceptance_contract_fingerprint_invalid")

    @property
    def is_real_acceptance(self) -> bool:
        return _is_real_acceptance(self.state)

    @classmethod
    def not_tested(cls) -> "DeploymentAcceptanceResult":
        return cls(
            state=DeploymentAcceptanceState.NOT_TESTED,
            environment="unknown",
            provider="unknown",
            product="unknown",
            runtime="unknown",
            action_classes=(ActionClass.UNKNOWN_ACTION,),
            control_method=ControlMethod.OBSERVE_ONLY,
            provider_version="unknown",
            adapter_version="unknown",
            contract_fingerprint="unknown",
            acceptance_run_ref="unknown",
            evidence_refs=(),
            lifecycle_events=(),
            allow_verified=False,
            block_verified=False,
            protected_callback_not_executed=False,
            deployment_reference="unknown",
            model_provider="unknown",
            model="unknown",
            route_identity="unknown",
            deployment_identity="unknown",
        )


@dataclass(frozen=True, slots=True)
class CapabilityManifest:
    schema_version: str
    descriptor_id: str
    provider: str
    product: str
    provider_version_min: str
    provider_version_max: str
    exact_verified_versions: tuple[str, ...]
    adapter_version: str
    verification_status: VerificationStatus
    verified_at: str | None
    source_reference: str
    capabilities: dict[CapabilityDimension, CapabilityClaim]
    security_properties: SecurityProperties
    required_permissions: tuple[str, ...]
    event_semantics: EventSemantics
    known_blind_spots: tuple[StructuredBlindSpot, ...]
    failure_modes: tuple[str, ...]
    supported_installation_modes: tuple[str, ...]
    supported_degradation_modes: tuple[DegradationMode, ...]
    execution_evidence_quality: EvidenceQuality
    selection_characteristics: SelectionCharacteristics
    contract_schema_version: str = "provider-control-contract/1.0"
    supported_action_classes: tuple[ActionClass, ...] = (ActionClass.UNKNOWN_ACTION,)
    supported_runtime_locations: tuple[RuntimeLocation, ...] = (RuntimeLocation.UNKNOWN,)
    supported_deployment_families: tuple[DeploymentFamily, ...] = ()
    supported_runtimes: tuple[str, ...] = ()
    supported_control_methods: tuple[ControlMethod, ...] = ()
    supported_lifecycle_events: tuple[str, ...] = ()
    required_account_modes: tuple[str, ...] = ()
    required_tenant_modes: tuple[str, ...] = ()
    supports_action_mutation: bool = False
    supports_approval_pause: bool = False
    retry_semantics: str = "unknown"
    failure_semantics: str = "unknown"
    privacy_profile: str = "unknown"
    reviewed_by: str | None = None
    reviewed_at: str | None = None
    reviewed_evidence_refs: tuple[str, ...] = ()
    deployment_acceptance: DeploymentAcceptanceResult = field(
        default_factory=DeploymentAcceptanceResult.not_tested
    )

    @property
    def is_reviewed_contract(self) -> bool:
        return (
            self.contract_schema_version == "provider-control-contract/1.0"
            and bool(str(self.reviewed_by or "").strip())
            and bool(str(self.reviewed_at or "").strip())
            and bool(self.reviewed_evidence_refs)
        )

    def canonical_review_material(self) -> dict[str, Any]:
        """Stable reviewed material; deployed acceptance is deliberately excluded.

        An acceptance record binds this digest. Including acceptance inside the
        digest would create a circular self-assertion and let a static manifest
        claim it was deployed.
        """

        return _canonical_contract_json({
            "contract_schema_version": self.contract_schema_version,
            "schema_version": self.schema_version,
            "descriptor_id": self.descriptor_id,
            "provider": self.provider,
            "product": self.product,
            "provider_version_min": self.provider_version_min,
            "provider_version_max": self.provider_version_max,
            "exact_verified_versions": self.exact_verified_versions,
            "adapter_version": self.adapter_version,
            "verification_status": self.verification_status.value,
            "verified_at": self.verified_at,
            "source_reference": self.source_reference,
            "capabilities": self.capabilities,
            "security_properties": self.security_properties,
            "required_permissions": self.required_permissions,
            "event_semantics": self.event_semantics,
            "known_blind_spots": self.known_blind_spots,
            "failure_modes": self.failure_modes,
            "supported_installation_modes": self.supported_installation_modes,
            "supported_degradation_modes": self.supported_degradation_modes,
            "execution_evidence_quality": self.execution_evidence_quality.value,
            "selection_characteristics": self.selection_characteristics,
            "supported_action_classes": self.supported_action_classes,
            "supported_runtime_locations": self.supported_runtime_locations,
            "supported_deployment_families": self.supported_deployment_families,
            "supported_runtimes": self.supported_runtimes,
            "supported_control_methods": self.supported_control_methods,
            "supported_lifecycle_events": self.supported_lifecycle_events,
            "required_account_modes": self.required_account_modes,
            "required_tenant_modes": self.required_tenant_modes,
            "supports_action_mutation": self.supports_action_mutation,
            "supports_approval_pause": self.supports_approval_pause,
            "retry_semantics": self.retry_semantics,
            "failure_semantics": self.failure_semantics,
            "privacy_profile": self.privacy_profile,
            "reviewed_by": self.reviewed_by,
            "reviewed_at": self.reviewed_at,
            "reviewed_evidence_refs": self.reviewed_evidence_refs,
        })

    @property
    def contract_fingerprint(self) -> str:
        return _strict_contract_hash(self.canonical_review_material())

    def provider_version_state(self, provider_version: str) -> ProviderVersionState:
        value = str(provider_version or "").strip()
        if not value or value.lower() == "unknown":
            return ProviderVersionState.UNKNOWN
        if self.verification_status is VerificationStatus.BROKEN:
            return ProviderVersionState.BROKEN
        if value in self.exact_verified_versions:
            return ProviderVersionState.EXACT_TESTED
        if version_in_verified_range(value, self.provider_version_min, self.provider_version_max):
            return ProviderVersionState.VERIFIED_COMPATIBLE_RANGE

        numeric = re.compile(r"^v?(\d+(?:\.\d+)*)$")
        current = numeric.fullmatch(value)
        minimum = numeric.fullmatch(str(self.provider_version_min or "").strip())
        maximum = numeric.fullmatch(str(self.provider_version_max or "").strip())
        if current and minimum and maximum:
            current_parts = tuple(int(part) for part in current.group(1).split("."))
            minimum_parts = tuple(int(part) for part in minimum.group(1).split("."))
            maximum_parts = tuple(int(part) for part in maximum.group(1).split("."))
            if current_parts < minimum_parts:
                return ProviderVersionState.UNSUPPORTED_OLDER
            if current_parts > maximum_parts:
                return ProviderVersionState.UNVERIFIED_NEWER
        return ProviderVersionState.UNSUPPORTED

    def enforcement_ineligibility_reasons(
        self,
        runtime_context: ProviderRuntimeContext | None,
        version_state: ProviderVersionState,
        *,
        require_deployment_acceptance: bool = True,
    ) -> tuple[str, ...]:
        """Return static-contract eligibility failures for a resolved runtime.

        A shipped adapter may prove its reviewed contract, but it cannot prove
        that a particular customer integration exercised that contract.  The
        registry therefore keeps the historical deployment-acceptance check by
        default.  The authenticated callback bridge can opt out only while it
        composes this static result with the immutable, tenant-bound deployed
        acceptance record held by the control plane.
        """
        reasons: list[str] = []
        if version_state not in {
            ProviderVersionState.EXACT_TESTED,
            ProviderVersionState.VERIFIED_COMPATIBLE_RANGE,
        }:
            reasons.append(f"provider_version_{version_state.value}")
        if self.verification_status is not VerificationStatus.VERIFIED:
            reasons.append("contract_not_verified")
        if not self.is_reviewed_contract:
            reasons.append("contract_review_missing")
        if runtime_context is None:
            reasons.append("runtime_context_missing")
        else:
            if not runtime_context.is_resolved_for_enforcement:
                reasons.append("runtime_context_unresolved")
            if runtime_context.provider != self.provider or runtime_context.product != self.product:
                reasons.append("runtime_context_provider_product_mismatch")
            if runtime_context.action_class not in self.supported_action_classes:
                reasons.append("action_class_not_reviewed")
            if runtime_context.runtime_location not in self.supported_runtime_locations:
                reasons.append("runtime_location_not_reviewed")
            if runtime_context.runtime not in self.supported_runtimes:
                reasons.append("runtime_not_reviewed")
            if runtime_context.control_method not in self.supported_control_methods:
                reasons.append("control_method_not_reviewed")
            if runtime_context.adapter_version != self.adapter_version:
                reasons.append("runtime_context_adapter_version_mismatch")
            if runtime_context.lifecycle_stage not in self.supported_lifecycle_events:
                reasons.append("lifecycle_event_not_reviewed")
            if (
                self.required_account_modes
                and runtime_context.account_mode not in self.required_account_modes
            ):
                reasons.append("account_mode_not_reviewed")
            if (
                self.required_tenant_modes
                and runtime_context.tenant_mode not in self.required_tenant_modes
            ):
                reasons.append("tenant_mode_not_reviewed")
        if not self.supported_deployment_families:
            reasons.append("deployment_family_not_reviewed")
        acceptance = self.deployment_acceptance
        if require_deployment_acceptance and not acceptance.is_real_acceptance:
            reasons.append("deployment_acceptance_not_real")
        elif acceptance.is_real_acceptance:
            if acceptance.contract_fingerprint != self.contract_fingerprint:
                reasons.append("deployment_acceptance_contract_drift")
            if runtime_context is not None:
                if (
                    acceptance.provider != runtime_context.provider
                    or acceptance.product != runtime_context.product
                    or acceptance.runtime != runtime_context.runtime
                    or acceptance.provider_version != runtime_context.provider_version
                ):
                    reasons.append("deployment_acceptance_runtime_mismatch")
                if acceptance.environment != runtime_context.environment:
                    reasons.append("deployment_acceptance_environment_mismatch")
                if acceptance.deployment_reference != runtime_context.deployment_reference:
                    reasons.append("deployment_acceptance_deployment_mismatch")
                if acceptance.model_provider != runtime_context.model_provider:
                    reasons.append("deployment_acceptance_model_provider_mismatch")
                if acceptance.model != runtime_context.model:
                    reasons.append("deployment_acceptance_model_mismatch")
                if acceptance.route_identity != runtime_context.route_identity:
                    reasons.append("deployment_acceptance_route_identity_mismatch")
                if acceptance.deployment_identity != runtime_context.deployment_identity:
                    reasons.append("deployment_acceptance_deployment_identity_mismatch")
                if acceptance.adapter_version != runtime_context.adapter_version:
                    reasons.append("deployment_acceptance_adapter_version_mismatch")
                if acceptance.control_method is not runtime_context.control_method:
                    reasons.append("deployment_acceptance_control_method_mismatch")
                if runtime_context.action_class not in acceptance.action_classes:
                    reasons.append("deployment_acceptance_action_class_mismatch")
                if runtime_context.lifecycle_stage not in acceptance.lifecycle_events:
                    reasons.append("deployment_acceptance_lifecycle_mismatch")
                accepted_locations = {
                    DeploymentAcceptanceState.REAL_BINARY_ACCEPTED: {
                        RuntimeLocation.LOCAL_ENDPOINT,
                    },
                    DeploymentAcceptanceState.REAL_ENTERPRISE_TENANT_ACCEPTED: {
                        RuntimeLocation.PROVIDER_HOSTED,
                        RuntimeLocation.REMOTE_AGENT,
                    },
                    DeploymentAcceptanceState.REAL_CLOUD_RUNTIME_ACCEPTED: {
                        RuntimeLocation.CUSTOMER_RUNTIME,
                        RuntimeLocation.CUSTOMER_CLOUD,
                        RuntimeLocation.MIXED,
                    },
                }
                if runtime_context.runtime_location not in accepted_locations.get(acceptance.state, set()):
                    reasons.append("deployment_acceptance_state_location_mismatch")
        return tuple(dict.fromkeys(reasons))


@dataclass(frozen=True, slots=True)
class InstallationPlan:
    adapter_id: str
    files_or_settings_affected: tuple[str, ...]
    permissions_required: tuple[str, ...]
    existing_configuration_detected: bool
    hawk_owned_fragment_key: str
    rollback_strategy: str
    restart_required: bool
    estimated_coverage_effect: tuple[str, ...]
    known_risks: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ControlConfigFingerprint:
    integration_instance_id: str
    provider: str
    config_location: str
    hawk_owned_content_hash: str
    surrounding_context_hash: str
    ordering: str
    callback_identity: str
    helper_identity: str
    event_subscriptions: tuple[str, ...]
    blocking_semantics: str
    version: str
    last_verified: str


@dataclass(frozen=True, slots=True)
class InstallationResult:
    configuration: dict[str, Any]
    fingerprint: ControlConfigFingerprint


@dataclass(frozen=True, slots=True)
class NativeControlEvent:
    tenant_id: str
    integration_instance_id: str
    provider: str
    product: str
    raw_provider_event_type: str
    provider_event_id: str
    provider_version: str
    adapter_version: str
    lifecycle_stage: str
    actor: dict[str, Any]
    session: dict[str, Any]
    runtime: dict[str, Any]
    tool: dict[str, Any]
    model: dict[str, Any]
    mcp: dict[str, Any]
    action: dict[str, Any]
    target: dict[str, Any]
    destination: dict[str, Any]
    side_effect_class: str
    persistence: dict[str, Any]
    provider_correlation: dict[str, Any]
    timing: dict[str, Any]
    integrity: dict[str, Any]
    policy_snapshot_id: str
    policy_profile: dict[str, Any]

    def to_authorization_request(self) -> AuthorizationRequest:
        parameter_hash = str(self.action.get("parameter_hash") or "unknown")
        target_hash = str(self.target.get("resource_hash") or "unknown")
        destination_hash = str(self.destination.get("destination_hash") or "unknown")
        actor_id = str(self.actor.get("identity_id") or "unknown")
        authority_type = str(self.actor.get("authority_type") or "unknown")
        authority_source = str(self.actor.get("authority_source") or "unknown")
        return AuthorizationRequest(
            tenant_id=self.tenant_id,
            environment=str(self.runtime.get("environment") or "unknown"),
            collector_id=f"native-adapter:{self.integration_instance_id}",
            action_id=self.provider_event_id,
            chain_id=str(self.provider_correlation.get("chain_id") or self.provider_event_id),
            surface="runtime_control",
            actor={
                "identity_id": actor_id,
                "identity_type": str(self.actor.get("identity_type") or "unknown"),
                "session_id": str(self.session.get("session_id") or "unknown"),
            },
            authority={
                "verified": authority_type != "unknown" and authority_source != "unknown",
                "authority_type": authority_type,
                "authority_source": authority_source,
            },
            runtime={
                **dict(self.runtime),
                "integration_instance_id": self.integration_instance_id,
                "adapter_version": self.adapter_version,
            },
            purpose={},
            action={
                "action_type": str(self.action.get("action_type") or "unknown"),
                "action_class": str(self.action.get("action_class") or "unknown"),
                "risk_level": "unknown",
            },
            tool={
                "name": str(self.tool.get("name") or "unknown"),
                "version": str(self.tool.get("version") or "unknown"),
                "fingerprint_id": str(self.tool.get("fingerprint_id") or "unknown"),
            },
            parameters={"parameter_hash": parameter_hash},
            target={
                "resource": str(self.target.get("resource") or "unknown"),
                "resource_hash": target_hash,
                "destination": str(self.destination.get("destination") or "unknown"),
                "destination_hash": destination_hash,
            },
            data_context={
                # Exact endpoint envelopes carry only pre-normalized hashes
                # and classifications.  Preserve that bounded context for
                # policy without retaining raw provider arguments/results.
                "prompt_hash": str(self.action.get("prompt_hash") or "unknown"),
                "response_hash": str(self.action.get("response_hash") or "unknown"),
                "classifications": list(self.action.get("data_classifications") or []),
                "execution_evidence_quality": str(
                    self.action.get("evidence_quality") or "none"
                ),
                "execution_status": str(self.action.get("execution_status") or "unknown"),
                "failure_hash": str(self.action.get("failure_hash") or "unknown"),
            },
            approval_context={
                "approval_action_hash": str(
                    self.action.get("approval_action_hash") or "unknown"
                ),
            },
            side_effect_context={
                "side_effect_class": self.side_effect_class,
                "persistent_side_effect": bool(self.persistence.get("persistent_side_effect")),
            },
            discovery_context={
                "provider": self.provider,
                "product": self.product,
                "provider_version": self.provider_version,
                "adapter_version": self.adapter_version,
                "model": str(self.model.get("name") or "unknown"),
                "mcp_server_id": str(self.mcp.get("server_id") or "unknown"),
                # Provider callback metadata cannot establish that a Hawk AI
                # Asset or target is approved. Discovery/asset resolution may
                # enrich this later through its own trusted reference; absent
                # that evidence, preserve the fail-safe Unknown state.
                "asset_status": "unknown",
                "raw_provider_event_type": self.raw_provider_event_type,
                "tool_class": str(self.action.get("action_class") or "unknown"),
            },
            policy_snapshot_id=self.policy_snapshot_id,
            policy_profile=dict(self.policy_profile),
            path_evidence={
                "collector_inline_capable": self.lifecycle_stage.startswith("before_"),
                "inline_pre_execution": self.lifecycle_stage.startswith("before_"),
                "native_control_route_binding": {
                    # Adapter normalization has no authority to promote its
                    # own callback route.  The authenticated router sets this
                    # only after the exact adapter resolution and its runtime
                    # eligibility checks have passed.
                    "verified": self.policy_profile.get("native_route_verified") is True,
                    # Provider event content alone is never authority for
                    # route binding.
                    "source": "authenticated_native_adapter",
                    "integration_instance_ids": [self.integration_instance_id],
                    "allowed_methods": [
                        str(self.runtime.get("integration_method") or "unknown")
                    ],
                },
            },
        )


@dataclass(frozen=True, slots=True)
class AdapterPipelineContext:
    tenant_id: str
    integration_instance_id: str
    credential_id: str
    environment: str
    provider_event_id: str
    correlation_id: str
    session_id: str
    chain_id: str
    provider_version: str
    policy_snapshot_id: str
    policy_profile: dict[str, Any]
    resolved_actor: dict[str, str]
    transport: ProviderTransport
    transport_authenticated: bool
    signature_valid: bool
    nonce: str
    received_at: str

    @classmethod
    def reference(
        cls,
        *,
        tenant_id: str,
        integration_instance_id: str,
        provider_event_id: str,
        policy_profile: dict[str, Any] | None = None,
    ) -> "AdapterPipelineContext":
        return cls(
            tenant_id=tenant_id,
            integration_instance_id=integration_instance_id,
            credential_id="reference-credential",
            environment="test",
            provider_event_id=provider_event_id,
            correlation_id=f"correlation:{provider_event_id}",
            session_id="reference-session",
            chain_id=f"chain:{provider_event_id}",
            provider_version="1.0.0",
            policy_snapshot_id="reference-policy",
            policy_profile=dict(policy_profile or {"base_decision": "allow", "dependencies_healthy": True}),
            resolved_actor={
                "identity_id": "reference-user",
                "identity_type": "human",
                "authority_type": "authenticated_user",
                "authority_source": "reference_directory",
            },
            transport=ProviderTransport.SDK_IN_PROCESS,
            transport_authenticated=True,
            signature_valid=True,
            nonce=f"nonce:{provider_event_id}",
            received_at=datetime.now(timezone.utc).isoformat(),
        )


@runtime_checkable
class NativeControlAdapter(Protocol):
    descriptor: AdapterDescriptor
    manifest: CapabilityManifest

    def normalize_event(
        self, raw_payload: Mapping[str, Any], context: AdapterPipelineContext
    ) -> NativeControlEvent: ...

    def format_decision_response(self, response: AuthorizationResponse) -> dict[str, Any]: ...

    def limitations(self) -> tuple[StructuredBlindSpot, ...]: ...


@runtime_checkable
class DetectableControlAdapter(Protocol):
    def detect_environment(self) -> dict[str, Any]: ...
    def validate_environment(self, detected: Mapping[str, Any]) -> bool: ...


@runtime_checkable
class InstallableControlAdapter(Protocol):
    def install_plan(self, existing_configuration: Mapping[str, Any]) -> InstallationPlan: ...
    def install(self, plan: InstallationPlan, existing_configuration: Mapping[str, Any]) -> InstallationResult: ...
    def validate_installation(self, configuration: Mapping[str, Any]) -> bool: ...
    def uninstall(self, configuration: Mapping[str, Any]) -> dict[str, Any]: ...


@runtime_checkable
class ManagedConfigAdapter(Protocol):
    def configure(self, configuration: Mapping[str, Any]) -> InstallationResult: ...
    def verify_integrity(self, configuration: Mapping[str, Any]) -> bool: ...
    def detect_drift(self, configuration: Mapping[str, Any]) -> tuple[str, ...]: ...


@runtime_checkable
class SynchronousBlockingAdapter(Protocol):
    def decision_deadline_ms(self) -> int: ...
    def timeout_budget(self) -> TimeoutBudget: ...


@runtime_checkable
class PostExecutionAdapter(Protocol):
    def capture_execution_result(self, provider_result: Mapping[str, Any]) -> dict[str, Any]: ...


@runtime_checkable
class ApprovalAwareAdapter(Protocol):
    def format_approval_pause(self, response: AuthorizationResponse) -> dict[str, Any]: ...


@runtime_checkable
class ToolAwareAdapter(Protocol):
    def supported_tool_events(self) -> tuple[str, ...]: ...


@runtime_checkable
class McpAwareAdapter(Protocol):
    def supported_mcp_events(self) -> tuple[str, ...]: ...


@runtime_checkable
class CommandAwareAdapter(Protocol):
    def supported_command_events(self) -> tuple[str, ...]: ...


@runtime_checkable
class FileAwareAdapter(Protocol):
    def supported_file_events(self) -> tuple[str, ...]: ...


@runtime_checkable
class NetworkAwareAdapter(Protocol):
    def supported_network_events(self) -> tuple[str, ...]: ...


@runtime_checkable
class ContainmentAdapter(Protocol):
    def bounded_containment_actions(self) -> tuple[str, ...]: ...


@runtime_checkable
class LocalPolicyAdapter(Protocol):
    def local_policy_schema_version(self) -> str: ...


@runtime_checkable
class ProviderSignedEventAdapter(Protocol):
    def provider_signature_algorithms(self) -> tuple[str, ...]: ...


@runtime_checkable
class HealthAwareAdapter(Protocol):
    def health(self) -> ControlPointHealth: ...


@runtime_checkable
class VersionAwareAdapter(Protocol):
    def supported_versions(self) -> tuple[str, str]: ...


@dataclass(frozen=True, slots=True)
class ValidationTestResult:
    name: str
    passed: bool
    reason: str


@dataclass(frozen=True, slots=True)
class ControlValidationReport:
    adapter_id: str
    adapter_version: str
    provider_version: str
    validation_time: str
    tests: tuple[ValidationTestResult, ...]
    verified_capabilities: tuple[CapabilityDimension, ...]
    failed_capabilities: tuple[CapabilityDimension, ...]
    assurance_achieved: AssuranceLevel
    limitations: tuple[StructuredBlindSpot, ...]
    resulting_health: ControlPointHealth

    @property
    def passed(self) -> bool:
        return all(row.passed for row in self.tests)


def _validate_version_range(manifest: CapabilityManifest) -> None:
    minimum = str(manifest.provider_version_min or "").strip()
    maximum = str(manifest.provider_version_max or "").strip()
    if not minimum and not maximum:
        if (
            manifest.exact_verified_versions
            or manifest.verification_status is VerificationStatus.VERIFIED
        ):
            raise AdapterContractError("invalid_provider_version_range")
        return
    if not minimum or not maximum:
        raise AdapterContractError("invalid_provider_version_range")
    if not version_in_verified_range(minimum, minimum, maximum):
        raise AdapterContractError("invalid_provider_version_range")
    if not version_in_verified_range(maximum, minimum, maximum):
        raise AdapterContractError("invalid_provider_version_range")
    numeric = re.compile(r"^v?(\d+(?:\.\d+)*)$")
    low = numeric.fullmatch(minimum)
    high = numeric.fullmatch(maximum)
    if low and high:
        low_parts = tuple(int(part) for part in low.group(1).split("."))
        high_parts = tuple(int(part) for part in high.group(1).split("."))
        if low_parts > high_parts:
            raise AdapterContractError("invalid_provider_version_range")


def validate_adapter_contract(adapter: NativeControlAdapter) -> None:
    if not isinstance(adapter, NativeControlAdapter):
        raise AdapterContractError("native_control_adapter_contract_incomplete")
    descriptor = adapter.descriptor
    manifest = adapter.manifest
    if manifest.descriptor_id != descriptor.adapter_id:
        raise AdapterContractError("manifest_descriptor_mismatch")
    if manifest.provider != descriptor.provider_family or manifest.product != descriptor.product_family:
        raise AdapterContractError("manifest_provider_product_mismatch")
    if manifest.adapter_version != descriptor.adapter_version:
        raise AdapterContractError("manifest_adapter_version_mismatch")
    if manifest.schema_version != "native-control-adapter-manifest/1.0":
        raise AdapterContractError("manifest_schema_version_unsupported")
    if not isinstance(manifest.verification_status, VerificationStatus):
        raise AdapterContractError("manifest_verification_status_invalid")
    if manifest.contract_schema_version != "provider-control-contract/1.0":
        raise AdapterContractError("manifest_contract_schema_version_unsupported")
    if (
        not isinstance(manifest.supported_action_classes, tuple)
        or not manifest.supported_action_classes
        or any(not isinstance(value, ActionClass) for value in manifest.supported_action_classes)
        or len(set(manifest.supported_action_classes)) != len(manifest.supported_action_classes)
    ):
        raise AdapterContractError("manifest_supported_action_classes_invalid")
    if (
        not isinstance(manifest.supported_runtime_locations, tuple)
        or not manifest.supported_runtime_locations
        or any(not isinstance(value, RuntimeLocation) for value in manifest.supported_runtime_locations)
        or len(set(manifest.supported_runtime_locations)) != len(manifest.supported_runtime_locations)
    ):
        raise AdapterContractError("manifest_supported_runtime_locations_invalid")
    if (
        not isinstance(manifest.supported_deployment_families, tuple)
        or any(
            not isinstance(value, DeploymentFamily)
            for value in manifest.supported_deployment_families
        )
        or len(set(manifest.supported_deployment_families))
        != len(manifest.supported_deployment_families)
    ):
        raise AdapterContractError("manifest_supported_deployment_families_invalid")
    if (
        not isinstance(manifest.supported_runtimes, tuple)
        or len(manifest.supported_runtimes) > 32
        or not all(
            isinstance(value, str)
            and _bounded_contract_value(value, field_name="manifest_supported_runtime", maximum=256)
            for value in manifest.supported_runtimes
        )
        or len(set(manifest.supported_runtimes)) != len(manifest.supported_runtimes)
    ):
        raise AdapterContractError("manifest_supported_runtimes_invalid")
    if (
        not isinstance(manifest.supported_control_methods, tuple)
        or any(
            not isinstance(value, ControlMethod)
            for value in manifest.supported_control_methods
        )
        or len(set(manifest.supported_control_methods)) != len(manifest.supported_control_methods)
        or not set(manifest.supported_control_methods)
        <= set(descriptor.enforcement_methods_supported)
    ):
        raise AdapterContractError("manifest_supported_control_methods_invalid")
    if (
        not isinstance(manifest.supported_lifecycle_events, tuple)
        or len(manifest.supported_lifecycle_events) > 32
    ):
        raise AdapterContractError("manifest_supported_lifecycle_events_invalid")
    for field_name, modes in (
        ("required_account_modes", manifest.required_account_modes),
        ("required_tenant_modes", manifest.required_tenant_modes),
    ):
        if (
            not isinstance(modes, tuple)
            or len(modes) > 32
            or any(not isinstance(mode, str) for mode in modes)
            or len(set(modes)) != len(modes)
        ):
            raise AdapterContractError(f"manifest_{field_name}_invalid")
        try:
            for mode in modes:
                _bounded_contract_value(
                    mode,
                    field_name=f"manifest_{field_name}",
                    maximum=256,
                )
        except ValueError as exc:
            raise AdapterContractError(f"manifest_{field_name}_invalid") from exc
    if any(
        not isinstance(value, bool)
        for value in (manifest.supports_action_mutation, manifest.supports_approval_pause)
    ):
        raise AdapterContractError("manifest_control_semantics_invalid")
    if not isinstance(manifest.reviewed_evidence_refs, tuple):
        raise AdapterContractError("manifest_reviewed_evidence_refs_invalid")
    try:
        for event in manifest.supported_lifecycle_events:
            _bounded_contract_value(event, field_name="manifest_lifecycle_event", maximum=128)
        for field_name in ("retry_semantics", "failure_semantics", "privacy_profile"):
            _bounded_contract_value(
                getattr(manifest, field_name),
                field_name=f"manifest_{field_name}",
                maximum=256,
            )
        if manifest.reviewed_by is not None:
            _bounded_contract_value(manifest.reviewed_by, field_name="manifest_reviewed_by")
        if manifest.reviewed_at is not None:
            _bounded_contract_value(manifest.reviewed_at, field_name="manifest_reviewed_at")
        if len(manifest.reviewed_evidence_refs) > 32:
            raise ValueError("manifest_reviewed_evidence_refs_invalid")
        for reference in manifest.reviewed_evidence_refs:
            _bounded_contract_value(reference, field_name="manifest_review_evidence_reference")
    except ValueError as exc:
        raise AdapterContractError(str(exc)) from exc
    review_fields_present = any(
        value not in (None, ())
        for value in (
            manifest.reviewed_by,
            manifest.reviewed_at,
            manifest.reviewed_evidence_refs,
        )
    )
    if review_fields_present and not manifest.is_reviewed_contract:
        raise AdapterContractError("manifest_review_envelope_incomplete")
    if not isinstance(manifest.deployment_acceptance, DeploymentAcceptanceResult):
        raise AdapterContractError("manifest_deployment_acceptance_invalid")
    if manifest.verification_status is VerificationStatus.VERIFIED and (
        not manifest.verified_at or not str(manifest.source_reference or "").strip()
    ):
        raise AdapterContractError("verified_manifest_evidence_required")
    _validate_version_range(manifest)
    if not manifest.known_blind_spots or any(
        not isinstance(value, StructuredBlindSpot) for value in manifest.known_blind_spots
    ):
        raise AdapterContractError("manifest_blind_spots_invalid")
    if any(not isinstance(key, CapabilityDimension) for key in manifest.capabilities):
        raise AdapterContractError("manifest_capability_dimension_invalid")
    if any(not isinstance(value, CapabilityClaim) for value in manifest.capabilities.values()):
        raise AdapterContractError("manifest_capability_claim_invalid")
    normalized = set(manifest.event_semantics.normalized_fields)
    parameter = manifest.capabilities.get(CapabilityDimension.PARAMETER_BINDING)
    if parameter and parameter.level is CapabilityLevel.INLINE_BOUND:
        required = {"canonical_parameters", "parameter_hash", "action_correlation"}
        if not required <= normalized or not manifest.event_semantics.pre_execution_events:
            raise AdapterContractError("parameter_binding_conformance_failed")
    target = manifest.capabilities.get(CapabilityDimension.TARGET_BINDING)
    if target and target.level is CapabilityLevel.INLINE_BOUND:
        required = {"canonical_target", "target_hash", "action_correlation"}
        if not required <= normalized or not manifest.event_semantics.pre_execution_events:
            raise AdapterContractError("target_binding_conformance_failed")
    blocking_dimensions = {
        CapabilityDimension.PROMPT_CONTROL,
        CapabilityDimension.RESPONSE_CONTROL,
        CapabilityDimension.TOOL_CONTROL,
        CapabilityDimension.MCP_CONTROL,
        CapabilityDimension.COMMAND_CONTROL,
        CapabilityDimension.FILE_READ_CONTROL,
        CapabilityDimension.FILE_WRITE_CONTROL,
        CapabilityDimension.NETWORK_CONTROL,
    }
    claims_blocking = any(
        dimension in blocking_dimensions
        and claim.level in {CapabilityLevel.INLINE, CapabilityLevel.INLINE_BOUND}
        for dimension, claim in manifest.capabilities.items()
    )
    if claims_blocking and (
        not isinstance(adapter, SynchronousBlockingAdapter)
        or not manifest.event_semantics.synchronous_decision_mechanism
        or not manifest.event_semantics.pre_execution_events
    ):
        raise AdapterContractError("blocking_capability_requires_synchronous_decision_mechanism")
    if claims_blocking:
        try:
            budget = adapter.timeout_budget()
        except Exception as exc:
            raise AdapterContractError("blocking_capability_timeout_budget_invalid") from exc
        if budget.response_deadline_ms != adapter.decision_deadline_ms():
            raise AdapterContractError("blocking_capability_timeout_deadline_mismatch")
    execution = manifest.capabilities.get(CapabilityDimension.POST_EXECUTION_VERIFICATION)
    if execution and execution.level not in {CapabilityLevel.UNAVAILABLE, CapabilityLevel.UNKNOWN}:
        if not isinstance(adapter, PostExecutionAdapter):
            raise AdapterContractError("post_execution_capability_requires_behavior")
        if not manifest.event_semantics.post_execution_events:
            raise AdapterContractError("post_execution_evidence_semantics_required")
        if execution.level is CapabilityLevel.INLINE_BOUND and (
            manifest.execution_evidence_quality is not EvidenceQuality.HAWK_EXTERNALLY_VERIFIED
        ):
            raise AdapterContractError("post_execution_verification_quality_insufficient")
    manifest.selection_characteristics.total()


class AdapterValidationSuite:
    """Safe framework validation. Adapters provide probes, Hawk scores the result."""

    def run(self, adapter: NativeControlAdapter, *, provider_version: str) -> ControlValidationReport:
        tests: list[ValidationTestResult] = []
        try:
            validate_adapter_contract(adapter)
            tests.append(ValidationTestResult("manifest_conformance", True, "verified"))
        except AdapterContractError as exc:
            tests.append(ValidationTestResult("manifest_conformance", False, str(exc)))
        supported = version_in_verified_range(
            provider_version,
            adapter.manifest.provider_version_min,
            adapter.manifest.provider_version_max,
        )
        tests.append(ValidationTestResult("provider_version", supported, "supported" if supported else "unsupported"))
        probe = getattr(adapter, "validation_probe", None)
        probe_result = probe() if callable(probe) else {}
        for name in (
            "environment",
            "installation",
            "authentication",
            "replay_defense",
            "event_delivery",
            "normalization",
            "safe_allow",
            "safe_deny",
            "policy_callback",
            "configuration_integrity",
            "privacy",
        ):
            passed = probe_result.get(name) is True
            tests.append(ValidationTestResult(name, passed, "verified" if passed else "not_verified"))
        passed = all(row.passed for row in tests)
        capabilities = tuple(
            sorted(
                (
                    dimension
                    for dimension, claim in adapter.manifest.capabilities.items()
                    if passed and claim.verification_status is VerificationStatus.VERIFIED
                    and claim.level not in {CapabilityLevel.UNKNOWN, CapabilityLevel.UNAVAILABLE}
                ),
                key=lambda value: value.value,
            )
        )
        assurance = AssuranceLevel.A0_UNKNOWN
        if passed:
            assurance = AssuranceLevel.A2_OBSERVED
            if isinstance(adapter, SynchronousBlockingAdapter):
                assurance = AssuranceLevel.A3_INLINE
            parameter = adapter.manifest.capabilities.get(CapabilityDimension.PARAMETER_BINDING)
            target = adapter.manifest.capabilities.get(CapabilityDimension.TARGET_BINDING)
            if parameter and target and parameter.level is CapabilityLevel.INLINE_BOUND and target.level is CapabilityLevel.INLINE_BOUND:
                assurance = AssuranceLevel.A4_BOUND
            execution = adapter.manifest.capabilities.get(CapabilityDimension.POST_EXECUTION_VERIFICATION)
            if execution and execution.level is CapabilityLevel.INLINE_BOUND:
                assurance = AssuranceLevel.A5_VERIFIED
        health = ControlPointHealth(
            state=HealthState.HEALTHY if passed else HealthState.UNHEALTHY,
            callback_authenticated=probe_result.get("authentication") is True,
            validation_current=passed,
            evidence_flowing=probe_result.get("event_delivery") is True,
            configuration_integrity_valid=probe_result.get("configuration_integrity") is True,
            policy_fresh=probe_result.get("policy_callback") is True,
            observed_latency_ms=max(0, int(adapter.manifest.security_properties.expected_latency_ms)),
            reason_codes=() if passed else tuple(row.name for row in tests if not row.passed),
        )
        return ControlValidationReport(
            adapter_id=adapter.descriptor.adapter_id,
            adapter_version=adapter.descriptor.adapter_version,
            provider_version=provider_version,
            validation_time=datetime.now(timezone.utc).isoformat(),
            tests=tuple(tests),
            verified_capabilities=capabilities,
            failed_capabilities=tuple(
                sorted(set(adapter.manifest.capabilities) - set(capabilities), key=lambda value: value.value)
            ),
            assurance_achieved=assurance,
            limitations=adapter.limitations(),
            resulting_health=health,
        )


def stable_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()
