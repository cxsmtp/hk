from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum, IntEnum
import hashlib
import json
from typing import Any


class CapabilityDimension(str, Enum):
    DISCOVERY = "discovery"
    IDENTITY = "identity"
    SUBJECT_BINDING = "subject_binding"
    BUSINESS_PURPOSE_BINDING = "business_purpose_binding"
    AUTHORITY_BINDING = "authority_binding"
    RUNTIME_IDENTITY = "runtime_identity"
    MODEL_ROUTE_BINDING = "model_route_binding"
    PROCESS_DISCOVERY = "process_discovery"
    PROCESS_IDENTITY = "process_identity"
    PROMPT_CONTROL = "prompt_control"
    RESPONSE_CONTROL = "response_control"
    TOOL_CONTROL = "tool_control"
    MCP_CONTROL = "mcp_control"
    COMMAND_CONTROL = "command_control"
    FILE_READ_CONTROL = "file_read_control"
    FILE_WRITE_CONTROL = "file_write_control"
    FILE_OPEN_CONTROL = "file_open_control"
    FILE_CREATE_CONTROL = "file_create_control"
    FILE_RENAME_CONTROL = "file_rename_control"
    FILE_DELETE_CONTROL = "file_delete_control"
    FILE_MMAP_CONTROL = "file_mmap_control"
    PROCESS_EXEC_CONTROL = "process_exec_control"
    CHILD_PROCESS_CONTROL = "child_process_control"
    NETWORK_CONTROL = "network_control"
    NETWORK_CONNECT_CONTROL = "network_connect_control"
    NETWORK_DESTINATION_BINDING = "network_destination_binding"
    URL_CONTROL = "url_control"
    HTTP_SEMANTICS = "http_semantics"
    CONTENT_INSPECTION = "content_inspection"
    QUIC_CONTROL = "quic_control"
    LOCAL_IPC_CONTROL = "local_ipc_control"
    UPLOAD_CONTROL = "upload_control"
    DOWNLOAD_CONTROL = "download_control"
    TAINT_PROPAGATION = "taint_propagation"
    APPROVAL_CONTROL = "approval_control"
    PROVIDER_PERMISSION_CONTEXT = "provider_permission_context"
    HAWK_APPROVAL_BINDING = "hawk_approval_binding"
    APPROVAL_CORRELATION = "approval_correlation"
    PARAMETER_BINDING = "parameter_binding"
    TARGET_BINDING = "target_binding"
    DESTINATION_BINDING = "destination_binding"
    DELEGATION_CONTROL = "delegation_control"
    POST_EXECUTION_VISIBILITY = "post_execution_visibility"
    TOOL_FAILURE_VISIBILITY = "tool_failure_visibility"
    EXECUTION_CORRELATION = "execution_correlation"
    POST_EXECUTION_VERIFICATION = "post_execution_verification"
    INDEPENDENT_VERIFICATION = "independent_verification"
    CONFIG_CHANGE_VISIBILITY = "config_change_visibility"
    BACKGROUND_EXECUTION_VISIBILITY = "background_execution_visibility"
    PERSISTENT_SIDE_EFFECT_VISIBILITY = "persistent_side_effect_visibility"
    PERSISTENT_SIDE_EFFECT_CONTROL = "persistent_side_effect_control"
    CONTAINMENT = "containment"
    BYPASS_DETECTION = "bypass_detection"
    TAMPER_RESISTANCE = "tamper_resistance"
    CONFIG_INTEGRITY = "config_integrity"
    VERSION_INTEGRITY = "version_integrity"
    SELF_PROTECTION = "self_protection"
    MODEL_REQUEST_CONTROL = "model_request_control"
    MODEL_RESPONSE_CONTROL = "model_response_control"
    FUNCTION_TOOL_CONTROL = "function_tool_control"
    FUNCTION_TOOL_PARAMETER_BINDING = "function_tool_parameter_binding"
    FUNCTION_TOOL_TARGET_BINDING = "function_tool_target_binding"
    LOCAL_MCP_CONTROL = "local_mcp_control"
    HOSTED_MCP_CONTROL = "hosted_mcp_control"
    LOCAL_SHELL_CONTROL = "local_shell_control"
    HOSTED_SHELL_CONTROL = "hosted_shell_control"
    PATCH_CONTROL = "patch_control"
    COMPUTER_CONTROL = "computer_control"
    AGENT_AS_TOOL_CONTROL = "agent_as_tool_control"
    HITL_APPROVAL = "hitl_approval"
    CODEX_COMMAND_CONTROL = "codex_command_control"
    CODEX_FILE_CONTROL = "codex_file_control"
    CODEX_MCP_CONTROL = "codex_mcp_control"
    DIRECT_API_CONTROL = "direct_api_control"


class ActionClass(str, Enum):
    """Provider-neutral action taxonomy used before adapter selection."""

    MODEL_REQUEST = "model_request"
    MODEL_RESPONSE = "model_response"
    PROMPT = "prompt"
    FUNCTION_TOOL = "function_tool"
    HOSTED_TOOL = "hosted_tool"
    MCP = "mcp"
    COMMAND = "command"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    PATCH = "patch"
    BROWSER_TASK = "browser_task"
    NETWORK_ACTION = "network_action"
    API_ACTION = "api_action"
    DELEGATION = "delegation"
    APPROVAL = "approval"
    IDENTITY_CHANGE = "identity_change"
    PRIVILEGE_CHANGE = "privilege_change"
    PERSISTENT_SIDE_EFFECT = "persistent_side_effect"
    ASYNC_ACTION = "async_action"
    UNKNOWN_ACTION = "unknown_action"


class RuntimeLocation(str, Enum):
    LOCAL_ENDPOINT = "local_endpoint"
    CUSTOMER_RUNTIME = "customer_runtime"
    CUSTOMER_CLOUD = "customer_cloud"
    PROVIDER_HOSTED = "provider_hosted"
    REMOTE_AGENT = "remote_agent"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class ProviderVersionState(str, Enum):
    EXACT_TESTED = "exact_tested"
    VERIFIED_COMPATIBLE_RANGE = "verified_compatible_range"
    UNVERIFIED_NEWER = "unverified_newer"
    UNSUPPORTED_OLDER = "unsupported_older"
    UNSUPPORTED = "unsupported"
    BROKEN = "broken"
    UNKNOWN = "unknown"


class DeploymentAcceptanceState(str, Enum):
    REAL_BINARY_ACCEPTED = "real_binary_accepted"
    REAL_ENTERPRISE_TENANT_ACCEPTED = "real_enterprise_tenant_accepted"
    REAL_CLOUD_RUNTIME_ACCEPTED = "real_cloud_runtime_accepted"
    SYNTHETIC_ONLY = "synthetic_only"
    DOCS_ONLY = "docs_only"
    NOT_TESTED = "not_tested"


class ControlMethod(str, Enum):
    NATIVE_HOOK = "native_hook"
    PROVIDER_ENTERPRISE_HOOK = "provider_enterprise_hook"
    PROVIDER_TENANT_RESTRICTION = "provider_tenant_restriction"
    SDK_MIDDLEWARE = "sdk_middleware"
    AGENT_MIDDLEWARE = "agent_middleware"
    FUNCTION_MIDDLEWARE = "function_middleware"
    TOOL_LOOP_INTERCEPT = "tool_loop_intercept"
    API_INTERCEPT = "api_intercept"
    GATEWAY_INLINE = "gateway_inline"
    ENDPOINT_RUNTIME = "endpoint_runtime"
    LOCAL_SEMANTIC_PROXY = "local_semantic_proxy"
    TARGET_SERVICE_REVALIDATION = "target_service_revalidation"
    RUNTIME_SANDBOX = "runtime_sandbox"
    BROWSER_INLINE = "browser_inline"
    SAAS_CONTROL_API = "saas_control_api"
    NETWORK_EXTERNAL = "network_external"
    OBSERVE_ONLY = "observe_only"


_CONTRACT_TEXT_MAX_LENGTH = 256
_CONTRACT_REFERENCE_MAX_LENGTH = 1024


def _bounded_contract_text(value: str, *, field_name: str, maximum: int = _CONTRACT_TEXT_MAX_LENGTH) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum or any(character in text for character in "\r\n\x00"):
        raise ValueError(f"{field_name}_invalid")
    return text


def _stable_contract_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class ProviderRuntimeContext:
    """Bounded observed runtime facts; never provider-supplied authorization."""

    provider: str
    product: str
    runtime: str
    action_class: ActionClass
    runtime_location: RuntimeLocation
    provider_version: str = "unknown"
    adapter_version: str = "unknown"
    control_method: ControlMethod = ControlMethod.OBSERVE_ONLY
    environment: str = "unknown"
    application: str = "unknown"
    application_version: str = "unknown"
    runtime_version: str = "unknown"
    model_provider: str = "unknown"
    model: str = "unknown"
    route_identity: str = "unknown"
    deployment_identity: str = "unknown"
    deployment_reference: str = "unknown"
    lifecycle_stage: str = "unknown"
    account_mode: str = "unknown"
    tenant_mode: str = "unknown"
    route_evidence_ref: str = "unknown"
    route_evidence_fresh: bool = False

    def __post_init__(self) -> None:
        for field_name in (
            "provider",
            "product",
            "runtime",
            "provider_version",
            "adapter_version",
            "environment",
            "application",
            "application_version",
            "runtime_version",
            "model_provider",
            "model",
            "route_identity",
            "deployment_identity",
            "deployment_reference",
            "lifecycle_stage",
            "account_mode",
            "tenant_mode",
        ):
            _bounded_contract_text(getattr(self, field_name), field_name=field_name)
        _bounded_contract_text(
            self.route_evidence_ref,
            field_name="route_evidence_ref",
            maximum=_CONTRACT_REFERENCE_MAX_LENGTH,
        )
        if not isinstance(self.action_class, ActionClass):
            raise ValueError("action_class_invalid")
        if not isinstance(self.runtime_location, RuntimeLocation):
            raise ValueError("runtime_location_invalid")
        if not isinstance(self.control_method, ControlMethod):
            raise ValueError("control_method_invalid")
        if not isinstance(self.route_evidence_fresh, bool):
            raise ValueError("route_evidence_fresh_invalid")

    @property
    def is_resolved_for_enforcement(self) -> bool:
        required = (
            self.provider,
            self.product,
            self.runtime,
            self.provider_version,
            self.adapter_version,
            self.environment,
            self.route_identity,
            self.deployment_identity,
            self.deployment_reference,
            self.lifecycle_stage,
            self.route_evidence_ref,
        )
        return (
            self.action_class is not ActionClass.UNKNOWN_ACTION
            and self.runtime_location is not RuntimeLocation.UNKNOWN
            and self.control_method is not ControlMethod.OBSERVE_ONLY
            and self.route_evidence_fresh
            and all(value.lower() != "unknown" for value in required)
        )

    def canonical_material(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "product": self.product,
            "runtime": self.runtime,
            "action_class": self.action_class.value,
            "runtime_location": self.runtime_location.value,
            "provider_version": self.provider_version,
            "adapter_version": self.adapter_version,
            "control_method": self.control_method.value,
            "environment": self.environment,
            "application": self.application,
            "application_version": self.application_version,
            "runtime_version": self.runtime_version,
            "model_provider": self.model_provider,
            "model": self.model,
            "route_identity": self.route_identity,
            "deployment_identity": self.deployment_identity,
            "deployment_reference": self.deployment_reference,
            "lifecycle_stage": self.lifecycle_stage,
            "account_mode": self.account_mode,
            "tenant_mode": self.tenant_mode,
            "route_evidence_ref": self.route_evidence_ref,
            "route_evidence_fresh": self.route_evidence_fresh,
        }

    @property
    def fingerprint(self) -> str:
        return _stable_contract_hash(self.canonical_material())


class CapabilityLevel(str, Enum):
    INLINE_BOUND = "inline_bound"
    INLINE = "inline"
    EXTERNAL = "external"
    OBSERVE = "observe"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class VerificationStatus(str, Enum):
    VERIFIED = "verified"
    EXPERIMENTAL = "experimental"
    UNVERIFIED = "unverified"
    BROKEN = "broken"
    REMOVED = "removed"


class AssuranceLevel(IntEnum):
    A0_UNKNOWN = 0
    A1_DISCOVERED = 1
    A2_OBSERVED = 2
    A3_INLINE = 3
    A4_BOUND = 4
    A5_VERIFIED = 5


class HealthState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNVERIFIED = "unverified"
    VERSION_MISMATCH = "version_mismatch"
    TAMPERED = "tampered"
    POLICY_STALE = "policy_stale"
    NOT_INSTALLED = "not_installed"
    UNKNOWN = "unknown"


class DegradationMode(str, Enum):
    FAIL_CLOSED = "fail_closed"
    FAIL_OPEN_WITH_EVIDENCE = "fail_open_with_evidence"
    LOCAL_POLICY_ONLY = "local_policy_only"
    BLOCK_HIGH_RISK_ONLY = "block_high_risk_only"
    REQUIRE_EXCEPTION = "require_exception"
    MONITOR_ONLY = "monitor_only"


class IntegrationMode(str, Enum):
    DISCOVER = "discover"
    MONITOR = "monitor"
    ENFORCE = "enforce"


class IntegrationState(str, Enum):
    DISCOVERED = "discovered"
    CONFIGURING = "configuring"
    VALIDATING = "validating"
    MONITORING = "monitoring"
    ENFORCING = "enforcing"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    DISABLED = "disabled"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class CapabilityClaim:
    level: CapabilityLevel
    verification_status: VerificationStatus
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SecurityProperties:
    pre_execution_capable: bool
    post_execution_capable: bool
    blocking_strength: int
    action_fidelity: int
    identity_quality: int
    parameter_fidelity: int
    target_fidelity: int
    destination_fidelity: int
    result_fidelity: int
    bypass_resistance: int
    tamper_resistance: int
    expected_latency_ms: int
    availability_profile: str
    required_permissions: tuple[str, ...]
    privacy_impact: str
    operational_complexity: int = 50
    required_privilege: int = 50
    privacy_impact_score: int = 50
    deployment_friction: int = 50


@dataclass(frozen=True, slots=True)
class ControlCapabilityProfile:
    profile_id: str
    profile_version: str
    provider: str
    product: str
    integration_method: ControlMethod
    adapter_version: str
    tested_min_version: str | None
    tested_max_version: str | None
    current_verified_version: str | None
    verification_status: VerificationStatus
    verification_source: str
    capabilities: dict[CapabilityDimension, CapabilityClaim]
    security_properties: SecurityProperties
    health_requirements: tuple[str, ...]
    degradation_modes: tuple[DegradationMode, ...]
    known_blind_spots: tuple[str, ...]
    documentation_references: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ControlPointHealth:
    state: HealthState
    callback_authenticated: bool
    validation_current: bool
    evidence_flowing: bool
    configuration_integrity_valid: bool
    policy_fresh: bool
    observed_latency_ms: int
    reason_codes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ControlRequirementProfile:
    action_class: str
    requires_pre_execution: bool
    pre_execution_capability: CapabilityDimension
    requires_identity: bool
    requires_parameter_binding: bool
    requires_target_binding: bool
    requires_destination_binding: bool
    requires_post_execution: bool
    requires_persistence_detection: bool
    minimum_assurance: AssuranceLevel
    maximum_latency_ms: int
    acceptable_degradation_modes: tuple[DegradationMode, ...]


@dataclass(frozen=True, slots=True)
class ControlPointCandidate:
    control_point_id: str
    integration_instance_id: str
    tenant_id: str
    profile: ControlCapabilityProfile
    health: ControlPointHealth
    provider_version: str
    adapter_version: str
    policy_version: str
    policy_binding_mode: str
    tenant_binding_valid: bool
    exposed_lifecycle_events: tuple[str, ...]
    visible_action_fields: tuple[str, ...]
    blocking_semantics: bool
    current_degradation_mode: DegradationMode
    response_coverage: str = "unknown"


@dataclass(frozen=True, slots=True)
class SelectionContext:
    tenant_id: str
    action_id: str
    policy_version: str
    matrix_version: str
    provider: str
    product: str
    provider_version: str
    adapter_version: str
    route_binding_source: str
    allowed_control_methods: tuple[str, ...]
    required_lifecycle_event: str | None
    current_bypass_state: str
    policy_fresh: bool
    evaluated_at: str = "1970-01-01T00:00:00+00:00"
    plan_expires_at: str | None = None


@dataclass(frozen=True, slots=True)
class RejectedCandidate:
    control_point_id: str
    reason_codes: tuple[str, ...]


def _json_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(_json_value(key)): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class ControlPointSelectionResult:
    selection_id: str
    action_id: str
    primary_control_point: str | None
    secondary_observation_points: tuple[str, ...]
    containment_points: tuple[str, ...]
    rejected_candidates: tuple[RejectedCandidate, ...]
    selection_reason: str
    required_capabilities: tuple[CapabilityDimension, ...]
    satisfied_capabilities: tuple[CapabilityDimension, ...]
    unsatisfied_capabilities: tuple[CapabilityDimension, ...]
    assurance_level: AssuranceLevel
    coverage_implications: dict[str, str]
    known_blind_spots: tuple[str, ...]
    selector_version: str
    matrix_version: str
    policy_version: str
    control_profile_version: str | None
    timestamp: str

    def as_dict(self) -> dict[str, Any]:
        return _json_value(asdict(self))


@dataclass(frozen=True, slots=True)
class MandatoryEnforcementFloorRequirement:
    floor_id: str
    capability: CapabilityDimension
    minimum_level: CapabilityLevel = CapabilityLevel.INLINE
    allowed_methods: tuple[ControlMethod, ...] = (ControlMethod.ENDPOINT_RUNTIME,)
    maximum_latency_ms: int = 25
    acceptable_degradation_modes: tuple[DegradationMode, ...] = (
        DegradationMode.FAIL_CLOSED,
        DegradationMode.LOCAL_POLICY_ONLY,
        DegradationMode.REQUIRE_EXCEPTION,
    )


@dataclass(frozen=True, slots=True)
class EndpointControlPlan:
    plan_id: str
    action_id: str
    mandatory_enforcement_floors: tuple[tuple[str, str], ...]
    semantic_primary_control: str | None
    secondary_context_points: tuple[str, ...]
    verification_points: tuple[str, ...]
    containment_points: tuple[str, ...]
    unsatisfied_mandatory_floors: tuple[str, ...]
    rejected_mandatory_floor_candidates: dict[str, tuple[RejectedCandidate, ...]]
    control_requirement_unsatisfied: bool
    reason_codes: tuple[str, ...]
    coverage_implications: dict[str, str]
    selector_version: str
    matrix_version: str
    policy_version: str
    timestamp: str
    required_capabilities: tuple[CapabilityDimension, ...] = ()
    satisfied_capabilities: tuple[CapabilityDimension, ...] = ()
    unsatisfied_capabilities: tuple[CapabilityDimension, ...] = ()
    minimum_assurance: AssuranceLevel = AssuranceLevel.A0_UNKNOWN
    degradation_policy: dict[str, str] = field(default_factory=dict)
    expiry: str | None = None
    blind_spots: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return _json_value(asdict(self))


# Backward-compatible import name for callers compiled against the first
# endpoint-floor selector contract. New code should use EndpointControlPlan.
ControlPlanResolutionResult = EndpointControlPlan
