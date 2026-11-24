from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class EndpointPrimitive(str, Enum):
    FILE_OPEN = "file_open"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_CREATE = "file_create"
    FILE_TRUNCATE = "file_truncate"
    FILE_RENAME = "file_rename"
    FILE_MOVE = "file_move"
    FILE_DELETE = "file_delete"
    FILE_EXECUTE = "file_execute"
    FILE_MEMORY_MAP = "file_memory_map"
    FILE_METADATA_CHANGE = "file_metadata_change"
    FILE_UNKNOWN = "file_unknown"
    PROCESS_EXECUTE = "process_execute"
    PROCESS_CHILD_CREATE = "process_child_create"
    PROCESS_SCRIPT_LAUNCH = "process_script_launch"
    PROCESS_INTERPRETER_LAUNCH = "process_interpreter_launch"
    PROCESS_TERMINATE = "process_terminate"
    PROCESS_UNKNOWN = "process_unknown"
    NETWORK_CONNECT = "network_connect"
    NETWORK_ACCEPT = "network_accept"
    NETWORK_LISTEN = "network_listen"
    NETWORK_REDIRECT = "network_redirect"
    NETWORK_SEND = "network_send"
    NETWORK_RECEIVE = "network_receive"
    NETWORK_DNS = "network_dns"
    NETWORK_QUIC = "network_quic"
    NETWORK_LOCALHOST = "network_localhost"
    NETWORK_UNIX_SOCKET = "network_unix_socket"
    NETWORK_NAMED_PIPE = "network_named_pipe"
    NETWORK_UNKNOWN = "network_unknown"
    DOWNLOAD = "download"
    UPLOAD = "upload"
    EXTERNAL_TRANSFER = "external_transfer"
    INTERNAL_TRANSFER = "internal_transfer"
    UNKNOWN_TRANSFER = "unknown_transfer"
    LOCAL_MCP_CONNECTION = "local_mcp_connection"
    LOCAL_AGENT_CONNECTION = "local_agent_connection"
    LOCAL_MODEL_CONNECTION = "local_model_connection"
    LOCAL_SERVICE_CONNECTION = "local_service_connection"
    UNKNOWN_LOCAL_SERVICE = "unknown_local_service"

    # Source compatibility only. Enum iteration and newly emitted evidence use
    # the canonical Phase 3 values above.
    PROCESS_EXEC = PROCESS_EXECUTE
    MCP_LOCAL_CONNECTION = LOCAL_MCP_CONNECTION
    LOCAL_SERVICE_ACCESS = LOCAL_SERVICE_CONNECTION
    UNKNOWN_ENDPOINT_ACTION = UNKNOWN_LOCAL_SERVICE

    @classmethod
    def _missing_(cls, value: object) -> EndpointPrimitive | None:
        legacy = {
            "process_exec": cls.PROCESS_EXECUTE,
            "mcp_local_connection": cls.LOCAL_MCP_CONNECTION,
            "local_service_access": cls.LOCAL_SERVICE_CONNECTION,
            "unknown_endpoint_action": cls.UNKNOWN_LOCAL_SERVICE,
        }
        return legacy.get(str(value or "").strip().lower())


class CapabilityState(str, Enum):
    INLINE_BOUND = "inline_bound"
    INLINE = "inline"
    EXTERNAL = "external"
    OBSERVE = "observe"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class VerificationState(str, Enum):
    VERIFIED = "verified"
    EXPERIMENTAL = "experimental"
    UNVERIFIED = "unverified"
    BROKEN = "broken"
    REMOVED = "removed"


class EndpointHealthState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    TAMPERED = "tampered"
    VERSION_MISMATCH = "version_mismatch"
    POLICY_STALE = "policy_stale"
    NOT_INSTALLED = "not_installed"
    UNKNOWN = "unknown"


class EndpointEvidenceQuality(str, Enum):
    OS_AUTHORIZED = "os_authorized"
    OS_DENIED = "os_denied"
    OS_OBSERVED = "os_observed"
    NATIVE_SEMANTIC = "native_semantic"
    SEMANTIC_PROXY = "semantic_proxy"
    CORRELATED = "correlated"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class FloorComponent(str, Enum):
    MACOS_ENDPOINT_FILE = "macos_endpoint_file"
    MACOS_ENDPOINT_PROCESS = "macos_endpoint_process"
    MACOS_ENDPOINT_NETWORK = "macos_endpoint_network"
    MACOS_SEMANTIC_PROXY = "macos_semantic_proxy"
    WINDOWS_ENDPOINT_FILE = "windows_endpoint_file"
    WINDOWS_ENDPOINT_PROCESS = "windows_endpoint_process"
    WINDOWS_ENDPOINT_NETWORK = "windows_endpoint_network"
    WINDOWS_SEMANTIC_PROXY = "windows_semantic_proxy"


def _bounded(value: str | None, *, limit: int = 512) -> str | None:
    if value is None:
        return None
    rendered = str(value).replace("\x00", "").strip()
    return rendered[:limit] or None


def _bounded_path(value: str | None) -> str | None:
    bounded = _bounded(value, limit=2048)
    return unicodedata.normalize("NFC", bounded) if bounded else None


def _bounded_tuple(
    values: tuple[str, ...] | list[str],
    *,
    maximum: int,
    limit: int = 256,
) -> tuple[str, ...]:
    if len(values) > maximum:
        raise ValueError(f"at most {maximum} values are permitted")
    return tuple(
        dict.fromkeys(
            item
            for value in values
            if (item := _bounded(value, limit=limit)) is not None
        )
    )


@dataclass(frozen=True, slots=True)
class EndpointProcessIdentity:
    process_id: int
    parent_process_id: int | None
    process_start_time_ns: int | None
    binary_path: str | None
    binary_signature: str | None
    binary_hash_reference: str | None
    bundle_or_package_identity: str | None
    user_id: str | None
    device_id: str
    session_id: str | None
    process_name: str | None = None
    application_asset_id: str | None = None
    ai_asset_id: str | None = None
    command_fingerprint: str | None = None
    workspace_reference: str | None = None
    process_tree_reference: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    tenant_id: str | None = None
    platform: str | None = None
    process_instance_id: str | None = None
    parent_process_instance_id: str | None = None
    responsible_process_instance_id: str | None = None
    responsible_application_identity: str | None = None
    canonical_executable_identity: str | None = None
    product: str | None = None
    product_version: str | None = None
    architecture: str | None = None
    integrity_or_trust_level: str | None = None
    sandbox_or_container: str | None = None
    app_group_identity: str | None = None
    schema_version: str = "2.0"

    def __post_init__(self) -> None:
        if self.process_id < 0:
            raise ValueError("process_id must be non-negative")
        if self.parent_process_id is not None and self.parent_process_id < 0:
            raise ValueError("parent_process_id must be non-negative")
        if not _bounded(self.device_id, limit=256):
            raise ValueError("device_id is required")
        for name in (
            "binary_path",
            "binary_signature",
            "binary_hash_reference",
            "bundle_or_package_identity",
            "user_id",
            "device_id",
            "session_id",
            "process_name",
            "application_asset_id",
            "ai_asset_id",
            "command_fingerprint",
            "workspace_reference",
            "process_tree_reference",
            "first_seen",
            "last_seen",
            "tenant_id",
            "platform",
            "process_instance_id",
            "parent_process_instance_id",
            "responsible_process_instance_id",
            "responsible_application_identity",
            "canonical_executable_identity",
            "product",
            "product_version",
            "architecture",
            "integrity_or_trust_level",
            "sandbox_or_container",
            "app_group_identity",
            "schema_version",
        ):
            object.__setattr__(self, name, _bounded(getattr(self, name)))
        if not self.schema_version:
            raise ValueError("schema_version is required")
        if self.process_start_time_ns is None and not any(
            (
                self.binary_signature,
                self.binary_hash_reference,
                self.bundle_or_package_identity,
                self.canonical_executable_identity,
            )
        ):
            raise ValueError("process identity cannot be PID-only")
        if not self.canonical_executable_identity:
            executable_material = {
                "path": self.binary_path,
                "signature": self.binary_signature,
                "hash": self.binary_hash_reference,
                "package": self.bundle_or_package_identity,
            }
            encoded = json.dumps(
                executable_material, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            object.__setattr__(
                self,
                "canonical_executable_identity",
                f"sha256:{hashlib.sha256(encoded).hexdigest()}",
            )
        if not self.process_instance_id:
            instance_material = {
                "tenant_id": self.tenant_id,
                "device_id": self.device_id,
                "platform": self.platform,
                "process_id": self.process_id,
                "process_start_time_ns": self.process_start_time_ns,
                "canonical_executable_identity": self.canonical_executable_identity,
                "user_id": self.user_id,
                "session_id": self.session_id,
            }
            encoded = json.dumps(
                instance_material, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            object.__setattr__(
                self,
                "process_instance_id",
                f"sha256:{hashlib.sha256(encoded).hexdigest()}",
            )

    @property
    def canonical_identity(self) -> str:
        # PID alone is intentionally insufficient. Start time and binary identity
        # distinguish PID reuse and same-name binary replacement.
        material = {
            "process_id": self.process_id,
            "process_start_time_ns": self.process_start_time_ns,
            "binary_path": self.binary_path,
            "binary_signature": self.binary_signature,
            "binary_hash_reference": self.binary_hash_reference,
            "bundle_or_package_identity": self.bundle_or_package_identity,
            "user_id": self.user_id,
            "device_id": self.device_id,
            "session_id": self.session_id,
            "tenant_id": self.tenant_id,
            "platform": self.platform,
            "process_instance_id": self.process_instance_id,
            "canonical_executable_identity": self.canonical_executable_identity,
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return f"sha256:{hashlib.sha256(encoded).hexdigest()}"

    def as_evidence(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["canonical_identity"] = self.canonical_identity
        return {key: value for key, value in payload.items() if value is not None}


class ProcessFamilyConfidence(str, Enum):
    CONFIRMED = "confirmed"
    STRONG_CORRELATION = "strong_correlation"
    POSSIBLE = "possible"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class EndpointProcessFamily:
    tenant_id: str
    device_id: str
    family_id: str
    root_process_instance_id: str
    member_process_instance_ids: tuple[str, ...]
    responsible_application_identity: str | None
    confidence: ProcessFamilyConfidence
    evidence_basis: tuple[str, ...]
    session_id: str | None = None
    ai_asset_id: str | None = None
    application_asset_id: str | None = None
    schema_version: str = "1.0"

    def __post_init__(self) -> None:
        for name in (
            "tenant_id",
            "device_id",
            "family_id",
            "root_process_instance_id",
            "responsible_application_identity",
            "session_id",
            "ai_asset_id",
            "application_asset_id",
            "schema_version",
        ):
            object.__setattr__(self, name, _bounded(getattr(self, name), limit=256))
        if not all((self.tenant_id, self.device_id, self.family_id, self.root_process_instance_id)):
            raise ValueError("tenant, device, family, and root process are required")
        members = _bounded_tuple(self.member_process_instance_ids, maximum=256)
        if self.root_process_instance_id not in members:
            members = (self.root_process_instance_id, *members)
        object.__setattr__(self, "member_process_instance_ids", members)
        basis = _bounded_tuple(self.evidence_basis, maximum=64, limit=512)
        object.__setattr__(self, "evidence_basis", basis)
        if self.confidence is not ProcessFamilyConfidence.UNKNOWN and not basis:
            raise ValueError("process-family evidence is required")
        if basis and all(item.lower().startswith("process_name:") for item in basis):
            raise ValueError("name-only process-family membership is prohibited")

    def as_evidence(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class EndpointFileIdentity:
    tenant_id: str
    device_id: str
    platform: str
    volume_identity: str | None = None
    filesystem_object_id: str | None = None
    inode_or_file_id: str | None = None
    file_version: str | None = None
    change_sequence: str | None = None
    canonical_path: str | None = None
    original_path: str | None = None
    resolved_path: str | None = None
    owner_reference: str | None = None
    classification_reference: str | None = None
    content_hash_reference: str | None = None
    sensitivity_label: str | None = None
    file_type: str | None = None
    source_provenance: str | None = None
    is_symlink: bool = False
    hard_link_count: int | None = None
    is_network_share: bool = False
    is_removable_volume: bool = False
    is_temporary: bool = False
    atomic_replacement_observed: bool = False
    first_seen: str | None = None
    last_seen: str | None = None
    schema_version: str = "1.0"

    def __post_init__(self) -> None:
        for name in (
            "tenant_id",
            "device_id",
            "platform",
            "volume_identity",
            "filesystem_object_id",
            "inode_or_file_id",
            "file_version",
            "change_sequence",
            "owner_reference",
            "classification_reference",
            "content_hash_reference",
            "sensitivity_label",
            "file_type",
            "source_provenance",
            "first_seen",
            "last_seen",
            "schema_version",
        ):
            object.__setattr__(self, name, _bounded(getattr(self, name), limit=512))
        for name in ("canonical_path", "original_path", "resolved_path"):
            object.__setattr__(self, name, _bounded_path(getattr(self, name)))
        if not all((self.tenant_id, self.device_id, self.platform, self.schema_version)):
            raise ValueError("tenant, device, platform, and schema_version are required")
        if self.hard_link_count is not None and self.hard_link_count < 0:
            raise ValueError("hard_link_count must be non-negative")

    @property
    def stable_object_identity(self) -> str | None:
        object_reference = self.filesystem_object_id or self.inode_or_file_id
        if not object_reference:
            return None
        material = {
            "tenant_id": self.tenant_id,
            "device_id": self.device_id,
            "platform": self.platform,
            "volume_identity": self.volume_identity,
            "object_reference": object_reference,
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return f"sha256:{hashlib.sha256(encoded).hexdigest()}"

    @property
    def binding_quality(self) -> str:
        if self.stable_object_identity:
            return "stable_object"
        if self.resolved_path or self.canonical_path or self.original_path:
            return "path_context"
        return "unknown"

    @property
    def canonical_identity(self) -> str:
        stable = self.stable_object_identity
        material = {
            "binding": stable,
            "path_context": None if stable else (
                self.resolved_path or self.canonical_path or self.original_path
            ),
            "file_version": self.file_version,
            "change_sequence": self.change_sequence,
            "content_hash_reference": self.content_hash_reference,
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        prefix = "object" if stable else "path-context"
        return f"{prefix}-sha256:{hashlib.sha256(encoded).hexdigest()}"

    def same_object_as(self, other: EndpointFileIdentity) -> bool:
        return bool(
            self.stable_object_identity
            and self.stable_object_identity == other.stable_object_identity
        )

    def as_evidence(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["stable_object_identity"] = self.stable_object_identity
        payload["binding_quality"] = self.binding_quality
        payload["canonical_identity"] = self.canonical_identity
        return {key: value for key, value in payload.items() if value is not None}


@dataclass(frozen=True, slots=True)
class EndpointPrimitiveContext:
    tenant_id: str
    device_id: str
    process: EndpointProcessIdentity
    primitive: EndpointPrimitive
    resource_reference: str | None
    resource_classification: str
    destination_reference: str | None
    destination_classification: str
    business_purpose_reference: str | None
    policy_version: str
    deadline_monotonic_ns: int | None = None
    application_asset_id: str | None = None
    ai_asset_id: str | None = None
    operation_reference: str | None = None
    policy_epoch: int | None = None

    def __post_init__(self) -> None:
        for name in (
            "tenant_id",
            "device_id",
            "resource_reference",
            "resource_classification",
            "destination_reference",
            "destination_classification",
            "business_purpose_reference",
            "policy_version",
            "application_asset_id",
            "ai_asset_id",
            "operation_reference",
        ):
            object.__setattr__(self, name, _bounded(getattr(self, name)))
        if not self.tenant_id or not self.device_id or not self.policy_version:
            raise ValueError("tenant_id, device_id, and policy_version are required")
        if self.process.device_id != self.device_id:
            raise ValueError("process identity device mismatch")
        if self.policy_epoch is not None and self.policy_epoch <= 0:
            raise ValueError("policy_epoch must be positive")


@dataclass(frozen=True, slots=True)
class EndpointPrimitiveEvidence:
    action_id: str
    chain_reference: str
    process_instance_id: str
    primitive: EndpointPrimitive
    resource_identity: str | None
    requested_rights: tuple[str, ...]
    destination_identity: str | None
    taint_ids: tuple[str, ...]
    control_plan_id: str
    permit_digest: str | None
    policy_version: str
    policy_epoch: int
    decision: str
    platform_control_point: str
    response_result: str
    latency_ns: int
    quality: EndpointEvidenceQuality
    blind_spots: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "action_id",
            "chain_reference",
            "process_instance_id",
            "control_plan_id",
            "policy_version",
            "decision",
            "platform_control_point",
            "response_result",
        ):
            value = _bounded(getattr(self, name), limit=512)
            if value is None:
                raise ValueError(f"{name} is required")
            object.__setattr__(self, name, value)
        for name in ("resource_identity", "destination_identity", "permit_digest"):
            object.__setattr__(self, name, _bounded(getattr(self, name), limit=1024))
        object.__setattr__(
            self,
            "requested_rights",
            _bounded_tuple(self.requested_rights, maximum=32, limit=128),
        )
        object.__setattr__(self, "taint_ids", _bounded_tuple(self.taint_ids, maximum=64))
        object.__setattr__(
            self,
            "blind_spots",
            _bounded_tuple(self.blind_spots, maximum=64, limit=512),
        )
        if not self.requested_rights:
            raise ValueError("at least one requested right is required")
        if type(self.policy_epoch) is not int or self.policy_epoch <= 0:
            raise ValueError("policy_epoch must be positive")
        if type(self.latency_ns) is not int or self.latency_ns < 0:
            raise ValueError("latency_ns must be non-negative")

    def as_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "chain_reference": self.chain_reference,
            "process_instance_id": self.process_instance_id,
            "primitive": self.primitive.value,
            "resource_identity": self.resource_identity,
            "requested_rights": list(self.requested_rights),
            "destination_identity": self.destination_identity,
            "taint_ids": list(self.taint_ids),
            "control_plan_id": self.control_plan_id,
            "permit_digest": self.permit_digest,
            "policy_version": self.policy_version,
            "policy_epoch": self.policy_epoch,
            "decision": self.decision,
            "platform_control_point": self.platform_control_point,
            "response_result": self.response_result,
            "latency_ns": self.latency_ns,
            "quality": self.quality.value,
            "blind_spots": list(self.blind_spots),
            "parallel_evidence_database": False,
        }


@dataclass(frozen=True, slots=True)
class RuntimeComponentState:
    component: FloorComponent
    active: bool
    healthy: bool
    verification: VerificationState
    policy_fresh: bool
    configuration_integrity_valid: bool
    binary_integrity_valid: bool
    deadline_miss_count: int
    dropped_event_count: int
    evidence_refs: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()
    health_state: EndpointHealthState | None = None


@dataclass(frozen=True, slots=True)
class EndpointFloorPosture:
    minimum_floor_satisfied: bool
    primitive_status: dict[str, str]
    component_status: dict[str, dict[str, Any]]
    reason_codes: tuple[str, ...] = ()
    blind_spots: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "minimum_floor_satisfied": self.minimum_floor_satisfied,
            "primitive_status": dict(self.primitive_status),
            "component_status": dict(self.component_status),
            "reason_codes": list(self.reason_codes),
            "blind_spots": list(self.blind_spots),
            "evidence_refs": list(self.evidence_refs),
        }
