from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import inspect
import json
import math
import re
from types import MappingProxyType
from typing import Any, Literal, Self
import unicodedata

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    ValidationError,
    ValidationInfo,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

from app.services.privacy_sanitizer import (
    BINARY_KEYS,
    RAW_MATERIAL_KEYS,
    SENSITIVE_KEYWORDS,
    TOKEN_KEYS,
    redact_sensitive_text,
    sanitize_privacy_scalar,
)


MAX_FLEXIBLE_DEPTH = 6
MAX_FLEXIBLE_ITEMS = 128
MAX_FLEXIBLE_KEY_CHARS = 128
MAX_FLEXIBLE_STRING_CHARS = 512
MAX_FLEXIBLE_ENCODED_BYTES = 32 * 1024
MAX_FLEXIBLE_NODES = 4096
MAX_STRING_COLLECTION_ITEM_CHARS = 128

# Limits are exact compact-JSON UTF-8 byte budgets for each string collection.
STRING_COLLECTION_ENCODED_BYTE_LIMITS: Mapping[str, int] = MappingProxyType(
    {
        "target_ids": 64 * 1024,
        "collector_ids": 8 * 1024,
        "permitted_methods": 2 * 1024,
        "exclusions": 16 * 1024,
        "active_capabilities": 4 * 1024,
        "passive_capabilities": 4 * 1024,
        "permissions_required": 4 * 1024,
        "sensitive_data_accessed": 4 * 1024,
        "limitations": 4 * 1024,
        "capability_hints": 4 * 1024,
        "contradiction_references": 4 * 1024,
    }
)

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_HASH_RE = re.compile(r"[0-9a-f]{64}")
_SEMANTIC_VERSION_RE = re.compile(
    r"^\d{1,3}(?:\.\d{1,5}){1,3}(?:[-+][A-Za-z0-9.-]{1,32})?$"
)
_PHONE_LIKE_DOTTED_VALUE_RE = re.compile(
    r"^(?:\d{1,3}\.)?\d{2,3}\.\d{3}\.\d{4}$"
)
_KEY_SEPARATOR_RE = re.compile(r"[^a-z0-9]+")
_CAMEL_BOUNDARY_RE = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL_ACRONYM_RE = re.compile(r"([a-z0-9])([A-Z])")
_FORBIDDEN_KEYS = frozenset(
    RAW_MATERIAL_KEYS
    | SENSITIVE_KEYWORDS
    | TOKEN_KEYS
    | BINARY_KEYS
    | {
        "body",
        "content",
        "raw",
        "raw_body",
        "raw_content",
    }
)
_FORBIDDEN_SUFFIXES = ("_body", "_content", "_prompt", "_b64", "_base64")
_FORBIDDEN_FRAGMENTS = (
    "access_token",
    "api_key",
    "password",
    "refresh_token",
    "secret",
    "token",
)
_COMPACT_FORBIDDEN_KEYS = frozenset(
    key.replace("_", "") for key in _FORBIDDEN_KEYS
)
_COMPACT_FORBIDDEN_SUFFIXES = tuple(
    suffix.replace("_", "") for suffix in _FORBIDDEN_SUFFIXES
)
_COMPACT_FORBIDDEN_FRAGMENTS = tuple(
    fragment.replace("_", "") for fragment in _FORBIDDEN_FRAGMENTS
)
_BASE_MODEL_VALIDATE_PARAMETERS = frozenset(
    inspect.signature(BaseModel.model_validate).parameters
)
_BASE_MODEL_VALIDATE_JSON_PARAMETERS = frozenset(
    inspect.signature(BaseModel.model_validate_json).parameters
)
_BASE_MODEL_VALIDATE_STRINGS_PARAMETERS = frozenset(
    inspect.signature(BaseModel.model_validate_strings).parameters
)


def is_safe_semantic_version(value: object) -> bool:
    return (
        type(value) is str
        and _SEMANTIC_VERSION_RE.fullmatch(value) is not None
        and _PHONE_LIKE_DOTTED_VALUE_RE.fullmatch(value) is None
    )


def _normalized_key(value: str) -> str:
    separated = _CAMEL_BOUNDARY_RE.sub(r"\1_\2", value)
    separated = _CAMEL_ACRONYM_RE.sub(r"\1_\2", separated)
    return _KEY_SEPARATOR_RE.sub("_", separated.casefold()).strip("_")


def _utf8_bytes(value: str, *, field_name: str) -> bytes:
    try:
        return value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ValueError(f"{field_name} must contain valid UTF-8 text") from None


def _privacy_safe_key(value: str) -> None:
    if not value or len(value) > MAX_FLEXIBLE_KEY_CHARS:
        raise ValueError("flexible object keys must be bounded non-empty strings")
    _utf8_bytes(value, field_name="flexible object keys")
    normalized = _normalized_key(value)
    compact = normalized.replace("_", "")
    if (
        normalized in _FORBIDDEN_KEYS
        or compact in _COMPACT_FORBIDDEN_KEYS
        or normalized.endswith(_FORBIDDEN_SUFFIXES)
        or compact.endswith(_COMPACT_FORBIDDEN_SUFFIXES)
        or any(fragment in normalized for fragment in _FORBIDDEN_FRAGMENTS)
        or any(fragment in compact for fragment in _COMPACT_FORBIDDEN_FRAGMENTS)
        or redact_sensitive_text(value, max_len=MAX_FLEXIBLE_KEY_CHARS) != value
    ):
        raise ValueError("flexible object keys cannot describe private or raw material")


def _bounded_string_collection(
    value: tuple[str, ...],
    *,
    field_name: str,
    unique: bool = False,
) -> tuple[str, ...]:
    normalized = tuple(item.strip() for item in value)
    encoded_items: list[str] = []
    for item in normalized:
        if not item or len(item) > MAX_STRING_COLLECTION_ITEM_CHARS:
            raise ValueError(
                "string collection items must contain between 1 and "
                f"{MAX_STRING_COLLECTION_ITEM_CHARS} characters"
            )
        _utf8_bytes(item, field_name=f"{field_name} items")
        encoded_items.append(item)
    if unique and len(set(normalized)) != len(normalized):
        raise ValueError(f"{field_name} values must be unique")
    encoded = json.dumps(
        encoded_items,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")
    if len(encoded) > STRING_COLLECTION_ENCODED_BYTE_LIMITS[field_name]:
        raise ValueError(f"{field_name} exceeds its aggregate encoded byte budget")
    return normalized


def _supported_alias_arguments(
    parameters: frozenset[str],
    *,
    by_alias: bool | None,
    by_name: bool | None,
) -> dict[str, bool | None]:
    forwarded: dict[str, bool | None] = {}
    if "by_alias" in parameters:
        forwarded["by_alias"] = by_alias
    if "by_name" in parameters:
        forwarded["by_name"] = by_name
    return forwarded


def _freeze_json_value(
    value: object,
    *,
    depth: int = 0,
    remaining: list[int] | None = None,
    seen_containers: set[int] | None = None,
    field_key: str = "",
) -> object:
    if remaining is None:
        remaining = [MAX_FLEXIBLE_NODES]
    if seen_containers is None:
        seen_containers = set()
    remaining[0] -= 1
    if remaining[0] < 0:
        raise ValueError("flexible values exceed the traversal-wide node budget")
    if depth > MAX_FLEXIBLE_DEPTH:
        raise ValueError("flexible values exceed the maximum nesting depth")
    if type(value) is dict:
        identity = id(value)
        if identity in seen_containers:
            raise ValueError("flexible values cannot reuse or cycle containers")
        seen_containers.add(identity)
        if len(value) > MAX_FLEXIBLE_ITEMS:
            raise ValueError("flexible objects contain too many entries")
        frozen: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("flexible object keys must be strings")
            _privacy_safe_key(key)
            frozen[key] = _freeze_json_value(
                item,
                depth=depth + 1,
                remaining=remaining,
                seen_containers=seen_containers,
                field_key=key,
            )
        return MappingProxyType(frozen)
    if type(value) in {list, tuple}:
        identity = id(value)
        if identity in seen_containers:
            raise ValueError("flexible values cannot reuse or cycle containers")
        seen_containers.add(identity)
        if len(value) > MAX_FLEXIBLE_ITEMS:
            raise ValueError("flexible arrays contain too many items")
        return tuple(
            _freeze_json_value(
                item,
                depth=depth + 1,
                remaining=remaining,
                seen_containers=seen_containers,
                field_key=field_key,
            )
            for item in value
        )
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if not -(1 << 63) <= value <= (1 << 63) - 1:
            raise ValueError("flexible integers must fit in signed 64-bit JSON")
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("flexible numbers must be finite")
        return value
    if type(value) is str:
        if len(value) > MAX_FLEXIBLE_STRING_CHARS:
            raise ValueError("flexible strings exceed the maximum length")
        _utf8_bytes(value, field_name="flexible strings")
        normalized_key = _normalized_key(field_key)
        opaque_digest = (
            value is not None
            and _HASH_RE.fullmatch(value) is not None
            and (
                normalized_key == "digest"
                or normalized_key.endswith("_digest")
                or normalized_key.endswith("_hash")
                or normalized_key.endswith("_fingerprint")
            )
        )
        semantic_version = (
            normalized_key == "version" and is_safe_semantic_version(value)
        )
        if (
            not opaque_digest
            and not semantic_version
            and (
                redact_sensitive_text(value, max_len=MAX_FLEXIBLE_STRING_CHARS)
                != value
                or sanitize_privacy_scalar(value, key="") != value
            )
        ):
            raise ValueError("flexible values cannot contain private or raw material")
        return value
    raise ValueError("flexible values must contain only JSON-safe data")


def _exact_hash(value: object) -> str:
    if type(value) is not str or _HASH_RE.fullmatch(value) is None:
        raise ValueError("hashes must be exactly 64 lowercase hexadecimal characters")
    return value


def _json_native(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _json_native(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_native(item) for item in value]
    return value


def _bounded_frozen_json(value: object) -> object:
    frozen = _freeze_json_value(value)
    encoded = json.dumps(
        _json_native(frozen),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > MAX_FLEXIBLE_ENCODED_BYTES:
        raise ValueError("flexible values exceed the maximum encoded size")
    return frozen


def _sanitized_validation_error(
    model: type[BaseModel],
    error: ValidationError | None = None,
) -> ValidationError:
    fields = frozenset(model.model_fields)
    locations: list[tuple[str, ...]] = []
    if error is not None:
        for detail in error.errors(
            include_url=False,
            include_context=False,
            include_input=False,
        )[: max(1, len(fields))]:
            location = detail.get("loc")
            if (
                isinstance(location, tuple)
                and location
                and isinstance(location[0], str)
                and location[0] in fields
            ):
                locations.append((location[0],))
            else:
                locations.append(())
    if not locations:
        locations.append(())
    return ValidationError.from_exception_data(
        model.__name__,
        [
            {
                "type": PydanticCustomError(
                    "hmair_contract_invalid",
                    "invalid HMAIR contract",
                ),
                "loc": location,
                "input": None,
            }
            for location in locations
        ],
        hide_input=True,
    )


class DiscoveryScanType(StrEnum):
    FULL_ENTERPRISE = "full_enterprise"
    TARGETED = "targeted"
    INCREMENTAL = "incremental"
    VERIFICATION = "verification"
    SCHEDULED = "scheduled"
    COLLECTOR_SPECIFIC = "collector_specific"


class DiscoveryScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PARTIALLY_COMPLETE = "partially_complete"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ObservationFreshness(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class SourceSurface(StrEnum):
    ENDPOINT = "endpoint"
    BROWSER = "browser"
    CLOUD = "cloud"
    SAAS = "saas"
    IDENTITY = "identity"
    SOURCE_CODE = "source_code"
    CI_CD = "ci_cd"
    NETWORK = "network"
    DNS = "dns"
    API_GATEWAY = "api_gateway"
    SERVICE_MESH = "service_mesh"
    MCP = "mcp"
    DATABASE = "database"
    VECTOR_STORE = "vector_store"
    MODEL_ENDPOINT = "model_endpoint"
    RUNTIME = "runtime"
    KUBERNETES = "kubernetes"
    CONTAINER = "container"
    UNKNOWN = "unknown"


class ObservationType(StrEnum):
    INSTALLED_APPLICATION = "installed_application"
    RUNNING_PROCESS = "running_process"
    BROWSER_EXTENSION = "browser_extension"
    WEB_AI_USAGE = "web_ai_usage"
    SDK_DEPENDENCY = "sdk_dependency"
    PACKAGE_REFERENCE = "package_reference"
    AI_ENDPOINT_REFERENCE = "ai_endpoint_reference"
    MODEL_DEPLOYMENT = "model_deployment"
    AGENT_RESOURCE = "agent_resource"
    MCP_CLIENT = "mcp_client"
    MCP_SERVER = "mcp_server"
    MCP_TOOL = "mcp_tool"
    OAUTH_APP = "oauth_app"
    SERVICE_PRINCIPAL = "service_principal"
    MANAGED_IDENTITY = "managed_identity"
    LICENSE_ASSIGNMENT = "license_assignment"
    NETWORK_FLOW = "network_flow"
    DNS_LOOKUP = "dns_lookup"
    API_CALL = "api_call"
    VECTOR_DB_REFERENCE = "vector_db_reference"
    RAG_INDEX = "rag_index"
    PROMPT_CONFIG = "prompt_config"
    AGENT_CONFIG = "agent_config"
    TOOL_CONFIG = "tool_config"
    MODEL_CONFIG = "model_config"
    AI_SAAS_FEATURE = "ai_saas_feature"
    ACTIVE_USER = "active_user"
    TOKEN_USAGE = "token_usage"
    REQUEST_USAGE = "request_usage"
    UNKNOWN_AI_SIGNAL = "unknown_ai_signal"


class ObservedFactState(StrEnum):
    INSTALLED = "installed"
    CONFIGURED = "configured"
    ENABLED = "enabled"
    REACHABLE = "reachable"
    OBSERVED = "observed"
    ACTIVELY_USED = "actively_used"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class FactVerificationState(StrEnum):
    VERIFIED = "verified"
    PARTIALLY_VERIFIED = "partially_verified"
    INFERRED = "inferred"
    CONTRADICTED = "contradicted"
    STALE = "stale"
    UNKNOWN = "unknown"


class SourceTrust(StrEnum):
    STRONG = "strong"
    MEDIUM = "medium"
    WEAK = "weak"
    UNKNOWN = "unknown"


class EvidenceMode(StrEnum):
    DIRECT = "direct"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class EvidenceMutability(StrEnum):
    IMMUTABLE = "immutable"
    MUTABLE = "mutable"
    UNKNOWN = "unknown"


class ContradictionState(StrEnum):
    NONE = "none"
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    UNRESOLVED = "unresolved"
    UNKNOWN = "unknown"


class DiscoveryTargetType(StrEnum):
    ENDPOINT_GROUP = "endpoint_group"
    BROWSER_TENANT = "browser_tenant"
    CLOUD_SUBSCRIPTION = "cloud_subscription"
    CLOUD_PROJECT = "cloud_project"
    KUBERNETES_CLUSTER = "kubernetes_cluster"
    SAAS_TENANT = "saas_tenant"
    IDENTITY_TENANT = "identity_tenant"
    REPOSITORY_ORG = "repository_org"
    REPOSITORY = "repository"
    NETWORK_RANGE = "network_range"
    DNS_DOMAIN = "dns_domain"
    API_GATEWAY = "api_gateway"
    DATABASE_PLATFORM = "database_platform"
    AI_PROVIDER_ACCOUNT = "ai_provider_account"
    MCP_ENVIRONMENT = "mcp_environment"
    LLM_GATEWAY = "llm_gateway"
    RUNTIME_ENVIRONMENT = "runtime_environment"


class CollectorRunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"
    UNSUPPORTED = "unsupported"
    PERMISSION_DENIED = "permission_denied"
    RATE_LIMITED = "rate_limited"
    STALE = "stale"
    EMPTY = "empty"


class StrictContract(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        str_strip_whitespace=True,
    )

    def __init__(self, **data: object) -> None:
        try:
            super().__init__(**data)
        except ValidationError as error:
            raise _sanitized_validation_error(type(self), error) from None

    @classmethod
    def model_validate(
        cls,
        obj: Any,
        *,
        strict: bool | None = None,
        from_attributes: bool | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        try:
            return super().model_validate(
                obj,
                strict=strict,
                from_attributes=from_attributes,
                context=context,
                **_supported_alias_arguments(
                    _BASE_MODEL_VALIDATE_PARAMETERS,
                    by_alias=by_alias,
                    by_name=by_name,
                ),
            )
        except ValidationError as error:
            raise _sanitized_validation_error(cls, error) from None

    @classmethod
    def model_validate_json(
        cls,
        json_data: str | bytes | bytearray,
        *,
        strict: bool | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        try:
            return super().model_validate_json(
                json_data,
                strict=strict,
                context=context,
                **_supported_alias_arguments(
                    _BASE_MODEL_VALIDATE_JSON_PARAMETERS,
                    by_alias=by_alias,
                    by_name=by_name,
                ),
            )
        except ValidationError as error:
            raise _sanitized_validation_error(cls, error) from None

    @classmethod
    def model_validate_strings(
        cls,
        obj: Any,
        *,
        strict: bool | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        try:
            return super().model_validate_strings(
                obj,
                strict=strict,
                context=context,
                **_supported_alias_arguments(
                    _BASE_MODEL_VALIDATE_STRINGS_PARAMETERS,
                    by_alias=by_alias,
                    by_name=by_name,
                ),
            )
        except ValidationError as error:
            raise _sanitized_validation_error(cls, error) from None

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        del deep
        material = self.model_dump(mode="json")
        if update is not None:
            if not isinstance(update, Mapping) or len(update) > len(
                type(self).model_fields
            ):
                raise _sanitized_validation_error(type(self))
            material.update(dict(update))
        return type(self).model_validate(material)


class DiscoveryScanCreate(StrictContract):
    name: str = Field(min_length=1, max_length=255)
    scan_type: DiscoveryScanType
    scope: Mapping[str, Any] = Field(max_length=128)
    target_ids: tuple[str, ...] = Field(min_length=1, max_length=1000)
    collector_ids: tuple[str, ...] = Field(min_length=1, max_length=100)
    safety_profile: Literal["read_only", "metadata_only"]
    dry_run: StrictBool = False

    @field_validator("scope", mode="wrap")
    @classmethod
    def bounded_scope(cls, value: object, handler: Any) -> object:
        checked = _bounded_frozen_json(value)
        normalized = _bounded_frozen_json(handler(_json_native(checked)))
        exclusions = normalized.get("exclusions")
        if exclusions is not None:
            if not isinstance(exclusions, (list, tuple)):
                raise ValueError("scan exclusions must be a bounded list")
            _bounded_string_collection(tuple(exclusions), field_name="exclusions")
        return normalized

    @field_serializer("scope")
    def serialize_scope(self, value: Mapping[str, Any]) -> object:
        return _json_native(value)

    @field_validator("target_ids", "collector_ids")
    @classmethod
    def unique_identifiers(
        cls,
        value: tuple[str, ...],
        info: ValidationInfo,
    ) -> tuple[str, ...]:
        return _bounded_string_collection(
            value,
            field_name=info.field_name,
            unique=True,
        )


class DiscoveryTargetInput(StrictContract):
    target_id: str = Field(min_length=1, max_length=128)
    target_type: DiscoveryTargetType
    identifier: str = Field(min_length=1, max_length=512)
    environment: str = Field(min_length=1, max_length=64)
    owner_hint: str | None = Field(default=None, max_length=255)
    credentials_reference: str | None = Field(default=None, max_length=255)
    permitted_methods: tuple[str, ...] = Field(min_length=1, max_length=32)
    exclusions: tuple[str, ...] = Field(max_length=256)
    rate_limit: StrictInt = Field(ge=1, le=10000)
    active_scan_allowed: StrictBool
    sensitive_scope: StrictBool
    last_scanned_at: datetime | None = None

    @field_validator("permitted_methods", "exclusions")
    @classmethod
    def bounded_target_collections(
        cls,
        value: tuple[str, ...],
        info: ValidationInfo,
    ) -> tuple[str, ...]:
        return _bounded_string_collection(value, field_name=info.field_name)


class CollectorDeclaration(StrictContract):
    collector_id: str = Field(min_length=1, max_length=128)
    collector_type: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=64)
    supported_targets: tuple[DiscoveryTargetType, ...] = Field(
        min_length=1,
        max_length=32,
    )
    active_capabilities: tuple[str, ...] = Field(max_length=64)
    passive_capabilities: tuple[str, ...] = Field(max_length=64)
    permissions_required: tuple[str, ...] = Field(max_length=64)
    sensitive_data_accessed: tuple[str, ...] = Field(max_length=64)
    health: Literal["healthy", "warning", "degraded", "offline", "unknown"]
    last_success_at: datetime | None = None
    last_failure_at: datetime | None = None
    data_residency: str = Field(min_length=1, max_length=128)
    control_capability: Literal[
        "inline",
        "warn_only",
        "monitor_only",
        "external_required",
        "unknown",
    ]
    schema_version: str = Field(min_length=1, max_length=32)
    limitations: tuple[str, ...] = Field(min_length=1, max_length=64)
    declaration_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=_HASH_PATTERN,
    )

    @field_validator("declaration_hash", mode="before")
    @classmethod
    def exact_declaration_hash(cls, value: object) -> str:
        return _exact_hash(value)

    @field_validator("last_success_at", "last_failure_at")
    @classmethod
    def require_utc_lifecycle_time(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("collector lifecycle times must include a timezone")
        return value.astimezone(timezone.utc)

    @field_validator(
        "active_capabilities",
        "passive_capabilities",
        "permissions_required",
        "sensitive_data_accessed",
        "limitations",
    )
    @classmethod
    def bounded_declaration_collections(
        cls,
        value: tuple[str, ...],
        info: ValidationInfo,
    ) -> tuple[str, ...]:
        return _bounded_string_collection(value, field_name=info.field_name)


class DiscoveryObservationInput(StrictContract):
    observation_id: str = Field(min_length=1, max_length=128)
    scan_id: str = Field(min_length=1, max_length=36)
    collector_id: str = Field(min_length=1, max_length=128)
    collector_type: str = Field(min_length=1, max_length=64)
    collector_version: str = Field(min_length=1, max_length=64)
    target_id: str = Field(min_length=1, max_length=128)
    source_surface: SourceSurface
    subject_reference: str | None = Field(max_length=255)
    raw_signal_type: ObservationType = Field(
        validation_alias=AliasChoices("raw_signal_type", "observation_type")
    )
    normalized_signal: Mapping[str, Any] = Field(max_length=128)
    observed_at: datetime
    asset_candidate_type: str = Field(
        min_length=1,
        max_length=64,
        validation_alias=AliasChoices(
            "asset_candidate_type", "candidate_asset_type"
        ),
    )
    observed_state: ObservedFactState
    identifiers: Mapping[str, str] = Field(max_length=64)
    attributes: Mapping[str, Any] = Field(max_length=128)
    configuration_summary: Mapping[str, Any] = Field(max_length=128)
    usage_summary: Mapping[str, Any] = Field(max_length=128)
    capability_hints: tuple[str, ...] = Field(max_length=64)
    identity_hints: tuple[Mapping[str, Any], ...] = Field(max_length=64)
    relationship_hints: tuple[Mapping[str, Any], ...] = Field(max_length=128)
    evidence_reference: str = Field(min_length=1, max_length=255)
    evidence_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=_HASH_PATTERN,
    )
    signature_status: str = Field(min_length=1, max_length=32)
    confidence: float = Field(ge=0.0, le=1.0)
    freshness: ObservationFreshness
    verification_state: FactVerificationState
    source_trust: SourceTrust
    collection_scope: Mapping[str, Any] = Field(max_length=128)
    parser_version: str = Field(min_length=1, max_length=64)
    schema_version: str = Field(min_length=1, max_length=32)
    evidence_mode: EvidenceMode
    evidence_mutability: EvidenceMutability
    contradiction_state: ContradictionState
    contradiction_references: tuple[str, ...] = Field(max_length=64)
    sensitivity: str = Field(min_length=1, max_length=32)
    redaction_status: str = Field(min_length=1, max_length=32)

    @property
    def observation_type(self) -> str:
        return self.raw_signal_type.value

    @property
    def candidate_asset_type(self) -> str:
        return self.asset_candidate_type

    @field_validator("evidence_hash", mode="before")
    @classmethod
    def exact_evidence_hash(cls, value: object) -> str:
        return _exact_hash(value)

    @field_validator("capability_hints", "contradiction_references")
    @classmethod
    def bounded_capability_hints(
        cls,
        value: tuple[str, ...],
        info: ValidationInfo,
    ) -> tuple[str, ...]:
        return _bounded_string_collection(value, field_name=info.field_name)

    @field_validator(
        "identifiers",
        "normalized_signal",
        "attributes",
        "configuration_summary",
        "usage_summary",
        "identity_hints",
        "relationship_hints",
        "collection_scope",
        mode="wrap",
    )
    @classmethod
    def bounded_flexible_values(
        cls,
        value: object,
        handler: Any,
    ) -> object:
        checked = _bounded_frozen_json(value)
        return _bounded_frozen_json(handler(_json_native(checked)))

    @field_serializer(
        "identifiers",
        "normalized_signal",
        "attributes",
        "configuration_summary",
        "usage_summary",
        "identity_hints",
        "relationship_hints",
        "collection_scope",
    )
    def serialize_flexible_values(self, value: object) -> object:
        return _json_native(value)

    @field_validator("observed_at")
    @classmethod
    def require_utc_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value.astimezone(timezone.utc)


# H1B asset and resolution contracts.  Canonical replay helpers deliberately
# remain module-private; only ``canonical_json_bytes`` is module-visible so the
# deterministic byte contract can be verified independently.


class AIAssetType(StrEnum):
    AI_APPLICATION = "ai_application"
    AI_SAAS = "ai_saas"
    AI_FEATURE = "ai_feature"
    MODEL = "model"
    MODEL_ENDPOINT = "model_endpoint"
    AGENT = "agent"
    AGENT_FRAMEWORK = "agent_framework"
    RUNTIME = "runtime"
    LLM_GATEWAY = "llm_gateway"
    MCP_SERVER = "mcp_server"
    MCP_CLIENT = "mcp_client"
    MCP_TOOL = "mcp_tool"
    IDE = "ide"
    CLI = "cli"
    BROWSER_EXTENSION = "browser_extension"
    ENDPOINT_APPLICATION = "endpoint_application"
    SDK = "sdk"
    API = "api"
    WORKFLOW = "workflow"
    PLUGIN = "plugin"
    VECTOR_DATABASE = "vector_database"
    KNOWLEDGE_BASE = "knowledge_base"
    PROMPT_STORE = "prompt_store"
    MEMORY_STORE = "memory_store"
    DATA_CONNECTOR = "data_connector"
    IDENTITY = "identity"
    SERVICE_ACCOUNT = "service_account"
    OAUTH_APPLICATION = "oauth_application"
    UNKNOWN_AI_CANDIDATE = "unknown_ai_candidate"


class AICapabilityType(StrEnum):
    MODEL_INFERENCE = "model_inference"
    EMBEDDINGS = "embeddings"
    FILE_UPLOAD = "file_upload"
    FILE_DOWNLOAD = "file_download"
    SOURCE_CODE_ACCESS = "source_code_access"
    TERMINAL_EXECUTION = "terminal_execution"
    PROCESS_EXECUTION = "process_execution"
    FILESYSTEM_READ = "filesystem_read"
    FILESYSTEM_WRITE = "filesystem_write"
    BROWSER_AUTOMATION = "browser_automation"
    EMAIL_SEND = "email_send"
    MESSAGING_SEND = "messaging_send"
    DATABASE_READ = "database_read"
    DATABASE_WRITE = "database_write"
    VECTOR_SEARCH = "vector_search"
    MCP_CLIENT = "MCP_client"
    MCP_SERVER = "MCP_server"
    TOOL_EXECUTION = "tool_execution"
    EXTERNAL_NETWORK = "external_network"
    SECRET_ACCESS = "secret_access"
    CLOUD_ADMIN = "cloud_admin"
    IDENTITY_CHANGE = "identity_change"
    MEMORY_WRITE = "memory_write"
    PERSISTENT_SIDE_EFFECT = "persistent_side_effect"
    CODE_CHANGE = "code_change"
    CI_CD = "CI_CD"
    CUSTOMER_DATA_ACCESS = "customer_data_access"


class DiscoveryCapabilityType(StrEnum):
    """Phase 2 inference vocabulary, kept separate from the exact H1B API enum."""

    INFERENCE = "inference"
    MODEL_INFERENCE = "model_inference"
    EMBEDDINGS = "embeddings"
    MULTIMODAL = "multimodal"
    IMAGE_GENERATION = "image_generation"
    AUDIO = "audio"
    CODE_GENERATION = "code_generation"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_UPLOAD = "file_upload"
    FILE_DOWNLOAD = "file_download"
    SOURCE_CODE_ACCESS = "source_code_access"
    TERMINAL_EXECUTION = "terminal_execution"
    PROCESS_EXECUTION = "process_execution"
    FILESYSTEM_READ = "filesystem_read"
    FILESYSTEM_WRITE = "filesystem_write"
    BROWSER_AUTOMATION = "browser_automation"
    EMAIL_SEND = "email_send"
    MESSAGING_SEND = "messaging_send"
    DATABASE_READ = "database_read"
    DATABASE_WRITE = "database_write"
    VECTOR_SEARCH = "vector_search"
    KNOWLEDGE_RETRIEVAL = "knowledge_retrieval"
    MEMORY_READ = "memory_read"
    MCP_CLIENT = "MCP_client"
    MCP_SERVER = "MCP_server"
    TOOL_EXECUTION = "tool_execution"
    SHELL_EXECUTION = "shell_execution"
    CODE_EXECUTION = "code_execution"
    CI_CD_EXECUTION = "ci_cd_execution"
    GIT_READ = "git_read"
    GIT_WRITE = "git_write"
    REPOSITORY_ACCESS = "repository_access"
    CODE_MODIFICATION = "code_modification"
    PATCH_APPLICATION = "patch_application"
    INTERNET_ACCESS = "internet_access"
    INTERNAL_NETWORK = "internal_network"
    API_CALL = "api_call"
    CLOUD_API = "cloud_api"
    WEBHOOK = "webhook"
    EXTERNAL_NETWORK = "external_network"
    A2A = "a2a"
    DELEGATION = "delegation"
    SUBAGENT = "subagent"
    PLANNING = "planning"
    PERSISTENT_AUTOMATION = "persistent_automation"
    SECRET_ACCESS = "secret_access"
    OAUTH = "oauth"
    MANAGED_IDENTITY = "managed_identity"
    SERVICE_PRINCIPAL = "service_principal"
    USER_IMPERSONATION = "user_impersonation"
    CLOUD_ADMIN = "cloud_admin"
    IDENTITY_CHANGE = "identity_change"
    MEMORY_WRITE = "memory_write"
    PERSISTENT_SIDE_EFFECT = "persistent_side_effect"
    CODE_CHANGE = "code_change"
    CI_CD = "CI_CD"
    CUSTOMER_DATA_ACCESS = "customer_data_access"


class AICapabilityState(StrEnum):
    DECLARED = "declared"
    CONFIGURED = "configured"
    OBSERVED = "observed"
    INFERRED = "inferred"
    DENIED = "denied"
    UNKNOWN = "unknown"


class ResolutionAction(StrEnum):
    CREATE = "create"
    MERGE = "merge"
    ATTACH = "attach"
    REJECT = "reject"
    MANUAL_REVIEW = "manual_review"


class ShadowAIStatus(StrEnum):
    APPROVED = "approved"
    APPROVED_BUT_UNCONTROLLED = "approved_but_uncontrolled"
    KNOWN_UNAPPROVED = "known_unapproved"
    SUSPECTED_SHADOW = "suspected_shadow"
    CONFIRMED_SHADOW = "confirmed_shadow"
    PERSONAL_ACCOUNT = "personal_account"
    OWNER_UNKNOWN = "owner_unknown"
    UNKNOWN = "unknown"


class FingerprintComponentCategory(StrEnum):
    EXECUTABLE = "executable"
    PACKAGE = "package"
    DEPENDENCY = "dependency"
    CONFIGURATION = "configuration"
    PROVIDER = "provider"
    MODEL = "model"
    PROTOCOL = "protocol"
    RUNTIME = "runtime"
    NETWORK = "network"
    CAPABILITY = "capability"
    IDENTITY = "identity"
    BEHAVIOR = "behavior"


class ResolutionSignalCategory(StrEnum):
    EXACT_PROVIDER_IDS = "exact provider IDs"
    TENANT_IDS = "tenant IDs"
    APP_REGISTRATION_IDS = "app registration IDs"
    ENDPOINT_DEVICE_IDS = "endpoint device IDs"
    PROCESS_AND_EXECUTABLE_HASHES = "process and executable hashes"
    PACKAGE_LOCKFILES = "package lockfiles"
    REPOSITORY_ORIGIN = "repository origin"
    API_ENDPOINT = "API endpoint"
    MODEL_DEPLOYMENT_ID = "model deployment ID"
    MCP_SERVER_URL = "MCP server URL"
    MCP_SCHEMA_FINGERPRINT = "MCP schema fingerprint"
    SERVICE_PRINCIPAL = "service principal"
    KUBERNETES_WORKLOAD_UID = "Kubernetes workload UID"
    SAAS_TENANT_ID = "SaaS tenant ID"
    USER_IDENTITY = "user identity"
    NETWORK_DESTINATION = "network destination"
    CONFIGURATION_PATH = "configuration path"
    TOOL_FINGERPRINT = "tool fingerprint"


class ResolutionActorRole(StrEnum):
    SYSTEM = "system"
    OWNER = "owner"
    ADMIN = "admin"


_CANONICAL_ERROR = "invalid HMAIR canonical material"


def _require_nfc_strings(value: object) -> None:
    """Reject hostile/deep model input before Pydantic retains it in errors."""

    stack: list[tuple[object, int, bool]] = [(value, 0, False)]
    active_containers: set[int] = set()
    try:
        while stack:
            current, depth, exiting = stack.pop()
            if exiting:
                active_containers.remove(id(current))
                continue
            if depth > MAX_FLEXIBLE_DEPTH:
                raise ValueError("HMAIR input exceeds its structural boundary")
            if type(current) is str:
                if unicodedata.normalize("NFC", current) != current:
                    raise ValueError("HMAIR text must use NFC")
                current.encode("utf-8", errors="strict")
                continue
            if isinstance(current, Mapping):
                identity = id(current)
                if identity in active_containers:
                    raise ValueError("HMAIR values cannot reuse or cycle containers")
                active_containers.add(identity)
                if len(current) > MAX_FLEXIBLE_ITEMS:
                    raise ValueError("HMAIR input contains too many object entries")
                stack.append((current, depth, True))
                for key, item in current.items():
                    if type(key) is not str:
                        raise ValueError("HMAIR object keys must be strings")
                    if unicodedata.normalize("NFC", key) != key:
                        raise ValueError("HMAIR text must use NFC")
                    key.encode("utf-8", errors="strict")
                    stack.append((item, depth + 1, False))
                continue
            if type(current) in {list, tuple}:
                identity = id(current)
                if identity in active_containers:
                    raise ValueError("HMAIR values cannot reuse or cycle containers")
                active_containers.add(identity)
                if len(current) > MAX_FLEXIBLE_ITEMS:
                    raise ValueError("HMAIR input contains too many array items")
                stack.append((current, depth, True))
                stack.extend((item, depth + 1, False) for item in current)
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        raise ValueError("invalid HMAIR contract structure") from None


def _preflight_canonical_value(value: object) -> None:
    stack: list[tuple[object, int, bool]] = [(value, 0, False)]
    active_containers: set[int] = set()
    while stack:
        current, depth, exiting = stack.pop()
        if exiting:
            active_containers.remove(id(current))
            continue
        if depth > MAX_FLEXIBLE_DEPTH:
            raise ValueError(_CANONICAL_ERROR)
        if current is None or type(current) is bool:
            continue
        if type(current) is int:
            if not -(1 << 63) <= current <= (1 << 63) - 1:
                raise ValueError(_CANONICAL_ERROR)
            continue
        if type(current) is float:
            if not math.isfinite(current) or (
                current == 0.0 and math.copysign(1.0, current) < 0.0
            ):
                raise ValueError(_CANONICAL_ERROR)
            continue
        if type(current) is str:
            if unicodedata.normalize("NFC", current) != current:
                raise ValueError(_CANONICAL_ERROR)
            current.encode("utf-8", errors="strict")
            continue
        if isinstance(current, StrEnum):
            stack.append((current.value, depth, False))
            continue
        if isinstance(current, Mapping):
            identity = id(current)
            if identity in active_containers:
                raise ValueError(_CANONICAL_ERROR)
            active_containers.add(identity)
            if len(current) > MAX_FLEXIBLE_ITEMS:
                raise ValueError(_CANONICAL_ERROR)
            stack.append((current, depth, True))
            for key, item in current.items():
                if type(key) is not str:
                    raise ValueError(_CANONICAL_ERROR)
                if unicodedata.normalize("NFC", key) != key:
                    raise ValueError(_CANONICAL_ERROR)
                key.encode("utf-8", errors="strict")
                stack.append((item, depth + 1, False))
            continue
        if type(current) in {list, tuple}:
            identity = id(current)
            if identity in active_containers:
                raise ValueError(_CANONICAL_ERROR)
            active_containers.add(identity)
            if len(current) > MAX_FLEXIBLE_ITEMS:
                raise ValueError(_CANONICAL_ERROR)
            stack.append((current, depth, True))
            stack.extend((item, depth + 1, False) for item in current)
            continue
        raise ValueError(_CANONICAL_ERROR)


def _canonical_native(value: object, *, seen: set[int]) -> object:
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if not -(1 << 63) <= value <= (1 << 63) - 1:
            raise ValueError(_CANONICAL_ERROR)
        return value
    if type(value) is float:
        if not math.isfinite(value) or (
            value == 0.0 and math.copysign(1.0, value) < 0.0
        ):
            raise ValueError(_CANONICAL_ERROR)
        return value
    if type(value) is str:
        if unicodedata.normalize("NFC", value) != value:
            raise ValueError(_CANONICAL_ERROR)
        value.encode("utf-8", errors="strict")
        return value
    if isinstance(value, StrEnum):
        return _canonical_native(value.value, seen=seen)
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in seen:
            raise ValueError(_CANONICAL_ERROR)
        seen.add(identity)
        native: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError(_CANONICAL_ERROR)
            if unicodedata.normalize("NFC", key) != key:
                raise ValueError(_CANONICAL_ERROR)
            key.encode("utf-8", errors="strict")
            native[key] = _canonical_native(item, seen=seen)
        seen.remove(identity)
        return native
    if type(value) in {list, tuple}:
        identity = id(value)
        if identity in seen:
            raise ValueError(_CANONICAL_ERROR)
        seen.add(identity)
        native_items = [_canonical_native(item, seen=seen) for item in value]
        seen.remove(identity)
        return native_items
    raise ValueError(_CANONICAL_ERROR)


def canonical_json_bytes(value: object) -> bytes:
    """Serialize exact H1B replay material without revealing rejected input."""

    try:
        _preflight_canonical_value(value)
        native = _canonical_native(value, seen=set())
        return json.dumps(
            native,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8", errors="strict")
    except (
        TypeError,
        ValueError,
        UnicodeError,
        OverflowError,
        RecursionError,
    ):
        raise ValueError(_CANONICAL_ERROR) from None


def _strict_confidence(value: object) -> float:
    if type(value) is not float:
        raise ValueError("confidence must be a Python float")
    if not math.isfinite(value):
        raise ValueError("confidence must be finite")
    if value == 0.0 and math.copysign(1.0, value) < 0.0:
        raise ValueError("confidence cannot be negative zero")
    if not 0.0 <= value <= 1.0:
        raise ValueError("confidence must be between zero and one")
    return value


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("time must include a timezone")
    return value.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _bounded_tuple_strings(
    value: tuple[str, ...],
    *,
    item_max: int,
    count_min: int,
    count_max: int,
    unique: bool,
    encoded_max: int | None = None,
    reject_untrimmed: bool = False,
    privacy_safe: bool = False,
) -> tuple[str, ...]:
    if not count_min <= len(value) <= count_max:
        raise ValueError("collection cardinality is outside its boundary")
    checked: list[str] = []
    for item in value:
        if type(item) is not str:
            raise ValueError("collection items must be strings")
        if reject_untrimmed and item != item.strip():
            raise ValueError("collection items must already be trimmed")
        item = item.strip()
        if not 1 <= len(item) <= item_max:
            raise ValueError("collection item length is outside its boundary")
        if unicodedata.normalize("NFC", item) != item:
            raise ValueError("collection items must use NFC")
        item.encode("utf-8", errors="strict")
        if privacy_safe:
            frozen = _freeze_json_value(item)
            if frozen != item:
                raise ValueError("collection item is not privacy safe")
        checked.append(item)
    result = tuple(checked)
    if unique and len(set(result)) != len(result):
        raise ValueError("collection items must be unique")
    if encoded_max is not None:
        encoded = json.dumps(
            result,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
        if len(encoded) > encoded_max:
            raise ValueError("collection exceeds its encoded byte boundary")
    return result


class _H1BContract(StrictContract):
    @model_validator(mode="before")
    @classmethod
    def require_nfc_input(cls, value: object) -> object:
        if isinstance(value, Mapping):
            try:
                if any(
                    type(key) is not str or key not in cls.model_fields
                    for key in value
                ):
                    raise ValueError("invalid HMAIR contract structure")
            except (TypeError, ValueError, RuntimeError, RecursionError):
                raise ValueError("invalid HMAIR contract structure") from None
        _require_nfc_strings(value)
        return value


class ResolutionSignal(_H1BContract):
    category: ResolutionSignalCategory


def _canonical_signals(
    value: tuple[ResolutionSignal, ...],
) -> tuple[ResolutionSignal, ...]:
    ordered = tuple(
        sorted(
            value,
            key=lambda item: canonical_json_bytes(
                {"category": item.category.value}
            ),
        )
    )
    if len({item.category for item in ordered}) != len(ordered):
        raise ValueError("resolution signal categories must be unique")
    if len(ordered) > 128:
        raise ValueError("too many resolution signals")
    if len(canonical_json_bytes(tuple(_signal_object(item) for item in ordered))) > 16384:
        raise ValueError("resolution signals exceed their encoded byte boundary")
    return ordered


def _signal_object(value: ResolutionSignal) -> Mapping[str, object]:
    return MappingProxyType({"category": value.category.value})


class AIAssetCreate(_H1BContract):
    asset_type: AIAssetType
    canonical_name: str = Field(min_length=1, max_length=255)
    provider: str | None = Field(default=None, max_length=255)
    product: str | None = Field(default=None, max_length=255)
    framework: str | None = Field(default=None, max_length=255)
    version: str | None = Field(default=None, max_length=255)
    deployment_family: str | None = Field(default=None, max_length=64)
    technical_surface: str | None = Field(default=None, max_length=128)
    environment: str | None = Field(default=None, max_length=64)


class AIAssetContract(AIAssetCreate):
    asset_id: str = Field(min_length=1, max_length=36)
    tenant_id: str = Field(min_length=1, max_length=36)
    owner: None
    business_unit: None
    approved_status: str = Field(min_length=1, max_length=64)
    shadow_ai_status: ShadowAIStatus
    lifecycle_status: str = Field(min_length=1, max_length=64)
    first_seen_at: datetime
    last_seen_at: datetime
    last_used_at: None
    identity_ids: tuple[str, ...]
    runtime_ids: tuple[str, ...]
    model_ids: tuple[str, ...]
    tool_ids: tuple[str, ...]
    data_source_ids: tuple[str, ...]
    capability_profile_id: None
    fingerprint_id: str | None = Field(default=None, min_length=1, max_length=36)
    usage_profile_id: None
    control_coverage_ref: None
    resolution_confidence: float
    source_observation_ids: tuple[str, ...] = Field(
        min_length=0,
        max_length=128,
        description=(
            "Ascending non-exhaustive preview of at most 128 current source "
            "observation identifiers."
        ),
    )
    unresolved_conflicts: tuple[ResolutionSignal, ...] = Field(max_length=128)
    evidence_bundle_id: str = Field(min_length=1, max_length=36)

    @field_validator("first_seen_at", "last_seen_at")
    @classmethod
    def utc_seen_times(cls, value: datetime) -> datetime:
        return _utc_datetime(value)

    @field_validator("resolution_confidence", mode="before")
    @classmethod
    def strict_resolution_confidence(cls, value: object) -> float:
        return _strict_confidence(value)

    @field_validator("identity_ids", "runtime_ids", "model_ids", "tool_ids", "data_source_ids")
    @classmethod
    def h1b_owned_empty(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value:
            raise ValueError("field remains empty in H1B")
        return ()

    @field_validator("source_observation_ids")
    @classmethod
    def source_preview(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        checked = _bounded_tuple_strings(
            value,
            item_max=128,
            count_min=0,
            count_max=128,
            unique=True,
        )
        if checked != tuple(sorted(checked)):
            raise ValueError("source observation preview must be ascending")
        return checked

    @field_validator("unresolved_conflicts")
    @classmethod
    def canonical_conflicts(
        cls, value: tuple[ResolutionSignal, ...]
    ) -> tuple[ResolutionSignal, ...]:
        return _canonical_signals(value)

    @model_validator(mode="after")
    def seen_times_are_ordered(self) -> Self:
        if self.first_seen_at > self.last_seen_at:
            raise ValueError("asset observation times are out of order")
        return self


class EvidenceClaimCreate(_H1BContract):
    claim_type: str = Field(min_length=1, max_length=64)
    subject_observation_id: str | None = Field(
        default=None, min_length=1, max_length=128
    )
    subject_asset_id: str | None = Field(default=None, min_length=1, max_length=36)
    source_observation_id: str = Field(min_length=1, max_length=128)
    evidence_node_id: str = Field(min_length=1, max_length=36)
    claim_result: str = Field(default="unknown", min_length=1, max_length=500)
    claim_method: str = Field(min_length=1, max_length=500)
    limitations: tuple[str, ...] = Field(max_length=128)
    confidence: float
    freshness: ObservationFreshness
    observed_at: datetime
    idempotency_key: str = Field(min_length=1, max_length=128)

    @field_validator("limitations")
    @classmethod
    def bounded_limitations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _bounded_tuple_strings(
            value,
            item_max=512,
            count_min=0,
            count_max=128,
            unique=False,
            encoded_max=4096,
            privacy_safe=True,
        )

    @field_validator("confidence", mode="before")
    @classmethod
    def strict_claim_confidence(cls, value: object) -> float:
        return _strict_confidence(value)

    @field_validator("observed_at")
    @classmethod
    def utc_observed_at(cls, value: datetime) -> datetime:
        return _utc_datetime(value)

    @model_validator(mode="after")
    def exactly_one_subject(self) -> Self:
        if (self.subject_observation_id is None) == (self.subject_asset_id is None):
            raise ValueError("exactly one evidence claim subject is required")
        return self


_FINGERPRINT_TUPLE_FIELDS = (
    "detected_products",
    "detected_frameworks",
    "detected_models",
    "detected_protocols",
    "observed_destinations",
)


class AssetFingerprintCreate(_H1BContract):
    asset_id: str = Field(min_length=1, max_length=36)
    source_observation_id: str = Field(min_length=1, max_length=128)
    evidence_claim_id: str = Field(min_length=1, max_length=36)
    fingerprint_version: str = Field(min_length=1, max_length=64)
    component_hashes: Mapping[FingerprintComponentCategory, str] = Field(max_length=12)
    detected_products: tuple[str, ...] = Field(max_length=128)
    detected_frameworks: tuple[str, ...] = Field(max_length=128)
    detected_models: tuple[str, ...] = Field(max_length=128)
    detected_protocols: tuple[str, ...] = Field(max_length=128)
    detected_capabilities: tuple[AICapabilityType, ...] = Field(max_length=128)
    observed_destinations: tuple[str, ...] = Field(max_length=128)
    confidence: float
    supersedes_fingerprint_id: str | None = Field(
        default=None, min_length=1, max_length=36
    )
    drift_summary: Mapping[str, Any]

    @field_validator("component_hashes", mode="wrap")
    @classmethod
    def exact_component_hashes(cls, value: object, handler: Any) -> object:
        parsed = handler(value)
        if len(parsed) > 12:
            raise ValueError("too many fingerprint components")
        return MappingProxyType({key: _exact_hash(item) for key, item in parsed.items()})

    @field_serializer("component_hashes")
    def serialize_component_hashes(
        self, value: Mapping[FingerprintComponentCategory, str]
    ) -> object:
        return {key.value: item for key, item in value.items()}

    @field_validator(*_FINGERPRINT_TUPLE_FIELDS)
    @classmethod
    def canonical_string_sets(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        checked = _bounded_tuple_strings(
            value,
            item_max=512,
            count_min=0,
            count_max=128,
            unique=True,
            encoded_max=8192,
            privacy_safe=True,
        )
        return tuple(sorted(checked, key=lambda item: item.encode("utf-8")))

    @field_validator("detected_capabilities")
    @classmethod
    def canonical_capability_set(
        cls, value: tuple[AICapabilityType, ...]
    ) -> tuple[AICapabilityType, ...]:
        if len(set(value)) != len(value):
            raise ValueError("detected capabilities must be unique")
        return tuple(sorted(value, key=lambda item: item.value.encode("utf-8")))

    @field_validator("confidence", mode="before")
    @classmethod
    def strict_fingerprint_confidence(cls, value: object) -> float:
        return _strict_confidence(value)

    @field_validator("drift_summary", mode="before")
    @classmethod
    def h1b_empty_drift(cls, value: object) -> object:
        if not isinstance(value, Mapping) or len(value) != 0:
            raise ValueError("drift summary remains empty in H1B")
        return MappingProxyType({})

    @field_serializer("drift_summary")
    def serialize_drift_summary(self, value: Mapping[str, Any]) -> object:
        del value
        return {}


class AIAssetFingerprintContract(_H1BContract):
    fingerprint_id: str = Field(min_length=1, max_length=36)
    asset_id: str = Field(min_length=1, max_length=36)
    fingerprint_version: str = Field(min_length=1, max_length=64)
    component_hashes: Mapping[FingerprintComponentCategory, str] = Field(max_length=12)
    detected_products: tuple[str, ...] = Field(max_length=128)
    detected_frameworks: tuple[str, ...] = Field(max_length=128)
    detected_models: tuple[str, ...] = Field(max_length=128)
    detected_protocols: tuple[str, ...] = Field(max_length=128)
    detected_capabilities: tuple[AICapabilityType, ...] = Field(max_length=128)
    observed_destinations: tuple[str, ...] = Field(max_length=128)
    evidence_sources: tuple[str, ...] = Field(min_length=1, max_length=1)
    confidence: float
    created_at: datetime
    supersedes_fingerprint_id: str | None = Field(
        default=None, min_length=1, max_length=36
    )
    drift_summary: Mapping[str, Any]

    @field_validator("component_hashes", mode="wrap")
    @classmethod
    def exact_component_hashes(cls, value: object, handler: Any) -> object:
        parsed = handler(value)
        if len(parsed) > 12:
            raise ValueError("too many fingerprint components")
        return MappingProxyType(
            {key: _exact_hash(item) for key, item in parsed.items()}
        )

    @field_serializer("component_hashes")
    def serialize_component_hashes(
        self, value: Mapping[FingerprintComponentCategory, str]
    ) -> object:
        return {key.value: item for key, item in value.items()}

    @field_validator(*_FINGERPRINT_TUPLE_FIELDS)
    @classmethod
    def canonical_string_sets(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        checked = _bounded_tuple_strings(
            value,
            item_max=512,
            count_min=0,
            count_max=128,
            unique=True,
            encoded_max=8192,
            privacy_safe=True,
        )
        return tuple(sorted(checked, key=lambda item: item.encode("utf-8")))

    @field_validator("detected_capabilities")
    @classmethod
    def canonical_capability_set(
        cls, value: tuple[AICapabilityType, ...]
    ) -> tuple[AICapabilityType, ...]:
        if len(set(value)) != len(value):
            raise ValueError("detected capabilities must be unique")
        return tuple(sorted(value, key=lambda item: item.value.encode("utf-8")))

    @field_validator("drift_summary", mode="before")
    @classmethod
    def h1b_empty_drift(cls, value: object) -> object:
        if not isinstance(value, Mapping) or len(value) != 0:
            raise ValueError("drift summary remains empty in H1B")
        return MappingProxyType({})

    @field_serializer("drift_summary")
    def serialize_drift_summary(self, value: Mapping[str, Any]) -> object:
        del value
        return {}

    @field_validator("evidence_sources", mode="before")
    @classmethod
    def exact_claim_reference(cls, value: object) -> tuple[str, ...]:
        if type(value) not in {list, tuple}:
            raise ValueError("evidence source must be an exact tuple")
        return _bounded_tuple_strings(
            tuple(value),
            item_max=36,
            count_min=1,
            count_max=1,
            unique=True,
            reject_untrimmed=True,
        )

    @field_validator("confidence", mode="before")
    @classmethod
    def strict_contract_confidence(cls, value: object) -> float:
        return _strict_confidence(value)

    @field_validator("created_at")
    @classmethod
    def utc_created_at(cls, value: datetime) -> datetime:
        return _utc_datetime(value)


class AICapabilityAssertionCreate(_H1BContract):
    asset_id: str = Field(min_length=1, max_length=36)
    source_observation_id: str = Field(min_length=1, max_length=128)
    evidence_claim_id: str = Field(min_length=1, max_length=36)
    name: AICapabilityType
    state: AICapabilityState
    confidence: float
    first_observed_at: datetime
    last_observed_at: datetime
    extractor_version: str = Field(min_length=1, max_length=64)
    supersedes_capability_id: str | None = Field(
        default=None, min_length=1, max_length=36
    )

    @field_validator("confidence", mode="before")
    @classmethod
    def strict_capability_confidence(cls, value: object) -> float:
        return _strict_confidence(value)

    @field_validator("first_observed_at", "last_observed_at")
    @classmethod
    def utc_capability_times(cls, value: datetime) -> datetime:
        return _utc_datetime(value)

    @model_validator(mode="after")
    def ordered_capability_times(self) -> Self:
        if self.first_observed_at > self.last_observed_at:
            raise ValueError("capability observation times are out of order")
        return self


class AICapabilityContract(_H1BContract):
    name: AICapabilityType
    state: AICapabilityState
    evidence: tuple[str, ...] = Field(min_length=1, max_length=1)
    confidence: float
    first_observed_at: datetime
    last_observed_at: datetime
    extractor_version: str = Field(min_length=1, max_length=64)

    @field_validator("evidence", mode="before")
    @classmethod
    def exact_claim_reference(cls, value: object) -> tuple[str, ...]:
        if type(value) not in {list, tuple}:
            raise ValueError("evidence must be an exact tuple")
        return _bounded_tuple_strings(
            tuple(value),
            item_max=36,
            count_min=1,
            count_max=1,
            unique=True,
            reject_untrimmed=True,
        )

    @field_validator("confidence", mode="before")
    @classmethod
    def strict_capability_confidence(cls, value: object) -> float:
        return _strict_confidence(value)

    @field_validator("first_observed_at", "last_observed_at")
    @classmethod
    def utc_capability_times(cls, value: datetime) -> datetime:
        return _utc_datetime(value)

    @model_validator(mode="after")
    def ordered_capability_times(self) -> Self:
        if self.first_observed_at > self.last_observed_at:
            raise ValueError("capability observation times are out of order")
        return self


class ResolutionActor(_H1BContract):
    actor_id: str = Field(min_length=1, max_length=128)
    actor_role: ResolutionActorRole


class _SignalFields(_H1BContract):
    matched_signals: tuple[ResolutionSignal, ...] = Field(max_length=128)
    conflicting_signals: tuple[ResolutionSignal, ...] = Field(max_length=128)
    confidence: float
    algorithm_version: str = Field(min_length=1, max_length=64)

    @field_validator("matched_signals", "conflicting_signals")
    @classmethod
    def canonical_signal_tuples(
        cls, value: tuple[ResolutionSignal, ...]
    ) -> tuple[ResolutionSignal, ...]:
        return _canonical_signals(value)

    @field_validator("confidence", mode="before")
    @classmethod
    def strict_resolution_confidence(cls, value: object) -> float:
        return _strict_confidence(value)


class ResolutionRequest(_SignalFields):
    candidate_observation_ids: tuple[str, ...] = Field(min_length=1, max_length=128)
    new_asset: AIAssetCreate | None = None
    existing_asset_id: str | None = Field(default=None, min_length=1, max_length=36)
    evidence_claim_id: str = Field(min_length=1, max_length=36)
    evidence_node_id: str = Field(min_length=1, max_length=36)
    idempotency_key: str = Field(min_length=1, max_length=128)
    reason: str | None = Field(default=None, min_length=1, max_length=500)

    @field_validator("candidate_observation_ids")
    @classmethod
    def candidate_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _bounded_tuple_strings(
            value, item_max=128, count_min=1, count_max=128, unique=True
        )

    @model_validator(mode="after")
    def at_most_one_target(self) -> Self:
        if self.new_asset is not None and self.existing_asset_id is not None:
            raise ValueError("resolution request permits at most one target")
        return self


class AssetMergeRequest(_SignalFields):
    source_asset_ids: tuple[str, ...] = Field(min_length=2, max_length=128)
    result_asset_id: str = Field(min_length=1, max_length=36)
    candidate_observation_ids: tuple[str, ...] = Field(min_length=1, max_length=128)
    evidence_claim_id: str = Field(min_length=1, max_length=36)
    evidence_node_id: str = Field(min_length=1, max_length=36)
    idempotency_key: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=500)

    @field_validator("source_asset_ids")
    @classmethod
    def source_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _bounded_tuple_strings(
            value, item_max=36, count_min=2, count_max=128, unique=True
        )

    @field_validator("candidate_observation_ids")
    @classmethod
    def candidate_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _bounded_tuple_strings(
            value, item_max=128, count_min=1, count_max=128, unique=True
        )


class SplitPartition(_SignalFields):
    candidate_observation_ids: tuple[str, ...] = Field(min_length=1, max_length=128)
    new_asset: AIAssetCreate | None = None
    existing_asset_id: str | None = Field(default=None, min_length=1, max_length=36)
    evidence_claim_id: str = Field(min_length=1, max_length=36)
    evidence_node_id: str = Field(min_length=1, max_length=36)

    @field_validator("candidate_observation_ids")
    @classmethod
    def candidate_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _bounded_tuple_strings(
            value, item_max=128, count_min=1, count_max=128, unique=True
        )

    @model_validator(mode="after")
    def exactly_one_target(self) -> Self:
        if (self.new_asset is None) == (self.existing_asset_id is None):
            raise ValueError("split partition requires exactly one target")
        return self


def _partition_identity(value: SplitPartition) -> bytes:
    return canonical_json_bytes(
        {
            "candidate_observation_ids": tuple(sorted(value.candidate_observation_ids)),
            "new_asset": _asset_create_object(value.new_asset),
            "existing_asset_id": value.existing_asset_id,
            "matched_signals": tuple(_signal_object(item) for item in value.matched_signals),
            "conflicting_signals": tuple(
                _signal_object(item) for item in value.conflicting_signals
            ),
            "confidence": value.confidence,
            "algorithm_version": value.algorithm_version,
            "evidence_claim_id": value.evidence_claim_id,
            "evidence_node_id": value.evidence_node_id,
        }
    )


class AssetSplitRequest(_H1BContract):
    idempotency_key: str = Field(min_length=1, max_length=128)
    source_asset_id: str = Field(min_length=1, max_length=36)
    reason: str = Field(min_length=1, max_length=500)
    event_evidence_claim_id: str = Field(min_length=1, max_length=36)
    event_evidence_node_id: str = Field(min_length=1, max_length=36)
    partitions: tuple[SplitPartition, ...] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def distinct_partition_authority(self) -> Self:
        claims = tuple(item.evidence_claim_id for item in self.partitions)
        if self.event_evidence_claim_id in claims or len(set(claims)) != len(claims):
            raise ValueError("split claims must be distinct")
        candidates = tuple(
            candidate
            for partition in self.partitions
            for candidate in partition.candidate_observation_ids
        )
        if len(set(candidates)) != len(candidates):
            raise ValueError("split candidates must not overlap")
        existing_targets = tuple(
            item.existing_asset_id
            for item in self.partitions
            if item.existing_asset_id is not None
        )
        if len(set(existing_targets)) != len(existing_targets):
            raise ValueError("split result targets must be distinct")
        new_targets = tuple(
            canonical_json_bytes(_asset_create_object(item.new_asset))
            for item in self.partitions
            if item.new_asset is not None
        )
        if len(set(new_targets)) != len(new_targets):
            raise ValueError("split new-asset targets must be distinct")
        identities = tuple(_partition_identity(item) for item in self.partitions)
        if len(set(identities)) != len(identities):
            raise ValueError("split partition material must be distinct")
        return self


class HistoryReversalRequest(_H1BContract):
    idempotency_key: str = Field(min_length=1, max_length=128)
    reversal_of_event_id: str = Field(min_length=1, max_length=36)
    reason: str = Field(min_length=1, max_length=500)
    evidence_claim_id: str = Field(min_length=1, max_length=36)
    evidence_node_id: str = Field(min_length=1, max_length=36)


class ResolutionDecisionContract(_SignalFields):
    decision_id: str = Field(min_length=1, max_length=36)
    candidate_observation_ids: tuple[str, ...] = Field(min_length=1, max_length=128)
    canonical_asset_id: str | None = Field(
        default=None, min_length=1, max_length=36
    )
    action: ResolutionAction
    created_at: datetime

    @field_validator("candidate_observation_ids")
    @classmethod
    def candidate_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _bounded_tuple_strings(
            value, item_max=128, count_min=1, count_max=128, unique=True
        )

    @field_validator("created_at")
    @classmethod
    def utc_created_at(cls, value: datetime) -> datetime:
        return _utc_datetime(value)

    @model_validator(mode="after")
    def decision_asset_shape(self) -> Self:
        history_action = self.action in {
            ResolutionAction.CREATE,
            ResolutionAction.ATTACH,
            ResolutionAction.MERGE,
        }
        if history_action != (self.canonical_asset_id is not None):
            raise ValueError("decision asset does not match action")
        return self


class ResolutionResult(_H1BContract):
    decision: ResolutionDecisionContract
    asset: AIAssetContract | None

    @model_validator(mode="after")
    def associated_asset(self) -> Self:
        if self.decision.canonical_asset_id is None:
            if self.asset is not None:
                raise ValueError("non-asset decision cannot return an asset")
        elif self.asset is None or self.asset.asset_id != self.decision.canonical_asset_id:
            raise ValueError("result asset does not match its decision")
        return self


class ResolutionOperationResult(_H1BContract):
    history_event_id: str = Field(min_length=1, max_length=36)
    results: tuple[ResolutionResult, ...]


def _asset_create_object(value: AIAssetCreate | None) -> Mapping[str, object] | None:
    if value is None:
        return None
    return MappingProxyType(
        {
            "asset_type": value.asset_type.value,
            "canonical_name": value.canonical_name,
            "provider": value.provider,
            "product": value.product,
            "framework": value.framework,
            "version": value.version,
            "deployment_family": value.deployment_family,
            "technical_surface": value.technical_surface,
            "environment": value.environment,
        }
    )


def _lp_bytes(value: bytes) -> bytes:
    return str(len(value)).encode("ascii") + b":" + value


def _lp_text(value: str) -> bytes:
    return _lp_bytes(value.encode("utf-8", errors="strict"))


def _sha256(*parts: bytes) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.hexdigest()


def _validated_tenant_id(value: object) -> str:
    if (
        type(value) is not str
        or value != value.strip()
        or not 1 <= len(value) <= 36
        or unicodedata.normalize("NFC", value) != value
    ):
        raise ValueError(_CANONICAL_ERROR)
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ValueError(_CANONICAL_ERROR) from None
    return value


@dataclass(frozen=True, slots=True)
class _CanonicalInputMaterial:
    canonical_object: Mapping[str, object]
    canonical_bytes: bytes
    input_digest: str


@dataclass(frozen=True, slots=True)
class _CanonicalDecisionMaterial:
    operation_index: int
    child_object: Mapping[str, object] | None
    child_bytes: bytes | None
    child_material_digest: str | None
    nonhistory_object: Mapping[str, object] | None
    nonhistory_bytes: bytes | None
    decision_idempotency_key: str
    decision_input_digest: str


@dataclass(frozen=True, slots=True)
class _CanonicalResolutionMaterial:
    event_object: Mapping[str, object] | None
    event_bytes: bytes | None
    event_input_digest: str | None
    decisions: tuple[_CanonicalDecisionMaterial, ...]


def _canonicalize_evidence_claim_input(
    *, tenant_id: str, payload: EvidenceClaimCreate
) -> _CanonicalInputMaterial:
    tenant_id = _validated_tenant_id(tenant_id)
    canonical_object = MappingProxyType(
        {
            "claim_method": payload.claim_method,
            "claim_result": payload.claim_result,
            "claim_type": payload.claim_type,
            "confidence": payload.confidence,
            "evidence_node_id": payload.evidence_node_id,
            "freshness": payload.freshness.value,
            "limitations": payload.limitations,
            "observed_at": _utc_text(payload.observed_at),
            "schema_version": "hmair-h1b-evidence-claim-v1",
            "source_observation_id": payload.source_observation_id,
            "subject_asset_id": payload.subject_asset_id,
            "subject_observation_id": payload.subject_observation_id,
            "tenant_id": tenant_id,
        }
    )
    canonical_bytes = canonical_json_bytes(canonical_object)
    return _CanonicalInputMaterial(
        canonical_object,
        canonical_bytes,
        _sha256(b"hmair:h1b:evidence-claim-input:v1", _lp_bytes(canonical_bytes)),
    )


def _canonicalize_asset_fingerprint_input(
    *, tenant_id: str, payload: AssetFingerprintCreate
) -> _CanonicalInputMaterial:
    tenant_id = _validated_tenant_id(tenant_id)
    canonical_object = MappingProxyType(
        {
            "asset_id": payload.asset_id,
            "component_hashes": MappingProxyType(
                {key.value: value for key, value in payload.component_hashes.items()}
            ),
            "confidence": payload.confidence,
            "detected_capabilities": tuple(item.value for item in payload.detected_capabilities),
            "detected_frameworks": payload.detected_frameworks,
            "detected_models": payload.detected_models,
            "detected_products": payload.detected_products,
            "detected_protocols": payload.detected_protocols,
            "drift_summary": MappingProxyType({}),
            "evidence_claim_id": payload.evidence_claim_id,
            "fingerprint_version": payload.fingerprint_version,
            "observed_destinations": payload.observed_destinations,
            "schema_version": "hmair-h1b-asset-fingerprint-v1",
            "source_observation_id": payload.source_observation_id,
            "supersedes_fingerprint_id": payload.supersedes_fingerprint_id,
            "tenant_id": tenant_id,
        }
    )
    canonical_bytes = canonical_json_bytes(canonical_object)
    return _CanonicalInputMaterial(
        canonical_object,
        canonical_bytes,
        _sha256(b"hmair:h1b:asset-fingerprint-input:v1", _lp_bytes(canonical_bytes)),
    )


def _canonicalize_ai_capability_input(
    *, tenant_id: str, payload: AICapabilityAssertionCreate
) -> _CanonicalInputMaterial:
    tenant_id = _validated_tenant_id(tenant_id)
    canonical_object = MappingProxyType(
        {
            "asset_id": payload.asset_id,
            "confidence": payload.confidence,
            "evidence_claim_id": payload.evidence_claim_id,
            "extractor_version": payload.extractor_version,
            "first_observed_at": _utc_text(payload.first_observed_at),
            "last_observed_at": _utc_text(payload.last_observed_at),
            "name": payload.name.value,
            "schema_version": "hmair-h1b-ai-capability-v1",
            "source_observation_id": payload.source_observation_id,
            "state": payload.state.value,
            "supersedes_capability_id": payload.supersedes_capability_id,
            "tenant_id": tenant_id,
        }
    )
    canonical_bytes = canonical_json_bytes(canonical_object)
    return _CanonicalInputMaterial(
        canonical_object,
        canonical_bytes,
        _sha256(b"hmair:h1b:ai-capability-input:v1", _lp_bytes(canonical_bytes)),
    )


def _resolution_child_material_digest(canonical_child_bytes: bytes) -> str:
    return _sha256(
        b"hmair:h1b:resolution-partition:v1", _lp_bytes(canonical_child_bytes)
    )


def _decision_key(tenant_id: str, request_key: str, operation_index: int) -> str:
    return _sha256(
        b"hmair:h1b:resolution-decision:v1",
        _lp_text(tenant_id),
        _lp_text(request_key),
        _lp_text(str(operation_index)),
    )


def _child_object(
    *,
    action: ResolutionAction,
    candidate_observation_ids: tuple[str, ...],
    new_asset: AIAssetCreate | None,
    result_asset_id: str | None,
    matched_signals: tuple[ResolutionSignal, ...],
    conflicting_signals: tuple[ResolutionSignal, ...],
    confidence: float,
    algorithm_version: str,
    evidence_claim_id: str,
    evidence_node_id: str,
) -> Mapping[str, object]:
    return MappingProxyType(
        {
            "action": action.value,
            "algorithm_version": algorithm_version,
            "candidate_observation_ids": tuple(sorted(candidate_observation_ids)),
            "confidence": confidence,
            "conflicting_signals": tuple(
                _signal_object(item) for item in conflicting_signals
            ),
            "evidence_claim_id": evidence_claim_id,
            "evidence_node_id": evidence_node_id,
            "matched_signals": tuple(_signal_object(item) for item in matched_signals),
            "new_asset": _asset_create_object(new_asset),
            "result_asset_id": result_asset_id,
            "schema_version": "hmair-h1b-decision-child-v1",
        }
    )


def _event_object(
    *,
    tenant_id: str,
    actor: ResolutionActor,
    event_type: str,
    reason: str,
    event_evidence_claim_id: str,
    event_evidence_node_id: str,
    source_asset_ids: tuple[str, ...],
    reversal_of_event_id: str | None,
    children: tuple[Mapping[str, object], ...],
) -> Mapping[str, object]:
    return MappingProxyType(
        {
            "actor_id": actor.actor_id,
            "actor_role": actor.actor_role.value,
            "children": children,
            "event_evidence_claim_id": event_evidence_claim_id,
            "event_evidence_node_id": event_evidence_node_id,
            "event_type": event_type,
            "reason": reason,
            "reversal_of_event_id": reversal_of_event_id,
            "schema_version": "hmair-h1b-event-v1",
            "source_asset_ids": tuple(sorted(source_asset_ids)),
            "tenant_id": tenant_id,
        }
    )


def _history_material(
    *,
    tenant_id: str,
    actor: ResolutionActor,
    event_type: str,
    reason: str,
    event_evidence_claim_id: str,
    event_evidence_node_id: str,
    source_asset_ids: tuple[str, ...],
    request_key: str,
    children: tuple[Mapping[str, object], ...],
) -> _CanonicalResolutionMaterial:
    staged: list[tuple[str, Mapping[str, object], bytes]] = []
    for child in children:
        child_bytes = canonical_json_bytes(child)
        staged.append(
            (_resolution_child_material_digest(child_bytes), child, child_bytes)
        )
    if event_type == "split":
        staged.sort(key=lambda item: item[0])
        if len({item[0] for item in staged}) != len(staged):
            raise ValueError("split child material digests must be distinct")
    event_children = tuple(
        MappingProxyType(
            {
                "child": child,
                "child_material_digest": child_digest,
                "operation_index": index,
            }
        )
        for index, (child_digest, child, _child_bytes) in enumerate(staged)
    )
    event_object = _event_object(
        tenant_id=tenant_id,
        actor=actor,
        event_type=event_type,
        reason=reason,
        event_evidence_claim_id=event_evidence_claim_id,
        event_evidence_node_id=event_evidence_node_id,
        source_asset_ids=source_asset_ids,
        reversal_of_event_id=None,
        children=event_children,
    )
    event_bytes = canonical_json_bytes(event_object)
    event_digest = _sha256(
        b"hmair:h1b:resolution-event-input:v1", _lp_bytes(event_bytes)
    )
    decisions = tuple(
        _CanonicalDecisionMaterial(
            operation_index=index,
            child_object=child,
            child_bytes=child_bytes,
            child_material_digest=child_digest,
            nonhistory_object=None,
            nonhistory_bytes=None,
            decision_idempotency_key=_decision_key(tenant_id, request_key, index),
            decision_input_digest=_sha256(
                b"hmair:h1b:resolution-decision-input:v1",
                _lp_text(event_digest),
                _lp_text(child_digest),
            ),
        )
        for index, (child_digest, child, child_bytes) in enumerate(staged)
    )
    return _CanonicalResolutionMaterial(
        event_object, event_bytes, event_digest, decisions
    )


def _canonicalize_resolution_request(
    *,
    tenant_id: str,
    actor: ResolutionActor,
    action: ResolutionAction,
    payload: ResolutionRequest,
) -> _CanonicalResolutionMaterial:
    tenant_id = _validated_tenant_id(tenant_id)
    if action in {ResolutionAction.CREATE, ResolutionAction.ATTACH}:
        if payload.reason is None:
            raise ValueError("history-backed resolution requires a reason")
        if action is ResolutionAction.CREATE:
            if payload.new_asset is None or payload.existing_asset_id is not None:
                raise ValueError("create resolution target is invalid")
            new_asset = payload.new_asset
            result_asset_id = None
        else:
            if payload.new_asset is not None or payload.existing_asset_id is None:
                raise ValueError("attach resolution target is invalid")
            new_asset = None
            result_asset_id = payload.existing_asset_id
        child = _child_object(
            action=action,
            candidate_observation_ids=payload.candidate_observation_ids,
            new_asset=new_asset,
            result_asset_id=result_asset_id,
            matched_signals=payload.matched_signals,
            conflicting_signals=payload.conflicting_signals,
            confidence=payload.confidence,
            algorithm_version=payload.algorithm_version,
            evidence_claim_id=payload.evidence_claim_id,
            evidence_node_id=payload.evidence_node_id,
        )
        return _history_material(
            tenant_id=tenant_id,
            actor=actor,
            event_type=action.value,
            reason=payload.reason,
            event_evidence_claim_id=payload.evidence_claim_id,
            event_evidence_node_id=payload.evidence_node_id,
            source_asset_ids=(),
            request_key=payload.idempotency_key,
            children=(child,),
        )
    if action not in {ResolutionAction.REJECT, ResolutionAction.MANUAL_REVIEW}:
        raise ValueError("resolution request action is unsupported")
    if payload.new_asset is not None or payload.existing_asset_id is not None:
        raise ValueError("non-history resolution cannot carry a target")
    nonhistory_object = MappingProxyType(
        {
            "action": action.value,
            "actor_id": actor.actor_id,
            "actor_role": actor.actor_role.value,
            "algorithm_version": payload.algorithm_version,
            "candidate_observation_ids": tuple(sorted(payload.candidate_observation_ids)),
            "canonical_asset_id": None,
            "confidence": payload.confidence,
            "conflicting_signals": tuple(
                _signal_object(item) for item in payload.conflicting_signals
            ),
            "evidence_claim_id": payload.evidence_claim_id,
            "evidence_node_id": payload.evidence_node_id,
            "matched_signals": tuple(_signal_object(item) for item in payload.matched_signals),
            "schema_version": "hmair-h1b-nonhistory-decision-v1",
            "tenant_id": tenant_id,
        }
    )
    nonhistory_bytes = canonical_json_bytes(nonhistory_object)
    decision = _CanonicalDecisionMaterial(
        operation_index=0,
        child_object=None,
        child_bytes=None,
        child_material_digest=None,
        nonhistory_object=nonhistory_object,
        nonhistory_bytes=nonhistory_bytes,
        decision_idempotency_key=_decision_key(
            tenant_id, payload.idempotency_key, 0
        ),
        decision_input_digest=_sha256(
            b"hmair:h1b:resolution-nonhistory-input:v1",
            _lp_bytes(nonhistory_bytes),
        ),
    )
    return _CanonicalResolutionMaterial(None, None, None, (decision,))


def _canonicalize_merge_request(
    *, tenant_id: str, actor: ResolutionActor, payload: AssetMergeRequest
) -> _CanonicalResolutionMaterial:
    tenant_id = _validated_tenant_id(tenant_id)
    child = _child_object(
        action=ResolutionAction.MERGE,
        candidate_observation_ids=payload.candidate_observation_ids,
        new_asset=None,
        result_asset_id=payload.result_asset_id,
        matched_signals=payload.matched_signals,
        conflicting_signals=payload.conflicting_signals,
        confidence=payload.confidence,
        algorithm_version=payload.algorithm_version,
        evidence_claim_id=payload.evidence_claim_id,
        evidence_node_id=payload.evidence_node_id,
    )
    return _history_material(
        tenant_id=tenant_id,
        actor=actor,
        event_type="merge",
        reason=payload.reason,
        event_evidence_claim_id=payload.evidence_claim_id,
        event_evidence_node_id=payload.evidence_node_id,
        source_asset_ids=payload.source_asset_ids,
        request_key=payload.idempotency_key,
        children=(child,),
    )


def _canonicalize_split_request(
    *, tenant_id: str, actor: ResolutionActor, payload: AssetSplitRequest
) -> _CanonicalResolutionMaterial:
    tenant_id = _validated_tenant_id(tenant_id)
    children = tuple(
        _child_object(
            action=(
                ResolutionAction.CREATE
                if partition.new_asset is not None
                else ResolutionAction.ATTACH
            ),
            candidate_observation_ids=partition.candidate_observation_ids,
            new_asset=partition.new_asset,
            result_asset_id=partition.existing_asset_id,
            matched_signals=partition.matched_signals,
            conflicting_signals=partition.conflicting_signals,
            confidence=partition.confidence,
            algorithm_version=partition.algorithm_version,
            evidence_claim_id=partition.evidence_claim_id,
            evidence_node_id=partition.evidence_node_id,
        )
        for partition in payload.partitions
    )
    return _history_material(
        tenant_id=tenant_id,
        actor=actor,
        event_type="split",
        reason=payload.reason,
        event_evidence_claim_id=payload.event_evidence_claim_id,
        event_evidence_node_id=payload.event_evidence_node_id,
        source_asset_ids=(payload.source_asset_id,),
        request_key=payload.idempotency_key,
        children=children,
    )


def _canonicalize_reversal_request(
    *, tenant_id: str, actor: ResolutionActor, payload: HistoryReversalRequest
) -> _CanonicalResolutionMaterial:
    tenant_id = _validated_tenant_id(tenant_id)
    event_object = _event_object(
        tenant_id=tenant_id,
        actor=actor,
        event_type="reversal",
        reason=payload.reason,
        event_evidence_claim_id=payload.evidence_claim_id,
        event_evidence_node_id=payload.evidence_node_id,
        source_asset_ids=(),
        reversal_of_event_id=payload.reversal_of_event_id,
        children=(),
    )
    event_bytes = canonical_json_bytes(event_object)
    event_digest = _sha256(
        b"hmair:h1b:resolution-event-input:v1", _lp_bytes(event_bytes)
    )
    return _CanonicalResolutionMaterial(event_object, event_bytes, event_digest, ())
