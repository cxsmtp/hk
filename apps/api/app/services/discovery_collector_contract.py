from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import inspect
import json
import re
from types import MappingProxyType
from typing import Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    ValidationError,
    ValidationInfo,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic_core import PydanticCustomError

from app.services.privacy_sanitizer import redact_sensitive_text


COLLECTOR_CONTRACT_SCHEMA_VERSION = "1.0"
MAX_IDENTIFIER_CHARS = 128
MAX_VERSION_CHARS = 64
MAX_PERMISSIONS = 64
MAX_OBSERVATION_TYPES = 64
MAX_TIMESTAMP_CHARS = 64

CollectorHealth = Literal["healthy", "warning", "degraded", "offline", "unknown"]
CollectorControlCapability = Literal[
    "inline",
    "warn_only",
    "monitor_only",
    "external_required",
    "unknown",
]

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
_IDENTIFIER_FIELDS = {
    "collector_id",
    "tenant_id",
    "collector_type",
    "source_system",
    "data_residency",
}
_STRING_FIELDS = _IDENTIFIER_FIELDS | {
    "collector_version",
    "health",
    "control_capability",
    "schema_version",
}
_TIMESTAMP_FIELDS = {"last_success", "last_failure"}
_EXPECTED_TOP_LEVEL_FIELDS = frozenset(
    {
        "collector_id",
        "tenant_id",
        "collector_type",
        "collector_version",
        "source_system",
        "health",
        "permissions",
        "last_success",
        "last_failure",
        "data_residency",
        "control_capability",
        "observation_types_emitted",
        "schema_version",
    }
)
_TIMESTAMP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,6})?"
    r"(?:Z|[+-]\d{2}:\d{2})\Z"
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


def _preflight_text(value: object, *, field_name: str, max_chars: int) -> None:
    if type(value) is not str:
        raise ValueError(f"{field_name} must be a string")
    if not value or len(value) > max_chars:
        raise ValueError(
            f"{field_name} must contain between 1 and {max_chars} characters"
        )


def _safe_identifier(value: str, *, field_name: str) -> str:
    if value != value.strip() or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ValueError(f"{field_name} must use the bounded ASCII identifier grammar")
    if redact_sensitive_text(value, max_len=MAX_IDENTIFIER_CHARS) != value:
        raise ValueError(f"{field_name} cannot contain secret or personal data")
    return value


def _utc_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("collector timestamps must include a timezone")
    return value.astimezone(timezone.utc)


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


def _sanitized_validation_error(error: ValidationError) -> ValidationError:
    safe_lines: list[dict[str, object]] = []
    for detail in error.errors(
        include_url=False,
        include_context=False,
        include_input=False,
    )[: len(_EXPECTED_TOP_LEVEL_FIELDS)]:
        location = detail.get("loc")
        safe_location: tuple[str, ...] = ()
        if (
            isinstance(location, tuple)
            and location
            and isinstance(location[0], str)
            and location[0] in _EXPECTED_TOP_LEVEL_FIELDS
        ):
            safe_location = (location[0],)
        safe_lines.append(
            {
                "type": PydanticCustomError(
                    "collector_contract_invalid",
                    "invalid discovery collector contract",
                ),
                "loc": safe_location,
                "input": None,
            }
        )
    if not safe_lines:
        safe_lines.append(
            {
                "type": PydanticCustomError(
                    "collector_contract_invalid",
                    "invalid discovery collector contract",
                ),
                "loc": (),
                "input": None,
            }
        )
    return ValidationError.from_exception_data(
        "DiscoveryCollectorContract",
        safe_lines,
        hide_input=True,
    )


class DiscoveryCollectorContract(BaseModel):
    """Immutable, bounded v1 declaration shared by Hawk discovery collectors.

    This model describes a collector. It deliberately does not derive control
    capability from health, permissions, collector type, or source system.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
    )

    collector_id: str
    tenant_id: str
    collector_type: str
    collector_version: str
    source_system: str
    health: CollectorHealth
    permissions: Mapping[str, StrictBool | None] = Field(
        min_length=1,
        max_length=MAX_PERMISSIONS,
    )
    last_success: datetime | None
    last_failure: datetime | None
    data_residency: str
    control_capability: CollectorControlCapability
    observation_types_emitted: tuple[str, ...] = Field(
        min_length=1,
        max_length=MAX_OBSERVATION_TYPES,
    )
    schema_version: Literal["1.0"]

    def __init__(self, **data: object) -> None:
        try:
            super().__init__(**data)
        except ValidationError as error:
            raise _sanitized_validation_error(error) from None

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
            raise _sanitized_validation_error(error) from None

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
            raise _sanitized_validation_error(error) from None

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
            raise _sanitized_validation_error(error) from None

    @model_validator(mode="before")
    @classmethod
    def _bounded_preflight(cls, value: object) -> object:
        if type(value) is not dict:
            raise ValueError("collector contract must be a plain object")
        data: dict[object, object] = value
        if len(data) != len(_EXPECTED_TOP_LEVEL_FIELDS):
            raise ValueError("collector contract fields do not match schema version 1.0")
        if any(type(key) is not str for key in data):
            raise ValueError("collector contract fields do not match schema version 1.0")
        if frozenset(data) != _EXPECTED_TOP_LEVEL_FIELDS:
            raise ValueError("collector contract fields do not match schema version 1.0")

        for field_name in _STRING_FIELDS:
            if field_name not in data:
                continue
            max_chars = (
                MAX_VERSION_CHARS
                if field_name in {"collector_version", "schema_version"}
                else MAX_IDENTIFIER_CHARS
            )
            _preflight_text(
                data[field_name],
                field_name=field_name,
                max_chars=max_chars,
            )

        permissions = data.get("permissions")
        if permissions is not None:
            if type(permissions) is not dict:
                raise ValueError("permissions must be a plain object")
            if not 1 <= len(permissions) <= MAX_PERMISSIONS:
                raise ValueError(
                    f"permissions must contain between 1 and {MAX_PERMISSIONS} entries"
                )
            for key, assertion in permissions.items():
                _preflight_text(
                    key,
                    field_name="permission name",
                    max_chars=MAX_IDENTIFIER_CHARS,
                )
                if type(assertion) is not bool and assertion is not None:
                    raise ValueError(
                        "permission assertions must be true, false, or null (unknown)"
                    )

        observations = data.get("observation_types_emitted")
        if observations is not None:
            if type(observations) not in {list, tuple}:
                raise ValueError("observation_types_emitted must be a list or tuple")
            if not 1 <= len(observations) <= MAX_OBSERVATION_TYPES:
                raise ValueError(
                    "observation_types_emitted must contain between 1 and "
                    f"{MAX_OBSERVATION_TYPES} entries"
                )
            for item in observations:
                _preflight_text(
                    item,
                    field_name="observation type",
                    max_chars=MAX_IDENTIFIER_CHARS,
                )

        for field_name in _TIMESTAMP_FIELDS:
            timestamp = data.get(field_name)
            if timestamp is None:
                continue
            if type(timestamp) is str:
                if (
                    not timestamp
                    or len(timestamp) > MAX_TIMESTAMP_CHARS
                    or _TIMESTAMP_RE.fullmatch(timestamp) is None
                ):
                    raise ValueError(
                        f"{field_name} must use bounded timezone-aware ISO-8601"
                    )
            elif type(timestamp) is not datetime:
                raise ValueError(
                    f"{field_name} must be an ISO-8601 string, datetime, or null"
                )
        return value

    @field_validator(
        "collector_id",
        "tenant_id",
        "collector_type",
        "source_system",
        "data_residency",
    )
    @classmethod
    def _validate_identifier(cls, value: str, info: ValidationInfo) -> str:
        return _safe_identifier(value, field_name=info.field_name)

    @field_validator("collector_version")
    @classmethod
    def _validate_version(cls, value: str) -> str:
        if value != value.strip() or _VERSION_RE.fullmatch(value) is None:
            raise ValueError("collector_version must use the bounded version grammar")
        if redact_sensitive_text(value, max_len=MAX_VERSION_CHARS) != value:
            raise ValueError("collector_version cannot contain secret or personal data")
        return value

    @field_validator("permissions")
    @classmethod
    def _validate_permissions(
        cls,
        value: Mapping[str, StrictBool | None],
    ) -> Mapping[str, StrictBool | None]:
        normalized: dict[str, StrictBool | None] = {}
        for permission, assertion in value.items():
            safe_permission = _safe_identifier(
                permission,
                field_name="permission name",
            )
            normalized[safe_permission] = assertion
        return MappingProxyType(dict(sorted(normalized.items())))

    @field_serializer("permissions")
    def _serialize_permissions(
        self,
        value: Mapping[str, StrictBool | None],
    ) -> dict[str, StrictBool | None]:
        return dict(value)

    @field_validator("observation_types_emitted")
    @classmethod
    def _validate_observation_types(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    _safe_identifier(item, field_name="observation type")
                    for item in value
                }
            )
        )

    @field_validator("last_success", "last_failure")
    @classmethod
    def _validate_timestamp(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _utc_timestamp(value)

    def canonical_projection(self) -> dict[str, Any]:
        """Return the complete, JSON-native v1 contract projection."""

        return self.model_dump(mode="json")

    def canonical_json(self) -> str:
        """Return a stable representation suitable for evidence references."""

        return json.dumps(
            self.canonical_projection(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )

    @property
    def contract_hash(self) -> str:
        """Tenant- and source-separated digest of the complete declaration."""

        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        del deep
        material = self.model_dump(mode="python")
        if update is not None:
            if type(update) is not dict or len(update) > len(
                _EXPECTED_TOP_LEVEL_FIELDS
            ):
                raise _sanitized_validation_error(
                    ValidationError.from_exception_data(
                        "DiscoveryCollectorContract",
                        [
                            {
                                "type": PydanticCustomError(
                                    "collector_contract_invalid",
                                    "invalid discovery collector contract",
                                ),
                                "loc": (),
                                "input": None,
                            }
                        ],
                        hide_input=True,
                    )
                )
            material.update(update)
        return type(self).model_validate(material)
