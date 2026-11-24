"""Strict privacy-safe contracts for customer-owned HMAIR source connectors."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from enum import StrEnum
import ipaddress
import re
from types import MappingProxyType
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import Field, StrictBool, field_serializer, field_validator, model_validator

from app.services.hmair.contracts import (
    ObservationType,
    SourceSurface,
    StrictContract,
    _bounded_frozen_json,
)


class HMAIRSourceProvider(StrEnum):
    MICROSOFT365 = "hmair_microsoft365_copilot"
    GITHUB_CLOUD = "hmair_github_cloud"
    GITHUB_GHES = "hmair_github_ghes"


TARGET_TYPE_BY_PROVIDER = MappingProxyType(
    {
        HMAIRSourceProvider.MICROSOFT365: "saas_tenant",
        HMAIRSourceProvider.GITHUB_CLOUD: "repository_org",
        HMAIRSourceProvider.GITHUB_GHES: "repository_org",
    }
)

SOURCE_FLAG_BY_PROVIDER = MappingProxyType(
    {
        HMAIRSourceProvider.MICROSOFT365: "hmair_microsoft365_source",
        HMAIRSourceProvider.GITHUB_CLOUD: "hmair_github_cloud_source",
        HMAIRSourceProvider.GITHUB_GHES: "hmair_github_ghes_source",
    }
)

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_GHES_ALLOWED_CREDENTIALS = frozenset({"access_token"})
_M365_ALLOWED_CREDENTIALS = frozenset({"tenant_id", "client_id", "client_secret"})
_GITHUB_CLOUD_ALLOWED_CREDENTIALS = frozenset(
    {"app_id", "installation_id", "private_key_pem"}
)
_CREDENTIAL_KEYS = MappingProxyType(
    {
        HMAIRSourceProvider.MICROSOFT365: _M365_ALLOWED_CREDENTIALS,
        HMAIRSourceProvider.GITHUB_CLOUD: _GITHUB_CLOUD_ALLOWED_CREDENTIALS,
        HMAIRSourceProvider.GITHUB_GHES: _GHES_ALLOWED_CREDENTIALS,
    }
)


def _safe_identifier(value: str, *, field_name: str) -> str:
    normalized = value.strip()
    if _SAFE_IDENTIFIER.fullmatch(normalized) is None:
        raise ValueError(f"{field_name} must be a safe opaque identifier")
    return normalized


def _validate_ghes_origin(value: str) -> str:
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("GHES target_identifier must be an HTTPS origin")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise ValueError("GHES target_identifier cannot use an IP literal")
    host = parsed.hostname.lower().rstrip(".")
    port = f":{parsed.port}" if parsed.port not in {None, 443} else ""
    return f"https://{host}{port}"


class HMAIRSourceConnectionInput(StrictContract):
    """Write-only connection input. Credentials are never serialized."""

    provider_key: HMAIRSourceProvider
    display_name: str = Field(min_length=1, max_length=128)
    target_identifier: str = Field(min_length=1, max_length=512)
    environment: str = Field(min_length=1, max_length=64)
    authorization_reference: str = Field(min_length=1, max_length=128)
    requested_capabilities: tuple[str, ...] = Field(min_length=1, max_length=16)
    include_entra_account_evidence: StrictBool = False
    metadata: Mapping[str, Any] = Field(default_factory=dict)
    credentials: Mapping[str, str] = Field(min_length=1, max_length=8, exclude=True)

    @field_validator("display_name", "environment", "authorization_reference")
    @classmethod
    def _safe_scalar(cls, value: str, info: Any) -> str:
        return _safe_identifier(value, field_name=info.field_name)

    @field_validator("target_identifier")
    @classmethod
    def _target_identifier(cls, value: str, info: Any) -> str:
        provider = info.data.get("provider_key")
        if provider == HMAIRSourceProvider.GITHUB_GHES:
            return _validate_ghes_origin(value)
        return _safe_identifier(value, field_name="target_identifier")

    @field_validator("requested_capabilities")
    @classmethod
    def _capabilities(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(
            _safe_identifier(item, field_name="requested_capabilities") for item in value
        )
        if len(set(normalized)) != len(normalized):
            raise ValueError("requested_capabilities must be unique")
        return normalized

    @field_validator("metadata")
    @classmethod
    def _metadata_is_privacy_safe(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        checked = _bounded_frozen_json(value)
        if not isinstance(checked, Mapping):
            raise ValueError("metadata must be a mapping")
        return checked

    @field_validator("credentials")
    @classmethod
    def _credentials_shape(cls, value: Mapping[str, str], info: Any) -> Mapping[str, str]:
        provider = info.data.get("provider_key")
        if not isinstance(provider, HMAIRSourceProvider):
            raise ValueError("provider_key is required before credentials")
        allowed = _CREDENTIAL_KEYS[provider]
        if set(value) != allowed:
            raise ValueError("credentials do not match the approved source contract")
        if any(not isinstance(item, str) or not item.strip() for item in value.values()):
            raise ValueError("credentials must contain non-empty strings")
        return MappingProxyType(dict(value))

    @model_validator(mode="after")
    def _provider_capabilities(self) -> "HMAIRSourceConnectionInput":
        if (
            self.include_entra_account_evidence
            and self.provider_key is not HMAIRSourceProvider.MICROSOFT365
        ):
            raise ValueError("Entra account evidence is only available for Microsoft 365")
        account_scope_kind = str(self.metadata.get("account_scope_kind") or "ORGANIZATION").upper()
        if self.provider_key is HMAIRSourceProvider.GITHUB_CLOUD and account_scope_kind not in {
            "ORGANIZATION",
            "PERSONAL",
        }:
            raise ValueError("account_scope_kind must be ORGANIZATION or PERSONAL")
        if self.provider_key is HMAIRSourceProvider.GITHUB_GHES and account_scope_kind != "ORGANIZATION":
            raise ValueError("account_scope_kind must be ORGANIZATION for GitHub Enterprise Server")
        return self

    @field_serializer("metadata")
    def _serialize_metadata(self, value: Mapping[str, Any]) -> Mapping[str, Any]:
        return dict(value)


class HMAIRSourceCapability(StrictContract):
    provider_key: HMAIRSourceProvider
    state: Literal[
        "not_connected",
        "ready",
        "partial",
        "empty",
        "stale",
        "permission_denied",
        "unsupported",
        "failed",
    ]
    allowed_capabilities: tuple[str, ...] = Field(max_length=16)
    denominator: int | None = Field(default=None, ge=0, le=10_000_000)
    fresh_at: datetime | None = None
    limitations: tuple[str, ...] = Field(max_length=32)

    @field_validator("allowed_capabilities", "limitations")
    @classmethod
    def _safe_strings(cls, value: tuple[str, ...], info: Any) -> tuple[str, ...]:
        return tuple(_safe_identifier(item, field_name=info.field_name) for item in value)

    @field_validator("fresh_at")
    @classmethod
    def _fresh_at_is_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("fresh_at must include a timezone")
        return value.astimezone(timezone.utc)


class HMAIRNormalizedRecord(StrictContract):
    """One bounded source fact, already stripped of source content."""

    record_id: str = Field(min_length=1, max_length=128)
    record_kind: str = Field(min_length=1, max_length=64)
    observed_at: datetime
    candidate_asset_type: str = Field(min_length=1, max_length=64)
    observation_type: ObservationType
    source_surface: SourceSurface = SourceSurface.SAAS
    identifiers: Mapping[str, str] = Field(max_length=16)
    metadata: Mapping[str, Any] = Field(default_factory=dict)

    @field_validator("record_id", "record_kind", "candidate_asset_type")
    @classmethod
    def _record_scalar(cls, value: str, info: Any) -> str:
        return _safe_identifier(value, field_name=info.field_name)

    @field_validator("observed_at")
    @classmethod
    def _observed_at_is_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("identifiers")
    @classmethod
    def _identifiers_are_safe(cls, value: Mapping[str, str]) -> Mapping[str, str]:
        checked = _bounded_frozen_json(value)
        if not isinstance(checked, Mapping) or any(
            not isinstance(item, str) for item in checked.values()
        ):
            raise ValueError("identifiers must contain safe strings")
        return checked

    @field_validator("metadata")
    @classmethod
    def _record_metadata_is_safe(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        checked = _bounded_frozen_json(value)
        if not isinstance(checked, Mapping):
            raise ValueError("metadata must be a mapping")
        return checked

    @field_serializer("identifiers", "metadata")
    def _serialize_flexible_values(self, value: Mapping[str, Any]) -> Mapping[str, Any]:
        return dict(value)


class HMAIRSourceCollectionResult(StrictContract):
    capability: HMAIRSourceCapability
    records: tuple[HMAIRNormalizedRecord, ...] = Field(max_length=10_000)
    entra_records: tuple[HMAIRNormalizedRecord, ...] = Field(max_length=10_000)
