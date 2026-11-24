"""Strict, privacy-bounded contracts for HMAIR production Deep Scan.

Deep Scan is a control-plane request over already-authorised discovery sources.
These contracts deliberately carry opaque identifiers, safe counts, and bounded
state only; they are not a transport for source credentials or content.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha256
import re
from typing import Literal, Mapping

from pydantic import Field, StrictBool, field_validator, model_validator

from app.services.hmair.contracts import StrictContract, canonical_json_bytes
from app.services.privacy_sanitizer import redact_sensitive_text, sanitize_privacy_scalar


_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/=-]{0,127}$")
_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/=-]{0,127}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_SOURCES = 64


class DeepScanReadinessState(StrEnum):
    READY = "ready"
    PARTIAL = "partial"
    NOT_CONNECTED = "not_connected"
    UNSUPPORTED = "unsupported"
    PERMISSION_DENIED = "permission_denied"
    STALE = "stale"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class DeepScanObservationMode(StrEnum):
    AUTHORITATIVE = "authoritative"
    OBSERVED_ONLY = "observed_only"


class DeepScanCoverageState(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    EMPTY = "empty"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"
    STALE = "stale"
    UNKNOWN = "unknown"


def _safe_identifier(value: object, *, field: str) -> str:
    if type(value) is not str:
        raise ValueError(f"{field} must be a safe identifier")
    normalized = value.strip()
    if not normalized or _IDENTIFIER_RE.fullmatch(normalized) is None:
        raise ValueError(f"{field} must be a safe identifier")
    return normalized


def _safe_reference(value: object, *, field: str) -> str:
    if type(value) is not str:
        raise ValueError(f"{field} must be an opaque safe reference")
    normalized = value.strip()
    if (
        not normalized
        or _REFERENCE_RE.fullmatch(normalized) is None
        or redact_sensitive_text(normalized, max_len=128) != normalized
        or sanitize_privacy_scalar(normalized, key=field) != normalized
    ):
        raise ValueError(f"{field} must be an opaque safe reference")
    return normalized


def _utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone")
    return value.astimezone(timezone.utc)


def _unique_identifiers(value: tuple[str, ...], *, field: str) -> tuple[str, ...]:
    if not value or len(value) > _MAX_SOURCES:
        raise ValueError(f"{field} must contain between one and {_MAX_SOURCES} identifiers")
    normalized = tuple(_safe_identifier(item, field=field) for item in value)
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field} must not contain duplicates")
    return normalized


class DeepScanCoverageBaseline(StrictContract):
    expected_count: int = Field(ge=1, le=1_000_000)
    authority_kind: Literal[
        "mdm",
        "browser_management",
        "runtime_registry",
        "vendor_api",
    ]
    authority_reference: str = Field(min_length=1, max_length=128)
    verified_at: datetime
    expires_at: datetime
    managed_browser_unit_hashes: tuple[str, ...] = Field(
        default=(), max_length=10_000
    )

    @field_validator("authority_reference")
    @classmethod
    def validate_authority_reference(cls, value: str) -> str:
        return _safe_reference(value, field="authority_reference")

    @field_validator("verified_at", "expires_at")
    @classmethod
    def validate_utc_time(cls, value: datetime, info) -> datetime:  # type: ignore[no-untyped-def]
        return _utc(value, field=info.field_name)

    @model_validator(mode="after")
    def validate_lifecycle(self) -> "DeepScanCoverageBaseline":
        if self.expires_at <= self.verified_at:
            raise ValueError("baseline expiry must be after verification")
        return self

    @field_validator("managed_browser_unit_hashes")
    @classmethod
    def validate_managed_browser_unit_hashes(
        cls, value: tuple[str, ...]
    ) -> tuple[str, ...]:
        if len(set(value)) != len(value) or any(
            re.fullmatch(r"[0-9a-f]{64}", item) is None for item in value
        ):
            raise ValueError("managed browser unit hashes must be unique SHA-256 values")
        return value


class DeepScanPreflightRequest(StrictContract):
    target_ids: tuple[str, ...] = Field(min_length=1, max_length=_MAX_SOURCES)
    collector_ids: tuple[str, ...] = Field(min_length=1, max_length=_MAX_SOURCES)
    required_target_ids: tuple[str, ...] = Field(default=(), max_length=_MAX_SOURCES)
    time_window_minutes: int = Field(ge=5, le=1_440)
    customer_authorization_reference: str = Field(min_length=1, max_length=128)
    requested_mode: Literal["partial", "full_enterprise"] = "partial"

    @field_validator("target_ids", "collector_ids")
    @classmethod
    def validate_required_identifiers(cls, value: tuple[str, ...], info) -> tuple[str, ...]:  # type: ignore[no-untyped-def]
        return _unique_identifiers(value, field=info.field_name)

    @field_validator("required_target_ids")
    @classmethod
    def validate_optional_identifiers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > _MAX_SOURCES:
            raise ValueError("required_target_ids is too large")
        normalized = tuple(
            _safe_identifier(item, field="required_target_ids") for item in value
        )
        if len(set(normalized)) != len(normalized):
            raise ValueError("required_target_ids must not contain duplicates")
        return normalized

    @field_validator("customer_authorization_reference")
    @classmethod
    def validate_customer_authorization_reference(cls, value: str) -> str:
        return _safe_reference(value, field="customer_authorization_reference")

    @model_validator(mode="after")
    def validate_required_targets(self) -> "DeepScanPreflightRequest":
        if not set(self.required_target_ids).issubset(self.target_ids):
            raise ValueError("required_target_ids must be selected target_ids")
        if (
            self.requested_mode == "full_enterprise"
            and set(self.required_target_ids) != set(self.target_ids)
        ):
            raise ValueError(
                "full_enterprise requests must require every selected target"
            )
        return self


class DeepScanLaunchRequest(StrictContract):
    name: str = Field(min_length=1, max_length=255)
    preflight: DeepScanPreflightRequest
    preflight_digest: str = Field(min_length=64, max_length=64)
    dry_run: StrictBool = False

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        safe = sanitize_privacy_scalar(value, key="deep_scan_name")
        if type(safe) is not str or safe != value or not value.strip():
            raise ValueError("name must be safe metadata")
        return value.strip()

    @field_validator("preflight_digest")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if _HASH_RE.fullmatch(value) is None:
            raise ValueError("preflight_digest must be a SHA-256 digest")
        return value


class DeepScanSourceReadiness(StrictContract):
    target_id: str = Field(min_length=1, max_length=128)
    collector_id: str = Field(min_length=1, max_length=128)
    target_type: str = Field(min_length=1, max_length=64)
    required: StrictBool = False
    state: DeepScanReadinessState
    observation_mode: DeepScanObservationMode
    expected_count: int | None = Field(default=None, ge=1, le=1_000_000)
    baseline: DeepScanCoverageBaseline | None = None
    last_success_at: datetime | None = None
    limitations: tuple[str, ...] = Field(default=(), max_length=32)

    @field_validator("target_id", "collector_id", "target_type")
    @classmethod
    def validate_identifier(cls, value: str, info) -> str:  # type: ignore[no-untyped-def]
        return _safe_identifier(value, field=info.field_name)

    @field_validator("last_success_at")
    @classmethod
    def validate_last_success_at(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _utc(value, field="last_success_at")

    @field_validator("limitations")
    @classmethod
    def validate_limitations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > 32:
            raise ValueError("limitations is too large")
        return tuple(_safe_identifier(item, field="limitations") for item in value)

    @model_validator(mode="after")
    def validate_readiness(self) -> "DeepScanSourceReadiness":
        if self.state is DeepScanReadinessState.READY:
            if self.observation_mode is not DeepScanObservationMode.AUTHORITATIVE:
                raise ValueError("ready sources must be authoritative")
            if self.baseline is None or self.expected_count is None:
                raise ValueError("ready sources require an authoritative baseline")
        if self.observation_mode is DeepScanObservationMode.OBSERVED_ONLY and self.state is DeepScanReadinessState.READY:
            raise ValueError("observed-only sources cannot be ready")
        return self


class DeepScanSourceCoverage(StrictContract):
    target_id: str = Field(min_length=1, max_length=128)
    collector_id: str = Field(min_length=1, max_length=128)
    state: DeepScanCoverageState
    expected_count: int | None = Field(default=None, ge=1, le=1_000_000)
    observed_count: int = Field(ge=0, le=1_000_000)
    evidence_fresh_at: datetime | None = None
    reason: str | None = Field(default=None, max_length=128)
    completion_receipts: tuple[DeepScanUnitCompletionReceipt, ...] = Field(
        default=(), max_length=10_000
    )

    @field_validator("target_id", "collector_id")
    @classmethod
    def validate_identifier(cls, value: str, info) -> str:  # type: ignore[no-untyped-def]
        return _safe_identifier(value, field=info.field_name)

    @field_validator("evidence_fresh_at")
    @classmethod
    def validate_evidence_time(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _utc(value, field="evidence_fresh_at")

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str | None) -> str | None:
        return None if value is None else _safe_identifier(value, field="reason")

    @model_validator(mode="after")
    def validate_counts(self) -> "DeepScanSourceCoverage":
        receipt_units = tuple(
            receipt.unit_id_hash for receipt in self.completion_receipts
        )
        if len(set(receipt_units)) != len(receipt_units):
            raise ValueError("completion receipts must be unique by source unit")
        if self.state is DeepScanCoverageState.COMPLETE:
            if self.expected_count is None or self.observed_count != self.expected_count:
                raise ValueError("complete coverage must reconcile the expected count")
            if self.completion_receipts and len(receipt_units) != self.observed_count:
                raise ValueError(
                    "complete receipt coverage must reconcile unique source units"
                )
        return self


class DeepScanUnitCompletionReceipt(StrictContract):
    """Signed proof that one authoritative source unit completed its scan.

    Unit and source-record identifiers are irreversibly tenant-keyed before
    they enter this contract.  Receipts therefore close a denominator without
    copying endpoint, browser-profile, runtime, or source identifiers into the
    generic scan summary.
    """

    version: Literal["v1"] = "v1"
    scan_id: str = Field(min_length=1, max_length=36)
    target_id: str = Field(min_length=1, max_length=128)
    collector_id: str = Field(min_length=1, max_length=128)
    tenant_binding_hash: str = Field(min_length=64, max_length=64)
    unit_id_hash: str = Field(min_length=64, max_length=64)
    source_record_hash: str = Field(min_length=64, max_length=64)
    observed_at: datetime
    status: Literal["complete"] = "complete"
    signing_key_id: str = Field(min_length=1, max_length=128)
    receipt_digest: str = Field(min_length=64, max_length=64)
    signature: str = Field(min_length=64, max_length=64)

    @field_validator("scan_id", "target_id", "collector_id", "signing_key_id")
    @classmethod
    def validate_identifiers(cls, value: str, info) -> str:  # type: ignore[no-untyped-def]
        return _safe_identifier(value, field=info.field_name)

    @field_validator(
        "tenant_binding_hash",
        "unit_id_hash",
        "source_record_hash",
        "receipt_digest",
        "signature",
    )
    @classmethod
    def validate_hashes(cls, value: str) -> str:
        if _HASH_RE.fullmatch(value) is None:
            raise ValueError("completion receipt hashes must be SHA-256 digests")
        return value

    @field_validator("observed_at")
    @classmethod
    def validate_observed_at(cls, value: datetime) -> datetime:
        return _utc(value, field="observed_at")


DeepScanSourceCoverage.model_rebuild()


class DeepScanProfile(StrictContract):
    version: Literal["v1"]
    mode: Literal["partial", "full_enterprise"]
    sources: tuple[DeepScanSourceReadiness, ...] = Field(min_length=1, max_length=_MAX_SOURCES)
    customer_authorization_reference: str = Field(min_length=1, max_length=128)
    window_start: datetime
    window_end: datetime
    issued_at: datetime
    expires_at: datetime
    digest: str = Field(min_length=64, max_length=64)

    @field_validator("customer_authorization_reference")
    @classmethod
    def validate_authorization_reference(cls, value: str) -> str:
        return _safe_reference(value, field="customer_authorization_reference")

    @field_validator("window_start", "window_end", "issued_at", "expires_at")
    @classmethod
    def validate_utc_times(cls, value: datetime, info) -> datetime:  # type: ignore[no-untyped-def]
        return _utc(value, field=info.field_name)

    @field_validator("digest")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if _HASH_RE.fullmatch(value) is None:
            raise ValueError("digest must be a SHA-256 digest")
        return value

    @model_validator(mode="after")
    def validate_profile_lifecycle(self) -> "DeepScanProfile":
        source_ids = tuple(source.target_id for source in self.sources)
        if len(set(source_ids)) != len(source_ids):
            raise ValueError("profile sources must be unique by target")
        if not self.window_start < self.window_end:
            raise ValueError("profile window must be ordered")
        if self.expires_at <= self.issued_at:
            raise ValueError("profile expiry must be after issuance")
        return self


class DeepScanStoredProfile(StrictContract):
    """The safe, immutable profile representation stored with a scan.

    A customer authorization reference is necessary to validate a live
    preflight, but it must not be copied into generic scan scope. That scope
    deliberately rejects authorization-bearing material. A one-way binding
    records that a reviewed reference was used without retaining it.
    """

    version: Literal["v1"]
    mode: Literal["partial", "full_enterprise"]
    sources: tuple[DeepScanSourceReadiness, ...] = Field(min_length=1, max_length=_MAX_SOURCES)
    customer_approval_binding_hash: str = Field(min_length=64, max_length=64)
    window_start: datetime
    window_end: datetime
    issued_at: datetime
    expires_at: datetime
    digest: str = Field(min_length=64, max_length=64)
    storage_digest: str = Field(min_length=64, max_length=64)

    @field_validator("customer_approval_binding_hash", "digest", "storage_digest")
    @classmethod
    def validate_hashes(cls, value: str) -> str:
        if _HASH_RE.fullmatch(value) is None:
            raise ValueError("stored profile hashes must be SHA-256 digests")
        return value

    @field_validator("window_start", "window_end", "issued_at", "expires_at")
    @classmethod
    def validate_utc_times(cls, value: datetime, info) -> datetime:  # type: ignore[no-untyped-def]
        return _utc(value, field=info.field_name)

    @model_validator(mode="after")
    def validate_profile_lifecycle(self) -> "DeepScanStoredProfile":
        source_ids = tuple(source.target_id for source in self.sources)
        if len(set(source_ids)) != len(source_ids):
            raise ValueError("profile sources must be unique by target")
        if not self.window_start < self.window_end:
            raise ValueError("profile window must be ordered")
        if self.expires_at <= self.issued_at:
            raise ValueError("profile expiry must be after issuance")
        material = self.model_dump(mode="json", exclude={"storage_digest"})
        if deep_scan_profile_digest(material) != self.storage_digest:
            raise ValueError("stored profile integrity digest does not match")
        return self


class DeepScanPreflightResult(StrictContract):
    profile: DeepScanProfile
    preflight_digest: str = Field(min_length=64, max_length=64)
    sources: tuple[DeepScanSourceReadiness, ...] = Field(min_length=1, max_length=_MAX_SOURCES)
    required_gaps: tuple[str, ...] = Field(default=(), max_length=_MAX_SOURCES)
    ready_assignment_count: int = Field(ge=0, le=_MAX_SOURCES)
    exhaustive_claim_permitted: StrictBool

    @field_validator("required_gaps")
    @classmethod
    def validate_required_gaps(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > _MAX_SOURCES:
            raise ValueError("required_gaps is too large")
        return tuple(_safe_identifier(item, field="required_gaps") for item in value)

    @field_validator("preflight_digest")
    @classmethod
    def validate_preflight_digest(cls, value: str) -> str:
        if _HASH_RE.fullmatch(value) is None:
            raise ValueError("preflight_digest must be a SHA-256 digest")
        return value


class DeepScanCoverage(StrictContract):
    scan_id: str = Field(min_length=1, max_length=36)
    sources: tuple[DeepScanSourceCoverage, ...] = Field(min_length=1, max_length=_MAX_SOURCES)
    exhaustive_claim_permitted: StrictBool

    @field_validator("scan_id")
    @classmethod
    def validate_scan_id(cls, value: str) -> str:
        return _safe_identifier(value, field="scan_id")


def deep_scan_profile_digest(value: object) -> str:
    """Return the deterministic SHA-256 digest for safe profile material."""

    return sha256(canonical_json_bytes(value)).hexdigest()


def deep_scan_approval_binding_hash(reference: str) -> str:
    """Create a non-reversible binding for a validated customer approval ref."""

    return deep_scan_profile_digest(
        {"version": "v1", "customer_approval_reference": reference}
    )


def persist_deep_scan_profile(profile: DeepScanProfile) -> DeepScanStoredProfile:
    """Produce the only Deep Scan profile shape allowed in generic scan scope."""

    normalized = profile.model_dump(mode="json")
    material: dict[str, object] = {
        "version": normalized["version"],
        "mode": normalized["mode"],
        "sources": normalized["sources"],
        "customer_approval_binding_hash": deep_scan_approval_binding_hash(
            profile.customer_authorization_reference
        ),
        "window_start": normalized["window_start"],
        "window_end": normalized["window_end"],
        "issued_at": normalized["issued_at"],
        "expires_at": normalized["expires_at"],
        "digest": normalized["digest"],
    }
    return DeepScanStoredProfile.model_validate(
        {
            **material,
            "storage_digest": deep_scan_profile_digest(material),
        }
    )


def parse_persisted_deep_scan_profile(value: object) -> DeepScanStoredProfile:
    """Load persisted data, retaining read compatibility for legacy rows.

    Legacy rows may contain a preflight-only reference. They are converted in
    memory and are never returned. New rows require the safe stored shape.
    """

    if not isinstance(value, Mapping):
        raise ValueError("stored Deep Scan profile must be an object")
    material = dict(value)
    if (
        "customer_authorization_reference" in material
        and "customer_approval_binding_hash" not in material
    ):
        return persist_deep_scan_profile(DeepScanProfile.model_validate(material))
    return DeepScanStoredProfile.model_validate(material)


def deep_scan_preflight_digest(
    request: DeepScanPreflightRequest,
    sources: tuple[DeepScanSourceReadiness, ...],
) -> str:
    """Digest stable selection/readiness facts, excluding issued timestamps.

    The frozen profile has its own digest.  This separate digest lets launch
    repeat preflight immediately before creation without treating a new
    ``issued_at`` value as a customer selection change.
    """

    return sha256(
        canonical_json_bytes(
            {
                "version": "v1",
                "request": request.model_dump(mode="json"),
                "sources": [source.model_dump(mode="json") for source in sources],
            }
        )
    ).hexdigest()


__all__ = [
    "DeepScanCoverage",
    "DeepScanCoverageBaseline",
    "DeepScanCoverageState",
    "DeepScanLaunchRequest",
    "DeepScanObservationMode",
    "DeepScanPreflightRequest",
    "DeepScanPreflightResult",
    "DeepScanProfile",
    "DeepScanStoredProfile",
    "DeepScanReadinessState",
    "DeepScanSourceCoverage",
    "DeepScanSourceReadiness",
    "DeepScanUnitCompletionReceipt",
    "deep_scan_approval_binding_hash",
    "deep_scan_preflight_digest",
    "deep_scan_profile_digest",
    "parse_persisted_deep_scan_profile",
    "persist_deep_scan_profile",
]
