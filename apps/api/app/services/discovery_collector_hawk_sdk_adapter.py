from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.services.collector_timestamp import (
    CollectorTimestampNormalizationError,
    normalize_collector_timestamp,
)
from app.services.discovery_collector_contract import (
    CollectorControlCapability,
    CollectorHealth,
    DiscoveryCollectorContract,
)
from app.services.health_freshness import COLLECTOR_EVIDENCE_MAX_AGE


HAWK_SDK_SOURCE_SYSTEM = "sdk"
HAWK_SDK_COLLECTOR_TYPE = "sdk"
HAWK_SDK_EVIDENCE_MAX_AGE = COLLECTOR_EVIDENCE_MAX_AGE
HAWK_SDK_OBSERVATION_TYPES = (
    "data_transfer_check",
    "data_transfer_justification",
    "llm_intercept",
    "mcp_authorize",
    "mcp_tool_scanned",
)


@dataclass(frozen=True, slots=True)
class HawkSDKCollectorEvidence:
    """Explicit current evidence for the pure Hawk SDK collector projection."""

    tenant_id: str
    collector_id: str
    source_system: str
    collector_version: str
    schema_version: str
    verified: bool = False
    current: bool = False
    observed_at: datetime | None = None
    health: CollectorHealth | None = None
    verified_permissions: dict[str, bool | None] | None = None
    last_success: datetime | None = None
    last_failure: datetime | None = None
    authoritative_data_residency: str | None = None
    control_capability: CollectorControlCapability | None = None


def _aware_utc(value: object) -> datetime:
    try:
        return normalize_collector_timestamp(value)
    except CollectorTimestampNormalizationError:
        raise ValueError("invalid Hawk SDK collector timestamp") from None


def _optional_aware_utc(value: object) -> datetime | None:
    return None if value is None else _aware_utc(value)


def _validate_declaration(
    *,
    tenant_id: object,
    collector_id: object,
    source_system: object,
    collector_version: object,
    schema_version: object,
) -> None:
    if (
        type(tenant_id) is not str
        or type(collector_id) is not str
        or type(source_system) is not str
        or type(collector_version) is not str
        or type(schema_version) is not str
    ):
        raise ValueError("invalid Hawk SDK collector declaration") from None
    if source_system != HAWK_SDK_SOURCE_SYSTEM or schema_version != "1.0":
        raise ValueError("invalid Hawk SDK collector declaration") from None


def build_hawk_sdk_collector_contract(
    *,
    tenant_id: str,
    collector_id: str,
    source_system: str,
    collector_version: str,
    schema_version: str,
    evaluated_at: datetime,
    evidence: HawkSDKCollectorEvidence | None = None,
) -> DiscoveryCollectorContract:
    """Project declared SDK observations without inferring installation or control."""

    _validate_declaration(
        tenant_id=tenant_id,
        collector_id=collector_id,
        source_system=source_system,
        collector_version=collector_version,
        schema_version=schema_version,
    )
    evaluated_at_utc = _aware_utc(evaluated_at)
    if evidence is not None and type(evidence) is not HawkSDKCollectorEvidence:
        raise ValueError("invalid Hawk SDK collector evidence") from None

    asserted_current = (
        evidence is not None
        and evidence.verified is True
        and evidence.current is True
    )
    scope_matches = (
        asserted_current
        and type(evidence.tenant_id) is str
        and evidence.tenant_id == tenant_id
        and type(evidence.collector_id) is str
        and evidence.collector_id == collector_id
        and type(evidence.source_system) is str
        and evidence.source_system == source_system
        and type(evidence.collector_version) is str
        and evidence.collector_version == collector_version
        and type(evidence.schema_version) is str
        and evidence.schema_version == schema_version
    )

    trusted = False
    observed_at_utc: datetime | None = None
    if scope_matches:
        observed_at_utc = _aware_utc(evidence.observed_at)
        age = evaluated_at_utc - observed_at_utc
        trusted = (
            age.total_seconds() >= 0
            and age <= HAWK_SDK_EVIDENCE_MAX_AGE
        )

    health: CollectorHealth = "unknown"
    permissions: dict[str, bool | None] = {"unknown": None}
    last_success: datetime | None = None
    last_failure: datetime | None = None
    data_residency = "unknown"
    control_capability: CollectorControlCapability = "unknown"

    if trusted:
        assert evidence is not None
        assert observed_at_utc is not None
        last_success = _optional_aware_utc(evidence.last_success)
        last_failure = _optional_aware_utc(evidence.last_failure)
        for timestamp in (last_success, last_failure):
            if (
                timestamp is not None
                and (
                    timestamp > observed_at_utc
                    or timestamp > evaluated_at_utc
                )
            ):
                raise ValueError("invalid Hawk SDK collector timestamp") from None
        if evidence.health is not None:
            health = evidence.health
        if evidence.verified_permissions is not None:
            permissions = evidence.verified_permissions
        if evidence.authoritative_data_residency is not None:
            data_residency = evidence.authoritative_data_residency
        if evidence.control_capability is not None:
            # The current SDK lifecycle remains post-action/shadow-only in the
            # depth plan. A caller attestation cannot upgrade it to prevention.
            if not (
                type(evidence.control_capability) is str
                and evidence.control_capability == "inline"
            ):
                control_capability = evidence.control_capability

    return DiscoveryCollectorContract.model_validate(
        {
            "collector_id": collector_id,
            "tenant_id": tenant_id,
            "collector_type": HAWK_SDK_COLLECTOR_TYPE,
            "collector_version": collector_version,
            "source_system": source_system,
            "health": health,
            "permissions": permissions,
            "last_success": last_success,
            "last_failure": last_failure,
            "data_residency": data_residency,
            "control_capability": control_capability,
            "observation_types_emitted": list(HAWK_SDK_OBSERVATION_TYPES),
            "schema_version": schema_version,
        }
    )
