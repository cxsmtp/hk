from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.services.collector_timestamp import (
    CollectorTimestampNormalizationError,
    normalize_collector_timestamp,
)
from app.services.discovery_collector_contract import (
    COLLECTOR_CONTRACT_SCHEMA_VERSION,
    CollectorControlCapability,
    CollectorHealth,
    DiscoveryCollectorContract,
)
from app.services.health_freshness import COLLECTOR_EVIDENCE_MAX_AGE


LLM_GATEWAY_ADAPTER_VERSION = "1.0.0"
LLM_GATEWAY_EVIDENCE_MAX_AGE = COLLECTOR_EVIDENCE_MAX_AGE
LLM_GATEWAY_SOURCE_SYSTEM = "llm_gateway"
LLM_GATEWAY_OBSERVATION_TYPES = (
    "llm_gateway.chat.complete",
    "llm_gateway.request",
    "llm_gateway.response",
)


@dataclass(frozen=True, slots=True)
class LLMGatewayCollectorEvidence:
    """Caller-attested current evidence used by the pure gateway projection.

    The adapter trusts optional values only when both ``verified`` and
    ``current`` are the literal boolean ``True``. It never derives coverage
    from gateway settings, registration, provider configuration, or routes.
    """

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


def _aware_utc(value: object, *, field_name: str) -> datetime:
    del field_name
    normalization_failed = False
    try:
        normalized = normalize_collector_timestamp(value)
    except CollectorTimestampNormalizationError:
        normalization_failed = True
    if normalization_failed:
        raise ValueError("invalid LLM Gateway collector timestamp") from None
    return normalized


def _optional_aware_utc(
    value: object,
    *,
    field_name: str,
) -> datetime | None:
    return None if value is None else _aware_utc(value, field_name=field_name)


def _trusted_event_timestamp(
    value: object,
    *,
    field_name: str,
    observed_at_utc: datetime,
) -> datetime | None:
    timestamp = _optional_aware_utc(value, field_name=field_name)
    if timestamp is not None and timestamp > observed_at_utc:
        raise ValueError("invalid LLM Gateway collector timestamp") from None
    return timestamp


def build_llm_gateway_collector_contract(
    *,
    tenant_id: str,
    collector_id: str,
    evaluated_at: datetime,
    evidence: LLMGatewayCollectorEvidence | None = None,
) -> DiscoveryCollectorContract:
    """Project explicit current LLM Gateway evidence into contract version 1.0."""

    evaluated_at_utc = _aware_utc(evaluated_at, field_name="evaluated_at")
    if evidence is not None and type(evidence) is not LLMGatewayCollectorEvidence:
        raise ValueError("invalid LLM Gateway collector evidence") from None

    asserted_current = (
        evidence is not None
        and evidence.verified is True
        and evidence.current is True
    )
    scope_matches = (
        asserted_current
        and type(tenant_id) is str
        and type(collector_id) is str
        and type(evidence.tenant_id) is str
        and evidence.tenant_id == tenant_id
        and type(evidence.collector_id) is str
        and evidence.collector_id == collector_id
        and type(evidence.source_system) is str
        and evidence.source_system == LLM_GATEWAY_SOURCE_SYSTEM
        and type(evidence.collector_version) is str
        and evidence.collector_version == LLM_GATEWAY_ADAPTER_VERSION
        and type(evidence.schema_version) is str
        and evidence.schema_version == COLLECTOR_CONTRACT_SCHEMA_VERSION
    )
    trusted = False
    observed_at_utc: datetime | None = None
    if scope_matches:
        observed_at_utc = _aware_utc(
            evidence.observed_at,
            field_name="observed_at",
        )
        evidence_age = evaluated_at_utc - observed_at_utc
        trusted = (
            evidence_age.total_seconds() >= 0
            and evidence_age <= LLM_GATEWAY_EVIDENCE_MAX_AGE
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
        if evidence.health is not None:
            health = evidence.health
        if evidence.verified_permissions is not None:
            permissions = evidence.verified_permissions
        last_success = _trusted_event_timestamp(
            evidence.last_success,
            field_name="last_success",
            observed_at_utc=observed_at_utc,
        )
        last_failure = _trusted_event_timestamp(
            evidence.last_failure,
            field_name="last_failure",
            observed_at_utc=observed_at_utc,
        )
        if evidence.authoritative_data_residency is not None:
            data_residency = evidence.authoritative_data_residency
        if evidence.control_capability is not None:
            control_capability = evidence.control_capability

    return DiscoveryCollectorContract.model_validate(
        {
            "collector_id": collector_id,
            "tenant_id": tenant_id,
            "collector_type": "llm_gateway",
            "collector_version": LLM_GATEWAY_ADAPTER_VERSION,
            "source_system": LLM_GATEWAY_SOURCE_SYSTEM,
            "health": health,
            "permissions": permissions,
            "last_success": last_success,
            "last_failure": last_failure,
            "data_residency": data_residency,
            "control_capability": control_capability,
            "observation_types_emitted": list(LLM_GATEWAY_OBSERVATION_TYPES),
            "schema_version": COLLECTOR_CONTRACT_SCHEMA_VERSION,
        }
    )
