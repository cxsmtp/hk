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


MICROSOFT_COPILOT_ADAPTER_VERSION = "1.0.0"
MICROSOFT_COPILOT_COLLECTOR_TYPE = "microsoft_copilot"
MICROSOFT_COPILOT_EVIDENCE_MAX_AGE = COLLECTOR_EVIDENCE_MAX_AGE
MICROSOFT_COPILOT_SOURCE_SYSTEM = (
    "microsoft_copilot_live_connector"
)
# Exact fixed event types emitted by ``_copilot_inventory_to_events``. The
# separate caller-driven M365, Copilot Studio, and Office Copilot routes are
# not part of this inventory collector declaration.
MICROSOFT_COPILOT_OBSERVATION_TYPES = (
    "copilot.inventory.activity",
    "copilot.inventory.connector",
    "copilot.inventory.graph_permission",
    "copilot.inventory.oauth_app",
    "copilot.inventory.purview_signal",
    "copilot.inventory.remediation_hook",
    "copilot.inventory.studio_agent",
)


@dataclass(frozen=True, slots=True)
class MicrosoftCopilotCollectorEvidence:
    """Exact caller-attested evidence for the pure Copilot declaration.

    Inventory availability, Graph permissions, remediation hooks, and
    ``gateway_routed`` agent hints never imply control capability. Optional
    values are projected only from literally verified, literally current,
    fresh evidence bound to every declared identity and version field.
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


def _aware_utc(value: object) -> datetime:
    try:
        return normalize_collector_timestamp(value)
    except CollectorTimestampNormalizationError:
        raise ValueError(
            "invalid Microsoft Copilot collector timestamp"
        ) from None


def _trusted_optional_timestamp(
    value: object,
    *,
    observed_at: datetime,
    evaluated_at: datetime,
) -> datetime | None:
    if value is None:
        return None
    timestamp = _aware_utc(value)
    if timestamp > observed_at or timestamp > evaluated_at:
        raise ValueError(
            "invalid Microsoft Copilot collector timestamp"
        ) from None
    return timestamp


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
        or source_system != MICROSOFT_COPILOT_SOURCE_SYSTEM
        or schema_version != COLLECTOR_CONTRACT_SCHEMA_VERSION
    ):
        raise ValueError(
            "invalid Microsoft Copilot collector declaration"
        ) from None


def build_microsoft_copilot_collector_contract(
    *,
    tenant_id: str,
    collector_id: str,
    source_system: str,
    collector_version: str,
    schema_version: str,
    evaluated_at: datetime,
    evidence: MicrosoftCopilotCollectorEvidence | None = None,
) -> DiscoveryCollectorContract:
    """Project the existing Copilot inventory connector into contract ``1.0``.

    This is an unwired declaration projection only. It does not persist
    observations, register a collector, expose an API, inspect a live tenant,
    or infer control from the existing event and inventory-sync routes.
    """

    _validate_declaration(
        tenant_id=tenant_id,
        collector_id=collector_id,
        source_system=source_system,
        collector_version=collector_version,
        schema_version=schema_version,
    )
    evaluated_at_utc = _aware_utc(evaluated_at)
    if (
        evidence is not None
        and type(evidence) is not MicrosoftCopilotCollectorEvidence
    ):
        raise ValueError(
            "invalid Microsoft Copilot collector evidence"
        ) from None

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
        assert evidence is not None
        observed_at_utc = _aware_utc(evidence.observed_at)
        age = evaluated_at_utc - observed_at_utc
        trusted = (
            age.total_seconds() >= 0
            and age <= MICROSOFT_COPILOT_EVIDENCE_MAX_AGE
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
        last_success = _trusted_optional_timestamp(
            evidence.last_success,
            observed_at=observed_at_utc,
            evaluated_at=evaluated_at_utc,
        )
        last_failure = _trusted_optional_timestamp(
            evidence.last_failure,
            observed_at=observed_at_utc,
            evaluated_at=evaluated_at_utc,
        )
        if evidence.authoritative_data_residency is not None:
            data_residency = evidence.authoritative_data_residency
        if evidence.control_capability is not None:
            control_capability = evidence.control_capability

    return DiscoveryCollectorContract.model_validate(
        {
            "collector_id": collector_id,
            "tenant_id": tenant_id,
            "collector_type": MICROSOFT_COPILOT_COLLECTOR_TYPE,
            "collector_version": collector_version,
            "source_system": source_system,
            "health": health,
            "permissions": permissions,
            "last_success": last_success,
            "last_failure": last_failure,
            "data_residency": data_residency,
            "control_capability": control_capability,
            "observation_types_emitted": list(
                MICROSOFT_COPILOT_OBSERVATION_TYPES
            ),
            "schema_version": schema_version,
        }
    )
