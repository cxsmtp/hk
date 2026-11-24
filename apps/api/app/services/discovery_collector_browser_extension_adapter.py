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


# Adapter implementation release. The projected collector version is the
# explicitly declared extension runtime version, not this implementation value.
BROWSER_EXTENSION_ADAPTER_VERSION = "1.0.0"
BROWSER_EXTENSION_EVIDENCE_MAX_AGE = COLLECTOR_EVIDENCE_MAX_AGE
BROWSER_EXTENSION_SOURCE_SYSTEM = "browser_extension"
# Exact ``extension/src/telemetry.ts`` BrowserEventType values after
# ``process_browser_telemetry_event`` signal-type normalization, plus the
# existing ``browser.interaction.eval`` evidence signal from the interaction
# endpoint. Keep this declaration explicit so the pure adapter has no runtime
# dependency on the extension or database-backed browser service.
BROWSER_EXTENSION_OBSERVATION_TYPES = (
    "browser.ai_app_opened",
    "browser.ai_domain_visit",
    "browser.backend_unreachable",
    "browser.browser_automation_action",
    "browser.browser_automation_blocked",
    "browser.browser_automation_detected",
    "browser.clipboard_copy_detected",
    "browser.clipboard_cut_detected",
    "browser.clipboard_paste_detected",
    "browser.context_invalidated",
    "browser.context_recovered",
    "browser.data_transfer_check",
    "browser.data_transfer_justification",
    "browser.extension_connected",
    "browser.extension_error",
    "browser.extension_health_status",
    "browser.extension_installed",
    "browser.file_upload_attempted",
    "browser.file_upload_detected",
    "browser.interaction.eval",
    "browser.meeting_ai_notetaker_block_requested",
    "browser.meeting_ai_notetaker_detected",
    "browser.output_flagged",
    "browser.paste_into_ai_app",
    "browser.policy_blocked",
    "browser.policy_sync_failed",
    "browser.policy_sync_success",
    "browser.policy_warned",
    "browser.prompt_blocked",
    "browser.prompt_drafted",
    "browser.prompt_held",
    "browser.prompt_submitted",
    "browser.prompt_warned",
    "browser.telemetry_queued",
    "shadow_ai.browser_agent_runtime_discovered",
    "shadow_ai.browser_unknown_domain",
)


@dataclass(frozen=True, slots=True)
class BrowserExtensionCollectorEvidence:
    """Direct, scope-bound evidence for the pure Browser Extension projection.

    The closed contract vocabulary includes ``inline`` for other collectors,
    but the current Browser Extension lifecycle remains post-action/shadow-only.
    This adapter therefore never projects ``inline`` even when caller-attested.
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
        raise ValueError("invalid Browser Extension collector timestamp") from None


def _trusted_optional_timestamp(
    value: object,
    *,
    observed_at: datetime,
) -> datetime | None:
    if value is None:
        return None
    timestamp = _aware_utc(value)
    if timestamp > observed_at:
        raise ValueError("invalid Browser Extension collector timestamp") from None
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
        or source_system != BROWSER_EXTENSION_SOURCE_SYSTEM
        or schema_version != COLLECTOR_CONTRACT_SCHEMA_VERSION
    ):
        raise ValueError(
            "invalid Browser Extension collector declaration"
        ) from None


def build_browser_extension_collector_contract(
    *,
    tenant_id: str,
    collector_id: str,
    source_system: str,
    collector_version: str,
    schema_version: str,
    evaluated_at: datetime,
    evidence: BrowserExtensionCollectorEvidence | None = None,
) -> DiscoveryCollectorContract:
    """Project only direct, current Browser Extension evidence into contract 1.0.

    Source, runtime version, and schema are caller declarations. Evidence must
    match all three exactly before it can upgrade any Unknown contract field.
    """

    _validate_declaration(
        tenant_id=tenant_id,
        collector_id=collector_id,
        source_system=source_system,
        collector_version=collector_version,
        schema_version=schema_version,
    )
    evaluated_at_utc = _aware_utc(evaluated_at)
    if evidence is not None and type(evidence) is not BrowserExtensionCollectorEvidence:
        raise ValueError("invalid Browser Extension collector evidence") from None

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
        evidence_age = evaluated_at_utc - observed_at_utc
        trusted = (
            evidence_age.total_seconds() >= 0
            and evidence_age <= BROWSER_EXTENSION_EVIDENCE_MAX_AGE
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
        )
        last_failure = _trusted_optional_timestamp(
            evidence.last_failure,
            observed_at=observed_at_utc,
        )
        if evidence.authoritative_data_residency is not None:
            data_residency = evidence.authoritative_data_residency
        if evidence.control_capability is not None:
            # Phase 5 keeps Browser Extension post-action/shadow-only. Requiring
            # direct evidence is necessary but not sufficient to claim inline.
            if (
                type(evidence.control_capability) is not str
                or evidence.control_capability != "inline"
            ):
                control_capability = evidence.control_capability

    return DiscoveryCollectorContract.model_validate(
        {
            "collector_id": collector_id,
            "tenant_id": tenant_id,
            "collector_type": "browser_extension",
            "collector_version": collector_version,
            "source_system": source_system,
            "health": health,
            "permissions": permissions,
            "last_success": last_success,
            "last_failure": last_failure,
            "data_residency": data_residency,
            "control_capability": control_capability,
            "observation_types_emitted": list(
                BROWSER_EXTENSION_OBSERVATION_TYPES
            ),
            "schema_version": schema_version,
        }
    )
