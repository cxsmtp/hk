"""Metadata-only evidence bridges for HMAIR Production Deep Scan.

The bridge reads existing, tenant-scoped evidence.  It deliberately does not
open browser profiles, scrape endpoints, inspect raw prompt bodies, or read
tool arguments/results.  An empty result means that the connected source
returned no usable safe metadata in the requested window; it is never proof
that the source, application, tool, or estate is absent.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import re

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.discovery_canonical import DiscoveryTarget
from app.db.models.endpoint_identity import EndpointDeviceIdentity
from app.db.models.monitoring import Connector, MonitoringSignal
from app.db.models.runtime_intelligence import RuntimeEvent
from app.services.hmair.collector_sdk import CollectorTerminalOutcome
from app.services.hmair.collectors.h4_catalog import H4_CONNECTOR_TARGET_TYPES
from app.services.hmair.deep_scan_contracts import DeepScanUnitCompletionReceipt
from app.services.hmair.deep_scan_receipt_service import (
    issue_deep_scan_unit_completion_receipt,
)
from app.services.connector_secret_service import decrypt_connector_secrets
from app.services.hmair.contracts import (
    ContradictionState,
    DiscoveryObservationInput,
    EvidenceMode,
    EvidenceMutability,
    FactVerificationState,
    ObservationFreshness,
    ObservationType,
    ObservedFactState,
    SourceSurface,
    SourceTrust,
    canonical_json_bytes,
    CollectorRunStatus,
)
from app.services.monitoring_service import run_connector_once
from app.services.hmair.source_connectors.contracts import (
    HMAIRSourceConnectionInput,
    HMAIRSourceProvider,
    SOURCE_FLAG_BY_PROVIDER,
)
from app.services.hmair.source_connectors.registry import source_registry


MAX_DEEP_SCAN_SOURCE_RECORDS = 1_000
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/=-]{0,127}$")
_SAFE_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
_BROWSER_SIGNAL_PREFIXES = ("browser.", "shadow_ai.browser_")
_MCP_TARGET_EVENTS = {
    "mcp_environment": frozenset({"mcp_authorize"}),
    "llm_gateway": frozenset({"llm_intercept"}),
    "runtime_environment": frozenset({"mcp_authorize", "llm_intercept"}),
}
CONNECTOR_TARGET_TYPES = {
    **H4_CONNECTOR_TARGET_TYPES,
    "entra_id": "identity_tenant",
    "sailpoint": "identity_tenant",
    "aws": "cloud_subscription",
    "microsoft_365": "saas_tenant",
    "google_workspace": "saas_tenant",
    "checkmarx": "repository_org",
    "fortinet": "network_range",
    "netskope": "network_range",
    "zscaler": "network_range",
    HMAIRSourceProvider.MICROSOFT365.value: "saas_tenant",
    HMAIRSourceProvider.GITHUB_CLOUD.value: "repository_org",
    HMAIRSourceProvider.GITHUB_GHES.value: "repository_org",
}
_CONNECTOR_SURFACES = {
    "identity_tenant": SourceSurface.IDENTITY,
    "cloud_subscription": SourceSurface.CLOUD,
    "cloud_project": SourceSurface.CLOUD,
    "kubernetes_cluster": SourceSurface.KUBERNETES,
    "saas_tenant": SourceSurface.SAAS,
    "ai_provider_account": SourceSurface.MODEL_ENDPOINT,
    "repository_org": SourceSurface.SOURCE_CODE,
    "repository": SourceSurface.SOURCE_CODE,
    "network_range": SourceSurface.NETWORK,
    "dns_domain": SourceSurface.DNS,
    "api_gateway": SourceSurface.API_GATEWAY,
    "database_platform": SourceSurface.DATABASE,
}


@dataclass(frozen=True)
class DeepScanSourceBatch:
    observations: tuple[DiscoveryObservationInput, ...]
    completion_receipts: tuple[DeepScanUnitCompletionReceipt, ...]


def _utc(value: object, *, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError(f"{field_name} must be a timestamp")
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _window(*, window_start: datetime, window_end: datetime) -> tuple[datetime, datetime]:
    start = _utc(window_start, field_name="window_start")
    end = _utc(window_end, field_name="window_end")
    if start >= end:
        raise ValueError("Deep Scan source window must be ordered")
    return start, end


def _safe_identifier(value: object) -> str | None:
    if type(value) is not str:
        return None
    normalized = value.strip()
    return normalized if _SAFE_IDENTIFIER.fullmatch(normalized) is not None else None


def _safe_domain(value: object) -> str | None:
    if type(value) is not str:
        return None
    normalized = value.strip().lower().rstrip(".")
    return normalized if _SAFE_DOMAIN.fullmatch(normalized) is not None else None


def managed_browser_unit_binding_hash(
    *, endpoint_id: str, browser: str, browser_profile: str
) -> str:
    """Return the opaque identity used by an admin-approved browser baseline."""

    normalized_endpoint = _safe_identifier(endpoint_id)
    normalized_browser = _safe_identifier(browser.lower())
    normalized_profile = _safe_identifier(browser_profile)
    if None in (normalized_endpoint, normalized_browser, normalized_profile):
        raise ValueError("managed browser unit identity is invalid")
    return sha256(
        canonical_json_bytes(
            {
                "endpoint_id": normalized_endpoint,
                "browser": normalized_browser,
                "browser_profile": normalized_profile,
            }
        )
    ).hexdigest()


def eligible_managed_browser_health_rows(
    db: Session,
    *,
    tenant_id: str,
    target: DiscoveryTarget,
    window_start: datetime,
    window_end: datetime,
) -> dict[str, MonitoringSignal]:
    """Resolve health only for admin-bound units on a freshly authenticated endpoint.

    Extension status is user-session telemetry. It becomes completion evidence
    only after it matches an opaque unit baseline and an active, recently
    authenticated endpoint identity assigned to that same server-resolved user.
    """

    start, end = _window(window_start=window_start, window_end=window_end)
    baseline = (
        target.coverage_baseline_json
        if isinstance(target.coverage_baseline_json, Mapping)
        else {}
    )
    allowed_hashes = {
        value
        for value in baseline.get("managed_browser_unit_hashes", ())
        if type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value)
    }
    if not allowed_hashes:
        return {}
    health_rows = tuple(
        db.scalars(
            select(MonitoringSignal)
            .where(
                MonitoringSignal.tenant_id == tenant_id,
                MonitoringSignal.signal_type == "browser.extension_health_status",
                MonitoringSignal.created_at >= start,
                MonitoringSignal.created_at <= end,
            )
            .order_by(MonitoringSignal.created_at.desc(), MonitoringSignal.id.desc())
            .limit(MAX_DEEP_SCAN_SOURCE_RECORDS)
        ).all()
    )
    endpoint_ids = {
        str((row.payload or {}).get("endpoint_id") or "").strip()
        for row in health_rows
        if isinstance(row.payload, Mapping)
    }
    endpoint_ids.discard("")
    identities = {
        row.endpoint_id: row
        for row in db.scalars(
            select(EndpointDeviceIdentity).where(
                EndpointDeviceIdentity.tenant_id == tenant_id,
                EndpointDeviceIdentity.endpoint_id.in_(tuple(endpoint_ids)),
                EndpointDeviceIdentity.status == "active",
            )
        ).all()
    } if endpoint_ids else {}
    latest_by_unit: dict[str, MonitoringSignal] = {}
    for row in health_rows:
        payload = row.payload if isinstance(row.payload, Mapping) else {}
        if payload.get("healthy") is not True:
            continue
        endpoint_id = _safe_identifier(payload.get("endpoint_id"))
        browser = _safe_identifier(str(payload.get("browser") or "").lower())
        profile = _safe_identifier(payload.get("browser_profile"))
        actor_user_id = _safe_identifier(payload.get("user_id"))
        if None in (endpoint_id, browser, profile, actor_user_id):
            continue
        unit_hash = managed_browser_unit_binding_hash(
            endpoint_id=endpoint_id,
            browser=browser,
            browser_profile=profile,
        )
        identity = identities.get(endpoint_id)
        last_authenticated = _utc(
            getattr(identity, "last_authenticated_at", None),
            field_name="endpoint_last_authenticated_at",
        ) if identity is not None and identity.last_authenticated_at is not None else None
        if (
            unit_hash not in allowed_hashes
            or identity is None
            or identity.assigned_user_id != actor_user_id
            or "endpoint:discovery:write" not in tuple(identity.scopes or ())
            or last_authenticated is None
            or not (start <= last_authenticated <= end)
        ):
            continue
        latest_by_unit.setdefault(unit_hash, row)
    return latest_by_unit


def _target(
    db: Session, *, tenant_id: str, target_id: str, accepted_types: frozenset[str]
) -> DiscoveryTarget:
    target = db.scalar(
        select(DiscoveryTarget).where(
            DiscoveryTarget.tenant_id == tenant_id,
            DiscoveryTarget.target_id == target_id,
        )
    )
    if target is None or target.target_type not in accepted_types:
        raise LookupError("Deep Scan source target was not found")
    return target


def _runtime_event_matches_target(
    *, target: DiscoveryTarget, event: RuntimeEvent
) -> bool:
    """Keep a Deep Scan source bound to its registered gateway/runtime id."""

    metadata = event.metadata_json if isinstance(event.metadata_json, Mapping) else {}
    server_id = metadata.get("mcp_server_id")
    if target.target_type == "mcp_environment":
        # An explicit MCP server identity is the authoritative binding.  The
        # generic application id is a legacy fallback only when the gateway
        # did not emit an MCP server id at all; it must not override a
        # contradictory server identity.
        if "mcp_server_id" in metadata:
            return server_id == target.identifier
        return event.app_id == target.identifier
    if target.target_type == "llm_gateway":
        return event.app_id == target.identifier
    return event.app_id == target.identifier or server_id == target.identifier


def _runtime_target_clause(target: DiscoveryTarget):
    if target.target_type == "llm_gateway":
        return RuntimeEvent.app_id == target.identifier
    return or_(
        RuntimeEvent.app_id == target.identifier,
        RuntimeEvent.metadata_json["mcp_server_id"].as_string() == target.identifier,
    )


def _observation(
    *,
    source_kind: str,
    source_record_id: str,
    scan_id: str,
    collector_id: str,
    collector_type: str,
    collector_version: str,
    target_id: str,
    source_surface: SourceSurface,
    raw_signal_type: ObservationType,
    asset_candidate_type: str,
    observed_at: datetime,
    identifiers: Mapping[str, str],
    normalized_signal: Mapping[str, object],
    configuration_summary: Mapping[str, object],
    usage_summary: Mapping[str, object],
    confidence: float,
    verification_state: FactVerificationState,
    source_trust: SourceTrust,
    observed_state: ObservedFactState = ObservedFactState.ACTIVELY_USED,
) -> DiscoveryObservationInput:
    material = {
        "source_kind": source_kind,
        "source_record_id": source_record_id,
        "scan_id": scan_id,
        "collector_id": collector_id,
        "target_id": target_id,
        "source_surface": source_surface.value,
        "raw_signal_type": raw_signal_type.value,
        "asset_candidate_type": asset_candidate_type,
        "observed_at": observed_at.isoformat(),
        "identifiers": dict(identifiers),
        "normalized_signal": dict(normalized_signal),
        "configuration_summary": dict(configuration_summary),
        "usage_summary": dict(usage_summary),
    }
    digest = sha256(canonical_json_bytes(material)).hexdigest()
    return DiscoveryObservationInput(
        observation_id=f"deep-{source_kind}-{digest[:48]}",
        scan_id=scan_id,
        collector_id=collector_id,
        collector_type=collector_type,
        collector_version=collector_version,
        target_id=target_id,
        source_surface=source_surface,
        subject_reference=None,
        raw_signal_type=raw_signal_type,
        normalized_signal=dict(normalized_signal),
        observed_at=observed_at,
        asset_candidate_type=asset_candidate_type,
        observed_state=observed_state,
        identifiers=dict(identifiers),
        attributes={"record_class": f"deep_scan_{source_kind}"},
        configuration_summary=dict(configuration_summary),
        usage_summary=dict(usage_summary),
        capability_hints=(),
        identity_hints=(),
        relationship_hints=(),
        evidence_reference=f"{source_kind}:{source_record_id}",
        evidence_hash=digest,
        signature_status="server_persisted",
        confidence=confidence,
        freshness=ObservationFreshness.FRESH,
        verification_state=verification_state,
        source_trust=source_trust,
        collection_scope={"mode": "metadata_only", "source": source_kind},
        parser_version="hmair-deep-scan-v1",
        schema_version="v1",
        evidence_mode=EvidenceMode.DIRECT,
        evidence_mutability=EvidenceMutability.MUTABLE,
        contradiction_state=ContradictionState.NONE,
        contradiction_references=(),
        sensitivity="metadata",
        redaction_status="not_required",
    )


def collect_browser_source_observations(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
    target_id: str,
    collector_id: str,
    window_start: datetime,
    window_end: datetime,
) -> tuple[DiscoveryObservationInput, ...]:
    """Project only safe managed-browser telemetry from the frozen window."""

    start, end = _window(window_start=window_start, window_end=window_end)
    _target(
        db,
        tenant_id=tenant_id,
        target_id=target_id,
        accepted_types=frozenset({"browser_tenant"}),
    )
    rows = tuple(
        db.scalars(
            select(MonitoringSignal)
            .where(
                MonitoringSignal.tenant_id == tenant_id,
                MonitoringSignal.created_at >= start,
                MonitoringSignal.created_at <= end,
            )
            .order_by(MonitoringSignal.created_at, MonitoringSignal.id)
            .limit(MAX_DEEP_SCAN_SOURCE_RECORDS)
        ).all()
    )
    observations: list[DiscoveryObservationInput] = []
    for row in rows:
        if not row.signal_type.startswith(_BROWSER_SIGNAL_PREFIXES):
            continue
        if row.signal_type == "browser.extension_health_status":
            # Health establishes one managed collection unit; it is not AI
            # usage and must not inflate activity observations.
            continue
        payload = row.payload if isinstance(row.payload, Mapping) else {}
        domain = _safe_domain(payload.get("domain"))
        if domain is None:
            # Do not parse URLs: paths, query values, and fragments are outside
            # the metadata contract and cannot be treated as a safe domain.
            continue
        source_record_id = _safe_identifier(row.id)
        if source_record_id is None:
            continue
        observations.append(
            _observation(
                source_kind="monitoring_signal",
                source_record_id=source_record_id,
                scan_id=scan_id,
                collector_id=collector_id,
                collector_type="browser_telemetry_bridge",
                collector_version="v1",
                target_id=target_id,
                source_surface=SourceSurface.BROWSER,
                raw_signal_type=ObservationType.WEB_AI_USAGE,
                asset_candidate_type="ai_application",
                observed_at=_utc(row.created_at, field_name="browser_observed_at"),
                identifiers={"ai_domain": domain},
                normalized_signal={"event_class": "managed_browser_ai_usage"},
                configuration_summary={"telemetry_path": "managed_extension"},
                usage_summary={"event_count": 1},
                confidence=0.8,
                verification_state=FactVerificationState.PARTIALLY_VERIFIED,
                source_trust=SourceTrust.MEDIUM,
            )
        )
    if not observations:
        raise CollectorTerminalOutcome(
            CollectorRunStatus.EMPTY,
            "source returned no safe browser metadata",
        )
    return tuple(observations)


def collect_browser_source_batch(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
    target_id: str,
    collector_id: str,
    window_start: datetime,
    window_end: datetime,
    settings_obj: object = settings,
) -> DeepScanSourceBatch:
    """Return safe activity plus one signed receipt per healthy browser unit."""

    start, end = _window(window_start=window_start, window_end=window_end)
    observations = collect_browser_source_observations(
        db,
        tenant_id=tenant_id,
        scan_id=scan_id,
        target_id=target_id,
        collector_id=collector_id,
        window_start=start,
        window_end=end,
    )
    target = _target(
        db,
        tenant_id=tenant_id,
        target_id=target_id,
        accepted_types=frozenset({"browser_tenant"}),
    )
    latest_by_unit = eligible_managed_browser_health_rows(
        db,
        tenant_id=tenant_id,
        target=target,
        window_start=start,
        window_end=end,
    )
    try:
        receipts = tuple(
            issue_deep_scan_unit_completion_receipt(
                tenant_id=tenant_id,
                scan_id=scan_id,
                target_id=target_id,
                collector_id=collector_id,
                unit_id=unit_id,
                source_record_id=row.id,
                observed_at=_utc(row.created_at, field_name="browser_health_at"),
                settings_obj=settings_obj,
            )
            for unit_id, row in sorted(latest_by_unit.items())
        )
    except ValueError:
        raise CollectorTerminalOutcome(
            CollectorRunStatus.UNSUPPORTED,
            "completion receipt signing unavailable",
        ) from None
    if not receipts:
        raise CollectorTerminalOutcome(
            CollectorRunStatus.STALE,
            "source returned no healthy managed browser completion units",
        )
    return DeepScanSourceBatch(
        observations=observations,
        completion_receipts=receipts,
    )


def collect_mcp_runtime_source_observations(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
    target_id: str,
    collector_id: str,
    window_start: datetime,
    window_end: datetime,
) -> tuple[DiscoveryObservationInput, ...]:
    """Project only gateway-routed MCP/runtime metadata from the frozen window."""

    start, end = _window(window_start=window_start, window_end=window_end)
    target = _target(
        db,
        tenant_id=tenant_id,
        target_id=target_id,
        accepted_types=frozenset(_MCP_TARGET_EVENTS),
    )
    allowed_events = _MCP_TARGET_EVENTS[target.target_type]
    rows = tuple(
        db.scalars(
            select(RuntimeEvent)
            .where(
                RuntimeEvent.tenant_id == tenant_id,
                RuntimeEvent.source_surface == "gateway",
                RuntimeEvent.event_type.in_(tuple(allowed_events)),
                RuntimeEvent.created_at >= start,
                RuntimeEvent.created_at <= end,
                _runtime_target_clause(target),
            )
            .order_by(RuntimeEvent.created_at, RuntimeEvent.event_id)
            .limit(MAX_DEEP_SCAN_SOURCE_RECORDS)
        ).all()
    )
    observations: list[DiscoveryObservationInput] = []
    for row in rows:
        if not _runtime_event_matches_target(target=target, event=row):
            continue
        source_record_id = _safe_identifier(row.event_id)
        metadata = row.metadata_json if isinstance(row.metadata_json, Mapping) else {}
        if source_record_id is None:
            continue
        if row.event_type == "mcp_authorize":
            server_id = _safe_identifier(metadata.get("mcp_server_id")) or _safe_identifier(
                row.app_id
            )
            if server_id is None:
                continue
            fingerprint = _safe_identifier(metadata.get("tool_fingerprint"))
            identifiers = {"mcp_server_id": server_id}
            if fingerprint is not None and len(fingerprint) == 64:
                identifiers["tool_fingerprint"] = fingerprint
            observations.append(
                _observation(
                    source_kind="runtime_event",
                    source_record_id=source_record_id,
                    scan_id=scan_id,
                    collector_id=collector_id,
                    collector_type="mcp_runtime_telemetry_bridge",
                    collector_version="v1",
                    target_id=target_id,
                    source_surface=SourceSurface.MCP,
                    raw_signal_type=ObservationType.MCP_SERVER,
                    asset_candidate_type="mcp_server",
                    observed_at=_utc(row.created_at, field_name="mcp_observed_at"),
                    identifiers=identifiers,
                    normalized_signal={"event_class": "gateway_mcp_authorize"},
                    configuration_summary={"telemetry_path": "gateway_proxy"},
                    usage_summary={"event_count": 1},
                    confidence=0.9,
                    verification_state=FactVerificationState.VERIFIED,
                    source_trust=SourceTrust.STRONG,
                )
            )
            continue
        gateway_id = _safe_identifier(row.app_id)
        if gateway_id is None:
            continue
        observations.append(
            _observation(
                source_kind="runtime_event",
                source_record_id=source_record_id,
                scan_id=scan_id,
                collector_id=collector_id,
                collector_type="mcp_runtime_telemetry_bridge",
                collector_version="v1",
                target_id=target_id,
                source_surface=SourceSurface.RUNTIME,
                raw_signal_type=ObservationType.AI_ENDPOINT_REFERENCE,
                asset_candidate_type="model_endpoint",
                observed_at=_utc(row.created_at, field_name="runtime_observed_at"),
                identifiers={"runtime_gateway_id": gateway_id},
                normalized_signal={"event_class": "gateway_llm_intercept"},
                configuration_summary={"telemetry_path": "gateway_hook"},
                usage_summary={"event_count": 1},
                confidence=0.9,
                verification_state=FactVerificationState.VERIFIED,
                source_trust=SourceTrust.STRONG,
            )
        )
    if not observations:
        raise CollectorTerminalOutcome(
            CollectorRunStatus.EMPTY,
            "source returned no safe routed runtime metadata",
        )
    return tuple(observations)


def collect_mcp_runtime_source_batch(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
    target_id: str,
    collector_id: str,
    window_start: datetime,
    window_end: datetime,
    settings_obj: object = settings,
) -> DeepScanSourceBatch:
    """Return routed observations plus an exact-target completion receipt."""

    start, end = _window(window_start=window_start, window_end=window_end)
    target = _target(
        db,
        tenant_id=tenant_id,
        target_id=target_id,
        accepted_types=frozenset(_MCP_TARGET_EVENTS),
    )
    observations = collect_mcp_runtime_source_observations(
        db,
        tenant_id=tenant_id,
        scan_id=scan_id,
        target_id=target_id,
        collector_id=collector_id,
        window_start=start,
        window_end=end,
    )
    allowed_events = _MCP_TARGET_EVENTS[target.target_type]
    rows = tuple(
        db.scalars(
            select(RuntimeEvent)
            .where(
                RuntimeEvent.tenant_id == tenant_id,
                RuntimeEvent.source_surface == "gateway",
                RuntimeEvent.event_type.in_(tuple(allowed_events)),
                RuntimeEvent.created_at >= start,
                RuntimeEvent.created_at <= end,
                _runtime_target_clause(target),
            )
            .order_by(RuntimeEvent.created_at.desc(), RuntimeEvent.event_id.desc())
            .limit(MAX_DEEP_SCAN_SOURCE_RECORDS)
        ).all()
    )
    latest = next(
        (row for row in rows if _runtime_event_matches_target(target=target, event=row)),
        None,
    )
    if latest is None:
        raise CollectorTerminalOutcome(
            CollectorRunStatus.STALE,
            "source returned no exact routed runtime completion unit",
        )
    try:
        receipt = issue_deep_scan_unit_completion_receipt(
            tenant_id=tenant_id,
            scan_id=scan_id,
            target_id=target_id,
            collector_id=collector_id,
            unit_id=f"{target.target_type}:{target.identifier}",
            source_record_id=latest.event_id,
            observed_at=_utc(latest.created_at, field_name="runtime_completion_at"),
            settings_obj=settings_obj,
        )
    except ValueError:
        raise CollectorTerminalOutcome(
            CollectorRunStatus.UNSUPPORTED,
            "completion receipt signing unavailable",
        ) from None
    return DeepScanSourceBatch(
        observations=observations,
        completion_receipts=(receipt,),
    )


def _connector_contract_is_inventory_capable(connector: Connector) -> bool:
    metadata = connector.metadata_json
    if not isinstance(metadata, Mapping):
        return False
    contract = metadata.get("hmair_deep_scan_contract")
    return bool(
        isinstance(contract, Mapping)
        and set(contract)
        == {
            "version",
            "metadata_only",
            "inventory_capable",
            "customer_authorization_reference",
        }
        and contract.get("version") == "v1"
        and contract.get("metadata_only") is True
        and contract.get("inventory_capable") is True
        and _safe_identifier(contract.get("customer_authorization_reference"))
        is not None
    )


def _connector_for_deep_scan(
    db: Session,
    *,
    tenant_id: str,
    target: DiscoveryTarget,
    connector_id: str,
) -> Connector:
    connector = db.scalar(
        select(Connector).where(
            Connector.tenant_id == tenant_id,
            Connector.id == connector_id,
        )
    )
    if connector is None:
        raise LookupError("Deep Scan connector was not found")
    typed_source = connector.provider_key in {
        provider.value for provider in HMAIRSourceProvider
    }
    if (
        target.credentials_reference != f"connector:{connector.id}"
        or CONNECTOR_TARGET_TYPES.get(connector.provider_key) != target.target_type
        or connector.enabled is not True
        or connector.is_stub is True
        or connector.status != "active"
        or (
            not typed_source
            and (
                connector.last_pull_status != "success"
                or not _connector_contract_is_inventory_capable(connector)
            )
        )
    ):
        raise CollectorTerminalOutcome(
            CollectorRunStatus.UNSUPPORTED,
            "connector source is not authorised for Deep Scan inventory",
        )
    return connector


def _typed_source_connection(
    *, connector: Connector, target: DiscoveryTarget
) -> HMAIRSourceConnectionInput:
    metadata = connector.metadata_json if isinstance(connector.metadata_json, Mapping) else {}
    contract = metadata.get("hmair_source_contract")
    if not isinstance(contract, Mapping):
        raise CollectorTerminalOutcome(
            CollectorRunStatus.UNSUPPORTED,
            "typed source contract is missing",
        )
    try:
        provider = HMAIRSourceProvider(connector.provider_key)
        credentials = decrypt_connector_secrets(connector.encrypted_secrets)
        return HMAIRSourceConnectionInput.model_validate(
            {
                "provider_key": provider.value,
                "display_name": connector.name,
                "target_identifier": target.identifier,
                "environment": target.environment,
                # The raw change reference is intentionally not retained in a
                # source record. Collectors do not use it after provisioning.
                "authorization_reference": "source-approval-binding",
                "requested_capabilities": tuple(contract.get("requested_capabilities", ())),
                "include_entra_account_evidence": bool(
                    contract.get("include_entra_account_evidence", False)
                ),
                "metadata": contract.get("source_metadata", {}),
                "credentials": credentials,
            }
        )
    except (TypeError, ValueError):
        raise CollectorTerminalOutcome(
            CollectorRunStatus.UNSUPPORTED,
            "typed source contract is invalid",
        ) from None


def _typed_source_http(*, connection: HMAIRSourceConnectionInput) -> object:
    """Build the source-owned authenticated transport at execution time.

    The runtime factory is deliberately lazy. Connection setup and preflight
    never open a provider connection, while source collection can still be
    unit-tested with an injected bounded transport.
    """

    from app.services.hmair.source_connectors.runtime import source_http_for_connection

    return source_http_for_connection(connection)


def _typed_source_observations(
    db: Session,
    *,
    connector: Connector,
    target: DiscoveryTarget,
    scan_id: str,
    collector_id: str,
    window_start: datetime,
    window_end: datetime,
    tenant_id: str,
) -> tuple[DiscoveryObservationInput, ...]:
    provider = HMAIRSourceProvider(connector.provider_key)
    if getattr(settings, SOURCE_FLAG_BY_PROVIDER[provider], False) is not True:
        raise CollectorTerminalOutcome(
            CollectorRunStatus.UNSUPPORTED,
            "provider-specific source flag is disabled",
        )
    connection = _typed_source_connection(connector=connector, target=target)
    source_http: object | None = None
    try:
        collector = source_registry.get_collector(connector.provider_key)
        source_http = _typed_source_http(connection=connection)
        result = collector.collect(
            connection,
            (window_start, window_end),
            source_http,
            identifier_salt=tenant_id,
        )
    except CollectorTerminalOutcome:
        raise
    except Exception:
        raise CollectorTerminalOutcome(
            CollectorRunStatus.STALE,
            "typed source did not produce current metadata",
        ) from None
    finally:
        close = getattr(source_http, "close", None)
        if callable(close):
            close()
    if connector.provider_key in {
        HMAIRSourceProvider.GITHUB_CLOUD.value,
        HMAIRSourceProvider.GITHUB_GHES.value,
    }:
        from app.services.github_repository_access_service import (
            derive_github_repository_ai_connections,
            persist_github_inventory_unit,
        )

        for record in result.records:
            if record.record_kind in {
                "github_organization",
                "github_repository",
                "github_repository_access",
                "github_repository_protection",
                "github_repository_ai_connection",
            }:
                persist_github_inventory_unit(
                    db,
                    tenant_id=tenant_id,
                    connection_id=connector.id,
                    record=record.model_dump(mode="python"),
                )
        derive_github_repository_ai_connections(db, tenant_id=tenant_id)
    observations = tuple(
        _observation(
            source_kind=connector.provider_key,
            source_record_id=record.record_id,
            scan_id=scan_id,
            collector_id=collector_id,
            collector_type="hmair_source_connector",
            collector_version="v1",
            target_id=target.target_id,
            source_surface=record.source_surface,
            raw_signal_type=record.observation_type,
            asset_candidate_type=record.candidate_asset_type,
            observed_at=record.observed_at,
            identifiers=dict(record.identifiers),
            normalized_signal={"record_kind": record.record_kind},
            configuration_summary={"source_provider": connector.provider_key},
            usage_summary=dict(record.metadata),
            confidence=0.9,
            verification_state=FactVerificationState.PARTIALLY_VERIFIED,
            source_trust=SourceTrust.STRONG,
        )
        for record in (*result.records, *result.entra_records)
    )
    if not observations:
        raise CollectorTerminalOutcome(
            CollectorRunStatus.EMPTY,
            "typed source returned no safe metadata in the selected window",
        )
    return observations


def collect_connector_source_observations(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
    target_id: str,
    collector_id: str,
    connector_id: str,
    window_start: datetime,
    window_end: datetime,
) -> tuple[DiscoveryObservationInput, ...]:
    """Run one admitted customer-owned connector and project safe metadata.

    The connector remains the system that owns its secret material.  This
    bridge passes no configuration or credentials, then ignores its raw
    provider payload and projects only the connector ID, provider family, and
    returned record count into HMAIR observations.
    """

    start, end = _window(window_start=window_start, window_end=window_end)
    target = _target(
        db,
        tenant_id=tenant_id,
        target_id=target_id,
        accepted_types=frozenset(_CONNECTOR_SURFACES),
    )
    normalized_connector_id = _safe_identifier(connector_id)
    if normalized_connector_id is None:
        raise LookupError("Deep Scan connector was not found")
    connector = _connector_for_deep_scan(
        db,
        tenant_id=tenant_id,
        target=target,
        connector_id=normalized_connector_id,
    )
    if connector.provider_key in {provider.value for provider in HMAIRSourceProvider}:
        return _typed_source_observations(
            db,
            connector=connector,
            target=target,
            scan_id=scan_id,
            collector_id=collector_id,
            window_start=start,
            window_end=end,
            tenant_id=tenant_id,
        )
    try:
        rows = tuple(run_connector_once(db, tenant_id=tenant_id, connector=connector))
    except CollectorTerminalOutcome:
        raise
    except Exception:
        raise CollectorTerminalOutcome(
            CollectorRunStatus.STALE,
            "connector pull did not produce current metadata",
        ) from None
    surface = _CONNECTOR_SURFACES[target.target_type]
    provider_key = _safe_identifier(connector.provider_key)
    safe_connector_id = _safe_identifier(connector.id)
    if provider_key is None or safe_connector_id is None:
        raise CollectorTerminalOutcome(
            CollectorRunStatus.UNSUPPORTED,
            "connector identity is not valid for Deep Scan",
        )
    observations: list[DiscoveryObservationInput] = []
    for row in rows[:MAX_DEEP_SCAN_SOURCE_RECORDS]:
        if row.tenant_id != tenant_id:
            continue
        observed_at = _utc(row.created_at, field_name="connector_observed_at")
        if observed_at < start or observed_at > end:
            continue
        source_record_id = _safe_identifier(row.id)
        if source_record_id is None:
            continue
        observations.append(
            _observation(
                source_kind="monitoring_signal",
                source_record_id=source_record_id,
                scan_id=scan_id,
                collector_id=collector_id,
                collector_type="connector_source_bridge",
                collector_version="v1",
                target_id=target_id,
                source_surface=surface,
                raw_signal_type=ObservationType.API_CALL,
                asset_candidate_type="ai_provider_account",
                observed_at=observed_at,
                identifiers={
                    # Connector records are tenant-local operational IDs, not
                    # discovery facts. Keep a stable one-way binding without
                    # projecting the connector row identifier into evidence.
                    "connector_id_hash": sha256(
                        safe_connector_id.encode("utf-8")
                    ).hexdigest(),
                    "provider_key": provider_key,
                },
                normalized_signal={
                    "event_class": "connector_inventory_metadata",
                    "provider_family": provider_key,
                },
                configuration_summary={"target_type": target.target_type},
                usage_summary={},
                confidence=0.9,
                verification_state=FactVerificationState.PARTIALLY_VERIFIED,
                source_trust=SourceTrust.STRONG,
                observed_state=ObservedFactState.OBSERVED,
            )
        )
    if not observations:
        raise CollectorTerminalOutcome(
            CollectorRunStatus.EMPTY,
            "connector returned no safe metadata in the selected window",
        )
    return tuple(observations)


__all__ = [
    "MAX_DEEP_SCAN_SOURCE_RECORDS",
    "CONNECTOR_TARGET_TYPES",
    "DeepScanSourceBatch",
    "collect_browser_source_batch",
    "collect_browser_source_observations",
    "collect_connector_source_observations",
    "collect_mcp_runtime_source_batch",
    "collect_mcp_runtime_source_observations",
]
