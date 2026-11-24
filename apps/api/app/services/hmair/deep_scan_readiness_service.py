"""Tenant-scoped readiness and profile freezing for production Deep Scan."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db.models.discovery_canonical import DiscoveryCollector, DiscoveryTarget
from app.db.models.endpoint_identity import EndpointDeviceIdentity
from app.db.models.monitoring import Connector
from app.db.models.runtime_intelligence import RuntimeEvent
from app.services.hmair.deep_scan_contracts import (
    DeepScanCoverage,
    DeepScanCoverageBaseline,
    DeepScanCoverageState,
    DeepScanObservationMode,
    DeepScanPreflightRequest,
    DeepScanPreflightResult,
    DeepScanProfile,
    DeepScanStoredProfile,
    DeepScanReadinessState,
    DeepScanSourceReadiness,
    deep_scan_preflight_digest,
    deep_scan_profile_digest,
)
from app.services.hmair.deep_scan_source_service import (
    eligible_managed_browser_health_rows,
)


SOURCE_FRESHNESS = timedelta(hours=24)
PREFLIGHT_VALIDITY = timedelta(minutes=5)
_READ_ONLY_METHOD = "collect_inventory"
_CONNECTOR_TARGET_TYPES = {
    "entra_id": "identity_tenant",
    "sailpoint": "identity_tenant",
    "aws": "cloud_subscription",
    "microsoft_365": "saas_tenant",
    "google_workspace": "saas_tenant",
    "checkmarx": "repository_org",
    "fortinet": "network_range",
    "netskope": "network_range",
    "zscaler": "network_range",
}
_BASELINE_AUTHORITY_BY_TARGET = {
    "endpoint_group": "mdm",
    "browser_tenant": "browser_management",
    "mcp_environment": "runtime_registry",
    "llm_gateway": "runtime_registry",
    "runtime_environment": "runtime_registry",
}
_RUNTIME_EVIDENCE_EVENTS = {
    "mcp_environment": frozenset({"mcp_authorize"}),
    "llm_gateway": frozenset({"llm_intercept"}),
    "runtime_environment": frozenset({"mcp_authorize", "llm_intercept"}),
}
_PER_UNIT_COMPLETION_RECEIPT_TARGET_TYPES = frozenset(
    {
        "endpoint_group",
        "browser_tenant",
        "mcp_environment",
        "llm_gateway",
        "runtime_environment",
    }
)
# A source-level denominator is not an organization-wide denominator. P0 has
# no authoritative, tenant-approved manifest that closes every in-scope
# surface, so a Deep Scan cannot truthfully make an enterprise-wide claim yet.
_ENTERPRISE_SCOPE_CLOSURE_READY = False


def _utc(value: datetime | None = None) -> datetime:
    observed = value or datetime.now(UTC)
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ValueError("deep scan timestamps must include a timezone")
    return observed.astimezone(UTC)


def _stored_utc(value: object) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _tenant_targets(
    db: Session, *, tenant_id: str, target_ids: Sequence[str]
) -> dict[str, DiscoveryTarget]:
    rows = tuple(
        db.scalars(
            select(DiscoveryTarget).where(
                DiscoveryTarget.tenant_id == tenant_id,
                DiscoveryTarget.target_id.in_(target_ids),
            )
        ).all()
    )
    result = {row.target_id: row for row in rows}
    if set(result) != set(target_ids):
        raise LookupError("one or more Deep Scan targets were not found")
    return result


def _tenant_collectors(
    db: Session, *, tenant_id: str, collector_ids: Sequence[str]
) -> dict[str, DiscoveryCollector]:
    rows = tuple(
        db.scalars(
            select(DiscoveryCollector).where(
                DiscoveryCollector.tenant_id == tenant_id,
                DiscoveryCollector.collector_id.in_(collector_ids),
            )
        ).all()
    )
    result = {row.collector_id: row for row in rows}
    if set(result) != set(collector_ids):
        raise LookupError("one or more Deep Scan collectors were not found")
    return result


def _baseline(target: DiscoveryTarget) -> DeepScanCoverageBaseline | None:
    raw = target.coverage_baseline_json
    if not isinstance(raw, Mapping) or not raw:
        return None
    try:
        return DeepScanCoverageBaseline.model_validate(dict(raw))
    except ValueError:
        return None


def _baseline_is_current(
    baseline: DeepScanCoverageBaseline | None, *, now: datetime, target_type: str
) -> bool:
    if baseline is None or baseline.expires_at <= now:
        return False
    expected_authority = _BASELINE_AUTHORITY_BY_TARGET.get(target_type)
    if expected_authority is not None and baseline.authority_kind != expected_authority:
        return False
    if target_type in _CONNECTOR_TARGET_TYPES.values() and baseline.authority_kind != "vendor_api":
        return False
    return True


def _matching_collector(
    *, target: DiscoveryTarget, collectors: Mapping[str, DiscoveryCollector]
) -> tuple[DiscoveryCollector | None, str | None]:
    matches = sorted(
        (
            row
            for row in collectors.values()
            if target.target_type in tuple(row.supported_targets_json or ())
        ),
        key=lambda row: row.collector_id,
    )
    if not matches:
        return None, "no_matching_collector"
    if len(matches) > 1:
        return None, "ambiguous_collector_selection"
    return matches[0], None


def _collector_problem(
    *, target: DiscoveryTarget, collector: DiscoveryCollector, now: datetime
) -> tuple[DeepScanReadinessState | None, str | None]:
    if not target.active_scan_allowed or _READ_ONLY_METHOD not in tuple(
        target.permitted_methods_json or ()
    ):
        return DeepScanReadinessState.PERMISSION_DENIED, "read_only_method_not_authorized"
    if collector.health != "healthy":
        return DeepScanReadinessState.DEGRADED, "collector_not_healthy"
    last_success = _stored_utc(collector.last_success_at)
    if last_success is None or last_success > now or now - last_success > SOURCE_FRESHNESS:
        return DeepScanReadinessState.STALE, "collector_evidence_stale"
    return None, None


def _active_endpoint_denominator(
    db: Session, *, tenant_id: str, now: datetime
) -> int:
    rows = tuple(
        db.scalars(
            select(EndpointDeviceIdentity).where(
                EndpointDeviceIdentity.tenant_id == tenant_id,
                EndpointDeviceIdentity.status == "active",
            )
        ).all()
    )
    return sum(
        1
        for row in rows
        if isinstance(row.scopes, list)
        and "endpoint:discovery:write" in row.scopes
        and (last_authenticated := _stored_utc(row.last_authenticated_at)) is not None
        and last_authenticated <= now
        and now - last_authenticated <= SOURCE_FRESHNESS
    )


def _runtime_event_matches_target(
    *, target: DiscoveryTarget, event: RuntimeEvent
) -> bool:
    identifier = target.identifier
    metadata = event.metadata_json if isinstance(event.metadata_json, Mapping) else {}
    server_id = metadata.get("mcp_server_id")
    if target.target_type == "mcp_environment":
        # Do not let a generic application id promote a source to ready when
        # the routed event explicitly identifies a different MCP server.
        if "mcp_server_id" in metadata:
            return server_id == identifier
        return event.app_id == identifier
    if target.target_type == "llm_gateway":
        return event.app_id == identifier
    return event.app_id == identifier or server_id == identifier


def _current_direct_source_evidence(
    db: Session,
    *,
    tenant_id: str,
    target: DiscoveryTarget,
    now: datetime,
) -> datetime | None:
    """Return only current authenticated Browser or gateway evidence.

    A registered adapter and a target baseline are not evidence that the
    source path is receiving data.  These two source families already have
    authoritative server-side records, so readiness requires one fresh record
    from the appropriate path before a profile can call the source ready.
    """

    since = now - SOURCE_FRESHNESS
    if target.target_type == "browser_tenant":
        rows = eligible_managed_browser_health_rows(
            db,
            tenant_id=tenant_id,
            target=target,
            window_start=since,
            window_end=now,
        )
        return max(
            (_stored_utc(row.created_at) for row in rows.values()),
            default=None,
        )
    allowed_events = _RUNTIME_EVIDENCE_EVENTS.get(target.target_type)
    if allowed_events is None:
        return None
    rows = tuple(
        db.scalars(
            select(RuntimeEvent)
            .where(
                RuntimeEvent.tenant_id == tenant_id,
                RuntimeEvent.source_surface == "gateway",
                RuntimeEvent.event_type.in_(tuple(allowed_events)),
                RuntimeEvent.created_at >= since,
                RuntimeEvent.created_at <= now,
                or_(RuntimeEvent.app_id == target.identifier, RuntimeEvent.metadata_json["mcp_server_id"].as_string() == target.identifier),
            )
            .order_by(RuntimeEvent.created_at.desc())
            .limit(1)
        ).all()
    )
    row = next(
        (
            item
            for item in rows
            if _runtime_event_matches_target(target=target, event=item)
        ),
        None,
    )
    if row is None:
        return None
    return _stored_utc(row.created_at)


def _direct_source_collector_problem(
    *, collector: DiscoveryCollector
) -> tuple[DeepScanReadinessState | None, str | None]:
    if collector.health not in {"healthy", "unknown"}:
        return DeepScanReadinessState.DEGRADED, "collector_not_healthy"
    return None, None


def _connector_for_target(
    db: Session, *, tenant_id: str, target: DiscoveryTarget
) -> Connector | None:
    reference = target.credentials_reference
    if not isinstance(reference, str) or not reference.startswith("connector:"):
        return None
    raw_id = reference.removeprefix("connector:")
    try:
        connector_id = str(UUID(raw_id))
    except (TypeError, ValueError, AttributeError):
        return None
    return db.scalar(
        select(Connector).where(
            Connector.tenant_id == tenant_id,
            Connector.id == connector_id,
        )
    )


def _connector_contract(
    connector: Connector, *, authorization_reference: str
) -> tuple[bool, bool]:
    metadata = connector.metadata_json
    if not isinstance(metadata, Mapping):
        return False, False
    contract = metadata.get("hmair_deep_scan_contract")
    if not isinstance(contract, Mapping) or set(contract) != {
        "version",
        "metadata_only",
        "inventory_capable",
        "customer_authorization_reference",
    }:
        return False, False
    if (
        contract.get("version") != "v1"
        or contract.get("metadata_only") is not True
        or type(contract.get("inventory_capable")) is not bool
        or contract.get("customer_authorization_reference") != authorization_reference
    ):
        return False, False
    return True, contract["inventory_capable"] is True


def _connector_ready(
    db: Session,
    *,
    tenant_id: str,
    target: DiscoveryTarget,
    now: datetime,
    authorization_reference: str,
) -> tuple[DeepScanReadinessState, DeepScanObservationMode, str | None]:
    connector = _connector_for_target(db, tenant_id=tenant_id, target=target)
    if connector is None:
        return DeepScanReadinessState.NOT_CONNECTED, DeepScanObservationMode.OBSERVED_ONLY, "connector_not_connected"
    if (
        connector.enabled is not True
        or connector.is_stub is True
        or connector.status != "active"
        or _CONNECTOR_TARGET_TYPES.get(connector.provider_key) != target.target_type
    ):
        return DeepScanReadinessState.NOT_CONNECTED, DeepScanObservationMode.OBSERVED_ONLY, "connector_not_eligible"
    accepted, inventory_capable = _connector_contract(
        connector, authorization_reference=authorization_reference
    )
    if not accepted:
        return DeepScanReadinessState.NOT_CONNECTED, DeepScanObservationMode.OBSERVED_ONLY, "connector_contract_missing"
    last_run = _stored_utc(connector.last_run_at)
    if connector.last_pull_status != "success":
        return DeepScanReadinessState.DEGRADED, DeepScanObservationMode.OBSERVED_ONLY, "connector_pull_not_current"
    if last_run is None or last_run > now or now - last_run > SOURCE_FRESHNESS:
        return DeepScanReadinessState.STALE, DeepScanObservationMode.OBSERVED_ONLY, "connector_evidence_stale"
    if not inventory_capable:
        return DeepScanReadinessState.PARTIAL, DeepScanObservationMode.OBSERVED_ONLY, "connector_observed_only"
    return DeepScanReadinessState.READY, DeepScanObservationMode.AUTHORITATIVE, None


def _source_readiness(
    db: Session,
    *,
    tenant_id: str,
    target: DiscoveryTarget,
    collectors: Mapping[str, DiscoveryCollector],
    request: DeepScanPreflightRequest,
    now: datetime,
) -> DeepScanSourceReadiness:
    required = target.target_id in request.required_target_ids
    collector, collector_issue = _matching_collector(target=target, collectors=collectors)
    if collector is None:
        selected_collector = sorted(collectors)[0]
        return DeepScanSourceReadiness(
            target_id=target.target_id,
            collector_id=selected_collector,
            target_type=target.target_type,
            required=required,
            state=(
                DeepScanReadinessState.UNSUPPORTED
                if collector_issue == "no_matching_collector"
                else DeepScanReadinessState.PARTIAL
            ),
            observation_mode=DeepScanObservationMode.OBSERVED_ONLY,
            limitations=(collector_issue or "collector_selection_invalid",),
        )

    baseline = _baseline(target)
    if target.target_type in _CONNECTOR_TARGET_TYPES.values():
        state, mode, connector_limitation = _connector_ready(
            db,
            tenant_id=tenant_id,
            target=target,
            now=now,
            authorization_reference=request.customer_authorization_reference,
        )
        if state is not DeepScanReadinessState.READY:
            return DeepScanSourceReadiness(
                target_id=target.target_id,
                collector_id=collector.collector_id,
                target_type=target.target_type,
                required=required,
                state=state,
                observation_mode=mode,
                last_success_at=_stored_utc(collector.last_success_at),
                limitations=(connector_limitation or "connector_not_ready",),
            )

    endpoint_denominator: int | None = None
    if target.target_type == "endpoint_group":
        endpoint_denominator = _active_endpoint_denominator(
            db, tenant_id=tenant_id, now=now
        )
        if endpoint_denominator == 0:
            return DeepScanSourceReadiness(
                target_id=target.target_id,
                collector_id=collector.collector_id,
                target_type=target.target_type,
                required=required,
                state=DeepScanReadinessState.NOT_CONNECTED,
                observation_mode=DeepScanObservationMode.OBSERVED_ONLY,
                last_success_at=_stored_utc(collector.last_success_at),
                limitations=("no_current_enrolled_endpoints",),
            )

    direct_evidence_at = _current_direct_source_evidence(
        db, tenant_id=tenant_id, target=target, now=now
    )
    if target.target_type == "browser_tenant" and direct_evidence_at is None:
        return DeepScanSourceReadiness(
            target_id=target.target_id,
            collector_id=collector.collector_id,
            target_type=target.target_type,
            required=required,
            state=DeepScanReadinessState.NOT_CONNECTED,
            observation_mode=DeepScanObservationMode.OBSERVED_ONLY,
            last_success_at=_stored_utc(collector.last_success_at),
            limitations=("managed_browser_identity_or_health_not_current",),
        )
    if target.target_type in _RUNTIME_EVIDENCE_EVENTS and direct_evidence_at is None:
        return DeepScanSourceReadiness(
            target_id=target.target_id,
            collector_id=collector.collector_id,
            target_type=target.target_type,
            required=required,
            state=DeepScanReadinessState.NOT_CONNECTED,
            observation_mode=DeepScanObservationMode.OBSERVED_ONLY,
            last_success_at=_stored_utc(collector.last_success_at),
            limitations=("routed_runtime_evidence_not_current",),
        )

    if target.target_type in _RUNTIME_EVIDENCE_EVENTS or target.target_type == "browser_tenant":
        collector_problem, limitation = _direct_source_collector_problem(
            collector=collector
        )
    else:
        collector_problem, limitation = _collector_problem(
            target=target, collector=collector, now=now
        )
    if collector_problem is not None:
        return DeepScanSourceReadiness(
            target_id=target.target_id,
            collector_id=collector.collector_id,
            target_type=target.target_type,
            required=required,
            state=collector_problem,
            observation_mode=DeepScanObservationMode.OBSERVED_ONLY,
            last_success_at=(direct_evidence_at or _stored_utc(collector.last_success_at)),
            limitations=(limitation or "collector_not_ready",),
        )

    if not _baseline_is_current(baseline, now=now, target_type=target.target_type):
        return DeepScanSourceReadiness(
            target_id=target.target_id,
            collector_id=collector.collector_id,
            target_type=target.target_type,
            required=required,
            state=DeepScanReadinessState.PARTIAL,
            observation_mode=DeepScanObservationMode.OBSERVED_ONLY,
            last_success_at=_stored_utc(collector.last_success_at),
            limitations=("authoritative_baseline_missing",),
        )

    assert baseline is not None
    if endpoint_denominator is not None and baseline.expected_count != endpoint_denominator:
        return DeepScanSourceReadiness(
            target_id=target.target_id,
            collector_id=collector.collector_id,
            target_type=target.target_type,
            required=required,
            state=DeepScanReadinessState.PARTIAL,
            observation_mode=DeepScanObservationMode.OBSERVED_ONLY,
            last_success_at=_stored_utc(collector.last_success_at),
            limitations=("baseline_does_not_match_enrolled_denominator",),
        )

    return DeepScanSourceReadiness(
        target_id=target.target_id,
        collector_id=collector.collector_id,
        target_type=target.target_type,
        required=required,
        state=DeepScanReadinessState.READY,
        observation_mode=DeepScanObservationMode.AUTHORITATIVE,
        expected_count=baseline.expected_count,
        baseline=baseline,
        last_success_at=(direct_evidence_at or _stored_utc(collector.last_success_at)),
        limitations=(
            ()
            if target.target_type in _PER_UNIT_COMPLETION_RECEIPT_TARGET_TYPES
            else ("per_unit_completion_receipt_unavailable",)
        ),
    )


def _profile_from_sources(
    *, request: DeepScanPreflightRequest, sources: tuple[DeepScanSourceReadiness, ...], now: datetime
) -> DeepScanProfile:
    material = {
        "version": "v1",
        "mode": request.requested_mode,
        "sources": [source.model_dump(mode="json") for source in sources],
        "customer_authorization_reference": request.customer_authorization_reference,
        "window_start": (now - timedelta(minutes=request.time_window_minutes)).isoformat(),
        "window_end": now.isoformat(),
        "issued_at": now.isoformat(),
        "expires_at": (now + PREFLIGHT_VALIDITY).isoformat(),
    }
    digest = deep_scan_profile_digest(material)
    return DeepScanProfile.model_validate({**material, "digest": digest})


def preflight_deep_scan(
    db: Session,
    *,
    tenant_id: str,
    request: DeepScanPreflightRequest,
    now: datetime | None = None,
) -> DeepScanPreflightResult:
    """Compute a bounded safe source profile from current tenant authorities."""

    observed_now = _utc(now)
    targets = _tenant_targets(db, tenant_id=tenant_id, target_ids=request.target_ids)
    collectors = _tenant_collectors(
        db, tenant_id=tenant_id, collector_ids=request.collector_ids
    )
    sources = tuple(
        _source_readiness(
            db,
            tenant_id=tenant_id,
            target=targets[target_id],
            collectors=collectors,
            request=request,
            now=observed_now,
        )
        for target_id in request.target_ids
    )
    required_gaps = tuple(
        source.target_id
        for source in sources
        if source.required and source.state is not DeepScanReadinessState.READY
    )
    profile = _profile_from_sources(request=request, sources=sources, now=observed_now)
    return DeepScanPreflightResult(
        profile=profile,
        preflight_digest=deep_scan_preflight_digest(request, sources),
        sources=sources,
        required_gaps=required_gaps,
        ready_assignment_count=sum(
            source.state is DeepScanReadinessState.READY for source in sources
        ),
        exhaustive_claim_permitted=(
            request.requested_mode == "full_enterprise"
            and _ENTERPRISE_SCOPE_CLOSURE_READY
            and not required_gaps
            and all(
                source.target_type in _PER_UNIT_COMPLETION_RECEIPT_TARGET_TYPES
                for source in sources
                if source.required
            )
        ),
    )


def freeze_deep_scan_profile(
    *, preflight: DeepScanPreflightResult, request: DeepScanPreflightRequest
) -> DeepScanProfile:
    """Return only a profile produced from the current matching selection."""

    profile = preflight.profile
    if profile.customer_authorization_reference != request.customer_authorization_reference:
        raise ValueError("Deep Scan authorization changed after preflight")
    if profile.mode != request.requested_mode:
        raise ValueError("Deep Scan mode changed after preflight")
    if tuple(source.target_id for source in profile.sources) != request.target_ids:
        raise ValueError("Deep Scan target selection changed after preflight")
    if profile.expires_at <= profile.issued_at:
        raise ValueError("Deep Scan preflight is invalid")
    return profile


def deep_scan_claim_is_permitted(
    profile: DeepScanProfile | DeepScanStoredProfile, coverage: DeepScanCoverage
) -> bool:
    """Permit an enterprise claim only with complete reconciled required sources."""

    if profile.mode != "full_enterprise" or not _ENTERPRISE_SCOPE_CLOSURE_READY:
        return False
    by_target = {item.target_id: item for item in coverage.sources}
    for source in profile.sources:
        if not source.required:
            continue
        result = by_target.get(source.target_id)
        if (
            source.state is not DeepScanReadinessState.READY
            or source.observation_mode is not DeepScanObservationMode.AUTHORITATIVE
            or result is None
            or result.state is not DeepScanCoverageState.COMPLETE
            or result.expected_count != source.expected_count
            or result.observed_count != source.expected_count
            or result.evidence_fresh_at is None
            or result.evidence_fresh_at < profile.window_start
        ):
            return False
    return True


__all__ = [
    "PREFLIGHT_VALIDITY",
    "SOURCE_FRESHNESS",
    "deep_scan_claim_is_permitted",
    "freeze_deep_scan_profile",
    "preflight_deep_scan",
]
