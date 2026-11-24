"""Bounded fleet delivery for metadata-only endpoint inventory.

The service only assigns work to active endpoint identities that already have
the discovery-write scope.  An assignment is delivered through that endpoint's
authenticated policy response; it is never a remote command, a reachability
claim, or an inference about unenrolled devices.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import re
from typing import Iterable, Mapping
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.discovery_canonical import (
    DiscoveryScan,
    DiscoveryScanAssignment,
)
from app.db.models.endpoint_identity import EndpointDeviceIdentity
from app.db.models.endpoint_metadata_inventory import (
    EndpointMetadataInventoryAssignment,
    EndpointMetadataInventoryRun,
)
from app.services.hmair.deep_scan_contracts import (
    DeepScanCoverage,
    DeepScanCoverageState,
    DeepScanStoredProfile,
    DeepScanSourceCoverage,
    parse_persisted_deep_scan_profile,
)
from app.services.hmair.deep_scan_readiness_service import deep_scan_claim_is_permitted
from app.services.hmair.scan_service import finalize_assignment, finalize_scan


MAX_ENDPOINT_METADATA_INVENTORY_ASSIGNMENTS = 5_000
MIN_ENDPOINT_METADATA_INVENTORY_EXPIRY_MINUTES = 5
MAX_ENDPOINT_METADATA_INVENTORY_EXPIRY_MINUTES = 1_440
_REQUEST_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_FAILURE_CODES = frozenset(
    {
        "scanner_unavailable",
        "scanner_rejected",
        "snapshot_rejected",
        "unsupported_platform",
    }
)
_ACTIVE_ASSIGNMENT_STATUSES = frozenset({"pending", "delivered"})
_ACTIVE_RUN_STATUSES = frozenset({"queued", "running"})
_TERMINAL_RUN_STATUSES = frozenset(
    {"complete", "partially_complete", "failed", "expired", "cancelled"}
)
_INVENTORY_LIMITATIONS = (
    "coverage:active_enrolled_endpoints_with_discovery_scope_only",
    "active_scan:not_performed",
    "raw_content:not_collected",
    "browser_activity:not_connected",
    "mcp_runtime:not_connected",
    "llm_runtime:not_connected",
    "saas:not_connected",
    "cloud:not_connected",
    "identity:not_connected",
    "repository:not_connected",
    "network:not_connected",
    "database:not_connected",
)


@dataclass(frozen=True, slots=True)
class EndpointMetadataInventoryDirective:
    assignment_id: str
    inventory_run_id: str
    mode: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class EndpointMetadataInventoryRunSummary:
    id: str
    status: str
    endpoint_denominator: int
    pending_count: int
    delivered_count: int
    completed_count: int
    failed_count: int
    expired_count: int
    cancelled_count: int
    expires_at: datetime
    limitations: tuple[str, ...]


def _utc(value: datetime | None = None) -> datetime:
    observed = value or datetime.now(UTC)
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ValueError("inventory timestamps must include a timezone")
    return observed.astimezone(UTC)


def _stored_utc(value: datetime) -> datetime:
    """Normalize database-returned timestamps from SQLite and PostgreSQL."""

    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _request_digest(
    *,
    tenant_id: str,
    endpoint_ids: tuple[str, ...] | None,
    expires_in_minutes: int,
    parent_scan_id: str | None,
    parent_assignment_id: str | None,
) -> str:
    payload = {
        "tenant_id": tenant_id,
        "endpoint_ids": list(endpoint_ids) if endpoint_ids is not None else None,
        "expires_in_minutes": expires_in_minutes,
        "mode": "metadata_only",
        "parent_scan_id": parent_scan_id,
        "parent_assignment_id": parent_assignment_id,
    }
    return sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
    ).hexdigest()


def _normalized_request_key(value: str) -> str:
    if type(value) is not str or _REQUEST_KEY.fullmatch(value) is None:
        raise ValueError("inventory request idempotency key is invalid")
    return value


def _normalized_endpoint_ids(
    endpoint_ids: Iterable[str] | None,
) -> tuple[str, ...] | None:
    if endpoint_ids is None:
        return None
    material = tuple(endpoint_ids)
    if not material or len(material) > MAX_ENDPOINT_METADATA_INVENTORY_ASSIGNMENTS:
        raise ValueError("inventory endpoint selection is invalid")
    if any(type(item) is not str or not item.strip() or len(item) > 128 for item in material):
        raise ValueError("inventory endpoint selection is invalid")
    normalized = tuple(sorted({item.strip() for item in material}))
    if len(normalized) != len(material):
        raise ValueError("inventory endpoint selection must be unique")
    return normalized


def _normalized_expiry(value: int) -> int:
    if type(value) is not int or not (
        MIN_ENDPOINT_METADATA_INVENTORY_EXPIRY_MINUTES
        <= value
        <= MAX_ENDPOINT_METADATA_INVENTORY_EXPIRY_MINUTES
    ):
        raise ValueError("inventory expiry is outside the allowed range")
    return value


def _normalized_parent_links(
    *, parent_scan_id: str | None, parent_assignment_id: str | None
) -> tuple[str | None, str | None]:
    if parent_scan_id is None and parent_assignment_id is None:
        return None, None
    if parent_scan_id is None or parent_assignment_id is None:
        raise ValueError("inventory parent scan and assignment must be supplied together")
    return _validate_scan_id(parent_scan_id), _validate_scan_id(parent_assignment_id)


def _deep_scan_parent(
    db: Session,
    *,
    tenant_id: str,
    parent_scan_id: str,
    parent_assignment_id: str,
    require_active_assignment: bool,
) -> tuple[DiscoveryScan, DiscoveryScanAssignment, DeepScanStoredProfile]:
    """Load a same-tenant running Deep Scan source assignment only."""

    scan = db.scalar(
        select(DiscoveryScan).where(
            DiscoveryScan.tenant_id == tenant_id,
            DiscoveryScan.scan_id == parent_scan_id,
        )
    )
    if scan is None:
        raise LookupError("metadata inventory parent scan was not found")
    assignment = db.scalar(
        select(DiscoveryScanAssignment).where(
            DiscoveryScanAssignment.tenant_id == tenant_id,
            DiscoveryScanAssignment.assignment_id == parent_assignment_id,
        )
    )
    if assignment is None:
        raise LookupError("metadata inventory parent assignment was not found")
    if assignment.scan_id != scan.scan_id:
        raise ValueError("metadata inventory parent assignment does not belong to scan")
    if require_active_assignment and assignment.status not in {"pending", "running"}:
        raise ValueError("metadata inventory parent assignment is no longer active")
    scope = scan.scope_json
    raw_profile = scope.get("deep_scan") if isinstance(scope, Mapping) else None
    if not isinstance(raw_profile, Mapping) or raw_profile.get("version") != "v1":
        raise ValueError("metadata inventory parent is not a Deep Scan")
    try:
        profile = parse_persisted_deep_scan_profile(raw_profile)
    except ValueError as exc:
        raise ValueError("metadata inventory parent Deep Scan profile is invalid") from exc
    source = next(
        (
            item
            for item in profile.sources
            if item.target_id == assignment.target_id
            and item.collector_id == assignment.collector_id
            and item.target_type == "endpoint_group"
        ),
        None,
    )
    if source is None:
        raise ValueError("metadata inventory parent assignment is not an endpoint source")
    if source.state != "ready" or source.observation_mode != "authoritative":
        raise ValueError("metadata inventory parent endpoint source is not ready")
    return scan, assignment, profile


def _eligible_endpoint_identities(
    db: Session,
    *,
    tenant_id: str,
    endpoint_ids: tuple[str, ...] | None,
) -> tuple[EndpointDeviceIdentity, ...]:
    statement = select(EndpointDeviceIdentity).where(
        EndpointDeviceIdentity.tenant_id == tenant_id
    )
    if endpoint_ids is not None:
        statement = statement.where(EndpointDeviceIdentity.endpoint_id.in_(endpoint_ids))
    rows = tuple(db.scalars(statement.order_by(EndpointDeviceIdentity.endpoint_id)).all())
    if endpoint_ids is not None and {row.endpoint_id for row in rows} != set(endpoint_ids):
        raise LookupError("one or more selected endpoints were not found")
    eligible = tuple(
        row
        for row in rows
        if row.status == "active"
        and isinstance(row.scopes, list)
        and "endpoint:discovery:write" in row.scopes
    )
    if endpoint_ids is not None and len(eligible) != len(rows):
        raise ValueError("one or more selected endpoints are not eligible for metadata inventory")
    if not eligible:
        raise ValueError("no active enrolled endpoints have discovery inventory scope")
    if len(eligible) > MAX_ENDPOINT_METADATA_INVENTORY_ASSIGNMENTS:
        raise ValueError("eligible endpoint count exceeds the bounded inventory limit")
    return eligible


def _assignments_for_run(
    db: Session, *, tenant_id: str, run_id: str
) -> tuple[EndpointMetadataInventoryAssignment, ...]:
    return tuple(
        db.scalars(
            select(EndpointMetadataInventoryAssignment)
            .where(
                EndpointMetadataInventoryAssignment.tenant_id == tenant_id,
                EndpointMetadataInventoryAssignment.inventory_run_id == run_id,
            )
            .order_by(EndpointMetadataInventoryAssignment.created_at)
        ).all()
    )


def _update_parent_deep_scan_coverage(
    db: Session,
    *,
    tenant_id: str,
    run: EndpointMetadataInventoryRun,
    assignments: tuple[EndpointMetadataInventoryAssignment, ...],
    now: datetime,
) -> None:
    """Reconcile exactly one linked endpoint source back to its parent scan.

    The inventory worker is never allowed to name a parent in its payload.  A
    parent link exists only when a tenant administrator created this run from a
    validated Deep Scan assignment.  This function therefore writes one
    source-coverage row and finalizes only that same parent assignment.
    """

    if run.parent_scan_id is None and run.parent_assignment_id is None:
        return
    if run.parent_scan_id is None or run.parent_assignment_id is None:
        raise RuntimeError("metadata inventory parent linkage is incomplete")
    scan, parent_assignment, profile = _deep_scan_parent(
        db,
        tenant_id=tenant_id,
        parent_scan_id=run.parent_scan_id,
        parent_assignment_id=run.parent_assignment_id,
        require_active_assignment=False,
    )
    if parent_assignment.status not in {"pending", "running"}:
        # A terminal parent was reconciled in the same transaction that made
        # this inventory run terminal. Later status reads must be idempotent
        # and must never refresh evidence timestamps or mutate the parent.
        return
    source = next(
        item
        for item in profile.sources
        if item.target_id == parent_assignment.target_id
        and item.collector_id == parent_assignment.collector_id
    )
    completed_count = sum(item.status == "complete" for item in assignments)
    total_count = len(assignments)
    if total_count != run.endpoint_denominator:
        raise RuntimeError("metadata inventory endpoint denominator does not reconcile")
    if completed_count == source.expected_count and run.status == "complete":
        coverage_state = DeepScanCoverageState.COMPLETE
        reason: str | None = None
        parent_status = "complete"
    elif completed_count:
        coverage_state = DeepScanCoverageState.PARTIAL
        reason = "endpoint_denominator_not_reconciled"
        parent_status = "failed"
    elif run.status == "expired":
        coverage_state = DeepScanCoverageState.STALE
        reason = "endpoint_inventory_expired"
        parent_status = "stale"
    elif run.status == "failed":
        coverage_state = DeepScanCoverageState.FAILED
        reason = "endpoint_inventory_failed"
        parent_status = "failed"
    else:
        coverage_state = DeepScanCoverageState.EMPTY
        reason = "endpoint_inventory_no_complete_receipts"
        parent_status = "empty"

    source_coverage = DeepScanSourceCoverage(
        target_id=source.target_id,
        collector_id=source.collector_id,
        state=coverage_state,
        expected_count=source.expected_count,
        observed_count=completed_count,
        evidence_fresh_at=now if completed_count else None,
        reason=reason,
    )
    existing_summary = scan.coverage_summary_json
    existing_deep = (
        existing_summary.get("deep_scan")
        if isinstance(existing_summary, Mapping)
        else None
    )
    existing_sources = (
        existing_deep.get("sources")
        if isinstance(existing_deep, Mapping)
        else ()
    )
    if not isinstance(existing_sources, (list, tuple)):
        raise RuntimeError("parent Deep Scan coverage summary is invalid")
    retained: list[DeepScanSourceCoverage] = []
    for raw_item in existing_sources:
        try:
            item = DeepScanSourceCoverage.model_validate(raw_item)
        except ValueError as exc:
            raise RuntimeError("parent Deep Scan coverage source is invalid") from exc
        if item.target_id == source.target_id:
            continue
        retained.append(item)
    coverage = DeepScanCoverage(
        scan_id=scan.scan_id,
        sources=tuple((*retained, source_coverage)),
        exhaustive_claim_permitted=False,
    )
    coverage = coverage.model_copy(
        update={
            "exhaustive_claim_permitted": deep_scan_claim_is_permitted(
                profile, coverage
            )
        }
    )
    summary = dict(existing_summary) if isinstance(existing_summary, Mapping) else {}
    summary["deep_scan"] = {
        "sources": [
            item.model_dump(mode="json", exclude_defaults=True)
            for item in coverage.sources
        ],
        "exhaustive_claim_permitted": coverage.exhaustive_claim_permitted,
    }
    scan.coverage_summary_json = summary
    db.flush()

    observation_count = sum(item.observations_count for item in assignments)
    finalized_parent = finalize_assignment(
        db,
        tenant_id=tenant_id,
        assignment_id=parent_assignment.assignment_id,
        status=parent_status,
        observations_count=observation_count,
        warning=reason,
        error=None if parent_status == "complete" else reason,
    )
    if finalized_parent.scan_id != scan.scan_id:
        raise RuntimeError("metadata inventory parent assignment changed unexpectedly")
    finalize_scan(db, tenant_id=tenant_id, scan_id=scan.scan_id)


def _reconcile_run(
    db: Session,
    *,
    tenant_id: str,
    run: EndpointMetadataInventoryRun,
    now: datetime,
) -> EndpointMetadataInventoryRunSummary:
    previous_status = run.status
    assignments = _assignments_for_run(db, tenant_id=tenant_id, run_id=run.id)
    counts = Counter(assignment.status for assignment in assignments)
    active_count = sum(counts[status] for status in _ACTIVE_ASSIGNMENT_STATUSES)
    total = len(assignments)
    if active_count:
        if counts["delivered"]:
            run.status = "running"
            run.started_at = run.started_at or now
        else:
            run.status = "queued"
        run.completed_at = None
        run.cancelled_at = None
    elif counts["complete"] == total:
        run.status = "complete"
        run.started_at = run.started_at or now
        run.completed_at = run.completed_at or now
        run.cancelled_at = None
    elif counts["complete"]:
        run.status = "partially_complete"
        run.started_at = run.started_at or now
        run.completed_at = run.completed_at or now
        run.cancelled_at = None
    elif counts["expired"]:
        run.status = "expired"
        run.completed_at = run.completed_at or now
        run.cancelled_at = None
    elif counts["cancelled"] == total:
        run.status = "cancelled"
        run.cancelled_at = run.cancelled_at or now
        run.completed_at = None
    else:
        run.status = "failed"
        run.completed_at = run.completed_at or now
        run.cancelled_at = None
    db.flush()
    if previous_status in _ACTIVE_RUN_STATUSES and run.status in _TERMINAL_RUN_STATUSES:
        _update_parent_deep_scan_coverage(
            db,
            tenant_id=tenant_id,
            run=run,
            assignments=assignments,
            now=now,
        )
    return EndpointMetadataInventoryRunSummary(
        id=run.id,
        status=run.status,
        endpoint_denominator=run.endpoint_denominator,
        pending_count=counts["pending"],
        delivered_count=counts["delivered"],
        completed_count=counts["complete"],
        failed_count=counts["failed"],
        expired_count=counts["expired"],
        cancelled_count=counts["cancelled"],
        expires_at=_stored_utc(run.expires_at),
        limitations=tuple(run.limitations_json),
    )


def _expire_runs(db: Session, *, tenant_id: str, now: datetime) -> None:
    runs = tuple(
        db.scalars(
            select(EndpointMetadataInventoryRun).where(
                EndpointMetadataInventoryRun.tenant_id == tenant_id,
                EndpointMetadataInventoryRun.status.in_(("queued", "running")),
            )
        ).all()
    )
    for run in runs:
        if _stored_utc(run.expires_at) > now:
            continue
        assignments = _assignments_for_run(db, tenant_id=tenant_id, run_id=run.id)
        for assignment in assignments:
            if assignment.status in _ACTIVE_ASSIGNMENT_STATUSES:
                assignment.status = "expired"
                assignment.failure_code = "expired"
        _reconcile_run(db, tenant_id=tenant_id, run=run, now=now)


def _run_summary(
    db: Session, *, tenant_id: str, run: EndpointMetadataInventoryRun, now: datetime
) -> EndpointMetadataInventoryRunSummary:
    _expire_runs(db, tenant_id=tenant_id, now=now)
    return _reconcile_run(db, tenant_id=tenant_id, run=run, now=now)


def create_endpoint_metadata_inventory_run(
    db: Session,
    *,
    tenant_id: str,
    requested_by_user_id: str | None,
    request_idempotency_key: str,
    endpoint_ids: Iterable[str] | None,
    expires_in_minutes: int,
    parent_scan_id: str | None = None,
    parent_assignment_id: str | None = None,
    now: datetime | None = None,
) -> EndpointMetadataInventoryRunSummary:
    """Create one bounded, metadata-only fleet inventory run.

    Passing ``None`` for ``endpoint_ids`` means every *currently active* tenant
    endpoint with the discovery-write scope, not every device in the customer
    estate.  A selection containing any ineligible endpoint is rejected rather
    than silently narrowed.
    """

    observed_now = _utc(now)
    normalized_ids = _normalized_endpoint_ids(endpoint_ids)
    expiry_minutes = _normalized_expiry(expires_in_minutes)
    request_key = _normalized_request_key(request_idempotency_key)
    normalized_parent_scan_id, normalized_parent_assignment_id = _normalized_parent_links(
        parent_scan_id=parent_scan_id,
        parent_assignment_id=parent_assignment_id,
    )
    digest = _request_digest(
        tenant_id=tenant_id,
        endpoint_ids=normalized_ids,
        expires_in_minutes=expiry_minutes,
        parent_scan_id=normalized_parent_scan_id,
        parent_assignment_id=normalized_parent_assignment_id,
    )
    existing = db.scalar(
        select(EndpointMetadataInventoryRun).where(
            EndpointMetadataInventoryRun.tenant_id == tenant_id,
            EndpointMetadataInventoryRun.request_idempotency_key == request_key,
        )
    )
    if existing is not None:
        if existing.request_digest != digest:
            raise ValueError("inventory request idempotency key was reused with different input")
        return _run_summary(db, tenant_id=tenant_id, run=existing, now=observed_now)

    endpoints = _eligible_endpoint_identities(
        db, tenant_id=tenant_id, endpoint_ids=normalized_ids
    )
    if normalized_parent_scan_id is not None and normalized_parent_assignment_id is not None:
        _scan, _assignment, profile = _deep_scan_parent(
            db,
            tenant_id=tenant_id,
            parent_scan_id=normalized_parent_scan_id,
            parent_assignment_id=normalized_parent_assignment_id,
            require_active_assignment=True,
        )
        source = next(
            item
            for item in profile.sources
            if item.target_id == _assignment.target_id
            and item.collector_id == _assignment.collector_id
        )
        if source.expected_count != len(endpoints):
            raise ValueError(
                "metadata inventory denominator does not match frozen Deep Scan source"
            )
    run = EndpointMetadataInventoryRun(
        tenant_id=tenant_id,
        requested_by_user_id=requested_by_user_id,
        request_idempotency_key=request_key,
        request_digest=digest,
        status="queued",
        endpoint_denominator=len(endpoints),
        expires_at=observed_now + timedelta(minutes=expiry_minutes),
        limitations_json=list(_INVENTORY_LIMITATIONS),
        parent_scan_id=normalized_parent_scan_id,
        parent_assignment_id=normalized_parent_assignment_id,
    )
    db.add(run)
    db.flush()
    db.add_all(
        [
            EndpointMetadataInventoryAssignment(
                tenant_id=tenant_id,
                inventory_run_id=run.id,
                endpoint_device_identity_id=endpoint.id,
                status="pending",
                observations_count=0,
            )
            for endpoint in endpoints
        ]
    )
    db.flush()
    return _reconcile_run(db, tenant_id=tenant_id, run=run, now=observed_now)


def get_endpoint_metadata_inventory_run(
    db: Session,
    *,
    tenant_id: str,
    run_id: str,
    now: datetime | None = None,
) -> EndpointMetadataInventoryRunSummary:
    observed_now = _utc(now)
    run = db.scalar(
        select(EndpointMetadataInventoryRun).where(
            EndpointMetadataInventoryRun.tenant_id == tenant_id,
            EndpointMetadataInventoryRun.id == run_id,
        )
    )
    if run is None:
        raise LookupError("metadata inventory run was not found")
    return _run_summary(db, tenant_id=tenant_id, run=run, now=observed_now)


def list_endpoint_metadata_inventory_runs(
    db: Session,
    *,
    tenant_id: str,
    limit: int = 20,
    now: datetime | None = None,
) -> tuple[EndpointMetadataInventoryRunSummary, ...]:
    """List bounded tenant-local inventory history without endpoint names."""

    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("inventory run limit is outside the allowed range")
    observed_now = _utc(now)
    _expire_runs(db, tenant_id=tenant_id, now=observed_now)
    rows = tuple(
        db.scalars(
            select(EndpointMetadataInventoryRun)
            .where(EndpointMetadataInventoryRun.tenant_id == tenant_id)
            .order_by(EndpointMetadataInventoryRun.created_at.desc())
            .limit(limit)
        ).all()
    )
    return tuple(
        _reconcile_run(db, tenant_id=tenant_id, run=row, now=observed_now)
        for row in rows
    )


def reconcile_endpoint_metadata_inventory_runs(
    db: Session,
    *,
    tenant_id: str,
    now: datetime | None = None,
) -> tuple[EndpointMetadataInventoryRunSummary, ...]:
    """Expire and reconcile bounded active runs for one tenant only.

    This is deliberately a lifecycle repair path rather than a scan trigger:
    it never creates endpoint work or probes endpoints.  It ensures that a
    Deep Scan whose enrolled endpoints do not return a receipt becomes an
    explicit partial/failed coverage result once the existing assignment
    expiry has elapsed.
    """

    observed_now = _utc(now)
    _expire_runs(db, tenant_id=tenant_id, now=observed_now)
    rows = tuple(
        db.scalars(
            select(EndpointMetadataInventoryRun)
            .where(
                EndpointMetadataInventoryRun.tenant_id == tenant_id,
                EndpointMetadataInventoryRun.status.in_(("queued", "running")),
            )
            .order_by(EndpointMetadataInventoryRun.created_at)
            .limit(MAX_ENDPOINT_METADATA_INVENTORY_ASSIGNMENTS)
        ).all()
    )
    return tuple(
        _reconcile_run(db, tenant_id=tenant_id, run=row, now=observed_now)
        for row in rows
    )


def next_endpoint_metadata_inventory_assignment(
    db: Session,
    *,
    tenant_id: str,
    endpoint_identity_id: str,
    now: datetime | None = None,
) -> EndpointMetadataInventoryDirective | None:
    """Return at most one active assignment for this authenticated endpoint."""

    observed_now = _utc(now)
    _expire_runs(db, tenant_id=tenant_id, now=observed_now)
    assignment = db.scalar(
        select(EndpointMetadataInventoryAssignment)
        .join(
            EndpointMetadataInventoryRun,
            EndpointMetadataInventoryRun.id
            == EndpointMetadataInventoryAssignment.inventory_run_id,
        )
        .where(
            EndpointMetadataInventoryAssignment.tenant_id == tenant_id,
            EndpointMetadataInventoryAssignment.endpoint_device_identity_id
            == endpoint_identity_id,
            EndpointMetadataInventoryAssignment.status.in_(tuple(_ACTIVE_ASSIGNMENT_STATUSES)),
            EndpointMetadataInventoryRun.tenant_id == tenant_id,
            EndpointMetadataInventoryRun.status.in_(("queued", "running")),
        )
        .order_by(
            EndpointMetadataInventoryRun.expires_at,
            EndpointMetadataInventoryAssignment.created_at,
        )
    )
    if assignment is None:
        return None
    run = db.scalar(
        select(EndpointMetadataInventoryRun).where(
            EndpointMetadataInventoryRun.tenant_id == tenant_id,
            EndpointMetadataInventoryRun.id == assignment.inventory_run_id,
        )
    )
    if run is None:  # defensive tenant-scoped integrity check
        raise RuntimeError("metadata inventory assignment parent is unavailable")
    if _stored_utc(run.expires_at) <= observed_now:
        _expire_runs(db, tenant_id=tenant_id, now=observed_now)
        return None
    if assignment.status == "pending":
        assignment.status = "delivered"
        assignment.delivered_at = observed_now
    _reconcile_run(db, tenant_id=tenant_id, run=run, now=observed_now)
    return EndpointMetadataInventoryDirective(
        assignment_id=assignment.id,
        inventory_run_id=run.id,
        mode="metadata_only",
        expires_at=_stored_utc(run.expires_at),
    )


def _validate_scan_id(value: str) -> str:
    if type(value) is not str:
        raise ValueError("inventory receipt scan identifier is invalid")
    try:
        return str(UUID(value))
    except (ValueError, AttributeError) as exc:
        raise ValueError("inventory receipt scan identifier is invalid") from exc


def _assignment_for_completion(
    db: Session,
    *,
    tenant_id: str,
    endpoint_identity_id: str,
    assignment_id: str,
) -> tuple[EndpointMetadataInventoryAssignment, EndpointMetadataInventoryRun]:
    assignment = db.scalar(
        select(EndpointMetadataInventoryAssignment).where(
            EndpointMetadataInventoryAssignment.tenant_id == tenant_id,
            EndpointMetadataInventoryAssignment.id == assignment_id,
        )
    )
    if assignment is None or assignment.endpoint_device_identity_id != endpoint_identity_id:
        raise ValueError("metadata inventory assignment is not assigned to this endpoint")
    run = db.scalar(
        select(EndpointMetadataInventoryRun).where(
            EndpointMetadataInventoryRun.tenant_id == tenant_id,
            EndpointMetadataInventoryRun.id == assignment.inventory_run_id,
        )
    )
    if run is None:
        raise RuntimeError("metadata inventory assignment parent is unavailable")
    return assignment, run


def complete_endpoint_metadata_inventory_assignment(
    db: Session,
    *,
    tenant_id: str,
    endpoint_identity_id: str,
    assignment_id: str,
    scan_id: str,
    observations_count: int,
    now: datetime | None = None,
) -> EndpointMetadataInventoryRunSummary:
    """Bind a persisted one-endpoint receipt to its original assignment."""

    if type(observations_count) is not int or observations_count < 0:
        raise ValueError("inventory observations count is invalid")
    observed_now = _utc(now)
    normalized_scan_id = _validate_scan_id(scan_id)
    _expire_runs(db, tenant_id=tenant_id, now=observed_now)
    assignment, run = _assignment_for_completion(
        db,
        tenant_id=tenant_id,
        endpoint_identity_id=endpoint_identity_id,
        assignment_id=assignment_id,
    )
    if assignment.status == "complete":
        if (
            assignment.scan_id != normalized_scan_id
            or assignment.observations_count != observations_count
        ):
            raise ValueError("metadata inventory assignment was already completed differently")
        return _reconcile_run(db, tenant_id=tenant_id, run=run, now=observed_now)
    if assignment.status not in _ACTIVE_ASSIGNMENT_STATUSES:
        raise ValueError("metadata inventory assignment is no longer active")
    if _stored_utc(run.expires_at) <= observed_now:
        _expire_runs(db, tenant_id=tenant_id, now=observed_now)
        raise ValueError("metadata inventory assignment has expired")
    assignment.status = "complete"
    assignment.scan_id = normalized_scan_id
    assignment.observations_count = observations_count
    assignment.failure_code = None
    assignment.completed_at = observed_now
    return _reconcile_run(db, tenant_id=tenant_id, run=run, now=observed_now)


def fail_endpoint_metadata_inventory_assignment(
    db: Session,
    *,
    tenant_id: str,
    endpoint_identity_id: str,
    assignment_id: str,
    code: str,
    now: datetime | None = None,
) -> EndpointMetadataInventoryRunSummary:
    """Record a bounded endpoint-side failure without accepting raw detail."""

    if code not in _FAILURE_CODES:
        raise ValueError("metadata inventory failure code is invalid")
    observed_now = _utc(now)
    _expire_runs(db, tenant_id=tenant_id, now=observed_now)
    assignment, run = _assignment_for_completion(
        db,
        tenant_id=tenant_id,
        endpoint_identity_id=endpoint_identity_id,
        assignment_id=assignment_id,
    )
    if assignment.status not in _ACTIVE_ASSIGNMENT_STATUSES:
        raise ValueError("metadata inventory assignment is no longer active")
    assignment.status = "failed"
    assignment.failure_code = code
    assignment.completed_at = observed_now
    return _reconcile_run(db, tenant_id=tenant_id, run=run, now=observed_now)


__all__ = [
    "EndpointMetadataInventoryDirective",
    "EndpointMetadataInventoryRunSummary",
    "MAX_ENDPOINT_METADATA_INVENTORY_ASSIGNMENTS",
    "complete_endpoint_metadata_inventory_assignment",
    "create_endpoint_metadata_inventory_run",
    "fail_endpoint_metadata_inventory_assignment",
    "get_endpoint_metadata_inventory_run",
    "list_endpoint_metadata_inventory_runs",
    "reconcile_endpoint_metadata_inventory_runs",
    "next_endpoint_metadata_inventory_assignment",
]
