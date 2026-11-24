from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import set_committed_value

from app.db.models.discovery_canonical import (
    DiscoveryCollector,
    DiscoveryScan,
    DiscoveryScanAssignment,
    DiscoveryScanTarget,
    DiscoveryTarget,
)
from app.db.models.user import User, UserTenantRole
from app.services.hmair.contracts import DiscoveryScanCreate
from app.services.hmair.deep_scan_contracts import (
    DeepScanCoverage,
    DeepScanCoverageState,
    DeepScanSourceCoverage,
    DeepScanUnitCompletionReceipt,
    parse_persisted_deep_scan_profile,
)
from app.services.hmair.deep_scan_receipt_service import (
    verify_deep_scan_unit_completion_receipt,
)
from app.core.config import settings
from app.services.hmair.deep_scan_readiness_service import deep_scan_claim_is_permitted
from app.services.hmair.collector_sdk import DiscoveryTargetView
from app.services.privacy_sanitizer import redact_sensitive_text


ALLOWED_SCAN_TRANSITIONS = {
    "queued": {"running", "cancelled", "failed"},
    "running": {
        "partially_complete",
        "complete",
        "failed",
        "cancelled",
    },
    "partially_complete": set(),
    "complete": set(),
    "failed": set(),
    "cancelled": set(),
}

_ASSIGNMENT_TERMINAL_STATUSES = frozenset(
    {
        "complete",
        "failed",
        "cancelled",
        "unsupported",
        "permission_denied",
        "rate_limited",
        "stale",
        "empty",
    }
)
_ASSIGNMENT_ACTIVE_STATUSES = frozenset({"pending", "running"})
_SCAN_FINAL_STATUSES = frozenset(
    {"partially_complete", "complete", "failed", "cancelled"}
)
_DECISIVE_FAILURE_STATUSES = frozenset(
    {"failed", "permission_denied", "unsupported"}
)
_REQUEST_UNIQUE_CONSTRAINT = "uq_discovery_scan_tenant_request"
_SQLITE_REQUEST_UNIQUE_MESSAGE = (
    "UNIQUE constraint failed: discovery_scans.tenant_id, "
    "discovery_scans.request_idempotency_key"
)
_UNPUBLISHED_ASSIGNMENT_STARTED_AT = datetime(1970, 1, 1, tzinfo=UTC)


@dataclass(frozen=True)
class ScanMutationResult:
    scan: DiscoveryScan
    created: bool


@dataclass(frozen=True)
class ScanCancellationResult:
    scan: DiscoveryScan
    changed: bool
    previous_status: str


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _bounded_request_key(value: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= 128:
        raise ValueError("request idempotency key must contain 1 to 128 characters")
    return value


def _request_material(
    *,
    tenant_id: str,
    requested_by: str | None,
    payload: DiscoveryScanCreate,
    rescan_of_scan_id: str | None,
) -> dict[str, Any]:
    return {
        "tenant_id": tenant_id,
        "requested_by": requested_by,
        "rescan_of_scan_id": rescan_of_scan_id,
        "payload": payload.model_dump(mode="json"),
    }


def _request_digest(material: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _tenant_targets(
    db: Session,
    *,
    tenant_id: str,
    target_ids: Iterable[str],
) -> dict[str, DiscoveryTarget]:
    expected = tuple(target_ids)
    rows = db.scalars(
        select(DiscoveryTarget).where(
            DiscoveryTarget.tenant_id == tenant_id,
            DiscoveryTarget.target_id.in_(expected),
        )
    )
    targets = {row.target_id: row for row in rows}
    if set(targets) != set(expected):
        raise LookupError("one or more scan targets were not found")
    return targets


def _tenant_collectors(
    db: Session,
    *,
    tenant_id: str,
    collector_ids: Iterable[str],
) -> dict[str, DiscoveryCollector]:
    expected = tuple(collector_ids)
    rows = db.scalars(
        select(DiscoveryCollector).where(
            DiscoveryCollector.tenant_id == tenant_id,
            DiscoveryCollector.collector_id.in_(expected),
        )
    )
    collectors = {row.collector_id: row for row in rows}
    if set(collectors) != set(expected):
        raise LookupError("one or more scan collectors were not found")
    return collectors


def _validate_assignments(
    *,
    targets: Mapping[str, DiscoveryTarget],
    collectors: Mapping[str, DiscoveryCollector],
    assignment_pairs: Iterable[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    pairs = tuple(assignment_pairs)
    if not pairs or len(set(pairs)) != len(pairs):
        raise ValueError("scan assignments must be unique and non-empty")
    for target_id, collector_id in pairs:
        target = targets.get(target_id)
        collector = collectors.get(collector_id)
        if target is None or collector is None:
            raise LookupError("scan assignment parent was not found")
        if target.target_type not in collector.supported_targets_json:
            raise ValueError("collector does not support the selected target type")
    return pairs


def _transition_scan(
    scan: DiscoveryScan,
    *,
    status: str,
    now: datetime,
) -> None:
    if status == scan.status:
        return
    if status not in ALLOWED_SCAN_TRANSITIONS.get(scan.status, set()):
        raise ValueError("scan lifecycle transition is not allowed")

    scan.status = status
    if status == "running":
        scan.started_at = scan.started_at or now
        scan.completed_at = None
        scan.cancelled_at = None
    elif status in {"complete", "partially_complete"}:
        if scan.started_at is None:
            raise ValueError("scan must be running before successful finalization")
        scan.completed_at = now
        scan.cancelled_at = None
    elif status == "failed":
        scan.completed_at = now
        scan.cancelled_at = None
    elif status == "cancelled":
        scan.completed_at = None
        scan.cancelled_at = now


def _safe_detail(value: str | None) -> str | None:
    if value is None:
        return None
    sanitized = redact_sensitive_text(value, max_len=480).strip()[:500]
    return sanitized or None


def _normalize_lifecycle_datetimes(
    row: DiscoveryScan | DiscoveryScanAssignment,
) -> None:
    fields = (
        ("started_at", "completed_at", "cancelled_at")
        if isinstance(row, DiscoveryScan)
        else ("started_at", "completed_at")
    )
    for field_name in fields:
        value = getattr(row, field_name)
        if value is not None and (
            value.tzinfo is None or value.utcoffset() is None
        ):
            # SQLite drops timezone metadata on round-trip. The canonical
            # service stores UTC; restore the in-memory contract without
            # marking the persisted value dirty.
            set_committed_value(row, field_name, value.replace(tzinfo=UTC))


def _deep_scan_completion_is_permitted(scan: DiscoveryScan) -> bool | None:
    """Return ``None`` for legacy scans and a strict claim result for Deep Scan."""

    scope = scan.scope_json
    if not isinstance(scope, Mapping):
        return None
    raw_profile = scope.get("deep_scan")
    if not isinstance(raw_profile, Mapping) or raw_profile.get("version") != "v1":
        return None
    summary = scan.coverage_summary_json
    if not isinstance(summary, Mapping):
        return False
    raw_coverage = summary.get("deep_scan")
    if not isinstance(raw_coverage, Mapping):
        return False
    try:
        profile = parse_persisted_deep_scan_profile(raw_profile)
        coverage = DeepScanCoverage.model_validate(
            {
                "scan_id": scan.scan_id,
                "sources": raw_coverage.get("sources", ()),
                "exhaustive_claim_permitted": raw_coverage.get(
                    "exhaustive_claim_permitted", False
                ),
            }
        )
    except ValueError:
        return False
    return deep_scan_claim_is_permitted(profile, coverage)


def record_deep_scan_source_coverage(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
    assignment_id: str,
    state: DeepScanCoverageState | str,
    observed_count: int,
    evidence_fresh_at: datetime | None,
    reason: str | None,
    completion_receipts: tuple[DeepScanUnitCompletionReceipt, ...] = (),
    settings_obj: object = settings,
) -> DiscoveryScan:
    """Persist one safe coverage result for the exact Deep Scan assignment.

    This is an internal source-bridge boundary: it validates the frozen
    profile and assignment tuple before replacing only that source's coverage
    row. Browser and MCP/runtime sources can assert complete only when signed,
    tenant-bound, fresh unit receipts reconcile their frozen denominator.
    """

    try:
        coverage_state = DeepScanCoverageState(state)
    except ValueError as exc:
        raise ValueError("Deep Scan coverage state is invalid") from exc
    if type(observed_count) is not int or observed_count < 0:
        raise ValueError("Deep Scan observed count is invalid")
    scan = _locked_scan(db, tenant_id=tenant_id, scan_id=scan_id)
    if scan is None:
        raise LookupError("scan was not found")
    scope = scan.scope_json
    raw_profile = scope.get("deep_scan") if isinstance(scope, Mapping) else None
    if not isinstance(raw_profile, Mapping) or raw_profile.get("version") != "v1":
        raise LookupError("Deep Scan profile was not found")
    try:
        profile = parse_persisted_deep_scan_profile(raw_profile)
    except ValueError as exc:
        raise ValueError("Deep Scan profile is invalid") from exc
    assignment = db.scalar(
        select(DiscoveryScanAssignment).where(
            DiscoveryScanAssignment.tenant_id == tenant_id,
            DiscoveryScanAssignment.assignment_id == assignment_id,
            DiscoveryScanAssignment.scan_id == scan_id,
        )
    )
    if assignment is None:
        raise LookupError("scan assignment was not found")
    source = next(
        (
            item
            for item in profile.sources
            if item.target_id == assignment.target_id
            and item.collector_id == assignment.collector_id
        ),
        None,
    )
    if source is None or source.expected_count is None:
        raise ValueError("Deep Scan assignment does not match a ready source")
    receipt_target_types = {
        "browser_tenant",
        "mcp_environment",
        "llm_gateway",
        "runtime_environment",
    }
    verified_units: set[str] = set()
    for receipt in completion_receipts:
        if (
            receipt.scan_id != scan_id
            or receipt.target_id != source.target_id
            or receipt.collector_id != source.collector_id
            or receipt.observed_at < profile.window_start
            or receipt.observed_at > profile.window_end
            or not verify_deep_scan_unit_completion_receipt(
                receipt,
                tenant_id=tenant_id,
                settings_obj=settings_obj,
            )
        ):
            raise ValueError("Deep Scan completion receipt is invalid")
        if receipt.unit_id_hash in verified_units:
            raise ValueError("Deep Scan completion receipt unit is duplicated")
        verified_units.add(receipt.unit_id_hash)
    if source.target_type in receipt_target_types:
        if observed_count != len(verified_units):
            raise ValueError("Deep Scan observed count must equal verified source units")
        if coverage_state is DeepScanCoverageState.COMPLETE and (
            not completion_receipts
            or len(verified_units) != source.expected_count
        ):
            raise ValueError(
                "source bridge cannot assert complete coverage without reconciled receipts"
            )
    elif completion_receipts:
        raise ValueError("source type does not accept bridge completion receipts")
    source_coverage = DeepScanSourceCoverage(
        target_id=source.target_id,
        collector_id=source.collector_id,
        state=coverage_state,
        expected_count=source.expected_count,
        observed_count=observed_count,
        evidence_fresh_at=evidence_fresh_at,
        reason=reason,
        completion_receipts=completion_receipts,
    )
    existing_summary = scan.coverage_summary_json
    raw_deep = (
        existing_summary.get("deep_scan")
        if isinstance(existing_summary, Mapping)
        else None
    )
    raw_sources = raw_deep.get("sources") if isinstance(raw_deep, Mapping) else ()
    if not isinstance(raw_sources, (list, tuple)):
        raise ValueError("Deep Scan coverage summary is invalid")
    retained: list[DeepScanSourceCoverage] = []
    for raw_item in raw_sources:
        try:
            item = DeepScanSourceCoverage.model_validate(raw_item)
        except ValueError as exc:
            raise ValueError("Deep Scan coverage summary is invalid") from exc
        if item.target_id != source.target_id:
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
    return scan


def _is_request_unique_conflict(error: IntegrityError) -> bool:
    original = error.orig
    diagnostic = getattr(original, "diag", None)
    constraint_name = getattr(diagnostic, "constraint_name", None)
    sqlstate = getattr(original, "sqlstate", None) or getattr(
        original, "pgcode", None
    )
    if sqlstate == "23505":
        return constraint_name == _REQUEST_UNIQUE_CONSTRAINT
    return str(original) == _SQLITE_REQUEST_UNIQUE_MESSAGE


def get_scan(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
) -> DiscoveryScan | None:
    return db.scalar(
        select(DiscoveryScan).where(
            DiscoveryScan.tenant_id == tenant_id,
            DiscoveryScan.scan_id == scan_id,
        )
    )


def get_target(
    db: Session,
    *,
    tenant_id: str,
    target_id: str,
) -> DiscoveryTargetView | None:
    target = db.scalar(
        select(DiscoveryTarget).where(
            DiscoveryTarget.tenant_id == tenant_id,
            DiscoveryTarget.target_id == target_id,
        )
    )
    if target is None:
        return None
    last_scanned_at = target.last_scanned_at
    if last_scanned_at is not None and (
        last_scanned_at.tzinfo is None
        or last_scanned_at.utcoffset() is None
    ):
        last_scanned_at = last_scanned_at.replace(tzinfo=UTC)
    return DiscoveryTargetView(
        target_id=target.target_id,
        target_type=target.target_type,
        identifier=target.identifier,
        environment=target.environment,
        owner_hint=target.owner_hint,
        credentials_reference=target.credentials_reference,
        permitted_methods=tuple(target.permitted_methods_json),
        exclusions=tuple(target.exclusions_json),
        rate_limit=target.rate_limit,
        active_scan_allowed=target.active_scan_allowed,
        sensitive_scope=target.sensitive_scope,
        last_scanned_at=last_scanned_at,
    )


def get_collector(
    db: Session,
    *,
    tenant_id: str,
    collector_id: str,
) -> DiscoveryCollector | None:
    return db.scalar(
        select(DiscoveryCollector).where(
            DiscoveryCollector.tenant_id == tenant_id,
            DiscoveryCollector.collector_id == collector_id,
        )
    )


def _locked_scan(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
) -> DiscoveryScan | None:
    scan = db.scalar(
        select(DiscoveryScan)
        .where(
            DiscoveryScan.tenant_id == tenant_id,
            DiscoveryScan.scan_id == scan_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if scan is not None:
        _normalize_lifecycle_datetimes(scan)
    return scan


def claim_assignment_batch(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
    limit: int,
) -> tuple[DiscoveryScanAssignment, ...]:
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("assignment claim limit must be between 1 and 100")

    # Serialize claims per scan before counting occupied slots. The assignment
    # lock below still uses SKIP LOCKED so independent scans do not block one
    # another and stale claimers cannot duplicate work.
    scan = _locked_scan(db, tenant_id=tenant_id, scan_id=scan_id)
    if scan is None or scan.status in _SCAN_FINAL_STATUSES:
        return ()

    running_count = db.scalar(
        select(func.count())
        .select_from(DiscoveryScanAssignment)
        .where(
            DiscoveryScanAssignment.tenant_id == tenant_id,
            DiscoveryScanAssignment.scan_id == scan_id,
            DiscoveryScanAssignment.status == "running",
        )
    )
    remaining_slots = limit - int(running_count or 0)
    if remaining_slots <= 0:
        return ()

    assignments = tuple(
        db.scalars(
            select(DiscoveryScanAssignment)
            .where(
                DiscoveryScanAssignment.tenant_id == tenant_id,
                DiscoveryScanAssignment.scan_id == scan_id,
                DiscoveryScanAssignment.status == "pending",
            )
            .order_by(DiscoveryScanAssignment.assignment_id)
            .limit(remaining_slots)
            .with_for_update(skip_locked=True)
            .execution_options(populate_existing=True)
        )
    )
    if not assignments:
        return ()

    now = _utcnow()
    if scan.status == "queued":
        _transition_scan(scan, status="running", now=now)
    elif scan.status != "running":
        return ()
    for assignment in assignments:
        assignment.status = "running"
        # A non-null sentinel satisfies the existing lifecycle constraint
        # while distinguishing a committed claim from a worker that has
        # actually begun execution. Publication recovery may safely return
        # only sentinel-marked work to pending without racing a live worker.
        assignment.started_at = _UNPUBLISHED_ASSIGNMENT_STARTED_AT
        assignment.completed_at = None
    db.flush()
    return assignments


def start_assignment(
    db: Session,
    *,
    tenant_id: str,
    assignment_id: str,
) -> DiscoveryScanAssignment | None:
    assignment = db.scalar(
        select(DiscoveryScanAssignment)
        .where(
            DiscoveryScanAssignment.tenant_id == tenant_id,
            DiscoveryScanAssignment.assignment_id == assignment_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if assignment is None:
        return None
    _normalize_lifecycle_datetimes(assignment)
    if assignment.status in _ASSIGNMENT_TERMINAL_STATUSES:
        return assignment
    if assignment.status == "running":
        if assignment.started_at == _UNPUBLISHED_ASSIGNMENT_STARTED_AT:
            assignment.started_at = _utcnow()
            db.flush()
        return assignment
    if assignment.status != "pending":
        raise ValueError("assignment lifecycle transition is not allowed")
    assignment.status = "running"
    assignment.started_at = _utcnow()
    assignment.completed_at = None
    db.flush()
    return assignment


def release_unpublished_assignment_claims(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
    assignment_ids: Iterable[str],
) -> int:
    identifiers = tuple(dict.fromkeys(assignment_ids))
    if not identifiers:
        return 0
    assignments = tuple(
        db.scalars(
            select(DiscoveryScanAssignment)
            .where(
                DiscoveryScanAssignment.tenant_id == tenant_id,
                DiscoveryScanAssignment.scan_id == scan_id,
                DiscoveryScanAssignment.assignment_id.in_(identifiers),
            )
            .order_by(DiscoveryScanAssignment.assignment_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    )
    released = 0
    for assignment in assignments:
        _normalize_lifecycle_datetimes(assignment)
        if (
            assignment.status == "running"
            and assignment.started_at
            == _UNPUBLISHED_ASSIGNMENT_STARTED_AT
        ):
            assignment.status = "pending"
            assignment.started_at = None
            assignment.completed_at = None
            released += 1
    if released:
        db.flush()
    return released


def _persist_scan_rows(
    db: Session,
    *,
    scan: DiscoveryScan,
    target_ids: Iterable[str],
    assignment_pairs: Iterable[tuple[str, str]],
) -> None:
    db.add(scan)
    db.add_all(
        DiscoveryScanTarget(
            tenant_id=scan.tenant_id,
            scan_id=scan.scan_id,
            target_id=target_id,
        )
        for target_id in target_ids
    )
    # These models intentionally expose no ORM relationships. Flush the
    # tenant-safe scan/target parents before their composite-FK assignments;
    # both flushes remain inside the caller-owned transaction.
    db.flush()
    db.add_all(
        DiscoveryScanAssignment(
            assignment_id=str(uuid4()),
            tenant_id=scan.tenant_id,
            scan_id=scan.scan_id,
            target_id=target_id,
            collector_id=collector_id,
            status="pending",
            warning=None,
            error=None,
            started_at=None,
            completed_at=None,
            observations_count=0,
        )
        for target_id, collector_id in assignment_pairs
    )
    db.flush()


def _create_scan(
    db: Session,
    *,
    tenant_id: str,
    requested_by: str | None,
    request_idempotency_key: str,
    payload: DiscoveryScanCreate,
    rescan_of_scan_id: str | None,
    assignment_pairs: Iterable[tuple[str, str]],
) -> ScanMutationResult:
    request_key = _bounded_request_key(request_idempotency_key)
    material = _request_material(
        tenant_id=tenant_id,
        requested_by=requested_by,
        payload=payload,
        rescan_of_scan_id=rescan_of_scan_id,
    )
    digest = _request_digest(material)
    existing = db.scalar(
        select(DiscoveryScan).where(
            DiscoveryScan.tenant_id == tenant_id,
            DiscoveryScan.request_idempotency_key == request_key,
        )
    )
    if existing is not None:
        if existing.request_digest != digest:
            raise ValueError("request idempotency key was reused with different input")
        return ScanMutationResult(scan=existing, created=False)

    if requested_by is not None:
        requester = db.scalar(
            select(User.id)
            .join(UserTenantRole, UserTenantRole.user_id == User.id)
            .where(
                User.id == requested_by,
                UserTenantRole.tenant_id == tenant_id,
            )
        )
        if requester is None:
            raise LookupError("requesting user was not found")

    targets = _tenant_targets(
        db,
        tenant_id=tenant_id,
        target_ids=payload.target_ids,
    )
    collectors = _tenant_collectors(
        db,
        tenant_id=tenant_id,
        collector_ids=payload.collector_ids,
    )
    pairs = _validate_assignments(
        targets=targets,
        collectors=collectors,
        assignment_pairs=assignment_pairs,
    )

    scan_id = str(uuid4())
    normalized_payload = material["payload"]
    scan = DiscoveryScan(
        scan_id=scan_id,
        tenant_id=tenant_id,
        name=payload.name,
        requested_by=requested_by,
        scan_type=payload.scan_type,
        scope_json=normalized_payload["scope"],
        safety_profile=payload.safety_profile,
        request_idempotency_key=request_key,
        request_digest=digest,
        status="queued",
        dry_run=payload.dry_run,
        started_at=None,
        completed_at=None,
        cancelled_at=None,
        observations_count=0,
        assets_created=0,
        assets_updated=0,
        assets_unresolved=0,
        warnings_json=[],
        errors_json=[],
        coverage_summary_json={},
        evidence_bundle_id=None,
        rescan_of_scan_id=rescan_of_scan_id,
    )
    # Establish a clean savepoint boundary before adding this request. The
    # service already owns a flush boundary, but never commits or rolls back
    # the caller's transaction.
    db.flush()
    try:
        with db.begin_nested():
            _persist_scan_rows(
                db,
                scan=scan,
                target_ids=payload.target_ids,
                assignment_pairs=pairs,
            )
    except IntegrityError as conflict:
        if not _is_request_unique_conflict(conflict):
            raise
        winner = db.scalar(
            select(DiscoveryScan)
            .where(
                DiscoveryScan.tenant_id == tenant_id,
                DiscoveryScan.request_idempotency_key == request_key,
            )
            .execution_options(populate_existing=True)
        )
        if winner is None:
            raise
        if winner.request_digest != digest:
            raise ValueError(
                "request idempotency key was reused with different input"
            ) from None
        return ScanMutationResult(scan=winner, created=False)
    return ScanMutationResult(scan=scan, created=True)


def create_scan_with_outcome(
    db: Session,
    *,
    tenant_id: str,
    requested_by: str | None,
    request_idempotency_key: str,
    payload: DiscoveryScanCreate,
) -> ScanMutationResult:
    assignment_pairs = (
        (target_id, collector_id)
        for target_id in payload.target_ids
        for collector_id in payload.collector_ids
    )
    return _create_scan(
        db,
        tenant_id=tenant_id,
        requested_by=requested_by,
        request_idempotency_key=request_idempotency_key,
        payload=payload,
        rescan_of_scan_id=None,
        assignment_pairs=assignment_pairs,
    )


def create_scan_with_assignment_pairs_outcome(
    db: Session,
    *,
    tenant_id: str,
    requested_by: str | None,
    request_idempotency_key: str,
    payload: DiscoveryScanCreate,
    assignment_pairs: Iterable[tuple[str, str]],
) -> ScanMutationResult:
    """Create a scan from explicitly validated target/collector pairs.

    Deep Scan freezes exactly one collector per ready source.  Reusing the
    normal scan lifecycle with an explicit pair set avoids accidental
    cartesian expansion when a customer has selected multiple collectors.
    """

    return _create_scan(
        db,
        tenant_id=tenant_id,
        requested_by=requested_by,
        request_idempotency_key=request_idempotency_key,
        payload=payload,
        rescan_of_scan_id=None,
        assignment_pairs=tuple(assignment_pairs),
    )


def create_scan(
    db: Session,
    *,
    tenant_id: str,
    requested_by: str | None,
    request_idempotency_key: str,
    payload: DiscoveryScanCreate,
) -> DiscoveryScan:
    return create_scan_with_outcome(
        db,
        tenant_id=tenant_id,
        requested_by=requested_by,
        request_idempotency_key=request_idempotency_key,
        payload=payload,
    ).scan


def cancel_scan_with_outcome(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
) -> ScanCancellationResult:
    scan = _locked_scan(db, tenant_id=tenant_id, scan_id=scan_id)
    if scan is None:
        raise LookupError("scan was not found")
    previous_status = scan.status
    if scan.status == "cancelled":
        return ScanCancellationResult(
            scan=scan,
            changed=False,
            previous_status=previous_status,
        )
    if scan.status in _SCAN_FINAL_STATUSES:
        raise ValueError("terminal scan cannot be cancelled")
    _transition_scan(scan, status="cancelled", now=_utcnow())
    db.flush()
    return ScanCancellationResult(
        scan=scan,
        changed=True,
        previous_status=previous_status,
    )


def cancel_scan(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
) -> DiscoveryScan:
    return cancel_scan_with_outcome(
        db,
        tenant_id=tenant_id,
        scan_id=scan_id,
    ).scan


def finalize_assignment(
    db: Session,
    *,
    tenant_id: str,
    assignment_id: str,
    status: str,
    observations_count: int,
    warning: str | None = None,
    error: str | None = None,
) -> DiscoveryScanAssignment:
    normalized_status = str(status)
    if normalized_status not in _ASSIGNMENT_TERMINAL_STATUSES:
        raise ValueError("assignment final status is not allowed")
    if type(observations_count) is not int or observations_count < 0:
        raise ValueError("assignment observation count must be non-negative")
    safe_warning = _safe_detail(warning)
    safe_error = _safe_detail(error)

    assignment = db.scalar(
        select(DiscoveryScanAssignment)
        .where(
            DiscoveryScanAssignment.tenant_id == tenant_id,
            DiscoveryScanAssignment.assignment_id == assignment_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if assignment is None:
        raise LookupError("scan assignment was not found")
    _normalize_lifecycle_datetimes(assignment)
    if assignment.status in _ASSIGNMENT_TERMINAL_STATUSES:
        if (
            assignment.status != normalized_status
            or assignment.observations_count != observations_count
            or assignment.warning != safe_warning
            or assignment.error != safe_error
        ):
            raise ValueError("terminal assignment cannot be changed")
        return assignment
    if assignment.status not in _ASSIGNMENT_ACTIVE_STATUSES:
        raise ValueError("assignment lifecycle transition is not allowed")

    assignment.status = normalized_status
    assignment.observations_count = observations_count
    assignment.warning = safe_warning
    assignment.error = safe_error
    assignment.completed_at = _utcnow()
    db.flush()
    return assignment


def finalize_scan(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
) -> DiscoveryScan:
    scan = _locked_scan(db, tenant_id=tenant_id, scan_id=scan_id)
    if scan is None:
        raise LookupError("scan was not found")
    if scan.status in _SCAN_FINAL_STATUSES:
        return scan

    assignments = tuple(
        db.scalars(
            select(DiscoveryScanAssignment)
            .where(
                DiscoveryScanAssignment.tenant_id == tenant_id,
                DiscoveryScanAssignment.scan_id == scan_id,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    )
    if not assignments:
        raise LookupError("scan assignments were not found")
    for assignment in assignments:
        _normalize_lifecycle_datetimes(assignment)

    scan.observations_count = sum(
        assignment.observations_count for assignment in assignments
    )
    statuses = tuple(assignment.status for assignment in assignments)
    if any(status in _ASSIGNMENT_ACTIVE_STATUSES for status in statuses):
        _transition_scan(scan, status="running", now=_utcnow())
        db.flush()
        return scan

    deep_scan_claim = _deep_scan_completion_is_permitted(scan)
    if deep_scan_claim is not None:
        _transition_scan(
            scan,
            status="complete" if deep_scan_claim else "partially_complete",
            now=_utcnow(),
        )
        db.flush()
        return scan

    successful = sum(status == "complete" for status in statuses)
    if successful == len(assignments):
        _transition_scan(scan, status="complete", now=_utcnow())
    elif successful:
        _transition_scan(scan, status="partially_complete", now=_utcnow())
    elif any(status in _DECISIVE_FAILURE_STATUSES for status in statuses):
        _transition_scan(scan, status="failed", now=_utcnow())
    else:
        # Every assignment is terminal here. With no successful observation
        # path, expected source outcomes still prove zero usable coverage and
        # must not leave the parent scan indefinitely running.
        _transition_scan(scan, status="failed", now=_utcnow())
    db.flush()
    return scan


def rescan_with_outcome(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
    requested_by: str | None,
    request_idempotency_key: str,
) -> ScanMutationResult:
    source = get_scan(db, tenant_id=tenant_id, scan_id=scan_id)
    if source is None:
        raise LookupError("source scan was not found")

    target_ids = tuple(
        db.scalars(
            select(DiscoveryScanTarget.target_id)
            .where(
                DiscoveryScanTarget.tenant_id == tenant_id,
                DiscoveryScanTarget.scan_id == scan_id,
            )
            .order_by(DiscoveryScanTarget.target_id)
        )
    )
    source_assignments = tuple(
        db.scalars(
            select(DiscoveryScanAssignment)
            .where(
                DiscoveryScanAssignment.tenant_id == tenant_id,
                DiscoveryScanAssignment.scan_id == scan_id,
            )
            .order_by(
                DiscoveryScanAssignment.target_id,
                DiscoveryScanAssignment.collector_id,
            )
        )
    )
    collector_ids = tuple(
        sorted({assignment.collector_id for assignment in source_assignments})
    )
    assignment_pairs = tuple(
        (assignment.target_id, assignment.collector_id)
        for assignment in source_assignments
    )
    if not target_ids or not collector_ids or not assignment_pairs:
        raise LookupError("source scan selections were not found")

    payload = DiscoveryScanCreate(
        name=source.name,
        scan_type=source.scan_type,
        scope=source.scope_json,
        target_ids=target_ids,
        collector_ids=collector_ids,
        safety_profile=source.safety_profile,
        dry_run=source.dry_run,
    )
    return _create_scan(
        db,
        tenant_id=tenant_id,
        requested_by=requested_by,
        request_idempotency_key=request_idempotency_key,
        payload=payload,
        rescan_of_scan_id=source.scan_id,
        assignment_pairs=assignment_pairs,
    )


def incremental_rescan_with_outcome(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
    target_ids: tuple[str, ...],
    asset_ids: tuple[str, ...],
    requested_by: str | None,
    request_idempotency_key: str,
) -> ScanMutationResult:
    """Create a bounded H5 rescan for changed assets' existing source targets."""

    if not target_ids or len(target_ids) > 500 or len(set(target_ids)) != len(target_ids):
        raise ValueError("incremental rescan targets must be unique and bounded")
    if not asset_ids or len(asset_ids) > 500 or len(set(asset_ids)) != len(asset_ids):
        raise ValueError("incremental rescan assets must be unique and bounded")
    source = get_scan(db, tenant_id=tenant_id, scan_id=scan_id)
    if source is None:
        raise LookupError("source scan was not found")
    source_targets = set(
        db.scalars(
            select(DiscoveryScanTarget.target_id).where(
                DiscoveryScanTarget.tenant_id == tenant_id,
                DiscoveryScanTarget.scan_id == scan_id,
            )
        )
    )
    if not set(target_ids).issubset(source_targets):
        raise ValueError("incremental rescan target is outside the source scan")
    assignments = tuple(
        db.scalars(
            select(DiscoveryScanAssignment)
            .where(
                DiscoveryScanAssignment.tenant_id == tenant_id,
                DiscoveryScanAssignment.scan_id == scan_id,
                DiscoveryScanAssignment.target_id.in_(target_ids),
            )
            .order_by(
                DiscoveryScanAssignment.target_id,
                DiscoveryScanAssignment.collector_id,
            )
        )
    )
    assignment_pairs = tuple(
        (row.target_id, row.collector_id) for row in assignments
    )
    if not assignment_pairs:
        raise LookupError("incremental rescan assignments were not found")
    collector_ids = tuple(sorted({row.collector_id for row in assignments}))
    source_scan_hash = hashlib.sha256(source.scan_id.encode("utf-8")).hexdigest()
    changed_assets_digest = hashlib.sha256(
        json.dumps(
            sorted(asset_ids),
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    payload = DiscoveryScanCreate(
        name=f"{source.name} incremental enrichment",
        scan_type="incremental",
        scope={
            "source_scan_hash": source_scan_hash,
            "changed_assets_digest": changed_assets_digest,
            "changed_asset_count": len(asset_ids),
            "incremental_reason": "canonical_asset_digest_changed",
        },
        target_ids=tuple(sorted(target_ids)),
        collector_ids=collector_ids,
        safety_profile=source.safety_profile,
        dry_run=source.dry_run,
    )
    return _create_scan(
        db,
        tenant_id=tenant_id,
        requested_by=requested_by,
        request_idempotency_key=request_idempotency_key,
        payload=payload,
        rescan_of_scan_id=source.scan_id,
        assignment_pairs=assignment_pairs,
    )


def rescan(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
    requested_by: str | None,
    request_idempotency_key: str,
) -> DiscoveryScan:
    return rescan_with_outcome(
        db,
        tenant_id=tenant_id,
        scan_id=scan_id,
        requested_by=requested_by,
        request_idempotency_key=request_idempotency_key,
    ).scan


__all__ = [
    "ALLOWED_SCAN_TRANSITIONS",
    "ScanCancellationResult",
    "ScanMutationResult",
    "cancel_scan",
    "cancel_scan_with_outcome",
    "claim_assignment_batch",
    "create_scan",
    "create_scan_with_assignment_pairs_outcome",
    "create_scan_with_outcome",
    "finalize_assignment",
    "finalize_scan",
    "get_collector",
    "get_scan",
    "get_target",
    "incremental_rescan_with_outcome",
    "release_unpublished_assignment_claims",
    "record_deep_scan_source_coverage",
    "rescan",
    "rescan_with_outcome",
    "start_assignment",
]
