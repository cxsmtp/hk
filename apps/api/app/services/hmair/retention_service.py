"""H6 retention for mutable scan summaries; canonical evidence stays immutable."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
import hashlib
import json

from pydantic import BaseModel, ConfigDict
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db.models.discovery_canonical import DiscoveryScan
from app.services.audit_service import write_audit_log


_TERMINAL = ("complete", "partially_complete", "failed", "cancelled")
_PRESERVED_COVERAGE_KEYS = (
    "confidence",
    "freshness",
    "unsupported",
    "unknown",
    "explicit_exclusions",
    "denominator_complete",
    "enterprise_denominator_complete",
)


class ScanSummaryCompactionPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    cutoff_at: datetime
    retention_days: int
    batch_size: int
    scan_ids: tuple[str, ...]
    plan_digest: str


class ScanSummaryCompactionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    cutoff_at: datetime
    compacted_scan_ids: tuple[str, ...]
    skipped_count: int
    plan_digest: str


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("retention time must be timezone-aware")
    return value.astimezone(timezone.utc)


def _validate(retention_days: int, batch_size: int) -> None:
    if type(retention_days) is not int or not 30 <= retention_days <= 3_650:
        raise ValueError("retention days must be between 30 and 3650")
    if type(batch_size) is not int or not 1 <= batch_size <= 1_000:
        raise ValueError("retention batch size must be between 1 and 1000")


def _digest(material: object) -> str:
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), default=str).encode(
            "utf-8"
        )
    ).hexdigest()


def _already_compacted(row: DiscoveryScan) -> bool:
    value = row.coverage_summary_json
    return isinstance(value, Mapping) and isinstance(
        value.get("retention_compaction"), Mapping
    )


def plan_terminal_scan_summary_compaction(
    db: Session,
    *,
    tenant_id: str,
    now: datetime,
    retention_days: int,
    batch_size: int,
) -> ScanSummaryCompactionPlan:
    _validate(retention_days, batch_size)
    cutoff = _utc(now) - timedelta(days=retention_days)
    rows = list(
        db.scalars(
            select(DiscoveryScan)
            .where(
                DiscoveryScan.tenant_id == tenant_id,
                DiscoveryScan.status.in_(_TERMINAL),
                or_(
                    DiscoveryScan.completed_at < cutoff,
                    DiscoveryScan.cancelled_at < cutoff,
                    DiscoveryScan.created_at < cutoff,
                ),
            )
            .order_by(DiscoveryScan.created_at, DiscoveryScan.scan_id)
            .limit(batch_size)
        )
    )
    scan_ids = tuple(row.scan_id for row in rows if not _already_compacted(row))
    material = {
        "version": "hmair-scan-summary-retention/v1",
        "tenant_id": tenant_id,
        "cutoff_at": cutoff.isoformat(),
        "retention_days": retention_days,
        "batch_size": batch_size,
        "scan_ids": scan_ids,
    }
    return ScanSummaryCompactionPlan(
        cutoff_at=cutoff,
        retention_days=retention_days,
        batch_size=batch_size,
        scan_ids=scan_ids,
        plan_digest=_digest(material),
    )


def _bounded_strings(value: object) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return sorted(
        {
            item.strip()[:160]
            for item in value
            if isinstance(item, str) and item.strip()
        }
    )[:128]


def _compact_scan(row: DiscoveryScan, *, now: datetime) -> None:
    coverage = (
        dict(row.coverage_summary_json)
        if isinstance(row.coverage_summary_json, Mapping)
        else {}
    )
    warning_count = len(row.warnings_json) if isinstance(row.warnings_json, list) else 0
    error_count = len(row.errors_json) if isinstance(row.errors_json, list) else 0
    original_material = {
        "coverage": coverage,
        "warnings": row.warnings_json,
        "errors": row.errors_json,
    }
    preserved: dict[str, object] = {}
    for key in _PRESERVED_COVERAGE_KEYS:
        if key not in coverage:
            continue
        value = coverage[key]
        preserved[key] = _bounded_strings(value) if isinstance(value, list) else value
    raw_deep_scan = coverage.get("deep_scan")
    if isinstance(raw_deep_scan, Mapping):
        preserved["deep_scan"] = {
            "exhaustive_claim_permitted": raw_deep_scan.get(
                "exhaustive_claim_permitted"
            )
            is True,
            "sources_compacted": len(raw_deep_scan.get("sources", ()))
            if isinstance(raw_deep_scan.get("sources"), Sequence)
            else 0,
        }
    preserved["retention_compaction"] = {
        "version": "v1",
        "compacted_at": _utc(now).isoformat(),
        "original_digest": _digest(original_material),
        "warning_count": warning_count,
        "error_count": error_count,
        "immutable_evidence_preserved": True,
    }
    row.coverage_summary_json = preserved
    row.warnings_json = (
        [f"{warning_count} warning entries compacted by retention policy."]
        if warning_count
        else []
    )
    row.errors_json = (
        [f"{error_count} error entries compacted by retention policy."]
        if error_count
        else []
    )


def compact_terminal_scan_summaries(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    now: datetime,
    retention_days: int,
    batch_size: int,
    plan_digest: str,
) -> ScanSummaryCompactionResult:
    plan = plan_terminal_scan_summary_compaction(
        db,
        tenant_id=tenant_id,
        now=now,
        retention_days=retention_days,
        batch_size=batch_size,
    )
    if plan.plan_digest != plan_digest:
        raise ValueError("retention plan no longer matches current state")
    rows = list(
        db.scalars(
            select(DiscoveryScan).where(
                DiscoveryScan.tenant_id == tenant_id,
                DiscoveryScan.scan_id.in_(plan.scan_ids),
            )
        )
    )
    by_id = {row.scan_id: row for row in rows}
    compacted: list[str] = []
    for scan_id in plan.scan_ids:
        row = by_id.get(scan_id)
        if row is None or _already_compacted(row):
            continue
        _compact_scan(row, now=now)
        compacted.append(scan_id)
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="user" if actor_user_id else "system",
        action="hmair.scan_summaries_compacted",
        resource_type="discovery_scan_retention",
        resource_id=plan.plan_digest[:32],
        payload={
            "plan_digest": plan.plan_digest,
            "retention_days": retention_days,
            "compacted_count": len(compacted),
            "immutable_evidence_preserved": True,
        },
    )
    return ScanSummaryCompactionResult(
        cutoff_at=plan.cutoff_at,
        compacted_scan_ids=tuple(compacted),
        skipped_count=len(plan.scan_ids) - len(compacted),
        plan_digest=plan.plan_digest,
    )


__all__ = [
    "ScanSummaryCompactionPlan",
    "ScanSummaryCompactionResult",
    "compact_terminal_scan_summaries",
    "plan_terminal_scan_summary_compaction",
]
