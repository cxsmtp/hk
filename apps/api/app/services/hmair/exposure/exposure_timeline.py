from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib

from app.services.hmair.contracts import canonical_json_bytes
from app.services.hmair.exposure.contracts import ExposureTimelineEntry
from app.services.hmair.exposure.drift import ExposureDrift


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timeline timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def build_timeline_entry(
    *,
    drift: ExposureDrift,
    rule_version: str,
) -> ExposureTimelineEntry:
    if not rule_version or len(rule_version) > 32:
        raise ValueError("rule_version must be bounded")
    source_event_refs = tuple(sorted(set(drift.source_event_refs)))
    event_id = hashlib.sha256(
        b"hawk:ai-exposure-event:v1"
        + canonical_json_bytes(
            {
                "source_event_ids": source_event_refs,
                "category_id": drift.category_id,
                "before_extent": (
                    drift.before_extent.value if drift.before_extent is not None else None
                ),
                "after_extent": (
                    drift.after_extent.value if drift.after_extent is not None else None
                ),
                "changed_factors": tuple(sorted(set(drift.changed_factors))),
                "rule_version": rule_version,
            }
        )
    ).hexdigest()
    return ExposureTimelineEntry(
        event_id=event_id,
        event_type=drift.event_type,
        category_id=drift.category_id,
        occurred_at=drift.occurred_at,
        before_extent=drift.before_extent,
        after_extent=drift.after_extent,
        changed_factors=drift.changed_factors,
        source_event_refs=source_event_refs,
        evidence_refs=drift.evidence_refs,
        confidence=drift.confidence,
        limitations=drift.limitations,
    )


def build_exposure_timeline(
    *,
    changes: tuple[ExposureDrift, ...],
    rule_version: str,
    as_of: datetime,
    lookback_days: int = 30,
    limit: int = 200,
) -> tuple[ExposureTimelineEntry, ...]:
    """Build a bounded reverse-chronological projection without persistence."""

    current = _aware_utc(as_of)
    if not 1 <= lookback_days <= 3650:
        raise ValueError("lookback_days must be between 1 and 3650")
    if not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    earliest = current - timedelta(days=lookback_days)
    eligible = tuple(
        item
        for item in changes
        if earliest <= _aware_utc(item.occurred_at) <= current
    )
    entries = tuple(
        build_timeline_entry(drift=item, rule_version=rule_version)
        for item in eligible
    )
    return tuple(
        sorted(
            entries,
            key=lambda item: (_aware_utc(item.occurred_at), item.event_id),
            reverse=True,
        )[:limit]
    )


__all__ = ["build_exposure_timeline", "build_timeline_entry"]
