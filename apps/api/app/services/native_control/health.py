from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import math

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.native_control import NativeControlHealthObservation


DEFAULT_HEALTH_WINDOW = timedelta(minutes=5)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class NativeControlHealthSnapshot:
    callback_authenticated: bool
    evidence_flowing: bool
    observed_latency_ms: int | None
    sample_count: int
    last_observed_at: datetime | None
    reason_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...]


def record_health_observation(
    db: Session,
    *,
    tenant_id: str,
    integration_id: str,
    credential_id: str,
    credential_epoch: int,
    provider_event_id: str,
    provider_event_type: str,
    callback_authenticated: bool,
    evidence_flowing: bool,
    latency_ms: int | None,
    source: str,
    evidence_ref: str | None,
    observed_at: datetime,
    ttl: timedelta = DEFAULT_HEALTH_WINDOW,
) -> NativeControlHealthObservation:
    if not provider_event_id or len(provider_event_id) > 512:
        raise ValueError("provider_event_id_invalid")
    if latency_ms is not None and (type(latency_ms) is not int or latency_ms < 0 or latency_ms > 300_000):
        raise ValueError("latency_ms_invalid")
    if source not in {"signed_native_callback", "endpoint_runtime_probe", "health_reconciler"}:
        raise ValueError("health_source_invalid")
    observed = _utc(observed_at)
    expiry = observed + ttl
    row = NativeControlHealthObservation(
        tenant_id=tenant_id,
        integration_instance_id=integration_id,
        credential_id=credential_id,
        credential_epoch=int(credential_epoch),
        provider_event_id_hash=hashlib.sha256(provider_event_id.encode("utf-8")).hexdigest(),
        provider_event_type=str(provider_event_type)[:64],
        callback_authenticated=callback_authenticated is True,
        evidence_flowing=evidence_flowing is True and bool(evidence_ref),
        latency_ms=latency_ms,
        source=source,
        evidence_ref=(str(evidence_ref)[:255] if evidence_ref else None),
        observed_at=observed,
        expires_at=expiry,
    )
    db.add(row)
    db.flush()
    return row


def _percentile_95(values: list[int]) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return ordered[index]


def health_snapshot(
    db: Session,
    *,
    tenant_id: str,
    integration_id: str,
    credential_id: str,
    credential_epoch: int,
    now: datetime,
    window: timedelta = DEFAULT_HEALTH_WINDOW,
) -> NativeControlHealthSnapshot:
    current = _utc(now)
    lower_bound = current - window
    rows = list(
        db.scalars(
            select(NativeControlHealthObservation)
            .where(
                NativeControlHealthObservation.tenant_id == tenant_id,
                NativeControlHealthObservation.integration_instance_id == integration_id,
                NativeControlHealthObservation.credential_id == credential_id,
                NativeControlHealthObservation.credential_epoch == int(credential_epoch),
                NativeControlHealthObservation.observed_at >= lower_bound,
                NativeControlHealthObservation.observed_at <= current,
                NativeControlHealthObservation.expires_at >= current,
            )
            .order_by(NativeControlHealthObservation.observed_at.desc())
            .limit(500)
        ).all()
    )
    callback_authenticated = any(row.callback_authenticated is True for row in rows)
    evidence_flowing = any(row.evidence_flowing is True and bool(row.evidence_ref) for row in rows)
    measured = [int(row.latency_ms) for row in rows if row.latency_ms is not None]
    reason_codes: list[str] = []
    if not callback_authenticated:
        reason_codes.append("callback_not_observed")
    if not evidence_flowing:
        reason_codes.append("evidence_not_flowing")
    if not measured:
        reason_codes.append("latency_not_measured")
    return NativeControlHealthSnapshot(
        callback_authenticated=callback_authenticated,
        evidence_flowing=evidence_flowing,
        observed_latency_ms=_percentile_95(measured),
        sample_count=len(measured),
        last_observed_at=max((_utc(row.observed_at) for row in rows), default=None),
        reason_codes=tuple(reason_codes),
        evidence_refs=tuple(sorted({str(row.evidence_ref) for row in rows if row.evidence_ref})),
    )
