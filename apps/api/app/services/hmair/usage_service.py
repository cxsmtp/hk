from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_asset import DiscoveryAIAsset
from app.db.models.discovery_intelligence import DiscoveryAssetUsageFact
from app.db.models.evidence import EvidenceNode
from app.services.hmair.contracts import SourceSurface, canonical_json_bytes


USAGE_STATES = frozenset(
    {"never_observed", "historical", "occasional", "active", "high_usage", "unknown"}
)
ACTOR_TYPES = frozenset(
    {"human", "agent", "service", "workload", "automation", "unknown"}
)
VERIFICATION_STATES = frozenset(
    {"verified", "partially_verified", "inferred", "contradicted", "stale", "unknown"}
)
FRESHNESS_STATES = frozenset({"fresh", "stale", "expired", "unknown"})


@dataclass(frozen=True, slots=True)
class UsageMethodology:
    active_window_days: int = 30
    historical_after_days: int = 90
    occasional_max_events: int = 5
    high_usage_min_events: int = 100
    methodology_id: str = "phase2-usage-default-v1"

    def __post_init__(self) -> None:
        if not 1 <= self.active_window_days <= 3650:
            raise ValueError("active usage window is invalid")
        if not self.active_window_days <= self.historical_after_days <= 3650:
            raise ValueError("historical usage window is invalid")
        if not 1 <= self.occasional_max_events < self.high_usage_min_events:
            raise ValueError("usage event thresholds are invalid")
        if not self.methodology_id or len(self.methodology_id) > 128:
            raise ValueError("usage methodology id is invalid")

    def as_dict(self) -> dict[str, int | str]:
        return {
            "methodology_id": self.methodology_id,
            "active_window_days": self.active_window_days,
            "historical_after_days": self.historical_after_days,
            "occasional_max_events": self.occasional_max_events,
            "high_usage_min_events": self.high_usage_min_events,
        }


@dataclass(frozen=True, slots=True)
class UsageClassification:
    state: str
    methodology: dict[str, int | str]
    explanation: str


def _utc(value: datetime | None, *, field_name: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def classify_usage(
    *,
    event_count: int,
    first_observed_at: datetime | None,
    last_observed_at: datetime | None,
    telemetry_complete: bool,
    now: datetime,
    methodology: UsageMethodology,
) -> UsageClassification:
    if type(event_count) is not int or event_count < 0:
        raise ValueError("usage event count is invalid")
    if type(telemetry_complete) is not bool:
        raise ValueError("usage telemetry completeness must be explicit")
    now_utc = _utc(now, field_name="now")
    first = _utc(first_observed_at, field_name="first_observed_at")
    last = _utc(last_observed_at, field_name="last_observed_at")
    if (first is None) != (last is None):
        raise ValueError("usage timestamps must be supplied together")
    if first is not None and last is not None and first > last:
        raise ValueError("usage timestamps are out of order")
    if event_count == 0:
        if first is not None:
            raise ValueError("zero usage cannot carry activity timestamps")
        state = "never_observed" if telemetry_complete else "unknown"
        explanation = (
            "Complete telemetry contains no use event"
            if telemetry_complete
            else "Telemetry is incomplete; absence cannot prove no use"
        )
        return UsageClassification(state, methodology.as_dict(), explanation)
    if first is None or last is None:
        raise ValueError("observed usage requires timestamps")
    if last > now_utc + timedelta(minutes=5):
        raise ValueError("usage timestamp is in the future")

    age = now_utc - last
    if age > timedelta(days=methodology.historical_after_days):
        state = "historical"
        explanation = "Last observed use is outside the documented historical window"
    elif age <= timedelta(days=methodology.active_window_days):
        if event_count >= methodology.high_usage_min_events:
            state = "high_usage"
            explanation = "Recent evidence meets the documented high-usage threshold"
        elif event_count <= methodology.occasional_max_events:
            state = "occasional"
            explanation = "Recent evidence remains below the documented occasional threshold"
        else:
            state = "active"
            explanation = "Recent use is observed within the documented active window"
    else:
        state = "occasional"
        explanation = "Use is observed but not within the active or historical boundary"
    return UsageClassification(state, methodology.as_dict(), explanation)


def _valid_hash(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def persist_usage_fact(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    actor_type: str,
    actor_reference_hash: str | None,
    usage_state: str,
    event_count: int,
    first_observed_at: datetime | None,
    last_observed_at: datetime | None,
    source_surface: str,
    evidence_node_id: str,
    confidence: float,
    verification_state: str,
    freshness: str,
    telemetry_complete: bool,
    methodology_id: str,
    limitations: tuple[str, ...],
    idempotency_key: str,
) -> DiscoveryAssetUsageFact:
    if actor_type not in ACTOR_TYPES or usage_state not in USAGE_STATES:
        raise ValueError("usage actor or state is invalid")
    if actor_type == "unknown":
        if actor_reference_hash is not None:
            raise ValueError("unknown usage actor cannot carry an identity")
    elif actor_reference_hash is None or not _valid_hash(actor_reference_hash):
        raise ValueError("known usage actor requires a pseudonymous identity")
    try:
        SourceSurface(source_surface)
    except ValueError:
        raise ValueError("usage source surface is invalid") from None
    if type(event_count) is not int or event_count < 0:
        raise ValueError("usage event count is invalid")
    if usage_state in {"active", "high_usage", "historical", "occasional"} and event_count == 0:
        raise ValueError("observed usage state requires events")
    if usage_state in {"never_observed", "unknown"} and event_count != 0:
        raise ValueError("non-observed usage state cannot carry events")
    if type(confidence) is not float or not 0.0 <= confidence <= 1.0:
        raise ValueError("usage confidence is invalid")
    if verification_state not in VERIFICATION_STATES or freshness not in FRESHNESS_STATES:
        raise ValueError("usage truth state is invalid")
    if type(telemetry_complete) is not bool:
        raise ValueError("usage telemetry completeness must be explicit")
    first = _utc(first_observed_at, field_name="first_observed_at")
    last = _utc(last_observed_at, field_name="last_observed_at")
    if (first is None) != (last is None) or (
        first is not None and last is not None and first > last
    ):
        raise ValueError("usage timestamps are invalid")
    if event_count > 0 and first is None:
        raise ValueError("usage evidence requires timestamps")
    if not methodology_id or len(methodology_id) > 128:
        raise ValueError("usage methodology is invalid")
    if not idempotency_key or len(idempotency_key) > 128:
        raise ValueError("usage idempotency key is invalid")
    if len(limitations) > 32 or any(not item or len(item) > 255 for item in limitations):
        raise ValueError("usage limitations are invalid")

    asset = db.scalar(
        select(DiscoveryAIAsset).where(
            DiscoveryAIAsset.tenant_id == tenant_id,
            DiscoveryAIAsset.asset_id == asset_id,
        )
    )
    evidence = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.id == evidence_node_id,
        )
    )
    if asset is None or evidence is None:
        raise ValueError("usage authority is unavailable")

    material: dict[str, Any] = {
        "tenant_id": tenant_id,
        "asset_id": asset_id,
        "actor_type": actor_type,
        "actor_reference_hash": actor_reference_hash,
        "usage_state": usage_state,
        "event_count": event_count,
        "first_observed_at": first.isoformat() if first else None,
        "last_observed_at": last.isoformat() if last else None,
        "source_surface": source_surface,
        "evidence_node_id": evidence_node_id,
        "confidence": confidence,
        "verification_state": verification_state,
        "freshness": freshness,
        "telemetry_complete": telemetry_complete,
        "methodology_id": methodology_id,
        "limitations": limitations,
    }
    digest = hashlib.sha256(
        b"hawk:discovery:usage:v1" + canonical_json_bytes(material)
    ).hexdigest()
    existing = db.scalar(
        select(DiscoveryAssetUsageFact).where(
            DiscoveryAssetUsageFact.tenant_id == tenant_id,
            DiscoveryAssetUsageFact.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        if existing.input_digest != digest:
            raise ValueError("usage idempotency conflict")
        return existing

    row = DiscoveryAssetUsageFact(
        usage_fact_id=str(uuid4()),
        tenant_id=tenant_id,
        asset_id=asset_id,
        actor_type=actor_type,
        actor_reference_hash=actor_reference_hash,
        usage_state=usage_state,
        event_count=event_count,
        first_observed_at=first,
        last_observed_at=last,
        source_surface=source_surface,
        evidence_node_id=evidence_node_id,
        confidence=confidence,
        verification_state=verification_state,
        freshness=freshness,
        telemetry_complete=telemetry_complete,
        methodology_id=methodology_id,
        limitations_json=list(limitations),
        idempotency_key=idempotency_key,
        input_digest=digest,
    )
    db.add(row)
    db.flush()
    return row


__all__ = [
    "ACTOR_TYPES",
    "USAGE_STATES",
    "UsageClassification",
    "UsageMethodology",
    "classify_usage",
    "persist_usage_fact",
]
