from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_asset import DiscoveryAICapability
from app.db.models.discovery_canonical import DiscoveryObservation
from app.services.hmair.capability_inference_service import infer_capability
from app.services.hmair.contracts import (
    AICapabilityState,
    AICapabilityType,
    StrictContract,
    canonical_json_bytes,
)
from app.services.hmair.evidence_claim_service import EvidenceClaimScopeError
from app.services.hmair.normalization_service import (
    NormalizedDiscoveryObservation,
    normalize_observation,
)


CAPABILITY_EXTRACTOR_VERSION = "hmair-capability-3.0.0"
SUPPORTED_CAPABILITY_EXTRACTORS = tuple(item.value for item in AICapabilityType)
_SUPPORTED = frozenset(SUPPORTED_CAPABILITY_EXTRACTORS)


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class CapabilityExtraction(StrictContract):
    name: AICapabilityType
    state: AICapabilityState
    confidence: float
    verification_state: str
    freshness: str
    observed_usage: bool
    declared_only: bool
    inferred_only: bool
    extractor_version: str


class CapabilityExtractionResult(StrictContract):
    assertions: tuple[CapabilityExtraction, ...]
    ignored_hints: tuple[str, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class PersistedCapabilityExtraction:
    assertions: tuple[DiscoveryAICapability, ...]
    ignored_hints: tuple[str, ...]
    limitations: tuple[str, ...]


def _explicit_denial(observation: NormalizedDiscoveryObservation) -> bool:
    if not (
        observation.evidence_mode == "direct"
        and observation.verification_state == "verified"
        and observation.freshness == "fresh"
    ):
        return False
    for source in (observation.attributes, observation.normalized_signal):
        for key in ("capability_state", "capability_decision", "policy_decision"):
            value = source.get(key)
            if isinstance(value, str) and value.strip().casefold() in {
                "blocked",
                "denied",
            }:
                return True
    return False


def _state(observation: NormalizedDiscoveryObservation) -> AICapabilityState:
    if _explicit_denial(observation):
        return AICapabilityState.DENIED
    if observation.evidence_mode == "inferred" or observation.observed_state == "inferred":
        return AICapabilityState.INFERRED
    if observation.observed_state in {"observed", "actively_used"}:
        return AICapabilityState.OBSERVED
    if observation.observed_state in {"configured", "enabled", "reachable"}:
        return AICapabilityState.CONFIGURED
    if observation.observed_state == "installed":
        return AICapabilityState.DECLARED
    return AICapabilityState.UNKNOWN


def _verification(value: str) -> str:
    if value in {"verified", "partially_verified", "inferred"}:
        return value
    return "unknown"


def extract_capabilities(
    observation: NormalizedDiscoveryObservation,
) -> CapabilityExtractionResult:
    hints = tuple(sorted(set(observation.capability_hints)))
    supported = tuple(item for item in SUPPORTED_CAPABILITY_EXTRACTORS if item in hints)
    ignored = tuple(item for item in hints if item not in _SUPPORTED)
    state = _state(observation)
    assertions = tuple(
        CapabilityExtraction(
            name=name,
            state=state,
            confidence=float(observation.confidence),
            verification_state=_verification(observation.verification_state),
            freshness=(
                observation.freshness
                if observation.freshness in {"fresh", "stale", "expired", "unknown"}
                else "unknown"
            ),
            observed_usage=state is AICapabilityState.OBSERVED,
            declared_only=state is AICapabilityState.DECLARED,
            inferred_only=state is AICapabilityState.INFERRED,
            extractor_version=CAPABILITY_EXTRACTOR_VERSION,
        )
        for name in supported
    )
    limitations = []
    if ignored:
        limitations.append("unsupported_capability_hints_ignored")
    if not assertions:
        limitations.append("no_supported_capability_evidence")
    if state is AICapabilityState.UNKNOWN and assertions:
        limitations.append("capability_truth_state_unknown")
    return CapabilityExtractionResult(
        assertions=assertions,
        ignored_hints=ignored,
        limitations=tuple(limitations),
    )


def extract_and_persist_capabilities(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    source_observation_id: str,
    evidence_claim_id: str,
) -> PersistedCapabilityExtraction:
    observation = db.scalar(
        select(DiscoveryObservation).where(
            DiscoveryObservation.tenant_id == tenant_id,
            DiscoveryObservation.observation_id == source_observation_id,
        )
    )
    if observation is None:
        raise EvidenceClaimScopeError("capability observation is unavailable")
    extracted = extract_capabilities(normalize_observation(observation))
    rows: list[DiscoveryAICapability] = []
    for assertion in extracted.assertions:
        key = hashlib.sha256(
            b"hawk:hmair:capability-extractor:v3\x00"
            + canonical_json_bytes(
                {
                    "tenant_id": tenant_id,
                    "asset_id": asset_id,
                    "observation_id": source_observation_id,
                    "evidence_claim_id": evidence_claim_id,
                    "capability": assertion.name.value,
                    "state": assertion.state.value,
                    "extractor_version": assertion.extractor_version,
                }
            )
        ).hexdigest()
        rows.append(
            infer_capability(
                db,
                tenant_id=tenant_id,
                asset_id=asset_id,
                source_observation_id=source_observation_id,
                evidence_claim_id=evidence_claim_id,
                name=assertion.name.value,
                state=assertion.state.value,
                confidence=assertion.confidence,
                verification_state=assertion.verification_state,
                freshness=assertion.freshness,
                observed_usage=assertion.observed_usage,
                declared_only=assertion.declared_only,
                inferred_only=assertion.inferred_only,
                first_observed_at=_aware(observation.observed_at),
                last_observed_at=_aware(observation.observed_at),
                extractor_version=assertion.extractor_version,
                idempotency_key=key,
            )
        )
    return PersistedCapabilityExtraction(
        assertions=tuple(rows),
        ignored_hints=extracted.ignored_hints,
        limitations=extracted.limitations,
    )


__all__ = [
    "CAPABILITY_EXTRACTOR_VERSION",
    "CapabilityExtraction",
    "CapabilityExtractionResult",
    "PersistedCapabilityExtraction",
    "SUPPORTED_CAPABILITY_EXTRACTORS",
    "extract_and_persist_capabilities",
    "extract_capabilities",
]
