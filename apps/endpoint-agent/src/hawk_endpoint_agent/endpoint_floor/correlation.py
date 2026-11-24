from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .contracts import EndpointProcessIdentity


class RelationshipConfidence(str, Enum):
    CONFIRMED = "confirmed"
    STRONG_CORRELATION = "strong_correlation"
    POSSIBLE = "possible"
    UNKNOWN = "unknown"

    # Source compatibility for pre-Phase-3 callers and stored labels.
    CORRELATED = STRONG_CORRELATION

    @classmethod
    def _missing_(cls, value: object) -> "RelationshipConfidence | None":
        if str(value or "").strip().lower() == "correlated":
            return cls.STRONG_CORRELATION
        return None


@dataclass(frozen=True, slots=True)
class FileActivity:
    evidence_ref: str
    process: EndpointProcessIdentity
    resource_reference: str
    observed_at_ns: int


@dataclass(frozen=True, slots=True)
class NetworkActivity:
    evidence_ref: str
    process: EndpointProcessIdentity
    destination_reference: str
    observed_at_ns: int
    semantic_transfer_id: str | None = None
    semantic_resource_reference: str | None = None


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    confidence: RelationshipConfidence
    reason: str
    evidence_refs: tuple[str, ...]


def correlate_file_and_network(
    file_activity: FileActivity,
    network_activity: NetworkActivity,
    *,
    window_ns: int,
) -> CorrelationResult:
    evidence = (file_activity.evidence_ref, network_activity.evidence_ref)
    if (
        network_activity.semantic_transfer_id
        and network_activity.semantic_resource_reference == file_activity.resource_reference
        and network_activity.process.canonical_identity == file_activity.process.canonical_identity
    ):
        return CorrelationResult(
            RelationshipConfidence.CONFIRMED,
            "semantic_transfer_resource_binding",
            evidence,
        )
    if network_activity.process.canonical_identity != file_activity.process.canonical_identity:
        return CorrelationResult(RelationshipConfidence.UNKNOWN, "process_identity_mismatch", evidence)
    delta = network_activity.observed_at_ns - file_activity.observed_at_ns
    if 0 <= delta <= max(0, window_ns):
        return CorrelationResult(
            RelationshipConfidence.STRONG_CORRELATION,
            "same_process_session_within_window",
            evidence,
        )
    if delta >= 0:
        return CorrelationResult(RelationshipConfidence.POSSIBLE, "same_process_outside_window", evidence)
    return CorrelationResult(RelationshipConfidence.UNKNOWN, "network_precedes_file_activity", evidence)
