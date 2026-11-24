from __future__ import annotations

from app.services.hmair.contracts import StrictContract


RESOLUTION_EXPLANATION_VERSION = "3.0.0"


class ResolutionExplanation(StrictContract):
    confidence: float | None
    confidence_band: str
    evidence_quality: float | None
    evidence_quality_band: str
    evidence_categories: tuple[str, ...]
    source_surfaces: tuple[str, ...]
    distinct_collector_count: int
    source_independence: str
    conflicts: tuple[str, ...]
    methodology_id: str
    methodology_version: str
    methodology_summary: str
    limitations: tuple[str, ...]
    is_empirical_probability: bool


def confidence_band(value: float | None) -> str:
    if value is None:
        return "unknown"
    if value >= 0.85:
        return "high"
    if value >= 0.60:
        return "moderate"
    return "low"


def public_evidence_state(
    *, freshness: str, verification_state: str, contradiction_state: str
) -> str:
    if contradiction_state in {"confirmed", "possible", "unknown", "unresolved"}:
        return "conflicted"
    if freshness == "stale":
        return "stale"
    if freshness == "expired":
        return "expired"
    if freshness != "fresh":
        return "unknown"
    if verification_state == "verified":
        return "verified_current"
    if verification_state == "partially_verified":
        return "partial"
    if verification_state == "inferred":
        return "inferred"
    return "unknown"


def explain_resolution(
    *,
    confidence: float | None,
    evidence_quality: float | None,
    evidence_categories: tuple[str, ...],
    source_surfaces: tuple[str, ...],
    collector_ids: tuple[str, ...],
    independent_source_groups: tuple[str, ...],
    conflicts: tuple[str, ...],
    limitations: tuple[str, ...],
    methodology_id: str,
    methodology_version: str,
) -> ResolutionExplanation:
    del methodology_version
    categories = tuple(sorted(set(evidence_categories)))
    surfaces = tuple(sorted(set(source_surfaces)))
    collectors = tuple(sorted({item for item in collector_ids if item}))
    independent_groups = tuple(
        sorted({item for item in independent_source_groups if item})
    )
    conflict_items = tuple(sorted(set(conflicts)))
    public_limitations = set(limitations)
    if len(independent_groups) >= 2:
        independence = "established_by_declared_groups"
    else:
        independence = "not_established"
        public_limitations.add("source_independence_not_established")
    if len(surfaces) < 2:
        public_limitations.add("single_surface_only")
    if conflict_items:
        public_limitations.add("conflicting_evidence_requires_review")
    if confidence is None:
        public_limitations.add("confidence_unknown")
    return ResolutionExplanation(
        confidence=confidence,
        confidence_band=confidence_band(confidence),
        evidence_quality=evidence_quality,
        evidence_quality_band=confidence_band(evidence_quality),
        evidence_categories=categories,
        source_surfaces=surfaces,
        distinct_collector_count=len(collectors),
        source_independence=independence,
        conflicts=conflict_items,
        methodology_id=methodology_id,
        methodology_version=RESOLUTION_EXPLANATION_VERSION,
        methodology_summary=(
            "Versioned evidence ranking considers current validation, source "
            "breadth, required anchors, and unresolved conflicts. Confidence "
            "is a ranking band, not an empirical probability."
        ),
        limitations=tuple(sorted(public_limitations)),
        is_empirical_probability=False,
    )


__all__ = [
    "RESOLUTION_EXPLANATION_VERSION",
    "ResolutionExplanation",
    "confidence_band",
    "explain_resolution",
    "public_evidence_state",
]
