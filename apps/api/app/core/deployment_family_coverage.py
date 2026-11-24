"""Pure conservative deployment-family Control Coverage calculation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Iterable, Mapping


METHODOLOGY_VERSION = "deployment-family-coverage/1.0"
FAMILY_ORDER = ("browser", "endpoint", "runtime", "saas_api", "unknown")
DIMENSION_ORDER = (
    "discovery",
    "identity",
    "authorization",
    "evidence",
    "containment",
    "bypass_detection",
)
FAMILY_LABELS = {
    "browser": "Browser",
    "endpoint": "Endpoint",
    "runtime": "Runtime",
    "saas_api": "SaaS & APIs",
    "unknown": "Unknown",
}
KNOWN_ESTATE_LIMITATION = (
    "Coverage applies only to Hawk's known, currently observed estate. "
    "Truly unobserved assets and paths remain outside the measured population."
)
CONFIDENCE_BASIS = (
    "Confidence reflects evidence quality and freshness, not a second score. "
    "The overall value uses the most conservative of all six dimensions."
)
MAX_EVIDENCE_REFS = 20
MAX_EVIDENCE_REF_LENGTH = 255
SAFE_EVIDENCE_REF_PREFIXES = (
    "runtime_event:",
    "ai_action:",
    "decision_receipt:",
    "execution_receipt:",
    "evidence:",
    "finding:",
)
V1_WATERMARK_KEYS = frozenset(
    {
        "runtime_event",
        "ai_action",
        "decision_receipt",
        "execution_receipt",
        "deployment_surface",
        "deployment_family_surface_projection",
    }
)
D4_WATERMARK_KEYS = frozenset(
    {
        "control_coverage_snapshot",
        "control_coverage_input_digest",
        "control_coverage_computed_at",
        "deployment_family_calculated_at",
    }
)
OUTPUT_WATERMARK_KEYS = V1_WATERMARK_KEYS | D4_WATERMARK_KEYS
_WATERMARK_IDENTIFIER_MAX = {
    "runtime_event": 36,
    "ai_action": 64,
    "decision_receipt": 36,
    "execution_receipt": 36,
    "deployment_surface": 36,
    "control_coverage_snapshot": 36,
}
_SAFE_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9._:-]+$")
_SECRET_SHAPED_MARKERS = (
    "bearer",
    "secret",
    "password",
    "token",
    "api_key",
    "apikey",
    "sk-",
    "ghp_",
    "github_pat_",
    "xox",
)
_CLOSED_STATES = {"covered", "not_covered", "unknown", "not_applicable"}
_PARTIAL_QUALITIES = {"partial", "metadata_only"}
_OPERATIONAL_HEALTH = {"healthy", "warning", "degraded"}
_CONFIDENCE_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3}


def safe_evidence_ref(value: object) -> str | None:
    if type(value) is not str:
        return None
    ref = value
    if (
        not ref
        or ref != ref.strip()
        or len(ref) > MAX_EVIDENCE_REF_LENGTH
        or not ref.startswith(SAFE_EVIDENCE_REF_PREFIXES)
        or any(character in ref for character in ("?", "#", "&", "\n", "\r"))
        or any(ref == prefix for prefix in SAFE_EVIDENCE_REF_PREFIXES)
    ):
        return None
    return ref


def sanitize_evidence_refs(values: Iterable[object]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                ref
                for value in values
                if (ref := safe_evidence_ref(value)) is not None
            }
        )[:MAX_EVIDENCE_REFS]
    )


def valid_watermark_value(key: object, value: object) -> bool:
    if type(key) is not str or type(value) is not str:
        return False
    if not value or value != value.strip():
        return False
    if key in _WATERMARK_IDENTIFIER_MAX:
        if value == "none":
            return True
        return bool(
            len(value) <= _WATERMARK_IDENTIFIER_MAX[key]
            and _SAFE_IDENTIFIER_PATTERN.fullmatch(value)
            and not any(
                marker in value.lower()
                for marker in _SECRET_SHAPED_MARKERS
            )
        )
    if key == "control_coverage_input_digest":
        return bool(re.fullmatch(r"[0-9a-f]{64}", value))
    if key == "deployment_family_surface_projection":
        return bool(re.fullmatch(r"[0-9a-f]{64}", value))
    if key in {
        "control_coverage_computed_at",
        "deployment_family_calculated_at",
    }:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return False
        return parsed.tzinfo is not None and parsed.isoformat() == value
    return False


@dataclass(frozen=True)
class DimensionAssertion:
    path_id: str
    family: str
    dimension: str
    state: str
    evidence_refs: tuple[str, ...] = ()
    evidence_quality: str = "verified"
    stale: bool = False
    conflicting: bool = False


@dataclass(frozen=True)
class ContainmentEvidence:
    capability: str = "unknown"
    health_status: str = "unknown"
    verified_block_inline_prevented: bool = False
    authorization_monitor_only_proven: bool = False
    deployment_offline_proven: bool = False
    evidence_refs: tuple[str, ...] = ()
    stale: bool = False
    conflicting: bool = False


@dataclass(frozen=True)
class ContainmentResult:
    state: str
    evidence_refs: tuple[str, ...]
    evidence_quality: str = "verified"
    stale: bool = False
    conflicting: bool = False


def evaluate_containment(evidence: ContainmentEvidence) -> ContainmentResult:
    """Evaluate containment without treating configured capability as proof."""

    refs = sanitize_evidence_refs(evidence.evidence_refs)
    health = (
        evidence.health_status
        if type(evidence.health_status) is str
        and evidence.health_status in {
            "healthy",
            "warning",
            "degraded",
            "offline",
            "stale",
            "unknown",
        }
        else "unknown"
    )
    capability = (
        evidence.capability
        if type(evidence.capability) is str
        and evidence.capability
        in {"direct", "surface_limited", "external", "none", "unknown"}
        else "unknown"
    )
    stale = bool(evidence.stale or health == "stale")
    conflicting = bool(evidence.conflicting)
    if stale or conflicting:
        return ContainmentResult(
            state="unknown",
            evidence_refs=refs,
            stale=stale,
            conflicting=conflicting,
        )
    if (
        evidence.deployment_offline_proven is True
        and health in {"offline", "degraded"}
        and refs
    ):
        return ContainmentResult(state="not_covered", evidence_refs=refs)
    if (
        capability in {"direct", "surface_limited"}
        and health in _OPERATIONAL_HEALTH
        and evidence.verified_block_inline_prevented is True
        and refs
    ):
        return ContainmentResult(state="covered", evidence_refs=refs)
    if (
        capability == "none"
        and evidence.authorization_monitor_only_proven is True
        and refs
    ):
        return ContainmentResult(state="not_covered", evidence_refs=refs)
    # External requires an exact verified action lineage that the current model
    # cannot prove. Stored capability, registration, and simulation are not proof.
    return ContainmentResult(state="unknown", evidence_refs=refs)


@dataclass(frozen=True)
class DimensionCoverage:
    name: str
    status: str
    covered_count: int
    not_covered_count: int
    total_known_eligible_count: int
    unknown_count: int
    excluded_count: int
    percentage_nullable: float | None
    confidence: str
    methodology: str
    evidence_refs: tuple[str, ...]
    calculated_at: datetime

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "status": self.status,
            "covered_count": self.covered_count,
            "not_covered_count": self.not_covered_count,
            "total_known_eligible_count": self.total_known_eligible_count,
            "unknown_count": self.unknown_count,
            "excluded_count": self.excluded_count,
            "percentage_nullable": self.percentage_nullable,
            "confidence": self.confidence,
            "methodology": self.methodology,
            "evidence_refs": list(self.evidence_refs),
            "calculated_at": self.calculated_at,
        }


@dataclass(frozen=True)
class OverallCoverage:
    status: str
    covered_count: int
    not_covered_count: int
    total_known_eligible_count: int
    unknown_count: int
    excluded_count: int
    percentage_nullable: float | None
    confidence: str
    confidence_basis: str
    methodology: str
    calculated_at: datetime

    def as_dict(self) -> dict[str, object]:
        return {
            "covered_count": self.covered_count,
            "not_covered_count": self.not_covered_count,
            "total_known_eligible_count": self.total_known_eligible_count,
            "unknown_count": self.unknown_count,
            "excluded_count": self.excluded_count,
            "percentage_nullable": self.percentage_nullable,
            "confidence": self.confidence,
            "confidence_basis": self.confidence_basis,
            "methodology": self.methodology,
            "calculated_at": self.calculated_at,
        }


@dataclass(frozen=True)
class FamilyCoverage:
    family: str
    label: str
    dimensions: tuple[DimensionCoverage, ...]
    overall: OverallCoverage
    estate_unknown_percentage_nullable: float | None

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "family": self.family,
            "label": self.label,
            "dimensions": [item.as_dict() for item in self.dimensions],
            "estate_unknown_percentage_nullable": (
                self.estate_unknown_percentage_nullable
            ),
        }
        if self.overall.status == "sufficient_data":
            result["overall"] = self.overall.as_dict()
        return result


@dataclass(frozen=True)
class FamilyCoverageCalculation:
    methodology_version: str
    calculated_at: datetime
    input_watermarks: Mapping[str, str]
    known_estate_limitation: str
    freshness_status: str
    confidence_basis: str
    diagnostics: tuple[str, ...]
    overall: OverallCoverage
    families: tuple[FamilyCoverage, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "methodology": self.methodology_version,
            "calculated_at": self.calculated_at,
            "input_watermarks": dict(self.input_watermarks),
            "known_estate_limitation": self.known_estate_limitation,
            "freshness_status": self.freshness_status,
            "confidence_basis": self.confidence_basis,
            "diagnostics": list(self.diagnostics),
            "items": [item.as_dict() for item in self.families],
        }


@dataclass(frozen=True)
class _EffectiveAssertion:
    path_id: str
    family: str
    dimension: str
    state: str
    evidence_refs: tuple[str, ...]
    evidence_quality: str
    stale: bool
    conflicting: bool


def _normalize_assertions(
    assertions: Iterable[DimensionAssertion],
) -> tuple[_EffectiveAssertion, ...]:
    grouped: dict[tuple[str, str], list[DimensionAssertion]] = {}
    for item in assertions:
        dimension = item.dimension if type(item.dimension) is str else ""
        if dimension not in DIMENSION_ORDER:
            continue
        path_id = item.path_id if type(item.path_id) is str else ""
        if not path_id or path_id != path_id.strip():
            continue
        grouped.setdefault((dimension, path_id), []).append(item)

    effective: list[_EffectiveAssertion] = []
    for (dimension, path_id), rows in sorted(grouped.items()):
        families = {
            row.family
            if type(row.family) is str and row.family in FAMILY_ORDER
            else "unknown"
            for row in rows
        }
        family_conflict = len(families) > 1
        family = "unknown" if family_conflict else next(iter(families))
        normalized_states = {
            row.state if type(row.state) is str else "unknown" for row in rows
        }
        invalid_state = any(state not in _CLOSED_STATES for state in normalized_states)
        states = {
            state if state in _CLOSED_STATES else "unknown"
            for state in normalized_states
        }
        duplicate_conflict = len(states) > 1
        qualities = {
            row.evidence_quality
            if type(row.evidence_quality) is str
            else "__invalid__"
            for row in rows
        }
        invalid_quality = any(
            quality not in {"verified", "partial", "metadata_only"}
            for quality in qualities
        )
        state = "unknown" if invalid_state or duplicate_conflict else next(iter(states))
        quality = (
            "metadata_only"
            if "metadata_only" in qualities
            else "partial"
            if "partial" in qualities
            else "verified"
        )
        stale = any(bool(row.stale) for row in rows)
        row_conflicting = any(bool(row.conflicting) for row in rows)
        refs = sanitize_evidence_refs(
            ref for row in rows for ref in row.evidence_refs
        )
        missing_required_refs = state in {"covered", "not_covered"} and not refs
        conflicting = (
            invalid_state
            or invalid_quality
            or duplicate_conflict
            or family_conflict
            or row_conflicting
            or missing_required_refs
        )
        if family_conflict:
            state = "unknown"
        if (
            state in {"covered", "not_covered"}
            and (
                stale
                or conflicting
                or (state == "covered" and quality in _PARTIAL_QUALITIES)
            )
        ):
            state = "unknown"
        effective.append(
            _EffectiveAssertion(
                path_id=path_id,
                family=family,
                dimension=dimension,
                state=state,
                evidence_refs=refs,
                evidence_quality=quality,
                stale=stale,
                conflicting=conflicting,
            )
        )
    return tuple(effective)


def _confidence(rows: tuple[_EffectiveAssertion, ...], *, eligible: int) -> str:
    if eligible == 0:
        return "unknown"
    applicable = tuple(row for row in rows if row.state != "not_applicable")
    if any(row.stale or row.conflicting for row in applicable):
        return "unknown"
    if any(row.evidence_quality in _PARTIAL_QUALITIES for row in applicable):
        return "low"
    if applicable and all(row.state == "unknown" for row in applicable):
        return "unknown"
    if any(row.state == "unknown" for row in applicable):
        return "medium"
    return "high"


def _dimension_coverage(
    name: str,
    rows: tuple[_EffectiveAssertion, ...],
    *,
    calculated_at: datetime,
) -> DimensionCoverage:
    covered = sum(row.state == "covered" for row in rows)
    not_covered = sum(row.state == "not_covered" for row in rows)
    unknown = sum(row.state == "unknown" for row in rows)
    excluded = sum(row.state == "not_applicable" for row in rows)
    eligible = covered + not_covered + unknown
    return DimensionCoverage(
        name=name,
        status="sufficient_data" if eligible else "insufficient_data",
        covered_count=covered,
        not_covered_count=not_covered,
        total_known_eligible_count=eligible,
        unknown_count=unknown,
        excluded_count=excluded,
        percentage_nullable=(
            round((covered / eligible) * 100.0, 2) if eligible else None
        ),
        confidence=_confidence(rows, eligible=eligible),
        methodology=METHODOLOGY_VERSION,
        evidence_refs=sanitize_evidence_refs(
            ref for row in rows for ref in row.evidence_refs
        ),
        calculated_at=calculated_at,
    )


def _overall(
    dimensions: tuple[DimensionCoverage, ...],
    *,
    calculated_at: datetime,
) -> OverallCoverage:
    sufficient = all(
        dimension.status == "sufficient_data" for dimension in dimensions
    )
    covered = sum(item.covered_count for item in dimensions)
    not_covered = sum(item.not_covered_count for item in dimensions)
    unknown = sum(item.unknown_count for item in dimensions)
    excluded = sum(item.excluded_count for item in dimensions)
    eligible = covered + not_covered + unknown
    confidence = min(
        (item.confidence for item in dimensions),
        key=lambda item: _CONFIDENCE_RANK[item],
        default="unknown",
    )
    status = "sufficient_data" if sufficient else "insufficient_data"
    if not sufficient:
        confidence = "unknown"
    return OverallCoverage(
        status=status,
        covered_count=covered,
        not_covered_count=not_covered,
        total_known_eligible_count=eligible,
        unknown_count=unknown,
        excluded_count=excluded,
        percentage_nullable=(
            round((covered / eligible) * 100.0, 2)
            if sufficient and eligible
            else None
        ),
        confidence=confidence,
        confidence_basis=CONFIDENCE_BASIS,
        methodology=METHODOLOGY_VERSION,
        calculated_at=calculated_at,
    )


def _family(
    family: str,
    rows: tuple[_EffectiveAssertion, ...],
    *,
    calculated_at: datetime,
) -> FamilyCoverage:
    dimensions = tuple(
        _dimension_coverage(
            dimension,
            tuple(row for row in rows if row.dimension == dimension),
            calculated_at=calculated_at,
        )
        for dimension in DIMENSION_ORDER
    )
    overall = _overall(dimensions, calculated_at=calculated_at)
    return FamilyCoverage(
        family=family,
        label=FAMILY_LABELS[family],
        dimensions=dimensions,
        overall=overall,
        estate_unknown_percentage_nullable=(
            round(
                (overall.unknown_count / overall.total_known_eligible_count) * 100.0,
                2,
            )
            if overall.total_known_eligible_count
            else None
        ),
    )


def calculate_family_coverage(
    assertions: Iterable[DimensionAssertion],
    *,
    calculated_at: datetime,
    input_watermarks: Mapping[str, object],
    diagnostics: Iterable[object] = (),
    freshness_status: str = "current",
) -> FamilyCoverageCalculation:
    effective = _normalize_assertions(assertions)
    families = tuple(
        _family(
            family,
            tuple(row for row in effective if row.family == family),
            calculated_at=calculated_at,
        )
        for family in FAMILY_ORDER
    )
    estate_dimensions = tuple(
        _dimension_coverage(
            dimension,
            tuple(row for row in effective if row.dimension == dimension),
            calculated_at=calculated_at,
        )
        for dimension in DIMENSION_ORDER
    )
    watermarks = {
        key: value
        for key, value in sorted(
            input_watermarks.items(),
            key=lambda item: item[0] if type(item[0]) is str else "",
        )
        if type(key) is str
        and key in OUTPUT_WATERMARK_KEYS
        and valid_watermark_value(key, value)
    }
    safe_diagnostics = tuple(
        sorted(
            {
                item
                for item in diagnostics
                if type(item) is str
                and item
                and item == item.strip()
                and len(item) <= 128
            }
        )
    )
    return FamilyCoverageCalculation(
        methodology_version=METHODOLOGY_VERSION,
        calculated_at=calculated_at,
        input_watermarks=watermarks,
        known_estate_limitation=KNOWN_ESTATE_LIMITATION,
        freshness_status=(
            freshness_status
            if type(freshness_status) is str
            and freshness_status in {"current", "stale", "unknown"}
            else "unknown"
        ),
        confidence_basis=CONFIDENCE_BASIS,
        diagnostics=safe_diagnostics,
        overall=_overall(estate_dimensions, calculated_at=calculated_at),
        families=families,
    )


__all__ = [
    "DIMENSION_ORDER",
    "FAMILY_ORDER",
    "KNOWN_ESTATE_LIMITATION",
    "METHODOLOGY_VERSION",
    "D4_WATERMARK_KEYS",
    "OUTPUT_WATERMARK_KEYS",
    "V1_WATERMARK_KEYS",
    "ContainmentEvidence",
    "DimensionAssertion",
    "FamilyCoverageCalculation",
    "calculate_family_coverage",
    "evaluate_containment",
    "safe_evidence_ref",
    "sanitize_evidence_refs",
    "valid_watermark_value",
]
