"""Evidence-gated blind spots and conditional deployment improvements."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence


DIMENSION_REQUIREMENTS: dict[str, tuple[str, set[str]]] = {
    "discovery": ("discovery", {"partial", "full"}),
    "identity": ("identity_attribution", {"supported"}),
    "authorization": ("inline_authorization", {"yes"}),
    "evidence": ("evidence_generation", {"partial", "full"}),
    "deployment": ("containment", {"surface", "end_to_end"}),
    "runtime": ("runtime_governance", {"supported"}),
    "bypass": ("bypass_detection", {"supported"}),
}

_BLIND_SPOT_DIMENSIONS: dict[str, set[str]] = {
    "unprotected_path": {"authorization", "deployment"},
    "bypass": {"authorization", "bypass"},
    "disconnected_gateway": {"deployment"},
    "missing_evidence": {"evidence"},
    "unmanaged_runtime": {"runtime"},
    "unmanaged_browser": {"discovery", "authorization", "deployment"},
    "unmanaged_mcp": {"authorization", "deployment"},
    "unknown_sdk": {"deployment", "runtime"},
}


@dataclass(frozen=True)
class CoveragePathView:
    path_id: str
    source_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class CoverageFindingView:
    finding_id: str
    kind: str
    path_id: str | None
    source_ref: str | None
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class CoverageAssertionView:
    assertion_id: str
    path_id: str
    dimension: str
    state: str
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class CapabilityProfileView:
    deployment_type: str
    capability_profile: Mapping[str, str]
    prerequisites: tuple[str, ...] = ()


@dataclass(frozen=True)
class BlindSpot:
    blind_spot_id: str
    kind: str
    path_id: str
    dimensions: tuple[str, ...]
    assertion_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class DeploymentImprovement:
    deployment_type: str
    addressable_assertion_count: int
    impacted_path_count: int
    dimensions: tuple[str, ...]
    path_ids: tuple[str, ...]
    assertion_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    prerequisites: tuple[str, ...] = field(default_factory=tuple)
    conditional: bool = True


def _normalize(value: object) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def build_blind_spots(
    *,
    paths: Sequence[CoveragePathView],
    findings: Sequence[CoverageFindingView],
    assertions: Sequence[CoverageAssertionView],
) -> list[BlindSpot]:
    path_by_id = {path.path_id: path for path in paths}
    path_by_source = {
        source_ref: path.path_id
        for path in paths
        for source_ref in path.source_refs
        if source_ref
    }
    assertions_by_path: dict[str, list[CoverageAssertionView]] = {}
    for assertion in assertions:
        assertions_by_path.setdefault(assertion.path_id, []).append(assertion)

    results: list[BlindSpot] = []
    for finding in findings:
        kind = _normalize(finding.kind)
        dimensions = _BLIND_SPOT_DIMENSIONS.get(kind)
        if dimensions is None or not finding.evidence_ids:
            continue
        path_id = finding.path_id if finding.path_id in path_by_id else path_by_source.get(finding.source_ref or "")
        if path_id is None:
            continue
        related = [
            assertion
            for assertion in assertions_by_path.get(path_id, [])
            if assertion.dimension in dimensions and assertion.state in {"not_covered", "unknown"}
        ]
        if not related:
            continue
        evidence_refs = tuple(
            [*(f"evidence:{item}" for item in sorted(set(finding.evidence_ids))), f"finding:{finding.finding_id}"]
        )
        results.append(
            BlindSpot(
                blind_spot_id=f"finding:{finding.finding_id}",
                kind=kind,
                path_id=path_id,
                dimensions=tuple(sorted({assertion.dimension for assertion in related})),
                assertion_ids=tuple(sorted({assertion.assertion_id for assertion in related})),
                evidence_refs=evidence_refs,
            )
        )
    return sorted(results, key=lambda item: (item.kind, item.path_id, item.blind_spot_id))


def rank_deployment_improvements(
    *,
    assertions: Sequence[CoverageAssertionView],
    capability_profiles: Sequence[CapabilityProfileView],
) -> list[DeploymentImprovement]:
    unresolved = [assertion for assertion in assertions if assertion.state in {"not_covered", "unknown"}]
    results: list[DeploymentImprovement] = []
    for profile in capability_profiles:
        addressable: dict[str, CoverageAssertionView] = {}
        for assertion in unresolved:
            requirement = DIMENSION_REQUIREMENTS.get(assertion.dimension)
            if requirement is None:
                continue
            capability, accepted_values = requirement
            current_value = _normalize(profile.capability_profile.get(capability))
            if current_value in accepted_values:
                addressable[assertion.assertion_id] = assertion
        if not addressable:
            continue
        rows = list(addressable.values())
        path_ids = tuple(sorted({row.path_id for row in rows}))
        evidence_refs = tuple(sorted({reference for row in rows for reference in row.evidence_refs}))
        results.append(
            DeploymentImprovement(
                deployment_type=profile.deployment_type,
                addressable_assertion_count=len(addressable),
                impacted_path_count=len(path_ids),
                dimensions=tuple(sorted({row.dimension for row in rows})),
                path_ids=path_ids,
                assertion_ids=tuple(sorted(addressable)),
                evidence_refs=evidence_refs,
                prerequisites=tuple(profile.prerequisites),
                conditional=True,
            )
        )
    return sorted(
        results,
        key=lambda item: (
            -item.addressable_assertion_count,
            -item.impacted_path_count,
            item.deployment_type,
        ),
    )
