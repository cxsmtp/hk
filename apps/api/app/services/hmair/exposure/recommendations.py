from __future__ import annotations

import hashlib

from app.core.control_coverage import CoverageState
from app.services.hmair.contracts import canonical_json_bytes
from app.services.hmair.exposure.category_catalog import ExposureCategoryDefinition
from app.services.hmair.exposure.contracts import (
    ExposureCoverageDimension,
    ExposureCoverageProjection,
    ExposureDimension,
    ExposureExtent,
    ExposureFactor,
    ExposureRecommendation,
    FreshnessState,
    VerificationStatus,
)
from app.services.hmair.exposure.reasoning_rules import ExposureRuleResult


CAPABILITY_ROUTES = {
    "runtime_governance": "/deploy?surface=runtime",
    "browser_governance": "/deploy?surface=browser",
    "mcp_restriction": "/protect?surface=mcp",
    "filesystem_restriction": "/protect?capability=filesystem",
    "sandbox": "/deploy?surface=runtime",
    "approval": "/protect?mode=approval",
    "owner_assignment": "/ai-iam",
    "control_coverage": "/surface-coverage",
    "identity_review": "/ai-iam",
    "personal_account_removal": "/ai-iam",
}

_ACTION_BY_CAPABILITY = {
    "runtime_governance": "Enable a verified Runtime Governance path",
    "browser_governance": "Enable a verified Browser Governance path",
    "mcp_restriction": "Restrict MCP servers and tool authority",
    "filesystem_restriction": "Reduce filesystem access to the required scope",
    "sandbox": "Move the workload into a governed sandbox",
    "approval": "Require approval for consequential actions",
    "owner_assignment": "Assign an accountable owner",
    "control_coverage": "Improve evidence-backed Control Coverage",
    "identity_review": "Review user, agent, and service identity authority",
    "personal_account_removal": "Remove personal account access",
}

_PREREQUISITES_BY_CAPABILITY = {
    "runtime_governance": ("supported_runtime_control_point",),
    "browser_governance": ("supported_browser_control_point",),
    "mcp_restriction": ("mcp_inventory",),
    "filesystem_restriction": ("filesystem_capability_evidence",),
    "sandbox": ("supported_runtime_control_point",),
    "approval": ("bound_identity", "approval_policy"),
    "owner_assignment": ("identity_inventory",),
    "control_coverage": ("current_coverage_evidence",),
    "identity_review": ("identity_inventory",),
    "personal_account_removal": ("account_identity_evidence",),
}


def _typed_refs(factors: tuple[ExposureFactor, ...], prefix: str) -> tuple[str, ...]:
    marker = f"{prefix}:"
    return tuple(
        sorted(
            {
                reference[len(marker):]
                for factor in factors
                for reference in factor.related_source_refs
                if reference.startswith(marker) and len(reference) > len(marker)
            }
        )
    )


def _bounded_typed_refs(
    factors: tuple[ExposureFactor, ...],
    prefix: str,
    *,
    limit: int,
) -> tuple[tuple[str, ...], bool]:
    references = _typed_refs(factors, prefix)
    return references[:limit], len(references) > limit


def _freshness(factors: tuple[ExposureFactor, ...]) -> FreshnessState:
    if not factors:
        return FreshnessState.UNKNOWN
    states = {item.freshness for item in factors}
    if FreshnessState.EXPIRED in states:
        return FreshnessState.EXPIRED
    if FreshnessState.STALE in states:
        return FreshnessState.STALE
    if FreshnessState.UNKNOWN in states:
        return FreshnessState.UNKNOWN
    return FreshnessState.FRESH


def _coverage_assertion_dimension(
    factors: tuple[ExposureFactor, ...],
    *,
    dimension: str,
) -> ExposureCoverageDimension:
    relevant = tuple(
        item
        for item in factors
        if item.source_type == "control_coverage_assertion"
        and item.state.casefold().startswith(f"{dimension}:")
    )
    path_ids, path_ids_truncated = _bounded_typed_refs(
        relevant, "control_coverage_path", limit=64
    )
    assertion_ids, assertion_ids_truncated = _bounded_typed_refs(
        relevant, "control_coverage_assertion", limit=128
    )
    blind_spots: set[str] = set()
    freshness = _freshness(relevant)
    state_parts = {item.state.casefold().split(":")[1] for item in relevant}
    related_reasons = {
        reference.removeprefix("coverage_reason:")
        for item in relevant
        for reference in item.related_source_refs
        if reference.startswith("coverage_reason:")
    }
    monitor_only = any("monitor_only" in item.state.casefold() for item in relevant) or (
        "monitor_only_surface" in related_reasons
    )

    if not relevant:
        state = CoverageState.UNKNOWN
        blind_spots.add(f"{dimension}_assertion_unavailable")
    elif freshness is not FreshnessState.FRESH:
        state = CoverageState.UNKNOWN
        blind_spots.add("stale_or_expired_assertion")
    elif any(item.verification_status is not VerificationStatus.VERIFIED for item in relevant):
        state = CoverageState.UNKNOWN
        blind_spots.add("assertion_not_verified")
    elif len(state_parts) > 1:
        state = CoverageState.UNKNOWN
        blind_spots.add("conflicting_coverage_assertions")
    elif monitor_only and dimension == "authorization":
        state = CoverageState.NOT_COVERED
        blind_spots.add("monitor_only_is_not_authorization")
    elif "not_covered" in state_parts:
        state = CoverageState.NOT_COVERED
        blind_spots.add(f"{dimension}_not_covered")
    elif "unknown" in state_parts or "not_applicable" in state_parts:
        state = CoverageState.UNKNOWN
        blind_spots.add(f"{dimension}_unknown")
    elif state_parts == {"covered"}:
        state = CoverageState.COVERED
    else:
        state = CoverageState.UNKNOWN
        blind_spots.add("conflicting_coverage_assertions")
    if path_ids_truncated or assertion_ids_truncated:
        state = CoverageState.UNKNOWN
        blind_spots.add("coverage_reference_projection_truncated")

    return ExposureCoverageDimension(
        state=state,
        path_ids=path_ids,
        assertion_ids=assertion_ids,
        control_mode="monitor_only" if monitor_only else None,
        external_control_dependency=None,
        blind_spots=tuple(sorted(blind_spots)),
        freshness=freshness,
    )


def _containment_dimension(
    factors: tuple[ExposureFactor, ...],
) -> ExposureCoverageDimension:
    relevant = tuple(
        item
        for item in factors
        if item.source_type == "deployment_surface"
        and item.state.casefold().startswith("containment:")
    )
    path_ids, path_ids_truncated = _bounded_typed_refs(
        relevant, "control_coverage_path", limit=64
    )
    blind_spots: set[str] = set()
    freshness = _freshness(relevant)
    control_modes = {
        item.state.casefold().split(":control:", maxsplit=1)[1]
        for item in relevant
        if ":control:" in item.state.casefold()
    }
    capabilities = {
        item.state.casefold().split(":", maxsplit=2)[1]
        for item in relevant
        if len(item.state.split(":")) >= 2
    }
    external = next(
        (item for item in relevant if ":external:" in item.state.casefold()),
        None,
    )

    if not relevant:
        state = CoverageState.UNKNOWN
        blind_spots.add("containment_evidence_unavailable")
    elif freshness is not FreshnessState.FRESH:
        state = CoverageState.UNKNOWN
        blind_spots.add("stale_or_expired_containment_evidence")
    elif any(item.verification_status is not VerificationStatus.VERIFIED for item in relevant):
        state = CoverageState.UNKNOWN
        blind_spots.add("containment_not_verified")
    elif len(capabilities) > 1:
        state = CoverageState.UNKNOWN
        blind_spots.add("conflicting_containment_evidence")
    elif len(control_modes) > 1:
        state = CoverageState.UNKNOWN
        blind_spots.add("conflicting_containment_control_modes")
    elif external is not None:
        state = CoverageState.NOT_COVERED
        blind_spots.add("external_containment_dependency")
    elif "none" in capabilities:
        state = CoverageState.NOT_COVERED
        blind_spots.add("containment_not_available")
    elif capabilities and capabilities <= {"direct", "surface_limited"}:
        state = CoverageState.COVERED
        if "surface_limited" in capabilities:
            blind_spots.add("containment_is_surface_limited")
    else:
        state = CoverageState.UNKNOWN
        blind_spots.add("containment_capability_unknown")
    if path_ids_truncated:
        state = CoverageState.UNKNOWN
        blind_spots.add("coverage_reference_projection_truncated")

    return ExposureCoverageDimension(
        state=state,
        path_ids=path_ids,
        assertion_ids=(),
        control_mode=(next(iter(control_modes)) if len(control_modes) == 1 else None),
        external_control_dependency=(
            f"deployment_surface:{external.source_id}" if external is not None else None
        ),
        blind_spots=tuple(sorted(blind_spots)),
        freshness=freshness,
    )


def project_exposure_coverage(
    factors: tuple[ExposureFactor, ...],
) -> ExposureCoverageProjection:
    coverage_factors = tuple(
        item for item in factors if item.dimension is ExposureDimension.CONTROL_COVERAGE
    )
    return ExposureCoverageProjection(
        discover=_coverage_assertion_dimension(coverage_factors, dimension="discovery"),
        authorize=_coverage_assertion_dimension(coverage_factors, dimension="authorization"),
        prove=_coverage_assertion_dimension(coverage_factors, dimension="evidence"),
        contain=_containment_dimension(coverage_factors),
    )


def build_recommendations(
    *,
    definition: ExposureCategoryDefinition,
    result: ExposureRuleResult,
    coverage: ExposureCoverageProjection,
) -> tuple[ExposureRecommendation, ...]:
    if result.extent is ExposureExtent.NONE:
        return ()
    factors = result.contributors + result.contradictions
    capability_factors = tuple(
        item for item in factors if item.dimension is ExposureDimension.CAPABILITY
    )

    def carries_gap_marker(item: ExposureFactor, *markers: str) -> bool:
        material = " ".join((item.state, *item.related_source_refs)).casefold()
        return any(marker in material for marker in markers)

    authorization_gaps = (
        tuple(
            item
            for item in factors
            if item.source_type == "control_coverage_assertion"
            and item.state.casefold().startswith("authorization:")
            and carries_gap_marker(item, "not_covered", "monitor_only")
        )
        if coverage.authorize.state is CoverageState.NOT_COVERED
        else ()
    )
    containment_gaps = (
        tuple(
            item
            for item in factors
            if item.source_type == "deployment_surface"
            and item.state.casefold().startswith("containment:")
            and any(
                marker in item.state.casefold()
                for marker in ("external", "none", "surface_limited")
            )
        )
        if coverage.contain.state is CoverageState.NOT_COVERED
        else ()
    )
    has_proven_coverage_gap = any(
        dimension.state is CoverageState.NOT_COVERED
        for dimension in (
            coverage.discover,
            coverage.authorize,
            coverage.prove,
            coverage.contain,
        )
    )
    coverage_gaps = (
        tuple(
            item
            for item in factors
            if item.dimension is ExposureDimension.CONTROL_COVERAGE
            and carries_gap_marker(
                item, "not_covered", "monitor_only", "external", "none"
            )
        )
        if has_proven_coverage_gap
        else ()
    )
    identity_gaps = tuple(
        item
        for item in factors
        if item.dimension in {ExposureDimension.IDENTITY, ExposureDimension.GOVERNANCE}
        and any(marker in item.state.casefold() for marker in ("unknown", "unmanaged", "owner_unknown"))
    )
    personal_identity = tuple(
        item
        for item in factors
        if item.dimension in {ExposureDimension.IDENTITY, ExposureDimension.GOVERNANCE}
        and "personal" in item.state.casefold()
    )

    def grounds(capability: str) -> tuple[ExposureFactor, ...]:
        gap = authorization_gaps + containment_gaps
        if capability == "approval":
            return authorization_gaps
        if capability == "control_coverage":
            return coverage_gaps
        if capability in {"identity_review", "owner_assignment"}:
            return identity_gaps
        if capability == "personal_account_removal":
            return personal_identity
        if capability == "filesystem_restriction":
            relevant = tuple(
                item
                for item in capability_factors
                if "file" in item.state.casefold()
            )
            return relevant + gap if relevant and gap else ()
        if capability == "mcp_restriction":
            relevant = tuple(
                item
                for item in capability_factors
                if "mcp" in item.state.casefold() or "tool_execution" in item.state.casefold()
            )
            return relevant + gap if relevant and gap else ()
        if capability == "browser_governance":
            relevant = tuple(
                item
                for item in capability_factors
                if any(marker in item.state.casefold() for marker in ("browser", "internet", "external"))
            )
            return relevant + gap if relevant and gap else ()
        if capability in {"runtime_governance", "sandbox"}:
            return capability_factors + gap if capability_factors and gap else ()
        return ()

    recommendations = []
    for capability in sorted(definition.recommendation_capabilities):
        if capability not in CAPABILITY_ROUTES:
            raise ValueError("unsupported exposure recommendation capability")
        grounding = tuple(
            sorted(
                set(grounds(capability)),
                key=lambda item: canonical_json_bytes(item.model_dump(mode="json")),
            )
        )
        if not grounding:
            continue
        source_refs = tuple(
            sorted(
                {
                    f"{item.source_type}:{item.source_id}"
                    for item in grounding
                }
                | {
                    evidence_ref
                    for item in grounding
                    for evidence_ref in item.evidence_refs
                }
                | {
                    related_ref
                    for item in grounding
                    for related_ref in item.related_source_refs
                }
            )
        )
        path_refs = tuple(
            reference
            for reference in source_refs
            if reference.startswith("control_coverage_path:")
        )
        if not path_refs or len(source_refs) > 64:
            continue
        target_control_path = (
            f"{capability}@path:"
            f"{hashlib.sha256(canonical_json_bytes(path_refs)).hexdigest()}"
        )
        recommendation_id = hashlib.sha256(
            b"hawk:ai-exposure-recommendation:v1"
            + canonical_json_bytes(
                {
                    "category_id": result.category_id,
                    "category_version": result.category_version,
                    "rule_version": result.methodology_version,
                    "capability": capability,
                    "extent": result.extent.value,
                    "target_control_path": target_control_path,
                    "source_refs": source_refs,
                    "coverage": coverage.model_dump(mode="json"),
                }
            )
        ).hexdigest()
        recommendations.append(
            ExposureRecommendation(
                recommendation_id=recommendation_id,
                capability=capability,
                governance_action=_ACTION_BY_CAPABILITY[capability],
                affected_category_id=result.category_id,
                reason=(
                    f"{definition.label} is {result.extent.value}; this action adds or improves "
                    "an existing Hawk governance capability without claiming capability removal."
                ),
                target_control_path=target_control_path,
                prerequisites=_PREREQUISITES_BY_CAPABILITY[capability],
                expected_effect="Qualitatively improve governance or evidence for this exposure path.",
                product_route=CAPABILITY_ROUTES[capability],
                source_refs=source_refs,
            )
        )
    return tuple(recommendations)


__all__ = [
    "CAPABILITY_ROUTES",
    "build_recommendations",
    "project_exposure_coverage",
]
