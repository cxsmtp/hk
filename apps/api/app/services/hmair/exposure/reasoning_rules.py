from __future__ import annotations

from pydantic import Field

from app.services.hmair.contracts import StrictContract, canonical_json_bytes
from app.services.hmair.exposure.category_catalog import ExposureCategoryDefinition
from app.services.hmair.exposure.contracts import (
    ExposureDimension,
    ExposureExtent,
    ExposureFactor,
    FreshnessState,
    VerificationStatus,
)


_VERIFICATION_STRENGTH = {
    VerificationStatus.CONTRADICTED: 0,
    VerificationStatus.UNKNOWN: 1,
    VerificationStatus.STALE: 2,
    VerificationStatus.INFERRED: 3,
    VerificationStatus.PARTIALLY_VERIFIED: 4,
    VerificationStatus.VERIFIED: 5,
}
_NEGATIVE_REACH_MARKERS = (
    "not_reachable",
    "unreachable",
    "denied",
    "no_reach",
    "blocked",
)
_CONSTRAINED_REACH_MARKERS = ("internal", "local", "scoped", "constrained")
_BROAD_REACH_MARKERS = ("internet", "external", "public", "global", "cross_environment")
_CONSTRAINED_PERMISSION_MARKERS = (
    "read_only",
    "scoped_read",
    "limited",
    "constrained",
    "metadata_only",
)
_BROAD_PERMISSION_MARKERS = ("admin", "unrestricted", "elevated", "write_all", "owner")
_DENIED_PERMISSION_MARKERS = (
    "denied",
    "none",
    "not_authorized",
    "blocked",
    "removed",
    "revoked",
)
_REMOVED_IDENTITY_MARKERS = ("removed", "revoked", "disabled")
_PATH_REF_PREFIX = "control_coverage_path:"
_EXTENT_STRENGTH = {
    ExposureExtent.NONE: 0,
    ExposureExtent.LIMITED: 1,
    ExposureExtent.MATERIAL: 2,
    ExposureExtent.BROAD: 3,
}
_PATH_FALLBACK_SOURCE_TYPES = {
    "control_coverage_path",
    "runtime_event_path_context",
    "ai_action_path_context",
}
_EXACT_ASSET_GLOBAL_SOURCE_TYPES = {"discovery_asset"}
_MAX_RESULT_CONTRIBUTORS = 256
_MAX_RESULT_CONTRADICTIONS = 128
_MAX_RESULT_EVIDENCE_REFS = 256
_MAX_COLLECTOR_DIVERSITY = 64


def _is_fallback_factor(factor: ExposureFactor) -> bool:
    return factor.source_type in _PATH_FALLBACK_SOURCE_TYPES or (
        factor.source_type == "discovery_asset"
        and factor.dimension in {ExposureDimension.RUNTIME, ExposureDimension.PROVIDER}
    )


class ExposureRuleResult(StrictContract):
    category_id: str = Field(min_length=1, max_length=64)
    category_version: str = Field(min_length=1, max_length=32)
    methodology_version: str = Field(min_length=1, max_length=32)
    extent: ExposureExtent
    proven_lower_bound: ExposureExtent | None = None
    contributors: tuple[ExposureFactor, ...] = Field(max_length=256)
    contradictions: tuple[ExposureFactor, ...] = Field(max_length=128)
    unknown_dimensions: tuple[ExposureDimension, ...] = Field(max_length=16)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    verification_status: VerificationStatus
    evidence_quality: float | None = Field(default=None, ge=0.0, le=1.0)
    collector_diversity: int = Field(ge=0, le=64)
    evidence_refs: tuple[str, ...] = Field(max_length=256)
    reasoning_trace: tuple[str, ...] = Field(min_length=1, max_length=64)
    limitations: tuple[str, ...] = Field(max_length=64)


def _is_current(factor: ExposureFactor) -> bool:
    state_parts = {
        part.strip().casefold()
        for part in factor.state.split(":")
        if part.strip()
    }
    return (
        factor.verification_status
        not in {
            VerificationStatus.UNKNOWN,
            VerificationStatus.STALE,
            VerificationStatus.CONTRADICTED,
        }
        and factor.freshness is FreshnessState.FRESH
        and "unknown" not in state_parts
        and factor.source_type not in {"missing_authority", "failed_authority"}
    )


def _is_verified(factor: ExposureFactor) -> bool:
    return _is_current(factor) and factor.verification_status is VerificationStatus.VERIFIED


def _contains(state: str, markers: tuple[str, ...]) -> bool:
    normalized = state.casefold()
    return any(marker in normalized for marker in markers)


def _control_coverage_conflicts(
    factors: tuple[ExposureFactor, ...],
) -> tuple[ExposureFactor, ...]:
    grouped: dict[str, dict[str, list[ExposureFactor]]] = {}
    for factor in factors:
        if not _is_verified(factor):
            continue
        parts = tuple(part for part in factor.state.casefold().split(":") if part)
        if factor.source_type == "control_coverage_assertion" and len(parts) >= 2:
            group, assertion = parts[0], parts[1]
            grouped.setdefault(group, {}).setdefault(assertion, []).append(factor)
        elif factor.source_type == "deployment_surface" and len(parts) >= 2:
            grouped.setdefault("containment", {}).setdefault(parts[1], []).append(factor)
            if "control" in parts:
                index = parts.index("control")
                if index + 1 < len(parts):
                    grouped.setdefault("containment_control", {}).setdefault(
                        parts[index + 1], []
                    ).append(factor)
    return tuple(
        sorted(
            {
                factor
                for assertions in grouped.values()
                if len(assertions) > 1
                for values in assertions.values()
                for factor in values
            },
            key=_factor_key,
        )
    )


def _governance_conflicts(
    factors: tuple[ExposureFactor, ...],
) -> tuple[ExposureFactor, ...]:
    positive: list[ExposureFactor] = []
    negative: list[ExposureFactor] = []
    positive_heads = {"approved", "governed", "governed_inline", "managed"}
    negative_heads = {
        "unapproved",
        "ungoverned",
        "unmanaged",
        "personal",
        "confirmed_shadow",
    }
    for factor in factors:
        if not _is_verified(factor):
            continue
        head = factor.state.casefold().split(":", maxsplit=1)[0]
        if head in positive_heads:
            positive.append(factor)
        elif head in negative_heads:
            negative.append(factor)
    if not positive or not negative:
        return ()
    return tuple(
        sorted(
            set(positive + negative),
            key=_factor_key,
        )
    )


def _semantic_required_conflicts(
    by_dimension: dict[ExposureDimension, tuple[ExposureFactor, ...]],
) -> tuple[ExposureFactor, ...]:
    conflicts = set(
        _control_coverage_conflicts(
            by_dimension.get(ExposureDimension.CONTROL_COVERAGE, ())
        )
    )
    conflicts.update(
        _governance_conflicts(by_dimension.get(ExposureDimension.GOVERNANCE, ()))
    )
    permissions = tuple(
        item
        for item in by_dimension.get(ExposureDimension.PERMISSION, ())
        if _is_verified(item)
    )
    denied = tuple(
        item for item in permissions if _contains(item.state, _DENIED_PERMISSION_MARKERS)
    )
    permitted = tuple(
        item for item in permissions if not _contains(item.state, _DENIED_PERMISSION_MARKERS)
    )
    if denied and permitted:
        conflicts.update(denied + permitted)
    identities = tuple(
        item
        for item in by_dimension.get(ExposureDimension.IDENTITY, ())
        if _is_verified(item)
    )
    removed_identities = tuple(
        item for item in identities if _contains(item.state, _REMOVED_IDENTITY_MARKERS)
    )
    active_identities = tuple(
        item for item in identities if not _contains(item.state, _REMOVED_IDENTITY_MARKERS)
    )
    if removed_identities and active_identities:
        conflicts.update(removed_identities + active_identities)
    return tuple(
        sorted(
            conflicts,
            key=_factor_key,
        )
    )


def _select_dimension_contributors(
    dimension: ExposureDimension,
    factors: tuple[ExposureFactor, ...],
) -> tuple[ExposureFactor, ...]:
    available = tuple(item for item in factors if item.dimension is dimension and _is_current(item))
    authoritative = tuple(
        item
        for item in available
        if not _is_fallback_factor(item)
        and item.verification_status is VerificationStatus.VERIFIED
    )
    if authoritative:
        available = tuple(
            item
            for item in available
            if not _is_fallback_factor(item)
        )
    return tuple(
        sorted(
            available,
            key=lambda item: (
                -_VERIFICATION_STRENGTH[item.verification_status],
                -(item.confidence if item.confidence is not None else -1.0),
                item.source_type,
                item.source_id,
                canonical_json_bytes(item.model_dump(mode="json")),
            ),
        )
    )


def _result(
    *,
    definition: ExposureCategoryDefinition,
    methodology_version: str,
    extent: ExposureExtent,
    lower_bound: ExposureExtent | None,
    contributors: tuple[ExposureFactor, ...],
    contradictions: tuple[ExposureFactor, ...],
    unknown_dimensions: tuple[ExposureDimension, ...],
    trace: tuple[str, ...],
    extra_limitations: tuple[str, ...] = (),
) -> ExposureRuleResult:
    required_dimensions = set(definition.required_dimensions)
    required_contributors = tuple(
        item for item in contributors if item.dimension in required_dimensions
    )
    confidence = (
        None
        if not required_contributors or any(item.confidence is None for item in required_contributors)
        else min(float(item.confidence) for item in required_contributors if item.confidence is not None)
    )
    verification = (
        VerificationStatus.UNKNOWN
        if not required_contributors
        else min(
            (item.verification_status for item in required_contributors),
            key=lambda status: _VERIFICATION_STRENGTH[status],
        )
    )
    if contradictions:
        verification = VerificationStatus.CONTRADICTED
    elif unknown_dimensions:
        confidence = None
        verification = VerificationStatus.UNKNOWN
    all_evidence_refs = tuple(
        sorted({reference for item in contributors + contradictions for reference in item.evidence_refs})
    )
    actual_collector_diversity = len(
        {item.collector_group for item in contributors if item.collector_group}
    )
    limitations = set(extra_limitations)
    ordered_contributors = tuple(
        sorted(
            contributors,
            key=lambda item: (
                0 if item.dimension in required_dimensions else 1,
                _factor_key(item),
            ),
        )
    )
    ordered_contradictions = tuple(
        sorted(
            contradictions,
            key=_factor_key,
        )
    )
    if len(ordered_contributors) > _MAX_RESULT_CONTRIBUTORS:
        limitations.add("category_contributors_truncated")
    if len(ordered_contradictions) > _MAX_RESULT_CONTRADICTIONS:
        limitations.add("category_contradictions_truncated")
    if len(all_evidence_refs) > _MAX_RESULT_EVIDENCE_REFS:
        limitations.add("category_evidence_refs_truncated")
    if actual_collector_diversity > _MAX_COLLECTOR_DIVERSITY:
        limitations.add("collector_diversity_capped")
    if confidence is None:
        limitations.add("required_confidence_unavailable")
    limitations.add("evidence_quality_authority_unavailable")
    return ExposureRuleResult(
        category_id=definition.category_id,
        category_version=definition.version,
        methodology_version=methodology_version,
        extent=extent,
        proven_lower_bound=lower_bound,
        contributors=ordered_contributors[:_MAX_RESULT_CONTRIBUTORS],
        contradictions=ordered_contradictions[:_MAX_RESULT_CONTRADICTIONS],
        unknown_dimensions=unknown_dimensions,
        confidence=confidence,
        verification_status=verification,
        evidence_quality=None,
        collector_diversity=min(actual_collector_diversity, _MAX_COLLECTOR_DIVERSITY),
        evidence_refs=all_evidence_refs[:_MAX_RESULT_EVIDENCE_REFS],
        reasoning_trace=trace,
        limitations=tuple(sorted(limitations)),
    )


def _evaluate_bound_category(
    *,
    definition: ExposureCategoryDefinition,
    factors: tuple[ExposureFactor, ...],
    methodology_version: str,
) -> ExposureRuleResult:
    ordered = tuple(
        sorted(
            factors,
            key=_factor_key,
        )
    )
    required = set(definition.required_dimensions)
    contradictions = tuple(
        item
        for item in ordered
        if item.dimension in required
        and item.verification_status is VerificationStatus.CONTRADICTED
        and item.freshness is FreshnessState.FRESH
    )
    by_dimension = {
        dimension: _select_dimension_contributors(dimension, ordered)
        for dimension in definition.required_dimensions
    }
    contradictions += _semantic_required_conflicts(by_dimension)
    current_capabilities = tuple(
        item
        for item in by_dimension.get(ExposureDimension.CAPABILITY, ())
        if item.state in set(definition.qualifying_capabilities)
    )
    if definition.category_id == "unknown_exposure":
        current_capabilities = by_dimension.get(ExposureDimension.CAPABILITY, ())
    verified_qualifying_capabilities = tuple(
        item for item in current_capabilities if _is_verified(item)
    )

    unknown_dimensions = {
        dimension
        for dimension, values in by_dimension.items()
        if not values
    }
    unknown_dimensions.update(
        factor.dimension
        for factor in ordered
        if factor.source_type == "failed_authority"
        and factor.dimension in required
    )
    if not current_capabilities:
        unknown_dimensions.add(ExposureDimension.CAPABILITY)

    reachability = by_dimension.get(ExposureDimension.REACHABILITY, ())
    verified_negative_reach = tuple(
        item for item in reachability if _is_verified(item) and _contains(item.state, _NEGATIVE_REACH_MARKERS)
    )
    verified_positive_reach = tuple(
        item for item in reachability if _is_verified(item) and not _contains(item.state, _NEGATIVE_REACH_MARKERS)
    )
    if verified_negative_reach and verified_positive_reach:
        contradictions += verified_negative_reach + verified_positive_reach

    contributors = tuple(
        item
        for dimension in definition.required_dimensions
        for item in by_dimension.get(dimension, ())
    )
    optional = tuple(
        item
        for item in ordered
        if item.dimension in set(definition.optional_dimensions) and _is_current(item)
    )
    contributors = tuple(
        sorted(
            set(contributors + optional),
            key=_factor_key,
        )
    )
    exact_required = tuple(
        item
        for dimension in definition.required_dimensions
        for item in by_dimension.get(dimension, ())
    )
    required_fully_verified = (
        not unknown_dimensions
        and bool(exact_required)
        and all(
            item.verification_status is VerificationStatus.VERIFIED
            for item in exact_required
        )
    )

    if contradictions:
        lower_bound = None
        if verified_qualifying_capabilities and verified_positive_reach:
            lower_bound = ExposureExtent.LIMITED
        return _result(
            definition=definition,
            methodology_version=methodology_version,
            extent=ExposureExtent.UNKNOWN,
            lower_bound=lower_bound,
            contributors=contributors,
            contradictions=tuple(
                sorted(
                    set(contradictions),
                    key=_factor_key,
                )
            ),
            unknown_dimensions=tuple(sorted(unknown_dimensions, key=lambda item: item.value)),
            trace=("verified_required_contradiction", "exact_extent_withheld"),
            extra_limitations=("verified_required_contradiction",),
        )

    if (
        current_capabilities
        and verified_negative_reach
        and not verified_positive_reach
        and required_fully_verified
    ):
        return _result(
            definition=definition,
            methodology_version=methodology_version,
            extent=ExposureExtent.NONE,
            lower_bound=ExposureExtent.NONE,
            contributors=contributors,
            contradictions=(),
            unknown_dimensions=(),
            trace=("qualifying_capability_present", "verified_non_reachability", "extent_none"),
        )

    if unknown_dimensions:
        lower_bound = (
            ExposureExtent.LIMITED
            if verified_qualifying_capabilities and verified_positive_reach
            else None
        )
        return _result(
            definition=definition,
            methodology_version=methodology_version,
            extent=ExposureExtent.UNKNOWN,
            lower_bound=lower_bound,
            contributors=contributors,
            contradictions=(),
            unknown_dimensions=tuple(sorted(unknown_dimensions, key=lambda item: item.value)),
            trace=("required_evidence_missing_or_stale", "exact_extent_withheld"),
            extra_limitations=("required_evidence_unavailable",),
        )

    identities = by_dimension.get(ExposureDimension.IDENTITY, ())
    verified_identities = tuple(item for item in identities if _is_verified(item))
    identity_removed = bool(verified_identities) and all(
        _contains(item.state, _REMOVED_IDENTITY_MARKERS)
        for item in verified_identities
    )
    permissions = by_dimension.get(ExposureDimension.PERMISSION, ())
    verified_permissions = tuple(item for item in permissions if _is_verified(item))
    if identity_removed:
        extent = ExposureExtent.LIMITED
        trace = (
            "qualifying_capability_present",
            "verified_identity_removed",
            "extent_limited",
        )
    elif any(_contains(item.state, _DENIED_PERMISSION_MARKERS) for item in verified_permissions):
        extent = ExposureExtent.LIMITED
        trace = ("qualifying_capability_present", "verified_permission_constraint", "extent_limited")
    elif any(_contains(item.state, _CONSTRAINED_PERMISSION_MARKERS) for item in verified_permissions) or any(
        _contains(item.state, _CONSTRAINED_REACH_MARKERS) for item in verified_positive_reach
    ):
        extent = ExposureExtent.LIMITED
        trace = ("qualifying_capability_present", "verified_scope_constraint", "extent_limited")
    else:
        extent = ExposureExtent.MATERIAL
        trace = ("qualifying_capability_present", "usable_authority_and_reach", "extent_material")

    broad_reach = any(_contains(item.state, _BROAD_REACH_MARKERS) for item in verified_positive_reach)
    broad_permission = any(_contains(item.state, _BROAD_PERMISSION_MARKERS) for item in verified_permissions)
    high_usage = any(
        item.dimension is ExposureDimension.USAGE
        and item.state == "high_usage"
        and _is_verified(item)
        for item in optional
    )
    if (
        not identity_removed
        and
        broad_reach
        and broad_permission
        and high_usage
    ):
        extent = ExposureExtent.BROAD
        trace = (
            "qualifying_capability_present",
            "verified_broad_reach",
            "verified_consequential_authority",
            "verified_scale_indicator",
            "extent_broad",
        )

    if any(item.verification_status is not VerificationStatus.VERIFIED for item in exact_required):
        return _result(
            definition=definition,
            methodology_version=methodology_version,
            extent=ExposureExtent.UNKNOWN,
            lower_bound=(
                ExposureExtent.LIMITED
                if verified_qualifying_capabilities and verified_positive_reach
                else None
            ),
            contributors=contributors,
            contradictions=(),
            unknown_dimensions=(),
            trace=("required_evidence_not_fully_verified", "exact_extent_withheld"),
            extra_limitations=("required_evidence_not_fully_verified",),
        )

    return _result(
        definition=definition,
        methodology_version=methodology_version,
        extent=extent,
        lower_bound=extent,
        contributors=contributors,
        contradictions=(),
        unknown_dimensions=(),
        trace=trace,
    )


def _path_refs(factor: ExposureFactor) -> tuple[str, ...]:
    return tuple(
        sorted(
            reference
            for reference in factor.related_source_refs
            if reference.startswith(_PATH_REF_PREFIX)
            and len(reference) > len(_PATH_REF_PREFIX)
        )
    )


def _factor_key(factor: ExposureFactor) -> tuple[str, str, str, str, bytes]:
    return (
        factor.dimension.value,
        factor.source_type,
        factor.source_id,
        factor.state,
        canonical_json_bytes(factor.model_dump(mode="json")),
    )


def evaluate_category(
    *,
    definition: ExposureCategoryDefinition,
    factors: tuple[ExposureFactor, ...],
    methodology_version: str,
) -> ExposureRuleResult:
    """Evaluate each exact exposure path independently, then combine conservatively."""

    qualifying_states = set(definition.qualifying_capabilities)
    qualifying_capabilities = tuple(
        factor
        for factor in factors
        if factor.dimension is ExposureDimension.CAPABILITY
        and _is_current(factor)
        and (
            definition.category_id == "unknown_exposure"
            or factor.state in qualifying_states
        )
    )
    path_refs = tuple(
        sorted(
            {
                reference
                for factor in qualifying_capabilities
                for reference in _path_refs(factor)
            }
        )
    )
    if not path_refs:
        current = tuple(
            sorted(
                (
                    factor
                    for factor in factors
                    if _is_current(factor)
                    and factor.dimension
                    in set(definition.required_dimensions + definition.optional_dimensions)
                ),
                key=_factor_key,
            )
        )
        return _result(
            definition=definition,
            methodology_version=methodology_version,
            extent=ExposureExtent.UNKNOWN,
            lower_bound=None,
            contributors=current,
            contradictions=(),
            unknown_dimensions=tuple(
                sorted(set(definition.required_dimensions), key=lambda item: item.value)
            ),
            trace=("exact_exposure_path_unavailable", "exact_extent_withheld"),
            extra_limitations=("exact_exposure_path_unavailable",),
        )

    path_results = tuple(
        _evaluate_bound_category(
            definition=definition,
            factors=tuple(
                factor
                for factor in factors
                if path_reference in _path_refs(factor)
                or factor.source_type in _EXACT_ASSET_GLOBAL_SOURCE_TYPES
                or factor.source_type == "failed_authority"
            ),
            methodology_version=methodology_version,
        )
        for path_reference in path_refs
    )
    if len(path_results) == 1:
        return path_results[0]

    contributors = tuple(
        sorted(
            {factor for result in path_results for factor in result.contributors},
            key=_factor_key,
        )
    )
    contradictions = tuple(
        sorted(
            {factor for result in path_results for factor in result.contradictions},
            key=_factor_key,
        )
    )
    unknown_dimensions = tuple(
        sorted(
            {
                dimension
                for result in path_results
                for dimension in result.unknown_dimensions
            },
            key=lambda item: item.value,
        )
    )
    lower_bounds = tuple(
        result.proven_lower_bound
        for result in path_results
        if result.proven_lower_bound is not None
        and result.proven_lower_bound is not ExposureExtent.UNKNOWN
    )
    proven_lower_bound = (
        max(lower_bounds, key=lambda item: _EXTENT_STRENGTH[item])
        if lower_bounds
        else None
    )
    has_unknown_path = any(
        result.extent is ExposureExtent.UNKNOWN for result in path_results
    )
    if has_unknown_path or contradictions:
        result = _result(
            definition=definition,
            methodology_version=methodology_version,
            extent=ExposureExtent.UNKNOWN,
            lower_bound=proven_lower_bound,
            contributors=contributors,
            contradictions=contradictions,
            unknown_dimensions=unknown_dimensions,
            trace=("multiple_exact_paths_evaluated", "uncertain_path_withholds_exact_extent"),
            extra_limitations=tuple(
                sorted(
                    {"one_or_more_paths_unknown"}
                    | {
                        limitation
                        for path_result in path_results
                        for limitation in path_result.limitations
                    }
                )
            ),
        )
        return result.model_copy(
            update={
                "confidence": None,
                "verification_status": (
                    VerificationStatus.CONTRADICTED
                    if contradictions
                    else VerificationStatus.UNKNOWN
                ),
            }
        )

    broad_path_count = sum(
        1
        for path_result in path_results
        if path_result.extent in {ExposureExtent.MATERIAL, ExposureExtent.BROAD}
        and any(
            item.dimension is ExposureDimension.REACHABILITY
            and _is_verified(item)
            and _contains(item.state, _BROAD_REACH_MARKERS)
            for item in path_result.contributors
        )
        and any(
            item.dimension is ExposureDimension.PERMISSION
            and _is_verified(item)
            and _contains(item.state, _BROAD_PERMISSION_MARKERS)
            for item in path_result.contributors
        )
    )
    exact_extent = max(
        (result.extent for result in path_results),
        key=lambda item: _EXTENT_STRENGTH[item],
    )
    if broad_path_count >= 2:
        exact_extent = ExposureExtent.BROAD
    combined = _result(
        definition=definition,
        methodology_version=methodology_version,
        extent=exact_extent,
        lower_bound=exact_extent,
        contributors=contributors,
        contradictions=(),
        unknown_dimensions=(),
        trace=("multiple_exact_paths_evaluated", f"maximum_extent_{exact_extent.value}"),
        extra_limitations=tuple(
            sorted(
                {
                    limitation
                    for path_result in path_results
                    for limitation in path_result.limitations
                }
            )
        ),
    )
    return combined


__all__ = ["ExposureRuleResult", "evaluate_category"]
