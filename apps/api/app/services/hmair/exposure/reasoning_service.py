from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_asset import DiscoveryAIAsset
from app.services.hmair.contracts import canonical_json_bytes
from app.services.hmair.exposure.category_catalog import (
    ExposureCategoryCatalog,
    ExposureCategoryDefinition,
    load_category_catalog,
)
from app.services.hmair.exposure.contracts import (
    CalculationStatus,
    ExposureConclusion,
    ExposureDimension,
    ExposureExtent,
    ExposureFactor,
    ExposureGraph,
    ExposureProjection,
    ExposureTimelineEntry,
    FreshnessState,
    VerificationStatus,
)
from app.services.hmair.exposure.exposure_graph import build_exposure_graph
from app.services.hmair.exposure.exposure_timeline import build_exposure_timeline
from app.services.hmair.exposure.input_assembler import (
    AssembledExposureInput,
    ExposureInputAssembler,
)
from app.services.hmair.exposure.reasoning_rules import (
    ExposureRuleResult,
    evaluate_category,
)
from app.services.hmair.exposure.recommendations import (
    build_recommendations,
    project_exposure_coverage,
)
from app.services.hmair.exposure.source_reader import ExposureSourceReader


REASONING_METHODOLOGY_ID = "ai-exposure-reasoning/1.2"
REASONING_RULE_VERSION = "1.2.0"
HISTORICAL_EXPOSURE_UNAVAILABLE = "historical_exposure_state_unavailable"


class ExposureCategoryUnavailable(LookupError):
    pass


@dataclass(frozen=True)
class _ReasoningMaterial:
    catalog: ExposureCategoryCatalog
    assembled: AssembledExposureInput
    definitions: tuple[ExposureCategoryDefinition, ...]
    results: tuple[ExposureRuleResult, ...]
    failed_authorities: tuple[str, ...]
    truncated: bool


@dataclass(frozen=True)
class ExposureTimelineProjection:
    items: tuple[ExposureTimelineEntry, ...]
    limitations: tuple[str, ...]


def _is_category_capability(factor: ExposureFactor) -> bool:
    return (
        factor.dimension is ExposureDimension.CAPABILITY
        and factor.source_type != "missing_authority"
        and factor.state != "unknown"
        and factor.freshness is FreshnessState.FRESH
        and factor.verification_status
        not in {
            VerificationStatus.UNKNOWN,
            VerificationStatus.STALE,
            VerificationStatus.CONTRADICTED,
        }
    )


def _qualify_categories(
    catalog: ExposureCategoryCatalog,
    factors: tuple[ExposureFactor, ...],
) -> tuple[ExposureCategoryDefinition, ...]:
    capabilities = {
        item.state for item in factors if _is_category_capability(item)
    }
    qualified = tuple(
        item
        for item in catalog.categories
        if item.category_id != "unknown_exposure"
        and capabilities.intersection(item.qualifying_capabilities)
    )
    if qualified:
        return tuple(sorted(qualified, key=lambda item: item.category_id))
    return tuple(
        item for item in catalog.categories if item.category_id == "unknown_exposure"
    )


def _dimension_refs(
    result: ExposureRuleResult,
    dimension: ExposureDimension,
) -> tuple[str, ...]:
    references = tuple(
        sorted(
            {
                item.source_id
                for item in result.contributors + result.contradictions
                if item.dimension is dimension and item.source_type != "missing_authority"
            }
        )
    )
    return references[:64]


def _dimension_refs_are_truncated(result: ExposureRuleResult) -> bool:
    return any(
        len(
            {
                item.source_id
                for item in result.contributors + result.contradictions
                if item.dimension is dimension
                and item.source_type != "missing_authority"
            }
        )
        > 64
        for dimension in ExposureDimension
    )


def _last_validation(result: ExposureRuleResult) -> datetime | None:
    values = tuple(
        item.validated_at
        for item in result.contributors + result.contradictions
        if item.validated_at is not None
    )
    return max(values) if values else None


class ExposureReasoningService:
    def __init__(
        self,
        *,
        source_reader: ExposureSourceReader | None = None,
        input_assembler: ExposureInputAssembler | None = None,
    ) -> None:
        self.source_reader = source_reader or ExposureSourceReader()
        self.input_assembler = input_assembler or ExposureInputAssembler()

    def _reason(
        self,
        db: Session,
        *,
        tenant_id: str,
        asset_id: str,
        as_of: datetime,
    ) -> _ReasoningMaterial:
        catalog = load_category_catalog()
        snapshot = self.source_reader.read(
            db,
            tenant_id=tenant_id,
            asset_id=asset_id,
            as_of=as_of,
        )
        required_dimensions = tuple(
            sorted(
                {
                    dimension
                    for definition in catalog.categories
                    for dimension in definition.required_dimensions
                },
                key=lambda item: item.value,
            )
        )
        assembled = self.input_assembler.assemble(
            snapshot,
            required_dimensions=required_dimensions,
        )
        definitions = _qualify_categories(catalog, assembled.factors)
        results = tuple(
            evaluate_category(
                definition=definition,
                factors=assembled.factors,
                methodology_version=REASONING_RULE_VERSION,
            )
            for definition in definitions
        )
        if snapshot.truncated:
            results = tuple(
                result.model_copy(
                    update={
                        "extent": ExposureExtent.UNKNOWN,
                        "confidence": None,
                        "verification_status": (
                            VerificationStatus.CONTRADICTED
                            if result.contradictions
                            else VerificationStatus.UNKNOWN
                        ),
                        "reasoning_trace": tuple(
                            dict.fromkeys(
                                result.reasoning_trace
                                + ("source_projection_truncated", "exact_extent_withheld")
                            )
                        )[:64],
                        "limitations": tuple(
                            sorted(
                                set(result.limitations)
                                | {"source_projection_truncated"}
                            )
                        )[:64],
                    }
                )
                for result in results
            )
        return _ReasoningMaterial(
            catalog=catalog,
            assembled=assembled,
            definitions=definitions,
            results=results,
            failed_authorities=snapshot.failed_authorities,
            truncated=snapshot.truncated,
        )

    def project(
        self,
        db: Session,
        *,
        tenant_id: str,
        asset_id: str,
        as_of: datetime,
    ) -> ExposureProjection:
        try:
            material = self._reason(
                db,
                tenant_id=tenant_id,
                asset_id=asset_id,
                as_of=as_of,
            )
        except TimeoutError:
            exists = db.scalar(
                select(DiscoveryAIAsset.asset_id).where(
                    DiscoveryAIAsset.tenant_id == tenant_id,
                    DiscoveryAIAsset.asset_id == asset_id,
                )
            )
            if exists is None:
                from app.services.hmair.exposure.source_reader import ExposureAssetUnavailable

                raise ExposureAssetUnavailable("asset is unavailable") from None
            digest = hashlib.sha256(
                b"hawk:ai-exposure-unavailable:v1"
                + canonical_json_bytes(
                    {
                        "asset_id": asset_id,
                        "as_of": as_of.isoformat(),
                        "reason_code": "source_reader_timeout",
                    }
                )
            ).hexdigest()
            return ExposureProjection(
                asset_id=asset_id,
                as_of=as_of,
                calculation_status=CalculationStatus.UNAVAILABLE,
                reasoning_methodology_id=REASONING_METHODOLOGY_ID,
                reasoning_rule_version=REASONING_RULE_VERSION,
                category_catalog_version=load_category_catalog().version,
                source_input_digest=digest,
                exposures=(),
                extent_distribution={extent: 0 for extent in ExposureExtent},
                unknown_dimensions=tuple(ExposureDimension),
                failed_authorities=("source_reader_timeout",),
                conflicts=(),
                limitations=("source_projection_unavailable",),
                truncated=False,
            )
        definitions = {item.category_id: item for item in material.definitions}
        conclusions: list[ExposureConclusion] = []
        for result in material.results:
            definition = definitions[result.category_id]
            dimension_refs_truncated = _dimension_refs_are_truncated(result)
            result_factors = result.contributors + result.contradictions
            result_path_refs = {
                reference
                for factor in result_factors
                for reference in factor.related_source_refs
                if reference.startswith("control_coverage_path:")
            }
            coverage = project_exposure_coverage(
                tuple(
                    factor
                    for factor in material.assembled.factors
                    if factor.dimension is ExposureDimension.CONTROL_COVERAGE
                    and result_path_refs.intersection(factor.related_source_refs)
                )
            )
            coverage_reference_truncated = any(
                "coverage_reference_projection_truncated" in dimension.blind_spots
                for dimension in (
                    coverage.discover,
                    coverage.authorize,
                    coverage.prove,
                    coverage.contain,
                )
            )
            governance_refs = _dimension_refs(result, ExposureDimension.GOVERNANCE)
            governance_states = tuple(
                item.state
                for item in result.contributors
                if item.dimension is ExposureDimension.GOVERNANCE
                and item.source_type != "missing_authority"
            )
            governance_conflicted = any(
                item.dimension is ExposureDimension.GOVERNANCE
                for item in result.contradictions
            )
            conclusions.append(
                ExposureConclusion(
                    category_id=result.category_id,
                    category_version=result.category_version,
                    label=definition.label,
                    extent=result.extent,
                    proven_lower_bound=result.proven_lower_bound,
                    capability_refs=_dimension_refs(result, ExposureDimension.CAPABILITY),
                    data_refs=_dimension_refs(result, ExposureDimension.DATA),
                    runtime_refs=_dimension_refs(result, ExposureDimension.RUNTIME),
                    provider_refs=_dimension_refs(result, ExposureDimension.PROVIDER),
                    model_refs=_dimension_refs(result, ExposureDimension.MODEL),
                    identity_refs=_dimension_refs(result, ExposureDimension.IDENTITY),
                    permission_refs=_dimension_refs(result, ExposureDimension.PERMISSION),
                    reachability_refs=_dimension_refs(result, ExposureDimension.REACHABILITY),
                    usage_refs=_dimension_refs(result, ExposureDimension.USAGE),
                    governance_state=(
                        "unknown"
                        if governance_conflicted
                        else sorted(governance_states)[0]
                        if governance_states
                        else "unknown"
                    ),
                    confidence=result.confidence,
                    evidence_count=len(result.evidence_refs),
                    evidence_refs=result.evidence_refs,
                    evidence_quality=result.evidence_quality,
                    verification_status=result.verification_status,
                    collector_diversity=result.collector_diversity,
                    last_validation=_last_validation(result),
                    contributors=result.contributors,
                    contradictions=result.contradictions,
                    unknown_dimensions=result.unknown_dimensions,
                    reasoning_trace=result.reasoning_trace,
                    coverage=coverage,
                    recommendations=build_recommendations(
                        definition=definition,
                        result=result,
                        coverage=coverage,
                    ),
                    limitations=tuple(
                        sorted(
                            set(result.limitations)
                            | ({"governance_state_unavailable"} if not governance_refs else set())
                            | (
                                {"category_dimension_refs_truncated"}
                                if dimension_refs_truncated
                                else set()
                            )
                            | (
                                {"governance_evidence_conflicted"}
                                if governance_conflicted
                                else set()
                            )
                            | (
                                {"coverage_reference_projection_truncated"}
                                if coverage_reference_truncated
                                else set()
                            )
                        )
                    ),
                )
            )
        ordered = tuple(sorted(conclusions, key=lambda item: item.category_id))
        distribution = {
            extent: sum(1 for item in ordered if item.extent is extent)
            for extent in ExposureExtent
        }
        unknown_dimensions = tuple(
            sorted(
                {
                    dimension
                    for result in material.results
                    for dimension in result.unknown_dimensions
                },
                key=lambda item: item.value,
            )
        )
        all_conflicts = tuple(
            sorted(
                {
                    item.source_id
                    for result in material.results
                    for item in result.contradictions
                }
            )
        )
        conflicts = all_conflicts[:64]
        conflicts_truncated = len(all_conflicts) > len(conflicts)
        limitations: set[str] = set()
        result_projection_truncated = any(
            any(
                marker in item.limitations
                for marker in (
                    "category_contributors_truncated",
                    "category_contradictions_truncated",
                    "category_evidence_refs_truncated",
                    "collector_diversity_capped",
                    "category_dimension_refs_truncated",
                    "projection_conflicts_truncated",
                    "coverage_reference_projection_truncated",
                )
            )
            for item in ordered
        )
        if material.failed_authorities:
            limitations.add("source_authority_failure")
        if material.truncated:
            limitations.add("source_projection_truncated")
        if result_projection_truncated:
            limitations.add("category_projection_truncated")
        if conflicts_truncated:
            limitations.add("projection_conflicts_truncated")
        incomplete = bool(unknown_dimensions) or any(
            item.extent is ExposureExtent.UNKNOWN
            or item.verification_status.value != "verified"
            for item in ordered
        )
        if incomplete:
            limitations.add("required_evidence_incomplete")
        status = (
            CalculationStatus.PARTIAL
            if (
                material.failed_authorities
                or material.truncated
                or result_projection_truncated
                or conflicts_truncated
                or incomplete
            )
            else CalculationStatus.COMPLETE
        )
        return ExposureProjection(
            asset_id=asset_id,
            as_of=as_of,
            calculation_status=status,
            reasoning_methodology_id=REASONING_METHODOLOGY_ID,
            reasoning_rule_version=REASONING_RULE_VERSION,
            category_catalog_version=material.catalog.version,
            source_input_digest=material.assembled.input_digest,
            exposures=ordered,
            extent_distribution=distribution,
            unknown_dimensions=unknown_dimensions,
            failed_authorities=material.failed_authorities,
            conflicts=conflicts,
            limitations=tuple(sorted(limitations)),
            truncated=(
                material.truncated
                or result_projection_truncated
                or conflicts_truncated
            ),
        )

    def graph(
        self,
        db: Session,
        *,
        tenant_id: str,
        asset_id: str,
        category_id: str,
        as_of: datetime,
        max_nodes: int = 200,
        max_edges: int = 400,
    ) -> ExposureGraph:
        projection = self.project(
            db, tenant_id=tenant_id, asset_id=asset_id, as_of=as_of
        )
        return self.graph_from_projection(
            projection=projection,
            category_id=category_id,
            max_nodes=max_nodes,
            max_edges=max_edges,
        )

    def graph_from_projection(
        self,
        *,
        projection: ExposureProjection,
        category_id: str,
        max_nodes: int = 200,
        max_edges: int = 400,
    ) -> ExposureGraph:
        conclusion = next(
            (item for item in projection.exposures if item.category_id == category_id),
            None,
        )
        if conclusion is None:
            raise ExposureCategoryUnavailable("exposure category is unavailable")
        return build_exposure_graph(
            asset_id=projection.asset_id,
            conclusion=conclusion,
            factors=conclusion.contributors + conclusion.contradictions,
            max_nodes=max_nodes,
            max_edges=max_edges,
        )

    def timeline(
        self,
        *,
        projection: ExposureProjection,
        as_of: datetime,
        lookback_days: int = 30,
        limit: int = 200,
    ) -> ExposureTimelineProjection:
        """Return explicit unavailability until adjacent historical states exist.

        Current authorities are sufficient for an as-of projection but do not all
        retain immutable before/after versions. An empty list without this
        limitation would incorrectly mean that Hawk proved no changes occurred.
        """

        items = build_exposure_timeline(
            changes=(),
            rule_version=projection.reasoning_rule_version,
            as_of=as_of,
            lookback_days=lookback_days,
            limit=limit,
        )
        return ExposureTimelineProjection(
            items=items,
            limitations=(HISTORICAL_EXPOSURE_UNAVAILABLE,),
        )


__all__ = [
    "ExposureCategoryUnavailable",
    "ExposureReasoningService",
    "ExposureTimelineProjection",
    "HISTORICAL_EXPOSURE_UNAVAILABLE",
    "REASONING_METHODOLOGY_ID",
    "REASONING_RULE_VERSION",
]
