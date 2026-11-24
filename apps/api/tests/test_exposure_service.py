from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.session import Base
from app.services.hmair.exposure.contracts import (
    CalculationStatus,
    ExposureDimension,
    ExposureExtent,
    ExposureGraphNodeType,
    FreshnessState,
    VerificationStatus,
)
from app.services.hmair.exposure.category_catalog import load_category_catalog
from app.services.hmair.exposure.contracts import ExposureFactor
from app.services.hmair.exposure.reasoning_service import (
    ExposureReasoningService,
    _qualify_categories,
)
from app.services.hmair.exposure.source_reader import (
    ExposureAssetSource,
    ExposureSourceReader,
    ExposureSourceRecord,
    ExposureSourceSnapshot,
)
from test_exposure_source_reader import _seed_asset_sources


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine, autoflush=False, expire_on_commit=False)
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        engine.dispose()


def _row_counts(db: Session) -> dict[str, int]:
    return {
        table.name: int(db.scalar(select(func.count()).select_from(table)) or 0)
        for table in Base.metadata.sorted_tables
    }


class _PartialReader(ExposureSourceReader):
    def read(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        snapshot = super().read(*args, **kwargs)
        return snapshot.model_copy(
            update={"failed_authorities": ("control_coverage",)}
        )


def _path_record(
    *,
    dimension: ExposureDimension,
    source_id: str,
    state: str,
    path_id: str,
    source_type: str = "test_authority",
    confidence: float | None = 0.9,
) -> ExposureSourceRecord:
    return ExposureSourceRecord(
        tenant_id="tenant-path-scope",
        authority="control_coverage" if dimension is ExposureDimension.CONTROL_COVERAGE else "test",
        source_type=source_type,
        source_id=source_id,
        dimension=dimension,
        state=state,
        evidence_refs=(f"evidence-{source_id}",),
        related_source_refs=(f"control_coverage_path:{path_id}",),
        confidence=confidence,
        verification_status=VerificationStatus.VERIFIED,
        freshness=FreshnessState.FRESH,
        observed_at=NOW,
        validated_at=NOW,
        methodology_id="path-scope-test/1.0",
        collector_group=source_type,
    )


class _PathScopedReader(ExposureSourceReader):
    def __init__(self) -> None:
        super().__init__()
        self.read_count = 0

    def read(self, _db, *, tenant_id: str, asset_id: str, as_of: datetime):  # type: ignore[no-untyped-def]
        self.read_count += 1
        assert tenant_id == "tenant-path-scope"
        path_a = (
            _path_record(dimension=ExposureDimension.CAPABILITY, source_id="coding-capability", state="filesystem_write", path_id="coding"),
            _path_record(dimension=ExposureDimension.REACHABILITY, source_id="coding-reach", state="filesystem:verified", path_id="coding"),
            _path_record(dimension=ExposureDimension.PERMISSION, source_id="coding-permission", state="write", path_id="coding"),
            _path_record(dimension=ExposureDimension.IDENTITY, source_id="coding-identity", state="workload_identity:active", path_id="coding"),
            _path_record(dimension=ExposureDimension.GOVERNANCE, source_id="coding-governance", state="unapproved", path_id="coding"),
            _path_record(
                dimension=ExposureDimension.CONTROL_COVERAGE,
                source_id="coding-authorization",
                state="authorization:not_covered",
                path_id="coding",
                source_type="control_coverage_assertion",
                confidence=None,
            ),
        )
        path_b = (
            _path_record(dimension=ExposureDimension.CAPABILITY, source_id="research-capability", state="web_search", path_id="research"),
            _path_record(dimension=ExposureDimension.REACHABILITY, source_id="research-reach", state="internet:verified", path_id="research"),
            _path_record(dimension=ExposureDimension.IDENTITY, source_id="research-identity", state="user:active", path_id="research"),
            _path_record(dimension=ExposureDimension.GOVERNANCE, source_id="research-governance", state="approved", path_id="research"),
            _path_record(
                dimension=ExposureDimension.CONTROL_COVERAGE,
                source_id="research-authorization",
                state="authorization:covered",
                path_id="research",
                source_type="control_coverage_assertion",
                confidence=None,
            ),
        )
        return ExposureSourceSnapshot(
            asset=ExposureAssetSource(
                tenant_id=tenant_id,
                asset_id=asset_id,
                asset_type="runtime",
                governance_state="approved",
                resolution_confidence=0.9,
                evidence_bundle_id="bundle-path-scope",
                last_seen_at=as_of,
            ),
            as_of=as_of,
            raw_sources=path_a + path_b,
        )


class _LargeBoundedReader(ExposureSourceReader):
    def read(self, _db, *, tenant_id: str, asset_id: str, as_of: datetime):  # type: ignore[no-untyped-def]
        path_id = "large-bounded"
        required = (
            _path_record(dimension=ExposureDimension.CAPABILITY, source_id="capability", state="filesystem_write", path_id=path_id),
            _path_record(dimension=ExposureDimension.REACHABILITY, source_id="reachability", state="filesystem:verified", path_id=path_id),
            _path_record(dimension=ExposureDimension.PERMISSION, source_id="permission", state="write", path_id=path_id),
            _path_record(dimension=ExposureDimension.IDENTITY, source_id="identity", state="workload_identity:active", path_id=path_id),
            _path_record(dimension=ExposureDimension.GOVERNANCE, source_id="governance", state="approved", path_id=path_id),
            _path_record(
                dimension=ExposureDimension.CONTROL_COVERAGE,
                source_id="authorization",
                state="authorization:not_covered",
                path_id=path_id,
                source_type="control_coverage_assertion",
                confidence=None,
            ),
        )
        optional = tuple(
            _path_record(
                dimension=ExposureDimension.USAGE,
                source_id=f"usage-{index:03d}",
                state="high_usage",
                path_id=path_id,
                source_type=f"collector-{index:03d}",
            )
            for index in range(251)
        )
        return ExposureSourceSnapshot(
            asset=ExposureAssetSource(
                tenant_id=tenant_id,
                asset_id=asset_id,
                asset_type="runtime",
                governance_state="approved",
                resolution_confidence=0.9,
                evidence_bundle_id="bundle-large-bounded",
                last_seen_at=as_of,
            ),
            as_of=as_of,
            raw_sources=required + optional,
        )


class _GovernanceConflictReader(_PathScopedReader):
    def read(self, _db, *, tenant_id: str, asset_id: str, as_of: datetime):  # type: ignore[no-untyped-def]
        snapshot = super().read(
            _db, tenant_id=tenant_id, asset_id=asset_id, as_of=as_of
        )
        sources = tuple(
            item.model_copy(update={"state": "approved"})
            if item.source_id == "coding-governance"
            else item
            for item in snapshot.raw_sources
        ) + (
            _path_record(
                dimension=ExposureDimension.GOVERNANCE,
                source_id="coding-shadow-governance",
                state="unmanaged:confirmed_shadow",
                path_id="coding",
            ),
        )
        return snapshot.model_copy(update={"raw_sources": sources})


class _TruncatedExactPathReader(_PathScopedReader):
    def read(self, _db, *, tenant_id: str, asset_id: str, as_of: datetime):  # type: ignore[no-untyped-def]
        snapshot = super().read(
            _db, tenant_id=tenant_id, asset_id=asset_id, as_of=as_of
        )
        exact = tuple(
            item
            for item in snapshot.raw_sources
            if "control_coverage_path:coding" in item.related_source_refs
        )
        return snapshot.model_copy(update={"raw_sources": exact, "truncated": True})


class _ConflictOverflowReader(_PathScopedReader):
    def read(self, _db, *, tenant_id: str, asset_id: str, as_of: datetime):  # type: ignore[no-untyped-def]
        snapshot = super().read(
            _db, tenant_id=tenant_id, asset_id=asset_id, as_of=as_of
        )
        conflicts = tuple(
            _path_record(
                dimension=ExposureDimension.GOVERNANCE,
                source_id=f"governance-overflow-{index:03d}",
                state="approved" if index % 2 == 0 else "unmanaged:confirmed_shadow",
                path_id="coding",
            )
            for index in range(130)
        )
        return snapshot.model_copy(update={"raw_sources": snapshot.raw_sources + conflicts})


class _CoverageReferenceOverflowReader(_PathScopedReader):
    def read(self, _db, *, tenant_id: str, asset_id: str, as_of: datetime):  # type: ignore[no-untyped-def]
        snapshot = super().read(
            _db, tenant_id=tenant_id, asset_id=asset_id, as_of=as_of
        )
        base = tuple(
            item for item in snapshot.raw_sources
            if not (
                item.dimension is ExposureDimension.CONTROL_COVERAGE
                and "control_coverage_path:coding" in item.related_source_refs
            )
        )
        assertions = tuple(
            _path_record(
                dimension=ExposureDimension.CONTROL_COVERAGE,
                source_id="shared-authorization-source",
                state="authorization:not_covered",
                path_id="coding",
                source_type="control_coverage_assertion",
                confidence=None,
            ).model_copy(
                update={
                    "related_source_refs": (
                        "control_coverage_path:coding",
                        f"control_coverage_assertion:assertion-{index:03d}",
                    )
                }
            )
            for index in range(129)
        )
        return snapshot.model_copy(update={"raw_sources": base + assertions})


def test_service_projects_only_qualified_categories_with_exact_versions(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="exposure-service")
    projection = ExposureReasoningService().project(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        as_of=NOW,
    )

    assert projection.asset_id == asset.asset_id
    assert projection.calculation_status is CalculationStatus.PARTIAL
    assert {item.category_id for item in projection.exposures} == {
        "coding_exposure",
        "persistent_side_effect_exposure",
    }
    assert projection.reasoning_methodology_id == "ai-exposure-reasoning/1.2"
    assert projection.reasoning_rule_version == "1.2.0"
    assert projection.category_catalog_version == "1.1.0"
    assert len(projection.source_input_digest) == 64
    assert sum(projection.extent_distribution.values()) == len(projection.exposures)
    assert set(projection.extent_distribution) == set(ExposureExtent)
    assert "score" not in projection.model_dump(mode="json")
    assert all(item.coverage.contain.state.value == "unknown" for item in projection.exposures)
    assert all(item.extent is ExposureExtent.UNKNOWN for item in projection.exposures)
    assert "required_evidence_incomplete" in projection.limitations


def test_service_marks_bounded_category_projection_partial_instead_of_failing(
    db: Session,
) -> None:
    projection = ExposureReasoningService(source_reader=_LargeBoundedReader()).project(
        db,
        tenant_id="tenant-large-bounded",
        asset_id="11111111-1111-1111-1111-111111111111",
        as_of=NOW,
    )

    coding = next(item for item in projection.exposures if item.category_id == "coding_exposure")
    assert projection.calculation_status is CalculationStatus.PARTIAL
    assert projection.truncated is True
    assert "category_projection_truncated" in projection.limitations
    assert len(coding.contributors) == 256
    assert coding.collector_diversity == 64
    assert "category_contributors_truncated" in coding.limitations
    assert "category_evidence_refs_truncated" in coding.limitations
    assert "collector_diversity_capped" in coding.limitations


def test_truncated_source_projection_withholds_exact_extent_but_preserves_lower_bound(
    db: Session,
) -> None:
    projection = ExposureReasoningService(
        source_reader=_TruncatedExactPathReader()
    ).project(
        db,
        tenant_id="tenant-path-scope",
        asset_id="33333333-3333-4333-8333-333333333333",
        as_of=NOW,
    )

    coding = next(item for item in projection.exposures if item.category_id == "coding_exposure")
    assert coding.extent is ExposureExtent.UNKNOWN
    assert coding.proven_lower_bound is ExposureExtent.MATERIAL
    assert coding.confidence is None
    assert "source_projection_truncated" in coding.limitations
    assert projection.calculation_status is CalculationStatus.PARTIAL
    assert projection.truncated is True


def test_projection_caps_conflict_refs_and_marks_partial_instead_of_failing(
    db: Session,
) -> None:
    projection = ExposureReasoningService(
        source_reader=_ConflictOverflowReader()
    ).project(
        db,
        tenant_id="tenant-path-scope",
        asset_id="55555555-5555-4555-8555-555555555555",
        as_of=NOW,
    )

    assert len(projection.conflicts) == 64
    assert projection.truncated is True
    assert projection.calculation_status is CalculationStatus.PARTIAL
    assert "projection_conflicts_truncated" in projection.limitations


def test_nested_coverage_reference_truncation_marks_conclusion_and_projection_partial(
    db: Session,
) -> None:
    projection = ExposureReasoningService(
        source_reader=_CoverageReferenceOverflowReader()
    ).project(
        db,
        tenant_id="tenant-path-scope",
        asset_id="99999999-9999-4999-8999-999999999999",
        as_of=NOW,
    )
    coding = next(item for item in projection.exposures if item.category_id == "coding_exposure")

    assert coding.coverage.authorize.state.value == "unknown"
    assert "coverage_reference_projection_truncated" in coding.coverage.authorize.blind_spots
    assert "coverage_reference_projection_truncated" in coding.limitations
    assert projection.calculation_status is CalculationStatus.PARTIAL
    assert projection.truncated is True
    assert "category_projection_truncated" in projection.limitations


def test_service_headline_governance_is_unknown_when_required_evidence_conflicts(
    db: Session,
) -> None:
    projection = ExposureReasoningService(
        source_reader=_GovernanceConflictReader()
    ).project(
        db,
        tenant_id="tenant-path-scope",
        asset_id="22222222-2222-2222-2222-222222222222",
        as_of=NOW,
    )

    coding = next(item for item in projection.exposures if item.category_id == "coding_exposure")
    assert coding.extent is ExposureExtent.UNKNOWN
    assert coding.governance_state == "unknown"
    assert "governance_evidence_conflicted" in coding.limitations


def test_service_marks_authority_failure_partial_not_zero(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="exposure-partial")
    projection = ExposureReasoningService(source_reader=_PartialReader()).project(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        as_of=NOW,
    )

    assert projection.calculation_status is CalculationStatus.PARTIAL
    assert projection.failed_authorities == ("control_coverage",)
    assert all(item.extent is ExposureExtent.UNKNOWN for item in projection.exposures)
    assert "source_authority_failure" in projection.limitations


def test_service_graph_links_exact_asset_category_and_sources(db: Session) -> None:
    seed, asset, capability = _seed_asset_sources(db, suffix="exposure-graph-service")
    graph = ExposureReasoningService().graph(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        category_id="coding_exposure",
        as_of=NOW,
        max_nodes=20,
        max_edges=20,
    )

    root = next(node for node in graph.nodes if node.node_type is ExposureGraphNodeType.AI_ASSET)
    assert root.source_id == asset.asset_id
    assert capability.capability_id in {node.source_id for node in graph.nodes}
    assert all(edge.source_refs for edge in graph.edges)


def test_service_projection_does_not_cache_or_write(db: Session) -> None:
    seed, asset, _ = _seed_asset_sources(db, suffix="exposure-no-write")
    db.expunge_all()
    before = _row_counts(db)

    first = ExposureReasoningService().project(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        as_of=NOW,
    )
    second = ExposureReasoningService().project(
        db,
        tenant_id=seed["tenant_id"],
        asset_id=asset.asset_id,
        as_of=NOW,
    )

    assert first == second
    assert _row_counts(db) == before
    assert not db.new
    assert not db.dirty
    assert not db.deleted


def test_category_coverage_and_graph_are_scoped_to_the_exact_evidence_path(db: Session) -> None:
    reader = _PathScopedReader()
    service = ExposureReasoningService(source_reader=reader)
    projection = service.project(
        db,
        tenant_id="tenant-path-scope",
        asset_id="00000000-0000-4000-8000-000000000123",
        as_of=NOW,
    )
    coding = next(item for item in projection.exposures if item.category_id == "coding_exposure")
    research = next(item for item in projection.exposures if item.category_id == "research_exposure")
    assert coding.coverage.authorize.state.value == "not_covered"
    assert coding.coverage.authorize.path_ids == ("coding",)
    assert research.coverage.authorize.state.value == "covered"
    assert research.coverage.authorize.path_ids == ("research",)

    graph = service.graph_from_projection(
        projection=projection,
        category_id="coding_exposure",
    )
    graph_source_ids = {node.source_id for node in graph.nodes}
    assert "coding-capability" in graph_source_ids
    assert "research-capability" not in graph_source_ids


def test_graph_reads_source_authorities_once(db: Session) -> None:
    reader = _PathScopedReader()
    service = ExposureReasoningService(source_reader=reader)
    service.graph(
        db,
        tenant_id="tenant-path-scope",
        asset_id="00000000-0000-4000-8000-000000000123",
        category_id="coding_exposure",
        as_of=NOW,
    )
    assert reader.read_count == 1


def test_stale_or_unverified_capability_does_not_select_a_specific_category() -> None:
    base = ExposureFactor(
        dimension=ExposureDimension.CAPABILITY,
        source_type="discovery_capability",
        source_id="historical-filesystem",
        state="filesystem_write",
        evidence_refs=("evidence-historical",),
        confidence=0.9,
        verification_status=VerificationStatus.VERIFIED,
        freshness=FreshnessState.STALE,
        observed_at=NOW,
        validated_at=NOW,
        methodology_id="category-qualification-test/1.0",
    )
    catalog = load_category_catalog()
    assert [item.category_id for item in _qualify_categories(catalog, (base,))] == [
        "unknown_exposure"
    ]
    unverified = base.model_copy(
        update={
            "freshness": FreshnessState.FRESH,
            "verification_status": VerificationStatus.UNKNOWN,
        }
    )
    assert [
        item.category_id for item in _qualify_categories(catalog, (unverified,))
    ] == ["unknown_exposure"]
