from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app.db.models.control_coverage import (
    ControlCoverageAssertion,
    ControlCoveragePath,
    ControlCoverageSnapshot,
)
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.control_coverage.calculator import AssertionView, summarize_assertions
from app.services.control_coverage.service import calculate_tenant_control_coverage


def _assertion(
    path_id: str,
    dimension: str,
    state: str,
    *,
    identity_ref: str = "user:u1",
) -> AssertionView:
    return AssertionView(
        assertion_id=f"{path_id}:{dimension}",
        path_id=path_id,
        asset_ref="asset:a1",
        identity_ref=identity_ref,
        runtime_ref="runtime:r1",
        deployment_surface_ref="gateway:g1",
        dimension=dimension,
        state=state,
    )


def _seeded_assertions() -> list[AssertionView]:
    return [
        _assertion("p1", "discovery", "covered"),
        _assertion("p1", "identity", "covered"),
        _assertion("p2", "discovery", "not_covered", identity_ref="user:u2"),
        _assertion("p2", "identity", "unknown", identity_ref="user:u2"),
    ]


def test_headline_is_micro_aggregation_without_weights() -> None:
    assertions = [
        _assertion("p1", "discovery", "covered"),
        _assertion("p1", "identity", "unknown"),
        _assertion("p2", "discovery", "not_covered"),
        _assertion("p2", "identity", "covered"),
    ]
    summary = summarize_assertions(assertions)
    assert summary.headline_counts.denominator == 4
    assert summary.headline_score == 50.0


def test_asset_and_user_projection_does_not_change_headline() -> None:
    assertions = _seeded_assertions()
    baseline = summarize_assertions(assertions)
    by_user = summarize_assertions(assertions, identity_ref="user:u1")
    assert baseline.headline_counts == summarize_assertions(assertions).headline_counts
    assert by_user.headline_counts.denominator < baseline.headline_counts.denominator


def test_not_applicable_is_excluded_and_empty_is_null() -> None:
    summary = summarize_assertions([_assertion("p1", "bypass", "not_applicable")])
    assert summary.headline_counts.denominator == 0
    assert summary.headline_score is None


def test_unknown_dimension_or_state_is_rejected() -> None:
    with pytest.raises(ValueError):
        summarize_assertions([_assertion("p1", "invented", "covered")])
    with pytest.raises(ValueError):
        summarize_assertions([_assertion("p1", "identity", "probably")])


def test_tenant_calculation_is_idempotent_and_stale_evidence_becomes_unknown() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a"))
        db.add(
            RuntimeEvent(
                event_id="event-coverage-1",
                tenant_id="tenant-a",
                source_surface="browser",
                event_type="observed_action",
                user_id="user-1",
                app_id="chat-app",
                metadata_json={
                    "provider": "openai",
                    "model": "gpt-5",
                    "tool_name": "knowledge.search",
                    "control_mode": "telemetry_only",
                },
                created_at=now,
            )
        )
        db.flush()

        first = calculate_tenant_control_coverage(db, tenant_id="tenant-a", now=now)
        second = calculate_tenant_control_coverage(db, tenant_id="tenant-a", now=now)

        assert first.snapshot.id == second.snapshot.id
        assert db.scalar(select(func.count()).select_from(ControlCoveragePath)) == 1
        assert db.scalar(select(func.count()).select_from(ControlCoverageAssertion)) == 7
        assert db.scalar(select(func.count()).select_from(ControlCoverageSnapshot)) == 1
        assert first.summary.headline_counts.denominator == 7
        assert first.snapshot.input_watermarks["runtime_event"] == "event-coverage-1"

        stale = calculate_tenant_control_coverage(
            db,
            tenant_id="tenant-a",
            now=now + timedelta(days=2),
        )

        assert stale.snapshot.id != first.snapshot.id
        assert db.scalar(select(func.count()).select_from(ControlCoveragePath)) == 1
        assert db.scalar(select(func.count()).select_from(ControlCoverageSnapshot)) == 2
        states = db.scalars(
            select(ControlCoverageAssertion.state).where(ControlCoverageAssertion.tenant_id == "tenant-a")
        ).all()
        assert states == ["unknown"] * 7
    engine.dispose()


def test_phase5_methodology_persists_exactly_thirteen_conservative_dimensions() -> None:
    from app.core.control_coverage import PHASE5_METHODOLOGY_VERSION, PHASE5_V2_DIMENSIONS

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    try:
        with Session(engine) as db:
            db.add(Tenant(id="tenant-phase5", name="Phase 5", slug="phase5-coverage"))
            db.add(RuntimeEvent(event_id="event-phase5", tenant_id="tenant-phase5", source_surface="browser", event_type="observed_action", user_id="user-1", app_id="chat-app", metadata_json={}, created_at=now))
            db.flush()
            result = calculate_tenant_control_coverage(db, tenant_id="tenant-phase5", now=now, methodology_version=PHASE5_METHODOLOGY_VERSION)
            assert tuple(sorted(result.summary.dimensions)) == tuple(sorted(PHASE5_V2_DIMENSIONS))
            assert result.snapshot.methodology_version == PHASE5_METHODOLOGY_VERSION
            assert result.summary.headline_counts.denominator == 13
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_calculation_validates_window_and_is_tenant_scoped() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    with Session(engine) as db:
        db.add_all(
            [
                Tenant(id="tenant-a", name="Tenant A", slug="tenant-a"),
                Tenant(id="tenant-b", name="Tenant B", slug="tenant-b"),
            ]
        )
        db.add(
            RuntimeEvent(
                event_id="event-tenant-b",
                tenant_id="tenant-b",
                source_surface="sdk",
                event_type="observed_action",
                metadata_json={},
                created_at=now,
            )
        )
        db.flush()

        result = calculate_tenant_control_coverage(db, tenant_id="tenant-a", now=now)
        assert result.paths == ()
        assert result.summary.headline_score is None
        assert result.snapshot.diagnostics == ["no_observed_paths"]

        with pytest.raises(ValueError):
            calculate_tenant_control_coverage(db, tenant_id="tenant-a", now=now, window_days=0)
        with pytest.raises(ValueError):
            calculate_tenant_control_coverage(db, tenant_id="tenant-a", now=now, window_days=91)
    engine.dispose()
