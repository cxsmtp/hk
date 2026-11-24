from __future__ import annotations

from sqlalchemy import create_engine, inspect

from app.db.models.control_coverage import (
    ControlCoverageAssertion,
    ControlCoveragePath,
    ControlCoverageSnapshot,
    DeploymentSurface,
)
from app.db.session import Base


def test_control_coverage_tables_are_registered() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    names = set(inspect(engine).get_table_names())
    assert {
        "deployment_surfaces",
        "control_coverage_paths",
        "control_coverage_assertions",
        "control_coverage_snapshots",
    }.issubset(names)
    engine.dispose()


def test_models_expose_tenant_scoped_identity() -> None:
    tables = (
        DeploymentSurface.__table__,
        ControlCoveragePath.__table__,
        ControlCoverageAssertion.__table__,
        ControlCoverageSnapshot.__table__,
    )
    for table in tables:
        assert "tenant_id" in table.c

    constraint_names = {
        constraint.name
        for table in tables
        for constraint in table.constraints
        if constraint.name
    }
    assert "uq_deployment_surface_tenant_source" in constraint_names
    assert "uq_control_coverage_path_tenant_key" in constraint_names
    assert "uq_control_coverage_assertion_current" in constraint_names
    assert "uq_control_coverage_snapshot_input" in constraint_names


def test_assertion_and_path_foreign_keys_are_tenant_composite() -> None:
    assertion_fk = next(
        constraint
        for constraint in ControlCoverageAssertion.__table__.foreign_key_constraints
        if constraint.name == "fk_control_coverage_assertion_tenant_path"
    )
    surface_fk = next(
        constraint
        for constraint in ControlCoveragePath.__table__.foreign_key_constraints
        if constraint.name == "fk_control_coverage_path_tenant_surface"
    )
    assert [element.parent.name for element in assertion_fk.elements] == ["tenant_id", "path_id"]
    assert [element.parent.name for element in surface_fk.elements] == ["tenant_id", "deployment_surface_id"]
    assert surface_fk.ondelete == "RESTRICT"


def test_score_is_nullable_for_unknown_population() -> None:
    assert ControlCoverageSnapshot.__table__.c.headline_score.nullable is True
