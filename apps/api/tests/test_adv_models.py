from __future__ import annotations

from sqlalchemy import Index

from app.db.models.discovery_verification import ADV_TABLE_MODELS
from app.db.session import Base


EXPECTED_ADV_TABLES = {
    "discovery_verification_policies",
    "discovery_verification_policy_requirements",
    "discovery_verification_episodes",
    "discovery_verification_attempts",
    "discovery_verification_results",
    "discovery_verification_assertions",
    "discovery_verification_events",
}


def test_adv_models_are_registered_and_tenant_indexed() -> None:
    assert set(ADV_TABLE_MODELS) == EXPECTED_ADV_TABLES
    assert EXPECTED_ADV_TABLES <= set(Base.metadata.tables)
    for table_name in EXPECTED_ADV_TABLES:
        table = Base.metadata.tables[table_name]
        indexes = [item for item in table.indexes if isinstance(item, Index)]
        assert indexes
        assert all(tuple(index.columns)[0].name == "tenant_id" for index in indexes)


def test_adv_models_are_tenant_bound_append_only_records() -> None:
    for table_name in EXPECTED_ADV_TABLES:
        table = Base.metadata.tables[table_name]
        composite_foreign_keys = {
            tuple(element.parent.name for element in constraint.elements)
            for constraint in table.foreign_key_constraints
        }
        assert any(
            columns[:1] == ("tenant_id",) and len(columns) >= 2
            for columns in composite_foreign_keys
        )

        constraint_sql = " ".join(
            str(item.sqltext)
            for item in table.constraints
            if hasattr(item, "sqltext")
        )
        assert "input_digest" in constraint_sql
        for column in table.columns:
            if str(column.type) == "JSON":
                assert column.name in constraint_sql


def test_adv_assertion_does_not_copy_erg_confidence() -> None:
    assertion = Base.metadata.tables["discovery_verification_assertions"]
    assert "erg_evaluation_id" in assertion.c
    assert "confidence" not in assertion.c
    assert "effective_confidence" not in assertion.c


def test_adv_semantic_outcomes_and_coverage_are_constrained() -> None:
    result = Base.metadata.tables["discovery_verification_results"]
    result_checks = " ".join(
        str(item.sqltext) for item in result.constraints if hasattr(item, "sqltext")
    )
    for outcome in ("verified", "failed", "contradicted", "unsupported", "unknown"):
        assert outcome in result_checks

    assertion = Base.metadata.tables["discovery_verification_assertions"]
    assertion_checks = " ".join(
        str(item.sqltext)
        for item in assertion.constraints
        if hasattr(item, "sqltext")
    )
    assert "required_verified_count <= required_requirement_count" in assertion_checks
    assert "conclusion <> 'verified'" in assertion_checks


def test_existing_verification_tasks_bind_episode_and_requirement() -> None:
    task = Base.metadata.tables["discovery_verification_tasks"]
    assert {
        "verification_episode_id",
        "verification_requirement_id",
        "task_contract_version",
    } <= set(task.c.keys())
