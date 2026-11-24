from __future__ import annotations

from sqlalchemy import Index

from app.db.models.evidence_resolution import ERG_TABLE_MODELS
from app.db.session import Base


EXPECTED_TABLES = {
    "discovery_hypothesis_evaluations",
    "discovery_hypothesis_evaluation_edges",
    "discovery_collector_quality_snapshots",
    "discovery_observation_quality_snapshots",
    "discovery_ai_ecosystems",
    "discovery_ecosystem_memberships",
    "discovery_ecosystem_resolution_events",
    "discovery_ecosystem_history_members",
}


def test_erg_models_are_registered_and_tenant_indexed() -> None:
    assert set(ERG_TABLE_MODELS) == EXPECTED_TABLES
    assert EXPECTED_TABLES <= set(Base.metadata.tables)
    for table_name in EXPECTED_TABLES:
        table = Base.metadata.tables[table_name]
        indexes = [item for item in table.indexes if isinstance(item, Index)]
        assert indexes
        assert all(tuple(index.columns)[0].name == "tenant_id" for index in indexes)


def test_resolution_edges_retain_exposed_successor_factors() -> None:
    table = Base.metadata.tables["discovery_resolution_graph_edges"]
    assert {
        "collector_id",
        "source_surface",
        "signal_class",
        "observation_quality_factor",
        "collector_quality_factor",
        "base_confidence",
        "relationship_weight",
        "relationship_rule_id",
        "relationship_rule_version",
        "decay_policy_id",
        "decay_policy_version",
        "last_validated_at",
        "edge_schema_version",
        "edge_sequence",
        "predecessor_edge_id",
    } <= set(table.c.keys())
    unique_constraints = {
        constraint.name
        for constraint in table.constraints
        if constraint.__class__.__name__ == "UniqueConstraint"
    }
    assert "uq_discovery_resolution_graph_edge_tenant_predecessor" in unique_constraints


def test_erg_models_use_composite_tenant_foreign_keys_and_bounded_json() -> None:
    for table_name in EXPECTED_TABLES:
        table = Base.metadata.tables[table_name]
        if table_name != "discovery_collector_quality_snapshots":
            composite_fks = {
                tuple(element.parent.name for element in constraint.elements)
                for constraint in table.foreign_key_constraints
            }
            assert any(columns[:1] == ("tenant_id",) and len(columns) >= 2 for columns in composite_fks)
        constraint_sql = " ".join(
            str(item.sqltext) for item in table.constraints if hasattr(item, "sqltext")
        )
        json_columns = [column.name for column in table.columns if str(column.type) == "JSON"]
        for column in json_columns:
            assert column in constraint_sql
