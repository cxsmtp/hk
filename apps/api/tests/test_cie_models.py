from __future__ import annotations

from sqlalchemy import Index

from app.db.models.capability_inference import CIE_TABLE_MODELS
from app.db.session import Base


EXPECTED_TABLES = {
    "discovery_capability_inference_runs",
    "discovery_capability_evidence",
    "discovery_capability_genomes",
    "discovery_capability_events",
}


def test_cie_append_only_models_are_registered_with_tenant_first_indexes() -> None:
    assert set(CIE_TABLE_MODELS) == EXPECTED_TABLES
    assert EXPECTED_TABLES <= set(Base.metadata.tables)
    for table_name in EXPECTED_TABLES:
        table = Base.metadata.tables[table_name]
        indexes = [item for item in table.indexes if isinstance(item, Index)]
        assert indexes
        assert all(tuple(index.columns)[0].name == "tenant_id" for index in indexes)


def test_cie_models_have_tenant_composite_references_and_bounded_json() -> None:
    run_table = Base.metadata.tables["discovery_capability_inference_runs"]
    evidence_table = Base.metadata.tables["discovery_capability_evidence"]
    genome_table = Base.metadata.tables["discovery_capability_genomes"]
    event_table = Base.metadata.tables["discovery_capability_events"]

    def constraint_sql(table) -> str:
        return " ".join(str(item.sqltext) for item in table.constraints if hasattr(item, "sqltext"))

    assert "observation_ids_json" in constraint_sql(run_table)
    assert "supporting_signal_ids_json" in constraint_sql(evidence_table)
    assert "capabilities_json" in constraint_sql(genome_table)
    assert "evidence_references_json" in constraint_sql(event_table)

    for table in (evidence_table, genome_table, event_table):
        composite_fks = {
            tuple(element.parent.name for element in constraint.elements)
            for constraint in table.foreign_key_constraints
        }
        assert any(columns[:1] == ("tenant_id",) and len(columns) >= 2 for columns in composite_fks)

