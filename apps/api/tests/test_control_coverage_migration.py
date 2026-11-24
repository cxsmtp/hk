from __future__ import annotations

from pathlib import Path


MIGRATION = Path("app/db/migrations/versions/0045_control_coverage.py")


def test_control_coverage_migration_is_linear_and_additive() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    assert 'revision = "0045_control_coverage"' in source
    assert 'down_revision = "0044_canonical_evidence_bundles"' in source
    for table in (
        "deployment_surfaces",
        "control_coverage_paths",
        "control_coverage_assertions",
        "control_coverage_snapshots",
    ):
        assert f'"{table}"' in source
        assert f'op.create_table(\n        "{table}"' in source
    assert "op.alter_column" not in source


def test_downgrade_drops_only_new_tables_in_dependency_order() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    downgrade = source.split("def downgrade()", maxsplit=1)[1]
    order = [
        downgrade.index('op.drop_table("control_coverage_assertions")'),
        downgrade.index('op.drop_table("control_coverage_snapshots")'),
        downgrade.index('op.drop_table("control_coverage_paths")'),
        downgrade.index('op.drop_table("deployment_surfaces")'),
    ]
    assert order == sorted(order)
