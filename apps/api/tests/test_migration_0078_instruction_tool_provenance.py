from __future__ import annotations

import ast
from pathlib import Path


MIGRATION = Path(__file__).parents[1] / "app/db/migrations/versions/0078_instruction_tool_provenance.py"


def test_migration_0078_is_reversible_and_chained_to_0077() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    tree = ast.parse(source)
    assignments = {
        node.targets[0].id: ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in {"revision", "down_revision"}
    }
    assert assignments == {
        "revision": "0078_instruction_tool_provenance",
        "down_revision": "0077_execution_effect_closure",
    }
    for table in (
        "instruction_provenance_sets",
        "instruction_provenance_records",
        "open_weight_attribution_evidence",
        "tool_principal_bindings",
        "tool_lifecycle_events",
        "tool_action_provenance_bindings",
    ):
        assert f'op.create_table(\n        "{table}"' in source
        assert f'op.drop_table("{table}")' in source
