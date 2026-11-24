from __future__ import annotations

import ast
from pathlib import Path


MIGRATION = (
    Path(__file__).parents[1]
    / "app/db/migrations/versions/0077_execution_effect_closure.py"
)


def test_migration_0077_is_reversible_and_chained_to_0076() -> None:
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
        "revision": "0077_execution_effect_closure",
        "down_revision": "0076_agent_collective_security",
    }
    for table in (
        "effect_delivery_fences_v2",
        "effect_reservations_v2",
        "effect_reservation_transitions_v2",
        "execution_permit_effect_bindings_v2",
    ):
        assert f'op.create_table(\n        "{table}"' in source
        assert f'op.drop_table("{table}")' in source
    assert "effect_reservation_id" in source
    assert "effect_closure_state" in source
