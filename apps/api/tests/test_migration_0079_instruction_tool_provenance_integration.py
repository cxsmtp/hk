from __future__ import annotations

import ast
from pathlib import Path


MIGRATION = Path(__file__).parents[1] / "app/db/migrations/versions/0079_instruction_tool_provenance_integration.py"


def test_migration_0079_is_reversible_and_chained_to_0078() -> None:
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
        "revision": "0079_instruction_tool_provenance_integration",
        "down_revision": "0078_instruction_tool_provenance",
    }
    for column in (
        "principal_assertion_algorithm",
        "signing_key_id",
        "assertion_digest",
        "assertion_signature",
        "assertion_assurance",
        "assertion_nonce",
        "assertion_issued_at",
        "assertion_expires_at",
        "principal_assertion_valid",
    ):
        assert f'op.add_column("tool_principal_bindings", sa.Column("{column}"' in source
        assert f'op.drop_column("tool_principal_bindings", "{column}")' in source
