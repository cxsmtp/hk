from __future__ import annotations

from copy import deepcopy

from test_phase5_canonical_action_v2 import action_v2


def test_exact_semantic_and_material_results_are_explicit() -> None:
    from app.services.action_integrity.canonical_v2 import semantic_equivalence

    expected = action_v2()
    assert semantic_equivalence(expected, deepcopy(expected))["result"] == "EXACT_MATCH"

    non_material = deepcopy(expected)
    non_material["correlation_id"] = "correlation-b"
    result = semantic_equivalence(expected, non_material)
    assert result["result"] == "SEMANTIC_MATCH"
    assert result["non_material_differences"] == ["correlation_id"]

    material = deepcopy(expected)
    material["action_semantics"]["destination_refs"] = ["destination:b"]
    result = semantic_equivalence(expected, material)
    assert result["result"] == "NOT_EQUIVALENT"
    assert result["material_differences"] == ["action_semantics.destination_refs[*]"]


def test_cross_version_and_unresolved_comparisons_never_become_equivalent() -> None:
    from app.services.action_integrity.canonical_v2 import semantic_equivalence

    action = action_v2()
    v1 = deepcopy(action)
    v1["schema_version"] = "1.1"
    assert semantic_equivalence(action, v1)["result"] == "UNKNOWN"

    unresolved = deepcopy(action)
    unresolved["unresolved_material"] = ["target_resolution"]
    result = semantic_equivalence(action, unresolved)
    assert result["result"] == "UNKNOWN"
    assert result["unresolved_differences"] == ["target_resolution"]
