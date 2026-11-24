from __future__ import annotations

from copy import deepcopy

import pytest

from test_phase5_canonical_action_v2 import action_v2


def test_closed_materiality_registry_is_utf8_ordered_and_complete() -> None:
    from app.services.action_integrity.materiality import MATERIAL_COLLECTION_SEMANTICS, MATERIAL_PATHS

    assert MATERIAL_PATHS == tuple(sorted(MATERIAL_PATHS, key=lambda value: value.encode("utf-8")))
    assert set(MATERIAL_PATHS) == set(MATERIAL_COLLECTION_SEMANTICS)
    assert MATERIAL_COLLECTION_SEMANTICS["action_semantics.values_or_quantities[*]"] == "UNORDERED_MULTISET"


def test_set_and_multiset_semantics_are_declared_not_inferred() -> None:
    from app.services.action_integrity.materiality import material_fields, material_fields_hash

    first = action_v2()
    first["resource_scopes"] = ["scope:z", "scope:a"]
    first["action_semantics"] = {**first["action_semantics"], "values_or_quantities": [{"value": "2"}, {"value": "1"}, {"value": "1"}]}
    reordered = deepcopy(first)
    reordered["resource_scopes"] = ["scope:a", "scope:z"]
    reordered["action_semantics"] = {**reordered["action_semantics"], "values_or_quantities": [{"value": "1"}, {"value": "2"}, {"value": "1"}]}
    assert material_fields_hash(first) == material_fields_hash(reordered)
    assert material_fields(first)["resource_scopes[*]"] == material_fields(reordered)["resource_scopes[*]"]


def test_missing_and_duplicate_material_values_fail_closed() -> None:
    from app.services.action_integrity.materiality import material_fields_hash

    missing = action_v2()
    missing.pop("business_purpose")
    with pytest.raises(ValueError, match="missing required"):
        material_fields_hash(missing)
    duplicate = action_v2()
    duplicate["resource_scopes"] = ["Cafe\u0301", "Caf\u00e9"]
    with pytest.raises(ValueError, match="duplicate canonical"):
        material_fields_hash(duplicate)


def test_every_declared_material_path_changes_its_own_field_hash() -> None:
    """The registry, not a hand-maintained comparison list, is authoritative."""
    from app.services.action_integrity.materiality import MATERIAL_PATHS, material_fields

    baseline = action_v2()
    before = material_fields(baseline)
    for path in MATERIAL_PATHS:
        candidate = deepcopy(baseline)
        target = candidate
        pieces = path.removesuffix("[*]").split(".")
        for piece in pieces[:-1]:
            target = target[piece]
        field = pieces[-1]
        value = target[field]
        if path.endswith("[*]"):
            assert isinstance(value, list)
            value.append({"value": "11"} if field == "values_or_quantities" else f"changed:{field}")
        elif isinstance(value, dict):
            value["changed"] = "value"
        elif isinstance(value, int):
            target[field] = value + 1
        elif value is None:
            target[field] = "parent:changed"
        elif field == "action_plan_binding":
            target[field] = {
                "binding_type": "PLAN_ROOT", "action_plan_id": "plan:changed",
                "action_plan_digest": "e" * 64, "action_plan_step_id": None,
                "action_plan_step_digest": None,
            }
        else:
            target[field] = f"{value}:changed"
        assert material_fields(candidate)[path] != before[path], path
