from __future__ import annotations

from copy import deepcopy

import pytest


def action_v2() -> dict[str, object]:
    return {
        "schema_version": "2.0", "tenant_id": "tenant-a", "action_id": "action-a", "chain_id": "chain-a",
        "parent_action_id": None, "correlation_id": "correlation-a", "actor_principal": "user:a",
        "executing_principal": "agent:a", "represented_subjects": ["subject:a"], "resource_scopes": ["scope:a"],
        "authority_context": "authority:a", "business_purpose": "purpose:a", "environment": "production",
        "provider_runtime_context": "runtime:a",
        "action_semantics": {
            "action_class": "consequential", "operation": "write", "object_type": "record",
            "tool_or_service_ref": "tool:a", "tool_fingerprint": "fingerprint:a", "safe_parameters": {"x": "y"},
            "represented_subject_refs": ["subject:a"], "resource_refs": ["resource:a"], "counterparty_refs": [],
            "target_refs": ["target:a"], "destination_refs": ["destination:a"],
            "values_or_quantities": [{"currency": "USD", "value": "10"}], "authority_ref": "authority:a",
            "business_purpose_ref": "purpose:a", "side_effect": "external_write", "persistence": "none",
            "environment": "production", "reversibility": "compensatable", "expected_outcome_ref": "outcome:a",
        },
        "domain_profile_ref": "profile:a", "domain_profile_hash": "a" * 64,
        "materiality_profile_ref": "phase5-p0", "materiality_profile_hash": "b" * 64,
        "resolver_versions": {}, "policy_version_id": "policy:a", "policy_epoch": 1,
        "control_plan_id": "plan:a", "control_plan_digest": "c" * 64, "approval_requirement": "required",
        "delegation_digest": "d" * 64,
        "action_plan_binding": {
            "binding_type": "STANDALONE", "action_plan_id": None, "action_plan_digest": None,
            "action_plan_step_id": None, "action_plan_step_digest": None,
        },
        "unresolved_material": [], "evidence_refs": [], "created_at": "2026-08-25T00:00:00.000000Z",
    }


def test_v2_canonical_bytes_are_nfc_utf16_sorted_and_domain_separated() -> None:
    from app.services.action_integrity.canonical_v2 import canonical_action_hash_v2, canonical_json_bytes, domain_hash

    assert canonical_json_bytes({"\ue000": "Cafe\u0301", "\U00010000": "x"}) == (
        b'{"\xf0\x90\x80\x80":"x","\xee\x80\x80":"Caf\xc3\xa9"}'
    )
    action = action_v2()
    assert canonical_action_hash_v2(action) == canonical_action_hash_v2(dict(reversed(list(action.items()))))
    assert domain_hash("hawk:test:a", {"a": 1}) != domain_hash("hawk:test:b", {"a": 1})


@pytest.mark.parametrize("value", [2**53, -(2**53), float("inf"), float("nan")])
def test_v2_rejects_non_interoperable_numbers(value: object) -> None:
    from app.services.action_integrity.canonical_v2 import canonical_json_bytes

    with pytest.raises(ValueError):
        canonical_json_bytes({"value": value})


def test_v2_rejects_duplicate_nfc_keys_and_ambiguous_decimal() -> None:
    from app.services.action_integrity.canonical_v2 import canonical_action_bytes_v2, canonical_json_bytes

    with pytest.raises(ValueError, match="duplicate key"):
        canonical_json_bytes({"Cafe\u0301": 1, "Caf\u00e9": 2})
    action = action_v2()
    action["action_semantics"] = {**action["action_semantics"], "values_or_quantities": [{"value": "1.0"}]}
    with pytest.raises(ValueError, match="decimal"):
        canonical_action_bytes_v2(action)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"Cafe\\u0301":1,"Caf\\u00e9":2}',
        b'{"value":-0}',
        b'{"value":9007199254740992}',
        b'{"value":"\\ud800"}',
    ],
)
def test_raw_json_canonical_input_rejects_ambiguous_or_non_interoperable_tokens(raw: bytes) -> None:
    from app.services.action_integrity.canonical_v2 import parse_canonical_json

    with pytest.raises(ValueError):
        parse_canonical_json(raw)


def test_v2_requires_the_complete_closed_action_contract() -> None:
    from app.services.action_integrity.canonical_v2 import canonical_action_bytes_v2

    action = action_v2()
    action.pop("control_plan_digest")
    with pytest.raises(ValueError, match="fields"):
        canonical_action_bytes_v2(action)
    action = action_v2()
    action["unexpected"] = True
    with pytest.raises(ValueError, match="fields"):
        canonical_action_bytes_v2(action)


def test_v2_rejects_tuple_and_unknown_consequential_material() -> None:
    from app.services.action_integrity.canonical_v2 import canonical_action_bytes_v2, canonical_json_bytes

    with pytest.raises(ValueError, match="unsupported canonical type"):
        canonical_json_bytes(("not", "a", "json", "array"))
    action = action_v2()
    action["action_semantics"] = {**action["action_semantics"], "target_refs": ["UNKNOWN"]}
    with pytest.raises(ValueError, match="unresolved material"):
        canonical_action_bytes_v2(action)


@pytest.mark.parametrize(
    "binding_type, expected",
    [
        ("STANDALONE", {"action_plan_id": None, "action_plan_digest": None, "action_plan_step_id": None, "action_plan_step_digest": None}),
        ("PLAN_ROOT", {"action_plan_id": "plan-a", "action_plan_digest": "a" * 64, "action_plan_step_id": None, "action_plan_step_digest": None}),
        ("PLANNED_STEP", {"action_plan_id": "plan-a", "action_plan_digest": "a" * 64, "action_plan_step_id": "step-a", "action_plan_step_digest": "b" * 64}),
    ],
)
def test_v2_accepts_only_complete_tagged_plan_bindings(binding_type: str, expected: dict[str, object]) -> None:
    from app.services.action_integrity.canonical_v2 import canonical_action_bytes_v2

    action = action_v2()
    action["action_plan_binding"] = {"binding_type": binding_type, **expected}
    canonical_action_bytes_v2(action)
    invalid = deepcopy(action)
    invalid["action_plan_binding"].pop("action_plan_digest")
    with pytest.raises(ValueError, match="binding"):
        canonical_action_bytes_v2(invalid)
