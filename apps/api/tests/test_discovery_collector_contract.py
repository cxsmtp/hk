from __future__ import annotations

from datetime import datetime, timezone
import json

import pytest
from pydantic import ValidationError

from app.services.discovery_collector_contract import DiscoveryCollectorContract


def _valid_contract(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "collector_id": "gateway-primary",
        "tenant_id": "tenant-a",
        "collector_type": "llm_gateway",
        "collector_version": "1.4.2",
        "source_system": "hawk.llm_gateway",
        "health": "healthy",
        "permissions": {
            "runtime.events.read": True,
            "runtime.actions.authorize": None,
        },
        "last_success": "2026-07-23T16:30:00+04:00",
        "last_failure": None,
        "data_residency": "uae-north",
        "control_capability": "monitor_only",
        "observation_types_emitted": [
            "runtime.action",
            "runtime.health",
        ],
        "schema_version": "1.0",
    }
    payload.update(overrides)
    return payload


def test_valid_contract_is_versioned_tenant_scoped_and_immutable() -> None:
    contract = DiscoveryCollectorContract.model_validate(_valid_contract())

    assert contract.collector_id == "gateway-primary"
    assert contract.tenant_id == "tenant-a"
    assert contract.health == "healthy"
    assert contract.control_capability == "monitor_only"
    assert contract.schema_version == "1.0"
    assert contract.last_success == datetime(2026, 7, 23, 12, 30, tzinfo=timezone.utc)
    assert contract.observation_types_emitted == ("runtime.action", "runtime.health")

    with pytest.raises(ValidationError):
        contract.health = "offline"  # type: ignore[misc]
    with pytest.raises(TypeError):
        contract.permissions["runtime.events.read"] = False


def test_permissions_resist_base_dict_mutation_and_preserve_hash() -> None:
    contract = DiscoveryCollectorContract.model_validate(_valid_contract())
    original_hash = contract.contract_hash

    with pytest.raises(TypeError):
        dict.__setitem__(contract.permissions, "unexpected.permission", True)

    assert contract.contract_hash == original_hash
    assert "unexpected.permission" not in contract.permissions


def test_unknowns_are_explicit_and_do_not_infer_capability() -> None:
    contract = DiscoveryCollectorContract.model_validate(
        _valid_contract(
            collector_type="mcp_gateway",
            health="unknown",
            permissions={"unknown": None},
            last_success=None,
            last_failure=None,
            data_residency="unknown",
            control_capability="unknown",
        )
    )

    assert contract.health == "unknown"
    assert contract.permissions == {"unknown": None}
    assert contract.last_success is None
    assert contract.last_failure is None
    assert contract.data_residency == "unknown"
    assert contract.control_capability == "unknown"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("health", "active"),
        ("health", "ok"),
        ("control_capability", "authorize"),
        ("control_capability", "partial"),
        ("schema_version", "2.0"),
        ("tenant_id", 42),
        ("permissions", {"runtime.events.read": "yes"}),
        ("last_success", "2026-07-23T12:30:00"),
        ("last_success", "1753273800"),
        ("last_failure", 1_753_273_800),
    ],
)
def test_malformed_enums_and_types_are_rejected(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        DiscoveryCollectorContract.model_validate(_valid_contract(**{field: value}))


def test_extra_and_raw_content_fields_are_rejected() -> None:
    raw_prompt = "customer-private-prompt-do-not-log"
    with pytest.raises(ValidationError) as captured:
        DiscoveryCollectorContract.model_validate(
            _valid_contract(raw_prompt=raw_prompt)
        )
    assert raw_prompt not in str(captured.value)
    assert raw_prompt not in json.dumps(captured.value.errors(), sort_keys=True)


def test_secret_shaped_unknown_key_never_appears_in_validation_errors() -> None:
    secret_key = "sk-unknown-field-abcdefghijk"
    payload = _valid_contract()
    payload[secret_key] = True

    with pytest.raises(ValidationError) as captured:
        DiscoveryCollectorContract.model_validate(payload)

    rendered_errors = json.dumps(captured.value.errors(), sort_keys=True)
    assert secret_key not in str(captured.value)
    assert secret_key not in rendered_errors


def test_many_extra_keys_fail_as_one_generic_preflight_error() -> None:
    payload = _valid_contract()
    payload.update({f"extra_{index}": index for index in range(10_000)})

    with pytest.raises(ValidationError) as captured:
        DiscoveryCollectorContract.model_validate(payload)

    assert len(captured.value.errors()) == 1
    assert not captured.value.errors()[0]["loc"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("collector_id", "c" * 129),
        ("permissions", {f"permission.{index}": True for index in range(65)}),
        (
            "observation_types_emitted",
            [f"runtime.event.{index}" for index in range(65)],
        ),
        ("observation_types_emitted", ["o" * 129]),
    ],
)
def test_hostile_oversized_inputs_are_rejected_preflight(
    field: str,
    value: object,
) -> None:
    with pytest.raises(ValidationError):
        DiscoveryCollectorContract.model_validate(_valid_contract(**{field: value}))


def test_hostile_object_is_rejected_without_string_coercion() -> None:
    class Hostile:
        def __str__(self) -> str:
            raise AssertionError("hostile input was stringified")

        def __repr__(self) -> str:
            return "<hostile>"

    with pytest.raises(ValidationError):
        DiscoveryCollectorContract.model_validate(
            _valid_contract(source_system=Hostile())
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("collector_id", "sk-abcdefghijklmno"),
        ("source_system", "sk-abcdefghijklmnopqrstuvwxyz"),
        ("data_residency", "operator@example.com"),
    ],
)
def test_secret_or_pii_shaped_identifiers_are_rejected(
    field: str,
    value: str,
) -> None:
    with pytest.raises(ValidationError):
        DiscoveryCollectorContract.model_validate(_valid_contract(**{field: value}))


def test_permission_names_are_bounded_and_cannot_carry_secret_values() -> None:
    with pytest.raises(ValidationError):
        DiscoveryCollectorContract.model_validate(
            _valid_contract(permissions={"token=supersecretvalue": True})
        )
    with pytest.raises(ValidationError):
        DiscoveryCollectorContract.model_validate(
            _valid_contract(permissions={"runtime.read": "sk-abcdefghijklmno"})
        )


def test_canonical_serialization_is_stable_across_map_and_list_order() -> None:
    first = DiscoveryCollectorContract.model_validate(
        _valid_contract(
            permissions={"z.read": None, "a.read": True},
            observation_types_emitted=["z.event", "a.event", "z.event"],
        )
    )
    second = DiscoveryCollectorContract.model_validate(
        _valid_contract(
            permissions={"a.read": True, "z.read": None},
            observation_types_emitted=["a.event", "z.event"],
        )
    )

    assert first.canonical_json() == second.canonical_json()
    assert first.contract_hash == second.contract_hash
    assert json.loads(first.canonical_json())["observation_types_emitted"] == [
        "a.event",
        "z.event",
    ]


def test_hash_projection_separates_tenant_and_source() -> None:
    baseline = DiscoveryCollectorContract.model_validate(_valid_contract())
    other_tenant = DiscoveryCollectorContract.model_validate(
        _valid_contract(tenant_id="tenant-b")
    )
    other_source = DiscoveryCollectorContract.model_validate(
        _valid_contract(source_system="hawk.browser_extension")
    )

    assert baseline.contract_hash != other_tenant.contract_hash
    assert baseline.contract_hash != other_source.contract_hash
    assert other_tenant.contract_hash != other_source.contract_hash


def test_inline_capability_is_never_derived_from_health_or_permissions() -> None:
    contract = DiscoveryCollectorContract.model_validate(
        _valid_contract(
            health="healthy",
            permissions={"runtime.actions.authorize": True},
            control_capability="unknown",
        )
    )

    assert contract.control_capability == "unknown"

    payload_without_capability = _valid_contract()
    payload_without_capability.pop("control_capability")
    with pytest.raises(ValidationError):
        DiscoveryCollectorContract.model_validate(payload_without_capability)


def test_model_copy_revalidates_updates_and_cannot_forge_contract_state() -> None:
    contract = DiscoveryCollectorContract.model_validate(_valid_contract())

    with pytest.raises(ValidationError):
        contract.model_copy(update={"health": "active"})
    with pytest.raises(ValidationError):
        contract.model_copy(update={"raw_prompt": "do-not-retain-this"})

    updated = contract.model_copy(update={"health": "warning"})
    assert updated.health == "warning"
    assert updated.contract_hash != contract.contract_hash
