from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from typing import Any

import pytest
from pydantic import ValidationError

import app.services.hmair as hmair
from app.services.hmair.contracts import (
    CollectorDeclaration,
    CollectorRunStatus,
    DiscoveryObservationInput,
    DiscoveryScanCreate,
    DiscoveryScanStatus,
    DiscoveryScanType,
    DiscoveryTargetInput,
    DiscoveryTargetType,
    ObservationFreshness,
)


def _scan_data(**updates: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "name": "Estate scan",
        "scan_type": "targeted",
        "scope": {"environment": "production"},
        "target_ids": ("target-1",),
        "collector_ids": ("collector-1",),
        "safety_profile": "read_only",
        "dry_run": False,
    }
    data.update(updates)
    return data


def _target_data(**updates: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "target_id": "target-1",
        "target_type": "endpoint_group",
        "identifier": "endpoint-group-1",
        "environment": "production",
        "owner_hint": None,
        "credentials_reference": None,
        "permitted_methods": ("inventory",),
        "exclusions": (),
        "rate_limit": 100,
        "active_scan_allowed": False,
        "sensitive_scope": False,
        "last_scanned_at": None,
    }
    data.update(updates)
    return data


def _collector_data(**updates: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "collector_id": "collector-1",
        "collector_type": "endpoint",
        "version": "1.0.0",
        "supported_targets": ("endpoint_group",),
        "active_capabilities": (),
        "passive_capabilities": ("inventory",),
        "permissions_required": ("process_list",),
        "sensitive_data_accessed": (),
        "health": "healthy",
        "last_success_at": datetime(2026, 7, 30, tzinfo=timezone.utc),
        "last_failure_at": None,
        "data_residency": "us-east-1",
        "control_capability": "monitor_only",
        "schema_version": "1.0",
        "limitations": ("metadata_only",),
        "declaration_hash": "a" * 64,
    }
    data.update(updates)
    return data


def _observation_data(**updates: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "observation_id": "obs-1",
        "scan_id": "scan-1",
        "collector_id": "collector-1",
        "collector_type": "endpoint",
        "collector_version": "1.0.0",
        "target_id": "target-1",
        "source_surface": "endpoint",
        "subject_reference": "managed-device-1",
        "observed_at": datetime(2026, 7, 30, tzinfo=timezone.utc),
        "observation_type": "running_process",
        "normalized_signal": {"process_family": "ai_application"},
        "candidate_asset_type": "ai_application",
        "observed_state": "observed",
        "identifiers": {"process_id": "42"},
        "attributes": {},
        "configuration_summary": {},
        "usage_summary": {},
        "capability_hints": (),
        "identity_hints": (),
        "relationship_hints": (),
        "evidence_reference": "evidence-1",
        "evidence_hash": "b" * 64,
        "signature_status": "unknown",
        "confidence": 0.4,
        "freshness": "fresh",
        "verification_state": "partially_verified",
        "source_trust": "medium",
        "collection_scope": {"scope_type": "endpoint_group"},
        "parser_version": "1.0.0",
        "schema_version": "2.0",
        "evidence_mode": "direct",
        "evidence_mutability": "immutable",
        "contradiction_state": "none",
        "contradiction_references": (),
        "sensitivity": "metadata",
        "redaction_status": "sanitized",
    }
    data.update(updates)
    return data


def _flexible_update(field_name: str, value: Any) -> tuple[type[Any], dict[str, Any]]:
    if field_name == "scope":
        return DiscoveryScanCreate, _scan_data(scope=value)
    if field_name in {"identity_hints", "relationship_hints"}:
        return DiscoveryObservationInput, _observation_data(**{field_name: (value,)})
    return DiscoveryObservationInput, _observation_data(**{field_name: value})


def _string_collection_update(
    field_name: str,
    value: tuple[str, ...],
) -> tuple[type[Any], dict[str, Any]]:
    if field_name in {"target_ids", "collector_ids"}:
        return DiscoveryScanCreate, _scan_data(**{field_name: value})
    if field_name in {"permitted_methods", "exclusions"}:
        return DiscoveryTargetInput, _target_data(**{field_name: value})
    if field_name == "capability_hints":
        return DiscoveryObservationInput, _observation_data(**{field_name: value})
    return CollectorDeclaration, _collector_data(**{field_name: value})


_STRING_COLLECTION_CASES = [
    ("target_ids", 64 * 1024),
    ("collector_ids", 8 * 1024),
    ("permitted_methods", 2 * 1024),
    ("exclusions", 16 * 1024),
    ("active_capabilities", 4 * 1024),
    ("passive_capabilities", 4 * 1024),
    ("permissions_required", 4 * 1024),
    ("sensitive_data_accessed", 4 * 1024),
    ("limitations", 4 * 1024),
    ("capability_hints", 4 * 1024),
]


class _StringOnlyContract(hmair.StrictContract):
    value: str


def test_vocabularies_and_fields_are_exact() -> None:
    assert {item.value for item in DiscoveryScanType} == {
        "full_enterprise",
        "targeted",
        "incremental",
        "verification",
        "scheduled",
        "collector_specific",
    }
    assert {item.value for item in DiscoveryScanStatus} == {
        "queued",
        "running",
        "partially_complete",
        "complete",
        "failed",
        "cancelled",
    }
    assert {item.value for item in ObservationFreshness} == {
        "fresh",
        "stale",
        "expired",
        "unknown",
    }
    assert {item.value for item in DiscoveryTargetType} == {
        "endpoint_group",
        "browser_tenant",
        "cloud_subscription",
        "cloud_project",
        "kubernetes_cluster",
        "saas_tenant",
        "identity_tenant",
        "repository_org",
        "repository",
        "network_range",
        "dns_domain",
        "api_gateway",
        "database_platform",
        "ai_provider_account",
        "mcp_environment",
        "llm_gateway",
        "runtime_environment",
    }
    assert {item.value for item in CollectorRunStatus} == {
        "pending",
        "running",
        "complete",
        "failed",
        "cancelled",
        "unsupported",
        "permission_denied",
        "rate_limited",
        "stale",
        "empty",
    }
    assert set(DiscoveryScanCreate.model_fields) == {
        "name",
        "scan_type",
        "scope",
        "target_ids",
        "collector_ids",
        "safety_profile",
        "dry_run",
    }
    assert set(DiscoveryTargetInput.model_fields) == {
        "target_id",
        "target_type",
        "identifier",
        "environment",
        "owner_hint",
        "credentials_reference",
        "permitted_methods",
        "exclusions",
        "rate_limit",
        "active_scan_allowed",
        "sensitive_scope",
        "last_scanned_at",
    }
    assert set(CollectorDeclaration.model_fields) == {
        "collector_id",
        "collector_type",
        "version",
        "supported_targets",
        "active_capabilities",
        "passive_capabilities",
        "permissions_required",
        "sensitive_data_accessed",
        "health",
        "last_success_at",
        "last_failure_at",
        "data_residency",
        "control_capability",
        "schema_version",
        "limitations",
        "declaration_hash",
    }
    assert set(DiscoveryObservationInput.model_fields) == {
        "observation_id",
        "scan_id",
        "collector_id",
        "collector_type",
        "collector_version",
        "target_id",
        "source_surface",
        "subject_reference",
        "raw_signal_type",
        "normalized_signal",
        "observed_at",
        "asset_candidate_type",
        "observed_state",
        "identifiers",
        "attributes",
        "configuration_summary",
        "usage_summary",
        "capability_hints",
        "identity_hints",
        "relationship_hints",
        "evidence_reference",
        "evidence_hash",
        "signature_status",
        "confidence",
        "freshness",
        "verification_state",
        "source_trust",
        "collection_scope",
        "parser_version",
        "schema_version",
        "evidence_mode",
        "evidence_mutability",
        "contradiction_state",
        "contradiction_references",
        "sensitivity",
        "redaction_status",
    }


def test_public_exports_are_complete_and_stable() -> None:
    assert {
        "CollectorDeclaration",
        "CollectorRunStatus",
        "DiscoveryObservationInput",
        "DiscoveryScanCreate",
        "DiscoveryScanStatus",
        "DiscoveryScanType",
        "DiscoveryTargetInput",
        "DiscoveryTargetType",
        "ObservationFreshness",
        "StrictContract",
    } <= set(hmair.__all__)
    for export in hmair.__all__:
        assert getattr(hmair, export) is getattr(hmair.contracts, export)


def test_scan_create_rejects_empty_target_ids_with_other_fields_valid() -> None:
    with pytest.raises(ValidationError):
        DiscoveryScanCreate(**_scan_data(target_ids=()))


def test_scan_create_rejects_empty_collector_ids_with_other_fields_valid() -> None:
    with pytest.raises(ValidationError):
        DiscoveryScanCreate(**_scan_data(collector_ids=()))


def test_collector_accepts_approved_deployment_and_lifecycle_fields() -> None:
    last_success_at = datetime(
        2026,
        7,
        30,
        4,
        tzinfo=timezone(timedelta(hours=4)),
    )
    collector = CollectorDeclaration(
        **_collector_data(
            last_success_at=last_success_at,
            last_failure_at=None,
            data_residency="us-east-1",
            control_capability="monitor_only",
        )
    )
    assert collector.last_success_at == datetime(
        2026,
        7,
        30,
        tzinfo=timezone.utc,
    )
    assert collector.last_success_at.tzinfo is timezone.utc
    assert collector.last_failure_at is None
    assert collector.data_residency == "us-east-1"
    assert collector.control_capability == "monitor_only"


def test_collector_lifecycle_times_are_optional() -> None:
    data = _collector_data()
    del data["last_success_at"]
    del data["last_failure_at"]
    collector = CollectorDeclaration(**data)
    assert collector.last_success_at is None
    assert collector.last_failure_at is None


def test_collector_data_residency_accepts_exact_maximum_length() -> None:
    collector = CollectorDeclaration(**_collector_data(data_residency="x" * 128))
    assert collector.data_residency == "x" * 128


@pytest.mark.parametrize(
    "health",
    ["healthy", "warning", "degraded", "offline", "unknown"],
)
def test_collector_accepts_exact_health_vocabulary(health: str) -> None:
    collector = CollectorDeclaration(**_collector_data(health=health))
    assert collector.health == health


@pytest.mark.parametrize(
    "health",
    ["", "Healthy", "unavailable", "healthy_now"],
)
def test_collector_rejects_health_outside_exact_vocabulary(health: str) -> None:
    with pytest.raises(ValidationError):
        CollectorDeclaration(**_collector_data(health=health))


@pytest.mark.parametrize(
    "control_capability",
    ["inline", "warn_only", "monitor_only", "external_required", "unknown"],
)
def test_collector_accepts_exact_control_capability_vocabulary(
    control_capability: str,
) -> None:
    collector = CollectorDeclaration(
        **_collector_data(control_capability=control_capability)
    )
    assert collector.control_capability == control_capability


@pytest.mark.parametrize(
    "control_capability",
    ["", "Inline", "authorize", "monitor"],
)
def test_collector_rejects_control_capability_outside_exact_vocabulary(
    control_capability: str,
) -> None:
    with pytest.raises(ValidationError):
        CollectorDeclaration(
            **_collector_data(control_capability=control_capability)
        )


@pytest.mark.parametrize("field_name", ["last_success_at", "last_failure_at"])
def test_collector_lifecycle_times_require_timezone(field_name: str) -> None:
    with pytest.raises(ValidationError):
        CollectorDeclaration(
            **_collector_data(**{field_name: datetime(2026, 7, 30)})
        )


@pytest.mark.parametrize("data_residency", ["", "   ", "x" * 129])
def test_collector_data_residency_is_bounded_and_nonempty(
    data_residency: str,
) -> None:
    with pytest.raises(ValidationError):
        CollectorDeclaration(**_collector_data(data_residency=data_residency))


def test_observation_scan_id_is_bounded_to_generated_uuid_length() -> None:
    observation = DiscoveryObservationInput(
        **_observation_data(scan_id="s" * 36)
    )
    assert observation.scan_id == "s" * 36
    with pytest.raises(ValidationError):
        DiscoveryObservationInput(**_observation_data(scan_id="s" * 37))


def test_observation_rejects_naive_time_with_other_fields_valid() -> None:
    with pytest.raises(ValidationError):
        DiscoveryObservationInput(
            **_observation_data(observed_at=datetime(2026, 7, 30))
        )


def test_observation_rejects_raw_material_with_aware_time() -> None:
    with pytest.raises(ValidationError):
        DiscoveryObservationInput(
            **_observation_data(attributes={"nested": {"raw_prompt": "do not keep"}})
        )


@pytest.mark.parametrize(
    ("model", "data"),
    [
        (DiscoveryScanCreate, _scan_data(dry_run=1)),
        (DiscoveryScanCreate, _scan_data(dry_run="false")),
        (DiscoveryTargetInput, _target_data(active_scan_allowed=0)),
        (DiscoveryTargetInput, _target_data(sensitive_scope="false")),
        (DiscoveryTargetInput, _target_data(rate_limit=True)),
        (DiscoveryTargetInput, _target_data(rate_limit=1.5)),
        (DiscoveryTargetInput, _target_data(rate_limit="100")),
    ],
)
def test_safety_controls_use_strict_primitive_types(
    model: type[Any],
    data: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        model(**data)


@pytest.mark.parametrize(
    "field_name",
    [case[0] for case in _STRING_COLLECTION_CASES],
)
def test_every_string_collection_rejects_a_100k_character_item(
    field_name: str,
) -> None:
    model, data = _string_collection_update(field_name, ("x" * 100_000,))
    with pytest.raises(ValidationError):
        model(**data)


@pytest.mark.parametrize(
    ("field_name", "encoded_byte_budget"),
    _STRING_COLLECTION_CASES,
)
def test_every_string_collection_enforces_its_aggregate_budget(
    field_name: str,
    encoded_byte_budget: int,
) -> None:
    item_count = (encoded_byte_budget // 128) + 2
    values = tuple(
        f"{index:04d}-" + ("x" * 123) for index in range(item_count)
    )
    assert all(len(item) == 128 for item in values)
    model, data = _string_collection_update(field_name, values)
    with pytest.raises(ValidationError):
        model(**data)


@pytest.mark.parametrize(
    ("model", "data_factory", "field_name"),
    [
        (CollectorDeclaration, _collector_data, "declaration_hash"),
        (DiscoveryObservationInput, _observation_data, "evidence_hash"),
    ],
)
@pytest.mark.parametrize(
    "bad_hash",
    [
        "a" * 63,
        "a" * 65,
        "A" * 64,
        ("a" * 64) + "-suffix",
        "prefix-" + ("a" * 64),
        ("a" * 63) + "g",
        " " + ("a" * 64),
        ("a" * 64) + "\t",
        ("a" * 64) + "\n",
    ],
)
def test_hashes_require_exactly_64_anchored_lowercase_hex_characters(
    model: type[Any],
    data_factory: Any,
    field_name: str,
    bad_hash: str,
) -> None:
    with pytest.raises(ValidationError):
        model(**data_factory(**{field_name: bad_hash}))


@pytest.mark.parametrize(
    ("field_name", "unsafe_value"),
    [
        ("scope", {"nested": {"prompt": "raw"}}),
        ("identifiers", {"api_key": "sk-unsafe-value"}),
        ("attributes", {"nested": {"request_body": "raw"}}),
        ("configuration_summary", {"nested": {"file_content": "raw"}}),
        ("usage_summary", {"nested": {"password": "unsafe"}}),
        ("identity_hints", {"nested": {"access_token": "unsafe"}}),
        ("relationship_hints", {"nested": {"screenshot_b64": "YWJj"}}),
    ],
)
def test_every_flexible_field_rejects_nested_private_or_raw_material(
    field_name: str,
    unsafe_value: Any,
) -> None:
    model, data = _flexible_update(field_name, unsafe_value)
    with pytest.raises(ValidationError):
        model(**data)


@pytest.mark.parametrize(
    "unsafe_key",
    [
        "rawprompt",
        "RAWPROMPT",
        "requestbody",
        "REQUESTBODY",
        "filecontent",
        "FILECONTENT",
        "apikey",
        "APIKEY",
        "customerrawprompt",
        "outboundrequestbody",
        "archivefilecontent",
        "serviceapikey",
        "binarypayloadbase64",
        "rawPrompt",
        "requestBody",
        "fileContent",
        "apiKey",
        "accessToken",
        "userPassword",
        "imageBase64",
    ],
)
def test_privacy_key_matching_covers_camel_case_variants(unsafe_key: str) -> None:
    with pytest.raises(ValidationError):
        DiscoveryScanCreate(
            **_scan_data(scope={"nested": {unsafe_key: "opaque"}})
        )


@pytest.mark.parametrize(
    "unsafe_value",
    [
        {"safe_key": b"raw bytes"},
        {"safe_key": bytearray(b"raw bytes")},
        {"safe_key": {"not", "json"}},
        {"safe_key": object()},
        {"safe_key": float("nan")},
        {"safe_key": float("inf")},
        {1: "non-string key"},
        {"x" * 129: "oversized key"},
        {"safe_key": "x" * 1025},
        {"safe_key": "Bearer abcdefghijklmnopqrstuvwxyz"},
        {"safe_key": "password=hunter123"},
        {"safe_key": "person@example.com"},
    ],
)
def test_flexible_values_are_json_safe_bounded_and_privacy_clean(
    unsafe_value: Any,
) -> None:
    with pytest.raises(ValidationError):
        DiscoveryScanCreate(**_scan_data(scope=unsafe_value))


@pytest.mark.parametrize(
    "unsafe_scope",
    [
        {"\ud800": "safe"},
        {"safe_key": "\udfff"},
    ],
)
def test_flexible_keys_and_values_reject_lone_surrogates(
    unsafe_scope: dict[str, str],
) -> None:
    with pytest.raises(ValidationError):
        DiscoveryScanCreate(**_scan_data(scope=unsafe_scope))


def test_valid_unicode_flexible_values_round_trip_through_json() -> None:
    scan = DiscoveryScanCreate(
        **_scan_data(
            scope={
                "résumé_label": "Grüße 😀",
                "地域": {"状態": "管理対象"},
            }
        )
    )
    encoded = scan.model_dump_json()
    assert json.loads(encoded)["scope"]["résumé_label"] == "Grüße 😀"
    restored = DiscoveryScanCreate.model_validate_json(encoded)
    assert restored.model_dump(mode="json") == scan.model_dump(mode="json")


@pytest.mark.parametrize(
    "field_name",
    [
        "scope",
        "identifiers",
        "attributes",
        "configuration_summary",
        "usage_summary",
        "identity_hints",
        "relationship_hints",
    ],
)
def test_every_flexible_field_has_an_encoded_size_limit(field_name: str) -> None:
    if field_name == "identifiers":
        oversized: Any = {f"item_{index}": "x" * 512 for index in range(64)}
    else:
        oversized = {"rows": ["x" * 512 for _ in range(64)]}
    model, data = _flexible_update(field_name, oversized)
    with pytest.raises(ValidationError):
        model(**data)


@pytest.mark.parametrize(
    "field_name",
    [
        "scope",
        "attributes",
        "configuration_summary",
        "usage_summary",
        "identity_hints",
        "relationship_hints",
    ],
)
def test_every_nested_flexible_field_has_depth_and_item_limits(
    field_name: str,
) -> None:
    too_deep: dict[str, Any] = {"leaf": "safe"}
    for _ in range(7):
        too_deep = {"level": too_deep}
    model, data = _flexible_update(field_name, too_deep)
    with pytest.raises(ValidationError):
        model(**data)

    too_many_items = {"items": list(range(129))}
    model, data = _flexible_update(field_name, too_many_items)
    with pytest.raises(ValidationError):
        model(**data)


def test_flexible_values_have_a_traversal_wide_node_budget() -> None:
    wide_tree = [[None] * 64 for _ in range(64)]
    with pytest.raises(ValidationError):
        DiscoveryScanCreate(**_scan_data(scope={"tree": wide_tree}))


def test_flexible_values_reject_repeated_container_references() -> None:
    shared: list[Any] = ["safe"] * 8
    for _ in range(3):
        shared = [shared] * 8
    with pytest.raises(ValidationError):
        DiscoveryScanCreate(**_scan_data(scope={"tree": shared}))


def test_flexible_integer_bounds_are_exactly_signed_64_bit() -> None:
    scan = DiscoveryScanCreate(
        **_scan_data(scope={"minimum": -(1 << 63), "maximum": (1 << 63) - 1})
    )
    assert scan.scope["minimum"] == -(1 << 63)
    assert scan.scope["maximum"] == (1 << 63) - 1
    for invalid in (-(1 << 63) - 1, 1 << 63):
        with pytest.raises(ValidationError):
            DiscoveryScanCreate(**_scan_data(scope={"value": invalid}))


def test_flexible_inputs_are_deeply_detached_frozen_and_json_friendly() -> None:
    scope = {"nested": {"labels": ["managed", "production"]}}
    scan = DiscoveryScanCreate(**_scan_data(scope=scope))
    scope["nested"]["labels"].append("mutated")
    scope["nested"]["new"] = "mutated"

    assert scan.scope["nested"]["labels"] == ("managed", "production")
    assert "new" not in scan.scope["nested"]
    with pytest.raises(TypeError):
        scan.scope["nested"]["new"] = "blocked"
    with pytest.raises(AttributeError):
        scan.scope["nested"]["labels"].append("blocked")

    dumped = scan.model_dump(mode="json")
    assert dumped["scope"] == {
        "nested": {"labels": ["managed", "production"]}
    }
    assert json.loads(scan.model_dump_json()) == dumped


def test_observation_flexible_inputs_are_all_detached_and_frozen() -> None:
    identifiers = {"process_id": "42"}
    attributes = {"labels": ["managed"]}
    configuration = {"mode": {"name": "passive"}}
    usage = {"counts": [1, 2]}
    identities = [{"identity_id": "principal-1", "groups": ["security"]}]
    relationships = [{"target_id": "asset-2", "types": ["uses"]}]
    observation = DiscoveryObservationInput(
        **_observation_data(
            identifiers=identifiers,
            attributes=attributes,
            configuration_summary=configuration,
            usage_summary=usage,
            identity_hints=identities,
            relationship_hints=relationships,
        )
    )

    identifiers["process_id"] = "mutated"
    attributes["labels"].append("mutated")
    configuration["mode"]["name"] = "mutated"
    usage["counts"].append(3)
    identities[0]["groups"].append("mutated")
    relationships[0]["types"].append("mutated")

    assert observation.identifiers["process_id"] == "42"
    assert observation.attributes["labels"] == ("managed",)
    assert observation.configuration_summary["mode"]["name"] == "passive"
    assert observation.usage_summary["counts"] == (1, 2)
    assert observation.identity_hints[0]["groups"] == ("security",)
    assert observation.relationship_hints[0]["types"] == ("uses",)
    for frozen_mapping in (
        observation.identifiers,
        observation.attributes,
        observation.configuration_summary,
        observation.usage_summary,
        observation.identity_hints[0],
        observation.relationship_hints[0],
    ):
        with pytest.raises(TypeError):
            frozen_mapping["new"] = "blocked"


@pytest.mark.parametrize(
    "instance",
    [
        DiscoveryScanCreate(**_scan_data()),
        DiscoveryTargetInput(**_target_data()),
        CollectorDeclaration(**_collector_data()),
        DiscoveryObservationInput(**_observation_data()),
    ],
)
def test_contracts_round_trip_through_json(instance: Any) -> None:
    dumped = instance.model_dump(mode="json")
    assert json.loads(json.dumps(dumped)) == dumped
    restored = type(instance).model_validate_json(instance.model_dump_json())
    assert restored.model_dump(mode="json") == dumped


def test_validation_entrypoints_forward_only_supported_alias_arguments() -> None:
    scan = DiscoveryScanCreate.model_validate(
        _scan_data(),
        by_alias=True,
        by_name=True,
    )
    restored = DiscoveryScanCreate.model_validate_json(
        scan.model_dump_json(),
        by_alias=True,
        by_name=True,
    )
    strings = _StringOnlyContract.model_validate_strings(
        {"value": "safe"},
        by_alias=True,
        by_name=True,
    )
    assert restored.model_dump(mode="json") == scan.model_dump(mode="json")
    assert strings.value == "safe"


def test_model_copy_revalidates_updates() -> None:
    scan = DiscoveryScanCreate(**_scan_data())
    copied = scan.model_copy(update={"dry_run": True})
    assert copied.dry_run is True
    with pytest.raises(ValidationError):
        scan.model_copy(update={"dry_run": "false"})
    with pytest.raises(ValidationError):
        scan.model_copy(update={"unexpected": "field"})

    observation = DiscoveryObservationInput(**_observation_data())
    with pytest.raises(ValidationError):
        observation.model_copy(
            update={"attributes": {"nested": {"secret": "unsafe"}}}
        )


@pytest.mark.parametrize(
    "entrypoint",
    ["constructor", "model_validate", "model_validate_strings"],
)
def test_validation_errors_do_not_retain_submitted_input_or_context(
    entrypoint: str,
) -> None:
    marker = "RAW-SUBMITTED-MARKER-DO-NOT-RETAIN"
    with pytest.raises(ValidationError) as captured:
        if entrypoint == "constructor":
            DiscoveryObservationInput(
                **_observation_data(evidence_hash=marker)
            )
        elif entrypoint == "model_validate":
            DiscoveryObservationInput.model_validate(
                _observation_data(evidence_hash=marker)
            )
        else:
            DiscoveryObservationInput.model_validate_strings(
                {"evidence_hash": marker}
            )

    rendered = str(captured.value)
    details = captured.value.errors()
    assert marker not in rendered
    assert marker not in repr(details)
    assert all(detail.get("input") is None for detail in details)
    assert all("ctx" not in detail for detail in details)


@pytest.mark.parametrize(
    "payload",
    [
        '{"evidence_hash":"RAW-JSON-MARKER"}',
        '{"evidence_hash":"RAW-JSON-MARKER"',
    ],
)
def test_model_validate_json_sanitizes_invalid_and_malformed_json(
    payload: str,
) -> None:
    with pytest.raises(ValidationError) as captured:
        DiscoveryObservationInput.model_validate_json(payload)
    rendered = f"{captured.value}\n{captured.value.errors()!r}"
    assert "RAW-JSON-MARKER" not in rendered
    assert all(
        detail.get("input") is None and "ctx" not in detail
        for detail in captured.value.errors()
    )


def test_unknown_is_a_valid_observation_state() -> None:
    observation = DiscoveryObservationInput(
        **_observation_data(
            freshness="unknown",
            observation_type="unknown_ai_signal",
            candidate_asset_type="unknown_ai_candidate",
            observed_state="unknown",
            verification_state="unknown",
            source_trust="unknown",
            evidence_mode="unknown",
            evidence_mutability="unknown",
            contradiction_state="unknown",
            confidence=0.0,
        )
    )
    assert observation.freshness.value == "unknown"
    assert observation.observed_state.value == "unknown"
    assert observation.verification_state.value == "unknown"
