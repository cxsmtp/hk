"""Deterministic Canonical AI Action V2 projection and comparison helpers."""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from datetime import datetime
from typing import Any, Mapping


CANONICAL_ACTION_V2 = "canonical-ai-action/2.0"
_LEGACY_CANONICAL_ACTION_VERSIONS = frozenset({"1.0", "1.1", "canonical-ai-action/1.0", "canonical-ai-action/1.1"})
SEMANTIC_COMPARATOR_VERSION = "semantic-comparison/1.0"
_MAX_CANONICAL_INTEGER = 2**53 - 1
_MAX_CANONICAL_COLLECTION_ITEMS = 128
_MAX_CANONICAL_DEPTH = 64
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_UNKNOWN_TAGS = frozenset({"UNKNOWN", "UNRESOLVED"})
_ACTION_FIELDS = frozenset({
    "schema_version", "tenant_id", "action_id", "chain_id", "parent_action_id",
    "correlation_id", "actor_principal", "executing_principal", "represented_subjects",
    "resource_scopes", "authority_context", "business_purpose", "environment",
    "provider_runtime_context", "action_semantics", "domain_profile_ref",
    "domain_profile_hash", "materiality_profile_ref", "materiality_profile_hash",
    "resolver_versions", "policy_version_id", "policy_epoch", "control_plan_id",
    "control_plan_digest", "approval_requirement", "delegation_digest",
    "action_plan_binding", "unresolved_material", "evidence_refs", "created_at",
})
_SEMANTIC_FIELDS = frozenset({
    "action_class", "operation", "object_type", "tool_or_service_ref", "tool_fingerprint",
    "safe_parameters", "represented_subject_refs", "resource_refs", "counterparty_refs",
    "target_refs", "destination_refs", "values_or_quantities", "authority_ref",
    "business_purpose_ref", "side_effect", "persistence", "environment", "reversibility",
    "expected_outcome_ref",
})


def _utf16_key(value: str) -> bytes:
    """Use the RFC 8785 object-member ordering, not Python code points."""
    return value.encode("utf-16-be")


def _normalize(value: Any, *, depth: int = 0) -> Any:
    if depth > _MAX_CANONICAL_DEPTH:
        raise ValueError("canonical value exceeds the depth bound")
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise ValueError("unpaired unicode surrogate")
        return unicodedata.normalize("NFC", value)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not -_MAX_CANONICAL_INTEGER <= value <= _MAX_CANONICAL_INTEGER:
            raise ValueError("canonical integer is outside the interoperable range")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite canonical number")
        raise ValueError("canonical decimal values must be strings")
    if isinstance(value, Mapping):
        if len(value) > _MAX_CANONICAL_COLLECTION_ITEMS:
            raise ValueError("canonical collection exceeds the item bound")
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("canonical object keys must be strings")
            normalized_key = _normalize(key, depth=depth + 1)
            if normalized_key in result:
                # Assignment would otherwise silently overwrite the first
                # member.  Distinct source keys that normalize to the same
                # NFC key are ambiguous across implementations.
                raise ValueError("duplicate key after normalization")
            result[normalized_key] = _normalize(item, depth=depth + 1)
        if len(result) != len(value):
            raise ValueError("duplicate key after normalization")
        return {key: result[key] for key in sorted(result, key=_utf16_key)}
    if isinstance(value, list):
        if len(value) > _MAX_CANONICAL_COLLECTION_ITEMS:
            raise ValueError("canonical collection exceeds the item bound")
        return [_normalize(item, depth=depth + 1) for item in value]
    raise ValueError(f"unsupported canonical type: {type(value).__name__}")


def _raw_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate raw and NFC-equivalent JSON member names at parse time."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        normalized = _normalize(key)
        if normalized in result:
            raise ValueError("duplicate key after normalization")
        result[normalized] = value
    return result


def _raw_json_integer(token: str) -> int:
    if token == "-0":
        raise ValueError("negative zero is not canonical")
    number = int(token)
    if not -_MAX_CANONICAL_INTEGER <= number <= _MAX_CANONICAL_INTEGER:
        raise ValueError("canonical integer is outside the interoperable range")
    return number


def _raw_json_float(_: str) -> Any:
    raise ValueError("canonical decimal values must be strings")


def _raw_json_constant(_: str) -> Any:
    raise ValueError("non-finite canonical number")


def parse_canonical_json(raw: str | bytes | bytearray) -> Any:
    """Parse untrusted JSON using the same interoperability contract as hashing.

    Hashing a Python mapping cannot recover duplicate wire names.  Callers that
    receive raw JSON must use this entry point before canonicalization.
    """
    if isinstance(raw, bytearray):
        raw = bytes(raw)
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ValueError("canonical JSON must be UTF-8") from exc
    if not isinstance(raw, str):
        raise ValueError("canonical JSON input must be text or UTF-8 bytes")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_raw_json_object,
            parse_int=_raw_json_integer,
            parse_float=_raw_json_float,
            parse_constant=_raw_json_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("invalid canonical JSON") from exc
    return _normalize(value)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(_normalize(value), ensure_ascii=False, sort_keys=False, separators=(",", ":")).encode("utf-8")


def domain_hash(domain: str, value: Any) -> str:
    if not domain.isascii() or not domain:
        raise ValueError("hash domain must be non-empty ASCII")
    return hashlib.sha256(domain.encode("ascii") + b"\0" + canonical_json_bytes(value)).hexdigest()


def validate_action_plan_binding(action: Mapping[str, Any]) -> None:
    binding = action.get("action_plan_binding")
    if not isinstance(binding, Mapping):
        raise ValueError("action plan binding is required")
    expected_fields = {
        "binding_type",
        "action_plan_id",
        "action_plan_digest",
        "action_plan_step_id",
        "action_plan_step_digest",
    }
    if set(binding) != expected_fields:
        raise ValueError("action plan binding fields are invalid")
    kind = binding.get("binding_type")
    values = tuple(binding.get(name) for name in ("action_plan_id", "action_plan_digest", "action_plan_step_id", "action_plan_step_digest"))
    if kind == "STANDALONE" and any(value is not None for value in values):
        raise ValueError("standalone actions cannot contain plan binding values")
    if kind == "PLAN_ROOT" and (not values[0] or not values[1] or values[2] is not None or values[3] is not None):
        raise ValueError("plan root binding is incomplete")
    if kind == "PLANNED_STEP" and any(not value for value in values):
        raise ValueError("planned step binding is incomplete")
    if kind not in {"STANDALONE", "PLAN_ROOT", "PLANNED_STEP"}:
        raise ValueError("unknown action plan binding type")
    for value in values:
        if value is not None and (not isinstance(value, str) or not value):
            raise ValueError("action plan binding values must be non-empty strings or null")


def _require_exact_utc_timestamp(*, field: str, value: object) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", value):
        raise ValueError(f"{field} must be an exact UTC timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise ValueError(f"{field} must be an exact UTC timestamp") from exc


def _validate_semantic_decimals(action: Mapping[str, Any]) -> None:
    semantics = action.get("action_semantics")
    values = semantics.get("values_or_quantities") if isinstance(semantics, Mapping) else None
    if not isinstance(values, list):
        raise ValueError("values_or_quantities must be a list")
    for quantity in values:
        if not isinstance(quantity, Mapping) or "value" not in quantity:
            raise ValueError("semantic quantity is invalid")
        for field in ("value", "permitted_min", "permitted_max"):
            if field not in quantity:
                continue
            decimal = quantity[field]
            if (
                not isinstance(decimal, str)
                or decimal == "-0"
                or not re.fullmatch(r"-?(0|[1-9][0-9]*)(\.[0-9]*[1-9])?", decimal)
            ):
                raise ValueError(f"semantic decimal is invalid: {field}")


def _require_exact_fields(*, value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    if set(value) != expected:
        missing = expected.difference(value)
        extra = set(value).difference(expected)
        raise ValueError(f"{label} fields are invalid (missing={sorted(missing)}, extra={sorted(extra)})")


def _require_string(value: object, *, field: str, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a non-empty string")


def _require_list_of_strings(value: object, *, field: str) -> None:
    if not isinstance(value, list) or len(value) > _MAX_CANONICAL_COLLECTION_ITEMS:
        raise ValueError(f"{field} must be a bounded list")
    for item in value:
        _require_string(item, field=field)


def _is_unknown(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().upper() in _UNKNOWN_TAGS
    if isinstance(value, Mapping):
        return any(_is_unknown(child) for child in value.values())
    if isinstance(value, list):
        return any(_is_unknown(child) for child in value)
    return False


def _validate_action_contract(action: Mapping[str, Any]) -> None:
    _require_exact_fields(value=action, expected=_ACTION_FIELDS, label="canonical action")
    for field in (
        "tenant_id", "action_id", "chain_id", "correlation_id", "actor_principal",
        "executing_principal", "authority_context", "business_purpose", "environment",
        "provider_runtime_context", "domain_profile_ref", "materiality_profile_ref",
        "policy_version_id", "control_plan_id", "approval_requirement",
    ):
        _require_string(action.get(field), field=field)
    _require_string(action.get("parent_action_id"), field="parent_action_id", nullable=True)
    for field in ("domain_profile_hash", "materiality_profile_hash", "control_plan_digest", "delegation_digest"):
        value = action.get(field)
        if not isinstance(value, str) or not _DIGEST.fullmatch(value):
            raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    if not isinstance(action.get("policy_epoch"), int) or isinstance(action.get("policy_epoch"), bool) or action["policy_epoch"] <= 0:
        raise ValueError("policy_epoch must be a positive integer")
    for field in ("represented_subjects", "resource_scopes", "evidence_refs", "unresolved_material"):
        _require_list_of_strings(action.get(field), field=field)
    resolvers = action.get("resolver_versions")
    if not isinstance(resolvers, Mapping) or len(resolvers) > _MAX_CANONICAL_COLLECTION_ITEMS:
        raise ValueError("resolver_versions must be a bounded object")
    for key, value in resolvers.items():
        _require_string(key, field="resolver_versions key")
        _require_string(value, field="resolver_versions value")
    semantics = action.get("action_semantics")
    if not isinstance(semantics, Mapping):
        raise ValueError("action_semantics must be an object")
    _require_exact_fields(value=semantics, expected=_SEMANTIC_FIELDS, label="action semantics")
    for field in (
        "action_class", "operation", "object_type", "tool_or_service_ref", "tool_fingerprint",
        "authority_ref", "business_purpose_ref", "side_effect", "persistence", "environment",
        "reversibility", "expected_outcome_ref",
    ):
        _require_string(semantics.get(field), field=f"action_semantics.{field}")
    if not isinstance(semantics.get("safe_parameters"), Mapping):
        raise ValueError("action_semantics.safe_parameters must be an object")
    for field in ("represented_subject_refs", "resource_refs", "counterparty_refs", "target_refs", "destination_refs"):
        _require_list_of_strings(semantics.get(field), field=f"action_semantics.{field}")
    if not isinstance(semantics.get("values_or_quantities"), list):
        raise ValueError("values_or_quantities must be a list")
    if semantics["action_class"].strip().lower() == "consequential":
        unresolved = set(action["unresolved_material"])
        unknown_fields = [
            field for field in _ACTION_FIELDS.difference({"unresolved_material", "evidence_refs", "created_at", "action_plan_binding"})
            if _is_unknown(action.get(field))
        ]
        unknown_fields.extend(
            f"action_semantics.{field}" for field in _SEMANTIC_FIELDS
            if _is_unknown(semantics.get(field))
        )
        if unknown_fields and not all(field in unresolved or f"{field}[*]" in unresolved for field in unknown_fields):
            raise ValueError("consequential action contains unresolved material not declared in unresolved_material")


def canonical_action_bytes_v2(action: Mapping[str, Any]) -> bytes:
    if "schema_version" not in action:
        raise ValueError("canonical action schema version is required")
    if action.get("schema_version") not in {CANONICAL_ACTION_V2, "2.0"}:
        raise ValueError("unexpected canonical action version")
    _validate_action_contract(action)
    _require_exact_utc_timestamp(field="created_at", value=action.get("created_at"))
    _validate_semantic_decimals(action)
    validate_action_plan_binding(action)
    return canonical_json_bytes({**dict(action), "schema_version": CANONICAL_ACTION_V2})


def canonical_action_hash_v2(action: Mapping[str, Any]) -> str:
    return hashlib.sha256(b"hawk:canonical-ai-action:v2\0" + canonical_action_bytes_v2(action)).hexdigest()


def _schema_version(value: Mapping[str, Any]) -> str | None:
    version = value.get("schema_version")
    return version if isinstance(version, str) else None


def _comparison_result(
    *,
    result: str,
    expected: Mapping[str, Any] | None,
    actual: Mapping[str, Any] | None,
    exact_matches: list[str] | None = None,
    semantic_matches: list[str] | None = None,
    material_differences: list[str] | None = None,
    non_material_differences: list[str] | None = None,
    unresolved_differences: list[str] | None = None,
) -> dict[str, Any]:
    reference = expected if expected is not None else actual or {}
    return {
        "result": result,
        "exact_matches": exact_matches or [],
        "semantic_matches": semantic_matches or [],
        "material_differences": material_differences or [],
        "non_material_differences": non_material_differences or [],
        "unresolved_differences": unresolved_differences or [],
        "materiality_profile_id": reference.get("materiality_profile_ref"),
        "materiality_profile_version": "1.0" if reference.get("materiality_profile_ref") == "phase5-p0" else None,
        "comparator_version": SEMANTIC_COMPARATOR_VERSION,
    }


def _unresolved_paths(action: Mapping[str, Any]) -> list[str]:
    unresolved = action.get("unresolved_material")
    if not isinstance(unresolved, list):
        return ["unresolved_material"]
    # The values are evidence references rather than an untrusted comparator
    # grammar.  Canonicalize them only to give callers a stable explanation.
    return sorted({str(value) for value in unresolved}, key=lambda value: value.encode("utf-8"))


def semantic_equivalence(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> dict[str, Any]:
    """Compare V2 actions without turning ambiguity into execution authority.

    V1/V1.1 bodies retain their own verification path.  This routine never
    projects an older object into V2 implicitly: a cross-version comparison is
    useful only as an explicit ``UNKNOWN`` analytic result.
    """

    expected_version, actual_version = _schema_version(expected), _schema_version(actual)
    if expected_version != actual_version:
        return _comparison_result(
            result="UNKNOWN",
            expected=expected,
            actual=actual,
            unresolved_differences=["schema_version"],
        )
    if expected_version in _LEGACY_CANONICAL_ACTION_VERSIONS:
        return _comparison_result(
            result="UNKNOWN",
            expected=expected,
            actual=actual,
            unresolved_differences=["legacy_canonical_action"],
        )
    if expected_version not in {CANONICAL_ACTION_V2, "2.0"}:
        return _comparison_result(
            result="UNKNOWN",
            expected=expected,
            actual=actual,
            unresolved_differences=["schema_version"],
        )

    try:
        expected_hash, actual_hash = canonical_action_hash_v2(expected), canonical_action_hash_v2(actual)
        # Local import avoids an authority-layer import cycle.  This is the
        # sole materiality grammar, shared with receipt/permit consumers.
        from .materiality import MATERIAL_PATHS, material_fields

        expected_fields, actual_fields = material_fields(expected), material_fields(actual)
    except (TypeError, ValueError):
        return _comparison_result(
            result="UNKNOWN",
            expected=expected,
            actual=actual,
            unresolved_differences=["canonical_action"],
        )

    unresolved = sorted(
        set(_unresolved_paths(expected)).union(_unresolved_paths(actual)),
        key=lambda value: value.encode("utf-8"),
    )
    if unresolved:
        return _comparison_result(
            result="UNKNOWN",
            expected=expected,
            actual=actual,
            unresolved_differences=unresolved,
        )

    material_differences = [
        path for path in MATERIAL_PATHS if expected_fields[path] != actual_fields[path]
    ]
    if material_differences:
        return _comparison_result(
            result="NOT_EQUIVALENT",
            expected=expected,
            actual=actual,
            material_differences=material_differences,
        )
    if expected_hash == actual_hash:
        return _comparison_result(
            result="EXACT_MATCH",
            expected=expected,
            actual=actual,
            exact_matches=list(MATERIAL_PATHS),
        )

    non_material_paths = ("correlation_id", "created_at", "evidence_refs")
    changed_non_material = [
        path
        for path in non_material_paths
        if canonical_json_bytes(expected.get(path)) != canonical_json_bytes(actual.get(path))
    ]
    # A different canonical body with equal material fields but no recognized
    # non-material delta is not a reusable authority relationship.
    if not changed_non_material:
        return _comparison_result(
            result="UNKNOWN",
            expected=expected,
            actual=actual,
            unresolved_differences=["canonical_action"],
        )
    return _comparison_result(
        result="SEMANTIC_MATCH",
        expected=expected,
        actual=actual,
        semantic_matches=list(MATERIAL_PATHS),
        non_material_differences=changed_non_material,
    )
