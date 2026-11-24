"""The single closed materiality projection used by V2 authority checks."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

from .canonical_v2 import canonical_json_bytes, domain_hash


MATERIALITY_PROFILE_ID = "phase5-p0"
MATERIALITY_PROFILE_VERSION = "1.0"
MAX_MATERIAL_COLLECTION_ITEMS = 128
_MATERIAL_PATHS = (
    "tenant_id", "action_id", "chain_id", "parent_action_id", "actor_principal",
    "executing_principal", "represented_subjects[*]", "resource_scopes[*]",
    "authority_context", "business_purpose", "environment", "provider_runtime_context",
    "action_semantics.action_class", "action_semantics.operation", "action_semantics.object_type",
    "action_semantics.tool_or_service_ref", "action_semantics.tool_fingerprint",
    "action_semantics.safe_parameters", "action_semantics.represented_subject_refs[*]",
    "action_semantics.resource_refs[*]", "action_semantics.counterparty_refs[*]",
    "action_semantics.target_refs[*]", "action_semantics.destination_refs[*]",
    "action_semantics.values_or_quantities[*]", "action_semantics.authority_ref",
    "action_semantics.business_purpose_ref", "action_semantics.side_effect",
    "action_semantics.persistence", "action_semantics.environment", "action_semantics.reversibility",
    "action_semantics.expected_outcome_ref", "domain_profile_ref", "domain_profile_hash",
    "materiality_profile_ref", "materiality_profile_hash", "resolver_versions", "policy_version_id",
    "policy_epoch", "control_plan_id", "control_plan_digest", "approval_requirement",
    "delegation_digest", "action_plan_binding", "unresolved_material[*]",
)
_MATERIAL_COLLECTION_SEMANTICS = {
    "tenant_id": "SCALAR",
    "action_id": "SCALAR",
    "chain_id": "SCALAR",
    "parent_action_id": "SCALAR",
    "actor_principal": "SCALAR",
    "executing_principal": "SCALAR",
    "represented_subjects[*]": "UNORDERED_SET",
    "resource_scopes[*]": "UNORDERED_SET",
    "authority_context": "SCALAR",
    "business_purpose": "SCALAR",
    "environment": "SCALAR",
    "provider_runtime_context": "SCALAR",
    "action_semantics.action_class": "SCALAR",
    "action_semantics.operation": "SCALAR",
    "action_semantics.object_type": "SCALAR",
    "action_semantics.tool_or_service_ref": "SCALAR",
    "action_semantics.tool_fingerprint": "SCALAR",
    "action_semantics.safe_parameters": "MAP_BY_KEY",
    "action_semantics.represented_subject_refs[*]": "UNORDERED_SET",
    "action_semantics.resource_refs[*]": "UNORDERED_SET",
    "action_semantics.counterparty_refs[*]": "UNORDERED_SET",
    "action_semantics.target_refs[*]": "UNORDERED_SET",
    "action_semantics.destination_refs[*]": "UNORDERED_SET",
    "action_semantics.values_or_quantities[*]": "UNORDERED_MULTISET",
    "action_semantics.authority_ref": "SCALAR",
    "action_semantics.business_purpose_ref": "SCALAR",
    "action_semantics.side_effect": "SCALAR",
    "action_semantics.persistence": "SCALAR",
    "action_semantics.environment": "SCALAR",
    "action_semantics.reversibility": "SCALAR",
    "action_semantics.expected_outcome_ref": "SCALAR",
    "domain_profile_ref": "SCALAR",
    "domain_profile_hash": "SCALAR",
    "materiality_profile_ref": "SCALAR",
    "materiality_profile_hash": "SCALAR",
    "resolver_versions": "MAP_BY_KEY",
    "policy_version_id": "SCALAR",
    "policy_epoch": "SCALAR",
    "control_plan_id": "SCALAR",
    "control_plan_digest": "SCALAR",
    "approval_requirement": "SCALAR",
    "delegation_digest": "SCALAR",
    "action_plan_binding": "SCALAR",
    "unresolved_material[*]": "UNORDERED_SET",
}
_MATERIAL_PATH_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}(?:\.[a-z][a-z0-9_]{0,63}){0,7}(?:\[\*\])?$")


def _unsigned_utf8(value: str) -> bytes:
    return value.encode("utf-8")


def _validate_registry_path(path: str) -> None:
    if not isinstance(path, str) or len(path.encode("utf-8")) > 256 or not _MATERIAL_PATH_PATTERN.fullmatch(path):
        raise RuntimeError(f"invalid material field registry path: {path!r}")
    if path.count("[*]") > 1 or ("[*]" in path and not path.endswith("[*]")):
        raise RuntimeError(f"invalid material field registry wildcard: {path!r}")


for _path in _MATERIAL_PATHS:
    _validate_registry_path(_path)
if len(set(_MATERIAL_PATHS)) != len(_MATERIAL_PATHS) or set(_MATERIAL_COLLECTION_SEMANTICS) != set(_MATERIAL_PATHS):
    raise RuntimeError("material field registry is incomplete or ambiguous")

# Persist/hash iteration order is part of the frozen cross-language contract.
MATERIAL_PATHS = tuple(sorted(_MATERIAL_PATHS, key=_unsigned_utf8))
MATERIAL_COLLECTION_SEMANTICS = {
    path: _MATERIAL_COLLECTION_SEMANTICS[path]
    for path in MATERIAL_PATHS
}


def _get_path(value: Mapping[str, Any], path: str) -> Any:
    current: Any = value
    for piece in path.removesuffix("[*]").split("."):
        if not isinstance(current, Mapping) or piece not in current:
            raise ValueError(f"missing required material path: {path}")
        current = current[piece]
    return current


def _normalize_material_value(*, path: str, value: Any) -> Any:
    semantics = MATERIAL_COLLECTION_SEMANTICS[path]
    if semantics == "SCALAR":
        return value
    if semantics == "MAP_BY_KEY":
        if not isinstance(value, Mapping) or len(value) > MAX_MATERIAL_COLLECTION_ITEMS:
            raise ValueError(f"material map is invalid or too large: {path}")
        return value
    if not isinstance(value, list) or len(value) > MAX_MATERIAL_COLLECTION_ITEMS:
        raise ValueError(f"material collection is invalid or too large: {path}")
    serialized = [(canonical_json_bytes(item), item) for item in value]
    if semantics == "UNORDERED_SET" and len({item[0] for item in serialized}) != len(serialized):
        raise ValueError(f"material set contains duplicate canonical elements: {path}")
    if semantics in {"UNORDERED_SET", "UNORDERED_MULTISET"}:
        return [item for _, item in sorted(serialized, key=lambda item: item[0])]
    raise ValueError(f"unknown material collection semantics: {semantics}")


def material_fields(action: Mapping[str, Any]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for path in MATERIAL_PATHS:
        normalized = _normalize_material_value(path=path, value=_get_path(action, path))
        fields[path] = domain_hash(
            "hawk:material-field:v1",
            {
                "collection_semantics": MATERIAL_COLLECTION_SEMANTICS[path],
                "path": path,
                "value": normalized,
            },
        )
    return fields


def material_fields_hash(action: Mapping[str, Any]) -> str:
    fields = material_fields(action)
    return domain_hash(
        "hawk:material-fields:v1",
        {
            "fields": [{"field_hash": fields[path], "path": path} for path in sorted(fields, key=_unsigned_utf8)],
            "materiality_profile_hash": action["materiality_profile_hash"],
        },
    )
