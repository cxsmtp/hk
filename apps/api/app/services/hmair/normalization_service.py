from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import posixpath
import re
from typing import Any
import unicodedata

from app.db.models.discovery_canonical import DiscoveryObservation
from app.services.hmair.contracts import StrictContract, canonical_json_bytes


NORMALIZATION_SCHEMA_VERSION = "phase-x-normalization-1.0"
_KEY_SEPARATOR_RE = re.compile(r"[^a-z0-9]+")
_CAMEL_BOUNDARY_RE = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL_ACRONYM_RE = re.compile(r"([a-z0-9])([A-Z])")
_TOKEN_SEPARATOR_RE = re.compile(r"[^a-z0-9]+")
_COMPARISON_CATEGORIES = (
    "applications",
    "configurations",
    "frameworks",
    "identities",
    "models",
    "paths",
    "providers",
    "sdks",
    "versions",
)
_KEY_CATEGORIES = {
    "applications": frozenset(
        {"application", "application_name", "app", "app_name", "product", "product_name"}
    ),
    "frameworks": frozenset({"framework", "framework_name"}),
    "identities": frozenset(
        {
            "actor",
            "actor_id",
            "email",
            "identity",
            "identity_id",
            "principal",
            "principal_id",
            "service_principal",
            "service_principal_id",
            "upn",
            "user",
            "user_email",
            "user_id",
        }
    ),
    "models": frozenset({"model", "model_family", "model_id", "model_name"}),
    "paths": frozenset(
        {
            "binary_path",
            "config_path",
            "cwd",
            "executable",
            "executable_path",
            "file_path",
            "path",
            "repository_path",
            "repository_root",
            "working_directory",
        }
    ),
    "providers": frozenset(
        {"inference_provider", "model_provider", "provider", "provider_family", "provider_name"}
    ),
    "sdks": frozenset({"client_library", "sdk", "sdk_name"}),
    "versions": frozenset(
        {"app_version", "framework_version", "model_version", "runtime_version", "sdk_version", "version"}
    ),
}


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _ordered_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): _ordered_json(value[key])
            for key in sorted(value, key=lambda item: str(item))
        }
    if isinstance(value, list):
        return [_ordered_json(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_ordered_json(item) for item in value)
    return value


def _normalized_key(value: object) -> str:
    text = unicodedata.normalize("NFKC", str(value)).strip()
    separated = _CAMEL_BOUNDARY_RE.sub(r"\1_\2", text)
    separated = _CAMEL_ACRONYM_RE.sub(r"\1_\2", separated)
    return _KEY_SEPARATOR_RE.sub("_", separated.casefold()).strip("_")


def _normalized_token(value: str) -> str:
    text = unicodedata.normalize("NFKC", value).strip().casefold()
    return _TOKEN_SEPARATOR_RE.sub("_", text).strip("_")


def _normalized_path(value: str) -> str:
    text = unicodedata.normalize("NFKC", value).strip().replace("\\", "/")
    normalized = posixpath.normpath(text)
    return "" if normalized == "." and text != "." else normalized


def _comparison_value(category: str, value: str) -> str:
    if category == "paths":
        return _normalized_path(value)
    if category == "identities":
        return unicodedata.normalize("NFKC", value).strip().casefold()
    if category == "versions":
        return unicodedata.normalize("NFKC", value).strip()
    return _normalized_token(value)


def _collect_comparison_values(
    value: object,
    *,
    output: dict[str, set[str]],
) -> None:
    if isinstance(value, Mapping):
        for raw_key in sorted(value, key=lambda item: str(item)):
            child = value[raw_key]
            key = _normalized_key(raw_key)
            for category, names in _KEY_CATEGORIES.items():
                if key not in names:
                    continue
                candidates = child if isinstance(child, (list, tuple)) else (child,)
                for candidate in candidates:
                    if not isinstance(candidate, str):
                        continue
                    normalized = _comparison_value(category, candidate)
                    if normalized:
                        output[category].add(normalized)
            _collect_comparison_values(child, output=output)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _collect_comparison_values(child, output=output)


def _collect_configuration_paths(
    value: object,
    *,
    prefix: tuple[str, ...],
    output: set[str],
) -> None:
    if isinstance(value, Mapping):
        for raw_key in sorted(value, key=lambda item: str(item)):
            key = _normalized_key(raw_key)
            if not key:
                continue
            path = (*prefix, key)
            output.add(".".join(path))
            _collect_configuration_paths(value[raw_key], prefix=path, output=output)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _collect_configuration_paths(child, prefix=prefix, output=output)


def _comparison_material(observation: DiscoveryObservation) -> dict[str, tuple[str, ...]]:
    values = {category: set() for category in _COMPARISON_CATEGORIES}
    for source in (
        observation.identifiers_json,
        observation.normalized_signal_json,
        observation.attributes_json,
        observation.configuration_summary_json,
        observation.usage_summary_json,
        observation.identity_hints_json,
        observation.relationship_hints_json,
    ):
        _collect_comparison_values(source, output=values)
    _collect_configuration_paths(
        observation.configuration_summary_json,
        prefix=(),
        output=values["configurations"],
    )
    return {
        category: tuple(sorted(values[category]))
        for category in _COMPARISON_CATEGORIES
    }


class NormalizedDiscoveryObservation(StrictContract):
    normalization_schema_version: str
    normalization_digest: str
    observation_id: str
    collector_id: str
    collector_type: str
    collector_version: str
    target_id: str
    source_surface: str
    subject_reference: str | None
    signal_type: str
    candidate_asset_type: str
    observed_state: str
    identifiers: Mapping[str, str]
    normalized_signal: Mapping[str, Any]
    attributes: Mapping[str, Any]
    configuration_summary: Mapping[str, Any]
    usage_summary: Mapping[str, Any]
    capability_hints: tuple[str, ...]
    identity_hints: tuple[Mapping[str, Any], ...]
    relationship_hints: tuple[Mapping[str, Any], ...]
    observed_at: datetime
    evidence_reference: str
    evidence_hash: str
    evidence_mode: str
    evidence_mutability: str
    signature_status: str
    confidence: float
    freshness: str
    verification_state: str
    source_trust: str
    contradiction_state: str
    contradiction_references: tuple[str, ...]
    parser_version: str
    source_schema_version: str
    comparison_material: Mapping[str, tuple[str, ...]]
    asset_id: None = None
    inferred_relationships: tuple[str, ...] = ()


def normalize_observation(
    observation: DiscoveryObservation,
) -> NormalizedDiscoveryObservation:
    if not isinstance(observation, DiscoveryObservation):
        raise TypeError("normalization requires a persisted observation")

    material: dict[str, object] = {
        "normalization_schema_version": NORMALIZATION_SCHEMA_VERSION,
        "observation_id": observation.observation_id,
        "collector_id": observation.collector_id,
        "collector_type": observation.collector_type,
        "collector_version": observation.collector_version,
        "target_id": observation.target_id,
        "source_surface": observation.source_surface,
        "subject_reference": observation.subject_reference,
        "signal_type": observation.observation_type,
        "candidate_asset_type": observation.candidate_asset_type,
        "observed_state": observation.observed_state,
        "identifiers": _ordered_json(observation.identifiers_json),
        "normalized_signal": _ordered_json(
            observation.normalized_signal_json
        ),
        "attributes": _ordered_json(observation.attributes_json),
        "configuration_summary": _ordered_json(
            observation.configuration_summary_json
        ),
        "usage_summary": _ordered_json(observation.usage_summary_json),
        "capability_hints": tuple(sorted(observation.capability_hints_json)),
        "identity_hints": tuple(
            _ordered_json(item) for item in observation.identity_hints_json
        ),
        "relationship_hints": tuple(
            _ordered_json(item)
            for item in observation.relationship_hints_json
        ),
        "observed_at": _utc(observation.observed_at).isoformat(),
        "evidence_reference": observation.evidence_reference,
        "evidence_hash": observation.evidence_hash,
        "evidence_mode": observation.evidence_mode,
        "evidence_mutability": observation.evidence_mutability,
        "signature_status": observation.signature_status,
        "confidence": float(observation.confidence),
        "freshness": observation.freshness,
        "verification_state": observation.verification_state,
        "source_trust": observation.source_trust,
        "contradiction_state": observation.contradiction_state,
        "contradiction_references": tuple(
            sorted(observation.contradiction_references_json)
        ),
        "parser_version": observation.parser_version,
        "source_schema_version": observation.schema_version,
        "comparison_material": _comparison_material(observation),
        "asset_id": None,
        "inferred_relationships": (),
    }
    digest = hashlib.sha256(
        b"hawk:hmair:normalization:v1\x00" + canonical_json_bytes(material)
    ).hexdigest()
    return NormalizedDiscoveryObservation(
        **{
            **material,
            "observed_at": _utc(observation.observed_at),
            "normalization_digest": digest,
        }
    )


__all__ = [
    "NORMALIZATION_SCHEMA_VERSION",
    "NormalizedDiscoveryObservation",
    "normalize_observation",
]
