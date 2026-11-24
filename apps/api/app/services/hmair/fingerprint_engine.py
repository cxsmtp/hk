from __future__ import annotations

from collections.abc import Mapping
import hashlib
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_asset import DiscoveryAssetFingerprint
from app.db.models.discovery_canonical import DiscoveryObservation
from app.services.hmair.contracts import (
    AICapabilityType,
    AssetFingerprintCreate,
    FingerprintComponentCategory,
    StrictContract,
    canonical_json_bytes,
)
from app.services.hmair.evidence_claim_service import EvidenceClaimScopeError
from app.services.hmair.fingerprint_service import persist_fingerprint
from app.services.hmair.normalization_service import (
    NormalizedDiscoveryObservation,
    normalize_observation,
)


FINGERPRINT_ENGINE_VERSION = "hmair-fingerprint-3.0.0"
SUPPORTED_FINGERPRINT_COMPONENTS = tuple(
    item.value for item in FingerprintComponentCategory
)

_CONTENT_KEYS = frozenset(
    {
        "body",
        "content",
        "cookie",
        "history",
        "message",
        "prompt",
        "raw",
        "response",
        "text",
    }
)
_SECRET_KEY_PARTS = (
    "authorization",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
)


class DerivedFingerprintMaterial(StrictContract):
    source_observation_id: str
    component_hashes: dict[str, str]
    detected_products: tuple[str, ...]
    detected_frameworks: tuple[str, ...]
    detected_models: tuple[str, ...]
    detected_protocols: tuple[str, ...]
    detected_capabilities: tuple[str, ...]
    observed_destinations: tuple[str, ...]
    confidence: float
    limitations: tuple[str, ...]


def _safe_value(value: object) -> object:
    if isinstance(value, Mapping):
        output: dict[str, object] = {}
        for raw_key in sorted(value, key=lambda item: str(item)):
            key = str(raw_key).strip().casefold()
            if key in _CONTENT_KEYS:
                output[key] = "content_excluded"
            elif any(part in key for part in _SECRET_KEY_PARTS):
                output[key] = "secret_value_excluded"
            else:
                output[key] = _safe_value(value[raw_key])
        return output
    if isinstance(value, (tuple, list)):
        return tuple(_safe_value(item) for item in value[:128])
    if value is None or type(value) in {bool, int, float}:
        return value
    if isinstance(value, str):
        return value.strip()[:512]
    return type(value).__name__


def _matching_values(value: object, fragments: tuple[str, ...]) -> tuple[str, ...]:
    output: set[str] = set()

    def visit(current: object) -> None:
        if isinstance(current, Mapping):
            for raw_key in sorted(current, key=lambda item: str(item)):
                key = str(raw_key).strip().casefold()
                child = current[raw_key]
                if any(fragment in key for fragment in fragments):
                    candidates = child if isinstance(child, (tuple, list)) else (child,)
                    for candidate in candidates:
                        if isinstance(candidate, str) and candidate.strip():
                            output.add(candidate.strip()[:512])
                visit(child)
        elif isinstance(current, (tuple, list)):
            for child in current[:128]:
                visit(child)

    visit(value)
    return tuple(sorted(output))[:128]


def _destination(value: str) -> str:
    candidate = value.strip()
    if "://" in candidate:
        parsed = urlsplit(candidate)
        return (parsed.hostname or "unknown_destination").casefold()[:255]
    return candidate.casefold()[:255]


def _component_material(
    observation: NormalizedDiscoveryObservation,
    category: str,
) -> object:
    sources = (
        observation.identifiers,
        observation.normalized_signal,
        observation.attributes,
        observation.configuration_summary,
        observation.usage_summary,
        observation.identity_hints,
        observation.relationship_hints,
    )
    combined = {f"source_{index}": _safe_value(source) for index, source in enumerate(sources)}
    selectors: dict[str, tuple[str, ...]] = {
        "executable": ("executable", "binary", "process", "path", "hash"),
        "package": ("package", "application", "product", "bundle"),
        "dependency": ("dependency", "sdk", "framework", "library"),
        "provider": ("provider", "workspace", "tenant"),
        "model": ("model", "deployment", "version"),
        "protocol": ("protocol", "transport", "scheme"),
        "runtime": ("runtime", "framework", "process", "container"),
        "network": ("destination", "domain", "host", "network", "url"),
        "identity": ("identity", "principal", "subject", "user", "account"),
    }
    if category == "configuration":
        return _safe_value(observation.configuration_summary)
    if category == "capability":
        return tuple(sorted(observation.capability_hints))
    if category == "behavior":
        return {
            "observed_state": observation.observed_state,
            "signal_type": observation.signal_type,
            "usage": _safe_value(observation.usage_summary),
        }
    fragments = selectors[category]
    values = _matching_values(combined, fragments)
    return values


def _hash_component(category: str, material: object) -> str:
    return hashlib.sha256(
        b"hawk:hmair:fingerprint-component:v3\x00"
        + category.encode("ascii")
        + b"\x00"
        + canonical_json_bytes(material)
    ).hexdigest()


def derive_fingerprint_material(
    observations: tuple[NormalizedDiscoveryObservation, ...],
) -> DerivedFingerprintMaterial:
    if not observations or len(observations) > 128:
        raise EvidenceClaimScopeError(
            "fingerprint observations must be non-empty and bounded"
        )
    ordered = tuple(
        sorted(observations, key=lambda item: (item.observed_at, item.observation_id))
    )
    if len({item.observation_id for item in ordered}) != len(ordered):
        raise EvidenceClaimScopeError("fingerprint observations must be unique")

    components: dict[str, str] = {}
    for category in SUPPORTED_FINGERPRINT_COMPONENTS:
        materials = tuple(
            material
            for observation in ordered
            if (material := _component_material(observation, category))
            not in ((), {}, None, "")
        )
        if materials:
            components[category] = _hash_component(category, materials)

    products = sorted(
        {
            value
            for observation in ordered
            for value in observation.comparison_material.get("applications", ())
        }
    )[:128]
    frameworks = sorted(
        {
            value
            for observation in ordered
            for value in observation.comparison_material.get("frameworks", ())
        }
    )[:128]
    models = sorted(
        {
            value
            for observation in ordered
            for value in observation.comparison_material.get("models", ())
        }
    )[:128]
    protocols = sorted(
        {
            value.casefold()
            for observation in ordered
            for source in (
                observation.normalized_signal,
                observation.attributes,
                observation.configuration_summary,
            )
            for value in _matching_values(source, ("protocol", "transport", "scheme"))
        }
    )[:128]
    capabilities = tuple(
        item.value
        for item in AICapabilityType
        if any(item.value in observation.capability_hints for observation in ordered)
    )
    destinations = sorted(
        {
            _destination(value)
            for observation in ordered
            for source in (observation.normalized_signal, observation.relationship_hints)
            for value in _matching_values(source, ("destination", "domain", "host", "url"))
        }
    )[:128]

    return DerivedFingerprintMaterial(
        source_observation_id=ordered[-1].observation_id,
        component_hashes=components,
        detected_products=tuple(products),
        detected_frameworks=tuple(frameworks),
        detected_models=tuple(models),
        detected_protocols=tuple(protocols),
        detected_capabilities=capabilities,
        observed_destinations=tuple(destinations),
        confidence=min(float(item.confidence) for item in ordered),
        limitations=(
            "content_values_excluded",
            "secret_bearing_values_excluded",
            "component_hashes_are_not_identity_proof",
        ),
    )


def fingerprint_observation(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    source_observation_id: str,
    evidence_claim_id: str,
) -> DiscoveryAssetFingerprint:
    observation = db.scalar(
        select(DiscoveryObservation).where(
            DiscoveryObservation.tenant_id == tenant_id,
            DiscoveryObservation.observation_id == source_observation_id,
        )
    )
    if observation is None:
        raise EvidenceClaimScopeError("fingerprint observation is unavailable")
    material = derive_fingerprint_material((normalize_observation(observation),))
    current = db.scalar(
        select(DiscoveryAssetFingerprint)
        .where(
            DiscoveryAssetFingerprint.tenant_id == tenant_id,
            DiscoveryAssetFingerprint.asset_id == asset_id,
        )
        .order_by(
            DiscoveryAssetFingerprint.chain_sequence.desc(),
            DiscoveryAssetFingerprint.fingerprint_id.desc(),
        )
        .limit(1)
    )
    return persist_fingerprint(
        db,
        tenant_id=tenant_id,
        payload=AssetFingerprintCreate(
            asset_id=asset_id,
            source_observation_id=material.source_observation_id,
            evidence_claim_id=evidence_claim_id,
            fingerprint_version=FINGERPRINT_ENGINE_VERSION,
            component_hashes=material.component_hashes,
            detected_products=material.detected_products,
            detected_frameworks=material.detected_frameworks,
            detected_models=material.detected_models,
            detected_protocols=material.detected_protocols,
            detected_capabilities=material.detected_capabilities,
            observed_destinations=material.observed_destinations,
            confidence=material.confidence,
            supersedes_fingerprint_id=(
                current.fingerprint_id if current is not None else None
            ),
            drift_summary={},
        ),
    )


__all__ = [
    "DerivedFingerprintMaterial",
    "FINGERPRINT_ENGINE_VERSION",
    "SUPPORTED_FINGERPRINT_COMPONENTS",
    "derive_fingerprint_material",
    "fingerprint_observation",
]
