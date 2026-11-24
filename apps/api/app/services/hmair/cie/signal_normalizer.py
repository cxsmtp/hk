from __future__ import annotations

from collections.abc import Mapping
import hashlib
import re
import unicodedata

from app.db.models.discovery_canonical import DiscoveryObservation
from app.services.hmair.cie.catalog import CAPABILITY_CATALOG
from app.services.hmair.cie.contracts import (
    CIESignalType,
    NormalizedCapabilitySignal,
)
from app.services.hmair.contracts import canonical_json_bytes
from app.services.hmair.normalization_service import normalize_observation


_TOKEN_SEPARATOR_RE = re.compile(r"[^a-z0-9]+")
_CAPABILITY_ALIASES = {
    "embeddings": "embedding_generation",
    "file_read": "filesystem_read",
    "file_write": "filesystem_write",
    "mcp_client": "mcp_client",
    "mcp_server": "mcp_server",
    "model_inference": "inference",
    "shell_execution": "terminal_execution",
    "tool_execution": "tool_invocation",
}
_SIGNAL_TYPE_BY_SURFACE = {
    "api_gateway": CIESignalType.API,
    "browser": CIESignalType.EXTENSION,
    "cloud": CIESignalType.API,
    "database": CIESignalType.DATABASE,
    "dns": CIESignalType.DNS,
    "endpoint": CIESignalType.PROCESS,
    "identity": CIESignalType.IDENTITY,
    "mcp": CIESignalType.MCP,
    "model_endpoint": CIESignalType.MODEL,
    "network": CIESignalType.NETWORK,
    "runtime": CIESignalType.RUNTIME,
    "saas": CIESignalType.API,
    "source_code": CIESignalType.REPOSITORY,
    "vector_store": CIESignalType.VECTOR_STORE,
}
_STRUCTURAL_KEY_FACTS = {
    "agent_framework": "agent_framework_context",
    "browser_automation": "browser_context",
    "database": "database_context",
    "database_id": "database_context",
    "execution_context": "execution_context",
    "executable": "execution_context",
    "executable_path": "execution_context",
    "identity": "identity_context",
    "identity_id": "identity_context",
    "mcp_server": "mcp_context",
    "mcp_tool": "tool_context",
    "memory": "memory_context",
    "memory_store": "memory_context",
    "model": "model_context",
    "model_id": "model_context",
    "model_provider": "model_context",
    "prompt_store": "prompt_store_context",
    "provider": "model_context",
    "repository": "repository_context",
    "repository_path": "repository_context",
    "repository_root": "repository_context",
    "runtime": "runtime_context",
    "runtime_id": "runtime_context",
    "tool": "tool_context",
    "tool_name": "tool_context",
    "vector_database": "vector_context",
    "vector_store": "vector_context",
}


def _token(value: object) -> str:
    normalized = unicodedata.normalize("NFKC", str(value)).strip().casefold()
    return _TOKEN_SEPARATOR_RE.sub("_", normalized).strip("_")


def _walk_facts(value: object, output: set[str]) -> None:
    if isinstance(value, Mapping):
        for raw_key in sorted(value, key=lambda item: str(item)):
            key = _token(raw_key)
            child = value[raw_key]
            has_value = child is not None and child is not False and child != "" and child != ()
            if key in _STRUCTURAL_KEY_FACTS and has_value:
                output.add(_STRUCTURAL_KEY_FACTS[key])
            _walk_facts(child, output)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _walk_facts(child, output)


class SignalNormalizer:
    """Adapt an immutable DiscoveryObservation without creating another signal row."""

    def normalize(self, observation: DiscoveryObservation) -> NormalizedCapabilitySignal:
        normalized = normalize_observation(observation)
        observation_type = _token(normalized.signal_type)
        try:
            signal_type = CIESignalType(observation_type)
        except ValueError:
            signal_type = _SIGNAL_TYPE_BY_SURFACE.get(
                normalized.source_surface, CIESignalType.USAGE
            )

        facts: set[str] = set()
        if signal_type is CIESignalType.REPOSITORY:
            facts.add("repository_context")
        if signal_type in {CIESignalType.EXECUTABLE, CIESignalType.PROCESS}:
            facts.add("execution_context")
        if signal_type is CIESignalType.RUNTIME:
            facts.add("runtime_context")
        if signal_type is CIESignalType.MODEL:
            facts.add("model_context")
        if signal_type is CIESignalType.VECTOR_STORE:
            facts.add("vector_context")
        if signal_type is CIESignalType.MCP:
            facts.add("mcp_context")
        if signal_type in {CIESignalType.NETWORK, CIESignalType.DNS}:
            facts.add("network_context")
        for material in (
            normalized.normalized_signal,
            normalized.attributes,
            normalized.configuration_summary,
        ):
            _walk_facts(material, facts)
        comparison = normalized.comparison_material
        if comparison.get("providers") or comparison.get("models"):
            facts.add("model_context")
        if comparison.get("identities") or normalized.identity_hints:
            facts.add("identity_context")
        if normalized.usage_summary:
            facts.add("usage_context")

        for raw_hint in normalized.capability_hints:
            hint = _token(raw_hint)
            capability_id = _CAPABILITY_ALIASES.get(hint, hint)
            if capability_id in CAPABILITY_CATALOG:
                facts.add(f"capability:{capability_id}")

        product_hint = next(iter(comparison.get("applications", ())), None)
        attributes = {
            "candidate_asset_type": normalized.candidate_asset_type,
            "collector_type": normalized.collector_type,
            "observed_state": normalized.observed_state,
            "subject_reference_hash": hashlib.sha256(
                (normalized.subject_reference or normalized.observation_id).encode(
                    "utf-8", errors="strict"
                )
            ).hexdigest(),
        }
        signal_material = {
            "normalization_digest": normalized.normalization_digest,
            "observation_id": normalized.observation_id,
            "facts": tuple(sorted(facts)),
            "attributes": attributes,
        }
        signal_id = hashlib.sha256(
            b"hawk:cie:normalized-signal:v1\x00"
            + canonical_json_bytes(signal_material)
        ).hexdigest()
        return NormalizedCapabilitySignal(
            signal_id=signal_id,
            tenant_id=observation.tenant_id,
            observation_id=normalized.observation_id,
            collector_id=normalized.collector_id,
            source=normalized.source_surface,
            signal_type=signal_type,
            timestamp=normalized.observed_at,
            confidence=normalized.confidence,
            attributes=attributes,
            facts=tuple(sorted(facts)),
            relationship_hints=tuple(dict(item) for item in normalized.relationship_hints),
            evidence_reference=normalized.evidence_reference,
            evidence_hash=normalized.evidence_hash,
            freshness=normalized.freshness,
            verification_state=normalized.verification_state,
            source_trust=normalized.source_trust,
            contradiction_state=normalized.contradiction_state,
            product_hint=product_hint,
        )

    def normalize_many(
        self, observations: tuple[DiscoveryObservation, ...]
    ) -> tuple[NormalizedCapabilitySignal, ...]:
        signals = tuple(self.normalize(item) for item in observations)
        return tuple(sorted(signals, key=lambda item: item.signal_id))


__all__ = ["SignalNormalizer"]
