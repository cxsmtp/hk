from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models.ai_system import AISystem
from app.db.models.shadow_ai import ShadowAIEntity
from app.services.shadow_ai.provider_catalog import canonical_tool_key, infer_from_signal

NON_UNIQUE_IDENTIFIERS = {
    "unknown",
    "unknown provider",
    "unknown_provider",
    "unknown_tool",
    "unknown_ai_entity",
    "unknown_ai_system",
    "none",
    "null",
    "n/a",
}


def _norm(value: str | None) -> str:
    return str(value or "").strip().lower()


def _title(value: str | None) -> str:
    text = str(value or "").strip()
    return text if text else ""


def _candidate_identifiers(signal: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    inferred = infer_from_signal(signal)
    for item in [
        inferred.get("domain"),
        inferred.get("provider"),
        inferred.get("tool_name"),
        inferred.get("canonical_key"),
        signal.get("domain"),
        signal.get("provider"),
        signal.get("tool_name"),
        signal.get("api_endpoint"),
        signal.get("app_id"),
        signal.get("model_name"),
        signal.get("process_name"),
        signal.get("host_id"),
    ]:
        normalized = _norm(str(item or ""))
        if not normalized:
            continue
        if normalized in NON_UNIQUE_IDENTIFIERS:
            continue
        if normalized.startswith("unknown_") or normalized.startswith("unknown "):
            continue
        if normalized:
            out.add(normalized)
    return out


def canonical_name_from_signal(signal: dict[str, Any]) -> str:
    runtime_identity = _norm(signal.get("agent_runtime_id"))
    if runtime_identity:
        # An observed runtime is distinct from the model provider it uses.
        return runtime_identity
    # Prefer normalized provider-catalog key so browser/proxy/dns/endpoint signals
    # collapse into one entity when they represent the same AI tool/provider.
    key = canonical_tool_key(signal)
    return str(key or "unknown_ai_entity").strip().lower() or "unknown_ai_entity"


@dataclass
class IdentityResolutionResult:
    canonical_name: str
    matched_ai_system_id: str | None
    shadow_ai_entity_id: str
    entity_created: bool
    match_type: str


def _find_ai_system_match(
    db: Session,
    *,
    tenant_id: str,
    canonical_name: str,
    explicit_ai_system_id: str | None,
) -> str | None:
    if explicit_ai_system_id:
        row = db.scalar(
            select(AISystem.id).where(
                AISystem.id == explicit_ai_system_id,
                AISystem.tenant_id == tenant_id,
            )
        )
        if row:
            return row

    lowered_name = canonical_name.lower()
    ai_system = db.scalar(
        select(AISystem).where(
            AISystem.tenant_id == tenant_id,
            func.lower(AISystem.name) == lowered_name,
        )
    )
    if ai_system:
        return ai_system.id
    return None


def _find_shadow_entity_match(
    db: Session,
    *,
    tenant_id: str,
    canonical_name: str,
    identifiers: set[str],
) -> ShadowAIEntity | None:
    direct = db.scalar(
        select(ShadowAIEntity).where(
            ShadowAIEntity.tenant_id == tenant_id,
            ShadowAIEntity.canonical_name == canonical_name,
        )
    )
    if direct is not None:
        return direct

    if not identifiers:
        return None

    rows = db.scalars(
        select(ShadowAIEntity).where(
            ShadowAIEntity.tenant_id == tenant_id,
        )
    ).all()
    best: ShadowAIEntity | None = None
    best_overlap = 0
    for row in rows:
        metadata = dict(row.metadata_json or {})
        # A provider observation cannot become an observed agent runtime merely
        # because both mention the same model, domain or provider.
        if metadata.get("agent_runtime_id"):
            continue
        existing = {_norm(item) for item in (metadata.get("source_identifiers") or []) if _norm(str(item))}
        overlap = len(existing.intersection(identifiers))
        if overlap > best_overlap:
            best = row
            best_overlap = overlap
    if best_overlap >= 2:
        return best
    return None


def resolve_identity(
    db: Session,
    *,
    tenant_id: str,
    signal: dict[str, Any],
    explicit_ai_system_id: str | None,
    source_surface: str,
    first_seen_at: datetime | None = None,
) -> IdentityResolutionResult:
    inferred = infer_from_signal(signal)
    normalized_signal = {
        **dict(signal or {}),
        "domain": signal.get("domain") or inferred.get("domain"),
        "provider": signal.get("provider") or inferred.get("provider"),
        "tool_name": signal.get("tool_name") or inferred.get("tool_name"),
        "tool_category": signal.get("tool_category") or inferred.get("tool_category"),
        "canonical_key": signal.get("canonical_key") or inferred.get("canonical_key"),
    }

    canonical_name = canonical_name_from_signal(normalized_signal)
    matched_ai_system_id = _find_ai_system_match(
        db,
        tenant_id=tenant_id,
        canonical_name=canonical_name,
        explicit_ai_system_id=explicit_ai_system_id,
    )
    observed_at = first_seen_at or datetime.now(timezone.utc)
    identifiers = _candidate_identifiers(normalized_signal)

    entity = _find_shadow_entity_match(
        db,
        tenant_id=tenant_id,
        canonical_name=canonical_name,
        # Shared model/provider identifiers cannot merge distinct runtimes.
        identifiers=set() if normalized_signal.get("agent_runtime_id") else identifiers,
    )

    if entity:
        surfaces = sorted(
            {
                *[str(item).strip().lower() for item in (entity.source_surfaces or []) if str(item).strip()],
                _norm(source_surface),
            }
        )
        entity.source_surfaces = surfaces
        # SQLite reloads timezone-aware columns as naive UTC values.
        previous_seen = entity.last_seen
        if previous_seen.tzinfo is None:
            previous_seen = previous_seen.replace(tzinfo=timezone.utc)
        if observed_at.tzinfo is None:
            observed_at = observed_at.replace(tzinfo=timezone.utc)
        entity.last_seen = max(observed_at, previous_seen)
        if matched_ai_system_id and not entity.linked_ai_system_id:
            entity.linked_ai_system_id = matched_ai_system_id
            entity.discovery_status = "reconciled"

        metadata = dict(entity.metadata_json or {})
        existing_identifiers = {
            *[str(item).strip() for item in (metadata.get("source_identifiers") or []) if str(item).strip()],
        }
        existing_identifiers.update(sorted(identifiers))
        metadata["source_identifiers"] = sorted(existing_identifiers)
        metadata["tool_category"] = normalized_signal.get("tool_category") or metadata.get("tool_category")
        metadata["canonical_key"] = canonical_name
        if normalized_signal.get("agent_runtime_id"):
            metadata["agent_runtime_id"] = _norm(normalized_signal["agent_runtime_id"])
        metadata["catalog_match"] = bool(inferred.get("catalog_match") or metadata.get("catalog_match"))
        entity.metadata_json = metadata
        if normalized_signal.get("provider") and not entity.vendor:
            entity.vendor = _title(str(normalized_signal.get("provider"))) or None
        db.flush()
        return IdentityResolutionResult(
            canonical_name=canonical_name,
            matched_ai_system_id=matched_ai_system_id or entity.linked_ai_system_id,
            shadow_ai_entity_id=entity.id,
            entity_created=False,
            match_type="existing_shadow_entity",
        )

    metadata = {
        "source_identifiers": sorted(identifiers),
        "first_observed_source": _norm(source_surface),
        "tool_category": normalized_signal.get("tool_category"),
        "canonical_key": canonical_name,
        "catalog_match": bool(inferred.get("catalog_match")),
    }
    if normalized_signal.get("agent_runtime_id"):
        metadata["agent_runtime_id"] = _norm(normalized_signal["agent_runtime_id"])
    new_entity = ShadowAIEntity(
        tenant_id=tenant_id,
        canonical_name=canonical_name,
        discovery_status="reconciled" if matched_ai_system_id else "discovered",
        confidence_score=0.0,
        provisional_risk_tier="MEDIUM",
        source_surfaces=[_norm(source_surface)],
        vendor=_title(str(normalized_signal.get("provider") or "")) or None,
        deployment_type=_title(str(normalized_signal.get("deployment_type") or "")) or None,
        ai_type=_title(str(normalized_signal.get("ai_type") or "")) or None,
        first_seen=observed_at,
        last_seen=observed_at,
        linked_ai_system_id=matched_ai_system_id,
        metadata_json=metadata,
    )
    db.add(new_entity)
    db.flush()
    return IdentityResolutionResult(
        canonical_name=canonical_name,
        matched_ai_system_id=matched_ai_system_id,
        shadow_ai_entity_id=new_entity.id,
        entity_created=True,
        match_type="created_shadow_entity",
    )
