"""Deterministic, redaction-safe projection of observed AI control paths."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.activity_audit import AIAction
from app.db.models.control_coverage import ControlCoveragePath, DeploymentSurface
from app.db.models.runtime_intelligence import RuntimeEvent


PATH_KEY_VERSION = "1.0"
MAX_SOURCE_REFS = 20


def _norm(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if not normalized:
        raise ValueError("path components must use explicit unknown placeholders")
    return normalized


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _text(value: object) -> str:
    return str(value or "").strip()


def _bounded_identifier(value: object, *, domain: str) -> str:
    """Return a display-safe identifier, hashing values that can contain URL detail."""
    raw = _text(value)
    if not raw:
        return ""
    lowered = raw.lower()
    secret_shaped = (
        lowered.startswith(("sk-", "ghp_", "github_pat_", "xoxb-", "xoxp-", "xoxa-", "xoxr-"))
        or any(
            marker in lowered
            for marker in (
                "api_key=",
                "apikey=",
                "access_token=",
                "authorization:",
                "bearer ",
                "password=",
                "secret=",
                "token=",
            )
        )
    )
    unsafe = secret_shaped or any(marker in raw for marker in ("?", "#", "&", "\n", "\r")) or "://" in raw
    if unsafe or len(raw) > 180:
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return f"{domain}_hash:{digest}"
    return raw.lower()


def _host(value: object) -> str:
    raw = _text(value)
    if not raw:
        return ""
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    return _bounded_identifier(parsed.hostname or "", domain="host")


def _prefixed(prefix: str, value: object) -> str:
    identifier = _bounded_identifier(value, domain=prefix.rstrip(":"))
    if not identifier:
        return ""
    if identifier.startswith(f"{prefix.rstrip(':')}_hash:"):
        return identifier
    return f"{prefix}{identifier}"


@dataclass(frozen=True)
class PathCandidate:
    asset_ref: str
    identity_type: str
    identity_ref: str
    runtime_ref: str
    deployment_surface_ref: str
    destination_type: str
    destination_ref: str
    source_ref: str
    deployment_surface_id: str | None = None

    def score_components(self) -> tuple[str, ...]:
        return tuple(
            _norm(item)
            for item in (
                self.asset_ref,
                self.identity_type,
                self.identity_ref,
                self.runtime_ref,
                self.deployment_surface_ref,
                self.destination_type,
                self.destination_ref,
            )
        )


def make_path_key(candidate: PathCandidate) -> str:
    body = json.dumps(
        {"version": PATH_KEY_VERSION, "components": candidate.score_components()},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def _surface_projection(
    *,
    deployment_surface: DeploymentSurface | None,
    fallback_surface: object,
    source_ref: str,
) -> tuple[str | None, str]:
    if deployment_surface is not None:
        return deployment_surface.id, _prefixed(f"{deployment_surface.source_kind}:", deployment_surface.source_id)
    fallback = _bounded_identifier(fallback_surface, domain="surface")
    if fallback:
        return None, f"source_surface:{fallback}"
    return None, f"unknown_surface:{source_ref}"


def _runtime_ref(metadata: Mapping[str, Any], *, fallback_model: object, source_ref: str) -> str:
    canonical = _mapping(metadata.get("canonical_ai_action_v1"))
    canonical_surface = _mapping(canonical.get("surface"))
    provider = (
        canonical_surface.get("provider")
        or metadata.get("provider")
        or metadata.get("model_provider")
        or metadata.get("provider_key")
    )
    model = canonical_surface.get("model") or metadata.get("model") or metadata.get("model_name") or fallback_model
    safe_provider = _bounded_identifier(provider, domain="provider")
    safe_model = _bounded_identifier(model, domain="model")
    if safe_provider and safe_model:
        return f"model:{safe_provider}/{safe_model}"
    if safe_model:
        return f"model:{safe_model}"
    if safe_provider:
        return f"provider:{safe_provider}"
    return f"unknown_runtime:{source_ref}"


def _destination(metadata: Mapping[str, Any], *, source_ref: str) -> tuple[str, str]:
    canonical = _mapping(metadata.get("canonical_ai_action_v1"))
    canonical_action = _mapping(canonical.get("action"))
    tool_name = canonical_action.get("tool_name") or metadata.get("tool_name") or metadata.get("tool")
    safe_tool = _bounded_identifier(tool_name, domain="tool")
    if safe_tool:
        return "tool", safe_tool if safe_tool.startswith("tool_hash:") else f"tool:{safe_tool}"

    destination_host = metadata.get("destination_host") or metadata.get("destination_domain")
    safe_host = _host(destination_host)
    if safe_host:
        return "host", f"host:{safe_host}"

    endpoint = metadata.get("api_endpoint") or metadata.get("destination_url")
    endpoint_host = _host(endpoint)
    if endpoint_host:
        return "host", f"host:{endpoint_host}"

    target = canonical_action.get("target_resource") or metadata.get("target_resource")
    if _text(target):
        digest = hashlib.sha256(_text(target).encode("utf-8")).hexdigest()
        return "resource", f"resource_hash:{digest}"
    return "unknown", f"unknown_destination:{source_ref}"


def runtime_event_candidate(
    event: RuntimeEvent,
    *,
    deployment_surface: DeploymentSurface | None = None,
) -> PathCandidate:
    source_ref = f"runtime_event:{_bounded_identifier(event.event_id, domain='runtime_event')}"
    metadata = _mapping(event.metadata_json)

    if event.ai_system_id:
        asset_ref = _prefixed("ai_system:", event.ai_system_id)
    elif metadata.get("discovery_asset_ref"):
        asset_ref = _prefixed("discovery_asset:", metadata.get("discovery_asset_ref"))
    elif metadata.get("shadow_asset_id"):
        asset_ref = _prefixed("shadow_asset:", metadata.get("shadow_asset_id"))
    elif event.app_id or event.application:
        asset_ref = _prefixed("application:", event.app_id or event.application)
    else:
        asset_ref = f"unknown_asset:{source_ref}"

    if event.user_id:
        identity_type, identity_ref = "user", _prefixed("user:", event.user_id)
    elif event.agent_id:
        identity_type, identity_ref = "agent", _prefixed("agent:", event.agent_id)
    else:
        service_id = (
            metadata.get("service_identity_id")
            or metadata.get("service_account_id")
            or metadata.get("workload_identity_id")
        )
        if service_id:
            identity_type, identity_ref = "service_identity", _prefixed("service_identity:", service_id)
        else:
            identity_type, identity_ref = "unknown", f"unknown_identity:{source_ref}"

    deployment_surface_id, deployment_surface_ref = _surface_projection(
        deployment_surface=deployment_surface,
        fallback_surface=event.source_surface,
        source_ref=source_ref,
    )
    destination_type, destination_ref = _destination(metadata, source_ref=source_ref)
    return PathCandidate(
        asset_ref=asset_ref,
        identity_type=identity_type,
        identity_ref=identity_ref,
        runtime_ref=_runtime_ref(metadata, fallback_model=None, source_ref=source_ref),
        deployment_surface_id=deployment_surface_id,
        deployment_surface_ref=deployment_surface_ref,
        destination_type=destination_type,
        destination_ref=destination_ref,
        source_ref=source_ref,
    )


def ai_action_candidate(
    action: AIAction,
    *,
    deployment_surface: DeploymentSurface | None = None,
) -> PathCandidate:
    source_ref = f"ai_action:{_bounded_identifier(action.action_id, domain='ai_action')}"
    metadata = _mapping(action.metadata_json)
    canonical = _mapping(metadata.get("canonical_ai_action_v1"))
    canonical_surface = _mapping(canonical.get("surface"))
    canonical_actor = _mapping(canonical.get("actor"))

    ai_system_id = metadata.get("ai_system_id")
    if ai_system_id:
        asset_ref = _prefixed("ai_system:", ai_system_id)
    elif action.ai_app or canonical_surface.get("application"):
        asset_ref = _prefixed("application:", action.ai_app or canonical_surface.get("application"))
    else:
        asset_ref = f"unknown_asset:{source_ref}"

    if action.user_id or canonical_actor.get("user_id"):
        identity_type = "user"
        identity_ref = _prefixed("user:", action.user_id or canonical_actor.get("user_id"))
    elif canonical_actor.get("agent_id"):
        identity_type = "agent"
        identity_ref = _prefixed("agent:", canonical_actor.get("agent_id"))
    elif canonical_actor.get("identity_id"):
        identity_type = _bounded_identifier(canonical_actor.get("identity_type"), domain="identity_type") or "service_identity"
        identity_ref = _prefixed(f"{identity_type}:", canonical_actor.get("identity_id"))
    else:
        identity_type, identity_ref = "unknown", f"unknown_identity:{source_ref}"

    fallback_surface = canonical_surface.get("surface_type") or metadata.get("source_surface")
    if not fallback_surface and action.endpoint_id:
        fallback_surface = f"endpoint:{action.endpoint_id}"
    deployment_surface_id, deployment_surface_ref = _surface_projection(
        deployment_surface=deployment_surface,
        fallback_surface=fallback_surface,
        source_ref=source_ref,
    )
    destination_type, destination_ref = _destination(metadata, source_ref=source_ref)
    return PathCandidate(
        asset_ref=asset_ref,
        identity_type=identity_type,
        identity_ref=identity_ref,
        runtime_ref=_runtime_ref(metadata, fallback_model=action.ai_model, source_ref=source_ref),
        deployment_surface_id=deployment_surface_id,
        deployment_surface_ref=deployment_surface_ref,
        destination_type=destination_type,
        destination_ref=destination_ref,
        source_ref=source_ref,
    )


def upsert_path(
    db: Session,
    *,
    tenant_id: str,
    candidate: PathCandidate,
    observed_at: datetime,
) -> ControlCoveragePath:
    path_key = make_path_key(candidate)
    row = db.scalar(
        select(ControlCoveragePath).where(
            ControlCoveragePath.tenant_id == tenant_id,
            ControlCoveragePath.path_key == path_key,
        )
    )
    if row is None:
        row = ControlCoveragePath(
            tenant_id=tenant_id,
            path_key=path_key,
            key_version=PATH_KEY_VERSION,
            asset_ref=_norm(candidate.asset_ref),
            identity_type=_norm(candidate.identity_type),
            identity_ref=_norm(candidate.identity_ref),
            runtime_ref=_norm(candidate.runtime_ref),
            deployment_surface_id=candidate.deployment_surface_id,
            deployment_surface_ref=_norm(candidate.deployment_surface_ref),
            destination_type=_norm(candidate.destination_type),
            destination_ref=_norm(candidate.destination_ref),
            lifecycle_status="active",
            source_refs=[candidate.source_ref],
            first_seen_at=observed_at,
            last_seen_at=observed_at,
        )
        db.add(row)
    else:
        row.last_seen_at = max(row.last_seen_at, observed_at)
        row.lifecycle_status = "active"
        source_refs = [str(item) for item in (row.source_refs or []) if item]
        if candidate.source_ref not in source_refs:
            source_refs.append(candidate.source_ref)
        row.source_refs = source_refs[-MAX_SOURCE_REFS:]
    db.flush()
    return row
