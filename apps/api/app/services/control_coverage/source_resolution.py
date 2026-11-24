"""Canonical tenant-local source-to-deployment-surface resolution."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from app.db.models.activity_audit import AIAction
from app.db.models.control_coverage import DeploymentSurface
from app.db.models.runtime_intelligence import RuntimeEvent


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def runtime_surface_source_id(event: RuntimeEvent) -> str:
    metadata = _mapping(event.metadata_json)
    source = str(event.source_surface or "unknown").strip().lower()
    source_id = str(
        metadata.get("deployment_surface_id")
        or metadata.get("gateway_id")
        or metadata.get("sdk_registration_id")
        or metadata.get("mcp_server_id")
        or source
    ).strip()
    return f"{source}:{source_id}"


def surface_indexes(
    surfaces: Iterable[DeploymentSurface],
) -> tuple[
    dict[str, DeploymentSurface],
    dict[tuple[str, str], DeploymentSurface],
]:
    by_id: dict[str, DeploymentSurface] = {}
    by_source: dict[tuple[str, str], DeploymentSurface] = {}
    for surface in surfaces:
        by_id[surface.id] = surface
        by_source[(surface.source_kind, surface.source_id)] = surface
    return by_id, by_source


def surface_for_event(
    event: RuntimeEvent,
    *,
    by_id: Mapping[str, DeploymentSurface],
    by_source: Mapping[tuple[str, str], DeploymentSurface],
) -> DeploymentSurface | None:
    metadata = _mapping(event.metadata_json)
    explicit = str(metadata.get("deployment_surface_row_id") or "").strip()
    if explicit and explicit in by_id:
        return by_id[explicit]
    return by_source.get(
        ("runtime_observation", runtime_surface_source_id(event))
    )


def surface_for_action(
    action: AIAction,
    *,
    by_source: Mapping[tuple[str, str], DeploymentSurface],
) -> DeploymentSurface | None:
    if action.endpoint_id:
        return by_source.get(("deployment_endpoint", str(action.endpoint_id)))
    return None


__all__ = [
    "runtime_surface_source_id",
    "surface_for_action",
    "surface_for_event",
    "surface_indexes",
]
