"""Versioned snapshot material for deployment-family coverage scoring."""

from __future__ import annotations

import hashlib
import json
from typing import Iterable, Mapping

from app.db.models.control_coverage import (
    ControlCoveragePath,
    DeploymentSurface,
)


SURFACE_PROJECTION_VERSION = "deployment-family-surface-projection/1.0"
SURFACE_PROJECTION_WATERMARK_KEY = "deployment_family_surface_projection"


def _strict_text(value: object) -> str:
    return value if type(value) is str else "__invalid__"


def _profile_bypass_detection(surface: DeploymentSurface) -> str:
    profile = surface.capability_profile
    if not isinstance(profile, Mapping):
        return "__invalid__"
    return _strict_text(profile.get("bypass_detection", "unknown"))


def deployment_family_surface_projection_digest(
    *,
    paths: Iterable[ControlCoveragePath],
    surfaces_by_id: Mapping[str, DeploymentSurface],
) -> str:
    """Bind every scored surface field to the snapshot's path population."""
    projected_paths: list[dict[str, object]] = []
    for path in paths:
        surface_id = (
            path.deployment_surface_id
            if type(path.deployment_surface_id) is str
            and path.deployment_surface_id
            else None
        )
        surface = surfaces_by_id.get(surface_id or "")
        projected_surface: dict[str, str] | None
        if surface is None:
            projected_surface = None
        else:
            projected_surface = {
                "id": _strict_text(surface.id),
                "source_kind": _strict_text(surface.source_kind),
                "source_id": _strict_text(surface.source_id),
                "deployment_family": _strict_text(
                    surface.deployment_family
                ),
                "containment_capability": _strict_text(
                    surface.containment_capability
                ),
                "health_status": _strict_text(surface.health_status),
                "profile_bypass_detection": _profile_bypass_detection(
                    surface
                ),
            }
        projected_paths.append(
            {
                "path_id": _strict_text(path.id),
                "path_key": _strict_text(path.path_key),
                "deployment_surface_id": surface_id,
                "surface": projected_surface,
            }
        )
    material = {
        "version": SURFACE_PROJECTION_VERSION,
        "paths": sorted(
            projected_paths,
            key=lambda item: (
                str(item["path_key"]),
                str(item["path_id"]),
            ),
        ),
    }
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "SURFACE_PROJECTION_VERSION",
    "SURFACE_PROJECTION_WATERMARK_KEY",
    "deployment_family_surface_projection_digest",
]
