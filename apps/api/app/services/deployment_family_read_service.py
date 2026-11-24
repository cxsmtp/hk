"""Read-only tenant-scoped projections for the deployment-family API."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models.control_coverage import DeploymentSurface
from app.services.deployment_family_contracts import (
    DEPLOYMENT_FAMILY_LABELS,
    DeploymentFamily,
)


FAMILY_ORDER: Final[tuple[str, ...]] = (
    "browser",
    "endpoint",
    "runtime",
    "saas_api",
    "unknown",
)
HEALTH_ORDER: Final[tuple[str, ...]] = (
    "healthy",
    "warning",
    "degraded",
    "offline",
    "stale",
    "unknown",
)
HOSTING_MODES: Final[frozenset[str]] = frozenset(
    {"saas", "hybrid", "private_cloud", "on_premises", "unknown"}
)
CONTROL_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {"inline", "warn_only", "monitor_only", "external_required", "unknown"}
)
EVIDENCE_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {"complete", "partial", "metadata_only", "none", "unknown"}
)
CONTAINMENT_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {"direct", "surface_limited", "external", "none", "unknown"}
)
BYPASS_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {"supported", "unsupported", "unknown"}
)
INSTANCE_PROJECTION_COLUMNS: Final[tuple[object, ...]] = (
    DeploymentSurface.id,
    DeploymentSurface.tenant_id,
    DeploymentSurface.name,
    DeploymentSurface.deployment_family,
    DeploymentSurface.surface_type,
    DeploymentSurface.deployment_mode,
    DeploymentSurface.hosting_mode,
    DeploymentSurface.environment,
    DeploymentSurface.provider,
    DeploymentSurface.region,
    DeploymentSurface.status,
    DeploymentSurface.feature_flag,
    DeploymentSurface.first_seen_at,
    DeploymentSurface.last_seen_at,
    DeploymentSurface.last_health_check_at,
    DeploymentSurface.policy_bundle_version,
    DeploymentSurface.collector_version,
    DeploymentSurface.control_capability,
    DeploymentSurface.evidence_capability,
    DeploymentSurface.containment_capability,
    DeploymentSurface.bypass_detection_capability,
    DeploymentSurface.health_status,
    DeploymentSurface.health_reason,
)


def _closed(value: object, allowed: tuple[str, ...] | frozenset[str]) -> str:
    return value if type(value) is str and value in allowed else "unknown"


def _fixed_counts(order: tuple[str, ...], values: Counter[str]) -> dict[str, int]:
    return {value: values.get(value, 0) for value in order}


def _dynamic_counts(values: Counter[str]) -> dict[str, int]:
    return {value: values[value] for value in sorted(values)}


def deployment_instance_projection(
    row: Mapping[str, object],
) -> dict[str, object]:
    """Return the approved normalized projection without deriving stored state."""

    return {
        "id": row["id"],
        "tenant_id": row["tenant_id"],
        "name": row["name"],
        "deployment_family": _closed(row["deployment_family"], FAMILY_ORDER),
        "technical_surface_type": row["surface_type"],
        "deployment_mode": row["deployment_mode"],
        "hosting_mode": _closed(row["hosting_mode"], HOSTING_MODES),
        "environment": row["environment"],
        "provider": row["provider"],
        "region": row["region"],
        "status": row["status"],
        "feature_flag": row["feature_flag"],
        "first_seen_at": row["first_seen_at"],
        "last_seen_at": row["last_seen_at"],
        "last_health_check_at": row["last_health_check_at"],
        "policy_bundle_version": row["policy_bundle_version"],
        "collector_version": row["collector_version"],
        "control_capability": _closed(
            row["control_capability"],
            CONTROL_CAPABILITIES,
        ),
        "evidence_capability": _closed(
            row["evidence_capability"],
            EVIDENCE_CAPABILITIES,
        ),
        "containment_capability": _closed(
            row["containment_capability"],
            CONTAINMENT_CAPABILITIES,
        ),
        "bypass_detection_capability": _closed(
            row["bypass_detection_capability"],
            BYPASS_CAPABILITIES,
        ),
        "health_status": _closed(row["health_status"], HEALTH_ORDER),
        "health_reason": row["health_reason"],
    }


def _grouped_counts(
    db: Session,
    *,
    tenant_id: str,
    column,
) -> list[tuple[object, int]]:
    return [
        (value, int(count))
        for value, count in db.execute(
            select(column, func.count())
            .where(DeploymentSurface.tenant_id == tenant_id)
            .group_by(column)
        ).all()
    ]


def _family_grouped_counts(
    db: Session,
    *,
    tenant_id: str,
    column,
) -> list[tuple[object, object, int]]:
    return [
        (family, value, int(count))
        for family, value, count in db.execute(
            select(
                DeploymentSurface.deployment_family,
                column,
                func.count(),
            )
            .where(DeploymentSurface.tenant_id == tenant_id)
            .group_by(DeploymentSurface.deployment_family, column)
        ).all()
    ]


def read_overview(
    db: Session,
    *,
    tenant_id: str,
    generated_at: datetime | None = None,
) -> dict[str, object]:
    family_counts: Counter[str] = Counter()
    health_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    for value, count in _grouped_counts(
        db,
        tenant_id=tenant_id,
        column=DeploymentSurface.deployment_family,
    ):
        family_counts[_closed(value, FAMILY_ORDER)] += count
    for value, count in _grouped_counts(
        db,
        tenant_id=tenant_id,
        column=DeploymentSurface.health_status,
    ):
        health_counts[_closed(value, HEALTH_ORDER)] += count
    for value, count in _grouped_counts(
        db,
        tenant_id=tenant_id,
        column=DeploymentSurface.status,
    ):
        status_counts[value] += count

    return {
        "tenant_id": tenant_id,
        "generated_at": generated_at or datetime.now(timezone.utc),
        "total_instances": sum(family_counts.values()),
        "family_counts": _fixed_counts(FAMILY_ORDER, family_counts),
        "health_counts": _fixed_counts(HEALTH_ORDER, health_counts),
        "status_counts": _dynamic_counts(status_counts),
    }


def read_families(
    db: Session,
    *,
    tenant_id: str,
    page: int,
    page_size: int,
) -> dict[str, object]:
    buckets = {
        family: {
            "technical_surface_counts": Counter(),
            "deployment_mode_counts": Counter(),
            "hosting_mode_counts": Counter(),
            "health_counts": Counter(),
            "status_counts": Counter(),
        }
        for family in FAMILY_ORDER
    }
    grouped_dimensions = (
        (
            "technical_surface_counts",
            DeploymentSurface.surface_type,
            None,
        ),
        (
            "deployment_mode_counts",
            DeploymentSurface.deployment_mode,
            None,
        ),
        (
            "hosting_mode_counts",
            DeploymentSurface.hosting_mode,
            HOSTING_MODES,
        ),
        (
            "health_counts",
            DeploymentSurface.health_status,
            HEALTH_ORDER,
        ),
        (
            "status_counts",
            DeploymentSurface.status,
            None,
        ),
    )
    for bucket_name, column, allowed_values in grouped_dimensions:
        for persisted_family, value, count in _family_grouped_counts(
            db,
            tenant_id=tenant_id,
            column=column,
        ):
            family = _closed(persisted_family, FAMILY_ORDER)
            normalized_value = (
                _closed(value, allowed_values)
                if allowed_values is not None
                else value
            )
            buckets[family][bucket_name][normalized_value] += count

    items = []
    for family in FAMILY_ORDER:
        bucket = buckets[family]
        health_counts = bucket["health_counts"]
        items.append(
            {
                "family": family,
                "label": DEPLOYMENT_FAMILY_LABELS[DeploymentFamily(family)],
                "instance_count": sum(health_counts.values()),
                "technical_surface_counts": _dynamic_counts(
                    bucket["technical_surface_counts"]
                ),
                "deployment_mode_counts": _dynamic_counts(
                    bucket["deployment_mode_counts"]
                ),
                "hosting_mode_counts": _dynamic_counts(
                    bucket["hosting_mode_counts"]
                ),
                "health_counts": _fixed_counts(HEALTH_ORDER, health_counts),
                "status_counts": _dynamic_counts(bucket["status_counts"]),
            }
        )

    start = (page - 1) * page_size
    return {
        "items": items[start : start + page_size],
        "total": len(FAMILY_ORDER),
        "page": page,
        "page_size": page_size,
    }


def read_instances(
    db: Session,
    *,
    tenant_id: str,
    page: int,
    page_size: int,
    deployment_family: str | None = None,
    technical_surface_type: str | None = None,
    deployment_mode: str | None = None,
    hosting_mode: str | None = None,
    environment: str | None = None,
    provider: str | None = None,
    region: str | None = None,
    status: str | None = None,
    feature_flag: str | None = None,
    health_status: str | None = None,
) -> dict[str, object]:
    predicates = [DeploymentSurface.tenant_id == tenant_id]
    filters = (
        (DeploymentSurface.deployment_family, deployment_family),
        (DeploymentSurface.surface_type, technical_surface_type),
        (DeploymentSurface.deployment_mode, deployment_mode),
        (DeploymentSurface.hosting_mode, hosting_mode),
        (DeploymentSurface.environment, environment),
        (DeploymentSurface.provider, provider),
        (DeploymentSurface.region, region),
        (DeploymentSurface.status, status),
        (DeploymentSurface.feature_flag, feature_flag),
        (DeploymentSurface.health_status, health_status),
    )
    predicates.extend(
        column == value for column, value in filters if value is not None
    )

    total = db.scalar(
        select(func.count())
        .select_from(DeploymentSurface)
        .where(*predicates)
    )
    rows = db.execute(
        select(*INSTANCE_PROJECTION_COLUMNS)
        .where(*predicates)
        .order_by(
            DeploymentSurface.last_seen_at.desc(),
            DeploymentSurface.id.asc(),
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).mappings().all()
    return {
        "items": [deployment_instance_projection(row) for row in rows],
        "total": int(total or 0),
        "page": page,
        "page_size": page_size,
    }


def read_instance(
    db: Session,
    *,
    tenant_id: str,
    instance_id: str,
) -> dict[str, object] | None:
    row = db.execute(
        select(*INSTANCE_PROJECTION_COLUMNS).where(
            DeploymentSurface.tenant_id == tenant_id,
            DeploymentSurface.id == instance_id,
        )
    ).mappings().one_or_none()
    return deployment_instance_projection(row) if row is not None else None
