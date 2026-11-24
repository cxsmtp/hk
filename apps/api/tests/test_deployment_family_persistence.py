from __future__ import annotations

import re

from sqlalchemy import CheckConstraint

from app.db.models.control_coverage import DeploymentSurface


NORMALIZED_FIELDS = {
    "deployment_family",
    "hosting_mode",
    "provider",
    "region",
    "feature_flag",
    "last_health_check_at",
    "policy_bundle_version",
    "collector_version",
    "control_capability",
    "evidence_capability",
    "containment_capability",
    "bypass_detection_capability",
}

EXPECTED_CONSTRAINT_VALUES = {
    "ck_deployment_surface_family": {
        "browser",
        "endpoint",
        "runtime",
        "saas_api",
        "unknown",
    },
    "ck_deployment_surface_hosting_mode": {
        "saas",
        "hybrid",
        "private_cloud",
        "on_premises",
        "unknown",
    },
    "ck_deployment_surface_control_capability": {
        "inline",
        "warn_only",
        "monitor_only",
        "external_required",
        "unknown",
    },
    "ck_deployment_surface_evidence_capability": {
        "complete",
        "partial",
        "metadata_only",
        "none",
        "unknown",
    },
    "ck_deployment_surface_containment_capability": {
        "direct",
        "surface_limited",
        "external",
        "none",
        "unknown",
    },
    "ck_deployment_surface_bypass_capability": {
        "supported",
        "unsupported",
        "unknown",
    },
    "ck_deployment_surface_health_status": {
        "healthy",
        "warning",
        "degraded",
        "offline",
        "stale",
        "unknown",
    },
}


def _check_sql(name: str) -> str:
    constraint = next(
        item
        for item in DeploymentSurface.__table__.constraints
        if isinstance(item, CheckConstraint) and item.name == name
    )
    return str(constraint.sqltext)


def _check_values(name: str) -> set[str]:
    return set(re.findall(r"'([^']+)'", _check_sql(name)))


def test_deployment_surface_model_adds_normalized_fields_without_replacing_sources(
) -> None:
    table = DeploymentSurface.__table__

    assert NORMALIZED_FIELDS <= set(table.c.keys())
    assert {
        "surface_type",
        "deployment_mode",
        "capability_profile",
        "capability_sources",
    } <= set(table.c.keys())
    assert "technical_surface_type" not in table.c
    assert table.c.surface_type.type.length == 64
    assert table.c.deployment_mode.type.length == 64

    for field_name in (
        "deployment_family",
        "hosting_mode",
        "control_capability",
        "evidence_capability",
        "containment_capability",
        "bypass_detection_capability",
    ):
        column = table.c[field_name]
        assert column.nullable is False
        assert column.server_default is not None
        assert str(column.server_default.arg) == "unknown"

    for field_name in (
        "provider",
        "region",
        "feature_flag",
        "last_health_check_at",
        "policy_bundle_version",
        "collector_version",
    ):
        assert table.c[field_name].nullable is True


def test_deployment_surface_model_uses_exact_closed_persistence_constraints() -> None:
    assert {
        name: _check_values(name)
        for name in EXPECTED_CONSTRAINT_VALUES
    } == EXPECTED_CONSTRAINT_VALUES


def test_deployment_surface_model_has_tenant_scoped_family_health_and_status_indexes() -> None:
    indexes = {
        index.name: tuple(column.name for column in index.columns)
        for index in DeploymentSurface.__table__.indexes
    }

    assert indexes["idx_deployment_surface_tenant_family"] == (
        "tenant_id",
        "deployment_family",
    )
    assert indexes["idx_deployment_surface_tenant_health"] == (
        "tenant_id",
        "health_status",
    )
    assert indexes["idx_deployment_surface_tenant_status"] == (
        "tenant_id",
        "status",
    )
