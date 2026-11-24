from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.enforcement import EnforcementEvent
from app.db.models.monitoring import Connector, MonitoringSignal
from app.db.models.runtime_intelligence import RuntimeEvent
from app.services.provider_catalog import (
    catalog_provider_counts,
    list_catalog,
    supported_surface_map,
)


CONNECTOR_SOURCE_SURFACES = {"connector", "monitoring", "endpoint", "dns", "proxy", "foundry", "copilot"}
NETWORK_SIGNAL_PREFIXES = ("network.", "api.")
CONNECTOR_SIGNAL_PREFIXES = (
    "identity.",
    "cloud.",
    "saas.",
    "ai.",
    "ticketing.",
    "network.",
    "appsec.",
    "endpoint.",
    "pam.",
    "api.",
    "integration.health.",
    "shadow_ai.",
)


@dataclass
class _SurfaceStats:
    observed_event_count: int = 0
    policy_enforced_count: int = 0
    last_seen_at: datetime | None = None

    def touch(self, created_at: datetime | None, *, policy_enforced: bool) -> None:
        self.observed_event_count += 1
        if policy_enforced:
            self.policy_enforced_count += 1
        if created_at and (self.last_seen_at is None or created_at > self.last_seen_at):
            self.last_seen_at = created_at

    @property
    def covered(self) -> bool:
        return self.observed_event_count > 0

    @property
    def coverage_percent(self) -> float:
        return 100.0 if self.covered else 0.0


def _safe_text(value: Any) -> str:
    return str(value or "").strip()


def _is_policy_enforced_runtime_event(row: RuntimeEvent) -> bool:
    if _safe_text(row.policy_version_id):
        return True
    metadata = dict(row.metadata_json or {})
    if _safe_text(metadata.get("policy_version_id")):
        return True
    if _safe_text(metadata.get("governance_version")):
        return True
    return False


def _surface_rows() -> dict[str, _SurfaceStats]:
    return {
        "browser_extension": _SurfaceStats(),
        "gateway": _SurfaceStats(),
        "connectors_saas": _SurfaceStats(),
        "network_api_layer": _SurfaceStats(),
    }


def _update_from_runtime_event(
    surfaces: dict[str, _SurfaceStats],
    *,
    row: RuntimeEvent,
) -> None:
    source = _safe_text(row.source_surface).lower()
    metadata = dict(row.metadata_json or {})
    policy_enforced = _is_policy_enforced_runtime_event(row)

    if source == "browser":
        surfaces["browser_extension"].touch(row.created_at, policy_enforced=policy_enforced)

    if source == "gateway":
        surfaces["gateway"].touch(row.created_at, policy_enforced=policy_enforced)

    if source in CONNECTOR_SOURCE_SURFACES:
        surfaces["connectors_saas"].touch(row.created_at, policy_enforced=policy_enforced)

    has_api_endpoint = _safe_text(metadata.get("api_endpoint")) != ""
    network_source = source in {"gateway", "endpoint", "dns", "proxy"}
    if has_api_endpoint or network_source:
        surfaces["network_api_layer"].touch(row.created_at, policy_enforced=policy_enforced)


def _update_from_monitoring_signal(
    surfaces: dict[str, _SurfaceStats],
    *,
    row: MonitoringSignal,
) -> None:
    signal_type = _safe_text(row.signal_type).lower()
    if not signal_type:
        return

    payload = dict(row.payload or {})
    routing = dict(payload.get("enforcement_routing") or {})
    policy_enforced = _safe_text(routing.get("policy_id")) not in {"", "none"} or _safe_text(routing.get("policy_version")) not in {"", "none"}

    if signal_type.startswith(CONNECTOR_SIGNAL_PREFIXES):
        surfaces["connectors_saas"].touch(row.created_at, policy_enforced=policy_enforced)

    if signal_type.startswith(NETWORK_SIGNAL_PREFIXES):
        surfaces["network_api_layer"].touch(row.created_at, policy_enforced=policy_enforced)


def get_deployment_coverage(db: Session, *, tenant_id: str) -> dict[str, Any]:
    surfaces = _surface_rows()

    runtime_rows = db.scalars(
        select(RuntimeEvent).where(RuntimeEvent.tenant_id == tenant_id)
    ).all()
    for row in runtime_rows:
        _update_from_runtime_event(surfaces, row=row)

    observed_surface_counts: dict[str, int] = {
        "browser": 0,
        "gateway": 0,
        "connector": 0,
        "aiiam": 0,
        "endpoint": 0,
        "dns": 0,
        "proxy": 0,
        "monitoring": 0,
    }
    observed_provider_category_counts: dict[str, int] = {}
    observed_provider_counts: dict[str, int] = {}
    provider_surface_mode_counts: dict[str, dict[str, int]] = {}
    coverage_by_surface_type: dict[str, int] = {
        "browser": 0,
        "saas": 0,
        "api": 0,
        "oss_local": 0,
        "agents": 0,
        "endpoint": 0,
        "dns": 0,
        "proxy": 0,
    }
    for row in runtime_rows:
        source_surface = _safe_text(row.source_surface).lower()
        if source_surface in observed_surface_counts:
            observed_surface_counts[source_surface] += 1
        metadata = dict(row.metadata_json or {})
        provider_type = _safe_text(metadata.get("provider_type"))
        provider_catalog = dict(metadata.get("provider_catalog") or {}) if isinstance(metadata.get("provider_catalog"), dict) else {}
        if not provider_type:
            provider_type = _safe_text(provider_catalog.get("provider_type"))
        provider_type = provider_type.lower() or "unknown"
        observed_provider_category_counts[provider_type] = int(observed_provider_category_counts.get(provider_type, 0)) + 1

        provider_id = _safe_text(metadata.get("provider_id"))
        if not provider_id:
            provider_id = _safe_text(provider_catalog.get("provider_id"))
        if provider_id:
            observed_provider_counts[provider_id] = int(observed_provider_counts.get(provider_id, 0)) + 1
            surface_mode = _safe_text(provider_catalog.get("surface_policy_mode")).lower()
            if not surface_mode:
                if source_surface in {"browser", "gateway", "aiiam"}:
                    surface_mode = "enforceable"
                elif source_surface in {"connector", "endpoint", "dns", "proxy", "monitoring"}:
                    surface_mode = "monitoring_only"
                else:
                    surface_mode = "unsupported"
            provider_modes = provider_surface_mode_counts.setdefault(
                provider_id,
                {"enforceable": 0, "monitoring_only": 0, "unsupported": 0},
            )
            if surface_mode not in provider_modes:
                surface_mode = "unsupported"
            provider_modes[surface_mode] = int(provider_modes.get(surface_mode, 0)) + 1

        if source_surface == "browser":
            coverage_by_surface_type["browser"] += 1
        if source_surface == "endpoint":
            coverage_by_surface_type["endpoint"] += 1
        if source_surface == "dns":
            coverage_by_surface_type["dns"] += 1
        if source_surface == "proxy":
            coverage_by_surface_type["proxy"] += 1
        if source_surface == "aiiam" or provider_type == "agent_framework":
            coverage_by_surface_type["agents"] += 1
        if provider_type in {"saas_ai", "embedded_copilot"}:
            coverage_by_surface_type["saas"] += 1
        if provider_type == "model_api" or source_surface == "gateway":
            coverage_by_surface_type["api"] += 1
        if provider_type == "local_model":
            coverage_by_surface_type["oss_local"] += 1

    monitoring_rows = db.scalars(
        select(MonitoringSignal).where(MonitoringSignal.tenant_id == tenant_id)
    ).all()
    for row in monitoring_rows:
        _update_from_monitoring_signal(surfaces, row=row)

    enforcement_rows = db.scalars(
        select(EnforcementEvent).where(EnforcementEvent.tenant_id == tenant_id)
    ).all()
    decision_counts: dict[str, int] = {}
    policy_bound_count = 0
    for row in enforcement_rows:
        decision = _safe_text(row.final_decision).lower() or "unknown"
        decision_counts[decision] = int(decision_counts.get(decision, 0)) + 1
        if _safe_text(row.policy_version_id):
            policy_bound_count += 1

    connector_rows = db.scalars(
        select(Connector).where(Connector.tenant_id == tenant_id)
    ).all()
    enabled_connector_count = sum(1 for row in connector_rows if bool(row.enabled))

    surface_items = []
    covered_count = 0
    gaps: list[str] = []
    for key, label in (
        ("browser_extension", "Browser Extension"),
        ("gateway", "Gateway (LLM/MCP)"),
        ("connectors_saas", "Connectors (SaaS)"),
        ("network_api_layer", "Network/API Layer"),
    ):
        stats = surfaces[key]
        if stats.covered:
            covered_count += 1
        else:
            gaps.append(f"no_telemetry:{key}")
        if stats.observed_event_count > 0 and stats.policy_enforced_count == 0:
            gaps.append(f"no_policy_enforcement:{key}")
        surface_items.append(
            {
                "surface": key,
                "label": label,
                "covered": stats.covered,
                "coverage_percent": stats.coverage_percent,
                "observed_event_count": stats.observed_event_count,
                "policy_enforced_count": stats.policy_enforced_count,
                "last_seen_at": stats.last_seen_at,
            }
        )

    if enabled_connector_count == 0:
        gaps.append("no_connectors_enabled")

    overall_percent = round((covered_count / len(surface_items)) * 100.0, 2) if surface_items else 0.0
    gaps = sorted(set(gaps))
    supported_surfaces = supported_surface_map()
    provider_catalog_entries = list_catalog()
    provider_type_lookup: dict[str, str] = {}
    provider_name_lookup: dict[str, str] = {}
    for row in provider_catalog_entries:
        provider_id = _safe_text(row.get("provider_id"))
        if not provider_id:
            continue
        provider_type_lookup[provider_id] = _safe_text(row.get("provider_type")).lower() or "unknown"
        provider_name_lookup[provider_id] = _safe_text(row.get("canonical_name")) or provider_id

    provider_blind_spots_by_category: dict[str, list[str]] = {}
    for provider_id, provider_type in provider_type_lookup.items():
        if observed_provider_counts.get(provider_id, 0) > 0:
            continue
        provider_blind_spots_by_category.setdefault(provider_type, []).append(provider_name_lookup.get(provider_id, provider_id))
    for category in list(provider_blind_spots_by_category.keys()):
        provider_blind_spots_by_category[category] = sorted(provider_blind_spots_by_category[category])

    surface_observed = {key: int(value) for key, value in observed_surface_counts.items()}
    enforcement_surface_gaps = sorted(
        [
            surface
            for surface in (supported_surfaces.get("enforcement_capable_surfaces") or [])
            if int(surface_observed.get(str(surface), 0)) <= 0
        ]
    )
    monitoring_surface_gaps = sorted(
        [
            surface
            for surface in (supported_surfaces.get("monitoring_only_surfaces") or [])
            if int(surface_observed.get(str(surface), 0)) <= 0
        ]
    )
    enforceable_count = sum(
        1 for row in surface_items if row["surface"] in {"browser_extension", "gateway"} and row["covered"]
    )
    monitoring_only_count = sum(
        1 for row in surface_items if row["surface"] in {"connectors_saas", "network_api_layer"} and row["covered"]
    )

    return {
        "tenant_id": tenant_id,
        "coverage_percent": overall_percent,
        "surfaces": surface_items,
        "policies_enforced": {
            "total_enforcement_events": len(enforcement_rows),
            "policy_bound_enforcement_events": policy_bound_count,
            "decision_counts": decision_counts,
        },
        "connector_posture": {
            "total_connectors": len(connector_rows),
            "enabled_connectors": enabled_connector_count,
        },
        "provider_catalog": {
            "supported_provider_counts": catalog_provider_counts(),
            "supported_source_surfaces": list(supported_surfaces.get("supported_source_surfaces") or []),
            "enforcement_capable_surfaces": list(supported_surfaces.get("enforcement_capable_surfaces") or []),
            "monitoring_only_surfaces": list(supported_surfaces.get("monitoring_only_surfaces") or []),
        },
        "observed_surface_counts": observed_surface_counts,
        "observed_provider_category_counts": observed_provider_category_counts,
        "observed_provider_counts": observed_provider_counts,
        "provider_surface_mode_counts": provider_surface_mode_counts,
        "provider_blind_spots_by_category": provider_blind_spots_by_category,
        "coverage_by_surface_type": coverage_by_surface_type,
        "enforcement_capability": {
            "enforceable_surfaces_observed": enforceable_count,
            "monitoring_only_surfaces_observed": monitoring_only_count,
            "enforcement_surface_gaps": enforcement_surface_gaps,
            "monitoring_surface_gaps": monitoring_surface_gaps,
        },
        "gaps": gaps,
    }
