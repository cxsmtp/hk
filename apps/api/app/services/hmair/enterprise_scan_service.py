"""Bounded, evidence-backed H6 scan result and source diagnostics projections."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence

from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from app.db.models.ai_asset import DiscoveryAIAsset
from app.db.models.discovery_canonical import (
    DiscoveryCollector,
    DiscoveryScan,
    DiscoveryScanAssignment,
    DiscoveryTarget,
)
from app.db.models.discovery_intelligence import (
    DiscoveryAssetFinding,
    DiscoveryAssetUsageFact,
)
from app.services.privacy_sanitizer import redact_sensitive_text


_MAX_ITEMS = 128
_ACTIVE_USAGE_STATES = frozenset({"active", "high_usage"})
_SHADOW_STATES = frozenset(
    {
        "known_unapproved",
        "suspected_shadow",
        "confirmed_shadow",
        "personal_account",
        "owner_unknown",
    }
)
_ASSET_FAMILIES: dict[str, frozenset[str]] = {
    "models": frozenset({"model", "model_endpoint"}),
    "agents": frozenset({"agent", "agent_framework"}),
    "mcp": frozenset({"mcp_server", "mcp_client", "mcp_tool"}),
    "developer_ai": frozenset(
        {"ide", "cli", "sdk", "endpoint_application", "browser_extension"}
    ),
    "saas_ai": frozenset({"ai_saas", "ai_application", "ai_feature"}),
    "ai_enabled_data": frozenset(
        {"vector_database", "knowledge_base", "prompt_store", "memory_store"}
    ),
    "runtimes": frozenset({"runtime", "llm_gateway", "workflow"}),
    "unknown_candidates": frozenset({"unknown_ai_candidate"}),
}


class EnterpriseScanBreadth(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    total_assets: int
    active_users: int
    shadow_ai: int
    models: int
    agents: int
    mcp: int
    developer_ai: int
    saas_ai: int
    ai_enabled_data: int
    runtimes: int
    unknown_candidates: int
    assets_by_type: dict[str, int]
    assets_by_surface: dict[str, int]
    findings_by_type: dict[str, int]
    control_coverage_state: str
    blind_spots: tuple[str, ...]


class ScanSourceDiagnostic(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    assignment_id: str
    target_id: str
    target_type: str
    collector_id: str
    collector_type: str
    collector_health: str
    assignment_status: str
    supported: bool
    active_scan_allowed: bool
    permission_gaps: tuple[str, ...]
    target_exclusions: tuple[str, ...]
    limitations: tuple[str, ...]
    observations_count: int
    warning: str | None
    error: str | None


class EnterpriseScanDiagnostics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_id: str
    assignments_total: int
    healthy_sources: int
    warning_sources: int
    degraded_sources: int
    unsupported_sources: int
    permission_denied_sources: int
    sources: tuple[ScanSourceDiagnostic, ...]
    limitations: tuple[str, ...]


def _safe_strings(value: object, *, prefix: str | None = None) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    items = {
        redact_sensitive_text(str(item).strip(), max_len=160)[:160]
        for item in value
        if isinstance(item, str) and item.strip()
    }
    selected = sorted(items)[:_MAX_ITEMS]
    return tuple(f"{prefix}:{item}" if prefix else item for item in selected)


def _coverage_mapping(scan: DiscoveryScan) -> Mapping[str, object]:
    return (
        scan.coverage_summary_json
        if isinstance(scan.coverage_summary_json, Mapping)
        else {}
    )


def build_scan_result_breadth(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
    asset_ids: Sequence[str],
) -> EnterpriseScanBreadth:
    """Build one bounded scan result projection without loading raw evidence."""

    scan = db.scalar(
        select(DiscoveryScan).where(
            DiscoveryScan.tenant_id == tenant_id,
            DiscoveryScan.scan_id == scan_id,
        )
    )
    if scan is None:
        raise LookupError("scan was not found")
    bounded_ids = tuple(dict.fromkeys(str(item) for item in asset_ids))[:10_000]
    assets = (
        list(
            db.scalars(
                select(DiscoveryAIAsset).where(
                    DiscoveryAIAsset.tenant_id == tenant_id,
                    DiscoveryAIAsset.asset_id.in_(bounded_ids),
                )
            )
        )
        if bounded_ids
        else []
    )
    type_counts = Counter(str(row.asset_type) for row in assets)
    surface_counts = Counter(str(row.technical_surface or "unknown") for row in assets)
    active_users = 0
    finding_counts: Counter[str] = Counter()
    if bounded_ids:
        active_users = int(
            db.scalar(
                select(func.count(func.distinct(DiscoveryAssetUsageFact.actor_reference_hash))).where(
                    DiscoveryAssetUsageFact.tenant_id == tenant_id,
                    DiscoveryAssetUsageFact.asset_id.in_(bounded_ids),
                    DiscoveryAssetUsageFact.usage_state.in_(_ACTIVE_USAGE_STATES),
                    DiscoveryAssetUsageFact.actor_reference_hash.is_not(None),
                )
            )
            or 0
        )
        finding_counts.update(
            {
                str(name): int(count)
                for name, count in db.execute(
                    select(DiscoveryAssetFinding.finding_type, func.count())
                    .where(
                        DiscoveryAssetFinding.tenant_id == tenant_id,
                        DiscoveryAssetFinding.asset_id.in_(bounded_ids),
                        DiscoveryAssetFinding.status.in_(("open", "reviewing")),
                    )
                    .group_by(DiscoveryAssetFinding.finding_type)
                )
            }
        )
    coverage = _coverage_mapping(scan)
    confidence = str(coverage.get("confidence") or "unknown").strip().lower()
    coverage_state = (
        confidence
        if confidence
        in {"current", "verified", "partial", "stale", "regressed", "unknown"}
        else "unknown"
    )
    blind_spots = tuple(
        sorted(
            {
                *_safe_strings(coverage.get("explicit_exclusions"), prefix="excluded"),
                *_safe_strings(coverage.get("unknown"), prefix="unknown"),
                *_safe_strings(coverage.get("unsupported"), prefix="unsupported"),
            }
        )[:_MAX_ITEMS]
    )
    family_counts = {
        family: sum(type_counts.get(asset_type, 0) for asset_type in asset_types)
        for family, asset_types in _ASSET_FAMILIES.items()
    }
    return EnterpriseScanBreadth(
        total_assets=len(assets),
        active_users=active_users,
        shadow_ai=sum(1 for row in assets if row.shadow_ai_status in _SHADOW_STATES),
        assets_by_type=dict(sorted(type_counts.items())),
        assets_by_surface=dict(sorted(surface_counts.items())),
        findings_by_type=dict(sorted(finding_counts.items())),
        control_coverage_state=coverage_state,
        blind_spots=blind_spots,
        **family_counts,
    )


def build_scan_diagnostics(
    db: Session,
    *,
    tenant_id: str,
    scan_id: str,
) -> EnterpriseScanDiagnostics:
    """Project exact registered scan-source health and permission truth."""

    scan = db.scalar(
        select(DiscoveryScan.scan_id).where(
            DiscoveryScan.tenant_id == tenant_id,
            DiscoveryScan.scan_id == scan_id,
        )
    )
    if scan is None:
        raise LookupError("scan was not found")
    rows = list(
        db.execute(
            select(DiscoveryScanAssignment, DiscoveryTarget, DiscoveryCollector)
            .join(
                DiscoveryTarget,
                and_(
                    DiscoveryTarget.tenant_id == DiscoveryScanAssignment.tenant_id,
                    DiscoveryTarget.target_id == DiscoveryScanAssignment.target_id,
                ),
            )
            .join(
                DiscoveryCollector,
                and_(
                    DiscoveryCollector.tenant_id == DiscoveryScanAssignment.tenant_id,
                    DiscoveryCollector.collector_id
                    == DiscoveryScanAssignment.collector_id,
                ),
            )
            .where(
                DiscoveryScanAssignment.tenant_id == tenant_id,
                DiscoveryScanAssignment.scan_id == scan_id,
            )
            .order_by(DiscoveryScanAssignment.assignment_id)
            .limit(1_000)
        )
    )
    sources: list[ScanSourceDiagnostic] = []
    for assignment, target, collector in rows:
        supported = target.target_type in set(collector.supported_targets_json or [])
        permitted = set(target.permitted_methods_json or [])
        required = set(collector.active_capabilities_json or [])
        sources.append(
            ScanSourceDiagnostic(
                assignment_id=assignment.assignment_id,
                target_id=target.target_id,
                target_type=target.target_type,
                collector_id=collector.collector_id,
                collector_type=collector.collector_type,
                collector_health=collector.health,
                assignment_status=assignment.status,
                supported=supported,
                active_scan_allowed=bool(target.active_scan_allowed),
                permission_gaps=tuple(sorted(required - permitted)),
                target_exclusions=_safe_strings(target.exclusions_json),
                limitations=_safe_strings(collector.limitations_json),
                observations_count=int(assignment.observations_count),
                warning=(
                    redact_sensitive_text(assignment.warning, max_len=500)
                    if assignment.warning
                    else None
                ),
                error=(
                    redact_sensitive_text(assignment.error, max_len=500)
                    if assignment.error
                    else None
                ),
            )
        )
    return EnterpriseScanDiagnostics(
        scan_id=scan_id,
        assignments_total=len(sources),
        healthy_sources=sum(item.collector_health == "healthy" for item in sources),
        warning_sources=sum(item.collector_health == "warning" for item in sources),
        degraded_sources=sum(
            item.collector_health in {"degraded", "offline"} for item in sources
        ),
        unsupported_sources=sum(not item.supported for item in sources),
        permission_denied_sources=sum(
            bool(item.permission_gaps) or not item.active_scan_allowed for item in sources
        ),
        sources=tuple(sources),
        limitations=(
            "Diagnostics cover only the registered sources assigned to this scan.",
            "Source health and configuration do not prove complete estate coverage.",
        ),
    )


__all__ = [
    "EnterpriseScanBreadth",
    "EnterpriseScanDiagnostics",
    "ScanSourceDiagnostic",
    "build_scan_diagnostics",
    "build_scan_result_breadth",
]
