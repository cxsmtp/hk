"""Read-only, bounded Discovery context for an already-decided AI action."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from typing import Any, Callable, Iterable, TypeVar

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.ai_asset import (
    DiscoveryAICapability,
    DiscoveryAIAsset,
    DiscoveryEvidenceClaim,
)
from app.db.models.capability_inference import DiscoveryCapabilityGenome
from app.db.models.control_coverage import ControlCoverageAssertion, ControlCoveragePath
from app.db.models.discovery_attribution import (
    DiscoveryAssetIdentityLink,
    DiscoveryAssetReachability,
)
from app.db.models.discovery_intelligence import DiscoveryAssetUsageFact
from app.db.models.discovery_resolution import DiscoveryResolutionGraphNode
from app.db.models.discovery_verification import DiscoveryVerificationAssertion
from app.db.models.evidence_resolution import (
    DiscoveryAIEcosystem,
    DiscoveryEcosystemMembership,
)


SCHEMA_VERSION = "discovery-context/1"
MAX_INPUT_LENGTH = 255
MAX_REFS_PER_DIMENSION = 64
MAX_TOTAL_REFS = 256
MAX_SOURCE_ROWS = 256
MAX_CONTEXT_BYTES = 32768
_SOURCE_LIMIT = MAX_SOURCE_ROWS + 1
_ASSET_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_T = TypeVar("_T")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | str | None) -> datetime:
    if value is None:
        return _utc_now()
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    if isinstance(value, str) and len(value) <= MAX_INPUT_LENGTH:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return _utc_now()
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    return _utc_now()


def _normal(value: object, *, max_length: int = MAX_INPUT_LENGTH) -> str | None:
    if not isinstance(value, str):
        return None
    compact = " ".join(value.strip().split())
    if not compact or len(compact) > max_length:
        return None
    return compact.casefold()


def _reference_hash(value: object) -> str | None:
    normalized = _normal(value, max_length=64)
    if normalized is None or not re.fullmatch(r"[0-9a-f]{64}", normalized):
        return None
    return normalized


def _format_time(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _to_utc(value).isoformat()


def _to_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _order_time(value: datetime | None) -> float:
    return _to_utc(value).timestamp() if value is not None else float("-inf")


def _at_or_before(value: datetime | None, as_of: datetime) -> bool:
    return value is not None and _to_utc(value) <= as_of


def _current_window(
    row: object,
    *,
    as_of: datetime,
    first: str = "first_observed_at",
    last: str = "last_observed_at",
) -> bool:
    first_value = getattr(row, first, None)
    last_value = getattr(row, last, None)
    return _at_or_before(first_value, as_of) and _at_or_before(last_value, as_of)


def _bounded_rows(rows: Iterable[_T]) -> tuple[list[_T], bool]:
    materialized = list(rows)
    return materialized[:MAX_SOURCE_ROWS], len(materialized) > MAX_SOURCE_ROWS


def _latest_by(
    rows: Iterable[_T],
    *,
    key: Callable[[_T], tuple[object, ...]],
    ordering: Callable[[_T], tuple[object, ...]],
    superseded_id: Callable[[_T], str | None] | None = None,
    row_id: Callable[[_T], str] | None = None,
) -> list[_T]:
    candidates = list(rows)
    if superseded_id is not None and row_id is not None:
        superseded = {item for row in candidates if (item := superseded_id(row))}
        candidates = [row for row in candidates if row_id(row) not in superseded]
    selected: dict[tuple[object, ...], _T] = {}
    for row in sorted(candidates, key=ordering, reverse=True):
        selected.setdefault(key(row), row)
    return list(selected.values())


def _append_refs(
    context: dict[str, Any],
    *,
    key: str,
    refs: Iterable[str],
    total_used: int,
    dimension_remaining: int | None = None,
) -> tuple[int, bool]:
    ordered = sorted({ref for ref in refs if isinstance(ref, str) and len(ref) <= 96})
    available = max(0, min(MAX_REFS_PER_DIMENSION, MAX_TOTAL_REFS - total_used))
    if dimension_remaining is not None:
        available = min(available, max(0, dimension_remaining))
    selected = ordered[:available]
    context[key] = selected
    return total_used + len(selected), len(ordered) > len(selected)


def _unknown_context(*, as_of: datetime, limitation: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _format_time(_utc_now()),
        "as_of": _format_time(as_of),
        "status": "unknown",
        "ai_asset_ref": None,
        "asset_version": None,
        "last_discovery": None,
        "last_verification": None,
        "capability_refs": [],
        "reachability_refs": [],
        "identity_refs": [],
        "dependency_refs": [],
        "usage_refs": [],
        "verification_refs": [],
        "evidence_refs": [],
        "control_coverage": {"path_refs": [], "assertion_refs": []},
        "confidence": {"reference_count": 0},
        "summaries": {},
        "limitations": [limitation],
    }


class DiscoveryContextProvider:
    """A conservative, tenant-scoped read projection; it never mutates Discovery."""

    def __init__(self, db: Session) -> None:
        self._db = db

    def get_context_for_ai_action(
        self,
        *,
        tenant: str,
        actor: str | None = None,
        asset: str | None = None,
        runtime: str | None = None,
        application: str | None = None,
        tool: str | None = None,
        model: str | None = None,
        provider: str | None = None,
        identity: str | None = None,
        as_of: datetime | str | None = None,
        enabled_override: bool | None = None,
    ) -> dict[str, Any]:
        cutoff = _as_utc(as_of)
        enabled = settings.discovery_context_provider if enabled_override is None else enabled_override
        if not enabled:
            return _unknown_context(as_of=cutoff, limitation="disabled") | {"status": "disabled"}

        tenant_id = _normal(tenant, max_length=36)
        if tenant_id is None:
            return _unknown_context(as_of=cutoff, limitation="asset_not_resolved")
        asset_row, resolution_limited = self._resolve_asset(
            tenant_id=tenant_id,
            asset=asset,
            application=application,
            tool=tool,
            model=model,
            provider=provider,
        )
        if asset_row is None:
            return _unknown_context(
                as_of=cutoff,
                limitation="result_bounds_reached" if resolution_limited else "asset_not_resolved",
            )
        if not _at_or_before(asset_row.first_seen_at, cutoff) or not _at_or_before(asset_row.last_seen_at, cutoff):
            return _unknown_context(as_of=cutoff, limitation="asset_not_resolved")
        return self._project(
            asset=asset_row,
            as_of=cutoff,
            actor_hash=_reference_hash(actor),
            identity_hash=_reference_hash(identity),
            runtime_ref=_normal(runtime),
            actor_supplied=actor is not None,
            identity_supplied=identity is not None,
            runtime_supplied=runtime is not None,
            resolution_limited=resolution_limited,
        )

    def getContextForAIAction(self, **kwargs: Any) -> dict[str, Any]:  # noqa: N802
        return self.get_context_for_ai_action(**kwargs)

    def _resolve_asset(
        self,
        *,
        tenant_id: str,
        asset: str | None,
        application: str | None,
        tool: str | None,
        model: str | None,
        provider: str | None,
    ) -> tuple[DiscoveryAIAsset | None, bool]:
        if asset is not None:
            explicit = _normal(asset, max_length=64)
            if explicit is None:
                return None, False
            if explicit.startswith("discovery_asset:"):
                explicit = explicit.removeprefix("discovery_asset:")
            if not _ASSET_ID_RE.fullmatch(explicit):
                return None, False
            row = self._db.scalar(
                select(DiscoveryAIAsset).where(
                    DiscoveryAIAsset.tenant_id == tenant_id,
                    DiscoveryAIAsset.asset_id == explicit,
                )
            )
            return row, False

        raw_criteria = {
            "application": application,
            "tool": tool,
            "model": model,
            "provider": provider,
        }
        criteria = {name: _normal(value) for name, value in raw_criteria.items()}
        if any(
            value is not None
            and (not isinstance(value, str) or (value.strip() and criteria[name] is None))
            for name, value in raw_criteria.items()
        ):
            return None, False
        supplied = {name: value for name, value in criteria.items() if value is not None}
        if not supplied:
            return None, False

        conditions = [DiscoveryAIAsset.tenant_id == tenant_id]
        for name, value in supplied.items():
            if name == "application":
                columns = (DiscoveryAIAsset.canonical_name, DiscoveryAIAsset.product)
            elif name == "tool":
                columns = (DiscoveryAIAsset.canonical_name, DiscoveryAIAsset.product, DiscoveryAIAsset.framework)
            elif name == "model":
                columns = (DiscoveryAIAsset.canonical_name, DiscoveryAIAsset.product, DiscoveryAIAsset.version)
            else:
                columns = (DiscoveryAIAsset.provider,)
            conditions.append(or_(*(func.lower(func.trim(column)) == value for column in columns)))
        rows = list(
            self._db.scalars(
                select(DiscoveryAIAsset)
                .where(and_(*conditions))
                .order_by(DiscoveryAIAsset.asset_id)
                .limit(2)
            )
        )
        return (rows[0] if len(rows) == 1 else None), len(rows) == 2

    def _project(
        self,
        *,
        asset: DiscoveryAIAsset,
        as_of: datetime,
        actor_hash: str | None,
        identity_hash: str | None,
        runtime_ref: str | None,
        actor_supplied: bool,
        identity_supplied: bool,
        runtime_supplied: bool,
        resolution_limited: bool,
    ) -> dict[str, Any]:
        context: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": _format_time(_utc_now()),
            "as_of": _format_time(as_of),
            "status": "partial",
            "ai_asset_ref": f"discovery_asset:{asset.asset_id}",
            # The status is an existing, tenant-scoped AI Asset governance
            # reference. It is not a Discovery policy decision and remains
            # usable even when unrelated context dimensions are partial.
            "asset_approval": {
                "asset_ref": f"discovery_asset:{asset.asset_id}",
                "approved_status": str(asset.approved_status or "unknown"),
                "lifecycle_status": str(asset.lifecycle_status or "unknown"),
                "evidence_ref": f"evidence:{asset.evidence_bundle_id}",
            },
            "asset_version": int(asset.projection_version),
            "last_discovery": _format_time(asset.last_seen_at),
            "last_verification": None,
            "confidence": {"asset": round(float(asset.resolution_confidence), 6), "reference_count": 0},
            "summaries": {},
            "limitations": [],
        }
        total_refs = 0
        bounded = resolution_limited
        observation_times: list[datetime] = [asset.last_seen_at]
        verification_times: list[datetime] = []
        confidence_values: list[float] = [float(asset.resolution_confidence)]

        capabilities, capability_scan_limited = _bounded_rows(
            self._db.scalars(
                select(DiscoveryAICapability)
                .where(
                    DiscoveryAICapability.tenant_id == asset.tenant_id,
                    DiscoveryAICapability.asset_id == asset.asset_id,
                )
                .order_by(
                    DiscoveryAICapability.assertion_sequence.desc(),
                    DiscoveryAICapability.last_observed_at.desc(),
                    DiscoveryAICapability.capability_id.desc(),
                )
                .limit(_SOURCE_LIMIT)
            )
        )
        current_capabilities = _latest_by(
            capabilities,
            key=lambda row: (row.capability_name,),
            ordering=lambda row: (int(row.assertion_sequence), _order_time(row.last_observed_at), row.capability_id),
            superseded_id=lambda row: row.supersedes_capability_id,
            row_id=lambda row: row.capability_id,
        )
        valid_capabilities = [
            row for row in current_capabilities
            if row.verification_state == "verified" and row.freshness == "fresh" and _current_window(row, as_of=as_of)
        ]
        total_refs, truncated = _append_refs(
            context, key="capability_refs", refs=(f"capability:{row.capability_id}" for row in valid_capabilities), total_used=total_refs
        )
        bounded |= capability_scan_limited or truncated
        observation_times.extend(row.last_observed_at for row in valid_capabilities)
        confidence_values.extend(float(row.confidence) for row in valid_capabilities)

        reachability, reachability_scan_limited = _bounded_rows(
            self._db.scalars(
                select(DiscoveryAssetReachability)
                .where(DiscoveryAssetReachability.tenant_id == asset.tenant_id, DiscoveryAssetReachability.asset_id == asset.asset_id)
                .order_by(DiscoveryAssetReachability.last_observed_at.desc(), DiscoveryAssetReachability.reachability_id.desc())
                .limit(_SOURCE_LIMIT)
            )
        )
        current_reachability = _latest_by(
            reachability,
            key=lambda row: (row.target_category, row.target_reference_hash),
            ordering=lambda row: (_order_time(row.last_observed_at), row.reachability_id),
        )
        valid_reachability = [
            row for row in current_reachability
            if row.verification_state == "verified" and row.freshness == "fresh" and _current_window(row, as_of=as_of)
        ]
        total_refs, truncated = _append_refs(
            context, key="reachability_refs", refs=(f"reachability:{row.reachability_id}" for row in valid_reachability), total_used=total_refs
        )
        bounded |= reachability_scan_limited or truncated
        observation_times.extend(row.last_observed_at for row in valid_reachability)
        confidence_values.extend(float(row.confidence) for row in valid_reachability)

        identities, identity_scan_limited = _bounded_rows(
            self._db.scalars(
                select(DiscoveryAssetIdentityLink)
                .where(DiscoveryAssetIdentityLink.tenant_id == asset.tenant_id, DiscoveryAssetIdentityLink.asset_id == asset.asset_id)
                .order_by(DiscoveryAssetIdentityLink.last_observed_at.desc(), DiscoveryAssetIdentityLink.identity_link_id.desc())
                .limit(_SOURCE_LIMIT)
            )
        )
        current_identities = _latest_by(
            identities,
            key=lambda row: (row.identity_type, row.identity_reference_hash),
            ordering=lambda row: (_order_time(row.last_observed_at), row.identity_link_id),
        )
        valid_identities = [
            row for row in current_identities
            if row.verification_state == "verified" and _current_window(row, as_of=as_of)
            and (not identity_supplied or (identity_hash is not None and row.identity_reference_hash == identity_hash))
        ]
        total_refs, truncated = _append_refs(
            context, key="identity_refs", refs=(f"identity:{row.identity_link_id}" for row in valid_identities), total_used=total_refs
        )
        bounded |= identity_scan_limited or truncated
        observation_times.extend(row.last_observed_at for row in valid_identities)
        confidence_values.extend(float(row.confidence) for row in valid_identities)

        usages, usage_scan_limited = _bounded_rows(
            self._db.scalars(
                select(DiscoveryAssetUsageFact)
                .where(DiscoveryAssetUsageFact.tenant_id == asset.tenant_id, DiscoveryAssetUsageFact.asset_id == asset.asset_id)
                .order_by(DiscoveryAssetUsageFact.last_observed_at.desc(), DiscoveryAssetUsageFact.usage_fact_id.desc())
                .limit(_SOURCE_LIMIT)
            )
        )
        current_usages = _latest_by(
            usages,
            key=lambda row: (row.actor_type, row.actor_reference_hash, row.source_surface),
            ordering=lambda row: (_order_time(row.last_observed_at), row.usage_fact_id),
        )
        valid_usages = [
            row for row in current_usages
            if row.verification_state == "verified" and row.freshness == "fresh" and _current_window(row, as_of=as_of)
            and (not actor_supplied or (actor_hash is not None and row.actor_reference_hash == actor_hash))
        ]
        total_refs, truncated = _append_refs(
            context, key="usage_refs", refs=(f"usage:{row.usage_fact_id}" for row in valid_usages), total_used=total_refs
        )
        bounded |= usage_scan_limited or truncated
        observation_times.extend(row.last_observed_at for row in valid_usages if row.last_observed_at is not None)
        confidence_values.extend(float(row.confidence) for row in valid_usages)

        evidence_claim_ids = {row.evidence_claim_id for row in valid_capabilities}
        claims: list[DiscoveryEvidenceClaim] = []
        claims_scan_limited = False
        if evidence_claim_ids:
            claims, claims_scan_limited = _bounded_rows(
                self._db.scalars(
                    select(DiscoveryEvidenceClaim)
                    .where(
                        DiscoveryEvidenceClaim.tenant_id == asset.tenant_id,
                        DiscoveryEvidenceClaim.subject_asset_id == asset.asset_id,
                        DiscoveryEvidenceClaim.claim_id.in_(evidence_claim_ids),
                    )
                    .order_by(DiscoveryEvidenceClaim.observed_at.desc(), DiscoveryEvidenceClaim.claim_id.desc())
                    .limit(_SOURCE_LIMIT)
                )
            )
        valid_claims = [
            row for row in claims if row.freshness == "fresh" and _at_or_before(row.observed_at, as_of)
        ]
        total_refs, truncated = _append_refs(
            context, key="evidence_refs", refs=(f"evidence_claim:{row.claim_id}" for row in valid_claims), total_used=total_refs
        )
        bounded |= claims_scan_limited or truncated
        observation_times.extend(row.observed_at for row in valid_claims)
        confidence_values.extend(float(row.confidence) for row in valid_claims)

        (
            dependency_refs,
            verification_refs,
            graph_observed,
            graph_verified,
            graph_confidence,
            graph_limited,
        ) = self._graph_refs(asset=asset, as_of=as_of)
        total_refs, dependency_truncated = _append_refs(
            context, key="dependency_refs", refs=dependency_refs, total_used=total_refs
        )
        total_refs, verification_truncated = _append_refs(
            context, key="verification_refs", refs=verification_refs, total_used=total_refs
        )
        bounded |= graph_limited or dependency_truncated or verification_truncated
        observation_times.extend(graph_observed)
        verification_times.extend(graph_verified)
        confidence_values.extend(graph_confidence)

        coverage_paths, coverage_assertions, coverage_limited = self._coverage_refs(
            asset=asset,
            as_of=as_of,
            runtime_ref=runtime_ref,
            runtime_supplied=runtime_supplied,
        )
        control_coverage: dict[str, list[str]] = {}
        total_refs, path_truncated = _append_refs(
            control_coverage, key="path_refs", refs=coverage_paths, total_used=total_refs
        )
        total_refs, assertion_truncated = _append_refs(
            control_coverage,
            key="assertion_refs",
            refs=coverage_assertions,
            total_used=total_refs,
            dimension_remaining=MAX_REFS_PER_DIMENSION - len(control_coverage["path_refs"]),
        )
        context["control_coverage"] = control_coverage
        bounded |= coverage_limited or path_truncated or assertion_truncated

        dimensions = {
            "capability": len(context["capability_refs"]),
            "reachability": len(context["reachability_refs"]),
            "identity": len(context["identity_refs"]),
            "dependency": len(context["dependency_refs"]),
            "usage": len(context["usage_refs"]),
            "verification": len(context["verification_refs"]),
            "evidence": len(context["evidence_refs"]),
            "control_coverage": len(control_coverage["assertion_refs"]),
        }
        context["summaries"] = {name: {"reference_count": count} for name, count in dimensions.items()}
        context["confidence"] = {
            "asset": round(float(asset.resolution_confidence), 6),
            "minimum": round(min(confidence_values), 6),
            "maximum": round(max(confidence_values), 6),
            "reference_count": total_refs,
        }
        context["last_discovery"] = _format_time(max(_to_utc(value) for value in observation_times)) if observation_times else None
        context["last_verification"] = _format_time(max(_to_utc(value) for value in verification_times)) if verification_times else None

        if actor_supplied and actor_hash is None:
            context["limitations"].append("actor_ref_unmatched")
        if identity_supplied and identity_hash is None:
            context["limitations"].append("identity_ref_unmatched")
        if runtime_supplied and runtime_ref is None:
            context["limitations"].append("runtime_ref_unmatched")
        if context["identity_refs"]:
            context["limitations"].append("identity_freshness_unproven")
        if context["evidence_refs"]:
            context["limitations"].append("evidence_verification_indirect")
        if bounded:
            context["limitations"].append("result_bounds_reached")
        if any(count == 0 for count in dimensions.values()):
            context["limitations"].append("missing_authoritative_dimensions")
        context["limitations"] = sorted(set(context["limitations"]))[:16]
        context["status"] = "available" if not context["limitations"] else "partial"
        if len(json.dumps(context, sort_keys=True, separators=(",", ":"))) > MAX_CONTEXT_BYTES:
            return _unknown_context(as_of=as_of, limitation="result_bounds_reached")
        return context

    def _graph_refs(
        self, *, asset: DiscoveryAIAsset, as_of: datetime
    ) -> tuple[list[str], list[str], list[datetime], list[datetime], list[float], bool]:
        nodes, nodes_limited = _bounded_rows(
            self._db.scalars(
                select(DiscoveryResolutionGraphNode)
                .where(
                    DiscoveryResolutionGraphNode.tenant_id == asset.tenant_id,
                    DiscoveryResolutionGraphNode.node_class == "ai_asset",
                    DiscoveryResolutionGraphNode.subject_reference.in_(
                        (asset.asset_id, f"discovery_asset:{asset.asset_id}")
                    ),
                )
                .order_by(DiscoveryResolutionGraphNode.graph_node_id)
                .limit(_SOURCE_LIMIT)
            )
        )
        if len(nodes) != 1:
            return [], [], [], [], [], nodes_limited
        memberships, memberships_limited = _bounded_rows(
            self._db.scalars(
                select(DiscoveryEcosystemMembership)
                .where(
                    DiscoveryEcosystemMembership.tenant_id == asset.tenant_id,
                    DiscoveryEcosystemMembership.graph_node_id == nodes[0].graph_node_id,
                )
                .order_by(
                    DiscoveryEcosystemMembership.membership_sequence.desc(),
                    DiscoveryEcosystemMembership.membership_id.desc(),
                )
                .limit(_SOURCE_LIMIT)
            )
        )
        current_memberships = _latest_by(
            memberships,
            key=lambda row: (row.ecosystem_id,),
            ordering=lambda row: (int(row.membership_sequence), _order_time(row.last_observed_at), row.membership_id),
            superseded_id=lambda row: row.predecessor_membership_id,
            row_id=lambda row: row.membership_id,
        )
        active_memberships = [
            row for row in current_memberships
            if row.membership_state == "active" and row.verification_state == "verified" and _current_window(row, as_of=as_of)
        ]
        if len(active_memberships) != 1:
            return [], [], [], [], [], nodes_limited or memberships_limited
        membership = active_memberships[0]
        ecosystems, ecosystems_limited = _bounded_rows(
            self._db.scalars(
                select(DiscoveryAIEcosystem)
                .where(
                    DiscoveryAIEcosystem.tenant_id == asset.tenant_id,
                    DiscoveryAIEcosystem.ecosystem_id == membership.ecosystem_id,
                )
                .order_by(
                    DiscoveryAIEcosystem.resolution_version.desc(),
                    DiscoveryAIEcosystem.last_validated_at.desc(),
                    DiscoveryAIEcosystem.ecosystem_record_id.desc(),
                )
                .limit(_SOURCE_LIMIT)
            )
        )
        current_ecosystems = _latest_by(
            ecosystems,
            key=lambda row: (row.ecosystem_id,),
            ordering=lambda row: (int(row.resolution_version), _order_time(row.last_validated_at), row.ecosystem_record_id),
            superseded_id=lambda row: row.supersedes_record_id,
            row_id=lambda row: row.ecosystem_record_id,
        )
        if len(current_ecosystems) != 1:
            return [], [], [], [], [], nodes_limited or memberships_limited or ecosystems_limited
        ecosystem = current_ecosystems[0]
        if (
            ecosystem.ecosystem_record_id != membership.ecosystem_record_id
            or ecosystem.lifecycle_state != "active"
            or ecosystem.resolution_state != "resolved"
            or not _current_window(ecosystem, as_of=as_of)
            or not _at_or_before(ecosystem.last_validated_at, as_of)
        ):
            return [], [], [], [], [], nodes_limited or memberships_limited or ecosystems_limited

        refs: list[str] = []
        assertions: list[str] = []
        observed = [membership.last_observed_at, ecosystem.last_observed_at]
        verified = [ecosystem.last_validated_at]
        confidence = [float(membership.confidence)]
        limited = nodes_limited or memberships_limited or ecosystems_limited
        if ecosystem.capability_genome_id:
            pinned_genome = self._db.scalar(
                select(DiscoveryCapabilityGenome).where(
                    DiscoveryCapabilityGenome.tenant_id == asset.tenant_id,
                    DiscoveryCapabilityGenome.genome_id == ecosystem.capability_genome_id,
                )
            )
            if pinned_genome is not None:
                genomes, genomes_limited = _bounded_rows(
                    self._db.scalars(
                        select(DiscoveryCapabilityGenome)
                        .where(
                            DiscoveryCapabilityGenome.tenant_id == asset.tenant_id,
                            DiscoveryCapabilityGenome.subject_reference_hash == pinned_genome.subject_reference_hash,
                        )
                        .order_by(DiscoveryCapabilityGenome.genome_version.desc(), DiscoveryCapabilityGenome.genome_id.desc())
                        .limit(_SOURCE_LIMIT)
                    )
                )
                current_genomes = _latest_by(
                    genomes,
                    key=lambda row: (row.subject_reference_hash,),
                    ordering=lambda row: (int(row.genome_version), _order_time(row.last_observed_at), row.genome_id),
                    superseded_id=lambda row: row.supersedes_genome_id,
                    row_id=lambda row: row.genome_id,
                )
                if (
                    len(current_genomes) == 1
                    and current_genomes[0].genome_id == ecosystem.capability_genome_id
                    and current_genomes[0].dependencies_json
                    and _current_window(current_genomes[0], as_of=as_of)
                ):
                    refs.append(f"capability_genome:{current_genomes[0].genome_id}")
                    observed.append(current_genomes[0].last_observed_at)
                limited |= genomes_limited

        assertions_rows, assertions_limited = _bounded_rows(
            self._db.scalars(
                select(DiscoveryVerificationAssertion)
                .where(
                    DiscoveryVerificationAssertion.tenant_id == asset.tenant_id,
                    DiscoveryVerificationAssertion.ecosystem_id == ecosystem.ecosystem_id,
                )
                .order_by(
                    DiscoveryVerificationAssertion.assertion_sequence.desc(),
                    DiscoveryVerificationAssertion.issued_at.desc(),
                    DiscoveryVerificationAssertion.assertion_id.desc(),
                )
                .limit(_SOURCE_LIMIT)
            )
        )
        current_assertions = _latest_by(
            assertions_rows,
            key=lambda row: (row.ecosystem_id,),
            ordering=lambda row: (int(row.assertion_sequence), _order_time(row.issued_at), row.assertion_id),
            superseded_id=lambda row: row.predecessor_assertion_id,
            row_id=lambda row: row.assertion_id,
        )
        for row in current_assertions:
            if (
                row.conclusion == "verified"
                and row.ecosystem_record_id == ecosystem.ecosystem_record_id
                and row.invalidated_at is None
                and _at_or_before(row.valid_from, as_of)
                and _to_utc(row.valid_until) > as_of
            ):
                assertions.append(f"verification_assertion:{row.assertion_id}")
                verified.append(row.issued_at)
        return refs, assertions, observed, verified, confidence, limited or assertions_limited

    def _coverage_refs(
        self,
        *,
        asset: DiscoveryAIAsset,
        as_of: datetime,
        runtime_ref: str | None,
        runtime_supplied: bool,
    ) -> tuple[list[str], list[str], bool]:
        paths, paths_limited = _bounded_rows(
            self._db.scalars(
                select(ControlCoveragePath)
                .where(
                    ControlCoveragePath.tenant_id == asset.tenant_id,
                    ControlCoveragePath.asset_ref.in_((asset.asset_id, f"discovery_asset:{asset.asset_id}")),
                )
                .order_by(ControlCoveragePath.last_seen_at.desc(), ControlCoveragePath.id.desc())
                .limit(_SOURCE_LIMIT)
            )
        )
        current_paths = [
            row for row in paths
            if row.lifecycle_status == "active" and _current_window(row, as_of=as_of, first="first_seen_at", last="last_seen_at")
            and (not runtime_supplied or (runtime_ref is not None and _normal(row.runtime_ref) == runtime_ref))
        ]
        if not current_paths:
            return [], [], paths_limited
        path_ids = [row.id for row in current_paths]
        assertions, assertions_limited = _bounded_rows(
            self._db.scalars(
                select(ControlCoverageAssertion)
                .where(
                    ControlCoverageAssertion.tenant_id == asset.tenant_id,
                    ControlCoverageAssertion.path_id.in_(path_ids),
                )
                .order_by(ControlCoverageAssertion.evaluated_at.desc(), ControlCoverageAssertion.id.desc())
                .limit(_SOURCE_LIMIT)
            )
        )
        latest_assertions = _latest_by(
            assertions,
            key=lambda row: (row.path_id, row.dimension),
            ordering=lambda row: (_order_time(row.evaluated_at), row.id),
        )
        valid_assertions = [
            row for row in latest_assertions
            if _at_or_before(row.observed_at, as_of)
            and _at_or_before(row.evaluated_at, as_of)
            and (row.valid_until is None or _to_utc(row.valid_until) > as_of)
        ]
        valid_path_ids = {row.path_id for row in valid_assertions}
        return (
            [f"control_coverage_path:{row.id}" for row in current_paths if row.id in valid_path_ids],
            [f"control_coverage_assertion:{row.id}" for row in valid_assertions],
            paths_limited or assertions_limited,
        )


def get_context_for_ai_action(db: Session, **kwargs: Any) -> dict[str, Any]:
    return DiscoveryContextProvider(db).get_context_for_ai_action(**kwargs)


def getContextForAIAction(db: Session, **kwargs: Any) -> dict[str, Any]:  # noqa: N802
    return get_context_for_ai_action(db, **kwargs)


__all__ = [
    "DiscoveryContextProvider",
    "getContextForAIAction",
    "get_context_for_ai_action",
]
