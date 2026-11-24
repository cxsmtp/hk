"""Conservative Phase 2 discovery inputs for Control Coverage.

This module is deliberately additive.  It does not alter the existing path
authorization, evidence, deployment, runtime, or bypass methodology.  Scores
are withheld until Hawk has an explicit fresh enterprise denominator.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_asset import DiscoveryAIAsset, DiscoveryEvidenceClaim
from app.db.models.discovery_attribution import (
    DiscoveryAssetIdentityLink,
    DiscoveryAssetReachability,
)
from app.db.models.discovery_canonical import DiscoveryCollector, DiscoveryScan
from app.db.models.discovery_intelligence import DiscoveryAssetUsageFact
from app.db.models.discovery_resolution import DiscoveryAssetHypothesis
from app.services.hmair.governance_contracts import H5_CONTROL_COVERAGE_DIMENSIONS


METHODOLOGY_VERSION = "discovery-coverage/2.0"
_SUPPORTED_RESULT = "supported"
_NEGATIVE_RESULTS = frozenset({"contradicted", "rejected", "not_supported"})
_CURRENT_FRESHNESS = frozenset({"fresh"})
_VERIFIED = frozenset({"verified", "partially_verified"})


@dataclass(frozen=True)
class DiscoveryDenominatorTruth:
    status: str
    known_assets: int
    unresolved_hypotheses: int
    inaccessible_sources: int
    stale_sources: int
    unknown_sources: tuple[str, ...]
    unsupported_sources: tuple[str, ...]
    enterprise_denominator_complete: bool
    evidence_ref: str | None
    explanation: str


@dataclass(frozen=True)
class DiscoveryCoverageDimension:
    name: str
    covered_count: int
    not_covered_count: int
    unknown_count: int
    covered_asset_ids: tuple[str, ...]
    not_covered_asset_ids: tuple[str, ...]
    unknown_asset_ids: tuple[str, ...]
    score: float | None
    score_withheld_reason: str | None
    methodology: str
    evidence_refs: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    improvement_actions: tuple[str, ...]


@dataclass(frozen=True)
class DiscoveryCoverageProjection:
    tenant_id: str
    methodology_version: str
    generated_at: datetime
    denominator: DiscoveryDenominatorTruth
    dimensions: dict[str, DiscoveryCoverageDimension]
    limitations: tuple[str, ...]


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("coverage time must be timezone-aware")
    return value.astimezone(timezone.utc)


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _safe_strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(
        sorted(
            {
                item.strip()[:128]
                for item in value
                if type(item) is str and item.strip()
            }
        )
    )


def _latest_by_asset(
    rows: Iterable[object], *, attribute: str = "asset_id"
) -> dict[str, object]:
    output: dict[str, object] = {}
    for row in rows:
        output[str(getattr(row, attribute))] = row
    return output


def _latest_claims_by_asset_and_type(
    rows: Iterable[DiscoveryEvidenceClaim],
) -> tuple[
    dict[str, DiscoveryEvidenceClaim],
    dict[tuple[str, str], DiscoveryEvidenceClaim],
    dict[str, tuple[DiscoveryEvidenceClaim, ...]],
]:
    discovery: dict[str, DiscoveryEvidenceClaim] = {}
    typed: dict[tuple[str, str], DiscoveryEvidenceClaim] = {}
    all_by_asset: dict[str, list[DiscoveryEvidenceClaim]] = {}
    for row in rows:
        if row.subject_asset_id is None:
            continue
        asset_id = str(row.subject_asset_id)
        all_by_asset.setdefault(asset_id, []).append(row)
        typed[(asset_id, str(row.claim_type))] = row
        if row.claim_type in {"asset_candidate", "canonical_asset", "asset_resolution"}:
            discovery[asset_id] = row
    return (
        discovery,
        typed,
        {key: tuple(value) for key, value in all_by_asset.items()},
    )


def _claim_coverage_state(claim: DiscoveryEvidenceClaim | None) -> str:
    if claim is None:
        return "unknown"
    if claim.claim_result == _SUPPORTED_RESULT and claim.freshness in _CURRENT_FRESHNESS:
        return "covered"
    if claim.claim_result in _NEGATIVE_RESULTS:
        return "not_covered"
    return "unknown"


def _denominator(
    *,
    assets: list[DiscoveryAIAsset],
    hypotheses: list[DiscoveryAssetHypothesis],
    collectors: list[DiscoveryCollector],
    scans: list[DiscoveryScan],
) -> DiscoveryDenominatorTruth:
    unresolved = sum(
        1
        for row in hypotheses
        if row.state not in {"confirmed", "rejected"}
    )
    inaccessible = sum(
        1 for row in collectors if row.health in {"degraded", "offline"}
    )
    latest = scans[-1] if scans else None
    coverage = _mapping(latest.coverage_summary_json) if latest else {}
    unknown = _safe_strings(coverage.get("unknown"))
    unsupported = _safe_strings(coverage.get("unsupported"))
    freshness = str(coverage.get("freshness") or "unknown").strip().lower()
    exclusions = _safe_strings(coverage.get("explicit_exclusions"))
    enterprise_complete = bool(
        latest is not None
        and latest.status == "complete"
        and latest.completed_at is not None
        and coverage.get("denominator_complete") is True
        and coverage.get("enterprise_denominator_complete") is True
        and latest.assets_unresolved == 0
        and not latest.errors_json
        and not unknown
        and not unsupported
        and not exclusions
        and freshness == "fresh"
        and unresolved == 0
    )
    stale_sources = 1 if latest is not None and freshness in {"stale", "expired"} else 0

    if enterprise_complete:
        status = "known"
        explanation = "A fresh, complete authoritative enterprise denominator and complete scan are present."
    elif stale_sources:
        status = "stale"
        explanation = "The latest denominator evidence is stale or expired; scores are withheld."
    elif collectors and inaccessible == len(collectors):
        status = "inaccessible"
        explanation = "All registered discovery sources are degraded or offline; scores are withheld."
    elif assets or unresolved or latest is not None:
        status = "inferred"
        explanation = "Hawk knows assets or scan scope, but no fresh complete enterprise denominator is proven."
    else:
        status = "unknown"
        explanation = "No authoritative enterprise denominator or canonical asset evidence is available."

    return DiscoveryDenominatorTruth(
        status=status,
        known_assets=len(assets),
        unresolved_hypotheses=unresolved,
        inaccessible_sources=inaccessible,
        stale_sources=stale_sources,
        unknown_sources=unknown,
        unsupported_sources=unsupported,
        enterprise_denominator_complete=enterprise_complete,
        evidence_ref=(f"discovery_scan:{latest.scan_id}" if latest else None),
        explanation=explanation,
    )


def _dimension(
    *,
    name: str,
    covered: list[str],
    not_covered: list[str],
    unknown: list[str],
    denominator_complete: bool,
    methodology: str,
    evidence_refs: set[str],
    missing_evidence: set[str],
    improvement_actions: tuple[str, ...],
) -> DiscoveryCoverageDimension:
    denominator = len(covered) + len(not_covered) + len(unknown)
    score = (
        round(100.0 * len(covered) / denominator, 2)
        if denominator_complete and denominator
        else None
    )
    return DiscoveryCoverageDimension(
        name=name,
        covered_count=len(covered),
        not_covered_count=len(not_covered),
        unknown_count=len(unknown),
        covered_asset_ids=tuple(sorted(covered)),
        not_covered_asset_ids=tuple(sorted(not_covered)),
        unknown_asset_ids=tuple(sorted(unknown)),
        score=score,
        score_withheld_reason=(
            None
            if score is not None
            else (
                "enterprise_denominator_not_established"
                if not denominator_complete
                else "no_in_scope_assets"
            )
        ),
        methodology=methodology,
        evidence_refs=tuple(sorted(evidence_refs)),
        missing_evidence=tuple(sorted(missing_evidence)),
        improvement_actions=improvement_actions,
    )


def calculate_discovery_coverage(
    db: Session,
    *,
    tenant_id: str,
    now: datetime,
) -> DiscoveryCoverageProjection:
    current = _utc(now)
    assets = list(
        db.scalars(
            select(DiscoveryAIAsset)
            .where(DiscoveryAIAsset.tenant_id == tenant_id)
            .order_by(DiscoveryAIAsset.asset_id)
        )
    )
    hypotheses = list(
        db.scalars(
            select(DiscoveryAssetHypothesis)
            .where(DiscoveryAssetHypothesis.tenant_id == tenant_id)
            .order_by(DiscoveryAssetHypothesis.hypothesis_id)
        )
    )
    collectors = list(
        db.scalars(
            select(DiscoveryCollector)
            .where(DiscoveryCollector.tenant_id == tenant_id)
            .order_by(DiscoveryCollector.collector_id)
        )
    )
    scans = list(
        db.scalars(
            select(DiscoveryScan)
            .where(DiscoveryScan.tenant_id == tenant_id)
            .order_by(DiscoveryScan.created_at, DiscoveryScan.scan_id)
        )
    )
    denominator = _denominator(
        assets=assets,
        hypotheses=hypotheses,
        collectors=collectors,
        scans=scans,
    )

    claim_rows = tuple(
        db.scalars(
            select(DiscoveryEvidenceClaim)
            .where(
                DiscoveryEvidenceClaim.tenant_id == tenant_id,
                DiscoveryEvidenceClaim.subject_asset_id.is_not(None),
            )
            .order_by(
                DiscoveryEvidenceClaim.created_at,
                DiscoveryEvidenceClaim.claim_id,
            )
        )
    )
    claims, typed_claims, all_claims = _latest_claims_by_asset_and_type(claim_rows)
    identities = _latest_by_asset(
        db.scalars(
            select(DiscoveryAssetIdentityLink)
            .where(DiscoveryAssetIdentityLink.tenant_id == tenant_id)
            .order_by(
                DiscoveryAssetIdentityLink.created_at,
                DiscoveryAssetIdentityLink.identity_link_id,
            )
        )
    )
    usage = _latest_by_asset(
        db.scalars(
            select(DiscoveryAssetUsageFact)
            .where(DiscoveryAssetUsageFact.tenant_id == tenant_id)
            .order_by(
                DiscoveryAssetUsageFact.created_at,
                DiscoveryAssetUsageFact.usage_fact_id,
            )
        )
    )
    reachability = _latest_by_asset(
        db.scalars(
            select(DiscoveryAssetReachability)
            .where(DiscoveryAssetReachability.tenant_id == tenant_id)
            .order_by(
                DiscoveryAssetReachability.created_at,
                DiscoveryAssetReachability.reachability_id,
            )
        )
    )

    buckets: dict[str, dict[str, list[str] | set[str]]] = {
        name: {
            "covered": [],
            "not_covered": [],
            "unknown": [],
            "evidence": set(),
            "missing": set(),
        }
        for name in H5_CONTROL_COVERAGE_DIMENSIONS
    }

    for asset in assets:
        asset_ref = f"evidence_node:{asset.evidence_bundle_id}"

        claim = claims.get(asset.asset_id)
        if claim is None:
            buckets["discovery"]["unknown"].append(asset.asset_id)  # type: ignore[union-attr]
            buckets["discovery"]["missing"].add(f"asset:{asset.asset_id}:current_resolution_claim")  # type: ignore[union-attr]
            buckets["discovery"]["evidence"].add(asset_ref)  # type: ignore[union-attr]
        else:
            buckets["discovery"]["evidence"].update(  # type: ignore[union-attr]
                {f"claim:{claim.claim_id}", f"evidence_node:{claim.evidence_node_id}"}
            )
            if claim.claim_result == _SUPPORTED_RESULT and claim.freshness in _CURRENT_FRESHNESS:
                buckets["discovery"]["covered"].append(asset.asset_id)  # type: ignore[union-attr]
            elif claim.claim_result in _NEGATIVE_RESULTS:
                buckets["discovery"]["not_covered"].append(asset.asset_id)  # type: ignore[union-attr]
            else:
                buckets["discovery"]["unknown"].append(asset.asset_id)  # type: ignore[union-attr]

        identity = identities.get(asset.asset_id)
        if identity is None:
            buckets["identity"]["not_covered"].append(asset.asset_id)  # type: ignore[union-attr]
            buckets["identity"]["missing"].add(f"asset:{asset.asset_id}:identity_binding")  # type: ignore[union-attr]
            buckets["identity"]["evidence"].add(asset_ref)  # type: ignore[union-attr]
        else:
            buckets["identity"]["evidence"].add(f"evidence_node:{identity.evidence_node_id}")  # type: ignore[union-attr]
            if identity.verification_state in _VERIFIED and identity.identity_type != "unknown" and identity.access_state != "unknown":
                buckets["identity"]["covered"].append(asset.asset_id)  # type: ignore[union-attr]
            else:
                buckets["identity"]["unknown"].append(asset.asset_id)  # type: ignore[union-attr]

        usage_fact = usage.get(asset.asset_id)
        if usage_fact is None:
            buckets["usage"]["not_covered"].append(asset.asset_id)  # type: ignore[union-attr]
            buckets["usage"]["missing"].add(f"asset:{asset.asset_id}:usage_telemetry")  # type: ignore[union-attr]
            buckets["usage"]["evidence"].add(asset_ref)  # type: ignore[union-attr]
        else:
            buckets["usage"]["evidence"].add(f"evidence_node:{usage_fact.evidence_node_id}")  # type: ignore[union-attr]
            if usage_fact.telemetry_complete and usage_fact.verification_state in _VERIFIED and usage_fact.freshness in _CURRENT_FRESHNESS and usage_fact.usage_state != "unknown":
                buckets["usage"]["covered"].append(asset.asset_id)  # type: ignore[union-attr]
            else:
                buckets["usage"]["unknown"].append(asset.asset_id)  # type: ignore[union-attr]

        reach = reachability.get(asset.asset_id)
        observed_path = bool(
            reach is not None
            and reach.observed_usage
            and reach.freshness in _CURRENT_FRESHNESS
        )

        evidence_claims = all_claims.get(asset.asset_id, ())
        current_supported_evidence = tuple(
            item
            for item in evidence_claims
            if item.claim_result == _SUPPORTED_RESULT
            and item.freshness in _CURRENT_FRESHNESS
        )
        if current_supported_evidence:
            buckets["evidence"]["covered"].append(asset.asset_id)  # type: ignore[union-attr]
            buckets["evidence"]["evidence"].update(  # type: ignore[union-attr]
                f"evidence_node:{item.evidence_node_id}"
                for item in current_supported_evidence
            )
        elif any(item.claim_result in _NEGATIVE_RESULTS for item in evidence_claims):
            buckets["evidence"]["not_covered"].append(asset.asset_id)  # type: ignore[union-attr]
            buckets["evidence"]["evidence"].add(asset_ref)  # type: ignore[union-attr]
        else:
            buckets["evidence"]["unknown"].append(asset.asset_id)  # type: ignore[union-attr]
            buckets["evidence"]["missing"].add(  # type: ignore[union-attr]
                f"asset:{asset.asset_id}:accepted_evidence_claim"
            )
            buckets["evidence"]["evidence"].add(asset_ref)  # type: ignore[union-attr]

        for dimension_name, claim_type in (
            ("authorization", "authorization_inline"),
            ("containment", "containment_control"),
            ("bypass_detection", "bypass_detection"),
        ):
            control_claim = typed_claims.get((asset.asset_id, claim_type))
            state = _claim_coverage_state(control_claim)
            if state == "unknown" and observed_path and dimension_name in {
                "authorization",
                "containment",
            }:
                state = "not_covered"
            buckets[dimension_name][state].append(asset.asset_id)  # type: ignore[union-attr]
            if control_claim is not None:
                buckets[dimension_name]["evidence"].add(  # type: ignore[union-attr]
                    f"evidence_node:{control_claim.evidence_node_id}"
                )
            else:
                buckets[dimension_name]["evidence"].add(  # type: ignore[union-attr]
                    f"evidence_node:{reach.evidence_node_id}" if reach else asset_ref
                )
                buckets[dimension_name]["missing"].add(  # type: ignore[union-attr]
                    f"asset:{asset.asset_id}:{claim_type}"
                )

    methods = {
        "discovery": "Covered only by a current supported asset evidence claim; contradictory claims are not covered and missing/stale claims are Unknown.",
        "identity": "Covered only by a verified or partially verified non-unknown identity binding; missing bindings are not covered.",
        "usage": "Covered only by complete, current, verified telemetry with an explicit usage state, including evidence-backed never-observed.",
        "authorization": "Covered only by a current accepted authorization_inline claim for the exact asset path; an observed monitor-only path is not covered and missing path truth remains Unknown.",
        "evidence": "Covered only when a current supported canonical evidence claim exists; rejected evidence is not covered and missing or stale evidence remains Unknown.",
        "containment": "Covered only by a current accepted containment_control claim for the exact asset path; observation without an effective control is not containment.",
        "bypass_detection": "Covered only by a current accepted bypass_detection claim; adapter presence or route visibility alone does not establish bypass detection.",
    }
    improvements = {
        "discovery": ("Run supported collectors against the unresolved scope.", "Complete bounded verification for stale or contradictory asset claims."),
        "identity": ("Connect authoritative identity telemetry and bind service, workload, agent, and human actors separately.",),
        "usage": ("Enable privacy-safe activity telemetry that distinguishes installed, configured, licensed, and active use.",),
        "authorization": ("Bind an accepted pre-execution decision and exact control path to the asset.",),
        "evidence": ("Create a current canonical evidence claim with retained provenance.",),
        "containment": ("Validate an effective current control capable of acting on the exact path.",),
        "bypass_detection": ("Validate current bypass-detection evidence for the exact path.",),
    }
    dimensions = {
        name: _dimension(
            name=name,
            covered=bucket["covered"],  # type: ignore[arg-type]
            not_covered=bucket["not_covered"],  # type: ignore[arg-type]
            unknown=bucket["unknown"],  # type: ignore[arg-type]
            denominator_complete=denominator.enterprise_denominator_complete,
            methodology=methods[name],
            evidence_refs=bucket["evidence"],  # type: ignore[arg-type]
            missing_evidence=bucket["missing"],  # type: ignore[arg-type]
            improvement_actions=improvements[name],
        )
        for name, bucket in buckets.items()
    }
    return DiscoveryCoverageProjection(
        tenant_id=tenant_id,
        methodology_version=METHODOLOGY_VERSION,
        generated_at=current,
        denominator=denominator,
        dimensions=dimensions,
        limitations=(
            "This additive projection does not change authorization, proof, deployment, runtime, or bypass scores.",
            "Collector health, installation, configuration, licenses, and API keys are not treated as proof of actual use.",
            "A score is withheld unless a fresh authoritative enterprise denominator is explicitly evidenced.",
        ),
    )


__all__ = [
    "DiscoveryCoverageDimension",
    "DiscoveryCoverageProjection",
    "DiscoveryDenominatorTruth",
    "METHODOLOGY_VERSION",
    "calculate_discovery_coverage",
]
