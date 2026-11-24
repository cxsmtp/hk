"""Evidence-backed HMAIR H5 governance projections.

All functions are pure and deterministic.  They consume canonical facts and do
not create authorization, mutate policy, or turn configuration into activity.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.services.hmair.contracts import canonical_json_bytes
from app.services.hmair.governance_contracts import (
    AcceptedGovernanceClaim,
    GovernanceAssetSnapshot,
    H5ActorUsageView,
    H5AssetUsageView,
    H5ChangeEvent,
    H5GraphRelationship,
    H5ReachabilityProjection,
    H5ShadowClassification,
    H5UsageAggregate,
    H5UsageProjection,
    H5UsageViews,
)


_LEGACY_USAGE_MAP = {
    "never_observed": "no_usage_observed",
    "historical": "historical_usage",
    "occasional": "active_usage",
    "active": "active_usage",
    "high_usage": "high_frequency_usage",
    "unknown": "unknown_usage",
}
_SERVICE_ACTORS = frozenset({"agent", "service", "workload", "automation"})


def project_h5_usage(
    *,
    tenant_id: str,
    asset_id: str,
    legacy_usage_state: str,
    actor_type: str,
    actor_reference_hash: str | None,
    event_count: int,
    first_observed_at,
    last_observed_at,
    telemetry_complete: bool,
    business_unit_reference_hash: str | None,
    geography: str,
    environment: str,
    account_class: str,
    governance_class: str,
    window_start,
    window_end,
    evidence_refs: tuple[str, ...],
    confidence: float,
) -> H5UsageProjection:
    """Map stored H1 usage truth into the exact H5 public vocabulary."""

    if legacy_usage_state not in _LEGACY_USAGE_MAP:
        raise ValueError("legacy usage state is unsupported")
    if actor_type not in {*_SERVICE_ACTORS, "human", "unknown"}:
        raise ValueError("usage actor type is unsupported")
    if type(telemetry_complete) is not bool:
        raise ValueError("usage telemetry completeness must be explicit")
    if not telemetry_complete:
        state = "unknown_usage"
        explanation = "Telemetry is incomplete, so Hawk does not infer an activity state."
    elif actor_type in _SERVICE_ACTORS and event_count > 0:
        state = "service_usage"
        explanation = "Current evidence attributes use to a service, workload, automation, or agent identity."
    else:
        state = _LEGACY_USAGE_MAP[legacy_usage_state]
        explanations = {
            "no_usage_observed": "Complete in-scope telemetry contains no observed usage event.",
            "historical_usage": "Usage exists but the latest evidence is outside the active window.",
            "active_usage": "Usage is observed within the selected active window.",
            "high_frequency_usage": "Observed usage meets the versioned high-frequency threshold.",
            "unknown_usage": "The available evidence does not support a usage conclusion.",
        }
        explanation = explanations[state]
    if state == "no_usage_observed" and event_count != 0:
        raise ValueError("no-usage projection cannot carry events")
    actor_class = (
        "human" if actor_type == "human" else
        "service_agent" if actor_type in _SERVICE_ACTORS else
        "unknown"
    )
    limitations = (
        "Installation, configuration, licence, or catalog presence is not active usage.",
        "Identity, geography, or business-unit scope remains unknown when no authoritative binding exists.",
    )
    return H5UsageProjection(
        tenant_id=tenant_id,
        asset_id=asset_id,
        state=state,
        actor_class=actor_class,
        actor_type=actor_type,
        actor_reference_hash=actor_reference_hash,
        business_unit_reference_hash=business_unit_reference_hash,
        geography=geography,
        environment=environment,
        account_class=account_class,
        governance_class=governance_class,
        event_count=event_count,
        first_observed_at=first_observed_at,
        last_observed_at=last_observed_at,
        window_start=window_start,
        window_end=window_end,
        telemetry_complete=telemetry_complete,
        evidence_refs=evidence_refs,
        confidence=confidence,
        explanation=explanation,
        limitations=limitations,
    )


def build_h5_usage_views(
    *,
    tenant_id: str,
    projections: tuple[H5UsageProjection, ...],
) -> H5UsageViews:
    """Build the required bounded user/asset and organization usage views."""

    if len(projections) > 100_000:
        raise ValueError("H5 usage projection input is unbounded")
    assets: dict[str, dict[str, Any]] = {}
    actors: dict[str, dict[str, Any]] = {}
    aggregates: dict[tuple[str, str], dict[str, Any]] = {}
    for item in projections:
        if item.tenant_id != tenant_id:
            raise ValueError("H5 usage projection is outside tenant scope")
        asset = assets.setdefault(item.asset_id, {"actors": set(), "events": 0})
        asset["events"] += item.event_count
        if item.actor_reference_hash is not None:
            asset["actors"].add(item.actor_reference_hash)
            actor = actors.setdefault(
                item.actor_reference_hash, {"assets": set(), "events": 0}
            )
            actor["assets"].add(item.asset_id)
            actor["events"] += item.event_count
        dimension_values = (
            ("business_unit", item.business_unit_reference_hash or "unknown"),
            ("geography", item.geography),
            ("environment", item.environment),
            (
                "time_window",
                f"{item.window_start.isoformat()}/{item.window_end.isoformat()}",
            ),
            ("account_class", item.account_class),
            ("governance_class", item.governance_class),
            ("actor_class", item.actor_class),
        )
        for dimension, key in dimension_values:
            aggregate = aggregates.setdefault(
                (dimension, key), {"assets": set(), "actors": set(), "events": 0}
            )
            aggregate["assets"].add(item.asset_id)
            if item.actor_reference_hash is not None:
                aggregate["actors"].add(item.actor_reference_hash)
            aggregate["events"] += item.event_count
    return H5UsageViews(
        tenant_id=tenant_id,
        assets_by_actor=tuple(
            H5ActorUsageView(
                actor_reference_hash=actor_ref,
                asset_ids=tuple(sorted(values["assets"])),
                event_count=values["events"],
            )
            for actor_ref, values in sorted(actors.items())[:500]
        ),
        actors_by_asset=tuple(
            H5AssetUsageView(
                asset_id=asset_id,
                actor_reference_hashes=tuple(sorted(values["actors"]))[:500],
                event_count=values["events"],
            )
            for asset_id, values in sorted(assets.items())[:500]
        ),
        aggregates=tuple(
            H5UsageAggregate(
                dimension=dimension,
                key=key,
                asset_count=len(values["assets"]),
                actor_count=len(values["actors"]),
                event_count=values["events"],
            )
            for (dimension, key), values in sorted(aggregates.items())[:500]
        ),
        limitations=(
            "Unknown identity and scope values remain explicit.",
            "Views are bounded; estate-scale pagination remains an H6 acceptance gate.",
        ),
    )
def classify_h5_shadow(
    *,
    tenant_id: str,
    asset_id: str,
    approval_state: str,
    control_state: str,
    owner_state: str,
    account_class: str,
    observed_usage: bool,
    independent_sources: tuple[str, ...],
    evidence_refs: tuple[str, ...],
    confidence: float,
) -> H5ShadowClassification:
    """Classify Shadow AI without treating a missing catalog match as proof."""

    if approval_state not in {"approved", "conditionally_approved", "unapproved", "expired", "unknown"}:
        raise ValueError("shadow approval state is invalid")
    if control_state not in {"current", "partial", "stale", "regressed", "gap", "unsupported", "unknown"}:
        raise ValueError("shadow control state is invalid")
    if owner_state not in {"known", "unknown", "conflicted"}:
        raise ValueError("shadow owner state is invalid")
    if account_class not in {"enterprise", "personal", "external", "anonymous", "unknown"}:
        raise ValueError("shadow account class is invalid")
    if type(observed_usage) is not bool:
        raise ValueError("shadow usage truth must be explicit")
    sources = tuple(sorted(set(independent_sources)))
    if any(not item or item != item.strip() or len(item) > 64 for item in sources):
        raise ValueError("shadow evidence sources are invalid")

    if approval_state in {"approved", "conditionally_approved"}:
        if control_state == "current":
            state = "approved"
            explanation = "Current evidence binds the asset to an approved governance record and current control."
            change = "A withdrawn approval, expired exception, or control regression would change this result."
        else:
            state = "approved_but_uncontrolled"
            explanation = "The asset is approved, but current path control is not established."
            change = "Validate a current supported control on the observed path."
    elif account_class == "personal" and observed_usage:
        state = "personal_account"
        explanation = "Current evidence identifies active use through a personal account context."
        change = "Bind the activity to an approved enterprise account or contradict the account evidence."
    elif owner_state == "unknown":
        state = "owner_unknown"
        explanation = "No authoritative business or technical owner is currently bound to the asset."
        change = "Verify an owner through an authoritative directory, repository, SaaS, or cloud source."
    elif approval_state in {"unapproved", "expired"} and not observed_usage:
        state = "known_unapproved"
        explanation = "The asset is known and unapproved, but active use is not evidenced."
        change = "An observed usage signal or a valid approval would change this result."
    elif approval_state in {"unapproved", "expired"} and observed_usage and len(sources) >= 2:
        state = "confirmed_shadow"
        explanation = "Unapproved active use is corroborated by at least two independent evidence sources."
        change = "A valid approval or contradictory current evidence would change this result."
    elif approval_state in {"unapproved", "expired"} and observed_usage:
        state = "suspected_shadow"
        explanation = "Unapproved use is indicated, but independent corroboration is incomplete."
        change = "Corroborate active use from another independent source or establish a valid approval."
    else:
        state = "unknown"
        explanation = "The available evidence does not establish approval, active shadow use, personal-account use, or ownership absence."
        change = "Collect current approval, owner, account, usage, and path-control evidence."

    bounded_confidence = min(confidence, 0.69) if state in {"suspected_shadow", "unknown"} else confidence
    return H5ShadowClassification(
        tenant_id=tenant_id,
        asset_id=asset_id,
        state=state,
        confidence=bounded_confidence,
        evidence_refs=evidence_refs,
        independent_sources=sources,
        explanation=explanation,
        change_condition=change,
        limitations=(
            "Lack of an approved-catalog match alone does not prove confirmed Shadow AI.",
            "Classification does not grant or revoke authority.",
        ),
    )


def project_h5_reachability(
    *,
    tenant_id: str,
    asset_id: str,
    target_type: str,
    target_reference_hash: str,
    state: str,
    source_surface: str,
    observed_usage: bool,
    control_capability: str,
    first_seen_at,
    last_seen_at,
    evidence_refs: tuple[str, ...],
    confidence: float,
    limitations: tuple[str, ...],
) -> H5ReachabilityProjection:
    return H5ReachabilityProjection(
        tenant_id=tenant_id,
        asset_id=asset_id,
        target_type=target_type,
        target_reference_hash=target_reference_hash,
        state=state,
        source_surface=source_surface,
        observed_usage=observed_usage,
        control_capability=control_capability,
        first_seen_at=first_seen_at,
        last_seen_at=last_seen_at,
        evidence_refs=evidence_refs,
        confidence=confidence,
        limitations=limitations,
    )


def project_accepted_claim_relationships(
    *, tenant_id: str, claims: tuple[AcceptedGovernanceClaim, ...]
) -> tuple[H5GraphRelationship, ...]:
    """Project accepted canonical claims while retaining inference truth."""

    output: dict[tuple[str, str, str, str], H5GraphRelationship] = {}
    for claim in claims:
        if claim.tenant_id != tenant_id:
            raise ValueError("governance claim is outside tenant scope")
        if (
            claim.admission_state != "accepted"
            or claim.freshness != "fresh"
            or claim.evidence_state == "unknown"
        ):
            continue
        relationship = H5GraphRelationship(
            tenant_id=tenant_id,
            from_ref=claim.subject_asset_id,
            relationship_type=claim.relationship_type,
            to_type=claim.target_type,
            to_ref=claim.target_reference_hash,
            evidence_state=claim.evidence_state,
            source_surface=claim.source_surface,
            evidence_refs=claim.evidence_refs,
            confidence=claim.confidence,
            first_seen_at=claim.first_seen_at,
            last_seen_at=claim.last_seen_at,
        )
        key = (
            relationship.from_ref,
            relationship.relationship_type,
            relationship.to_type,
            relationship.to_ref,
        )
        current = output.get(key)
        if current is None or relationship.confidence > current.confidence:
            output[key] = relationship
    return tuple(output[key] for key in sorted(output))


def _compact(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))[:500] or "none"


def _event(
    *,
    current: GovernanceAssetSnapshot,
    event_type: str,
    before: Any,
    after: Any,
) -> H5ChangeEvent:
    material = {
        "tenant_id": current.tenant_id,
        "asset_id": current.asset_id,
        "event_type": event_type,
        "before": before,
        "after": after,
        "evidence_refs": current.evidence_refs,
        "observed_at": current.observed_at.isoformat(),
    }
    digest = hashlib.sha256(
        b"hawk:hmair:h5-change:v1\x00" + canonical_json_bytes(material)
    ).hexdigest()
    return H5ChangeEvent(
        tenant_id=current.tenant_id,
        asset_id=current.asset_id,
        event_type=event_type,
        before_state=_compact(before),
        after_state=_compact(after),
        evidence_refs=current.evidence_refs,
        observed_at=current.observed_at,
        input_digest=digest,
    )


def derive_h5_change_events(
    *, previous: GovernanceAssetSnapshot | None, current: GovernanceAssetSnapshot
) -> tuple[H5ChangeEvent, ...]:
    if previous is None:
        return (_event(current=current, event_type="AI_ASSET_DISCOVERED", before="absent", after="present"),)
    if previous.tenant_id != current.tenant_id or previous.asset_id != current.asset_id:
        raise ValueError("governance snapshots must describe the same tenant asset")
    if previous.observed_at > current.observed_at:
        raise ValueError("governance snapshots are out of order")

    meaningful_before = previous.model_dump(exclude={"observed_at", "evidence_refs"})
    meaningful_after = current.model_dump(exclude={"observed_at", "evidence_refs"})
    changes: list[H5ChangeEvent] = []
    if meaningful_before != meaningful_after:
        changes.append(_event(current=current, event_type="AI_ASSET_CHANGED", before="previous_projection", after="current_projection"))
    if not previous.active and current.active:
        changes.append(_event(current=current, event_type="AI_ASSET_BECAME_ACTIVE", before=False, after=True))
    if previous.owner_reference_hash != current.owner_reference_hash:
        changes.append(_event(current=current, event_type="AI_ASSET_OWNER_CHANGED", before=previous.owner_reference_hash or "unknown", after=current.owner_reference_hash or "unknown"))
    added = sorted(set(current.capability_ids) - set(previous.capability_ids))
    if added:
        changes.append(_event(current=current, event_type="AI_CAPABILITY_ADDED", before=(), after=added))
    if current.usage_count > previous.usage_count:
        changes.append(_event(current=current, event_type="AI_USAGE_INCREASED", before=previous.usage_count, after=current.usage_count))
    if previous.identity_reference_hash != current.identity_reference_hash:
        changes.append(_event(current=current, event_type="AI_IDENTITY_CHANGED", before=previous.identity_reference_hash or "unknown", after=current.identity_reference_hash or "unknown"))
    if previous.reachability_digest != current.reachability_digest:
        changes.append(_event(current=current, event_type="AI_REACHABILITY_CHANGED", before=previous.reachability_digest, after=current.reachability_digest))
    if previous.fingerprint_digest != current.fingerprint_digest:
        changes.append(_event(current=current, event_type="AI_FINGERPRINT_DRIFT", before=previous.fingerprint_digest, after=current.fingerprint_digest))
    if previous.shadow_state != "confirmed_shadow" and current.shadow_state == "confirmed_shadow":
        changes.append(_event(current=current, event_type="SHADOW_AI_CONFIRMED", before=previous.shadow_state, after=current.shadow_state))
    rank = {"not_covered": 0, "unknown": 1, "covered": 2}
    before_coverage = dict(previous.coverage_states)
    after_coverage = dict(current.coverage_states)
    reduced = tuple(
        name for name in before_coverage
        if rank[after_coverage[name]] < rank[before_coverage[name]]
    )
    if reduced:
        changes.append(_event(current=current, event_type="CONTROL_COVERAGE_REDUCED", before={name: before_coverage[name] for name in reduced}, after={name: after_coverage[name] for name in reduced}))
    return tuple(changes)


__all__ = [
    "build_h5_usage_views",
    "classify_h5_shadow",
    "derive_h5_change_events",
    "project_accepted_claim_relationships",
    "project_h5_reachability",
    "project_h5_usage",
]
