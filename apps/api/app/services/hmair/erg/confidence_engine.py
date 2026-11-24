from __future__ import annotations

from datetime import datetime, timezone
from types import MappingProxyType
from typing import Mapping

from app.services.hmair.erg.contracts import (
    EdgeConfidenceEvaluation,
    EdgeConfidenceInput,
    EvidenceDecayPolicy,
    EvidenceQualityAggregate,
    ResolutionConfidenceEvaluation,
)


CREATE_THRESHOLD = 0.90
ATTACH_THRESHOLD = 0.95
QUALITY_METHODOLOGY_ID = "erg-weighted-edge-quality"
QUALITY_METHODOLOGY_VERSION = "1.0.0"


_SIGNAL_CLASSES = (
    "observation", "capability", "identity", "provider", "model", "runtime",
    "configuration", "marketplace", "extension", "dependency", "repository",
    "project", "database", "network_destination", "process", "tool", "mcp",
    "usage", "user", "service_account", "application", "environment",
    "permission", "relationship", "ai_ecosystem",
)
DEFAULT_DECAY_POLICIES = MappingProxyType(
    {
        signal_class: EvidenceDecayPolicy(
            policy_id=f"erg-decay-{signal_class.replace('_', '-')}",
            version="1.0.0",
            signal_class=signal_class,
            fresh_days=30,
            stale_days=90,
            fresh_factor=1.0,
            stale_factor=0.65,
            expired_factor=0.25,
        )
        for signal_class in _SIGNAL_CLASSES
    }
)


class ConfidenceEngine:
    def __init__(
        self,
        *,
        decay_policies: Mapping[str, EvidenceDecayPolicy] = DEFAULT_DECAY_POLICIES,
    ) -> None:
        self._decay_policies = decay_policies

    def evaluate_edge(
        self,
        *,
        edge: EdgeConfidenceInput,
        evaluated_at: datetime,
    ) -> EdgeConfidenceEvaluation:
        if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
            raise ValueError("evaluated_at must be timezone-aware")
        evaluated_at = evaluated_at.astimezone(timezone.utc)
        if evaluated_at < edge.observed_at:
            raise ValueError("edge cannot be evaluated before it was observed")
        limitations: list[str] = []
        policy = self._decay_policies.get(edge.signal_class)
        decay_factor: float | None = None
        freshness = "unknown"
        if policy is None:
            limitations.append("decay_policy_unknown")
        else:
            age_days = (evaluated_at - edge.observed_at).total_seconds() / 86400.0
            if age_days <= policy.fresh_days:
                freshness = "fresh"
                decay_factor = policy.fresh_factor
            elif age_days <= policy.stale_days:
                freshness = "stale"
                decay_factor = policy.stale_factor
            else:
                freshness = "expired"
                decay_factor = policy.expired_factor
            declared_rank = {"fresh": 0, "unknown": 1, "stale": 2, "expired": 3}
            if declared_rank[edge.declared_freshness] > declared_rank[freshness]:
                freshness = edge.declared_freshness
                decay_factor = {
                    "fresh": policy.fresh_factor,
                    "stale": policy.stale_factor,
                    "expired": policy.expired_factor,
                    "unknown": None,
                }[freshness]
        if edge.observation_quality is None:
            limitations.append("observation_quality_unknown")
        if edge.collector_quality is None:
            limitations.append("collector_quality_unknown")
        effective_confidence: float | None = None
        edge_quality: float | None = None
        if (
            edge.observation_quality is not None
            and edge.collector_quality is not None
            and decay_factor is not None
        ):
            edge_quality = round(
                edge.observation_quality * edge.collector_quality * decay_factor,
                12,
            )
            effective_confidence = round(edge.base_confidence * edge_quality, 12)
        if freshness == "stale":
            limitations.append("stale_evidence")
        elif freshness == "expired":
            limitations.append("expired_evidence")
        if edge.validation_state in {"unknown", "stale", "contradicted"}:
            limitations.append("validation_not_current")
        if edge.contradiction_state in {"confirmed", "unresolved"}:
            limitations.append("unresolved_confirmed_contradiction")
        automatic_resolution_eligible = bool(
            effective_confidence is not None
            and freshness in {"fresh", "stale"}
            and edge.validation_state in {"verified", "partially_verified", "inferred"}
            and edge.contradiction_state not in {"confirmed", "unresolved"}
        )
        return EdgeConfidenceEvaluation(
            edge_id=edge.edge_id,
            signal_class=edge.signal_class,
            source_surface=edge.source_surface,
            collector_id=edge.collector_id,
            base_confidence=edge.base_confidence,
            observation_quality_factor=edge.observation_quality,
            collector_quality_factor=edge.collector_quality,
            decay_factor=decay_factor,
            decay_policy_id=policy.policy_id if policy else None,
            decay_policy_version=policy.version if policy else None,
            relationship_weight=edge.relationship_weight,
            effective_confidence=effective_confidence,
            edge_quality=edge_quality,
            freshness=freshness,
            validation_state=edge.validation_state,
            contradiction_state=edge.contradiction_state,
            automatic_resolution_eligible=automatic_resolution_eligible,
            evaluated_at=evaluated_at,
            limitations=tuple(sorted(set(limitations))),
        )

    @staticmethod
    def aggregate_evidence_quality(
        *, edges: tuple[EdgeConfidenceEvaluation, ...]
    ) -> EvidenceQualityAggregate:
        ordered = tuple(sorted(edges, key=lambda item: item.edge_id))
        unknown = tuple(item.edge_id for item in ordered if item.edge_quality is None)
        total_weight = round(sum(item.relationship_weight for item in ordered), 12)
        quality: float | None = None
        if ordered and not unknown and total_weight > 0.0:
            quality = round(
                sum(
                    float(item.edge_quality) * item.relationship_weight
                    for item in ordered
                )
                / total_weight,
                12,
            )
        return EvidenceQualityAggregate(
            evidence_quality=quality,
            total_weight=total_weight,
            contributor_edge_ids=tuple(item.edge_id for item in ordered),
            unknown_edge_ids=unknown,
            methodology_id=QUALITY_METHODOLOGY_ID,
            methodology_version=QUALITY_METHODOLOGY_VERSION,
        )

    def evaluate_resolution(
        self,
        *,
        edges: tuple[EdgeConfidenceEvaluation, ...],
        rule_cap: float,
        anchor_confidences: tuple[float, ...],
        anchors_satisfied: bool,
        strong_relationship: bool,
    ) -> ResolutionConfidenceEvaluation:
        if not 0.0 < rule_cap <= 1.0:
            raise ValueError("rule cap must be within (0, 1]")
        ordered = tuple(sorted(edges, key=lambda item: item.edge_id))
        sources = tuple(sorted({item.source_surface for item in ordered}))
        source_diversity = len(sources)
        source_cap = 0.0 if source_diversity == 0 else (0.70 if source_diversity == 1 else (0.90 if source_diversity == 2 else 0.98))
        quality = self.aggregate_evidence_quality(edges=ordered)
        unknown_confidence = tuple(
            item.edge_id for item in ordered if item.effective_confidence is None
        )
        total_weight = sum(item.relationship_weight for item in ordered)
        weighted_support: float | None = None
        if ordered and not unknown_confidence and total_weight > 0.0:
            weighted_support = round(
                sum(
                    float(item.effective_confidence) * item.relationship_weight
                    for item in ordered
                ) / total_weight,
                12,
            )
        anchor_floor = min(anchor_confidences) if anchor_confidences else None
        freshness_validation_cap: float | None = 0.98
        if any(item.freshness == "expired" for item in ordered):
            freshness_validation_cap = 0.25
        elif any(item.freshness == "stale" for item in ordered):
            freshness_validation_cap = 0.55
        if any(item.freshness == "unknown" for item in ordered):
            freshness_validation_cap = None
        if any(item.validation_state == "inferred" for item in ordered):
            freshness_validation_cap = min(freshness_validation_cap or 0.65, 0.65)
        if any(item.validation_state == "partially_verified" for item in ordered):
            freshness_validation_cap = min(freshness_validation_cap or 0.90, 0.90)
        if any(item.validation_state in {"unknown", "stale", "contradicted"} for item in ordered):
            freshness_validation_cap = None
        contradiction_present = any(
            item.contradiction_state in {"confirmed", "unresolved"}
            for item in ordered
        )
        contradiction_cap = 0.40 if contradiction_present else None

        limitations = {
            limitation for item in ordered for limitation in item.limitations
        }
        if not anchors_satisfied or anchor_floor is None:
            limitations.add("required_anchor_missing")
        if source_diversity < 2:
            limitations.add("insufficient_source_diversity")
        if unknown_confidence:
            limitations.add("edge_confidence_unknown")
        if quality.evidence_quality is None:
            limitations.add("evidence_quality_unknown")
        if contradiction_present:
            limitations.add("unresolved_confirmed_contradiction")

        caps = [rule_cap, source_cap]
        if weighted_support is not None:
            caps.append(weighted_support)
        if anchor_floor is not None:
            caps.append(anchor_floor)
        if freshness_validation_cap is not None:
            caps.append(freshness_validation_cap)
        if contradiction_cap is not None:
            caps.append(contradiction_cap)
        confidence = round(min(caps), 12) if weighted_support is not None else None
        automatically_eligible = bool(
            confidence is not None
            and quality.evidence_quality is not None
            and anchors_satisfied
            and anchor_floor is not None
            and source_diversity >= 2
            and not contradiction_present
            and freshness_validation_cap is not None
        )
        create_eligible = bool(
            automatically_eligible and confidence >= CREATE_THRESHOLD
        )
        attach_eligible = bool(
            automatically_eligible
            and confidence >= ATTACH_THRESHOLD
            and strong_relationship
            and all(item.freshness == "fresh" for item in ordered)
        )
        if contradiction_present or not anchors_satisfied:
            recommended_action = "manual_review"
        elif attach_eligible:
            recommended_action = "attach_observation"
        elif create_eligible:
            recommended_action = "create_ecosystem"
        elif confidence is None:
            recommended_action = "unknown"
        else:
            recommended_action = "manual_review"
        calculation = {
            "rule_cap": rule_cap,
            "anchor_confidence_floor": anchor_floor,
            "weighted_supporting_confidence": weighted_support,
            "source_diversity_cap": source_cap,
            "freshness_validation_cap": freshness_validation_cap,
            "contradiction_cap": contradiction_cap,
            "evidence_quality": quality.evidence_quality,
            "create_threshold": CREATE_THRESHOLD,
            "attach_threshold": ATTACH_THRESHOLD,
        }
        return ResolutionConfidenceEvaluation(
            confidence=confidence,
            evidence_quality=quality.evidence_quality,
            weighted_supporting_confidence=weighted_support,
            source_diversity=source_diversity,
            source_diversity_cap=source_cap,
            anchor_confidence_floor=anchor_floor,
            freshness_validation_cap=freshness_validation_cap,
            contradiction_cap=contradiction_cap,
            rule_cap=rule_cap,
            create_threshold=CREATE_THRESHOLD,
            attach_threshold=ATTACH_THRESHOLD,
            create_eligible=create_eligible,
            attach_eligible=attach_eligible,
            recommended_action=recommended_action,
            supporting_edge_ids=tuple(item.edge_id for item in ordered),
            source_surfaces=sources,
            limitations=tuple(sorted(limitations)),
            calculation=calculation,
        )


__all__ = [
    "ATTACH_THRESHOLD",
    "CREATE_THRESHOLD",
    "DEFAULT_DECAY_POLICIES",
    "ConfidenceEngine",
]

