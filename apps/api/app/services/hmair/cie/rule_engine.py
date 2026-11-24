from __future__ import annotations

from datetime import datetime, timezone
from types import MappingProxyType
from typing import Mapping

from app.services.hmair.cie.catalog import CAPABILITY_CATALOG, CAPABILITY_RULES
from app.services.hmair.cie.contracts import (
    CapabilityEvaluation,
    CapabilityRule,
    NormalizedCapabilitySignal,
)


_FRESHNESS_ORDER = MappingProxyType(
    {"fresh": 0, "unknown": 1, "stale": 2, "expired": 3}
)


class CapabilityRuleEngine:
    """Deterministic product-neutral capability evaluation.

    Confidence is intentionally capped rather than averaged. A weak or stale
    required signal cannot be hidden by several strong signals.
    """

    def __init__(
        self,
        *,
        rules: Mapping[str, CapabilityRule] = CAPABILITY_RULES,
    ) -> None:
        self._rules = rules

    def evaluate(
        self,
        *,
        signals: tuple[NormalizedCapabilitySignal, ...],
        validated_at: datetime,
    ) -> tuple[CapabilityEvaluation, ...]:
        if validated_at.tzinfo is None or validated_at.utcoffset() is None:
            raise ValueError("validated_at must be timezone-aware")
        validated_at = validated_at.astimezone(timezone.utc)
        if not signals:
            return ()
        tenants = {item.tenant_id for item in signals}
        if len(tenants) != 1:
            raise ValueError("capability signals must belong to one tenant")
        signal_ids = [item.signal_id for item in signals]
        if len(signal_ids) != len(set(signal_ids)):
            raise ValueError("capability signal IDs must be unique")
        ordered = tuple(sorted(signals, key=lambda item: item.signal_id))
        evaluations = tuple(
            evaluation
            for _rule_id, rule in sorted(self._rules.items())
            if (
                evaluation := self._evaluate_rule(
                    rule=rule,
                    signals=ordered,
                    validated_at=validated_at,
                )
            )
            is not None
        )
        return evaluations

    @staticmethod
    def _signals_for_fact(
        signals: tuple[NormalizedCapabilitySignal, ...], predicate: str
    ) -> tuple[NormalizedCapabilitySignal, ...]:
        return tuple(item for item in signals if predicate in item.facts)

    def _evaluate_rule(
        self,
        *,
        rule: CapabilityRule,
        signals: tuple[NormalizedCapabilitySignal, ...],
        validated_at: datetime,
    ) -> CapabilityEvaluation | None:
        supporting: dict[str, NormalizedCapabilitySignal] = {}
        for predicate in rule.required_all:
            matching = self._signals_for_fact(signals, predicate)
            if not matching:
                return None
            supporting.update((item.signal_id, item) for item in matching)
        for alternatives in rule.required_any:
            matching = tuple(
                item
                for item in signals
                if any(predicate in item.facts for predicate in alternatives)
            )
            if not matching:
                return None
            supporting.update((item.signal_id, item) for item in matching)
        unknown_predicates: list[str] = []
        for predicate in rule.optional:
            matching = self._signals_for_fact(signals, predicate)
            if not matching:
                unknown_predicates.append(predicate)
            else:
                supporting.update((item.signal_id, item) for item in matching)
        if not supporting:
            return None

        conflicts = tuple(
            item
            for item in signals
            if item.contradiction_state in {"contradicted", "unresolved"}
            or any(predicate in item.facts for predicate in rule.contradictions)
        )
        supporting_signals = tuple(
            supporting[item] for item in sorted(supporting)
        )
        source_diversity = len({item.source for item in supporting_signals})
        confidence_caps = [
            rule.base_confidence_cap,
            min(item.confidence for item in supporting_signals),
        ]
        limitations: list[str] = []
        if source_diversity == 1:
            confidence_caps.append(0.70)
            limitations.append("single_source_only")
        elif source_diversity == 2:
            confidence_caps.append(0.90)
            limitations.append("two_source_confidence_cap")
        if any(item.freshness == "stale" for item in supporting_signals):
            confidence_caps.append(0.55)
            limitations.append("contains_stale_evidence")
        if any(item.freshness == "expired" for item in supporting_signals):
            confidence_caps.append(0.25)
            limitations.append("contains_expired_evidence")
        if any(
            item.verification_state in {"inferred", "unknown"}
            for item in supporting_signals
        ):
            confidence_caps.append(0.65)
            limitations.append("contains_inferred_evidence")
        if conflicts:
            confidence_caps.append(0.40)
            limitations.append("contains_contradiction")
        confidence = round(min(confidence_caps), 6)
        freshness = max(
            (item.freshness for item in supporting_signals),
            key=_FRESHNESS_ORDER.__getitem__,
        )
        if conflicts:
            verification_state = "contradicted"
        elif any(
            item.verification_state in {"inferred", "unknown"}
            or item.freshness == "expired"
            for item in supporting_signals
        ):
            verification_state = "inferred"
        elif all(
            item.verification_state == "verified" for item in supporting_signals
        ) and confidence >= 0.90:
            verification_state = "verified"
        else:
            verification_state = "partially_verified"

        definition = CAPABILITY_CATALOG[rule.capability_id]
        explanation = (
            f"{rule.explanation} Matched {len(supporting_signals)} signal(s) "
            f"from {source_diversity} source type(s); confidence is the lowest "
            "support value or applicable conservative cap."
        )
        return CapabilityEvaluation(
            capability_id=rule.capability_id,
            family=definition.family,
            rule_id=rule.rule_id,
            rule_version=rule.version,
            calibration_version=rule.calibration_version,
            confidence=confidence,
            supporting_signal_ids=tuple(item.signal_id for item in supporting_signals),
            conflicting_signal_ids=tuple(item.signal_id for item in conflicts),
            unknown_predicates=tuple(sorted(unknown_predicates)),
            source_diversity=source_diversity,
            freshness=freshness,
            verification_state=verification_state,
            last_validated_at=validated_at,
            explanation=explanation,
            limitations=tuple(sorted(set(limitations))),
            recommended_asset_type=rule.recommended_asset_type,
            recommended_ecosystem=rule.recommended_ecosystem,
        )


__all__ = ["CapabilityRuleEngine"]
