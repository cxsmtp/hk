from __future__ import annotations

from datetime import datetime, timezone
import hashlib

from app.services.hmair.cie.catalog import CATALOG_VERSION, RULESET_VERSION
from app.services.hmair.cie.contracts import (
    CapabilityInferenceOptions,
    CapabilityInferenceResult,
    NormalizedCapabilitySignal,
)
from app.services.hmair.cie.rule_engine import CapabilityRuleEngine
from app.services.hmair.contracts import canonical_json_bytes


ENGINE_VERSION = "cie-engine-1.0.0"


class CapabilityInferenceEngine:
    """Side-effect-free inference over one explicit tenant-scoped signal bundle."""

    def __init__(self, *, rule_engine: CapabilityRuleEngine | None = None) -> None:
        self._rule_engine = rule_engine or CapabilityRuleEngine()

    def infer_signals(
        self,
        *,
        signals: tuple[NormalizedCapabilitySignal, ...],
        validated_at: datetime,
        options: CapabilityInferenceOptions | None = None,
    ) -> CapabilityInferenceResult:
        if not signals:
            raise ValueError("capability inference requires at least one signal")
        if validated_at.tzinfo is None or validated_at.utcoffset() is None:
            raise ValueError("validated_at must be timezone-aware")
        validated_at = validated_at.astimezone(timezone.utc)
        ordered = tuple(sorted(signals, key=lambda item: item.signal_id))
        tenants = {item.tenant_id for item in ordered}
        if len(tenants) != 1:
            raise ValueError("capability signals must belong to one tenant")
        observation_ids = tuple(sorted({item.observation_id for item in ordered}))
        if len(observation_ids) != len(ordered):
            raise ValueError("one normalized signal per observation is required")
        options = options or CapabilityInferenceOptions()
        if options.drift and not options.genome:
            raise ValueError("drift inference requires genome projection")

        evaluations = self._rule_engine.evaluate(
            signals=ordered, validated_at=validated_at
        )
        if evaluations:
            leading = max(
                evaluations,
                key=lambda item: (
                    item.confidence,
                    item.source_diversity,
                    item.rule_id.endswith("composition-v1"),
                    item.rule_id,
                ),
            )
            recommended_asset_type = leading.recommended_asset_type
            recommended_ecosystem = leading.recommended_ecosystem
        else:
            recommended_asset_type = "unknown_ai_candidate"
            recommended_ecosystem = "unknown"

        subject_material = {
            "tenant_id": next(iter(tenants)),
            "signals": tuple(
                {
                    "signal_id": item.signal_id,
                    "observation_id": item.observation_id,
                    "evidence_hash": item.evidence_hash,
                }
                for item in ordered
            ),
        }
        subject_reference_hash = hashlib.sha256(
            b"hawk:cie:subject:v1\x00" + canonical_json_bytes(subject_material)
        ).hexdigest()
        products = tuple(
            sorted({item.product_hint for item in ordered if item.product_hint})
        )
        product_explanations = tuple(
            f"Observed product metadata '{product}' is explanatory only and did not independently satisfy a rule."
            for product in products
        )
        limitations: list[str] = []
        if not evaluations:
            limitations.append("no_capability_rule_matched")
        if not options.genome:
            limitations.append("genome_disabled")
        if not options.marketplace:
            limitations.append("marketplace_disabled")
        if not options.dependency_graph:
            limitations.append("dependency_graph_disabled")
        if not options.drift:
            limitations.append("drift_disabled")
        return CapabilityInferenceResult(
            subject_reference_hash=subject_reference_hash,
            observation_ids=observation_ids,
            evaluations=evaluations,
            product_explanations=product_explanations,
            recommended_asset_type=recommended_asset_type,
            recommended_ecosystem=recommended_ecosystem,
            engine_version=ENGINE_VERSION,
            catalog_version=CATALOG_VERSION,
            ruleset_version=RULESET_VERSION,
            first_observed_at=min(item.timestamp for item in ordered),
            last_observed_at=max(item.timestamp for item in ordered),
            validated_at=validated_at,
            limitations=tuple(sorted(limitations)),
        )


__all__ = ["CapabilityInferenceEngine", "ENGINE_VERSION"]

