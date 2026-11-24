from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.evidence_resolution import (
    DiscoveryCollectorQualitySnapshot,
    DiscoveryObservationQualitySnapshot,
)
from app.services.hmair.cie.contracts import (
    CapabilityGraphProjection,
    CapabilityInferenceResult,
    NormalizedCapabilitySignal,
)
from app.services.hmair.resolution_graph_service import (
    create_graph_edge,
    create_graph_node,
)


def _reference_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="strict")).hexdigest()


class CapabilityGraphService:
    """Project CIE evidence into Hawk's existing resolution graph authority."""

    def project(
        self,
        db: Session,
        *,
        tenant_id: str,
        evidence_node_id: str,
        result: CapabilityInferenceResult,
        signals: tuple[NormalizedCapabilitySignal, ...],
    ) -> CapabilityGraphProjection:
        if not signals:
            return CapabilityGraphProjection.empty()
        ordered = tuple(sorted(signals, key=lambda item: item.signal_id))
        if {item.tenant_id for item in ordered} != {tenant_id}:
            raise ValueError("capability graph signals must belong to one tenant")
        if tuple(sorted(item.observation_id for item in ordered)) != result.observation_ids:
            raise ValueError("capability graph signals do not match the inference bundle")

        signal_by_id = {item.signal_id: item for item in ordered}
        node_ids: set[str] = set()
        edge_ids: set[str] = set()
        dependency_refs: set[str] = set()
        observation_nodes: dict[str, str] = {}
        capability_nodes: dict[str, str] = {}
        quality_by_observation = self._quality_factors(
            db,
            tenant_id=tenant_id,
            signals=ordered,
        )

        for signal in ordered:
            node = create_graph_node(
                db,
                tenant_id=tenant_id,
                node_class="observation",
                subject_reference=f"observation:{_reference_hash(signal.observation_id)}",
                idempotency_key=f"cie-observation-{signal.signal_id}",
            )
            observation_nodes[signal.signal_id] = node.graph_node_id
            node_ids.add(node.graph_node_id)

        for evaluation in result.evaluations:
            capability_node = capability_nodes.get(evaluation.capability_id)
            if capability_node is None:
                node = create_graph_node(
                    db,
                    tenant_id=tenant_id,
                    node_class="capability",
                    subject_reference=f"capability:{evaluation.capability_id}",
                    idempotency_key=f"cie-capability-{evaluation.capability_id}",
                )
                capability_node = node.graph_node_id
                capability_nodes[evaluation.capability_id] = capability_node
                node_ids.add(capability_node)
            for signal_id in evaluation.supporting_signal_ids:
                signal = signal_by_id.get(signal_id)
                if signal is None:
                    raise ValueError("capability evaluation references an unknown signal")
                edge = create_graph_edge(
                    db,
                    tenant_id=tenant_id,
                    from_node_id=observation_nodes[signal_id],
                    to_node_id=capability_node,
                    edge_type="supports",
                    evidence_node_id=evidence_node_id,
                    confidence=float(evaluation.confidence),
                    verification_state=(
                        evaluation.verification_state
                        if evaluation.verification_state
                        in {"verified", "partially_verified", "inferred", "unknown"}
                        else "inferred"
                    ),
                    freshness=evaluation.freshness,
                    contradiction_state="none",
                    first_observed_at=signal.timestamp,
                    last_observed_at=evaluation.last_validated_at,
                    collector_id=signal.collector_id,
                    source_surface=signal.source,
                    signal_class="capability",
                    observation_quality=quality_by_observation.get(
                        signal.observation_id, (None, None)
                    )[0],
                    collector_quality=quality_by_observation.get(
                        signal.observation_id, (None, None)
                    )[1],
                    idempotency_key=(
                        f"cie-v2-support-{signal_id}-{evaluation.rule_id}"
                    )[:128],
                )
                edge_ids.add(edge.edge_id)
                for hint in signal.relationship_hints:
                    relationship = str(
                        hint.get("relationship") or hint.get("type") or ""
                    ).strip().casefold()
                    target = hint.get("target_reference") or hint.get("target")
                    if relationship not in {"depends_on", "dependency"} or not isinstance(target, str) or not target.strip():
                        continue
                    reference = _reference_hash(target.strip())
                    dependency = create_graph_node(
                        db,
                        tenant_id=tenant_id,
                        node_class="dependency",
                        subject_reference=f"dependency:{reference}",
                        idempotency_key=f"cie-dependency-{reference}",
                    )
                    dependency_edge = create_graph_edge(
                        db,
                        tenant_id=tenant_id,
                        from_node_id=capability_node,
                        to_node_id=dependency.graph_node_id,
                        edge_type="depends_on",
                        evidence_node_id=evidence_node_id,
                        confidence=float(min(evaluation.confidence, signal.confidence)),
                        verification_state="inferred",
                        freshness=signal.freshness,
                        contradiction_state="none",
                        first_observed_at=signal.timestamp,
                        last_observed_at=evaluation.last_validated_at,
                        collector_id=signal.collector_id,
                        source_surface=signal.source,
                        signal_class="dependency",
                        observation_quality=quality_by_observation.get(
                            signal.observation_id, (None, None)
                        )[0],
                        collector_quality=quality_by_observation.get(
                            signal.observation_id, (None, None)
                        )[1],
                        idempotency_key=(
                            f"cie-v2-dep-{evaluation.capability_id}-{reference}"
                        )[:128],
                    )
                    node_ids.add(dependency.graph_node_id)
                    edge_ids.add(dependency_edge.edge_id)
                    dependency_refs.add(reference)
            for signal_id in evaluation.conflicting_signal_ids:
                signal = signal_by_id.get(signal_id)
                if signal is None:
                    raise ValueError("capability contradiction references an unknown signal")
                edge = create_graph_edge(
                    db,
                    tenant_id=tenant_id,
                    from_node_id=observation_nodes[signal_id],
                    to_node_id=capability_node,
                    edge_type="contradicts",
                    evidence_node_id=evidence_node_id,
                    confidence=float(evaluation.confidence),
                    verification_state="inferred",
                    freshness=signal.freshness,
                    contradiction_state="confirmed",
                    first_observed_at=signal.timestamp,
                    last_observed_at=evaluation.last_validated_at,
                    collector_id=signal.collector_id,
                    source_surface=signal.source,
                    signal_class="capability",
                    observation_quality=quality_by_observation.get(
                        signal.observation_id, (None, None)
                    )[0],
                    collector_quality=quality_by_observation.get(
                        signal.observation_id, (None, None)
                    )[1],
                    idempotency_key=(
                        f"cie-v2-conflict-{signal_id}-{evaluation.rule_id}"
                    )[:128],
                )
                edge_ids.add(edge.edge_id)

        limitations = () if dependency_refs else ("no_explicit_dependency_evidence",)
        return CapabilityGraphProjection(
            node_ids=tuple(sorted(node_ids)),
            edge_ids=tuple(sorted(edge_ids)),
            dependency_refs=tuple(sorted(dependency_refs)),
            limitations=limitations,
        )

    @staticmethod
    def _quality_factors(
        db: Session,
        *,
        tenant_id: str,
        signals: tuple[NormalizedCapabilitySignal, ...],
    ) -> dict[str, tuple[float | None, float | None]]:
        observation_ids = tuple(sorted({item.observation_id for item in signals}))
        if not observation_ids:
            return {}
        rows = tuple(
            db.scalars(
                select(DiscoveryObservationQualitySnapshot)
                .where(
                    DiscoveryObservationQualitySnapshot.tenant_id == tenant_id,
                    DiscoveryObservationQualitySnapshot.observation_id.in_(observation_ids),
                )
                .order_by(
                    DiscoveryObservationQualitySnapshot.observation_id,
                    DiscoveryObservationQualitySnapshot.calculated_at.desc(),
                    DiscoveryObservationQualitySnapshot.snapshot_id.desc(),
                )
            )
        )
        latest: dict[str, DiscoveryObservationQualitySnapshot] = {}
        for row in rows:
            latest.setdefault(row.observation_id, row)
        collector_ids = tuple(
            sorted({row.collector_quality_snapshot_id for row in latest.values()})
        )
        collectors = {
            row.snapshot_id: row
            for row in db.scalars(
                select(DiscoveryCollectorQualitySnapshot).where(
                    DiscoveryCollectorQualitySnapshot.tenant_id == tenant_id,
                    DiscoveryCollectorQualitySnapshot.snapshot_id.in_(collector_ids),
                )
            )
        } if collector_ids else {}
        signal_collectors = {item.observation_id: item.collector_id for item in signals}
        output: dict[str, tuple[float | None, float | None]] = {}
        for observation_id, row in latest.items():
            collector = collectors.get(row.collector_quality_snapshot_id)
            if (
                row.quality is None
                or collector is None
                or collector.quality is None
                or collector.collector_id != signal_collectors.get(observation_id)
            ):
                output[observation_id] = (None, None)
                continue
            factors = row.quality_factors_json.get("factors")
            if not isinstance(factors, dict):
                output[observation_id] = (None, None)
                continue
            values = [
                float(value)
                for key, value in factors.items()
                if key != "collector_quality" and isinstance(value, (int, float))
            ]
            if not values or any(not 0.0 <= value <= 1.0 for value in values):
                output[observation_id] = (None, None)
                continue
            output[observation_id] = (min(values), float(collector.quality))
        return output


__all__ = ["CapabilityGraphService"]
