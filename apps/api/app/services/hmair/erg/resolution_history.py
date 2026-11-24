from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from uuid import NAMESPACE_URL, uuid5

from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.audit import AuditLog
from app.db.models.discovery_resolution import DiscoveryResolutionGraphNode
from app.db.models.evidence import EvidenceNode
from app.db.models.evidence_resolution import (
    DiscoveryAIEcosystem,
    DiscoveryEcosystemHistoryMember,
    DiscoveryEcosystemMembership,
    DiscoveryEcosystemResolutionEvent,
)
from app.services.hmair.contracts import StrictContract, canonical_json_bytes
from app.services.hmair.erg.confidence_engine import ATTACH_THRESHOLD


RESOLUTION_METHODOLOGY_ID = "erg-reversible-resolution-history"
RESOLUTION_METHODOLOGY_VERSION = "1.0.0"
MUTATING_ROLES = frozenset({"owner", "admin"})


class ResolutionConflict(RuntimeError):
    """Resolution history or current membership preconditions are invalid."""


class ResolutionAuthorizationError(RuntimeError):
    """The actor is not authorized to mutate ecosystem resolution."""


class ResolutionMutation(StrictContract):
    event_id: str
    action: str
    ecosystem_ids: tuple[str, ...] = Field(max_length=128)
    before_memberships: tuple[dict, ...] = Field(max_length=10000)
    after_memberships: tuple[dict, ...] = Field(max_length=10000)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ResolutionConflict("resolution timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _stored_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _digest(domain: str, material: dict[str, object]) -> str:
    return hashlib.sha256(domain.encode("ascii") + canonical_json_bytes(material)).hexdigest()


def _uuid(domain: str, tenant_id: str, key: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"hawk:{domain}:v1:{tenant_id}:{key}"))


class ResolutionHistory:
    """Append-only, reversible ecosystem membership history."""

    def create_ecosystem(
        self,
        db: Session,
        *,
        tenant_id: str,
        canonical_name: str,
        ecosystem_class: str,
        graph_node_ids: tuple[str, ...],
        evidence_node_id: str,
        confidence: float | None,
        evidence_quality: float | None,
        operator_id: str,
        operator_role: str,
        reason: str,
        occurred_at: datetime,
        idempotency_key: str,
    ) -> ResolutionMutation:
        self._authorize_create(
            operator_role, confidence=confidence, evidence_quality=evidence_quality
        )
        occurred_at = self._idempotent_event_time(
            db, tenant_id, idempotency_key, _utc(occurred_at)
        )
        nodes = self._nodes(db, tenant_id, graph_node_ids)
        self._evidence(db, tenant_id, evidence_node_id)
        ecosystem_id = _uuid("erg-ecosystem", tenant_id, idempotency_key)
        material = {
            "action": "create",
            "tenant_id": tenant_id,
            "ecosystem_id": ecosystem_id,
            "canonical_name": canonical_name,
            "ecosystem_class": ecosystem_class,
            "graph_node_ids": sorted(graph_node_ids),
            "evidence_node_id": evidence_node_id,
            "confidence": confidence,
            "evidence_quality": evidence_quality,
            "operator_id": operator_id,
            "operator_role": operator_role,
            "reason": reason,
            "occurred_at": occurred_at.isoformat(),
        }
        replay = self._replay(db, tenant_id, idempotency_key, material)
        if replay is not None:
            return replay
        record = self._append_ecosystem(
            db,
            tenant_id=tenant_id,
            ecosystem_id=ecosystem_id,
            predecessor=None,
            canonical_name=canonical_name,
            ecosystem_class=ecosystem_class,
            lifecycle_state="active",
            resolution_state="resolved" if confidence is not None else "manual_review",
            confidence=confidence,
            evidence_quality=evidence_quality,
            observed_at=occurred_at,
            contradictions=0,
            limitations=(),
            idempotency_key=f"{idempotency_key}:record",
        )
        after = tuple(
            self._append_membership(
                db,
                tenant_id=tenant_id,
                record=record,
                node=node,
                evidence_node_id=evidence_node_id,
                confidence=float(confidence or 0.0),
                verification_state="verified" if confidence is not None else "unknown",
                occurred_at=occurred_at,
                state="active",
            )
            for node in nodes
        )
        return self._record_event(
            db,
            tenant_id=tenant_id,
            action="create",
            source_ids=(),
            result_ids=(ecosystem_id,),
            before=(),
            after=after,
            evidence_node_id=evidence_node_id,
            reason=reason,
            confidence=confidence,
            operator_id=operator_id,
            operator_role=operator_role,
            occurred_at=occurred_at,
            idempotency_key=idempotency_key,
            material=material,
        )

    def attach_observation(
        self,
        db: Session,
        *,
        tenant_id: str,
        ecosystem_id: str,
        graph_node_id: str,
        evidence_node_id: str,
        confidence: float,
        evidence_quality: float | None,
        operator_id: str,
        operator_role: str,
        reason: str,
        occurred_at: datetime,
        idempotency_key: str,
    ) -> ResolutionMutation:
        """Append one proven graph observation to an existing ecosystem.

        System attachment is deliberately stricter than ecosystem creation. An
        operator may correct resolution manually, while the resolver must cross
        the explicit attach threshold and provide measurable evidence quality.
        """
        self._authorize_attach(
            operator_role,
            confidence=confidence,
            evidence_quality=evidence_quality,
        )
        occurred_at = self._idempotent_event_time(
            db, tenant_id, idempotency_key, _utc(occurred_at)
        )
        material = {
            "action": "attach",
            "tenant_id": tenant_id,
            "ecosystem_id": ecosystem_id,
            "graph_node_id": graph_node_id,
            "evidence_node_id": evidence_node_id,
            "confidence": confidence,
            "evidence_quality": evidence_quality,
            "operator_id": operator_id,
            "operator_role": operator_role,
            "reason": reason,
            "occurred_at": occurred_at.isoformat(),
        }
        replay = self._replay(db, tenant_id, idempotency_key, material)
        if replay is not None:
            return replay
        self._evidence(db, tenant_id, evidence_node_id)
        node = self._nodes(db, tenant_id, (graph_node_id,))[0]
        predecessor = self._latest_record(db, tenant_id, ecosystem_id)
        if predecessor.lifecycle_state != "active":
            raise ResolutionConflict("target ecosystem is not active")
        before = self._snapshot_current(db, tenant_id, (ecosystem_id,))
        if graph_node_id in {item["graph_node_id"] for item in before}:
            raise ResolutionConflict("observation is already attached to this ecosystem")
        updated_confidence = min(
            value for value in (predecessor.confidence, confidence) if value is not None
        )
        quality_values = tuple(
            value
            for value in (predecessor.evidence_quality, evidence_quality)
            if value is not None
        )
        updated_quality = min(quality_values) if quality_values else None
        record = self._append_ecosystem(
            db,
            tenant_id=tenant_id,
            ecosystem_id=ecosystem_id,
            predecessor=predecessor,
            canonical_name=predecessor.canonical_name,
            ecosystem_class=predecessor.ecosystem_class,
            lifecycle_state="active",
            resolution_state="resolved",
            confidence=updated_confidence,
            evidence_quality=updated_quality,
            observed_at=occurred_at,
            contradictions=predecessor.outstanding_contradictions,
            limitations=tuple(predecessor.limitations_json),
            idempotency_key=f"{idempotency_key}:record",
        )
        attached = self._append_membership(
            db,
            tenant_id=tenant_id,
            record=record,
            node=node,
            evidence_node_id=evidence_node_id,
            confidence=confidence,
            verification_state="verified" if evidence_quality is not None else "unknown",
            occurred_at=occurred_at,
            state="active",
        )
        after = tuple((*before, attached))
        return self._record_event(
            db,
            tenant_id=tenant_id,
            action="attach",
            source_ids=(ecosystem_id,),
            result_ids=(ecosystem_id,),
            before=before,
            after=after,
            evidence_node_id=evidence_node_id,
            reason=reason,
            confidence=confidence,
            operator_id=operator_id,
            operator_role=operator_role,
            occurred_at=occurred_at,
            idempotency_key=idempotency_key,
            material=material,
        )

    def record_disposition(
        self,
        db: Session,
        *,
        tenant_id: str,
        action: str,
        subject_reference: str,
        evidence_node_id: str,
        confidence: float | None,
        operator_id: str,
        operator_role: str,
        reason: str,
        occurred_at: datetime,
        idempotency_key: str,
    ) -> ResolutionMutation:
        """Record a non-merging outcome without manufacturing an ecosystem."""
        if action not in {"reject", "manual_review", "unknown"}:
            raise ResolutionConflict("resolution disposition is invalid")
        if not subject_reference or len(subject_reference) > 255:
            raise ResolutionConflict("resolution disposition subject is invalid")
        if operator_role not in MUTATING_ROLES and not (
            operator_role == "system" and action in {"manual_review", "unknown"}
        ):
            raise ResolutionAuthorizationError(
                "resolution disposition requires owner/admin review"
            )
        occurred_at = self._idempotent_event_time(
            db, tenant_id, idempotency_key, _utc(occurred_at)
        )
        self._evidence(db, tenant_id, evidence_node_id)
        material = {
            "action": action,
            "tenant_id": tenant_id,
            "subject_reference": subject_reference,
            "evidence_node_id": evidence_node_id,
            "confidence": confidence,
            "operator_id": operator_id,
            "operator_role": operator_role,
            "reason": reason,
            "occurred_at": occurred_at.isoformat(),
        }
        replay = self._replay(db, tenant_id, idempotency_key, material)
        if replay is not None:
            return replay
        return self._record_event(
            db,
            tenant_id=tenant_id,
            action=action,
            source_ids=(),
            result_ids=(),
            before=(),
            after=(),
            subject_reference=subject_reference,
            evidence_node_id=evidence_node_id,
            reason=reason,
            confidence=confidence,
            operator_id=operator_id,
            operator_role=operator_role,
            occurred_at=occurred_at,
            idempotency_key=idempotency_key,
            material=material,
        )

    def merge(
        self,
        db: Session,
        *,
        tenant_id: str,
        source_ecosystem_ids: tuple[str, ...],
        canonical_name: str,
        ecosystem_class: str,
        evidence_node_id: str,
        operator_id: str,
        operator_role: str,
        reason: str,
        occurred_at: datetime,
        idempotency_key: str,
    ) -> ResolutionMutation:
        self._authorize(operator_role)
        if len(set(source_ecosystem_ids)) < 2:
            raise ResolutionConflict("merge requires at least two unique ecosystems")
        occurred_at = self._idempotent_event_time(
            db, tenant_id, idempotency_key, _utc(occurred_at)
        )
        self._evidence(db, tenant_id, evidence_node_id)
        result_id = _uuid("erg-ecosystem-merge", tenant_id, idempotency_key)
        existing = self._event_by_idempotency(db, tenant_id, idempotency_key)
        if existing is not None:
            replay_material = {
                "action": "merge", "tenant_id": tenant_id,
                "source_ecosystem_ids": sorted(source_ecosystem_ids),
                "result_ecosystem_id": result_id,
                "before": list(existing.before_memberships_json),
                "canonical_name": canonical_name, "ecosystem_class": ecosystem_class,
                "evidence_node_id": evidence_node_id, "operator_id": operator_id,
                "operator_role": operator_role, "reason": reason,
                "occurred_at": occurred_at.isoformat(),
            }
            replay = self._replay(db, tenant_id, idempotency_key, replay_material)
            assert replay is not None
            return replay
        before = self._snapshot_current(db, tenant_id, source_ecosystem_ids)
        if {item["ecosystem_id"] for item in before} != set(source_ecosystem_ids):
            raise ResolutionConflict("every source ecosystem must have current membership")
        material = {
            "action": "merge", "tenant_id": tenant_id,
            "source_ecosystem_ids": sorted(source_ecosystem_ids),
            "result_ecosystem_id": result_id, "before": list(before),
            "canonical_name": canonical_name, "ecosystem_class": ecosystem_class,
            "evidence_node_id": evidence_node_id, "operator_id": operator_id,
            "operator_role": operator_role, "reason": reason,
            "occurred_at": occurred_at.isoformat(),
        }
        for ecosystem_id in source_ecosystem_ids:
            self._append_terminal_version(db, tenant_id, ecosystem_id, "superseded", occurred_at, idempotency_key)
        self._historical_memberships(db, tenant_id, before, evidence_node_id, occurred_at)
        confidence = min(float(item["confidence"]) for item in before)
        record = self._append_ecosystem(
            db, tenant_id=tenant_id, ecosystem_id=result_id, predecessor=None,
            canonical_name=canonical_name, ecosystem_class=ecosystem_class,
            lifecycle_state="active", resolution_state="resolved",
            confidence=confidence, evidence_quality=confidence,
            observed_at=occurred_at, contradictions=0, limitations=(),
            idempotency_key=f"{idempotency_key}:result",
        )
        node_map = {node.graph_node_id: node for node in self._nodes(
            db, tenant_id, tuple(sorted({item["graph_node_id"] for item in before}))
        )}
        merged_memberships: dict[str, dict] = {}
        verification_rank = {
            "unknown": 0,
            "inferred": 1,
            "partially_verified": 2,
            "verified": 3,
        }
        for item in before:
            node_id = str(item["graph_node_id"])
            previous = merged_memberships.get(node_id)
            if previous is None:
                merged_memberships[node_id] = dict(item)
                continue
            previous["confidence"] = min(
                float(previous["confidence"]), float(item["confidence"])
            )
            if verification_rank.get(str(item["verification_state"]), 0) < verification_rank.get(
                str(previous["verification_state"]), 0
            ):
                previous["verification_state"] = item["verification_state"]
        after = tuple(
            self._append_membership(
                db, tenant_id=tenant_id, record=record,
                node=node_map[item["graph_node_id"]], evidence_node_id=evidence_node_id,
                confidence=float(item["confidence"]),
                verification_state=str(item["verification_state"]),
                occurred_at=occurred_at, state="active",
            )
            for item in (
                merged_memberships[node_id] for node_id in sorted(merged_memberships)
            )
        )
        return self._record_event(
            db, tenant_id=tenant_id, action="merge", source_ids=source_ecosystem_ids,
            result_ids=(result_id,), before=before, after=after,
            evidence_node_id=evidence_node_id, reason=reason, confidence=confidence,
            operator_id=operator_id, operator_role=operator_role,
            occurred_at=occurred_at, idempotency_key=idempotency_key, material=material,
        )

    def split(
        self,
        db: Session,
        *,
        tenant_id: str,
        source_ecosystem_id: str,
        groups: tuple[tuple[str, ...], ...],
        canonical_names: tuple[str, ...],
        ecosystem_classes: tuple[str, ...],
        evidence_node_id: str,
        operator_id: str,
        operator_role: str,
        reason: str,
        occurred_at: datetime,
        idempotency_key: str,
    ) -> ResolutionMutation:
        self._authorize(operator_role)
        if len(groups) < 2 or len(groups) != len(canonical_names) or len(groups) != len(ecosystem_classes):
            raise ResolutionConflict("split groups and labels must align")
        flattened = tuple(node for group in groups for node in group)
        if len(flattened) != len(set(flattened)):
            raise ResolutionConflict("split groups must be disjoint")
        occurred_at = self._idempotent_event_time(
            db, tenant_id, idempotency_key, _utc(occurred_at)
        )
        self._evidence(db, tenant_id, evidence_node_id)
        result_ids = tuple(
            _uuid("erg-ecosystem-split", tenant_id, f"{idempotency_key}:{index}")
            for index in range(len(groups))
        )
        material = {
            "action": "split", "tenant_id": tenant_id,
            "source_ecosystem_id": source_ecosystem_id,
            "groups": [list(group) for group in groups], "result_ids": list(result_ids),
            "canonical_names": list(canonical_names), "ecosystem_classes": list(ecosystem_classes),
            "evidence_node_id": evidence_node_id, "operator_id": operator_id,
            "operator_role": operator_role, "reason": reason,
            "occurred_at": occurred_at.isoformat(),
        }
        replay = self._replay(db, tenant_id, idempotency_key, material)
        if replay is not None:
            return replay
        before = self._snapshot_current(db, tenant_id, (source_ecosystem_id,))
        if set(flattened) != {item["graph_node_id"] for item in before}:
            raise ResolutionConflict("split must exactly partition current membership")
        self._append_terminal_version(db, tenant_id, source_ecosystem_id, "split", occurred_at, idempotency_key)
        self._historical_memberships(db, tenant_id, before, evidence_node_id, occurred_at)
        snapshot_by_node = {item["graph_node_id"]: item for item in before}
        node_map = {node.graph_node_id: node for node in self._nodes(db, tenant_id, flattened)}
        after_rows: list[dict] = []
        for index, group in enumerate(groups):
            confidence = min(float(snapshot_by_node[node]["confidence"]) for node in group)
            record = self._append_ecosystem(
                db, tenant_id=tenant_id, ecosystem_id=result_ids[index], predecessor=None,
                canonical_name=canonical_names[index], ecosystem_class=ecosystem_classes[index],
                lifecycle_state="active", resolution_state="resolved", confidence=confidence,
                evidence_quality=confidence, observed_at=occurred_at, contradictions=0,
                limitations=(), idempotency_key=f"{idempotency_key}:result:{index}",
            )
            after_rows.extend(
                self._append_membership(
                    db, tenant_id=tenant_id, record=record, node=node_map[node_id],
                    evidence_node_id=evidence_node_id,
                    confidence=float(snapshot_by_node[node_id]["confidence"]),
                    verification_state=str(snapshot_by_node[node_id]["verification_state"]),
                    occurred_at=occurred_at, state="active",
                )
                for node_id in group
            )
        return self._record_event(
            db, tenant_id=tenant_id, action="split", source_ids=(source_ecosystem_id,),
            result_ids=result_ids, before=before, after=tuple(after_rows),
            evidence_node_id=evidence_node_id, reason=reason,
            confidence=min(float(item["confidence"]) for item in before),
            operator_id=operator_id, operator_role=operator_role, occurred_at=occurred_at,
            idempotency_key=idempotency_key, material=material,
        )

    def reverse(
        self,
        db: Session,
        *,
        tenant_id: str,
        resolution_event_id: str,
        evidence_node_id: str,
        operator_id: str,
        operator_role: str,
        reason: str,
        occurred_at: datetime,
        idempotency_key: str,
    ) -> ResolutionMutation:
        self._authorize(operator_role)
        occurred_at = self._idempotent_event_time(
            db, tenant_id, idempotency_key, _utc(occurred_at)
        )
        target = db.scalar(select(DiscoveryEcosystemResolutionEvent).where(
            DiscoveryEcosystemResolutionEvent.tenant_id == tenant_id,
            DiscoveryEcosystemResolutionEvent.resolution_event_id == resolution_event_id,
        ))
        if target is None or target.action not in {"merge", "split"}:
            raise ResolutionConflict("only merge or split events can be reversed")
        self._evidence(db, tenant_id, evidence_node_id)
        before = tuple(dict(item) for item in target.after_memberships_json)
        restored = tuple(dict(item) for item in target.before_memberships_json)
        material = {
            "action": "reversal", "tenant_id": tenant_id,
            "resolution_event_id": resolution_event_id, "before": list(before),
            "after": list(restored), "evidence_node_id": evidence_node_id,
            "operator_id": operator_id, "operator_role": operator_role,
            "reason": reason, "occurred_at": occurred_at.isoformat(),
        }
        replay = self._replay(db, tenant_id, idempotency_key, material)
        if replay is not None:
            return replay
        already = db.scalar(select(DiscoveryEcosystemResolutionEvent).where(
            DiscoveryEcosystemResolutionEvent.tenant_id == tenant_id,
            DiscoveryEcosystemResolutionEvent.reverses_event_id == resolution_event_id,
        ))
        if already is not None:
            raise ResolutionConflict("resolution event was already reversed")
        current = self._snapshot_current(
            db, tenant_id, tuple(target.result_ecosystem_ids_json)
        )
        if self._canonical_memberships(current) != self._canonical_memberships(before):
            raise ResolutionConflict(
                "resolution result changed after the target event; reversal requires manual review"
            )
        for ecosystem_id in target.result_ecosystem_ids_json:
            self._append_terminal_version(db, tenant_id, ecosystem_id, "superseded", occurred_at, idempotency_key)
        self._historical_memberships(db, tenant_id, before, evidence_node_id, occurred_at)
        node_map = {node.graph_node_id: node for node in self._nodes(
            db, tenant_id, tuple(sorted({item["graph_node_id"] for item in restored}))
        )}
        after_rows: list[dict] = []
        for ecosystem_id in target.source_ecosystem_ids_json:
            source = self._latest_record(db, tenant_id, ecosystem_id)
            active = self._append_ecosystem(
                db, tenant_id=tenant_id, ecosystem_id=ecosystem_id, predecessor=source,
                canonical_name=source.canonical_name, ecosystem_class=source.ecosystem_class,
                lifecycle_state="active", resolution_state="reversed",
                confidence=source.confidence, evidence_quality=source.evidence_quality,
                observed_at=occurred_at, contradictions=source.outstanding_contradictions,
                limitations=tuple(source.limitations_json),
                idempotency_key=f"{idempotency_key}:restore:{ecosystem_id}",
            )
            for item in restored:
                if item["ecosystem_id"] != ecosystem_id:
                    continue
                after_rows.append(self._append_membership(
                    db, tenant_id=tenant_id, record=active,
                    node=node_map[item["graph_node_id"]], evidence_node_id=evidence_node_id,
                    confidence=float(item["confidence"]),
                    verification_state=str(item["verification_state"]),
                    occurred_at=occurred_at, state="active",
                ))
        return self._record_event(
            db, tenant_id=tenant_id, action="reversal",
            source_ids=tuple(target.result_ecosystem_ids_json),
            result_ids=tuple(target.source_ecosystem_ids_json), before=before,
            after=tuple(after_rows), evidence_node_id=evidence_node_id, reason=reason,
            confidence=target.confidence, operator_id=operator_id,
            operator_role=operator_role, occurred_at=occurred_at,
            idempotency_key=idempotency_key, material=material,
            reverses_event_id=resolution_event_id,
        )

    @staticmethod
    def _authorize(role: str) -> None:
        if role not in MUTATING_ROLES:
            raise ResolutionAuthorizationError("ecosystem resolution requires owner or admin")

    @staticmethod
    def _authorize_create(
        role: str, *, confidence: float | None, evidence_quality: float | None
    ) -> None:
        if role in MUTATING_ROLES:
            return
        if role != "system" or confidence is None or evidence_quality is None or confidence < 0.90:
            raise ResolutionAuthorizationError(
                "automatic ecosystem creation requires evidence-backed system resolution"
            )

    @staticmethod
    def _authorize_attach(
        role: str, *, confidence: float, evidence_quality: float | None
    ) -> None:
        if role in MUTATING_ROLES:
            return
        if (
            role != "system"
            or confidence < ATTACH_THRESHOLD
            or evidence_quality is None
        ):
            raise ResolutionAuthorizationError(
                "automatic observation attachment requires evidence-backed system resolution"
            )

    @staticmethod
    def _evidence(db: Session, tenant_id: str, evidence_node_id: str) -> None:
        if db.scalar(select(EvidenceNode).where(
            EvidenceNode.tenant_id == tenant_id, EvidenceNode.id == evidence_node_id
        )) is None:
            raise ResolutionConflict("resolution evidence is outside tenant scope")

    @staticmethod
    def _nodes(db: Session, tenant_id: str, graph_node_ids: tuple[str, ...]) -> tuple[DiscoveryResolutionGraphNode, ...]:
        if not graph_node_ids or len(set(graph_node_ids)) != len(graph_node_ids):
            raise ResolutionConflict("resolution nodes must be a non-empty unique set")
        rows = tuple(db.scalars(select(DiscoveryResolutionGraphNode).where(
            DiscoveryResolutionGraphNode.tenant_id == tenant_id,
            DiscoveryResolutionGraphNode.graph_node_id.in_(graph_node_ids),
        )))
        if len(rows) != len(graph_node_ids):
            raise ResolutionConflict("resolution nodes are outside tenant scope")
        by_id = {item.graph_node_id: item for item in rows}
        return tuple(by_id[item] for item in graph_node_ids)

    @staticmethod
    def _latest_record(db: Session, tenant_id: str, ecosystem_id: str) -> DiscoveryAIEcosystem:
        row = db.scalar(select(DiscoveryAIEcosystem).where(
            DiscoveryAIEcosystem.tenant_id == tenant_id,
            DiscoveryAIEcosystem.ecosystem_id == ecosystem_id,
        ).order_by(DiscoveryAIEcosystem.resolution_version.desc()).limit(1))
        if row is None:
            raise ResolutionConflict("ecosystem is outside tenant scope")
        return row

    def _append_ecosystem(
        self, db: Session, *, tenant_id: str, ecosystem_id: str,
        predecessor: DiscoveryAIEcosystem | None, canonical_name: str,
        ecosystem_class: str, lifecycle_state: str, resolution_state: str,
        confidence: float | None, evidence_quality: float | None,
        observed_at: datetime, contradictions: int, limitations: tuple[str, ...],
        idempotency_key: str,
    ) -> DiscoveryAIEcosystem:
        version = predecessor.resolution_version + 1 if predecessor else 1
        material = {
            "ecosystem_id": ecosystem_id, "version": version,
            "predecessor": predecessor.ecosystem_record_id if predecessor else None,
            "canonical_name": canonical_name, "class": ecosystem_class,
            "lifecycle": lifecycle_state, "resolution": resolution_state,
            "confidence": confidence, "quality": evidence_quality,
            "observed_at": observed_at.isoformat(), "contradictions": contradictions,
        }
        digest = _digest("hawk:erg:ecosystem-record:v1", material)
        row = DiscoveryAIEcosystem(
            ecosystem_record_id=_uuid("erg-ecosystem-record", tenant_id, digest),
            tenant_id=tenant_id, ecosystem_id=ecosystem_id, resolution_version=version,
            supersedes_record_id=predecessor.ecosystem_record_id if predecessor else None,
            canonical_name=canonical_name, ecosystem_class=ecosystem_class,
            lifecycle_state=lifecycle_state, resolution_state=resolution_state,
            confidence=confidence, evidence_quality=evidence_quality,
            capability_genome_id=predecessor.capability_genome_id if predecessor else None,
            first_observed_at=(
                _stored_utc(predecessor.first_observed_at) if predecessor else observed_at
            ),
            last_observed_at=observed_at, last_validated_at=observed_at,
            methodology_id=RESOLUTION_METHODOLOGY_ID,
            methodology_version=RESOLUTION_METHODOLOGY_VERSION,
            limitations_json=list(limitations), outstanding_contradictions=contradictions,
            idempotency_key=idempotency_key, input_digest=digest,
        )
        db.add(row)
        db.flush()
        return row

    def _append_terminal_version(
        self, db: Session, tenant_id: str, ecosystem_id: str, lifecycle: str,
        occurred_at: datetime, idempotency_key: str,
    ) -> DiscoveryAIEcosystem:
        predecessor = self._latest_record(db, tenant_id, ecosystem_id)
        return self._append_ecosystem(
            db, tenant_id=tenant_id, ecosystem_id=ecosystem_id, predecessor=predecessor,
            canonical_name=predecessor.canonical_name,
            ecosystem_class=predecessor.ecosystem_class, lifecycle_state=lifecycle,
            resolution_state=predecessor.resolution_state,
            confidence=predecessor.confidence, evidence_quality=predecessor.evidence_quality,
            observed_at=occurred_at, contradictions=predecessor.outstanding_contradictions,
            limitations=tuple(predecessor.limitations_json),
            idempotency_key=f"{idempotency_key}:terminal:{ecosystem_id}:{lifecycle}",
        )

    @staticmethod
    def _current_memberships(db: Session, tenant_id: str, ecosystem_id: str) -> tuple[DiscoveryEcosystemMembership, ...]:
        rows = tuple(db.scalars(select(DiscoveryEcosystemMembership).where(
            DiscoveryEcosystemMembership.tenant_id == tenant_id,
            DiscoveryEcosystemMembership.ecosystem_id == ecosystem_id,
        ).order_by(DiscoveryEcosystemMembership.membership_sequence.desc())))
        latest: dict[str, DiscoveryEcosystemMembership] = {}
        for row in rows:
            latest.setdefault(row.graph_node_id, row)
        return tuple(sorted(
            (row for row in latest.values() if row.membership_state == "active"),
            key=lambda row: row.graph_node_id,
        ))

    def _snapshot_current(self, db: Session, tenant_id: str, ecosystem_ids: tuple[str, ...]) -> tuple[dict, ...]:
        output = []
        for ecosystem_id in sorted(ecosystem_ids):
            record = self._latest_record(db, tenant_id, ecosystem_id)
            if record.lifecycle_state != "active":
                raise ResolutionConflict("source ecosystem is not active")
            output.extend(self._snapshot_membership(row) for row in self._current_memberships(db, tenant_id, ecosystem_id))
        return tuple(output)

    @staticmethod
    def _snapshot_membership(row: DiscoveryEcosystemMembership) -> dict:
        return {
            "ecosystem_id": row.ecosystem_id,
            "graph_node_id": row.graph_node_id,
            "member_type": row.member_type,
            "confidence": row.confidence,
            "verification_state": row.verification_state,
            "evidence_node_id": row.evidence_node_id,
        }

    def _append_membership(
        self, db: Session, *, tenant_id: str, record: DiscoveryAIEcosystem,
        node: DiscoveryResolutionGraphNode, evidence_node_id: str, confidence: float,
        verification_state: str, occurred_at: datetime, state: str,
    ) -> dict:
        predecessor = db.scalar(select(DiscoveryEcosystemMembership).where(
            DiscoveryEcosystemMembership.tenant_id == tenant_id,
            DiscoveryEcosystemMembership.ecosystem_id == record.ecosystem_id,
            DiscoveryEcosystemMembership.graph_node_id == node.graph_node_id,
        ).order_by(DiscoveryEcosystemMembership.membership_sequence.desc()).limit(1))
        sequence = predecessor.membership_sequence + 1 if predecessor else 1
        material = {
            "ecosystem_record_id": record.ecosystem_record_id,
            "ecosystem_id": record.ecosystem_id, "graph_node_id": node.graph_node_id,
            "state": state, "sequence": sequence,
            "predecessor": predecessor.membership_id if predecessor else None,
            "evidence_node_id": evidence_node_id, "confidence": confidence,
            "verification_state": verification_state, "occurred_at": occurred_at.isoformat(),
        }
        digest = _digest("hawk:erg:ecosystem-membership:v1", material)
        row = DiscoveryEcosystemMembership(
            membership_id=_uuid("erg-ecosystem-membership", tenant_id, digest),
            tenant_id=tenant_id, ecosystem_record_id=record.ecosystem_record_id,
            ecosystem_id=record.ecosystem_id, graph_node_id=node.graph_node_id,
            member_type=node.node_class, membership_state=state,
            membership_sequence=sequence,
            predecessor_membership_id=predecessor.membership_id if predecessor else None,
            evidence_node_id=evidence_node_id, confidence=confidence,
            verification_state=verification_state,
            first_observed_at=(
                _stored_utc(predecessor.first_observed_at) if predecessor else occurred_at
            ),
            last_observed_at=occurred_at, limitations_json=[], input_digest=digest,
        )
        db.add(row)
        db.flush()
        return self._snapshot_membership(row)

    def _historical_memberships(
        self, db: Session, tenant_id: str, snapshots: tuple[dict, ...],
        evidence_node_id: str, occurred_at: datetime,
    ) -> None:
        node_map = {node.graph_node_id: node for node in self._nodes(
            db, tenant_id, tuple(sorted({item["graph_node_id"] for item in snapshots}))
        )}
        for item in snapshots:
            record = self._latest_record(db, tenant_id, item["ecosystem_id"])
            self._append_membership(
                db, tenant_id=tenant_id, record=record,
                node=node_map[item["graph_node_id"]], evidence_node_id=evidence_node_id,
                confidence=float(item["confidence"]),
                verification_state=str(item["verification_state"]),
                occurred_at=occurred_at, state="historical",
            )

    def _record_event(
        self, db: Session, *, tenant_id: str, action: str,
        source_ids: tuple[str, ...], result_ids: tuple[str, ...],
        before: tuple[dict, ...], after: tuple[dict, ...], evidence_node_id: str,
        reason: str, confidence: float | None, operator_id: str,
        operator_role: str, occurred_at: datetime, idempotency_key: str,
        material: dict[str, object], reverses_event_id: str | None = None,
        subject_reference: str | None = None,
    ) -> ResolutionMutation:
        digest = _digest("hawk:erg:resolution-event:v1", material)
        event_id = _uuid("erg-resolution-event", tenant_id, digest)
        event = DiscoveryEcosystemResolutionEvent(
            resolution_event_id=event_id, tenant_id=tenant_id, action=action,
            source_ecosystem_ids_json=list(source_ids),
            result_ecosystem_ids_json=list(result_ids),
            before_memberships_json=list(before), after_memberships_json=list(after),
            subject_reference=subject_reference,
            evidence_node_id=evidence_node_id, reason=reason, confidence=confidence,
            operator_id=operator_id, operator_role=operator_role,
            methodology_id=RESOLUTION_METHODOLOGY_ID,
            methodology_version=RESOLUTION_METHODOLOGY_VERSION,
            reverses_event_id=reverses_event_id, occurred_at=occurred_at,
            idempotency_key=idempotency_key, input_digest=digest,
        )
        db.add(event)
        db.flush()
        for side, memberships in (("before", before), ("after", after)):
            for item in memberships:
                snapshot_digest = _digest("hawk:erg:resolution-history-member:v1", {
                    "event_id": event_id, "side": side, "membership": item,
                })
                db.add(DiscoveryEcosystemHistoryMember(
                    history_member_id=_uuid("erg-history-member", tenant_id, snapshot_digest),
                    tenant_id=tenant_id, resolution_event_id=event_id, side=side,
                    ecosystem_id=str(item["ecosystem_id"]),
                    graph_node_id=str(item["graph_node_id"]),
                    membership_snapshot_json=dict(item), input_digest=snapshot_digest,
                ))
        db.add(AuditLog(
            tenant_id=tenant_id, correlation_id=event_id, actor_user_id=None,
            actor_type=operator_role, action=f"discovery.ecosystem.{action}",
            resource_type="ai_ecosystem",
            resource_id=(
                result_ids[0]
                if result_ids
                else (source_ids[0] if source_ids else evidence_node_id)
            ),
            payload={"event_id": event_id, "source_ids": list(source_ids), "result_ids": list(result_ids), "reason": reason},
        ))
        db.flush()
        return ResolutionMutation(
            event_id=event_id, action=action, ecosystem_ids=result_ids,
            before_memberships=before, after_memberships=after,
        )

    def _replay(
        self, db: Session, tenant_id: str, idempotency_key: str,
        material: dict[str, object],
    ) -> ResolutionMutation | None:
        row = db.scalar(select(DiscoveryEcosystemResolutionEvent).where(
            DiscoveryEcosystemResolutionEvent.tenant_id == tenant_id,
            DiscoveryEcosystemResolutionEvent.idempotency_key == idempotency_key,
        ))
        if row is None:
            return None
        if row.input_digest != _digest("hawk:erg:resolution-event:v1", material):
            raise ResolutionConflict("resolution idempotency conflict")
        return self._mutation_from_event(db, row)

    @staticmethod
    def _event_by_idempotency(
        db: Session, tenant_id: str, idempotency_key: str
    ) -> DiscoveryEcosystemResolutionEvent | None:
        return db.scalar(
            select(DiscoveryEcosystemResolutionEvent).where(
                DiscoveryEcosystemResolutionEvent.tenant_id == tenant_id,
                DiscoveryEcosystemResolutionEvent.idempotency_key == idempotency_key,
            )
        )

    @classmethod
    def _idempotent_event_time(
        cls,
        db: Session,
        tenant_id: str,
        idempotency_key: str,
        proposed: datetime,
    ) -> datetime:
        existing = cls._event_by_idempotency(db, tenant_id, idempotency_key)
        return _stored_utc(existing.occurred_at) if existing is not None else proposed

    @staticmethod
    def _canonical_memberships(items: tuple[dict, ...]) -> bytes:
        return canonical_json_bytes(
            sorted(
                (dict(item) for item in items),
                key=lambda item: (
                    str(item.get("ecosystem_id", "")),
                    str(item.get("graph_node_id", "")),
                    str(item.get("membership_id", "")),
                ),
            )
        )

    @staticmethod
    def _mutation_from_event(db: Session, row: DiscoveryEcosystemResolutionEvent) -> ResolutionMutation:
        return ResolutionMutation(
            event_id=row.resolution_event_id, action=row.action,
            ecosystem_ids=tuple(row.result_ecosystem_ids_json),
            before_memberships=tuple(row.before_memberships_json),
            after_memberships=tuple(row.after_memberships_json),
        )


__all__ = [
    "ResolutionAuthorizationError", "ResolutionConflict", "ResolutionHistory",
    "ResolutionMutation",
]
