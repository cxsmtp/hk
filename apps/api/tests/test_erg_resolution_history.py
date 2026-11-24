from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.models.evidence_resolution import (
    DiscoveryEcosystemResolutionEvent,
    DiscoveryEcosystemHistoryMember,
)
from app.db.session import Base
from app.services.hmair.erg.resolution_history import (
    ResolutionAuthorizationError,
    ResolutionConflict,
    ResolutionHistory,
)
from app.services.hmair.resolution_graph_service import create_graph_node
from test_phase2_asset_resolution_service import _seed


NOW = datetime(2026, 8, 16, 12, 0, tzinfo=timezone.utc)


def _db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine, autoflush=False, expire_on_commit=False)


def test_manual_merge_split_and_reversal_preserve_before_after_history() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-history")
        nodes = tuple(
            create_graph_node(
                db,
                tenant_id=seed["tenant_id"],
                node_class=node_class,
                subject_reference=f"{node_class}:opaque-{index}",
                idempotency_key=f"history-node-{index}",
            )
            for index, node_class in enumerate(("application", "runtime", "repository"), 1)
        )
        history = ResolutionHistory()
        first = history.create_ecosystem(
            db,
            tenant_id=seed["tenant_id"],
            canonical_name="Coding workspace",
            ecosystem_class="coding",
            graph_node_ids=(nodes[0].graph_node_id, nodes[1].graph_node_id),
            evidence_node_id=seed["node_id"],
            confidence=0.96,
            evidence_quality=0.94,
            operator_id="owner-1",
            operator_role="owner",
            reason="Operator confirmed the first evidence group",
            occurred_at=NOW,
            idempotency_key="create-first",
        )
        second = history.create_ecosystem(
            db,
            tenant_id=seed["tenant_id"],
            canonical_name="Repository workspace",
            ecosystem_class="coding",
            graph_node_ids=(nodes[2].graph_node_id,),
            evidence_node_id=seed["node_id"],
            confidence=0.95,
            evidence_quality=0.93,
            operator_id="owner-1",
            operator_role="owner",
            reason="Operator confirmed the repository evidence group",
            occurred_at=NOW,
            idempotency_key="create-second",
        )
        merged = history.merge(
            db,
            tenant_id=seed["tenant_id"],
            source_ecosystem_ids=(first.ecosystem_ids[0], second.ecosystem_ids[0]),
            canonical_name="Enterprise coding ecosystem",
            ecosystem_class="coding",
            evidence_node_id=seed["node_id"],
            operator_id="owner-1",
            operator_role="owner",
            reason="Shared strong runtime and repository identity",
            occurred_at=NOW,
            idempotency_key="manual-merge",
        )
        assert len(merged.before_memberships) == 3
        assert len(merged.after_memberships) == 3
        assert history.merge(
            db,
            tenant_id=seed["tenant_id"],
            source_ecosystem_ids=(first.ecosystem_ids[0], second.ecosystem_ids[0]),
            canonical_name="Enterprise coding ecosystem",
            ecosystem_class="coding",
            evidence_node_id=seed["node_id"],
            operator_id="owner-1",
            operator_role="owner",
            reason="Shared strong runtime and repository identity",
            occurred_at=NOW + timedelta(seconds=5),
            idempotency_key="manual-merge",
        ) == merged
        with pytest.raises(ResolutionConflict, match="idempotency conflict"):
            history.merge(
                db,
                tenant_id=seed["tenant_id"],
                source_ecosystem_ids=(first.ecosystem_ids[0], second.ecosystem_ids[0]),
                canonical_name="Altered ecosystem name",
                ecosystem_class="coding",
                evidence_node_id=seed["node_id"],
                operator_id="owner-1",
                operator_role="owner",
                reason="Shared strong runtime and repository identity",
                occurred_at=NOW,
                idempotency_key="manual-merge",
            )

        reversed_merge = history.reverse(
            db,
            tenant_id=seed["tenant_id"],
            resolution_event_id=merged.event_id,
            evidence_node_id=seed["node_id"],
            operator_id="owner-1",
            operator_role="owner",
            reason="New contradictory evidence requires reversal",
            occurred_at=NOW,
            idempotency_key="reverse-merge",
        )
        assert set(reversed_merge.ecosystem_ids) == {
            first.ecosystem_ids[0],
            second.ecosystem_ids[0],
        }
        assert len(reversed_merge.after_memberships) == 3
        assert history.reverse(
            db,
            tenant_id=seed["tenant_id"],
            resolution_event_id=merged.event_id,
            evidence_node_id=seed["node_id"],
            operator_id="owner-1",
            operator_role="owner",
            reason="New contradictory evidence requires reversal",
            occurred_at=NOW + timedelta(seconds=5),
            idempotency_key="reverse-merge",
        ) == reversed_merge
        with pytest.raises(ResolutionConflict, match="idempotency conflict"):
            history.reverse(
                db,
                tenant_id=seed["tenant_id"],
                resolution_event_id=merged.event_id,
                evidence_node_id=seed["node_id"],
                operator_id="owner-1",
                operator_role="owner",
                reason="Altered reversal reason",
                occurred_at=NOW,
                idempotency_key="reverse-merge",
            )

        split = history.split(
            db,
            tenant_id=seed["tenant_id"],
            source_ecosystem_id=first.ecosystem_ids[0],
            groups=((nodes[0].graph_node_id,), (nodes[1].graph_node_id,)),
            canonical_names=("Desktop client", "Local runtime"),
            ecosystem_classes=("ai_application", "runtime"),
            evidence_node_id=seed["node_id"],
            operator_id="admin-1",
            operator_role="admin",
            reason="Contradiction proves two ecosystems",
            occurred_at=NOW,
            idempotency_key="manual-split",
        )
        assert len(split.ecosystem_ids) == 2
        assert len(split.after_memberships) == 2
        assert history.split(
            db,
            tenant_id=seed["tenant_id"],
            source_ecosystem_id=first.ecosystem_ids[0],
            groups=((nodes[0].graph_node_id,), (nodes[1].graph_node_id,)),
            canonical_names=("Desktop client", "Local runtime"),
            ecosystem_classes=("ai_application", "runtime"),
            evidence_node_id=seed["node_id"],
            operator_id="admin-1",
            operator_role="admin",
            reason="Contradiction proves two ecosystems",
            occurred_at=NOW + timedelta(seconds=5),
            idempotency_key="manual-split",
        ) == split
        assert db.scalar(select(DiscoveryEcosystemResolutionEvent).where(
            DiscoveryEcosystemResolutionEvent.resolution_event_id == split.event_id
        )) is not None
        assert len(tuple(db.scalars(select(DiscoveryEcosystemHistoryMember)))) >= 16
    finally:
        db.close()
        db.bind.dispose()


def test_manual_ecosystem_creation_requires_an_authorized_role() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-history-auth")
        node = create_graph_node(
            db,
            tenant_id=seed["tenant_id"],
            node_class="application",
            subject_reference="application:manual-only",
            idempotency_key="manual-only-node",
        )
        history = ResolutionHistory()
        with pytest.raises(ResolutionAuthorizationError):
            history.create_ecosystem(
                db,
                tenant_id=seed["tenant_id"],
                canonical_name="Invalid operator ecosystem",
                ecosystem_class="unknown",
                graph_node_ids=(node.graph_node_id,),
                evidence_node_id=seed["node_id"],
                confidence=0.8,
                evidence_quality=0.8,
                operator_id="viewer-1",
                operator_role="viewer",
                reason="Viewer cannot mutate resolution",
                occurred_at=NOW,
                idempotency_key="viewer-create",
            )
    finally:
        db.close()
        db.bind.dispose()


def test_merge_deduplicates_shared_current_nodes_but_reversal_restores_each_source() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-history-overlap")
        application = create_graph_node(
            db,
            tenant_id=seed["tenant_id"],
            node_class="application",
            subject_reference="application:overlap-client",
            idempotency_key="overlap-application",
        )
        runtime = create_graph_node(
            db,
            tenant_id=seed["tenant_id"],
            node_class="runtime",
            subject_reference="runtime:shared",
            idempotency_key="overlap-runtime",
        )
        repository = create_graph_node(
            db,
            tenant_id=seed["tenant_id"],
            node_class="repository",
            subject_reference="repository:overlap-workspace",
            idempotency_key="overlap-repository",
        )
        history = ResolutionHistory()
        first = history.create_ecosystem(
            db,
            tenant_id=seed["tenant_id"],
            canonical_name="Application candidate",
            ecosystem_class="coding",
            graph_node_ids=(application.graph_node_id, runtime.graph_node_id),
            evidence_node_id=seed["node_id"],
            confidence=0.96,
            evidence_quality=0.94,
            operator_id="owner-1",
            operator_role="owner",
            reason="First competing hypothesis",
            occurred_at=NOW,
            idempotency_key="overlap-create-first",
        )
        second = history.create_ecosystem(
            db,
            tenant_id=seed["tenant_id"],
            canonical_name="Repository candidate",
            ecosystem_class="coding",
            graph_node_ids=(runtime.graph_node_id, repository.graph_node_id),
            evidence_node_id=seed["node_id"],
            confidence=0.95,
            evidence_quality=0.93,
            operator_id="owner-1",
            operator_role="owner",
            reason="Second competing hypothesis",
            occurred_at=NOW,
            idempotency_key="overlap-create-second",
        )
        merged = history.merge(
            db,
            tenant_id=seed["tenant_id"],
            source_ecosystem_ids=(first.ecosystem_ids[0], second.ecosystem_ids[0]),
            canonical_name="Resolved coding ecosystem",
            ecosystem_class="coding",
            evidence_node_id=seed["node_id"],
            operator_id="owner-1",
            operator_role="owner",
            reason="Manual review resolved the shared runtime",
            occurred_at=NOW,
            idempotency_key="overlap-merge",
        )

        assert len(merged.before_memberships) == 4
        assert len(merged.after_memberships) == 3
        assert len({item["graph_node_id"] for item in merged.after_memberships}) == 3

        reversed_merge = history.reverse(
            db,
            tenant_id=seed["tenant_id"],
            resolution_event_id=merged.event_id,
            evidence_node_id=seed["node_id"],
            operator_id="owner-1",
            operator_role="owner",
            reason="Restore both competing source ecosystems",
            occurred_at=NOW,
            idempotency_key="overlap-reverse",
        )
        assert len(reversed_merge.after_memberships) == 4
        assert set(reversed_merge.ecosystem_ids) == {
            first.ecosystem_ids[0],
            second.ecosystem_ids[0],
        }
    finally:
        db.close()
        db.bind.dispose()


def test_attach_observation_appends_membership_and_preserves_before_after_history() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-history-attach")
        original = create_graph_node(
            db,
            tenant_id=seed["tenant_id"],
            node_class="application",
            subject_reference="application:governed-client",
            idempotency_key="attach-original-node",
        )
        discovered = create_graph_node(
            db,
            tenant_id=seed["tenant_id"],
            node_class="mcp",
            subject_reference="mcp:opaque-server",
            idempotency_key="attach-discovered-node",
        )
        history = ResolutionHistory()
        created = history.create_ecosystem(
            db,
            tenant_id=seed["tenant_id"],
            canonical_name="Governed agent ecosystem",
            ecosystem_class="agentic_workflow",
            graph_node_ids=(original.graph_node_id,),
            evidence_node_id=seed["node_id"],
            confidence=0.96,
            evidence_quality=0.94,
            operator_id="owner-1",
            operator_role="owner",
            reason="Initial verified application evidence",
            occurred_at=NOW,
            idempotency_key="attach-create",
        )

        attached = history.attach_observation(
            db,
            tenant_id=seed["tenant_id"],
            ecosystem_id=created.ecosystem_ids[0],
            graph_node_id=discovered.graph_node_id,
            evidence_node_id=seed["node_id"],
            confidence=0.95,
            evidence_quality=0.93,
            operator_id="erg-ecosystem-resolver",
            operator_role="system",
            reason="Strong resolved-match evidence crossed the attach threshold",
            occurred_at=NOW,
            idempotency_key="attach-new-observation",
        )

        assert attached.action == "attach"
        assert attached.ecosystem_ids == created.ecosystem_ids
        assert [item["graph_node_id"] for item in attached.before_memberships] == [
            original.graph_node_id
        ]
        assert {item["graph_node_id"] for item in attached.after_memberships} == {
            original.graph_node_id,
            discovered.graph_node_id,
        }
        replay = history.attach_observation(
            db,
            tenant_id=seed["tenant_id"],
            ecosystem_id=created.ecosystem_ids[0],
            graph_node_id=discovered.graph_node_id,
            evidence_node_id=seed["node_id"],
            confidence=0.95,
            evidence_quality=0.93,
            operator_id="erg-ecosystem-resolver",
            operator_role="system",
            reason="Strong resolved-match evidence crossed the attach threshold",
            occurred_at=NOW + timedelta(seconds=5),
            idempotency_key="attach-new-observation",
        )
        assert replay == attached
    finally:
        db.close()
        db.bind.dispose()


def test_attach_replay_survives_a_later_ecosystem_merge() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-history-attach-replay-after-merge")
        nodes = tuple(
            create_graph_node(
                db,
                tenant_id=seed["tenant_id"],
                node_class=node_class,
                subject_reference=f"{node_class}:attach-replay-{index}",
                idempotency_key=f"attach-replay-node-{index}",
            )
            for index, node_class in enumerate(
                ("application", "mcp", "repository"), start=1
            )
        )
        history = ResolutionHistory()
        target = history.create_ecosystem(
            db,
            tenant_id=seed["tenant_id"],
            canonical_name="Attach replay target",
            ecosystem_class="agentic_workflow",
            graph_node_ids=(nodes[0].graph_node_id,),
            evidence_node_id=seed["node_id"],
            confidence=0.96,
            evidence_quality=0.95,
            operator_id="owner-1",
            operator_role="owner",
            reason="Initial target evidence",
            occurred_at=NOW,
            idempotency_key="attach-replay-target",
        )
        peer = history.create_ecosystem(
            db,
            tenant_id=seed["tenant_id"],
            canonical_name="Attach replay peer",
            ecosystem_class="coding",
            graph_node_ids=(nodes[2].graph_node_id,),
            evidence_node_id=seed["node_id"],
            confidence=0.96,
            evidence_quality=0.95,
            operator_id="owner-1",
            operator_role="owner",
            reason="Initial peer evidence",
            occurred_at=NOW,
            idempotency_key="attach-replay-peer",
        )
        attached = history.attach_observation(
            db,
            tenant_id=seed["tenant_id"],
            ecosystem_id=target.ecosystem_ids[0],
            graph_node_id=nodes[1].graph_node_id,
            evidence_node_id=seed["node_id"],
            confidence=0.95,
            evidence_quality=0.94,
            operator_id="erg-ecosystem-resolver",
            operator_role="system",
            reason="Strong evidence crossed the attach threshold",
            occurred_at=NOW,
            idempotency_key="attach-before-merge",
        )
        history.merge(
            db,
            tenant_id=seed["tenant_id"],
            source_ecosystem_ids=(target.ecosystem_ids[0], peer.ecosystem_ids[0]),
            canonical_name="Merged after attachment",
            ecosystem_class="agentic_workflow",
            evidence_node_id=seed["node_id"],
            operator_id="owner-1",
            operator_role="owner",
            reason="Later evidence resolved both sources together",
            occurred_at=NOW + timedelta(seconds=2),
            idempotency_key="merge-after-attach",
        )

        replay = history.attach_observation(
            db,
            tenant_id=seed["tenant_id"],
            ecosystem_id=target.ecosystem_ids[0],
            graph_node_id=nodes[1].graph_node_id,
            evidence_node_id=seed["node_id"],
            confidence=0.95,
            evidence_quality=0.94,
            operator_id="erg-ecosystem-resolver",
            operator_role="system",
            reason="Strong evidence crossed the attach threshold",
            occurred_at=NOW + timedelta(seconds=5),
            idempotency_key="attach-before-merge",
        )

        assert replay == attached
    finally:
        db.close()
        db.bind.dispose()


def test_reversal_rejects_a_result_changed_after_merge() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-history-reverse-precondition")
        nodes = tuple(
            create_graph_node(
                db,
                tenant_id=seed["tenant_id"],
                node_class=node_class,
                subject_reference=f"{node_class}:reverse-precondition-{index}",
                idempotency_key=f"reverse-precondition-node-{index}",
            )
            for index, node_class in enumerate(
                ("application", "repository", "runtime"), start=1
            )
        )
        history = ResolutionHistory()
        sources = tuple(
            history.create_ecosystem(
                db,
                tenant_id=seed["tenant_id"],
                canonical_name=f"Source {index}",
                ecosystem_class="coding",
                graph_node_ids=(nodes[index].graph_node_id,),
                evidence_node_id=seed["node_id"],
                confidence=0.96,
                evidence_quality=0.95,
                operator_id="owner-1",
                operator_role="owner",
                reason="Seed source",
                occurred_at=NOW,
                idempotency_key=f"reverse-precondition-source-{index}",
            )
            for index in range(2)
        )
        merged = history.merge(
            db,
            tenant_id=seed["tenant_id"],
            source_ecosystem_ids=tuple(item.ecosystem_ids[0] for item in sources),
            canonical_name="Merged before later evidence",
            ecosystem_class="coding",
            evidence_node_id=seed["node_id"],
            operator_id="owner-1",
            operator_role="owner",
            reason="Initial merge",
            occurred_at=NOW,
            idempotency_key="reverse-precondition-merge",
        )
        history.attach_observation(
            db,
            tenant_id=seed["tenant_id"],
            ecosystem_id=merged.ecosystem_ids[0],
            graph_node_id=nodes[2].graph_node_id,
            evidence_node_id=seed["node_id"],
            confidence=0.95,
            evidence_quality=0.94,
            operator_id="owner-1",
            operator_role="owner",
            reason="Later evidence changed the result",
            occurred_at=NOW,
            idempotency_key="reverse-precondition-attach",
        )

        with pytest.raises(ResolutionConflict, match="changed after"):
            history.reverse(
                db,
                tenant_id=seed["tenant_id"],
                resolution_event_id=merged.event_id,
                evidence_node_id=seed["node_id"],
                operator_id="owner-1",
                operator_role="owner",
                reason="Unsafe stale reversal",
                occurred_at=NOW,
                idempotency_key="reverse-precondition-reversal",
            )
    finally:
        db.close()
        db.bind.dispose()


def test_automatic_attach_requires_exact_evidence_threshold() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-history-attach-threshold")
        nodes = tuple(
            create_graph_node(
                db,
                tenant_id=seed["tenant_id"],
                node_class=node_class,
                subject_reference=f"{node_class}:attach-threshold-{index}",
                idempotency_key=f"attach-threshold-node-{index}",
            )
            for index, node_class in enumerate(("application", "runtime"), 1)
        )
        history = ResolutionHistory()
        created = history.create_ecosystem(
            db,
            tenant_id=seed["tenant_id"],
            canonical_name="Threshold ecosystem",
            ecosystem_class="runtime",
            graph_node_ids=(nodes[0].graph_node_id,),
            evidence_node_id=seed["node_id"],
            confidence=0.96,
            evidence_quality=0.96,
            operator_id="owner-1",
            operator_role="owner",
            reason="Initial evidence",
            occurred_at=NOW,
            idempotency_key="attach-threshold-create",
        )
        with pytest.raises(ResolutionAuthorizationError):
            history.attach_observation(
                db,
                tenant_id=seed["tenant_id"],
                ecosystem_id=created.ecosystem_ids[0],
                graph_node_id=nodes[1].graph_node_id,
                evidence_node_id=seed["node_id"],
                confidence=0.949999,
                evidence_quality=0.99,
                operator_id="erg-ecosystem-resolver",
                operator_role="system",
                reason="Below automatic threshold",
                occurred_at=NOW,
                idempotency_key="attach-threshold-denied",
            )
    finally:
        db.close()
        db.bind.dispose()


def test_manual_review_unknown_and_reject_are_explicit_audited_dispositions() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="erg-history-disposition")
        history = ResolutionHistory()
        manual = history.record_disposition(
            db,
            tenant_id=seed["tenant_id"],
            action="manual_review",
            subject_reference="hypothesis:opaque-candidate",
            evidence_node_id=seed["node_id"],
            confidence=0.72,
            operator_id="admin-1",
            operator_role="admin",
            reason="Competing ecosystems remain plausible",
            occurred_at=NOW,
            idempotency_key="disposition-manual",
        )
        unknown = history.record_disposition(
            db,
            tenant_id=seed["tenant_id"],
            action="unknown",
            subject_reference="observation:opaque-unreadable",
            evidence_node_id=seed["node_id"],
            confidence=None,
            operator_id="erg-ecosystem-resolver",
            operator_role="system",
            reason="Required evidence is inaccessible",
            occurred_at=NOW,
            idempotency_key="disposition-unknown",
        )
        rejected = history.record_disposition(
            db,
            tenant_id=seed["tenant_id"],
            action="reject",
            subject_reference="observation:proven-unrelated",
            evidence_node_id=seed["node_id"],
            confidence=0.99,
            operator_id="owner-1",
            operator_role="owner",
            reason="Direct evidence proves the observation belongs elsewhere",
            occurred_at=NOW,
            idempotency_key="disposition-reject",
        )
        assert (manual.action, unknown.action, rejected.action) == (
            "manual_review",
            "unknown",
            "reject",
        )
        events = tuple(db.scalars(select(DiscoveryEcosystemResolutionEvent)))
        assert {item.subject_reference for item in events} == {
            "hypothesis:opaque-candidate",
            "observation:opaque-unreadable",
            "observation:proven-unrelated",
        }
        with pytest.raises(ResolutionAuthorizationError):
            history.record_disposition(
                db,
                tenant_id=seed["tenant_id"],
                action="reject",
                subject_reference="observation:unsafe-auto-reject",
                evidence_node_id=seed["node_id"],
                confidence=0.99,
                operator_id="erg-ecosystem-resolver",
                operator_role="system",
                reason="Automatic rejection is not accepted in this ruleset",
                occurred_at=NOW,
                idempotency_key="disposition-system-reject",
            )
    finally:
        db.close()
        db.bind.dispose()
