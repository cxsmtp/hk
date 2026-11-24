from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.models.discovery_verification import DiscoveryVerificationResult
from app.db.models.discovery_verification import DiscoveryVerificationEvent
from app.db.models.evidence_resolution import DiscoveryAIEcosystem
from app.db.session import Base
from app.services.hmair.adv.planner import VerificationPlanner, VerificationPlanningConflict
from app.services.hmair.adv.policy import create_verification_policy
from app.services.hmair.erg.hypothesis_engine import HypothesisEngine
from app.services.hmair.erg.resolution_history import ResolutionHistory
from test_adv_policy import _requirements
from test_erg_ecosystem_resolver import NOW, _qualified_coding_edges
from test_erg_hypotheses import _inference
from test_phase2_asset_resolution_service import _seed


def _db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine, autoflush=False, expire_on_commit=False)


def _scenario(db: Session) -> tuple[dict[str, str], str, str]:
    seed = _seed(db, suffix="adv-planner")
    run_id = _inference(
        db,
        tenant_id=seed["tenant_id"],
        evidence_node_id=seed["node_id"],
        coding_confidence=1.0,
        include_retrieval=False,
    )
    edges = _qualified_coding_edges(db, seed, strong_relationship=False)
    evaluation = HypothesisEngine().evaluate(
        db,
        tenant_id=seed["tenant_id"],
        inference_run_id=run_id,
        graph_edge_ids=edges,
        evaluated_at=NOW,
        idempotency_prefix="adv-planner-evaluation",
    )[0]
    node_ids = tuple(
        db.scalar(
            select(DiscoveryResolutionGraphEdge).where(
                DiscoveryResolutionGraphEdge.edge_id == edge_id
            )
        ).from_node_id
        for edge_id in edges[:1]
    )
    created = ResolutionHistory().create_ecosystem(
        db,
        tenant_id=seed["tenant_id"],
        canonical_name="ADV coding ecosystem",
        ecosystem_class="coding",
        graph_node_ids=node_ids,
        evidence_node_id=seed["node_id"],
        confidence=0.96,
        evidence_quality=0.94,
        operator_id="system",
        operator_role="system",
        reason="Create the verification target",
        occurred_at=NOW,
        idempotency_key="adv-planner-ecosystem",
    )
    create_verification_policy(
        db,
        tenant_id=seed["tenant_id"],
        policy_id="coding-production",
        version=1,
        ecosystem_classes=("coding",),
        environments=("production",),
        minimum_evidence_quality=0.8,
        minimum_confidence=0.85,
        minimum_source_diversity=1,
        assertion_ttl_seconds=3600,
        rescan_interval_seconds=1800,
        effective_from=NOW - timedelta(minutes=1),
        effective_until=NOW + timedelta(days=1),
        requirements=_requirements(),
        actor_id="admin-1",
        idempotency_key="adv-planner-policy",
    )
    return seed, evaluation.evaluation_id, created.ecosystem_ids[0]


def test_planner_materializes_every_requirement_as_task_or_unsupported() -> None:
    db = _db()
    try:
        seed, evaluation_id, ecosystem_id = _scenario(db)
        plan = VerificationPlanner().start(
            db,
            tenant_id=seed["tenant_id"],
            ecosystem_id=ecosystem_id,
            hypothesis_evaluation_id=evaluation_id,
            environment="production",
            trigger="hypothesis_created",
            triggered_at=NOW,
            idempotency_key="adv-plan-1",
        )
        assert set(plan.required_requirement_ids) == {"endpoint_identity"}
        assert set(plan.task_requirement_ids) | set(plan.unsupported_requirement_ids) == {
            "endpoint_identity",
            "network_usage",
        }
        assert plan.task_requirement_ids == ("endpoint_identity",)
        assert plan.unsupported_requirement_ids == ("network_usage",)
        assert plan.tasks[0].verification_episode_id == plan.episode.episode_id
        assert plan.tasks[0].verification_requirement_id is not None
        unsupported = db.scalar(
            select(DiscoveryVerificationResult).where(
                DiscoveryVerificationResult.episode_id == plan.episode.episode_id
            )
        )
        assert unsupported.outcome == "unsupported"
        assert unsupported.satisfies_requirement is False
        start_event = db.scalar(
            select(DiscoveryVerificationEvent).where(
                DiscoveryVerificationEvent.episode_id == plan.episode.episode_id,
                DiscoveryVerificationEvent.event_type == "verification_started",
            )
        )
        assert start_event is not None
        assert start_event.actor_type == "system"

        replay = VerificationPlanner().start(
            db,
            tenant_id=seed["tenant_id"],
            ecosystem_id=ecosystem_id,
            hypothesis_evaluation_id=evaluation_id,
            environment="production",
            trigger="hypothesis_created",
            triggered_at=NOW,
            idempotency_key="adv-plan-1",
        )
        assert replay.episode.episode_id == plan.episode.episode_id
        assert tuple(item.task_id for item in replay.tasks) == tuple(
            item.task_id for item in plan.tasks
        )
    finally:
        db.close()
        db.bind.dispose()


def test_planner_rejects_cross_tenant_evaluation_binding() -> None:
    db = _db()
    try:
        seed, evaluation_id, ecosystem_id = _scenario(db)
        with pytest.raises(VerificationPlanningConflict, match="evaluation"):
            VerificationPlanner().start(
                db,
                tenant_id="wrong-tenant",
                ecosystem_id=ecosystem_id,
                hypothesis_evaluation_id=evaluation_id,
                environment="production",
                trigger="hypothesis_created",
                triggered_at=NOW,
                idempotency_key="adv-cross-tenant",
            )
    finally:
        db.close()
        db.bind.dispose()
