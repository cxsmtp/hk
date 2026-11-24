from __future__ import annotations

from datetime import timedelta

from app.services.hmair.adv.planner import InitialVerificationCoordinator
from app.services.hmair.adv.policy import create_verification_policy
from app.services.hmair.erg.ecosystem_resolver import EcosystemResolver
from app.services.hmair.erg.hypothesis_engine import HypothesisEngine
from test_adv_policy import _requirements
from test_adv_planner import _scenario
from test_erg_ecosystem_resolver import _db, _qualified_coding_edges
from test_erg_hypotheses import NOW, _inference
from test_phase2_asset_resolution_service import _seed


def test_resolved_ecosystem_autonomously_receives_exact_policy_proof_tasks() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="adv-auto-plan")
        run_id = _inference(
            db,
            tenant_id=seed["tenant_id"],
            evidence_node_id=seed["node_id"],
            coding_confidence=1.0,
            include_retrieval=False,
        )
        evaluation = HypothesisEngine().evaluate(
            db,
            tenant_id=seed["tenant_id"],
            inference_run_id=run_id,
            graph_edge_ids=_qualified_coding_edges(db, seed, strong_relationship=False),
            evaluated_at=NOW,
            idempotency_prefix="adv-auto-hypothesis",
        )[0]
        create_verification_policy(
            db,
            tenant_id=seed["tenant_id"],
            policy_id="adv-auto-policy",
            version=1,
            ecosystem_classes=(evaluation.candidate_ecosystem_class,),
            environments=("production",),
            minimum_evidence_quality=0.8,
            minimum_confidence=0.8,
            minimum_source_diversity=1,
            assertion_ttl_seconds=3600,
            rescan_interval_seconds=1800,
            effective_from=NOW - timedelta(minutes=1),
            effective_until=None,
            requirements=_requirements(),
            actor_id="admin-1",
            idempotency_key="adv-auto-policy-v1",
        )
        outcome = EcosystemResolver().resolve(
            db,
            tenant_id=seed["tenant_id"],
            evaluation_id=evaluation.evaluation_id,
            evidence_node_id=seed["node_id"],
            evaluated_at=NOW,
            idempotency_key="adv-auto-resolve",
        )

        planned = InitialVerificationCoordinator().plan_resolved_outcomes(
            db,
            tenant_id=seed["tenant_id"],
            outcomes=(outcome.model_dump(mode="json"),),
            environment="production",
            triggered_at=NOW,
            idempotency_prefix="adv-auto-pipeline",
        )
        replay = InitialVerificationCoordinator().plan_resolved_outcomes(
            db,
            tenant_id=seed["tenant_id"],
            outcomes=(outcome.model_dump(mode="json"),),
            environment="production",
            triggered_at=NOW,
            idempotency_prefix="adv-auto-pipeline",
        )

        assert len(planned.plans) == 1
        assert planned.plans[0].episode.ecosystem_id == outcome.ecosystem_ids[0]
        assert planned.plans[0].episode.hypothesis_evaluation_id == evaluation.evaluation_id
        assert set(planned.plans[0].task_requirement_ids) | set(
            planned.plans[0].unsupported_requirement_ids
        ) == {"endpoint_identity", "network_usage"}
        assert planned.limitations == ()
        assert replay.plans[0].episode.episode_id == planned.plans[0].episode.episode_id
    finally:
        db.close()
        db.bind.dispose()


def test_missing_policy_remains_an_explicit_autonomy_limitation() -> None:
    db = _db()
    try:
        seed, evaluation_id, ecosystem_id = _scenario(db)
        planned = InitialVerificationCoordinator().plan_resolved_outcomes(
            db,
            tenant_id=seed["tenant_id"],
            outcomes=(
                {
                    "evaluation_id": evaluation_id,
                    "ecosystem_ids": (ecosystem_id,),
                    "mutated": True,
                },
            ),
            environment="staging",
            triggered_at=NOW,
            idempotency_prefix="adv-auto-no-matching-policy",
        )
        assert planned.plans == ()
        assert planned.limitations == (
            f"verification_policy_unavailable:{ecosystem_id}",
        )
    finally:
        db.close()
        db.bind.dispose()
