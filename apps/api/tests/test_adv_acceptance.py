from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from app.db.models.discovery_verification import DiscoveryVerificationEvent
from app.db.models.evidence_resolution import DiscoveryHypothesisEvaluation
from app.services.hmair.adv.assertions import VerificationAssertionEngine
from app.services.hmair.adv.continuous_validation import ContinuousValidationService
from app.services.hmair.adv.contracts import DiscoveryStage, VerificationOutcome
from app.services.hmair.adv.planner import VerificationPlanner
from app.services.hmair.adv.projection import VerificationProjectionService
from app.services.hmair.adv.results import VerificationResultValidator
from app.services.hmair.verification_service import claim_verification_task
from test_adv_planner import NOW, _db, _scenario
from test_adv_results import WORKER_ID, _collector_integrity


def _result_scenario(outcome: VerificationOutcome, *, transport_failed: bool = False):
    db = _db()
    seed, evaluation_id, ecosystem_id = _scenario(db)
    plan = VerificationPlanner().start(
        db,
        tenant_id=seed["tenant_id"], ecosystem_id=ecosystem_id,
        hypothesis_evaluation_id=evaluation_id, environment="production",
        trigger="hypothesis_created", triggered_at=NOW,
        idempotency_key=f"adv-acceptance-plan-{outcome.value}",
    )
    integrity = _collector_integrity(
        db, seed["tenant_id"], suffix=f"acceptance-{outcome.value}"
    )
    task = claim_verification_task(
        db,
        tenant_id=seed["tenant_id"], task_id=plan.tasks[0].task_id,
        worker_id=WORKER_ID, now=NOW + timedelta(seconds=1),
    )
    result = VerificationResultValidator().accept(
        db,
        tenant_id=seed["tenant_id"], task_id=task.task_id,
        worker_id=WORKER_ID, outcome=outcome,
        evidence_node_ids=(seed["node_id"],) if outcome in {
            VerificationOutcome.VERIFIED, VerificationOutcome.CONTRADICTED
        } else (),
        observed_at=NOW, validated_at=NOW + timedelta(seconds=2),
        limitations=("collector_unreachable",) if transport_failed else (),
        idempotency_key=f"adv-acceptance-result-{outcome.value}",
        execution_state="transport_failed" if transport_failed else "completed",
        collector_integrity_ref=(
            integrity.snapshot_id
            if outcome in {VerificationOutcome.VERIFIED, VerificationOutcome.CONTRADICTED}
            else None
        ),
    )
    return db, seed, ecosystem_id, plan, result


def test_complete_proof_path_reaches_continuously_validated_without_copying_confidence() -> None:
    db, seed, ecosystem_id, plan, _ = _result_scenario(
        VerificationOutcome.VERIFIED
    )
    try:
        assertion = ContinuousValidationService().evaluate_ready(
            db,
            tenant_id=seed["tenant_id"], evaluated_at=NOW + timedelta(seconds=5),
        )[0]
        projection = VerificationProjectionService().get(
            db,
            tenant_id=seed["tenant_id"], ecosystem_id=ecosystem_id,
            evaluated_at=NOW + timedelta(seconds=6),
        )
        assert assertion.conclusion == "verified"
        assert projection.stage is DiscoveryStage.CONTINUOUSLY_VALIDATED
        assert projection.required_outcomes == (VerificationOutcome.VERIFIED,)
        assert projection.verification_coverage == 1.0
        assert projection.verification_quality == 1.0
        assert projection.erg_evaluation_id == plan.episode.hypothesis_evaluation_id
        assert projection.confidence == db.scalar(
            select(DiscoveryHypothesisEvaluation.effective_confidence).where(
                DiscoveryHypothesisEvaluation.evaluation_id
                == plan.episode.hypothesis_evaluation_id
            )
        )
    finally:
        db.close()
        db.bind.dispose()


def test_expired_required_evidence_returns_projection_to_verification() -> None:
    db, seed, ecosystem_id, _, result = _result_scenario(
        VerificationOutcome.VERIFIED
    )
    try:
        ContinuousValidationService().evaluate_ready(
            db,
            tenant_id=seed["tenant_id"], evaluated_at=NOW + timedelta(seconds=5),
        )
        projection = VerificationProjectionService().get(
            db,
            tenant_id=seed["tenant_id"], ecosystem_id=ecosystem_id,
            evaluated_at=result.expires_at + timedelta(seconds=1),
        )
        assert projection.stage is DiscoveryStage.VERIFICATION
        assert projection.assertion_current is False
        assert projection.required_outcomes == (VerificationOutcome.UNKNOWN,)
        assert projection.verification_coverage == 0.0
    finally:
        db.close()
        db.bind.dispose()


def test_contradiction_and_collector_outage_remain_distinct_semantic_outcomes() -> None:
    contradicted_db, seed, ecosystem_id, plan, _ = _result_scenario(
        VerificationOutcome.CONTRADICTED
    )
    try:
        assertion = VerificationAssertionEngine().evaluate(
            contradicted_db,
            tenant_id=seed["tenant_id"], episode_id=plan.episode.episode_id,
            evaluated_at=NOW + timedelta(seconds=5),
            idempotency_key="adv-acceptance-contradicted-assertion",
        )
        projection = VerificationProjectionService().get(
            contradicted_db,
            tenant_id=seed["tenant_id"], ecosystem_id=ecosystem_id,
            evaluated_at=NOW + timedelta(seconds=6),
        )
        assert assertion.conclusion == "contradicted"
        assert projection.required_outcomes == (VerificationOutcome.CONTRADICTED,)
        assert "required_verification_contradicted" in projection.limitations
    finally:
        contradicted_db.close()
        contradicted_db.bind.dispose()

    unknown_db, seed, ecosystem_id, plan, _ = _result_scenario(
        VerificationOutcome.UNKNOWN, transport_failed=True
    )
    try:
        assertion = VerificationAssertionEngine().evaluate(
            unknown_db,
            tenant_id=seed["tenant_id"], episode_id=plan.episode.episode_id,
            evaluated_at=NOW + timedelta(seconds=5),
            idempotency_key="adv-acceptance-outage-assertion",
        )
        assert assertion.conclusion == "incomplete"
        assert assertion.contradictions_json == []
        assert VerificationProjectionService().get(
            unknown_db,
            tenant_id=seed["tenant_id"], ecosystem_id=ecosystem_id,
            evaluated_at=NOW + timedelta(seconds=6),
        ).required_outcomes == (VerificationOutcome.UNKNOWN,)
    finally:
        unknown_db.close()
        unknown_db.bind.dispose()


def test_lifecycle_events_are_append_only_explanations_not_mutable_stage_truth() -> None:
    db, seed, _, plan, _ = _result_scenario(VerificationOutcome.VERIFIED)
    try:
        ContinuousValidationService().evaluate_ready(
            db,
            tenant_id=seed["tenant_id"], evaluated_at=NOW + timedelta(seconds=5),
        )
        events = tuple(
            db.scalars(
                select(DiscoveryVerificationEvent)
                .where(DiscoveryVerificationEvent.episode_id == plan.episode.episode_id)
                .order_by(DiscoveryVerificationEvent.occurred_at)
            ).all()
        )
        assert events[0].event_type == "verification_started"
        assert events[-1].event_type == "verification_passed"
        assert all(item.after_json is not None for item in events)
    finally:
        db.close()
        db.bind.dispose()
