from __future__ import annotations

from datetime import timedelta

from app.services.hmair.adv.assertions import VerificationAssertionEngine
from app.services.hmair.adv.contracts import DiscoveryStage, VerificationOutcome
from app.services.hmair.adv.planner import VerificationPlanner
from app.services.hmair.adv.projection import VerificationProjectionService
from app.services.hmair.adv.results import VerificationResultValidator
from app.services.hmair.verification_service import claim_verification_task
from test_adv_planner import NOW, _db, _scenario
from test_adv_results import WORKER_ID, _collector_integrity


def _plan(db):
    seed, evaluation_id, ecosystem_id = _scenario(db)
    plan = VerificationPlanner().start(
        db,
        tenant_id=seed["tenant_id"],
        ecosystem_id=ecosystem_id,
        hypothesis_evaluation_id=evaluation_id,
        environment="production",
        trigger="hypothesis_created",
        triggered_at=NOW,
        idempotency_key="adv-assertion-plan",
    )
    return seed, ecosystem_id, plan


def test_incomplete_required_proof_never_promotes_verified() -> None:
    db = _db()
    try:
        seed, ecosystem_id, plan = _plan(db)
        task = claim_verification_task(
            db,
            tenant_id=seed["tenant_id"],
            task_id=plan.tasks[0].task_id,
            worker_id=WORKER_ID,
            now=NOW + timedelta(seconds=1),
        )
        VerificationResultValidator().accept(
            db,
            tenant_id=seed["tenant_id"],
            task_id=task.task_id,
            worker_id=WORKER_ID,
            outcome=VerificationOutcome.VERIFIED,
            evidence_node_ids=(seed["node_id"],),
            observed_at=NOW,
            validated_at=NOW + timedelta(seconds=2),
            limitations=(),
            idempotency_key="adv-assertion-unverified-integrity",
        )
        assertion = VerificationAssertionEngine().evaluate(
            db,
            tenant_id=seed["tenant_id"],
            episode_id=plan.episode.episode_id,
            evaluated_at=NOW + timedelta(seconds=10),
            idempotency_key="adv-assertion-incomplete",
        )
        assert assertion.conclusion == "incomplete"
        assert assertion.required_verified_count == 0
        projection = VerificationProjectionService().get(
            db,
            tenant_id=seed["tenant_id"],
            ecosystem_id=ecosystem_id,
            evaluated_at=NOW + timedelta(seconds=11),
        )
        assert projection.stage is DiscoveryStage.VERIFICATION
        assert projection.required_outcomes == (VerificationOutcome.UNKNOWN,)
    finally:
        db.close()
        db.bind.dispose()


def test_complete_required_proof_promotes_and_optional_unsupported_is_visible() -> None:
    db = _db()
    try:
        seed, ecosystem_id, plan = _plan(db)
        integrity = _collector_integrity(db, seed["tenant_id"], suffix="assertions")
        task = claim_verification_task(
            db,
            tenant_id=seed["tenant_id"],
            task_id=plan.tasks[0].task_id,
            worker_id=WORKER_ID,
            now=NOW + timedelta(seconds=1),
        )
        VerificationResultValidator().accept(
            db,
            tenant_id=seed["tenant_id"],
            task_id=task.task_id,
            worker_id=WORKER_ID,
            outcome=VerificationOutcome.VERIFIED,
            evidence_node_ids=(seed["node_id"],),
            observed_at=NOW,
            validated_at=NOW + timedelta(seconds=2),
            limitations=(),
            idempotency_key="adv-assertion-verified-result",
            collector_integrity_ref=integrity.snapshot_id,
        )
        assertion = VerificationAssertionEngine().evaluate(
            db,
            tenant_id=seed["tenant_id"],
            episode_id=plan.episode.episode_id,
            evaluated_at=NOW + timedelta(seconds=10),
            idempotency_key="adv-assertion-verified",
        )
        assert assertion.conclusion == "verified"
        assert assertion.required_verified_count == assertion.required_requirement_count == 1
        assert assertion.optional_verified_count == 0
        assert assertion.verification_quality == 1.0

        projection = VerificationProjectionService().get(
            db,
            tenant_id=seed["tenant_id"],
            ecosystem_id=ecosystem_id,
            evaluated_at=NOW + timedelta(seconds=11),
        )
        assert projection.stage is DiscoveryStage.CONTINUOUSLY_VALIDATED
        assert projection.required_outcomes == (VerificationOutcome.VERIFIED,)
        assert projection.optional_outcomes == (VerificationOutcome.UNSUPPORTED,)
        assert projection.erg_evaluation_id == plan.episode.hypothesis_evaluation_id
        assert projection.confidence is not None
    finally:
        db.close()
        db.bind.dispose()
