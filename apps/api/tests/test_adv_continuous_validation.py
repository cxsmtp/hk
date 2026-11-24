from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app.db.models.discovery_verification import (
    DiscoveryVerificationEpisode,
    DiscoveryVerificationEvent,
)
from app.services.hmair.adv.assertions import VerificationAssertionEngine
from app.services.hmair.adv.continuous_validation import (
    SUPPORTED_DRIFT_CATEGORIES,
    ContinuousValidationService,
)
from app.services.hmair.adv.contracts import VerificationOutcome
from app.services.hmair.adv.planner import VerificationPlanner
from app.services.hmair.adv.results import VerificationResultValidator
from app.services.hmair.erg.evidence_timeline import EvidenceTimeline
from app.jobs.celery_app import celery_app
from app.services.hmair.verification_service import claim_verification_task
from test_adv_planner import NOW, _db, _scenario
from test_adv_results import WORKER_ID, _collector_integrity


def _verified_scenario(db):
    seed, evaluation_id, ecosystem_id = _scenario(db)
    plan = VerificationPlanner().start(
        db,
        tenant_id=seed["tenant_id"], ecosystem_id=ecosystem_id,
        hypothesis_evaluation_id=evaluation_id, environment="production",
        trigger="hypothesis_created", triggered_at=NOW,
        idempotency_key="adv-continuous-plan",
    )
    integrity = _collector_integrity(db, seed["tenant_id"], suffix="continuous")
    task = claim_verification_task(
        db, tenant_id=seed["tenant_id"], task_id=plan.tasks[0].task_id,
        worker_id=WORKER_ID, now=NOW + timedelta(seconds=1),
    )
    VerificationResultValidator().accept(
        db, tenant_id=seed["tenant_id"], task_id=task.task_id,
        worker_id=WORKER_ID, outcome=VerificationOutcome.VERIFIED,
        evidence_node_ids=(seed["node_id"],), observed_at=NOW,
        validated_at=NOW + timedelta(seconds=2), limitations=(),
        idempotency_key="adv-continuous-result",
        collector_integrity_ref=integrity.snapshot_id,
    )
    assertion = VerificationAssertionEngine().evaluate(
        db, tenant_id=seed["tenant_id"], episode_id=plan.episode.episode_id,
        evaluated_at=NOW + timedelta(seconds=10),
        idempotency_key="adv-continuous-assertion",
    )
    return seed, ecosystem_id, plan, assertion


def test_due_revalidation_is_bounded_and_deduplicated() -> None:
    db = _db()
    try:
        seed, ecosystem_id, first, _ = _verified_scenario(db)
        service = ContinuousValidationService()
        due_at = NOW + timedelta(seconds=1811)
        due = service.list_due(
            db, tenant_id=seed["tenant_id"], evaluated_at=due_at, limit=10
        )
        assert [(item.ecosystem_id, item.reason) for item in due] == [
            (ecosystem_id, "rescan_due")
        ]
        created = service.schedule_due(
            db, tenant_id=seed["tenant_id"], evaluated_at=due_at, limit=10
        )
        assert len(created) == 1
        assert created[0].episode.episode_sequence == first.episode.episode_sequence + 1
        assert created[0].episode.predecessor_episode_id == first.episode.episode_id

        replay = service.schedule_due(
            db, tenant_id=seed["tenant_id"], evaluated_at=due_at, limit=10
        )
        assert replay == ()
        assert db.scalar(
            select(func.count(DiscoveryVerificationEpisode.episode_id)).where(
                DiscoveryVerificationEpisode.tenant_id == seed["tenant_id"]
            )
        ) == 2
    finally:
        db.close()
        db.bind.dispose()


def test_completed_episode_is_asserted_automatically_without_manual_promotion() -> None:
    db = _db()
    try:
        seed, evaluation_id, ecosystem_id = _scenario(db)
        plan = VerificationPlanner().start(
            db,
            tenant_id=seed["tenant_id"], ecosystem_id=ecosystem_id,
            hypothesis_evaluation_id=evaluation_id, environment="production",
            trigger="hypothesis_created", triggered_at=NOW,
            idempotency_key="adv-auto-assert-plan",
        )
        integrity = _collector_integrity(
            db, seed["tenant_id"], suffix="auto-assert"
        )
        task = claim_verification_task(
            db, tenant_id=seed["tenant_id"], task_id=plan.tasks[0].task_id,
            worker_id=WORKER_ID, now=NOW + timedelta(seconds=1),
        )
        VerificationResultValidator().accept(
            db, tenant_id=seed["tenant_id"], task_id=task.task_id,
            worker_id=WORKER_ID, outcome=VerificationOutcome.VERIFIED,
            evidence_node_ids=(seed["node_id"],), observed_at=NOW,
            validated_at=NOW + timedelta(seconds=2), limitations=(),
            idempotency_key="adv-auto-assert-result",
            collector_integrity_ref=integrity.snapshot_id,
        )
        service = ContinuousValidationService()
        created = service.evaluate_ready(
            db, tenant_id=seed["tenant_id"], evaluated_at=NOW + timedelta(seconds=5)
        )
        assert len(created) == 1
        assert created[0].conclusion == "verified"
        assert service.evaluate_ready(
            db, tenant_id=seed["tenant_id"], evaluated_at=NOW + timedelta(seconds=6)
        ) == ()
    finally:
        db.close()
        db.bind.dispose()


def test_drift_revalidation_binds_trigger_and_is_idempotent() -> None:
    db = _db()
    try:
        seed, ecosystem_id, first, _ = _verified_scenario(db)
        service = ContinuousValidationService()
        created = service.schedule_for_drift(
            db,
            tenant_id=seed["tenant_id"], ecosystem_id=ecosystem_id,
            hypothesis_evaluation_id=first.episode.hypothesis_evaluation_id,
            environment="production", drift_event_id="capability-drift-1",
            triggered_at=NOW + timedelta(minutes=5),
        )
        replay = service.schedule_for_drift(
            db,
            tenant_id=seed["tenant_id"], ecosystem_id=ecosystem_id,
            hypothesis_evaluation_id=first.episode.hypothesis_evaluation_id,
            environment="production", drift_event_id="capability-drift-1",
            triggered_at=NOW + timedelta(minutes=5),
        )
        assert replay.episode.episode_id == created.episode.episode_id
        assert created.episode.trigger == "drift"
        assert created.episode.trigger_event_id == "capability-drift-1"
        assert db.scalar(
            select(func.count(DiscoveryVerificationEvent.event_id)).where(
                DiscoveryVerificationEvent.event_type == "verification_updated"
            )
        ) == 1
    finally:
        db.close()
        db.bind.dispose()


@pytest.mark.parametrize("drift_category", sorted(SUPPORTED_DRIFT_CATEGORIES))
def test_every_approved_drift_category_routes_to_reverification(
    drift_category: str,
) -> None:
    db = _db()
    try:
        seed, ecosystem_id, first, _ = _verified_scenario(db)
        event_id = f"{drift_category}-event"
        created = ContinuousValidationService().schedule_for_drift(
            db,
            tenant_id=seed["tenant_id"], ecosystem_id=ecosystem_id,
            hypothesis_evaluation_id=first.episode.hypothesis_evaluation_id,
            environment="production", drift_event_id=event_id,
            drift_category=drift_category,
            triggered_at=NOW + timedelta(minutes=5),
        )
        assert created.episode.trigger == "drift"
        assert created.episode.trigger_event_id == event_id
    finally:
        db.close()
        db.bind.dispose()


def test_verification_events_join_existing_timeline_and_scheduler_is_registered() -> None:
    db = _db()
    try:
        seed, ecosystem_id, _, _ = _verified_scenario(db)
        timeline = EvidenceTimeline().list(db, tenant_id=seed["tenant_id"])
        verification = [item for item in timeline if item.source_type == "verification_event"]
        assert verification
        assert all(ecosystem_id in item.ecosystem_ids for item in verification)
        assert (
            celery_app.conf.beat_schedule["adv-continuous-validation-every-five-minutes"][
                "task"
            ]
            == "app.jobs.discovery_verification_jobs.enqueue_due_discovery_verifications"
        )
        assert celery_app.conf.task_routes[
            "app.jobs.discovery_verification_jobs.run_due_discovery_verifications"
        ] == {"queue": "discovery"}
    finally:
        db.close()
        db.bind.dispose()
