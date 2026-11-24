from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from sqlalchemy import func, select

from app.db.models.discovery_resolution import DiscoveryResolutionGraphEdge
from app.db.models.discovery_verification import (
    DiscoveryVerificationAttempt,
    DiscoveryVerificationEvent,
    DiscoveryVerificationResult,
)
from app.services.hmair.adv.contracts import VerificationOutcome
from app.services.hmair.adv.planner import VerificationPlanner
from app.services.hmair.adv.reconciler import VerificationEvidenceReconciler
from app.services.hmair.adv.results import (
    VerificationResultConflict,
    VerificationResultValidator,
)
from app.services.hmair.erg.evidence_quality import EvidenceQualitySnapshots
from app.services.hmair.verification_service import claim_verification_task
from test_adv_planner import NOW, _db, _scenario


WORKER_ID = "collector:collector-adv-planner"


def _collector_integrity(
    db,
    tenant_id: str,
    *,
    freshness: str = "fresh",
    signature_state: str = "verified",
    suffix: str = "verified",
    calculated_at: datetime = NOW,
):
    return EvidenceQualitySnapshots().record_collector(
        db,
        tenant_id=tenant_id,
        collector_id="collector-adv-planner",
        input_count=1,
        validated_count=1,
        freshness=freshness,
        signature_state=signature_state,
        calculated_at=calculated_at,
        idempotency_key=f"adv-result-collector-integrity-{suffix}",
    )


def _claimed_task(db):
    seed, evaluation_id, ecosystem_id = _scenario(db)
    plan = VerificationPlanner().start(
        db,
        tenant_id=seed["tenant_id"],
        ecosystem_id=ecosystem_id,
        hypothesis_evaluation_id=evaluation_id,
        environment="production",
        trigger="hypothesis_created",
        triggered_at=NOW,
        idempotency_key="adv-result-plan",
    )
    task = claim_verification_task(
        db,
        tenant_id=seed["tenant_id"],
        task_id=plan.tasks[0].task_id,
        worker_id=WORKER_ID,
        now=NOW + timedelta(seconds=1),
    )
    return seed, plan, task


def test_verified_result_without_collector_integrity_cannot_satisfy_requirement() -> None:
    db = _db()
    try:
        seed, _, task = _claimed_task(db)
        result = VerificationResultValidator().accept(
            db,
            tenant_id=seed["tenant_id"],
            task_id=task.task_id,
            worker_id=WORKER_ID,
            outcome=VerificationOutcome.VERIFIED,
            evidence_node_ids=(seed["node_id"],),
            observed_at=NOW,
            validated_at=NOW + timedelta(seconds=2),
            limitations=(),
            idempotency_key="adv-result-unverified-integrity",
        )
        assert result.outcome == "unknown"
        assert result.integrity_state == "unknown"
        assert result.satisfies_requirement is False
        assert "collector_integrity_unverified" in result.limitations_json
    finally:
        db.close()
        db.bind.dispose()


def test_result_rejects_expired_collector_integrity_snapshot() -> None:
    db = _db()
    try:
        seed, _, task = _claimed_task(db)
        integrity = _collector_integrity(
            db,
            seed["tenant_id"],
            suffix="expired",
            calculated_at=NOW - timedelta(hours=2),
        )
        with pytest.raises(VerificationResultConflict, match="collector integrity"):
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
                idempotency_key="adv-result-expired-integrity",
                collector_integrity_ref=integrity.snapshot_id,
            )
    finally:
        db.close()
        db.bind.dispose()


def test_verified_result_separates_attempt_and_reuses_canonical_evidence() -> None:
    db = _db()
    try:
        seed, plan, task = _claimed_task(db)
        integrity = _collector_integrity(db, seed["tenant_id"])
        before_edges = db.scalar(select(func.count(DiscoveryResolutionGraphEdge.edge_id)))
        result = VerificationResultValidator().accept(
            db,
            tenant_id=seed["tenant_id"],
            task_id=task.task_id,
            worker_id=WORKER_ID,
            outcome=VerificationOutcome.VERIFIED,
            evidence_node_ids=(seed["node_id"],),
            observed_at=NOW,
            validated_at=NOW + timedelta(seconds=2),
            limitations=(),
            idempotency_key="adv-result-verified",
            collector_integrity_ref=integrity.snapshot_id,
        )
        assert result.outcome == "verified"
        assert result.satisfies_requirement is True
        assert result.integrity_state == "verified"
        assert task.status == "succeeded"
        attempt = db.get(DiscoveryVerificationAttempt, result.attempt_id)
        assert attempt.execution_state == "completed"
        assert attempt.output_digest is not None

        replay = VerificationResultValidator().accept(
            db,
            tenant_id=seed["tenant_id"],
            task_id=task.task_id,
            worker_id=WORKER_ID,
            outcome=VerificationOutcome.VERIFIED,
            evidence_node_ids=(seed["node_id"],),
            observed_at=NOW,
            validated_at=NOW + timedelta(seconds=2),
            limitations=(),
            idempotency_key="adv-result-verified",
            collector_integrity_ref=integrity.snapshot_id,
        )
        assert replay.result_id == result.result_id

        event = VerificationEvidenceReconciler().reconcile(
            db,
            tenant_id=seed["tenant_id"],
            result_id=result.result_id,
            reconciled_at=NOW + timedelta(seconds=3),
            idempotency_key="adv-result-reconcile",
        )
        assert event.event_type == "evidence_added"
        assert db.scalar(select(func.count(DiscoveryResolutionGraphEdge.edge_id))) == before_edges
    finally:
        db.close()
        db.bind.dispose()


def test_completed_transport_can_return_unsupported_without_evidence() -> None:
    db = _db()
    try:
        seed, _, task = _claimed_task(db)
        result = VerificationResultValidator().accept(
            db,
            tenant_id=seed["tenant_id"],
            task_id=task.task_id,
            worker_id=WORKER_ID,
            outcome=VerificationOutcome.UNSUPPORTED,
            evidence_node_ids=(),
            observed_at=NOW,
            validated_at=NOW + timedelta(seconds=2),
            limitations=("provider_method_unavailable",),
            idempotency_key="adv-result-unsupported",
        )
        assert result.outcome == "unsupported"
        assert result.satisfies_requirement is False
        assert task.status == "succeeded"
    finally:
        db.close()
        db.bind.dispose()


def test_transport_failure_is_unknown_not_contradiction() -> None:
    db = _db()
    try:
        seed, _, task = _claimed_task(db)
        result = VerificationResultValidator().accept(
            db,
            tenant_id=seed["tenant_id"],
            task_id=task.task_id,
            worker_id=WORKER_ID,
            outcome=VerificationOutcome.UNKNOWN,
            evidence_node_ids=(),
            observed_at=NOW,
            validated_at=NOW + timedelta(seconds=2),
            limitations=("collector_unreachable",),
            idempotency_key="adv-result-outage",
            execution_state="transport_failed",
        )
        assert result.outcome == "unknown"
        assert task.status == "failed"
        assert db.get(DiscoveryVerificationAttempt, result.attempt_id).execution_state == "transport_failed"
    finally:
        db.close()
        db.bind.dispose()


def test_result_rejects_wrong_worker_and_unsubstantiated_contradiction() -> None:
    db = _db()
    try:
        seed, _, task = _claimed_task(db)
        validator = VerificationResultValidator()
        with pytest.raises(VerificationResultConflict, match="worker"):
            validator.accept(
                db,
                tenant_id=seed["tenant_id"], task_id=task.task_id,
                worker_id="collector:wrong", outcome=VerificationOutcome.UNKNOWN,
                evidence_node_ids=(), observed_at=NOW,
                validated_at=NOW + timedelta(seconds=2), limitations=(),
                idempotency_key="adv-result-wrong-worker",
            )
        with pytest.raises(VerificationResultConflict, match="evidence"):
            validator.accept(
                db,
                tenant_id=seed["tenant_id"], task_id=task.task_id,
                worker_id=WORKER_ID,
                outcome=VerificationOutcome.CONTRADICTED,
                evidence_node_ids=(), observed_at=NOW,
                validated_at=NOW + timedelta(seconds=2), limitations=(),
                idempotency_key="adv-result-no-evidence",
            )
        assert db.scalar(select(func.count(DiscoveryVerificationAttempt.attempt_id))) == 0
        assert db.scalar(
            select(func.count(DiscoveryVerificationEvent.event_id))
        ) == 1
        assert db.scalar(select(DiscoveryVerificationEvent.event_type)) == "verification_started"
    finally:
        db.close()
        db.bind.dispose()


@pytest.mark.parametrize(
    ("freshness", "signature_state"),
    (("stale", "verified"), ("fresh", "unknown")),
)
def test_result_rejects_untrusted_collector_integrity_snapshot(
    freshness: str,
    signature_state: str,
) -> None:
    db = _db()
    try:
        seed, _, task = _claimed_task(db)
        integrity = _collector_integrity(
            db,
            seed["tenant_id"],
            freshness=freshness,
            signature_state=signature_state,
            suffix=f"{freshness}-{signature_state}",
        )
        with pytest.raises(VerificationResultConflict, match="collector integrity"):
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
                idempotency_key=f"adv-result-bad-integrity-{freshness}-{signature_state}",
                collector_integrity_ref=integrity.snapshot_id,
            )
    finally:
        db.close()
        db.bind.dispose()
