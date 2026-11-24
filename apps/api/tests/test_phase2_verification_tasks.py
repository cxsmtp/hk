from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.session import Base
from app.services.hmair.hypothesis_service import create_hypothesis
from app.services.hmair.verification_service import (
    VerificationTaskConflict,
    claim_verification_task,
    complete_verification_task,
    enqueue_verification_task,
)
from test_phase2_resolution_graph import _seed_tenant


NOW = datetime(2026, 8, 15, 10, 0, tzinfo=timezone.utc)


@pytest.fixture
def db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine, autoflush=False, expire_on_commit=False)
    try:
        yield session
    finally:
        session.rollback()
        session.close()
        engine.dispose()


def _hypothesis(db: Session) -> tuple[str, str, str]:
    tenant_id, evidence_id = _seed_tenant(db, "verification")
    row = create_hypothesis(
        db,
        tenant_id=tenant_id,
        hypothesis_type="ai_application",
        label="Candidate coding assistant",
        candidate_key_hash="b" * 64,
        confidence=0.6,
        verification_state="partially_verified",
        freshness="fresh",
        contradiction_state="none",
        evidence_node_id=evidence_id,
        observed_at=NOW,
        idempotency_key="verification-hypothesis",
    )
    return tenant_id, evidence_id, row.hypothesis_id


def test_verification_tasks_are_bounded_safe_and_idempotent(db: Session) -> None:
    tenant_id, evidence_id, hypothesis_id = _hypothesis(db)
    task = enqueue_verification_task(
        db,
        tenant_id=tenant_id,
        hypothesis_id=hypothesis_id,
        task_type="endpoint_confirm",
        method="process_metadata",
        scope={"device_ref": "managed-device-fingerprint"},
        rate_limit_key="endpoint:managed-device-fingerprint",
        priority=50,
        max_attempts=2,
        expires_at=NOW + timedelta(minutes=15),
        idempotency_key="verify-endpoint-a",
        now=NOW,
    )
    replay = enqueue_verification_task(
        db,
        tenant_id=tenant_id,
        hypothesis_id=hypothesis_id,
        task_type="endpoint_confirm",
        method="process_metadata",
        scope={"device_ref": "managed-device-fingerprint"},
        rate_limit_key="endpoint:managed-device-fingerprint",
        priority=50,
        max_attempts=2,
        expires_at=NOW + timedelta(minutes=15),
        idempotency_key="verify-endpoint-a",
        now=NOW,
    )
    assert replay.task_id == task.task_id

    claimed = claim_verification_task(
        db,
        tenant_id=tenant_id,
        task_id=task.task_id,
        worker_id="endpoint-agent-fingerprint",
        now=NOW + timedelta(seconds=1),
    )
    assert claimed.status == "claimed"
    completed = complete_verification_task(
        db,
        tenant_id=tenant_id,
        task_id=task.task_id,
        worker_id="endpoint-agent-fingerprint",
        outcome="succeeded",
        evidence_node_id=evidence_id,
        limitations=(),
        now=NOW + timedelta(seconds=2),
    )
    assert completed.status == "succeeded"
    assert completed.result_evidence_node_id == evidence_id


def test_verification_rejects_destructive_and_expired_work(db: Session) -> None:
    tenant_id, _evidence_id, hypothesis_id = _hypothesis(db)
    with pytest.raises(VerificationTaskConflict):
        enqueue_verification_task(
            db,
            tenant_id=tenant_id,
            hypothesis_id=hypothesis_id,
            task_type="endpoint_confirm",
            method="shell_execute",
            scope={"command": "delete"},
            rate_limit_key="endpoint:unsafe",
            priority=50,
            max_attempts=1,
            expires_at=NOW + timedelta(minutes=1),
            idempotency_key="verify-unsafe",
            now=NOW,
        )
    with pytest.raises(VerificationTaskConflict):
        enqueue_verification_task(
            db,
            tenant_id=tenant_id,
            hypothesis_id=hypothesis_id,
            task_type="endpoint_confirm",
            method="process_metadata",
            scope={},
            rate_limit_key="endpoint:expired",
            priority=50,
            max_attempts=1,
            expires_at=NOW,
            idempotency_key="verify-expired",
            now=NOW,
        )

