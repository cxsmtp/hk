from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.services.hmair.adv.contracts import VerificationOutcome
from app.services.hmair.adv.policy import VerificationPolicyConflict, create_verification_policy
from app.services.hmair.adv.results import (
    VerificationResultConflict,
    VerificationResultValidator,
)
from app.services.hmair.verification_service import (
    VerificationTaskConflict,
    enqueue_verification_task,
)
from test_adv_api import _activate_current_policy, _client, _ctx
from test_adv_policy import _requirements
from test_adv_results import NOW, WORKER_ID, _claimed_task
from test_adv_planner import _db, _scenario


def test_stale_wrong_tenant_and_mutated_task_authority_are_rejected() -> None:
    db = _db()
    try:
        seed, _, task = _claimed_task(db)
        validator = VerificationResultValidator()
        with pytest.raises(VerificationResultConflict, match="unavailable"):
            validator.accept(
                db,
                tenant_id="00000000-0000-0000-0000-000000000099",
                task_id=task.task_id, worker_id="collector:endpoint:v1",
                outcome=VerificationOutcome.UNKNOWN, evidence_node_ids=(),
                observed_at=NOW, validated_at=NOW + timedelta(seconds=2),
                limitations=(), idempotency_key="adv-security-cross-tenant",
            )
        with pytest.raises(VerificationResultConflict, match="stale"):
            validator.accept(
                db,
                tenant_id=seed["tenant_id"], task_id=task.task_id,
                worker_id=WORKER_ID,
                outcome=VerificationOutcome.UNKNOWN, evidence_node_ids=(),
                observed_at=NOW,
                validated_at=task.expires_at.replace(tzinfo=timezone.utc)
                + timedelta(seconds=1),
                limitations=(), idempotency_key="adv-security-stale",
            )
        task.method = "arbitrary_shell"
        with pytest.raises(VerificationResultConflict, match="authority binding"):
            validator.accept(
                db,
                tenant_id=seed["tenant_id"], task_id=task.task_id,
                worker_id=WORKER_ID,
                outcome=VerificationOutcome.UNKNOWN, evidence_node_ids=(),
                observed_at=NOW, validated_at=NOW + timedelta(seconds=2),
                limitations=(), idempotency_key="adv-security-mutated-task",
            )
    finally:
        db.close()
        db.bind.dispose()


@pytest.mark.parametrize(
    "scope",
    (
        {"api_token": "must-never-enter-verification-scope"},
        {"safe_reference": "x" * 1025},
        {"a": {"b": {"c": {"d": {"e": {"f": {"g": 1}}}}}}},
    ),
)
def test_verification_work_rejects_sensitive_oversized_or_unbounded_scope(scope) -> None:
    db = _db()
    try:
        seed, _, claimed_task = _claimed_task(db)
        with pytest.raises(VerificationTaskConflict):
            enqueue_verification_task(
                db,
                tenant_id=seed["tenant_id"],
                hypothesis_id=claimed_task.hypothesis_id,
                task_type="endpoint_confirm", method="endpoint_metadata",
                scope=scope, rate_limit_key="adv-security-scope",
                priority=50, max_attempts=1,
                expires_at=NOW + timedelta(minutes=5),
                idempotency_key="adv-security-scope", now=NOW,
            )
    finally:
        db.close()
        db.bind.dispose()


def test_policy_rejects_control_characters_in_security_identifiers() -> None:
    db = _db()
    try:
        seed, _, _ = _scenario(db)
        bad = list(_requirements())
        bad[0] = {**bad[0], "requirement_id": "endpoint\x00identity"}
        with pytest.raises(VerificationPolicyConflict, match="identifier"):
            create_verification_policy(
                db,
                tenant_id=seed["tenant_id"], policy_id="bad-control-char", version=1,
                ecosystem_classes=("coding",), environments=("production",),
                minimum_evidence_quality=0.8, minimum_confidence=0.8,
                minimum_source_diversity=1, assertion_ttl_seconds=3600,
                rescan_interval_seconds=1800,
                effective_from=datetime.now(timezone.utc), effective_until=None,
                requirements=bad, actor_id="admin-1",
                idempotency_key="adv-security-control-character",
            )
    finally:
        db.close()
        db.bind.dispose()


def test_api_has_no_direct_verified_mutation_and_rejects_extra_stage_fields(monkeypatch) -> None:
    from app.core.config import settings

    monkeypatch.setattr(settings, "cie_core", True)
    db = _db()
    try:
        seed, evaluation_id, ecosystem_id = _scenario(db)
        _activate_current_policy(db, seed["tenant_id"], datetime.now(timezone.utc))
        context = {"ctx": _ctx(seed["tenant_id"], "owner")}
        client = _client(db, context)
        response = client.post(
            f"/discovery/evidence-resolution/ecosystems/{ecosystem_id}/verification/start",
            json={
                "hypothesis_evaluation_id": evaluation_id,
                "environment": "production",
                "trigger": "manual_verification",
                "idempotency_key": "adv-security-no-direct-promotion",
                "verified": True,
            },
        )
        assert response.status_code == 422
        paths = client.app.openapi()["paths"]
        assert not any(path.endswith("/verified") for path in paths)
        assert not any("set-verified" in path for path in paths)
    finally:
        db.close()
        db.bind.dispose()
