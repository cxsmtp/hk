from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routers.discovery_adv import router as adv_router
from app.core.config import settings
from app.core.tenant import require_tenant
from app.db.session import get_db
from app.services.hmair.adv.assertions import VerificationAssertionEngine
from app.services.hmair.adv.planner import VerificationPlanner
from app.services.hmair.adv.policy import create_verification_policy
from test_adv_planner import _db, _scenario
from test_adv_policy import _requirements


def _ctx(tenant_id: str, role: str = "owner") -> SimpleNamespace:
    return SimpleNamespace(
        tenant=SimpleNamespace(id=tenant_id),
        user=SimpleNamespace(id="adv-api-owner"),
        role=role,
    )


def _client(db, context: dict[str, object]) -> TestClient:
    app = FastAPI()
    app.include_router(adv_router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_tenant] = lambda: context["ctx"]
    return TestClient(app)


def _activate_current_policy(db, tenant_id: str, now: datetime) -> None:
    create_verification_policy(
        db,
        tenant_id=tenant_id,
        policy_id="coding-production",
        version=2,
        ecosystem_classes=("coding",),
        environments=("production",),
        minimum_evidence_quality=0.8,
        minimum_confidence=0.85,
        minimum_source_diversity=1,
        assertion_ttl_seconds=3600,
        rescan_interval_seconds=1800,
        effective_from=now - timedelta(minutes=1),
        effective_until=now + timedelta(days=1),
        requirements=_requirements(),
        actor_id="adv-api-owner",
        idempotency_key="adv-api-current-policy",
    )


def test_adv_api_reads_derived_projection_and_tenant_scoped_history(monkeypatch) -> None:
    monkeypatch.setattr(settings, "cie_core", True)
    db = _db()
    try:
        seed, evaluation_id, ecosystem_id = _scenario(db)
        now = datetime.now(timezone.utc)
        _activate_current_policy(db, seed["tenant_id"], now)
        plan = VerificationPlanner().start(
            db,
            tenant_id=seed["tenant_id"],
            ecosystem_id=ecosystem_id,
            hypothesis_evaluation_id=evaluation_id,
            environment="production",
            trigger="hypothesis_created",
            triggered_at=now,
            idempotency_key="adv-api-read-plan",
        )
        VerificationAssertionEngine().evaluate(
            db,
            tenant_id=seed["tenant_id"],
            episode_id=plan.episode.episode_id,
            evaluated_at=now + timedelta(seconds=10),
            idempotency_key="adv-api-read-assertion",
        )
        db.commit()

        context = {"ctx": _ctx(seed["tenant_id"], "viewer")}
        client = _client(db, context)
        projection = client.get(
            f"/discovery/evidence-resolution/ecosystems/{ecosystem_id}/verification"
        )
        assert projection.status_code == 200
        body = projection.json()
        assert body["stage"] == "verification"
        assert body["confidence"] is not None
        assert body["verification_coverage"] == 0.0
        assert body["required_outcomes"] == ["unknown"]
        assert body["optional_outcomes"] == ["unsupported"]

        history = client.get(
            f"/discovery/evidence-resolution/ecosystems/{ecosystem_id}/verification/history"
        )
        assert history.status_code == 200
        assert history.json()["episodes"][0]["episode_id"] == plan.episode.episode_id
        assert history.json()["results"][0]["outcome"] == "unsupported"
        assert history.json()["assertions"][0]["conclusion"] == "incomplete"

        context["ctx"] = _ctx("00000000-0000-0000-0000-000000000099", "viewer")
        assert client.get(
            f"/discovery/evidence-resolution/ecosystems/{ecosystem_id}/verification"
        ).status_code == 404
        assert client.get(
            f"/discovery/evidence-resolution/ecosystems/{ecosystem_id}/verification/history"
        ).status_code == 404
    finally:
        db.close()
        db.bind.dispose()


def test_adv_api_owner_starts_and_evaluates_idempotently_viewer_cannot_mutate(monkeypatch) -> None:
    monkeypatch.setattr(settings, "cie_core", True)
    db = _db()
    try:
        seed, evaluation_id, ecosystem_id = _scenario(db)
        _activate_current_policy(db, seed["tenant_id"], datetime.now(timezone.utc))
        context = {"ctx": _ctx(seed["tenant_id"], "viewer")}
        client = _client(db, context)
        request = {
            "hypothesis_evaluation_id": evaluation_id,
            "environment": "production",
            "trigger": "manual_verification",
            "idempotency_key": "adv-api-start-plan",
        }
        assert client.post(
            f"/discovery/evidence-resolution/ecosystems/{ecosystem_id}/verification/start",
            json=request,
        ).status_code == 403

        context["ctx"] = _ctx(seed["tenant_id"], "owner")
        started = client.post(
            f"/discovery/evidence-resolution/ecosystems/{ecosystem_id}/verification/start",
            json=request,
        )
        assert started.status_code == 200
        assert started.json()["task_count"] == 1
        assert started.json()["unsupported_requirement_ids"] == ["network_usage"]
        replay = client.post(
            f"/discovery/evidence-resolution/ecosystems/{ecosystem_id}/verification/start",
            json=request,
        )
        assert replay.status_code == 200
        assert replay.json() == started.json()

        episode_id = started.json()["episode_id"]
        evaluated = client.post(
            f"/discovery/evidence-resolution/verification/episodes/{episode_id}/evaluate",
            json={"idempotency_key": "adv-api-evaluate-plan"},
        )
        assert evaluated.status_code == 200
        assert evaluated.json()["conclusion"] == "incomplete"
        replayed = client.post(
            f"/discovery/evidence-resolution/verification/episodes/{episode_id}/evaluate",
            json={"idempotency_key": "adv-api-evaluate-plan"},
        )
        assert replayed.status_code == 200
        assert replayed.json() == evaluated.json()

        episodes = client.get(
            f"/discovery/evidence-resolution/ecosystems/{ecosystem_id}/verification/episodes"
        )
        assert episodes.status_code == 200
        assert episodes.json()[0]["episode_id"] == episode_id
        detail = client.get(
            f"/discovery/evidence-resolution/verification/episodes/{episode_id}"
        )
        assert detail.status_code == 200
        assert detail.json()["episode"]["episode_id"] == episode_id

        retried = client.post(
            f"/discovery/evidence-resolution/verification/episodes/{episode_id}/retry",
            json={"idempotency_key": "adv-api-retry-plan"},
        )
        assert retried.status_code == 200
        assert retried.json()["episode_id"] != episode_id
        cancelled = client.post(
            f"/discovery/evidence-resolution/verification/episodes/{retried.json()['episode_id']}/cancel",
            json={
                "idempotency_key": "adv-api-cancel-plan",
                "reason": "Operator cancelled the bounded verification retry",
            },
        )
        assert cancelled.status_code == 200
        assert cancelled.json()["cancelled_task_count"] == 1

        policies = client.get(
            "/discovery/evidence-resolution/verification/policies"
        )
        assert policies.status_code == 200
        assert policies.json()[0]["policy_id"] == "coding-production"
        future = datetime.now(timezone.utc) + timedelta(days=2)
        created_policy = client.post(
            "/discovery/evidence-resolution/verification/policies",
            json={
                "policy_id": "coding-production",
                "version": 3,
                "ecosystem_classes": ["coding"],
                "environments": ["production"],
                "minimum_evidence_quality": 0.8,
                "minimum_confidence": 0.85,
                "minimum_source_diversity": 1,
                "assertion_ttl_seconds": 3600,
                "rescan_interval_seconds": 1800,
                "effective_from": future.isoformat(),
                "effective_until": None,
                "requirements": _requirements(),
                "idempotency_key": "adv-api-owner-policy-create",
            },
        )
        assert created_policy.status_code == 200, created_policy.text
        assert created_policy.json()["version"] == 3

        context["ctx"] = _ctx(seed["tenant_id"], "viewer")
        assert client.post(
            f"/discovery/evidence-resolution/verification/episodes/{episode_id}/evaluate",
            json={"idempotency_key": "viewer-must-not-evaluate"},
        ).status_code == 403
        assert client.post(
            "/discovery/evidence-resolution/verification/policies",
            json={
                "policy_id": "viewer-denied",
                "version": 1,
                "ecosystem_classes": ["coding"],
                "environments": ["production"],
                "minimum_evidence_quality": 0.8,
                "minimum_confidence": 0.85,
                "minimum_source_diversity": 1,
                "assertion_ttl_seconds": 3600,
                "rescan_interval_seconds": 1800,
                "effective_from": datetime.now(timezone.utc).isoformat(),
                "effective_until": None,
                "requirements": _requirements(),
                "idempotency_key": "adv-api-viewer-policy-denied",
            },
        ).status_code == 403
    finally:
        db.close()
        db.bind.dispose()
