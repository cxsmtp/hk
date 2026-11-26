from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.finding import Finding
from app.db.models.ai_system import AISystem
from app.db.models.evidence import EvidenceNode
from app.db.models.knowledge_base import KBControl, KBFramework
from app.db.models.monitoring import Connector, MonitoringSignal
from app.db.models.remediation import RemediationAction
from app.db.models.runtime_intelligence import RuntimeEvent, RuntimeGovernanceRecommendation, RuntimeSimulationTrigger
from app.db.models.simulation import SimulationScheduleDecision
from app.db.session import Base, get_db
from app.main import app
from app.services import outbound_destination_policy
from app.jobs import monitoring_jobs
from app.services.monitoring_service import (
    connector_control_coverage,
    consume_runtime_intelligence_outputs,
    evaluate_scheduled_monitoring_remediation,
)
from ai_system_approval_helpers import approve_ai_system


PASSWORD = "Password123!"


@pytest.fixture(autouse=True)
def _mock_public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        outbound_destination_policy,
        "_system_resolver",
        lambda _hostname, _port: ("93.184.216.34",),
    )


class _FakeResponse:
    def __init__(self, payload, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("GET", "https://example.com")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("error", request=request, response=response)

    def json(self):
        return self._payload


class _FakeHTTPClient:
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def request(self, method: str, url: str, **kwargs):
        if method.upper() == "POST":
            return self.post(
                url,
                data=kwargs.get("data"),
                json=kwargs.get("json"),
                headers=kwargs.get("headers"),
            )
        return self.get(url, headers=kwargs.get("headers"))

    def get(self, url: str, headers=None):
        if "/organization/usage/completions" in url:
            return _FakeResponse({"data": [{"id": "cmp-1", "prompt_tokens": 12}]})
        if "/organization/usage/embeddings" in url:
            return _FakeResponse({"data": [{"id": "emb-1", "tokens": 33}]})
        if "/organization/costs" in url:
            return _FakeResponse({"data": [{"id": "cost-1", "amount": 99.0}]})
        return _FakeResponse({"data": []})

    def post(self, url: str, data=None, json=None, headers=None):
        return _FakeResponse({"access_token": "token-1"})


@pytest.fixture()
def test_env(tmp_path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "monitoring_backbone.sqlite3"
    artifact_dir = tmp_path / "artifacts"
    monkeypatch.setenv("ARTIFACT_DIR", str(artifact_dir))
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    testing_session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = testing_session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield {
            "client": client,
            "SessionLocal": testing_session_local,
            "tmp_path": tmp_path,
            "artifact_dir": artifact_dir,
        }
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Monitoring Owner"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    return {
        "access_token": payload["access_token"],
        "tenant_id": payload["tenants"][0]["id"],
    }


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "X-Tenant-ID": tenant_id,
    }


def _create_ai_system(client: TestClient, *, headers: dict[str, str], risk_tier: str = "HIGH") -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Monitoring Backbone AI", "description": "", "risk_tier": risk_tier},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    activate = approve_ai_system(client, headers, ai_system_id, status="active")
    assert activate.status_code == 200, activate.text
    return ai_system_id


def _approve_and_apply_remediation(client: TestClient, *, headers: dict[str, str], remediation_id: str) -> dict:
    approve = client.post(
        f"/findings/remediations/{remediation_id}/approve",
        headers=headers,
        json={"justification": "monitoring remediation approved"},
    )
    assert approve.status_code == 200, approve.text
    apply = client.post(
        f"/findings/remediations/{remediation_id}/apply",
        headers=headers,
        json={"justification": "monitoring remediation applied"},
    )
    assert apply.status_code == 200, apply.text
    return apply.json()


def test_monitoring_signal_creates_finding_and_simulation_schedule(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="monitoring-chain@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers)

    response = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "connector.config_drift",
            "severity": "high",
            "payload": {
                "ai_tool": "aws",
                "risk_category": "monitoring_drift",
                "related_control_ids": ["CTRL-TOOL-001"],
            },
        },
    )
    assert response.status_code == 200, response.text

    with session_local() as db:
        finding = db.scalar(
            select(Finding).where(
                Finding.tenant_id == owner["tenant_id"],
                Finding.finding_type == "drift_alert",
                Finding.ai_system_id == ai_system_id,
            )
        )
        assert finding is not None
        assert finding.severity in {"high", "critical"}

        decision = db.scalar(
            select(SimulationScheduleDecision).where(
                SimulationScheduleDecision.tenant_id == owner["tenant_id"],
                SimulationScheduleDecision.reason_code == "connector_drift_event",
                SimulationScheduleDecision.target_ai_system_id == ai_system_id,
            )
        )
        assert decision is not None
        assert decision.status in {"scheduled", "completed", "failed", "no_simulations"}


def test_runtime_intelligence_outputs_are_consumed_by_monitoring(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="monitoring-runtime-consume@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers)

    with session_local() as db:
        event = RuntimeEvent(
            tenant_id=owner["tenant_id"],
            source_surface="gateway",
            event_type="llm_intercept",
            ai_system_id=ai_system_id,
            app_id="llm_gateway",
            user_id="owner",
            agent_id=None,
            risk_tier="HIGH",
            policy_version_id=None,
            governance_version="g1",
            severity="high",
            confidence_tier="clear_negative",
            evidence_node_ids=[],
            correlation_id="corr-monitoring-1",
            metadata_json={"decision": "block"},
        )
        db.add(event)
        db.flush()

        finding = Finding(
            tenant_id=owner["tenant_id"],
            source_surface="gateway",
            ai_tool="llm_gateway",
            ai_system_id=ai_system_id,
            user_id=None,
            severity="high",
            finding_type="repeated_tool_denials",
            risk_category="agent_tooling",
            status="open",
            recommended_action="route_to_review",
            policy_version_id=None,
            evidence_node_ids=[],
            related_control_ids=["CTRL-TOOL-001"],
            dedupe_key="runtime-find-repeated_tool_denials",
            occurrence_count=3,
            first_seen_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
        )
        db.add(finding)
        db.flush()

        trigger = RuntimeSimulationTrigger(
            tenant_id=owner["tenant_id"],
            ai_system_id=ai_system_id,
            event_id=event.event_id,
            reason_code="repeated_denied_tool_calls",
            target_pack="tool_abuse_pack",
            related_control_ids=["CTRL-TOOL-001"],
            evidence_node_ids=[],
            correlation_id="corr-monitoring-1",
            recommended_action="run_tool_abuse_pack",
            status="pending",
            schedule_decision_id=None,
        )
        db.add(trigger)
        db.flush()

        recommendation = RuntimeGovernanceRecommendation(
            tenant_id=owner["tenant_id"],
            event_id=event.event_id,
            ai_system_id=ai_system_id,
            recommendation_type="route_to_review",
            reason_code="repeated_denied_tool_calls",
            priority="high",
            payload={"related_control_ids": ["CTRL-TOOL-001"], "evidence_node_ids": []},
            status="proposed",
        )
        db.add(recommendation)
        db.commit()

    with session_local() as db:
        summary = consume_runtime_intelligence_outputs(
            db,
            tenant_id=owner["tenant_id"],
            lookback_minutes=120,
            actor_user_id=None,
        )
        db.commit()
        assert int(summary["ingested_runtime_findings"]) >= 1
        assert int(summary["ingested_runtime_triggers"]) >= 1
        assert int(summary["ingested_runtime_recommendations"]) >= 1

        rows = db.scalars(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == owner["tenant_id"],
                MonitoringSignal.signal_type.like("runtime_intelligence.%"),
            )
        ).all()
        assert rows
        payloads = [dict(row.payload or {}) for row in rows]
        assert any(str(payload.get("runtime_finding_id") or "").strip() for payload in payloads)
        assert any(str(payload.get("runtime_trigger_id") or "").strip() for payload in payloads)
        assert any(str(payload.get("runtime_recommendation_id") or "").strip() for payload in payloads)


def test_monitoring_coverage_and_auditor_export_include_live_inputs(test_env, monkeypatch: pytest.MonkeyPatch) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="monitoring-coverage@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    with session_local() as db:
        framework = KBFramework(name="NIST AI RMF", version="1.0", source_type="authored")
        db.add(framework)
        db.flush()
        db.add(
            KBControl(
                id="CTRL-TOOL-001",
                framework_id=framework.id,
                title="Tool Control",
                objective="Control tool usage",
                requirement_level="MUST",
                applicability_tags=["runtime"],
                maturity_model={},
                evidence_requirements={},
            )
        )
        db.commit()

    connector = client.post(
        "/monitoring/connectors",
        headers=headers,
        json={
            "name": "OpenAI Monitoring",
            "provider_key": "openai",
            "connector_type": "openai",
            "config": {"base_url": "https://api.openai.com/v1"},
            "secrets": {"access_token": "demo-token"},
        },
    )
    assert connector.status_code == 200, connector.text
    connector_id = connector.json()["id"]

    monkeypatch.setattr("app.services.integration_connector_service.httpx.Client", _FakeHTTPClient)

    pull = client.post(f"/monitoring/connectors/{connector_id}/pull", headers=headers)
    assert pull.status_code == 200, pull.text
    assert int(pull.json()["last_signal_count"]) >= 1

    coverage = client.get("/monitoring/connectors/coverage?page=1&page_size=200", headers=headers)
    assert coverage.status_code == 200, coverage.text
    rows = [row for row in coverage.json()["items"] if row["provider_key"] == "openai"]
    assert rows
    assert all("framework_names" in row for row in rows)
    assert any("NIST AI RMF" in (row.get("framework_names") or []) for row in rows)
    assert any(bool(row.get("has_live_evidence")) for row in rows)
    assert any(int(row.get("live_evidence_count", 0)) > 0 for row in rows)

    summary = client.get("/monitoring/connectors/coverage/summary", headers=headers)
    assert summary.status_code == 200, summary.text
    summary_payload = summary.json()
    assert int(summary_payload["controls_covered"]) >= 1
    assert int(summary_payload["frameworks_with_live_evidence"]) >= 1
    assert int(summary_payload["signals_with_live_evidence"]) >= 1

    exported = client.post("/auditor/export", headers=headers, json={})
    assert exported.status_code == 200, exported.text
    export_payload = exported.json()
    json_artifact_path = test_env["artifact_dir"] / Path(str(export_payload["artifacts"]["json"]))
    assert json_artifact_path.exists()

    parsed = json.loads(json_artifact_path.read_text(encoding="utf-8"))
    monitoring_inputs = dict(parsed.get("continuous_monitoring_inputs") or {})
    assert int(monitoring_inputs.get("monitoring_signal_count") or 0) >= 1
    assert int(monitoring_inputs.get("monitoring_evidence_count") or 0) >= 1


def test_connector_coverage_aggregates_without_loading_large_payload_columns(
    test_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Coverage summaries must not hydrate telemetry/evidence JSON into API or worker memory."""
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="monitoring-bounded-coverage@example.com")
    tenant_id = owner["tenant_id"]

    monkeypatch.setattr(
        "app.services.monitoring_service.list_connector_signal_coverage",
        lambda provider_key=None: [
            {
                "provider_key": provider_key or "openai",
                "signal_type": "openai.usage",
                "evidence_signal_type": "connector.openai.usage",
                "control_id": "CTRL-OPENAI-001",
            }
        ],
    )

    with session_local() as db:
        db.add(
            Connector(
                tenant_id=tenant_id,
                name="Bounded coverage connector",
                provider_key="openai",
                connector_type="openai",
                enabled=True,
                status="active",
                config={},
            )
        )
        db.add_all(
            [
                MonitoringSignal(
                    tenant_id=tenant_id,
                    signal_type="openai.usage",
                    severity="low",
                    payload={"large": "x" * 100_000},
                ),
                EvidenceNode(
                    tenant_id=tenant_id,
                    node_type="integration_signal",
                    signal_type="connector.openai.usage",
                    label="OpenAI usage",
                    payload={"large": "x" * 100_000},
                ),
            ]
        )
        db.commit()

        statements: list[str] = []

        def capture_statement(_conn, _cursor, statement, _parameters, _context, _executemany):
            statements.append(str(statement).lower())

        event.listen(db.get_bind(), "before_cursor_execute", capture_statement)
        try:
            rows = connector_control_coverage(db, tenant_id=tenant_id)
        finally:
            event.remove(db.get_bind(), "before_cursor_execute", capture_statement)

    assert rows[0]["observed_count"] == 1
    assert rows[0]["live_evidence_count"] == 1
    coverage_queries = [
        statement
        for statement in statements
        if "from monitoring_signals" in statement or "from evidence_nodes" in statement
    ]
    assert coverage_queries
    assert all("monitoring_signals.payload" not in statement for statement in coverage_queries)
    assert all("evidence_nodes.payload" not in statement for statement in coverage_queries)


def test_connector_pull_retries_on_sqlite_lock_and_succeeds(test_env, monkeypatch: pytest.MonkeyPatch) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="monitoring-lock-retry@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    connector = client.post(
        "/monitoring/connectors",
        headers=headers,
        json={
            "name": "Lock Retry Connector",
            "provider_key": "openai",
            "connector_type": "openai",
            "config": {"base_url": "https://api.openai.com/v1"},
            "secrets": {"access_token": "demo-token"},
        },
    )
    assert connector.status_code == 200, connector.text
    connector_id = connector.json()["id"]

    attempts = {"count": 0}

    def _flaky_run(db, *, tenant_id: str, connector: Connector):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise OperationalError(
                "INSERT",
                {},
                sqlite3.OperationalError("database is locked"),
            )
        connector.last_pull_status = "success"
        connector.last_pull_error = None
        connector.last_signal_count = 0
        connector.status = "active"
        connector.is_stub = False
        connector.stub_reason = ""
        return []

    monkeypatch.setattr("app.api.routers.monitoring.run_connector_once", _flaky_run)

    pull = client.post(f"/monitoring/connectors/{connector_id}/pull", headers=headers)
    assert pull.status_code == 200, pull.text
    assert attempts["count"] == 2
    assert pull.json()["last_pull_status"] == "success"


def test_scheduled_monitoring_marks_invalid_connector_degraded_without_retrying_cycle(
    test_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deterministic configuration defect is evidence, not a transient worker failure."""
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="monitoring-invalid-config@example.com")

    with session_local() as db:
        connector = Connector(
            tenant_id=owner["tenant_id"],
            name="Invalid scheduled connector",
            provider_key="openai",
            connector_type="openai",
            enabled=True,
            status="active",
            config={},
            polling_interval_minutes=1,
        )
        db.add(connector)
        db.commit()
        connector_id = connector.id

    def _invalid_configuration(_db, *, tenant_id: str, connector: Connector):
        del tenant_id, connector
        raise ValueError("Missing base_url configuration.")

    monkeypatch.setattr(monitoring_jobs, "SessionLocal", session_local)
    monkeypatch.setattr(monitoring_jobs, "run_connector_once", _invalid_configuration)

    result = monitoring_jobs.run_all_connectors.run(owner["tenant_id"])

    assert result["executed_connectors"] == 1
    assert result["configuration_error_count"] == 1
    with session_local() as db:
        persisted = db.get(Connector, connector_id)
        assert persisted is not None
        assert persisted.status == "degraded"
        assert persisted.last_pull_status == "error"
        assert persisted.last_pull_error == "Missing base_url configuration."


def test_control_drift_marks_system_non_compliant_and_creates_remediation(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="monitoring-drift-remediation@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="MEDIUM")

    ingest = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "connector.control_drift",
            "severity": "high",
            "payload": {
                "reason_code": "control_drift_detected",
                "related_control_ids": ["CTRL-TOOL-001"],
            },
        },
    )
    assert ingest.status_code == 200, ingest.text
    signal_id = ingest.json()["id"]

    with session_local() as db:
        ai_system = db.get(AISystem, ai_system_id)
        assert ai_system is not None
        metadata = dict(ai_system.metadata_json or {})
        assert metadata.get("compliance_state") == "non_compliant"
        assert metadata.get("remediation_required") is True
        assert metadata.get("control_drift_detected") is True

        remediation = db.scalar(
            select(RemediationAction).where(
                RemediationAction.tenant_id == owner["tenant_id"],
                RemediationAction.source_trigger_id == signal_id,
                RemediationAction.target_type == "ai_system",
                RemediationAction.target_id == ai_system_id,
            )
        )
        assert remediation is not None
        assert remediation.remediation_type == "policy_tighten"


def test_connector_risk_signal_restricts_connector_and_disables_high_risk_actions(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="monitoring-connector-risk@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    connector_response = client.post(
        "/monitoring/connectors",
        headers=headers,
        json={
            "name": "Risky Connector",
            "provider_key": "outlook",
            "connector_type": "outlook",
            "config": {},
            "secrets": {"token": "demo"},
        },
    )
    assert connector_response.status_code == 200, connector_response.text
    connector_id = connector_response.json()["id"]

    ingest = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "signal_type": "integration.health.outlook_drift",
            "severity": "high",
            "payload": {
                "connector_id": connector_id,
                "provider_key": "outlook",
                "pull_status": "error",
                "connector_risk_exposed": True,
                "reason_code": "connector_risk_exposed",
            },
        },
    )
    assert ingest.status_code == 200, ingest.text
    signal_id = ingest.json()["id"]

    remediations = client.get(
        "/findings/remediations",
        headers=headers,
        params={
            "source_trigger_type": "drift_alert",
            "target_type": "connector",
            "target_id": connector_id,
        },
    )
    assert remediations.status_code == 200, remediations.text
    items = remediations.json()["items"]
    connector_remediation = next((item for item in items if item["source_trigger_id"] == signal_id), None)
    assert connector_remediation is not None
    assert connector_remediation["remediation_type"] == "connector_disable"
    assert connector_remediation["requires_approval"] is True

    applied = _approve_and_apply_remediation(
        client,
        headers=headers,
        remediation_id=connector_remediation["id"],
    )
    assert applied["status"] == "applied"

    with session_local() as db:
        connector = db.get(Connector, connector_id)
        assert connector is not None
        assert connector.enabled is False
        assert connector.status == "degraded"
        metadata = dict(connector.metadata_json or {})
        assert metadata.get("restricted_permissions") is True
        assert metadata.get("high_risk_actions_disabled") is True


def test_unknown_connector_ai_usage_is_blocked_and_registered_for_governance(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="monitoring-shadow-register@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ingest = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "signal_type": "saas.slack.ai_usage",
            "severity": "high",
            "payload": {
                "provider_key": "slack",
                "record": {"domain": "chat.openai.com", "user": "owner@example.com"},
            },
        },
    )
    assert ingest.status_code == 200, ingest.text
    retro = dict(ingest.json().get("payload", {}).get("retroactive_policy") or {})
    assert retro.get("decision") == "block"
    assert retro.get("register_shadow_candidate") is True

    remediations = client.get(
        "/findings/remediations",
        headers=headers,
        params={"source_trigger_type": "shadow_ai_detection"},
    )
    assert remediations.status_code == 200, remediations.text
    shadow_items = remediations.json()["items"]
    shadow_remediation = next(
        (
            item
            for item in shadow_items
            if str(item.get("target_type") or "") in {"source", "ai_system"}
        ),
        None,
    )
    assert shadow_remediation is not None
    _approve_and_apply_remediation(
        client,
        headers=headers,
        remediation_id=shadow_remediation["id"],
    )

    with session_local() as db:
        findings = db.scalars(
            select(Finding).where(
                Finding.tenant_id == owner["tenant_id"],
                Finding.finding_type == "unregistered_ai_system",
                Finding.source_surface == "connector",
            )
        ).all()
        assert findings

        candidates = db.scalars(
            select(AISystem).where(
                AISystem.tenant_id == owner["tenant_id"],
                AISystem.status == "pending_review",
            )
        ).all()
        assert candidates
        assert any(str(row.risk_tier or "").upper() == "HIGH" for row in candidates)


def test_scheduled_remediation_evaluation_rechecks_monitoring_signals(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="monitoring-remediation-scheduled@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="MEDIUM")

    ingest = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "monitoring.evidence.gap",
            "severity": "high",
            "payload": {
                "missing_evidence_detected": True,
                "require_revalidation": True,
                "reason_code": "monitoring_evidence_gap_detected",
                "related_control_ids": ["CTRL-TOOL-001"],
            },
        },
    )
    assert ingest.status_code == 200, ingest.text
    signal_id = ingest.json()["id"]

    with session_local() as db:
        summary = evaluate_scheduled_monitoring_remediation(
            db,
            tenant_id=owner["tenant_id"],
            lookback_minutes=180,
            actor_user_id=None,
        )
        db.commit()
        assert int(summary["signals_evaluated"]) >= 1
        assert int(summary["remediations_evaluated"]) >= 1

        signal = db.get(MonitoringSignal, signal_id)
        assert signal is not None
        payload = dict(signal.payload or {})
        assert str(payload.get("last_remediation_evaluated_at") or "").strip() != ""

        ai_system = db.get(AISystem, ai_system_id)
        assert ai_system is not None
        metadata = dict(ai_system.metadata_json or {})
        assert metadata.get("missing_evidence_detected") is True
        assert metadata.get("requires_revalidation") is True


def test_scheduled_remediation_ignores_lifecycle_signals(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="monitoring-remediation-lifecycle@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="MEDIUM")

    ingest = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "remediation.lifecycle.proposed",
            "severity": "high",
            "payload": {"reason_code": "control_drift_detected", "control_drift_detected": True},
        },
    )
    assert ingest.status_code == 200, ingest.text

    with session_local() as db:
        summary = evaluate_scheduled_monitoring_remediation(
            db, tenant_id=owner["tenant_id"], lookback_minutes=180, actor_user_id=None
        )
        assert summary["signals_scanned"] == 0
        assert summary["signals_evaluated"] == 0
        assert summary["remediations_evaluated"] == 0


def test_hourly_monitoring_can_be_explicitly_deferred_without_loading_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bounded recovery flag must not start the memory-heavy hourly work."""

    monkeypatch.setattr(
        monitoring_jobs.settings,
        "monitoring_hourly_coverage_enabled",
        False,
        raising=False,
    )

    def _unexpected_cycle(**_kwargs):
        raise AssertionError("deferred hourly monitoring must not run the coverage cycle")

    monkeypatch.setattr(monitoring_jobs, "_run_monitoring_cycle", _unexpected_cycle)

    assert monitoring_jobs.run_monitoring_hourly_checks() == {
        "cadence": "hourly",
        "status": "deferred",
        "reason_code": "hourly_coverage_disabled",
    }
