from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.ai_iam import AgentIdentity
from app.db.models.ai_orchestration import AIReasoningTrace
from app.db.models.finding import Finding
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.simulation import SimulationDefinition, SimulationRun
from app.db.models.user import UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services.llm_gateway_secure.schemas import SecureModelCallResult
from app.services.ai_orchestration.routing import choose_route
from app.services.ai_orchestration.safety import apply_post_call_guards, apply_pre_call_guards
from app.services.ai_orchestration.schemas import OrchestrationTaskRequest, RouteDecision


PASSWORD = "Password123!"
ALLOWED_ACTIONS = [
    "policy_update",
    "restrict_permission",
    "review_owner",
    "run_simulation",
    "ticket",
    "investigate",
    "rollback",
]


class _DummyProvider:
    def __init__(self, payload: dict):
        self._payload = payload

    def secure_generate_json(self, **kwargs):  # noqa: ANN003
        del kwargs
        post_guard = apply_post_call_guards(raw_output=dict(self._payload))
        blocked = not bool(post_guard.passed)
        return SecureModelCallResult(
            blocked=blocked,
            block_reason=("post_call_policy_rejected" if blocked else None),
            output_text=None,
            output_json=(None if blocked else dict(self._payload)),
            pre_call_guard={"passed": True, "reason": "ok", "details": {}},
            post_call_guard=post_guard.model_dump(),
            trace={"trace_id": f"dummy-{uuid4().hex[:8]}"},
        )


@pytest.fixture()
def orchestration_env(tmp_path):
    db_file = tmp_path / "orchestration_layer.sqlite3"
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
        yield {"client": client, "session_factory": testing_session_local}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Orchestration Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
        "user_id": body["user"]["id"],
        "email": email,
    }


def _elevate_role(*, session_factory, user_id: str, tenant_id: str, role: str = "owner") -> None:
    with session_factory() as db:
        row = db.scalar(
            select(UserTenantRole).where(
                UserTenantRole.user_id == user_id,
                UserTenantRole.tenant_id == tenant_id,
            )
        )
        assert row is not None
        row.role = role
        db.add(row)
        db.commit()


def _login(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["selected_tenant_id"],
        "user_id": body["user"]["id"],
        "email": email,
    }


def _create_ai_system(client: TestClient, headers: dict[str, str], risk_tier: str = "HIGH") -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Orchestration AI", "description": "test", "risk_tier": risk_tier},
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _insert_finding(*, session_factory, tenant_id: str, ai_system_id: str, user_id: str) -> str:
    with session_factory() as db:
        row = Finding(
            tenant_id=tenant_id,
            source_surface="gateway",
            ai_tool="chatgpt.com",
            ai_system_id=ai_system_id,
            user_id=user_id,
            severity="high",
            finding_type="policy_failure",
            risk_category="governance",
            status="open",
            recommended_action="route_to_governance",
            evidence_node_ids=["ev-node-1"],
            related_control_ids=["CTRL-1"],
            dedupe_key=f"test-finding-{uuid4().hex}",
        )
        db.add(row)
        db.commit()
        return row.finding_id


def _insert_simulation_run(*, session_factory, tenant_id: str, ai_system_id: str) -> str:
    with session_factory() as db:
        sim_def = SimulationDefinition(
            tenant_id=tenant_id,
            name="Prompt injection validation",
            category="injection",
            target_module="runtime_control",
            version="1.0",
            dsl_json={"steps": []},
        )
        db.add(sim_def)
        db.flush()
        sim_run = SimulationRun(
            tenant_id=tenant_id,
            simulation_id=sim_def.id,
            ai_system_id=ai_system_id,
            correlation_id=f"corr-{uuid4().hex[:8]}",
            mode="deterministic",
            inputs_used={"prompt": "ignore safety"},
            results={
                "final_outcome": "fail",
                "failed_assertions": ["control_not_triggered"],
                "summary": "Simulation bypass observed",
                "evidence_node_ids": ["ev-sim-1"],
            },
            controls_impacted=[{"control_id": "CTRL-SIM-1"}],
            notes="simulation failure for orchestration test",
        )
        db.add(sim_run)
        db.commit()
        return sim_run.id


def _insert_agent_and_event(*, session_factory, tenant_id: str, ai_system_id: str) -> str:
    with session_factory() as db:
        agent = AgentIdentity(
            tenant_id=tenant_id,
            name="test-agent",
            description="agent for orchestration tests",
            status="active",
            max_chain_depth=2,
            action_scope=["tool_execution"],
            tool_registry=["mail_send", "db_query"],
            external_system_access=["mail.google.com"],
            agent_type="workflow_agent",
            autonomy_level="medium",
        )
        db.add(agent)
        db.flush()
        event = RuntimeEvent(
            tenant_id=tenant_id,
            source_surface="aiiam",
            event_type="agent_action",
            ai_system_id=ai_system_id,
            agent_id=agent.id,
            risk_tier="high",
            severity="high",
            evidence_node_ids=["ev-agent-1"],
            risk_score=0.91,
            metadata_json={"decision": "block"},
            created_at=datetime.now(timezone.utc),
        )
        db.add(event)
        db.commit()
        return agent.id


def _monkeypatch_provider(monkeypatch, payload: dict):
    from app.services.ai_orchestration import orchestrator

    monkeypatch.setattr(
        orchestrator,
        "get_orchestration_provider",
        lambda route: _DummyProvider(payload),  # noqa: ARG005
    )


def _default_guidance_payload(issue_id: str = "issue-1") -> dict:
    return {
        "issue_id": issue_id,
        "summary": "Recommended bounded remediation actions.",
        "root_cause_hypothesis": "Control mapping drift and stale policy thresholds.",
        "recommended_steps": [
            {
                "step_order": 1,
                "action_type": "policy_update",
                "title": "Tighten policy",
                "description": "Move warn to block for sensitive external transfers.",
                "requires_approval": True,
                "estimated_impact": "medium",
                "linked_controls": ["CTRL-1"],
                "linked_frameworks": ["NIST AI RMF"],
            }
        ],
        "priority": "high",
        "confidence": 0.82,
        "notes": "Human review required before application.",
    }


def test_choose_route_respects_sensitivity_region_and_cost_policy() -> None:
    high_sensitivity = OrchestrationTaskRequest(
        task_type="remediation_guidance",
        issue_type="finding",
        issue_id="f-1",
        issue_title="sensitive issue",
        issue_summary="sensitive data path",
        severity="high",
        risk_tier="high",
        data_sensitivity="restricted",
        customer_region="uae",
        residency_required=True,
        cost_ceiling_usd=0.009,
    )
    route = choose_route(high_sensitivity)
    assert route.provider in {"llama", "gpt"}
    assert route.region_route == "uae"
    assert isinstance(route.reasoning, list)
    assert route.routing_policy_id == "orchestration-routing-policy-v2"


def test_pre_call_redaction_masks_sensitive_content() -> None:
    task = OrchestrationTaskRequest(
        task_type="remediation_guidance",
        issue_type="finding",
        issue_id="f-2",
        issue_title="sensitive finding",
        issue_summary="emirates id 784198765432101 and email me@corp.ai",
        severity="high",
        risk_tier="high",
        data_sensitivity="sensitive",
    )
    route = RouteDecision(
        provider="gpt",
        model="gpt-4.1-mini",
        model_version="gpt-4.1-mini",
        route_id="test",
        routing_policy_id="routing-test",
        region_route="global",
        reasoning=[],
        estimated_cost_usd=0.02,
    )
    redacted, result = apply_pre_call_guards(
        task=task,
        route=route,
        prompt_variables={
            "issue_summary": task.issue_summary,
            "raw": "contact me@corp.ai +971501234567",
        },
    )
    assert result.details.get("redacted_fields")
    assert "[REDACTED]" in str(redacted["issue_summary"])
    assert "[REDACTED]" in str(redacted["raw"])


def test_post_call_guard_rejects_unsafe_recommendations() -> None:
    result = apply_post_call_guards(
        raw_output={
            "summary": "auto-apply enforce immediately",
            "recommended_steps": [],
        }
    )
    assert result.passed is False
    assert result.reason == "post_call_policy_rejected"


def test_finding_guidance_persists_full_traceability(orchestration_env, monkeypatch) -> None:
    _monkeypatch_provider(monkeypatch, _default_guidance_payload("finding-1"))
    client: TestClient = orchestration_env["client"]
    session_factory = orchestration_env["session_factory"]
    owner = _register_owner(client, email="orchestration-finding@example.com")
    _elevate_role(session_factory=session_factory, user_id=owner["user_id"], tenant_id=owner["tenant_id"])
    owner = _login(client, email=owner["email"])
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers)
    finding_id = _insert_finding(
        session_factory=session_factory,
        tenant_id=owner["tenant_id"],
        ai_system_id=ai_system_id,
        user_id=owner["user_id"],
    )

    response = client.post(f"/ai-orchestration/findings/{finding_id}/remediation-guidance", headers=headers, json={})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["trace_id"]
    assert body["task_type"] == "remediation_guidance"
    assert body["prompt_template_id"] == "hawk.remediation_guidance"
    assert body["prompt_template_version"] in {"v2", "v3"}
    assert body["output_schema_valid"] is True
    assert body["remediation_guidance"]["recommended_steps"]

    trace_response = client.get(f"/ai-orchestration/traces/{body['trace_id']}", headers=headers)
    assert trace_response.status_code == 200, trace_response.text
    trace_body = trace_response.json()
    assert trace_body["issue_type"] == "finding"
    assert trace_body["issue_id"] == finding_id
    assert trace_body["provider"]
    assert trace_body["model"]
    assert trace_body["routing_policy_id"]
    assert isinstance(trace_body["pre_call_guard_results_json"], dict)
    assert isinstance(trace_body["post_call_guard_results_json"], dict)

    with session_factory() as db:
        trace = db.scalar(select(AIReasoningTrace).where(AIReasoningTrace.id == body["trace_id"]))
        assert trace is not None
        assert trace.tenant_id == owner["tenant_id"]
        assert trace.prompt_template_id.startswith("hawk.")
        assert trace.policy_route_id
        assert trace.region_route


def test_simulation_failure_and_agent_guidance_endpoints(orchestration_env, monkeypatch) -> None:
    _monkeypatch_provider(monkeypatch, _default_guidance_payload("sim-1"))
    client: TestClient = orchestration_env["client"]
    session_factory = orchestration_env["session_factory"]
    owner = _register_owner(client, email="orchestration-sim@example.com")
    _elevate_role(session_factory=session_factory, user_id=owner["user_id"], tenant_id=owner["tenant_id"])
    owner = _login(client, email=owner["email"])
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers)
    run_id = _insert_simulation_run(session_factory=session_factory, tenant_id=owner["tenant_id"], ai_system_id=ai_system_id)
    agent_id = _insert_agent_and_event(session_factory=session_factory, tenant_id=owner["tenant_id"], ai_system_id=ai_system_id)

    sim_response = client.post(f"/ai-orchestration/simulations/{run_id}/remediation-guidance", headers=headers, json={})
    assert sim_response.status_code == 200, sim_response.text
    sim_body = sim_response.json()
    assert sim_body["task_type"] == "simulation_failure_explanation"
    assert sim_body["remediation_guidance"]["priority"] in {"med", "high", "critical"}

    agent_response = client.post(f"/ai-orchestration/agents/{agent_id}/remediation-guidance", headers=headers, json={})
    assert agent_response.status_code == 200, agent_response.text
    agent_body = agent_response.json()
    assert agent_body["task_type"] == "control_gap_analysis"
    assert agent_body["remediation_guidance"]["recommended_steps"]


def test_ticket_payload_generation_for_jira_and_servicenow(orchestration_env, monkeypatch) -> None:
    _monkeypatch_provider(monkeypatch, _default_guidance_payload("issue-ticket"))
    client: TestClient = orchestration_env["client"]
    session_factory = orchestration_env["session_factory"]
    owner = _register_owner(client, email="orchestration-ticket@example.com")
    _elevate_role(session_factory=session_factory, user_id=owner["user_id"], tenant_id=owner["tenant_id"])
    owner = _login(client, email=owner["email"])
    headers = _headers(owner["access_token"], owner["tenant_id"])

    reason_response = client.post(
        "/ai-orchestration/reason",
        headers=headers,
        json={
            "task": {
                "task_type": "remediation_guidance",
                "issue_type": "runtime_pattern",
                "issue_id": "pattern-1",
                "issue_title": "Repeated prompt injection",
                "issue_summary": "Pattern indicates repeated jailbreak attempts.",
                "severity": "high",
                "risk_tier": "high",
                "data_sensitivity": "sensitive",
                "customer_region": "global",
                "residency_required": False,
                "cost_ceiling_usd": 0.2,
                "allowed_remediation_types": ALLOWED_ACTIONS,
            }
        },
    )
    assert reason_response.status_code == 200, reason_response.text
    trace_id = reason_response.json()["trace_id"]

    jira = client.post(
        f"/ai-orchestration/traces/{trace_id}/ticket-payload",
        headers=headers,
        json={"system": "jira"},
    )
    assert jira.status_code == 200, jira.text
    jira_body = jira.json()
    assert jira_body["system"] == "jira"
    assert jira_body["trace_id"] == trace_id
    assert "Summary" in jira_body["description"] or "summary" in jira_body["description"].lower()

    servicenow = client.post(
        f"/ai-orchestration/traces/{trace_id}/ticket-payload",
        headers=headers,
        json={"system": "servicenow"},
    )
    assert servicenow.status_code == 200, servicenow.text
    assert servicenow.json()["system"] == "servicenow"

    create_ticket = client.post(
        f"/ai-orchestration/traces/{trace_id}/ticket-create",
        headers=headers,
        json={"system": "jira"},
    )
    assert create_ticket.status_code == 200, create_ticket.text
    create_body = create_ticket.json()
    assert create_body["system"] == "jira"
    assert create_body["status"] in {"local_placeholder_only", "created_externally", "failed_external_create"}
    if create_body["status"] == "local_placeholder_only":
        assert create_body["created_externally"] is False


def test_unsafe_provider_output_is_blocked_and_does_not_bypass_controls(orchestration_env, monkeypatch) -> None:
    unsafe_payload = _default_guidance_payload("issue-unsafe")
    unsafe_payload["summary"] = "Auto-apply this immediately and enforce automatically."
    _monkeypatch_provider(monkeypatch, unsafe_payload)

    client: TestClient = orchestration_env["client"]
    session_factory = orchestration_env["session_factory"]
    owner = _register_owner(client, email="orchestration-unsafe@example.com")
    _elevate_role(session_factory=session_factory, user_id=owner["user_id"], tenant_id=owner["tenant_id"])
    owner = _login(client, email=owner["email"])
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/ai-orchestration/reason",
        headers=headers,
        json={
            "task": {
                "task_type": "remediation_guidance",
                "issue_type": "drift_alert",
                "issue_id": "drift-unsafe-1",
                "issue_title": "Critical drift",
                "issue_summary": "Detected control drift in data movement policy.",
                "severity": "critical",
                "risk_tier": "critical",
                "data_sensitivity": "restricted",
                "customer_region": "uae",
                "residency_required": True,
                "cost_ceiling_usd": 0.1,
                "allowed_remediation_types": ALLOWED_ACTIONS,
            }
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "rejected_post_call"
    assert body["rejection_reason"] == "post_call_policy_rejected"
    assert body["remediation_guidance"]["summary"].lower().startswith("fallback remediation guidance generated")
    for step in body["remediation_guidance"]["recommended_steps"]:
        assert step["action_type"] in ALLOWED_ACTIONS

    with session_factory() as db:
        traces = db.scalars(select(AIReasoningTrace).where(AIReasoningTrace.tenant_id == owner["tenant_id"])).all()
        assert len(traces) == 1
        assert traces[0].status == "rejected_post_call"
