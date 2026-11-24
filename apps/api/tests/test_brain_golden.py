from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.brain import BrainArbitration, BrainModelCall, BrainToolCall
from app.db.models.simulation import Control, SimulationDefinition
from app.db.session import Base, get_db
from app.main import app
from app.services.brain.router import ModelRouter


PASSWORD = "Password123!"


@dataclass
class GoldenCase:
    question: str
    non_trivial: bool
    expect_refusal: bool = False


class DeterministicBrainProvider:
    name = "openai"
    model = "brain-mock"

    def generate_json(self, system_prompt: str, user_prompt: str, json_schema: dict) -> dict:
        properties = (json_schema or {}).get("properties") or {}
        if "steps" in properties:
            return self._plan(user_prompt)
        if "answer" in properties:
            return self._summary(user_prompt)
        return {}

    def generate_text(self, system_prompt: str, user_prompt: str) -> str:
        return "unused"

    def _extract_question_context(self, prompt: str) -> tuple[str, dict[str, Any]]:
        question = ""
        context: dict[str, Any] = {}
        if "Question:\n" in prompt:
            after = prompt.split("Question:\n", 1)[1]
            question = after.split("\n\nContext JSON:\n", 1)[0].strip()
        elif "Question: " in prompt:
            question = prompt.split("Question: ", 1)[1].splitlines()[0].strip()
        if "\n\nContext JSON:\n" in prompt and "\n\nAvailable tools:\n" in prompt:
            context_text = prompt.split("\n\nContext JSON:\n", 1)[1].split("\n\nAvailable tools:\n", 1)[0].strip()
            if context_text:
                context = json.loads(context_text)
        return question, context

    def _plan(self, user_prompt: str) -> dict:
        question, context = self._extract_question_context(user_prompt)
        q = question.lower()
        ai_system_id = context.get("ai_system_id")
        policy_version_id = context.get("policy_version_id")
        control_id = context.get("control_id")
        simulation_id = context.get("simulation_id")
        snapshot_id = context.get("snapshot_id")

        def step(index: int, tool: str, args: dict[str, Any], on_error: str = "stop") -> dict[str, Any]:
            return {
                "step_id": f"s{index}",
                "tool": tool,
                "args": args,
                "expect_schema": {"type": "object"},
                "on_error": on_error,
            }

        if "insufficient evidence" in q:
            return {
                "steps": [
                    step(
                        1,
                        "evidence.query",
                        {"time_range": {}, "filters": {"signal_type": "no.such.signal"}, "limit": 25, "cursor": "0"},
                    ),
                    step(
                        2,
                        "governance.list_ai_systems",
                        {"filters": {}, "limit": 10, "cursor": "0"},
                        on_error="continue_with_warning",
                    ),
                ]
            }
        if "governance inventory" in q:
            return {
                "steps": [
                    step(1, "governance.list_ai_systems", {"filters": {}, "limit": 20, "cursor": "0"}),
                    step(2, "evidence.query", {"time_range": {}, "filters": {}, "limit": 20, "cursor": "0"}),
                ]
            }
        if "ai system detail" in q:
            return {"steps": [step(1, "governance.get_ai_system", {"id": ai_system_id})]}
        if "policy version details" in q:
            return {"steps": [step(1, "policies.get_policy_version", {"policy_version_id": policy_version_id})]}
        if "guardian matrix" in q:
            return {"steps": [step(1, "policies.get_guardian_matrix", {"policy_version_id": policy_version_id})]}
        if "enforcement events" in q:
            return {"steps": [step(1, "enforcement.list_events", {"filters": {"ai_system_id": ai_system_id}, "limit": 20, "cursor": "0"})]}
        if "simulation catalog" in q:
            return {"steps": [step(1, "simulations.list_for_control", {"control_id": control_id, "ai_system_id": ai_system_id})]}
        if "run simulation" in q:
            return {
                "steps": [
                    step(1, "simulations.run", {"simulation_id": simulation_id, "ai_system_id": ai_system_id, "mode": "deterministic"}),
                    step(2, "simulations.list_for_control", {"control_id": control_id, "ai_system_id": ai_system_id}),
                ]
            }
        if "create auditor snapshot" in q:
            return {"steps": [step(1, "auditor.create_snapshot", {"framework": "NIST-AI-RMF", "period": {"days": 30}, "ai_system_id": ai_system_id})]}
        if "export existing snapshot as json" in q:
            return {"steps": [step(1, "auditor.export_snapshot", {"snapshot_id": snapshot_id, "format": "json"})]}
        if "export existing snapshot as csv" in q:
            return {"steps": [step(1, "auditor.export_snapshot", {"snapshot_id": snapshot_id, "format": "csv"})]}
        if "ops job status overview" in q:
            return {"steps": [step(1, "ops.jobs_status", {"limit": 5})]}
        if "cross-check governance and enforcement" in q:
            return {
                "steps": [
                    step(1, "governance.list_ai_systems", {"filters": {}, "limit": 20, "cursor": "0"}),
                    step(2, "enforcement.list_events", {"filters": {"ai_system_id": ai_system_id}, "limit": 20, "cursor": "0"}),
                ]
            }
        if "cross-check policy and guardian" in q:
            return {
                "steps": [
                    step(1, "policies.get_policy_version", {"policy_version_id": policy_version_id}),
                    step(2, "policies.get_guardian_matrix", {"policy_version_id": policy_version_id}),
                ]
            }
        if "what evidence is available" in q:
            return {"steps": [step(1, "evidence.query", {"time_range": {}, "filters": {}, "limit": 20, "cursor": "0"})]}

        return {
            "steps": [
                step(1, "governance.list_ai_systems", {"filters": {}, "limit": 10, "cursor": "0"}),
                step(2, "evidence.query", {"time_range": {}, "filters": {}, "limit": 20, "cursor": "0"}),
            ]
        }

    def _summary(self, user_prompt: str) -> dict:
        question = ""
        if "Question: " in user_prompt:
            question = user_prompt.split("Question: ", 1)[1].split("\n", 1)[0].strip().lower()

        allowed_ids: list[str] = []
        markers = ("Allowed citations:\n", "Allowed citation ids:\n")
        marker = next((item for item in markers if item in user_prompt), None)
        if marker:
            text = user_prompt.split(marker, 1)[1].strip()
            loaded = json.loads(text)
            if isinstance(loaded, list):
                for item in loaded:
                    if isinstance(item, str):
                        allowed_ids.append(str(item))
                    elif isinstance(item, dict):
                        value = str(item.get("id") or "").strip()
                        if value:
                            allowed_ids.append(value)

        if not allowed_ids:
            return {
                "answer": "INSUFFICIENT EVIDENCE",
                "claims": [],
                "citations": [],
                "controls": [],
                "frameworks": [],
                "confidence": 0.0,
                "missing_evidence": ["No citations available."],
                "proposed_actions": [{"tool": "evidence.query", "args": {"filters": {}, "limit": 100}}],
            }

        citation_id = allowed_ids[0]
        if "unsupported claim" in question:
            return {
                "answer": "This output includes an unsupported claim.",
                "claims": [{"id": "c1", "text": "Unsupported claim"}],
                "citations": [{"type": "evidence_node", "id": citation_id, "supports": []}],
                "controls": [],
                "frameworks": [],
                "confidence": 0.7,
                "missing_evidence": [],
                "proposed_actions": [],
            }

        return {
            "answer": (
                f"Tool outputs indicate the current tenant state for this question [{citation_id}].\n"
                f"Only cited execution artifacts were used in this response [{citation_id}]."
            ),
            "claims": [
                {"id": "c1", "text": "Tool outputs indicate the current tenant state for this question."},
                {"id": "c2", "text": "Only cited execution artifacts were used in this response."},
            ],
            "citations": [citation_id],
            "controls": [],
            "frameworks": [],
            "confidence": 0.8,
            "missing_evidence": [],
            "proposed_actions": [],
        }


@pytest.fixture()
def test_env(tmp_path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "brain_golden.sqlite3"
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
    monkeypatch.setattr(
        ModelRouter,
        "choose_models",
        lambda self, task_type, risk_tier, tenant_policy: [DeterministicBrainProvider()],
    )
    client = TestClient(app)
    try:
        yield {"client": client, "SessionLocal": testing_session_local}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Brain Golden Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {"access_token": body["access_token"], "tenant_id": body["tenants"][0]["id"]}


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def _create_ai_system(client: TestClient, *, headers: dict[str, str], name: str) -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": name, "description": "brain golden", "risk_tier": "HIGH"},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    approved = client.patch(f"/ai-systems/{ai_system_id}", headers=headers, json={"status": "approved"})
    assert approved.status_code == 200, approved.text
    return ai_system_id


def _create_policy_pack(client: TestClient, *, headers: dict[str, str]) -> str:
    response = client.post(
        "/policies/packs",
        headers=headers,
        json={"name": "Brain Golden Policy", "description": "golden", "status": "active"},
    )
    assert response.status_code == 200, response.text
    return response.json()["default_version"]["id"]


def _create_control_and_simulation(session_local: sessionmaker, *, tenant_id: str, control_id: str, simulation_id: str) -> None:
    with session_local() as db:
        control = Control(
            id=control_id,
            tenant_id=tenant_id,
            is_global=False,
            name="Brain Golden Control",
            category="interaction_security",
            description="control",
            mapped_framework_refs=[{"framework": "NIST-AI-RMF", "control_ref": "GV-1"}],
        )
        db.add(control)

        simulation = SimulationDefinition(
            id=simulation_id,
            tenant_id=tenant_id,
            name="Brain Golden Simulation",
            category="injection",
            target_module="interaction_security",
            version="1.0.0",
            dsl_json={
                "id": simulation_id,
                "name": "Brain Golden Simulation",
                "category": "injection",
                "target_module": "interaction_security",
                "version": "1.0.0",
                "safety": {"requires_sandbox": True, "max_runtime_seconds": 30, "no_external_network": True},
                "inputs_schema": {"fields": [{"name": "prompt", "type": "string"}]},
                "steps": [],
                "assertions": [],
                "maps_to_controls": [control_id],
                "expected_outcomes": {"pass_conditions": ["always"], "fail_conditions": []},
            },
        )
        db.add(simulation)
        db.commit()


def _create_snapshot(client: TestClient, *, headers: dict[str, str], ai_system_id: str) -> str:
    response = client.post(
        "/auditor/snapshot",
        headers=headers,
        json={"ai_system_id": ai_system_id, "trigger_type": "manual", "payload": {"seed": True}},
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


GOLDEN_CASES = [
    GoldenCase("Show governance inventory and evidence posture.", non_trivial=True),
    GoldenCase("Get AI system detail.", non_trivial=False),
    GoldenCase("Retrieve policy version details.", non_trivial=False),
    GoldenCase("Show guardian matrix for the current policy.", non_trivial=False),
    GoldenCase("List recent enforcement events for this system.", non_trivial=False),
    GoldenCase("List simulation catalog for this control.", non_trivial=False),
    GoldenCase("Run simulation and summarize impact.", non_trivial=True, expect_refusal=True),
    GoldenCase("Create auditor snapshot for this system.", non_trivial=False),
    GoldenCase("Export existing snapshot as json.", non_trivial=False),
    GoldenCase("Export existing snapshot as csv.", non_trivial=False),
    GoldenCase("Show ops job status overview.", non_trivial=False),
    GoldenCase("Cross-check governance and enforcement.", non_trivial=True),
    GoldenCase("Cross-check policy and guardian controls.", non_trivial=True),
    GoldenCase("What evidence is available now?", non_trivial=False),
    GoldenCase("Prove insufficient evidence for exfiltration claim.", non_trivial=True, expect_refusal=True),
]


def test_brain_ask_golden_questions(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="brain-golden-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers=headers, name="Brain Golden AI")
    policy_version_id = _create_policy_pack(client, headers=headers)
    control_id = "CTRL-BRAIN-GOLDEN-001"
    simulation_id = "SIM-BRAIN-GOLDEN-001"
    _create_control_and_simulation(
        session_local,
        tenant_id=owner["tenant_id"],
        control_id=control_id,
        simulation_id=simulation_id,
    )
    snapshot_id = _create_snapshot(client, headers=headers, ai_system_id=ai_system_id)

    context = {
        "ai_system_id": ai_system_id,
        "policy_version_id": policy_version_id,
        "control_id": control_id,
        "simulation_id": simulation_id,
        "snapshot_id": snapshot_id,
    }

    for case in GOLDEN_CASES:
        response = client.post(
            "/brain/ask",
            headers=headers,
            json={"question": case.question, "context": context},
        )
        assert response.status_code == 200, response.text
        body = response.json()

        assert "citations" in body
        assert isinstance(body["citations"], list)
        assert "claims" in body
        assert isinstance(body["claims"], list)

        is_refusal = body.get("answer") == "INSUFFICIENT EVIDENCE"
        if case.expect_refusal:
            assert is_refusal
            assert body["citations"] == []
            assert body.get("proposed_actions")
        else:
            assert not is_refusal, {"question": case.question, "response": body}
            assert len(body["claims"]) > 0
            assert len(body["citations"]) > 0
            claim_ids = {claim["id"] for claim in body["claims"]}
            supported: set[str] = set()
            for citation in body["citations"]:
                assert isinstance(citation, dict)
                assert citation.get("type") in {"evidence_node", "snapshot"}
                assert isinstance(citation.get("id"), str) and citation["id"]
                supports = citation.get("supports")
                assert isinstance(supports, list) and supports
                supported.update(str(item) for item in supports)
            assert all(claim_id in supported for claim_id in claim_ids)

        if not is_refusal:
            assert len(body["citations"]) > 0

    with session_local() as db:
        model_calls = db.scalar(select(func.count()).select_from(BrainModelCall))
        arbitrations = db.scalar(select(func.count()).select_from(BrainArbitration))
        tool_calls = db.scalar(select(func.count()).select_from(BrainToolCall))
        assert int(model_calls or 0) >= len(GOLDEN_CASES)
        assert int(arbitrations or 0) >= len(GOLDEN_CASES)
        assert int(tool_calls or 0) >= len(GOLDEN_CASES)


def test_brain_plan_and_execute_roundtrip(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="brain-golden-roundtrip@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, name="Brain Roundtrip AI")
    _create_policy_pack(client, headers=headers)

    control_id = "CTRL-BRAIN-GOLDEN-002"
    simulation_id = "SIM-BRAIN-GOLDEN-002"
    _create_control_and_simulation(
        session_local,
        tenant_id=owner["tenant_id"],
        control_id=control_id,
        simulation_id=simulation_id,
    )
    snapshot_id = _create_snapshot(client, headers=headers, ai_system_id=ai_system_id)

    context = {
        "ai_system_id": ai_system_id,
        "control_id": control_id,
        "simulation_id": simulation_id,
        "snapshot_id": snapshot_id,
        "policy_version_id": "",
    }
    plan_response = client.post(
        "/brain/plan",
        headers=headers,
        json={"question": "Show governance inventory and evidence posture.", "context": context},
    )
    assert plan_response.status_code == 200, plan_response.text
    plan = plan_response.json()
    assert plan.get("plan_id")
    assert len(plan.get("steps", [])) >= 2
    assert all(step.get("on_error") in {"stop", "continue_with_warning"} for step in plan["steps"])

    execute_response = client.post(
        "/brain/execute",
        headers=headers,
        json={"plan_id": plan["plan_id"]},
    )
    assert execute_response.status_code == 200, execute_response.text
    result = execute_response.json()
    assert result.get("plan_id") == plan["plan_id"]
    assert isinstance(result.get("steps_executed"), list)
    assert len(result["steps_executed"]) >= 2
    assert "citations" in result


def test_brain_claim_support_enforced(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="brain-golden-unsupported-claim@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, name="Brain Unsupported Claim AI")
    policy_version_id = _create_policy_pack(client, headers=headers)
    control_id = "CTRL-BRAIN-GOLDEN-003"
    simulation_id = "SIM-BRAIN-GOLDEN-003"
    _create_control_and_simulation(
        session_local,
        tenant_id=owner["tenant_id"],
        control_id=control_id,
        simulation_id=simulation_id,
    )
    snapshot_id = _create_snapshot(client, headers=headers, ai_system_id=ai_system_id)

    context = {
        "ai_system_id": ai_system_id,
        "policy_version_id": policy_version_id,
        "control_id": control_id,
        "simulation_id": simulation_id,
        "snapshot_id": snapshot_id,
    }
    response = client.post(
        "/brain/ask",
        headers=headers,
        json={"question": "Return unsupported claim output.", "context": context},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["answer"] == "INSUFFICIENT EVIDENCE"
    assert body["citations"] == []
    assert body["claims"] == []
    assert body["proposed_actions"]
