from __future__ import annotations

import os
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.monitoring import MonitoringSignal
from app.db.session import Base, get_db
from app.main import app
from app.services.simulation_pack_service import evaluate_simulation_coverage_remediation


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "sim_templates.sqlite3"
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
        yield {"client": client, "SessionLocal": testing_session_local}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Template Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {"access_token": body["access_token"], "tenant_id": body["tenants"][0]["id"]}


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def test_template_generation_and_coverage_endpoints(test_env) -> None:
    client: TestClient = test_env["client"]
    auth = _register_owner(client, email="template-owner@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    control_id = "CTRL-TEMPLATE-001"
    control_resp = client.post(
        "/simulations/controls",
        headers=headers,
        json={
            "id": control_id,
            "name": "Template Coverage Control",
            "category": "interaction_security",
            "description": "Template coverage control",
            "mapped_framework_refs": [{"framework": "NIST AI RMF", "control_ref": "GOV-1"}],
            "is_global": False,
        },
    )
    assert control_resp.status_code == 200, control_resp.text

    template_resp = client.post(
        "/simulations/templates",
        headers=headers,
        json={
            "name": "Template Generation Test",
            "description": "template coverage test",
            "status": "active",
            "category": "injection",
            "target_module": "interaction_security",
            "version_prefix": "1.5",
            "parameter_schema": {"fields": [{"name": "scenario", "type": "string", "required": True}]},
            "generation_defaults": {
                "parameter_sets": [
                    {"scenario": "s1", "prompt": "ignore policy one"},
                    {"scenario": "s2", "prompt": "ignore policy two"},
                    {"scenario": "s3", "prompt": "ignore policy three"},
                ]
            },
            "template_body": {
                "id": "tmpl-{{index}}-{{uuid}}",
                "name": "Template Generation Test :: {{scenario}}",
                "category": "injection",
                "target_module": "interaction_security",
                "version": "{{simulation_version}}",
                "safety": {"requires_sandbox": True, "max_runtime_seconds": 30, "no_external_network": True},
                "inputs_schema": {
                    "fields": [
                        {"name": "prompt", "type": "string", "required": True},
                        {"name": "rag_context", "type": "string", "required": False},
                    ]
                },
                "steps": [
                    {
                        "step_id": "s1",
                        "kind": "llm_intercept",
                        "payload_template": {
                            "request_id": "tmpl-gen-{{index}}",
                            "prompt": "{{prompt}}",
                            "context_summary": "ctx",
                            "actor_type": "human",
                            "actor_id": "template-user",
                        },
                        "variable_bindings": {},
                    }
                ],
                "assertions": [
                    {
                        "assertion_id": "a1",
                        "check": {"field": "s1.final_decision", "operator": "in", "value": ["allow", "warn", "block", "redact", "hold_for_approval"]},
                        "on_fail": {"result": "fail", "evidence_signal_type": "template.failed", "severity": "low"},
                    }
                ],
                "maps_to_controls": [control_id],
                "expected_outcomes": {"pass_conditions": ["decision present"], "fail_conditions": ["none"]},
            },
        },
    )
    assert template_resp.status_code == 200, template_resp.text
    template_id = template_resp.json()["id"]

    generate_resp = client.post(
        f"/simulations/templates/{template_id}/generate",
        headers=headers,
        json={"count": 3},
    )
    assert generate_resp.status_code == 200, generate_resp.text
    generated_payload = generate_resp.json()
    assert generated_payload["total_generated"] == 3
    assert len(generated_payload["generated"]) == 3

    defs_resp = client.get("/simulations/definitions", headers=headers)
    assert defs_resp.status_code == 200, defs_resp.text
    defs_payload = defs_resp.json()
    assert defs_payload["total"] >= 3

    control_coverage_resp = client.get(f"/controls/{control_id}/coverage", headers=headers)
    assert control_coverage_resp.status_code == 200, control_coverage_resp.text
    control_coverage = control_coverage_resp.json()
    assert control_coverage["coverage_summary"]["simulation_count"] >= 3
    assert len(control_coverage["mapped_simulations"]) >= 3

    framework = quote("NIST AI RMF", safe="")
    framework_resp = client.get(f"/frameworks/{framework}/coverage?min_simulations=1", headers=headers)
    assert framework_resp.status_code == 200, framework_resp.text
    framework_payload = framework_resp.json()
    assert framework_payload["total_controls"] >= 1
    assert framework_payload["covered_controls"] >= 1


def test_simulation_coverage_gap_generates_recommendations_and_monitoring_signal(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local = test_env["SessionLocal"]
    auth = _register_owner(client, email="template-coverage-gap@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    covered_control_id = "CTRL-TEMPLATE-COVERED-001"
    uncovered_control_id = "CTRL-TEMPLATE-UNCOVERED-001"
    for control_id in [covered_control_id, uncovered_control_id]:
        control_resp = client.post(
            "/simulations/controls",
            headers=headers,
            json={
                "id": control_id,
                "name": f"Control {control_id}",
                "category": "interaction_security",
                "description": "Template coverage control",
                "mapped_framework_refs": [{"framework": "NIST AI RMF", "control_ref": f"{control_id}-REF"}],
                "is_global": False,
            },
        )
        assert control_resp.status_code == 200, control_resp.text

    template_resp = client.post(
        "/simulations/templates",
        headers=headers,
        json={
            "name": "Coverage Gap Template",
            "description": "coverage gap test",
            "status": "active",
            "category": "injection",
            "target_module": "interaction_security",
            "version_prefix": "1.6",
            "parameter_schema": {"fields": [{"name": "scenario", "type": "string", "required": True}]},
            "generation_defaults": {"parameter_sets": [{"scenario": "gap"}]},
            "template_body": {
                "id": "tmpl-gap-{{index}}-{{uuid}}",
                "name": "Coverage Gap Template :: {{scenario}}",
                "category": "injection",
                "target_module": "interaction_security",
                "version": "{{simulation_version}}",
                "safety": {"requires_sandbox": True, "max_runtime_seconds": 30, "no_external_network": True},
                "inputs_schema": {"fields": [{"name": "prompt", "type": "string", "required": False}]},
                "steps": [
                    {
                        "step_id": "s1",
                        "kind": "monitoring_signal",
                        "payload_template": {"signal_type": "simulation.coverage.gap.synthetic", "severity": "low"},
                        "variable_bindings": {},
                    }
                ],
                "assertions": [
                    {
                        "assertion_id": "a1",
                        "check": {"field": "s1.signal_type", "operator": "equals", "value": "simulation.coverage.gap.synthetic"},
                        "on_fail": {"result": "fail", "evidence_signal_type": "template.failed", "severity": "low"},
                    }
                ],
                "maps_to_controls": [covered_control_id],
                "expected_outcomes": {"pass_conditions": ["decision present"], "fail_conditions": ["none"]},
            },
        },
    )
    assert template_resp.status_code == 200, template_resp.text
    template_id = template_resp.json()["id"]

    generate_resp = client.post(
        f"/simulations/templates/{template_id}/generate",
        headers=headers,
        json={"count": 1},
    )
    assert generate_resp.status_code == 200, generate_resp.text

    with session_local() as db:
        remediation_summary = evaluate_simulation_coverage_remediation(
            db,
            tenant_id=auth["tenant_id"],
            actor_user_id=None,
        )
        db.commit()
        assert remediation_summary["coverage_gap_detected"] is True
        assert uncovered_control_id in remediation_summary["controls_without_simulations"]
        assert int(remediation_summary["recommendation_count"]) >= 1
        assert str(remediation_summary["monitoring_signal_id"] or "").strip()

        signal = db.get(MonitoringSignal, remediation_summary["monitoring_signal_id"])
        assert signal is not None
        assert signal.signal_type == "simulation.coverage.gap"
        payload = dict(signal.payload or {})
        assert uncovered_control_id in list(payload.get("controls_without_simulations") or [])
        assert bool(payload.get("recommended_simulations")) is True
