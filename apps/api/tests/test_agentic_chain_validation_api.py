from __future__ import annotations

import os

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.session import Base, get_db
from app.db.models.evidence import EvidenceNode
from app.db.models.finding import Finding
from app.db.models.simulation import SimulationDefinition, SimulationExecutionStep, SimulationRun
from app.main import app


PASSWORD = "Password123!"


def test_agentic_chain_validation_api_lists_runs_and_summarizes(tmp_path):
    db_file = tmp_path / "agentic_chain_validation_api.sqlite3"
    engine = create_engine(f"sqlite+pysqlite:///{db_file}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        register = client.post(
            "/auth/register",
            json={"email": "chain-validation-owner@example.com", "password": PASSWORD, "full_name": "Chain Owner"},
        )
        assert register.status_code == 200, register.text
        auth = register.json()
        headers = {
            "Authorization": f"Bearer {auth['access_token']}",
            "X-Tenant-ID": auth["tenants"][0]["id"],
        }

        scenarios = client.get("/simulations/agentic-chain-integrity/scenarios", headers=headers)
        assert scenarios.status_code == 200, scenarios.text
        scenario_body = scenarios.json()
        assert scenario_body["total"] >= 12
        assert any(item["scenario_id"] == "ACI-003" for item in scenario_body["items"])

        run_one = client.post(
            "/simulations/agentic-chain-integrity/run",
            headers=headers,
            json={"scenario_id": "ACI-003", "defense_mode": "hawk_chain_integrity"},
        )
        assert run_one.status_code == 200, run_one.text
        run_body = run_one.json()
        assert run_body["total_runs"] == 1
        assert run_body["reports"][0]["scenario_id"] == "ACI-003"
        assert run_body["reports"][0]["pass_fail"] == "pass"
        assert "APPROVAL_EXECUTION_DRIFT" in run_body["reports"][0]["findings"]
        assert run_body["metrics"]["total_runs"] == 1
        assert len(run_body["persistence"]["run_ids"]) == 1
        assert len(run_body["persistence"]["evidence_node_ids"]) == 1
        assert run_body["persistence"]["finding_ids"]

        chain_id = run_body["reports"][0]["chain_id"]
        graph = client.get(f"/runtime-intelligence/chains/{chain_id}/graph", headers=headers)
        assert graph.status_code == 200, graph.text
        graph_body = graph.json()
        assert graph_body["chain_id"] == chain_id
        assert graph_body["total_edges"] >= 3
        assert {node["node_type"] for node in graph_body["nodes"]} >= {
            "simulation_scenario",
            "defense_mode",
            "policy",
            "evidence_bundle",
        }
        assert {event["event_type"] for event in graph_body["events"]} >= {
            "user_intent_created",
            "policy_evaluated",
            "evidence_created",
        }

        evidence_bundle = client.get(f"/runtime-intelligence/chains/{chain_id}/evidence", headers=headers)
        assert evidence_bundle.status_code == 200, evidence_bundle.text
        evidence_body = evidence_bundle.json()
        assert evidence_body["chain_id"] == chain_id
        assert run_body["persistence"]["evidence_node_ids"][0] in evidence_body["evidence_bundle_ids"]
        assert evidence_body["evidence"][0]["signal_type"] == "simulation.agentic_chain_integrity.report"

        with TestingSessionLocal() as db:
            persisted_run = db.query(SimulationRun).filter(SimulationRun.id == run_body["persistence"]["run_ids"][0]).one()
            assert persisted_run.results["chain_integrity_report"]["scenario_id"] == "ACI-003"
            assert persisted_run.results["evidence_nodes_created"] == run_body["persistence"]["evidence_node_ids"]
            assert persisted_run.controls_impacted == ["agentic_action_integrity"]

            persisted_definition = db.query(SimulationDefinition).filter(SimulationDefinition.id == persisted_run.simulation_id).one()
            assert persisted_definition.name == "Agentic Chain Integrity Validation Harness"

            step = db.query(SimulationExecutionStep).filter(SimulationExecutionStep.simulation_run_id == persisted_run.id).one()
            assert step.step_type == "agentic_chain_integrity_validation"
            assert step.evidence_refs == run_body["persistence"]["evidence_node_ids"]

            evidence = db.query(EvidenceNode).filter(EvidenceNode.id == run_body["persistence"]["evidence_node_ids"][0]).one()
            assert evidence.signal_type == "simulation.agentic_chain_integrity.report"
            assert evidence.payload["report"]["chain_id"] == run_body["reports"][0]["chain_id"]

            finding = db.query(Finding).filter(Finding.finding_id == run_body["persistence"]["finding_ids"][0]).one()
            assert finding.source_surface == "simulation"
            assert finding.related_event_ids == [run_body["reports"][0]["chain_id"]]

        run_all = client.post(
            "/simulations/agentic-chain-integrity/run",
            headers=headers,
            json={"run_all": True},
        )
        assert run_all.status_code == 200, run_all.text
        all_body = run_all.json()
        assert all_body["total_runs"] >= 60
        assert all_body["metrics"]["chain_control_uplift"] > 0
        assert len(all_body["persistence"]["run_ids"]) == all_body["total_runs"]

        metrics = client.get("/simulations/agentic-chain-integrity/metrics", headers=headers)
        assert metrics.status_code == 200, metrics.text
        assert metrics.json()["total_scenarios"] >= 12
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
