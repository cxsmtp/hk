from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session, sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.audit import AuditLog
from app.db.models.activity_audit import AIAction, AISession, DeploymentEndpoint, PromptPayload, UserRegistry
from app.db.models.ai_system import AISystem
from app.db.models.discovery import DiscoveryApplication
from app.db.models.enforcement import EnforcementEvent
from app.db.models.evidence import EvidenceEdge, EvidenceNode
from app.db.models.finding import Finding
from app.db.models.maturity import ConflictResolution, ControlConflict
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.shadow_ai import ShadowAIEntity, ShadowAISignal, ShadowAIUsage
from app.db.models.snapshot import AuditorSnapshot
from app.db.models.user import User
from app.db.session import Base, get_db
from app.main import app
from app.services.audit_service import write_audit_log
from app.services.maturity_service import recalculate_control_maturity
from app.services import snapshot_service
from ai_system_approval_helpers import approve_ai_system


PASSWORD = "Password123!"


def _install_snapshot_immutability_trigger(db: Session) -> None:
    db.execute(
        text(
            """
            CREATE TRIGGER trg_auditor_snapshots_immutable_update
            BEFORE UPDATE ON auditor_snapshots
            FOR EACH ROW
            BEGIN
                SELECT RAISE(ABORT, 'immutable_table:auditor_snapshots');
            END;
            """
        )
    )
    db.execute(
        text(
            """
            CREATE TRIGGER trg_auditor_snapshots_immutable_delete
            BEFORE DELETE ON auditor_snapshots
            FOR EACH ROW
            BEGIN
                SELECT RAISE(ABORT, 'immutable_table:auditor_snapshots');
            END;
            """
        )
    )
    db.commit()


@pytest.fixture()
def test_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ARTIFACT_DIR", str(tmp_path / "artifacts"))
    db_file = tmp_path / "auditor_defensibility.sqlite3"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    testing_session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    with testing_session_local() as db:
        _install_snapshot_immutability_trigger(db)

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


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def _download_json_artifact(client: TestClient, *, headers: dict[str, str], body: dict, name: str = "json") -> dict:
    url = body["download_urls"][name]
    response = client.get(url, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def _assert_relative_artifact_contract(body: dict) -> None:
    expected_names = {"json", "csv", "evidence_pack", "pdf_ready_model", "pdf"}
    artifacts = dict(body.get("artifacts") or {})
    download_urls = dict(body.get("download_urls") or {})
    hashes = dict(artifacts.get("artifact_hashes") or {})

    assert expected_names.issubset(artifacts)
    assert expected_names.issubset(download_urls)
    assert expected_names.issubset(hashes)
    assert artifacts.get("pdf_renderer_available") is True
    assert artifacts.get("pdf_renderer") == "simple_pdf"
    for name in expected_names:
        value = str(artifacts[name] or "")
        assert value
        assert not Path(value).is_absolute()
        assert download_urls[name] == f"/auditor/snapshots/{body['snapshot_id']}/artifacts/{name}"
        assert len(str(hashes[name])) == 64


def _items(payload: list[dict] | dict) -> list[dict]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        items = payload.get("items")
        if isinstance(items, list):
            return items
    return []


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Auditor Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {"access_token": body["access_token"], "tenant_id": body["tenants"][0]["id"]}


def _create_control(client: TestClient, *, headers: dict[str, str], control_id: str) -> None:
    response = client.post(
        "/simulations/controls",
        headers=headers,
        json={
            "id": control_id,
            "name": f"Control {control_id}",
            "category": "monitoring",
            "description": "control for conflict testing",
            "mapped_framework_refs": [{"framework": "INTERNAL", "control_ref": "AUD-1"}],
            "is_global": False,
        },
    )
    assert response.status_code == 200, response.text


def _create_ai_system(
    client: TestClient,
    *,
    headers: dict[str, str],
    name: str,
    approve: bool = True,
) -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": name, "description": "", "risk_tier": "HIGH"},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    if approve:
        approved = approve_ai_system(client, headers, ai_system_id)
        assert approved.status_code == 200, approved.text
    return ai_system_id


def _revalidate_ai_system_for_snapshot(session_local: sessionmaker, *, tenant_id: str, ai_system_id: str) -> None:
    with session_local() as db:
        row = db.scalar(select(AISystem).where(AISystem.tenant_id == tenant_id, AISystem.id == ai_system_id))
        assert row is not None
        metadata = dict(row.metadata_json or {})
        metadata["governance_state"] = "APPROVED"
        metadata["lifecycle_state"] = "ACTIVE"
        metadata["snapshot_revalidated_for_test"] = True
        row.status = "approved"
        row.metadata_json = metadata
        db.add(row)
        db.commit()


def _create_blocking_policy_version(
    client: TestClient,
    *,
    headers: dict[str, str],
    trigger_token: str,
    version: str = "9.9.9",
) -> str:
    pack = client.post(
        "/policies/packs",
        headers=headers,
        json={"name": "Auditor Proof Pack", "description": "proof-chain", "status": "draft"},
    )
    assert pack.status_code == 200, pack.text
    pack_id = pack.json()["pack"]["id"]

    activate = client.patch(
        f"/policies/packs/{pack_id}",
        headers=headers,
        json={"status": "active"},
    )
    assert activate.status_code == 200, activate.text

    created = client.post(
        f"/policies/packs/{pack_id}/versions",
        headers=headers,
        json={
            "version": version,
            "scope": {
                "applies_to_risk_tiers": ["LOW", "MEDIUM", "HIGH", "CRITICAL", "RESTRICTED"],
                "applies_to_ai_system_ids": None,
                "applies_to_actor_types": ["human", "agent", "system"],
            },
            "enforcement_defaults": {"default_decision": "allow", "escalation": "notify"},
            "guardian_contracts": [
                {
                    "guardian_id": "auditor_proof_block_guard",
                    "description": "Deterministic block for proof-chain testing",
                    "enabled": True,
                    "trigger": {
                        "signal_types": ["prompt.text"],
                        "conditions": [
                            {
                                "field": "prompt.text",
                                "operator": "contains",
                                "value": trigger_token,
                                "case_sensitive": False,
                            }
                        ],
                    },
                    "evaluation": {"method": "rules", "confidence_threshold": 0.5},
                    "decision": {"on_pass": "allow", "on_fail": "block", "on_uncertain": "warn"},
                    "actions": {
                        "redact": {"fields": ["prompt"], "strategy": "mask"},
                        "mutate_output": {"enabled": False, "strategy": "safe_completion"},
                        "notify": {"channels": []},
                        "create_ticket": {"system": "jira", "severity": "high"},
                    },
                    "evidence": {
                        "evidence_signal_type": "guardian.auditor_proof_block_guard.detected",
                        "link_to_controls": ["CTRL-PROOF-001"],
                    },
                    "control_impact": {
                        "maturity_delta_on_fail": -0.1,
                        "increase_simulation_frequency": False,
                        "enforcement_strictness_increase": 1,
                    },
                    "approval_workflow": {
                        "required_roles": ["owner", "admin"],
                        "sla_minutes": 30,
                        "default_if_timeout": "block",
                    },
                }
            ],
        },
    )
    assert created.status_code == 200, created.text
    return created.json()["id"]


def _simulation_dsl(
    *,
    tenant_id: str,
    control_id: str,
    assertion_operator: str,
    assertion_value: str,
) -> dict:
    assertion_field = "s1.signal_id" if assertion_operator == "exists" else "s1.payload.marker"
    return {
        "id": f"dsl-{uuid4()}",
        "tenant_id": tenant_id,
        "name": f"Simulation {uuid4().hex[:6]}",
        "category": "injection",
        "target_module": "monitoring",
        "version": "1.0.0",
        "safety": {"requires_sandbox": True, "max_runtime_seconds": 60, "no_external_network": True},
        "inputs_schema": {"fields": []},
        "steps": [
            {
                "step_id": "s1",
                "kind": "monitoring_signal",
                "payload_template": {
                    "signal_type": "phase.e.signal",
                    "severity": "low",
                    "marker": "{{iteration.index}}",
                },
                "variable_bindings": {},
            }
        ],
        "assertions": [
            {
                "assertion_id": "a1",
                "check": {"field": assertion_field, "operator": assertion_operator, "value": assertion_value},
                "on_fail": {"result": "fail", "evidence_signal_type": "simulation.fail", "severity": "high"},
            }
        ],
        "maps_to_controls": [control_id],
        "expected_outcomes": {"pass_conditions": ["assertion passes"], "fail_conditions": ["assertion fails"]},
    }


def _create_simulation(
    client: TestClient,
    *,
    headers: dict[str, str],
    tenant_id: str,
    control_id: str,
    assertion_operator: str,
    assertion_value: str,
) -> str:
    dsl = _simulation_dsl(
        tenant_id=tenant_id,
        control_id=control_id,
        assertion_operator=assertion_operator,
        assertion_value=assertion_value,
    )
    response = client.post(
        "/simulations/definitions",
        headers=headers,
        json={
            "name": dsl["name"],
            "category": dsl["category"],
            "target_module": dsl["target_module"],
            "version": dsl["version"],
            "dsl_json": dsl,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _run_simulation(client: TestClient, *, headers: dict[str, str], simulation_id: str, ai_system_id: str) -> dict:
    response = client.post(
        f"/simulations/definitions/{simulation_id}/run",
        headers=headers,
        json={"ai_system_id": ai_system_id, "mode": "deterministic", "inputs_used": {}},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _create_llm_simulation(
    client: TestClient,
    *,
    headers: dict[str, str],
    tenant_id: str,
    control_id: str,
    name: str,
    expected_decision: str,
) -> str:
    dsl = {
        "id": f"dsl-llm-{uuid4()}",
        "tenant_id": tenant_id,
        "name": name,
        "category": "injection",
        "target_module": "interaction_security",
        "version": "1.0.0",
        "safety": {"requires_sandbox": True, "max_runtime_seconds": 60, "no_external_network": True},
        "inputs_schema": {"fields": []},
        "steps": [
            {
                "step_id": "s1",
                "kind": "llm_intercept",
                "payload_template": {
                    "actor_type": "system",
                    "actor_id": "simulator",
                    "request_id": f"llm-step-{uuid4().hex[:8]}",
                    "prompt": "safe prompt for precedence test",
                    "context_summary": "simulation context",
                    "attachments_meta": [],
                },
                "variable_bindings": {},
            }
        ],
        "assertions": [
            {
                "assertion_id": "a1",
                "check": {"field": "s1.final_decision", "operator": "equals", "value": expected_decision},
                "on_fail": {"result": "fail", "evidence_signal_type": "simulation.fail", "severity": "high"},
            }
        ],
        "maps_to_controls": [control_id],
        "expected_outcomes": {"pass_conditions": ["assertion passes"], "fail_conditions": ["assertion fails"]},
    }
    response = client.post(
        "/simulations/definitions",
        headers=headers,
        json={
            "name": name,
            "category": dsl["category"],
            "target_module": dsl["target_module"],
            "version": dsl["version"],
            "dsl_json": dsl,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _seed_manual_event_with_evidence(
    session_local: sessionmaker,
    *,
    tenant_id: str,
    ai_system_id: str,
    control_id: str,
) -> tuple[str, str]:
    with session_local() as db:
        telemetry_node = EvidenceNode(
            tenant_id=tenant_id,
            node_type="telemetry_signal",
            signal_type="telemetry.runtime.spike",
            label="Telemetry spike",
            payload={"source": "telemetry"},
        )
        simulation_node = EvidenceNode(
            tenant_id=tenant_id,
            node_type="simulation_signal",
            signal_type="simulation.synthetic.marker",
            label="Simulation marker",
            payload={"source": "simulation"},
        )
        db.add(telemetry_node)
        db.add(simulation_node)
        db.flush()

        audit = write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=None,
            actor_type="system",
            action="test.seed.enforcement_event",
            resource_type="ai_system",
            resource_id=ai_system_id,
            payload={},
        )
        event = EnforcementEvent(
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            actor_type="system",
            actor_id="seed",
            request_id=f"seed-{uuid4()}",
            input_prompt="seed",
            input_context_summary="seed",
            input_attachments_meta=[],
            guardian_results=[],
            final_decision="warn",
            final_actions={},
            evidence_nodes_created=[telemetry_node.id, simulation_node.id],
            controls_impacted=[{"control_id": control_id, "delta": 0.2}],
            policy_version_id=None,
            audit_log_id=audit.id,
        )
        db.add(event)
        db.commit()
        return telemetry_node.id, simulation_node.id


def _recalculate_for_control(
    session_local: sessionmaker,
    *,
    tenant_id: str,
    ai_system_id: str,
    control_id: str,
    reason: str,
) -> None:
    with session_local() as db:
        recalculate_control_maturity(
            db,
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            control_ids=[control_id],
            reason=reason,
        )
        db.commit()


def test_snapshot_is_immutable_and_hash_stored(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="auditor-immutable@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    export_response = client.post("/auditor/export", headers=headers, json={})
    assert export_response.status_code == 200, export_response.text
    export_body = export_response.json()
    snapshot_id = export_body["snapshot_id"]
    export_hash = export_body["artifacts"]["hash"]
    artifact_relative_path = export_body["artifact_relative_path"]
    download_url = export_body["download_url"]
    assert len(export_hash) == 64
    assert artifact_relative_path
    assert not artifact_relative_path.startswith("/")
    assert download_url == f"/auditor/snapshots/{snapshot_id}/download"

    download_response = client.get(download_url, headers=headers)
    assert download_response.status_code == 200, download_response.text
    assert download_response.headers.get("content-disposition")

    with session_local() as db:
        snapshot = db.scalar(
            select(AuditorSnapshot).where(
                AuditorSnapshot.id == snapshot_id,
                AuditorSnapshot.tenant_id == owner["tenant_id"],
            )
        )
        assert snapshot is not None
        assert snapshot.artifact_hash == export_hash
        assert snapshot.artifact_path == artifact_relative_path

        with pytest.raises(Exception):
            db.execute(
                text("UPDATE auditor_snapshots SET trigger_type = 'tampered' WHERE id = :id"),
                {"id": snapshot_id},
            )
            db.commit()
        db.rollback()

        with pytest.raises(Exception):
            db.execute(text("DELETE FROM auditor_snapshots WHERE id = :id"), {"id": snapshot_id})
            db.commit()
        db.rollback()


def test_export_includes_executive_pdf_and_leadership_sections(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="auditor-executive-report@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    control_id = f"CTRL-EXEC-{uuid4().hex[:8]}"
    _create_control(client, headers=headers, control_id=control_id)
    ai_system_id = _create_ai_system(client, headers=headers, name="Executive Report System")

    with session_local() as db:
        discovery_app = DiscoveryApplication(
            tenant_id=owner["tenant_id"],
            tool_key="shadow-chatgpt-web",
            tool_name="ChatGPT Web",
            vendor="OpenAI",
            status="discovered",
            provisional_risk_tier="high",
            ai_system_id=ai_system_id,
        )
        db.add(discovery_app)

        shadow_entity = ShadowAIEntity(
            tenant_id=owner["tenant_id"],
            canonical_name="Unknown Browser AI Helper",
            discovery_status="discovered",
            confidence_score=0.92,
            provisional_risk_tier="HIGH",
            source_surfaces=["browser"],
            vendor="Unknown",
            risk_score=82.0,
            usage_count=7,
            unique_users=1,
            endpoints_count=1,
            linked_ai_system_id=ai_system_id,
        )
        db.add(shadow_entity)
        db.flush()

        db.add(
            ShadowAISignal(
                tenant_id=owner["tenant_id"],
                shadow_ai_entity_id=shadow_entity.id,
                source_surface="browser",
                source_event_id=f"sig-{uuid4().hex[:8]}",
                domain="chatgpt.com",
                provider="openai",
                tool_name="ChatGPT",
                user_id="executive-owner",
                confidence_signal={"score": 0.92},
                raw_fingerprint={"surface": "browser"},
            )
        )
        db.commit()

    _create_blocking_policy_version(
        client,
        headers=headers,
        trigger_token="executive-report-block-token",
        version="9.9.9",
    )

    for idx in range(2):
        browser = client.post(
            "/telemetry/browser",
            headers=headers,
            json={
                "event_type": "prompt_blocked",
                "ai_system_id": ai_system_id,
                "domain": "chatgpt.com",
                "url": "https://chatgpt.com",
                "action_taken": "block",
                "severity": "high",
                "prompt_preview_redacted": f"blocked prompt preview {idx}",
                "input_signal_types": ["sensitive_data_pattern"],
            },
        )
        assert browser.status_code == 200, browser.text

    gateway = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "auditor-executive-user",
            "request_id": f"exec-gateway-{uuid4().hex[:8]}",
            "prompt": "execute executive-report-block-token now",
            "context_summary": "executive report gateway signal",
            "attachments_meta": [],
            "response_text": "blocked",
            "provider": "openai",
            "model": "gpt-4.1",
            "model_version": "2026-03",
        },
    )
    assert gateway.status_code == 200, gateway.text
    assert gateway.json().get("final_decision") == "block"

    with session_local() as db:
        db.add(
            RuntimeEvent(
                tenant_id=owner["tenant_id"],
                source_surface="browser",
                event_type="prompt_blocked",
                ai_system_id=ai_system_id,
                application="ChatGPT",
                decision="block",
                severity="high",
                metadata_json={"prompt_preview_redacted": "executive redacted prompt preview"},
            )
        )
        db.commit()

    exported = client.post("/auditor/export", headers=headers, json={"ai_system_id": ai_system_id})
    assert exported.status_code == 200, exported.text
    body = exported.json()
    snapshot_id = str(body["snapshot_id"])
    _assert_relative_artifact_contract(body)

    downloaded_pdf = client.get(f"/auditor/snapshots/{snapshot_id}/artifacts/pdf", headers=headers)
    assert downloaded_pdf.status_code == 200, downloaded_pdf.text
    assert downloaded_pdf.content.startswith(b"%PDF-")
    assert b"%%EOF" in downloaded_pdf.content[-32:]

    payload = _download_json_artifact(client, headers=headers, body=body)
    executive_report = dict(payload.get("executive_report") or {})
    sections = dict(executive_report.get("sections") or {})

    assert dict(sections.get("shadow_ai_discovered") or {}).get("total_discovered", 0) >= 1
    assert dict(sections.get("risk_breakdown") or {}).get("severity_counts")
    assert list(sections.get("top_violators") or [])
    assert list(sections.get("policies_violated") or [])
    assert list(sections.get("blocked_prompts") or [])
    assert list(sections.get("top_apps_tools") or [])


def test_export_named_artifacts_download_with_hashes_and_relative_paths(test_env) -> None:
    client: TestClient = test_env["client"]

    owner = _register_owner(client, email="auditor-artifact-contract@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    exported = client.post("/auditor/export", headers=headers, json={})
    assert exported.status_code == 200, exported.text
    body = exported.json()
    _assert_relative_artifact_contract(body)

    expected_content_types = {
        "json": "application/json",
        "csv": "text/csv",
        "evidence_pack": "application/json",
        "pdf_ready_model": "application/json",
        "pdf": "application/pdf",
        "signature_manifest": "application/json",
    }
    for name, url in body["download_urls"].items():
        downloaded = client.get(url, headers=headers)
        assert downloaded.status_code == 200, downloaded.text
        assert expected_content_types[name] in downloaded.headers.get("content-type", "")
        assert downloaded.content

    evidence_pack = client.get(body["download_urls"]["evidence_pack"], headers=headers).json()
    integrity = dict(evidence_pack.get("integrity") or {})
    payload_without_integrity = dict(evidence_pack)
    payload_without_integrity.pop("integrity", None)
    expected_payload_hash = hashlib.sha256(
        json.dumps(payload_without_integrity, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()
    assert integrity["integrity_status"] == "valid"
    assert integrity["hash_algorithm"] == "sha256"
    assert integrity["payload_sha256"] == expected_payload_hash
    assert integrity["evidence_node_count"] == len(evidence_pack.get("evidence_nodes") or [])
    assert integrity["evidence_edge_count"] == len(evidence_pack.get("evidence_edges") or [])
    assert integrity["redaction_policy"] == "privacy_sanitizer"

    assert client.get(body["download_urls"]["pdf"], headers=headers).content.startswith(b"%PDF-")


def test_auditor_evidence_edge_collection_is_bounded(test_env) -> None:
    session_local: sessionmaker = test_env["SessionLocal"]
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="auditor-bounded-edges@example.com")

    with session_local() as db:
        source = EvidenceNode(
            tenant_id=owner["tenant_id"],
            node_type="test_source",
            signal_type="test.source",
            label="Bounded source",
            payload={},
        )
        targets = [
            EvidenceNode(
                tenant_id=owner["tenant_id"],
                node_type="test_target",
                signal_type="test.target",
                label=f"Bounded target {index}",
                payload={},
            )
            for index in range(3)
        ]
        db.add_all([source, *targets])
        db.flush()
        db.add_all(
            [
                EvidenceEdge(
                    tenant_id=owner["tenant_id"],
                    from_node_id=source.id,
                    to_node_id=target.id,
                    edge_type="test_link",
                    integrity_key=f"bounded-edge-{index}",
                    payload={},
                )
                for index, target in enumerate(targets)
            ]
        )
        db.commit()

        edges, truncated = snapshot_service._collect_bounded_evidence_edges(
            db,
            tenant_id=owner["tenant_id"],
            linked_node_ids={source.id},
            limit=2,
        )

    assert len(edges) == 2
    assert truncated is True
    assert all(edge.from_node_id == source.id for edge in edges)


def test_auditor_export_includes_detailed_pilot_user_activity(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="auditor-pilot-user-detail@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    with session_local() as db:
        user = db.scalar(select(User).where(User.email == "auditor-pilot-user-detail@example.com"))
        assert user is not None

        endpoint = DeploymentEndpoint(
            endpoint_id="pilot-endpoint-1",
            tenant_id=owner["tenant_id"],
            user_id=user.id,
            hostname="pilot-laptop-1",
            device_type="laptop",
            os_type="windows",
            os_version="10.0.22631",
            browser_type="chrome",
            browser_version="126.0.6478.127",
            extension_version="pilot-test",
            status="active",
            metadata_json={"extension_name": "AI Control Plane - Discovery & Guard"},
        )
        db.add(endpoint)
        db.add(
            UserRegistry(
                tenant_id=owner["tenant_id"],
                user_id=user.id,
                display_name="Auditor Owner",
                email=user.email,
                department="Engineering",
                role="owner",
                status="active",
                deployment_surfaces=["browser"],
            )
        )
        session = AISession(
            session_id="pilot-session-1",
            tenant_id=owner["tenant_id"],
            user_id=user.id,
            endpoint_id=endpoint.endpoint_id,
            source_surface="browser",
            ai_app="ChatGPT",
            ai_model="gpt-4.1",
            total_actions=2,
            risk_score=0.74,
            correlation_id="pilot-corr-1",
        )
        db.add(session)
        action = AIAction(
            action_id="pilot-action-1",
            tenant_id=owner["tenant_id"],
            session_id=session.session_id,
            user_id=user.id,
            endpoint_id=endpoint.endpoint_id,
            action_type="prompt_input",
            ai_app="ChatGPT",
            ai_model="gpt-4.1",
            data_classification="restricted",
            sensitivity_score=0.94,
            policy_triggered="secret_or_credential_detected",
            enforcement_action="blocked",
            risk_score=0.9,
            correlation_id="pilot-corr-1",
            metadata_json={
                "domain": "chatgpt.com",
                "runtime_event_id": "runtime-pilot-1",
                "control_mode": "inline_prevented",
                "decision_explanation_id": "decision-expl-1",
                "evidence_bundle_id": "evidence-bundle-1",
                "trace_id": "trace-pilot-1",
                "surface_type": "browser",
                "destination_trust_level": "public_ai",
                "justification_text": "Approved for customer support case triage.",
                "justification_status": "accepted",
                "justification_user_email": user.email,
                "justification_submitted_at": "2026-06-25T12:00:00Z",
            },
        )
        db.add(action)
        db.add(
            PromptPayload(
                action_id=action.action_id,
                raw_prompt=None,
                redacted_prompt="Please analyze this API key: [REDACTED_SECRET]",
                pii_detected=False,
                sensitive_entities=["api_key"],
                storage_mode="hashed_only",
                prompt_hash="abc123",
            )
        )
        shadow = ShadowAIEntity(
            tenant_id=owner["tenant_id"],
            canonical_name="chatgpt.com",
            discovery_status="discovered",
            confidence_score=0.96,
            provisional_risk_tier="HIGH",
            source_surfaces=["browser"],
            vendor="OpenAI",
            approved_status="unknown",
            risk_score=0.81,
            usage_count=1,
            unique_users=1,
            endpoints_count=1,
        )
        db.add(shadow)
        db.flush()
        db.add(
            ShadowAIUsage(
                tenant_id=owner["tenant_id"],
                asset_id=shadow.id,
                user_id=user.id,
                endpoint_id=endpoint.endpoint_id,
                session_id=session.session_id,
                interaction_type="prompt",
                sensitivity_detected=True,
                policy_triggered="secret_or_credential_detected",
                metadata_json={"domain": "chatgpt.com", "event_id": "runtime-pilot-1"},
            )
        )
        db.add(
            Finding(
                tenant_id=owner["tenant_id"],
                source_surface="browser",
                ai_tool="ChatGPT",
                user_id=user.id,
                user_email=user.email,
                machine_id=endpoint.endpoint_id,
                browser_type="chrome",
                application="ChatGPT",
                severity="high",
                finding_type="SECRET_OR_CREDENTIAL_TO_AI",
                risk_category="data_exfiltration",
                decision="block",
                status="open",
                recommended_action="Rotate exposed secret and review prompt.",
                evidence_node_ids=[],
                related_event_ids=["runtime-pilot-1"],
                related_control_ids=["CTRL-DATA-001"],
                related_runtime_event_id="runtime-pilot-1",
                dedupe_key="pilot-user-export-finding",
                occurrence_count=1,
            )
        )
        db.commit()

    exported = client.post("/auditor/export", headers=headers, json={})
    assert exported.status_code == 200, exported.text
    payload = _download_json_artifact(client, headers=headers, body=exported.json())
    pilot = dict(payload.get("pilot_user_activity") or {})

    assert pilot["user_count"] == 1
    user_row = pilot["users"][0]
    assert user_row["email"] == "auditor-pilot-user-detail@example.com"
    assert user_row["ai_tools_visited"][0]["tool"] == "ChatGPT"
    assert user_row["ai_tools_visited"][0]["visit_count"] == 1
    assert user_row["shadow_ai_usage"][0]["domain"] == "chatgpt.com"
    assert user_row["prompts_entered"][0]["storage_mode"] == "hashed_only"
    assert user_row["prompts_entered"][0]["prompt"] == "[hashed_only]"
    assert user_row["prompts_entered"][0]["raw_prompt"] == "[hashed_only]"
    assert user_row["justifications"][0]["justification"] == "Approved for customer support case triage."
    assert user_row["justifications"][0]["justification_status"] == "accepted"
    assert user_row["justifications"][0]["submitted_by"] == "auditor-pilot-user-detail@example.com"
    assert user_row["justifications"][0]["evidence_bundle_id"] == "evidence-bundle-1"
    assert user_row["violations"][0]["finding_type"] == "SECRET_OR_CREDENTIAL_TO_AI"
    assert user_row["violations"][0]["related_runtime_event_id"] == "runtime-pilot-1"
    device_row = user_row["devices"][0]
    assert device_row["hostname"] == "pilot-laptop-1"
    assert device_row["user_email"] == "auditor-pilot-user-detail@example.com"
    assert device_row["user_display_name"] == "Auditor Owner"
    assert device_row["device_type"] == "laptop"
    assert device_row["os_type"] == "windows"
    assert device_row["os_version"] == "10.0.22631"
    assert device_row["browser_type"] == "chrome"
    assert device_row["browser_version"] == "126.0.6478.127"
    assert device_row["extension_name"] == "AI Control Plane - Discovery & Guard"
    assert device_row["extension_version"] == "pilot-test"
    ledger_row = pilot["action_control_ledger"][0]
    assert ledger_row["email"] == "auditor-pilot-user-detail@example.com"
    assert ledger_row["hostname"] == "pilot-laptop-1"
    assert ledger_row["ai_app"] == "ChatGPT"
    assert ledger_row["domain"] == "chatgpt.com"
    assert ledger_row["action_type"] == "prompt_input"
    assert ledger_row["decision"] == "blocked"
    assert ledger_row["control_mode"] == "inline_prevented"
    assert ledger_row["surface"] == "browser"
    assert ledger_row["prompt_preview"] == "[hashed_only]"
    assert ledger_row["raw_prompt"] == "[hashed_only]"
    assert ledger_row["finding_type"] == "SECRET_OR_CREDENTIAL_TO_AI"
    assert ledger_row["evidence_bundle_id"] == "evidence-bundle-1"
    assert ledger_row["decision_explanation_id"] == "decision-expl-1"
    assert ledger_row["trace_id"] == "trace-pilot-1"
    assert pilot["control_mode_breakdown"] == {"inline_prevented": 1}
    assert pilot["justification_count"] == 1
    assert pilot["app_usage_summary"][0]["ai_app"] == "ChatGPT"
    assert pilot["app_usage_summary"][0]["blocked_count"] == 1
    assert pilot["device_activity_rollup"][0]["hostname"] == "pilot-laptop-1"
    assert pilot["device_activity_rollup"][0]["action_count"] == 1

    executive_report = dict(payload.get("executive_report") or {})
    executive_pilot = dict((executive_report.get("sections") or {}).get("pilot_user_activity") or {})
    assert executive_pilot["user_count"] == 1
    assert executive_pilot["users"][0]["email"] == "auditor-pilot-user-detail@example.com"
    assert executive_pilot["prompt_evidence"][0]["prompt"] == "[hashed_only]"
    assert executive_pilot["justification_count"] == 1
    assert executive_pilot["justification_evidence"][0]["justification"] == "Approved for customer support case triage."
    assert executive_pilot["justification_evidence"][0]["justification_status"] == "accepted"
    assert executive_pilot["justification_evidence"][0]["submitted_by"] == "auditor-pilot-user-detail@example.com"
    assert executive_pilot["detailed_violations"][0]["finding_type"] == "SECRET_OR_CREDENTIAL_TO_AI"
    assert executive_pilot["detailed_violations"][0]["prompt_preview"] == "[hashed_only]"
    assert executive_pilot["top_ai_tools"][0] == {
        "tool": "ChatGPT",
        "domain": "chatgpt.com",
        "visit_count": 1,
        "blocked_count": 1,
        "warned_count": 0,
        "unique_users": 1,
    }
    assert executive_pilot["decision_breakdown"] == {"blocked": 1}
    assert executive_pilot["prompt_storage_breakdown"] == {"hashed_only": 1}
    assert executive_pilot["action_type_breakdown"] == {"prompt_input": 1}
    assert executive_pilot["user_risk_rollup"][0]["email"] == "auditor-pilot-user-detail@example.com"
    assert executive_pilot["user_risk_rollup"][0]["violation_count"] == 1
    assert executive_pilot["user_risk_rollup"][0]["blocked_count"] == 1
    assert executive_pilot["user_risk_rollup"][0]["prompt_count"] == 1
    assert executive_pilot["action_control_ledger"][0]["control_mode"] == "inline_prevented"
    assert executive_pilot["action_control_ledger"][0]["evidence_bundle_id"] == "evidence-bundle-1"
    assert executive_pilot["control_mode_breakdown"] == {"inline_prevented": 1}
    user_violation_report = executive_pilot["per_user_violation_report"][0]
    assert user_violation_report["email"] == "auditor-pilot-user-detail@example.com"
    assert user_violation_report["blocked_count"] == 1
    assert user_violation_report["devices"][0]["hostname"] == "pilot-laptop-1"
    assert user_violation_report["devices"][0]["browser"] == "Chrome"
    assert user_violation_report["devices"][0]["extension_version"] == "pilot-test"
    assert user_violation_report["action_samples"][0]["prompt_preview"] == "[hashed_only]"
    assert user_violation_report["action_samples"][0]["control_mode"] == "inline_prevented"
    assert user_violation_report["action_samples"][0]["evidence_bundle_id"] == "evidence-bundle-1"
    assert user_violation_report["violation_samples"][0]["finding_type"] == "SECRET_OR_CREDENTIAL_TO_AI"
    assert user_violation_report["violation_samples"][0]["prompt_preview"] == "[hashed_only]"
    assert user_violation_report["justification_samples"][0]["justification"] == "Approved for customer support case triage."
    assert user_violation_report["justification_samples"][0]["submitted_by"] == "auditor-pilot-user-detail@example.com"
    assert "evidence-bundle-1" in user_violation_report["evidence_refs"]
    assert "decision-expl-1" in user_violation_report["evidence_refs"]
    assert "trace-pilot-1" in user_violation_report["evidence_refs"]

    pdf = client.get(exported.json()["download_urls"]["pdf"], headers=headers)
    assert pdf.status_code == 200, pdf.text
    assert b"Pilot User Activity Detail" in pdf.content
    assert b"Pilot Activity Rollups" in pdf.content
    assert b"Justification Evidence" in pdf.content
    assert b"Approved for customer support case triage" in pdf.content
    assert b"Detailed Violations" in pdf.content
    assert b"AI Action Control Ledger" in pdf.content
    assert b"inline_prevented" in pdf.content
    assert b"pilot-laptop-1" in pdf.content
    assert b"Please analyze this API key" not in pdf.content
    assert b"[hashed_only]" in pdf.content


def test_auditor_executive_report_filters_system_telemetry_noise(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="auditor-noise-filter@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    with session_local() as db:
        db.add_all(
            [
                RuntimeEvent(
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    event_type="extension_health_status",
                    application="extension.local",
                    decision="allow",
                    severity="low",
                    metadata_json={"domain": "extension.local"},
                ),
                RuntimeEvent(
                    tenant_id=owner["tenant_id"],
                    source_surface="monitoring",
                    event_type="monitoring_signal_ingest",
                    application="monitoring_signal_ingest",
                    decision="observe",
                    severity="low",
                    metadata_json={"domain": "localhost"},
                ),
                RuntimeEvent(
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    event_type="prompt_blocked",
                    application="ChatGPT",
                    decision="block",
                    severity="high",
                    metadata_json={"domain": "chatgpt.com", "prompt_preview_redacted": "blocked customer prompt"},
                ),
                DiscoveryApplication(
                    tenant_id=owner["tenant_id"],
                    tool_key="extension.local",
                    tool_name="extension.local",
                    status="discovered",
                    provisional_risk_tier="HIGH",
                    vendor="Unknown",
                ),
                DiscoveryApplication(
                    tenant_id=owner["tenant_id"],
                    tool_key="chatgpt.com",
                    tool_name="chatgpt.com",
                    status="approved",
                    provisional_risk_tier="HIGH",
                    vendor="OpenAI",
                ),
            ]
        )
        db.commit()

    exported = client.post("/auditor/export", headers=headers, json={})
    assert exported.status_code == 200, exported.text
    payload = _download_json_artifact(client, headers=headers, body=exported.json())
    sections = dict((payload.get("executive_report") or {}).get("sections") or {})

    apps = [row["name"] for row in sections["top_apps_tools"]]
    assert "ChatGPT" in apps
    assert "extension.local" not in apps
    assert "monitoring_signal_ingest" not in apps

    shadow_apps = [row["name"] for row in sections["shadow_ai_discovered"]["top_shadow_apps"]]
    assert "chatgpt.com" in shadow_apps
    assert "extension.local" not in shadow_apps


def test_named_artifact_download_rejects_tampered_snapshot_path(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="auditor-artifact-tamper@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    exported = client.post("/auditor/export", headers=headers, json={})
    assert exported.status_code == 200, exported.text
    snapshot_id = exported.json()["snapshot_id"]

    with session_local() as db:
        db.execute(text("DROP TRIGGER trg_auditor_snapshots_immutable_update"))
        snapshot = db.scalar(select(AuditorSnapshot).where(AuditorSnapshot.id == snapshot_id))
        assert snapshot is not None
        payload = dict(snapshot.payload or {})
        artifacts = dict(payload.get("artifacts") or {})
        artifacts["pdf"] = "../outside.pdf"
        payload["artifacts"] = artifacts
        snapshot.payload = payload
        db.commit()

    downloaded = client.get(f"/auditor/snapshots/{snapshot_id}/artifacts/pdf", headers=headers)
    assert downloaded.status_code == 400, downloaded.text


def test_export_period_filters_runtime_events_and_findings(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="auditor-period-filter@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, name="Period Filter System")

    start = datetime(2026, 5, 1, tzinfo=timezone.utc)
    end = datetime(2026, 5, 2, tzinfo=timezone.utc)
    in_window = start + timedelta(hours=2)
    old = start - timedelta(days=7)

    with session_local() as db:
        db.add_all(
            [
                RuntimeEvent(
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    event_type="prompt_blocked",
                    ai_system_id=ai_system_id,
                    application="ChatGPT",
                    decision="block",
                    severity="high",
                    metadata_json={"prompt_preview_redacted": "in-window redacted prompt"},
                    created_at=in_window,
                ),
                RuntimeEvent(
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    event_type="prompt_blocked",
                    ai_system_id=ai_system_id,
                    application="ChatGPT",
                    decision="block",
                    severity="high",
                    metadata_json={"prompt_preview_redacted": "old redacted prompt"},
                    created_at=old,
                ),
                Finding(
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    ai_tool="ChatGPT",
                    ai_system_id=ai_system_id,
                    severity="high",
                    finding_type="browser_interaction_security",
                    risk_category="data_leakage",
                    decision="block",
                    recommended_action="review",
                    dedupe_key=f"in-window-{uuid4()}",
                    first_seen_at=in_window,
                    last_seen_at=in_window,
                ),
                Finding(
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    ai_tool="ChatGPT",
                    ai_system_id=ai_system_id,
                    severity="high",
                    finding_type="browser_interaction_security",
                    risk_category="data_leakage",
                    decision="block",
                    recommended_action="review",
                    dedupe_key=f"old-{uuid4()}",
                    first_seen_at=old,
                    last_seen_at=old,
                ),
            ]
        )
        db.commit()

    exported = client.post(
        "/auditor/export",
        headers=headers,
        json={"ai_system_id": ai_system_id, "period_start": start.isoformat(), "period_end": end.isoformat()},
    )
    assert exported.status_code == 200, exported.text
    payload = _download_json_artifact(client, headers=headers, body=exported.json())

    runtime_events = payload["runtime_intelligence_inputs"]["runtime_events"]
    findings = payload["findings"]
    assert len(runtime_events) == 1
    assert len(findings) == 1
    assert "in-window" in runtime_events[0]["event_id"] or runtime_events[0]["created_at"].startswith("2026-05-01")
    assert findings[0]["last_seen_at"].startswith("2026-05-01")


def test_executive_report_uses_only_redacted_prompt_previews(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="auditor-redaction@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, name="Redaction System")

    with session_local() as db:
        db.add(
            RuntimeEvent(
                tenant_id=owner["tenant_id"],
                source_surface="browser",
                event_type="prompt_blocked",
                ai_system_id=ai_system_id,
                application="ChatGPT",
                decision="block",
                severity="high",
                metadata_json={
                    "prompt_or_content": "raw secret prompt must never export",
                    "prompt_preview_redacted": "redacted secret prompt",
                },
            )
        )
        db.commit()

    exported = client.post("/auditor/export", headers=headers, json={"ai_system_id": ai_system_id})
    assert exported.status_code == 200, exported.text
    payload = _download_json_artifact(client, headers=headers, body=exported.json())
    blocked = payload["executive_report"]["sections"]["blocked_prompts"]
    serialized = json.dumps(blocked)
    assert "redacted secret prompt" in serialized
    assert "raw secret prompt must never export" not in serialized


def test_conflict_detection_and_resolution_workflow(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="auditor-conflict@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    control_id = f"CTRL-CONFLICT-{uuid4().hex[:8]}"
    _create_control(client, headers=headers, control_id=control_id)
    ai_system_id = _create_ai_system(client, headers=headers, name="Conflict System")

    pass_sim_id = _create_simulation(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        control_id=control_id,
        assertion_operator="exists",
        assertion_value=True,
    )
    pass_run = _run_simulation(client, headers=headers, simulation_id=pass_sim_id, ai_system_id=ai_system_id)
    assert pass_run["results"]["result"] == "pass"

    fail_sim_id = _create_simulation(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        control_id=control_id,
        assertion_operator="equals",
        assertion_value="never-match",
    )
    fail_run = _run_simulation(client, headers=headers, simulation_id=fail_sim_id, ai_system_id=ai_system_id)
    assert fail_run["results"]["result"] == "fail"

    conflicts_response = client.get("/auditor/conflicts?status_filter=open", headers=headers)
    assert conflicts_response.status_code == 200, conflicts_response.text
    open_conflicts = _items(conflicts_response.json())
    conflict = next((row for row in open_conflicts if row["control_id"] == control_id and row["ai_system_id"] == ai_system_id), None)
    assert conflict is not None
    conflict_id = conflict["id"]

    maturity_response = client.get("/trust-center/maturity", headers=headers)
    assert maturity_response.status_code == 200, maturity_response.text
    maturity_rows = _items(maturity_response.json())
    maturity_row = next(
        row for row in maturity_rows if row["control_id"] == control_id and row["ai_system_id"] == ai_system_id
    )
    assert maturity_row["status"] == "contested"

    resolve_response = client.post(
        f"/auditor/conflicts/{conflict_id}/resolve",
        headers=headers,
        json={"decision": "accept_negative", "notes": "manual adjudication"},
    )
    assert resolve_response.status_code == 200, resolve_response.text
    assert resolve_response.json()["status"] == "resolved"

    resolved_response = client.get("/auditor/conflicts?status_filter=resolved", headers=headers)
    assert resolved_response.status_code == 200, resolved_response.text
    resolved_rows = _items(resolved_response.json())
    assert any(row["id"] == conflict_id for row in resolved_rows)

    maturity_after_response = client.get("/trust-center/maturity", headers=headers)
    assert maturity_after_response.status_code == 200, maturity_after_response.text
    maturity_after_rows = _items(maturity_after_response.json())
    maturity_after = next(
        row for row in maturity_after_rows if row["control_id"] == control_id and row["ai_system_id"] == ai_system_id
    )
    assert maturity_after["status"] in {"healthy", "needs_review"}

    with session_local() as db:
        conflict_audit = db.scalar(
            select(AuditLog).where(
                AuditLog.tenant_id == owner["tenant_id"],
                AuditLog.action == "auditor.conflict.resolve",
                AuditLog.resource_id == conflict_id,
            )
        )
        assert conflict_audit is not None

    with session_local() as db:
        conflict_evidence_rows = db.scalars(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == owner["tenant_id"],
                EvidenceNode.signal_type == "control.conflict.resolved",
            )
        ).all()
        conflict_evidence = next(
            (row for row in conflict_evidence_rows if (row.payload or {}).get("conflict_id") == conflict_id),
            None,
        )
        assert conflict_evidence is not None


def test_evidence_conflict_resolution(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="auditor-precedence@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    control_id = f"CTRL-PRECEDENCE-{uuid4().hex[:8]}"
    _create_control(client, headers=headers, control_id=control_id)
    ai_system_id = _create_ai_system(client, headers=headers, name="Precedence System")

    pass_sim_id = _create_llm_simulation(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        control_id=control_id,
        name="Precedence Pass",
        expected_decision="allow",
    )
    fail_sim_id = _create_llm_simulation(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        control_id=control_id,
        name="Precedence Fail",
        expected_decision="block",
    )
    assert _run_simulation(client, headers=headers, simulation_id=pass_sim_id, ai_system_id=ai_system_id)["results"]["result"] == "pass"
    assert _run_simulation(client, headers=headers, simulation_id=fail_sim_id, ai_system_id=ai_system_id)["results"]["result"] == "fail"

    telemetry_node_id, simulation_node_id = _seed_manual_event_with_evidence(
        session_local,
        tenant_id=owner["tenant_id"],
        ai_system_id=ai_system_id,
        control_id=control_id,
    )
    _recalculate_for_control(
        session_local,
        tenant_id=owner["tenant_id"],
        ai_system_id=ai_system_id,
        control_id=control_id,
        reason="test_evidence_conflict_resolution",
    )

    with session_local() as db:
        resolutions = db.scalars(
            select(ConflictResolution)
            .where(
                ConflictResolution.tenant_id == owner["tenant_id"],
                ConflictResolution.ai_system_id == ai_system_id,
                ConflictResolution.control_id == control_id,
            )
            .order_by(ConflictResolution.created_at.desc())
        ).all()
        assert resolutions
        resolution = None
        chosen_node = None
        resolution_debug: list[dict[str, object]] = []
        for row in resolutions:
            candidate = db.scalar(
                select(EvidenceNode).where(
                    EvidenceNode.id == row.chosen_evidence_id,
                    EvidenceNode.tenant_id == owner["tenant_id"],
                )
            )
            discarded_nodes = db.scalars(
                select(EvidenceNode).where(
                    EvidenceNode.tenant_id == owner["tenant_id"],
                    EvidenceNode.id.in_(row.discarded_evidence_ids or []),
                )
            ).all()
            resolution_debug.append(
                {
                    "chosen": candidate.signal_type if candidate else None,
                    "chosen_node_type": candidate.node_type if candidate else None,
                    "discarded": [
                        {"signal_type": node.signal_type, "node_type": node.node_type}
                        for node in discarded_nodes
                    ],
                    "reason": row.reason,
                }
            )
            if candidate and candidate.signal_type.startswith(("telemetry.", "gateway.")) and any(
                str(node.signal_type or "").startswith("simulation.") for node in discarded_nodes
            ):
                resolution = row
                chosen_node = candidate
                break

        assert resolution is not None, resolution_debug
        assert chosen_node is not None
        assert chosen_node.signal_type.startswith(("telemetry.", "gateway."))
        assert "telemetry>simulation>configuration>documentation" in resolution.reason


def test_confidence_breakdown(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="auditor-confidence@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    control_id = f"CTRL-CONFIDENCE-{uuid4().hex[:8]}"
    _create_control(client, headers=headers, control_id=control_id)
    ai_system_id = _create_ai_system(client, headers=headers, name="Confidence System")

    pass_sim_id = _create_llm_simulation(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        control_id=control_id,
        name="Confidence Pass",
        expected_decision="allow",
    )
    fail_sim_id = _create_llm_simulation(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        control_id=control_id,
        name="Confidence Fail",
        expected_decision="block",
    )
    _run_simulation(client, headers=headers, simulation_id=pass_sim_id, ai_system_id=ai_system_id)
    _run_simulation(client, headers=headers, simulation_id=fail_sim_id, ai_system_id=ai_system_id)

    _seed_manual_event_with_evidence(
        session_local,
        tenant_id=owner["tenant_id"],
        ai_system_id=ai_system_id,
        control_id=control_id,
    )
    _recalculate_for_control(
        session_local,
        tenant_id=owner["tenant_id"],
        ai_system_id=ai_system_id,
        control_id=control_id,
        reason="test_confidence_breakdown",
    )

    explanation_response = client.get(
        f"/trust-center/maturity/{ai_system_id}/controls/{control_id}/explanation",
        headers=headers,
    )
    assert explanation_response.status_code == 200, explanation_response.text
    payload = explanation_response.json()
    confidence = payload["confidence_inputs"]

    telemetry_count = confidence["telemetry_evidence_count"]
    simulation_count = confidence["simulation_evidence_count"]
    assert telemetry_count >= 1
    assert simulation_count >= 1
    assert confidence["telemetry_bonus"] == pytest.approx(0.1 * telemetry_count, abs=1e-6)
    assert confidence["simulation_bonus"] == pytest.approx(0.05 * simulation_count, abs=1e-6)
    assert confidence["conflict_penalty"] == pytest.approx(-0.2, abs=1e-6)
    expected = max(
        0.0,
        min(
            1.0,
            confidence["base_score"]
            + confidence["telemetry_bonus"]
            + confidence["simulation_bonus"]
            + confidence["conflict_penalty"],
        ),
    )
    assert confidence["confidence_score"] == pytest.approx(expected, abs=1e-6)


def test_auditor_challenge_flow(test_env) -> None:
    client: TestClient = test_env["client"]

    owner = _register_owner(client, email="auditor-challenge@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    control_id = f"CTRL-CHALLENGE-{uuid4().hex[:8]}"
    _create_control(client, headers=headers, control_id=control_id)
    ai_system_id = _create_ai_system(client, headers=headers, name="Challenge System")

    intercept = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "auditor",
            "prompt": "baseline prompt",
            "context_summary": "baseline",
            "attachments_meta": [],
        },
    )
    assert intercept.status_code == 200, intercept.text
    evidence_ids = intercept.json().get("evidence_nodes_created") or []
    assert evidence_ids

    challenge = client.post(
        "/auditor/challenge",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "control_id": control_id,
            "challenge_reason": "Evidence chain is incomplete for this control.",
            "evidence_node_ids": evidence_ids[:1],
        },
    )
    assert challenge.status_code == 200, challenge.text
    challenge_body = challenge.json()
    assert challenge_body["status"] == "open"
    assert challenge_body["reason"] == "auditor_challenge"
    assert challenge_body["details"]["requires_human_resolution"] is True
    conflict_id = challenge_body["id"]

    conflicts_response = client.get("/auditor/conflicts?status_filter=open", headers=headers)
    assert conflicts_response.status_code == 200, conflicts_response.text
    open_conflicts = _items(conflicts_response.json())
    assert any(row["id"] == conflict_id for row in open_conflicts)

    edges_response = client.get("/trust-center/evidence/edges", headers=headers)
    assert edges_response.status_code == 200, edges_response.text
    edges = _items(edges_response.json())
    assert any(edge["edge_type"] == "challenged_by" and edge["to_node_id"] in challenge_body["evidence_node_ids"] for edge in edges)

    resolve_response = client.post(
        f"/auditor/conflicts/{conflict_id}/resolve",
        headers=headers,
        json={"decision": "inconclusive", "notes": "Reviewed by human auditor"},
    )
    assert resolve_response.status_code == 200, resolve_response.text
    assert resolve_response.json()["status"] == "resolved"


def test_export_includes_runtime_monitoring_and_posture_views(test_env) -> None:
    client: TestClient = test_env["client"]

    owner = _register_owner(client, email="auditor-export-runtime-monitoring@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    control_id = f"CTRL-EXPORT-{uuid4().hex[:8]}"
    _create_control(client, headers=headers, control_id=control_id)
    ai_system_id = _create_ai_system(
        client,
        headers=headers,
        name="Export Runtime Monitoring System",
        approve=False,
    )

    approved = approve_ai_system(client, headers, ai_system_id)
    assert approved.status_code == 200, approved.text

    intercept = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "auditor",
            "prompt": "runtime payload for export validation",
            "context_summary": "auditor export coverage",
            "attachments_meta": [],
        },
    )
    assert intercept.status_code == 200, intercept.text

    monitor = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "connector.risk.exposed",
            "severity": "high",
            "payload": {
                "ai_tool": "openai",
                "reason_code": "connector_risk_exposed",
                "related_control_ids": [control_id],
            },
        },
    )
    assert monitor.status_code == 200, monitor.text

    exported = client.post("/auditor/export", headers=headers, json={"ai_system_id": ai_system_id})
    assert exported.status_code == 200, exported.text
    body = exported.json()

    _assert_relative_artifact_contract(body)
    assert client.get(body["download_urls"]["evidence_pack"], headers=headers).status_code == 200
    assert client.get(body["download_urls"]["pdf_ready_model"], headers=headers).status_code == 200

    payload = _download_json_artifact(client, headers=headers, body=body)
    runtime = payload.get("runtime_intelligence_inputs") or {}
    monitoring = payload.get("monitoring_inputs") or {}
    posture = payload.get("control_posture_views") or {}

    assert int(runtime.get("runtime_event_count") or 0) >= 1
    assert int(runtime.get("behavior_graph_edge_count") or 0) >= 1
    assert int(monitoring.get("monitoring_signal_count") or 0) >= 1
    assert int(monitoring.get("drift_alert_count") or 0) >= 1
    assert len(payload.get("findings") or []) >= 1
    assert isinstance(posture.get("framework"), list)
    assert isinstance(posture.get("domain"), list)
    assert isinstance(posture.get("ai_system"), list)

    csv_response = client.get(body["download_urls"]["csv"], headers=headers)
    assert csv_response.status_code == 200, csv_response.text
    csv_header = csv_response.text.splitlines()[0]
    assert "implementation_state" in csv_header
    assert "frameworks" in csv_header


def test_auditor_proof_chain_converges_browser_gateway_monitoring_and_validation(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="auditor-proof-chain@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    control_id = f"CTRL-PROOF-{uuid4().hex[:8]}"
    _create_control(client, headers=headers, control_id=control_id)
    ai_system_id = _create_ai_system(
        client,
        headers=headers,
        name="Proof Chain System",
        approve=False,
    )

    approve = approve_ai_system(client, headers, ai_system_id)
    assert approve.status_code == 200, approve.text

    _create_blocking_policy_version(
        client,
        headers=headers,
        trigger_token="proof-chain-block-token",
        version="9.9.9",
    )

    # Browser-originated finding + runtime trigger seed.
    for idx in range(3):
        browser = client.post(
            "/telemetry/browser",
            headers=headers,
            json={
                "event_type": "prompt_blocked",
                "ai_system_id": ai_system_id,
                "domain": "chat.openai.com",
                "url": "https://chat.openai.com",
                "action_taken": "block",
                "severity": "high",
                "prompt_preview_redacted": f"redacted sensitive prompt {idx}",
                "input_signal_types": ["prompt_injection", "sensitive_data_pattern"],
            },
        )
        assert browser.status_code == 200, browser.text
        assert browser.json().get("finding_id")

    # Gateway-originated finding.
    gateway = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "auditor-proof-user",
            "request_id": f"proof-gateway-{uuid4().hex[:8]}",
            "prompt": "execute proof-chain-block-token now",
            "context_summary": "proof chain gateway signal",
            "attachments_meta": [],
            "response_text": "blocked",
            "provider": "openai",
            "model": "gpt-4.1",
            "model_version": "2026-03",
        },
    )
    assert gateway.status_code == 200, gateway.text
    assert gateway.json().get("final_decision") == "block"

    # Simulation failure path.
    fail_sim_id = _create_simulation(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        control_id=control_id,
        assertion_operator="equals",
        assertion_value="never-match",
    )
    fail_run = _run_simulation(client, headers=headers, simulation_id=fail_sim_id, ai_system_id=ai_system_id)
    assert fail_run["results"]["result"] == "fail"

    # Drift alert path.
    drift = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "signal_type": "connector.risk.exposed",
            "severity": "high",
            "payload": {
                "ai_tool": "openai",
                "reason_code": "connector_risk_exposed",
                "related_control_ids": [control_id],
            },
        },
    )
    assert drift.status_code == 200, drift.text

    _revalidate_ai_system_for_snapshot(session_local, tenant_id=owner["tenant_id"], ai_system_id=ai_system_id)

    exported = client.post("/auditor/export", headers=headers, json={"ai_system_id": ai_system_id})
    assert exported.status_code == 200, exported.text
    body = exported.json()

    _assert_relative_artifact_contract(body)
    csv_response = client.get(body["download_urls"]["csv"], headers=headers)
    assert csv_response.status_code == 200
    assert client.get(body["download_urls"]["pdf_ready_model"], headers=headers).status_code == 200

    payload = _download_json_artifact(client, headers=headers, body=body)

    findings = list(payload.get("findings") or [])
    finding_types = {str(row.get("finding_type") or "") for row in findings}
    assert "browser_interaction_security" in finding_types
    assert "enforcement_event" in finding_types
    assert "drift_alert" in finding_types

    evidence_links = list(payload.get("evidence_links") or [])
    assert evidence_links
    evidence_ids = {str(row.get("node_id") or "").strip() for row in evidence_links if str(row.get("node_id") or "").strip()}
    assert evidence_ids

    finding_evidence_ids = {
        str(node_id).strip()
        for finding in findings
        for node_id in (finding.get("evidence_node_ids") or [])
        if str(node_id).strip()
    }
    assert finding_evidence_ids
    assert finding_evidence_ids.issubset(evidence_ids)

    runtime_inputs = dict(payload.get("runtime_intelligence_inputs") or {})
    runtime_triggers = list(runtime_inputs.get("runtime_triggers") or [])
    assert int(runtime_inputs.get("runtime_trigger_count") or 0) >= 1
    assert runtime_triggers
    assert any(str(item.get("reason_code") or "").strip() for item in runtime_triggers)
    assert any(str(item.get("path") or "").strip() == "/runtime-intelligence/triggers" for item in runtime_triggers)

    validation_inputs = dict(payload.get("validation_inputs") or {})
    outcomes = list(validation_inputs.get("simulation_outcomes") or [])
    assert any(str(row.get("result") or "").lower() == "fail" for row in outcomes)

    posture_explanations = list(payload.get("maturity_explanations") or [])
    explanation = next(
        (
            row
            for row in posture_explanations
            if row.get("ai_system_id") == ai_system_id and row.get("control_id") == control_id
        ),
        None,
    )
    assert explanation is not None
    assert isinstance((explanation.get("control_posture_explanation") or {}).get("why"), list)
    assert "INTERNAL" in (explanation.get("frameworks") or [])

    csv_header = csv_response.text.splitlines()[0]
    assert "implementation_state" in csv_header
    assert "frameworks" in csv_header

    pdf_ready_response = client.get(body["download_urls"]["pdf_ready_model"], headers=headers)
    assert pdf_ready_response.status_code == 200
    pdf_payload = pdf_ready_response.json()
    assert isinstance(pdf_payload.get("summary"), dict)
    assert isinstance(((pdf_payload.get("sections") or {}).get("runtime_intelligence") or {}), dict)


def test_export_preserves_challenge_and_conflict_ledger(test_env) -> None:
    client: TestClient = test_env["client"]

    owner = _register_owner(client, email="auditor-export-conflict-ledger@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    control_id = f"CTRL-LEDGER-{uuid4().hex[:8]}"
    _create_control(client, headers=headers, control_id=control_id)
    ai_system_id = _create_ai_system(
        client,
        headers=headers,
        name="Conflict Ledger System",
        approve=False,
    )

    approved = approve_ai_system(client, headers, ai_system_id)
    assert approved.status_code == 200, approved.text

    intercept = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "auditor",
            "prompt": "baseline prompt for challenge ledger",
            "context_summary": "challenge ledger flow",
            "attachments_meta": [],
        },
    )
    assert intercept.status_code == 200, intercept.text
    evidence_ids = intercept.json().get("evidence_nodes_created") or []
    assert evidence_ids

    challenge = client.post(
        "/auditor/challenge",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "control_id": control_id,
            "challenge_reason": "Need manual review before signoff.",
            "evidence_node_ids": evidence_ids[:1],
        },
    )
    assert challenge.status_code == 200, challenge.text
    challenge_body = challenge.json()
    conflict_id = challenge_body["id"]

    resolve = client.post(
        f"/auditor/conflicts/{conflict_id}/resolve",
        headers=headers,
        json={"decision": "inconclusive", "notes": "human resolved during export validation"},
    )
    assert resolve.status_code == 200, resolve.text

    exported = client.post("/auditor/export", headers=headers, json={"ai_system_id": ai_system_id})
    assert exported.status_code == 200, exported.text
    body = exported.json()
    payload = _download_json_artifact(client, headers=headers, body=body)

    conflicts = payload.get("conflicts") or []
    conflict = next((row for row in conflicts if row.get("conflict_id") == conflict_id), None)
    assert conflict is not None
    assert conflict.get("reason") == "auditor_challenge"
    details = conflict.get("details") or {}
    assert str(details.get("challenge_reason") or "").strip() != ""
    assert details.get("lineage_preserved") is True
    challenge_node_id = str(details.get("challenge_node_id") or "").strip()
    assert challenge_node_id
    assert str(conflict.get("resolution_notes") or "").strip() != ""

    resolutions = payload.get("conflict_resolutions") or []
    resolution = next((row for row in resolutions if row.get("conflict_id") == conflict_id), None)
    assert resolution is not None

    governance_state_changes = payload.get("governance_state_changes") or []
    # The approval (app/services/ai_system_approval_service.py) is among the governance changes the auditor exports.
    assert any(row.get("action") == "ai_system.approval.granted" for row in governance_state_changes)

    evidence_pack_response = client.get(body["download_urls"]["evidence_pack"], headers=headers)
    assert evidence_pack_response.status_code == 200, evidence_pack_response.text
    evidence_pack = evidence_pack_response.json()
    evidence_edges = list(evidence_pack.get("evidence_edges") or [])
    assert any(
        edge.get("edge_type") == "challenged_by"
        and str(edge.get("payload", {}).get("conflict_id") or "") == conflict_id
        for edge in evidence_edges
    )
    assert any(
        edge.get("edge_type") == "adjudicated"
        and str(edge.get("payload", {}).get("conflict_id") or "") == conflict_id
        for edge in evidence_edges
    )


def test_auditor_control_posture_view_endpoint(test_env) -> None:
    client: TestClient = test_env["client"]

    owner = _register_owner(client, email="auditor-control-posture@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    control_id = f"CTRL-POSTURE-{uuid4().hex[:8]}"
    _create_control(client, headers=headers, control_id=control_id)
    ai_system_id = _create_ai_system(client, headers=headers, name="Posture View System")

    sim_id = _create_simulation(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        control_id=control_id,
        assertion_operator="exists",
        assertion_value=True,
    )
    _run_simulation(client, headers=headers, simulation_id=sim_id, ai_system_id=ai_system_id)

    for group_by in ["framework", "domain", "ai_system"]:
        response = client.get(f"/auditor/control-posture?group_by={group_by}", headers=headers)
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["group_by"] == group_by
        assert isinstance(payload["rows"], list)
