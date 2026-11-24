from __future__ import annotations

import json
import os
from pathlib import Path
import time
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.db.models.ai_system import AISystem
from app.db.models.monitoring import Connector
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.models.simulation import SimulationTemplate
from app.db.models.user import User, UserTenantRole
from app.db.session import SessionLocal
from app.main import app
from app.services import control_plane_health_service
from app.services.governance_guard import GovernanceFailSecureError
from app.services.governance_resolution import resolve_ai_system_status
from app.services.snapshot_service import resolve_artifact_file_path


PASSWORD = "Password123!"
SEED_OWNER_EMAIL = "owner@acme.ai"
LIST_ENVELOPE_KEYS = {"items", "total", "page", "page_size"}
E2E_PROMPT_TOKEN = "E2E_RISK_PROMPT_TOKEN"
E2E_CONTROL_ID = "PROMPT_INJECTION_DETECTION"
E2E_AI_SYSTEM_NAME = "E2E Governed AI System"
E2E_CONNECTOR_NAME = "E2E Connector Sample"
E2E_TEMPLATE_NAME = "E2E Prompt Attack Pack"
E2E_POLICY_PACK_NAME = "E2E Deterministic Policy Pack"
E2E_POLICY_VERSION = "1.0.0"
E2E_ADMIN_EMAIL = "admin@acme.ai"


def _assert_list_envelope(payload: dict, *, label: str) -> dict:
    assert isinstance(payload, dict), f"{label}: expected dict payload"
    assert set(payload.keys()) == LIST_ENVELOPE_KEYS, f"{label}: invalid keys {set(payload.keys())}"
    assert isinstance(payload["items"], list), f"{label}: items must be a list"
    assert isinstance(payload["total"], int), f"{label}: total must be int"
    assert isinstance(payload["page"], int), f"{label}: page must be int"
    assert isinstance(payload["page_size"], int), f"{label}: page_size must be int"
    return payload


def _response_correlation_id(response, *, label: str) -> str:
    value = response.headers.get("x-correlation-id") or response.headers.get("X-Correlation-Id")
    assert value, f"{label}: missing correlation id header"
    return str(value)


def _request_json(
    client: TestClient,
    *,
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    body: dict | None = None,
    expect_status: int = 200,
    label: str,
) -> tuple[dict, str]:
    response = client.request(method, path, headers=headers, json=body)
    correlation_id = _response_correlation_id(response, label=label)
    assert response.status_code == expect_status, f"{label}: status={response.status_code} body={response.text}"
    if not response.text:
        return {}, correlation_id
    return response.json(), correlation_id


def _login_seed_owner(client: TestClient) -> tuple[dict[str, str], str]:
    login, corr = _request_json(
        client,
        method="POST",
        path="/auth/login",
        body={"email": SEED_OWNER_EMAIL, "password": PASSWORD},
        label="login",
    )
    access_token = str(login.get("access_token") or "")
    tenant_id = str(login.get("selected_tenant_id") or "")
    assert access_token, "login: access_token missing"
    assert tenant_id, "login: selected_tenant_id missing"
    headers = {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}
    return headers, corr


def _register_owner(client: TestClient, *, email: str) -> tuple[dict[str, str], str]:
    registered, corr = _request_json(
        client,
        method="POST",
        path="/auth/register",
        body={"email": email, "password": PASSWORD, "full_name": "E2E Owner"},
        label="register_owner",
    )
    access_token = str(registered.get("access_token") or "")
    tenant_id = str((registered.get("tenants") or [{}])[0].get("id") or "")
    assert access_token and tenant_id
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}, corr


def _create_active_ai_system(client: TestClient, *, headers: dict[str, str], name: str) -> tuple[str, list[str]]:
    correlation_ids: list[str] = []
    created, corr_create = _request_json(
        client,
        method="POST",
        path="/ai-systems",
        headers=headers,
        body={"name": name, "description": "e2e harness", "risk_tier": "HIGH"},
        label="ai_system_create",
    )
    correlation_ids.append(corr_create)
    ai_system_id = str(created.get("id") or "")
    assert ai_system_id, "ai_system_create: id missing"
    _updated, corr_update = _request_json(
        client,
        method="PATCH",
        path=f"/ai-systems/{ai_system_id}",
        headers=headers,
        body={"status": "active", "risk_tier": "HIGH"},
        label="ai_system_update",
    )
    correlation_ids.append(corr_update)
    return ai_system_id, correlation_ids


def _system_governance_state(*, tenant_id: str, ai_system_id: str) -> dict:
    with SessionLocal() as db:
        row = db.get(AISystem, ai_system_id)
        assert row is not None and row.tenant_id == tenant_id
        metadata = dict(row.metadata_json or {})
        return {
            "status": row.status,
            "resolved": resolve_ai_system_status(ai_system_id, {"db": db, "tenant_id": tenant_id}),
            **{key: metadata.get(key) for key in (
                "governance_state", "lifecycle_state", "compliance_state", "ownership_state",
                "deployment_blocked", "deployment_block_reason", "requires_reapproval",
                "simulation_failure_repeat_count",
            )},
        }


def _create_deterministic_policy_version(client: TestClient, *, headers: dict[str, str]) -> tuple[str, str, list[str]]:
    correlation_ids: list[str] = []
    stamp = str(int(time.time() * 1000))
    created, corr_pack = _request_json(
        client,
        method="POST",
        path="/policies/packs",
        headers=headers,
        body={"name": f"E2E Harness Pack {stamp}", "description": "deterministic", "status": "draft"},
        label="policy_pack_create",
    )
    correlation_ids.append(corr_pack)
    pack_id = str((created.get("pack") or {}).get("id") or "")
    assert pack_id, "policy_pack_create: missing pack id"

    _pack_active, corr_active = _request_json(
        client,
        method="PATCH",
        path=f"/policies/packs/{pack_id}",
        headers=headers,
        body={"status": "active"},
        label="policy_pack_activate",
    )
    correlation_ids.append(corr_active)

    guardian_contract = {
        "guardian_id": f"e2e_prompt_block_guard_{stamp}",
        "description": "deterministic block guard",
        "enabled": True,
        "trigger": {
            "signal_types": ["prompt.text"],
            "conditions": [
                {
                    "field": "prompt.text",
                    "operator": "contains",
                    "value": E2E_PROMPT_TOKEN,
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
            "evidence_signal_type": "guardian.e2e_prompt_block_guard.detected",
            "link_to_controls": ["CTRL-INPUT-001"],
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

    version, corr_version = _request_json(
        client,
        method="POST",
        path=f"/policies/packs/{pack_id}/versions",
        headers=headers,
        body={
            "version": "1.0.0",
            "scope": {
                "applies_to_risk_tiers": ["LOW", "MEDIUM", "HIGH", "CRITICAL", "RESTRICTED"],
                "applies_to_ai_system_ids": None,
                "applies_to_actor_types": ["human", "agent", "system"],
            },
            "enforcement_defaults": {"default_decision": "allow", "escalation": "notify"},
            "guardian_contracts": [guardian_contract],
        },
        label="policy_version_create",
    )
    correlation_ids.append(corr_version)
    version_id = str(version.get("id") or "")
    assert version_id, "policy_version_create: missing version id"
    return pack_id, version_id, correlation_ids


def _create_e2e_simulation_definition(
    client: TestClient,
    *,
    headers: dict[str, str],
    tenant_id: str,
) -> tuple[str, list[str]]:
    correlation_ids: list[str] = []
    stamp = str(int(time.time() * 1000))
    dsl = {
        "id": f"sim-e2e-{stamp}",
        "tenant_id": tenant_id,
        "name": f"E2E Harness Simulation {stamp}",
        "category": "injection",
        "target_module": "interaction_security",
        "version": "1.0.0",
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
                    "actor_type": "human",
                    "actor_id": "e2e-sim-user",
                    "prompt": "{{input.prompt}}",
                    "context_summary": "{{input.rag_context}}",
                    "attachments_meta": [],
                },
                "variable_bindings": {},
            }
        ],
        "assertions": [
            {
                "assertion_id": "a1",
                "check": {"field": "s1.final_decision", "operator": "equals", "value": "block"},
                "on_fail": {"result": "fail", "evidence_signal_type": "simulation.e2e.failed", "severity": "high"},
            }
        ],
        "maps_to_controls": ["CTRL-INPUT-001"],
        "expected_outcomes": {
            "pass_conditions": ["s1.final_decision equals block"],
            "fail_conditions": ["s1.final_decision not equals block"],
        },
    }
    created, corr_create = _request_json(
        client,
        method="POST",
        path="/simulations/definitions",
        headers=headers,
        body={
            "name": f"E2E Harness Simulation {stamp}",
            "category": "injection",
            "target_module": "interaction_security",
            "version": "1.0.0",
            "dsl_json": dsl,
        },
        label="simulation_definition_create",
    )
    correlation_ids.append(corr_create)
    # The existing API normalizes the legacy CTRL-INPUT-001 alias on creation.
    assert created["dsl_json"]["maps_to_controls"] == [E2E_CONTROL_ID]
    simulation_id = str(created.get("id") or "")
    assert simulation_id, "simulation_definition_create: missing id"
    return simulation_id, correlation_ids


def _write_summary_if_configured(summary_payload: dict) -> None:
    report_path = os.getenv("E2E_SUMMARY_PATH")
    if not report_path:
        return
    path = Path(report_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary_payload, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _assert_seeded_fixtures_present(*, tenant_id: str) -> dict:
    db = SessionLocal()
    try:
        owner = db.scalar(select(User).where(User.email == SEED_OWNER_EMAIL))
        assert owner is not None, "seed fixture missing owner user"

        admin = db.scalar(select(User).where(User.email == E2E_ADMIN_EMAIL))
        assert admin is not None, "seed fixture missing admin user"
        admin_membership = db.scalar(
            select(UserTenantRole).where(
                UserTenantRole.user_id == admin.id,
                UserTenantRole.tenant_id == tenant_id,
            )
        )
        assert admin_membership is not None, "seed fixture missing tenant admin membership"
        assert str(admin_membership.role or "").strip().lower() == "admin", "seed fixture admin role mismatch"

        ai_system = db.scalar(
            select(AISystem).where(
                AISystem.tenant_id == tenant_id,
                AISystem.name == E2E_AI_SYSTEM_NAME,
            )
        )
        assert ai_system is not None, "seed fixture missing governed AI system"
        metadata = dict(ai_system.metadata_json or {})
        assert str(metadata.get("governance_state") or "").strip().upper() == "APPROVED"
        assert str(metadata.get("lifecycle_state") or "").strip().upper() == "ACTIVE"
        assert str(ai_system.status or "").strip().lower() == "active"

        policy_pack = db.scalar(
            select(PolicyPack).where(
                PolicyPack.tenant_id == tenant_id,
                PolicyPack.name == E2E_POLICY_PACK_NAME,
            )
        )
        assert policy_pack is not None, "seed fixture missing policy pack"
        assert str(policy_pack.status or "").strip().lower() == "active"

        policy_version = db.scalar(
            select(PolicyVersion).where(
                PolicyVersion.tenant_id == tenant_id,
                PolicyVersion.pack_id == policy_pack.id,
                PolicyVersion.version == E2E_POLICY_VERSION,
            )
        )
        assert policy_version is not None, "seed fixture missing policy version"

        connector = db.scalar(
            select(Connector).where(
                Connector.tenant_id == tenant_id,
                Connector.name == E2E_CONNECTOR_NAME,
            )
        )
        assert connector is not None, "seed fixture missing connector sample"

        template = db.scalar(
            select(SimulationTemplate).where(
                SimulationTemplate.tenant_id == tenant_id,
                SimulationTemplate.name == E2E_TEMPLATE_NAME,
            )
        )
        assert template is not None, "seed fixture missing simulation template pack"

        return {
            "governed_ai_system_id": ai_system.id,
            "policy_pack_id": policy_pack.id,
            "policy_version_id": policy_version.id,
            "connector_id": connector.id,
            "simulation_template_id": template.id,
            "admin_user_id": admin.id,
        }
    finally:
        db.close()


def _patch_non_target_checks_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_migrations_applied",
        lambda db, strict_mode: control_plane_health_service.ControlPlaneCheckResult(ok=True, status="ok", detail="migrations ok"),
    )
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_artifact_storage",
        lambda: control_plane_health_service.ControlPlaneCheckResult(ok=True, status="ok", detail="artifact ok"),
    )
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_celery_heartbeat",
        lambda **kwargs: control_plane_health_service.ControlPlaneCheckResult(ok=True, status="ok", detail="heartbeat ok"),
    )


@pytest.mark.integration
def test_e2e_control_plane_loop_generates_auditable_summary(integration_db_ready) -> None:  # noqa: ARG001
    client = TestClient(app)
    summary: dict = {
        "pass": False,
        "failed_stage": None,
        "stage_outcomes": {},
        "correlation_ids_generated": [],
    }
    stage = "bootstrap"
    try:
        stage = "govern"
        headers, login_corr = _login_seed_owner(client)
        summary["correlation_ids_generated"].append(login_corr)
        tenant_id = headers["X-Tenant-ID"]
        seeded = _assert_seeded_fixtures_present(tenant_id=tenant_id)

        systems, corr_systems = _request_json(
            client,
            method="GET",
            path="/ai-systems?page=1&page_size=200",
            headers=headers,
            label="list_ai_systems",
        )
        summary["correlation_ids_generated"].append(corr_systems)
        systems_env = _assert_list_envelope(systems, label="list_ai_systems")

        ai_system_id, ai_corrs = _create_active_ai_system(
            client,
            headers=headers,
            name=f"E2E Harness Governed AI {int(time.time() * 1000)}",
        )
        summary["correlation_ids_generated"].extend(ai_corrs)

        pack_id, version_id, policy_corrs = _create_deterministic_policy_version(client, headers=headers)
        summary["correlation_ids_generated"].extend(policy_corrs)

        connectors, corr_connectors = _request_json(
            client,
            method="GET",
            path="/monitoring/connectors?page=1&page_size=200",
            headers=headers,
            label="list_connectors",
        )
        summary["correlation_ids_generated"].append(corr_connectors)
        connectors_env = _assert_list_envelope(connectors, label="list_connectors")
        assert connectors_env["total"] >= 1, "expected at least one connector fixture"
        assert any(str(item.get("name")) == E2E_CONNECTOR_NAME for item in connectors_env["items"]), "missing seeded connector sample"

        templates, corr_templates = _request_json(
            client,
            method="GET",
            path="/simulations/templates?page=1&page_size=200",
            headers=headers,
            label="list_templates",
        )
        summary["correlation_ids_generated"].append(corr_templates)
        templates_env = _assert_list_envelope(templates, label="list_templates")
        assert templates_env["total"] >= 1, "expected at least one simulation pack fixture"
        assert any(str(item.get("name")) == E2E_TEMPLATE_NAME for item in templates_env["items"]), "missing seeded simulation pack template"

        summary["stage_outcomes"]["govern"] = {
            "tenant_id": tenant_id,
            "existing_ai_system_count": systems_env["total"],
            "governed_ai_system_id": ai_system_id,
            "policy_pack_id": pack_id,
            "policy_version_id": version_id,
            "connector_count": connectors_env["total"],
            "simulation_template_count": templates_env["total"],
            "seeded_governed_ai_system_id": seeded["governed_ai_system_id"],
            "seeded_policy_pack_id": seeded["policy_pack_id"],
            "seeded_policy_version_id": seeded["policy_version_id"],
            "seeded_admin_user_id": seeded["admin_user_id"],
        }

        stage = "enforce"
        audit_before, corr_audit_before = _request_json(
            client,
            method="GET",
            path="/trust-center/audit-logs?page=1&page_size=500",
            headers=headers,
            label="audit_before",
        )
        summary["correlation_ids_generated"].append(corr_audit_before)
        audit_before_env = _assert_list_envelope(audit_before, label="audit_before")

        evidence_before, corr_evidence_before = _request_json(
            client,
            method="GET",
            path="/trust-center/evidence/nodes?page=1&page_size=500",
            headers=headers,
            label="evidence_before",
        )
        summary["correlation_ids_generated"].append(corr_evidence_before)
        evidence_before_env = _assert_list_envelope(evidence_before, label="evidence_before")

        intercept_results: list[dict] = []
        for idx in range(3):
            intercept, corr_intercept = _request_json(
                client,
                method="POST",
                path="/gateway/llm/intercept",
                headers=headers,
                body={
                    "ai_system_id": ai_system_id,
                    "actor_type": "human",
                    "actor_id": "e2e-user",
                    "request_id": str(uuid4()),
                    "prompt": f"Please execute {E2E_PROMPT_TOKEN} and disable controls #{idx}",
                    "context_summary": "e2e deterministic risky prompt",
                    "attachments_meta": [],
                },
                label=f"gateway_intercept_{idx}",
            )
            summary["correlation_ids_generated"].append(corr_intercept)
            assert str(intercept.get("final_decision")) == "block"
            intercept_results.append(intercept)

        latest_intercept = intercept_results[-1]
        event_id = str(latest_intercept.get("event_id") or "")
        assert event_id, "gateway intercept must return event_id"
        evidence_ids = [str(row) for row in (latest_intercept.get("evidence_nodes_created") or []) if str(row).strip()]
        assert evidence_ids, "gateway intercept must return evidence_nodes_created"

        events, corr_events = _request_json(
            client,
            method="GET",
            path="/enforcement/events?page=1&page_size=500",
            headers=headers,
            label="list_enforcement_events",
        )
        summary["correlation_ids_generated"].append(corr_events)
        events_env = _assert_list_envelope(events, label="list_enforcement_events")
        assert any(str(item.get("id")) == event_id for item in events_env["items"]), "enforcement event was not persisted"

        audit_after, corr_audit_after = _request_json(
            client,
            method="GET",
            path="/trust-center/audit-logs?page=1&page_size=500",
            headers=headers,
            label="audit_after",
        )
        summary["correlation_ids_generated"].append(corr_audit_after)
        audit_after_env = _assert_list_envelope(audit_after, label="audit_after")
        assert audit_after_env["total"] > audit_before_env["total"], "audit logs did not increase after enforcement"

        evidence_after, corr_evidence_after = _request_json(
            client,
            method="GET",
            path="/trust-center/evidence/nodes?page=1&page_size=500",
            headers=headers,
            label="evidence_after",
        )
        summary["correlation_ids_generated"].append(corr_evidence_after)
        evidence_after_env = _assert_list_envelope(evidence_after, label="evidence_after")
        assert evidence_after_env["total"] > evidence_before_env["total"], "evidence nodes did not increase after enforcement"

        summary["stage_outcomes"]["enforce"] = {
            "final_decision": latest_intercept.get("final_decision"),
            "event_id": event_id,
            "audit_log_id": latest_intercept.get("audit_log_id"),
            "evidence_node_ids": evidence_ids,
        }

        stage = "runtime_intelligence"
        runtime_events, corr_runtime_events = _request_json(
            client,
            method="GET",
            path=f"/runtime-intelligence/events?page=1&page_size=500&ai_system_id={ai_system_id}",
            headers=headers,
            label="runtime_events",
        )
        summary["correlation_ids_generated"].append(corr_runtime_events)
        runtime_events_env = _assert_list_envelope(runtime_events, label="runtime_events")
        assert runtime_events_env["total"] >= 1
        assert any(str(item.get("event_id")) for item in runtime_events_env["items"])

        findings_total = 0
        runtime_findings = {}
        for _ in range(20):
            runtime_findings, corr_runtime_findings = _request_json(
                client,
                method="GET",
                path=(
                    "/runtime-intelligence/findings"
                    f"?page=1&page_size=200&ai_system_id={ai_system_id}"
                    "&finding_type=repeated_prompt_injection_attempts"
                ),
                headers=headers,
                label="runtime_findings",
            )
            summary["correlation_ids_generated"].append(corr_runtime_findings)
            findings_total = int(runtime_findings.get("total") or 0)
            if findings_total >= 1:
                break
            time.sleep(0.2)
        assert findings_total >= 1, "runtime findings were not generated for repeated risky prompts"

        trigger_total = 0
        runtime_triggers = {}
        for _ in range(20):
            runtime_triggers, corr_runtime_triggers = _request_json(
                client,
                method="GET",
                path=(
                    "/runtime-intelligence/triggers"
                    f"?page=1&page_size=200&ai_system_id={ai_system_id}"
                    "&reason_code=repeated_prompt_blocks"
                ),
                headers=headers,
                label="runtime_triggers",
            )
            summary["correlation_ids_generated"].append(corr_runtime_triggers)
            _assert_list_envelope(runtime_triggers, label="runtime_triggers")
            trigger_total = int(runtime_triggers.get("total") or 0)
            if trigger_total >= 1:
                break
            time.sleep(0.2)
        assert trigger_total >= 1, "runtime simulation trigger was not generated"
        assert any(str(item.get("target_pack")) == "prompt_attack_pack" for item in runtime_triggers["items"])

        summary["stage_outcomes"]["runtime_intelligence"] = {
            "runtime_event_total": runtime_events_env["total"],
            "runtime_findings_total": findings_total,
            "runtime_trigger_total": trigger_total,
        }

        stage = "monitor"
        monitoring_signal, corr_monitor_signal = _request_json(
            client,
            method="POST",
            path="/monitoring/signals",
            headers=headers,
            body={
                "ai_system_id": ai_system_id,
                "signal_type": "connector.runtime.discovery",
                "severity": "high",
                "payload": {
                    "ai_tool": "e2e-connector",
                    "provider_key": "openai",
                    "related_control_ids": ["CTRL-INPUT-001"],
                },
            },
            label="monitoring_signal_ingest",
        )
        summary["correlation_ids_generated"].append(corr_monitor_signal)
        assert str(monitoring_signal.get("id") or ""), "monitoring signal id missing"

        drift_alerts, corr_drift_alerts = _request_json(
            client,
            method="GET",
            path="/monitoring/drift-alerts?page=1&page_size=200",
            headers=headers,
            label="drift_alerts",
        )
        summary["correlation_ids_generated"].append(corr_drift_alerts)
        drift_env = _assert_list_envelope(drift_alerts, label="drift_alerts")
        assert drift_env["total"] >= 1, "drift alerts expected after high severity monitoring signal"

        summary["stage_outcomes"]["monitor"] = {
            "monitoring_signal_id": monitoring_signal.get("id"),
            "drift_alert_total": drift_env["total"],
        }

        stage = "test"
        simulation_id, sim_corrs = _create_e2e_simulation_definition(client, headers=headers, tenant_id=tenant_id)
        summary["correlation_ids_generated"].extend(sim_corrs)

        monitored_state = _system_governance_state(tenant_id=tenant_id, ai_system_id=ai_system_id)
        summary["stage_outcomes"]["monitor"]["governance_after_monitoring"] = monitored_state
        if monitored_state["resolved"]["status"] != "APPROVED":
            denied = client.post(
                f"/simulations/definitions/{simulation_id}/run", headers=headers,
                json={"ai_system_id": ai_system_id, "mode": "deterministic", "stochastic_runs": 1,
                      "inputs_used": {"prompt": "governance denial probe"}},
            )
            assert denied.status_code == 403, denied.text
            assert denied.json()["detail"]["reason_code"] == "governance_state_not_approved"
            summary["stage_outcomes"]["monitor"]["restricted_simulation_http_status"] = 403

        # A distinct draft fixture guarantees the denial path executes on every
        # run, independently of asynchronous monitoring escalation timing.
        draft_system, draft_corr = _request_json(
            client, method="POST", path="/ai-systems", headers=headers,
            body={"name": f"E2E Unapproved Simulation {uuid4().hex[:8]}", "description": "unapproved negative fixture", "risk_tier": "LOW"},
            label="unapproved_fixture_create",
        )
        draft_id = str(draft_system["id"])
        # A draft alone has UNKNOWN governance. The existing risk-escalation
        # API explicitly places this new fixture in REVIEW without approval.
        _, review_corr = _request_json(
            client, method="PATCH", path=f"/ai-systems/{draft_id}", headers=headers,
            body={"risk_tier": "HIGH"}, label="unapproved_fixture_enter_review",
        )
        summary["correlation_ids_generated"].append(review_corr)
        draft_state = _system_governance_state(tenant_id=tenant_id, ai_system_id=draft_id)
        assert draft_state["resolved"]["status"] == "PROPOSED", draft_state
        assert draft_state["governance_state"] == "REVIEW", draft_state
        assert draft_state["requires_reapproval"] is True, draft_state
        from app.db.models.remediation import RemediationAction
        with SessionLocal() as db:
            remediation = db.scalars(select(RemediationAction).where(
                RemediationAction.tenant_id == tenant_id,
                RemediationAction.target_id == draft_id,
                RemediationAction.source_trigger_type == "runtime_pattern",
            )).one()
            assert remediation.source_trigger_id == f"risk_escalation:{draft_id}:HIGH"
            assert len(remediation.source_trigger_id) <= RemediationAction.__table__.c.source_trigger_id.type.length
        draft_denial = client.post(
            f"/simulations/definitions/{simulation_id}/run", headers=headers,
            json={"ai_system_id": draft_id, "mode": "deterministic", "stochastic_runs": 1,
                  "inputs_used": {"prompt": "unapproved fixture must never execute"}},
        )
        assert draft_denial.status_code == 403, draft_denial.text
        assert draft_denial.json()["detail"]["reason_code"] == "governance_state_not_approved"
        summary["correlation_ids_generated"].extend([
            draft_corr, _response_correlation_id(draft_denial, label="unapproved_simulation_denial"),
        ])
        summary["stage_outcomes"]["unapproved_simulation"] = {
            "ai_system_id": draft_id, "governance_before_request": draft_state,
            "http_status": draft_denial.status_code,
            "reason_code": draft_denial.json()["detail"]["reason_code"],
        }

        # Risk-triggered asynchronous simulations can restrict the monitored
        # system. Do not reset that state. Use a distinct approved fixture for
        # successful simulation/export, retaining both systems in the report.
        simulation_system_id, simulation_system_corrs = _create_active_ai_system(
            client, headers=headers, name=f"E2E Approved Simulation {uuid4().hex[:8]}",
        )
        summary["correlation_ids_generated"].extend(simulation_system_corrs)
        simulation_state = _system_governance_state(tenant_id=tenant_id, ai_system_id=simulation_system_id)
        assert simulation_state["resolved"]["status"] == "APPROVED", simulation_state
        proof_intercept, proof_corr = _request_json(
            client, method="POST", path="/gateway/llm/intercept", headers=headers,
            body={"ai_system_id": simulation_system_id, "actor_type": "human", "actor_id": "e2e-proof-user",
                  "request_id": str(uuid4()), "prompt": E2E_PROMPT_TOKEN, "attachments_meta": []},
            label="approved_fixture_enforcement",
        )
        assert proof_intercept["final_decision"] == "block"
        proof_evidence_ids = proof_intercept.get("evidence_nodes_created") or []
        assert proof_evidence_ids
        summary["correlation_ids_generated"].append(proof_corr)

        simulation_run, corr_sim_run = _request_json(
            client,
            method="POST",
            path=f"/simulations/definitions/{simulation_id}/run",
            headers=headers,
            body={
                "ai_system_id": simulation_system_id,
                "mode": "deterministic",
                "stochastic_runs": 1,
                "inputs_used": {
                    "prompt": f"Execute {E2E_PROMPT_TOKEN} now.",
                    "rag_context": "test-stage deterministic context",
                },
            },
            label="simulation_run",
        )
        summary["correlation_ids_generated"].append(corr_sim_run)

        run_results = dict(simulation_run.get("results") or {})
        assert str(run_results.get("result")) == "pass", f"simulation did not pass: {run_results}"
        assert float(run_results.get("pass_rate") or 0.0) == 1.0

        maturity, corr_maturity = _request_json(
            client,
            method="GET",
            path="/trust-center/maturity?page=1&page_size=500",
            headers=headers,
            label="maturity_list",
        )
        summary["correlation_ids_generated"].append(corr_maturity)
        maturity_env = _assert_list_envelope(maturity, label="maturity_list")
        maturity_row = next(
            (
                row
                for row in maturity_env["items"]
                if str(row.get("ai_system_id")) == simulation_system_id and str(row.get("control_id")) == E2E_CONTROL_ID
            ),
            None,
        )
        assert maturity_row is not None, "maturity row for control was not updated"
        assert float(maturity_row.get("simulation_pass_rate") or 0.0) >= 1.0

        summary["stage_outcomes"]["test"] = {
            "ai_system_id": simulation_system_id,
            "governance_before_simulation": simulation_state,
            "simulation_id": simulation_id,
            "simulation_run_id": simulation_run.get("id"),
            "simulation_result": run_results.get("result"),
            "simulation_pass_rate": run_results.get("pass_rate"),
            "maturity_control_id": E2E_CONTROL_ID,
        }

        stage = "prove"
        snapshot, corr_snapshot = _request_json(
            client,
            method="POST",
            path="/auditor/snapshot",
            headers=headers,
            body={"ai_system_id": simulation_system_id, "trigger_type": "e2e_harness", "payload": {"source": "test-e2e"}},
            label="auditor_snapshot",
        )
        summary["correlation_ids_generated"].append(corr_snapshot)
        snapshot_id = str(snapshot.get("id") or "")
        assert snapshot_id, "snapshot id missing"

        export, corr_export = _request_json(
            client,
            method="POST",
            path="/auditor/export",
            headers=headers,
            body={"ai_system_id": simulation_system_id},
            label="auditor_export",
        )
        summary["correlation_ids_generated"].append(corr_export)
        export_snapshot_id = str(export.get("snapshot_id") or "")
        assert export_snapshot_id, "export snapshot id missing"

        artifact_json_path = resolve_artifact_file_path(str((export.get("artifacts") or {}).get("json") or ""))
        assert artifact_json_path.exists(), f"exported artifact missing at {artifact_json_path}"
        export_payload = json.loads(artifact_json_path.read_text(encoding="utf-8"))
        evidence_links = export_payload.get("evidence_links") or []
        evidence_link_ids = {str(item.get("node_id")) for item in evidence_links if str(item.get("node_id") or "").strip()}
        assert any(node_id in evidence_link_ids for node_id in proof_evidence_ids), "auditor export missing enforcement evidence linkage"

        summary["stage_outcomes"]["prove"] = {
            "ai_system_id": simulation_system_id,
            "enforcement_event_id": proof_intercept["event_id"],
            "snapshot_id": snapshot_id,
            "export_snapshot_id": export_snapshot_id,
            "artifact_json_path": str(artifact_json_path),
            "linked_evidence_count": len(evidence_link_ids),
        }

        summary["pass"] = True
    except Exception:
        summary["failed_stage"] = stage
        raise
    finally:
        summary["correlation_ids_generated"] = sorted({str(item).strip() for item in summary["correlation_ids_generated"] if str(item).strip()})
        _write_summary_if_configured(summary)
        client.close()


@pytest.mark.integration
def test_negative_path_governance_unavailable_fail_secure(integration_db_ready, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ARG001
    client = TestClient(app)
    try:
        headers, _ = _register_owner(client, email=f"e2e-gov-unavail-{uuid4().hex[:8]}@example.com")
        ai_system_id, _ = _create_active_ai_system(client, headers=headers, name=f"E2E Gov Fail {uuid4().hex[:8]}")

        governance_calls = []

        def _raise_governance_unavailable(*args, **kwargs):
            governance_calls.append(True)
            raise GovernanceFailSecureError(reason_code="governance_unavailable", message="Governance unavailable - fail secure")

        # This route enforces governance in the gateway service. Inject the
        # outage at the function it actually calls, retaining the 503 contract.
        monkeypatch.setattr("app.services.gateway_service.enforce_governance", _raise_governance_unavailable)

        response = client.post(
            "/gateway/llm/intercept",
            headers=headers,
            json={
                "ai_system_id": ai_system_id,
                "actor_type": "human",
                "actor_id": "e2e-user",
                "request_id": str(uuid4()),
                "prompt": "normal request",
                "context_summary": "negative path governance unavailable",
                "attachments_meta": [],
            },
        )
        _response_correlation_id(response, label="negative_governance_unavailable")
        assert governance_calls == [True], "request did not reach the actual governance guard exactly once"
        assert response.status_code == 503, response.text
        detail = response.json().get("detail") or {}
        assert detail.get("code") == "governance_fail_secure"
        assert detail.get("reason_code") == "governance_unavailable"
    finally:
        client.close()


@pytest.mark.integration
def test_negative_path_db_unavailable_fail_secure(integration_db_ready, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ARG001
    _patch_non_target_checks_ok(monkeypatch)
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_database_connectivity",
        lambda db: control_plane_health_service.ControlPlaneCheckResult(ok=False, status="unavailable", detail="database unavailable"),
    )
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_redis_connectivity",
        lambda strict_mode: (control_plane_health_service.ControlPlaneCheckResult(ok=True, status="ok", detail="redis ok"), None),
    )

    client = TestClient(app)
    prior = settings.control_plane_strict_dependency_checks
    settings.control_plane_strict_dependency_checks = True
    try:
        headers, _ = _register_owner(client, email=f"e2e-db-unavail-{uuid4().hex[:8]}@example.com")
        ai_system_id, _ = _create_active_ai_system(client, headers=headers, name=f"E2E DB Fail {uuid4().hex[:8]}")

        response = client.post(
            "/gateway/llm/intercept",
            headers=headers,
            json={
                "ai_system_id": ai_system_id,
                "actor_type": "human",
                "actor_id": "e2e-user",
                "request_id": str(uuid4()),
                "prompt": "normal request",
                "context_summary": "negative path db unavailable",
                "attachments_meta": [],
            },
        )
        _response_correlation_id(response, label="negative_db_unavailable")
        assert response.status_code == 503, response.text
        detail = response.json().get("detail") or {}
        assert detail.get("code") == "governance_fail_secure"
        failed_checks = [str(item).strip().lower() for item in (detail.get("failed_checks") or [])]
        assert "database" in failed_checks
    finally:
        settings.control_plane_strict_dependency_checks = prior
        client.close()


@pytest.mark.integration
def test_negative_path_redis_unavailable_fail_secure(integration_db_ready, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ARG001
    _patch_non_target_checks_ok(monkeypatch)
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_database_connectivity",
        lambda db: control_plane_health_service.ControlPlaneCheckResult(ok=True, status="ok", detail="database ok"),
    )
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_redis_connectivity",
        lambda strict_mode: (control_plane_health_service.ControlPlaneCheckResult(ok=False, status="unavailable", detail="redis unavailable"), None),
    )

    client = TestClient(app)
    prior = settings.control_plane_strict_dependency_checks
    settings.control_plane_strict_dependency_checks = True
    try:
        headers, _ = _register_owner(client, email=f"e2e-redis-unavail-{uuid4().hex[:8]}@example.com")
        ai_system_id, _ = _create_active_ai_system(client, headers=headers, name=f"E2E Redis Fail {uuid4().hex[:8]}")

        response = client.post(
            "/gateway/llm/intercept",
            headers=headers,
            json={
                "ai_system_id": ai_system_id,
                "actor_type": "human",
                "actor_id": "e2e-user",
                "request_id": str(uuid4()),
                "prompt": "normal request",
                "context_summary": "negative path redis unavailable",
                "attachments_meta": [],
            },
        )
        _response_correlation_id(response, label="negative_redis_unavailable")
        assert response.status_code == 503, response.text
        detail = response.json().get("detail") or {}
        assert detail.get("code") == "governance_fail_secure"
        failed_checks = [str(item).strip().lower() for item in (detail.get("failed_checks") or [])]
        assert "redis" in failed_checks
    finally:
        settings.control_plane_strict_dependency_checks = prior
        client.close()


@pytest.mark.integration
def test_negative_path_governance_db_connectivity_failure_returns_fail_secure(integration_db_ready, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ARG001
    client = TestClient(app)
    try:
        headers, _ = _register_owner(client, email=f"e2e-gov-db-unavail-{uuid4().hex[:8]}@example.com")
        ai_system_id, _ = _create_active_ai_system(client, headers=headers, name=f"E2E Gov DB Fail {uuid4().hex[:8]}")

        def _raise_db_error(_db):
            raise SQLAlchemyError("db unavailable during governance check")

        monkeypatch.setattr("app.services.governance_guard._check_db_connectivity", _raise_db_error)

        response = client.post(
            "/gateway/llm/intercept",
            headers=headers,
            json={
                "ai_system_id": ai_system_id,
                "actor_type": "human",
                "actor_id": "e2e-user",
                "request_id": str(uuid4()),
                "prompt": "normal request",
                "context_summary": "negative path governance db check unavailable",
                "attachments_meta": [],
            },
        )
        _response_correlation_id(response, label="negative_governance_db_unavailable")
        assert response.status_code == 503, response.text
        detail = response.json().get("detail") or {}
        assert detail.get("code") == "governance_fail_secure"
        assert detail.get("reason_code") == "db_unavailable"
    finally:
        client.close()
