from __future__ import annotations

import os
import threading
import time
from typing import Any

import pytest
from fastapi import BackgroundTasks
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session, sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.core.security import get_password_hash
from app.db.models.activity_audit import UserRegistry
from app.db.models.ai_iam import AgentIdentity, CapabilityToken
from app.db.models.audit import AuditLog
from app.db.models.evidence import EvidenceEdge, EvidenceNode
from app.db.models.policy import ApprovalRequest
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app


PASSWORD = "Password123!"


def _items(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        items = payload.get("items")
        if isinstance(items, list):
            return items
    return []


def _install_sqlite_immutability_triggers(db: Session) -> None:
    tables = ("audit_logs", "evidence_nodes", "evidence_edges", "auditor_snapshots")
    for table in tables:
        db.execute(
            text(
                f"""
                CREATE TRIGGER trg_{table}_immutable_update
                BEFORE UPDATE ON {table}
                FOR EACH ROW
                BEGIN
                    SELECT RAISE(ABORT, 'immutable_table:{table}');
                END;
                """
            )
        )
        db.execute(
            text(
                f"""
                CREATE TRIGGER trg_{table}_immutable_delete
                BEFORE DELETE ON {table}
                FOR EACH ROW
                BEGIN
                    SELECT RAISE(ABORT, 'immutable_table:{table}');
                END;
                """
            )
        )
    db.commit()


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "hardening.sqlite3"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    testing_session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    with testing_session_local() as db:
        _install_sqlite_immutability_triggers(db)

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
    return {
        "Authorization": f"Bearer {access_token}",
        "X-Tenant-ID": tenant_id,
    }


def _register_owner(client: TestClient, *, email: str, full_name: str) -> dict[str, Any]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": full_name},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    return {
        "access_token": data["access_token"],
        "tenant_id": data["tenants"][0]["id"],
        "user_id": data["user"]["id"],
    }


def _create_tenant_user_with_role(
    session_local: sessionmaker,
    *,
    tenant_id: str,
    role: str,
    email: str,
) -> None:
    with session_local() as db:
        user = User(
            email=email,
            hashed_password=get_password_hash(PASSWORD),
            full_name=f"{role} user",
            is_active=True,
        )
        db.add(user)
        db.flush()
        db.add(UserTenantRole(user_id=user.id, tenant_id=tenant_id, role=role))
        db.commit()


def _login(client: TestClient, *, email: str) -> dict[str, Any]:
    response = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return response.json()


def test_inactive_tenant_is_rejected_by_shared_tenant_dependency(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="inactive-owner@example.com", full_name="Inactive Owner")

    with test_env["SessionLocal"]() as db:
        tenant = db.get(Tenant, owner["tenant_id"])
        assert tenant is not None
        tenant.is_active = False
        db.commit()

    response = client.get(
        "/ai-systems",
        headers=_headers(owner["access_token"], owner["tenant_id"]),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Tenant is inactive"


def test_block_user_revokes_existing_access_token(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="containment-owner@example.com", full_name="Containment Owner")
    tenant_id = owner["tenant_id"]
    _create_tenant_user_with_role(
        session_local,
        tenant_id=tenant_id,
        role="viewer",
        email="contained-user@example.com",
    )
    contained = _login(client, email="contained-user@example.com")

    with session_local() as db:
        user = db.scalar(select(User).where(User.email == "contained-user@example.com"))
        assert user is not None
        db.add(
            UserRegistry(
                tenant_id=tenant_id,
                user_id=user.id,
                display_name=user.full_name,
                email=user.email,
                status="active",
            )
        )
        db.commit()
        contained_user_id = user.id

    blocked = client.post(
        f"/users/{contained_user_id}/block",
        headers=_headers(owner["access_token"], tenant_id),
        json={"reason": "security containment test"},
    )
    assert blocked.status_code == 200, blocked.text

    rejected = client.get(
        "/ai-systems",
        headers=_headers(contained["access_token"], tenant_id),
    )
    assert rejected.status_code == 401


def test_tenant_isolation_across_core_modules(test_env) -> None:
    client: TestClient = test_env["client"]

    owner_a = _register_owner(client, email="owner-a@example.com", full_name="Owner A")
    owner_b = _register_owner(client, email="owner-b@example.com", full_name="Owner B")

    headers_a = _headers(owner_a["access_token"], owner_a["tenant_id"])
    headers_b = _headers(owner_b["access_token"], owner_b["tenant_id"])

    ai_system_resp = client.post(
        "/ai-systems",
        headers=headers_a,
        json={"name": "A System", "description": "", "risk_tier": "HIGH"},
    )
    assert ai_system_resp.status_code == 200, ai_system_resp.text
    ai_system_id = ai_system_resp.json()["id"]
    approved = client.patch(f"/ai-systems/{ai_system_id}", headers=headers_a, json={"status": "approved"})
    assert approved.status_code == 200, approved.text

    pack_resp = client.post(
        "/policies/packs",
        headers=headers_a,
        json={"name": "Tenant A Pack", "description": "pack", "status": "draft"},
    )
    assert pack_resp.status_code == 200, pack_resp.text
    pack_id = pack_resp.json()["pack"]["id"]

    event_resp = client.post(
        "/gateway/llm/intercept",
        headers=headers_a,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "owner-a",
            "prompt": "safe prompt",
            "context_summary": "baseline context",
            "attachments_meta": [],
        },
    )
    assert event_resp.status_code == 200, event_resp.text
    event_id = event_resp.json()["event_id"]

    get_foreign_system = client.get(f"/ai-systems/{ai_system_id}", headers=headers_b)
    assert get_foreign_system.status_code == 404

    patch_foreign_pack = client.patch(
        f"/policies/packs/{pack_id}",
        headers=headers_b,
        json={"status": "active"},
    )
    assert patch_foreign_pack.status_code == 404

    events_b = client.get("/enforcement/events", headers=headers_b)
    assert events_b.status_code == 200
    events_rows = _items(events_b.json())
    assert all(row["id"] != event_id for row in events_rows)

    snapshot_b = client.post(
        "/auditor/snapshot",
        headers=headers_b,
        json={"ai_system_id": ai_system_id, "trigger_type": "manual", "payload": {}},
    )
    assert snapshot_b.status_code == 403

    control_id = "CTRL-TENANT-B-001"
    control_b = client.post(
        "/simulations/controls",
        headers=headers_b,
        json={
            "id": control_id,
            "name": "Tenant B Control",
            "category": "monitoring",
            "description": "tenant b control",
            "mapped_framework_refs": [{"framework": "INTERNAL", "control_ref": "B-1"}],
            "is_global": False,
        },
    )
    assert control_b.status_code == 200, control_b.text

    simulation_def = client.post(
        "/simulations/definitions",
        headers=headers_b,
        json={
            "name": "B Simulation",
            "category": "injection",
            "target_module": "interaction_security",
            "version": "1.0.0",
            "dsl_json": {
                "id": "sim-b-tenant",
                "tenant_id": owner_b["tenant_id"],
                "name": "B Simulation",
                "category": "injection",
                "target_module": "interaction_security",
                "version": "1.0.0",
                "safety": {"requires_sandbox": True, "max_runtime_seconds": 30, "no_external_network": True},
                "inputs_schema": {"fields": []},
                "steps": [
                    {
                        "step_id": "s1",
                        "kind": "monitoring_signal",
                        "payload_template": {"signal_type": "test.signal", "severity": "low"},
                        "variable_bindings": {},
                    }
                ],
                "assertions": [
                    {
                        "assertion_id": "a1",
                        "check": {"field": "s1.signal_id", "operator": "contains", "value": "-"},
                        "on_fail": {"result": "fail", "evidence_signal_type": "simulation.fail", "severity": "low"},
                    }
                ],
                "maps_to_controls": [control_id],
                "expected_outcomes": {"pass_conditions": ["signal exists"], "fail_conditions": ["signal missing"]},
            },
        },
    )
    assert simulation_def.status_code == 200, simulation_def.text
    simulation_id = simulation_def.json()["id"]

    foreign_run = client.post(
        f"/simulations/definitions/{simulation_id}/run",
        headers=headers_b,
        json={"ai_system_id": ai_system_id, "mode": "deterministic", "inputs_used": {}},
    )
    assert foreign_run.status_code == 403


def test_db_level_immutability_for_audit_and_evidence(test_env) -> None:
    session_local: sessionmaker = test_env["SessionLocal"]

    with session_local() as db:
        tenant = Tenant(name="Immutable Org", slug="immutable-org", is_active=True)
        db.add(tenant)
        db.flush()

        audit = AuditLog(
            tenant_id=tenant.id,
            actor_user_id=None,
            actor_type="system",
            action="test.audit",
            resource_type="test_resource",
            resource_id="resource-1",
            payload={"k": "v"},
        )
        db.add(audit)
        db.flush()

        node_a = EvidenceNode(
            tenant_id=tenant.id,
            node_type="test_node",
            signal_type="test.signal",
            label="Node A",
            payload={},
        )
        node_b = EvidenceNode(
            tenant_id=tenant.id,
            node_type="test_node",
            signal_type="test.signal",
            label="Node B",
            payload={},
        )
        db.add(node_a)
        db.add(node_b)
        db.flush()

        edge = EvidenceEdge(
            tenant_id=tenant.id,
            from_node_id=node_a.id,
            to_node_id=node_b.id,
            edge_type="generated",
            payload={},
        )
        db.add(edge)
        db.commit()

        with pytest.raises(Exception):
            db.execute(text("UPDATE audit_logs SET action = 'tampered' WHERE id = :id"), {"id": audit.id})
            db.commit()
        db.rollback()

        with pytest.raises(Exception):
            db.execute(text("DELETE FROM audit_logs WHERE id = :id"), {"id": audit.id})
            db.commit()
        db.rollback()

        with pytest.raises(Exception):
            db.execute(text("UPDATE evidence_nodes SET label = 'tampered' WHERE id = :id"), {"id": node_a.id})
            db.commit()
        db.rollback()

        with pytest.raises(Exception):
            db.execute(text("DELETE FROM evidence_nodes WHERE id = :id"), {"id": node_a.id})
            db.commit()
        db.rollback()

        with pytest.raises(Exception):
            db.execute(text("UPDATE evidence_edges SET edge_type = 'tampered' WHERE id = :id"), {"id": edge.id})
            db.commit()
        db.rollback()

        with pytest.raises(Exception):
            db.execute(text("DELETE FROM evidence_edges WHERE id = :id"), {"id": edge.id})
            db.commit()
        db.rollback()


def test_rbac_approval_requires_owner_or_admin(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="owner-rbac@example.com", full_name="Owner RBAC")
    tenant_id = owner["tenant_id"]

    _create_tenant_user_with_role(session_local, tenant_id=tenant_id, role="admin", email="admin-rbac@example.com")
    _create_tenant_user_with_role(session_local, tenant_id=tenant_id, role="operator", email="operator-rbac@example.com")
    _create_tenant_user_with_role(session_local, tenant_id=tenant_id, role="auditor", email="auditor-rbac@example.com")
    _create_tenant_user_with_role(session_local, tenant_id=tenant_id, role="viewer", email="viewer-rbac@example.com")

    owner_headers = _headers(owner["access_token"], tenant_id)
    admin = _login(client, email="admin-rbac@example.com")
    operator = _login(client, email="operator-rbac@example.com")
    auditor = _login(client, email="auditor-rbac@example.com")
    viewer = _login(client, email="viewer-rbac@example.com")
    admin_headers = _headers(admin["access_token"], tenant_id)
    operator_headers = _headers(operator["access_token"], tenant_id)
    auditor_headers = _headers(auditor["access_token"], tenant_id)
    viewer_headers = _headers(viewer["access_token"], tenant_id)

    ai_system_resp = client.post(
        "/ai-systems",
        headers=owner_headers,
        json={"name": "Approval System", "description": "", "risk_tier": "MEDIUM"},
    )
    assert ai_system_resp.status_code == 200, ai_system_resp.text
    ai_system_id = ai_system_resp.json()["id"]

    with session_local() as db:
        req = ApprovalRequest(
            tenant_id=tenant_id,
            enforcement_event_id=None,
            ai_system_id=ai_system_id,
            request_payload={"reason": "manual test"},
            required_roles=["owner", "admin"],
            sla_minutes=30,
            status="pending",
        )
        db.add(req)
        db.commit()
        approval_id = req.id

    for denied_headers in (operator_headers, auditor_headers, viewer_headers):
        denied = client.post(
            f"/enforcement/approvals/{approval_id}/decision",
            headers=denied_headers,
            json={"decision": "approve"},
        )
        assert denied.status_code == 403

    approved = client.post(
        f"/enforcement/approvals/{approval_id}/decision",
        headers=admin_headers,
        json={"decision": "approve"},
    )
    assert approved.status_code == 200, approved.text

    with session_local() as db:
        req2 = ApprovalRequest(
            tenant_id=tenant_id,
            enforcement_event_id=None,
            ai_system_id=ai_system_id,
            request_payload={"reason": "owner path"},
            required_roles=["owner", "admin"],
            sla_minutes=30,
            status="pending",
        )
        db.add(req2)
        db.commit()
        approval_id_2 = req2.id

    owner_decision = client.post(
        f"/enforcement/approvals/{approval_id_2}/decision",
        headers=owner_headers,
        json={"decision": "deny"},
    )
    assert owner_decision.status_code == 200, owner_decision.text

    with session_local() as db:
        operator_req = ApprovalRequest(
            tenant_id=tenant_id,
            enforcement_event_id=None,
            ai_system_id=ai_system_id,
            request_payload={"reason": "operator-authorized path"},
            required_roles=["operator"],
            sla_minutes=30,
            status="pending",
        )
        db.add(operator_req)
        db.commit()
        operator_approval_id = operator_req.id

    operator_decision = client.post(
        f"/enforcement/approvals/{operator_approval_id}/decision",
        headers=operator_headers,
        json={"decision": "approve"},
    )
    assert operator_decision.status_code == 200, operator_decision.text


def test_rbac_token_mint_revoke_and_kill_switch_boundaries(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="owner-iam@example.com", full_name="Owner IAM")
    tenant_id = owner["tenant_id"]
    owner_headers = _headers(owner["access_token"], tenant_id)

    _create_tenant_user_with_role(session_local, tenant_id=tenant_id, role="admin", email="admin-iam@example.com")
    _create_tenant_user_with_role(session_local, tenant_id=tenant_id, role="operator", email="operator-iam@example.com")
    _create_tenant_user_with_role(session_local, tenant_id=tenant_id, role="viewer", email="viewer-iam@example.com")

    admin = _login(client, email="admin-iam@example.com")
    operator = _login(client, email="operator-iam@example.com")
    viewer = _login(client, email="viewer-iam@example.com")

    admin_headers = _headers(admin["access_token"], tenant_id)
    operator_headers = _headers(operator["access_token"], tenant_id)
    viewer_headers = _headers(viewer["access_token"], tenant_id)

    create_agent = client.post(
        "/ai-iam/agents",
        headers=owner_headers,
        json={"name": "Agent One", "description": "rbac test", "max_chain_depth": 2},
    )
    assert create_agent.status_code == 200, create_agent.text
    agent_id = create_agent.json()["id"]

    ai_system_resp = client.post(
        "/ai-systems",
        headers=owner_headers,
        json={"name": "IAM System", "description": "", "risk_tier": "MEDIUM"},
    )
    assert ai_system_resp.status_code == 200, ai_system_resp.text
    ai_system_id = ai_system_resp.json()["id"]

    denied_mint = client.post(
        f"/ai-iam/agents/{agent_id}/tokens",
        headers=operator_headers,
        json={"ai_system_id": ai_system_id, "scopes": ["tool.run"], "expires_minutes": 30, "chain_depth": 1},
    )
    assert denied_mint.status_code == 403

    minted = client.post(
        f"/ai-iam/agents/{agent_id}/tokens",
        headers=admin_headers,
        json={"ai_system_id": ai_system_id, "scopes": ["tool.run"], "expires_minutes": 30, "chain_depth": 1},
    )
    assert minted.status_code == 200, minted.text
    token_id = minted.json()["token_id"]

    denied_revoke = client.post(
        f"/ai-iam/tokens/{token_id}/revoke",
        headers=viewer_headers,
    )
    assert denied_revoke.status_code == 403

    allowed_revoke = client.post(
        f"/ai-iam/tokens/{token_id}/revoke",
        headers=owner_headers,
    )
    assert allowed_revoke.status_code == 200, allowed_revoke.text

    denied_kill = client.post(
        f"/ai-iam/agents/{agent_id}/kill-switch",
        headers=operator_headers,
    )
    assert denied_kill.status_code == 403

    allowed_kill = client.post(
        f"/ai-iam/agents/{agent_id}/kill-switch",
        headers=admin_headers,
    )
    assert allowed_kill.status_code == 200, allowed_kill.text

    with session_local() as db:
        agent = db.get(AgentIdentity, agent_id)
        assert agent is not None
        assert agent.status == "isolated"


def test_token_revocation_schedules_a_post_response_runtime_projection(test_env, monkeypatch: pytest.MonkeyPatch) -> None:
    """Authority revocation is committed before its optional runtime projection is scheduled."""
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="revoke-latency-owner@example.com", full_name="Revoke Latency Owner")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    agent_response = client.post(
        "/ai-iam/agents",
        headers=headers,
        json={"name": "Revoke latency agent", "description": "", "max_chain_depth": 1},
    )
    assert agent_response.status_code == 200, agent_response.text
    ai_system_response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Revoke latency system", "description": "", "risk_tier": "MEDIUM"},
    )
    assert ai_system_response.status_code == 200, ai_system_response.text
    minted = client.post(
        f"/ai-iam/agents/{agent_response.json()['id']}/tokens",
        headers=headers,
        json={
            "ai_system_id": ai_system_response.json()["id"],
            "scopes": ["tool.run"],
            "expires_minutes": 30,
            "chain_depth": 1,
        },
    )
    assert minted.status_code == 200, minted.text
    token_id = minted.json()["token_id"]

    from app.services.runtime_intelligence import runtime_event_normalizer
    projection_started = threading.Event()
    scheduled_tasks: list[tuple[Any, tuple[Any, ...], dict[str, Any]]] = []

    def _delayed_projection(*_args: Any, **_kwargs: Any) -> None:
        projection_started.set()
        threading.Event().wait(1.0)

    monkeypatch.setattr(runtime_event_normalizer, "ingest_from_ai_iam_event", _delayed_projection)

    def _capture_add_task(self, func: Any, *args: Any, **kwargs: Any) -> None:
        scheduled_tasks.append((func, args, kwargs))

    monkeypatch.setattr(BackgroundTasks, "add_task", _capture_add_task)

    started = time.monotonic()
    revoked = client.post(f"/ai-iam/tokens/{token_id}/revoke", headers=headers)
    elapsed = time.monotonic() - started

    assert revoked.status_code == 200, revoked.text
    assert not projection_started.is_set()
    assert elapsed < 0.5
    assert len(scheduled_tasks) == 1
    task, args, kwargs = scheduled_tasks[0]
    assert task.__name__ == "_project_token_revocation_runtime_event"
    assert args == ()
    assert kwargs["bind"] is session_local.kw["bind"]
    assert {
        key: value
        for key, value in kwargs.items()
        if key not in {"bind", "correlation_id"}
    } == {
        "tenant_id": owner["tenant_id"],
        "token_id": token_id,
        "agent_id": agent_response.json()["id"],
        "ai_system_id": ai_system_response.json()["id"],
        "scopes": ["tool.run"],
    }
    assert isinstance(kwargs["correlation_id"], str) and kwargs["correlation_id"]
    with session_local() as db:
        token = db.get(CapabilityToken, token_id)
        assert token is not None
        assert token.revoked_at is not None
        audit = db.scalar(
            select(AuditLog).where(
                AuditLog.tenant_id == owner["tenant_id"],
                AuditLog.action == "ai_iam.token.revoke",
                AuditLog.resource_id == token_id,
            )
        )
        assert audit is not None


def test_token_mint_commits_before_post_response_runtime_projection(test_env, monkeypatch: pytest.MonkeyPatch) -> None:
    """A token mint commits its authority records before optional enrichment starts."""
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="mint-latency-owner@example.com", full_name="Mint Latency Owner")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    agent_response = client.post(
        "/ai-iam/agents",
        headers=headers,
        json={"name": "Mint latency agent", "description": "", "max_chain_depth": 1},
    )
    assert agent_response.status_code == 200, agent_response.text
    ai_system_response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Mint latency system", "description": "", "risk_tier": "HIGH"},
    )
    assert ai_system_response.status_code == 200, ai_system_response.text
    agent_id = agent_response.json()["id"]
    ai_system_id = ai_system_response.json()["id"]
    mint_payload = {
        "ai_system_id": ai_system_id,
        "scopes": ["records.read"],
        "expires_minutes": 30,
        "chain_depth": 1,
    }

    requires_approval = client.post(f"/ai-iam/agents/{agent_id}/tokens", headers=headers, json=mint_payload)
    assert requires_approval.status_code == 409, requires_approval.text
    approval_request_id = requires_approval.json()["detail"]["approval_request_id"]
    approved = client.post(
        f"/enforcement/approvals/{approval_request_id}/decision",
        headers=headers,
        json={"decision": "approve"},
    )
    assert approved.status_code == 200, approved.text

    from app.services.runtime_intelligence import runtime_event_normalizer

    projection_started = threading.Event()
    scheduled_tasks: list[tuple[Any, tuple[Any, ...], dict[str, Any]]] = []

    def _delayed_projection(*_args: Any, **_kwargs: Any) -> None:
        projection_started.set()
        threading.Event().wait(1.0)

    def _capture_add_task(self, func: Any, *args: Any, **kwargs: Any) -> None:
        scheduled_tasks.append((func, args, kwargs))

    monkeypatch.setattr(runtime_event_normalizer, "ingest_from_ai_iam_event", _delayed_projection)
    monkeypatch.setattr(BackgroundTasks, "add_task", _capture_add_task)

    started = time.monotonic()
    minted = client.post(
        f"/ai-iam/agents/{agent_id}/tokens",
        headers=headers,
        json={**mint_payload, "approval_request_id": approval_request_id},
    )
    elapsed = time.monotonic() - started

    assert minted.status_code == 200, minted.text
    assert not projection_started.is_set()
    assert elapsed < 0.5
    assert len(scheduled_tasks) == 1
    task, args, kwargs = scheduled_tasks[0]
    assert task.__name__ == "_project_token_mint_runtime_event"
    assert args == ()
    assert kwargs["bind"] is session_local.kw["bind"]
    assert {
        key: value
        for key, value in kwargs.items()
        if key not in {"bind", "correlation_id"}
    } == {
        "tenant_id": owner["tenant_id"],
        "token_id": minted.json()["token_id"],
        "agent_id": agent_id,
        "ai_system_id": ai_system_id,
        "scopes": ["records.read"],
        "chain_depth": 1,
        "approval_request_id": approval_request_id,
    }
    assert isinstance(kwargs["correlation_id"], str) and kwargs["correlation_id"]
    assert minted.json()["capability_token"] not in repr((args, kwargs))


def test_token_mint_projection_failure_does_not_undo_authority(test_env, monkeypatch: pytest.MonkeyPatch) -> None:
    """Optional token-mint enrichment cannot roll back committed authority records."""
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="mint-isolation-owner@example.com", full_name="Mint Isolation Owner")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    agent_response = client.post(
        "/ai-iam/agents",
        headers=headers,
        json={"name": "Mint isolation agent", "description": "", "max_chain_depth": 1},
    )
    assert agent_response.status_code == 200, agent_response.text
    ai_system_response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Mint isolation system", "description": "", "risk_tier": "HIGH"},
    )
    assert ai_system_response.status_code == 200, ai_system_response.text
    agent_id = agent_response.json()["id"]
    ai_system_id = ai_system_response.json()["id"]
    mint_payload = {
        "ai_system_id": ai_system_id,
        "scopes": ["records.read"],
        "expires_minutes": 30,
        "chain_depth": 1,
    }

    requires_approval = client.post(f"/ai-iam/agents/{agent_id}/tokens", headers=headers, json=mint_payload)
    assert requires_approval.status_code == 409, requires_approval.text
    approval_request_id = requires_approval.json()["detail"]["approval_request_id"]
    approved = client.post(
        f"/enforcement/approvals/{approval_request_id}/decision",
        headers=headers,
        json={"decision": "approve"},
    )
    assert approved.status_code == 200, approved.text

    from app.services.runtime_intelligence import runtime_event_normalizer

    projection_metadata: list[dict[str, Any]] = []
    scheduled_tasks: list[tuple[Any, tuple[Any, ...], dict[str, Any]]] = []

    def _failing_projection(*_args: Any, **kwargs: Any) -> None:
        projection_metadata.append(dict(kwargs["metadata"]))
        raise RuntimeError("simulated Runtime Intelligence failure")

    def _capture_add_task(self, func: Any, *args: Any, **kwargs: Any) -> None:
        scheduled_tasks.append((func, args, kwargs))

    monkeypatch.setattr(runtime_event_normalizer, "ingest_from_ai_iam_event", _failing_projection)
    monkeypatch.setattr(BackgroundTasks, "add_task", _capture_add_task)

    minted = client.post(
        f"/ai-iam/agents/{agent_id}/tokens",
        headers=headers,
        json={**mint_payload, "approval_request_id": approval_request_id},
    )
    assert minted.status_code == 200, minted.text
    assert len(scheduled_tasks) == 1

    task, args, kwargs = scheduled_tasks[0]
    task(*args, **kwargs)
    assert projection_metadata == [
        {
            "action": "token_mint",
            "capability_token_id": minted.json()["token_id"],
            "scopes": ["records.read"],
            "chain_depth": 1,
            "approval_request_id": approval_request_id,
            "operational_telemetry": True,
        }
    ]

    with session_local() as db:
        token = db.get(CapabilityToken, minted.json()["token_id"])
        assert token is not None
        approval = db.get(ApprovalRequest, approval_request_id)
        assert approval is not None
        assert approval.status == "used"
        audit = db.scalar(
            select(AuditLog).where(
                AuditLog.tenant_id == owner["tenant_id"],
                AuditLog.action == "ai_iam.token.mint",
                AuditLog.resource_id == token.id,
            )
        )
        assert audit is not None
