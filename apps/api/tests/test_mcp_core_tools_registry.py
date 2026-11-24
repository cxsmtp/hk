from __future__ import annotations

import os
from uuid import uuid4

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.ai_system import AISystem
from app.db.models.finding import Finding
from app.db.models.monitoring import Connector
from app.db.models.policy import ApprovalRequest, PolicyPack, PolicyVersion
from app.db.models.simulation import Control, SimulationDefinition
from app.db.models.tenant import Tenant
from app.db.models.user import User
from app.db.session import Base
from app.services.brain.tools import execute_tool, list_tools


def _make_session(tmp_path) -> Session:
    db_file = tmp_path / "mcp_core_tools.sqlite3"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    return session_local()


def _seed(db: Session) -> dict[str, str]:
    suffix = uuid4().hex[:8]
    tenant = Tenant(name="Acme", slug=f"acme-mcp-{suffix}", is_active=True, platform_mode="enforce")
    user = User(
        email=f"owner-mcp-{suffix}@acme.ai",
        hashed_password="x",
        full_name="Owner MCP",
        is_active=True,
    )
    db.add_all([tenant, user])
    db.flush()

    ai_system = AISystem(
        tenant_id=tenant.id,
        name="MCP System",
        description="MCP",
        risk_tier="HIGH",
        status="active",
        metadata_json={"governance_state": "APPROVED"},
    )
    db.add(ai_system)
    db.flush()

    finding = Finding(
        tenant_id=tenant.id,
        source_surface="gateway",
        ai_tool="llm_gateway",
        ai_system_id=ai_system.id,
        user_id=user.id,
        department="security",
        severity="high",
        finding_type="enforcement_violation",
        risk_category="interaction_security",
        status="open",
        recommended_action="Investigate",
        policy_version_id=None,
        evidence_node_ids=[],
        related_control_ids=["CTRL-MCP-001"],
        dedupe_key=f"mcp-{suffix}",
        occurrence_count=1,
    )
    db.add(finding)

    pack = PolicyPack(
        tenant_id=tenant.id,
        name="Pack",
        description="pack",
        status="active",
    )
    db.add(pack)
    db.flush()

    policy = PolicyVersion(
        tenant_id=tenant.id,
        pack_id=pack.id,
        version="1.0.0",
        created_by=user.id,
        scope={"applies_to_risk_tiers": ["HIGH"], "applies_to_ai_system_ids": [ai_system.id]},
        enforcement_defaults={"default_decision": "allow", "escalation": "none"},
        guardian_contracts=[],
        contract_json={},
    )
    db.add(policy)

    connector = Connector(
        tenant_id=tenant.id,
        name="MCP Connector",
        connector_type="jira",
        provider_key="jira",
        auth_type="bearer",
        enabled=True,
        status="active",
        config={},
    )
    db.add(connector)

    control = Control(
        id="CTRL-MCP-001",
        tenant_id=tenant.id,
        is_global=False,
        name="MCP Control",
        category="validation",
        description="MCP control",
        mapped_framework_refs=[],
        success_criteria={
            "required_sim_pass_rate": 0.8,
            "required_evidence_sources": ["simulation"],
            "min_maturity": 3,
        },
    )
    db.add(control)

    sim = SimulationDefinition(
        tenant_id=tenant.id,
        name="MCP Simulation",
        category="injection",
        target_module="interaction_security",
        version="1.0.0",
        dsl_json={
            "id": "SIM-MCP-001",
            "name": "MCP Simulation",
            "category": "injection",
            "target_module": "interaction_security",
            "version": "1.0.0",
            "safety": {"requires_sandbox": True, "max_runtime_seconds": 5, "no_external_network": True},
            "inputs_schema": {"fields": {}},
            "steps": [],
            "assertions": [],
            "maps_to_controls": ["CTRL-MCP-001"],
            "expected_outcomes": {"pass_conditions": [], "fail_conditions": []},
        },
    )
    db.add(sim)

    db.commit()
    return {
        "tenant_id": tenant.id,
        "user_id": user.id,
        "ai_system_id": ai_system.id,
        "finding_id": finding.finding_id,
        "policy_version_id": policy.id,
        "connector_id": connector.id,
    }


def test_mcp_registry_lists_all_core_tools(tmp_path) -> None:
    db = _make_session(tmp_path)
    try:
        _seed(db)
        names = {row["name"] for row in list_tools()}
        expected = {
            "governance.get_ai_system",
            "governance.list_ai_systems",
            "governance.update_ai_system_state",
            "governance.assign_owner",
            "governance.set_risk_tier",
            "findings.list",
            "findings.get",
            "findings.update_status",
            "findings.analyze",
            "policies.get_policy_version",
            "policies.get_guardian_matrix",
            "policies.activate_policy_version",
            "evidence.query",
            "evidence.get_node",
            "evidence.get_trace",
            "simulations.list_for_control",
            "simulations.run",
            "simulations.run_pack",
            "simulations.get_result",
            "auditor.create_snapshot",
            "auditor.export_snapshot",
            "auditor.challenge_control",
            "auditor.get_snapshot",
            "aiiam.get_agent",
            "aiiam.mint_token",
            "aiiam.revoke_token",
            "aiiam.kill_switch",
            "integrations.list",
            "integrations.pull_signals",
            "integrations.get_health",
            "tickets.create_jira",
            "workflows.request_approval",
        }
        assert expected.issubset(names)
    finally:
        db.close()


def test_mcp_core_tools_execute_paths(tmp_path) -> None:
    db = _make_session(tmp_path)
    try:
        seed = _seed(db)

        governance = execute_tool(
            db=db,
            tenant_id=seed["tenant_id"],
            user_id=seed["user_id"],
            user_role="admin",
            tool_name="governance.get_ai_system",
            args={"ai_system_id": seed["ai_system_id"]},
        )
        assert governance["ai_system"]["id"] == seed["ai_system_id"]

        findings = execute_tool(
            db=db,
            tenant_id=seed["tenant_id"],
            user_id=seed["user_id"],
            user_role="auditor",
            tool_name="findings.list",
            args={"filters": {}, "limit": 20, "cursor": "0"},
        )
        assert findings["total"] >= 1

        approval = execute_tool(
            db=db,
            tenant_id=seed["tenant_id"],
            user_id=seed["user_id"],
            user_role="operator",
            tool_name="workflows.request_approval",
            args={
                "ai_system_id": seed["ai_system_id"],
                "request_payload": {"reason": "mcp test"},
                "required_roles": ["owner", "admin"],
                "sla_minutes": 30,
                "default_if_timeout": "block",
            },
        )
        assert approval["status"] == "pending"

        row = db.scalar(
            select(ApprovalRequest).where(
                ApprovalRequest.id == approval["approval_request_id"],
                ApprovalRequest.tenant_id == seed["tenant_id"],
            )
        )
        assert row is not None
    finally:
        db.close()
