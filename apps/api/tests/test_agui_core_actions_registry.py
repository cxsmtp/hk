from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.core.security import token_hash
from app.db.models.ai_iam import AgentIdentity, CapabilityToken
from app.db.models.ai_system import AISystem
from app.db.models.discovery import DiscoveryApplication
from app.db.models.finding import Finding
from app.db.models.maturity import ControlConflict
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.models.simulation import Control, SimulationDefinition, SimulationRun
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base
from app.services.agui.context import AGUIExecutionContext
from app.services.agui.core_actions import CORE_AGUI_ACTION_IDS, register_core_agui_actions
from app.services.agui.registry import AGUIRegistry


def _make_session(tmp_path) -> Session:
    db_file = tmp_path / "agui_core_actions.sqlite3"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    return session_local()


def _seed(db: Session) -> dict[str, str]:
    suffix = uuid4().hex[:8]
    tenant = Tenant(name="AGUI Core", slug=f"agui-core-{suffix}", is_active=True, platform_mode="enforce")
    admin = User(email=f"admin-{suffix}@acme.ai", hashed_password="x", full_name="Admin", is_active=True)
    owner = User(email=f"owner-{suffix}@acme.ai", hashed_password="x", full_name="Owner", is_active=True)
    db.add_all([tenant, admin, owner])
    db.flush()

    db.add_all(
        [
            UserTenantRole(user_id=admin.id, tenant_id=tenant.id, role="admin"),
            UserTenantRole(user_id=owner.id, tenant_id=tenant.id, role="owner"),
        ]
    )
    db.flush()

    ai_system = AISystem(
        tenant_id=tenant.id,
        name="Core AGUI System",
        description="seed",
        risk_tier="HIGH",
        status="active",
        metadata_json={"governance_state": "APPROVED", "lifecycle_state": "ACTIVE"},
    )
    db.add(ai_system)
    db.flush()

    finding = Finding(
        tenant_id=tenant.id,
        source_surface="gateway",
        ai_tool="llm_gateway",
        ai_system_id=ai_system.id,
        user_id=owner.id,
        department="security",
        severity="high",
        finding_type="enforcement_event",
        risk_category="interaction_security",
        status="open",
        recommended_action="Review and remediate.",
        policy_version_id=None,
        evidence_node_ids=[],
        related_control_ids=[],
        dedupe_key=f"dedupe-{suffix}",
        occurrence_count=1,
        first_seen_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
    )
    db.add(finding)
    db.flush()

    app = DiscoveryApplication(
        tenant_id=tenant.id,
        tool_key="chatgpt",
        tool_name="ChatGPT",
        vendor="OpenAI",
        status="discovered",
        owner_user_id=None,
        owner_department=None,
        provisional_risk_tier="HIGH",
        ai_system_id=ai_system.id,
        first_seen_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
        metadata_json={},
    )
    db.add(app)
    db.flush()

    pack = PolicyPack(tenant_id=tenant.id, name="AGUI Pack", description="pack", status="draft")
    db.add(pack)
    db.flush()

    policy = PolicyVersion(
        tenant_id=tenant.id,
        pack_id=pack.id,
        version="1.0.0",
        created_by=admin.id,
        scope={"applies_to_risk_tiers": ["HIGH"], "applies_to_actor_types": ["human"]},
        enforcement_defaults={"default_decision": "allow", "escalation": "none"},
        guardian_contracts=[
            {
                "guardian_id": "prompt_injection",
                "enabled": True,
                "decision": {"on_pass": "allow", "on_fail": "block", "on_uncertain": "warn"},
            }
        ],
        contract_json={
            "id": "contract-1",
            "version": "1.0.0",
            "guardian_contracts": [{"guardian_id": "prompt_injection", "enabled": True}],
            "enforcement_defaults": {"default_decision": "allow", "escalation": "none"},
        },
    )
    db.add(policy)
    db.flush()

    control = Control(
        id="CTRL-AGUI-001",
        tenant_id=tenant.id,
        is_global=False,
        name="AGUI Control",
        category="validation",
        description="control",
        mapped_framework_refs=[],
        success_criteria={
            "required_sim_pass_rate": 0.8,
            "required_evidence_sources": ["simulation"],
            "min_maturity": 3,
        },
    )
    db.add(control)
    db.flush()

    sim = SimulationDefinition(
        tenant_id=tenant.id,
        name="AGUI Sim",
        category="injection",
        target_module="interaction_security",
        version="1.0.0",
        dsl_json={
            "id": "SIM-AGUI-001",
            "name": "AGUI Sim",
            "category": "injection",
            "target_module": "interaction_security",
            "version": "1.0.0",
            "safety": {"requires_sandbox": True, "max_runtime_seconds": 30, "no_external_network": True},
            "inputs_schema": {"fields": {}},
            "steps": [],
            "assertions": [],
            "maps_to_controls": ["CTRL-AGUI-001"],
            "expected_outcomes": {"pass_conditions": [], "fail_conditions": []},
        },
    )
    db.add(sim)
    db.flush()

    sim_run = SimulationRun(
        tenant_id=tenant.id,
        simulation_id=sim.id,
        ai_system_id=ai_system.id,
        mode="deterministic",
        inputs_used={},
        results={"result": "fail", "pass_rate": 0.0, "failed_assertions": ["A1"]},
        controls_impacted=[{"control_id": "CTRL-AGUI-001", "delta": -1}],
        notes="initial",
    )
    db.add(sim_run)
    db.flush()

    conflict = ControlConflict(
        tenant_id=tenant.id,
        ai_system_id=ai_system.id,
        control_id=control.id,
        status="open",
        reason="auditor_challenge",
        positive_signals=0,
        negative_signals=1,
        latest_signal_at=datetime.now(timezone.utc),
        evidence_node_ids=[],
        details={},
        audit_log_id=None,
    )
    db.add(conflict)
    db.flush()

    agent = AgentIdentity(
        tenant_id=tenant.id,
        name="AGUI Agent",
        description="agent",
        status="active",
        owner_attested_at=datetime.now(timezone.utc),
        owner_attestation_expiry=datetime.now(timezone.utc) + timedelta(days=30),
        max_chain_depth=3,
        capability_inheritance=False,
    )
    db.add(agent)
    db.flush()

    token_raw = f"seed-token-{suffix}"
    token = CapabilityToken(
        tenant_id=tenant.id,
        agent_identity_id=agent.id,
        ai_system_id=ai_system.id,
        token_hash=token_hash(token_raw),
        scopes=["tool.read", "tool.write"],
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
        chain_depth=1,
        issued_by_user_id=admin.id,
    )
    db.add(token)
    db.commit()

    return {
        "tenant_id": tenant.id,
        "admin_user_id": admin.id,
        "owner_user_id": owner.id,
        "finding_id": finding.finding_id,
        "application_id": app.id,
        "ai_system_id": ai_system.id,
        "policy_version_id": policy.id,
        "simulation_id": sim.id,
        "simulation_run_id": sim_run.id,
        "conflict_id": conflict.id,
        "agent_id": agent.id,
        "token_id": token.id,
    }


def _ctx(seed: dict[str, str]) -> AGUIExecutionContext:
    return AGUIExecutionContext(
        tenant_id=seed["tenant_id"],
        user_id=seed["admin_user_id"],
        user_role="admin",
        correlation_id="corr-agui-core-actions",
        evidence_displayed=True,
        diff_preview_displayed=True,
    )


def test_agui_core_actions_registered_and_executable(tmp_path) -> None:
    db = _make_session(tmp_path)
    try:
        seed = _seed(db)
        registry = AGUIRegistry()
        register_core_agui_actions(registry)

        listed = {row["action_id"] for row in registry.list_actions()}
        assert set(CORE_AGUI_ACTION_IDS).issubset(listed)

        for action_id in CORE_AGUI_ACTION_IDS:
            result = registry.execute_decision(
                db=db,
                context=_ctx(seed),
                action_id=action_id,
                decision="reject",
                justification="not approved in this test run",
                decision_payload={"source_object_id": f"obj-{action_id}"},
            )
            assert result.action_id == action_id
            assert result.decision == "reject"
    finally:
        db.close()


def test_agui_core_actions_side_effects_by_module(tmp_path) -> None:
    db = _make_session(tmp_path)
    try:
        seed = _seed(db)
        registry = AGUIRegistry()
        register_core_agui_actions(registry)
        context = _ctx(seed)

        registry.execute_decision(
            db=db,
            context=context,
            action_id="findings.accept_risk",
            decision="approve",
            justification="Business impact accepted until remediation sprint.",
            decision_payload={"finding_id": seed["finding_id"]},
        )
        finding = db.scalar(select(Finding).where(Finding.finding_id == seed["finding_id"]))
        assert finding is not None
        assert finding.status == "accepted_risk"

        registry.execute_decision(
            db=db,
            context=context,
            action_id="governance.change_risk_tier",
            decision="approve",
            justification="Risk re-classification approved.",
            decision_payload={"ai_system_id": seed["ai_system_id"], "risk_tier": "CRITICAL"},
        )
        ai_system = db.scalar(select(AISystem).where(AISystem.id == seed["ai_system_id"]))
        assert ai_system is not None
        assert ai_system.risk_tier == "CRITICAL"

        registry.execute_decision(
            db=db,
            context=context,
            action_id="policies.approve_activation",
            decision="approve",
            decision_payload={"policy_version_id": seed["policy_version_id"]},
        )
        policy = db.scalar(select(PolicyVersion).where(PolicyVersion.id == seed["policy_version_id"]))
        pack = db.scalar(select(PolicyPack).where(PolicyPack.id == policy.pack_id)) if policy else None
        assert policy is not None
        assert pack is not None
        assert pack.status == "active"

        registry.execute_decision(
            db=db,
            context=context,
            action_id="simulations.suppress_failure_with_justification",
            decision="approve",
            justification="Suppressed pending root-cause fix.",
            decision_payload={"simulation_run_id": seed["simulation_run_id"]},
        )
        sim_run = db.scalar(select(SimulationRun).where(SimulationRun.id == seed["simulation_run_id"]))
        assert sim_run is not None
        assert bool((sim_run.results or {}).get("suppressed")) is True

        registry.execute_decision(
            db=db,
            context=context,
            action_id="auditor.resolve_contested_control",
            decision="approve",
            justification="Evidence review complete.",
            decision_payload={"conflict_id": seed["conflict_id"], "resolution_decision": "accept_negative"},
        )
        conflict = db.scalar(select(ControlConflict).where(ControlConflict.id == seed["conflict_id"]))
        assert conflict is not None
        assert conflict.status == "resolved"

        registry.execute_decision(
            db=db,
            context=context,
            action_id="aiiam.revoke_privilege",
            decision="approve",
            decision_payload={"token_id": seed["token_id"]},
        )
        token = db.scalar(select(CapabilityToken).where(CapabilityToken.id == seed["token_id"]))
        assert token is not None
        assert token.revoked_at is not None
    finally:
        db.close()
