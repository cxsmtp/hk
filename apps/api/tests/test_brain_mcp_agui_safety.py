from __future__ import annotations

import ast
import os
from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.ai_system import AISystem
from app.db.models.audit import AuditLog
from app.db.models.evidence import EvidenceNode
from app.db.models.policy import ApprovalRequest
from app.db.models.tenant import Tenant
from app.db.models.user import User
from app.db.session import Base
from app.services.brain.executor import execute_plan
from app.services.brain.store import create_brain_session, save_brain_plan
from app.services.mcp.contracts import ToolContract, ToolRegistration
from app.services.mcp.registry import get_mcp_registry


def _new_session(tmp_path) -> Session:
    db_file = tmp_path / "brain_mcp_agui.sqlite3"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    return session_local()


def _seed_identity(db: Session) -> tuple[str, str, str]:
    suffix = uuid4().hex[:8]
    tenant = Tenant(
        name="Brain Safety Tenant",
        slug=f"brain-safety-{suffix}",
        is_active=True,
        platform_mode="enforce",
    )
    user = User(
        email=f"brain-safety-{suffix}@acme.ai",
        hashed_password="x",
        full_name="Brain Safety User",
        is_active=True,
    )
    db.add_all([tenant, user])
    db.flush()
    ai_system = AISystem(
        tenant_id=tenant.id,
        name="Brain Safety AI",
        description="brain mcp/agui safety",
        risk_tier="HIGH",
        status="active",
        metadata_json={"governance_state": "APPROVED"},
    )
    db.add(ai_system)
    db.flush()
    return tenant.id, user.id, ai_system.id


def test_brain_executor_routes_approval_tools_to_agui_requests(tmp_path) -> None:
    db = _new_session(tmp_path)
    try:
        tenant_id, user_id, ai_system_id = _seed_identity(db)
        called = {"count": 0}
        tool_name = f"test.approval_tool.{uuid4().hex[:8]}"
        registry = get_mcp_registry()
        if registry.get(tool_name) is None:
            registry.register(
                ToolRegistration(
                    contract=ToolContract(
                        tool_name=tool_name,
                        module="test",
                        version="1.0.0",
                        description="Approval-gated test tool for Brain executor",
                        input_schema={
                            "type": "object",
                            "properties": {"ai_system_id": {"type": "string"}},
                            "required": ["ai_system_id"],
                            "additionalProperties": False,
                        },
                        output_schema={
                            "type": "object",
                            "properties": {"ok": {"type": "boolean"}},
                            "required": ["ok"],
                            "additionalProperties": False,
                        },
                        required_role=["admin", "owner"],
                        requires_approval=True,
                        writes_evidence=False,
                        side_effect_level="enforce",
                        citations_supported=False,
                        governance_scope_required=False,
                        tenant_scope_required=True,
                        idempotent=False,
                        timeout_ms=5000,
                    ),
                    executor=lambda _db, _ctx, _args: _mark_called(called),
                )
            )

        session = create_brain_session(db, tenant_id=tenant_id, user_id=user_id)
        plan = save_brain_plan(
            db,
            session_id=session.id,
            question="Run approval-gated tool",
            plan_json={
                "question": "Run approval-gated tool",
                "steps": [
                    {
                        "step_id": "s1",
                        "execution_type": "mcp_tool_call",
                        "tool": tool_name,
                        "args": {"ai_system_id": ai_system_id},
                        "expect_schema": {"type": "object"},
                        "on_error": "stop",
                    }
                ],
                "status": "planned",
            },
        )

        result = execute_plan(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            user_role="admin",
            plan_id=plan.id,
            correlation_id="corr-brain-approval-route",
        )

        assert called["count"] == 0
        assert len(result.steps_executed) == 1
        step = result.steps_executed[0]
        assert step.status == "needs_approval"
        assert step.execution_type == "mcp_tool_call"
        assert isinstance(step.result.get("action_id"), str)
        assert step.result["action_id"].startswith("brain.approve_tool.")
        assert isinstance(step.result.get("approval_request_id"), str)
        assert step.result.get("requested_tool") == tool_name

        approval_row = db.scalar(
            select(ApprovalRequest).where(
                ApprovalRequest.id == step.result["approval_request_id"],
                ApprovalRequest.tenant_id == tenant_id,
            )
        )
        assert approval_row is not None
        assert approval_row.status == "pending"

        action_audit = db.scalar(
            select(AuditLog).where(
                AuditLog.tenant_id == tenant_id,
                AuditLog.action == "brain.action_request",
            )
        )
        assert action_audit is not None

        action_evidence = db.scalar(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == tenant_id,
                EvidenceNode.node_type == "brain_action_request",
                EvidenceNode.signal_type == "brain.action_request",
            )
        )
        assert action_evidence is not None
        assert any(c.type == "evidence_node" and c.id == action_evidence.id for c in result.citations)
    finally:
        db.close()


def _mark_called(counter: dict[str, int]) -> dict[str, bool]:
    counter["count"] += 1
    return {"ok": True}


def test_brain_executor_accepts_agui_action_request_steps(tmp_path) -> None:
    db = _new_session(tmp_path)
    try:
        tenant_id, user_id, _ai_system_id = _seed_identity(db)
        session = create_brain_session(db, tenant_id=tenant_id, user_id=user_id)
        plan = save_brain_plan(
            db,
            session_id=session.id,
            question="Request AGUI action",
            plan_json={
                "question": "Request AGUI action",
                "steps": [
                    {
                        "step_id": "s1",
                        "execution_type": "agui_action_request",
                        "action_id": "findings.accept_risk",
                        "args": {"finding_id": "finding-placeholder"},
                        "expect_schema": {"type": "object"},
                        "on_error": "stop",
                    }
                ],
                "status": "planned",
            },
        )

        result = execute_plan(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            user_role="admin",
            plan_id=plan.id,
            correlation_id="corr-brain-agui-step",
        )

        assert len(result.steps_executed) == 1
        step = result.steps_executed[0]
        assert step.execution_type == "agui_action_request"
        assert step.status == "needs_approval"
        assert step.action_id == "findings.accept_risk"
        assert step.result.get("action_id") == "findings.accept_risk"
        assert step.result.get("status") == "pending"
    finally:
        db.close()


def test_brain_executor_enforce_side_effect_requires_approval_by_default(tmp_path) -> None:
    db = _new_session(tmp_path)
    try:
        tenant_id, user_id, ai_system_id = _seed_identity(db)
        called = {"count": 0}
        tool_name = f"test.enforce_side_effect.{uuid4().hex[:8]}"
        registry = get_mcp_registry()
        if registry.get(tool_name) is None:
            registry.register(
                ToolRegistration(
                    contract=ToolContract(
                        tool_name=tool_name,
                        module="test",
                        version="1.0.0",
                        description="Enforce side-effect tool without explicit approval flag",
                        input_schema={
                            "type": "object",
                            "properties": {"ai_system_id": {"type": "string"}},
                            "required": ["ai_system_id"],
                            "additionalProperties": False,
                        },
                        output_schema={
                            "type": "object",
                            "properties": {"ok": {"type": "boolean"}},
                            "required": ["ok"],
                            "additionalProperties": False,
                        },
                        required_role=["admin", "owner"],
                        requires_approval=False,
                        writes_evidence=False,
                        side_effect_level="enforce",
                        citations_supported=False,
                        governance_scope_required=False,
                        tenant_scope_required=True,
                        idempotent=False,
                        timeout_ms=5000,
                    ),
                    executor=lambda _db, _ctx, _args: _mark_called(called),
                )
            )

        session = create_brain_session(db, tenant_id=tenant_id, user_id=user_id)
        plan = save_brain_plan(
            db,
            session_id=session.id,
            question="Run enforce-side-effect tool",
            plan_json={
                "question": "Run enforce-side-effect tool",
                "steps": [
                    {
                        "step_id": "s1",
                        "execution_type": "mcp_tool_call",
                        "tool": tool_name,
                        "args": {"ai_system_id": ai_system_id},
                        "expect_schema": {"type": "object"},
                        "on_error": "stop",
                    }
                ],
                "status": "planned",
            },
        )

        result = execute_plan(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            user_role="admin",
            plan_id=plan.id,
            correlation_id="corr-brain-enforce-side-effect",
        )

        assert called["count"] == 0
        assert len(result.steps_executed) == 1
        assert result.steps_executed[0].status == "needs_approval"
    finally:
        db.close()


def test_brain_execution_modules_only_depend_on_brain_mcp_agui_execution_surfaces() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    files = [
        repo_root / "app/services/brain/planner.py",
        repo_root / "app/services/brain/executor.py",
        repo_root / "app/services/brain/summarizer.py",
    ]
    allowed_prefixes = (
        "app.services.brain",
        "app.services.mcp",
        "app.services.agui",
    )
    allowed_exact = {
        "app.services.audit_service",
        "app.services.evidence_service",
    }

    violations: list[str] = []
    for file_path in files:
        tree = ast.parse(file_path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            module_names: list[str] = []
            if isinstance(node, ast.Import):
                module_names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                module_names = [node.module]

            for module_name in module_names:
                if not module_name.startswith("app.services."):
                    continue
                if module_name in allowed_exact:
                    continue
                if module_name.startswith(allowed_prefixes):
                    continue
                violations.append(f"{file_path.name}: disallowed import '{module_name}'")

    assert not violations, "\n".join(violations)
