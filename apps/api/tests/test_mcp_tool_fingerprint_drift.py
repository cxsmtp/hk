from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.finding import Finding
from app.db.models.evidence import EvidenceNode
from app.db.models.policy import ToolFingerprint, ToolScanResult
from app.db.session import Base, get_db
from app.main import app
from app.services.agentic_action_integrity_service import (
    _tool_poisoning_lock_statement,
    evaluate_mcp_tool_call_integrity,
    scan_mcp_tool,
)
from app.services.ai_iam_service import (
    build_ai_action_record,
    build_pre_action_governance_check,
)


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "mcp_tool_fingerprint_drift.sqlite3"
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


def _register_owner(client: TestClient, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Fingerprint Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "tenant_id": body["tenants"][0]["id"],
        "user_id": body["user"]["id"],
    }


def _scan(
    db,
    *,
    tenant_id: str,
    tool_version: str = "1.0.0",
    manifest: dict | None = None,
    chain_id: str = "chain-fingerprint-drift",
) -> dict:
    return scan_mcp_tool(
        db,
        tenant_id=tenant_id,
        mcp_server_id="records-server",
        tool_name="read_record",
        tool_version=tool_version,
        description="Read one approved record",
        schema={
            "type": "object",
            "properties": {"record_id": {"type": "string"}},
            "required": ["record_id"],
        },
        examples=[{"record_id": "customer-42"}],
        manifest=manifest
        or {
            "name": "read_record",
            "version": tool_version,
            "description": "Read one approved record",
            "inputSchema": {
                "type": "object",
                "properties": {"record_id": {"type": "string"}},
                "required": ["record_id"],
            },
            "annotations": {"readOnlyHint": True},
        },
        chain_id=chain_id,
    )


@pytest.mark.parametrize(
    ("change", "expected_factor"),
    [
        ("manifest", "manifest_drift"),
        ("version", "tool_version_drift"),
    ],
)
def test_scan_marks_manifest_or_version_change_as_metadata_drift(
    test_env,
    change: str,
    expected_factor: str,
) -> None:
    owner = _register_owner(
        test_env["client"],
        f"{change}-drift-owner@example.com",
    )
    with test_env["SessionLocal"]() as db:
        first = _scan(db, tenant_id=owner["tenant_id"])
        assert first["trust_status"] == "unknown"

        if change == "manifest":
            changed = _scan(
                db,
                tenant_id=owner["tenant_id"],
                manifest={
                    "name": "read_record",
                    "version": "1.0.0",
                    "description": "Read one approved record",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"record_id": {"type": "string"}},
                        "required": ["record_id"],
                    },
                    "annotations": {"readOnlyHint": False},
                },
            )
        else:
            changed = _scan(
                db,
                tenant_id=owner["tenant_id"],
                tool_version="2.0.0",
            )

        assert changed["trust_status"] == "changed"
        assert expected_factor in changed["risk_factors"]
        findings = db.scalars(
            select(Finding).where(Finding.tenant_id == owner["tenant_id"])
        ).all()
        assert "MCP_TOOL_METADATA_DRIFT" in {
            finding.finding_type for finding in findings
        }


def test_integrity_allows_exact_claimed_fingerprint_and_blocks_stale_claim(
    test_env,
) -> None:
    owner = _register_owner(
        test_env["client"],
        "claimed-fingerprint-owner@example.com",
    )
    with test_env["SessionLocal"]() as db:
        row = ToolFingerprint(
            tenant_id=owner["tenant_id"],
            mcp_server_id="records-server",
            tool_name="read_record",
            tool_version="1.0.0",
            manifest_hash="manifest-v1",
            description_hash="description-v1",
            schema_hash="schema-v1",
            examples_hash="examples-v1",
            approved_hash="manifest-v1",
            trust_status="approved",
            approved_by=owner["user_id"],
            approved_at=datetime.now(timezone.utc),
        )
        db.add(row)
        db.commit()
        db.refresh(row)

        exact = evaluate_mcp_tool_call_integrity(
            db,
            tenant_id=owner["tenant_id"],
            chain_id="chain-exact-fingerprint",
            action_id="action-exact-fingerprint",
            agent_id="agent-record-reader",
            action="tool.run",
            resource="records-server",
            tool_name="read_record",
            tool_version="1.0.0",
            tool_fingerprint_id=row.id,
            mcp_server_id="records-server",
            parameters={"record_id": "customer-42"},
        )
        assert exact["decision"] == "allow"
        assert exact["tool_fingerprint_id"] == row.id

        stale = evaluate_mcp_tool_call_integrity(
            db,
            tenant_id=owner["tenant_id"],
            chain_id="chain-stale-fingerprint",
            action_id="action-stale-fingerprint",
            agent_id="agent-record-reader",
            action="tool.run",
            resource="records-server",
            tool_name="read_record",
            tool_version="1.0.0",
            tool_fingerprint_id="stale-or-foreign-fingerprint",
            mcp_server_id="records-server",
            parameters={"record_id": "customer-42"},
        )
        assert stale["decision"] == "block"
        assert "tool_fingerprint_mismatch" in stale["risk_factors"]
        assert "MCP_TOOL_METADATA_DRIFT" in stale["finding_types"]


@pytest.mark.parametrize(
    ("trust_status", "include_claim", "expected_factor"),
    [
        ("approved", False, "tool_fingerprint_missing"),
        ("unknown", True, "tool_trust_unknown"),
        ("changed", True, "tool_trust_changed"),
    ],
)
def test_integrity_blocks_without_exact_current_approved_fingerprint_authority(
    test_env,
    trust_status: str,
    include_claim: bool,
    expected_factor: str,
) -> None:
    owner = _register_owner(
        test_env["client"],
        f"{trust_status}-{include_claim}-authority-owner@example.com",
    )
    with test_env["SessionLocal"]() as db:
        row = ToolFingerprint(
            tenant_id=owner["tenant_id"],
            mcp_server_id="records-server",
            tool_name="read_record",
            tool_version="1.0.0",
            manifest_hash="manifest-v1",
            description_hash="description-v1",
            schema_hash="schema-v1",
            examples_hash="examples-v1",
            approved_hash="manifest-v1" if trust_status == "approved" else None,
            trust_status=trust_status,
            approved_by=owner["user_id"] if trust_status == "approved" else None,
            approved_at=datetime.now(timezone.utc) if trust_status == "approved" else None,
        )
        db.add(row)
        db.commit()
        db.refresh(row)

        result = evaluate_mcp_tool_call_integrity(
            db,
            tenant_id=owner["tenant_id"],
            chain_id=f"chain-{trust_status}-fingerprint-authority",
            action_id=f"action-{trust_status}-fingerprint-authority",
            agent_id="agent-record-reader",
            action="tool.run",
            resource="records-server",
            tool_name="read_record",
            tool_version="1.0.0",
            tool_fingerprint_id=row.id if include_claim else None,
            mcp_server_id="records-server",
            parameters={"record_id": "customer-42"},
        )

        assert result["decision"] == "block"
        assert expected_factor in result["risk_factors"]
        assert "MCP_TOOL_METADATA_DRIFT" in result["finding_types"]


def test_idempotent_replay_cannot_downgrade_current_changed_trust(test_env) -> None:
    owner = _register_owner(
        test_env["client"],
        "replay-fingerprint-owner@example.com",
    )
    changed_manifest = {
        "name": "read_record",
        "version": "1.0.0",
        "description": "Read one approved record",
        "inputSchema": {
            "type": "object",
            "properties": {"record_id": {"type": "string"}},
            "required": ["record_id"],
        },
        "annotations": {"readOnlyHint": False},
    }
    with test_env["SessionLocal"]() as db:
        first = _scan(db, tenant_id=owner["tenant_id"])
        initial_scan = db.get(ToolScanResult, first["scan_result_id"])
        assert initial_scan is not None
        initial_scan.created_at = datetime.now(timezone.utc) + timedelta(days=1)
        db.commit()

        changed = _scan(
            db,
            tenant_id=owner["tenant_id"],
            manifest=changed_manifest,
        )
        assert changed["trust_status"] == "changed"

        replay = _scan(
            db,
            tenant_id=owner["tenant_id"],
            manifest=changed_manifest,
        )

        assert replay["idempotent_replay"] is True
        assert replay["trust_status"] == "changed"


def test_detector_failure_is_sanitized_and_cannot_be_replayed_as_completed(
    test_env,
    monkeypatch,
) -> None:
    owner = _register_owner(
        test_env["client"],
        "detector-failure-fingerprint-owner@example.com",
    )
    from app.services.guardians import threat_detectors

    real_evaluate = threat_detectors.evaluate_threat_detectors

    def fail_detector(**_kwargs):
        raise RuntimeError("detector backend secret")

    monkeypatch.setattr(
        threat_detectors,
        "evaluate_threat_detectors",
        fail_detector,
    )
    with test_env["SessionLocal"]() as db:
        failed = _scan(db, tenant_id=owner["tenant_id"])

        assert failed["status"] == "failed"
        assert failed["tool_fingerprint_id"] is None
        assert failed["error"] == "MCP tool metadata scan failed"
        assert "detector backend secret" not in str(failed)
        assert db.scalars(
            select(ToolScanResult).where(
                ToolScanResult.tenant_id == owner["tenant_id"]
            )
        ).all() == []

        monkeypatch.setattr(
            threat_detectors,
            "evaluate_threat_detectors",
            real_evaluate,
        )
        completed = _scan(db, tenant_id=owner["tenant_id"])
        assert completed["status"] == "completed"
        assert completed["idempotent_replay"] is False

        monkeypatch.setattr(
            threat_detectors,
            "evaluate_threat_detectors",
            fail_detector,
        )
        failed_replay = _scan(db, tenant_id=owner["tenant_id"])
        assert failed_replay["status"] == "failed"
        assert failed_replay["idempotent_replay"] is False
        assert "detector backend secret" not in str(failed_replay)

        monkeypatch.setattr(
            threat_detectors,
            "evaluate_threat_detectors",
            real_evaluate,
        )
        replay = _scan(db, tenant_id=owner["tenant_id"])
        assert replay["status"] == "completed"
        assert replay["idempotent_replay"] is True


@pytest.mark.parametrize(
    "invalid_detector_output",
    [
        [{}],
        [{"decision": "not-a-decision"}],
        [{"decision": {"forged": "allow"}}],
        ["malformed-hit"],
    ],
)
def test_invalid_detector_decision_fails_closed_on_replay(
    test_env,
    monkeypatch,
    invalid_detector_output,
) -> None:
    owner = _register_owner(
        test_env["client"],
        f"invalid-detector-{abs(hash(str(invalid_detector_output)))}@example.com",
    )
    from app.services.guardians import threat_detectors

    monkeypatch.setattr(
        threat_detectors,
        "evaluate_threat_detectors",
        lambda **_kwargs: [],
    )
    with test_env["SessionLocal"]() as db:
        completed = _scan(db, tenant_id=owner["tenant_id"])
        assert completed["status"] == "completed"

        monkeypatch.setattr(
            threat_detectors,
            "evaluate_threat_detectors",
            lambda **_kwargs: invalid_detector_output,
        )
        replay = _scan(db, tenant_id=owner["tenant_id"])

        assert replay["status"] == "failed"
        assert replay["idempotent_replay"] is False
        assert replay["tool_poisoning_decision"] == "block"
        assert replay["error"] == "MCP tool metadata scan failed"


def test_idempotent_replay_cannot_downgrade_tool_poisoning_decision(
    test_env,
    monkeypatch,
) -> None:
    owner = _register_owner(
        test_env["client"],
        "poisoning-replay-fingerprint-owner@example.com",
    )
    from app.services.guardians import threat_detectors

    detector_decisions = iter(["allow", "block", "allow"])

    monkeypatch.setattr(
        threat_detectors,
        "evaluate_threat_detectors",
        lambda **_kwargs: [
            {
                "guardian_id": "tool-poisoning-test",
                "threat_types": ["tool_poisoning"],
                "decision": next(detector_decisions),
                "framework_refs": ["OWASP-LLM"],
            }
        ],
    )
    with test_env["SessionLocal"]() as db:
        first = _scan(db, tenant_id=owner["tenant_id"])
        persisted = db.get(ToolScanResult, first["scan_result_id"])
        fingerprint = db.get(ToolFingerprint, first["tool_fingerprint_id"])
        assert persisted is not None
        assert fingerprint is not None
        fingerprint.trust_status = "approved"
        fingerprint.approved_hash = fingerprint.manifest_hash
        fingerprint.approved_by = owner["user_id"]
        fingerprint.approved_at = datetime.now(timezone.utc)
        persisted.trust_status = "approved"
        db.commit()

        stronger_replay = _scan(db, tenant_id=owner["tenant_id"])
        later_replay = _scan(db, tenant_id=owner["tenant_id"])

        assert first["tool_poisoning_decision"] == "allow"
        assert stronger_replay["idempotent_replay"] is True
        assert stronger_replay["tool_poisoning_decision"] == "block"
        assert later_replay["idempotent_replay"] is True
        assert later_replay["tool_poisoning_decision"] == "block"
        assert "tool_poisoning_decision:block" in later_replay["risk_factors"]
        persisted = db.get(ToolScanResult, first["scan_result_id"])
        assert persisted is not None
        assert "tool_poisoning_decision:block" in persisted.risk_factors
        evidence = db.get(EvidenceNode, persisted.evidence_node_id)
        assert evidence is not None
        assert "tool_poisoning_decision:block" in evidence.payload["risk_factors"]
        assert evidence.payload["tool_poisoning_decision"] == "block"
        authority = db.scalar(
            select(ToolScanResult).where(
                ToolScanResult.id == fingerprint.id,
                ToolScanResult.tenant_id == owner["tenant_id"],
                ToolScanResult.chain_id == f"mcp-authority:{fingerprint.id}",
                ToolScanResult.tool_fingerprint_id == fingerprint.id,
            )
        )
        assert authority is not None
        assert "tool_poisoning_decision:block" in authority.risk_factors

        authorization = evaluate_mcp_tool_call_integrity(
            db,
            tenant_id=owner["tenant_id"],
            chain_id="chain-poisoning-authorization",
            action_id="action-poisoning-authorization",
            agent_id="agent-record-reader",
            action="tool.run",
            resource="records-server",
            tool_name="read_record",
            tool_version="1.0.0",
            tool_fingerprint_id=fingerprint.id,
            mcp_server_id="records-server",
            parameters={"record_id": "customer-42"},
        )
        assert authorization["decision"] == "block"
        assert "tool_poisoning_decision:block" in authorization["risk_factors"]


def test_poisoning_authority_lookup_is_index_keyed_and_bounded_with_large_history(
    test_env,
) -> None:
    owner = _register_owner(
        test_env["client"],
        "bounded-poisoning-authority-owner@example.com",
    )
    with test_env["SessionLocal"]() as db:
        fingerprint = ToolFingerprint(
            tenant_id=owner["tenant_id"],
            mcp_server_id="records-server",
            tool_name="read_record",
            tool_version="1.0.0",
            manifest_hash="manifest-v1",
            description_hash="description-v1",
            schema_hash="schema-v1",
            examples_hash="examples-v1",
            approved_hash="manifest-v1",
            trust_status="approved",
            approved_by=owner["user_id"],
            approved_at=datetime.now(timezone.utc),
        )
        db.add(fingerprint)
        db.flush()
        db.add(
            ToolScanResult(
                id=fingerprint.id,
                tenant_id=owner["tenant_id"],
                chain_id=f"mcp-authority:{fingerprint.id}",
                tool_fingerprint_id=fingerprint.id,
                mcp_server_id="records-server",
                tool_name="read_record",
                trust_status="approved",
                risk_factors=["tool_poisoning_decision:block"],
            )
        )
        db.add_all(
            [
                ToolScanResult(
                    tenant_id=owner["tenant_id"],
                    chain_id=f"history-{index}",
                    tool_fingerprint_id=fingerprint.id,
                    mcp_server_id="records-server",
                    tool_name="read_record",
                    trust_status="approved",
                    risk_factors=[],
                )
                for index in range(1500)
            ]
        )
        db.commit()

        statements: list[str] = []

        def capture_statement(
            _conn,
            _cursor,
            statement,
            _parameters,
            _context,
            _executemany,
        ) -> None:
            if "from tool_scan_results" in statement.lower():
                statements.append(" ".join(statement.lower().split()))

        event.listen(db.get_bind(), "before_cursor_execute", capture_statement)
        try:
            authorization = evaluate_mcp_tool_call_integrity(
                db,
                tenant_id=owner["tenant_id"],
                chain_id="chain-bounded-poisoning-authorization",
                action_id="action-bounded-poisoning-authorization",
                agent_id="agent-record-reader",
                action="tool.run",
                resource="records-server",
                tool_name="read_record",
                tool_version="1.0.0",
                tool_fingerprint_id=fingerprint.id,
                mcp_server_id="records-server",
                parameters={"record_id": "customer-42"},
            )
        finally:
            event.remove(db.get_bind(), "before_cursor_execute", capture_statement)

        assert authorization["decision"] == "block"
        assert "tool_poisoning_decision:block" in authorization["risk_factors"]
        assert len(statements) == 1
        assert "tool_scan_results.id =" in statements[0]
        assert "tool_scan_results.chain_id =" in statements[0]
        assert " limit " in statements[0]


def test_reserved_authority_chain_namespace_cannot_shadow_deterministic_authority(
    test_env,
    monkeypatch,
) -> None:
    owner = _register_owner(
        test_env["client"],
        "reserved-authority-chain-owner@example.com",
    )
    from app.services.guardians import threat_detectors

    monkeypatch.setattr(
        threat_detectors,
        "evaluate_threat_detectors",
        lambda **_kwargs: [],
    )
    with test_env["SessionLocal"]() as db:
        setup = _scan(
            db,
            tenant_id=owner["tenant_id"],
            chain_id="chain-authority-setup",
        )
        fingerprint = db.get(ToolFingerprint, setup["tool_fingerprint_id"])
        authority = db.get(ToolScanResult, fingerprint.id)
        assert fingerprint is not None
        assert authority is not None
        db.delete(authority)
        db.commit()

        malicious_chain = f"mcp-authority:{fingerprint.id}"
        detector_decisions = iter(["allow", "block", "allow"])
        monkeypatch.setattr(
            threat_detectors,
            "evaluate_threat_detectors",
            lambda **_kwargs: [
                {
                    "guardian_id": "reserved-authority-chain-test",
                    "threat_types": ["tool_poisoning"],
                    "decision": next(detector_decisions),
                    "framework_refs": ["OWASP-LLM"],
                }
            ],
        )

        before_authority = _scan(
            db,
            tenant_id=owner["tenant_id"],
            chain_id=malicious_chain,
        )
        after_authority = _scan(
            db,
            tenant_id=owner["tenant_id"],
            chain_id=malicious_chain,
        )
        later_allow = _scan(
            db,
            tenant_id=owner["tenant_id"],
            chain_id=malicious_chain,
        )

        assert before_authority["tool_poisoning_decision"] == "allow"
        assert after_authority["tool_poisoning_decision"] == "block"
        assert later_allow["tool_poisoning_decision"] == "block"

        authority = db.get(ToolScanResult, fingerprint.id)
        assert authority is not None
        assert authority.chain_id == malicious_chain
        assert "tool_poisoning_decision:block" in authority.risk_factors
        colliding_rows = db.scalars(
            select(ToolScanResult).where(
                ToolScanResult.tenant_id == owner["tenant_id"],
                ToolScanResult.chain_id == malicious_chain,
                ToolScanResult.tool_fingerprint_id == fingerprint.id,
            )
        ).all()
        assert [row.id for row in colliding_rows] == [fingerprint.id]
        receipts = db.scalars(
            select(ToolScanResult).where(
                ToolScanResult.tenant_id == owner["tenant_id"],
                ToolScanResult.tool_fingerprint_id == fingerprint.id,
                ToolScanResult.id != fingerprint.id,
            )
        ).all()
        assert any(
            row.id == before_authority["scan_result_id"]
            and row.chain_id
            and not row.chain_id.startswith("mcp-authority:")
            for row in receipts
        )

        fingerprint.trust_status = "approved"
        fingerprint.approved_hash = fingerprint.manifest_hash
        fingerprint.approved_by = owner["user_id"]
        fingerprint.approved_at = datetime.now(timezone.utc)
        db.commit()
        authorization = evaluate_mcp_tool_call_integrity(
            db,
            tenant_id=owner["tenant_id"],
            chain_id="chain-reserved-authority-authorization",
            action_id="action-reserved-authority-authorization",
            agent_id="agent-record-reader",
            action="tool.run",
            resource="records-server",
            tool_name="read_record",
            tool_version="1.0.0",
            tool_fingerprint_id=fingerprint.id,
            mcp_server_id="records-server",
            parameters={"record_id": "customer-42"},
        )

        assert authorization["decision"] == "block"
        assert "tool_poisoning_decision:block" in authorization["risk_factors"]


def test_concurrent_allow_cannot_downgrade_block_poisoning_authority(
    test_env,
    monkeypatch,
) -> None:
    owner = _register_owner(
        test_env["client"],
        "concurrent-poisoning-authority-owner@example.com",
    )
    from app.services.guardians import threat_detectors

    monkeypatch.setattr(
        threat_detectors,
        "evaluate_threat_detectors",
        lambda **_kwargs: [],
    )
    with test_env["SessionLocal"]() as db:
        setup = _scan(
            db,
            tenant_id=owner["tenant_id"],
            chain_id="chain-concurrent-authority-setup",
        )
        fingerprint_id = setup["tool_fingerprint_id"]

    detector_barrier = threading.Barrier(2)
    detector_state = threading.local()

    def concurrent_detector(**_kwargs):
        decision = detector_state.decision
        detector_barrier.wait(timeout=5)
        if decision == "allow":
            time.sleep(0.15)
        return [
            {
                "guardian_id": "concurrent-poisoning-authority-test",
                "threat_types": ["tool_poisoning"],
                "decision": decision,
                "framework_refs": ["OWASP-LLM"],
            }
        ]

    monkeypatch.setattr(
        threat_detectors,
        "evaluate_threat_detectors",
        concurrent_detector,
    )

    def run_scan(decision: str) -> dict:
        detector_state.decision = decision
        with test_env["SessionLocal"]() as db:
            return _scan(
                db,
                tenant_id=owner["tenant_id"],
                chain_id=f"chain-concurrent-{decision}",
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        block_future = executor.submit(run_scan, "block")
        allow_future = executor.submit(run_scan, "allow")
        block_result = block_future.result(timeout=10)
        allow_result = allow_future.result(timeout=10)

    assert block_result["tool_poisoning_decision"] == "block"
    assert allow_result["tool_poisoning_decision"] == "block"
    with test_env["SessionLocal"]() as db:
        authority = db.get(ToolScanResult, fingerprint_id)
        assert authority is not None
        assert "tool_poisoning_decision:block" in authority.risk_factors


def test_postgresql_poisoning_authority_lock_is_row_scoped() -> None:
    statement = _tool_poisoning_lock_statement(
        tenant_id="tenant-lock-test",
        tool_fingerprint_id="fingerprint-lock-test",
    )
    compiled = str(
        statement.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    ).lower()

    assert "from tool_fingerprints" in compiled
    assert "tool_fingerprints.id = 'fingerprint-lock-test'" in compiled
    assert "tool_fingerprints.tenant_id = 'tenant-lock-test'" in compiled
    assert "for update" in compiled


def test_foreign_tenant_fingerprint_id_is_not_authority(test_env) -> None:
    owner = _register_owner(
        test_env["client"],
        "tenant-a-fingerprint-owner@example.com",
    )
    foreign = _register_owner(
        test_env["client"],
        "tenant-b-fingerprint-owner@example.com",
    )
    with test_env["SessionLocal"]() as db:
        own = ToolFingerprint(
            tenant_id=owner["tenant_id"],
            mcp_server_id="records-server",
            tool_name="read_record",
            tool_version="1.0.0",
            manifest_hash="manifest-owner",
            description_hash="description-owner",
            schema_hash="schema-owner",
            examples_hash="examples-owner",
            approved_hash="manifest-owner",
            trust_status="approved",
            approved_by=owner["user_id"],
            approved_at=datetime.now(timezone.utc),
        )
        foreign_row = ToolFingerprint(
            tenant_id=foreign["tenant_id"],
            mcp_server_id="records-server",
            tool_name="read_record",
            tool_version="1.0.0",
            manifest_hash="manifest-foreign",
            description_hash="description-foreign",
            schema_hash="schema-foreign",
            examples_hash="examples-foreign",
            approved_hash="manifest-foreign",
            trust_status="approved",
            approved_by=foreign["user_id"],
            approved_at=datetime.now(timezone.utc),
        )
        db.add_all([own, foreign_row])
        db.commit()
        db.refresh(foreign_row)

        result = evaluate_mcp_tool_call_integrity(
            db,
            tenant_id=owner["tenant_id"],
            chain_id="chain-foreign-fingerprint",
            action_id="action-foreign-fingerprint",
            agent_id="agent-record-reader",
            action="tool.run",
            resource="records-server",
            tool_name="read_record",
            tool_version="1.0.0",
            tool_fingerprint_id=foreign_row.id,
            mcp_server_id="records-server",
            parameters={"record_id": "customer-42"},
        )

        assert result["decision"] == "block"
        assert "tool_fingerprint_mismatch" in result["risk_factors"]
        assert result["tool_fingerprint_id"] == own.id


def test_mcp_pre_action_material_preserves_exact_binding_fields() -> None:
    result = build_pre_action_governance_check(
        tenant_id="tenant-binding",
        action_id="action-binding",
        source_event_id=None,
        actor={"identity_id": "agent-binding", "identity_type": "agent"},
        authority={
            "authority_type": "delegated_agent",
            "authority_source": "mcp_authorize",
            "verified": True,
        },
        purpose_permission=None,
        purpose_result={"decision": "allow"},
        surface={
            "surface_type": "mcp",
            "application": "read_record",
            "mcp_server_id": "records-server",
            "domain": "records.example.test",
        },
        action={
            "action_type": "tool_execution",
            "target_resource": "customer-42",
            "data_destination": "https://records.example.test/customers/42",
            "tool_name": "read_record",
            "tool_version": "1.0.0",
            "tool_fingerprint_id": "fingerprint-exact",
            "parameter_hash": "arguments-hash-exact",
            "expected_parameter_hash": "expected-arguments-hash-exact",
            "side_effect_class": "read",
            "persistent_side_effect": False,
        },
    )

    assert result["surface"]["mcp_server_id"] == "records-server"
    assert result["action"]["tool_fingerprint_id"] == "fingerprint-exact"
    assert result["action"]["parameter_hash"] == "arguments-hash-exact"
    assert result["action"]["target_resource"] == "customer-42"
    assert (
        result["action"]["data_destination"]
        == "https://records.example.test/customers/42"
    )
    assert (
        result["action"]["expected_parameter_hash"]
        == "expected-arguments-hash-exact"
    )
    assert result["action"]["side_effect_class"] == "read"
    assert result["action"]["persistent_side_effect"] is False

    record = build_ai_action_record(
        tenant_id="tenant-binding",
        action_id="action-binding",
        timestamp="2026-07-23T00:00:00+00:00",
        source_surface="gateway",
        event_type="mcp_authorize",
        agent_id="agent-binding",
        decision="allow",
        correlation_id="correlation-binding",
        chain_id="chain-binding",
        trusted_pre_action_governance_check=result,
    )

    assert (
        record["action"]["data_destination"]
        == "https://records.example.test/customers/42"
    )
    assert (
        record["action"]["expected_parameter_hash"]
        == "expected-arguments-hash-exact"
    )
    assert record["action"]["side_effect_class"] == "read"
    assert record["action"]["persistent_side_effect"] is False
