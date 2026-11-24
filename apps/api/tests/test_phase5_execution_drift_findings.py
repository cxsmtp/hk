from __future__ import annotations

from types import SimpleNamespace

from test_phase5_execution_receipt_v2 import _action


def test_execution_drift_has_hashed_per_field_evidence_without_raw_parameter_values() -> None:
    from app.services.action_integrity.execution_proof import compare_authorized_to_executed
    executed = _action()
    executed["action_semantics"] = {**executed["action_semantics"], "safe_parameters": {"secret": "do-not-store"}}
    result = compare_authorized_to_executed(_action(), executed)
    assert result["result"] == "DRIFTED"
    assert all("authorized_hash" in item and "executed_hash" in item for item in result["difference_hashes"])
    assert "do-not-store" not in repr(result["difference_hashes"])


def test_drift_persistence_creates_tenant_scoped_evidence_and_deduplicated_finding(tmp_path) -> None:
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker

    from app.db.models.evidence import EvidenceNode
    from app.db.models.finding import Finding
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.lifecycle_persistence import persist_execution_receipt_v2_and_comparison
    from test_phase5_execution_receipt_v2 import NOW, _provider

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'drift.sqlite3'}")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with sessions.begin() as db:
            db.add(Tenant(id="tenant-exec", name="Execution", slug="execution-drift", is_active=True))
        executed = _action()
        executed["action_semantics"] = {**executed["action_semantics"], "target_refs": ["target:changed"]}
        receipt = SimpleNamespace(receipt_id="receipt-drift", tenant_id="tenant-exec", execution_attempt_id="attempt-drift", execution_status="success", decision_receipt_id=None)
        with sessions.begin() as db:
            persist_execution_receipt_v2_and_comparison(db, provider=_provider(), execution_receipt=receipt, authorized=_action(), executed=executed, permit_id="permit", issued_at=NOW)
            finding = db.scalar(select(Finding).where(Finding.tenant_id == "tenant-exec", Finding.finding_type == "EXECUTION_DRIFT_DETECTED"))
            assert finding is not None and finding.evidence_node_ids
            node = db.get(EvidenceNode, finding.evidence_node_ids[0])
            assert node is not None and node.tenant_id == "tenant-exec"
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
