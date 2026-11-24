from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.knowledge_base import (
    KBControl,
    KBControlGuardianMap,
    KBControlSimMap,
    KBDoc,
    KBFramework,
    KBGuardianContract,
    KBSimulationTemplate,
)
from app.db.session import Base
from app.services.brain.rag.retriever import retrieve_knowledge_bundle


def _seed_minimal_kb(db) -> dict[str, str]:
    fw_iso = KBFramework(name="ISO42001", version="2023", source_type="authored")
    fw_owasp = KBFramework(name="OWASP-AGENTIC", version="2026.1", source_type="authored")
    db.add_all([fw_iso, fw_owasp])
    db.flush()

    controls = [
        KBControl(
            id="ISO42001.7.2",
            framework_id=fw_iso.id,
            title="Auditability baseline",
            objective="Keep immutable logs for policy and approvals.",
            requirement_level="MUST",
            applicability_tags=["audit", "logging"],
            maturity_model={"level_0": "ad_hoc", "level_5": "adaptive"},
            evidence_requirements={"sources": ["audit_log"], "freshness_sla_hours": 24},
        ),
        KBControl(
            id="OWASP-AGENTIC.A01",
            framework_id=fw_owasp.id,
            title="Prompt injection containment",
            objective="Detect prompt injection and contain instruction hijack attempts.",
            requirement_level="MUST",
            applicability_tags=["prompt", "injection"],
            maturity_model={"level_0": "ad_hoc", "level_5": "adaptive"},
            evidence_requirements={"sources": ["enforcement_event"], "freshness_sla_hours": 24},
        ),
        KBControl(
            id="OWASP-AGENTIC.A02",
            framework_id=fw_owasp.id,
            title="Tool output sanitization",
            objective="Sanitize untrusted tool output before model use.",
            requirement_level="MUST",
            applicability_tags=["tool", "output"],
            maturity_model={"level_0": "ad_hoc", "level_5": "adaptive"},
            evidence_requirements={"sources": ["enforcement_event"], "freshness_sla_hours": 24},
        ),
    ]
    db.add_all(controls)

    guardian = KBGuardianContract(
        name="prompt_injection",
        intent="Detect prompt injection patterns and block unsafe requests.",
        detection_inputs={"signal_types": ["prompt.text"]},
        enforcement_contract={"on_fail": "block"},
    )
    sim = KBSimulationTemplate(
        name="Injection Simulation",
        category="injection",
        template_schema={"fields": ["prompt"]},
        safe_boundary={"requires_sandbox": True, "no_external_network": True},
    )
    db.add_all([guardian, sim])
    db.flush()

    db.add_all(
        [
            KBControlGuardianMap(
                control_id="OWASP-AGENTIC.A01",
                guardian_contract_id=guardian.id,
                enforcement_strength="maximum",
            ),
            KBControlSimMap(
                control_id="OWASP-AGENTIC.A01",
                simulation_template_id=sim.id,
                required_frequency="daily",
                failure_impact={"maturity_delta_on_fail": -0.1},
            ),
        ]
    )

    db.add_all(
        [
            KBDoc(
                framework_id=fw_owasp.id,
                title="Agentic control summary",
                body="Authored summary for prompt injection and tool safety controls.",
                source_type="authored",
            ),
            KBDoc(
                framework_id=fw_owasp.id,
                title="Licensed framework text",
                body="CUSTOMER_LICENSED_FRAMEWORK_TEXT",
                source_type="customer_provided",
            ),
        ]
    )

    db.commit()
    return {"iso_id": fw_iso.id, "owasp_id": fw_owasp.id, "guardian_id": guardian.id, "sim_id": sim.id}


def test_retriever_prioritizes_controls_contracts_and_templates_before_docs(tmp_path) -> None:
    db_file = tmp_path / "kb_retriever.sqlite3"
    engine = create_engine(f"sqlite+pysqlite:///{db_file}", connect_args={"check_same_thread": False})
    testing_session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    try:
        with testing_session_local() as db:
            refs = _seed_minimal_kb(db)
            result = retrieve_knowledge_bundle(
                db,
                question="How do we prevent prompt injection and sanitize tool output?",
                tenant_id="tenant-test",
                ai_system_id="ai-123",
                frameworks_in_scope=["OWASP-AGENTIC"],
            )

        top_controls = result["top_controls"]
        assert top_controls
        assert top_controls[0]["control_id"] == "OWASP-AGENTIC.A01"
        assert all("control_id" in row and "framework_id" in row for row in top_controls)
        assert all(row["framework_id"] == refs["owasp_id"] for row in top_controls)

        top_guardians = result["top_guardian_contracts"]
        assert top_guardians
        assert top_guardians[0]["guardian_contract_id"] == refs["guardian_id"]

        top_sim_templates = result["top_sim_templates"]
        assert top_sim_templates
        assert top_sim_templates[0]["simulation_template_id"] == refs["sim_id"]

        top_docs = result["top_docs"]
        assert top_docs
        assert all(row["source_type"] == "authored" for row in top_docs)

        hooks = result["evidence_hooks"]
        assert hooks
        assert hooks[0]["tool"] == "evidence.query"
        assert hooks[1]["tool"] == "enforcement.list_events"
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_retriever_returns_stable_id_shapes(tmp_path) -> None:
    db_file = tmp_path / "kb_retriever_stable.sqlite3"
    engine = create_engine(f"sqlite+pysqlite:///{db_file}", connect_args={"check_same_thread": False})
    testing_session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    try:
        with testing_session_local() as db:
            _seed_minimal_kb(db)
            result = retrieve_knowledge_bundle(
                db,
                question="Show controls for auditability",
                tenant_id="tenant-test",
                ai_system_id=None,
                frameworks_in_scope=["ISO42001"],
            )

        assert all(isinstance(row.get("control_id"), str) and row["control_id"] for row in result["top_controls"])
        assert all(
            isinstance(row.get("guardian_contract_id"), str) and row["guardian_contract_id"]
            for row in result["top_guardian_contracts"]
        )
        assert all(
            isinstance(row.get("simulation_template_id"), str) and row["simulation_template_id"]
            for row in result["top_sim_templates"]
        )
        assert all(isinstance(row.get("doc_id"), str) and row["doc_id"] for row in result["top_docs"])
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
