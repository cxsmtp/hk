from __future__ import annotations

from sqlalchemy import select

from app.db.models.knowledge_base import (
    KBControl,
    KBControlGuardianMap,
    KBControlSimMap,
    KBCrosswalk,
    KBDoc,
    KBFramework,
    KBGuardianContract,
    KBSimulationTemplate,
    KBThreat,
    KBThreatControlMap,
)
from app.db.session import SessionLocal


FRAMEWORKS = [
    {"name": "NIST-AI-RMF", "version": "1.0", "source_type": "authored"},
    {"name": "ISO42001", "version": "2023", "source_type": "authored"},
    {"name": "OWASP-AGENTIC", "version": "2026.1", "source_type": "authored"},
]


NIST_CONTROLS = [
    ("NIST-AI-RMF.GOV-1", "Governed AI Ownership", "Define accountable ownership for each AI system and control objective."),
    ("NIST-AI-RMF.GOV-2", "Policy Lifecycle Discipline", "Require policy versioning, approvals, and retirement criteria."),
    ("NIST-AI-RMF.GOV-3", "Decision Logging", "Persist deterministic decision metadata for every critical AI interaction."),
    ("NIST-AI-RMF.MAP-1", "System Context Mapping", "Maintain documented context boundaries, trust zones, and permitted data flows."),
    ("NIST-AI-RMF.MAP-2", "Threat Scenario Catalog", "Maintain known misuse patterns mapped to prevention and detection controls."),
    ("NIST-AI-RMF.MAP-3", "Evidence Traceability", "Link every control claim to machine-verifiable evidence nodes."),
    ("NIST-AI-RMF.MEASURE-1", "Continuous Signal Validation", "Collect and evaluate monitoring signals on a fixed cadence."),
    ("NIST-AI-RMF.MEASURE-2", "Simulation Verification", "Exercise high-risk controls using deterministic simulation runs."),
    ("NIST-AI-RMF.MANAGE-1", "Adaptive Enforcement", "Tighten enforcement levels when control confidence declines."),
    ("NIST-AI-RMF.MANAGE-2", "Incident Response Hooks", "Trigger response workflows when critical AI control failures occur."),
]


ISO_CONTROLS = [
    ("ISO42001.5.1", "AI Governance Charter", "Adopt and maintain an AI management charter with review checkpoints."),
    ("ISO42001.5.2", "Role Segregation", "Separate control authorship, approval, and operations responsibilities."),
    ("ISO42001.6.1", "Risk Register for AI", "Track AI-specific risks with owners, residual risk, and closure criteria."),
    ("ISO42001.6.2", "Control Applicability Logic", "Define when each control is mandatory based on risk tier and context."),
    ("ISO42001.7.1", "Operational Monitoring", "Run operational monitors and alert on drift from expected behavior."),
    ("ISO42001.7.2", "Auditability Baseline", "Keep immutable logs for policy decisions, approvals, and overrides."),
    ("ISO42001.8.1", "Supplier Boundary Controls", "Constrain third-party model/tool usage through explicit gateways."),
    ("ISO42001.8.2", "Human Oversight Controls", "Require human approval for high-impact uncertain decisions."),
    ("ISO42001.9.1", "Corrective Action Tracking", "Record and track remediation actions for failed controls."),
    ("ISO42001.9.2", "Improvement Cadence", "Periodically improve controls using maturity trend data."),
]


OWASP_CONTROLS = [
    ("OWASP-AGENTIC.A01", "Prompt Injection Containment", "Detect and contain adversarial prompt steering attempts."),
    ("OWASP-AGENTIC.A02", "Tool Output Sanitization", "Validate and sanitize tool outputs before downstream use."),
    ("OWASP-AGENTIC.A03", "Context Isolation", "Enforce strict context isolation across tenants and sessions."),
    ("OWASP-AGENTIC.A04", "Sensitive Data Guardrails", "Block or redact sensitive payload exposure in prompts and outputs."),
    ("OWASP-AGENTIC.A05", "RAG Integrity Verification", "Check retrieval content integrity and provenance signals."),
    ("OWASP-AGENTIC.A06", "Agent Capability Scoping", "Scope agent actions through least-privilege capability tokens."),
    ("OWASP-AGENTIC.A07", "Execution Chain Limits", "Bound multi-step execution depth and time for autonomous agents."),
    ("OWASP-AGENTIC.A08", "Action Authorization", "Authorize each high-risk tool invocation through policy contracts."),
    ("OWASP-AGENTIC.A09", "Safety Fallbacks", "Fail closed for critical paths when dependencies become unavailable."),
    ("OWASP-AGENTIC.A10", "Evidence-Backed Responses", "Require cited internal evidence for compliance or safety claims."),
]


THREATS = [
    ("ATLAS.T1559", "ATLAS.T1559", "Prompt Directive Hijack", "Attacker-crafted text attempts to override trusted instructions."),
    ("ATLAS.T1565", "ATLAS.T1565", "Data Artifact Tampering", "Manipulated artifacts corrupt downstream AI decisions."),
    ("ATLAS.T1608", "ATLAS.T1608", "Model Resource Abuse", "Abuse of model invocation patterns to evade controls."),
    ("ATLAS.T1611", "ATLAS.T1611", "Agent Tool Misuse", "Unauthorized agent tool execution to reach restricted actions."),
    ("ATLAS.T1613", "ATLAS.T1613", "Context Exfiltration", "Cross-context data extraction from prior sessions."),
    ("OWASP-GENAI.A01", "OWASP-GENAI.A01", "Prompt Injection", "Untrusted input manipulates model instructions."),
    ("OWASP-GENAI.A03", "OWASP-GENAI.A03", "Training Data Leakage", "Sensitive knowledge leakage through model responses."),
    ("OWASP-GENAI.A05", "OWASP-GENAI.A05", "Supply Chain Weakness", "Upstream model/tool dependency introduces unsafe behavior."),
    ("OWASP-GENAI.A07", "OWASP-GENAI.A07", "Insecure Plugin Invocation", "Unsafe connector or plugin execution path."),
    ("OWASP-GENAI.A09", "OWASP-GENAI.A09", "Output Handling Failure", "Unsafe output forwarded without policy enforcement."),
]


GUARDIANS = [
    {
        "name": "prompt_injection",
        "intent": "Prevent instruction hijack and malicious prompt overrides.",
        "detection_inputs": {"signal_types": ["prompt.text", "context.rag"]},
        "enforcement_contract": {"on_fail": "block", "escalation": "notify", "evidence_signal": "guardian.prompt_injection.detected"},
    },
    {
        "name": "jailbreak",
        "intent": "Detect jailbreak patterns and enforce restricted completion policy.",
        "detection_inputs": {"signal_types": ["prompt.text"]},
        "enforcement_contract": {"on_fail": "hold_for_approval", "escalation": "approval_required", "evidence_signal": "guardian.jailbreak.detected"},
    },
    {
        "name": "sensitive_data_leakage",
        "intent": "Block or redact PII, secrets, and regulated content leakage.",
        "detection_inputs": {"signal_types": ["prompt.text", "tool.output", "response.text"]},
        "enforcement_contract": {"on_fail": "redact", "escalation": "ticket", "evidence_signal": "guardian.sensitive_data.detected"},
    },
    {
        "name": "tool_output_injection",
        "intent": "Filter hostile instructions embedded in tool outputs.",
        "detection_inputs": {"signal_types": ["tool.output"]},
        "enforcement_contract": {"on_fail": "block", "escalation": "notify", "evidence_signal": "guardian.tool_output_injection.detected"},
    },
    {
        "name": "cross_context_leakage_stub",
        "intent": "Detect cross-tenant or cross-session leakage indicators.",
        "detection_inputs": {"signal_types": ["context.rag", "response.text"]},
        "enforcement_contract": {"on_fail": "hold_for_approval", "escalation": "approval_required", "evidence_signal": "guardian.cross_context.detected"},
    },
]


SIM_TEMPLATES = [
    {
        "name": "Injection Stress Template",
        "category": "injection",
        "template_schema": {"fields": ["prompt", "context"]},
        "safe_boundary": {"requires_sandbox": True, "no_external_network": True, "max_runtime_seconds": 60},
    },
    {
        "name": "Leakage Control Template",
        "category": "leakage",
        "template_schema": {"fields": ["prompt", "expected_redaction"]},
        "safe_boundary": {"requires_sandbox": True, "no_external_network": True, "max_runtime_seconds": 60},
    },
    {
        "name": "Agent Identity Abuse Template",
        "category": "identity_abuse",
        "template_schema": {"fields": ["agent_action", "token_scopes"]},
        "safe_boundary": {"requires_sandbox": True, "no_external_network": True, "max_runtime_seconds": 60},
    },
    {
        "name": "RAG Poisoning Guard Template",
        "category": "rag_poisoning",
        "template_schema": {"fields": ["rag_context", "prompt"]},
        "safe_boundary": {"requires_sandbox": True, "no_external_network": True, "max_runtime_seconds": 60},
    },
    {
        "name": "Output Injection Template",
        "category": "output_injection",
        "template_schema": {"fields": ["tool_output", "prompt"]},
        "safe_boundary": {"requires_sandbox": True, "no_external_network": True, "max_runtime_seconds": 60},
    },
]


DOCS = [
    {
        "framework": "NIST-AI-RMF",
        "title": "Operationalized Governance for AI",
        "body": "Authored control intent summaries and control-to-evidence expectations for governance and monitoring.",
        "source_type": "authored",
    },
    {
        "framework": "ISO42001",
        "title": "AI Management System Control Intents",
        "body": "Authored operational requirements linking policy lifecycle, approvals, and corrective action evidence.",
        "source_type": "authored",
    },
    {
        "framework": "OWASP-AGENTIC",
        "title": "Agentic Security Control Playbook",
        "body": "Authored guardrail-focused controls for prompt safety, tool safety, and context isolation.",
        "source_type": "authored",
    },
]


def _get_or_create_framework(db, *, name: str, version: str, source_type: str) -> KBFramework:
    row = db.scalar(select(KBFramework).where(KBFramework.name == name, KBFramework.version == version))
    if row:
        return row
    row = KBFramework(name=name, version=version, source_type=source_type)
    db.add(row)
    db.flush()
    return row


def _upsert_control(db, *, framework_id: str, control_id: str, title: str, objective: str) -> None:
    row = db.scalar(select(KBControl).where(KBControl.id == control_id))
    payload = {
        "framework_id": framework_id,
        "title": title,
        "objective": objective,
        "requirement_level": "MUST",
        "applicability_tags": ["governance", "security", "operations"],
        "maturity_model": {
            "level_0": "ad_hoc",
            "level_3": "enforced",
            "level_5": "adaptive_and_verified",
        },
        "evidence_requirements": {
            "sources": ["audit_log", "evidence_graph", "enforcement_event", "simulation_run"],
            "freshness_sla_hours": 24,
        },
    }
    if row:
        for key, value in payload.items():
            setattr(row, key, value)
        return
    db.add(KBControl(id=control_id, **payload))


def _seed_threats(db) -> None:
    for threat_id, framework_ref, title, description_short in THREATS:
        row = db.scalar(select(KBThreat).where(KBThreat.id == threat_id))
        if row:
            row.framework_ref = framework_ref
            row.title = title
            row.description_short = description_short
            continue
        db.add(
            KBThreat(
                id=threat_id,
                framework_ref=framework_ref,
                title=title,
                description_short=description_short,
            )
        )


def _seed_guardians(db) -> list[KBGuardianContract]:
    rows: list[KBGuardianContract] = []
    for item in GUARDIANS:
        row = db.scalar(select(KBGuardianContract).where(KBGuardianContract.name == item["name"]))
        if row:
            row.intent = item["intent"]
            row.detection_inputs = item["detection_inputs"]
            row.enforcement_contract = item["enforcement_contract"]
        else:
            row = KBGuardianContract(
                name=item["name"],
                intent=item["intent"],
                detection_inputs=item["detection_inputs"],
                enforcement_contract=item["enforcement_contract"],
            )
            db.add(row)
            db.flush()
        rows.append(row)
    return rows


def _seed_sim_templates(db) -> list[KBSimulationTemplate]:
    rows: list[KBSimulationTemplate] = []
    for item in SIM_TEMPLATES:
        row = db.scalar(select(KBSimulationTemplate).where(KBSimulationTemplate.name == item["name"]))
        if row:
            row.category = item["category"]
            row.template_schema = item["template_schema"]
            row.safe_boundary = item["safe_boundary"]
        else:
            row = KBSimulationTemplate(
                name=item["name"],
                category=item["category"],
                template_schema=item["template_schema"],
                safe_boundary=item["safe_boundary"],
            )
            db.add(row)
            db.flush()
        rows.append(row)
    return rows


def _seed_docs(db, frameworks: dict[str, KBFramework]) -> None:
    for item in DOCS:
        framework = frameworks[item["framework"]]
        row = db.scalar(
            select(KBDoc).where(
                KBDoc.framework_id == framework.id,
                KBDoc.title == item["title"],
            )
        )
        if row:
            row.body = item["body"]
            row.source_type = item["source_type"]
            continue
        db.add(
            KBDoc(
                framework_id=framework.id,
                title=item["title"],
                body=item["body"],
                source_type=item["source_type"],
            )
        )


def _ensure_threat_control_mapping(db, *, threat_id: str, control_id: str, coverage: str, severity: str) -> None:
    row = db.scalar(
        select(KBThreatControlMap).where(
            KBThreatControlMap.threat_id == threat_id,
            KBThreatControlMap.control_id == control_id,
        )
    )
    if row:
        row.coverage = coverage
        row.severity = severity
        return
    db.add(
        KBThreatControlMap(
            threat_id=threat_id,
            control_id=control_id,
            coverage=coverage,
            severity=severity,
        )
    )


def _ensure_control_sim_mapping(db, *, control_id: str, sim_id: str, required_frequency: str) -> None:
    row = db.scalar(
        select(KBControlSimMap).where(
            KBControlSimMap.control_id == control_id,
            KBControlSimMap.simulation_template_id == sim_id,
        )
    )
    failure_impact = {
        "maturity_delta_on_fail": -0.1,
        "enforcement_strictness_increase": 1,
        "increase_simulation_frequency": True,
    }
    if row:
        row.required_frequency = required_frequency
        row.failure_impact = failure_impact
        return
    db.add(
        KBControlSimMap(
            control_id=control_id,
            simulation_template_id=sim_id,
            required_frequency=required_frequency,
            failure_impact=failure_impact,
        )
    )


def _ensure_control_guardian_mapping(db, *, control_id: str, guardian_id: str, strength: str) -> None:
    row = db.scalar(
        select(KBControlGuardianMap).where(
            KBControlGuardianMap.control_id == control_id,
            KBControlGuardianMap.guardian_contract_id == guardian_id,
        )
    )
    if row:
        row.enforcement_strength = strength
        return
    db.add(
        KBControlGuardianMap(
            control_id=control_id,
            guardian_contract_id=guardian_id,
            enforcement_strength=strength,
        )
    )


def _ensure_crosswalk(db, *, from_control_id: str, to_control_id: str, mapping_type: str, rationale: str) -> None:
    row = db.scalar(
        select(KBCrosswalk).where(
            KBCrosswalk.from_control_id == from_control_id,
            KBCrosswalk.to_control_id == to_control_id,
        )
    )
    if row:
        row.mapping_type = mapping_type
        row.rationale = rationale
        return
    db.add(
        KBCrosswalk(
            from_control_id=from_control_id,
            to_control_id=to_control_id,
            mapping_type=mapping_type,
            rationale=rationale,
        )
    )


def seed_kb() -> None:
    with SessionLocal() as db:
        frameworks: dict[str, KBFramework] = {}
        for item in FRAMEWORKS:
            framework = _get_or_create_framework(db, **item)
            frameworks[item["name"]] = framework

        for control_id, title, objective in NIST_CONTROLS:
            _upsert_control(db, framework_id=frameworks["NIST-AI-RMF"].id, control_id=control_id, title=title, objective=objective)
        for control_id, title, objective in ISO_CONTROLS:
            _upsert_control(db, framework_id=frameworks["ISO42001"].id, control_id=control_id, title=title, objective=objective)
        for control_id, title, objective in OWASP_CONTROLS:
            _upsert_control(db, framework_id=frameworks["OWASP-AGENTIC"].id, control_id=control_id, title=title, objective=objective)

        _seed_threats(db)
        guardians = _seed_guardians(db)
        sims = _seed_sim_templates(db)
        _seed_docs(db, frameworks)

        control_ids = [row[0] for row in NIST_CONTROLS[:8]] + [row[0] for row in ISO_CONTROLS[:8]] + [row[0] for row in OWASP_CONTROLS[:8]]
        threat_ids = [row[0] for row in THREATS]

        for index, control_id in enumerate(control_ids):
            threat_id = threat_ids[index % len(threat_ids)]
            coverage = ["prevent", "detect", "respond"][index % 3]
            severity = ["high", "critical", "med", "high"][index % 4]
            _ensure_threat_control_mapping(
                db,
                threat_id=threat_id,
                control_id=control_id,
                coverage=coverage,
                severity=severity,
            )

            sim = sims[index % len(sims)]
            frequency = ["daily", "weekly", "monthly", "on_change"][index % 4]
            _ensure_control_sim_mapping(
                db,
                control_id=control_id,
                sim_id=sim.id,
                required_frequency=frequency,
            )

            guardian = guardians[index % len(guardians)]
            strength = ["baseline", "strict", "maximum"][index % 3]
            _ensure_control_guardian_mapping(
                db,
                control_id=control_id,
                guardian_id=guardian.id,
                strength=strength,
            )

        crosswalk_pairs = [
            ("NIST-AI-RMF.MAP-3", "ISO42001.7.2", "equivalent", "Both require robust auditability and traceability."),
            ("NIST-AI-RMF.MANAGE-1", "OWASP-AGENTIC.A09", "supports", "Adaptive enforcement strengthens fail-closed behavior."),
            ("ISO42001.8.2", "OWASP-AGENTIC.A08", "partial", "Both establish human approval boundaries for high-risk actions."),
            ("OWASP-AGENTIC.A01", "NIST-AI-RMF.MAP-2", "supports", "Prompt attack patterns feed threat scenario mapping."),
        ]
        for from_control_id, to_control_id, mapping_type, rationale in crosswalk_pairs:
            _ensure_crosswalk(
                db,
                from_control_id=from_control_id,
                to_control_id=to_control_id,
                mapping_type=mapping_type,
                rationale=rationale,
            )

        db.commit()

    print("KB seed complete: frameworks=3 controls=30 threats=10 guardians=5 sim_templates=5 mappings>=20")


if __name__ == "__main__":
    seed_kb()
