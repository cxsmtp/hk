from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.simulation import Control, SimulationDefinition, SimulationRun
from app.services.crq_service import aggregate_financials, compute_control_crq_profile, compute_simulation_crq
from app.services.hmair.governance_contracts import AcceptedGovernanceClaim
from app.services.hmair.governance_projection_service import (
    project_accepted_claim_relationships,
)


def _uniq(items: list[str]) -> list[str]:
    return sorted({str(item).strip() for item in items if str(item).strip()})


def _discovery_coverage_state_map(projection: Any) -> dict[tuple[str, str], str]:
    states: dict[tuple[str, str], str] = {}
    for dimension_name, dimension in projection.dimensions.items():
        for asset_id in dimension.covered_asset_ids:
            states[(str(asset_id), str(dimension_name))] = "covered"
        for asset_id in dimension.not_covered_asset_ids:
            states[(str(asset_id), str(dimension_name))] = "not_covered"
        for asset_id in dimension.unknown_asset_ids:
            states[(str(asset_id), str(dimension_name))] = "unknown"
    return states


def project_discovery_coverage_relationships(projection: Any) -> list[dict[str, Any]]:
    """Project current discovery truth without turning it into authorization."""

    states = _discovery_coverage_state_map(projection)
    output: list[dict[str, Any]] = []
    for (asset_id, dimension_name), state in sorted(states.items()):
        dimension = projection.dimensions[dimension_name]
        output.append(
            {
                "tenant_id": projection.tenant_id,
                "from_type": "ai_asset",
                "from_ref": asset_id,
                "relationship_type": "discovery_coverage_state",
                "to_type": "coverage_dimension",
                "to_ref": dimension_name,
                "dimension": dimension_name,
                "coverage_state": state,
                "evidence_refs": list(dimension.evidence_refs),
                "methodology_version": projection.methodology_version,
                "authorization_effect": "none",
            }
        )
    return output


def discovery_coverage_change_events(
    previous: Any,
    current: Any,
) -> list[dict[str, Any]]:
    """Return deterministic, evidence-bound state changes for an operator job.

    Persistence is intentionally left to the existing audited job boundary; a
    read API must never create events as a side effect.
    """

    if previous.tenant_id != current.tenant_id:
        raise ValueError("coverage projections must belong to the same tenant")
    before = _discovery_coverage_state_map(previous)
    after = _discovery_coverage_state_map(current)
    events: list[dict[str, Any]] = []
    for asset_dimension in sorted(set(before) | set(after)):
        old_state = before.get(asset_dimension)
        new_state = after.get(asset_dimension)
        if old_state == new_state:
            continue
        asset_id, dimension_name = asset_dimension
        dimension = current.dimensions.get(dimension_name)
        events.append(
            {
                "tenant_id": current.tenant_id,
                "asset_id": asset_id,
                "dimension": dimension_name,
                "previous_state": old_state,
                "current_state": new_state,
                "evidence_refs": list(dimension.evidence_refs) if dimension else [],
                "methodology_version": current.methodology_version,
                "observed_at": current.generated_at.isoformat(),
                "authorization_effect": "none",
            }
        )
    return events


def project_h5_governance_relationships(
    *,
    tenant_id: str,
    claims: tuple[AcceptedGovernanceClaim, ...],
) -> list[dict[str, Any]]:
    """Expose accepted H5 claims through the existing Control Graph service."""

    return [
        relationship.model_dump(mode="json")
        for relationship in project_accepted_claim_relationships(
            tenant_id=tenant_id,
            claims=claims,
        )
    ]


def _framework_key(value: str) -> str:
    token = str(value or "").strip().upper().replace("/", "_")
    token = "_".join(part for part in token.replace("-", "_").replace(" ", "_").split("_") if part)
    return token


def _framework_ref(
    framework: str,
    domain: str,
    subdomain_or_reference: str,
    reference_or_description: str,
    description: str | None = None,
) -> dict[str, str]:
    if description is None:
        subdomain = ""
        reference_id = str(subdomain_or_reference or "").strip()
        resolved_description = str(reference_or_description or "").strip()
    else:
        subdomain = str(subdomain_or_reference or "").strip()
        reference_id = str(reference_or_description or "").strip()
        resolved_description = str(description or "").strip()

    return {
        "framework": framework,
        "framework_key": _framework_key(framework),
        "domain": domain,
        "subdomain": subdomain,
        "reference_id": reference_id,
        "description": resolved_description,
    }


FRAMEWORK_CATALOG: list[dict[str, str]] = [
    {"framework": "NIST AI RMF", "framework_key": "NIST_AI_RMF", "domain": "Govern/Map/Measure/Manage"},
    {"framework": "ISO/IEC 42001", "framework_key": "ISO_42001", "domain": "AI Management Lifecycle"},
    {"framework": "EU AI Act", "framework_key": "EU_AI_ACT", "domain": "Risk, Transparency, Governance"},
    {"framework": "MITRE ATLAS", "framework_key": "MITRE_ATLAS", "domain": "Adversarial Tactics and Techniques"},
    {"framework": "OWASP GenAI Top 10", "framework_key": "OWASP_GENAI_TOP_10", "domain": "GenAI Risks"},
    {"framework": "OWASP LLM Top 10", "framework_key": "OWASP_LLM_TOP_10", "domain": "LLM Application Risks"},
    {"framework": "OWASP Agentic Top 10", "framework_key": "OWASP_AGENTIC_TOP_10", "domain": "Agentic Risks"},
    {
        "framework": "Microsoft Responsible AI Standard",
        "framework_key": "MICROSOFT_RESPONSIBLE_AI_STANDARD",
        "domain": "Responsible AI Controls",
    },
    {"framework": "Google SAIF", "framework_key": "GOOGLE_SAIF", "domain": "Secure AI Lifecycle"},
    {"framework": "CSA AI Controls", "framework_key": "CSA_AI_CONTROLS", "domain": "Cloud AI Security Controls"},
]


LEGACY_CONTROL_ALIASES: dict[str, str] = {
    "CTRL-INPUT-001": "PROMPT_INJECTION_DETECTION",
    "CTRL-PI-001": "PROMPT_INJECTION_DETECTION",
    "CTRL-INPUT-002": "JAILBREAK_DETECTION",
    "CTRL-DLP-001": "PII_EXFILTRATION_PREVENTION",
    "CTRL-TOOL-001": "TOOL_CALL_VALIDATION",
    "CTRL-AI-IAM-001": "AGENT_ACTION_AUTHORIZATION",
    "CTRL-RAG-001": "RAG_POISONING_DETECTION",
    "CTRL-OUTPUT-001": "MODEL_OUTPUT_VALIDATION",
    "CTRL-TENANT-ISO-001": "POLICY_ENFORCEMENT_CONTROL",
    "OCR_BASED_EXTRACTION_CONTROL": "OCR_DATA_EXTRACTION_CONTROL",
}


TOP20_CONTROL_IDS: tuple[str, ...] = (
    "PROMPT_INJECTION_DETECTION",
    "JAILBREAK_DETECTION",
    "SENSITIVE_DATA_DETECTION",
    "PII_EXFILTRATION_PREVENTION",
    "FILE_UPLOAD_INSPECTION",
    "OCR_DATA_EXTRACTION_CONTROL",
    "RAG_POISONING_DETECTION",
    "MODEL_OUTPUT_VALIDATION",
    "MODEL_ACCESS_CONTROL",
    "SHADOW_AI_DETECTION",
    "AI_SYSTEM_INVENTORY_CONTROL",
    "AI_IDENTITY_BINDING",
    "NON_HUMAN_IDENTITY_CONTROL",
    "TOKEN_SCOPE_ENFORCEMENT",
    "PRIVILEGE_DRIFT_DETECTION",
    "TOOL_CALL_VALIDATION",
    "AGENT_ACTION_AUTHORIZATION",
    "CHAIN_OF_ACTION_VALIDATION",
    "CONTEXT_LEAKAGE_DETECTION",
    "POLICY_ENFORCEMENT_CONTROL",
)


CANONICAL_CONTROLS: list[dict[str, Any]] = [
    {
        "control_id": "AI_IDENTITY_BINDING",
        "control_name": "AI Identity Binding",
        "category": "identity",
        "description": "Bind every AI action to a verified user/agent identity with tenant context.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Govern", "Accountability", "GV-2", "Identity accountability for AI actions."),
            _framework_ref("ISO/IEC 42001", "A.6", "Roles", "A.6.2", "Define accountable AI responsibilities."),
            _framework_ref("EU AI Act", "Governance", "Provider obligations", "Art.17", "Assign ownership and accountability."),
            _framework_ref("Microsoft Responsible AI Standard", "Govern", "Accountability", "MSRAI-GOV-01", "Traceability to accountable owner."),
            _framework_ref("CSA AI Controls", "Identity", "Access", "CSA-AI-IA-01", "Identity linkage for AI actions."),
        ],
        "risk_tags": ["identity_abuse", "impersonation", "tenant_boundary"],
        "severity": "high",
        "enforcement_points": ["gateway", "runtime", "connector"],
        "detection_methods": ["policy_rule", "behavioral"],
        "response_actions": ["step_up_auth", "alert", "quarantine"],
        "evidence_types": ["runtime_event", "audit_log", "policy_decision"],
        "remediation_templates": ["tighten_identity_binding", "require_owner_attestation"],
    },
    {
        "control_id": "NON_HUMAN_IDENTITY_CONTROL",
        "control_name": "Non-human Identity Control",
        "category": "identity",
        "description": "Validate non-human agent identities and token provenance for every action.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Govern", "Risk Controls", "GV-4", "Manage identity risks in AI operations."),
            _framework_ref("ISO/IEC 42001", "A.8", "Operations", "A.8.4", "Control automated AI operations."),
            _framework_ref("OWASP Agentic Top 10", "Identity", "Agent Identity", "AGENT01", "Control autonomous identity abuse."),
            _framework_ref("Google SAIF", "Protect", "Identity", "SAIF-P2", "Verify service identity for AI systems."),
            _framework_ref("CSA AI Controls", "Identity", "Machine Identity", "CSA-AI-IA-02", "Control non-human credentials."),
        ],
        "risk_tags": ["agent_abuse", "token_sprawl", "identity_abuse"],
        "severity": "high",
        "enforcement_points": ["gateway", "runtime", "simulation"],
        "detection_methods": ["policy_rule", "pattern"],
        "response_actions": ["block", "step_up_auth", "quarantine"],
        "evidence_types": ["runtime_event", "audit_log"],
        "remediation_templates": ["rotate_agent_tokens", "suspend_agent_identity"],
    },
    {
        "control_id": "TOKEN_SCOPE_ENFORCEMENT",
        "control_name": "Token Scope Enforcement",
        "category": "identity",
        "description": "Enforce scoped capability tokens for tool/API operations.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Manage", "Operational Controls", "MG-2", "Enforce operational least privilege."),
            _framework_ref("ISO/IEC 42001", "A.9", "Access Control", "A.9.1", "Enforce scoped access."),
            _framework_ref("OWASP Agentic Top 10", "Authorization", "Scope", "AGENT03", "Restrict tool scope."),
            _framework_ref("Google SAIF", "Protect", "Authorization", "SAIF-P3", "Scope actions to approved permissions."),
            _framework_ref("CSA AI Controls", "Access", "Least Privilege", "CSA-AI-AC-01", "Limit permissions and scope."),
        ],
        "risk_tags": ["privilege_drift", "tool_misuse", "unauthorized_action"],
        "severity": "high",
        "enforcement_points": ["gateway", "runtime", "simulation"],
        "detection_methods": ["policy_rule", "behavioral"],
        "response_actions": ["block", "modify", "alert"],
        "evidence_types": ["runtime_event", "policy_decision", "audit_log"],
        "remediation_templates": ["reduce_token_scope", "enforce_allowlist"],
    },
    {
        "control_id": "PRIVILEGE_DRIFT_DETECTION",
        "control_name": "Privilege Drift Detection",
        "category": "identity",
        "description": "Detect drift from baseline privilege and capability posture.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Measure", "Monitoring", "ME-2", "Monitor control effectiveness and drift."),
            _framework_ref("ISO/IEC 42001", "A.12", "Monitoring", "A.12.3", "Continuous monitoring of AI controls."),
            _framework_ref("MITRE ATLAS", "Privilege Escalation", "Agent Abuse", "AML.TA0004", "Detect escalation behavior."),
            _framework_ref("OWASP Agentic Top 10", "Authorization", "Drift", "AGENT05", "Detect drift in agent privileges."),
            _framework_ref("CSA AI Controls", "Monitoring", "Identity Drift", "CSA-AI-MN-02", "Track privilege drift events."),
        ],
        "risk_tags": ["privilege_drift", "identity_abuse"],
        "severity": "high",
        "enforcement_points": ["runtime", "simulation", "connector"],
        "detection_methods": ["behavioral", "pattern"],
        "response_actions": ["alert", "step_up_auth", "quarantine"],
        "evidence_types": ["runtime_event", "simulation_result", "audit_log"],
        "remediation_templates": ["reduce_capabilities", "require_reapproval"],
    },
    {
        "control_id": "SENSITIVE_DATA_DETECTION",
        "control_name": "Sensitive Data Detection",
        "category": "data",
        "description": "Detect sensitive entities in prompts, responses, uploads, and copied content.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Map", "Data Risks", "MP-2", "Identify sensitive data exposure risks."),
            _framework_ref("ISO/IEC 42001", "A.7", "Data Governance", "A.7.1", "Classify and detect sensitive data."),
            _framework_ref("EU AI Act", "Data Governance", "High-risk data", "Art.10", "Data governance and quality controls."),
            _framework_ref("OWASP GenAI Top 10", "Sensitive Information Disclosure", "GENAI06", "Detect sensitive leakage."),
            _framework_ref("CSA AI Controls", "Data", "Classification", "CSA-AI-DATA-01", "Sensitive data classification and detection."),
        ],
        "risk_tags": ["sensitive_data", "pii_exposure", "data_exfiltration"],
        "severity": "high",
        "enforcement_points": ["browser_extension", "gateway", "runtime", "simulation"],
        "detection_methods": ["regex", "pattern", "ml_model", "policy_rule"],
        "response_actions": ["block", "warn", "modify", "alert"],
        "evidence_types": ["runtime_event", "simulation_result", "policy_decision", "audit_log"],
        "remediation_templates": ["tighten_data_policy", "require_justification"],
    },
    {
        "control_id": "PII_EXFILTRATION_PREVENTION",
        "control_name": "PII Exfiltration Prevention",
        "category": "data",
        "description": "Prevent outbound PII/sensitive data transfer to untrusted systems.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Manage", "Safeguards", "MG-4", "Implement safeguards against data exfiltration."),
            _framework_ref("ISO/IEC 42001", "A.8", "Operations", "A.8.6", "Prevent unauthorized data transfer."),
            _framework_ref("EU AI Act", "Risk Management", "Post-market monitoring", "Art.9", "Mitigate high-risk adverse outcomes."),
            _framework_ref("OWASP LLM Top 10", "Sensitive Information Disclosure", "LLM06", "Prevent private data leakage."),
            _framework_ref("Google SAIF", "Protect", "Data Protection", "SAIF-P4", "Prevent exfiltration to untrusted targets."),
        ],
        "risk_tags": ["data_exfiltration", "pii_exposure"],
        "severity": "critical",
        "enforcement_points": ["browser_extension", "gateway", "runtime", "connector", "simulation"],
        "detection_methods": ["regex", "pattern", "behavioral", "policy_rule"],
        "response_actions": ["block", "modify", "step_up_auth", "alert", "quarantine"],
        "evidence_types": ["runtime_event", "policy_decision", "audit_log", "simulation_result"],
        "remediation_templates": ["restrict_external_destinations", "escalate_policy_strictness"],
    },
    {
        "control_id": "FILE_UPLOAD_INSPECTION",
        "control_name": "File Upload Inspection",
        "category": "data",
        "description": "Inspect uploaded files before transfer to external or AI destinations.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Measure", "Controls Testing", "ME-1", "Test data handling safeguards."),
            _framework_ref("ISO/IEC 42001", "A.8", "Operations", "A.8.7", "Control upload and transfer channels."),
            _framework_ref("OWASP GenAI Top 10", "Data Leakage", "GENAI05", "Guard risky file uploads."),
            _framework_ref("OWASP LLM Top 10", "Supply Chain", "LLM05", "Inspect input artifacts."),
            _framework_ref("CSA AI Controls", "Data", "Transfer", "CSA-AI-DATA-03", "Upload channel safeguards."),
        ],
        "risk_tags": ["file_exfiltration", "sensitive_upload"],
        "severity": "high",
        "enforcement_points": ["browser_extension", "gateway", "simulation"],
        "detection_methods": ["regex", "pattern", "ml_model", "policy_rule"],
        "response_actions": ["block", "warn", "quarantine", "alert"],
        "evidence_types": ["runtime_event", "policy_decision", "audit_log"],
        "remediation_templates": ["quarantine_source", "tighten_upload_controls"],
    },
    {
        "control_id": "OCR_DATA_EXTRACTION_CONTROL",
        "control_name": "OCR-based Extraction Control",
        "category": "data",
        "description": "Run OCR extraction on image/PDF content and enforce policies on extracted entities.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Map", "Data Risks", "MP-3", "Assess hidden sensitive content risk."),
            _framework_ref("ISO/IEC 42001", "A.7", "Data Governance", "A.7.4", "Validate data extraction controls."),
            _framework_ref("OWASP GenAI Top 10", "Prompt Injection", "GENAI01", "Detect hidden payloads in assets."),
            _framework_ref("Google SAIF", "Secure-by-Design", "Input Handling", "SAIF-S1", "Handle hidden data safely."),
            _framework_ref("CSA AI Controls", "Data", "Inspection", "CSA-AI-DATA-04", "Extract and classify embedded data."),
        ],
        "risk_tags": ["ocr_sensitive_data", "hidden_payload"],
        "severity": "high",
        "enforcement_points": ["browser_extension", "gateway", "simulation"],
        "detection_methods": ["ml_model", "regex", "pattern"],
        "response_actions": ["block", "warn", "alert"],
        "evidence_types": ["runtime_event", "policy_decision", "simulation_result"],
        "remediation_templates": ["enable_ocr_inspection", "block_sensitive_upload"],
    },
    {
        "control_id": "MODEL_INTEGRITY_CHECK",
        "control_name": "Model Integrity Check",
        "category": "model",
        "description": "Validate model integrity posture and detect tampering or unsafe model states.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Manage", "Model Governance", "MG-5", "Monitor model integrity and trust."),
            _framework_ref("ISO/IEC 42001", "A.8", "Model Ops", "A.8.10", "Integrity checks for model artifacts."),
            _framework_ref("MITRE ATLAS", "Model Tampering", "Integrity", "AML.TA0001", "Detect model integrity compromise."),
            _framework_ref("Google SAIF", "Protect", "Model Integrity", "SAIF-P6", "Secure model assets and outputs."),
            _framework_ref("CSA AI Controls", "Model", "Integrity", "CSA-AI-MODEL-01", "Model artifact integrity controls."),
        ],
        "risk_tags": ["model_integrity", "model_tampering"],
        "severity": "critical",
        "enforcement_points": ["gateway", "runtime", "simulation"],
        "detection_methods": ["pattern", "behavioral", "policy_rule"],
        "response_actions": ["block", "quarantine", "alert"],
        "evidence_types": ["runtime_event", "audit_log", "simulation_result"],
        "remediation_templates": ["block_model", "rollback_model_version"],
    },
    {
        "control_id": "MODEL_ACCESS_CONTROL",
        "control_name": "Model Access Control",
        "category": "model",
        "description": "Enforce sanctioned model/provider access and prevent unauthorized invocation.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Govern", "Policy Controls", "GV-3", "Define model access governance."),
            _framework_ref("ISO/IEC 42001", "A.9", "Access", "A.9.3", "Restrict access to approved AI systems."),
            _framework_ref("EU AI Act", "Governance", "Risk controls", "Art.14", "Apply human oversight and controls."),
            _framework_ref("OWASP LLM Top 10", "Supply Chain", "LLM05", "Restrict untrusted model dependencies."),
            _framework_ref("CSA AI Controls", "Access", "Model Access", "CSA-AI-AC-03", "Model/provider allowlist control."),
        ],
        "risk_tags": ["unsanctioned_model_access", "shadow_ai"],
        "severity": "high",
        "enforcement_points": ["gateway", "runtime", "connector", "simulation"],
        "detection_methods": ["policy_rule", "behavioral"],
        "response_actions": ["block", "warn", "alert"],
        "evidence_types": ["runtime_event", "policy_decision", "audit_log"],
        "remediation_templates": ["restrict_model_access", "route_to_governance"],
    },
    {
        "control_id": "RAG_POISONING_DETECTION",
        "control_name": "RAG Poisoning Detection",
        "category": "model",
        "description": "Detect retrieval poisoning and manipulated grounding content.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Measure", "Robustness", "ME-4", "Assess robustness against poisoning."),
            _framework_ref("ISO/IEC 42001", "A.8", "Data/Model Ops", "A.8.11", "Controls for retrieval integrity."),
            _framework_ref("MITRE ATLAS", "Poisoning", "Knowledge Attack", "AML.TA0002", "Detect poisoning paths."),
            _framework_ref("OWASP GenAI Top 10", "RAG Risks", "GENAI08", "RAG poisoning safeguards."),
            _framework_ref("Google SAIF", "Detect", "Threat Detection", "SAIF-D2", "Detect poisoning activity."),
        ],
        "risk_tags": ["rag_poisoning", "model_poisoning"],
        "severity": "high",
        "enforcement_points": ["gateway", "runtime", "simulation"],
        "detection_methods": ["pattern", "behavioral", "ml_model"],
        "response_actions": ["block", "modify", "alert", "quarantine"],
        "evidence_types": ["runtime_event", "simulation_result", "audit_log"],
        "remediation_templates": ["quarantine_knowledge_source", "revalidate_index"],
    },
    {
        "control_id": "MODEL_OUTPUT_VALIDATION",
        "control_name": "Model Output Validation",
        "category": "model",
        "description": "Validate model outputs for policy, safety, and leakage violations.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Manage", "Output Controls", "MG-3", "Govern model outputs and side effects."),
            _framework_ref("ISO/IEC 42001", "A.8", "Output Controls", "A.8.12", "Validate model responses before release."),
            _framework_ref("EU AI Act", "Transparency", "Output transparency", "Art.13", "Transparent and safe outputs."),
            _framework_ref("OWASP LLM Top 10", "Output Handling", "LLM02", "Validate and constrain outputs."),
            _framework_ref("Microsoft Responsible AI Standard", "Safety", "Output Safety", "MSRAI-SAFE-02", "Output safety and reliability."),
        ],
        "risk_tags": ["unsafe_output", "context_leakage", "policy_violation"],
        "severity": "high",
        "enforcement_points": ["gateway", "runtime", "simulation"],
        "detection_methods": ["pattern", "policy_rule", "ml_model"],
        "response_actions": ["modify", "block", "warn", "alert"],
        "evidence_types": ["runtime_event", "policy_decision", "audit_log"],
        "remediation_templates": ["tighten_output_filters", "add_post_call_guard"],
    },
    {
        "control_id": "PROMPT_INJECTION_DETECTION",
        "control_name": "Prompt Injection Detection",
        "category": "interaction",
        "description": "Detect prompt injection payloads and adversarial override attempts.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Manage", "Abuse Protection", "MG-1", "Mitigate abuse and adversarial inputs."),
            _framework_ref("ISO/IEC 42001", "A.8", "Input Controls", "A.8.5", "Validate malicious prompt input."),
            _framework_ref("MITRE ATLAS", "Prompt Injection", "Input Manipulation", "AML.TA0003", "Detect adversarial prompt injection."),
            _framework_ref("OWASP LLM Top 10", "Prompt Injection", "LLM01", "Defend against prompt injection."),
            _framework_ref("Google SAIF", "Defend", "Prompt Security", "SAIF-DF1", "Prompt injection defenses."),
        ],
        "risk_tags": ["prompt_injection", "jailbreak"],
        "severity": "critical",
        "enforcement_points": ["browser_extension", "gateway", "runtime", "simulation"],
        "detection_methods": ["regex", "pattern", "ml_model", "policy_rule"],
        "response_actions": ["block", "modify", "warn", "alert"],
        "evidence_types": ["runtime_event", "policy_decision", "simulation_result", "audit_log"],
        "remediation_templates": ["tighten_prompt_guard", "increase_simulation_frequency"],
    },
    {
        "control_id": "JAILBREAK_DETECTION",
        "control_name": "Jailbreak Detection",
        "category": "interaction",
        "description": "Detect jailbreak prompts targeting bypass of model and policy boundaries.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Manage", "Abuse Protection", "MG-1", "Prevent model abuse through jailbreaks."),
            _framework_ref("ISO/IEC 42001", "A.8", "Abuse Controls", "A.8.9", "Detect and stop jailbreak attempts."),
            _framework_ref("MITRE ATLAS", "Evasion", "Guardrail Bypass", "AML.TA0005", "Detect guardrail bypass tactics."),
            _framework_ref("OWASP LLM Top 10", "Insecure Output", "LLM02", "Jailbreak and output evasion control."),
            _framework_ref("OWASP GenAI Top 10", "Model Abuse", "GENAI02", "Jailbreak prevention controls."),
        ],
        "risk_tags": ["jailbreak", "policy_bypass"],
        "severity": "high",
        "enforcement_points": ["browser_extension", "gateway", "runtime", "simulation"],
        "detection_methods": ["pattern", "ml_model", "policy_rule"],
        "response_actions": ["block", "warn", "alert"],
        "evidence_types": ["runtime_event", "policy_decision", "simulation_result"],
        "remediation_templates": ["harden_system_prompts", "tighten_jailbreak_rules"],
    },
    {
        "control_id": "TOOL_MISUSE_PREVENTION",
        "control_name": "Tool Misuse Prevention",
        "category": "interaction",
        "description": "Detect and prevent unsafe or out-of-scope tool usage in AI workflows.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Manage", "Operational Safeguards", "MG-2", "Control tool and action risks."),
            _framework_ref("ISO/IEC 42001", "A.9", "Authorization", "A.9.5", "Restrict high-risk tool use."),
            _framework_ref("MITRE ATLAS", "Execution", "Tool Abuse", "AML.TA0006", "Detect unauthorized tool actions."),
            _framework_ref("OWASP Agentic Top 10", "Tool Safety", "AGENT02", "Tool misuse controls."),
            _framework_ref("CSA AI Controls", "Operations", "Tooling", "CSA-AI-OPS-02", "Control tool usage paths."),
        ],
        "risk_tags": ["tool_misuse", "unauthorized_action"],
        "severity": "high",
        "enforcement_points": ["gateway", "runtime", "simulation"],
        "detection_methods": ["policy_rule", "behavioral", "pattern"],
        "response_actions": ["block", "modify", "alert", "step_up_auth"],
        "evidence_types": ["runtime_event", "audit_log", "policy_decision"],
        "remediation_templates": ["reduce_tool_permissions", "disable_high_risk_tool"],
    },
    {
        "control_id": "CONTEXT_LEAKAGE_DETECTION",
        "control_name": "Context Leakage Detection",
        "category": "interaction",
        "description": "Detect leakage of private context/memory/system instructions across boundaries.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Measure", "Privacy/Security", "ME-3", "Measure leakage and privacy exposure."),
            _framework_ref("ISO/IEC 42001", "A.7", "Data Privacy", "A.7.5", "Prevent context and memory leakage."),
            _framework_ref("EU AI Act", "Transparency", "User information", "Art.13", "Prevent misleading unsafe outputs."),
            _framework_ref("OWASP LLM Top 10", "Sensitive Disclosure", "LLM06", "Context and memory leakage risk."),
            _framework_ref("Microsoft Responsible AI Standard", "Privacy", "Data handling", "MSRAI-PRIV-01", "Protect confidential context."),
        ],
        "risk_tags": ["context_leakage", "data_exfiltration"],
        "severity": "high",
        "enforcement_points": ["gateway", "runtime", "simulation"],
        "detection_methods": ["pattern", "ml_model", "policy_rule"],
        "response_actions": ["modify", "block", "alert"],
        "evidence_types": ["runtime_event", "policy_decision", "simulation_result"],
        "remediation_templates": ["tighten_context_boundary", "reduce_prompt_context"],
    },
    {
        "control_id": "AGENT_ACTION_AUTHORIZATION",
        "control_name": "Agent Action Authorization",
        "category": "agent",
        "description": "Authorize every agent action against identity, scope, and policy.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Govern", "Authorization", "GV-5", "Agent action authorization controls."),
            _framework_ref("ISO/IEC 42001", "A.9", "Authorization", "A.9.6", "Action-level authorization checks."),
            _framework_ref("OWASP Agentic Top 10", "Authorization", "AGENT04", "Authorize each delegated step."),
            _framework_ref("MITRE ATLAS", "Execution", "Agent Abuse", "AML.TA0007", "Detect unauthorized agent actions."),
            _framework_ref("CSA AI Controls", "Agent", "Authorization", "CSA-AI-AGENT-01", "Control agent actions."),
        ],
        "risk_tags": ["agent_abuse", "unauthorized_action", "delegation_misuse"],
        "severity": "critical",
        "enforcement_points": ["gateway", "runtime", "simulation"],
        "detection_methods": ["policy_rule", "behavioral"],
        "response_actions": ["block", "step_up_auth", "quarantine", "alert"],
        "evidence_types": ["runtime_event", "policy_decision", "audit_log"],
        "remediation_templates": ["suspend_agent", "revoke_tokens"],
    },
    {
        "control_id": "TOOL_CALL_VALIDATION",
        "control_name": "Tool Call Validation",
        "category": "agent",
        "description": "Validate tool calls, arguments, and destination constraints before execution.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Manage", "Operational Safeguards", "MG-2", "Validate tool operations."),
            _framework_ref("ISO/IEC 42001", "A.8", "Operational Controls", "A.8.13", "Validate execution arguments and endpoints."),
            _framework_ref("OWASP Agentic Top 10", "Tool Safety", "AGENT02", "Tool call validation controls."),
            _framework_ref("MITRE ATLAS", "Command and Control", "Tool Abuse", "AML.TA0006", "Guard unsafe tool calls."),
            _framework_ref("Google SAIF", "Protect", "Execution Control", "SAIF-P5", "Validate execution path safety."),
        ],
        "risk_tags": ["tool_misuse", "unauthorized_action", "api_exfiltration"],
        "severity": "high",
        "enforcement_points": ["gateway", "runtime", "simulation"],
        "detection_methods": ["policy_rule", "pattern", "behavioral"],
        "response_actions": ["block", "modify", "warn", "alert"],
        "evidence_types": ["runtime_event", "policy_decision", "audit_log"],
        "remediation_templates": ["restrict_tool_allowlist", "validate_tool_arguments"],
    },
    {
        "control_id": "CHAIN_OF_ACTION_VALIDATION",
        "control_name": "Chain-of-Action Validation",
        "category": "agent",
        "description": "Validate multi-step chains for safe sequencing and depth limits.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Measure", "Behavioral Monitoring", "ME-5", "Validate multi-step autonomous behavior."),
            _framework_ref("ISO/IEC 42001", "A.12", "Monitoring", "A.12.4", "Monitor chain-of-action anomalies."),
            _framework_ref("OWASP Agentic Top 10", "Autonomy Control", "AGENT06", "Limit unsafe autonomous chains."),
            _framework_ref("MITRE ATLAS", "Persistence", "Action Chaining", "AML.TA0008", "Detect chained attack flows."),
            _framework_ref("CSA AI Controls", "Agent", "Chain Control", "CSA-AI-AGENT-02", "Chain depth and sequence control."),
        ],
        "risk_tags": ["chain_abuse", "agent_abuse", "multi_step_attack"],
        "severity": "high",
        "enforcement_points": ["gateway", "runtime", "simulation"],
        "detection_methods": ["behavioral", "pattern", "policy_rule"],
        "response_actions": ["block", "step_up_auth", "alert"],
        "evidence_types": ["runtime_event", "simulation_result", "audit_log"],
        "remediation_templates": ["reduce_chain_depth", "require_manual_approval"],
    },
    {
        "control_id": "CROSS_AGENT_BOUNDARY_CONTROL",
        "control_name": "Cross-agent Boundary Control",
        "category": "agent",
        "description": "Enforce safe delegation boundaries across agents and tool scopes.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Govern", "Boundary Controls", "GV-6", "Control cross-agent boundaries."),
            _framework_ref("ISO/IEC 42001", "A.9", "Segregation", "A.9.7", "Segregate responsibilities and delegation."),
            _framework_ref("OWASP Agentic Top 10", "Delegation", "AGENT07", "Protect delegation boundaries."),
            _framework_ref("MITRE ATLAS", "Lateral Movement", "Delegation Abuse", "AML.TA0009", "Detect cross-agent lateral abuse."),
            _framework_ref("CSA AI Controls", "Agent", "Boundary", "CSA-AI-AGENT-03", "Boundary and delegation safeguards."),
        ],
        "risk_tags": ["delegation_misuse", "cross_agent_abuse"],
        "severity": "high",
        "enforcement_points": ["gateway", "runtime", "simulation"],
        "detection_methods": ["policy_rule", "behavioral"],
        "response_actions": ["block", "alert", "quarantine"],
        "evidence_types": ["runtime_event", "audit_log", "policy_decision"],
        "remediation_templates": ["revoke_delegation", "enforce_boundary_policy"],
    },
    {
        "control_id": "AI_SYSTEM_INVENTORY_CONTROL",
        "control_name": "AI System Inventory Control",
        "category": "governance",
        "description": "Maintain authoritative inventory of sanctioned AI systems in Trust Center.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Govern", "Inventory", "GV-1", "Establish AI inventory and accountability."),
            _framework_ref("ISO/IEC 42001", "A.5", "Governance", "A.5.1", "Maintain AI system inventory."),
            _framework_ref("EU AI Act", "Risk Classification", "System registry", "Art.51", "Maintain registered AI systems."),
            _framework_ref("Microsoft Responsible AI Standard", "Govern", "System Registry", "MSRAI-GOV-02", "Track deployed AI systems."),
            _framework_ref("CSA AI Controls", "Governance", "Inventory", "CSA-AI-GOV-01", "AI system inventory lifecycle."),
        ],
        "risk_tags": ["unknown_ai", "governance_gap"],
        "severity": "critical",
        "enforcement_points": ["runtime", "connector", "simulation"],
        "detection_methods": ["policy_rule", "behavioral"],
        "response_actions": ["block", "alert", "quarantine"],
        "evidence_types": ["runtime_event", "audit_log", "policy_decision", "simulation_result"],
        "remediation_templates": ["register_ai_system", "require_owner_assignment"],
    },
    {
        "control_id": "SHADOW_AI_DETECTION",
        "control_name": "Shadow AI Detection",
        "category": "governance",
        "description": "Detect unknown AI use and route to governed lifecycle and review.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Map", "Context", "MP-1", "Map actual AI usage context."),
            _framework_ref("ISO/IEC 42001", "A.12", "Monitoring", "A.12.5", "Detect unsanctioned AI usage."),
            _framework_ref("EU AI Act", "Risk Management", "Unknown systems", "Art.9", "Identify unmanaged risk sources."),
            _framework_ref("OWASP GenAI Top 10", "Governance", "GENAI10", "Govern shadow AI usage."),
            _framework_ref("Google SAIF", "Detect", "Unknown Exposure", "SAIF-D3", "Detect unknown model/tool exposure."),
        ],
        "risk_tags": ["shadow_ai", "unknown_ai", "governance_gap"],
        "severity": "high",
        "enforcement_points": ["browser_extension", "runtime", "connector", "simulation"],
        "detection_methods": ["behavioral", "pattern", "policy_rule"],
        "response_actions": ["alert", "block", "quarantine"],
        "evidence_types": ["runtime_event", "audit_log", "policy_decision"],
        "remediation_templates": ["route_to_trust_center", "restrict_unknown_usage"],
    },
    {
        "control_id": "POLICY_ENFORCEMENT_CONTROL",
        "control_name": "Policy Enforcement Control",
        "category": "governance",
        "description": "Ensure runtime actions are evaluated and enforced by active policy versions.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Manage", "Policy Operations", "MG-6", "Operationalize policy controls."),
            _framework_ref("ISO/IEC 42001", "A.10", "Policy", "A.10.2", "Execute AI policies consistently."),
            _framework_ref("EU AI Act", "Governance", "Compliance", "Art.16", "Maintain enforceable compliance controls."),
            _framework_ref("Microsoft Responsible AI Standard", "Govern", "Policy", "MSRAI-GOV-03", "Enforce AI governance policies."),
            _framework_ref("CSA AI Controls", "Governance", "Policy Enforcement", "CSA-AI-GOV-03", "Policy control at runtime."),
        ],
        "risk_tags": ["policy_bypass", "governance_gap"],
        "severity": "critical",
        "enforcement_points": ["browser_extension", "gateway", "runtime", "connector", "simulation"],
        "detection_methods": ["policy_rule", "pattern"],
        "response_actions": ["block", "warn", "modify", "step_up_auth", "alert"],
        "evidence_types": ["runtime_event", "policy_decision", "audit_log", "simulation_result"],
        "remediation_templates": ["tighten_guardian_contract", "require_policy_review"],
    },
    {
        "control_id": "RISK_CLASSIFICATION_CONTROL",
        "control_name": "Risk Classification Control",
        "category": "governance",
        "description": "Classify AI systems and actions by risk and trigger proportional controls.",
        "frameworks": [
            _framework_ref("NIST AI RMF", "Map", "Risk Assessment", "MP-4", "Classify risk and impact."),
            _framework_ref("ISO/IEC 42001", "A.6", "Risk", "A.6.4", "AI risk classification lifecycle."),
            _framework_ref("EU AI Act", "Risk Classification", "High-risk determination", "Art.6", "Risk-based obligations."),
            _framework_ref("MITRE ATLAS", "Threat Modeling", "Risk Prioritization", "AML.TA0010", "Threat-informed prioritization."),
            _framework_ref("CSA AI Controls", "Risk", "Classification", "CSA-AI-RISK-01", "Risk-tier based controls."),
        ],
        "risk_tags": ["risk_escalation", "governance_gap"],
        "severity": "high",
        "enforcement_points": ["runtime", "simulation", "connector"],
        "detection_methods": ["policy_rule", "behavioral", "pattern"],
        "response_actions": ["step_up_auth", "alert", "quarantine", "block"],
        "evidence_types": ["runtime_event", "audit_log", "simulation_result", "policy_decision"],
        "remediation_templates": ["raise_risk_tier", "trigger_stricter_controls"],
    },
]


SIGNAL_RISK_TAG_HINTS: dict[str, list[str]] = {
    "prompt_injection": ["prompt_injection"],
    "jailbreak": ["jailbreak"],
    "sensitive_data": ["sensitive_data", "pii_exposure"],
    "pii": ["pii_exposure"],
    "exfil": ["data_exfiltration"],
    "shadow_ai": ["shadow_ai", "unknown_ai"],
    "unknown_ai": ["shadow_ai", "unknown_ai"],
    "tool": ["tool_misuse"],
    "agent": ["agent_abuse"],
    "chain": ["chain_abuse"],
    "drift": ["privilege_drift"],
    "policy": ["policy_violation"],
    "rag": ["rag_poisoning"],
    "poison": ["rag_poisoning", "model_poisoning"],
    "integrity": ["model_integrity"],
    "context": ["context_leakage"],
}


RISK_TAG_TO_CONTROLS: dict[str, list[str]] = {
    "prompt_injection": ["PROMPT_INJECTION_DETECTION"],
    "jailbreak": ["JAILBREAK_DETECTION"],
    "sensitive_data": ["SENSITIVE_DATA_DETECTION"],
    "pii_exposure": ["PII_EXFILTRATION_PREVENTION", "SENSITIVE_DATA_DETECTION"],
    "data_exfiltration": ["PII_EXFILTRATION_PREVENTION", "CONTEXT_LEAKAGE_DETECTION"],
    "sensitive_upload": ["FILE_UPLOAD_INSPECTION", "OCR_DATA_EXTRACTION_CONTROL"],
    "shadow_ai": ["SHADOW_AI_DETECTION", "AI_SYSTEM_INVENTORY_CONTROL"],
    "unknown_ai": ["SHADOW_AI_DETECTION", "AI_SYSTEM_INVENTORY_CONTROL"],
    "tool_misuse": ["TOOL_CALL_VALIDATION"],
    "agent_abuse": ["AGENT_ACTION_AUTHORIZATION", "CHAIN_OF_ACTION_VALIDATION"],
    "chain_abuse": ["CHAIN_OF_ACTION_VALIDATION"],
    "privilege_drift": ["PRIVILEGE_DRIFT_DETECTION", "TOKEN_SCOPE_ENFORCEMENT"],
    "policy_violation": ["POLICY_ENFORCEMENT_CONTROL"],
    "model_integrity": ["MODEL_OUTPUT_VALIDATION"],
    "rag_poisoning": ["RAG_POISONING_DETECTION"],
    "model_poisoning": ["RAG_POISONING_DETECTION", "MODEL_OUTPUT_VALIDATION"],
    "context_leakage": ["CONTEXT_LEAKAGE_DETECTION", "MODEL_OUTPUT_VALIDATION"],
}


EVENT_TYPE_HINTS: dict[str, list[str]] = {
    "llm_intercept": ["PROMPT_INJECTION_DETECTION", "POLICY_ENFORCEMENT_CONTROL"],
    "mcp_authorize": ["AGENT_ACTION_AUTHORIZATION", "TOOL_CALL_VALIDATION"],
    "unknown_ai_detected": ["SHADOW_AI_DETECTION", "AI_SYSTEM_INVENTORY_CONTROL"],
    "data_transfer": ["PII_EXFILTRATION_PREVENTION", "SENSITIVE_DATA_DETECTION"],
    "file_upload": ["FILE_UPLOAD_INSPECTION", "OCR_DATA_EXTRACTION_CONTROL"],
    "simulation_failure": ["POLICY_ENFORCEMENT_CONTROL"],
}


CANONICAL_CONTROL_IDS: set[str] = {str(item["control_id"]).upper() for item in CANONICAL_CONTROLS}


def normalize_control_id(control_id: str | None) -> str | None:
    if not control_id:
        return None
    token = str(control_id).strip()
    if not token:
        return None
    token_upper = token.upper()
    if token_upper in CANONICAL_CONTROL_IDS:
        return token_upper
    alias = LEGACY_CONTROL_ALIASES.get(token_upper)
    if alias:
        return alias
    return token


def normalize_control_ids(control_ids: list[str] | None) -> list[str]:
    out: list[str] = []
    for raw in list(control_ids or []):
        normalized = normalize_control_id(raw)
        if normalized:
            out.append(normalized)
    return _uniq(out)


def framework_ref_labels_for_control_ids(control_ids: list[str] | None) -> list[str]:
    canonical_ids = set(normalize_control_ids(control_ids))
    labels: list[str] = []
    for spec in CANONICAL_CONTROLS:
        if str(spec["control_id"]) not in canonical_ids:
            continue
        for item in list(spec.get("frameworks") or []):
            if not isinstance(item, dict):
                continue
            framework = str(item.get("framework") or "").strip()
            reference = str(item.get("reference_id") or "").strip()
            domain = str(item.get("domain") or "").strip()
            if framework and reference:
                labels.append(f"{framework}:{reference}")
            elif framework and domain:
                labels.append(f"{framework}:{domain}")
            elif framework:
                labels.append(framework)
    return _uniq(labels)


def _merge_dict_list(existing: list[dict[str, Any]] | None, additions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for item in list(existing or []) + list(additions or []):
        if not isinstance(item, dict):
            continue
        key = (
            str(item.get("framework") or "").strip(),
            str(item.get("domain") or "").strip(),
            str(item.get("subdomain") or "").strip(),
            str(item.get("reference_id") or "").strip(),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "framework": key[0],
                "framework_key": _framework_key(key[0]),
                "domain": key[1],
                "subdomain": key[2],
                "reference_id": key[3],
                "description": str(item.get("description") or "").strip(),
            }
        )
    return out


def ensure_canonical_controls(db: Session, *, tenant_id: str) -> dict[str, int]:
    created = 0
    updated = 0

    dialect_name = db.get_bind().dialect.name
    for spec in CANONICAL_CONTROLS:
        values = {
            "id": str(spec["control_id"]),
            "tenant_id": tenant_id,
            "is_global": False,
            "name": str(spec["control_name"]),
            "category": str(spec["category"]),
            "description": str(spec["description"]),
            "mapped_framework_refs": list(spec["frameworks"]),
            "risk_tags": _uniq(list(spec["risk_tags"])),
            "severity": str(spec["severity"]),
            "enforcement_points": _uniq(list(spec["enforcement_points"])),
            "detection_methods": _uniq(list(spec["detection_methods"])),
            "response_actions": _uniq(list(spec["response_actions"])),
            "evidence_types": _uniq(list(spec["evidence_types"])),
            "remediation_templates": _uniq(list(spec["remediation_templates"])),
        }
        if dialect_name == "postgresql":
            result = db.execute(
                postgresql_insert(Control)
                .values(**values)
                .on_conflict_do_nothing(index_elements=["id", "tenant_id"])
            )
            created += max(0, int(result.rowcount or 0))
        elif dialect_name == "sqlite":
            result = db.execute(
                sqlite_insert(Control)
                .values(**values)
                .on_conflict_do_nothing(index_elements=["id", "tenant_id"])
            )
            created += max(0, int(result.rowcount or 0))
        else:
            try:
                with db.begin_nested():
                    db.add(Control(**values))
                    db.flush()
                    created += 1
            except IntegrityError:
                pass

    existing_rows = {
        row.id: row
        for row in db.scalars(
            select(Control).where(
                Control.tenant_id == tenant_id,
                Control.id.in_([item["control_id"] for item in CANONICAL_CONTROLS]),
            )
        ).all()
    }

    for spec in CANONICAL_CONTROLS:
        control_id = str(spec["control_id"])
        row = existing_rows.get(control_id)
        if row is None:
            raise RuntimeError(f"Failed to persist canonical control {control_id}")

        changed = False
        if not str(row.name or "").strip():
            row.name = str(spec["control_name"])
            changed = True
        if not str(row.category or "").strip():
            row.category = str(spec["category"])
            changed = True
        if not str(row.description or "").strip():
            row.description = str(spec["description"])
            changed = True

        merged_framework_refs = _merge_dict_list(list(row.mapped_framework_refs or []), list(spec["frameworks"]))
        if merged_framework_refs != list(row.mapped_framework_refs or []):
            row.mapped_framework_refs = merged_framework_refs
            changed = True

        for field_name, values in [
            ("risk_tags", spec["risk_tags"]),
            ("enforcement_points", spec["enforcement_points"]),
            ("detection_methods", spec["detection_methods"]),
            ("response_actions", spec["response_actions"]),
            ("evidence_types", spec["evidence_types"]),
            ("remediation_templates", spec["remediation_templates"]),
        ]:
            merged_values = _uniq([*list(getattr(row, field_name) or []), *list(values)])
            if merged_values != list(getattr(row, field_name) or []):
                setattr(row, field_name, merged_values)
                changed = True

        if not str(row.severity or "").strip():
            row.severity = str(spec["severity"])
            changed = True

        if changed:
            updated += 1

    db.flush()
    return {
        "created": created,
        "updated": updated,
        "total_canonical": len(CANONICAL_CONTROLS),
    }


def _simulation_counts_by_control(db: Session, *, tenant_id: str) -> tuple[dict[str, int], dict[str, int], dict[str, int]]:
    sim_defs = db.scalars(select(SimulationDefinition).where(SimulationDefinition.tenant_id == tenant_id)).all()
    sim_count_by_control: dict[str, int] = defaultdict(int)
    simulation_ids_by_control: dict[str, set[str]] = defaultdict(set)

    for sim in sim_defs:
        mapped_controls = normalize_control_ids(list((sim.dsl_json or {}).get("maps_to_controls") or []))
        for control_id in mapped_controls:
            sim_count_by_control[control_id] += 1
            simulation_ids_by_control[control_id].add(sim.id)

    run_count_by_control: dict[str, int] = defaultdict(int)
    pass_count_by_control: dict[str, int] = defaultdict(int)
    simulation_id_lookup = {sim.id: sim for sim in sim_defs}
    runs = db.scalars(select(SimulationRun).where(SimulationRun.tenant_id == tenant_id)).all()
    for run in runs:
        sim = simulation_id_lookup.get(run.simulation_id)
        if not sim:
            continue
        mapped_controls = normalize_control_ids(list((sim.dsl_json or {}).get("maps_to_controls") or []))
        result = str((run.results or {}).get("result") or "").strip().lower()
        for control_id in mapped_controls:
            run_count_by_control[control_id] += 1
            if result == "pass":
                pass_count_by_control[control_id] += 1

    pass_rate_by_control: dict[str, int] = {}
    for control_id, run_count in run_count_by_control.items():
        passes = pass_count_by_control.get(control_id, 0)
        pass_rate_by_control[control_id] = int(round((passes / run_count) * 100)) if run_count > 0 else 0

    return dict(sim_count_by_control), dict(run_count_by_control), pass_rate_by_control


def _runtime_counts_by_control(
    db: Session,
    *,
    tenant_id: str,
    lookback_hours: int,
) -> tuple[dict[str, dict[str, int]], int]:
    lookback = max(1, min(24 * 30, int(lookback_hours or 24)))
    since = datetime.now(timezone.utc) - timedelta(hours=lookback)
    events = db.scalars(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.created_at >= since,
        )
    ).all()

    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"trigger_count": 0, "miss_count": 0})
    for row in events:
        metadata = dict(row.metadata_json or {}) if isinstance(row.metadata_json, dict) else {}
        mapping = infer_runtime_control_mapping(
            event_type=row.event_type,
            metadata=metadata,
            source_surface=row.source_surface,
        )
        for control_id in mapping["triggered_controls"]:
            counts[control_id]["trigger_count"] += 1
        for control_id in mapping["missed_controls"]:
            counts[control_id]["miss_count"] += 1

    return dict(counts), len(events)


def list_control_explorer(
    db: Session,
    *,
    tenant_id: str,
    foundation_only: bool = True,
    framework: str | None = None,
    category: str | None = None,
    enforcement_point: str | None = None,
    risk_tag: str | None = None,
) -> dict[str, Any]:
    ensure_canonical_controls(db, tenant_id=tenant_id)

    rows = db.scalars(
        select(Control).where(
            Control.tenant_id == tenant_id,
        )
    ).all()

    framework_filter = str(framework or "").strip().lower()
    category_filter = str(category or "").strip().lower()
    surface_filter = str(enforcement_point or "").strip().lower()
    risk_tag_filter = str(risk_tag or "").strip().lower()

    sim_count_by_control, run_count_by_control, pass_rate_by_control = _simulation_counts_by_control(db, tenant_id=tenant_id)
    runtime_counts_by_control, observed_runtime_event_count = _runtime_counts_by_control(
        db,
        tenant_id=tenant_id,
        lookback_hours=24 * 30,
    )

    items: list[dict[str, Any]] = []
    for row in rows:
        control_id = str(row.id or "").strip()
        if foundation_only and control_id not in TOP20_CONTROL_IDS:
            continue

        framework_refs = [dict(item) for item in list(row.mapped_framework_refs or []) if isinstance(item, dict)]
        frameworks_observed = _uniq([str(item.get("framework") or "") for item in framework_refs])
        if framework_filter and framework_filter not in {name.lower() for name in frameworks_observed}:
            continue
        if category_filter and category_filter != str(row.category or "").strip().lower():
            continue

        enforcement_points = _uniq(list(row.enforcement_points or []))
        if surface_filter and surface_filter not in {value.lower() for value in enforcement_points}:
            continue

        risk_tags = _uniq(list(row.risk_tags or []))
        if risk_tag_filter and risk_tag_filter not in {value.lower() for value in risk_tags}:
            continue

        trigger_count = int((runtime_counts_by_control.get(control_id) or {}).get("trigger_count") or 0)
        miss_count = int((runtime_counts_by_control.get(control_id) or {}).get("miss_count") or 0)
        simulation_pass_rate = float(pass_rate_by_control.get(control_id, 0))
        crq_profile = compute_control_crq_profile(
            control_id=control_id,
            category=str(row.category or "governance"),
            severity=str(row.severity or "medium"),
            risk_tags=risk_tags,
            trigger_count=trigger_count,
            miss_count=miss_count,
            observed_event_count=max(1, observed_runtime_event_count),
            lookback_hours=24 * 30,
            simulation_pass_rate_percent=simulation_pass_rate,
            threat_type=(risk_tags[0] if risk_tags else str(row.category or "governance")),
            asset=str(row.category or "governance"),
        )

        items.append(
            {
                "control_id": control_id,
                "control_name": row.name,
                "category": row.category,
                "description": row.description,
                "frameworks": framework_refs,
                "risk_tags": risk_tags,
                "severity": row.severity,
                "enforcement_points": enforcement_points,
                "detection_methods": _uniq(list(row.detection_methods or [])),
                "response_actions": _uniq(list(row.response_actions or [])),
                "evidence_types": _uniq(list(row.evidence_types or [])),
                "remediation_templates": _uniq(list(row.remediation_templates or [])),
                "simulation_count": int(sim_count_by_control.get(control_id, 0)),
                "simulation_run_count": int(run_count_by_control.get(control_id, 0)),
                "simulation_pass_rate_percent": int(simulation_pass_rate),
                "runtime_trigger_count": trigger_count,
                "runtime_miss_count": miss_count,
                "risk_event": crq_profile["risk_event"],
                "control_risk_profile": crq_profile["control_risk_profile"],
                "decision_score": crq_profile["decision_score"],
                "financials": crq_profile["financials"],
                "risk_if_exploited": crq_profile["risk_if_exploited"],
                "likelihood": crq_profile["likelihood"],
                "annualized_loss_expectancy": crq_profile["annualized_loss_expectancy"],
                "is_global": bool(row.is_global),
                "foundation_control": control_id in TOP20_CONTROL_IDS,
            }
        )

    category_counts: dict[str, int] = defaultdict(int)
    framework_counts: dict[str, int] = defaultdict(int)
    for item in items:
        category_counts[str(item["category"])] += 1
        for framework_name in _uniq([str(ref.get("framework") or "") for ref in item["frameworks"]]):
            framework_counts[framework_name] += 1

    return {
        "tenant_id": tenant_id,
        "foundation_only": bool(foundation_only),
        "foundation_control_ids": list(TOP20_CONTROL_IDS),
        "framework_catalog": FRAMEWORK_CATALOG,
        "legacy_aliases": LEGACY_CONTROL_ALIASES,
        "total_controls": len(items),
        "category_counts": dict(sorted(category_counts.items())),
        "framework_counts": dict(sorted(framework_counts.items())),
        "crq_summary": aggregate_financials(items),
        "controls": sorted(items, key=lambda item: (str(item["category"]), str(item["control_id"]))),
    }


def _extract_signal_tokens(event_type: str, metadata: dict[str, Any]) -> list[str]:
    tokens: list[str] = []
    for key in ["reason_codes", "input_signal_types", "risk_labels", "triggered_controls"]:
        raw = metadata.get(key)
        if isinstance(raw, list):
            tokens.extend([str(item).strip().lower() for item in raw if str(item).strip()])
        elif isinstance(raw, str) and raw.strip():
            tokens.append(raw.strip().lower())

    for key in ["reason", "decision", "final_decision", "classification", "data_classification"]:
        value = str(metadata.get(key) or "").strip().lower()
        if value:
            tokens.append(value)

    event_token = str(event_type or "").strip().lower()
    if event_token:
        tokens.append(event_token)
    return tokens


def _infer_enforcement_status(*, decision: str, source_surface: str, metadata: dict[str, Any]) -> str:
    explicit = str(
        metadata.get("enforcement_status")
        or metadata.get("control_enforcement_status")
        or metadata.get("enforcement_mode")
        or ""
    ).strip().lower()
    if explicit:
        return explicit

    decision_norm = str(decision or "").strip().lower()
    surface = str(source_surface or "").strip().lower()
    if surface == "remediation" or decision_norm in {"proposed", "queued", "pending_remediation"}:
        return "remediation_pending"
    if decision_norm in {
        "block",
        "blocked",
        "deny",
        "denied",
        "warn",
        "redact",
        "modify",
        "restrict",
        "require_justification",
        "hold_for_approval",
        "step_up",
    }:
        return "enforced"
    if decision_norm in {"simulate", "simulated"}:
        return "simulated"
    return "observed"


def infer_runtime_control_mapping(
    *,
    event_type: str,
    metadata: dict[str, Any],
    source_surface: str,
) -> dict[str, Any]:
    signal_tokens = _extract_signal_tokens(event_type, metadata)

    risk_tags: list[str] = []
    for token in signal_tokens:
        for hint, mapped_tags in SIGNAL_RISK_TAG_HINTS.items():
            if hint in token:
                risk_tags.extend(mapped_tags)

    risk_tags = _uniq([*risk_tags, *list(metadata.get("risk_tags") or [])])

    triggered_controls = normalize_control_ids(list(metadata.get("triggered_controls") or []))
    if not triggered_controls:
        reason_controls = normalize_control_ids(list(metadata.get("related_control_ids") or []))
        triggered_controls.extend(reason_controls)

    event_hints = EVENT_TYPE_HINTS.get(str(event_type or "").strip().lower(), [])
    triggered_controls.extend(event_hints)

    for tag in risk_tags:
        triggered_controls.extend(RISK_TAG_TO_CONTROLS.get(tag, []))

    source_surface_norm = str(source_surface or "").strip().lower()
    if source_surface_norm == "browser":
        triggered_controls.extend(["POLICY_ENFORCEMENT_CONTROL", "SENSITIVE_DATA_DETECTION"])
    elif source_surface_norm in {"gateway", "aiiam", "connector", "agent", "remediation"}:
        triggered_controls.extend(["POLICY_ENFORCEMENT_CONTROL"])

    triggered_controls = normalize_control_ids(triggered_controls)

    missed_controls = normalize_control_ids(list(metadata.get("missed_controls") or []))
    policy_eval = dict(metadata.get("policy_evaluation") or {})
    decision = str(
        metadata.get("decision")
        or metadata.get("final_decision")
        or policy_eval.get("decision")
        or ""
    ).strip().lower()
    if decision in {"allow", "defer"} and risk_tags:
        # If risky signals are present but enforcement still allowed/deferred, treat these as potential misses.
        missed_controls = _uniq([*missed_controls, *triggered_controls])

    return {
        "triggered_controls": triggered_controls,
        "missed_controls": missed_controls,
        "risk_tags": risk_tags,
        "enforcement_status": _infer_enforcement_status(
            decision=decision,
            source_surface=source_surface,
            metadata=metadata,
        ),
    }


def build_runtime_control_view(
    db: Session,
    *,
    tenant_id: str,
    lookback_hours: int = 24,
    foundation_only: bool = True,
) -> dict[str, Any]:
    ensure_canonical_controls(db, tenant_id=tenant_id)

    lookback = max(1, min(24 * 30, int(lookback_hours or 24)))
    since = datetime.now(timezone.utc) - timedelta(hours=lookback)

    events = db.scalars(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.created_at >= since,
        )
    ).all()

    control_stats: dict[str, dict[str, Any]] = {}

    for row in events:
        metadata = dict(row.metadata_json or {}) if isinstance(row.metadata_json, dict) else {}
        mapping = infer_runtime_control_mapping(
            event_type=row.event_type,
            metadata=metadata,
            source_surface=row.source_surface,
        )
        for control_id in mapping["triggered_controls"]:
            stat = control_stats.setdefault(
                control_id,
                {
                    "control_id": control_id,
                    "trigger_count": 0,
                    "miss_count": 0,
                    "source_surface_counts": defaultdict(int),
                    "severity_counts": defaultdict(int),
                    "risk_tag_counts": defaultdict(int),
                    "enforcement_status_counts": defaultdict(int),
                    "last_triggered_at": None,
                },
            )
            stat["trigger_count"] += 1
            stat["source_surface_counts"][str(row.source_surface)] += 1
            stat["severity_counts"][str(row.severity or "unknown")] += 1
            stat["enforcement_status_counts"][str(mapping.get("enforcement_status") or "observed")] += 1
            for tag in mapping["risk_tags"]:
                stat["risk_tag_counts"][tag] += 1
            if stat["last_triggered_at"] is None or row.created_at > stat["last_triggered_at"]:
                stat["last_triggered_at"] = row.created_at

        for control_id in mapping["missed_controls"]:
            stat = control_stats.setdefault(
                control_id,
                {
                    "control_id": control_id,
                    "trigger_count": 0,
                    "miss_count": 0,
                    "source_surface_counts": defaultdict(int),
                    "severity_counts": defaultdict(int),
                    "risk_tag_counts": defaultdict(int),
                    "enforcement_status_counts": defaultdict(int),
                    "last_triggered_at": None,
                },
            )
            stat["miss_count"] += 1

    control_rows = {
        row.id: row
        for row in db.scalars(
            select(Control).where(Control.tenant_id == tenant_id)
        ).all()
    }

    _, _, pass_rate_by_control = _simulation_counts_by_control(db, tenant_id=tenant_id)
    controls: list[dict[str, Any]] = []
    for control_id, stat in control_stats.items():
        if foundation_only and control_id not in TOP20_CONTROL_IDS:
            continue
        row = control_rows.get(control_id)
        simulation_pass_rate = float(pass_rate_by_control.get(control_id, 0))
        risk_tags = sorted((stat["risk_tag_counts"] or {}).keys())
        crq_profile = compute_control_crq_profile(
            control_id=control_id,
            category=str(row.category if row else "governance"),
            severity=str(row.severity if row else "medium"),
            risk_tags=risk_tags,
            trigger_count=int(stat["trigger_count"]),
            miss_count=int(stat["miss_count"]),
            observed_event_count=max(1, len(events)),
            lookback_hours=lookback,
            simulation_pass_rate_percent=simulation_pass_rate,
            threat_type=(risk_tags[0] if risk_tags else str(row.category if row else "governance")),
            asset=str(row.category if row else "governance"),
        )
        controls.append(
            {
                "control_id": control_id,
                "control_name": row.name if row else control_id,
                "category": row.category if row else "unknown",
                "severity": row.severity if row else "med",
                "trigger_count": int(stat["trigger_count"]),
                "miss_count": int(stat["miss_count"]),
                "source_surface_counts": dict(sorted(stat["source_surface_counts"].items())),
                "severity_counts": dict(sorted(stat["severity_counts"].items())),
                "risk_tag_counts": dict(sorted(stat["risk_tag_counts"].items())),
                "enforcement_status_counts": dict(sorted(stat["enforcement_status_counts"].items())),
                "last_triggered_at": stat["last_triggered_at"].isoformat() if stat["last_triggered_at"] else None,
                "risk_event": crq_profile["risk_event"],
                "control_risk_profile": crq_profile["control_risk_profile"],
                "decision_score": crq_profile["decision_score"],
                "financials": crq_profile["financials"],
                "risk_if_exploited": crq_profile["risk_if_exploited"],
                "likelihood": crq_profile["likelihood"],
                "annualized_loss_expectancy": crq_profile["annualized_loss_expectancy"],
            }
        )

    controls.sort(key=lambda item: (-int(item["trigger_count"]), str(item["control_id"])))

    return {
        "tenant_id": tenant_id,
        "foundation_only": bool(foundation_only),
        "foundation_control_ids": list(TOP20_CONTROL_IDS),
        "lookback_hours": lookback,
        "event_count": len(events),
        "control_count": len(controls),
        "crq_summary": aggregate_financials(controls),
        "controls": controls,
    }


def build_simulation_control_view(db: Session, *, tenant_id: str, foundation_only: bool = True) -> dict[str, Any]:
    ensure_canonical_controls(db, tenant_id=tenant_id)

    controls = db.scalars(
        select(Control).where(Control.tenant_id == tenant_id)
    ).all()
    control_map = {row.id: row for row in controls}

    sim_defs = db.scalars(select(SimulationDefinition).where(SimulationDefinition.tenant_id == tenant_id)).all()
    simulation_ids_by_control: dict[str, set[str]] = defaultdict(set)
    for sim in sim_defs:
        mapped = normalize_control_ids(list((sim.dsl_json or {}).get("maps_to_controls") or []))
        for control_id in mapped:
            simulation_ids_by_control[control_id].add(sim.id)

    run_stats_by_control: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    runs = db.scalars(select(SimulationRun).where(SimulationRun.tenant_id == tenant_id)).all()
    simulation_index = {sim.id: sim for sim in sim_defs}
    for run in runs:
        sim = simulation_index.get(run.simulation_id)
        if not sim:
            continue
        mapped = normalize_control_ids(list((sim.dsl_json or {}).get("maps_to_controls") or []))
        result = str((run.results or {}).get("result") or "not_executable").strip().lower() or "not_executable"
        for control_id in mapped:
            run_stats_by_control[control_id]["total_runs"] += 1
            run_stats_by_control[control_id][result] += 1

    rows: list[dict[str, Any]] = []
    for control_id, control in control_map.items():
        if foundation_only and control_id not in TOP20_CONTROL_IDS:
            continue
        run_stats = dict(run_stats_by_control.get(control_id) or {})
        total_runs = int(run_stats.get("total_runs") or 0)
        passes = int(run_stats.get("pass") or 0)
        fail_count = int(run_stats.get("fail") or 0)
        partial_count = int(run_stats.get("partial") or 0)
        not_executable_count = int(run_stats.get("not_executable") or 0)
        pass_rate = (passes / total_runs) if total_runs else 0.0
        if total_runs <= 0:
            final_outcome = "not_executable"
        elif fail_count > 0 and passes == 0 and partial_count == 0:
            final_outcome = "fail"
        elif partial_count > 0 or not_executable_count > 0 or (fail_count > 0 and passes > 0):
            final_outcome = "partial"
        elif passes == total_runs:
            final_outcome = "pass"
        else:
            final_outcome = "fail"

        simulation_crq = compute_simulation_crq(
            simulation_run_id=f"control:{control_id}",
            control_ids=[control_id],
            category=str(control.category or "governance"),
            severity=str(control.severity or "medium"),
            final_outcome=final_outcome,
            pass_rate=pass_rate,
            iterations=max(1, total_runs),
        )
        financials = {
            "risk_exposure_usd": float(simulation_crq.get("current_ale") or 0.0),
            "risk_reduced_usd": float(simulation_crq.get("risk_reduction") or 0.0),
            "at_risk_if_ignored_usd": float(simulation_crq.get("baseline_ale") or 0.0),
        }

        rows.append(
            {
                "control_id": control_id,
                "control_name": control.name,
                "category": control.category,
                "severity": control.severity,
                "simulation_count": len(simulation_ids_by_control.get(control_id, set())),
                "run_count": total_runs,
                "pass_rate_percent": int(round(pass_rate * 100)) if total_runs else 0,
                "result_breakdown": {
                    "pass": passes,
                    "fail": fail_count,
                    "partial": partial_count,
                    "not_executable": not_executable_count,
                },
                "framework_count": len(_uniq([str(ref.get("framework") or "") for ref in list(control.mapped_framework_refs or []) if isinstance(ref, dict)])),
                "crq": simulation_crq,
                "financials": financials,
            }
        )

    rows.sort(key=lambda item: (-int(item["simulation_count"]), str(item["control_id"])))

    return {
        "tenant_id": tenant_id,
        "foundation_only": bool(foundation_only),
        "foundation_control_ids": list(TOP20_CONTROL_IDS),
        "control_count": len(rows),
        "crq_summary": aggregate_financials(rows),
        "controls": rows,
    }
