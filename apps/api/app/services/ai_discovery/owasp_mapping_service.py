from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.models.monitoring import MonitoringSignal
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.simulation import SimulationCatalogEntry, SimulationDefinition, SimulationRun
from app.services.control_graph_service import normalize_control_ids


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_utc(value: datetime | None) -> datetime:
    if value is None:
        return _utcnow()
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _safe_dict(value: Any) -> dict[str, Any]:
    return dict(value or {}) if isinstance(value, dict) else {}


def _safe_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return list(value)
    return []


def _started_at(lookback_hours: int) -> datetime:
    safe_hours = max(1, min(24 * 180, int(lookback_hours or 24 * 7)))
    return _utcnow() - timedelta(hours=safe_hours)


def _normalize_controls(values: list[Any]) -> list[str]:
    return normalize_control_ids([str(item).strip() for item in list(values or []) if str(item).strip()])


OWASP_FRAMEWORK_REGISTRY: list[dict[str, str]] = [
    {
        "framework": "OWASP Top 10 for LLM Applications",
        "framework_key": "OWASP_LLM_TOP_10",
        "version": "2025",
        "source_reference_url": "https://genai.owasp.org/llm-top-10/",
    },
    {
        "framework": "OWASP Top 10 for Agentic Applications for 2026",
        "framework_key": "OWASP_AGENTIC_TOP_10_2026",
        "version": "2026",
        "source_reference_url": "https://genai.owasp.org/agentic-security-initiative/",
    },
    {
        "framework": "OWASP MCP Top 10",
        "framework_key": "OWASP_MCP_TOP_10",
        "version": "2025",
        "source_reference_url": "https://owasp.org/www-project-mcp-top-10/",
    },
]


LLM_2025_REFERENCE_OVERRIDES: dict[str, tuple[str, str]] = {
    "LLM01_PROMPT_INJECTION": ("LLM01:2025", "Prompt Injection"),
    "LLM02_INSECURE_OUTPUT_HANDLING": ("LLM05:2025", "Improper Output Handling"),
    "LLM03_TRAINING_DATA_POISONING": ("LLM04:2025", "Data and Model Poisoning"),
    "LLM04_MODEL_DOS": ("LLM10:2025", "Unbounded Consumption"),
    "LLM05_SUPPLY_CHAIN": ("LLM03:2025", "Supply Chain"),
    "LLM06_DATA_LEAKAGE": ("LLM02:2025", "Sensitive Information Disclosure"),
    "LLM07_INSECURE_PLUGIN_DESIGN": ("LLM08:2025", "Vector and Embedding Weaknesses"),
    "LLM08_EXCESSIVE_AGENCY": ("LLM06:2025", "Excessive Agency"),
    "LLM09_OVERRELIANCE": ("LLM09:2025", "Misinformation"),
    "LLM10_MODEL_ABUSE_OR_THEFT": ("LLM07:2025", "System Prompt Leakage"),
}


AGENTIC_TOP_10_2026_MAPPINGS: list[dict[str, Any]] = [
    {
        "risk_id": "AGENTIC_ASI01_GOAL_AND_INSTRUCTION_MANIPULATION",
        "reference": "ASI01:2026",
        "title": "Agent Goal and Instruction Manipulation",
        "risk_tags": ["agent_goal_hijack", "instruction_hijack", "prompt_override"],
        "controls": ["PROMPT_INJECTION_DETECTION", "CONTEXT_LEAKAGE_DETECTION", "CHAIN_OF_ACTION_VALIDATION"],
        "simulations": ["SIM-PROMPT-001", "SIM-PROMPT-002", "SIM-TOOL-003"],
        "enforcement_actions": ["block", "require_approval", "isolate_agent"],
        "blast_radius_dimensions": ["agent_goal", "execution_chain", "delegation_boundary"],
        "remediation_templates": ["goal_integrity_validation", "require_manual_approval"],
        "extends_llm_risks": ["LLM01_PROMPT_INJECTION", "LLM08_EXCESSIVE_AGENCY"],
    },
    {
        "risk_id": "AGENTIC_ASI02_TOOL_MISUSE",
        "reference": "ASI02:2026",
        "title": "Tool Misuse",
        "risk_tags": ["tool_misuse", "parameter_injection", "exfiltration_via_tool"],
        "controls": ["TOOL_CALL_VALIDATION", "AGENT_ACTION_AUTHORIZATION", "TOKEN_SCOPE_ENFORCEMENT"],
        "simulations": ["SIM-TOOL-001", "SIM-TOOL-002", "SIM-TOOL-004"],
        "enforcement_actions": ["block", "restrict", "require_approval"],
        "blast_radius_dimensions": ["tool_permissions", "external_api", "data_path"],
        "remediation_templates": ["restrict_tool_allowlist", "validate_tool_arguments"],
        "extends_llm_risks": ["LLM02_INSECURE_OUTPUT_HANDLING", "LLM07_INSECURE_PLUGIN_DESIGN"],
    },
    {
        "risk_id": "AGENTIC_ASI03_IDENTITY_PRIVILEGE_ABUSE",
        "reference": "ASI03:2026",
        "title": "Identity and Privilege Abuse",
        "risk_tags": ["identity_impersonation", "privilege_escalation", "confused_deputy"],
        "controls": ["AI_IDENTITY_BINDING", "NON_HUMAN_IDENTITY_CONTROL", "TOKEN_SCOPE_ENFORCEMENT"],
        "simulations": ["SIM-IAM-001", "SIM-IAM-002", "SIM-IAM-004"],
        "enforcement_actions": ["block", "restrict", "isolate_agent", "require_approval"],
        "blast_radius_dimensions": ["identity_graph", "token_scope", "delegation_graph"],
        "remediation_templates": ["rotate_agent_tokens", "reduce_capabilities", "revoke_delegation"],
        "extends_llm_risks": ["LLM08_EXCESSIVE_AGENCY", "LLM10_MODEL_ABUSE_OR_THEFT"],
    },
    {
        "risk_id": "AGENTIC_ASI04_AGENTIC_SUPPLY_CHAIN",
        "reference": "ASI04:2026",
        "title": "Agentic Supply Chain Vulnerabilities",
        "risk_tags": ["agent_supply_chain", "compromised_connector", "model_version_drift"],
        "controls": ["MODEL_ACCESS_CONTROL", "TOOL_CALL_VALIDATION", "POLICY_ENFORCEMENT_CONTROL"],
        "simulations": ["SIM-MODEL-001", "SIM-MODEL-002", "SIM-TOOL-004"],
        "enforcement_actions": ["block", "restrict", "isolate_agent"],
        "blast_radius_dimensions": ["provider_dependency", "connector_dependency", "mcp_server_trust"],
        "remediation_templates": ["enforce_dependency_allowlist", "pin_model_version"],
        "extends_llm_risks": ["LLM05_SUPPLY_CHAIN"],
    },
    {
        "risk_id": "AGENTIC_ASI05_UNEXPECTED_CODE_EXECUTION",
        "reference": "ASI05:2026",
        "title": "Unexpected Code Execution",
        "risk_tags": ["unexpected_code_execution", "command_injection", "unsafe_browser_execution"],
        "controls": ["TOOL_CALL_VALIDATION", "AGENT_ACTION_AUTHORIZATION", "CHAIN_OF_ACTION_VALIDATION"],
        "simulations": ["SIM-TOOL-002", "SIM-TOOL-003", "SIM-RESOURCE-002"],
        "enforcement_actions": ["block", "isolate_agent", "require_approval"],
        "blast_radius_dimensions": ["execution_surface", "host_access", "tool_boundary"],
        "remediation_templates": ["sandbox_execution", "high_risk_action_approval"],
        "extends_llm_risks": ["LLM02_INSECURE_OUTPUT_HANDLING", "LLM08_EXCESSIVE_AGENCY"],
    },
    {
        "risk_id": "AGENTIC_ASI06_RESOURCE_ABUSE",
        "reference": "ASI06:2026",
        "title": "Resource Abuse and Denial of Service",
        "risk_tags": ["recursive_loop", "cost_amplification", "resource_abuse"],
        "controls": ["CHAIN_OF_ACTION_VALIDATION", "POLICY_ENFORCEMENT_CONTROL", "AGENT_ACTION_AUTHORIZATION"],
        "simulations": ["SIM-RESOURCE-001", "SIM-RESOURCE-002"],
        "enforcement_actions": ["block", "restrict", "isolate_agent"],
        "blast_radius_dimensions": ["token_budget", "runtime_quota", "service_availability"],
        "remediation_templates": ["reduce_chain_depth", "enforce_rate_limits"],
        "extends_llm_risks": ["LLM04_MODEL_DOS", "LLM08_EXCESSIVE_AGENCY"],
    },
    {
        "risk_id": "AGENTIC_ASI07_MEMORY_CONTEXT_POISONING",
        "reference": "ASI07:2026",
        "title": "Memory and Context Poisoning",
        "risk_tags": ["context_poisoning", "memory_exposure", "rag_poisoning"],
        "controls": ["CONTEXT_LEAKAGE_DETECTION", "RAG_POISONING_DETECTION", "MODEL_OUTPUT_VALIDATION"],
        "simulations": ["SIM-RAG-001", "SIM-RAG-002", "SIM-DATA-003"],
        "enforcement_actions": ["block", "modify", "quarantine"],
        "blast_radius_dimensions": ["memory_store", "retrieval_context", "agent_goal"],
        "remediation_templates": ["memory_scope_hardening", "quarantine_knowledge_source"],
        "extends_llm_risks": ["LLM03_TRAINING_DATA_POISONING", "LLM06_DATA_LEAKAGE"],
    },
    {
        "risk_id": "AGENTIC_ASI08_DELEGATION_BOUNDARY_FAILURE",
        "reference": "ASI08:2026",
        "title": "Delegation and Multi-Agent Boundary Failure",
        "risk_tags": ["delegation_abuse", "chain_abuse", "boundary_bypass"],
        "controls": ["AGENT_ACTION_AUTHORIZATION", "TOKEN_SCOPE_ENFORCEMENT", "CHAIN_OF_ACTION_VALIDATION"],
        "simulations": ["SIM-IAM-002", "SIM-IAM-003", "SIM-TOOL-003"],
        "enforcement_actions": ["block", "restrict", "require_approval"],
        "blast_radius_dimensions": ["delegation_chain", "agent_scope", "privilege_graph"],
        "remediation_templates": ["revoke_delegation", "tighten_scope_policy"],
        "extends_llm_risks": ["LLM08_EXCESSIVE_AGENCY"],
    },
    {
        "risk_id": "AGENTIC_ASI09_OBSERVABILITY_REPUDIATION_GAP",
        "reference": "ASI09:2026",
        "title": "Observability and Repudiation Gaps",
        "risk_tags": ["missing_evidence", "audit_gap", "repudiation"],
        "controls": ["POLICY_ENFORCEMENT_CONTROL", "AI_IDENTITY_BINDING", "NON_HUMAN_IDENTITY_CONTROL"],
        "simulations": ["SIM-DECISION-001", "SIM-IAM-004"],
        "enforcement_actions": ["warn", "require_approval", "block"],
        "blast_radius_dimensions": ["audit_trace", "identity_graph", "evidence_chain"],
        "remediation_templates": ["require_evidence_linkage", "enable_runtime_trace"],
        "extends_llm_risks": ["LLM09_OVERRELIANCE"],
    },
    {
        "risk_id": "AGENTIC_ASI10_UNSAFE_AUTONOMY",
        "reference": "ASI10:2026",
        "title": "Unsafe Autonomy and Human Oversight Failure",
        "risk_tags": ["unsafe_decisioning", "autonomous_unsafe_action", "insufficient_validation"],
        "controls": ["AGENT_ACTION_AUTHORIZATION", "POLICY_ENFORCEMENT_CONTROL", "MODEL_OUTPUT_VALIDATION"],
        "simulations": ["SIM-DECISION-001", "SIM-DECISION-002", "SIM-IAM-001"],
        "enforcement_actions": ["require_approval", "restrict", "block"],
        "blast_radius_dimensions": ["decision_quality", "approval_gate", "business_impact"],
        "remediation_templates": ["enable_human_in_loop", "high_risk_action_approval"],
        "extends_llm_risks": ["LLM08_EXCESSIVE_AGENCY", "LLM09_OVERRELIANCE"],
    },
]


MCP_TOP_10_2025_MAPPINGS: list[dict[str, Any]] = [
    {
        "risk_id": "MCP01_PROMPT_INJECTION",
        "reference": "MCP01:2025",
        "title": "Prompt Injection",
        "risk_tags": ["mcp_prompt_injection", "instruction_hijack"],
        "controls": ["PROMPT_INJECTION_DETECTION", "CONTEXT_LEAKAGE_DETECTION", "POLICY_ENFORCEMENT_CONTROL"],
        "simulations": ["SIM-PROMPT-001", "SIM-PROMPT-004"],
        "enforcement_actions": ["block", "modify", "require_approval"],
        "blast_radius_dimensions": ["context_boundary", "agent_goal", "tool_execution"],
        "remediation_templates": ["tighten_prompt_guard", "revalidate_context_source"],
    },
    {
        "risk_id": "MCP02_TOOL_POISONING",
        "reference": "MCP02:2025",
        "title": "Tool Poisoning",
        "risk_tags": ["mcp_tool_poisoning", "compromised_connector"],
        "controls": ["TOOL_CALL_VALIDATION", "MODEL_ACCESS_CONTROL", "POLICY_ENFORCEMENT_CONTROL"],
        "simulations": ["SIM-TOOL-001", "SIM-TOOL-004"],
        "enforcement_actions": ["block", "restrict", "quarantine"],
        "blast_radius_dimensions": ["tool_boundary", "connector_dependency", "mcp_server_trust"],
        "remediation_templates": ["enforce_dependency_allowlist", "restrict_tool_allowlist"],
    },
    {
        "risk_id": "MCP03_EXCESSIVE_TOOL_PERMISSIONS",
        "reference": "MCP03:2025",
        "title": "Excessive Tool Permissions",
        "risk_tags": ["over_permissioned_tool", "tool_scope", "privilege_escalation"],
        "controls": ["TOKEN_SCOPE_ENFORCEMENT", "AGENT_ACTION_AUTHORIZATION", "TOOL_CALL_VALIDATION"],
        "simulations": ["SIM-IAM-001", "SIM-TOOL-003"],
        "enforcement_actions": ["block", "restrict", "require_approval"],
        "blast_radius_dimensions": ["tool_permissions", "api_scope", "identity_graph"],
        "remediation_templates": ["reduce_token_scope", "restrict_tool_allowlist"],
    },
    {
        "risk_id": "MCP04_RUG_PULL_ATTACK",
        "reference": "MCP04:2025",
        "title": "Rug Pull Attack",
        "risk_tags": ["mcp_rug_pull", "provider_drift", "supply_chain"],
        "controls": ["MODEL_ACCESS_CONTROL", "TOOL_CALL_VALIDATION", "POLICY_ENFORCEMENT_CONTROL"],
        "simulations": ["SIM-MODEL-001", "SIM-MODEL-002"],
        "enforcement_actions": ["block", "restrict", "alert"],
        "blast_radius_dimensions": ["provider_dependency", "connector_dependency", "model_endpoint"],
        "remediation_templates": ["pin_mcp_provider_binding", "enforce_dependency_allowlist"],
    },
    {
        "risk_id": "MCP05_TOOL_SHADOWING",
        "reference": "MCP05:2025",
        "title": "Tool Shadowing",
        "risk_tags": ["tool_shadowing", "tool_impersonation", "confused_deputy"],
        "controls": ["AI_IDENTITY_BINDING", "TOOL_CALL_VALIDATION", "TOKEN_SCOPE_ENFORCEMENT"],
        "simulations": ["SIM-TOOL-001", "SIM-IAM-004"],
        "enforcement_actions": ["block", "restrict", "require_approval"],
        "blast_radius_dimensions": ["identity_graph", "tool_boundary", "api_scope"],
        "remediation_templates": ["pin_tool_identity", "validate_tool_arguments"],
    },
    {
        "risk_id": "MCP06_INDIRECT_PROMPT_INJECTION",
        "reference": "MCP06:2025",
        "title": "Indirect Prompt Injection",
        "risk_tags": ["indirect_prompt_injection", "context_poisoning"],
        "controls": ["PROMPT_INJECTION_DETECTION", "RAG_POISONING_DETECTION", "CONTEXT_LEAKAGE_DETECTION"],
        "simulations": ["SIM-PROMPT-004", "SIM-RAG-001"],
        "enforcement_actions": ["block", "modify", "quarantine"],
        "blast_radius_dimensions": ["retrieval_context", "context_boundary", "agent_goal"],
        "remediation_templates": ["quarantine_knowledge_source", "tighten_context_boundary"],
    },
    {
        "risk_id": "MCP07_TOKEN_THEFT",
        "reference": "MCP07:2025",
        "title": "Token Theft",
        "risk_tags": ["token_theft", "credential_exposure", "identity_impersonation"],
        "controls": ["SENSITIVE_DATA_DETECTION", "TOKEN_SCOPE_ENFORCEMENT", "NON_HUMAN_IDENTITY_CONTROL"],
        "simulations": ["SIM-DATA-001", "SIM-IAM-004"],
        "enforcement_actions": ["block", "rotate", "isolate_agent"],
        "blast_radius_dimensions": ["identity_scope", "token_scope", "provider_access"],
        "remediation_templates": ["rotate_agent_tokens", "reduce_capabilities"],
    },
    {
        "risk_id": "MCP08_CONFUSED_DEPUTY",
        "reference": "MCP08:2025",
        "title": "Confused Deputy",
        "risk_tags": ["confused_deputy", "authorization_bypass", "delegation_abuse"],
        "controls": ["AGENT_ACTION_AUTHORIZATION", "AI_IDENTITY_BINDING", "POLICY_ENFORCEMENT_CONTROL"],
        "simulations": ["SIM-IAM-002", "SIM-IAM-003"],
        "enforcement_actions": ["block", "require_approval", "restrict"],
        "blast_radius_dimensions": ["delegation_chain", "privilege_graph", "business_impact"],
        "remediation_templates": ["revoke_delegation", "require_manual_approval"],
    },
    {
        "risk_id": "MCP09_EXCESSIVE_AGENCY",
        "reference": "MCP09:2025",
        "title": "Excessive Agency",
        "risk_tags": ["excessive_agency", "autonomous_unsafe_action", "scope_breach"],
        "controls": ["AGENT_ACTION_AUTHORIZATION", "CHAIN_OF_ACTION_VALIDATION", "POLICY_ENFORCEMENT_CONTROL"],
        "simulations": ["SIM-IAM-001", "SIM-DECISION-001"],
        "enforcement_actions": ["require_approval", "restrict", "block"],
        "blast_radius_dimensions": ["agent_scope", "execution_chain", "approval_gate"],
        "remediation_templates": ["tighten_scope_policy", "enable_human_in_loop"],
    },
    {
        "risk_id": "MCP10_UNTRUSTED_ROOT",
        "reference": "MCP10:2025",
        "title": "Untrusted Root",
        "risk_tags": ["untrusted_root", "mcp_server_trust", "supply_chain"],
        "controls": ["MODEL_ACCESS_CONTROL", "AI_IDENTITY_BINDING", "POLICY_ENFORCEMENT_CONTROL"],
        "simulations": ["SIM-MODEL-002", "SIM-TOOL-004"],
        "enforcement_actions": ["block", "restrict", "alert"],
        "blast_radius_dimensions": ["mcp_server_trust", "provider_dependency", "connector_dependency"],
        "remediation_templates": ["pin_mcp_provider_binding", "enforce_dependency_allowlist"],
    },
]


OWASP_RISK_MAPPINGS: list[dict[str, Any]] = [
    {
        "risk_id": "LLM01_PROMPT_INJECTION",
        "framework": "OWASP Top 10 for LLM Applications",
        "framework_key": "OWASP_LLM_TOP_10",
        "reference": "LLM01",
        "title": "Prompt Injection",
        "source_reference_url": "https://genai.owasp.org/llm-top-10/",
        "risk_tags": ["prompt_injection", "jailbreak", "agent_instruction_hijack"],
        "controls": ["PROMPT_INJECTION_DETECTION", "CONTEXT_LEAKAGE_DETECTION", "CHAIN_OF_ACTION_VALIDATION"],
        "simulations": ["SIM-PROMPT-001", "SIM-PROMPT-002", "SIM-PROMPT-003", "SIM-PROMPT-004", "SIM-PROMPT-005"],
        "enforcement_actions": ["block", "modify", "require_approval"],
        "blast_radius_dimensions": ["agent_goal", "prompt_context", "delegation_chain"],
        "remediation_templates": ["tighten_prompt_guard", "tighten_context_boundary"],
    },
    {
        "risk_id": "LLM02_INSECURE_OUTPUT_HANDLING",
        "framework": "OWASP Top 10 for LLM Applications",
        "framework_key": "OWASP_LLM_TOP_10",
        "reference": "LLM02",
        "title": "Insecure Output Handling",
        "source_reference_url": "https://genai.owasp.org/llm-top-10/",
        "risk_tags": ["unsafe_output", "output_command_execution", "tool_injection"],
        "controls": ["MODEL_OUTPUT_VALIDATION", "TOOL_CALL_VALIDATION", "POLICY_ENFORCEMENT_CONTROL"],
        "simulations": ["SIM-TOOL-002", "SIM-TOOL-004", "SIM-DECISION-002"],
        "enforcement_actions": ["block", "modify", "restrict"],
        "blast_radius_dimensions": ["tool_execution", "downstream_api", "data_write"],
        "remediation_templates": ["tighten_output_filters", "validate_tool_arguments"],
    },
    {
        "risk_id": "LLM03_TRAINING_DATA_POISONING",
        "framework": "OWASP Top 10 for LLM Applications",
        "framework_key": "OWASP_LLM_TOP_10",
        "reference": "LLM03",
        "title": "Training Data Poisoning",
        "source_reference_url": "https://genai.owasp.org/llm-top-10/",
        "risk_tags": ["rag_poisoning", "poisoned_knowledge_base"],
        "controls": ["RAG_POISONING_DETECTION", "MODEL_OUTPUT_VALIDATION"],
        "simulations": ["SIM-RAG-001", "SIM-RAG-002"],
        "enforcement_actions": ["block", "quarantine", "restrict"],
        "blast_radius_dimensions": ["knowledge_base", "retrieval_context", "model_output"],
        "remediation_templates": ["quarantine_knowledge_source", "revalidate_index"],
    },
    {
        "risk_id": "LLM04_MODEL_DOS",
        "framework": "OWASP Top 10 for LLM Applications",
        "framework_key": "OWASP_LLM_TOP_10",
        "reference": "LLM04",
        "title": "Model Denial of Service",
        "source_reference_url": "https://genai.owasp.org/llm-top-10/",
        "risk_tags": ["recursive_loop", "cost_amplification", "resource_abuse"],
        "controls": ["CHAIN_OF_ACTION_VALIDATION", "POLICY_ENFORCEMENT_CONTROL"],
        "simulations": ["SIM-RESOURCE-001", "SIM-RESOURCE-002"],
        "enforcement_actions": ["block", "restrict", "isolate_agent"],
        "blast_radius_dimensions": ["token_budget", "runtime_quota", "service_availability"],
        "remediation_templates": ["reduce_chain_depth", "enforce_rate_limits"],
    },
    {
        "risk_id": "LLM05_SUPPLY_CHAIN",
        "framework": "OWASP Top 10 for LLM Applications",
        "framework_key": "OWASP_LLM_TOP_10",
        "reference": "LLM05",
        "title": "Supply Chain Vulnerabilities",
        "source_reference_url": "https://genai.owasp.org/llm-top-10/",
        "risk_tags": ["supply_chain", "vulnerable_dependency", "unapproved_model"],
        "controls": ["MODEL_ACCESS_CONTROL", "TOOL_CALL_VALIDATION", "POLICY_ENFORCEMENT_CONTROL"],
        "simulations": ["SIM-MODEL-001", "SIM-MODEL-002", "SIM-TOOL-004"],
        "enforcement_actions": ["block", "restrict", "require_approval"],
        "blast_radius_dimensions": ["provider_dependency", "connector_dependency", "model_registry"],
        "remediation_templates": ["restrict_model_access", "enforce_dependency_allowlist"],
    },
    {
        "risk_id": "LLM06_DATA_LEAKAGE",
        "framework": "OWASP Top 10 for LLM Applications",
        "framework_key": "OWASP_LLM_TOP_10",
        "reference": "LLM06",
        "title": "Sensitive Information Disclosure",
        "source_reference_url": "https://genai.owasp.org/llm-top-10/",
        "risk_tags": ["data_exfiltration", "sensitive_data", "context_leakage"],
        "controls": ["SENSITIVE_DATA_DETECTION", "PII_EXFILTRATION_PREVENTION", "CONTEXT_LEAKAGE_DETECTION"],
        "simulations": ["SIM-DATA-001", "SIM-DATA-002", "SIM-DATA-003", "SIM-DATA-004", "SIM-DATA-005"],
        "enforcement_actions": ["block", "modify", "warn"],
        "blast_radius_dimensions": ["regulated_data", "memory_context", "external_destination"],
        "remediation_templates": ["tighten_data_policy", "enable_redaction"],
    },
    {
        "risk_id": "LLM07_INSECURE_PLUGIN_DESIGN",
        "framework": "OWASP Top 10 for LLM Applications",
        "framework_key": "OWASP_LLM_TOP_10",
        "reference": "LLM07",
        "title": "Insecure Plugin/Tool Design",
        "source_reference_url": "https://genai.owasp.org/llm-top-10/",
        "risk_tags": ["insecure_tool", "tool_misuse", "over_permissioned_tool"],
        "controls": ["TOOL_CALL_VALIDATION", "AGENT_ACTION_AUTHORIZATION", "TOKEN_SCOPE_ENFORCEMENT"],
        "simulations": ["SIM-TOOL-001", "SIM-TOOL-002", "SIM-TOOL-003", "SIM-TOOL-004"],
        "enforcement_actions": ["block", "restrict", "require_approval"],
        "blast_radius_dimensions": ["tool_permissions", "api_scope", "data_transfer_path"],
        "remediation_templates": ["restrict_tool_allowlist", "reduce_token_scope"],
    },
    {
        "risk_id": "LLM08_EXCESSIVE_AGENCY",
        "framework": "OWASP Top 10 for LLM Applications",
        "framework_key": "OWASP_LLM_TOP_10",
        "reference": "LLM08",
        "title": "Excessive Agency",
        "source_reference_url": "https://genai.owasp.org/llm-top-10/",
        "risk_tags": ["autonomous_unsafe_action", "excessive_agency", "scope_breach"],
        "controls": ["AGENT_ACTION_AUTHORIZATION", "TOKEN_SCOPE_ENFORCEMENT", "POLICY_ENFORCEMENT_CONTROL"],
        "simulations": ["SIM-IAM-001", "SIM-IAM-002", "SIM-IAM-003", "SIM-DECISION-001"],
        "enforcement_actions": ["require_approval", "restrict", "isolate_agent"],
        "blast_radius_dimensions": ["agent_scope", "privilege_graph", "execution_chain"],
        "remediation_templates": ["require_manual_approval", "tighten_scope_policy"],
    },
    {
        "risk_id": "LLM09_OVERRELIANCE",
        "framework": "OWASP Top 10 for LLM Applications",
        "framework_key": "OWASP_LLM_TOP_10",
        "reference": "LLM09",
        "title": "Overreliance",
        "source_reference_url": "https://genai.owasp.org/llm-top-10/",
        "risk_tags": ["unsafe_decisioning", "insufficient_validation"],
        "controls": ["MODEL_OUTPUT_VALIDATION", "POLICY_ENFORCEMENT_CONTROL"],
        "simulations": ["SIM-DECISION-001", "SIM-DECISION-002"],
        "enforcement_actions": ["require_approval", "warn", "block"],
        "blast_radius_dimensions": ["decision_quality", "approval_gate", "business_impact"],
        "remediation_templates": ["enable_human_in_loop", "evidence_requirement"],
    },
    {
        "risk_id": "LLM10_MODEL_ABUSE_OR_THEFT",
        "framework": "OWASP Top 10 for LLM Applications",
        "framework_key": "OWASP_LLM_TOP_10",
        "reference": "LLM10",
        "title": "Model Abuse / Theft",
        "source_reference_url": "https://genai.owasp.org/llm-top-10/",
        "risk_tags": ["model_abuse", "unauthorized_model_access", "identity_impersonation"],
        "controls": ["MODEL_ACCESS_CONTROL", "AI_IDENTITY_BINDING", "NON_HUMAN_IDENTITY_CONTROL"],
        "simulations": ["SIM-MODEL-001", "SIM-IAM-004"],
        "enforcement_actions": ["block", "restrict", "isolate_agent"],
        "blast_radius_dimensions": ["model_endpoint", "identity_scope", "provider_access"],
        "remediation_templates": ["restrict_model_access", "rotate_agent_tokens"],
    },
    {
        "risk_id": "AGENTIC_AGENT_GOAL_HIJACK",
        "framework": "OWASP Top 10 for Agentic Applications for 2026",
        "framework_key": "OWASP_AGENTIC_TOP_10_2026",
        "reference": "Agent Goal Hijack",
        "title": "Agent Goal Hijack",
        "source_reference_url": "https://genai.owasp.org/agentic-security-initiative/",
        "risk_tags": ["agent_goal_hijack", "instruction_hijack", "prompt_override"],
        "controls": [
            "PROMPT_INJECTION_DETECTION",
            "CONTEXT_LEAKAGE_DETECTION",
            "CHAIN_OF_ACTION_VALIDATION",
            "POLICY_ENFORCEMENT_CONTROL",
        ],
        "simulations": ["SIM-PROMPT-001", "SIM-PROMPT-002", "SIM-PROMPT-004", "SIM-TOOL-003"],
        "enforcement_actions": ["block", "require_approval", "isolate_agent"],
        "blast_radius_dimensions": ["agent_goal", "execution_chain", "delegation_boundary"],
        "remediation_templates": ["goal_integrity_validation", "require_manual_approval"],
        "extends_llm_risks": ["LLM01_PROMPT_INJECTION", "LLM08_EXCESSIVE_AGENCY"],
    },
    {
        "risk_id": "AGENTIC_TOOL_MISUSE",
        "framework": "OWASP Top 10 for Agentic Applications for 2026",
        "framework_key": "OWASP_AGENTIC_TOP_10_2026",
        "reference": "Tool Misuse",
        "title": "Tool Misuse",
        "source_reference_url": "https://genai.owasp.org/agentic-security-initiative/",
        "risk_tags": ["tool_misuse", "parameter_injection", "exfiltration_via_tool"],
        "controls": [
            "TOOL_CALL_VALIDATION",
            "AGENT_ACTION_AUTHORIZATION",
            "TOKEN_SCOPE_ENFORCEMENT",
            "POLICY_ENFORCEMENT_CONTROL",
        ],
        "simulations": ["SIM-TOOL-001", "SIM-TOOL-002", "SIM-TOOL-003", "SIM-TOOL-004"],
        "enforcement_actions": ["block", "restrict", "require_approval"],
        "blast_radius_dimensions": ["tool_permissions", "external_api", "data_path"],
        "remediation_templates": ["restrict_tool_allowlist", "validate_tool_arguments"],
        "extends_llm_risks": ["LLM02_INSECURE_OUTPUT_HANDLING", "LLM07_INSECURE_PLUGIN_DESIGN"],
    },
    {
        "risk_id": "AGENTIC_IDENTITY_PRIVILEGE_ABUSE",
        "framework": "OWASP Top 10 for Agentic Applications for 2026",
        "framework_key": "OWASP_AGENTIC_TOP_10_2026",
        "reference": "Identity & Privilege Abuse",
        "title": "Identity & Privilege Abuse",
        "source_reference_url": "https://genai.owasp.org/agentic-security-initiative/",
        "risk_tags": ["identity_impersonation", "privilege_escalation", "confused_deputy"],
        "controls": [
            "AI_IDENTITY_BINDING",
            "NON_HUMAN_IDENTITY_CONTROL",
            "TOKEN_SCOPE_ENFORCEMENT",
            "PRIVILEGE_DRIFT_DETECTION",
            "AGENT_ACTION_AUTHORIZATION",
        ],
        "simulations": ["SIM-IAM-001", "SIM-IAM-002", "SIM-IAM-003", "SIM-IAM-004", "SIM-TOOL-003"],
        "enforcement_actions": ["block", "restrict", "isolate_agent", "require_approval"],
        "blast_radius_dimensions": ["identity_graph", "token_scope", "delegation_graph"],
        "remediation_templates": ["rotate_agent_tokens", "reduce_capabilities", "revoke_delegation"],
        "extends_llm_risks": ["LLM08_EXCESSIVE_AGENCY", "LLM10_MODEL_ABUSE_OR_THEFT"],
    },
    {
        "risk_id": "AGENTIC_SUPPLY_CHAIN_VULNERABILITIES",
        "framework": "OWASP Top 10 for Agentic Applications for 2026",
        "framework_key": "OWASP_AGENTIC_TOP_10_2026",
        "reference": "Agentic Supply Chain Vulnerabilities",
        "title": "Agentic Supply Chain Vulnerabilities",
        "source_reference_url": "https://genai.owasp.org/agentic-security-initiative/",
        "risk_tags": ["agent_supply_chain", "compromised_connector", "model_version_drift"],
        "controls": ["MODEL_ACCESS_CONTROL", "TOOL_CALL_VALIDATION", "POLICY_ENFORCEMENT_CONTROL"],
        "simulations": ["SIM-MODEL-001", "SIM-MODEL-002", "SIM-TOOL-004"],
        "enforcement_actions": ["block", "restrict", "isolate_agent"],
        "blast_radius_dimensions": ["provider_dependency", "connector_dependency", "mcp_server_trust"],
        "remediation_templates": ["enforce_dependency_allowlist", "pin_model_version"],
        "extends_llm_risks": ["LLM05_SUPPLY_CHAIN"],
    },
    {
        "risk_id": "AGENTIC_UNEXPECTED_CODE_EXECUTION",
        "framework": "OWASP Top 10 for Agentic Applications for 2026",
        "framework_key": "OWASP_AGENTIC_TOP_10_2026",
        "reference": "Unexpected Code Execution",
        "title": "Unexpected Code Execution",
        "source_reference_url": "https://genai.owasp.org/agentic-security-initiative/",
        "risk_tags": ["unexpected_code_execution", "command_injection", "unsafe_browser_execution"],
        "controls": [
            "TOOL_CALL_VALIDATION",
            "AGENT_ACTION_AUTHORIZATION",
            "CHAIN_OF_ACTION_VALIDATION",
            "POLICY_ENFORCEMENT_CONTROL",
        ],
        "simulations": ["SIM-TOOL-002", "SIM-TOOL-003", "SIM-RESOURCE-002"],
        "enforcement_actions": ["block", "isolate_agent", "require_approval"],
        "blast_radius_dimensions": ["execution_surface", "host_access", "tool_boundary"],
        "remediation_templates": ["sandbox_execution", "high_risk_action_approval"],
        "extends_llm_risks": ["LLM02_INSECURE_OUTPUT_HANDLING", "LLM08_EXCESSIVE_AGENCY"],
    },
    {
        "risk_id": "MCP_MODEL_MISBINDING",
        "framework": "OWASP MCP Top 10",
        "framework_key": "OWASP_MCP_TOP_10",
        "reference": "Model Misbinding",
        "title": "Model Misbinding",
        "source_reference_url": "https://genai.owasp.org/",
        "risk_tags": ["mcp_model_misbinding", "provider_drift"],
        "controls": ["MODEL_ACCESS_CONTROL", "AI_IDENTITY_BINDING", "POLICY_ENFORCEMENT_CONTROL"],
        "simulations": ["SIM-MODEL-001", "SIM-MODEL-002"],
        "enforcement_actions": ["block", "restrict", "alert"],
        "blast_radius_dimensions": ["mcp_connection", "provider_binding", "model_endpoint"],
        "remediation_templates": ["pin_mcp_provider_binding"],
    },
    {
        "risk_id": "MCP_CONTEXT_SPOOFING",
        "framework": "OWASP MCP Top 10",
        "framework_key": "OWASP_MCP_TOP_10",
        "reference": "Context Spoofing",
        "title": "Context Spoofing",
        "source_reference_url": "https://genai.owasp.org/",
        "risk_tags": ["mcp_context_spoofing", "context_poisoning"],
        "controls": ["CONTEXT_LEAKAGE_DETECTION", "PROMPT_INJECTION_DETECTION", "POLICY_ENFORCEMENT_CONTROL"],
        "simulations": ["SIM-PROMPT-004", "SIM-RAG-001"],
        "enforcement_actions": ["block", "modify", "alert"],
        "blast_radius_dimensions": ["context_boundary", "retrieval_context", "agent_goal"],
        "remediation_templates": ["tighten_context_boundary", "revalidate_context_source"],
    },
    {
        "risk_id": "MCP_PROMPT_STATE_MANIPULATION",
        "framework": "OWASP MCP Top 10",
        "framework_key": "OWASP_MCP_TOP_10",
        "reference": "Prompt-State Manipulation",
        "title": "Prompt-State Manipulation",
        "source_reference_url": "https://genai.owasp.org/",
        "risk_tags": ["mcp_prompt_state", "state_manipulation", "goal_override"],
        "controls": ["PROMPT_INJECTION_DETECTION", "CHAIN_OF_ACTION_VALIDATION", "POLICY_ENFORCEMENT_CONTROL"],
        "simulations": ["SIM-PROMPT-001", "SIM-PROMPT-002", "SIM-TOOL-003"],
        "enforcement_actions": ["block", "require_approval", "isolate_agent"],
        "blast_radius_dimensions": ["state_machine", "execution_chain", "delegation_boundary"],
        "remediation_templates": ["goal_integrity_validation", "approval_gate_for_state_mutation"],
    },
    {
        "risk_id": "MCP_INSECURE_MEMORY_REFERENCES",
        "framework": "OWASP MCP Top 10",
        "framework_key": "OWASP_MCP_TOP_10",
        "reference": "Insecure Memory References",
        "title": "Insecure Memory References",
        "source_reference_url": "https://genai.owasp.org/",
        "risk_tags": ["mcp_memory_reference", "context_leakage", "memory_exposure"],
        "controls": ["CONTEXT_LEAKAGE_DETECTION", "SENSITIVE_DATA_DETECTION", "PII_EXFILTRATION_PREVENTION"],
        "simulations": ["SIM-DATA-003", "SIM-DATA-004", "SIM-DATA-005"],
        "enforcement_actions": ["block", "modify", "warn"],
        "blast_radius_dimensions": ["memory_store", "regulated_data", "response_channel"],
        "remediation_templates": ["memory_scope_hardening", "enable_output_redaction"],
    },
    {
        "risk_id": "MCP_UNSAFE_CHANNEL_BEHAVIOR",
        "framework": "OWASP MCP Top 10",
        "framework_key": "OWASP_MCP_TOP_10",
        "reference": "Covert / Unsafe Channel Behaviors",
        "title": "Covert / Unsafe Channel Behaviors",
        "source_reference_url": "https://genai.owasp.org/",
        "risk_tags": ["mcp_covert_channel", "unsafe_data_channel", "exfiltration"],
        "controls": ["TOOL_CALL_VALIDATION", "PII_EXFILTRATION_PREVENTION", "POLICY_ENFORCEMENT_CONTROL"],
        "simulations": ["SIM-TOOL-004", "SIM-DATA-001", "SIM-DATA-002"],
        "enforcement_actions": ["block", "restrict", "alert", "isolate_agent"],
        "blast_radius_dimensions": ["channel_path", "destination_control", "data_reachability"],
        "remediation_templates": ["channel_allowlist", "restrict_external_destinations"],
    },
]


def list_framework_registry() -> list[dict[str, str]]:
    return [dict(item) for item in OWASP_FRAMEWORK_REGISTRY]


def _audit_metadata_for_mapping(mapping: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_node_type": "owasp_risk_mapping",
        "audit_signal_type": "ai_discovery.owasp_mapping",
        "trace_fields": [
            "risk_id",
            "framework_key",
            "reference",
            "matched_controls",
            "runtime_event_id",
            "agent_id",
            "ai_system_id",
        ],
        "framework_key": str(mapping.get("framework_key") or ""),
        "reference": str(mapping.get("reference") or ""),
    }


def _normalize_mapping_payload(mapping: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(mapping)
    normalized["risk_tags"] = list(normalized.get("risk_tags") or [])
    normalized["controls"] = list(normalized.get("controls") or [])
    normalized["simulations"] = list(normalized.get("simulations") or [])
    normalized["enforcement_actions"] = list(normalized.get("enforcement_actions") or [])
    normalized["blast_radius_dimensions"] = list(normalized.get("blast_radius_dimensions") or [])
    normalized["remediation_templates"] = list(normalized.get("remediation_templates") or [])
    normalized["extends_llm_risks"] = list(normalized.get("extends_llm_risks") or [])
    normalized["audit_metadata"] = dict(normalized.get("audit_metadata") or _audit_metadata_for_mapping(normalized))
    return normalized


def _normalized_llm_2025_mappings() -> list[dict[str, Any]]:
    mappings: list[dict[str, Any]] = []
    for item in OWASP_RISK_MAPPINGS:
        if str(item.get("framework_key") or "") != "OWASP_LLM_TOP_10":
            continue
        reference, title = LLM_2025_REFERENCE_OVERRIDES.get(
            str(item.get("risk_id") or ""),
            (str(item.get("reference") or ""), str(item.get("title") or "")),
        )
        updated = dict(item)
        updated["reference"] = reference
        updated["title"] = title
        updated["source_reference_url"] = "https://genai.owasp.org/llm-top-10/"
        mappings.append(_normalize_mapping_payload(updated))
    return sorted(mappings, key=lambda value: str(value.get("reference") or ""))


def _normalized_agentic_2026_mappings() -> list[dict[str, Any]]:
    mappings: list[dict[str, Any]] = []
    for item in AGENTIC_TOP_10_2026_MAPPINGS:
        updated = {
            **dict(item),
            "framework": "OWASP Top 10 for Agentic Applications for 2026",
            "framework_key": "OWASP_AGENTIC_TOP_10_2026",
            "source_reference_url": "https://genai.owasp.org/agentic-security-initiative/",
        }
        mappings.append(_normalize_mapping_payload(updated))
    return sorted(mappings, key=lambda value: str(value.get("reference") or ""))


def _normalized_mcp_2025_mappings() -> list[dict[str, Any]]:
    mappings: list[dict[str, Any]] = []
    for item in MCP_TOP_10_2025_MAPPINGS:
        updated = {
            **dict(item),
            "framework": "OWASP MCP Top 10",
            "framework_key": "OWASP_MCP_TOP_10",
            "source_reference_url": "https://owasp.org/www-project-mcp-top-10/",
        }
        mappings.append(_normalize_mapping_payload(updated))
    return sorted(mappings, key=lambda value: str(value.get("reference") or ""))


def list_owasp_risk_mappings() -> list[dict[str, Any]]:
    return [
        *_normalized_llm_2025_mappings(),
        *_normalized_agentic_2026_mappings(),
        *_normalized_mcp_2025_mappings(),
    ]


def map_controls_to_owasp(control_ids: list[str] | None) -> list[dict[str, Any]]:
    normalized_controls = set(_normalize_controls([str(item) for item in list(control_ids or [])]))
    if not normalized_controls:
        return []

    matches: list[dict[str, Any]] = []
    for mapping in list_owasp_risk_mappings():
        controls = set(_normalize_controls([str(item) for item in list(mapping.get("controls") or [])]))
        overlap = sorted(normalized_controls.intersection(controls))
        if not overlap:
            continue
        matches.append(
            {
                "risk_id": str(mapping.get("risk_id") or ""),
                "framework": str(mapping.get("framework") or ""),
                "framework_key": str(mapping.get("framework_key") or ""),
                "reference": str(mapping.get("reference") or ""),
                "title": str(mapping.get("title") or ""),
                "source_reference_url": str(mapping.get("source_reference_url") or ""),
                "matched_controls": overlap,
                "risk_tags": list(mapping.get("risk_tags") or []),
                "controls": list(mapping.get("controls") or []),
                "simulations": list(mapping.get("simulations") or []),
                "enforcement_actions": list(mapping.get("enforcement_actions") or []),
                "blast_radius_dimensions": list(mapping.get("blast_radius_dimensions") or []),
                "remediation_templates": list(mapping.get("remediation_templates") or []),
                "audit_metadata": dict(mapping.get("audit_metadata") or {}),
            }
        )
    return matches


def _collect_controls_from_runtime_event(row: RuntimeEvent) -> list[str]:
    metadata = _safe_dict(row.metadata_json)
    controls: list[str] = []
    for key in ("triggered_controls", "related_control_ids", "mapped_controls", "control_ids"):
        controls.extend([_safe_str(item) for item in _safe_list(metadata.get(key)) if _safe_str(item)])
    return _normalize_controls(controls)


def _collect_controls_from_anomaly(row: MonitoringSignal) -> list[str]:
    payload = _safe_dict(row.payload)
    controls = [_safe_str(item) for item in _safe_list(payload.get("control_ids")) if _safe_str(item)]
    return _normalize_controls(controls)


def _simulation_key(definition: SimulationDefinition) -> str:
    dsl = _safe_dict(definition.dsl_json)
    return _safe_str(dsl.get("id")) or _safe_str(definition.id)


def _simulation_controls(definition: SimulationDefinition) -> list[str]:
    dsl = _safe_dict(definition.dsl_json)
    return _normalize_controls([str(item) for item in _safe_list(dsl.get("maps_to_controls"))])


def _normalize_run_result(value: Any) -> str:
    token = _safe_str(value).lower()
    if token in {"pass", "fail", "partial", "not_executable"}:
        return token
    if token in {"blocked", "block"}:
        return "pass"
    if token in {"allow", "allowed"}:
        return "fail"
    return "not_executable"


def build_agent_owasp_coverage(
    db: Session,
    *,
    tenant_id: str,
    agent_id: str,
    lookback_hours: int = 24 * 7,
) -> dict[str, Any]:
    normalized_agent_id = _safe_str(agent_id)
    if not normalized_agent_id:
        raise ValueError("agent_id is required")

    started_at = _started_at(lookback_hours)
    window_hours = max(1, min(24 * 180, int(lookback_hours or 24 * 7)))

    runtime_events = db.scalars(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.agent_id == normalized_agent_id,
            RuntimeEvent.created_at >= started_at,
        )
    ).all()

    anomaly_candidates = db.scalars(
        select(MonitoringSignal)
        .where(
            MonitoringSignal.tenant_id == tenant_id,
            MonitoringSignal.signal_type.like("ai_anomaly.%"),
            MonitoringSignal.created_at >= started_at,
        )
        .order_by(desc(MonitoringSignal.created_at))
    ).all()

    anomaly_rows: list[MonitoringSignal] = []
    for row in anomaly_candidates:
        payload = _safe_dict(row.payload)
        if _safe_str(payload.get("agent_id")) == normalized_agent_id:
            anomaly_rows.append(row)
            continue
        related_entities = _safe_list(payload.get("related_entities"))
        for entity in related_entities:
            if not isinstance(entity, dict):
                continue
            if _safe_str(entity.get("type")).lower() != "agent":
                continue
            if _safe_str(entity.get("id")) == normalized_agent_id:
                anomaly_rows.append(row)
                break

    definitions = db.scalars(
        select(SimulationDefinition).where(SimulationDefinition.tenant_id == tenant_id)
    ).all()
    definition_by_id = {row.id: row for row in definitions}

    run_rows = db.scalars(
        select(SimulationRun).where(
            SimulationRun.tenant_id == tenant_id,
            SimulationRun.started_at >= started_at,
        )
    ).all()

    agent_related_runs: list[SimulationRun] = []
    for run in run_rows:
        inputs_used = _safe_dict(run.inputs_used)
        run_agent_id = _safe_str(inputs_used.get("agent_id"))
        trigger_source = _safe_str(inputs_used.get("trigger_source"))
        if run_agent_id == normalized_agent_id or trigger_source == "ai_discovery_agent_security":
            agent_related_runs.append(run)

    catalog_rows = db.scalars(
        select(SimulationCatalogEntry).where(SimulationCatalogEntry.tenant_id == tenant_id)
    ).all()
    catalog_by_sim_id = {str(row.simulation_id): row for row in catalog_rows}

    event_controls_by_event_id: dict[str, set[str]] = {}
    all_event_controls: set[str] = set()
    for event in runtime_events:
        controls = set(_collect_controls_from_runtime_event(event))
        event_id = _safe_str(event.event_id)
        if event_id:
            event_controls_by_event_id[event_id] = controls
        all_event_controls.update(controls)

    anomaly_controls_by_id: dict[str, set[str]] = {}
    all_anomaly_controls: set[str] = set()
    for row in anomaly_rows:
        controls = set(_collect_controls_from_anomaly(row))
        row_id = _safe_str(row.id)
        if row_id:
            anomaly_controls_by_id[row_id] = controls
        all_anomaly_controls.update(controls)

    all_controls = sorted(all_event_controls.union(all_anomaly_controls))

    coverage_rows: list[dict[str, Any]] = []
    framework_counts: Counter[str] = Counter()
    runtime_active = 0
    simulation_active = 0

    for mapping in list_owasp_risk_mappings():
        controls = set(_normalize_controls([str(item) for item in list(mapping.get("controls") or [])]))
        matched_controls = sorted(controls.intersection(set(all_controls)))

        runtime_event_hits = sum(1 for event_controls in event_controls_by_event_id.values() if event_controls.intersection(controls))
        anomaly_hits = sum(1 for anomaly_controls in anomaly_controls_by_id.values() if anomaly_controls.intersection(controls))

        expected_sim_ids = [_safe_str(item) for item in list(mapping.get("simulations") or []) if _safe_str(item)]
        catalog_matches: list[SimulationCatalogEntry] = []
        for sim_id in expected_sim_ids:
            row = catalog_by_sim_id.get(sim_id)
            if row is not None:
                catalog_matches.append(row)
        if not catalog_matches:
            for row in catalog_rows:
                row_controls = set(_normalize_controls([str(item) for item in list(row.control_ids or [])]))
                if controls.intersection(row_controls):
                    catalog_matches.append(row)

        executable_now = sum(1 for row in catalog_matches if _safe_str(row.executable_status).lower() == "executable_now")
        partially_executable = sum(1 for row in catalog_matches if _safe_str(row.executable_status).lower() == "partially_executable")
        not_executable = max(0, len(catalog_matches) - executable_now - partially_executable)

        run_counters: Counter[str] = Counter()
        for run in agent_related_runs:
            definition = definition_by_id.get(run.simulation_id)
            if definition is None:
                continue
            sim_key = _simulation_key(definition)
            sim_controls = set(_simulation_controls(definition))
            sim_matches = (sim_key in expected_sim_ids) or bool(sim_controls.intersection(controls))
            if not sim_matches:
                continue
            result = _normalize_run_result(_safe_dict(run.results).get("result"))
            run_counters[result] += 1

        executable_results = run_counters.get("pass", 0) + run_counters.get("fail", 0) + run_counters.get("partial", 0)
        pass_rate = (run_counters.get("pass", 0) / executable_results) if executable_results else 0.0

        if runtime_event_hits or anomaly_hits:
            runtime_active += 1
        if executable_results:
            simulation_active += 1

        framework = str(mapping.get("framework") or "")
        framework_counts[framework] += 1

        if runtime_event_hits or anomaly_hits:
            coverage_status = "runtime_active"
        elif executable_results > 0:
            coverage_status = "simulation_active"
        elif executable_now > 0 or partially_executable > 0:
            coverage_status = "mapped_ready"
        else:
            coverage_status = "mapped_only"

        coverage_rows.append(
            {
                **mapping,
                "matched_controls": matched_controls,
                "mapped_catalog_simulations": sorted({_safe_str(row.simulation_id) for row in catalog_matches if _safe_str(row.simulation_id)}),
                "runtime_event_hits": runtime_event_hits,
                "anomaly_hits": anomaly_hits,
                "simulation_runs": {
                    "total": int(sum(run_counters.values())),
                    "pass": int(run_counters.get("pass", 0)),
                    "fail": int(run_counters.get("fail", 0)),
                    "partial": int(run_counters.get("partial", 0)),
                    "not_executable": int(run_counters.get("not_executable", 0)),
                },
                "simulation_pass_rate": round(pass_rate, 4),
                "defined_simulations": len(catalog_matches),
                "executable_simulations": executable_now,
                "partially_executable_simulations": partially_executable,
                "not_executable_simulations": not_executable,
                "coverage_status": coverage_status,
            }
        )

    summary = {
        "total_categories": len(coverage_rows),
        "framework_counts": dict(sorted(framework_counts.items(), key=lambda item: item[0].lower())),
        "runtime_active_categories": runtime_active,
        "simulation_active_categories": simulation_active,
        "controls_observed": all_controls,
        "controls_observed_count": len(all_controls),
        "runtime_events_considered": len(runtime_events),
        "anomalies_considered": len(anomaly_rows),
        "simulation_runs_considered": len(agent_related_runs),
    }

    return {
        "agent_id": normalized_agent_id,
        "window_hours": window_hours,
        "generated_at": _utcnow().isoformat(),
        "framework_registry": list_framework_registry(),
        "categories": coverage_rows,
        "summary": summary,
    }
