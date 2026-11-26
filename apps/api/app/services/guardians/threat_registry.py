from __future__ import annotations

from enum import Enum


class ThreatType(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SENSITIVE_DATA_LEAKAGE = "sensitive_data_leakage"
    TOOL_OUTPUT_INJECTION = "tool_output_injection"
    AGENT_CHAIN_ABUSE = "agent_chain_abuse"
    AI_IDENTITY_MISUSE = "ai_identity_misuse"
    ACTION_AUTH_ABUSE = "action_auth_abuse"
    RAG_POISONING = "rag_poisoning"
    CROSS_CONTEXT_LEAKAGE = "cross_context_leakage"
    OUTPUT_ASYMMETRY = "output_asymmetry"
    # Extended coverage: OWASP LLM Top 10 (2025), OWASP Agentic AI Top 10, MITRE ATLAS.
    SYSTEM_PROMPT_LEAKAGE = "system_prompt_leakage"
    ENCODING_OBFUSCATION = "encoding_obfuscation"
    EXCESSIVE_AGENCY = "excessive_agency"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CONTEXT_POISONING = "context_poisoning"
    GOAL_MANIPULATION = "goal_manipulation"
    IDENTITY_SPOOFING = "identity_spoofing"
    DECEPTIVE_BEHAVIOR = "deceptive_behavior"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    CODE_EXECUTION = "code_execution"
    TOOL_POISONING = "tool_poisoning"
    MEMORY_POISONING = "memory_poisoning"


THREAT_TYPE_TO_GUARDIAN_CONTRACTS: dict[str, list[str]] = {
    ThreatType.PROMPT_INJECTION.value: [
        "prompt_injection",
        "prompt_injection_guard",
        "threat.detector.prompt_injection_engine",
    ],
    ThreatType.JAILBREAK.value: [
        "jailbreak",
        "prompt_injection_guard",
        "threat.detector.prompt_injection_engine",
    ],
    ThreatType.SENSITIVE_DATA_LEAKAGE.value: [
        "sensitive_data_leakage",
        "sensitive_data_leakage_guard",
        "sensitive_data_leak_guard",
    ],
    ThreatType.TOOL_OUTPUT_INJECTION.value: [
        "tool_output_injection",
        "tool_output_injection_guard",
    ],
    ThreatType.AGENT_CHAIN_ABUSE.value: [
        "tool_output_injection_guard",
    ],
    ThreatType.AI_IDENTITY_MISUSE.value: [
        "cross_context_leakage_stub",
    ],
    ThreatType.ACTION_AUTH_ABUSE.value: [
        "cross_context_leakage_stub",
    ],
    ThreatType.RAG_POISONING.value: [
        "rag_poisoning_stub",
    ],
    ThreatType.CROSS_CONTEXT_LEAKAGE.value: [
        "cross_context_leakage_stub",
    ],
    ThreatType.OUTPUT_ASYMMETRY.value: [
        "tool_output_injection",
        "tool_output_injection_guard",
    ],
    ThreatType.SYSTEM_PROMPT_LEAKAGE.value: [
        "threat.detector.system_prompt_extraction",
    ],
    ThreatType.ENCODING_OBFUSCATION.value: [
        "threat.detector.encoding_obfuscation",
        "threat.detector.structural_obfuscation",
    ],
    ThreatType.EXCESSIVE_AGENCY.value: [
        "threat.detector.excessive_agency_destructive",
    ],
    ThreatType.PRIVILEGE_ESCALATION.value: [
        "threat.detector.privilege_escalation",
    ],
    ThreatType.CONTEXT_POISONING.value: [
        "threat.detector.context_poisoning",
    ],
    ThreatType.GOAL_MANIPULATION.value: [
        "threat.detector.goal_manipulation",
    ],
    ThreatType.IDENTITY_SPOOFING.value: [
        "threat.detector.identity_spoofing",
    ],
    ThreatType.DECEPTIVE_BEHAVIOR.value: [
        "threat.detector.deceptive_repudiation",
    ],
    ThreatType.RESOURCE_EXHAUSTION.value: [
        "threat.detector.resource_exhaustion",
    ],
    ThreatType.CODE_EXECUTION.value: [
        "threat.detector.insecure_output_code_exec",
    ],
    ThreatType.TOOL_POISONING.value: [
        "threat.detector.tool_output_injection",
    ],
    ThreatType.MEMORY_POISONING.value: [
        "threat.detector.rag_poisoning",
    ],
}


def get_threat_registry() -> dict[str, list[str]]:
    return {threat_type: list(contract_ids) for threat_type, contract_ids in THREAT_TYPE_TO_GUARDIAN_CONTRACTS.items()}


def guardian_contract_to_threat_types(guardian_contract_id: str) -> list[str]:
    contract_id = str(guardian_contract_id or "").strip()
    if not contract_id:
        return []
    out: list[str] = []
    for threat_type, contract_ids in THREAT_TYPE_TO_GUARDIAN_CONTRACTS.items():
        if contract_id in contract_ids and threat_type not in out:
            out.append(threat_type)
    return out


def threat_type_to_guardian_contracts(threat_type: str) -> list[str]:
    key = str(threat_type or "").strip().lower()
    return list(THREAT_TYPE_TO_GUARDIAN_CONTRACTS.get(key, []))
