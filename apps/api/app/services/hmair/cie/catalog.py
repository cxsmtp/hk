from __future__ import annotations

from types import MappingProxyType

from app.services.hmair.cie.contracts import (
    CapabilityDefinition,
    CapabilityFamily,
    CapabilityRule,
)


CATALOG_VERSION = "2026.08.16.1"
RULESET_VERSION = "2026.08.16.1"
CALIBRATION_VERSION = "conservative-caps-v1"


_CAPABILITY_MATERIAL: dict[str, tuple[CapabilityFamily, str, str]] = {
    "filesystem_read": (CapabilityFamily.INFRASTRUCTURE, "high", "Reads files or file-backed resources."),
    "filesystem_write": (CapabilityFamily.INFRASTRUCTURE, "high", "Creates or modifies files or file-backed resources."),
    "terminal_execution": (CapabilityFamily.DEVOPS, "critical", "Executes commands through a terminal or interpreter."),
    "git_read": (CapabilityFamily.CODING, "medium", "Reads version-control repository state."),
    "git_write": (CapabilityFamily.CODING, "high", "Changes version-control repository state."),
    "repository_access": (CapabilityFamily.CODING, "high", "Accesses a source-code or content repository."),
    "database_read": (CapabilityFamily.DATA_SCIENCE, "high", "Reads records from a database."),
    "database_write": (CapabilityFamily.DATA_SCIENCE, "critical", "Creates, changes, or deletes database records."),
    "vector_search": (CapabilityFamily.RAG, "medium", "Searches a vector index or embedding store."),
    "embedding_generation": (CapabilityFamily.RAG, "medium", "Generates vector embeddings from input material."),
    "inference": (CapabilityFamily.MODEL_HOSTING, "medium", "Runs model inference."),
    "prompt_storage": (CapabilityFamily.MEMORY, "high", "Persists prompt or instruction material."),
    "memory_storage": (CapabilityFamily.MEMORY, "high", "Persists model or agent memory."),
    "code_execution": (CapabilityFamily.CODING, "critical", "Executes generated or selected code in a repository context."),
    "browser_automation": (CapabilityFamily.WORKFLOW_AUTOMATION, "high", "Automates browser navigation or interaction."),
    "mcp_client": (CapabilityFamily.WORKFLOW_AUTOMATION, "high", "Invokes tools exposed by an MCP server."),
    "mcp_server": (CapabilityFamily.INFRASTRUCTURE, "high", "Exposes tools or resources through MCP."),
    "model_hosting": (CapabilityFamily.MODEL_HOSTING, "critical", "Hosts a model-serving runtime."),
    "model_invocation": (CapabilityFamily.MODEL_HOSTING, "high", "Invokes an external or local model endpoint."),
    "tool_invocation": (CapabilityFamily.WORKFLOW_AUTOMATION, "high", "Invokes a declared tool or function."),
    "agent_framework": (CapabilityFamily.WORKFLOW_AUTOMATION, "high", "Coordinates model and tool activity through an agent runtime."),
    "scheduler": (CapabilityFamily.WORKFLOW_AUTOMATION, "high", "Schedules autonomous or recurring work."),
    "workflow": (CapabilityFamily.WORKFLOW_AUTOMATION, "high", "Coordinates a multi-step automated workflow."),
    "secret_access": (CapabilityFamily.SECURITY, "critical", "Accesses secret or credential material."),
    "identity_change": (CapabilityFamily.SECURITY, "critical", "Changes identity, membership, role, or entitlement state."),
    "cloud_api": (CapabilityFamily.CLOUD_ADMINISTRATION, "critical", "Invokes cloud control-plane or data-plane APIs."),
    "container_management": (CapabilityFamily.INFRASTRUCTURE, "critical", "Creates or changes container workloads."),
    "email_send": (CapabilityFamily.OFFICE_PRODUCTIVITY, "high", "Sends email or creates an email draft for delivery."),
    "slack_send": (CapabilityFamily.OFFICE_PRODUCTIVITY, "high", "Sends a Slack message or equivalent collaboration action."),
    "webhook_creation": (CapabilityFamily.WORKFLOW_AUTOMATION, "critical", "Creates or changes an outbound webhook."),
    "persistent_memory": (CapabilityFamily.MEMORY, "high", "Retains memory across sessions or executions."),
    "ci_cd": (CapabilityFamily.DEVOPS, "critical", "Changes or invokes a software delivery pipeline."),
    "knowledge_base": (CapabilityFamily.RAG, "high", "Reads or updates a governed knowledge base."),
    "external_network": (CapabilityFamily.INFRASTRUCTURE, "high", "Connects to a destination outside the governed local boundary."),
    "model_routing": (CapabilityFamily.MODEL_HOSTING, "high", "Selects or routes traffic across model providers or runtimes."),
    "rag": (CapabilityFamily.RAG, "high", "Combines retrieval evidence with model generation."),
    "fine_tuning": (CapabilityFamily.DATA_SCIENCE, "critical", "Creates or changes model weights through training or tuning."),
    "human_approval": (CapabilityFamily.SECURITY, "medium", "Requires a bound human approval before a consequential action."),
}


def _direct_rule(capability_id: str) -> CapabilityRule:
    family, _risk, description = _CAPABILITY_MATERIAL[capability_id]
    return CapabilityRule(
        rule_id=f"observed-{capability_id}-v1",
        version="1.0.0",
        capability_id=capability_id,
        required_all=(f"capability:{capability_id}",),
        required_any=(),
        optional=("usage_context",),
        contradictions=(f"capability_disabled:{capability_id}", "explicitly_disabled"),
        base_confidence_cap=0.98,
        recommended_asset_type="unknown_ai_candidate",
        recommended_ecosystem=family.value,
        explanation=f"Product-neutral discovery evidence supports this capability: {description}",
        calibration_version=CALIBRATION_VERSION,
    )


_rules: dict[str, CapabilityRule] = {
    rule.rule_id: rule for rule in (_direct_rule(item) for item in _CAPABILITY_MATERIAL)
}
_rules["coding-composition-v1"] = CapabilityRule(
    rule_id="coding-composition-v1",
    version="1.0.0",
    capability_id="code_execution",
    required_all=("repository_context", "execution_context", "model_context"),
    required_any=(),
    optional=("usage_context", "identity_context"),
    contradictions=("explicitly_disabled", "execution_denied"),
    base_confidence_cap=0.98,
    recommended_asset_type="agent",
    recommended_ecosystem="coding",
    explanation="Repository, execution, and model evidence support a coding capability.",
    calibration_version=CALIBRATION_VERSION,
)
_rules["rag-composition-v1"] = CapabilityRule(
    rule_id="rag-composition-v1",
    version="1.0.0",
    capability_id="rag",
    required_all=("vector_context", "model_context"),
    required_any=(("agent_framework_context", "retrieval_context"),),
    optional=("repository_context", "usage_context"),
    contradictions=("explicitly_disabled", "retrieval_disabled"),
    base_confidence_cap=0.98,
    recommended_asset_type="agent",
    recommended_ecosystem="retrieval_augmented_generation",
    explanation="Vector retrieval and model invocation are joined by an agent or retrieval runtime.",
    calibration_version=CALIBRATION_VERSION,
)
_rules["agent-composition-v1"] = CapabilityRule(
    rule_id="agent-composition-v1",
    version="1.0.0",
    capability_id="agent_framework",
    required_all=("model_context", "tool_context"),
    required_any=(("runtime_context", "execution_context"),),
    optional=("identity_context", "usage_context", "memory_context"),
    contradictions=("explicitly_disabled", "tool_execution_denied"),
    base_confidence_cap=0.96,
    recommended_asset_type="agent",
    recommended_ecosystem="agent_automation",
    explanation="Model, tool, and runtime evidence support an agent automation capability.",
    calibration_version=CALIBRATION_VERSION,
)


CAPABILITY_RULES = MappingProxyType(dict(sorted(_rules.items())))


_catalog: dict[str, CapabilityDefinition] = {}
for capability_id, (family, risk, description) in _CAPABILITY_MATERIAL.items():
    rule_ids = tuple(
        rule_id
        for rule_id, rule in CAPABILITY_RULES.items()
        if rule.capability_id == capability_id
    )
    _catalog[capability_id] = CapabilityDefinition(
        capability_id=capability_id,
        family=family,
        description=description,
        risk=risk,
        rule_ids=rule_ids,
        version=CATALOG_VERSION,
    )


CAPABILITY_CATALOG = MappingProxyType(dict(sorted(_catalog.items())))


__all__ = [
    "CALIBRATION_VERSION",
    "CAPABILITY_CATALOG",
    "CAPABILITY_RULES",
    "CATALOG_VERSION",
    "RULESET_VERSION",
]

