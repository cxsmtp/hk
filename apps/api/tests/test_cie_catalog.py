from __future__ import annotations

from types import MappingProxyType

from app.services.hmair.cie.catalog import (
    CAPABILITY_CATALOG,
    CAPABILITY_RULES,
    CATALOG_VERSION,
    RULESET_VERSION,
)


REQUIRED_CAPABILITIES = {
    "filesystem_read",
    "filesystem_write",
    "terminal_execution",
    "git_read",
    "git_write",
    "repository_access",
    "database_read",
    "database_write",
    "vector_search",
    "embedding_generation",
    "inference",
    "prompt_storage",
    "memory_storage",
    "code_execution",
    "browser_automation",
    "mcp_client",
    "mcp_server",
    "model_hosting",
    "model_invocation",
    "tool_invocation",
    "agent_framework",
    "scheduler",
    "workflow",
    "secret_access",
    "identity_change",
    "cloud_api",
    "container_management",
    "email_send",
    "slack_send",
    "webhook_creation",
    "persistent_memory",
    "ci_cd",
    "knowledge_base",
    "external_network",
    "model_routing",
    "rag",
    "fine_tuning",
    "human_approval",
}


def test_catalog_is_complete_immutable_and_versioned() -> None:
    assert isinstance(CAPABILITY_CATALOG, MappingProxyType)
    assert isinstance(CAPABILITY_RULES, MappingProxyType)
    assert set(CAPABILITY_CATALOG) == REQUIRED_CAPABILITIES
    assert CATALOG_VERSION
    assert RULESET_VERSION
    for capability_id, definition in CAPABILITY_CATALOG.items():
        assert definition.capability_id == capability_id
        assert definition.description
        assert definition.risk in {"low", "medium", "high", "critical"}
        assert definition.rule_ids
        assert definition.version == CATALOG_VERSION
        assert set(definition.rule_ids) <= set(CAPABILITY_RULES)


def test_catalog_rules_are_product_neutral_and_explicitly_calibrated() -> None:
    for rule_id, rule in CAPABILITY_RULES.items():
        assert rule.rule_id == rule_id
        assert rule.capability_id in CAPABILITY_CATALOG
        assert rule.calibration_version == "conservative-caps-v1"
        assert 0.0 < rule.base_confidence_cap < 1.0
        predicates = (
            tuple(rule.required_all)
            + tuple(item for group in rule.required_any for item in group)
            + tuple(rule.optional)
            + tuple(rule.contradictions)
        )
        assert not any(item.startswith("product:") for item in predicates)

