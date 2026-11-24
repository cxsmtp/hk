from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from pydantic import Field, ValidationError, field_validator, model_validator

from app.services.hmair.contracts import StrictContract
from app.services.hmair.exposure.contracts import ExposureDimension


_SEMVER_PATTERN = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
_SEMVER_RE = re.compile(_SEMVER_PATTERN)
DEFAULT_CATALOG_PATH = Path(__file__).with_name("catalog") / "exposure_categories.v1.json"
RECOMMENDATION_CAPABILITIES = frozenset(
    {
        "runtime_governance",
        "browser_governance",
        "mcp_restriction",
        "filesystem_restriction",
        "sandbox",
        "approval",
        "owner_assignment",
        "control_coverage",
        "identity_review",
        "personal_account_removal",
    }
)

# Reviewed source bindings for every customer-facing selector.  Values name the
# existing Hawk authority and exact source state/operation capable of producing
# the selector; they are documentation and validation material, not inference
# weights or executable policy.
EXPOSURE_CAPABILITY_SELECTOR_SOURCES = {
    "agent_execution": ("ai_action:agent_execution", "runtime_event:agent_execution"),
    "browser_automation": ("discovery_capability:browser_automation",),
    "cloud_admin": ("discovery_capability:cloud_admin",),
    "cloud_api": ("discovery_capability:cloud_api",),
    "code_execution": ("discovery_capability:code_execution", "ai_action:code_execution"),
    "credential_access": ("ai_action:credential_access", "runtime_event:credential_access"),
    "crm_access": ("ai_action:crm_access", "runtime_event:crm_access"),
    "customer_data_access": ("discovery_capability:customer_data_access",),
    "database_read": ("discovery_capability:database_read",),
    "database_write": ("discovery_capability:database_write",),
    "delegation": ("discovery_capability:delegation",),
    "developer_tooling": ("ai_action:developer_tooling", "runtime_event:developer_tooling"),
    "external_ai_access": ("ai_action:external_ai_access", "runtime_event:external_ai_access"),
    "external_data_retrieval": ("ai_action:external_data_retrieval", "runtime_event:external_data_retrieval"),
    "external_side_effect": ("ai_action:external_side_effect", "runtime_event:external_side_effect"),
    "filesystem_read": ("discovery_capability:filesystem_read",),
    "filesystem_write": ("discovery_capability:filesystem_write",),
    "financial_data_access": ("ai_action:financial_data_access", "runtime_event:financial_data_access"),
    "identity_change": ("discovery_capability:identity_change",),
    "inference": ("discovery_capability:inference",),
    "internet_access": ("discovery_capability:internet_access",),
    "knowledge_retrieval": ("discovery_capability:knowledge_retrieval",),
    "local_model_connection": ("ai_action:local_model_connection", "runtime_event:local_model_connection"),
    "mcp_client": ("discovery_capability:MCP_client",),
    "mcp_server": ("discovery_capability:MCP_server",),
    "mcp_tool_invocation": ("ai_action:mcp_tool_call", "runtime_event:mcp_tool_call"),
    "model_configuration": ("ai_action:model_configuration", "runtime_event:model_configuration"),
    "model_hosting": ("ai_action:model_hosting", "runtime_event:model_hosting"),
    "model_inference": ("discovery_capability:model_inference",),
    "payment_access": ("ai_action:payment_access", "runtime_event:payment_access"),
    "persistent_automation": ("discovery_capability:persistent_automation",),
    "persistent_side_effect": ("discovery_capability:persistent_side_effect",),
    "pii_access": ("ai_action:pii_access", "runtime_event:pii_access"),
    "process_execution": ("discovery_capability:process_execution",),
    "provider_api_access": ("ai_action:provider_api_access", "runtime_event:provider_api_access"),
    "query_execution": ("ai_action:query_execution", "runtime_event:query_execution"),
    "repository_access": ("discovery_capability:repository_access",),
    "resource_mutation": ("ai_action:resource_mutation", "runtime_event:resource_mutation"),
    "secret_access": ("discovery_capability:secret_access",),
    "token_access": ("ai_action:token_access", "runtime_event:token_access"),
    "trade_execution": ("ai_action:trade_execution", "runtime_event:trade_execution"),
    "unmanaged_ai_access": ("shadow_classification:unmanaged",),
    "unknown_ai_usage": ("shadow_classification:unknown_ai_workload",),
    "web_search": ("ai_action:web_search", "runtime_event:web_search"),
}
SUPPORTED_EXPOSURE_CAPABILITY_SELECTORS = frozenset(
    EXPOSURE_CAPABILITY_SELECTOR_SOURCES
)


class ExposureCategoryDefinition(StrictContract):
    category_id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    label: str = Field(min_length=1, max_length=128)
    version: str = Field(pattern=_SEMVER_PATTERN)
    description: str = Field(min_length=1, max_length=500)
    qualifying_capabilities: tuple[str, ...] = Field(max_length=64)
    required_dimensions: tuple[ExposureDimension, ...] = Field(min_length=1, max_length=16)
    optional_dimensions: tuple[ExposureDimension, ...] = Field(default=(), max_length=16)
    recommendation_capabilities: tuple[str, ...] = Field(default=(), max_length=16)

    @field_validator("qualifying_capabilities", "recommendation_capabilities")
    @classmethod
    def canonical_strings(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(item.strip() for item in value)))
        if any(not item or len(item) > 64 for item in normalized):
            raise ValueError("category selectors must be bounded non-empty strings")
        return normalized

    @field_validator("required_dimensions", "optional_dimensions")
    @classmethod
    def canonical_dimensions(cls, value: tuple[ExposureDimension, ...]) -> tuple[ExposureDimension, ...]:
        return tuple(sorted(set(value), key=lambda item: item.value))

    @model_validator(mode="after")
    def validate_definition(self) -> "ExposureCategoryDefinition":
        if self.category_id != "unknown_exposure" and not self.qualifying_capabilities:
            raise ValueError("every non-unknown category requires a qualifying capability")
        unsupported = set(self.recommendation_capabilities) - RECOMMENDATION_CAPABILITIES
        if unsupported:
            raise ValueError("category contains unsupported recommendation capabilities")
        unsupported_selectors = (
            set(self.qualifying_capabilities)
            - SUPPORTED_EXPOSURE_CAPABILITY_SELECTORS
        )
        if unsupported_selectors:
            raise ValueError("category contains unsupported capability selectors")
        if set(self.required_dimensions) & set(self.optional_dimensions):
            raise ValueError("required and optional dimensions must be disjoint")
        return self


class ExposureCategoryCatalog(StrictContract):
    catalog_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{2,127}$")
    version: str = Field(pattern=_SEMVER_PATTERN)
    categories: tuple[ExposureCategoryDefinition, ...] = Field(min_length=1, max_length=64)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")


def _canonical_payload(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def load_category_catalog(path: str | Path | None = None) -> ExposureCategoryCatalog:
    catalog_path = Path(path) if path is not None else DEFAULT_CATALOG_PATH
    try:
        raw = json.loads(catalog_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("catalog root must be an object")
        category_rows = raw.get("categories")
        if not isinstance(category_rows, list):
            raise ValueError("catalog categories must be a list")
        identifiers = [row.get("category_id") for row in category_rows if isinstance(row, dict)]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("duplicate category IDs")
        if any(
            isinstance(row, dict)
            and row.get("category_id") != "unknown_exposure"
            and not row.get("qualifying_capabilities")
            for row in category_rows
        ):
            raise ValueError("non-unknown category requires a qualifying capability")
        definitions = tuple(
            sorted(
                (ExposureCategoryDefinition.model_validate(row) for row in category_rows),
                key=lambda item: item.category_id,
            )
        )
        version = raw.get("version")
        if not isinstance(version, str) or _SEMVER_RE.fullmatch(version) is None:
            raise ValueError("catalog version must use semantic versioning")
        material = {
            "catalog_id": raw.get("catalog_id"),
            "version": version,
            "categories": [item.model_dump(mode="json") for item in definitions],
        }
        digest = hashlib.sha256(_canonical_payload(material)).hexdigest()
        return ExposureCategoryCatalog(**material, digest=digest)
    except ValueError as exc:
        if str(exc) in {
            "duplicate category IDs",
            "non-unknown category requires a qualifying capability",
        }:
            raise
        raise ValueError("invalid exposure category catalog") from None
    except (OSError, json.JSONDecodeError, ValidationError, TypeError):
        raise ValueError("invalid exposure category catalog") from None


__all__ = [
    "DEFAULT_CATALOG_PATH",
    "ExposureCategoryCatalog",
    "ExposureCategoryDefinition",
    "EXPOSURE_CAPABILITY_SELECTOR_SOURCES",
    "RECOMMENDATION_CAPABILITIES",
    "SUPPORTED_EXPOSURE_CAPABILITY_SELECTORS",
    "load_category_catalog",
]
