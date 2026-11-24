from __future__ import annotations

import hashlib
import json
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, model_validator


BankingTransport = Literal["function", "mcp", "toolbox", "rest", "openapi", "apim"]
class BankingTransportBinding(BaseModel):
    """Route-specific material that must remain bound until execution."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    transport: BankingTransport
    route_id: str = Field(min_length=1, max_length=256)
    authentication_mode: str = Field(min_length=1, max_length=64)
    direct_bypass: bool = False

    function_manifest_id: str | None = Field(default=None, min_length=1, max_length=256)

    mcp_server_id: str | None = Field(default=None, min_length=1, max_length=128)
    mcp_tool_name: str | None = Field(default=None, min_length=1, max_length=128)
    mcp_tool_version: str | None = Field(default=None, min_length=1, max_length=64)
    mcp_tool_fingerprint_id: str | None = Field(default=None, min_length=1, max_length=128)

    toolbox_id: str | None = Field(default=None, min_length=1, max_length=128)
    toolbox_version: str | None = Field(default=None, min_length=1, max_length=64)
    project_connection_id: str | None = Field(default=None, min_length=1, max_length=256)

    http_method: str | None = Field(default=None, min_length=1, max_length=16)
    route_template: str | None = Field(default=None, min_length=1, max_length=512)
    openapi_operation_id: str | None = Field(default=None, min_length=1, max_length=256)
    openapi_document_fingerprint: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
    )

    apim_api_id: str | None = Field(default=None, min_length=1, max_length=256)
    apim_revision: str | None = Field(default=None, min_length=1, max_length=64)
    apim_backend_id: str | None = Field(default=None, min_length=1, max_length=256)

    @model_validator(mode="after")
    def _require_transport_material(self) -> "BankingTransportBinding":
        required: dict[str, tuple[str, ...]] = {
            "function": ("function_manifest_id",),
            "mcp": (
                "mcp_server_id",
                "mcp_tool_name",
                "mcp_tool_version",
                "mcp_tool_fingerprint_id",
            ),
            "toolbox": (
                "toolbox_id",
                "toolbox_version",
                "project_connection_id",
                "mcp_server_id",
                "mcp_tool_name",
                "mcp_tool_version",
                "mcp_tool_fingerprint_id",
            ),
            "rest": ("http_method", "route_template"),
            "openapi": (
                "http_method",
                "route_template",
                "openapi_operation_id",
                "openapi_document_fingerprint",
            ),
            "apim": (
                "http_method",
                "route_template",
                "openapi_operation_id",
                "openapi_document_fingerprint",
                "apim_api_id",
                "apim_revision",
                "apim_backend_id",
            ),
        }
        missing = [name for name in required[self.transport] if not getattr(self, name)]
        if missing:
            raise ValueError(
                f"{self.transport} transport is missing required binding material: "
                + ", ".join(missing)
            )
        return self


class BankingTransportAction(BaseModel):
    """One business action plus the exact route selected to execute it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=64)
    ai_transaction_id: str = Field(min_length=1, max_length=64)
    action_id: str = Field(min_length=1, max_length=64)
    chain_id: str = Field(min_length=1, max_length=64)
    business_purpose_id: str = Field(min_length=1, max_length=128)
    operation_type: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(min_length=1, max_length=255)
    tool_version: str = Field(min_length=1, max_length=64)
    tool_schema_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    arguments: dict[str, Any]
    target_resource_type: str = Field(min_length=1, max_length=128)
    target_resource_reference: str = Field(min_length=1, max_length=512, repr=False)
    target_resolver_version: str = Field(min_length=1, max_length=128)
    destination: str = Field(min_length=1, max_length=512)
    identity_type: str = Field(min_length=1, max_length=128)
    side_effect_class: Literal["read_only", "reversible", "persistent"]
    persistent_side_effect: bool
    idempotency_key_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    transport_binding: BankingTransportBinding

    @model_validator(mode="after")
    def _validate_persistence_declaration(self) -> "BankingTransportAction":
        if self.side_effect_class == "persistent" and not self.persistent_side_effect:
            raise ValueError("persistent side effects must be declared explicitly")
        if self.side_effect_class != "persistent" and self.persistent_side_effect:
            raise ValueError("persistent side-effect declaration conflicts with its class")
        return self


class BankingTransportProjection(BaseModel):
    """Privacy-safe canonical material consumed by the existing Hawk policy path."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    semantic_action: dict[str, Any]
    semantic_action_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    execution_binding: dict[str, Any]
    execution_binding_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    identity_quality: str
    shared_authority: bool
    control_requirement_satisfied: bool
    reason_code: str


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _tenant_fingerprint(tenant_id: str, value: str) -> str:
    return _sha256(f"{tenant_id}\x00{value}".encode("utf-8"))


def _identity_claim(authentication_mode: str) -> tuple[str, bool]:
    claims = {
        "oauth_passthrough": ("verified_end_user", False),
        "agent_identity": ("dedicated_agent_identity", False),
        "project_managed_identity": ("project_shared_identity", True),
        "managed_identity": ("managed_workload_identity", True),
        "service_principal": ("service_principal", True),
        "shared_key": ("shared_credential", True),
        "api_key": ("shared_credential", True),
    }
    return claims.get(authentication_mode, ("unverified_authentication", True))


def _inventory_value(record: Mapping[str, Any] | Any, name: str) -> Any:
    if isinstance(record, Mapping):
        return record.get(name)
    return getattr(record, name, None)


def _mcp_inventory_reason(
    action: BankingTransportAction,
    mcp_inventory_record: Mapping[str, Any] | Any | None,
) -> str | None:
    binding = action.transport_binding
    if binding.transport not in {"mcp", "toolbox"}:
        return None
    if (
        binding.mcp_tool_name != action.tool_name
        or binding.mcp_tool_version != action.tool_version
    ):
        return "MCP_TOOL_FINGERPRINT_DRIFT"
    if mcp_inventory_record is None:
        return "MCP_INVENTORY_UNVERIFIED"

    expected = {
        "id": binding.mcp_tool_fingerprint_id,
        "mcp_server_id": binding.mcp_server_id,
        "tool_name": binding.mcp_tool_name,
        "tool_version": binding.mcp_tool_version,
        "schema_hash": action.tool_schema_fingerprint,
    }
    if any(_inventory_value(mcp_inventory_record, key) != value for key, value in expected.items()):
        return "MCP_TOOL_FINGERPRINT_DRIFT"
    if _inventory_value(mcp_inventory_record, "trust_status") != "approved":
        return "MCP_TOOL_NOT_APPROVED"
    if not _inventory_value(mcp_inventory_record, "approved_hash"):
        return "MCP_TOOL_NOT_APPROVED"
    return None


def canonicalize_banking_transport_action(
    action: BankingTransportAction,
    *,
    mcp_inventory_record: Mapping[str, Any] | Any | None = None,
) -> BankingTransportProjection:
    """Create one semantic action and a separate, exact execution-route binding.

    This function deliberately performs no policy evaluation. Its output is bound into
    Hawk's existing Decision Receipt and revalidated by the existing final gate.
    """

    arguments_hash = _sha256(_canonical_json(action.arguments))
    semantic_action: dict[str, Any] = {
        "business_purpose_id": action.business_purpose_id,
        "operation_type": action.operation_type,
        "tool_name": action.tool_name,
        "tool_version": action.tool_version,
        "tool_schema_fingerprint": action.tool_schema_fingerprint,
        "arguments_hash": arguments_hash,
        "target_resource_type": action.target_resource_type,
        "target_resource_fingerprint": _tenant_fingerprint(
            action.tenant_id,
            action.target_resource_reference,
        ),
        "target_resolver_version": action.target_resolver_version,
        "destination": action.destination,
        "identity_type": action.identity_type,
        "side_effect_class": action.side_effect_class,
        "persistent_side_effect": action.persistent_side_effect,
        "idempotency_key_hash": action.idempotency_key_hash,
    }
    semantic_action_hash = _sha256(_canonical_json(semantic_action))

    binding = action.transport_binding
    execution_binding = {
        key: value
        for key, value in binding.model_dump(mode="json").items()
        if value is not None
    }
    execution_binding["semantic_action_hash"] = semantic_action_hash
    execution_binding_hash = _sha256(_canonical_json(execution_binding))
    identity_quality, shared_authority = _identity_claim(binding.authentication_mode)

    reason_code = "TRANSPORT_BINDING_VERIFIED"
    requirement_satisfied = True
    if binding.direct_bypass:
        requirement_satisfied = False
        reason_code = "DIRECT_TRANSPORT_BYPASS"
    elif identity_quality == "unverified_authentication":
        requirement_satisfied = False
        reason_code = "TRANSPORT_AUTHENTICATION_UNVERIFIED"
    elif action.target_resource_reference.strip().lower() in {"unknown", "unresolved"}:
        requirement_satisfied = False
        reason_code = "TARGET_UNRESOLVED"
    else:
        inventory_reason = _mcp_inventory_reason(action, mcp_inventory_record)
        if inventory_reason is not None:
            requirement_satisfied = False
            reason_code = inventory_reason

    return BankingTransportProjection(
        semantic_action=semantic_action,
        semantic_action_hash=semantic_action_hash,
        execution_binding=execution_binding,
        execution_binding_hash=execution_binding_hash,
        identity_quality=identity_quality,
        shared_authority=shared_authority,
        control_requirement_satisfied=requirement_satisfied,
        reason_code=reason_code,
    )
