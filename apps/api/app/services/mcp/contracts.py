from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from app.services.mcp.context import MCPExecutionContext


RoleName = Literal["owner", "admin", "auditor", "operator", "viewer"]
SideEffectLevel = Literal["read", "analyze", "recommend", "write", "enforce", "export", "admin"]

class MCPExecutionObservation(BaseModel):
    """Post-callback facts captured by the MCP executor's execution observer.

    This is intentionally separate from the pre-execution authorization action:
    the registry can only create execution proof from this returned material.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    actual_args: dict[str, Any]
    tool_or_service_ref: str = Field(min_length=1)
    target_ref: str = Field(min_length=1)
    operation: str = Field(default="tool_execution", min_length=1)
    tool_fingerprint: str | None = None
    persistent_effect: dict[str, Any] | None = None
    expected_outcome: dict[str, Any] | None = None
    outcome_verification: dict[str, Any] | None = None
    delegated_child: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class MCPExecutionResult:
    """Internal result envelope for a tool output plus post-callback facts."""

    output: dict[str, Any]
    observation: MCPExecutionObservation | None = None


ToolExecutor = Callable[[Session, MCPExecutionContext, dict[str, Any]], dict[str, Any] | MCPExecutionResult]
MCPExecutionObserver = Callable[[Session, MCPExecutionContext, dict[str, Any]], MCPExecutionObservation | None]


class ToolContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_name: str = Field(min_length=1)
    module: str = Field(min_length=1)
    version: str = Field(min_length=1)
    description: str = Field(min_length=1)
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    required_role: list[RoleName] = Field(min_length=1)
    requires_approval: bool
    writes_evidence: bool
    side_effect_level: SideEffectLevel
    citations_supported: bool
    governance_scope_required: bool
    tenant_scope_required: bool
    idempotent: bool
    timeout_ms: int = Field(ge=1, le=120000)

    @field_validator("version")
    @classmethod
    def _validate_semver(cls, value: str) -> str:
        if not re.fullmatch(r"\d+\.\d+\.\d+", value):
            raise ValueError("version must be semver, for example 1.0.0")
        return value

    @field_validator("input_schema", "output_schema")
    @classmethod
    def _validate_schema_root(cls, value: dict[str, Any]) -> dict[str, Any]:
        schema_type = str(value.get("type", "")).strip().lower()
        if schema_type != "object":
            raise ValueError("schema root type must be 'object'")
        return value

    @field_validator("required_role")
    @classmethod
    def _validate_required_role(cls, value: list[RoleName]) -> list[RoleName]:
        deduped = []
        for item in value:
            if item not in deduped:
                deduped.append(item)
        if not deduped:
            raise ValueError("required_role must not be empty")
        return deduped


class ToolRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    contract: ToolContract
    executor: ToolExecutor = Field(exclude=True, repr=False)
    execution_observer: MCPExecutionObserver | None = Field(default=None, exclude=True, repr=False)
