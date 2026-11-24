from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class MCPExecutionContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    user_role: str = Field(min_length=1)
    platform_mode: str = Field(min_length=1)
    correlation_id: str | None = None
    ai_system_id: str | None = None
    risk_tier: str | None = None
    governance_version: str | None = None
    policy_version_id: str | None = None
    brain_session_id: str | None = None
    brain_plan_id: str | None = None
