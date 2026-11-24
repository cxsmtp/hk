from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class AGUIExecutionContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1)
    user_id: str = Field(min_length=1)
    user_role: str = Field(min_length=1)
    correlation_id: str | None = None
    evidence_displayed: bool = False
    diff_preview_displayed: bool = False
