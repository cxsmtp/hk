from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from app.services.agui.context import AGUIExecutionContext


RoleName = Literal["owner", "admin", "auditor", "operator", "viewer"]
SideEffectLevel = Literal["read", "analyze", "recommend", "write", "enforce", "export", "admin"]
AGUIExecutor = Callable[
    [Session, AGUIExecutionContext, "AGUIActionContract", str, Optional[str], list[str], dict[str, Any]],
    Optional[dict[str, Any]],
]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AGUIActionContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str = Field(min_length=1)
    action_type: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    source_module: str = Field(min_length=1)
    source_object_type: str = Field(min_length=1)
    source_object_id: str = Field(min_length=1)
    required_role: list[RoleName] = Field(min_length=1)
    decision_options: list[str] = Field(min_length=1)
    requires_justification: bool
    requires_evidence_display: bool
    requires_diff_preview: bool
    side_effect_level: SideEffectLevel
    created_at: datetime = Field(default_factory=_utcnow)

    @field_validator("action_id", "action_type", "source_module", "source_object_type")
    @classmethod
    def _validate_compact_identifier(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("identifier fields must not be empty")
        return cleaned

    @field_validator("required_role")
    @classmethod
    def _validate_roles(cls, value: list[RoleName]) -> list[RoleName]:
        deduped: list[RoleName] = []
        for item in value:
            if item not in deduped:
                deduped.append(item)
        if not deduped:
            raise ValueError("required_role must not be empty")
        return deduped

    @field_validator("decision_options")
    @classmethod
    def _validate_decision_options(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for raw in value:
            item = str(raw).strip()
            if not item or item in seen:
                continue
            seen.add(item)
            cleaned.append(item)
        if not cleaned:
            raise ValueError("decision_options must not be empty")
        return cleaned


class AGUIDecisionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_id: str
    action_id: str
    decision: str
    justification: str | None = None
    decided_by: str
    decided_at: datetime
    correlation_id: str | None = None
    evidence_node_ids: list[str] = Field(default_factory=list)
    audit_log_id: str


class AGUIActionRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    contract: AGUIActionContract
    executor: Optional[AGUIExecutor] = Field(default=None, exclude=True, repr=False)
