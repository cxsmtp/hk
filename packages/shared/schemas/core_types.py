from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class RiskTier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TenantRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    AUDITOR = "auditor"
    OPERATOR = "operator"
    VIEWER = "viewer"


class ActorType(str, Enum):
    HUMAN = "human"
    AGENT = "agent"
    SYSTEM = "system"


class Decision(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"
    REDACT = "redact"
    HOLD_FOR_APPROVAL = "hold_for_approval"


class DetectionConfidenceTier(str, Enum):
    CLEAR_NEGATIVE = "clear_negative"
    AMBIGUOUS = "ambiguous"
    CLEAR_POSITIVE = "clear_positive"


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


class Escalation(str, Enum):
    NONE = "none"
    NOTIFY = "notify"
    TICKET = "ticket"
    APPROVAL_REQUIRED = "approval_required"


class Timestamped(BaseModel):
    created_at: datetime
    updated_at: datetime | None = None


class Pagination(BaseModel):
    page: int = 1
    page_size: int = 50
    total: int = 0


class ApiResponse(BaseModel):
    data: Any
    meta: dict[str, Any] = Field(default_factory=dict)
