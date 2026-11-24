from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


RiskLevel = Literal["low", "med", "high", "critical"]
DiscoverySourceSurface = Literal["browser", "gateway", "agent", "connector", "dns", "proxy", "monitoring", "unknown"]


class AIUsageEvent(BaseModel):
    user_id: str | None = None
    device_id: str | None = None
    browser_type: str | None = None
    app_name: str
    model: str | None = None
    agent_id: str | None = None
    tool_used: str | None = None
    timestamp: datetime
    action_type: str
    source_surface: DiscoverySourceSurface = "unknown"
    risk_level: RiskLevel = "low"
    risk_score: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AIIdentityProfile(BaseModel):
    user_id: str
    display_name: str = ""
    email: str = ""
    devices: list[str] = Field(default_factory=list)
    browsers: list[str] = Field(default_factory=list)
    ai_apps: list[str] = Field(default_factory=list)
    agents: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    usage_patterns: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0
    anomaly_score: float = 0.0
    anomaly_count_7d: int = 0
