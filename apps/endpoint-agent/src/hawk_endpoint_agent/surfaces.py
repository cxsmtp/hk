"""Endpoint adapter capability registry.

The endpoint surface is additive. It collaborates with browser, gateway, SDK,
and provider-native controls and earns coverage only for adapter paths evidenced
on an action. Registry entries describe capability, not current coverage.
"""

from __future__ import annotations

from dataclasses import dataclass


class Surface:
    LLM = "llm"
    MCP = "mcp"
    AI_AGENT = "ai_agent"
    BROWSER = "browser"
    SDK = "sdk"
    DEVELOPER_AGENT = "developer_agent"
    FOUNDRY = "foundry"
    DESKTOP_NATIVE = "desktop_native"
    SAAS = "saas"
    DATA_TRANSFER = "data_transfer"
    NOTETAKER = "notetaker"
    AI_IDENTITY = "ai_identity"


@dataclass(frozen=True)
class SurfaceCoverage:
    surface: str
    description: str
    hawk_endpoint: str
    module: str
    collaborates_with: tuple[str, ...]
    inline_capable: bool


COVERAGE: tuple[SurfaceCoverage, ...] = (
    SurfaceCoverage(
        Surface.LLM,
        "LLM prompt/response DLP and threat evaluation on a verified route",
        "/gateway/llm/intercept",
        "interaction_security",
        ("llm-gateway", "hawk-sdk"),
        True,
    ),
    SurfaceCoverage(
        Surface.MCP,
        "MCP tool-call authorization on a managed client route",
        "/gateway/mcp/authorize",
        "agent_runtime",
        ("mcp-gateway",),
        True,
    ),
    SurfaceCoverage(
        Surface.AI_AGENT,
        "On-device autonomous-agent action authorization",
        "/gateway/mcp/authorize",
        "agent_runtime",
        ("mcp-gateway", "hawk-sdk"),
        True,
    ),
    SurfaceCoverage(
        Surface.BROWSER,
        "Browser-native AI interaction through the managed companion",
        "/gateway/llm/intercept",
        "interaction_security",
        ("browser-extension",),
        True,
    ),
    SurfaceCoverage(
        Surface.SDK,
        "Explicitly instrumented SDK or verified local provider route",
        "/gateway/llm/intercept",
        "interaction_security",
        ("hawk-sdk", "llm-gateway"),
        True,
    ),
    SurfaceCoverage(
        Surface.DEVELOPER_AGENT,
        "Supported IDE or CLI developer-agent action authorization",
        "/gateway/mcp/authorize",
        "agent_runtime",
        ("mcp-gateway", "hawk-sdk"),
        True,
    ),
    SurfaceCoverage(
        Surface.FOUNDRY,
        "Endpoint-originated Foundry/provider-bound request classification",
        "/gateway/llm/intercept",
        "interaction_security",
        ("provider-native", "llm-gateway"),
        True,
    ),
    SurfaceCoverage(
        Surface.DESKTOP_NATIVE,
        "AI-capable native desktop application activity",
        "/gateway/llm/intercept",
        "desktop_native",
        ("llm-gateway",),
        True,
    ),
    SurfaceCoverage(
        Surface.SAAS,
        "SaaS AI application discovery from endpoint signals",
        "/telemetry/browser",
        "shadow_ai",
        ("browser-extension",),
        False,
    ),
    SurfaceCoverage(
        Surface.DATA_TRANSFER,
        "Copy, paste, upload, and download policy evaluation",
        "/runtime-control/data-transfer-check",
        "data_transfer",
        ("browser-extension",),
        True,
    ),
    SurfaceCoverage(
        Surface.NOTETAKER,
        "AI meeting-notetaker detection and supported eviction",
        "/endpoint-agent/notetaker/evaluate",
        "notetaker",
        (),
        True,
    ),
    SurfaceCoverage(
        Surface.AI_IDENTITY,
        "Human and non-human identity binding evidence",
        "/ai-iam/agents",
        "identity",
        (),
        False,
    ),
)

_BY_SURFACE = {item.surface: item for item in COVERAGE}


def coverage_for(surface: str) -> SurfaceCoverage | None:
    return _BY_SURFACE.get(surface)


def coverage_manifest() -> list[dict[str, object]]:
    return [
        {
            "surface": item.surface,
            "description": item.description,
            "hawk_endpoint": item.hawk_endpoint,
            "module": item.module,
            "collaborates_with": list(item.collaborates_with),
            "inline_capable": item.inline_capable,
        }
        for item in COVERAGE
    ]


def replaces_components() -> list[str]:
    """Compatibility shim: Endpoint Inline Control replaces no Hawk surface."""
    return []
