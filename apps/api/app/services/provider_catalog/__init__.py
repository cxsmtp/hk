from __future__ import annotations

from dataclasses import asdict, dataclass
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse


SOURCE_SURFACES = (
    "browser",
    "gateway",
    "connector",
    "aiiam",
    "endpoint",
    "dns",
    "proxy",
    "monitoring",
    "foundry",
    "copilot",
)
ENFORCEMENT_CAPABLE_SURFACES = ("browser", "gateway", "aiiam")
MONITORING_ONLY_SURFACES = ("connector", "endpoint", "dns", "proxy", "monitoring", "foundry", "copilot")
PROVIDER_TYPES = ("saas_ai", "model_api", "local_model", "agent_framework", "embedded_copilot", "agentic_platform")


@dataclass(frozen=True)
class ProviderCatalogObject:
    provider_id: str
    canonical_name: str
    provider_type: str
    deployment_surfaces: tuple[str, ...]
    known_domains: tuple[str, ...]
    known_api_endpoints: tuple[str, ...]
    known_process_names: tuple[str, ...]
    known_model_names: tuple[str, ...]
    known_tool_names: tuple[str, ...]
    aliases: tuple[str, ...]
    trust_level: str
    default_risk_hint: str


CATALOG: tuple[ProviderCatalogObject, ...] = (
    # Browser / SaaS AI
    ProviderCatalogObject(
        provider_id="openai_chatgpt",
        canonical_name="OpenAI ChatGPT",
        provider_type="saas_ai",
        deployment_surfaces=("browser", "connector", "proxy", "dns"),
        known_domains=("chat.openai.com", "*.chatgpt.com"),
        known_api_endpoints=("/backend-api/",),
        known_process_names=(),
        known_model_names=("gpt-4o", "gpt-4.1", "gpt-4", "gpt-3.5"),
        known_tool_names=("chatgpt", "openai chat"),
        aliases=("openai", "chatgpt"),
        trust_level="unknown",
        default_risk_hint="HIGH",
    ),
    ProviderCatalogObject(
        provider_id="anthropic_claude",
        canonical_name="Anthropic Claude",
        provider_type="saas_ai",
        deployment_surfaces=("browser", "connector", "proxy", "dns"),
        known_domains=("claude.ai",),
        known_api_endpoints=("/api/organizations/",),
        known_process_names=(),
        known_model_names=("claude-3", "claude-3.5", "claude-3.7", "claude-4"),
        known_tool_names=("claude",),
        aliases=("anthropic",),
        trust_level="unknown",
        default_risk_hint="HIGH",
    ),
    ProviderCatalogObject(
        provider_id="google_gemini",
        canonical_name="Google Gemini",
        provider_type="saas_ai",
        deployment_surfaces=("browser", "connector", "proxy", "dns"),
        known_domains=("gemini.google.com",),
        known_api_endpoints=("/app",),
        known_process_names=(),
        known_model_names=("gemini-pro", "gemini-1.5", "gemini-2.0"),
        known_tool_names=("gemini",),
        aliases=("google gemini",),
        trust_level="unknown",
        default_risk_hint="HIGH",
    ),
    ProviderCatalogObject(
        provider_id="microsoft_copilot",
        canonical_name="Microsoft Copilot",
        provider_type="embedded_copilot",
        deployment_surfaces=("browser", "connector", "proxy", "dns", "endpoint", "copilot"),
        known_domains=("copilot.microsoft.com", "m365.cloud.microsoft"),
        known_api_endpoints=("/copilot/", "/m365copilot/"),
        known_process_names=("copilot",),
        known_model_names=(),
        known_tool_names=("copilot", "m365 copilot", "microsoft 365 copilot"),
        aliases=("microsoft copilot", "copilot", "m365 copilot", "office copilot"),
        trust_level="unknown",
        default_risk_hint="MEDIUM",
    ),
    ProviderCatalogObject(
        provider_id="microsoft_copilot_studio",
        canonical_name="Microsoft Copilot Studio",
        provider_type="agentic_platform",
        deployment_surfaces=("copilot", "connector", "browser", "proxy", "dns"),
        known_domains=("copilotstudio.microsoft.com", "powerva.microsoft.com", "make.powerapps.com", "powerplatform.microsoft.com"),
        known_api_endpoints=("/copilotstudio/", "/bots/", "/agents/"),
        known_process_names=("copilot-studio", "power-virtual-agents"),
        known_model_names=(),
        known_tool_names=("copilot studio", "copilot studio agent", "power virtual agents"),
        aliases=("copilot studio", "microsoft copilot studio", "power virtual agents"),
        trust_level="unknown",
        default_risk_hint="HIGH",
    ),
    ProviderCatalogObject(
        provider_id="slack_ai",
        canonical_name="Slack AI",
        provider_type="embedded_copilot",
        deployment_surfaces=("browser", "connector", "proxy", "dns"),
        known_domains=("slack.com", "*.slack-msgs.com"),
        known_api_endpoints=("/api/ai.",),
        known_process_names=(),
        known_model_names=(),
        known_tool_names=("slack ai",),
        aliases=("slack",),
        trust_level="unknown",
        default_risk_hint="HIGH",
    ),
    ProviderCatalogObject(
        provider_id="notion_ai",
        canonical_name="Notion AI",
        provider_type="embedded_copilot",
        deployment_surfaces=("browser", "connector", "proxy", "dns", "endpoint"),
        known_domains=("notion.so", "*.notion.so"),
        known_api_endpoints=("/api/v3/",),
        known_process_names=("notion",),
        known_model_names=(),
        known_tool_names=("notion ai",),
        aliases=("notion",),
        trust_level="unknown",
        default_risk_hint="MEDIUM",
    ),
    ProviderCatalogObject(
        provider_id="salesforce_einstein",
        canonical_name="Salesforce Einstein",
        provider_type="embedded_copilot",
        deployment_surfaces=("browser", "connector", "proxy", "dns"),
        known_domains=("salesforce.com", "*.my.salesforce.com"),
        known_api_endpoints=("/einstein/",),
        known_process_names=(),
        known_model_names=(),
        known_tool_names=("einstein", "einstein copilot"),
        aliases=("salesforce einstein", "einstein"),
        trust_level="unknown",
        default_risk_hint="HIGH",
    ),
    ProviderCatalogObject(
        provider_id="perplexity",
        canonical_name="Perplexity",
        provider_type="saas_ai",
        deployment_surfaces=("browser", "proxy", "dns"),
        known_domains=("perplexity.ai",),
        known_api_endpoints=(),
        known_process_names=(),
        known_model_names=(),
        known_tool_names=("perplexity",),
        aliases=("perplexity ai",),
        trust_level="unknown",
        default_risk_hint="HIGH",
    ),
    # API / model providers
    ProviderCatalogObject(
        provider_id="openai_api",
        canonical_name="OpenAI API",
        provider_type="model_api",
        deployment_surfaces=("gateway", "proxy", "dns", "endpoint", "connector"),
        known_domains=("api.openai.com",),
        known_api_endpoints=("/v1/chat/completions", "/v1/responses", "/v1/embeddings"),
        known_process_names=("openai",),
        known_model_names=("gpt-4o", "gpt-4.1", "o1", "o3"),
        known_tool_names=("openai api",),
        aliases=("openai",),
        trust_level="trusted",
        default_risk_hint="MEDIUM",
    ),
    ProviderCatalogObject(
        provider_id="anthropic_api",
        canonical_name="Anthropic API",
        provider_type="model_api",
        deployment_surfaces=("gateway", "proxy", "dns", "endpoint", "connector"),
        known_domains=("api.anthropic.com",),
        known_api_endpoints=("/v1/messages",),
        known_process_names=("anthropic",),
        known_model_names=("claude-3", "claude-4"),
        known_tool_names=("anthropic api",),
        aliases=("anthropic",),
        trust_level="trusted",
        default_risk_hint="MEDIUM",
    ),
    ProviderCatalogObject(
        provider_id="google_gemini_api",
        canonical_name="Google Gemini API",
        provider_type="model_api",
        deployment_surfaces=("gateway", "proxy", "dns", "endpoint", "connector"),
        known_domains=("generativelanguage.googleapis.com", "aiplatform.googleapis.com"),
        known_api_endpoints=("/v1beta/models/", "/v1/models/"),
        known_process_names=("gemini",),
        known_model_names=("gemini-1.5", "gemini-2.0"),
        known_tool_names=("gemini api",),
        aliases=("gemini api", "google ai studio"),
        trust_level="trusted",
        default_risk_hint="MEDIUM",
    ),
    ProviderCatalogObject(
        provider_id="azure_openai_api",
        canonical_name="Azure OpenAI",
        provider_type="model_api",
        deployment_surfaces=("gateway", "proxy", "dns", "endpoint", "connector"),
        known_domains=("*.openai.azure.com",),
        known_api_endpoints=("/openai/deployments/",),
        known_process_names=("azure-openai", "azure openai"),
        known_model_names=("gpt-4o", "gpt-4.1"),
        known_tool_names=("azure openai",),
        aliases=("azure openai",),
        trust_level="trusted",
        default_risk_hint="MEDIUM",
    ),
    ProviderCatalogObject(
        provider_id="microsoft_foundry",
        canonical_name="Microsoft Foundry",
        provider_type="agentic_platform",
        deployment_surfaces=("gateway", "foundry", "connector", "proxy", "dns"),
        known_domains=("ai.azure.com", "*.services.ai.azure.com", "*.cognitiveservices.azure.com"),
        known_api_endpoints=("/projects/", "/agents/", "/assistants/", "/threads/", "/runs/", "/foundry/"),
        known_process_names=("azure-ai-foundry", "microsoft-foundry"),
        known_model_names=("gpt-4o", "gpt-4.1"),
        known_tool_names=("azure ai foundry", "microsoft foundry", "foundry agent", "azure ai agent"),
        aliases=("microsoft foundry", "azure ai foundry", "azure foundry", "foundry"),
        trust_level="trusted",
        default_risk_hint="HIGH",
    ),
    ProviderCatalogObject(
        provider_id="mistral_api",
        canonical_name="Mistral API",
        provider_type="model_api",
        deployment_surfaces=("gateway", "proxy", "dns", "endpoint", "connector"),
        known_domains=("api.mistral.ai",),
        known_api_endpoints=("/v1/chat/completions", "/v1/embeddings"),
        known_process_names=("mistral",),
        known_model_names=("mistral-large", "mixtral", "codestral"),
        known_tool_names=("mistral api",),
        aliases=("mistral",),
        trust_level="unknown",
        default_risk_hint="MEDIUM",
    ),
    # OSS / local inference
    ProviderCatalogObject(
        provider_id="mistral_self_hosted",
        canonical_name="Mistral (Self-hosted)",
        provider_type="local_model",
        deployment_surfaces=("endpoint", "proxy", "dns", "gateway"),
        known_domains=("localhost", "127.0.0.1"),
        known_api_endpoints=("/mistral/",),
        known_process_names=("mistral-server", "mistral"),
        known_model_names=("mistral", "mixtral"),
        known_tool_names=("self-hosted mistral",),
        aliases=("mistral self hosted",),
        trust_level="unknown",
        default_risk_hint="HIGH",
    ),
    ProviderCatalogObject(
        provider_id="huggingface_inference",
        canonical_name="Hugging Face Inference Endpoints",
        provider_type="model_api",
        deployment_surfaces=("gateway", "proxy", "dns", "endpoint"),
        known_domains=("api-inference.huggingface.co", "*.hf.space", "huggingface.co"),
        known_api_endpoints=("/models/", "/pipeline/"),
        known_process_names=("huggingface",),
        known_model_names=("llama", "mistral", "mixtral"),
        known_tool_names=("huggingface inference",),
        aliases=("hf inference", "huggingface"),
        trust_level="unknown",
        default_risk_hint="MEDIUM",
    ),
    ProviderCatalogObject(
        provider_id="ollama",
        canonical_name="Ollama",
        provider_type="local_model",
        deployment_surfaces=("endpoint", "proxy", "dns", "gateway"),
        known_domains=("localhost", "127.0.0.1"),
        known_api_endpoints=(":11434", "/api/generate", "/api/chat"),
        known_process_names=("ollama",),
        known_model_names=("llama3", "mistral", "qwen"),
        known_tool_names=("ollama",),
        aliases=("ollama runtime",),
        trust_level="unknown",
        default_risk_hint="HIGH",
    ),
    ProviderCatalogObject(
        provider_id="vllm",
        canonical_name="vLLM",
        provider_type="local_model",
        deployment_surfaces=("endpoint", "proxy", "gateway"),
        known_domains=("localhost", "127.0.0.1"),
        known_api_endpoints=("/v1/completions", "/v1/chat/completions"),
        known_process_names=("vllm",),
        known_model_names=("llama", "mistral", "qwen"),
        known_tool_names=("vllm",),
        aliases=("vllm server",),
        trust_level="unknown",
        default_risk_hint="HIGH",
    ),
    ProviderCatalogObject(
        provider_id="llama_cpp",
        canonical_name="llama.cpp",
        provider_type="local_model",
        deployment_surfaces=("endpoint", "proxy"),
        known_domains=("localhost", "127.0.0.1"),
        known_api_endpoints=("/completion", "/v1/chat/completions"),
        known_process_names=("llama.cpp", "llama-server"),
        known_model_names=("llama", "gguf"),
        known_tool_names=("llama.cpp",),
        aliases=("llama cpp",),
        trust_level="unknown",
        default_risk_hint="HIGH",
    ),
    ProviderCatalogObject(
        provider_id="tgi",
        canonical_name="Text Generation Inference (TGI)",
        provider_type="local_model",
        deployment_surfaces=("endpoint", "proxy", "gateway"),
        known_domains=("localhost", "127.0.0.1"),
        known_api_endpoints=("/generate", "/generate_stream"),
        known_process_names=("text-generation-launcher", "tgi"),
        known_model_names=("llama", "mistral"),
        known_tool_names=("tgi", "text generation inference"),
        aliases=("hf tgi",),
        trust_level="unknown",
        default_risk_hint="HIGH",
    ),
    ProviderCatalogObject(
        provider_id="litellm",
        canonical_name="LiteLLM",
        provider_type="local_model",
        deployment_surfaces=("endpoint", "proxy", "gateway"),
        known_domains=("localhost", "127.0.0.1"),
        known_api_endpoints=("/chat/completions", "/v1/chat/completions"),
        known_process_names=("litellm",),
        known_model_names=(),
        known_tool_names=("litellm", "litellm proxy"),
        aliases=("litellm proxy",),
        trust_level="unknown",
        default_risk_hint="HIGH",
    ),
    ProviderCatalogObject(
        provider_id="local_inference_generic",
        canonical_name="Generic Local Inference",
        provider_type="local_model",
        deployment_surfaces=("endpoint", "proxy", "gateway", "dns"),
        known_domains=("localhost", "127.0.0.1"),
        known_api_endpoints=("/v1/", "/generate", "/completions"),
        known_process_names=("python", "node", "uvicorn"),
        known_model_names=("llama", "mistral", "qwen", "gemma"),
        known_tool_names=("local inference",),
        aliases=("self hosted llm", "oss model"),
        trust_level="unknown",
        default_risk_hint="HIGH",
    ),
    # Agent / framework surfaces
    ProviderCatalogObject(
        provider_id="mcp_tools",
        canonical_name="MCP Tools/Servers",
        provider_type="agent_framework",
        deployment_surfaces=("gateway", "aiiam", "endpoint"),
        known_domains=(),
        known_api_endpoints=("/gateway/mcp/authorize",),
        known_process_names=("mcp",),
        known_model_names=(),
        known_tool_names=("mcp", "mcp server"),
        aliases=("model context protocol",),
        trust_level="trusted",
        default_risk_hint="MEDIUM",
    ),
    ProviderCatalogObject(
        provider_id="internal_agents",
        canonical_name="Internal Agent Framework",
        provider_type="agent_framework",
        deployment_surfaces=("aiiam", "gateway", "endpoint"),
        known_domains=(),
        known_api_endpoints=("/runtime-control/agent-action-intercept",),
        known_process_names=("agent", "worker"),
        known_model_names=(),
        known_tool_names=("internal agent",),
        aliases=("workflow agent",),
        trust_level="trusted",
        default_risk_hint="MEDIUM",
    ),
    ProviderCatalogObject(
        provider_id="langchain_agents",
        canonical_name="LangChain-style Agents",
        provider_type="agent_framework",
        deployment_surfaces=("endpoint", "gateway", "aiiam"),
        known_domains=(),
        known_api_endpoints=(),
        known_process_names=("langchain",),
        known_model_names=(),
        known_tool_names=("langchain",),
        aliases=("langchain agent",),
        trust_level="unknown",
        default_risk_hint="HIGH",
    ),
    ProviderCatalogObject(
        provider_id="crewai_agents",
        canonical_name="CrewAI-style Workflows",
        provider_type="agent_framework",
        deployment_surfaces=("endpoint", "gateway", "aiiam"),
        known_domains=(),
        known_api_endpoints=(),
        known_process_names=("crewai",),
        known_model_names=(),
        known_tool_names=("crewai",),
        aliases=("crew ai",),
        trust_level="unknown",
        default_risk_hint="HIGH",
    ),
    ProviderCatalogObject(
        provider_id="autogpt_agents",
        canonical_name="AutoGPT-style Workflows",
        provider_type="agent_framework",
        deployment_surfaces=("endpoint", "gateway", "aiiam"),
        known_domains=(),
        known_api_endpoints=(),
        known_process_names=("autogpt",),
        known_model_names=(),
        known_tool_names=("autogpt",),
        aliases=("auto gpt",),
        trust_level="unknown",
        default_risk_hint="HIGH",
    ),
)


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _extract_domain(value: Any) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = parsed.netloc or parsed.path
        host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if ":" in host:
            host = host.split(":", 1)[0]
        host = host.strip().strip(".").lower()
        return host or None
    except Exception:
        return None


def _domain_matches(pattern: str, domain: str) -> bool:
    p = _norm(pattern)
    d = _norm(domain)
    if not p or not d:
        return False
    if p.startswith("*."):
        return d.endswith(p[1:])
    return d == p


def _contains_any(haystack: str, needles: tuple[str, ...]) -> bool:
    h = _norm(haystack)
    if not h:
        return False
    for needle in needles:
        n = _norm(needle)
        if n and n in h:
            return True
    return False


def _model_family(model_name: str | None) -> str | None:
    name = _norm(model_name)
    if not name:
        return None
    if "gpt" in name or name.startswith("o1") or name.startswith("o3"):
        return "gpt_family"
    if "claude" in name:
        return "claude_family"
    if "gemini" in name:
        return "gemini_family"
    if "mistral" in name or "mixtral" in name:
        return "mistral_family"
    if "llama" in name:
        return "llama_family"
    if "qwen" in name:
        return "qwen_family"
    if "gemma" in name:
        return "gemma_family"
    return "other_family"


def _candidate_score(
    entry: ProviderCatalogObject,
    *,
    domain: str | None,
    api_endpoint: str | None,
    process_name: str | None,
    command_line: str | None,
    model_name: str | None,
    tool_name: str | None,
    provider_raw: str | None,
) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    if domain and any(_domain_matches(pattern, domain) for pattern in entry.known_domains):
        score += 60
        reasons.append("domain_match")
    endpoint_text = f"{api_endpoint or ''} {domain or ''}"
    if entry.known_api_endpoints and _contains_any(endpoint_text, entry.known_api_endpoints):
        score += 30
        reasons.append("api_endpoint_match")
    process_text = f"{process_name or ''} {command_line or ''}"
    if entry.known_process_names and _contains_any(process_text, entry.known_process_names):
        score += 20
        reasons.append("process_match")
    if entry.known_model_names and _contains_any(model_name or "", entry.known_model_names):
        score += 25
        reasons.append("model_match")
    if entry.known_tool_names and _contains_any(tool_name or "", entry.known_tool_names):
        score += 25
        reasons.append("tool_match")
    alias_text = f"{provider_raw or ''} {tool_name or ''} {process_name or ''}"
    if entry.aliases and _contains_any(alias_text, entry.aliases):
        score += 20
        reasons.append("alias_match")
    return score, reasons


@lru_cache(maxsize=1)
def list_catalog_entries() -> list[dict[str, Any]]:
    return [asdict(entry) for entry in CATALOG]


def list_catalog() -> list[dict[str, Any]]:
    return list_catalog_entries()


def catalog_provider_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in CATALOG:
        counts[row.provider_type] = counts.get(row.provider_type, 0) + 1
    return counts


def supported_surface_map() -> dict[str, Any]:
    return {
        "supported_source_surfaces": list(SOURCE_SURFACES),
        "enforcement_capable_surfaces": list(ENFORCEMENT_CAPABLE_SURFACES),
        "monitoring_only_surfaces": list(MONITORING_ONLY_SURFACES),
    }


def _surface_policy_mode(surface: str | None) -> str:
    s = _norm(surface)
    if s in ENFORCEMENT_CAPABLE_SURFACES:
        return "enforceable"
    if s in MONITORING_ONLY_SURFACES:
        return "monitoring_only"
    return "unsupported"


def _surface_behavior_profile(*, surface: str | None, provider_type: str | None) -> str:
    s = _norm(surface)
    ptype = _norm(provider_type)
    if s == "browser":
        if ptype in {"saas_ai", "embedded_copilot"}:
            return "browser_prompt_and_data_movement_control"
        return "browser_discovery_and_policy_overlay"
    if s == "gateway":
        if ptype in {"model_api", "local_model", "agent_framework"}:
            return "gateway_request_response_and_tool_control"
        return "gateway_generic_enforcement"
    if s == "aiiam":
        return "agent_identity_and_action_scope_enforcement"
    if s in {"connector", "endpoint", "dns", "proxy", "monitoring"}:
        return "monitoring_and_retroactive_policy_only"
    return "unsupported_surface"


def provider_surface_capability(provider_id: str, *, source_surface: str | None = None) -> dict[str, Any]:
    wanted_id = _norm(provider_id)
    entry = next((item for item in CATALOG if _norm(item.provider_id) == wanted_id), None)
    surface = _norm(source_surface)
    if entry is None:
        mode = _surface_policy_mode(surface)
        return {
            "provider_id": provider_id,
            "provider_name": provider_id,
            "provider_type": "unknown",
            "deployment_surfaces": [],
            "enforcement_capable_surfaces": [],
            "monitoring_only_surfaces": [],
            "source_surface": surface or None,
            "surface_policy_mode": mode,
            "enforcement_supported_for_source": mode == "enforceable",
            "monitoring_only_for_source": mode == "monitoring_only",
            "behavior_profile": _surface_behavior_profile(surface=surface, provider_type="unknown"),
        }

    enforcement_surfaces = sorted(
        [item for item in entry.deployment_surfaces if _norm(item) in ENFORCEMENT_CAPABLE_SURFACES]
    )
    monitoring_surfaces = sorted(
        [item for item in entry.deployment_surfaces if _norm(item) in MONITORING_ONLY_SURFACES]
    )
    mode = _surface_policy_mode(surface)
    is_supported_on_surface = bool(surface and surface in {_norm(item) for item in entry.deployment_surfaces})
    if surface and not is_supported_on_surface:
        mode = "unsupported"
    return {
        "provider_id": entry.provider_id,
        "provider_name": entry.canonical_name,
        "provider_type": entry.provider_type,
        "deployment_surfaces": list(entry.deployment_surfaces),
        "enforcement_capable_surfaces": enforcement_surfaces,
        "monitoring_only_surfaces": monitoring_surfaces,
        "source_surface": surface or None,
        "surface_policy_mode": mode,
        "enforcement_supported_for_source": bool(mode == "enforceable" and is_supported_on_surface),
        "monitoring_only_for_source": bool(mode == "monitoring_only" and is_supported_on_surface),
        "behavior_profile": _surface_behavior_profile(surface=surface, provider_type=entry.provider_type),
    }


def resolve_provider(signal: dict[str, Any], *, source_surface: str | None = None) -> dict[str, Any]:
    domain = (
        _extract_domain(signal.get("domain"))
        or _extract_domain(signal.get("destination_domain"))
        or _extract_domain(signal.get("request_domain"))
        or _extract_domain(signal.get("queried_domain"))
        or _extract_domain(signal.get("api_endpoint"))
        or _extract_domain(signal.get("full_url"))
        or _extract_domain(signal.get("app_id"))
    )
    api_endpoint = str(signal.get("api_endpoint") or signal.get("full_url") or "").strip() or None
    process_name = str(signal.get("process_name") or "").strip() or None
    command_line = str(signal.get("command_line") or "").strip() or None
    model_name = str(signal.get("model_name") or "").strip() or None
    tool_name = str(signal.get("tool_name") or signal.get("app_name") or "").strip() or None
    provider_raw = str(signal.get("provider") or signal.get("model_provider") or "").strip() or None
    surface = _norm(source_surface or signal.get("source_surface")) or None

    best: ProviderCatalogObject | None = None
    best_score = 0
    best_reasons: list[str] = []
    for row in CATALOG:
        if surface and row.deployment_surfaces and surface not in row.deployment_surfaces:
            continue
        score, reasons = _candidate_score(
            row,
            domain=domain,
            api_endpoint=api_endpoint,
            process_name=process_name,
            command_line=command_line,
            model_name=model_name,
            tool_name=tool_name,
            provider_raw=provider_raw,
        )
        if score > best_score:
            best = row
            best_score = score
            best_reasons = reasons

    if not best:
        unknown_capability = provider_surface_capability("unknown_provider", source_surface=surface)
        return {
            "catalog_match": False,
            "provider_id": "unknown_provider",
            "provider_name": provider_raw or "Unknown Provider",
            "provider_type": "unknown",
            "canonical_tool_name": tool_name or domain or "unknown_tool",
            "normalized_model_family": _model_family(model_name),
            "confidence_hint": "low",
            "matched_on": [],
            "domain": domain,
            "source_surface": surface,
            "default_risk_hint": "HIGH",
            "trust_level": "unknown",
            "surface_policy_mode": unknown_capability.get("surface_policy_mode"),
            "enforcement_supported_for_source": bool(unknown_capability.get("enforcement_supported_for_source")),
            "monitoring_only_for_source": bool(unknown_capability.get("monitoring_only_for_source")),
            "behavior_profile": unknown_capability.get("behavior_profile"),
            "provider_capability": unknown_capability,
        }

    confidence_hint = "low"
    if best_score >= 80:
        confidence_hint = "high"
    elif best_score >= 40:
        confidence_hint = "medium"

    canonical_tool_name = tool_name or (best.known_tool_names[0] if best.known_tool_names else best.canonical_name)
    capability = provider_surface_capability(best.provider_id, source_surface=surface)
    return {
        "catalog_match": True,
        "provider_id": best.provider_id,
        "provider_name": best.canonical_name,
        "provider_type": best.provider_type,
        "canonical_tool_name": canonical_tool_name,
        "normalized_model_family": _model_family(model_name),
        "confidence_hint": confidence_hint,
        "matched_on": best_reasons,
        "domain": domain,
        "source_surface": surface,
        "default_risk_hint": best.default_risk_hint,
        "trust_level": best.trust_level,
        "surface_policy_mode": capability.get("surface_policy_mode"),
        "enforcement_supported_for_source": bool(capability.get("enforcement_supported_for_source")),
        "monitoring_only_for_source": bool(capability.get("monitoring_only_for_source")),
        "behavior_profile": capability.get("behavior_profile"),
        "provider_capability": capability,
    }
