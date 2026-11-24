import type { ConnectorProviderCatalogItem } from "@/lib/types";

export const CONNECTOR_CATEGORIES = [
  "Agent and model platforms",
  "MCP gateways and proxies",
  "Browser, desktop, IDE and CLI",
  "Enterprise applications",
  "Endpoint, EDR, SASE and network controls",
  "Cloud and AI runtimes",
  "SDK and application bindings",
] as const;

export type ConnectorCategory = (typeof CONNECTOR_CATEGORIES)[number];

export type ConnectorReadiness = {
  delivery: "production" | "preview" | "planned";
  coverageEligible: boolean;
  statusLabel: string;
  assertion: string;
};

export type ConnectorCapabilities = {
  discover: boolean;
  authorize: false;
  prove: boolean;
};

const ENTERPRISE_APPLICATION_CATEGORIES = new Set([
  "collaboration",
  "identity",
  "microsoft",
  "productivity",
  "storage",
  "ticketing",
]);

const ENDPOINT_AND_NETWORK_CATEGORIES = new Set([
  "endpoint",
  "network_firewall",
  "pam",
  "security",
]);

export function normalizeConnectorCategory(category?: string | null, providerKey?: string | null): ConnectorCategory {
  const normalizedCategory = String(category || "").trim().toLowerCase();
  const normalizedKey = String(providerKey || "").trim().toLowerCase();

  if (normalizedKey.includes("mcp")) return "MCP gateways and proxies";
  if (/browser|chrome|claude_desktop|codex|cursor|\bide\b|\bcli\b/.test(normalizedKey)) {
    return "Browser, desktop, IDE and CLI";
  }
  if (/foundry|copilot|openai|anthropic|bedrock|vertex|ai_platform/.test(`${normalizedCategory} ${normalizedKey}`)) {
    return "Agent and model platforms";
  }
  if (ENTERPRISE_APPLICATION_CATEGORIES.has(normalizedCategory)) return "Enterprise applications";
  if (/microsoft|gmail|google_workspace|slack|teams|sharepoint|salesforce|servicenow/.test(normalizedKey)) {
    return "Enterprise applications";
  }
  if (ENDPOINT_AND_NETWORK_CATEGORIES.has(normalizedCategory)) return "Endpoint, EDR, SASE and network controls";
  if (/endpoint|crowdstrike|edr|sase|ztna|zscaler|netskope|network|firewall/.test(normalizedKey)) {
    return "Endpoint, EDR, SASE and network controls";
  }
  if (normalizedCategory === "cloud" || /aws|azure|gcp|cloud/.test(normalizedKey)) return "Cloud and AI runtimes";
  if (["api_security", "appsec"].includes(normalizedCategory) || /sdk|api|application/.test(normalizedKey)) {
    return "SDK and application bindings";
  }
  return "Enterprise applications";
}

export function deriveConnectorReadiness(provider: ConnectorProviderCatalogItem): ConnectorReadiness {
  if (provider.is_stub) {
    return {
      delivery: "planned",
      coverageEligible: false,
      statusLabel: "Planned",
      assertion: "Unsupported today. Does not contribute to coverage.",
    };
  }
  if (!provider.supports_live_pull) {
    return {
      delivery: "preview",
      coverageEligible: false,
      statusLabel: "Preview",
      assertion: "Adapter metadata exists, but live evidence collection is unavailable.",
    };
  }
  return {
    delivery: "production",
    coverageEligible: true,
    statusLabel: "Production",
    assertion: "Verified evidence still required before Hawk reports coverage.",
  };
}

export function deriveConnectorCapabilities(provider: ConnectorProviderCatalogItem): ConnectorCapabilities {
  const hasSignals = provider.signals.length > 0;
  return {
    discover: provider.supports_live_pull && hasSignals,
    authorize: false,
    prove: provider.supports_live_pull && provider.signals.some((signal) => Boolean(signal.evidence_signal_type)),
  };
}
