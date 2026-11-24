import { describe, expect, it } from "vitest";

import { classifyDiscoveryEligibility } from "./discovery-heuristics";

const scopedDomains = new Set([
  "chatgpt.com",
  "claude.ai",
  "mail.google.com",
]);

const policyManagedDomains = [
  "mail.google.com",
  "outlook.com",
  "hotmail.com",
];

describe("discovery heuristics", () => {
  it("marks known AI domains as eligible", () => {
    const result = classifyDiscoveryEligibility(
      {
        domain: "chatgpt.com",
        url: "https://chatgpt.com/",
        title: "ChatGPT",
      },
      {
        scopedDomains,
        policyManagedDomains,
      }
    );
    expect(result.eligible).toBe(true);
    expect(result.hint).toBe("known_ai_domain");
  });

  it("marks policy managed collaboration domains as eligible", () => {
    const result = classifyDiscoveryEligibility(
      {
        domain: "mail.google.com",
        url: "https://mail.google.com/mail/u/0/#inbox",
        title: "Inbox",
      },
      {
        scopedDomains,
        policyManagedDomains,
      }
    );
    expect(result.eligible).toBe(true);
    expect(result.hint).toBe("policy_managed_domain");
  });

  it("discovers unknown agentic domains using keyword hints", () => {
    const result = classifyDiscoveryEligibility(
      {
        domain: "agent-os-demo.company.internal",
        url: "https://agent-os-demo.company.internal/workflows",
        title: "Agent OS Dashboard",
      },
      {
        scopedDomains,
        policyManagedDomains,
      }
    );
    expect(result.eligible).toBe(true);
    expect(result.hint).toBe("agentic_keyword");
  });

  it("discovers local agent runtimes when URL/title indicates agent activity", () => {
    const result = classifyDiscoveryEligibility(
      {
        domain: "localhost",
        url: "http://localhost:3000/mcp",
        title: "Local MCP Agent",
      },
      {
        scopedDomains,
        policyManagedDomains,
      }
    );
    expect(result.eligible).toBe(true);
    expect(result.hint).toBe("agentic_keyword");
  });

  it("does not discover the Hawk control plane as a local agent runtime", () => {
    const result = classifyDiscoveryEligibility(
      {
        domain: "localhost",
        url: "http://localhost:3000/dashboard/command-center",
        title: "AI Control Plane",
      },
      {
        scopedDomains,
        policyManagedDomains,
      }
    );
    expect(result.eligible).toBe(false);
    expect(result.hint).toBeNull();
  });

  it("discovers localhost model runtimes for ollama/qwen signals", () => {
    const result = classifyDiscoveryEligibility(
      {
        domain: "localhost",
        url: "http://localhost:3000/chat",
        title: "Open WebUI - Qwen",
      },
      {
        scopedDomains,
        policyManagedDomains,
      }
    );
    expect(result.eligible).toBe(true);
    expect(result.hint).toBe("local_agent_runtime");
  });

  it("discovers localhost ollama runtime by port even with neutral title", () => {
    const result = classifyDiscoveryEligibility(
      {
        domain: "localhost",
        url: "http://localhost:11434/",
        title: "Localhost",
      },
      {
        scopedDomains,
        policyManagedDomains,
      }
    );
    expect(result.eligible).toBe(true);
    expect(result.hint).toBe("local_agent_runtime");
  });

  it("does not mark unrelated domains as AI usage targets", () => {
    const result = classifyDiscoveryEligibility(
      {
        domain: "nytimes.com",
        url: "https://www.nytimes.com/",
        title: "Top Stories",
      },
      {
        scopedDomains,
        policyManagedDomains,
      }
    );
    expect(result.eligible).toBe(false);
    expect(result.hint).toBeNull();
  });
});
