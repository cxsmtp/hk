import { describe, expect, it } from "vitest";

import { detectAgentRuntimeProfile } from "./agent-runtime-discovery";

describe("agent runtime discovery", () => {
  it("detects local agent runtime with model, tools, actions, and privileges", () => {
    const profile = detectAgentRuntimeProfile({
      domain: "localhost",
      url: "http://localhost:5173",
      title: "Agent OS",
      bodyText: [
        "Agent OS",
        "qwen2.5:14b · web_search",
        "Ollama connected",
        "Tools & MCP",
        "Web Search",
        "MCP Tools (2)",
        "Command center online. I can search the web in real-time, write and summarize emails, run research, and save drafts in Gmail.",
      ].join("\n"),
    });

    expect(profile).not.toBeNull();
    expect(profile?.agent_name).toBe("agent-os");
    expect(profile?.model_name).toBe("qwen2.5:14b");
    expect(profile?.runtime_provider).toBe("ollama");
    expect(profile?.tools).toEqual(expect.arrayContaining(["web.search", "mcp.tools", "gmail.draft"]));
    expect(profile?.actions).toEqual(expect.arrayContaining(["research.company", "draft.email", "save.gmail_draft"]));
    expect(profile?.privileges).toEqual(
      expect.arrayContaining(["network.web_access", "mcp.tool.invoke", "email.gmail_draft_write"])
    );
    expect(profile?.agent_id).toMatch(/^agt-[a-f0-9]{32}$/);
  });

  it("returns null for non-agent pages", () => {
    const profile = detectAgentRuntimeProfile({
      domain: "nytimes.com",
      url: "https://nytimes.com",
      title: "Top Stories",
      bodyText: "News and analysis",
    });
    expect(profile).toBeNull();
  });

  it("returns null for the Hawk control plane running on localhost", () => {
    const profile = detectAgentRuntimeProfile({
      domain: "localhost",
      url: "http://localhost:3000/discovery/findings/d76b863f-11fc-447e-a84b-2a0a8b0ac479",
      title: "AI Control Plane",
      bodyText: [
        "AI Control Plane",
        "Command Center",
        "Discovery findings",
        "AI IAM agents",
        "Governance review queue",
      ].join("\n"),
    });
    expect(profile).toBeNull();
  });
});
