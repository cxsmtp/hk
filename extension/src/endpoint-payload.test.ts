import { describe, expect, it } from "vitest";

import { endpointInteractionPayload } from "./endpoint-payload";

describe("endpoint bridge payload normalization", () => {
  it("preserves browser app identity when interaction evaluation is routed through the endpoint agent", () => {
    const payload = endpointInteractionPayload({
      ai_action: {
        kind: "prompt",
        surface: {
          source_surface: "browser",
          domain: "chatgpt.com",
          application: "ChatGPT",
          url: "https://chatgpt.com/c/demo",
        },
      },
      context: {
        page_context: {
          domain: "chatgpt.com",
          url: "https://chatgpt.com/c/demo",
          title: "ChatGPT",
        },
        app_context: {
          app_id: "chatgpt",
          app_name: "ChatGPT",
          app_domain: "chatgpt.com",
        },
      },
      legacy_interaction_payload: {
        raw_prompt: "demo prompt",
        prompt_preview_redacted: "[redacted prompt]",
      },
    });

    expect(payload).toMatchObject({
      prompt: "demo prompt",
      domain: "chatgpt.com",
      url: "https://chatgpt.com/c/demo",
      application: "ChatGPT",
      ai_app: "chatgpt.com",
      source_surface: "browser",
      browser_type: "chrome",
      page_title: "ChatGPT",
    });
  });

  it("does not let placeholder desktop-native domain override the observed app name", () => {
    const payload = endpointInteractionPayload({
      ai_action: {
        kind: "prompt",
        surface: {
          source_surface: "browser",
          domain: "desktop-native",
          application: "ChatGPT Desktop",
        },
      },
      legacy_interaction_payload: {
        raw_prompt: "demo prompt",
        prompt_preview_redacted: "[redacted prompt]",
      },
    });

    expect(payload).toMatchObject({
      domain: "desktop-native",
      application: "ChatGPT Desktop",
      ai_app: "ChatGPT Desktop",
      source_surface: "browser",
    });
  });
});
