import test from "node:test";
import assert from "node:assert/strict";

import {
  HawkAgentBindingBlockedError,
  createAgentOsBinding,
  detectGmailTransport,
} from "./hawk-binding.mjs";

const TEST_AI_SYSTEM_ID = "8ccac84e-41d5-4f49-980f-dd389ec022aa";


function allowedDecision(surface = "developer_agent") {
  return {
    final_decision: "allow",
    decision: "allow",
    control_mode: "inline_allowed",
    endpoint_authorized: true,
    decision_source: "endpoint_agent",
    endpoint_surface: surface,
    evidence_bundle_id: "evidence-1",
  };
}


test("detects the active Gmail transport from runtime configuration without reading credentials", () => {
  assert.equal(detectGmailTransport({ COMPOSIO_API_KEY: "present" }), "composio");
  assert.equal(detectGmailTransport({ GMAIL_TRANSPORT: "google_direct" }), "google_direct");
  assert.equal(detectGmailTransport({ GMAIL_TRANSPORT: "composio", GOOGLE_TOKEN_PATH: "/tmp/token.json" }), "composio");
  assert.equal(detectGmailTransport({}), "unknown");
});


test("registers a secret-free runtime profile with both Gmail bindings and the active transport", async () => {
  const registrations = [];
  const client = {
    async endpointRegisterAgent(payload) {
      registrations.push(payload);
      return {
        status: "registered",
        registration_id: "registration-1",
        evidence_state: "sdk_self_registration",
        control_state: "monitor_only",
        active_integration_transport: payload.active_integration_transport,
        evidence_ref: "evidence-registration-1",
      };
    },
  };
  const binding = await createAgentOsBinding({
    hawkClient: client,
    env: {
      COMPOSIO_API_KEY: "composio-secret",
      TAVILY_API_KEY: "tavily-secret",
      HAWK_AGENT_CAPABILITY_TOKEN: "capability-secret",
      HAWK_AGENT_MODE: "enforce",
    },
  });

  const result = await binding.register({ models: ["qwen3.5:9b", "qwen2.5:14b"] });

  assert.equal(result.active_integration_transport, "composio");
  assert.equal(registrations[0].control_binding.mode, "enforce");
  assert.deepEqual(
    registrations[0].integration_transports
      .filter((item) => item.capability === "gmail")
      .map((item) => [item.transport, item.active]),
    [["composio", true], ["google_direct", false]],
  );
  const serialized = JSON.stringify(registrations[0]);
  assert.equal(serialized.includes("composio-secret"), false);
  assert.equal(serialized.includes("tavily-secret"), false);
  assert.equal(serialized.includes("capability-secret"), false);
});


test("authorizes Ollama before executing the model callback", async () => {
  const order = [];
  const client = {
    async endpointLlm(payload) {
      order.push(["hawk", payload.provider, payload.model]);
      return allowedDecision("llm");
    },
  };
  const binding = await createAgentOsBinding({
    hawkClient: client,
    env: { HAWK_AGENT_AI_SYSTEM_ID: TEST_AI_SYSTEM_ID, HAWK_AGENT_MODE: "enforce" },
  });

  const result = await binding.withLlmAuthorization(
    { prompt: "Summarize public data", model: "qwen3.5:9b" },
    async () => {
      order.push(["ollama"]);
      return "model-result";
    },
  );

  assert.equal(result.result, "model-result");
  assert.deepEqual(order, [["hawk", "ollama", "qwen3.5:9b"], ["ollama"]]);
});


test("uses the explicitly configured registered Hawk AI system for every decision", async () => {
  const seen = [];
  const client = {
    async endpointLlm(payload) {
      seen.push(["llm", payload.ai_system_id]);
      return allowedDecision("llm");
    },
    async endpointDeveloperAgent(payload) {
      seen.push(["tool", payload.ai_system_id]);
      return allowedDecision();
    },
  };
  const binding = await createAgentOsBinding({
    hawkClient: client,
    env: {
      COMPOSIO_API_KEY: "present",
      HAWK_AGENT_AI_SYSTEM_ID: TEST_AI_SYSTEM_ID,
      HAWK_AGENT_MODE: "enforce",
    },
    capabilityTokenProvider: () => "short-lived-capability-token",
  });

  await binding.authorizeLlm({ prompt: "Synthetic", model: "qwen3.5:9b" });
  await binding.authorizeTool({ toolName: "GMAIL_FETCH_EMAILS", args: {} });

  assert.deepEqual(seen, [
    ["llm", "8ccac84e-41d5-4f49-980f-dd389ec022aa"],
    ["tool", "8ccac84e-41d5-4f49-980f-dd389ec022aa"],
  ]);
});


test("missing Hawk AI system configuration fails closed before an endpoint call", async () => {
  let calls = 0;
  const binding = await createAgentOsBinding({
    hawkClient: {
      async endpointLlm() {
        calls += 1;
        return allowedDecision("llm");
      },
    },
    env: { HAWK_AGENT_MODE: "enforce" },
  });

  await assert.rejects(
    () => binding.authorizeLlm({ prompt: "Synthetic", model: "qwen3.5:9b" }),
    (error) => error instanceof HawkAgentBindingBlockedError
      && error.reasonCode === "hawk_ai_system_configuration_missing",
  );
  assert.equal(calls, 0);
});


test("maps Gmail and Tavily operations to content-free endpoint authorization before callbacks", async () => {
  const order = [];
  const requests = [];
  const client = {
    async endpointDeveloperAgent(payload) {
      order.push(`hawk:${payload.tool_name}`);
      requests.push(payload);
      return allowedDecision();
    },
  };
  const binding = await createAgentOsBinding({
    hawkClient: client,
    env: {
      COMPOSIO_API_KEY: "present",
      HAWK_AGENT_AI_SYSTEM_ID: TEST_AI_SYSTEM_ID,
      HAWK_AGENT_MODE: "enforce",
    },
    capabilityTokenProvider: () => "short-lived-capability-token",
  });

  const send = await binding.withToolAuthorization(
    {
      toolName: "GMAIL_SEND_EMAIL",
      args: { recipient_email: "ciso@bank.example", subject: "Private", body: "Sensitive body" },
    },
    async () => {
      order.push("execute:gmail");
      return "sent";
    },
  );
  await binding.withToolAuthorization(
    { toolName: "web_search", args: { query: "bank acquisition" } },
    async () => {
      order.push("execute:web");
      return "searched";
    },
  );

  assert.equal(send.result, "sent");
  assert.deepEqual(order, [
    "hawk:GMAIL_SEND_EMAIL",
    "execute:gmail",
    "hawk:web_search",
    "execute:web",
  ]);
  assert.equal(requests[0].action, "email.send");
  assert.equal(requests[0].resource, "gmail://outbound");
  assert.equal(requests[0].tool_usage_meta.integration_transport, "composio");
  assert.equal(requests[1].action, "web.read");
  assert.equal(requests[1].tool_usage_meta.integration_transport, "tavily_direct");
  const serialized = JSON.stringify(requests);
  assert.equal(serialized.includes("ciso@bank.example"), false);
  assert.equal(serialized.includes("Sensitive body"), false);
  assert.equal(serialized.includes("bank acquisition"), false);
});


test("blocks callbacks on denied, monitor-only, unavailable, or missing-capability paths", async () => {
  let executions = 0;
  const deniedClient = {
    async endpointDeveloperAgent() {
      return {
        ...allowedDecision(),
        final_decision: "block",
        decision: "block",
        control_mode: "inline_prevented",
      };
    },
  };
  const monitorClient = {
    async endpointDeveloperAgent() {
      return {
        ...allowedDecision(),
        endpoint_authorized: false,
        decision_source: "endpoint_agent_monitor",
        control_mode: "monitor_would_allow",
      };
    },
  };
  const unavailableClient = {
    async endpointDeveloperAgent() {
      throw new Error("socket unavailable");
    },
  };

  for (const [client, tokenProvider] of [
    [deniedClient, () => "token"],
    [monitorClient, () => "token"],
    [unavailableClient, () => "token"],
    [deniedClient, () => ""],
  ]) {
    const binding = await createAgentOsBinding({
      hawkClient: client,
      env: {
        COMPOSIO_API_KEY: "present",
        HAWK_AGENT_AI_SYSTEM_ID: TEST_AI_SYSTEM_ID,
        HAWK_AGENT_MODE: "enforce",
      },
      capabilityTokenProvider: tokenProvider,
    });
    await assert.rejects(
      () => binding.withToolAuthorization(
        { toolName: "GMAIL_SEND_EMAIL", args: {} },
        async () => {
          executions += 1;
        },
      ),
      (error) => error instanceof HawkAgentBindingBlockedError,
    );
  }
  assert.equal(executions, 0);
});
